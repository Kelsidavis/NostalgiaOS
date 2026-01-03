//! Plug and Play (PnP) Manager
//!
//! The PnP Manager is responsible for:
//! - Enumerating hardware devices during boot
//! - Managing device drivers (loading, unloading)
//! - Handling device arrival and removal
//! - Managing device resources (IRQ, I/O ports, memory)
//! - Sending PnP IRPs to drivers
//!
//! # Architecture
//!
//! The PnP Manager maintains a device tree (devnode tree) rooted at the
//! "HTREE\\ROOT\\0" device. Each device node represents a physical or
//! logical device in the system.
//!
//! # Reference
//!
//! Based on Windows Server 2003 PnP implementation from base/ntos/io/pnpmgr/

mod devnode;
mod enumerate;
mod irp;
mod resource;

pub use devnode::*;
pub use enumerate::*;
pub use irp::*;
pub use resource::*;

use crate::io::{DeviceObject, DriverObject};
use crate::ke::SpinLock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

extern crate alloc;

/// PnP subsystem initialized flag
static PNP_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Device instance ID counter
static NEXT_INSTANCE_ID: AtomicU32 = AtomicU32::new(0);

/// Global PnP state
pub struct PnpState {
    /// Root device node
    root_devnode: Option<Arc<DeviceNode>>,
    /// All device nodes by instance path
    devices: SpinLock<BTreeMap<DeviceInstancePath, Arc<DeviceNode>>>,
    /// Pending device enumerations
    pending_enumerations: SpinLock<Vec<Arc<DeviceNode>>>,
    /// Resource arbiter registry
    resource_arbiters: SpinLock<BTreeMap<ResourceType, Arc<dyn ResourceArbiter>>>,
}

impl PnpState {
    pub const fn new() -> Self {
        Self {
            root_devnode: None,
            devices: SpinLock::new(BTreeMap::new()),
            pending_enumerations: SpinLock::new(Vec::new()),
            resource_arbiters: SpinLock::new(BTreeMap::new()),
        }
    }
}

static mut PNP_STATE: Option<PnpState> = None;

fn get_pnp_state() -> &'static PnpState {
    unsafe { PNP_STATE.as_ref().expect("PnP not initialized") }
}

fn get_pnp_state_mut() -> &'static mut PnpState {
    unsafe { PNP_STATE.as_mut().expect("PnP not initialized") }
}

/// Initialize the PnP Manager
pub fn pp_init_system() -> bool {
    if PNP_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return true; // Already initialized
    }

    unsafe {
        PNP_STATE = Some(PnpState::new());
    }

    // Create root device node
    let root = Arc::new(DeviceNode::new_root());
    get_pnp_state_mut().root_devnode = Some(root.clone());

    // Register in devices map
    {
        let mut devices = get_pnp_state().devices.lock();
        devices.insert(root.instance_path().clone(), root);
    }

    // Register standard resource arbiters
    register_standard_arbiters();

    crate::serial_println!("[PNP] Plug and Play Manager initialized");
    true
}

/// Register standard resource arbiters
fn register_standard_arbiters() {
    let state = get_pnp_state();
    let mut arbiters = state.resource_arbiters.lock();

    // IRQ arbiter
    arbiters.insert(
        ResourceType::Interrupt,
        Arc::new(IrqArbiter::new()) as Arc<dyn ResourceArbiter>,
    );

    // Memory arbiter
    arbiters.insert(
        ResourceType::Memory,
        Arc::new(MemoryArbiter::new()) as Arc<dyn ResourceArbiter>,
    );

    // I/O port arbiter
    arbiters.insert(
        ResourceType::Port,
        Arc::new(IoPortArbiter::new()) as Arc<dyn ResourceArbiter>,
    );

    // DMA channel arbiter
    arbiters.insert(
        ResourceType::Dma,
        Arc::new(DmaArbiter::new()) as Arc<dyn ResourceArbiter>,
    );
}

/// Device instance path (e.g., "PCI\\VEN_8086&DEV_1234\\0")
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceInstancePath {
    path: String,
}

impl DeviceInstancePath {
    pub fn new(path: String) -> Self {
        Self { path }
    }

    pub fn from_str(s: &str) -> Self {
        Self {
            path: String::from(s),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.path
    }

    pub fn root() -> Self {
        Self::from_str("HTREE\\ROOT\\0")
    }
}

/// Device registry property
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRegistryProperty {
    DeviceDescription = 0,
    HardwareId = 1,
    CompatibleIds = 2,
    BootConfiguration = 3,
    BootConfigurationTranslated = 4,
    ClassName = 5,
    ClassGuid = 6,
    DriverKeyName = 7,
    Manufacturer = 8,
    FriendlyName = 9,
    LocationInformation = 10,
    PhysicalDeviceObjectName = 11,
    BusTypeGuid = 12,
    LegacyBusType = 13,
    BusNumber = 14,
    EnumeratorName = 15,
    Address = 16,
    UiNumber = 17,
    InstallState = 18,
    RemovalPolicy = 19,
}

/// Device install state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceInstallState {
    #[default]
    Installed = 0,
    NeedsReinstall = 1,
    FailedInstall = 2,
    FinishInstall = 3,
}

/// Device removal policy
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceRemovalPolicy {
    #[default]
    ExpectNoRemoval = 1,
    ExpectOrderlyRemoval = 2,
    ExpectSurpriseRemoval = 3,
}

/// PnP bus information
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PnpBusInformation {
    /// Bus type GUID
    pub bus_type_guid: crate::etw::Guid,
    /// Legacy bus type
    pub legacy_bus_type: InterfaceType,
    /// Bus number
    pub bus_number: u32,
}

/// Interface type enumeration
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InterfaceType {
    #[default]
    InterfaceTypeUndefined = 0xFFFFFFFF,
    Internal = 0,
    Isa = 1,
    Eisa = 2,
    MicroChannel = 3,
    TurboChannel = 4,
    PCIBus = 5,
    VMEBus = 6,
    NuBus = 7,
    PCMCIABus = 8,
    CBus = 9,
    MPIBus = 10,
    MPSABus = 11,
    ProcessorInternal = 12,
    InternalPowerBus = 13,
    PNPISABus = 14,
    PNPBus = 15,
    Vmcs = 16,
    ACPIBus = 17,
}

/// Device relation type for IRP_MN_QUERY_DEVICE_RELATIONS
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRelationType {
    /// Child devices
    BusRelations = 0,
    /// Eject relations
    EjectionRelations = 1,
    /// Power relations
    PowerRelations = 2,
    /// Removal relations
    RemovalRelations = 3,
    /// Target device relations
    TargetDeviceRelation = 4,
    /// Single bus relations
    SingleBusRelations = 5,
}

/// Device relations structure
#[repr(C)]
pub struct DeviceRelations {
    /// Number of objects
    pub count: u32,
    /// Array of device objects
    pub objects: [*mut DeviceObject; 1], // Variable length array
}

/// Report a detected (legacy) device
pub fn io_report_detected_device(
    _driver: &DriverObject,
    bus_type: InterfaceType,
    bus_number: u32,
    _slot_number: u32,
    resources: Option<&CmResourceList>,
) -> Result<Arc<DeviceNode>, PnpError> {
    let state = get_pnp_state();

    // Generate instance path
    let instance_id = NEXT_INSTANCE_ID.fetch_add(1, Ordering::SeqCst);
    let instance_path = DeviceInstancePath::from_str(&alloc::format!(
        "Root\\LEGACY_{}\\{:04X}",
        "DEVICE", // Would come from driver
        instance_id
    ));

    // Create device node
    let devnode = Arc::new(DeviceNode::new(
        instance_path.clone(),
        DeviceNodeType::PhysicalDeviceObject,
    ));

    // Set bus information
    devnode.set_bus_info(PnpBusInformation {
        legacy_bus_type: bus_type,
        bus_number,
        ..Default::default()
    });

    // Register resources if provided
    if let Some(res) = resources {
        devnode.set_boot_resources(res.clone());
    }

    // Add to device tree under root
    if let Some(root) = &state.root_devnode {
        root.add_child(devnode.clone());
    }

    // Register in devices map
    {
        let mut devices = state.devices.lock();
        devices.insert(instance_path, devnode.clone());
    }

    Ok(devnode)
}

/// Invalidate device relations (trigger re-enumeration)
pub fn io_invalidate_device_relations(device: &DeviceObject, _relation_type: DeviceRelationType) {
    let state = get_pnp_state();

    // Find device node for this device object
    let devices = state.devices.lock();
    for (_path, devnode) in devices.iter() {
        if devnode.matches_device(device) {
            // Queue for enumeration
            let mut pending = state.pending_enumerations.lock();
            pending.push(devnode.clone());
            break;
        }
    }

    // Trigger async enumeration
    // In a real implementation, this would queue a work item
}

/// Synchronously invalidate device relations
pub fn io_synchronous_invalidate_device_relations(
    device: &DeviceObject,
    relation_type: DeviceRelationType,
) -> Result<(), PnpError> {
    // Perform synchronous enumeration
    io_invalidate_device_relations(device, relation_type);
    // Wait for completion (synchronous)
    Ok(())
}

/// Request device eject
pub fn io_request_device_eject(pdo: &DeviceObject) {
    // Find device node
    let state = get_pnp_state();
    let devices = state.devices.lock();

    for (_path, devnode) in devices.iter() {
        if devnode.matches_device(pdo) {
            devnode.request_eject();
            break;
        }
    }
}

/// Get device property
pub fn io_get_device_property(
    device: &DeviceObject,
    property: DeviceRegistryProperty,
    buffer: &mut [u8],
) -> Result<usize, PnpError> {
    let state = get_pnp_state();
    let devices = state.devices.lock();

    for (_path, devnode) in devices.iter() {
        if devnode.matches_device(device) {
            return devnode.get_property(property, buffer);
        }
    }

    Err(PnpError::DeviceNotFound)
}

/// PnP device registration
pub fn pp_device_registration(
    instance_path: &str,
    add: bool,
    service_key: Option<&str>,
) -> Result<(), PnpError> {
    let state = get_pnp_state();
    let path = DeviceInstancePath::from_str(instance_path);

    if add {
        // Register new device
        let devnode = Arc::new(DeviceNode::new(path.clone(), DeviceNodeType::Unknown));

        if let Some(service) = service_key {
            devnode.set_service(String::from(service));
        }

        let mut devices = state.devices.lock();
        devices.insert(path, devnode);
    } else {
        // Unregister device
        let mut devices = state.devices.lock();
        devices.remove(&path);
    }

    Ok(())
}

/// PnP errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnpError {
    DeviceNotFound,
    InvalidParameter,
    ResourceConflict,
    DriverNotFound,
    DeviceFailed,
    InsufficientResources,
    NotSupported,
}

/// Device capabilities structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceCapabilities {
    /// Size of structure
    pub size: u16,
    /// Version
    pub version: u16,
    /// Capability flags (packed)
    pub capabilities: u32,
    /// Device address
    pub address: u32,
    /// UI number
    pub ui_number: u32,
    /// Device power state mapping
    pub device_state: [DevicePowerState; 7],
    /// System wake level
    pub system_wake: SystemPowerState,
    /// Device wake level
    pub device_wake: DevicePowerState,
    /// D1 latency (ms)
    pub d1_latency: u32,
    /// D2 latency (ms)
    pub d2_latency: u32,
    /// D3 latency (ms)
    pub d3_latency: u32,
}

impl DeviceCapabilities {
    pub fn new() -> Self {
        Self {
            size: core::mem::size_of::<Self>() as u16,
            version: 1,
            ..Default::default()
        }
    }

    // Capability flag accessors
    pub fn device_d1(&self) -> bool {
        (self.capabilities & 0x0001) != 0
    }
    pub fn device_d2(&self) -> bool {
        (self.capabilities & 0x0002) != 0
    }
    pub fn lock_supported(&self) -> bool {
        (self.capabilities & 0x0004) != 0
    }
    pub fn eject_supported(&self) -> bool {
        (self.capabilities & 0x0008) != 0
    }
    pub fn removable(&self) -> bool {
        (self.capabilities & 0x0010) != 0
    }
    pub fn dock_device(&self) -> bool {
        (self.capabilities & 0x0020) != 0
    }
    pub fn unique_id(&self) -> bool {
        (self.capabilities & 0x0040) != 0
    }
    pub fn silent_install(&self) -> bool {
        (self.capabilities & 0x0080) != 0
    }
    pub fn raw_device_ok(&self) -> bool {
        (self.capabilities & 0x0100) != 0
    }
    pub fn surprise_removal_ok(&self) -> bool {
        (self.capabilities & 0x0200) != 0
    }
}

/// Device power state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DevicePowerState {
    #[default]
    Unspecified = 0,
    D0 = 1,
    D1 = 2,
    D2 = 3,
    D3 = 4,
    Maximum = 5,
}

/// System power state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SystemPowerState {
    #[default]
    Unspecified = 0,
    Working = 1,
    Sleeping1 = 2,
    Sleeping2 = 3,
    Sleeping3 = 4,
    Hibernate = 5,
    Shutdown = 6,
    Maximum = 7,
}

/// PnP statistics
#[derive(Debug, Default)]
pub struct PnpStatistics {
    /// Total devices
    pub total_devices: u32,
    /// Started devices
    pub started_devices: u32,
    /// Stopped devices
    pub stopped_devices: u32,
    /// Failed devices
    pub failed_devices: u32,
    /// Pending enumerations
    pub pending_enumerations: u32,
}

/// Get PnP statistics
pub fn pnp_get_statistics() -> PnpStatistics {
    let state = get_pnp_state();

    let devices = state.devices.lock();
    let pending = state.pending_enumerations.lock();

    let mut stats = PnpStatistics {
        total_devices: devices.len() as u32,
        pending_enumerations: pending.len() as u32,
        ..Default::default()
    };

    for (_path, devnode) in devices.iter() {
        match devnode.state() {
            DeviceNodeState::Started => stats.started_devices += 1,
            DeviceNodeState::Stopped => stats.stopped_devices += 1,
            DeviceNodeState::Failed => stats.failed_devices += 1,
            _ => {}
        }
    }

    stats
}
