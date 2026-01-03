//! Plug and Play Manager (PnP)
//!
//! The PnP manager handles device enumeration, resource allocation, and driver loading.
//!
//! # Windows NT PnP Architecture
//!
//! - **Device Tree**: Hierarchical structure of devices
//! - **Device Nodes**: Represent hardware instances
//! - **Resources**: IRQ, I/O ports, memory, DMA channels
//! - **Bus Drivers**: Enumerate children (PCI, USB, ACPI)
//!
//! # IRP_MJ_PNP Minor Functions
//!
//! - IRP_MN_START_DEVICE: Assign resources and start device
//! - IRP_MN_STOP_DEVICE: Stop device (for resource rebalancing)
//! - IRP_MN_REMOVE_DEVICE: Remove device from system
//! - IRP_MN_QUERY_DEVICE_RELATIONS: Enumerate children
//! - IRP_MN_QUERY_CAPABILITIES: Query power/removal capabilities

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use crate::ke::SpinLock;

// ============================================================================
// PnP Minor Function Codes
// ============================================================================

/// PnP IRP minor function codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PnpMinorFunction {
    /// Start the device
    StartDevice = 0x00,
    /// Query if device can be removed
    QueryRemoveDevice = 0x01,
    /// Remove device
    RemoveDevice = 0x02,
    /// Cancel pending remove
    CancelRemoveDevice = 0x03,
    /// Stop device for rebalancing
    StopDevice = 0x04,
    /// Query if device can be stopped
    QueryStopDevice = 0x05,
    /// Cancel pending stop
    CancelStopDevice = 0x06,
    /// Query device relations
    QueryDeviceRelations = 0x07,
    /// Query device interface
    QueryInterface = 0x08,
    /// Query device capabilities
    QueryCapabilities = 0x09,
    /// Query device resources
    QueryResources = 0x0A,
    /// Query resource requirements
    QueryResourceRequirements = 0x0B,
    /// Query device text
    QueryDeviceText = 0x0C,
    /// Filter resource requirements
    FilterResourceRequirements = 0x0D,
    /// Read device config
    ReadConfig = 0x0F,
    /// Write device config
    WriteConfig = 0x10,
    /// Device eject
    Eject = 0x11,
    /// Set device lock
    SetLock = 0x12,
    /// Query device ID
    QueryId = 0x13,
    /// Query PnP device state
    QueryPnpDeviceState = 0x14,
    /// Query bus information
    QueryBusInformation = 0x15,
    /// Device usage notification
    DeviceUsageNotification = 0x16,
    /// Surprise removal
    SurpriseRemoval = 0x17,
}

// ============================================================================
// Device Relations Types
// ============================================================================

/// Type of device relations query
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceRelationType {
    /// Bus devices (children)
    BusRelations = 0,
    /// Ejection relations
    EjectionRelations = 1,
    /// Power relations
    PowerRelations = 2,
    /// Removal relations
    RemovalRelations = 3,
    /// Target device relation
    TargetDeviceRelation = 4,
}

// ============================================================================
// Device ID Types
// ============================================================================

/// Type of device ID query
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BusQueryIdType {
    /// Device ID
    DeviceId = 0,
    /// Hardware IDs
    HardwareIds = 1,
    /// Compatible IDs
    CompatibleIds = 2,
    /// Instance ID
    InstanceId = 3,
    /// Device serial number
    DeviceSerialNumber = 4,
    /// Container ID
    ContainerId = 5,
}

// ============================================================================
// Device State
// ============================================================================

/// PnP device state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PnpDeviceState {
    /// Device not started
    NotStarted = 0,
    /// Device started and operational
    Started = 1,
    /// Stop pending
    StopPending = 2,
    /// Device stopped
    Stopped = 3,
    /// Remove pending
    RemovePending = 4,
    /// Surprise remove pending
    SurpriseRemovePending = 5,
    /// Device deleted
    Deleted = 6,
}

// ============================================================================
// Device Capabilities
// ============================================================================

/// Device power state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum DevicePowerState {
    /// Unspecified
    #[default]
    Unspecified = 0,
    /// D0 - Full power
    D0 = 1,
    /// D1 - Light sleep
    D1 = 2,
    /// D2 - Deep sleep
    D2 = 3,
    /// D3 - Off
    D3 = 4,
}

/// Device capabilities
#[derive(Debug, Clone, Default)]
pub struct DeviceCapabilities {
    /// Can device be locked?
    pub lock_supported: bool,
    /// Can device be ejected?
    pub eject_supported: bool,
    /// Is device removable?
    pub removable: bool,
    /// Is dock device?
    pub dock_device: bool,
    /// Unique ID?
    pub unique_id: bool,
    /// Silent install?
    pub silent_install: bool,
    /// Raw device OK?
    pub raw_device_ok: bool,
    /// Surprise removal OK?
    pub surprise_removal_ok: bool,
    /// Hardware disabled?
    pub hardware_disabled: bool,
    /// Device power states for each system power state
    pub device_state: [DevicePowerState; 7],
    /// System wake capability
    pub system_wake: u32,
    /// Device wake capability
    pub device_wake: u32,
    /// D1 latency (100ns units)
    pub d1_latency: u32,
    /// D2 latency (100ns units)
    pub d2_latency: u32,
    /// D3 latency (100ns units)
    pub d3_latency: u32,
    /// Physical device object address
    pub address: u64,
    /// UI number
    pub ui_number: u32,
}

// ============================================================================
// Resource Descriptors
// ============================================================================

/// Resource type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResourceType {
    /// Null (unused)
    Null = 0,
    /// I/O port range
    Port = 1,
    /// Interrupt
    Interrupt = 2,
    /// Memory range
    Memory = 3,
    /// DMA channel
    Dma = 4,
    /// Device specific
    DeviceSpecific = 5,
    /// Bus number
    BusNumber = 6,
    /// Memory large
    MemoryLarge = 7,
}

/// I/O port resource
#[derive(Debug, Clone, Default)]
pub struct IoPortResource {
    /// Base address
    pub base: u64,
    /// Length in bytes
    pub length: u32,
    /// Alignment
    pub alignment: u32,
}

/// Memory resource
#[derive(Debug, Clone, Default)]
pub struct MemoryResource {
    /// Base address
    pub base: u64,
    /// Length in bytes
    pub length: u64,
    /// Alignment
    pub alignment: u64,
    /// Write combined?
    pub write_combined: bool,
    /// Prefetchable?
    pub prefetchable: bool,
    /// Cacheable?
    pub cacheable: bool,
}

/// Interrupt resource
#[derive(Debug, Clone, Default)]
pub struct InterruptResource {
    /// IRQ level
    pub level: u32,
    /// IRQ vector
    pub vector: u32,
    /// Affinity mask
    pub affinity: u64,
    /// Interrupt flags
    pub flags: u32,
}

/// DMA resource
#[derive(Debug, Clone, Default)]
pub struct DmaResource {
    /// DMA channel
    pub channel: u32,
    /// DMA port
    pub port: u32,
}

/// Resource descriptor union
#[derive(Debug, Clone)]
pub enum ResourceDescriptor {
    /// I/O port
    Port(IoPortResource),
    /// Memory
    Memory(MemoryResource),
    /// Interrupt
    Interrupt(InterruptResource),
    /// DMA
    Dma(DmaResource),
}

/// Resource list
#[derive(Debug, Clone, Default)]
pub struct ResourceList {
    /// Resources assigned to device
    pub resources: Vec<ResourceDescriptor>,
}

// ============================================================================
// Device Node
// ============================================================================

/// Device node in the PnP tree
pub struct DeviceNode {
    /// Device instance ID
    pub instance_id: String,
    /// Device ID
    pub device_id: String,
    /// Hardware IDs
    pub hardware_ids: Vec<String>,
    /// Compatible IDs
    pub compatible_ids: Vec<String>,
    /// Device description
    pub description: String,
    /// Device state
    pub state: PnpDeviceState,
    /// Device capabilities
    pub capabilities: DeviceCapabilities,
    /// Assigned resources
    pub resources: ResourceList,
    /// Parent node index (None for root)
    pub parent: Option<usize>,
    /// Child node indices
    pub children: Vec<usize>,
    /// Is device problem?
    pub problem: u32,
    /// Device flags
    pub flags: u32,
}

impl DeviceNode {
    /// Create a new device node
    pub fn new(instance_id: String, device_id: String) -> Self {
        Self {
            instance_id,
            device_id,
            hardware_ids: Vec::new(),
            compatible_ids: Vec::new(),
            description: String::new(),
            state: PnpDeviceState::NotStarted,
            capabilities: DeviceCapabilities::default(),
            resources: ResourceList::default(),
            parent: None,
            children: Vec::new(),
            problem: 0,
            flags: 0,
        }
    }
}

// ============================================================================
// PnP Manager State
// ============================================================================

/// Maximum device nodes
pub const MAX_DEVICE_NODES: usize = 32;

/// Device nodes
static mut DEVICE_NODES: Option<Vec<DeviceNode>> = None;

/// Device node lock
static DEVICE_NODE_LOCK: SpinLock<()> = SpinLock::new(());

/// PnP initialized flag
static PNP_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Statistics
static DEVICES_ENUMERATED: AtomicU32 = AtomicU32::new(0);
static DEVICES_STARTED: AtomicU32 = AtomicU32::new(0);
static DEVICES_REMOVED: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// PnP Manager Functions
// ============================================================================

/// Initialize PnP manager
pub fn init() {
    crate::serial_println!("[PNP] Initializing Plug and Play manager...");

    unsafe {
        // Start with small capacity, will grow as needed
        DEVICE_NODES = Some(Vec::with_capacity(8));
    }

    // Create root device node
    let root = DeviceNode::new(
        String::from("HTREE\\ROOT\\0"),
        String::from("ROOT"),
    );

    let _guard = DEVICE_NODE_LOCK.lock();
    unsafe {
        if let Some(ref mut nodes) = DEVICE_NODES {
            nodes.push(root);
        }
    }

    PNP_INITIALIZED.store(true, Ordering::SeqCst);
    crate::serial_println!("[PNP] Plug and Play manager initialized");
}

/// Check if PnP is initialized
pub fn is_initialized() -> bool {
    PNP_INITIALIZED.load(Ordering::SeqCst)
}

/// Create a device node
pub fn create_device_node(
    instance_id: &str,
    device_id: &str,
    parent: Option<usize>,
) -> Result<usize, &'static str> {
    if !is_initialized() {
        return Err("PnP not initialized");
    }

    let _guard = DEVICE_NODE_LOCK.lock();
    unsafe {
        if let Some(ref mut nodes) = DEVICE_NODES {
            if nodes.len() >= MAX_DEVICE_NODES {
                return Err("Maximum device nodes reached");
            }

            let index = nodes.len();
            let mut node = DeviceNode::new(
                String::from(instance_id),
                String::from(device_id),
            );
            node.parent = parent;
            nodes.push(node);

            // Add to parent's children list
            if let Some(parent_idx) = parent {
                if parent_idx < nodes.len() - 1 {
                    nodes[parent_idx].children.push(index);
                }
            }

            DEVICES_ENUMERATED.fetch_add(1, Ordering::Relaxed);
            crate::serial_println!("[PNP] Created device node: {}", instance_id);
            Ok(index)
        } else {
            Err("Device nodes not initialized")
        }
    }
}

/// Start a device
pub fn start_device(index: usize) -> Result<(), &'static str> {
    let _guard = DEVICE_NODE_LOCK.lock();
    unsafe {
        if let Some(ref mut nodes) = DEVICE_NODES {
            if index >= nodes.len() {
                return Err("Invalid device node index");
            }

            let node = &mut nodes[index];
            if node.state != PnpDeviceState::NotStarted &&
               node.state != PnpDeviceState::Stopped {
                return Err("Device not in valid state to start");
            }

            node.state = PnpDeviceState::Started;
            DEVICES_STARTED.fetch_add(1, Ordering::Relaxed);
            crate::serial_println!("[PNP] Started device: {}", node.instance_id);
            Ok(())
        } else {
            Err("Device nodes not initialized")
        }
    }
}

/// Stop a device
pub fn stop_device(index: usize) -> Result<(), &'static str> {
    let _guard = DEVICE_NODE_LOCK.lock();
    unsafe {
        if let Some(ref mut nodes) = DEVICE_NODES {
            if index >= nodes.len() {
                return Err("Invalid device node index");
            }

            let node = &mut nodes[index];
            if node.state != PnpDeviceState::Started {
                return Err("Device not started");
            }

            node.state = PnpDeviceState::Stopped;
            crate::serial_println!("[PNP] Stopped device: {}", node.instance_id);
            Ok(())
        } else {
            Err("Device nodes not initialized")
        }
    }
}

/// Remove a device
pub fn remove_device(index: usize) -> Result<(), &'static str> {
    let _guard = DEVICE_NODE_LOCK.lock();
    unsafe {
        if let Some(ref mut nodes) = DEVICE_NODES {
            if index >= nodes.len() {
                return Err("Invalid device node index");
            }

            // First remove all children recursively
            let children: Vec<usize> = nodes[index].children.clone();
            drop(_guard);
            for child in children {
                remove_device(child)?;
            }

            let _guard = DEVICE_NODE_LOCK.lock();
            if let Some(ref mut nodes) = DEVICE_NODES {
                let node = &mut nodes[index];
                node.state = PnpDeviceState::Deleted;
                DEVICES_REMOVED.fetch_add(1, Ordering::Relaxed);
                crate::serial_println!("[PNP] Removed device: {}", node.instance_id);
            }
            Ok(())
        } else {
            Err("Device nodes not initialized")
        }
    }
}

/// Set device capabilities
pub fn set_device_capabilities(
    index: usize,
    capabilities: DeviceCapabilities,
) -> Result<(), &'static str> {
    let _guard = DEVICE_NODE_LOCK.lock();
    unsafe {
        if let Some(ref mut nodes) = DEVICE_NODES {
            if index >= nodes.len() {
                return Err("Invalid device node index");
            }

            nodes[index].capabilities = capabilities;
            Ok(())
        } else {
            Err("Device nodes not initialized")
        }
    }
}

/// Assign resources to a device
pub fn assign_resources(
    index: usize,
    resources: ResourceList,
) -> Result<(), &'static str> {
    let _guard = DEVICE_NODE_LOCK.lock();
    unsafe {
        if let Some(ref mut nodes) = DEVICE_NODES {
            if index >= nodes.len() {
                return Err("Invalid device node index");
            }

            nodes[index].resources = resources;
            Ok(())
        } else {
            Err("Device nodes not initialized")
        }
    }
}

/// Get device node count
pub fn device_node_count() -> usize {
    let _guard = DEVICE_NODE_LOCK.lock();
    unsafe {
        DEVICE_NODES.as_ref().map(|n| n.len()).unwrap_or(0)
    }
}

/// Get PnP statistics
pub fn get_stats() -> (u32, u32, u32) {
    (
        DEVICES_ENUMERATED.load(Ordering::Relaxed),
        DEVICES_STARTED.load(Ordering::Relaxed),
        DEVICES_REMOVED.load(Ordering::Relaxed),
    )
}

/// Device node snapshot for diagnostics
#[derive(Debug)]
pub struct DeviceNodeSnapshot {
    pub index: usize,
    pub instance_id: String,
    pub device_id: String,
    pub state: PnpDeviceState,
    pub parent: Option<usize>,
    pub child_count: usize,
}

/// Get device node snapshots
pub fn get_device_node_snapshots() -> Vec<DeviceNodeSnapshot> {
    let _guard = DEVICE_NODE_LOCK.lock();
    unsafe {
        if let Some(ref nodes) = DEVICE_NODES {
            nodes.iter().enumerate().map(|(i, node)| {
                DeviceNodeSnapshot {
                    index: i,
                    instance_id: node.instance_id.clone(),
                    device_id: node.device_id.clone(),
                    state: node.state,
                    parent: node.parent,
                    child_count: node.children.len(),
                }
            }).collect()
        } else {
            Vec::new()
        }
    }
}

/// Get device state name
pub fn device_state_name(state: PnpDeviceState) -> &'static str {
    match state {
        PnpDeviceState::NotStarted => "Not Started",
        PnpDeviceState::Started => "Started",
        PnpDeviceState::StopPending => "Stop Pending",
        PnpDeviceState::Stopped => "Stopped",
        PnpDeviceState::RemovePending => "Remove Pending",
        PnpDeviceState::SurpriseRemovePending => "Surprise Remove",
        PnpDeviceState::Deleted => "Deleted",
    }
}
