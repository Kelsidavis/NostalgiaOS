//! PnP Device Node (Devnode) Management
//!
//! Device nodes represent devices in the system device tree.

use super::{
    CmResourceList, DeviceCapabilities, DeviceInstancePath, DeviceRegistryProperty,
    PnpBusInformation, PnpError,
};
use crate::io::DeviceObject;
use crate::ke::SpinLock;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

extern crate alloc;

/// Device node state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceNodeState {
    /// Device not initialized
    #[default]
    Uninitialized = 0,
    /// Device initialized but not started
    Initialized = 1,
    /// Driver loaded
    DriverLoaded = 2,
    /// Resources assigned
    ResourcesAssigned = 3,
    /// Starting device
    Starting = 4,
    /// Device started
    Started = 5,
    /// Device stopping
    QueryStopped = 6,
    /// Device stopped
    Stopped = 7,
    /// Query for removal
    QueryRemoved = 8,
    /// Device removed
    Removed = 9,
    /// Device failed
    Failed = 10,
    /// Device disabled
    Disabled = 11,
}

/// Device node type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceNodeType {
    #[default]
    Unknown = 0,
    /// Physical device object (PDO)
    PhysicalDeviceObject = 1,
    /// Functional device object (FDO)
    FunctionalDeviceObject = 2,
    /// Filter device object
    FilterDeviceObject = 3,
    /// Root enumerator
    RootEnumerator = 4,
}

/// Device node flags
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct DeviceNodeFlags: u32 {
        /// Device is a root device
        const ROOT = 0x00000001;
        /// Device has been enumerated
        const ENUMERATED = 0x00000002;
        /// Device has resources assigned
        const RESOURCE_ASSIGNED = 0x00000004;
        /// Device is using boot resources
        const BOOT_CONFIG = 0x00000008;
        /// Device needs enumeration
        const NEEDS_ENUMERATION = 0x00000010;
        /// Device driver loaded
        const DRIVER_LOADED = 0x00000020;
        /// Device is legacy device
        const LEGACY_DRIVER = 0x00000040;
        /// Device failed start
        const FAILED_START = 0x00000080;
        /// Device is being removed
        const REMOVING = 0x00000100;
        /// Device has problem
        const HAS_PROBLEM = 0x00000200;
        /// Device is phantom (removed but not deleted)
        const PHANTOM = 0x00000400;
    }
}

/// Device problem codes
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceProblemCode {
    #[default]
    None = 0,
    NotConfigured = 1,
    DevLoader = 2,
    OutOfMemory = 3,
    Entry = 4,
    WrongType = 5,
    Lacked = 6,
    BootConfigConflict = 7,
    FilteredResourceConflict = 8,
    DevLoaderNotFound = 9,
    InvalidDevice = 10,
    FailedStart = 11,
    LackingResources = 12,
    ResourceConflict = 13,
    NotVerified = 14,
    NeedRestart = 15,
    Reenumeration = 16,
    PartialLogConf = 17,
    UnknownResourceType = 18,
    Reinstall = 19,
    VxdLoader = 20,
    Registry = 21,
    Will_Be_Removed = 22,
    Disabled = 23,
    DevLoaderNotReady = 24,
    DeviceNotThere = 25,
    Moved = 26,
    TooEarly = 27,
    NoValidLogConf = 28,
    FailedInstall = 29,
    HardwareDisabled = 30,
    CantShareIrq = 31,
    FailedAdd = 32,
    DisabledService = 33,
    TranslationFailed = 34,
    NoSoftConfig = 35,
    BiosTable = 36,
    IrqTranslationFailed = 37,
    FailedDriverEntry = 38,
    DriverFailedPriorUnload = 39,
    DriverFailedLoad = 40,
    DriverServiceKeyInvalid = 41,
    LegacyServiceNoDevices = 42,
    DuplicateDevice = 43,
    FailedPostStart = 44,
    Halted = 45,
    Phantom = 46,
    SystemShutdown = 47,
    HeldForEject = 48,
    DriverBlocked = 49,
    RegistryTooLarge = 50,
    SetPropertiesFailed = 51,
}

/// Device node - represents a device in the device tree
pub struct DeviceNode {
    /// Device instance path
    instance_path: DeviceInstancePath,
    /// Device node type
    node_type: DeviceNodeType,
    /// Current state
    state: AtomicU32,
    /// Flags
    flags: AtomicU32,
    /// Problem code
    problem: AtomicU32,
    /// Parent device node (weak reference to avoid cycles)
    parent: SpinLock<Option<*const DeviceNode>>,
    /// Child device nodes
    children: SpinLock<Vec<Arc<DeviceNode>>>,
    /// Physical device object
    pdo: SpinLock<Option<*mut DeviceObject>>,
    /// Service name (driver)
    service: SpinLock<Option<String>>,
    /// Bus information
    bus_info: SpinLock<PnpBusInformation>,
    /// Boot resources
    boot_resources: SpinLock<Option<CmResourceList>>,
    /// Allocated resources
    allocated_resources: SpinLock<Option<CmResourceList>>,
    /// Device capabilities
    capabilities: SpinLock<DeviceCapabilities>,
    /// Device description
    description: SpinLock<Option<String>>,
    /// Hardware IDs
    hardware_ids: SpinLock<Vec<String>>,
    /// Compatible IDs
    compatible_ids: SpinLock<Vec<String>>,
    /// Location information
    location_info: SpinLock<Option<String>>,
}

impl DeviceNode {
    /// Create a new device node
    pub fn new(instance_path: DeviceInstancePath, node_type: DeviceNodeType) -> Self {
        Self {
            instance_path,
            node_type,
            state: AtomicU32::new(DeviceNodeState::Uninitialized as u32),
            flags: AtomicU32::new(0),
            problem: AtomicU32::new(DeviceProblemCode::None as u32),
            parent: SpinLock::new(None),
            children: SpinLock::new(Vec::new()),
            pdo: SpinLock::new(None),
            service: SpinLock::new(None),
            bus_info: SpinLock::new(PnpBusInformation::default()),
            boot_resources: SpinLock::new(None),
            allocated_resources: SpinLock::new(None),
            capabilities: SpinLock::new(DeviceCapabilities::new()),
            description: SpinLock::new(None),
            hardware_ids: SpinLock::new(Vec::new()),
            compatible_ids: SpinLock::new(Vec::new()),
            location_info: SpinLock::new(None),
        }
    }

    /// Create root device node
    pub fn new_root() -> Self {
        let node = Self::new(DeviceInstancePath::root(), DeviceNodeType::RootEnumerator);
        node.flags
            .store(DeviceNodeFlags::ROOT.bits(), Ordering::SeqCst);
        node.state
            .store(DeviceNodeState::Started as u32, Ordering::SeqCst);
        node
    }

    /// Get instance path
    pub fn instance_path(&self) -> &DeviceInstancePath {
        &self.instance_path
    }

    /// Get node type
    pub fn node_type(&self) -> DeviceNodeType {
        self.node_type
    }

    /// Get current state
    pub fn state(&self) -> DeviceNodeState {
        match self.state.load(Ordering::SeqCst) {
            0 => DeviceNodeState::Uninitialized,
            1 => DeviceNodeState::Initialized,
            2 => DeviceNodeState::DriverLoaded,
            3 => DeviceNodeState::ResourcesAssigned,
            4 => DeviceNodeState::Starting,
            5 => DeviceNodeState::Started,
            6 => DeviceNodeState::QueryStopped,
            7 => DeviceNodeState::Stopped,
            8 => DeviceNodeState::QueryRemoved,
            9 => DeviceNodeState::Removed,
            10 => DeviceNodeState::Failed,
            11 => DeviceNodeState::Disabled,
            _ => DeviceNodeState::Uninitialized,
        }
    }

    /// Set device state
    pub fn set_state(&self, state: DeviceNodeState) {
        self.state.store(state as u32, Ordering::SeqCst);
    }

    /// Get flags
    pub fn flags(&self) -> DeviceNodeFlags {
        DeviceNodeFlags::from_bits_truncate(self.flags.load(Ordering::SeqCst))
    }

    /// Set flags
    pub fn set_flags(&self, flags: DeviceNodeFlags) {
        self.flags.store(flags.bits(), Ordering::SeqCst);
    }

    /// Add flags
    pub fn add_flags(&self, flags: DeviceNodeFlags) {
        let old = self.flags.load(Ordering::SeqCst);
        self.flags.store(old | flags.bits(), Ordering::SeqCst);
    }

    /// Remove flags
    pub fn remove_flags(&self, flags: DeviceNodeFlags) {
        let old = self.flags.load(Ordering::SeqCst);
        self.flags.store(old & !flags.bits(), Ordering::SeqCst);
    }

    /// Get problem code
    pub fn problem(&self) -> DeviceProblemCode {
        match self.problem.load(Ordering::SeqCst) {
            0 => DeviceProblemCode::None,
            11 => DeviceProblemCode::FailedStart,
            12 => DeviceProblemCode::LackingResources,
            13 => DeviceProblemCode::ResourceConflict,
            23 => DeviceProblemCode::Disabled,
            _ => DeviceProblemCode::None,
        }
    }

    /// Set problem code
    pub fn set_problem(&self, problem: DeviceProblemCode) {
        self.problem.store(problem as u32, Ordering::SeqCst);
        if problem != DeviceProblemCode::None {
            self.add_flags(DeviceNodeFlags::HAS_PROBLEM);
        } else {
            self.remove_flags(DeviceNodeFlags::HAS_PROBLEM);
        }
    }

    /// Add a child device node
    pub fn add_child(&self, child: Arc<DeviceNode>) {
        // Set parent
        {
            let mut parent = child.parent.lock();
            *parent = Some(self as *const DeviceNode);
        }

        // Add to children
        let mut children = self.children.lock();
        children.push(child);
    }

    /// Remove a child device node
    pub fn remove_child(&self, child: &Arc<DeviceNode>) {
        let mut children = self.children.lock();
        children.retain(|c| !Arc::ptr_eq(c, child));
    }

    /// Get children
    pub fn children(&self) -> Vec<Arc<DeviceNode>> {
        self.children.lock().clone()
    }

    /// Check if this node matches a device object
    pub fn matches_device(&self, device: &DeviceObject) -> bool {
        let pdo = self.pdo.lock();
        if let Some(p) = *pdo {
            core::ptr::eq(p, device as *const DeviceObject as *mut DeviceObject)
        } else {
            false
        }
    }

    /// Set physical device object
    pub fn set_pdo(&self, pdo: *mut DeviceObject) {
        let mut p = self.pdo.lock();
        *p = Some(pdo);
    }

    /// Set service name
    pub fn set_service(&self, service: String) {
        let mut s = self.service.lock();
        *s = Some(service);
    }

    /// Set bus information
    pub fn set_bus_info(&self, info: PnpBusInformation) {
        let mut bus = self.bus_info.lock();
        *bus = info;
    }

    /// Set boot resources
    pub fn set_boot_resources(&self, resources: CmResourceList) {
        let mut boot = self.boot_resources.lock();
        *boot = Some(resources);
        self.add_flags(DeviceNodeFlags::BOOT_CONFIG);
    }

    /// Set allocated resources
    pub fn set_allocated_resources(&self, resources: CmResourceList) {
        let mut alloc = self.allocated_resources.lock();
        *alloc = Some(resources);
        self.add_flags(DeviceNodeFlags::RESOURCE_ASSIGNED);
    }

    /// Set device description
    pub fn set_description(&self, desc: String) {
        let mut d = self.description.lock();
        *d = Some(desc);
    }

    /// Add hardware ID
    pub fn add_hardware_id(&self, id: String) {
        let mut ids = self.hardware_ids.lock();
        ids.push(id);
    }

    /// Add compatible ID
    pub fn add_compatible_id(&self, id: String) {
        let mut ids = self.compatible_ids.lock();
        ids.push(id);
    }

    /// Set location information
    pub fn set_location_info(&self, location: String) {
        let mut loc = self.location_info.lock();
        *loc = Some(location);
    }

    /// Request device eject
    pub fn request_eject(&self) {
        // Mark device for removal
        self.add_flags(DeviceNodeFlags::REMOVING);
        self.set_state(DeviceNodeState::QueryRemoved);
    }

    /// Get device property
    pub fn get_property(
        &self,
        property: DeviceRegistryProperty,
        buffer: &mut [u8],
    ) -> Result<usize, PnpError> {
        match property {
            DeviceRegistryProperty::DeviceDescription => {
                let desc = self.description.lock();
                if let Some(ref d) = *desc {
                    let bytes = d.as_bytes();
                    let len = bytes.len().min(buffer.len());
                    buffer[..len].copy_from_slice(&bytes[..len]);
                    Ok(len)
                } else {
                    Ok(0)
                }
            }
            DeviceRegistryProperty::HardwareId => {
                let ids = self.hardware_ids.lock();
                if let Some(first) = ids.first() {
                    let bytes = first.as_bytes();
                    let len = bytes.len().min(buffer.len());
                    buffer[..len].copy_from_slice(&bytes[..len]);
                    Ok(len)
                } else {
                    Ok(0)
                }
            }
            DeviceRegistryProperty::CompatibleIds => {
                let ids = self.compatible_ids.lock();
                if let Some(first) = ids.first() {
                    let bytes = first.as_bytes();
                    let len = bytes.len().min(buffer.len());
                    buffer[..len].copy_from_slice(&bytes[..len]);
                    Ok(len)
                } else {
                    Ok(0)
                }
            }
            DeviceRegistryProperty::LocationInformation => {
                let loc = self.location_info.lock();
                if let Some(ref l) = *loc {
                    let bytes = l.as_bytes();
                    let len = bytes.len().min(buffer.len());
                    buffer[..len].copy_from_slice(&bytes[..len]);
                    Ok(len)
                } else {
                    Ok(0)
                }
            }
            DeviceRegistryProperty::BusNumber => {
                let info = self.bus_info.lock();
                if buffer.len() >= 4 {
                    buffer[..4].copy_from_slice(&info.bus_number.to_le_bytes());
                    Ok(4)
                } else {
                    Err(PnpError::InvalidParameter)
                }
            }
            DeviceRegistryProperty::LegacyBusType => {
                let info = self.bus_info.lock();
                if buffer.len() >= 4 {
                    buffer[..4].copy_from_slice(&(info.legacy_bus_type as u32).to_le_bytes());
                    Ok(4)
                } else {
                    Err(PnpError::InvalidParameter)
                }
            }
            _ => Err(PnpError::NotSupported),
        }
    }

    /// Get device capabilities
    pub fn get_capabilities(&self) -> DeviceCapabilities {
        *self.capabilities.lock()
    }

    /// Set device capabilities
    pub fn set_capabilities(&self, caps: DeviceCapabilities) {
        *self.capabilities.lock() = caps;
    }
}

impl core::fmt::Debug for DeviceNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceNode")
            .field("instance_path", &self.instance_path)
            .field("node_type", &self.node_type)
            .field("state", &self.state())
            .field("flags", &self.flags())
            .field("problem", &self.problem())
            .finish()
    }
}

// Safety: DeviceNode uses internal synchronization
unsafe impl Send for DeviceNode {}
unsafe impl Sync for DeviceNode {}
