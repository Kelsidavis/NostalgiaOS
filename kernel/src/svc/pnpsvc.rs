//! Plug and Play Service (PlugPlay)
//!
//! The Plug and Play service manages device detection, driver installation,
//! and hardware resource allocation. It works with the kernel PnP manager
//! to enumerate devices and load appropriate drivers.
//!
//! # Features
//!
//! - **Device Enumeration**: Detect hardware devices at boot and runtime
//! - **Driver Installation**: Install and configure device drivers
//! - **Resource Allocation**: Manage I/O ports, IRQs, DMA, memory
//! - **Device Tree**: Maintain hierarchical device relationships
//! - **Hot Plug**: Handle device arrival and removal at runtime
//!
//! # Device States
//!
//! - Unknown: Device detected but not identified
//! - Stopped: Device identified but driver not started
//! - Started: Device and driver operational
//! - Disabled: Device disabled by user/policy
//! - Problem: Device has configuration problem
//!
//! # Device Nodes
//!
//! Each device is represented by a device node (devnode) containing:
//! - Device instance ID
//! - Hardware IDs
//! - Compatible IDs
//! - Driver information
//! - Resource requirements/assignments

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum device nodes
const MAX_DEVNODES: usize = 128;

/// Maximum pending installations
const MAX_PENDING: usize = 32;

/// Maximum device ID length
const MAX_DEVICE_ID: usize = 128;

/// Maximum hardware ID length
const MAX_HWID: usize = 128;

/// Maximum driver name length
const MAX_DRIVER: usize = 64;

/// Maximum class name length
const MAX_CLASS: usize = 64;

/// Maximum hardware IDs per device
const MAX_HWIDS: usize = 8;

/// Device status flags
pub mod device_status {
    pub const DN_ROOT_ENUMERATED: u32 = 0x00000001;
    pub const DN_DRIVER_LOADED: u32 = 0x00000002;
    pub const DN_ENUM_LOADED: u32 = 0x00000004;
    pub const DN_STARTED: u32 = 0x00000008;
    pub const DN_MANUAL: u32 = 0x00000010;
    pub const DN_NEED_TO_ENUM: u32 = 0x00000020;
    pub const DN_NOT_FIRST_TIME: u32 = 0x00000040;
    pub const DN_HARDWARE_ENUM: u32 = 0x00000080;
    pub const DN_LIAR: u32 = 0x00000100;
    pub const DN_HAS_MARK: u32 = 0x00000200;
    pub const DN_HAS_PROBLEM: u32 = 0x00000400;
    pub const DN_FILTERED: u32 = 0x00000800;
    pub const DN_DISABLEABLE: u32 = 0x00001000;
    pub const DN_REMOVABLE: u32 = 0x00002000;
    pub const DN_PRIVATE_PROBLEM: u32 = 0x00004000;
    pub const DN_NEED_RESTART: u32 = 0x00000100;
    pub const DN_DEVICE_DISCONNECTED: u32 = 0x02000000;
}

/// Device problem codes
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProblemCode {
    /// No problem
    None = 0,
    /// Configuration problem
    ConfigError = 1,
    /// No driver
    NeedsDriver = 3,
    /// Driver failed
    FailedStart = 10,
    /// Device failed
    FailedAdd = 12,
    /// Service failed
    FailedService = 14,
    /// Resource conflict
    ResourceConflict = 18,
    /// Device disabled
    Disabled = 22,
    /// Device not present
    NotPresent = 24,
    /// Phantom device
    Phantom = 45,
}

impl ProblemCode {
    const fn empty() -> Self {
        ProblemCode::None
    }
}

/// Device type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceNodeType {
    /// Root device
    Root = 0,
    /// Bus device
    Bus = 1,
    /// Controller
    Controller = 2,
    /// Peripheral
    Peripheral = 3,
    /// Function device
    Function = 4,
}

impl DeviceNodeType {
    const fn empty() -> Self {
        DeviceNodeType::Peripheral
    }
}

/// Resource type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    /// Memory range
    Memory = 0,
    /// I/O port range
    IoPort = 1,
    /// IRQ
    Irq = 2,
    /// DMA channel
    Dma = 3,
    /// Bus number
    BusNumber = 4,
}

/// Resource assignment
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ResourceAssignment {
    /// Resource type
    pub res_type: ResourceType,
    /// Start address/value
    pub start: u64,
    /// Length/count
    pub length: u64,
    /// Flags
    pub flags: u32,
    /// Valid
    pub valid: bool,
}

impl ResourceAssignment {
    const fn empty() -> Self {
        ResourceAssignment {
            res_type: ResourceType::Memory,
            start: 0,
            length: 0,
            flags: 0,
            valid: false,
        }
    }
}

/// Device node
#[repr(C)]
#[derive(Clone)]
pub struct DeviceNode {
    /// Device instance ID
    pub instance_id: [u8; MAX_DEVICE_ID],
    /// Hardware IDs
    pub hardware_ids: [[u8; MAX_HWID]; MAX_HWIDS],
    /// Hardware ID count
    pub hwid_count: usize,
    /// Device description
    pub description: [u8; MAX_DRIVER],
    /// Driver name
    pub driver: [u8; MAX_DRIVER],
    /// Device class
    pub device_class: [u8; MAX_CLASS],
    /// Class GUID
    pub class_guid: [u8; 16],
    /// Node type
    pub node_type: DeviceNodeType,
    /// Parent node index
    pub parent: Option<usize>,
    /// Status flags
    pub status: u32,
    /// Problem code
    pub problem: ProblemCode,
    /// Resource assignments
    pub resources: [ResourceAssignment; 4],
    /// Resource count
    pub resource_count: usize,
    /// Enumeration time
    pub enum_time: i64,
    /// Entry is valid
    pub valid: bool,
}

impl DeviceNode {
    const fn empty() -> Self {
        DeviceNode {
            instance_id: [0; MAX_DEVICE_ID],
            hardware_ids: [[0; MAX_HWID]; MAX_HWIDS],
            hwid_count: 0,
            description: [0; MAX_DRIVER],
            driver: [0; MAX_DRIVER],
            device_class: [0; MAX_CLASS],
            class_guid: [0; 16],
            node_type: DeviceNodeType::empty(),
            parent: None,
            status: 0,
            problem: ProblemCode::empty(),
            resources: [const { ResourceAssignment::empty() }; 4],
            resource_count: 0,
            enum_time: 0,
            valid: false,
        }
    }
}

/// Pending installation
#[repr(C)]
#[derive(Clone)]
pub struct PendingInstall {
    /// Device node index
    pub devnode_idx: usize,
    /// Status
    pub status: InstallStatus,
    /// Driver path (if known)
    pub driver_path: [u8; MAX_DRIVER],
    /// Request time
    pub request_time: i64,
    /// Entry is valid
    pub valid: bool,
}

impl PendingInstall {
    const fn empty() -> Self {
        PendingInstall {
            devnode_idx: 0,
            status: InstallStatus::Pending,
            driver_path: [0; MAX_DRIVER],
            request_time: 0,
            valid: false,
        }
    }
}

/// Installation status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallStatus {
    /// Pending installation
    Pending = 0,
    /// Searching for driver
    Searching = 1,
    /// Installing driver
    Installing = 2,
    /// Installation complete
    Complete = 3,
    /// No driver found
    NoDriver = 4,
    /// Installation failed
    Failed = 5,
}

/// Plug and Play service state
pub struct PnpState {
    /// Service is running
    pub running: bool,
    /// Device nodes
    pub devnodes: [DeviceNode; MAX_DEVNODES],
    /// Device node count
    pub devnode_count: usize,
    /// Pending installations
    pub pending: [PendingInstall; MAX_PENDING],
    /// Pending count
    pub pending_count: usize,
    /// Root devnode index
    pub root_devnode: usize,
    /// Service start time
    pub start_time: i64,
    /// Enumeration in progress
    pub enumerating: bool,
}

impl PnpState {
    const fn new() -> Self {
        PnpState {
            running: false,
            devnodes: [const { DeviceNode::empty() }; MAX_DEVNODES],
            devnode_count: 0,
            pending: [const { PendingInstall::empty() }; MAX_PENDING],
            pending_count: 0,
            root_devnode: 0,
            start_time: 0,
            enumerating: false,
        }
    }
}

/// Global state
static PNP_STATE: Mutex<PnpState> = Mutex::new(PnpState::new());

/// Statistics
static DEVICES_ENUMERATED: AtomicU64 = AtomicU64::new(0);
static DRIVERS_INSTALLED: AtomicU64 = AtomicU64::new(0);
static DRIVER_FAILURES: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize Plug and Play service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = PNP_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    // Create root device node
    create_root_devnode(&mut state);

    crate::serial_println!("[PNPSVC] Plug and Play service initialized");
}

/// Create root device node
fn create_root_devnode(state: &mut PnpState) {
    let root = &mut state.devnodes[0];

    let instance_id = b"HTREE\\ROOT\\0";
    root.instance_id[..instance_id.len()].copy_from_slice(instance_id);

    let desc = b"Root Device";
    root.description[..desc.len()].copy_from_slice(desc);

    root.node_type = DeviceNodeType::Root;
    root.parent = None;
    root.status = device_status::DN_ROOT_ENUMERATED | device_status::DN_STARTED;
    root.problem = ProblemCode::None;
    root.enum_time = crate::rtl::time::rtl_get_system_time();
    root.valid = true;

    state.root_devnode = 0;
    state.devnode_count = 1;

    DEVICES_ENUMERATED.fetch_add(1, Ordering::SeqCst);
}

/// Enumerate a device
pub fn enumerate_device(
    instance_id: &[u8],
    hardware_ids: &[&[u8]],
    description: &[u8],
    parent: Option<usize>,
    node_type: DeviceNodeType,
) -> Result<usize, u32> {
    let mut state = PNP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Check if device already exists
    let inst_len = instance_id.len().min(MAX_DEVICE_ID);
    for (idx, node) in state.devnodes.iter().enumerate() {
        if node.valid && node.instance_id[..inst_len] == instance_id[..inst_len] {
            return Ok(idx);
        }
    }

    // Find free slot
    let slot = state.devnodes.iter().position(|n| !n.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let now = crate::rtl::time::rtl_get_system_time();

    let node = &mut state.devnodes[slot];
    node.instance_id[..inst_len].copy_from_slice(&instance_id[..inst_len]);

    // Copy hardware IDs
    let hwid_count = hardware_ids.len().min(MAX_HWIDS);
    for (i, hwid) in hardware_ids.iter().take(hwid_count).enumerate() {
        let len = hwid.len().min(MAX_HWID);
        node.hardware_ids[i][..len].copy_from_slice(&hwid[..len]);
    }
    node.hwid_count = hwid_count;

    let desc_len = description.len().min(MAX_DRIVER);
    node.description[..desc_len].copy_from_slice(&description[..desc_len]);

    node.node_type = node_type;
    node.parent = parent;
    node.status = device_status::DN_HARDWARE_ENUM;
    node.problem = ProblemCode::NeedsDriver;
    node.enum_time = now;
    node.valid = true;

    state.devnode_count += 1;
    DEVICES_ENUMERATED.fetch_add(1, Ordering::SeqCst);

    // Queue for driver installation
    drop(state);
    queue_driver_install(slot);

    Ok(slot)
}

/// Queue a device for driver installation
fn queue_driver_install(devnode_idx: usize) {
    let mut state = PNP_STATE.lock();

    if !state.running {
        return;
    }

    let slot = state.pending.iter().position(|p| !p.valid);
    let slot = match slot {
        Some(s) => s,
        None => return,
    };

    let pending = &mut state.pending[slot];
    pending.devnode_idx = devnode_idx;
    pending.status = InstallStatus::Pending;
    pending.request_time = crate::rtl::time::rtl_get_system_time();
    pending.valid = true;

    state.pending_count += 1;
}

/// Process pending installations
pub fn process_pending_installs() {
    let mut state = PNP_STATE.lock();

    if !state.running {
        return;
    }

    for i in 0..MAX_PENDING {
        if !state.pending[i].valid {
            continue;
        }

        if state.pending[i].status != InstallStatus::Pending {
            continue;
        }

        state.pending[i].status = InstallStatus::Searching;

        // Simulate driver search
        // In real implementation, would search driver store

        let devnode_idx = state.pending[i].devnode_idx;
        if devnode_idx < MAX_DEVNODES && state.devnodes[devnode_idx].valid {
            // Simulate successful driver installation
            state.pending[i].status = InstallStatus::Complete;

            state.devnodes[devnode_idx].status |= device_status::DN_DRIVER_LOADED | device_status::DN_STARTED;
            state.devnodes[devnode_idx].status &= !device_status::DN_HAS_PROBLEM;
            state.devnodes[devnode_idx].problem = ProblemCode::None;

            let driver_name = b"generic.sys";
            state.devnodes[devnode_idx].driver[..driver_name.len()].copy_from_slice(driver_name);

            DRIVERS_INSTALLED.fetch_add(1, Ordering::SeqCst);
        } else {
            state.pending[i].status = InstallStatus::Failed;
            DRIVER_FAILURES.fetch_add(1, Ordering::SeqCst);
        }
    }

    // Clean up completed installations
    let mut cleaned = 0usize;
    for pending in state.pending.iter_mut() {
        if pending.valid {
            let is_done = matches!(
                pending.status,
                InstallStatus::Complete | InstallStatus::NoDriver | InstallStatus::Failed
            );
            if is_done {
                pending.valid = false;
                cleaned += 1;
            }
        }
    }
    state.pending_count = state.pending_count.saturating_sub(cleaned);
}

/// Start a device
pub fn start_device(devnode_idx: usize) -> Result<(), u32> {
    let mut state = PNP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    if devnode_idx >= MAX_DEVNODES || !state.devnodes[devnode_idx].valid {
        return Err(0x80070057);
    }

    let node = &mut state.devnodes[devnode_idx];

    // Check if driver is loaded
    if (node.status & device_status::DN_DRIVER_LOADED) == 0 {
        return Err(0x8007001F); // ERROR_GEN_FAILURE
    }

    node.status |= device_status::DN_STARTED;
    node.status &= !device_status::DN_HAS_PROBLEM;
    node.problem = ProblemCode::None;

    Ok(())
}

/// Stop a device
pub fn stop_device(devnode_idx: usize) -> Result<(), u32> {
    let mut state = PNP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    if devnode_idx >= MAX_DEVNODES || !state.devnodes[devnode_idx].valid {
        return Err(0x80070057);
    }

    state.devnodes[devnode_idx].status &= !device_status::DN_STARTED;

    Ok(())
}

/// Disable a device
pub fn disable_device(devnode_idx: usize) -> Result<(), u32> {
    let mut state = PNP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    if devnode_idx >= MAX_DEVNODES || !state.devnodes[devnode_idx].valid {
        return Err(0x80070057);
    }

    let node = &mut state.devnodes[devnode_idx];
    node.status &= !device_status::DN_STARTED;
    node.status |= device_status::DN_HAS_PROBLEM;
    node.problem = ProblemCode::Disabled;

    Ok(())
}

/// Enable a device
pub fn enable_device(devnode_idx: usize) -> Result<(), u32> {
    let mut state = PNP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    if devnode_idx >= MAX_DEVNODES || !state.devnodes[devnode_idx].valid {
        return Err(0x80070057);
    }

    let node = &mut state.devnodes[devnode_idx];

    if node.problem == ProblemCode::Disabled {
        node.problem = ProblemCode::None;
        node.status &= !device_status::DN_HAS_PROBLEM;

        if (node.status & device_status::DN_DRIVER_LOADED) != 0 {
            node.status |= device_status::DN_STARTED;
        }
    }

    Ok(())
}

/// Remove a device
pub fn remove_device(devnode_idx: usize) -> Result<(), u32> {
    let mut state = PNP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    if devnode_idx >= MAX_DEVNODES || !state.devnodes[devnode_idx].valid {
        return Err(0x80070057);
    }

    // Can't remove root
    if devnode_idx == state.root_devnode {
        return Err(0x80070005); // ACCESS_DENIED
    }

    state.devnodes[devnode_idx].valid = false;
    state.devnode_count = state.devnode_count.saturating_sub(1);

    Ok(())
}

/// Get device node by instance ID
pub fn get_device_by_id(instance_id: &[u8]) -> Option<usize> {
    let state = PNP_STATE.lock();
    let inst_len = instance_id.len().min(MAX_DEVICE_ID);

    state.devnodes.iter().enumerate()
        .find(|(_, n)| n.valid && n.instance_id[..inst_len] == instance_id[..inst_len])
        .map(|(idx, _)| idx)
}

/// Get device node
pub fn get_device_node(devnode_idx: usize) -> Option<DeviceNode> {
    let state = PNP_STATE.lock();

    if devnode_idx < MAX_DEVNODES && state.devnodes[devnode_idx].valid {
        Some(state.devnodes[devnode_idx].clone())
    } else {
        None
    }
}

/// Enumerate all devices
pub fn enum_devices() -> ([DeviceNode; MAX_DEVNODES], usize) {
    let state = PNP_STATE.lock();
    let mut result = [const { DeviceNode::empty() }; MAX_DEVNODES];
    let mut count = 0;

    for node in state.devnodes.iter() {
        if node.valid && count < MAX_DEVNODES {
            result[count] = node.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get children of a device
pub fn get_children(parent_idx: usize) -> ([usize; MAX_DEVNODES], usize) {
    let state = PNP_STATE.lock();
    let mut children = [0usize; MAX_DEVNODES];
    let mut count = 0;

    for (idx, node) in state.devnodes.iter().enumerate() {
        if node.valid && node.parent == Some(parent_idx) && count < MAX_DEVNODES {
            children[count] = idx;
            count += 1;
        }
    }

    (children, count)
}

/// Assign resource to device
pub fn assign_resource(
    devnode_idx: usize,
    res_type: ResourceType,
    start: u64,
    length: u64,
) -> Result<(), u32> {
    let mut state = PNP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    if devnode_idx >= MAX_DEVNODES || !state.devnodes[devnode_idx].valid {
        return Err(0x80070057);
    }

    let node = &mut state.devnodes[devnode_idx];

    if node.resource_count >= 4 {
        return Err(0x8007000E);
    }

    let res_idx = node.resource_count;
    node.resources[res_idx].res_type = res_type;
    node.resources[res_idx].start = start;
    node.resources[res_idx].length = length;
    node.resources[res_idx].valid = true;
    node.resource_count += 1;

    Ok(())
}

/// Get pending installation count
pub fn get_pending_count() -> usize {
    let state = PNP_STATE.lock();
    state.pending_count
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64) {
    (
        DEVICES_ENUMERATED.load(Ordering::SeqCst),
        DRIVERS_INSTALLED.load(Ordering::SeqCst),
        DRIVER_FAILURES.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = PNP_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = PNP_STATE.lock();
    state.running = false;

    // Clear pending installations
    for pending in state.pending.iter_mut() {
        pending.valid = false;
    }
    state.pending_count = 0;

    crate::serial_println!("[PNPSVC] Plug and Play service stopped");
}
