//! Device Manager
//!
//! Implements the Device Manager dialog following Windows Server 2003.
//! Provides device enumeration, properties, driver management, and resource viewing.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - devmgr.dll - Device Manager
//! - setupapi.dll - Device installation API
//! - cfgmgr32.dll - Configuration Manager

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum devices
const MAX_DEVICES: usize = 256;

/// Maximum device name length
const MAX_NAME: usize = 128;

/// Maximum device ID length
const MAX_DEVICE_ID: usize = 200;

/// Maximum driver name length
const MAX_DRIVER: usize = 64;

/// Maximum resource entries per device
const MAX_RESOURCES: usize = 8;

// ============================================================================
// Device Status
// ============================================================================

/// Device status codes
pub mod device_status {
    /// Device is working properly
    pub const OK: u32 = 0;
    /// Device is not configured correctly
    pub const CONFIG_ERROR: u32 = 1;
    /// Driver for device could not be loaded
    pub const DRIVER_LOAD_ERROR: u32 = 2;
    /// Driver is corrupted or missing
    pub const DRIVER_CORRUPTED: u32 = 3;
    /// Device is not working properly
    pub const NOT_WORKING: u32 = 4;
    /// Device driver needs to be reinstalled
    pub const NEED_REINSTALL: u32 = 5;
    /// Device is disabled
    pub const DISABLED: u32 = 6;
    /// Device has a resource conflict
    pub const RESOURCE_CONFLICT: u32 = 7;
    /// Device not present
    pub const NOT_PRESENT: u32 = 8;
    /// Device failed to start
    pub const FAILED_START: u32 = 9;
    /// Device has a problem (code in problem field)
    pub const HAS_PROBLEM: u32 = 10;
}

// ============================================================================
// Device Type
// ============================================================================

/// Device class type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceClass {
    /// Computer (root)
    #[default]
    Computer = 0,
    /// Disk drives
    DiskDrive = 1,
    /// Display adapters
    Display = 2,
    /// DVD/CD-ROM drives
    CdRom = 3,
    /// Floppy disk controllers
    FloppyController = 4,
    /// Floppy disk drives
    FloppyDrive = 5,
    /// IDE ATA/ATAPI controllers
    IdeController = 6,
    /// Keyboards
    Keyboard = 7,
    /// Mice and other pointing devices
    Mouse = 8,
    /// Monitors
    Monitor = 9,
    /// Network adapters
    Network = 10,
    /// Ports (COM & LPT)
    Ports = 11,
    /// Processors
    Processor = 12,
    /// SCSI and RAID controllers
    ScsiController = 13,
    /// Sound, video and game controllers
    Multimedia = 14,
    /// System devices
    System = 15,
    /// USB controllers
    UsbController = 16,
    /// USB devices
    UsbDevice = 17,
    /// Human Interface Devices
    Hid = 18,
    /// Storage volumes
    Volume = 19,
    /// Battery
    Battery = 20,
    /// PCMCIA adapters
    Pcmcia = 21,
    /// Printers
    Printer = 22,
    /// Imaging devices
    Image = 23,
    /// Smart card readers
    SmartCard = 24,
    /// Other devices
    Other = 255,
}

impl DeviceClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceClass::Computer => "Computer",
            DeviceClass::DiskDrive => "Disk drives",
            DeviceClass::Display => "Display adapters",
            DeviceClass::CdRom => "DVD/CD-ROM drives",
            DeviceClass::FloppyController => "Floppy disk controllers",
            DeviceClass::FloppyDrive => "Floppy disk drives",
            DeviceClass::IdeController => "IDE ATA/ATAPI controllers",
            DeviceClass::Keyboard => "Keyboards",
            DeviceClass::Mouse => "Mice and other pointing devices",
            DeviceClass::Monitor => "Monitors",
            DeviceClass::Network => "Network adapters",
            DeviceClass::Ports => "Ports (COM & LPT)",
            DeviceClass::Processor => "Processors",
            DeviceClass::ScsiController => "SCSI and RAID controllers",
            DeviceClass::Multimedia => "Sound, video and game controllers",
            DeviceClass::System => "System devices",
            DeviceClass::UsbController => "USB controllers",
            DeviceClass::UsbDevice => "USB devices",
            DeviceClass::Hid => "Human Interface Devices",
            DeviceClass::Volume => "Storage volumes",
            DeviceClass::Battery => "Batteries",
            DeviceClass::Pcmcia => "PCMCIA adapters",
            DeviceClass::Printer => "Printers",
            DeviceClass::Image => "Imaging devices",
            DeviceClass::SmartCard => "Smart card readers",
            DeviceClass::Other => "Other devices",
        }
    }
}

// ============================================================================
// Resource Type
// ============================================================================

/// Hardware resource type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResourceType {
    /// No resource
    #[default]
    None = 0,
    /// Memory range
    Memory = 1,
    /// I/O port range
    IoPort = 2,
    /// IRQ (interrupt request)
    Irq = 3,
    /// DMA channel
    Dma = 4,
    /// Bus number
    BusNumber = 5,
}

// ============================================================================
// Device Resource
// ============================================================================

/// Hardware resource entry
#[derive(Debug, Clone, Copy)]
pub struct DeviceResource {
    /// Resource type
    pub resource_type: ResourceType,
    /// Start address/value
    pub start: u64,
    /// End address/value
    pub end: u64,
    /// Flags
    pub flags: u32,
}

impl DeviceResource {
    pub const fn new() -> Self {
        Self {
            resource_type: ResourceType::None,
            start: 0,
            end: 0,
            flags: 0,
        }
    }
}

impl Default for DeviceResource {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Device Entry
// ============================================================================

/// Device entry
#[derive(Debug, Clone, Copy)]
pub struct DeviceEntry {
    /// Device name (friendly name)
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Device ID (hardware ID)
    pub device_id: [u8; MAX_DEVICE_ID],
    /// Device ID length
    pub device_id_len: usize,
    /// Device class
    pub device_class: DeviceClass,
    /// Device status
    pub status: u32,
    /// Problem code (if status indicates problem)
    pub problem_code: u32,
    /// Driver name
    pub driver: [u8; MAX_DRIVER],
    /// Driver name length
    pub driver_len: usize,
    /// Driver version
    pub driver_version: [u8; 32],
    /// Driver version length
    pub driver_version_len: usize,
    /// Manufacturer
    pub manufacturer: [u8; MAX_NAME],
    /// Manufacturer length
    pub manufacturer_len: usize,
    /// Device is enabled
    pub enabled: bool,
    /// Device is hidden
    pub hidden: bool,
    /// Resources
    pub resources: [DeviceResource; MAX_RESOURCES],
    /// Resource count
    pub resource_count: usize,
    /// Parent device index (-1 for root)
    pub parent: i32,
}

impl DeviceEntry {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME],
            name_len: 0,
            device_id: [0u8; MAX_DEVICE_ID],
            device_id_len: 0,
            device_class: DeviceClass::Other,
            status: device_status::OK,
            problem_code: 0,
            driver: [0u8; MAX_DRIVER],
            driver_len: 0,
            driver_version: [0u8; 32],
            driver_version_len: 0,
            manufacturer: [0u8; MAX_NAME],
            manufacturer_len: 0,
            enabled: true,
            hidden: false,
            resources: [const { DeviceResource::new() }; MAX_RESOURCES],
            resource_count: 0,
            parent: -1,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_device_id(&mut self, id: &[u8]) {
        let len = id.len().min(MAX_DEVICE_ID);
        self.device_id[..len].copy_from_slice(&id[..len]);
        self.device_id_len = len;
    }

    pub fn set_driver(&mut self, driver: &[u8]) {
        let len = driver.len().min(MAX_DRIVER);
        self.driver[..len].copy_from_slice(&driver[..len]);
        self.driver_len = len;
    }

    pub fn set_manufacturer(&mut self, mfr: &[u8]) {
        let len = mfr.len().min(MAX_NAME);
        self.manufacturer[..len].copy_from_slice(&mfr[..len]);
        self.manufacturer_len = len;
    }

    pub fn add_resource(&mut self, res_type: ResourceType, start: u64, end: u64) -> bool {
        if self.resource_count >= MAX_RESOURCES {
            return false;
        }
        self.resources[self.resource_count] = DeviceResource {
            resource_type: res_type,
            start,
            end,
            flags: 0,
        };
        self.resource_count += 1;
        true
    }
}

impl Default for DeviceEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Device Manager State
// ============================================================================

/// Device Manager state
struct DeviceManagerState {
    /// All devices
    devices: [DeviceEntry; MAX_DEVICES],
    /// Device count
    device_count: usize,
    /// Show hidden devices
    show_hidden: bool,
    /// View mode (0=by type, 1=by connection, 2=by resources)
    view_mode: u32,
}

impl DeviceManagerState {
    pub const fn new() -> Self {
        Self {
            devices: [const { DeviceEntry::new() }; MAX_DEVICES],
            device_count: 0,
            show_hidden: false,
            view_mode: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static DEVMGR_INITIALIZED: AtomicBool = AtomicBool::new(false);
static DEVMGR_STATE: SpinLock<DeviceManagerState> = SpinLock::new(DeviceManagerState::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Device Manager
pub fn init() {
    if DEVMGR_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = DEVMGR_STATE.lock();

    // Add sample devices for testing
    add_sample_devices(&mut state);

    crate::serial_println!("[WIN32K] Device Manager initialized");
}

/// Add sample devices
fn add_sample_devices(state: &mut DeviceManagerState) {
    // Computer (root)
    add_device(state, b"ACPI x64-based PC", b"ACPI\\PNP0A08", DeviceClass::Computer, -1);

    // Processors
    let cpu_parent = state.device_count as i32 - 1;
    add_device(state, b"Intel(R) Pentium(R) 4 CPU 3.00GHz", b"ACPI\\GenuineIntel_-_x86", DeviceClass::Processor, cpu_parent);

    // Disk drives
    add_device(state, b"WDC WD800JD-75MSA3 ATA Device", b"IDE\\DiskWDC_WD800JD-75MSA3", DeviceClass::DiskDrive, -1);
    add_device(state, b"Generic USB Storage Device", b"USBSTOR\\Disk", DeviceClass::DiskDrive, -1);

    // Display
    let disp_idx = state.device_count;
    add_device(state, b"NVIDIA GeForce 6600 GT", b"PCI\\VEN_10DE&DEV_00F1", DeviceClass::Display, -1);
    if disp_idx < state.device_count {
        state.devices[disp_idx].set_manufacturer(b"NVIDIA");
        state.devices[disp_idx].set_driver(b"nv4_disp.dll");
        state.devices[disp_idx].add_resource(ResourceType::Memory, 0xFD000000, 0xFDFFFFFF);
        state.devices[disp_idx].add_resource(ResourceType::Memory, 0xE0000000, 0xEFFFFFFF);
        state.devices[disp_idx].add_resource(ResourceType::IoPort, 0xEC00, 0xEC7F);
        state.devices[disp_idx].add_resource(ResourceType::Irq, 16, 16);
    }

    // CD-ROM
    add_device(state, b"HL-DT-ST DVDRAM GSA-4163B", b"IDE\\CdRomHL-DT-ST_DVDRAM", DeviceClass::CdRom, -1);

    // IDE controllers
    let ide_idx = state.device_count;
    add_device(state, b"Intel(R) 82801FB/FBM Ultra ATA Storage Controller", b"PCI\\VEN_8086&DEV_2651", DeviceClass::IdeController, -1);
    if ide_idx < state.device_count {
        state.devices[ide_idx].set_manufacturer(b"Intel");
        state.devices[ide_idx].add_resource(ResourceType::IoPort, 0x01F0, 0x01F7);
        state.devices[ide_idx].add_resource(ResourceType::IoPort, 0x03F6, 0x03F6);
        state.devices[ide_idx].add_resource(ResourceType::Irq, 14, 14);
    }

    // Keyboard
    let kbd_idx = state.device_count;
    add_device(state, b"Standard 101/102-Key or Microsoft Natural PS/2 Keyboard", b"ACPI\\PNP0303", DeviceClass::Keyboard, -1);
    if kbd_idx < state.device_count {
        state.devices[kbd_idx].set_driver(b"i8042prt.sys");
        state.devices[kbd_idx].add_resource(ResourceType::IoPort, 0x60, 0x60);
        state.devices[kbd_idx].add_resource(ResourceType::IoPort, 0x64, 0x64);
        state.devices[kbd_idx].add_resource(ResourceType::Irq, 1, 1);
    }

    // Mouse
    let mouse_idx = state.device_count;
    add_device(state, b"PS/2 Compatible Mouse", b"ACPI\\PNP0F13", DeviceClass::Mouse, -1);
    if mouse_idx < state.device_count {
        state.devices[mouse_idx].set_driver(b"i8042prt.sys");
        state.devices[mouse_idx].add_resource(ResourceType::Irq, 12, 12);
    }

    // Monitor
    add_device(state, b"Plug and Play Monitor", b"DISPLAY\\Default_Monitor", DeviceClass::Monitor, -1);

    // Network
    let net_idx = state.device_count;
    add_device(state, b"Intel(R) PRO/1000 MT Network Connection", b"PCI\\VEN_8086&DEV_100F", DeviceClass::Network, -1);
    if net_idx < state.device_count {
        state.devices[net_idx].set_manufacturer(b"Intel Corporation");
        state.devices[net_idx].set_driver(b"e1000.sys");
        state.devices[net_idx].add_resource(ResourceType::Memory, 0xFEB00000, 0xFEB1FFFF);
        state.devices[net_idx].add_resource(ResourceType::IoPort, 0xD000, 0xD03F);
        state.devices[net_idx].add_resource(ResourceType::Irq, 17, 17);
    }

    // Ports
    add_device(state, b"Communications Port (COM1)", b"ACPI\\PNP0501", DeviceClass::Ports, -1);
    add_device(state, b"Printer Port (LPT1)", b"ACPI\\PNP0400", DeviceClass::Ports, -1);

    // Sound
    let snd_idx = state.device_count;
    add_device(state, b"Realtek AC'97 Audio", b"PCI\\VEN_10EC&DEV_0650", DeviceClass::Multimedia, -1);
    if snd_idx < state.device_count {
        state.devices[snd_idx].set_manufacturer(b"Realtek");
        state.devices[snd_idx].add_resource(ResourceType::IoPort, 0xD800, 0xD8FF);
        state.devices[snd_idx].add_resource(ResourceType::Irq, 5, 5);
    }

    // USB controllers
    add_device(state, b"Intel(R) 82801FB/FBM USB Universal Host Controller", b"PCI\\VEN_8086&DEV_2658", DeviceClass::UsbController, -1);
    add_device(state, b"Intel(R) 82801FB/FBM USB2 Enhanced Host Controller", b"PCI\\VEN_8086&DEV_265C", DeviceClass::UsbController, -1);

    // System devices
    add_device(state, b"ACPI Fixed Feature Button", b"ACPI\\FixedButton", DeviceClass::System, -1);
    add_device(state, b"System CMOS/real time clock", b"ACPI\\PNP0B00", DeviceClass::System, -1);
    add_device(state, b"System timer", b"ACPI\\PNP0100", DeviceClass::System, -1);
    add_device(state, b"Direct memory access controller", b"ACPI\\PNP0200", DeviceClass::System, -1);
    add_device(state, b"Programmable interrupt controller", b"ACPI\\PNP0000", DeviceClass::System, -1);
}

/// Helper to add a device
fn add_device(state: &mut DeviceManagerState, name: &[u8], device_id: &[u8], class: DeviceClass, parent: i32) {
    if state.device_count >= MAX_DEVICES {
        return;
    }

    let mut dev = DeviceEntry::new();
    dev.set_name(name);
    dev.set_device_id(device_id);
    dev.device_class = class;
    dev.parent = parent;
    dev.status = device_status::OK;
    dev.enabled = true;

    state.devices[state.device_count] = dev;
    state.device_count += 1;
}

// ============================================================================
// Device Enumeration
// ============================================================================

/// Get device count
pub fn get_device_count() -> usize {
    DEVMGR_STATE.lock().device_count
}

/// Get device by index
pub fn get_device(index: usize) -> Option<DeviceEntry> {
    let state = DEVMGR_STATE.lock();
    if index < state.device_count {
        Some(state.devices[index])
    } else {
        None
    }
}

/// Get devices by class
pub fn get_devices_by_class(class: DeviceClass) -> ([usize; 32], usize) {
    let state = DEVMGR_STATE.lock();
    let mut indices = [0usize; 32];
    let mut count = 0;

    for i in 0..state.device_count {
        if state.devices[i].device_class == class && count < 32 {
            indices[count] = i;
            count += 1;
        }
    }

    (indices, count)
}

/// Find device by hardware ID
pub fn find_device_by_id(device_id: &[u8]) -> Option<usize> {
    let state = DEVMGR_STATE.lock();
    for i in 0..state.device_count {
        let dev = &state.devices[i];
        if dev.device_id_len == device_id.len() &&
           &dev.device_id[..dev.device_id_len] == device_id {
            return Some(i);
        }
    }
    None
}

/// Get child devices
pub fn get_child_devices(parent_index: i32) -> ([usize; 32], usize) {
    let state = DEVMGR_STATE.lock();
    let mut indices = [0usize; 32];
    let mut count = 0;

    for i in 0..state.device_count {
        if state.devices[i].parent == parent_index && count < 32 {
            indices[count] = i;
            count += 1;
        }
    }

    (indices, count)
}

// ============================================================================
// Device Control
// ============================================================================

/// Enable a device
pub fn enable_device(index: usize) -> bool {
    let mut state = DEVMGR_STATE.lock();
    if index >= state.device_count {
        return false;
    }

    state.devices[index].enabled = true;
    state.devices[index].status = device_status::OK;
    true
}

/// Disable a device
pub fn disable_device(index: usize) -> bool {
    let mut state = DEVMGR_STATE.lock();
    if index >= state.device_count {
        return false;
    }

    state.devices[index].enabled = false;
    state.devices[index].status = device_status::DISABLED;
    true
}

/// Uninstall a device
pub fn uninstall_device(index: usize) -> bool {
    let mut state = DEVMGR_STATE.lock();
    if index >= state.device_count {
        return false;
    }

    // Mark as not present
    state.devices[index].status = device_status::NOT_PRESENT;
    state.devices[index].hidden = true;
    true
}

/// Scan for hardware changes
pub fn scan_for_hardware_changes() {
    // In a real implementation, this would trigger PnP enumeration
    // For now, just update device states
    let mut state = DEVMGR_STATE.lock();
    for i in 0..state.device_count {
        if state.devices[i].status == device_status::NOT_PRESENT {
            // Re-detect device
            state.devices[i].status = device_status::OK;
            state.devices[i].hidden = false;
        }
    }
}

/// Update driver for device
pub fn update_driver(index: usize, driver_name: &[u8]) -> bool {
    let mut state = DEVMGR_STATE.lock();
    if index >= state.device_count {
        return false;
    }

    state.devices[index].set_driver(driver_name);
    true
}

// ============================================================================
// View Settings
// ============================================================================

/// View mode constants
pub mod view_mode {
    /// View by device type
    pub const BY_TYPE: u32 = 0;
    /// View by connection
    pub const BY_CONNECTION: u32 = 1;
    /// View by resources (IRQ, DMA, Memory, I/O)
    pub const BY_RESOURCES: u32 = 2;
}

/// Set view mode
pub fn set_view_mode(mode: u32) {
    DEVMGR_STATE.lock().view_mode = mode;
}

/// Get view mode
pub fn get_view_mode() -> u32 {
    DEVMGR_STATE.lock().view_mode
}

/// Set show hidden devices
pub fn set_show_hidden(show: bool) {
    DEVMGR_STATE.lock().show_hidden = show;
}

/// Get show hidden devices
pub fn get_show_hidden() -> bool {
    DEVMGR_STATE.lock().show_hidden
}

// ============================================================================
// Resource Viewing
// ============================================================================

/// Get devices using a specific IRQ
pub fn get_devices_by_irq(irq: u32) -> ([usize; 16], usize) {
    let state = DEVMGR_STATE.lock();
    let mut indices = [0usize; 16];
    let mut count = 0;

    for i in 0..state.device_count {
        for r in 0..state.devices[i].resource_count {
            let res = &state.devices[i].resources[r];
            if res.resource_type == ResourceType::Irq && res.start == irq as u64 {
                if count < 16 {
                    indices[count] = i;
                    count += 1;
                }
                break;
            }
        }
    }

    (indices, count)
}

/// Get devices using a specific I/O port range
pub fn get_devices_by_ioport(start: u16, end: u16) -> ([usize; 16], usize) {
    let state = DEVMGR_STATE.lock();
    let mut indices = [0usize; 16];
    let mut count = 0;

    for i in 0..state.device_count {
        for r in 0..state.devices[i].resource_count {
            let res = &state.devices[i].resources[r];
            if res.resource_type == ResourceType::IoPort {
                // Check for overlap
                if res.start <= end as u64 && res.end >= start as u64 {
                    if count < 16 {
                        indices[count] = i;
                        count += 1;
                    }
                    break;
                }
            }
        }
    }

    (indices, count)
}

/// Get devices using memory in a range
pub fn get_devices_by_memory(start: u64, end: u64) -> ([usize; 16], usize) {
    let state = DEVMGR_STATE.lock();
    let mut indices = [0usize; 16];
    let mut count = 0;

    for i in 0..state.device_count {
        for r in 0..state.devices[i].resource_count {
            let res = &state.devices[i].resources[r];
            if res.resource_type == ResourceType::Memory {
                // Check for overlap
                if res.start <= end && res.end >= start {
                    if count < 16 {
                        indices[count] = i;
                        count += 1;
                    }
                    break;
                }
            }
        }
    }

    (indices, count)
}

// ============================================================================
// Statistics
// ============================================================================

/// Device Manager statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceManagerStats {
    pub initialized: bool,
    pub total_devices: usize,
    pub enabled_devices: usize,
    pub disabled_devices: usize,
    pub problem_devices: usize,
}

/// Get Device Manager statistics
pub fn get_stats() -> DeviceManagerStats {
    let state = DEVMGR_STATE.lock();
    let mut enabled = 0;
    let mut disabled = 0;
    let mut problems = 0;

    for i in 0..state.device_count {
        if state.devices[i].enabled {
            enabled += 1;
        } else {
            disabled += 1;
        }
        if state.devices[i].status != device_status::OK {
            problems += 1;
        }
    }

    DeviceManagerStats {
        initialized: DEVMGR_INITIALIZED.load(Ordering::Relaxed),
        total_devices: state.device_count,
        enabled_devices: enabled,
        disabled_devices: disabled,
        problem_devices: problems,
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Device Manager dialog handle
pub type HDEVMGRDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Device Manager dialog
pub fn create_devmgr_dialog(_parent: super::super::HWND) -> HDEVMGRDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}

/// Device properties tab
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DevicePropertiesTab {
    /// General tab
    #[default]
    General = 0,
    /// Driver tab
    Driver = 1,
    /// Details tab
    Details = 2,
    /// Resources tab
    Resources = 3,
}

/// Get properties tab count
pub fn get_properties_tab_count() -> u32 {
    4
}

/// Get properties tab name
pub fn get_properties_tab_name(tab: DevicePropertiesTab) -> &'static str {
    match tab {
        DevicePropertiesTab::General => "General",
        DevicePropertiesTab::Driver => "Driver",
        DevicePropertiesTab::Details => "Details",
        DevicePropertiesTab::Resources => "Resources",
    }
}
