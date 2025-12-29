//! Driver Object Implementation
//!
//! Driver objects represent loaded device drivers. They contain:
//! - Driver entry point and unload routine
//! - Dispatch table for IRP major functions
//! - List of device objects owned by the driver
//!
//! # Driver Entry
//! When a driver is loaded, its DriverEntry function is called with
//! a pointer to the driver object and a registry path.
//!
//! # Dispatch Routines
//! Each major function (Create, Read, Write, etc.) has a dispatch
//! routine in the driver object. The I/O manager calls these routines
//! when an IRP of that type is sent to a device owned by the driver.

use core::ptr;
use crate::ke::SpinLock;
use crate::ob::ObjectHeader;
use super::irp::{Irp, IrpMajorFunction};
use super::device::DeviceObject;

/// Maximum driver name length
pub const DRIVER_NAME_LENGTH: usize = 64;

/// Number of dispatch routines (one per major function)
pub const IRP_MJ_MAXIMUM_FUNCTION: usize = 28;

/// Driver dispatch routine type
///
/// Called by the I/O manager to handle an IRP for a device.
/// Returns NTSTATUS code.
pub type DriverDispatch = fn(
    device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32;

/// Driver unload routine type
///
/// Called when the driver is being unloaded.
pub type DriverUnload = fn(driver: *mut DriverObject);

/// Driver initialization routine type
///
/// Called when the driver is loaded.
pub type DriverInitialize = fn(
    driver: *mut DriverObject,
    registry_path: *const u8,
) -> i32;

/// Driver add device routine type (for PnP)
///
/// Called when a new device is detected.
pub type DriverAddDevice = fn(
    driver: *mut DriverObject,
    physical_device: *mut DeviceObject,
) -> i32;

/// Driver start I/O routine type
///
/// Called to start I/O on a device (for StartIo-based drivers)
pub type DriverStartIo = fn(
    device: *mut DeviceObject,
    irp: *mut Irp,
);

/// Driver Object structure
#[repr(C)]
pub struct DriverObject {
    /// Object header (for object manager integration)
    pub header: ObjectHeader,

    /// Type identifier
    pub type_id: u16,
    /// Size of structure
    pub size: u16,

    /// First device object in driver's device list
    pub device_object: *mut DeviceObject,

    /// Driver flags
    pub flags: u32,

    /// Driver start address (base of driver image)
    pub driver_start: *mut u8,

    /// Driver size
    pub driver_size: u32,

    /// Driver section (for memory-mapped driver image)
    pub driver_section: *mut u8,

    /// Driver extension
    pub driver_extension: *mut DriverExtension,

    /// Driver name
    pub driver_name: [u8; DRIVER_NAME_LENGTH],

    /// Driver name length
    pub driver_name_length: u8,

    /// Hardware database (registry path for hardware info)
    pub hardware_database: *const u8,

    /// Fast I/O dispatch table
    pub fast_io_dispatch: *mut FastIoDispatch,

    /// Driver initialization routine
    pub driver_init: Option<DriverInitialize>,

    /// Driver start I/O routine
    pub driver_start_io: Option<DriverStartIo>,

    /// Driver unload routine
    pub driver_unload: Option<DriverUnload>,

    /// Major function dispatch table
    pub major_function: [Option<DriverDispatch>; IRP_MJ_MAXIMUM_FUNCTION],
}

// Safety: DriverObject is designed for kernel-mode use
unsafe impl Sync for DriverObject {}
unsafe impl Send for DriverObject {}

impl DriverObject {
    /// Create a new driver object
    pub const fn new() -> Self {
        Self {
            header: ObjectHeader::new(),
            type_id: 0x0004, // IO_TYPE_DRIVER
            size: 0,
            device_object: ptr::null_mut(),
            flags: 0,
            driver_start: ptr::null_mut(),
            driver_size: 0,
            driver_section: ptr::null_mut(),
            driver_extension: ptr::null_mut(),
            driver_name: [0; DRIVER_NAME_LENGTH],
            driver_name_length: 0,
            hardware_database: ptr::null(),
            fast_io_dispatch: ptr::null_mut(),
            driver_init: None,
            driver_start_io: None,
            driver_unload: None,
            major_function: [None; IRP_MJ_MAXIMUM_FUNCTION],
        }
    }

    /// Initialize a driver object
    pub unsafe fn init(&mut self, name: &[u8]) {
        let len = name.len().min(DRIVER_NAME_LENGTH - 1);
        self.driver_name[..len].copy_from_slice(&name[..len]);
        self.driver_name[len] = 0;
        self.driver_name_length = len as u8;

        // Set default dispatch routine for all major functions
        for i in 0..IRP_MJ_MAXIMUM_FUNCTION {
            self.major_function[i] = Some(default_dispatch);
        }
    }

    /// Get driver name
    pub fn name(&self) -> &[u8] {
        &self.driver_name[..self.driver_name_length as usize]
    }

    /// Set dispatch routine for a major function
    pub fn set_dispatch(&mut self, major: IrpMajorFunction, routine: DriverDispatch) {
        let index = major as usize;
        if index < IRP_MJ_MAXIMUM_FUNCTION {
            self.major_function[index] = Some(routine);
        }
    }

    /// Get dispatch routine for a major function
    pub fn get_dispatch(&self, major: IrpMajorFunction) -> Option<DriverDispatch> {
        let index = major as usize;
        if index < IRP_MJ_MAXIMUM_FUNCTION {
            self.major_function[index]
        } else {
            None
        }
    }
}

impl Default for DriverObject {
    fn default() -> Self {
        Self::new()
    }
}

/// Default dispatch routine - returns not implemented
fn default_dispatch(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    unsafe {
        if !irp.is_null() {
            (*irp).io_status.status = -1073741822; // STATUS_NOT_IMPLEMENTED
            (*irp).io_status.information = 0;
        }
    }
    -1073741822 // STATUS_NOT_IMPLEMENTED
}

/// Driver Extension (additional driver data)
#[repr(C)]
pub struct DriverExtension {
    /// Back pointer to driver object
    pub driver_object: *mut DriverObject,

    /// Add device routine (for PnP drivers)
    pub add_device: Option<DriverAddDevice>,

    /// Count of unclaimed devices
    pub count: u32,

    /// Service key name (registry)
    pub service_key_name: [u8; 64],
}

impl DriverExtension {
    pub const fn new() -> Self {
        Self {
            driver_object: ptr::null_mut(),
            add_device: None,
            count: 0,
            service_key_name: [0; 64],
        }
    }
}

impl Default for DriverExtension {
    fn default() -> Self {
        Self::new()
    }
}

/// Fast I/O Dispatch Table
///
/// Contains function pointers for fast I/O paths that bypass IRPs.
#[repr(C)]
pub struct FastIoDispatch {
    /// Size of this structure
    pub size_of_fast_io_dispatch: u32,

    /// Fast I/O check routine
    pub fast_io_check_if_possible: Option<FastIoCheck>,

    /// Fast read
    pub fast_io_read: Option<FastIoReadWrite>,

    /// Fast write
    pub fast_io_write: Option<FastIoReadWrite>,

    /// Fast query basic info
    pub fast_io_query_basic_info: Option<FastIoQueryInfo>,

    /// Fast query standard info
    pub fast_io_query_standard_info: Option<FastIoQueryInfo>,

    /// Fast lock
    pub fast_io_lock: Option<FastIoLock>,

    /// Fast unlock single
    pub fast_io_unlock_single: Option<FastIoUnlock>,

    /// Fast unlock all
    pub fast_io_unlock_all: Option<FastIoUnlockAll>,

    /// Fast unlock all by key
    pub fast_io_unlock_all_by_key: Option<FastIoUnlockAllByKey>,

    /// Fast device control
    pub fast_io_device_control: Option<FastIoDeviceControl>,
}

impl FastIoDispatch {
    pub const fn new() -> Self {
        Self {
            size_of_fast_io_dispatch: core::mem::size_of::<Self>() as u32,
            fast_io_check_if_possible: None,
            fast_io_read: None,
            fast_io_write: None,
            fast_io_query_basic_info: None,
            fast_io_query_standard_info: None,
            fast_io_lock: None,
            fast_io_unlock_single: None,
            fast_io_unlock_all: None,
            fast_io_unlock_all_by_key: None,
            fast_io_device_control: None,
        }
    }
}

impl Default for FastIoDispatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Fast I/O function types
pub type FastIoCheck = fn(
    file: *mut super::file::FileObject,
    offset: u64,
    length: u32,
    wait: bool,
    lock_key: u32,
    read: bool,
    status: *mut super::irp::IoStatusBlock,
    device: *mut DeviceObject,
) -> bool;

pub type FastIoReadWrite = fn(
    file: *mut super::file::FileObject,
    offset: u64,
    length: u32,
    wait: bool,
    lock_key: u32,
    buffer: *mut u8,
    status: *mut super::irp::IoStatusBlock,
    device: *mut DeviceObject,
) -> bool;

pub type FastIoQueryInfo = fn(
    file: *mut super::file::FileObject,
    wait: bool,
    buffer: *mut u8,
    status: *mut super::irp::IoStatusBlock,
    device: *mut DeviceObject,
) -> bool;

pub type FastIoLock = fn(
    file: *mut super::file::FileObject,
    offset: u64,
    length: u64,
    process: *mut u8,
    key: u32,
    fail_immediately: bool,
    exclusive: bool,
    status: *mut super::irp::IoStatusBlock,
    device: *mut DeviceObject,
) -> bool;

pub type FastIoUnlock = fn(
    file: *mut super::file::FileObject,
    offset: u64,
    length: u64,
    process: *mut u8,
    key: u32,
    status: *mut super::irp::IoStatusBlock,
    device: *mut DeviceObject,
) -> bool;

pub type FastIoUnlockAll = fn(
    file: *mut super::file::FileObject,
    process: *mut u8,
    status: *mut super::irp::IoStatusBlock,
    device: *mut DeviceObject,
) -> bool;

pub type FastIoUnlockAllByKey = fn(
    file: *mut super::file::FileObject,
    process: *mut u8,
    key: u32,
    status: *mut super::irp::IoStatusBlock,
    device: *mut DeviceObject,
) -> bool;

pub type FastIoDeviceControl = fn(
    file: *mut super::file::FileObject,
    wait: bool,
    input_buffer: *mut u8,
    input_length: u32,
    output_buffer: *mut u8,
    output_length: u32,
    ioctl: u32,
    status: *mut super::irp::IoStatusBlock,
    device: *mut DeviceObject,
) -> bool;

// ============================================================================
// Driver Object Pool
// ============================================================================

/// Maximum number of drivers
pub const MAX_DRIVERS: usize = 32;

/// Driver object pool
static mut DRIVER_POOL: [DriverObject; MAX_DRIVERS] = {
    const INIT: DriverObject = DriverObject::new();
    [INIT; MAX_DRIVERS]
};

/// Driver pool bitmap
static mut DRIVER_POOL_BITMAP: u32 = 0;

/// Driver pool lock
static DRIVER_POOL_LOCK: SpinLock<()> = SpinLock::new(());

/// Create a driver object
///
/// # Arguments
/// * `name` - Driver name
///
/// # Returns
/// Pointer to driver object, or null on failure
pub unsafe fn io_create_driver(name: &[u8]) -> *mut DriverObject {
    let _guard = DRIVER_POOL_LOCK.lock();

    for i in 0..MAX_DRIVERS {
        if DRIVER_POOL_BITMAP & (1 << i) == 0 {
            DRIVER_POOL_BITMAP |= 1 << i;
            let driver = &mut DRIVER_POOL[i] as *mut DriverObject;
            (*driver) = DriverObject::new();
            (*driver).init(name);
            return driver;
        }
    }

    ptr::null_mut()
}

/// Delete a driver object
pub unsafe fn io_delete_driver(driver: *mut DriverObject) {
    if driver.is_null() {
        return;
    }

    // Call unload routine if present
    if let Some(unload) = (*driver).driver_unload {
        unload(driver);
    }

    let _guard = DRIVER_POOL_LOCK.lock();

    let base = DRIVER_POOL.as_ptr() as usize;
    let offset = driver as usize - base;
    let index = offset / core::mem::size_of::<DriverObject>();

    if index < MAX_DRIVERS {
        DRIVER_POOL_BITMAP &= !(1 << index);
    }
}

/// Call a driver dispatch routine
///
/// This is the main entry point for sending IRPs to drivers.
pub unsafe fn io_call_driver(
    device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if device.is_null() || irp.is_null() {
        return -1073741811; // STATUS_INVALID_PARAMETER
    }

    // Move to next stack location
    (*irp).current_location -= 1;
    let stack_idx = (*irp).current_location as usize;

    if stack_idx == 0 || stack_idx > (*irp).stack_count as usize {
        return -1073741811; // STATUS_INVALID_PARAMETER
    }

    // Set device in current stack location
    (*irp).stack[stack_idx - 1].device_object = device;

    // Get the driver
    let driver = (*device).driver_object;
    if driver.is_null() {
        return -1073741810; // STATUS_NO_SUCH_DEVICE
    }

    // Get the major function
    let major = (*irp).stack[stack_idx - 1].major_function;

    // Call the dispatch routine
    if let Some(dispatch) = (*driver).get_dispatch(major) {
        dispatch(device, irp)
    } else {
        -1073741822 // STATUS_NOT_IMPLEMENTED
    }
}

/// Initialize driver subsystem
pub unsafe fn init_driver_system() {
    crate::serial_println!("[IO] Driver subsystem initialized ({} drivers available)", MAX_DRIVERS);
}

// ============================================================================
// Driver Pool Inspection (for debugging)
// ============================================================================

/// Driver pool statistics
#[derive(Debug, Clone, Copy)]
pub struct DriverPoolStats {
    /// Total number of drivers in pool
    pub total_drivers: usize,
    /// Number of allocated drivers
    pub allocated_drivers: usize,
    /// Number of free drivers
    pub free_drivers: usize,
}

/// Snapshot of an allocated driver
#[derive(Debug, Clone, Copy)]
pub struct DriverSnapshot {
    /// Driver address
    pub address: u64,
    /// Driver name
    pub name: [u8; 32],
    /// Name length
    pub name_length: u8,
    /// Number of devices
    pub device_count: u32,
    /// Has unload routine
    pub has_unload: bool,
    /// Has start I/O routine
    pub has_start_io: bool,
    /// Number of major functions registered
    pub major_function_count: u32,
    /// Driver flags
    pub flags: u32,
}

/// Get driver pool statistics
pub fn io_get_driver_stats() -> DriverPoolStats {
    unsafe {
        let _guard = DRIVER_POOL_LOCK.lock();
        let allocated = DRIVER_POOL_BITMAP.count_ones() as usize;

        DriverPoolStats {
            total_drivers: MAX_DRIVERS,
            allocated_drivers: allocated,
            free_drivers: MAX_DRIVERS - allocated,
        }
    }
}

/// Get snapshots of allocated drivers
pub fn io_get_driver_snapshots(max_count: usize) -> ([DriverSnapshot; 16], usize) {
    let mut snapshots = [DriverSnapshot {
        address: 0,
        name: [0; 32],
        name_length: 0,
        device_count: 0,
        has_unload: false,
        has_start_io: false,
        major_function_count: 0,
        flags: 0,
    }; 16];

    let max_count = max_count.min(16);
    let mut count = 0;

    unsafe {
        let _guard = DRIVER_POOL_LOCK.lock();

        for i in 0..MAX_DRIVERS {
            if count >= max_count {
                break;
            }
            if DRIVER_POOL_BITMAP & (1 << i) != 0 {
                let driver = &DRIVER_POOL[i];

                // Copy name
                let mut name = [0u8; 32];
                let name_len = (driver.driver_name_length as usize).min(31);
                name[..name_len].copy_from_slice(&driver.driver_name[..name_len]);

                // Count devices
                let mut device_count = 0u32;
                let mut dev = driver.device_object;
                while !dev.is_null() {
                    device_count += 1;
                    dev = (*dev).next_device;
                }

                // Count major functions
                let mut major_count = 0u32;
                for func in driver.major_function.iter() {
                    if func.is_some() {
                        major_count += 1;
                    }
                }

                snapshots[count] = DriverSnapshot {
                    address: &DRIVER_POOL[i] as *const _ as u64,
                    name,
                    name_length: name_len as u8,
                    device_count,
                    has_unload: driver.driver_unload.is_some(),
                    has_start_io: driver.driver_start_io.is_some(),
                    major_function_count: major_count,
                    flags: driver.flags,
                };
                count += 1;
            }
        }
    }

    (snapshots, count)
}
