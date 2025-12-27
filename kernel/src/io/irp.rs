//! I/O Request Packet (IRP) Implementation
//!
//! IRPs are the fundamental data structure for I/O in NT. Every I/O
//! operation (read, write, ioctl, etc.) is represented by an IRP that
//! flows through the device stack.
//!
//! # IRP Structure
//! - Fixed header with status, flags, and pointers
//! - Array of IO_STACK_LOCATION entries (one per driver in stack)
//! - System/user buffers for data transfer
//!
//! # IRP Flow
//! 1. Allocated by I/O manager or driver
//! 2. Filled with operation parameters
//! 3. Sent to device via IoCallDriver
//! 4. Each driver processes its stack location
//! 5. Bottom driver completes the IRP
//! 6. Completion routines called as IRP unwinds

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::ke::{list::ListEntry, KEvent, SpinLock};

/// Maximum number of stack locations per IRP
pub const IRP_MAX_STACK_SIZE: usize = 8;

/// IRP flags
pub mod irp_flags {
    /// IRP is pending (not yet completed)
    pub const IRP_PENDING: u32 = 0x0001;
    /// IRP is synchronous (caller waiting)
    pub const IRP_SYNCHRONOUS: u32 = 0x0002;
    /// Create operation
    pub const IRP_CREATE_OPERATION: u32 = 0x0004;
    /// Read operation
    pub const IRP_READ_OPERATION: u32 = 0x0008;
    /// Write operation
    pub const IRP_WRITE_OPERATION: u32 = 0x0010;
    /// Close operation
    pub const IRP_CLOSE_OPERATION: u32 = 0x0020;
    /// IRP is being deallocated
    pub const IRP_DEALLOCATE_BUFFER: u32 = 0x0040;
    /// Buffered I/O
    pub const IRP_BUFFERED_IO: u32 = 0x0080;
    /// Direct I/O
    pub const IRP_DIRECT_IO: u32 = 0x0100;
    /// Input operation (device to memory)
    pub const IRP_INPUT_OPERATION: u32 = 0x0200;
    /// Associated IRP (part of a larger I/O)
    pub const IRP_ASSOCIATED_IRP: u32 = 0x0400;
    /// Paging I/O
    pub const IRP_PAGING_IO: u32 = 0x0800;
    /// Nocache
    pub const IRP_NOCACHE: u32 = 0x1000;
    /// IRP has been completed
    pub const IRP_COMPLETED: u32 = 0x2000;
}

/// Major function codes (IRP types)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IrpMajorFunction {
    Create = 0,
    CreateNamedPipe = 1,
    Close = 2,
    Read = 3,
    Write = 4,
    QueryInformation = 5,
    SetInformation = 6,
    QueryEa = 7,
    SetEa = 8,
    FlushBuffers = 9,
    QueryVolumeInformation = 10,
    SetVolumeInformation = 11,
    DirectoryControl = 12,
    FileSystemControl = 13,
    DeviceControl = 14,
    InternalDeviceControl = 15,
    Shutdown = 16,
    LockControl = 17,
    Cleanup = 18,
    CreateMailslot = 19,
    QuerySecurity = 20,
    SetSecurity = 21,
    Power = 22,
    SystemControl = 23,
    DeviceChange = 24,
    QueryQuota = 25,
    SetQuota = 26,
    Pnp = 27,
    MaximumFunction = 28,
}

impl Default for IrpMajorFunction {
    fn default() -> Self {
        Self::Create
    }
}

/// Minor function codes (for PnP, Power, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IrpMinorFunction(pub u8);

/// I/O Status Block - result of an I/O operation
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoStatusBlock {
    /// Status code (NTSTATUS)
    pub status: i32,
    /// Information (bytes transferred, etc.)
    pub information: usize,
}

impl IoStatusBlock {
    pub const fn new() -> Self {
        Self {
            status: 0,
            information: 0,
        }
    }

    /// Create a success status
    pub const fn success(information: usize) -> Self {
        Self {
            status: 0, // STATUS_SUCCESS
            information,
        }
    }

    /// Create an error status
    pub const fn error(status: i32) -> Self {
        Self {
            status,
            information: 0,
        }
    }
}

impl Default for IoStatusBlock {
    fn default() -> Self {
        Self::new()
    }
}

/// I/O Stack Location - per-driver IRP parameters
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoStackLocation {
    /// Major function code
    pub major_function: IrpMajorFunction,
    /// Minor function code
    pub minor_function: IrpMinorFunction,
    /// Flags
    pub flags: u8,
    /// Control flags
    pub control: u8,

    /// Parameters union (depends on major function)
    pub parameters: IoStackParameters,

    /// Device object this stack location is for
    pub device_object: *mut super::device::DeviceObject,

    /// File object (if applicable)
    pub file_object: *mut super::file::FileObject,

    /// Completion routine
    pub completion_routine: Option<IoCompletionRoutine>,

    /// Context for completion routine
    pub completion_context: *mut u8,
}

/// Stack location control flags
pub mod sl_control {
    /// Invoke completion routine on success
    pub const SL_INVOKE_ON_SUCCESS: u8 = 0x01;
    /// Invoke completion routine on error
    pub const SL_INVOKE_ON_ERROR: u8 = 0x02;
    /// Invoke completion routine on cancel
    pub const SL_INVOKE_ON_CANCEL: u8 = 0x04;
    /// Pending returned from dispatch
    pub const SL_PENDING_RETURNED: u8 = 0x08;
}

/// I/O completion routine type
pub type IoCompletionRoutine = fn(
    device: *mut super::device::DeviceObject,
    irp: *mut Irp,
    context: *mut u8,
) -> i32;

/// Parameters for different IRP major functions
#[repr(C)]
#[derive(Clone, Copy)]
pub union IoStackParameters {
    /// Create parameters
    pub create: CreateParameters,
    /// Read parameters
    pub read: ReadWriteParameters,
    /// Write parameters
    pub write: ReadWriteParameters,
    /// Device I/O control parameters
    pub device_io_control: DeviceIoControlParameters,
    /// Query file information parameters
    pub query_file: QueryFileParameters,
    /// Set file information parameters
    pub set_file: SetFileParameters,
    /// Generic parameters (raw bytes)
    pub others: [u8; 32],
}

impl Default for IoStackParameters {
    fn default() -> Self {
        Self { others: [0; 32] }
    }
}

/// Create operation parameters
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CreateParameters {
    /// Security context
    pub security_context: *mut u8,
    /// Desired access
    pub options: u32,
    /// File attributes
    pub file_attributes: u16,
    /// Share access
    pub share_access: u16,
    /// EA length
    pub ea_length: u32,
}

/// Read/Write operation parameters
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReadWriteParameters {
    /// Length of transfer
    pub length: u32,
    /// Key for byte-range locks
    pub key: u32,
    /// Byte offset
    pub byte_offset: u64,
}

/// Device I/O control parameters
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DeviceIoControlParameters {
    /// Output buffer length
    pub output_buffer_length: u32,
    /// Input buffer length
    pub input_buffer_length: u32,
    /// I/O control code
    pub io_control_code: u32,
    /// Type3 input buffer (for METHOD_NEITHER)
    pub type3_input_buffer: *mut u8,
}

/// Query file information parameters
#[repr(C)]
#[derive(Clone, Copy)]
pub struct QueryFileParameters {
    /// Length of buffer
    pub length: u32,
    /// Information class
    pub file_information_class: u32,
}

/// Set file information parameters
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetFileParameters {
    /// Length of buffer
    pub length: u32,
    /// Information class
    pub file_information_class: u32,
    /// File object (for rename/link)
    pub file_object: *mut super::file::FileObject,
    /// Replace if exists
    pub replace_if_exists: bool,
    /// Advance only (for position)
    pub advance_only: bool,
}

impl IoStackLocation {
    pub const fn new() -> Self {
        Self {
            major_function: IrpMajorFunction::Create,
            minor_function: IrpMinorFunction(0),
            flags: 0,
            control: 0,
            parameters: IoStackParameters { others: [0; 32] },
            device_object: ptr::null_mut(),
            file_object: ptr::null_mut(),
            completion_routine: None,
            completion_context: ptr::null_mut(),
        }
    }
}

impl Default for IoStackLocation {
    fn default() -> Self {
        Self::new()
    }
}

/// I/O Request Packet
#[repr(C)]
pub struct Irp {
    /// Type and size for pool management
    pub type_id: u16,
    pub size: u16,

    /// IRP flags
    pub flags: AtomicU32,

    /// List entry for driver queues
    pub list_entry: ListEntry,

    /// I/O status block
    pub io_status: IoStatusBlock,

    /// Requestor mode (kernel or user)
    pub requestor_mode: u8,

    /// Pending returned from driver
    pub pending_returned: bool,

    /// Current stack location index
    pub current_location: i8,

    /// Total stack locations
    pub stack_count: i8,

    /// Cancel flag
    pub cancel: bool,

    /// Cancel IRQL
    pub cancel_irql: u8,

    /// APC environment
    pub apc_environment: u8,

    /// Allocation flags
    pub allocation_flags: u8,

    /// User I/O status block pointer
    pub user_io_status_block: *mut IoStatusBlock,

    /// User event to signal on completion
    pub user_event: *mut KEvent,

    /// Overlay for associated IRPs or allocation
    pub overlay_async: AsyncOverlay,

    /// Cancel routine
    pub cancel_routine: Option<CancelRoutine>,

    /// User buffer (for buffered I/O)
    pub user_buffer: *mut u8,

    /// System buffer (for buffered I/O)
    pub system_buffer: *mut u8,

    /// MDL for direct I/O
    pub mdl_address: *mut u8,

    /// Thread that initiated the IRP
    pub thread: *mut crate::ke::KThread,

    /// Tail overlay (completion info)
    pub tail: IrpTail,

    /// Stack locations (variable size, placed at end)
    pub stack: [IoStackLocation; IRP_MAX_STACK_SIZE],
}

/// Cancel routine type
pub type CancelRoutine = fn(
    device: *mut super::device::DeviceObject,
    irp: *mut Irp,
);

/// Alias for cancel routine (NT naming convention)
pub type IoCancel = CancelRoutine;

/// Async overlay for IRP
#[repr(C)]
#[derive(Clone, Copy)]
pub union AsyncOverlay {
    /// User APC for async completion
    pub user_apc: UserApcOverlay,
    /// Associated IRP info
    pub associated: AssociatedIrpOverlay,
}

impl Default for AsyncOverlay {
    fn default() -> Self {
        Self {
            user_apc: UserApcOverlay {
                user_apc_routine: None,
                user_apc_context: ptr::null_mut(),
            }
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UserApcOverlay {
    pub user_apc_routine: Option<fn(*mut u8, *mut IoStatusBlock, u32)>,
    pub user_apc_context: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AssociatedIrpOverlay {
    pub master_irp: *mut Irp,
    pub irp_count: i32,
}

/// IRP tail (completion tracking)
#[repr(C)]
pub struct IrpTail {
    /// File object associated with this IRP
    pub file_object: *mut super::file::FileObject,
    /// Completion key for I/O completion port
    pub completion_key: *mut u8,
    /// Overlay for driver use
    pub driver_context: [*mut u8; 4],
}

impl Default for IrpTail {
    fn default() -> Self {
        Self {
            file_object: ptr::null_mut(),
            completion_key: ptr::null_mut(),
            driver_context: [ptr::null_mut(); 4],
        }
    }
}

// Safety: IRP uses atomic flags and is designed for cross-thread use
unsafe impl Sync for Irp {}
unsafe impl Send for Irp {}

impl Irp {
    /// Create a new uninitialized IRP
    pub const fn new() -> Self {
        Self {
            type_id: 0x0006, // IO_TYPE_IRP
            size: 0,
            flags: AtomicU32::new(0),
            list_entry: ListEntry::new(),
            io_status: IoStatusBlock::new(),
            requestor_mode: 0, // KernelMode
            pending_returned: false,
            current_location: 0,
            stack_count: 0,
            cancel: false,
            cancel_irql: 0,
            apc_environment: 0,
            allocation_flags: 0,
            user_io_status_block: ptr::null_mut(),
            user_event: ptr::null_mut(),
            overlay_async: AsyncOverlay {
                user_apc: UserApcOverlay {
                    user_apc_routine: None,
                    user_apc_context: ptr::null_mut(),
                }
            },
            cancel_routine: None,
            user_buffer: ptr::null_mut(),
            system_buffer: ptr::null_mut(),
            mdl_address: ptr::null_mut(),
            thread: ptr::null_mut(),
            tail: IrpTail {
                file_object: ptr::null_mut(),
                completion_key: ptr::null_mut(),
                driver_context: [ptr::null_mut(); 4],
            },
            stack: [IoStackLocation::new(); IRP_MAX_STACK_SIZE],
        }
    }

    /// Initialize an IRP
    pub fn init(&mut self, stack_size: i8) {
        self.type_id = 0x0006;
        self.size = core::mem::size_of::<Self>() as u16;
        self.stack_count = stack_size;
        self.current_location = stack_size; // Start past the end
        self.flags = AtomicU32::new(0);
        self.io_status = IoStatusBlock::new();
        self.cancel = false;
        self.pending_returned = false;

        // Clear stack locations
        for i in 0..stack_size as usize {
            if i < IRP_MAX_STACK_SIZE {
                self.stack[i] = IoStackLocation::new();
            }
        }
    }

    /// Get the current stack location
    pub fn get_current_stack_location(&self) -> Option<&IoStackLocation> {
        let idx = self.current_location as usize;
        if idx > 0 && idx <= self.stack_count as usize && idx <= IRP_MAX_STACK_SIZE {
            Some(&self.stack[idx - 1])
        } else {
            None
        }
    }

    /// Get mutable current stack location
    pub fn get_current_stack_location_mut(&mut self) -> Option<&mut IoStackLocation> {
        let idx = self.current_location as usize;
        if idx > 0 && idx <= self.stack_count as usize && idx <= IRP_MAX_STACK_SIZE {
            Some(&mut self.stack[idx - 1])
        } else {
            None
        }
    }

    /// Get the next stack location (for setting up before IoCallDriver)
    pub fn get_next_stack_location(&self) -> Option<&IoStackLocation> {
        let idx = self.current_location as usize;
        if idx > 1 && idx <= self.stack_count as usize + 1 && idx <= IRP_MAX_STACK_SIZE + 1 {
            Some(&self.stack[idx - 2])
        } else {
            None
        }
    }

    /// Get mutable next stack location
    pub fn get_next_stack_location_mut(&mut self) -> Option<&mut IoStackLocation> {
        let idx = self.current_location as usize;
        if idx > 1 && idx <= self.stack_count as usize + 1 && idx <= IRP_MAX_STACK_SIZE + 1 {
            Some(&mut self.stack[idx - 2])
        } else {
            None
        }
    }

    /// Move to the next stack location (IoSkipCurrentIrpStackLocation)
    pub fn skip_current_stack_location(&mut self) {
        self.current_location -= 1;
    }

    /// Set up next stack location by copying current (IoCopyCurrentIrpStackLocationToNext)
    pub fn copy_current_to_next(&mut self) {
        if let (Some(current), next_idx) = (
            self.get_current_stack_location(),
            self.current_location as usize - 1
        ) {
            if next_idx > 0 && next_idx <= IRP_MAX_STACK_SIZE {
                let current_copy = *current;
                self.stack[next_idx - 1] = current_copy;
                self.stack[next_idx - 1].completion_routine = None;
                self.stack[next_idx - 1].completion_context = ptr::null_mut();
                self.stack[next_idx - 1].control = 0;
            }
        }
    }

    /// Set a flag
    pub fn set_flag(&self, flag: u32) {
        self.flags.fetch_or(flag, Ordering::SeqCst);
    }

    /// Clear a flag
    pub fn clear_flag(&self, flag: u32) {
        self.flags.fetch_and(!flag, Ordering::SeqCst);
    }

    /// Check if a flag is set
    pub fn has_flag(&self, flag: u32) -> bool {
        (self.flags.load(Ordering::SeqCst) & flag) != 0
    }

    /// Mark IRP as pending
    pub fn mark_pending(&mut self) {
        self.set_flag(irp_flags::IRP_PENDING);
        self.pending_returned = true;
        if let Some(stack) = self.get_current_stack_location_mut() {
            stack.control |= sl_control::SL_PENDING_RETURNED;
        }
    }

    /// Check if IRP is pending
    pub fn is_pending(&self) -> bool {
        self.has_flag(irp_flags::IRP_PENDING)
    }
}

impl Default for Irp {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// IRP Pool (Static Allocation)
// ============================================================================

/// Maximum number of IRPs in the pool
pub const MAX_IRPS: usize = 128;

/// IRP pool
static mut IRP_POOL: [Irp; MAX_IRPS] = {
    const INIT: Irp = Irp::new();
    [INIT; MAX_IRPS]
};

/// IRP pool bitmap (2 u64s for 128 IRPs)
static mut IRP_POOL_BITMAP: [u64; 2] = [0; 2];

/// IRP pool lock
static IRP_POOL_LOCK: SpinLock<()> = SpinLock::new(());

/// Allocate an IRP
///
/// # Arguments
/// * `stack_size` - Number of stack locations needed
///
/// # Returns
/// Pointer to allocated IRP, or null if pool exhausted
pub unsafe fn io_allocate_irp(stack_size: i8) -> *mut Irp {
    if stack_size <= 0 || stack_size as usize > IRP_MAX_STACK_SIZE {
        return ptr::null_mut();
    }

    let _guard = IRP_POOL_LOCK.lock();

    for word_idx in 0..2 {
        if IRP_POOL_BITMAP[word_idx] != u64::MAX {
            for bit_idx in 0..64 {
                let global_idx = word_idx * 64 + bit_idx;
                if global_idx >= MAX_IRPS {
                    return ptr::null_mut();
                }
                if IRP_POOL_BITMAP[word_idx] & (1 << bit_idx) == 0 {
                    IRP_POOL_BITMAP[word_idx] |= 1 << bit_idx;
                    let irp = &mut IRP_POOL[global_idx] as *mut Irp;
                    (*irp).init(stack_size);
                    return irp;
                }
            }
        }
    }

    ptr::null_mut()
}

/// Free an IRP back to the pool
pub unsafe fn io_free_irp(irp: *mut Irp) {
    if irp.is_null() {
        return;
    }

    let _guard = IRP_POOL_LOCK.lock();

    let base = IRP_POOL.as_ptr() as usize;
    let offset = irp as usize - base;
    let index = offset / core::mem::size_of::<Irp>();

    if index < MAX_IRPS {
        let word_idx = index / 64;
        let bit_idx = index % 64;
        IRP_POOL_BITMAP[word_idx] &= !(1 << bit_idx);
    }
}

/// Initialize the IRP subsystem
pub unsafe fn init_irp_system() {
    crate::serial_println!("[IO] IRP subsystem initialized ({} IRPs available)", MAX_IRPS);
}
