//! File Object Implementation
//!
//! File objects represent open instances of files, devices, or other
//! I/O resources. When a process opens a file, a file object is created
//! to track the open state including:
//! - Current file position
//! - Access mode (read, write, etc.)
//! - Sharing mode
//! - File locks
//!
//! # File Object vs Handle
//! A handle is a process-local reference to a file object. Multiple
//! handles can reference the same file object (via DuplicateHandle).

use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::{list::ListEntry, SpinLock, KEvent};
use crate::ob::ObjectHeader;
use super::device::DeviceObject;

/// Maximum file name length
pub const FILE_NAME_LENGTH: usize = 256;

/// File flags
pub mod file_flags {
    /// File opened for read access
    pub const FO_FILE_OPEN: u32 = 0x00000001;
    /// Synchronous I/O
    pub const FO_SYNCHRONOUS_IO: u32 = 0x00000002;
    /// Alertable I/O
    pub const FO_ALERTABLE_IO: u32 = 0x00000004;
    /// No intermediate buffering
    pub const FO_NO_INTERMEDIATE_BUFFERING: u32 = 0x00000008;
    /// Write through
    pub const FO_WRITE_THROUGH: u32 = 0x00000010;
    /// Sequential only
    pub const FO_SEQUENTIAL_ONLY: u32 = 0x00000020;
    /// Cache supported
    pub const FO_CACHE_SUPPORTED: u32 = 0x00000040;
    /// Named pipe
    pub const FO_NAMED_PIPE: u32 = 0x00000080;
    /// Stream file
    pub const FO_STREAM_FILE: u32 = 0x00000100;
    /// Mailslot
    pub const FO_MAILSLOT: u32 = 0x00000200;
    /// File modified
    pub const FO_FILE_MODIFIED: u32 = 0x00001000;
    /// File size changed
    pub const FO_FILE_SIZE_CHANGED: u32 = 0x00002000;
    /// Cleanup complete
    pub const FO_CLEANUP_COMPLETE: u32 = 0x00004000;
    /// Temporary file
    pub const FO_TEMPORARY_FILE: u32 = 0x00008000;
    /// Delete on close
    pub const FO_DELETE_ON_CLOSE: u32 = 0x00010000;
    /// Opened by file ID
    pub const FO_OPENED_CASE_SENSITIVE: u32 = 0x00020000;
    /// Handle created
    pub const FO_HANDLE_CREATED: u32 = 0x00040000;
    /// File fast I/O read
    pub const FO_FILE_FAST_IO_READ: u32 = 0x00080000;
    /// Random access
    pub const FO_RANDOM_ACCESS: u32 = 0x00100000;
    /// File open cancelled
    pub const FO_FILE_OPEN_CANCELLED: u32 = 0x00200000;
    /// Volume open
    pub const FO_VOLUME_OPEN: u32 = 0x00400000;
    /// Remote origin
    pub const FO_REMOTE_ORIGIN: u32 = 0x01000000;
}

/// File access rights
pub mod file_access {
    /// Read data
    pub const FILE_READ_DATA: u32 = 0x0001;
    /// Write data
    pub const FILE_WRITE_DATA: u32 = 0x0002;
    /// Append data
    pub const FILE_APPEND_DATA: u32 = 0x0004;
    /// Read EA
    pub const FILE_READ_EA: u32 = 0x0008;
    /// Write EA
    pub const FILE_WRITE_EA: u32 = 0x0010;
    /// Execute
    pub const FILE_EXECUTE: u32 = 0x0020;
    /// Delete child
    pub const FILE_DELETE_CHILD: u32 = 0x0040;
    /// Read attributes
    pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    /// Write attributes
    pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    /// All access
    pub const FILE_ALL_ACCESS: u32 = 0x001F01FF;
    /// Generic read
    pub const FILE_GENERIC_READ: u32 = 0x00120089;
    /// Generic write
    pub const FILE_GENERIC_WRITE: u32 = 0x00120116;
    /// Generic execute
    pub const FILE_GENERIC_EXECUTE: u32 = 0x001200A0;
}

/// File share modes
pub mod file_share {
    /// Share read
    pub const FILE_SHARE_READ: u32 = 0x00000001;
    /// Share write
    pub const FILE_SHARE_WRITE: u32 = 0x00000002;
    /// Share delete
    pub const FILE_SHARE_DELETE: u32 = 0x00000004;
}

/// File Object structure
#[repr(C)]
pub struct FileObject {
    /// Object header (for object manager integration)
    pub header: ObjectHeader,

    /// Type identifier
    pub type_id: u16,
    /// Size of structure
    pub size: u16,

    /// Device object this file is on
    pub device_object: *mut DeviceObject,

    /// Volume parameter block (for file systems)
    pub vpb: *mut u8,

    /// FS context (opaque to I/O manager)
    pub fs_context: *mut u8,

    /// FS context 2
    pub fs_context2: *mut u8,

    /// Section object pointer (for memory-mapped files)
    pub section_object_pointer: *mut u8,

    /// Private cache map
    pub private_cache_map: *mut u8,

    /// Final status from create
    pub final_status: i32,

    /// Related file object (for relative opens)
    pub related_file_object: *mut FileObject,

    /// Lock held
    pub lock_operation: bool,

    /// Delete pending
    pub delete_pending: bool,

    /// Read access granted
    pub read_access: bool,

    /// Write access granted
    pub write_access: bool,

    /// Delete access granted
    pub delete_access: bool,

    /// Shared read access
    pub shared_read: bool,

    /// Shared write access
    pub shared_write: bool,

    /// Shared delete access
    pub shared_delete: bool,

    /// File object flags
    pub flags: AtomicU32,

    /// File name
    pub file_name: [u8; FILE_NAME_LENGTH],

    /// File name length
    pub file_name_length: u16,

    /// Current byte offset
    pub current_byte_offset: AtomicU64,

    /// Waiters (for synchronous I/O)
    pub waiters: AtomicU32,

    /// Busy count
    pub busy: AtomicU32,

    /// Last lock (for file locking)
    pub last_lock: *mut u8,

    /// Lock event
    pub lock: KEvent,

    /// Event for synchronous I/O completion
    pub event: KEvent,

    /// Completion context (for async I/O)
    pub completion_context: *mut CompletionContext,

    /// Spin lock
    pub irp_list_lock: SpinLock<()>,

    /// IRP list (pending IRPs on this file)
    pub irp_list: ListEntry,
}

// Safety: FileObject uses atomic operations and locks
unsafe impl Sync for FileObject {}
unsafe impl Send for FileObject {}

impl FileObject {
    /// Create a new file object
    pub const fn new() -> Self {
        Self {
            header: ObjectHeader::new(),
            type_id: 0x0005, // IO_TYPE_FILE
            size: 0,
            device_object: ptr::null_mut(),
            vpb: ptr::null_mut(),
            fs_context: ptr::null_mut(),
            fs_context2: ptr::null_mut(),
            section_object_pointer: ptr::null_mut(),
            private_cache_map: ptr::null_mut(),
            final_status: 0,
            related_file_object: ptr::null_mut(),
            lock_operation: false,
            delete_pending: false,
            read_access: false,
            write_access: false,
            delete_access: false,
            shared_read: false,
            shared_write: false,
            shared_delete: false,
            flags: AtomicU32::new(0),
            file_name: [0; FILE_NAME_LENGTH],
            file_name_length: 0,
            current_byte_offset: AtomicU64::new(0),
            waiters: AtomicU32::new(0),
            busy: AtomicU32::new(0),
            last_lock: ptr::null_mut(),
            lock: KEvent::new(),
            event: KEvent::new(),
            completion_context: ptr::null_mut(),
            irp_list_lock: SpinLock::new(()),
            irp_list: ListEntry::new(),
        }
    }

    /// Initialize a file object
    pub unsafe fn init(
        &mut self,
        device: *mut DeviceObject,
        name: Option<&[u8]>,
        access: u32,
        share: u32,
    ) {
        self.device_object = device;

        // Set name if provided
        if let Some(n) = name {
            let len = n.len().min(FILE_NAME_LENGTH - 1);
            self.file_name[..len].copy_from_slice(&n[..len]);
            self.file_name[len] = 0;
            self.file_name_length = len as u16;
        }

        // Set access rights
        self.read_access = (access & file_access::FILE_READ_DATA) != 0;
        self.write_access = (access & file_access::FILE_WRITE_DATA) != 0;
        self.delete_access = (access & 0x00010000) != 0; // DELETE

        // Set share mode
        self.shared_read = (share & file_share::FILE_SHARE_READ) != 0;
        self.shared_write = (share & file_share::FILE_SHARE_WRITE) != 0;
        self.shared_delete = (share & file_share::FILE_SHARE_DELETE) != 0;

        // Initialize events
        self.lock.init(crate::ke::EventType::Notification, false);
        self.event.init(crate::ke::EventType::Notification, true);

        // Initialize IRP list
        self.irp_list.init_head();

        // Mark as open
        self.set_flag(file_flags::FO_FILE_OPEN);
    }

    /// Get the file name
    pub fn name(&self) -> &[u8] {
        &self.file_name[..self.file_name_length as usize]
    }

    /// Get current file position
    pub fn position(&self) -> u64 {
        self.current_byte_offset.load(Ordering::SeqCst)
    }

    /// Set current file position
    pub fn set_position(&self, offset: u64) {
        self.current_byte_offset.store(offset, Ordering::SeqCst);
    }

    /// Advance file position
    pub fn advance_position(&self, amount: u64) {
        self.current_byte_offset.fetch_add(amount, Ordering::SeqCst);
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

    /// Check if file is open
    pub fn is_open(&self) -> bool {
        self.has_flag(file_flags::FO_FILE_OPEN)
    }

    /// Check if synchronous I/O
    pub fn is_synchronous(&self) -> bool {
        self.has_flag(file_flags::FO_SYNCHRONOUS_IO)
    }
}

impl Default for FileObject {
    fn default() -> Self {
        Self::new()
    }
}

/// Completion context for async I/O
#[repr(C)]
pub struct CompletionContext {
    /// Completion port
    pub port: *mut u8,
    /// Completion key
    pub key: *mut u8,
}

impl CompletionContext {
    pub const fn new() -> Self {
        Self {
            port: ptr::null_mut(),
            key: ptr::null_mut(),
        }
    }
}

// ============================================================================
// File Object Pool
// ============================================================================

/// Maximum number of file objects
pub const MAX_FILES: usize = 256;

/// File object pool
static mut FILE_POOL: [FileObject; MAX_FILES] = {
    const INIT: FileObject = FileObject::new();
    [INIT; MAX_FILES]
};

/// File pool bitmap (4 u64s for 256 files)
static mut FILE_POOL_BITMAP: [u64; 4] = [0; 4];

/// File pool lock
static FILE_POOL_LOCK: SpinLock<()> = SpinLock::new(());

/// Create a file object
///
/// # Arguments
/// * `device` - Device object
/// * `name` - File name
/// * `access` - Desired access
/// * `share` - Share mode
///
/// # Returns
/// Pointer to file object, or null on failure
pub unsafe fn io_create_file_object(
    device: *mut DeviceObject,
    name: Option<&[u8]>,
    access: u32,
    share: u32,
) -> *mut FileObject {
    let _guard = FILE_POOL_LOCK.lock();

    for word_idx in 0..4 {
        if FILE_POOL_BITMAP[word_idx] != u64::MAX {
            for bit_idx in 0..64 {
                let global_idx = word_idx * 64 + bit_idx;
                if global_idx >= MAX_FILES {
                    return ptr::null_mut();
                }
                if FILE_POOL_BITMAP[word_idx] & (1 << bit_idx) == 0 {
                    FILE_POOL_BITMAP[word_idx] |= 1 << bit_idx;
                    let file = &mut FILE_POOL[global_idx] as *mut FileObject;
                    (*file) = FileObject::new();
                    (*file).init(device, name, access, share);
                    return file;
                }
            }
        }
    }

    ptr::null_mut()
}

/// Close/free a file object
pub unsafe fn io_close_file_object(file: *mut FileObject) {
    if file.is_null() {
        return;
    }

    let _guard = FILE_POOL_LOCK.lock();

    // Clear flags
    (*file).clear_flag(file_flags::FO_FILE_OPEN);

    let base = FILE_POOL.as_ptr() as usize;
    let offset = file as usize - base;
    let index = offset / core::mem::size_of::<FileObject>();

    if index < MAX_FILES {
        let word_idx = index / 64;
        let bit_idx = index % 64;
        FILE_POOL_BITMAP[word_idx] &= !(1 << bit_idx);
    }
}

/// Initialize file object subsystem
pub unsafe fn init_file_system() {
    crate::serial_println!("[IO] File object subsystem initialized ({} files available)", MAX_FILES);
}
