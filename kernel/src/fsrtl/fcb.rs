//! File Control Block (FCB) Header Structures
//!
//! Provides the common FCB header used by file systems for cache manager
//! integration and fast I/O support.
//!
//! The FCB header contains:
//! - File size information (allocation, file size, valid data length)
//! - Resource pointers for synchronization
//! - Flags for fast I/O eligibility
//!
//! This implementation is NT 5.2 (Windows Server 2003) compatible.

use core::ptr;
use crate::ex::resource::EResource;

/// Fast I/O possibility states
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FastIoPossible {
    /// Fast I/O is not possible (always go through IRP path)
    FastIoIsNotPossible = 0,
    /// Fast I/O is possible (can use fast path)
    FastIoIsPossible = 1,
    /// Fast I/O may or may not be possible (need to check)
    FastIoIsQuestionable = 2,
}

/// FSRTL flags (first set)
#[allow(non_snake_case)]
pub mod FsrtlFlags {
    /// File has been modified
    pub const FILE_MODIFIED: u8 = 0x01;
    /// File length has changed
    pub const FILE_LENGTH_CHANGED: u8 = 0x02;
    /// Limit modified page writes
    pub const LIMIT_MODIFIED_PAGES: u8 = 0x04;
    /// Acquire main resource exclusive for paging I/O
    pub const ACQUIRE_MAIN_RSRC_EX: u8 = 0x08;
    /// Acquire main resource shared for paging I/O
    pub const ACQUIRE_MAIN_RSRC_SH: u8 = 0x10;
    /// File is user-mapped (memory mapped by user)
    pub const USER_MAPPED_FILE: u8 = 0x20;
    /// Using advanced FCB header
    pub const ADVANCED_HEADER: u8 = 0x40;
    /// EOF advance is active
    pub const EOF_ADVANCE_ACTIVE: u8 = 0x80;
}

/// FSRTL flags (second set)
#[allow(non_snake_case)]
pub mod FsrtlFlags2 {
    /// Do modified page write
    pub const DO_MODIFIED_WRITE: u8 = 0x01;
    /// Supports filter contexts
    pub const SUPPORTS_FILTER_CONTEXTS: u8 = 0x02;
    /// Purge file when mapped
    pub const PURGE_WHEN_MAPPED: u8 = 0x04;
    /// Is a paging file
    pub const IS_PAGING_FILE: u8 = 0x08;
}

/// Common FCB Header
///
/// This is the header that must be at the start of every file system's
/// stream context (FCB/SCB) structure for cache manager integration.
#[repr(C)]
pub struct FsrtlCommonFcbHeader {
    /// Node type code (file system specific)
    pub node_type_code: i16,
    /// Size of this structure in bytes
    pub node_byte_size: i16,
    /// First set of flags
    pub flags: u8,
    /// Fast I/O possibility state
    pub is_fast_io_possible: u8,
    /// Second set of flags
    pub flags2: u8,
    /// Reserved
    _reserved: u8,
    /// Main resource for file synchronization (read/write)
    pub resource: *mut EResource,
    /// Paging I/O resource
    pub paging_io_resource: *mut EResource,
    /// Allocated size of file (on disk)
    pub allocation_size: i64,
    /// Current file size (logical end of file)
    pub file_size: i64,
    /// Valid data length (how much data is actually valid)
    pub valid_data_length: i64,
}

impl FsrtlCommonFcbHeader {
    /// Create a new empty FCB header
    pub const fn new() -> Self {
        Self {
            node_type_code: 0,
            node_byte_size: 0,
            flags: 0,
            is_fast_io_possible: FastIoPossible::FastIoIsNotPossible as u8,
            flags2: 0,
            _reserved: 0,
            resource: ptr::null_mut(),
            paging_io_resource: ptr::null_mut(),
            allocation_size: 0,
            file_size: 0,
            valid_data_length: 0,
        }
    }

    /// Initialize the FCB header
    pub fn init(&mut self, node_type: i16, node_size: i16) {
        self.node_type_code = node_type;
        self.node_byte_size = node_size;
        self.flags = 0;
        self.is_fast_io_possible = FastIoPossible::FastIoIsNotPossible as u8;
        self.flags2 = 0;
        self.resource = ptr::null_mut();
        self.paging_io_resource = ptr::null_mut();
        self.allocation_size = 0;
        self.file_size = 0;
        self.valid_data_length = 0;
    }

    /// Check if fast I/O is possible
    pub fn fast_io_possible(&self) -> FastIoPossible {
        match self.is_fast_io_possible {
            0 => FastIoPossible::FastIoIsNotPossible,
            1 => FastIoPossible::FastIoIsPossible,
            _ => FastIoPossible::FastIoIsQuestionable,
        }
    }

    /// Set fast I/O possibility
    pub fn set_fast_io_possible(&mut self, possible: FastIoPossible) {
        self.is_fast_io_possible = possible as u8;
    }
}

impl Default for FsrtlCommonFcbHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// Advanced FCB Header
///
/// Extended header with additional fields for filter driver support.
#[repr(C)]
pub struct FsrtlAdvancedFcbHeader {
    /// Common header (must be first)
    pub common: FsrtlCommonFcbHeader,
    /// Fast mutex for filter context synchronization
    pub fast_mutex: *mut crate::ex::fast_mutex::FastMutex,
    /// List of per-stream filter contexts
    pub filter_contexts: crate::ke::list::ListEntry,
    /// Push lock for synchronization
    pub push_lock: u64,
    /// File object that opened this FCB (for oplocks)
    pub file_object_c: *mut u8,
}

impl FsrtlAdvancedFcbHeader {
    /// Create a new empty advanced FCB header
    pub const fn new() -> Self {
        Self {
            common: FsrtlCommonFcbHeader::new(),
            fast_mutex: ptr::null_mut(),
            filter_contexts: crate::ke::list::ListEntry::new(),
            push_lock: 0,
            file_object_c: ptr::null_mut(),
        }
    }

    /// Initialize the advanced FCB header
    pub fn init(&mut self, node_type: i16, node_size: i16) {
        self.common.init(node_type, node_size);
        self.common.flags |= FsrtlFlags::ADVANCED_HEADER;
        self.common.flags2 |= FsrtlFlags2::SUPPORTS_FILTER_CONTEXTS;
        self.fast_mutex = ptr::null_mut();
        self.filter_contexts.init_head();
        self.push_lock = 0;
        self.file_object_c = ptr::null_mut();
    }
}

impl Default for FsrtlAdvancedFcbHeader {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Fast I/O Copy Functions
// ============================================================================

/// Copy read from cache
///
/// Performs a cached read operation without going through the IRP path.
///
/// # Returns
/// Number of bytes read, or error
pub fn fsrtl_copy_read(
    _fcb: &FsrtlCommonFcbHeader,
    _file_offset: i64,
    _length: u32,
    _wait: bool,
    _buffer: *mut u8,
    _bytes_read: &mut u32,
) -> bool {
    // TODO: Integrate with cache manager when available
    // For now, return false to fall back to IRP path
    false
}

/// Copy write to cache
///
/// Performs a cached write operation without going through the IRP path.
///
/// # Returns
/// Number of bytes written, or error
pub fn fsrtl_copy_write(
    _fcb: &mut FsrtlCommonFcbHeader,
    _file_offset: i64,
    _length: u32,
    _wait: bool,
    _buffer: *const u8,
    _bytes_written: &mut u32,
) -> bool {
    // TODO: Integrate with cache manager when available
    // For now, return false to fall back to IRP path
    false
}

/// Get file size
pub fn fsrtl_get_file_size(fcb: &FsrtlCommonFcbHeader) -> i64 {
    fcb.file_size
}

/// Set file size
///
/// Updates file size and triggers cache manager notification.
pub fn fsrtl_set_file_size(fcb: &mut FsrtlCommonFcbHeader, new_size: i64) {
    let old_size = fcb.file_size;
    fcb.file_size = new_size;

    if new_size != old_size {
        fcb.flags |= FsrtlFlags::FILE_LENGTH_CHANGED;
    }

    // Ensure valid data length doesn't exceed file size
    if fcb.valid_data_length > new_size {
        fcb.valid_data_length = new_size;
    }

    // TODO: Notify cache manager of size change
}

/// Extend valid data length
pub fn fsrtl_extend_valid_data_length(fcb: &mut FsrtlCommonFcbHeader, new_valid: i64) -> bool {
    if new_valid > fcb.file_size {
        return false;
    }

    if new_valid > fcb.valid_data_length {
        fcb.valid_data_length = new_valid;
        fcb.flags |= FsrtlFlags::FILE_MODIFIED;
    }

    true
}
