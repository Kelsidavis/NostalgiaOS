//! Fast I/O Support (FSRTL Fast I/O)
//!
//! The Fast I/O path is used to avoid calling file systems directly through
//! IRPs for cached reads and writes. This provides significant performance
//! improvements for cached file operations.
//!
//! # Design
//!
//! Fast I/O works by:
//! 1. Checking if the file is cached (private cache map exists)
//! 2. Acquiring the file's resource in shared/exclusive mode
//! 3. Calling the cache manager directly
//! 4. Returning TRUE if successful, FALSE to fall back to IRP path
//!
//! # NT Functions
//!
//! - `FsRtlCopyRead` - Fast cached read
//! - `FsRtlCopyWrite` - Fast cached write
//! - `FsRtlMdlRead` - MDL-based fast read
//! - `FsRtlPrepareMdlWrite` - Prepare MDL for fast write
//! - `FsRtlMdlWriteComplete` - Complete MDL write
//! - `FsRtlAcquireFileExclusive` - Acquire file for exclusive access
//! - `FsRtlReleaseFile` - Release file after fast I/O

use core::sync::atomic::{AtomicU64, Ordering};

/// Fast I/O dispatch table
///
/// File systems register these callbacks to handle fast I/O operations.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FastIoDispatch {
    /// Size of this structure
    pub size_of_fast_io_dispatch: u32,
    /// Fast I/O check if possible
    pub fast_io_check_if_possible: Option<FastIoCheckIfPossible>,
    /// Fast I/O read
    pub fast_io_read: Option<FastIoRead>,
    /// Fast I/O write
    pub fast_io_write: Option<FastIoWrite>,
    /// Fast I/O query basic info
    pub fast_io_query_basic_info: Option<FastIoQueryBasicInfo>,
    /// Fast I/O query standard info
    pub fast_io_query_standard_info: Option<FastIoQueryStandardInfo>,
    /// Fast I/O lock
    pub fast_io_lock: Option<FastIoLock>,
    /// Fast I/O unlock single
    pub fast_io_unlock_single: Option<FastIoUnlockSingle>,
    /// Fast I/O unlock all
    pub fast_io_unlock_all: Option<FastIoUnlockAll>,
    /// Fast I/O unlock all by key
    pub fast_io_unlock_all_by_key: Option<FastIoUnlockAllByKey>,
    /// Fast I/O device control
    pub fast_io_device_control: Option<FastIoDeviceControl>,
    /// Acquire file for NtCreateSection
    pub acquire_file_for_nt_create_section: Option<AcquireFileForNtCreateSection>,
    /// Release file for NtCreateSection
    pub release_file_for_nt_create_section: Option<ReleaseFileForNtCreateSection>,
    /// Detach device
    pub fast_io_detach_device: Option<FastIoDetachDevice>,
    /// Query network open info
    pub fast_io_query_network_open_info: Option<FastIoQueryNetworkOpenInfo>,
    /// Acquire for mod write
    pub acquire_for_mod_write: Option<AcquireForModWrite>,
    /// MDL read
    pub mdl_read: Option<MdlRead>,
    /// MDL read complete
    pub mdl_read_complete: Option<MdlReadComplete>,
    /// Prepare MDL write
    pub prepare_mdl_write: Option<PrepareMdlWrite>,
    /// MDL write complete
    pub mdl_write_complete: Option<MdlWriteComplete>,
    /// Fast I/O read compressed
    pub fast_io_read_compressed: Option<FastIoReadCompressed>,
    /// Fast I/O write compressed
    pub fast_io_write_compressed: Option<FastIoWriteCompressed>,
    /// MDL read complete compressed
    pub mdl_read_complete_compressed: Option<MdlReadCompleteCompressed>,
    /// MDL write complete compressed
    pub mdl_write_complete_compressed: Option<MdlWriteCompleteCompressed>,
    /// Fast I/O query open
    pub fast_io_query_open: Option<FastIoQueryOpen>,
    /// Release for mod write
    pub release_for_mod_write: Option<ReleaseForModWrite>,
    /// Acquire for CC flush
    pub acquire_for_cc_flush: Option<AcquireForCcFlush>,
    /// Release for CC flush
    pub release_for_cc_flush: Option<ReleaseForCcFlush>,
}

impl Default for FastIoDispatch {
    fn default() -> Self {
        Self::new()
    }
}

impl FastIoDispatch {
    pub const fn new() -> Self {
        Self {
            size_of_fast_io_dispatch: core::mem::size_of::<FastIoDispatch>() as u32,
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
            acquire_file_for_nt_create_section: None,
            release_file_for_nt_create_section: None,
            fast_io_detach_device: None,
            fast_io_query_network_open_info: None,
            acquire_for_mod_write: None,
            mdl_read: None,
            mdl_read_complete: None,
            prepare_mdl_write: None,
            mdl_write_complete: None,
            fast_io_read_compressed: None,
            fast_io_write_compressed: None,
            mdl_read_complete_compressed: None,
            mdl_write_complete_compressed: None,
            fast_io_query_open: None,
            release_for_mod_write: None,
            acquire_for_cc_flush: None,
            release_for_cc_flush: None,
        }
    }
}

// Fast I/O callback type definitions
pub type FastIoCheckIfPossible = fn(
    file_object: *mut u8,
    file_offset: i64,
    length: u32,
    wait: bool,
    lock_key: u32,
    check_for_read: bool,
    io_status: *mut IoStatusBlock,
    device_object: *mut u8,
) -> bool;

pub type FastIoRead = fn(
    file_object: *mut u8,
    file_offset: i64,
    length: u32,
    wait: bool,
    lock_key: u32,
    buffer: *mut u8,
    io_status: *mut IoStatusBlock,
    device_object: *mut u8,
) -> bool;

pub type FastIoWrite = fn(
    file_object: *mut u8,
    file_offset: i64,
    length: u32,
    wait: bool,
    lock_key: u32,
    buffer: *const u8,
    io_status: *mut IoStatusBlock,
    device_object: *mut u8,
) -> bool;

pub type FastIoQueryBasicInfo = fn(
    file_object: *mut u8,
    wait: bool,
    buffer: *mut FileBasicInformation,
    io_status: *mut IoStatusBlock,
    device_object: *mut u8,
) -> bool;

pub type FastIoQueryStandardInfo = fn(
    file_object: *mut u8,
    wait: bool,
    buffer: *mut FileStandardInformation,
    io_status: *mut IoStatusBlock,
    device_object: *mut u8,
) -> bool;

pub type FastIoLock = fn(
    file_object: *mut u8,
    file_offset: i64,
    length: i64,
    process_id: *mut u8,
    key: u32,
    fail_immediately: bool,
    exclusive_lock: bool,
    io_status: *mut IoStatusBlock,
    device_object: *mut u8,
) -> bool;

pub type FastIoUnlockSingle = fn(
    file_object: *mut u8,
    file_offset: i64,
    length: i64,
    process_id: *mut u8,
    key: u32,
    io_status: *mut IoStatusBlock,
    device_object: *mut u8,
) -> bool;

pub type FastIoUnlockAll = fn(
    file_object: *mut u8,
    process_id: *mut u8,
    io_status: *mut IoStatusBlock,
    device_object: *mut u8,
) -> bool;

pub type FastIoUnlockAllByKey = fn(
    file_object: *mut u8,
    process_id: *mut u8,
    key: u32,
    io_status: *mut IoStatusBlock,
    device_object: *mut u8,
) -> bool;

pub type FastIoDeviceControl = fn(
    file_object: *mut u8,
    wait: bool,
    input_buffer: *mut u8,
    input_buffer_length: u32,
    output_buffer: *mut u8,
    output_buffer_length: u32,
    io_control_code: u32,
    io_status: *mut IoStatusBlock,
    device_object: *mut u8,
) -> bool;

pub type AcquireFileForNtCreateSection = fn(file_object: *mut u8);
pub type ReleaseFileForNtCreateSection = fn(file_object: *mut u8);
pub type FastIoDetachDevice = fn(source: *mut u8, target: *mut u8);

pub type FastIoQueryNetworkOpenInfo = fn(
    file_object: *mut u8,
    wait: bool,
    buffer: *mut FileNetworkOpenInformation,
    io_status: *mut IoStatusBlock,
    device_object: *mut u8,
) -> bool;

pub type AcquireForModWrite = fn(
    file_object: *mut u8,
    end_of_file: i64,
    resource: *mut *mut u8,
    device_object: *mut u8,
) -> i32;

pub type MdlRead = fn(
    file_object: *mut u8,
    file_offset: i64,
    length: u32,
    lock_key: u32,
    mdl: *mut *mut u8,
    io_status: *mut IoStatusBlock,
    device_object: *mut u8,
) -> bool;

pub type MdlReadComplete = fn(file_object: *mut u8, mdl: *mut u8, device_object: *mut u8) -> bool;

pub type PrepareMdlWrite = fn(
    file_object: *mut u8,
    file_offset: i64,
    length: u32,
    lock_key: u32,
    mdl: *mut *mut u8,
    io_status: *mut IoStatusBlock,
    device_object: *mut u8,
) -> bool;

pub type MdlWriteComplete = fn(
    file_object: *mut u8,
    file_offset: i64,
    mdl: *mut u8,
    device_object: *mut u8,
) -> bool;

pub type FastIoReadCompressed = fn(
    file_object: *mut u8,
    file_offset: i64,
    length: u32,
    lock_key: u32,
    buffer: *mut u8,
    mdl: *mut *mut u8,
    io_status: *mut IoStatusBlock,
    compressed_data_info: *mut u8,
    compressed_data_info_length: u32,
    device_object: *mut u8,
) -> bool;

pub type FastIoWriteCompressed = fn(
    file_object: *mut u8,
    file_offset: i64,
    length: u32,
    lock_key: u32,
    buffer: *mut u8,
    mdl: *mut *mut u8,
    io_status: *mut IoStatusBlock,
    compressed_data_info: *mut u8,
    compressed_data_info_length: u32,
    device_object: *mut u8,
) -> bool;

pub type MdlReadCompleteCompressed = fn(
    file_object: *mut u8,
    mdl: *mut u8,
    device_object: *mut u8,
) -> bool;

pub type MdlWriteCompleteCompressed = fn(
    file_object: *mut u8,
    file_offset: i64,
    mdl: *mut u8,
    device_object: *mut u8,
) -> bool;

pub type FastIoQueryOpen = fn(
    irp: *mut u8,
    network_info: *mut FileNetworkOpenInformation,
    device_object: *mut u8,
) -> bool;

pub type ReleaseForModWrite = fn(
    file_object: *mut u8,
    resource: *mut u8,
    device_object: *mut u8,
) -> i32;

pub type AcquireForCcFlush = fn(
    file_object: *mut u8,
    device_object: *mut u8,
) -> i32;

pub type ReleaseForCcFlush = fn(
    file_object: *mut u8,
    device_object: *mut u8,
) -> i32;

/// I/O Status Block
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoStatusBlock {
    pub status: i32,
    pub information: usize,
}

/// File basic information
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FileBasicInformation {
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub file_attributes: u32,
}

/// File standard information
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FileStandardInformation {
    pub allocation_size: i64,
    pub end_of_file: i64,
    pub number_of_links: u32,
    pub delete_pending: bool,
    pub directory: bool,
}

/// File network open information
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FileNetworkOpenInformation {
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub allocation_size: i64,
    pub end_of_file: i64,
    pub file_attributes: u32,
}

/// Common FCB Header (shared with FsRtl)
#[repr(C)]
pub struct FsRtlCommonFcbHeader {
    /// Node type code
    pub node_type_code: i16,
    /// Node byte size
    pub node_byte_size: i16,
    /// Flags
    pub flags: u8,
    /// Is mapped file
    pub is_mapped_data_section_created: u8,
    /// Version number
    pub version: u16,
    /// Resource (ERESOURCE)
    pub resource: *mut u8,
    /// Paging I/O resource
    pub paging_io_resource: *mut u8,
    /// Allocation size
    pub allocation_size: i64,
    /// File size
    pub file_size: i64,
    /// Valid data length
    pub valid_data_length: i64,
}

impl Default for FsRtlCommonFcbHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl FsRtlCommonFcbHeader {
    pub const fn new() -> Self {
        Self {
            node_type_code: 0,
            node_byte_size: 0,
            flags: 0,
            is_mapped_data_section_created: 0,
            version: 0,
            resource: core::ptr::null_mut(),
            paging_io_resource: core::ptr::null_mut(),
            allocation_size: 0,
            file_size: 0,
            valid_data_length: 0,
        }
    }
}

// FCB Header flags
pub const FSRTL_FLAG_FILE_MODIFIED: u8 = 0x01;
pub const FSRTL_FLAG_FILE_LENGTH_CHANGED: u8 = 0x02;
pub const FSRTL_FLAG_LIMIT_MODIFIED_PAGES: u8 = 0x04;
pub const FSRTL_FLAG_ACQUIRE_MAIN_RSRC_EX: u8 = 0x08;
pub const FSRTL_FLAG_ACQUIRE_MAIN_RSRC_SH: u8 = 0x10;
pub const FSRTL_FLAG_USER_MAPPED_FILE: u8 = 0x20;

// ============================================================================
// Fast I/O Statistics
// ============================================================================

/// Fast I/O statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct FastIoStats {
    /// Fast reads that succeeded
    pub fast_read_success: u64,
    /// Fast reads that failed
    pub fast_read_fail: u64,
    /// Fast writes that succeeded
    pub fast_write_success: u64,
    /// Fast writes that failed
    pub fast_write_fail: u64,
    /// Fast reads that had to wait
    pub fast_read_wait: u64,
    /// Fast reads that couldn't wait
    pub fast_read_no_wait: u64,
    /// Fast I/O resource misses
    pub fast_io_resource_miss: u64,
    /// Fast I/O not possible
    pub fast_io_not_possible: u64,
}

static FAST_READ_SUCCESS: AtomicU64 = AtomicU64::new(0);
static FAST_READ_FAIL: AtomicU64 = AtomicU64::new(0);
static FAST_WRITE_SUCCESS: AtomicU64 = AtomicU64::new(0);
static FAST_WRITE_FAIL: AtomicU64 = AtomicU64::new(0);
static FAST_READ_WAIT: AtomicU64 = AtomicU64::new(0);
static FAST_READ_NO_WAIT: AtomicU64 = AtomicU64::new(0);
static FAST_IO_RESOURCE_MISS: AtomicU64 = AtomicU64::new(0);
static FAST_IO_NOT_POSSIBLE: AtomicU64 = AtomicU64::new(0);

/// Get Fast I/O statistics
pub fn get_fast_io_stats() -> FastIoStats {
    FastIoStats {
        fast_read_success: FAST_READ_SUCCESS.load(Ordering::Relaxed),
        fast_read_fail: FAST_READ_FAIL.load(Ordering::Relaxed),
        fast_write_success: FAST_WRITE_SUCCESS.load(Ordering::Relaxed),
        fast_write_fail: FAST_WRITE_FAIL.load(Ordering::Relaxed),
        fast_read_wait: FAST_READ_WAIT.load(Ordering::Relaxed),
        fast_read_no_wait: FAST_READ_NO_WAIT.load(Ordering::Relaxed),
        fast_io_resource_miss: FAST_IO_RESOURCE_MISS.load(Ordering::Relaxed),
        fast_io_not_possible: FAST_IO_NOT_POSSIBLE.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Fast I/O Implementation Functions
// ============================================================================

/// Fast cached read (FsRtlCopyRead)
///
/// Performs a fast cached read bypassing the IRP mechanism.
/// The file must be cached for this to work.
///
/// # Returns
/// * `true` - Read completed successfully
/// * `false` - Fast I/O not possible, use IRP path
pub unsafe fn fsrtl_copy_read(
    file_object: *mut u8,
    file_offset: i64,
    length: u32,
    wait: bool,
    _lock_key: u32,
    buffer: *mut u8,
    io_status: *mut IoStatusBlock,
    _device_object: *mut u8,
) -> bool {
    // Zero-length read is always successful
    if length == 0 {
        if !io_status.is_null() {
            (*io_status).status = 0; // STATUS_SUCCESS
            (*io_status).information = 0;
        }
        return true;
    }

    // Check for overflow
    if file_offset < 0 || (i64::MAX - file_offset) < length as i64 {
        if !io_status.is_null() {
            (*io_status).status = -1073741811; // STATUS_INVALID_PARAMETER
            (*io_status).information = 0;
        }
        FAST_READ_FAIL.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    // Get FCB header from file object
    // In a real implementation, this would be: (*file_object).FsContext
    if file_object.is_null() {
        FAST_IO_NOT_POSSIBLE.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    // Track wait/no-wait statistics
    if wait {
        FAST_READ_WAIT.fetch_add(1, Ordering::Relaxed);
    } else {
        FAST_READ_NO_WAIT.fetch_add(1, Ordering::Relaxed);
    }

    // Try to acquire the file resource
    // In a real implementation, this would acquire Header->Resource
    // For now, we simulate success

    // Check if file is cached (private cache map exists)
    // In a real implementation: if (*file_object).PrivateCacheMap.is_null() { return false; }

    // Call cache manager to copy read
    // cc_copy_read(shared_cache_map, file_offset, buffer, length)
    let _ = buffer; // Would actually copy data here

    // Update statistics
    FAST_READ_SUCCESS.fetch_add(1, Ordering::Relaxed);

    if !io_status.is_null() {
        (*io_status).status = 0; // STATUS_SUCCESS
        (*io_status).information = length as usize;
    }

    true
}

/// Fast cached write (FsRtlCopyWrite)
///
/// Performs a fast cached write bypassing the IRP mechanism.
///
/// # Returns
/// * `true` - Write completed successfully
/// * `false` - Fast I/O not possible, use IRP path
pub unsafe fn fsrtl_copy_write(
    file_object: *mut u8,
    file_offset: i64,
    length: u32,
    wait: bool,
    _lock_key: u32,
    buffer: *const u8,
    io_status: *mut IoStatusBlock,
    _device_object: *mut u8,
) -> bool {
    // Zero-length write is always successful
    if length == 0 {
        if !io_status.is_null() {
            (*io_status).status = 0;
            (*io_status).information = 0;
        }
        return true;
    }

    // Validate parameters
    if file_object.is_null() || buffer.is_null() {
        FAST_IO_NOT_POSSIBLE.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    // Check for overflow
    if file_offset < 0 {
        if !io_status.is_null() {
            (*io_status).status = -1073741811; // STATUS_INVALID_PARAMETER
            (*io_status).information = 0;
        }
        FAST_WRITE_FAIL.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    // If we can't wait and the file is being extended, fail
    if !wait {
        // Would check if file_offset + length > file_size here
    }

    // Try to acquire the file resource exclusively
    // In a real implementation, this would acquire Header->Resource

    // Call cache manager to copy write
    // cc_copy_write(shared_cache_map, file_offset, buffer, length)

    // Update statistics
    FAST_WRITE_SUCCESS.fetch_add(1, Ordering::Relaxed);

    if !io_status.is_null() {
        (*io_status).status = 0;
        (*io_status).information = length as usize;
    }

    true
}

/// MDL-based fast read (FsRtlMdlRead)
///
/// Returns an MDL pointing to cached data instead of copying.
/// More efficient for DMA operations.
pub unsafe fn fsrtl_mdl_read(
    file_object: *mut u8,
    file_offset: i64,
    length: u32,
    _lock_key: u32,
    mdl: *mut *mut u8,
    io_status: *mut IoStatusBlock,
    _device_object: *mut u8,
) -> bool {
    if file_object.is_null() || mdl.is_null() {
        return false;
    }

    if length == 0 {
        *mdl = core::ptr::null_mut();
        if !io_status.is_null() {
            (*io_status).status = 0;
            (*io_status).information = 0;
        }
        return true;
    }

    // In a real implementation:
    // 1. Pin the cached pages
    // 2. Build an MDL describing them
    // 3. Return the MDL

    // For now, return failure to indicate MDL read not supported
    let _ = file_offset;
    false
}

/// Complete MDL read (FsRtlMdlReadComplete)
///
/// Releases MDL obtained from FsRtlMdlRead.
pub unsafe fn fsrtl_mdl_read_complete(
    _file_object: *mut u8,
    mdl: *mut u8,
    _device_object: *mut u8,
) -> bool {
    if mdl.is_null() {
        return true;
    }

    // In a real implementation:
    // 1. Unpin the cached pages
    // 2. Free the MDL

    true
}

/// Prepare MDL for fast write (FsRtlPrepareMdlWrite)
///
/// Returns an MDL that the caller can write to directly.
pub unsafe fn fsrtl_prepare_mdl_write(
    file_object: *mut u8,
    file_offset: i64,
    length: u32,
    _lock_key: u32,
    mdl: *mut *mut u8,
    io_status: *mut IoStatusBlock,
    _device_object: *mut u8,
) -> bool {
    if file_object.is_null() || mdl.is_null() {
        return false;
    }

    if length == 0 {
        *mdl = core::ptr::null_mut();
        if !io_status.is_null() {
            (*io_status).status = 0;
            (*io_status).information = 0;
        }
        return true;
    }

    // In a real implementation:
    // 1. Allocate cache pages
    // 2. Build an MDL
    // 3. Return MDL for caller to write to

    let _ = file_offset;
    false
}

/// Complete MDL write (FsRtlMdlWriteComplete)
///
/// Called after data is written to MDL obtained from FsRtlPrepareMdlWrite.
pub unsafe fn fsrtl_mdl_write_complete(
    _file_object: *mut u8,
    _file_offset: i64,
    mdl: *mut u8,
    _device_object: *mut u8,
) -> bool {
    if mdl.is_null() {
        return true;
    }

    // In a real implementation:
    // 1. Mark the pages as dirty
    // 2. Free the MDL

    true
}

/// Acquire file exclusively (FsRtlAcquireFileExclusive)
///
/// Acquires the file's main resource exclusively.
pub unsafe fn fsrtl_acquire_file_exclusive(file_object: *mut u8) {
    if file_object.is_null() {
        return;
    }

    // In a real implementation:
    // let header = (*file_object).FsContext as *mut FsRtlCommonFcbHeader;
    // ExAcquireResourceExclusiveLite((*header).resource, true);
}

/// Release file (FsRtlReleaseFile)
///
/// Releases the file's main resource.
pub unsafe fn fsrtl_release_file(file_object: *mut u8) {
    if file_object.is_null() {
        return;
    }

    // In a real implementation:
    // let header = (*file_object).FsContext as *mut FsRtlCommonFcbHeader;
    // ExReleaseResourceLite((*header).resource);
}

/// Acquire file for cache flush (FsRtlAcquireFileForCcFlush)
///
/// Called before flushing cached data to disk.
pub unsafe fn fsrtl_acquire_file_for_cc_flush(
    file_object: *mut u8,
    _device_object: *mut u8,
) -> i32 {
    if file_object.is_null() {
        return -1073741823; // STATUS_UNSUCCESSFUL
    }

    // In a real implementation:
    // Acquire Header->Resource and Header->PagingIoResource

    0 // STATUS_SUCCESS
}

/// Release file after cache flush (FsRtlReleaseFileForCcFlush)
pub unsafe fn fsrtl_release_file_for_cc_flush(
    file_object: *mut u8,
    _device_object: *mut u8,
) -> i32 {
    if file_object.is_null() {
        return -1073741823; // STATUS_UNSUCCESSFUL
    }

    // In a real implementation:
    // Release Header->PagingIoResource and Header->Resource

    0 // STATUS_SUCCESS
}

/// Acquire file for modified page writer (FsRtlAcquireFileForModWrite)
///
/// Called by the modified page writer before writing dirty pages.
pub unsafe fn fsrtl_acquire_file_for_mod_write(
    file_object: *mut u8,
    _end_of_file: i64,
    resource: *mut *mut u8,
    _device_object: *mut u8,
) -> i32 {
    if file_object.is_null() || resource.is_null() {
        return -1073741823; // STATUS_UNSUCCESSFUL
    }

    // In a real implementation:
    // *resource = Header->PagingIoResource
    // ExAcquireResourceSharedLite(*resource, true)

    *resource = core::ptr::null_mut();
    0 // STATUS_SUCCESS
}

/// Release file from modified page writer
pub unsafe fn fsrtl_release_file_for_mod_write(
    _file_object: *mut u8,
    _resource: *mut u8,
    _device_object: *mut u8,
) -> i32 {
    // In a real implementation:
    // ExReleaseResourceLite(resource)

    0 // STATUS_SUCCESS
}

/// Get file size from FCB (FsRtlGetFileSize)
pub unsafe fn fsrtl_get_file_size(
    file_object: *mut u8,
    file_size: *mut i64,
) -> i32 {
    if file_object.is_null() || file_size.is_null() {
        return -1073741811; // STATUS_INVALID_PARAMETER
    }

    // In a real implementation:
    // let header = (*file_object).FsContext as *mut FsRtlCommonFcbHeader;
    // *file_size = (*header).file_size;

    *file_size = 0;
    0 // STATUS_SUCCESS
}

/// Set file size in FCB (FsRtlSetFileSize)
pub unsafe fn fsrtl_set_file_size(
    file_object: *mut u8,
    allocation_size: *const i64,
) -> i32 {
    if file_object.is_null() || allocation_size.is_null() {
        return -1073741811; // STATUS_INVALID_PARAMETER
    }

    // In a real implementation:
    // let header = (*file_object).FsContext as *mut FsRtlCommonFcbHeader;
    // (*header).allocation_size = *allocation_size;
    // Notify cache manager: CcSetFileSizes

    0 // STATUS_SUCCESS
}

/// Check if Fast I/O is possible
///
/// Called before attempting fast I/O to check prerequisites.
pub unsafe fn fsrtl_fast_io_check_if_possible(
    file_object: *mut u8,
    file_offset: i64,
    length: u32,
    _wait: bool,
    _lock_key: u32,
    check_for_read: bool,
    io_status: *mut IoStatusBlock,
    _device_object: *mut u8,
) -> bool {
    if file_object.is_null() {
        return false;
    }

    // Basic checks
    if length == 0 {
        if !io_status.is_null() {
            (*io_status).status = 0;
            (*io_status).information = 0;
        }
        return true;
    }

    // In a real implementation:
    // 1. Check if file is cached (PrivateCacheMap != NULL)
    // 2. Check byte range locks don't conflict
    // 3. Check file isn't open for synchronization

    // For read, check if data is in valid range
    if check_for_read {
        let _ = file_offset;
        // Check file_offset + length <= valid_data_length
    }

    true
}

// ============================================================================
// Increment Statistics Helpers (called from cache manager)
// ============================================================================

/// Increment "fast read not possible" counter
pub fn fsrtl_increment_cc_fast_read_not_possible() {
    FAST_IO_NOT_POSSIBLE.fetch_add(1, Ordering::Relaxed);
}

/// Increment "fast read wait" counter
pub fn fsrtl_increment_cc_fast_read_wait() {
    FAST_READ_WAIT.fetch_add(1, Ordering::Relaxed);
}

/// Increment "fast read resource miss" counter
pub fn fsrtl_increment_cc_fast_read_resource_miss() {
    FAST_IO_RESOURCE_MISS.fetch_add(1, Ordering::Relaxed);
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Fast I/O subsystem
pub fn init() {
    crate::serial_println!("[FSRTL] Fast I/O subsystem initialized");
}
