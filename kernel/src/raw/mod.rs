//! RAW File System
//!
//! The RAW file system provides direct block access to unformatted or
//! unrecognized disk volumes. When no other file system can mount a volume,
//! the RAW file system is used to provide basic I/O access.
//!
//! # Overview
//!
//! Unlike traditional file systems, RAW:
//! - Has no directory structure
//! - Provides only the volume root as an accessible "file"
//! - Passes read/write requests directly to the underlying device
//! - Is always the last file system checked during mount
//!
//! # Device Objects
//!
//! RAW registers three device objects:
//! - `\Device\RawDisk` - For hard disk volumes
//! - `\Device\RawCdRom` - For CD-ROM volumes
//! - `\Device\RawTape` - For tape drives
//!
//! # Use Cases
//!
//! - Accessing unformatted partitions
//! - Low-level disk utilities (disk imaging, partitioning)
//! - Accessing volumes with damaged/unknown file systems
//! - Direct sector read/write operations

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;

pub mod vcb;
pub mod dispatch;

/// RAW file system signature
pub const RAW_SIGNATURE: u32 = 0x57415752; // 'RAWR'

/// RAW node type code for VCB
pub const RAW_NTC_VCB: u16 = 0x0501;

/// Device type constants
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawDeviceType {
    /// Disk file system
    Disk = 0x00000008,
    /// CD-ROM file system
    CdRom = 0x00000002,
    /// Tape file system
    Tape = 0x0000001F,
}

/// VCB (Volume Control Block) state flags
pub mod vcb_state {
    /// Volume is mounted
    pub const MOUNTED: u32 = 0x0001;
    /// Volume is locked
    pub const LOCKED: u32 = 0x0002;
    /// Dismount is pending
    pub const DISMOUNTED: u32 = 0x0004;
    /// Volume is read-only
    pub const READ_ONLY: u32 = 0x0008;
}

/// Maximum concurrent RAW volumes
pub const MAX_RAW_VOLUMES: usize = 32;

/// Maximum open handles per volume
pub const MAX_HANDLES_PER_VOLUME: usize = 16;

// ============================================================================
// Global State
// ============================================================================

/// RAW file system statistics
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawStats {
    /// Number of mounted volumes
    pub volumes_mounted: u32,
    /// Total read operations
    pub read_ops: u64,
    /// Total write operations
    pub write_ops: u64,
    /// Bytes read
    pub bytes_read: u64,
    /// Bytes written
    pub bytes_written: u64,
    /// Create operations
    pub create_ops: u64,
    /// Close operations
    pub close_ops: u64,
    /// Device control operations
    pub ioctl_ops: u64,
}

impl Default for RawStats {
    fn default() -> Self {
        Self::new()
    }
}

impl RawStats {
    pub const fn new() -> Self {
        Self {
            volumes_mounted: 0,
            read_ops: 0,
            write_ops: 0,
            bytes_read: 0,
            bytes_written: 0,
            create_ops: 0,
            close_ops: 0,
            ioctl_ops: 0,
        }
    }
}

/// Global RAW statistics
static mut RAW_STATS: RawStats = RawStats::new();

/// RAW initialized flag
static RAW_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// RAW file system lock
static RAW_LOCK: SpinLock<()> = SpinLock::new(());

/// Device objects for each RAW type
static mut RAW_DISK_DEVICE: usize = 0;
static mut RAW_CDROM_DEVICE: usize = 0;
static mut RAW_TAPE_DEVICE: usize = 0;

// ============================================================================
// RAW File System API
// ============================================================================

/// Initialize the RAW file system
pub fn init() {
    if RAW_INITIALIZED.swap(true, Ordering::AcqRel) {
        return; // Already initialized
    }

    unsafe {
        RAW_STATS = RawStats::new();
        RAW_DISK_DEVICE = 0;
        RAW_CDROM_DEVICE = 0;
        RAW_TAPE_DEVICE = 0;
    }

    // Initialize VCB pool
    vcb::init();

    // Initialize dispatch
    dispatch::init();

    crate::serial_println!("[RAW] RAW file system initialized");
}

/// Check if RAW is initialized
pub fn is_initialized() -> bool {
    RAW_INITIALIZED.load(Ordering::Acquire)
}

/// Get RAW statistics
pub fn get_stats() -> RawStats {
    unsafe { RAW_STATS }
}

/// Increment read stats
pub fn record_read(bytes: u64) {
    let _guard = RAW_LOCK.lock();
    unsafe {
        RAW_STATS.read_ops += 1;
        RAW_STATS.bytes_read += bytes;
    }
}

/// Increment write stats
pub fn record_write(bytes: u64) {
    let _guard = RAW_LOCK.lock();
    unsafe {
        RAW_STATS.write_ops += 1;
        RAW_STATS.bytes_written += bytes;
    }
}

/// Increment create stats
pub fn record_create() {
    let _guard = RAW_LOCK.lock();
    unsafe {
        RAW_STATS.create_ops += 1;
    }
}

/// Increment close stats
pub fn record_close() {
    let _guard = RAW_LOCK.lock();
    unsafe {
        RAW_STATS.close_ops += 1;
    }
}

/// Increment ioctl stats
pub fn record_ioctl() {
    let _guard = RAW_LOCK.lock();
    unsafe {
        RAW_STATS.ioctl_ops += 1;
    }
}

/// Increment mounted volumes
pub fn record_mount() {
    let _guard = RAW_LOCK.lock();
    unsafe {
        RAW_STATS.volumes_mounted += 1;
    }
}

/// Decrement mounted volumes
pub fn record_dismount() {
    let _guard = RAW_LOCK.lock();
    unsafe {
        if RAW_STATS.volumes_mounted > 0 {
            RAW_STATS.volumes_mounted -= 1;
        }
    }
}

// ============================================================================
// Volume Operations
// ============================================================================

/// Mount a raw volume
///
/// Returns the VCB index on success.
pub fn raw_mount(target_device: usize, device_type: RawDeviceType) -> Result<usize, i32> {
    if !is_initialized() {
        return Err(-1); // STATUS_NOT_INITIALIZED
    }

    let vcb_idx = vcb::allocate_vcb(target_device, device_type)?;
    record_mount();

    Ok(vcb_idx)
}

/// Dismount a raw volume
pub fn raw_dismount(vcb_idx: usize) -> Result<(), i32> {
    vcb::free_vcb(vcb_idx)?;
    record_dismount();
    Ok(())
}

/// Get volume size
pub fn raw_get_volume_size(vcb_idx: usize) -> Option<u64> {
    vcb::get_volume_size(vcb_idx)
}

/// Set volume size
pub fn raw_set_volume_size(vcb_idx: usize, size: u64) -> Result<(), i32> {
    vcb::set_volume_size(vcb_idx, size)
}

/// Read from raw volume
pub fn raw_read(vcb_idx: usize, offset: u64, buffer: &mut [u8]) -> Result<usize, i32> {
    let bytes = dispatch::raw_read_write(vcb_idx, offset, buffer, false)?;
    record_read(bytes as u64);
    Ok(bytes)
}

/// Write to raw volume
pub fn raw_write(vcb_idx: usize, offset: u64, buffer: &[u8]) -> Result<usize, i32> {
    // Need mutable buffer reference for the dispatch function even though we're writing
    let bytes = dispatch::raw_read_write_const(vcb_idx, offset, buffer)?;
    record_write(bytes as u64);
    Ok(bytes)
}

/// Open a handle to raw volume
pub fn raw_open(vcb_idx: usize) -> Result<u32, i32> {
    record_create();
    dispatch::raw_create(vcb_idx)
}

/// Close a handle to raw volume
pub fn raw_close(vcb_idx: usize, handle: u32) -> Result<(), i32> {
    record_close();
    dispatch::raw_close(vcb_idx, handle)
}

/// Device control operation
pub fn raw_ioctl(vcb_idx: usize, code: u32, in_buf: &[u8], out_buf: &mut [u8]) -> Result<usize, i32> {
    record_ioctl();
    dispatch::raw_device_control(vcb_idx, code, in_buf, out_buf)
}

// ============================================================================
// Query Operations
// ============================================================================

/// Query volume information
pub fn raw_query_volume_info(vcb_idx: usize) -> Option<RawVolumeInfo> {
    let vcb = vcb::get_vcb(vcb_idx)?;
    Some(RawVolumeInfo {
        device_type: vcb.device_type,
        state: vcb.state,
        volume_size: vcb.volume_size,
        sector_size: vcb.sector_size,
        open_count: vcb.open_count,
    })
}

/// Volume information
#[derive(Debug, Clone, Copy)]
pub struct RawVolumeInfo {
    pub device_type: RawDeviceType,
    pub state: u32,
    pub volume_size: u64,
    pub sector_size: u32,
    pub open_count: u32,
}

/// List mounted raw volumes
pub fn raw_list_volumes() -> ([usize; MAX_RAW_VOLUMES], usize) {
    vcb::list_active_vcbs()
}

// ============================================================================
// File System Recognition
// ============================================================================

/// Check if a volume should use RAW
///
/// RAW is used when no other file system recognizes the volume.
/// This is typically called after all other file systems have failed.
pub fn raw_recognize_volume(_sector0: &[u8]) -> bool {
    // RAW always "recognizes" a volume as a fallback
    // In NT, this is the last file system checked
    true
}

/// File system type identifier for RAW
pub const RAW_FS_TYPE: u32 = 0x52415746; // 'RAWF'

// ============================================================================
// IRP Major Function Codes (for compatibility)
// ============================================================================

pub mod irp_mj {
    pub const CREATE: u8 = 0x00;
    pub const CLOSE: u8 = 0x02;
    pub const READ: u8 = 0x03;
    pub const WRITE: u8 = 0x04;
    pub const QUERY_INFORMATION: u8 = 0x05;
    pub const SET_INFORMATION: u8 = 0x06;
    pub const QUERY_VOLUME_INFORMATION: u8 = 0x0A;
    pub const FILE_SYSTEM_CONTROL: u8 = 0x0D;
    pub const DEVICE_CONTROL: u8 = 0x0E;
    pub const CLEANUP: u8 = 0x12;
    pub const PNP: u8 = 0x1B;
    pub const SHUTDOWN: u8 = 0x10;
}

/// File system control minor codes
pub mod fsctl_mn {
    pub const MOUNT_VOLUME: u8 = 0x01;
    pub const DISMOUNT_VOLUME: u8 = 0x02;
    pub const USER_FS_REQUEST: u8 = 0x00;
}
