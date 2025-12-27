//! Block Device Abstraction Layer
//!
//! Provides a unified interface for block devices (hard disks, SSDs, etc.)
//! Block devices transfer data in fixed-size blocks (typically 512 bytes).
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    File System Layer                         │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                Block Device Abstraction                      │
//! │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
//! │  │   BlockDev  │ │  BlockOps   │ │   DiskGeo   │            │
//! │  └─────────────┘ └─────────────┘ └─────────────┘            │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!          ┌───────────────────┼───────────────────┐
//!          ▼                   ▼                   ▼
//! ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
//! │    ATA/IDE      │ │     AHCI        │ │      NVMe       │
//! │    Driver       │ │    Driver       │ │     Driver      │
//! └─────────────────┘ └─────────────────┘ └─────────────────┘
//! ```

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// Maximum number of block devices
pub const MAX_BLOCK_DEVICES: usize = 16;

/// Default sector size
pub const SECTOR_SIZE: usize = 512;

/// Block device status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockStatus {
    /// Operation succeeded
    Success = 0,
    /// Device not found
    NotFound = 1,
    /// I/O error
    IoError = 2,
    /// Invalid parameter
    InvalidParameter = 3,
    /// Device busy
    Busy = 4,
    /// Media not present
    NoMedia = 5,
    /// Write protected
    WriteProtected = 6,
    /// Timeout
    Timeout = 7,
    /// Not ready
    NotReady = 8,
    /// Bad sector
    BadSector = 9,
}

/// Block device type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockDeviceType {
    /// Unknown device
    Unknown = 0,
    /// Hard disk drive
    HardDisk = 1,
    /// Solid state drive
    SSD = 2,
    /// CD/DVD-ROM
    Optical = 3,
    /// Floppy disk
    Floppy = 4,
    /// USB mass storage
    USB = 5,
    /// RAM disk
    RamDisk = 6,
    /// Network block device
    Network = 7,
}

impl Default for BlockDeviceType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Block device flags
pub mod block_flags {
    /// Device is removable
    pub const REMOVABLE: u32 = 0x0001;
    /// Device is read-only
    pub const READONLY: u32 = 0x0002;
    /// Device supports DMA
    pub const DMA: u32 = 0x0004;
    /// Device supports LBA48
    pub const LBA48: u32 = 0x0008;
    /// Device supports NCQ (Native Command Queuing)
    pub const NCQ: u32 = 0x0010;
    /// Device supports TRIM
    pub const TRIM: u32 = 0x0020;
    /// Device is present/online
    pub const PRESENT: u32 = 0x0100;
    /// Device is the boot device
    pub const BOOT: u32 = 0x0200;
}

/// Disk geometry information
#[derive(Debug, Clone, Copy)]
pub struct DiskGeometry {
    /// Total number of sectors
    pub total_sectors: u64,
    /// Bytes per sector
    pub sector_size: u32,
    /// Cylinders (CHS mode)
    pub cylinders: u32,
    /// Heads per cylinder (CHS mode)
    pub heads: u32,
    /// Sectors per track (CHS mode)
    pub sectors_per_track: u32,
}

impl DiskGeometry {
    pub const fn empty() -> Self {
        Self {
            total_sectors: 0,
            sector_size: SECTOR_SIZE as u32,
            cylinders: 0,
            heads: 0,
            sectors_per_track: 0,
        }
    }

    /// Get total size in bytes
    pub fn total_bytes(&self) -> u64 {
        self.total_sectors * self.sector_size as u64
    }

    /// Get size in megabytes
    pub fn size_mb(&self) -> u64 {
        self.total_bytes() / (1024 * 1024)
    }

    /// Get size in gigabytes
    pub fn size_gb(&self) -> u64 {
        self.total_bytes() / (1024 * 1024 * 1024)
    }

    /// Convert LBA to CHS
    pub fn lba_to_chs(&self, lba: u64) -> (u32, u32, u32) {
        if self.heads == 0 || self.sectors_per_track == 0 {
            return (0, 0, 0);
        }
        let temp = lba as u32;
        let sector = (temp % self.sectors_per_track) + 1;
        let temp = temp / self.sectors_per_track;
        let head = temp % self.heads;
        let cylinder = temp / self.heads;
        (cylinder, head, sector)
    }
}

impl Default for DiskGeometry {
    fn default() -> Self {
        Self::empty()
    }
}

/// Block device operations (vtable)
#[repr(C)]
pub struct BlockOps {
    /// Read sectors from device
    pub read: Option<unsafe fn(dev_index: u8, lba: u64, count: u32, buf: *mut u8) -> BlockStatus>,
    /// Write sectors to device
    pub write: Option<unsafe fn(dev_index: u8, lba: u64, count: u32, buf: *const u8) -> BlockStatus>,
    /// Flush device cache
    pub flush: Option<unsafe fn(dev_index: u8) -> BlockStatus>,
    /// Get device geometry
    pub get_geometry: Option<unsafe fn(dev_index: u8) -> DiskGeometry>,
    /// Check if device is ready
    pub is_ready: Option<unsafe fn(dev_index: u8) -> bool>,
    /// Reset device
    pub reset: Option<unsafe fn(dev_index: u8) -> BlockStatus>,
}

impl BlockOps {
    pub const fn empty() -> Self {
        Self {
            read: None,
            write: None,
            flush: None,
            get_geometry: None,
            is_ready: None,
            reset: None,
        }
    }
}

impl Default for BlockOps {
    fn default() -> Self {
        Self::empty()
    }
}

/// Block device information
#[repr(C)]
pub struct BlockDevice {
    /// Device is registered
    pub registered: bool,
    /// Device type
    pub device_type: BlockDeviceType,
    /// Device flags
    pub flags: u32,
    /// Device index
    pub index: u8,
    /// Controller index
    pub controller: u8,
    /// Device number on controller
    pub device_num: u8,
    /// Disk geometry
    pub geometry: DiskGeometry,
    /// Device operations
    pub ops: BlockOps,
    /// Device name (e.g., "hda", "sda")
    pub name: [u8; 16],
    /// Model string
    pub model: [u8; 48],
    /// Serial number
    pub serial: [u8; 24],
    /// Firmware revision
    pub firmware: [u8; 12],
    /// Read count
    pub reads: AtomicU64,
    /// Write count
    pub writes: AtomicU64,
    /// Sectors read
    pub sectors_read: AtomicU64,
    /// Sectors written
    pub sectors_written: AtomicU64,
    /// Error count
    pub errors: AtomicU32,
}

impl BlockDevice {
    pub const fn empty() -> Self {
        Self {
            registered: false,
            device_type: BlockDeviceType::Unknown,
            flags: 0,
            index: 0,
            controller: 0,
            device_num: 0,
            geometry: DiskGeometry::empty(),
            ops: BlockOps::empty(),
            name: [0; 16],
            model: [0; 48],
            serial: [0; 24],
            firmware: [0; 12],
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            sectors_read: AtomicU64::new(0),
            sectors_written: AtomicU64::new(0),
            errors: AtomicU32::new(0),
        }
    }

    /// Get device name as string
    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(16);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    /// Get model as string
    pub fn model_str(&self) -> &str {
        let len = self.model.iter().position(|&b| b == 0).unwrap_or(48);
        core::str::from_utf8(&self.model[..len]).unwrap_or("")
    }

    /// Get serial as string
    pub fn serial_str(&self) -> &str {
        let len = self.serial.iter().position(|&b| b == 0).unwrap_or(24);
        core::str::from_utf8(&self.serial[..len]).unwrap_or("")
    }

    /// Check if device is present
    pub fn is_present(&self) -> bool {
        (self.flags & block_flags::PRESENT) != 0
    }

    /// Check if device is removable
    pub fn is_removable(&self) -> bool {
        (self.flags & block_flags::REMOVABLE) != 0
    }

    /// Check if device is read-only
    pub fn is_readonly(&self) -> bool {
        (self.flags & block_flags::READONLY) != 0
    }

    /// Set device name
    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(15);
        self.name = [0; 16];
        self.name[..len].copy_from_slice(&bytes[..len]);
    }

    /// Set model string
    pub fn set_model(&mut self, model: &str) {
        let bytes = model.as_bytes();
        let len = bytes.len().min(47);
        self.model = [0; 48];
        self.model[..len].copy_from_slice(&bytes[..len]);
    }

    /// Set serial number
    pub fn set_serial(&mut self, serial: &str) {
        let bytes = serial.as_bytes();
        let len = bytes.len().min(23);
        self.serial = [0; 24];
        self.serial[..len].copy_from_slice(&bytes[..len]);
    }
}

impl Default for BlockDevice {
    fn default() -> Self {
        Self::empty()
    }
}

// Safety: Block device uses atomics for counters
unsafe impl Sync for BlockDevice {}
unsafe impl Send for BlockDevice {}

// ============================================================================
// Block Device Registry
// ============================================================================

/// Block device table
static mut BLOCK_DEVICES: [BlockDevice; MAX_BLOCK_DEVICES] = {
    const INIT: BlockDevice = BlockDevice::empty();
    [INIT; MAX_BLOCK_DEVICES]
};

/// Block device lock
static BLOCK_LOCK: SpinLock<()> = SpinLock::new(());

/// Device count
static DEVICE_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Block Device API
// ============================================================================

/// Register a block device
pub fn register_block_device(
    device_type: BlockDeviceType,
    controller: u8,
    device_num: u8,
    geometry: DiskGeometry,
    ops: BlockOps,
    flags: u32,
) -> Option<u8> {
    let _guard = BLOCK_LOCK.lock();

    unsafe {
        // Find free slot
        for i in 0..MAX_BLOCK_DEVICES {
            if !BLOCK_DEVICES[i].registered {
                let dev = &mut BLOCK_DEVICES[i];
                dev.registered = true;
                dev.device_type = device_type;
                dev.index = i as u8;
                dev.controller = controller;
                dev.device_num = device_num;
                dev.geometry = geometry;
                dev.ops = ops;
                dev.flags = flags | block_flags::PRESENT;

                // Generate device name
                let name = match device_type {
                    BlockDeviceType::HardDisk | BlockDeviceType::SSD => {
                        // hda, hdb, hdc... or sda, sdb, sdc...
                        let prefix = if device_type == BlockDeviceType::SSD { b's' } else { b'h' };
                        let letter = b'a' + (i as u8);
                        [prefix, b'd', letter, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                    }
                    BlockDeviceType::Optical => {
                        [b's', b'r', b'0' + (i as u8), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                    }
                    _ => {
                        [b'b', b'l', b'k', b'0' + (i as u8), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                    }
                };
                dev.name = name;

                DEVICE_COUNT.fetch_add(1, Ordering::SeqCst);

                crate::serial_println!(
                    "[BLOCK] Registered {} ({} MB)",
                    dev.name_str(),
                    geometry.size_mb()
                );

                return Some(i as u8);
            }
        }
    }

    None
}

/// Unregister a block device
pub fn unregister_block_device(index: u8) -> bool {
    if index as usize >= MAX_BLOCK_DEVICES {
        return false;
    }

    let _guard = BLOCK_LOCK.lock();

    unsafe {
        if BLOCK_DEVICES[index as usize].registered {
            BLOCK_DEVICES[index as usize] = BlockDevice::empty();
            DEVICE_COUNT.fetch_sub(1, Ordering::SeqCst);
            return true;
        }
    }

    false
}

/// Get block device by index
pub fn get_block_device(index: u8) -> Option<&'static BlockDevice> {
    if index as usize >= MAX_BLOCK_DEVICES {
        return None;
    }

    unsafe {
        let dev = &BLOCK_DEVICES[index as usize];
        if dev.registered {
            Some(dev)
        } else {
            None
        }
    }
}

/// Get mutable block device
pub fn get_block_device_mut(index: u8) -> Option<&'static mut BlockDevice> {
    if index as usize >= MAX_BLOCK_DEVICES {
        return None;
    }

    unsafe {
        let dev = &mut BLOCK_DEVICES[index as usize];
        if dev.registered {
            Some(dev)
        } else {
            None
        }
    }
}

/// Find block device by name
pub fn find_block_device(name: &str) -> Option<u8> {
    unsafe {
        for i in 0..MAX_BLOCK_DEVICES {
            if BLOCK_DEVICES[i].registered && BLOCK_DEVICES[i].name_str() == name {
                return Some(i as u8);
            }
        }
    }
    None
}

/// Get device count
pub fn device_count() -> u32 {
    DEVICE_COUNT.load(Ordering::SeqCst)
}

// ============================================================================
// Block I/O Operations
// ============================================================================

/// Read sectors from a block device
pub fn read_sectors(index: u8, lba: u64, count: u32, buf: &mut [u8]) -> BlockStatus {
    let dev = match get_block_device(index) {
        Some(d) => d,
        None => return BlockStatus::NotFound,
    };

    // Validate buffer size
    let required_size = count as usize * dev.geometry.sector_size as usize;
    if buf.len() < required_size {
        return BlockStatus::InvalidParameter;
    }

    // Check bounds
    if lba + count as u64 > dev.geometry.total_sectors {
        return BlockStatus::InvalidParameter;
    }

    // Call driver read function
    let read_fn = match dev.ops.read {
        Some(f) => f,
        None => return BlockStatus::IoError,
    };

    let status = unsafe { read_fn(index, lba, count, buf.as_mut_ptr()) };

    if status == BlockStatus::Success {
        dev.reads.fetch_add(1, Ordering::Relaxed);
        dev.sectors_read.fetch_add(count as u64, Ordering::Relaxed);
    } else {
        dev.errors.fetch_add(1, Ordering::Relaxed);
    }

    status
}

/// Write sectors to a block device
pub fn write_sectors(index: u8, lba: u64, count: u32, buf: &[u8]) -> BlockStatus {
    let dev = match get_block_device(index) {
        Some(d) => d,
        None => return BlockStatus::NotFound,
    };

    // Check write protection
    if dev.is_readonly() {
        return BlockStatus::WriteProtected;
    }

    // Validate buffer size
    let required_size = count as usize * dev.geometry.sector_size as usize;
    if buf.len() < required_size {
        return BlockStatus::InvalidParameter;
    }

    // Check bounds
    if lba + count as u64 > dev.geometry.total_sectors {
        return BlockStatus::InvalidParameter;
    }

    // Call driver write function
    let write_fn = match dev.ops.write {
        Some(f) => f,
        None => return BlockStatus::IoError,
    };

    let status = unsafe { write_fn(index, lba, count, buf.as_ptr()) };

    if status == BlockStatus::Success {
        dev.writes.fetch_add(1, Ordering::Relaxed);
        dev.sectors_written.fetch_add(count as u64, Ordering::Relaxed);
    } else {
        dev.errors.fetch_add(1, Ordering::Relaxed);
    }

    status
}

/// Flush device cache
pub fn flush_device(index: u8) -> BlockStatus {
    let dev = match get_block_device(index) {
        Some(d) => d,
        None => return BlockStatus::NotFound,
    };

    match dev.ops.flush {
        Some(f) => unsafe { f(index) },
        None => BlockStatus::Success, // No-op if not supported
    }
}

/// Check if device is ready
pub fn is_device_ready(index: u8) -> bool {
    let dev = match get_block_device(index) {
        Some(d) => d,
        None => return false,
    };

    match dev.ops.is_ready {
        Some(f) => unsafe { f(index) },
        None => dev.is_present(),
    }
}

/// Reset device
pub fn reset_device(index: u8) -> BlockStatus {
    let dev = match get_block_device(index) {
        Some(d) => d,
        None => return BlockStatus::NotFound,
    };

    match dev.ops.reset {
        Some(f) => unsafe { f(index) },
        None => BlockStatus::Success,
    }
}

// ============================================================================
// Convenience Functions for File System
// ============================================================================

/// Read a single sector (convenience wrapper)
pub fn read_sector(index: u8, lba: u64, buf: &mut [u8; SECTOR_SIZE]) -> bool {
    read_sectors(index, lba, 1, buf) == BlockStatus::Success
}

/// Write a single sector (convenience wrapper)
pub fn write_sector(index: u8, lba: u64, buf: &[u8; SECTOR_SIZE]) -> bool {
    write_sectors(index, lba, 1, buf) == BlockStatus::Success
}

/// Get block device for file system use
/// Returns a function pointer pair for read/write operations
pub fn get_fs_callbacks(index: u8) -> Option<(
    unsafe fn(*mut u8, u64, &mut [u8]) -> bool,
    unsafe fn(*mut u8, u64, &[u8]) -> bool,
)> {
    let dev = get_block_device(index)?;
    if !dev.is_present() {
        return None;
    }

    // Return wrapper functions
    Some((fs_read_sector, fs_write_sector))
}

/// File system read callback
unsafe fn fs_read_sector(device: *mut u8, sector: u64, buf: &mut [u8]) -> bool {
    let index = device as u8;
    read_sectors(index, sector, 1, buf) == BlockStatus::Success
}

/// File system write callback
unsafe fn fs_write_sector(device: *mut u8, sector: u64, buf: &[u8]) -> bool {
    let index = device as u8;
    write_sectors(index, sector, 1, buf) == BlockStatus::Success
}

// ============================================================================
// Statistics
// ============================================================================

/// Block device statistics
#[derive(Debug, Clone, Copy)]
pub struct BlockStats {
    /// Number of registered devices
    pub device_count: u32,
    /// Total reads across all devices
    pub total_reads: u64,
    /// Total writes across all devices
    pub total_writes: u64,
    /// Total sectors read
    pub total_sectors_read: u64,
    /// Total sectors written
    pub total_sectors_written: u64,
    /// Total errors
    pub total_errors: u32,
}

/// Get block device statistics
pub fn get_stats() -> BlockStats {
    let mut stats = BlockStats {
        device_count: device_count(),
        total_reads: 0,
        total_writes: 0,
        total_sectors_read: 0,
        total_sectors_written: 0,
        total_errors: 0,
    };

    unsafe {
        for dev in BLOCK_DEVICES.iter() {
            if dev.registered {
                stats.total_reads += dev.reads.load(Ordering::Relaxed);
                stats.total_writes += dev.writes.load(Ordering::Relaxed);
                stats.total_sectors_read += dev.sectors_read.load(Ordering::Relaxed);
                stats.total_sectors_written += dev.sectors_written.load(Ordering::Relaxed);
                stats.total_errors += dev.errors.load(Ordering::Relaxed);
            }
        }
    }

    stats
}

/// List all registered devices
pub fn list_devices() {
    crate::serial_println!("[BLOCK] Registered devices:");
    unsafe {
        for dev in BLOCK_DEVICES.iter() {
            if dev.registered {
                crate::serial_println!(
                    "  {}: {:?} {} MB ({})",
                    dev.name_str(),
                    dev.device_type,
                    dev.geometry.size_mb(),
                    dev.model_str()
                );
            }
        }
    }
}

/// Initialize block device subsystem
pub fn init() {
    crate::serial_println!("[BLOCK] Block device subsystem initialized ({} max devices)", MAX_BLOCK_DEVICES);
}
