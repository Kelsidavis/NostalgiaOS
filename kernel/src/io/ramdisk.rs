//! RAM Disk Driver
//!
//! Provides an in-memory block device for testing and temporary storage.
//! The RAM disk is backed by a static memory buffer and supports standard
//! block device operations.
//!
//! # Features
//! - Fixed-size memory backing store
//! - Full read/write support
//! - Multiple RAM disk instances
//! - No persistence (data lost on reboot)

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use super::block::{
    BlockStatus, BlockDeviceType, BlockOps, DiskGeometry,
    register_block_device, SECTOR_SIZE,
};

/// Default RAM disk size (4MB)
pub const DEFAULT_RAMDISK_SIZE: usize = 4 * 1024 * 1024;

/// Maximum RAM disk size (16MB)
pub const MAX_RAMDISK_SIZE: usize = 16 * 1024 * 1024;

/// Maximum number of RAM disks
pub const MAX_RAM_DISKS: usize = 4;

/// RAM disk instance data
struct RamDiskInstance {
    /// Whether this instance is in use
    active: AtomicBool,
    /// Block device index
    dev_index: AtomicU8,
    /// Size in bytes
    size: usize,
    /// Sector count
    sector_count: u64,
}

impl RamDiskInstance {
    const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            dev_index: AtomicU8::new(0xFF),
            size: 0,
            sector_count: 0,
        }
    }
}

/// RAM disk storage buffers (static allocation)
/// Each RAM disk gets 4MB of storage
static mut RAMDISK_BUFFERS: [[u8; DEFAULT_RAMDISK_SIZE]; MAX_RAM_DISKS] =
    [[0u8; DEFAULT_RAMDISK_SIZE]; MAX_RAM_DISKS];

/// RAM disk instances
static mut RAMDISK_INSTANCES: [RamDiskInstance; MAX_RAM_DISKS] = {
    const INIT: RamDiskInstance = RamDiskInstance::new();
    [INIT; MAX_RAM_DISKS]
};

/// RAM disk count
static RAMDISK_COUNT: AtomicU8 = AtomicU8::new(0);

// ============================================================================
// Block Device Operations
// ============================================================================

/// Read sectors from RAM disk
unsafe fn ramdisk_read(
    dev_index: u8,
    lba: u64,
    count: u32,
    buf: *mut u8,
) -> BlockStatus {
    // Find the RAM disk instance for this device index
    let instance_idx = find_instance_by_dev_index(dev_index);
    if instance_idx >= MAX_RAM_DISKS {
        return BlockStatus::NotFound;
    }

    let instance = &RAMDISK_INSTANCES[instance_idx];
    if !instance.active.load(Ordering::SeqCst) {
        return BlockStatus::NotFound;
    }

    // Validate request
    let end_sector = lba.saturating_add(count as u64);
    if end_sector > instance.sector_count {
        return BlockStatus::InvalidParameter;
    }

    // Calculate offsets
    let offset = (lba as usize) * SECTOR_SIZE;
    let byte_count = (count as usize) * SECTOR_SIZE;

    // Copy data to buffer
    let src = RAMDISK_BUFFERS[instance_idx].as_ptr().add(offset);
    core::ptr::copy_nonoverlapping(src, buf, byte_count);

    BlockStatus::Success
}

/// Write sectors to RAM disk
unsafe fn ramdisk_write(
    dev_index: u8,
    lba: u64,
    count: u32,
    buf: *const u8,
) -> BlockStatus {
    // Find the RAM disk instance for this device index
    let instance_idx = find_instance_by_dev_index(dev_index);
    if instance_idx >= MAX_RAM_DISKS {
        return BlockStatus::NotFound;
    }

    let instance = &RAMDISK_INSTANCES[instance_idx];
    if !instance.active.load(Ordering::SeqCst) {
        return BlockStatus::NotFound;
    }

    // Validate request
    let end_sector = lba.saturating_add(count as u64);
    if end_sector > instance.sector_count {
        return BlockStatus::InvalidParameter;
    }

    // Calculate offsets
    let offset = (lba as usize) * SECTOR_SIZE;
    let byte_count = (count as usize) * SECTOR_SIZE;

    // Copy data from buffer
    let dst = RAMDISK_BUFFERS[instance_idx].as_mut_ptr().add(offset);
    core::ptr::copy_nonoverlapping(buf, dst, byte_count);

    BlockStatus::Success
}

/// Flush RAM disk (no-op for RAM disk)
unsafe fn ramdisk_flush(_dev_index: u8) -> BlockStatus {
    // RAM disk has no cache to flush
    BlockStatus::Success
}

/// Get RAM disk geometry
unsafe fn ramdisk_get_geometry(dev_index: u8) -> DiskGeometry {
    let instance_idx = find_instance_by_dev_index(dev_index);
    if instance_idx >= MAX_RAM_DISKS {
        return DiskGeometry::empty();
    }

    let instance = &RAMDISK_INSTANCES[instance_idx];
    if !instance.active.load(Ordering::SeqCst) {
        return DiskGeometry::empty();
    }

    // Build geometry
    let total_sectors = instance.sector_count;
    let heads = 16;
    let sectors_per_track = 63;
    let cylinders = (total_sectors / (heads * sectors_per_track) as u64) as u32;

    DiskGeometry {
        total_sectors,
        sector_size: SECTOR_SIZE as u32,
        cylinders,
        heads,
        sectors_per_track,
    }
}

/// Check if RAM disk is ready
unsafe fn ramdisk_is_ready(dev_index: u8) -> bool {
    let instance_idx = find_instance_by_dev_index(dev_index);
    if instance_idx >= MAX_RAM_DISKS {
        return false;
    }

    RAMDISK_INSTANCES[instance_idx].active.load(Ordering::SeqCst)
}

/// Reset RAM disk (no-op)
unsafe fn ramdisk_reset(_dev_index: u8) -> BlockStatus {
    BlockStatus::Success
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Find RAM disk instance by block device index
fn find_instance_by_dev_index(dev_index: u8) -> usize {
    unsafe {
        for i in 0..MAX_RAM_DISKS {
            if RAMDISK_INSTANCES[i].active.load(Ordering::SeqCst) &&
               RAMDISK_INSTANCES[i].dev_index.load(Ordering::SeqCst) == dev_index {
                return i;
            }
        }
    }
    MAX_RAM_DISKS // Not found
}

/// Find a free RAM disk slot
fn find_free_slot() -> Option<usize> {
    unsafe {
        for i in 0..MAX_RAM_DISKS {
            if !RAMDISK_INSTANCES[i].active.load(Ordering::SeqCst) {
                return Some(i);
            }
        }
    }
    None
}

// ============================================================================
// Public API
// ============================================================================

/// Create a new RAM disk with default size (4MB)
///
/// Returns the block device index on success, or None if creation failed.
pub fn create_ramdisk() -> Option<u8> {
    create_ramdisk_with_size(DEFAULT_RAMDISK_SIZE)
}

/// Create a new RAM disk with specified size
///
/// Size will be rounded down to sector boundary and capped at MAX_RAMDISK_SIZE.
///
/// # Arguments
/// * `size` - Size in bytes (will be capped at DEFAULT_RAMDISK_SIZE due to static allocation)
///
/// # Returns
/// The block device index on success, or None if creation failed.
pub fn create_ramdisk_with_size(size: usize) -> Option<u8> {
    // Find a free slot
    let slot = find_free_slot()?;

    // Cap size at our static buffer size
    let actual_size = size.min(DEFAULT_RAMDISK_SIZE);
    let sector_count = (actual_size / SECTOR_SIZE) as u64;

    if sector_count == 0 {
        return None;
    }

    // Build geometry
    let heads = 16u32;
    let sectors_per_track = 63u32;
    let cylinders = (sector_count / (heads as u64 * sectors_per_track as u64)) as u32;

    let geometry = DiskGeometry {
        total_sectors: sector_count,
        sector_size: SECTOR_SIZE as u32,
        cylinders: cylinders.max(1),
        heads,
        sectors_per_track,
    };

    // Create operations vtable
    let ops = BlockOps {
        read: Some(ramdisk_read),
        write: Some(ramdisk_write),
        flush: Some(ramdisk_flush),
        get_geometry: Some(ramdisk_get_geometry),
        is_ready: Some(ramdisk_is_ready),
        reset: Some(ramdisk_reset),
    };

    // Register with block layer
    let dev_index = register_block_device(
        BlockDeviceType::RamDisk,
        0,                  // controller (N/A for RAM disk)
        slot as u8,         // device number
        geometry,
        ops,
        0,                  // no special flags
    )?;

    // Initialize our instance
    unsafe {
        let instance = &mut RAMDISK_INSTANCES[slot];
        instance.size = actual_size;
        instance.sector_count = sector_count;
        instance.dev_index.store(dev_index, Ordering::SeqCst);
        instance.active.store(true, Ordering::SeqCst);

        // Zero the buffer
        RAMDISK_BUFFERS[slot].fill(0);
    }

    RAMDISK_COUNT.fetch_add(1, Ordering::SeqCst);

    crate::serial_println!(
        "[RAMDISK] Created RAM disk {} ({} KB)",
        slot,
        actual_size / 1024
    );

    Some(dev_index)
}

/// Destroy a RAM disk by its block device index
///
/// # Arguments
/// * `dev_index` - Block device index returned from create_ramdisk
///
/// # Returns
/// true if destroyed successfully, false if not found
pub fn destroy_ramdisk(dev_index: u8) -> bool {
    let instance_idx = find_instance_by_dev_index(dev_index);
    if instance_idx >= MAX_RAM_DISKS {
        return false;
    }

    unsafe {
        let instance = &mut RAMDISK_INSTANCES[instance_idx];

        // Mark as inactive
        instance.active.store(false, Ordering::SeqCst);
        instance.dev_index.store(0xFF, Ordering::SeqCst);
        instance.size = 0;
        instance.sector_count = 0;

        // Zero the buffer for security
        RAMDISK_BUFFERS[instance_idx].fill(0);
    }

    // Unregister from block layer
    super::block::unregister_block_device(dev_index);

    RAMDISK_COUNT.fetch_sub(1, Ordering::SeqCst);

    crate::serial_println!("[RAMDISK] Destroyed RAM disk (dev {})", dev_index);

    true
}

/// Get the number of active RAM disks
pub fn ramdisk_count() -> u8 {
    RAMDISK_COUNT.load(Ordering::SeqCst)
}

/// Initialize the RAM disk subsystem
pub fn init() {
    crate::serial_println!("[RAMDISK] RAM disk driver initialized");
    crate::serial_println!("[RAMDISK]   Max disks: {}", MAX_RAM_DISKS);
    crate::serial_println!("[RAMDISK]   Max size per disk: {} KB", DEFAULT_RAMDISK_SIZE / 1024);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_create_destroy_ramdisk() {
        let dev_idx = create_ramdisk().expect("Failed to create RAM disk");
        assert!(destroy_ramdisk(dev_idx));
    }

    #[test_case]
    fn test_ramdisk_read_write() {
        let dev_idx = create_ramdisk().expect("Failed to create RAM disk");

        // Write test data
        let write_data = [0xABu8; 512];
        unsafe {
            let status = ramdisk_write(dev_idx, 0, 1, write_data.as_ptr());
            assert_eq!(status, BlockStatus::Success);
        }

        // Read it back
        let mut read_data = [0u8; 512];
        unsafe {
            let status = ramdisk_read(dev_idx, 0, 1, read_data.as_mut_ptr());
            assert_eq!(status, BlockStatus::Success);
        }

        assert_eq!(write_data, read_data);

        destroy_ramdisk(dev_idx);
    }
}
