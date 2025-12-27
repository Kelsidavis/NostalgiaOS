//! FAT32 File System Driver
//!
//! Implements FAT32 file system support for Nostalgia OS.
//! This driver provides:
//! - FAT32 volume mounting
//! - Directory traversal
//! - File reading/writing
//! - Long File Name (LFN) support
//!
//! # Structure
//! - `bpb` - BIOS Parameter Block and boot sector
//! - `dir` - Directory entry structures
//! - `file` - File operations and VFS interface

pub mod bpb;
pub mod dir;
pub mod file;

// Re-export commonly used items
pub use bpb::{Fat32BootSector, BiosParameterBlock, Fat32ExtendedBpb, FatType, FsInfo};
pub use bpb::cluster_values;
pub use dir::{FatDirEntry, LfnDirEntry, file_attr, entry_status, lfn_checksum};
pub use dir::{DIR_ENTRY_SIZE, MAX_LFN_LENGTH, LFN_CHARS_PER_ENTRY};
pub use file::{Fat32Mount, fat32_ops, fat32_mount_count, mount_volume, get_mount};

use crate::fs::vfs::{vfs_register_fs, FsType};
use core::sync::atomic::{AtomicU16, Ordering};

/// FAT32 file system driver name
pub const FAT32_NAME: &str = "fat32";

/// VFS index of the FAT32 driver (set during registration)
static FAT32_VFS_INDEX: AtomicU16 = AtomicU16::new(u16::MAX);

/// Get the FAT32 driver's VFS index
pub fn vfs_index() -> Option<u16> {
    let idx = FAT32_VFS_INDEX.load(Ordering::Relaxed);
    if idx == u16::MAX {
        None
    } else {
        Some(idx)
    }
}

/// Register FAT32 with VFS
pub fn register() {
    unsafe {
        let ops = file::fat32_ops();
        if let Some(idx) = vfs_register_fs(FAT32_NAME, FsType::Fat32, ops) {
            FAT32_VFS_INDEX.store(idx, Ordering::Relaxed);
            crate::serial_println!("[FS] FAT32 driver registered with VFS (index={})", idx);
        } else {
            crate::serial_println!("[FS] Failed to register FAT32 driver");
        }
    }
}

/// Initialize FAT32 subsystem
pub fn init() {
    crate::serial_println!("[FS] FAT32 driver initializing...");

    // Initialize sub-modules
    bpb::init();
    dir::init();
    file::init();

    // Register with VFS
    register();

    crate::serial_println!("[FS] FAT32 driver initialized");
}
