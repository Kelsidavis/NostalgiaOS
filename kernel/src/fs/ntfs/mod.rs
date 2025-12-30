//! NTFS File System Driver
//!
//! Implements NTFS (New Technology File System) support for Nostalgia OS.
//! NTFS is the primary file system for Windows NT and later versions.
//!
//! # NTFS Features Supported
//! - Boot sector and BPB parsing
//! - Master File Table (MFT) reading
//! - File record parsing
//! - Attribute handling ($STANDARD_INFORMATION, $FILE_NAME, $DATA)
//! - Directory enumeration
//! - File reading (resident and non-resident data)
//!
//! # Key Structures
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Boot Sector (512 bytes)                   │
//! │  - BIOS Parameter Block                                      │
//! │  - MFT location                                              │
//! │  - Cluster/sector sizes                                      │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │              Master File Table (MFT)                         │
//! │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
//! │  │  $MFT   │ │$MFTMirr │ │ $LogFile│ │ $Volume │ ...        │
//! │  └─────────┘ └─────────┘ └─────────┘ └─────────┘           │
//! │                                                              │
//! │  Each MFT entry (FILE record) contains:                     │
//! │  - Standard header (FILE signature)                          │
//! │  - Sequence of attributes                                    │
//! │  - Each attribute: header + resident/non-resident data       │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # References
//! - Windows Internals, 6th Edition
//! - NTFS Documentation Project (ntfs.com)

pub mod boot;
pub mod mft;
pub mod attr;
pub mod file;

// Re-export commonly used items
pub use boot::{NtfsBootSector, NtfsBpb, NTFS_SIGNATURE};
pub use mft::{
    FileRecord, FileRecordHeader, MftRef,
    FILE_RECORD_MAGIC, MFT_RECORD_IN_USE, MFT_RECORD_IS_DIRECTORY,
    well_known_mft,
};
pub use attr::{
    AttributeHeader, AttributeType, ResidentHeader, NonResidentHeader,
    StandardInformation, FileName, DataRun,
    attr_types, file_name_types,
};
pub use file::{NtfsMount, ntfs_ops, ntfs_mount_count, mount_volume, get_mount};

use crate::fs::vfs::{vfs_register_fs, FsType};
use core::sync::atomic::{AtomicU16, Ordering};

/// NTFS file system driver name
pub const NTFS_NAME: &str = "ntfs";

/// VFS index of the NTFS driver (set during registration)
static NTFS_VFS_INDEX: AtomicU16 = AtomicU16::new(u16::MAX);

/// Get the NTFS driver's VFS index
pub fn vfs_index() -> Option<u16> {
    let idx = NTFS_VFS_INDEX.load(Ordering::Relaxed);
    if idx == u16::MAX {
        None
    } else {
        Some(idx)
    }
}

/// Register NTFS with VFS
pub fn register() {
    unsafe {
        let ops = file::ntfs_ops();
        if let Some(idx) = vfs_register_fs(NTFS_NAME, FsType::Ntfs, ops) {
            NTFS_VFS_INDEX.store(idx, Ordering::Relaxed);
            crate::serial_println!("[FS] NTFS driver registered with VFS (index={})", idx);
        } else {
            crate::serial_println!("[FS] Failed to register NTFS driver");
        }
    }
}

/// Initialize NTFS subsystem
pub fn init() {
    crate::serial_println!("[FS] NTFS driver initializing...");

    // Initialize sub-modules
    boot::init();
    mft::init();
    attr::init();
    file::init();

    // Register with VFS
    register();

    crate::serial_println!("[FS] NTFS driver initialized");
}

/// NTFS volume statistics
#[derive(Debug, Clone, Copy)]
pub struct NtfsStats {
    /// Number of mounted NTFS volumes
    pub mounted_volumes: u32,
    /// Bytes per cluster
    pub bytes_per_cluster: u32,
    /// Total clusters
    pub total_clusters: u64,
    /// Free clusters
    pub free_clusters: u64,
    /// MFT record size
    pub mft_record_size: u32,
}

impl NtfsStats {
    pub const fn empty() -> Self {
        Self {
            mounted_volumes: 0,
            bytes_per_cluster: 0,
            total_clusters: 0,
            free_clusters: 0,
            mft_record_size: 0,
        }
    }
}

/// Get NTFS statistics for a mounted volume
pub fn get_stats(mount_index: u16) -> Option<NtfsStats> {
    let mount = get_mount(mount_index)?;
    Some(NtfsStats {
        mounted_volumes: ntfs_mount_count() as u32,
        bytes_per_cluster: mount.bytes_per_cluster,
        total_clusters: mount.total_clusters,
        free_clusters: 0, // TODO: Read from $Bitmap
        mft_record_size: mount.mft_record_size,
    })
}
