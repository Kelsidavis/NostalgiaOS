//! FAT32 File System Driver
//!
//! Implements FAT32 file system based on Windows Server 2003 fastfat implementation.
//!
//! # On-Disk Structures
//! - Boot sector with BIOS Parameter Block (BPB)
//! - FSInfo sector for free cluster tracking
//! - File Allocation Table (FAT) - cluster chain
//! - Directory entries (32 bytes each)
//!
//! # Reference
//! Windows Server 2003: base/fs/fastfat/fat.h

use crate::ke::SpinLock;
use super::disk::{volume_read, volume_write, get_volume};
use super::block::SECTOR_SIZE;

/// Maximum mounted FAT32 volumes
pub const MAX_FAT_VOLUMES: usize = 8;

/// Maximum files per directory listing
pub const MAX_DIR_ENTRIES: usize = 256;

/// Maximum open files
pub const MAX_OPEN_FILES: usize = 64;

/// Maximum path length
pub const MAX_PATH_LEN: usize = 260;

// ============================================================================
// On-Disk Structures (packed, from Windows Server 2003)
// ============================================================================

/// BIOS Parameter Block (FAT32 extended)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BiosParameterBlock {
    /// Bytes per sector (typically 512)
    pub bytes_per_sector: u16,
    /// Sectors per cluster (1, 2, 4, 8, 16, 32, 64, 128)
    pub sectors_per_cluster: u8,
    /// Reserved sectors (before first FAT)
    pub reserved_sectors: u16,
    /// Number of FATs (typically 2)
    pub fats: u8,
    /// Root entries (0 for FAT32)
    pub root_entries: u16,
    /// Total sectors (0 if > 65535)
    pub sectors: u16,
    /// Media type (0xF8 = hard disk)
    pub media: u8,
    /// Sectors per FAT (0 for FAT32)
    pub sectors_per_fat: u16,
    /// Sectors per track (CHS)
    pub sectors_per_track: u16,
    /// Number of heads (CHS)
    pub heads: u16,
    /// Hidden sectors before partition
    pub hidden_sectors: u32,
    /// Large sector count (if sectors == 0)
    pub large_sectors: u32,
    // FAT32 extended fields
    /// Large sectors per FAT
    pub large_sectors_per_fat: u32,
    /// Extended flags (active FAT, mirroring)
    pub extended_flags: u16,
    /// File system version
    pub fs_version: u16,
    /// Root directory first cluster
    pub root_dir_first_cluster: u32,
    /// FSInfo sector number
    pub fs_info_sector: u16,
    /// Backup boot sector
    pub backup_boot_sector: u16,
    /// Reserved
    pub reserved: [u8; 12],
}

impl BiosParameterBlock {
    /// Read from raw bytes
    pub fn from_bytes(data: &[u8]) -> Self {
        unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Self) }
    }

    /// Check if this is FAT32
    pub fn is_fat32(&self) -> bool {
        self.sectors_per_fat == 0
    }

    /// Get total sectors
    pub fn total_sectors(&self) -> u64 {
        if self.sectors != 0 {
            self.sectors as u64
        } else {
            self.large_sectors as u64
        }
    }

    /// Get sectors per FAT
    pub fn get_sectors_per_fat(&self) -> u32 {
        if self.is_fat32() {
            self.large_sectors_per_fat
        } else {
            self.sectors_per_fat as u32
        }
    }

    /// Get bytes per cluster
    pub fn bytes_per_cluster(&self) -> u32 {
        self.bytes_per_sector as u32 * self.sectors_per_cluster as u32
    }

    /// Get first FAT sector (LBA relative to volume start)
    pub fn fat_start_sector(&self) -> u64 {
        self.reserved_sectors as u64
    }

    /// Get first data sector (where cluster 2 starts)
    pub fn data_start_sector(&self) -> u64 {
        let fat_sectors = self.fats as u64 * self.get_sectors_per_fat() as u64;
        self.reserved_sectors as u64 + fat_sectors
    }

    /// Get sector for a given cluster
    pub fn cluster_to_sector(&self, cluster: u32) -> u64 {
        // Clusters start at 2
        self.data_start_sector() + ((cluster - 2) as u64 * self.sectors_per_cluster as u64)
    }

    /// Get total number of clusters
    pub fn total_clusters(&self) -> u32 {
        let data_sectors = self.total_sectors() - self.data_start_sector();
        (data_sectors / self.sectors_per_cluster as u64) as u32
    }
}

/// Boot Sector (FAT32)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BootSector {
    /// Jump instruction
    pub jump: [u8; 3],
    /// OEM name
    pub oem_name: [u8; 8],
    /// BIOS Parameter Block
    pub bpb: BiosParameterBlock,
    /// Physical drive number
    pub physical_drive_number: u8,
    /// Reserved (current head)
    pub current_head: u8,
    /// Extended boot signature (0x29)
    pub signature: u8,
    /// Volume serial number
    pub volume_id: u32,
    /// Volume label
    pub volume_label: [u8; 11],
    /// File system type string
    pub system_id: [u8; 8],
}

impl BootSector {
    /// Check if boot sector is valid
    pub fn is_valid(&self) -> bool {
        // Check for FAT32 signature
        self.signature == 0x29 || self.signature == 0x28
    }

    /// Get volume label as string
    pub fn label(&self) -> &str {
        let len = self.volume_label.iter().position(|&b| b == 0 || b == b' ').unwrap_or(11);
        core::str::from_utf8(&self.volume_label[..len]).unwrap_or("")
    }
}

/// FSInfo Sector (FAT32)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct FsInfoSector {
    /// Lead signature (0x41615252)
    pub lead_signature: u32,
    /// Reserved
    pub reserved1: [u8; 480],
    /// Structure signature (0x61417272)
    pub struct_signature: u32,
    /// Free cluster count (0xFFFFFFFF if unknown)
    pub free_cluster_count: u32,
    /// Next free cluster hint
    pub next_free_cluster: u32,
    /// Reserved
    pub reserved2: [u8; 12],
    /// Trail signature (0xAA550000)
    pub trail_signature: u32,
}

impl FsInfoSector {
    pub const LEAD_SIGNATURE: u32 = 0x41615252;
    pub const STRUCT_SIGNATURE: u32 = 0x61417272;
    pub const TRAIL_SIGNATURE: u32 = 0xAA550000;

    pub fn is_valid(&self) -> bool {
        self.lead_signature == Self::LEAD_SIGNATURE &&
        self.struct_signature == Self::STRUCT_SIGNATURE &&
        (self.trail_signature & 0xFFFF0000) == 0xAA550000
    }
}

/// Directory Entry (32 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DirectoryEntry {
    /// File name (8.3 format)
    pub name: [u8; 11],
    /// File attributes
    pub attributes: u8,
    /// NT reserved (case info)
    pub nt_reserved: u8,
    /// Creation time (10ms units)
    pub creation_time_tenth: u8,
    /// Creation time
    pub creation_time: u16,
    /// Creation date
    pub creation_date: u16,
    /// Last access date
    pub last_access_date: u16,
    /// First cluster high word (FAT32)
    pub first_cluster_hi: u16,
    /// Last write time
    pub last_write_time: u16,
    /// Last write date
    pub last_write_date: u16,
    /// First cluster low word
    pub first_cluster_lo: u16,
    /// File size in bytes
    pub file_size: u32,
}

/// Directory entry attribute flags
pub mod dir_attr {
    pub const READ_ONLY: u8 = 0x01;
    pub const HIDDEN: u8 = 0x02;
    pub const SYSTEM: u8 = 0x04;
    pub const VOLUME_ID: u8 = 0x08;
    pub const DIRECTORY: u8 = 0x10;
    pub const ARCHIVE: u8 = 0x20;
    pub const LONG_NAME: u8 = READ_ONLY | HIDDEN | SYSTEM | VOLUME_ID;
}

/// Special first-byte values for directory entries
pub mod dir_entry_marker {
    pub const NEVER_USED: u8 = 0x00;
    pub const DELETED: u8 = 0xE5;
    pub const DOT_ENTRY: u8 = 0x2E;
    pub const KANJI_E5: u8 = 0x05;
}

impl DirectoryEntry {
    /// Check if entry is free
    pub fn is_free(&self) -> bool {
        self.name[0] == dir_entry_marker::NEVER_USED ||
        self.name[0] == dir_entry_marker::DELETED
    }

    /// Check if this is the end of directory
    pub fn is_end(&self) -> bool {
        self.name[0] == dir_entry_marker::NEVER_USED
    }

    /// Check if this is a deleted entry
    pub fn is_deleted(&self) -> bool {
        self.name[0] == dir_entry_marker::DELETED
    }

    /// Check if this is a long file name entry
    pub fn is_long_name(&self) -> bool {
        self.attributes == dir_attr::LONG_NAME
    }

    /// Check if this is a directory
    pub fn is_directory(&self) -> bool {
        (self.attributes & dir_attr::DIRECTORY) != 0
    }

    /// Check if this is a volume label
    pub fn is_volume_label(&self) -> bool {
        (self.attributes & dir_attr::VOLUME_ID) != 0 &&
        (self.attributes & dir_attr::DIRECTORY) == 0
    }

    /// Get first cluster number
    pub fn first_cluster(&self) -> u32 {
        ((self.first_cluster_hi as u32) << 16) | (self.first_cluster_lo as u32)
    }

    /// Get 8.3 filename as string
    pub fn short_name(&self) -> [u8; 13] {
        let mut result = [0u8; 13];
        let mut pos = 0;

        // Handle first character (0x05 = 0xE5 in first byte)
        let first = if self.name[0] == dir_entry_marker::KANJI_E5 {
            0xE5
        } else {
            self.name[0]
        };

        // Copy name part (8 chars, trimmed)
        if first != b' ' && first != 0 {
            result[pos] = first;
            pos += 1;
        }
        for i in 1..8 {
            if self.name[i] != b' ' && self.name[i] != 0 {
                result[pos] = self.name[i];
                pos += 1;
            }
        }

        // Add extension if present
        if self.name[8] != b' ' && self.name[8] != 0 {
            result[pos] = b'.';
            pos += 1;
            for i in 8..11 {
                if self.name[i] != b' ' && self.name[i] != 0 {
                    result[pos] = self.name[i];
                    pos += 1;
                }
            }
        }

        result
    }

    /// Get filename as string slice
    pub fn name_str(&self) -> &str {
        // This is a bit unsafe but we just want to display
        let name = self.short_name();
        let len = name.iter().position(|&b| b == 0).unwrap_or(13);
        unsafe { core::str::from_utf8_unchecked(&*(&name[..len] as *const [u8])) }
    }
}

/// Long File Name entry (32 bytes, same size as directory entry)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct LfnEntry {
    /// Sequence number
    pub sequence: u8,
    /// Characters 1-5 (UCS-2)
    pub name1: [u16; 5],
    /// Attributes (always 0x0F)
    pub attributes: u8,
    /// Type (always 0)
    pub entry_type: u8,
    /// Checksum of 8.3 name
    pub checksum: u8,
    /// Characters 6-11 (UCS-2)
    pub name2: [u16; 6],
    /// First cluster (always 0)
    pub first_cluster: u16,
    /// Characters 12-13 (UCS-2)
    pub name3: [u16; 2],
}

/// FAT entry special values
pub mod fat_entry {
    pub const FREE: u32 = 0x00000000;
    pub const RESERVED_MIN: u32 = 0x0FFFFFF0;
    pub const BAD_CLUSTER: u32 = 0x0FFFFFF7;
    pub const END_OF_CHAIN: u32 = 0x0FFFFFF8;
    pub const MASK: u32 = 0x0FFFFFFF;
}

// ============================================================================
// In-Memory Structures
// ============================================================================

/// Mounted FAT32 volume
pub struct Fat32Volume {
    /// Volume is mounted
    pub mounted: bool,
    /// Volume number (from disk.rs)
    pub volume_number: u8,
    /// BIOS Parameter Block (cached)
    pub bpb: BiosParameterBlock,
    /// Volume label
    pub label: [u8; 12],
    /// Volume serial number
    pub serial: u32,
    /// Free cluster count (cached)
    pub free_clusters: u32,
    /// Next free cluster hint
    pub next_free: u32,
    /// Sector buffer for operations
    sector_buffer: [u8; SECTOR_SIZE],
}

impl Fat32Volume {
    pub const fn empty() -> Self {
        Self {
            mounted: false,
            volume_number: 0,
            bpb: unsafe { core::mem::zeroed() },
            label: [0; 12],
            serial: 0,
            free_clusters: 0xFFFFFFFF,
            next_free: 2,
            sector_buffer: [0; SECTOR_SIZE],
        }
    }

    /// Get label as string
    pub fn label_str(&self) -> &str {
        let len = self.label.iter().position(|&b| b == 0 || b == b' ').unwrap_or(11);
        core::str::from_utf8(&self.label[..len]).unwrap_or("")
    }
}

/// File handle
#[derive(Clone, Copy)]
pub struct FileHandle {
    /// Handle is valid
    pub valid: bool,
    /// Volume index
    pub volume_idx: u8,
    /// First cluster of file
    pub first_cluster: u32,
    /// Current cluster
    pub current_cluster: u32,
    /// Current position in file
    pub position: u64,
    /// File size
    pub size: u64,
    /// Is directory
    pub is_directory: bool,
    /// File path (for display)
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: usize,
}

impl FileHandle {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            volume_idx: 0,
            first_cluster: 0,
            current_cluster: 0,
            position: 0,
            size: 0,
            is_directory: false,
            path: [0; MAX_PATH_LEN],
            path_len: 0,
        }
    }

    pub fn path_str(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }
}

/// Directory entry info (user-friendly)
#[derive(Clone, Copy)]
pub struct DirEntryInfo {
    /// File name
    pub name: [u8; 256],
    pub name_len: usize,
    /// Is directory
    pub is_directory: bool,
    /// File size
    pub size: u64,
    /// First cluster
    pub first_cluster: u32,
    /// Attributes
    pub attributes: u8,
}

impl DirEntryInfo {
    pub const fn empty() -> Self {
        Self {
            name: [0; 256],
            name_len: 0,
            is_directory: false,
            size: 0,
            first_cluster: 0,
            attributes: 0,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Mounted volumes
static mut FAT_VOLUMES: [Fat32Volume; MAX_FAT_VOLUMES] = {
    const INIT: Fat32Volume = Fat32Volume::empty();
    [INIT; MAX_FAT_VOLUMES]
};

/// Open file handles
static mut FILE_HANDLES: [FileHandle; MAX_OPEN_FILES] = {
    const INIT: FileHandle = FileHandle::empty();
    [INIT; MAX_OPEN_FILES]
};

/// FAT32 lock
static FAT_LOCK: SpinLock<()> = SpinLock::new(());

// ============================================================================
// Volume Operations
// ============================================================================

/// Mount a FAT32 volume
pub fn mount(volume_number: u8) -> Option<usize> {
    let _guard = FAT_LOCK.lock();

    // Check if volume exists
    let _vol = get_volume(volume_number)?;

    // Find free slot
    let slot = unsafe {
        FAT_VOLUMES.iter().position(|v| !v.mounted)?
    };

    // Read boot sector
    let mut boot_sector_buf = [0u8; SECTOR_SIZE];
    if volume_read(volume_number, 0, 1, &mut boot_sector_buf) != super::block::BlockStatus::Success {
        crate::serial_println!("[FAT32] Failed to read boot sector from volume {}", volume_number);
        return None;
    }

    // Parse boot sector
    let boot_sector = unsafe {
        core::ptr::read_unaligned(boot_sector_buf.as_ptr() as *const BootSector)
    };

    // Validate
    if !boot_sector.is_valid() {
        crate::serial_println!("[FAT32] Invalid boot sector signature on volume {}", volume_number);
        return None;
    }

    // Check if FAT32
    if !boot_sector.bpb.is_fat32() {
        crate::serial_println!("[FAT32] Volume {} is not FAT32", volume_number);
        return None;
    }

    // Read FSInfo sector
    let mut fsinfo_buf = [0u8; SECTOR_SIZE];
    let fsinfo_sector = boot_sector.bpb.fs_info_sector as u64;
    let mut free_clusters = 0xFFFFFFFFu32;
    let mut next_free = 2u32;

    if fsinfo_sector > 0 && fsinfo_sector < boot_sector.bpb.reserved_sectors as u64 {
        if volume_read(volume_number, fsinfo_sector, 1, &mut fsinfo_buf) == super::block::BlockStatus::Success {
            let fsinfo = unsafe {
                core::ptr::read_unaligned(fsinfo_buf.as_ptr() as *const FsInfoSector)
            };
            if fsinfo.is_valid() {
                free_clusters = fsinfo.free_cluster_count;
                next_free = fsinfo.next_free_cluster;
            }
        }
    }

    // Store volume info
    unsafe {
        let fat_vol = &mut FAT_VOLUMES[slot];
        fat_vol.mounted = true;
        fat_vol.volume_number = volume_number;
        fat_vol.bpb = boot_sector.bpb;
        fat_vol.label[..11].copy_from_slice(&boot_sector.volume_label);
        fat_vol.serial = boot_sector.volume_id;
        fat_vol.free_clusters = free_clusters;
        fat_vol.next_free = next_free;
    }

    crate::serial_println!(
        "[FAT32] Mounted volume {} as FAT32 (label: {}, {} clusters)",
        volume_number,
        boot_sector.label(),
        boot_sector.bpb.total_clusters()
    );

    Some(slot)
}

/// Unmount a FAT32 volume
pub fn unmount(slot: usize) -> bool {
    if slot >= MAX_FAT_VOLUMES {
        return false;
    }

    let _guard = FAT_LOCK.lock();

    unsafe {
        if FAT_VOLUMES[slot].mounted {
            // Close any open files on this volume
            for handle in FILE_HANDLES.iter_mut() {
                if handle.valid && handle.volume_idx == slot as u8 {
                    handle.valid = false;
                }
            }

            FAT_VOLUMES[slot] = Fat32Volume::empty();
            crate::serial_println!("[FAT32] Unmounted volume slot {}", slot);
            return true;
        }
    }

    false
}

/// Get mounted volume info
pub fn get_mounted_volume(slot: usize) -> Option<&'static Fat32Volume> {
    if slot >= MAX_FAT_VOLUMES {
        return None;
    }

    unsafe {
        let vol = &FAT_VOLUMES[slot];
        if vol.mounted {
            Some(vol)
        } else {
            None
        }
    }
}

// ============================================================================
// FAT Table Operations
// ============================================================================

/// Read FAT entry for a cluster
fn read_fat_entry(vol: &Fat32Volume, cluster: u32) -> Option<u32> {
    if cluster < 2 || cluster >= vol.bpb.total_clusters() + 2 {
        return None;
    }

    // Calculate sector and offset
    let fat_offset = cluster * 4; // FAT32 uses 4 bytes per entry
    let fat_sector = vol.bpb.fat_start_sector() + (fat_offset / SECTOR_SIZE as u32) as u64;
    let entry_offset = (fat_offset % SECTOR_SIZE as u32) as usize;

    // Read sector
    let mut buf = [0u8; SECTOR_SIZE];
    if volume_read(vol.volume_number, fat_sector, 1, &mut buf) != super::block::BlockStatus::Success {
        return None;
    }

    // Read entry (little-endian)
    let entry = u32::from_le_bytes([
        buf[entry_offset],
        buf[entry_offset + 1],
        buf[entry_offset + 2],
        buf[entry_offset + 3],
    ]) & fat_entry::MASK;

    Some(entry)
}

/// Check if cluster marks end of chain
fn is_end_of_chain(entry: u32) -> bool {
    entry >= fat_entry::END_OF_CHAIN
}

/// Write FAT entry for a cluster (writes to both FAT copies)
fn write_fat_entry(vol: &Fat32Volume, cluster: u32, value: u32) -> bool {
    if cluster < 2 || cluster >= vol.bpb.total_clusters() + 2 {
        return false;
    }

    // Calculate sector and offset
    let fat_offset = cluster * 4; // FAT32 uses 4 bytes per entry
    let fat_sector_offset = (fat_offset / SECTOR_SIZE as u32) as u64;
    let entry_offset = (fat_offset % SECTOR_SIZE as u32) as usize;

    // Write to both FAT copies
    for fat_idx in 0..vol.bpb.fats {
        let fat_start = vol.bpb.fat_start_sector() +
                        (fat_idx as u64 * vol.bpb.get_sectors_per_fat() as u64);
        let sector = fat_start + fat_sector_offset;

        // Read sector
        let mut buf = [0u8; SECTOR_SIZE];
        if volume_read(vol.volume_number, sector, 1, &mut buf) != super::block::BlockStatus::Success {
            return false;
        }

        // Modify entry (preserve high 4 bits)
        let existing = u32::from_le_bytes([
            buf[entry_offset],
            buf[entry_offset + 1],
            buf[entry_offset + 2],
            buf[entry_offset + 3],
        ]);
        let new_value = (existing & 0xF0000000) | (value & fat_entry::MASK);
        let bytes = new_value.to_le_bytes();
        buf[entry_offset..entry_offset + 4].copy_from_slice(&bytes);

        // Write sector back
        if volume_write(vol.volume_number, sector, 1, &buf) != super::block::BlockStatus::Success {
            return false;
        }
    }

    true
}

/// Allocate a free cluster
fn allocate_cluster(vol: &mut Fat32Volume) -> Option<u32> {
    let total_clusters = vol.bpb.total_clusters();
    let mut cluster = vol.next_free;

    // Search for a free cluster
    for _ in 0..total_clusters {
        if cluster >= total_clusters + 2 {
            cluster = 2; // Wrap around
        }

        if let Some(entry) = read_fat_entry(vol, cluster) {
            if entry == fat_entry::FREE {
                // Found free cluster - mark as end of chain
                if write_fat_entry(vol, cluster, fat_entry::END_OF_CHAIN) {
                    // Update next_free hint
                    vol.next_free = cluster + 1;
                    if vol.free_clusters != 0xFFFFFFFF {
                        vol.free_clusters = vol.free_clusters.saturating_sub(1);
                    }
                    return Some(cluster);
                }
            }
        }

        cluster += 1;
    }

    None // No free clusters
}

/// Zero out a cluster (for new directories)
fn zero_cluster(vol: &Fat32Volume, cluster: u32) -> bool {
    let sector = vol.bpb.cluster_to_sector(cluster);
    let sectors_per_cluster = vol.bpb.sectors_per_cluster as u64;
    let zero_buf = [0u8; SECTOR_SIZE];

    for i in 0..sectors_per_cluster {
        if volume_write(vol.volume_number, sector + i, 1, &zero_buf) != super::block::BlockStatus::Success {
            return false;
        }
    }

    true
}

/// Get next cluster in chain
pub fn get_next_cluster(vol: &Fat32Volume, cluster: u32) -> Option<u32> {
    let entry = read_fat_entry(vol, cluster)?;

    if is_end_of_chain(entry) || entry == fat_entry::BAD_CLUSTER || entry < 2 {
        None
    } else {
        Some(entry)
    }
}

// ============================================================================
// Directory Operations
// ============================================================================

/// Read directory entries from a cluster chain
pub fn read_directory(slot: usize, start_cluster: u32, entries: &mut [DirEntryInfo]) -> usize {
    let _guard = FAT_LOCK.lock();

    let vol = match unsafe { FAT_VOLUMES.get(slot) } {
        Some(v) if v.mounted => v,
        _ => return 0,
    };

    let mut count = 0;
    let max_entries = entries.len();
    let mut current_cluster = start_cluster;

    // Buffer for reading clusters
    let bytes_per_cluster = vol.bpb.bytes_per_cluster() as usize;
    let entries_per_cluster = bytes_per_cluster / 32;

    // We'll read one sector at a time
    let sectors_per_cluster = vol.bpb.sectors_per_cluster as u64;

    loop {
        // Read each sector in the cluster
        let cluster_start_sector = vol.bpb.cluster_to_sector(current_cluster);

        for sector_offset in 0..sectors_per_cluster {
            let mut sector_buf = [0u8; SECTOR_SIZE];
            let sector = cluster_start_sector + sector_offset;

            if volume_read(vol.volume_number, sector, 1, &mut sector_buf) != super::block::BlockStatus::Success {
                return count;
            }

            // Parse directory entries in this sector
            let entries_in_sector = SECTOR_SIZE / 32;
            for i in 0..entries_in_sector {
                if count >= max_entries {
                    return count;
                }

                let offset = i * 32;
                let dirent = unsafe {
                    core::ptr::read_unaligned(sector_buf[offset..].as_ptr() as *const DirectoryEntry)
                };

                // End of directory
                if dirent.is_end() {
                    return count;
                }

                // Skip deleted, LFN, and volume label entries
                if dirent.is_deleted() || dirent.is_long_name() || dirent.is_volume_label() {
                    continue;
                }

                // Skip . and .. entries
                if dirent.name[0] == b'.' {
                    continue;
                }

                // Add entry to results
                let entry = &mut entries[count];
                let short_name = dirent.short_name();
                let name_len = short_name.iter().position(|&b| b == 0).unwrap_or(13);
                entry.name[..name_len].copy_from_slice(&short_name[..name_len]);
                entry.name_len = name_len;
                entry.is_directory = dirent.is_directory();
                entry.size = dirent.file_size as u64;
                entry.first_cluster = dirent.first_cluster();
                entry.attributes = dirent.attributes;

                count += 1;
            }
        }

        // Move to next cluster
        match get_next_cluster(vol, current_cluster) {
            Some(next) => current_cluster = next,
            None => break,
        }
    }

    count
}

/// Read root directory
pub fn read_root_directory(slot: usize, entries: &mut [DirEntryInfo]) -> usize {
    let root_cluster = match get_mounted_volume(slot) {
        Some(v) => v.bpb.root_dir_first_cluster,
        None => return 0,
    };

    read_directory(slot, root_cluster, entries)
}

/// Convert filename to 8.3 format
fn make_short_name(name: &str) -> [u8; 11] {
    let mut result = [b' '; 11];

    // Split into name and extension
    let mut name_part = name;
    let mut ext_part = "";

    if let Some(dot_pos) = name.rfind('.') {
        if dot_pos > 0 && dot_pos < name.len() - 1 {
            name_part = &name[..dot_pos];
            ext_part = &name[dot_pos + 1..];
        }
    }

    // Copy name (up to 8 chars, uppercase)
    let mut pos = 0;
    for ch in name_part.chars() {
        if pos >= 8 {
            break;
        }
        let c = ch.to_ascii_uppercase();
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            result[pos] = c as u8;
            pos += 1;
        }
    }

    // Copy extension (up to 3 chars, uppercase)
    pos = 0;
    for ch in ext_part.chars() {
        if pos >= 3 {
            break;
        }
        let c = ch.to_ascii_uppercase();
        if c.is_ascii_alphanumeric() {
            result[8 + pos] = c as u8;
            pos += 1;
        }
    }

    result
}

/// Get current date/time in FAT format
fn get_fat_datetime() -> (u16, u16) {
    // Use RTC if available, otherwise use a default time
    let time = crate::hal::rtc::get_system_time();

    // FAT time: bits 0-4 = seconds/2, bits 5-10 = minutes, bits 11-15 = hours
    // FAT date: bits 0-4 = day, bits 5-8 = month, bits 9-15 = year from 1980

    // For now, use a simple conversion from Unix timestamp
    // This is approximate but functional
    let seconds = (time % 60) as u16;
    let minutes = ((time / 60) % 60) as u16;
    let hours = ((time / 3600) % 24) as u16;

    let fat_time = (seconds / 2) | (minutes << 5) | (hours << 11);

    // Use a default date of 2024-01-01 (year 44 from 1980)
    let day = 1u16;
    let month = 1u16;
    let year = 44u16; // 2024 - 1980

    let fat_date = day | (month << 5) | (year << 9);

    (fat_time, fat_date)
}

/// Create a new directory entry in a parent directory
fn create_directory_entry_internal(
    vol: &mut Fat32Volume,
    parent_cluster: u32,
    name: &str,
    is_directory: bool,
    file_cluster: u32,
    file_size: u32,
) -> bool {
    let short_name = make_short_name(name);
    let (time, date) = get_fat_datetime();

    // Search for a free entry in the directory
    let sectors_per_cluster = vol.bpb.sectors_per_cluster as u64;
    let mut current_cluster = parent_cluster;

    loop {
        let cluster_start_sector = vol.bpb.cluster_to_sector(current_cluster);

        for sector_offset in 0..sectors_per_cluster {
            let sector = cluster_start_sector + sector_offset;
            let mut sector_buf = [0u8; SECTOR_SIZE];

            if volume_read(vol.volume_number, sector, 1, &mut sector_buf) != super::block::BlockStatus::Success {
                return false;
            }

            // Search for free entry in this sector
            let entries_per_sector = SECTOR_SIZE / 32;
            for i in 0..entries_per_sector {
                let offset = i * 32;
                let first_byte = sector_buf[offset];

                // Found free slot (deleted or never used)
                if first_byte == dir_entry_marker::NEVER_USED || first_byte == dir_entry_marker::DELETED {
                    // Build directory entry
                    let attributes = if is_directory { dir_attr::DIRECTORY } else { dir_attr::ARCHIVE };

                    // Clear the entry space
                    for j in 0..32 {
                        sector_buf[offset + j] = 0;
                    }

                    // Set short name
                    sector_buf[offset..offset + 11].copy_from_slice(&short_name);

                    // Set attributes
                    sector_buf[offset + 11] = attributes;

                    // Set creation time/date
                    sector_buf[offset + 14..offset + 16].copy_from_slice(&time.to_le_bytes());
                    sector_buf[offset + 16..offset + 18].copy_from_slice(&date.to_le_bytes());

                    // Set last access date
                    sector_buf[offset + 18..offset + 20].copy_from_slice(&date.to_le_bytes());

                    // Set first cluster high
                    let cluster_hi = ((file_cluster >> 16) & 0xFFFF) as u16;
                    sector_buf[offset + 20..offset + 22].copy_from_slice(&cluster_hi.to_le_bytes());

                    // Set last write time/date
                    sector_buf[offset + 22..offset + 24].copy_from_slice(&time.to_le_bytes());
                    sector_buf[offset + 24..offset + 26].copy_from_slice(&date.to_le_bytes());

                    // Set first cluster low
                    let cluster_lo = (file_cluster & 0xFFFF) as u16;
                    sector_buf[offset + 26..offset + 28].copy_from_slice(&cluster_lo.to_le_bytes());

                    // Set file size
                    sector_buf[offset + 28..offset + 32].copy_from_slice(&file_size.to_le_bytes());

                    // Write sector back
                    if volume_write(vol.volume_number, sector, 1, &sector_buf) != super::block::BlockStatus::Success {
                        return false;
                    }

                    return true;
                }
            }
        }

        // Move to next cluster, or allocate a new one
        match get_next_cluster(vol, current_cluster) {
            Some(next) => current_cluster = next,
            None => {
                // Need to allocate a new cluster for the directory
                if let Some(new_cluster) = allocate_cluster(vol) {
                    // Link to previous cluster
                    if !write_fat_entry(vol, current_cluster, new_cluster) {
                        return false;
                    }
                    // Zero the new cluster
                    if !zero_cluster(vol, new_cluster) {
                        return false;
                    }
                    current_cluster = new_cluster;
                } else {
                    return false; // No space
                }
            }
        }
    }
}

/// Create . and .. entries for a new directory
fn create_dot_entries(vol: &Fat32Volume, dir_cluster: u32, parent_cluster: u32) -> bool {
    let (time, date) = get_fat_datetime();
    let sector = vol.bpb.cluster_to_sector(dir_cluster);

    let mut sector_buf = [0u8; SECTOR_SIZE];
    if volume_read(vol.volume_number, sector, 1, &mut sector_buf) != super::block::BlockStatus::Success {
        return false;
    }

    // . entry (self)
    sector_buf[0..11].copy_from_slice(b".          ");
    sector_buf[11] = dir_attr::DIRECTORY;
    sector_buf[14..16].copy_from_slice(&time.to_le_bytes());
    sector_buf[16..18].copy_from_slice(&date.to_le_bytes());
    sector_buf[18..20].copy_from_slice(&date.to_le_bytes());
    let cluster_hi = ((dir_cluster >> 16) & 0xFFFF) as u16;
    sector_buf[20..22].copy_from_slice(&cluster_hi.to_le_bytes());
    sector_buf[22..24].copy_from_slice(&time.to_le_bytes());
    sector_buf[24..26].copy_from_slice(&date.to_le_bytes());
    let cluster_lo = (dir_cluster & 0xFFFF) as u16;
    sector_buf[26..28].copy_from_slice(&cluster_lo.to_le_bytes());

    // .. entry (parent)
    sector_buf[32..43].copy_from_slice(b"..         ");
    sector_buf[43] = dir_attr::DIRECTORY;
    sector_buf[46..48].copy_from_slice(&time.to_le_bytes());
    sector_buf[48..50].copy_from_slice(&date.to_le_bytes());
    sector_buf[50..52].copy_from_slice(&date.to_le_bytes());
    let parent_hi = ((parent_cluster >> 16) & 0xFFFF) as u16;
    sector_buf[52..54].copy_from_slice(&parent_hi.to_le_bytes());
    sector_buf[54..56].copy_from_slice(&time.to_le_bytes());
    sector_buf[56..58].copy_from_slice(&date.to_le_bytes());
    let parent_lo = (parent_cluster & 0xFFFF) as u16;
    sector_buf[58..60].copy_from_slice(&parent_lo.to_le_bytes());

    if volume_write(vol.volume_number, sector, 1, &sector_buf) != super::block::BlockStatus::Success {
        return false;
    }

    true
}

/// Find entry in directory by name (case-insensitive)
pub fn find_entry(slot: usize, dir_cluster: u32, name: &str) -> Option<DirEntryInfo> {
    let mut entries = [DirEntryInfo::empty(); 64];
    let count = read_directory(slot, dir_cluster, &mut entries);

    for i in 0..count {
        let entry_name = entries[i].name_str();
        if entry_name.eq_ignore_ascii_case(name) {
            return Some(entries[i]);
        }
    }

    None
}

/// Resolve path to directory entry
pub fn resolve_path(slot: usize, path: &str) -> Option<DirEntryInfo> {
    let vol = get_mounted_volume(slot)?;

    // Handle root directory
    if path.is_empty() || path == "/" || path == "\\" {
        let mut entry = DirEntryInfo::empty();
        entry.is_directory = true;
        entry.first_cluster = vol.bpb.root_dir_first_cluster;
        entry.name[0] = b'/';
        entry.name_len = 1;
        return Some(entry);
    }

    // Split path and resolve each component
    let mut current_cluster = vol.bpb.root_dir_first_cluster;

    for component in path.split(|c| c == '/' || c == '\\') {
        if component.is_empty() {
            continue;
        }

        match find_entry(slot, current_cluster, component) {
            Some(entry) => {
                if entry.is_directory {
                    current_cluster = entry.first_cluster;
                } else {
                    // Found file - must be last component
                    return Some(entry);
                }
            }
            None => return None,
        }
    }

    // Return directory entry for final path component
    let mut entry = DirEntryInfo::empty();
    entry.is_directory = true;
    entry.first_cluster = current_cluster;
    Some(entry)
}

// ============================================================================
// Directory/File Creation
// ============================================================================

/// Create a new directory (folder)
pub fn create_directory(slot: usize, parent_path: &str, name: &str) -> bool {
    let _guard = FAT_LOCK.lock();

    // Get volume (we need mutable access)
    let vol = match unsafe { FAT_VOLUMES.get_mut(slot) } {
        Some(v) if v.mounted => v,
        _ => {
            crate::serial_println!("[FAT32] create_directory: volume {} not mounted", slot);
            return false;
        }
    };

    // Resolve parent path to get parent cluster
    let parent_cluster = if parent_path.is_empty() || parent_path == "/" || parent_path == "\\" {
        vol.bpb.root_dir_first_cluster
    } else {
        // Need to temporarily release lock to call resolve_path
        // Actually, we can inline the resolution here
        let mut current = vol.bpb.root_dir_first_cluster;
        for component in parent_path.split(|c| c == '/' || c == '\\') {
            if component.is_empty() {
                continue;
            }
            // Find this component in current directory
            let mut found = false;
            let mut entries = [DirEntryInfo::empty(); 64];
            let sectors_per_cluster = vol.bpb.sectors_per_cluster as u64;
            let mut search_cluster = current;

            'outer: loop {
                let cluster_start = vol.bpb.cluster_to_sector(search_cluster);
                for sector_off in 0..sectors_per_cluster {
                    let mut buf = [0u8; SECTOR_SIZE];
                    if volume_read(vol.volume_number, cluster_start + sector_off, 1, &mut buf) != super::block::BlockStatus::Success {
                        break 'outer;
                    }
                    for i in 0..(SECTOR_SIZE / 32) {
                        let offset = i * 32;
                        if buf[offset] == 0 {
                            break 'outer; // End of directory
                        }
                        if buf[offset] == 0xE5 || buf[offset + 11] == dir_attr::LONG_NAME {
                            continue;
                        }
                        // Check name match
                        let dirent = unsafe {
                            core::ptr::read_unaligned(buf[offset..].as_ptr() as *const DirectoryEntry)
                        };
                        if dirent.is_directory() {
                            let entry_name_arr = dirent.short_name();
                            let entry_name = core::str::from_utf8(&entry_name_arr[..entry_name_arr.iter().position(|&b| b == 0).unwrap_or(13)]).unwrap_or("");
                            if entry_name.eq_ignore_ascii_case(component) {
                                current = dirent.first_cluster();
                                found = true;
                                break 'outer;
                            }
                        }
                    }
                }
                match get_next_cluster(vol, search_cluster) {
                    Some(next) => search_cluster = next,
                    None => break,
                }
            }

            if !found {
                crate::serial_println!("[FAT32] create_directory: parent path not found: {}", parent_path);
                return false;
            }
        }
        current
    };

    // Check if entry already exists
    {
        let sectors_per_cluster = vol.bpb.sectors_per_cluster as u64;
        let mut search_cluster = parent_cluster;

        'check_loop: loop {
            let cluster_start = vol.bpb.cluster_to_sector(search_cluster);
            for sector_off in 0..sectors_per_cluster {
                let mut buf = [0u8; SECTOR_SIZE];
                if volume_read(vol.volume_number, cluster_start + sector_off, 1, &mut buf) != super::block::BlockStatus::Success {
                    break 'check_loop;
                }
                for i in 0..(SECTOR_SIZE / 32) {
                    let offset = i * 32;
                    if buf[offset] == 0 {
                        // End of directory - no match found, exit all loops
                        break 'check_loop;
                    }
                    if buf[offset] == 0xE5 || buf[offset + 11] == dir_attr::LONG_NAME {
                        continue;
                    }
                    let dirent = unsafe {
                        core::ptr::read_unaligned(buf[offset..].as_ptr() as *const DirectoryEntry)
                    };
                    let entry_name_arr = dirent.short_name();
                    let entry_name = core::str::from_utf8(&entry_name_arr[..entry_name_arr.iter().position(|&b| b == 0).unwrap_or(13)]).unwrap_or("");
                    crate::serial_println!("[FAT32] create_directory: checking entry '{}' vs '{}'", entry_name, name);
                    if entry_name.eq_ignore_ascii_case(name) {
                        crate::serial_println!("[FAT32] create_directory: entry already exists: {}", name);
                        return false;
                    }
                }
            }
            match get_next_cluster(vol, search_cluster) {
                Some(next) => search_cluster = next,
                None => break,
            }
        }
    }

    // Allocate cluster for new directory
    let new_cluster = match allocate_cluster(vol) {
        Some(c) => c,
        None => {
            crate::serial_println!("[FAT32] create_directory: no free clusters");
            return false;
        }
    };

    // Zero the new cluster
    if !zero_cluster(vol, new_cluster) {
        crate::serial_println!("[FAT32] create_directory: failed to zero cluster");
        return false;
    }

    // Create . and .. entries
    if !create_dot_entries(vol, new_cluster, parent_cluster) {
        crate::serial_println!("[FAT32] create_directory: failed to create dot entries");
        return false;
    }

    // Create directory entry in parent
    if !create_directory_entry_internal(vol, parent_cluster, name, true, new_cluster, 0) {
        crate::serial_println!("[FAT32] create_directory: failed to create directory entry");
        return false;
    }

    crate::serial_println!("[FAT32] Created directory '{}' in cluster {} (new cluster {})", name, parent_cluster, new_cluster);
    true
}

/// Create a new file
pub fn create_file(slot: usize, parent_path: &str, name: &str) -> bool {
    let _guard = FAT_LOCK.lock();

    // Get volume (we need mutable access)
    let vol = match unsafe { FAT_VOLUMES.get_mut(slot) } {
        Some(v) if v.mounted => v,
        _ => {
            crate::serial_println!("[FAT32] create_file: volume {} not mounted", slot);
            return false;
        }
    };

    // Resolve parent path to get parent cluster
    let parent_cluster = if parent_path.is_empty() || parent_path == "/" || parent_path == "\\" {
        vol.bpb.root_dir_first_cluster
    } else {
        let mut current = vol.bpb.root_dir_first_cluster;
        for component in parent_path.split(|c| c == '/' || c == '\\') {
            if component.is_empty() {
                continue;
            }
            let mut found = false;
            let sectors_per_cluster = vol.bpb.sectors_per_cluster as u64;
            let mut search_cluster = current;

            'outer: loop {
                let cluster_start = vol.bpb.cluster_to_sector(search_cluster);
                for sector_off in 0..sectors_per_cluster {
                    let mut buf = [0u8; SECTOR_SIZE];
                    if volume_read(vol.volume_number, cluster_start + sector_off, 1, &mut buf) != super::block::BlockStatus::Success {
                        break 'outer;
                    }
                    for i in 0..(SECTOR_SIZE / 32) {
                        let offset = i * 32;
                        if buf[offset] == 0 {
                            break 'outer;
                        }
                        if buf[offset] == 0xE5 || buf[offset + 11] == dir_attr::LONG_NAME {
                            continue;
                        }
                        let dirent = unsafe {
                            core::ptr::read_unaligned(buf[offset..].as_ptr() as *const DirectoryEntry)
                        };
                        if dirent.is_directory() {
                            let entry_name_arr = dirent.short_name();
                            let entry_name = core::str::from_utf8(&entry_name_arr[..entry_name_arr.iter().position(|&b| b == 0).unwrap_or(13)]).unwrap_or("");
                            if entry_name.eq_ignore_ascii_case(component) {
                                current = dirent.first_cluster();
                                found = true;
                                break 'outer;
                            }
                        }
                    }
                }
                match get_next_cluster(vol, search_cluster) {
                    Some(next) => search_cluster = next,
                    None => break,
                }
            }

            if !found {
                crate::serial_println!("[FAT32] create_file: parent path not found: {}", parent_path);
                return false;
            }
        }
        current
    };

    // Check if entry already exists
    {
        let sectors_per_cluster = vol.bpb.sectors_per_cluster as u64;
        let mut search_cluster = parent_cluster;

        loop {
            let cluster_start = vol.bpb.cluster_to_sector(search_cluster);
            for sector_off in 0..sectors_per_cluster {
                let mut buf = [0u8; SECTOR_SIZE];
                if volume_read(vol.volume_number, cluster_start + sector_off, 1, &mut buf) != super::block::BlockStatus::Success {
                    break;
                }
                for i in 0..(SECTOR_SIZE / 32) {
                    let offset = i * 32;
                    if buf[offset] == 0 {
                        break;
                    }
                    if buf[offset] == 0xE5 || buf[offset + 11] == dir_attr::LONG_NAME {
                        continue;
                    }
                    let dirent = unsafe {
                        core::ptr::read_unaligned(buf[offset..].as_ptr() as *const DirectoryEntry)
                    };
                    let entry_name_arr = dirent.short_name();
                    let entry_name = core::str::from_utf8(&entry_name_arr[..entry_name_arr.iter().position(|&b| b == 0).unwrap_or(13)]).unwrap_or("");
                    if entry_name.eq_ignore_ascii_case(name) {
                        crate::serial_println!("[FAT32] create_file: entry already exists: {}", name);
                        return false;
                    }
                }
            }
            match get_next_cluster(vol, search_cluster) {
                Some(next) => search_cluster = next,
                None => break,
            }
        }
    }

    // Create an empty file (cluster 0, size 0)
    // Files with size 0 don't need a cluster allocated
    if !create_directory_entry_internal(vol, parent_cluster, name, false, 0, 0) {
        crate::serial_println!("[FAT32] create_file: failed to create file entry");
        return false;
    }

    crate::serial_println!("[FAT32] Created file '{}' in cluster {}", name, parent_cluster);
    true
}

// ============================================================================
// File Operations
// ============================================================================

/// Open a file
pub fn open_file(slot: usize, path: &str) -> Option<usize> {
    let _guard = FAT_LOCK.lock();

    // Resolve path
    let entry = resolve_path(slot, path)?;

    // Find free handle
    let handle_idx = unsafe {
        FILE_HANDLES.iter().position(|h| !h.valid)?
    };

    // Initialize handle
    unsafe {
        let handle = &mut FILE_HANDLES[handle_idx];
        handle.valid = true;
        handle.volume_idx = slot as u8;
        handle.first_cluster = entry.first_cluster;
        handle.current_cluster = entry.first_cluster;
        handle.position = 0;
        handle.size = entry.size;
        handle.is_directory = entry.is_directory;

        // Copy path
        let path_bytes = path.as_bytes();
        let copy_len = path_bytes.len().min(MAX_PATH_LEN);
        handle.path[..copy_len].copy_from_slice(&path_bytes[..copy_len]);
        handle.path_len = copy_len;
    }

    Some(handle_idx)
}

/// Close a file
pub fn close_file(handle_idx: usize) -> bool {
    if handle_idx >= MAX_OPEN_FILES {
        return false;
    }

    let _guard = FAT_LOCK.lock();

    unsafe {
        if FILE_HANDLES[handle_idx].valid {
            FILE_HANDLES[handle_idx] = FileHandle::empty();
            return true;
        }
    }

    false
}

/// Read from file
pub fn read_file(handle_idx: usize, buf: &mut [u8]) -> usize {
    if handle_idx >= MAX_OPEN_FILES {
        return 0;
    }

    let _guard = FAT_LOCK.lock();

    let handle = unsafe { &mut FILE_HANDLES[handle_idx] };
    if !handle.valid {
        return 0;
    }

    let vol = match unsafe { FAT_VOLUMES.get(handle.volume_idx as usize) } {
        Some(v) if v.mounted => v,
        _ => return 0,
    };

    // Calculate bytes remaining
    let remaining = handle.size.saturating_sub(handle.position) as usize;
    let to_read = buf.len().min(remaining);

    if to_read == 0 {
        return 0;
    }

    let bytes_per_cluster = vol.bpb.bytes_per_cluster() as u64;
    let mut bytes_read = 0;

    while bytes_read < to_read {
        // Calculate position within current cluster
        let cluster_offset = (handle.position % bytes_per_cluster) as usize;
        let bytes_in_cluster = (bytes_per_cluster as usize - cluster_offset).min(to_read - bytes_read);

        // Read from current cluster
        let sector = vol.bpb.cluster_to_sector(handle.current_cluster) +
                     (cluster_offset / SECTOR_SIZE) as u64;
        let sector_offset = cluster_offset % SECTOR_SIZE;

        // Read sector by sector
        let mut sector_buf = [0u8; SECTOR_SIZE];
        let mut cluster_bytes_read = 0;

        while cluster_bytes_read < bytes_in_cluster {
            let current_sector = sector + (cluster_bytes_read / SECTOR_SIZE) as u64;
            if volume_read(vol.volume_number, current_sector, 1, &mut sector_buf) != super::block::BlockStatus::Success {
                return bytes_read;
            }

            let offset_in_sector = if cluster_bytes_read == 0 { sector_offset } else { 0 };
            let bytes_from_sector = (SECTOR_SIZE - offset_in_sector).min(bytes_in_cluster - cluster_bytes_read);

            buf[bytes_read..bytes_read + bytes_from_sector]
                .copy_from_slice(&sector_buf[offset_in_sector..offset_in_sector + bytes_from_sector]);

            cluster_bytes_read += bytes_from_sector;
            bytes_read += bytes_from_sector;
            handle.position += bytes_from_sector as u64;
        }

        // Move to next cluster if needed
        if handle.position % bytes_per_cluster == 0 && bytes_read < to_read {
            match get_next_cluster(vol, handle.current_cluster) {
                Some(next) => handle.current_cluster = next,
                None => break,
            }
        }
    }

    bytes_read
}

/// Seek in file
pub fn seek_file(handle_idx: usize, position: u64) -> bool {
    if handle_idx >= MAX_OPEN_FILES {
        return false;
    }

    let _guard = FAT_LOCK.lock();

    let handle = unsafe { &mut FILE_HANDLES[handle_idx] };
    if !handle.valid {
        return false;
    }

    // Clamp to file size
    let new_pos = position.min(handle.size);

    let vol = match unsafe { FAT_VOLUMES.get(handle.volume_idx as usize) } {
        Some(v) if v.mounted => v,
        _ => return false,
    };

    // Calculate which cluster the new position is in
    let bytes_per_cluster = vol.bpb.bytes_per_cluster() as u64;
    let target_cluster_idx = new_pos / bytes_per_cluster;

    // Walk cluster chain to find the cluster
    let mut current = handle.first_cluster;
    for _ in 0..target_cluster_idx {
        match get_next_cluster(vol, current) {
            Some(next) => current = next,
            None => return false,
        }
    }

    handle.current_cluster = current;
    handle.position = new_pos;

    true
}

// ============================================================================
// Statistics and Inspection
// ============================================================================

/// FAT32 statistics
#[derive(Debug, Clone, Copy)]
pub struct Fat32Stats {
    pub mounted_volumes: usize,
    pub open_files: usize,
    pub total_free_clusters: u64,
}

/// Get FAT32 statistics
pub fn get_stats() -> Fat32Stats {
    let mut stats = Fat32Stats {
        mounted_volumes: 0,
        open_files: 0,
        total_free_clusters: 0,
    };

    unsafe {
        for vol in FAT_VOLUMES.iter() {
            if vol.mounted {
                stats.mounted_volumes += 1;
                if vol.free_clusters != 0xFFFFFFFF {
                    stats.total_free_clusters += vol.free_clusters as u64;
                }
            }
        }

        for handle in FILE_HANDLES.iter() {
            if handle.valid {
                stats.open_files += 1;
            }
        }
    }

    stats
}

/// Volume info for display
#[derive(Clone, Copy)]
pub struct Fat32VolumeInfo {
    pub slot: u8,
    pub volume_number: u8,
    pub label: [u8; 12],
    pub serial: u32,
    pub total_clusters: u32,
    pub free_clusters: u32,
    pub bytes_per_cluster: u32,
}

impl Fat32VolumeInfo {
    pub const fn empty() -> Self {
        Self {
            slot: 0,
            volume_number: 0,
            label: [0; 12],
            serial: 0,
            total_clusters: 0,
            free_clusters: 0,
            bytes_per_cluster: 0,
        }
    }

    pub fn label_str(&self) -> &str {
        let len = self.label.iter().position(|&b| b == 0 || b == b' ').unwrap_or(11);
        core::str::from_utf8(&self.label[..len]).unwrap_or("")
    }

    pub fn total_size_mb(&self) -> u64 {
        (self.total_clusters as u64 * self.bytes_per_cluster as u64) / (1024 * 1024)
    }

    pub fn free_size_mb(&self) -> u64 {
        if self.free_clusters == 0xFFFFFFFF {
            0
        } else {
            (self.free_clusters as u64 * self.bytes_per_cluster as u64) / (1024 * 1024)
        }
    }
}

/// Get info for all mounted volumes
pub fn get_volume_info(max_count: usize) -> ([Fat32VolumeInfo; 8], usize) {
    let mut infos = [Fat32VolumeInfo::empty(); 8];
    let mut count = 0;

    let limit = max_count.min(8).min(MAX_FAT_VOLUMES);

    unsafe {
        for (i, vol) in FAT_VOLUMES.iter().enumerate() {
            if count >= limit {
                break;
            }

            if vol.mounted {
                let info = &mut infos[count];
                info.slot = i as u8;
                info.volume_number = vol.volume_number;
                info.label = vol.label;
                info.serial = vol.serial;
                info.total_clusters = vol.bpb.total_clusters();
                info.free_clusters = vol.free_clusters;
                info.bytes_per_cluster = vol.bpb.bytes_per_cluster();
                count += 1;
            }
        }
    }

    (infos, count)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize FAT32 driver
pub fn init() {
    crate::serial_println!("[FAT32] FAT32 file system driver initialized");
    crate::serial_println!("[FAT32]   Max volumes: {}", MAX_FAT_VOLUMES);
    crate::serial_println!("[FAT32]   Max open files: {}", MAX_OPEN_FILES);
}

/// Auto-mount FAT32 volumes
pub fn auto_mount() {
    crate::serial_println!("[FAT32] Auto-mounting FAT32 volumes...");

    // Get volume snapshots from disk layer
    let (snapshots, count) = super::disk::io_get_volume_snapshots(32);

    for i in 0..count {
        let vol = &snapshots[i];

        // Check if FAT32 partition
        if super::disk::partition_type::is_fat(vol.partition_type) {
            crate::serial_println!(
                "[FAT32] Attempting to mount volume {} (type {:#x})",
                vol.volume_number,
                vol.partition_type
            );

            if let Some(slot) = mount(vol.volume_number) {
                crate::serial_println!(
                    "[FAT32] Mounted volume {} at slot {}",
                    vol.volume_number,
                    slot
                );
            }
        }
    }
}
