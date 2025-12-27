//! FAT32 File Operations
//!
//! Implements file system operations for FAT32:
//! - Reading/writing files
//! - Directory traversal
//! - File creation/deletion
//! - Cluster chain management

use core::sync::atomic::{AtomicU32, Ordering};
use crate::ke::SpinLock;
use super::bpb::{Fat32BootSector, FsInfo, cluster_values, FatType};
use super::dir::{FatDirEntry, LfnDirEntry, file_attr, entry_status, DIR_ENTRY_SIZE};
use crate::fs::vfs::{FsStatus, FileInfo, FileType, DirEntry, FsOps, FsInfo as VfsFsInfo, FsType};

/// Maximum mounted FAT32 file systems
pub const MAX_FAT32_MOUNTS: usize = 4;

/// Sector buffer size
pub const SECTOR_SIZE: usize = 512;

/// FAT32 mount information
#[repr(C)]
pub struct Fat32Mount {
    /// Is mounted
    pub mounted: bool,
    /// File system index
    pub fs_index: u16,
    /// Boot sector copy
    pub boot_sector: Fat32BootSector,
    /// FSInfo sector copy
    pub fs_info: FsInfo,
    /// Bytes per sector
    pub bytes_per_sector: u32,
    /// Sectors per cluster
    pub sectors_per_cluster: u32,
    /// Cluster size in bytes
    pub cluster_size: u32,
    /// First FAT sector
    pub fat_start: u32,
    /// Sectors per FAT
    pub fat_sectors: u32,
    /// First data sector
    pub data_start: u32,
    /// Root directory cluster
    pub root_cluster: u32,
    /// Total clusters
    pub total_clusters: u32,
    /// Free cluster count (cached)
    pub free_clusters: AtomicU32,
    /// Next free cluster hint
    pub next_free: AtomicU32,
    /// Device read function
    pub read_sector: Option<unsafe fn(device: *mut u8, sector: u64, buf: &mut [u8]) -> bool>,
    /// Device write function
    pub write_sector: Option<unsafe fn(device: *mut u8, sector: u64, buf: &[u8]) -> bool>,
    /// Device pointer
    pub device: *mut u8,
}

impl Fat32Mount {
    pub const fn empty() -> Self {
        Self {
            mounted: false,
            fs_index: 0,
            boot_sector: unsafe { core::mem::zeroed() },
            fs_info: unsafe { core::mem::zeroed() },
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            cluster_size: 512,
            fat_start: 0,
            fat_sectors: 0,
            data_start: 0,
            root_cluster: 2,
            total_clusters: 0,
            free_clusters: AtomicU32::new(0),
            next_free: AtomicU32::new(2),
            read_sector: None,
            write_sector: None,
            device: core::ptr::null_mut(),
        }
    }

    /// Calculate cluster to sector
    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        self.data_start + (cluster - 2) * self.sectors_per_cluster
    }

    /// Calculate FAT entry offset
    pub fn fat_entry_offset(&self, cluster: u32) -> (u32, u32) {
        let offset = cluster * 4;
        let sector = self.fat_start + (offset / self.bytes_per_sector);
        let offset_in_sector = offset % self.bytes_per_sector;
        (sector, offset_in_sector)
    }
}

impl Default for Fat32Mount {
    fn default() -> Self {
        Self::empty()
    }
}

// Safety: Mount uses atomics for counters
unsafe impl Sync for Fat32Mount {}
unsafe impl Send for Fat32Mount {}

// ============================================================================
// FAT32 Mount Table
// ============================================================================

/// FAT32 mount table
static mut FAT32_MOUNTS: [Fat32Mount; MAX_FAT32_MOUNTS] = {
    const INIT: Fat32Mount = Fat32Mount::empty();
    [INIT; MAX_FAT32_MOUNTS]
};

/// FAT32 mount lock
static FAT32_LOCK: SpinLock<()> = SpinLock::new(());

/// Sector buffer for I/O
static mut SECTOR_BUFFER: [u8; SECTOR_SIZE] = [0; SECTOR_SIZE];

// ============================================================================
// Open File Tracking
// ============================================================================

/// Maximum open files per mount
const MAX_OPEN_FILES: usize = 64;

/// Open file entry - tracks directory location for size updates
#[derive(Clone, Copy)]
struct OpenFile {
    /// File is in use
    in_use: bool,
    /// File system index
    fs_index: u16,
    /// First cluster of file (used as identifier)
    first_cluster: u32,
    /// Directory cluster containing this file's entry
    dir_cluster: u32,
    /// Entry index within directory
    entry_index: u32,
    /// Current file size
    file_size: u32,
    /// Modified flag
    dirty: bool,
}

impl OpenFile {
    const fn empty() -> Self {
        Self {
            in_use: false,
            fs_index: 0,
            first_cluster: 0,
            dir_cluster: 0,
            entry_index: 0,
            file_size: 0,
            dirty: false,
        }
    }
}

/// Open file table
static mut OPEN_FILES: [OpenFile; MAX_OPEN_FILES] = {
    const INIT: OpenFile = OpenFile::empty();
    [INIT; MAX_OPEN_FILES]
};

/// Register an open file for tracking
unsafe fn register_open_file(
    fs_index: u16,
    first_cluster: u32,
    dir_cluster: u32,
    entry_index: u32,
    file_size: u32,
) -> Option<usize> {
    for (i, file) in OPEN_FILES.iter_mut().enumerate() {
        if !file.in_use {
            file.in_use = true;
            file.fs_index = fs_index;
            file.first_cluster = first_cluster;
            file.dir_cluster = dir_cluster;
            file.entry_index = entry_index;
            file.file_size = file_size;
            file.dirty = false;
            return Some(i);
        }
    }
    None
}

/// Find open file by first cluster
unsafe fn find_open_file(fs_index: u16, first_cluster: u32) -> Option<&'static mut OpenFile> {
    for file in OPEN_FILES.iter_mut() {
        if file.in_use && file.fs_index == fs_index && file.first_cluster == first_cluster {
            return Some(file);
        }
    }
    None
}

/// Update file size and mark dirty
unsafe fn update_open_file_size(fs_index: u16, first_cluster: u32, new_size: u32) {
    if let Some(file) = find_open_file(fs_index, first_cluster) {
        if new_size > file.file_size {
            file.file_size = new_size;
            file.dirty = true;
        }
    }
}

/// Flush open file (write size to directory entry)
unsafe fn flush_open_file(mount: &Fat32Mount, file: &mut OpenFile) -> bool {
    if !file.dirty {
        return true;
    }

    // Read current directory entry
    if let Some(mut entry) = read_dir_entry(mount, file.dir_cluster, file.entry_index) {
        entry.file_size = file.file_size;
        if write_dir_entry(mount, file.dir_cluster, file.entry_index, &entry) {
            file.dirty = false;
            return true;
        }
    }
    false
}

/// Close an open file
unsafe fn close_open_file(fs_index: u16, first_cluster: u32) {
    for mount in FAT32_MOUNTS.iter() {
        if mount.mounted && mount.fs_index == fs_index {
            for file in OPEN_FILES.iter_mut() {
                if file.in_use && file.fs_index == fs_index && file.first_cluster == first_cluster {
                    // Flush before closing
                    flush_open_file(mount, file);
                    file.in_use = false;
                    return;
                }
            }
        }
    }
}

// ============================================================================
// FAT Operations
// ============================================================================

/// Read a FAT entry
unsafe fn read_fat_entry(mount: &Fat32Mount, cluster: u32) -> Option<u32> {
    if cluster < 2 || cluster >= mount.total_clusters + 2 {
        return None;
    }

    let (sector, offset) = mount.fat_entry_offset(cluster);
    let read_fn = mount.read_sector?;

    if !read_fn(mount.device, sector as u64, &mut SECTOR_BUFFER) {
        return None;
    }

    let entry = u32::from_le_bytes([
        SECTOR_BUFFER[offset as usize],
        SECTOR_BUFFER[offset as usize + 1],
        SECTOR_BUFFER[offset as usize + 2],
        SECTOR_BUFFER[offset as usize + 3],
    ]);

    Some(entry & cluster_values::CLUSTER_MASK)
}

/// Write a FAT entry
unsafe fn write_fat_entry(mount: &Fat32Mount, cluster: u32, value: u32) -> bool {
    if cluster < 2 || cluster >= mount.total_clusters + 2 {
        return false;
    }

    let (sector, offset) = mount.fat_entry_offset(cluster);
    let read_fn = mount.read_sector;
    let write_fn = mount.write_sector;

    if read_fn.is_none() || write_fn.is_none() {
        return false;
    }

    // Read current sector
    if !(read_fn.unwrap())(mount.device, sector as u64, &mut SECTOR_BUFFER) {
        return false;
    }

    // Preserve high 4 bits, set low 28 bits
    let current = u32::from_le_bytes([
        SECTOR_BUFFER[offset as usize],
        SECTOR_BUFFER[offset as usize + 1],
        SECTOR_BUFFER[offset as usize + 2],
        SECTOR_BUFFER[offset as usize + 3],
    ]);

    let new_value = (current & 0xF0000000) | (value & cluster_values::CLUSTER_MASK);
    let bytes = new_value.to_le_bytes();

    SECTOR_BUFFER[offset as usize] = bytes[0];
    SECTOR_BUFFER[offset as usize + 1] = bytes[1];
    SECTOR_BUFFER[offset as usize + 2] = bytes[2];
    SECTOR_BUFFER[offset as usize + 3] = bytes[3];

    // Write back
    (write_fn.unwrap())(mount.device, sector as u64, &SECTOR_BUFFER)
}

/// Allocate a cluster
unsafe fn alloc_cluster(mount: &Fat32Mount) -> Option<u32> {
    let start = mount.next_free.load(Ordering::SeqCst);
    let mut cluster = start;

    loop {
        if let Some(entry) = read_fat_entry(mount, cluster) {
            if cluster_values::is_free(entry) {
                // Mark as end of chain
                if write_fat_entry(mount, cluster, cluster_values::EOC) {
                    mount.next_free.store(cluster + 1, Ordering::SeqCst);
                    mount.free_clusters.fetch_sub(1, Ordering::SeqCst);
                    return Some(cluster);
                }
            }
        }

        cluster += 1;
        if cluster >= mount.total_clusters + 2 {
            cluster = 2;
        }
        if cluster == start {
            break; // Wrapped around, disk is full
        }
    }

    None
}

/// Free a cluster chain
unsafe fn free_cluster_chain(mount: &Fat32Mount, start_cluster: u32) {
    let mut cluster = start_cluster;

    while cluster_values::is_valid(cluster) {
        if let Some(next) = read_fat_entry(mount, cluster) {
            write_fat_entry(mount, cluster, cluster_values::FREE);
            mount.free_clusters.fetch_add(1, Ordering::SeqCst);

            if cluster_values::is_eoc(next) {
                break;
            }
            cluster = next;
        } else {
            break;
        }
    }
}

/// Follow cluster chain
unsafe fn get_cluster_at_offset(
    mount: &Fat32Mount,
    start_cluster: u32,
    offset: u64,
) -> Option<u32> {
    let cluster_offset = (offset / mount.cluster_size as u64) as u32;
    let mut cluster = start_cluster;

    for _ in 0..cluster_offset {
        let next = read_fat_entry(mount, cluster)?;
        if cluster_values::is_eoc(next) {
            return None;
        }
        cluster = next;
    }

    Some(cluster)
}

// ============================================================================
// Directory Operations
// ============================================================================

/// Read a directory entry at a specific index
unsafe fn read_dir_entry(
    mount: &Fat32Mount,
    dir_cluster: u32,
    index: u32,
) -> Option<FatDirEntry> {
    let entries_per_sector = mount.bytes_per_sector / DIR_ENTRY_SIZE as u32;
    let entries_per_cluster = entries_per_sector * mount.sectors_per_cluster;

    let cluster_index = index / entries_per_cluster;
    let entry_in_cluster = index % entries_per_cluster;

    // Find the right cluster
    let cluster = get_cluster_at_offset(mount, dir_cluster, (cluster_index * mount.cluster_size) as u64)?;

    // Calculate sector and offset within cluster
    let sector_in_cluster = entry_in_cluster / entries_per_sector;
    let entry_in_sector = entry_in_cluster % entries_per_sector;

    let sector = mount.cluster_to_sector(cluster) + sector_in_cluster;
    let offset = (entry_in_sector * DIR_ENTRY_SIZE as u32) as usize;

    let read_fn = mount.read_sector?;
    if !read_fn(mount.device, sector as u64, &mut SECTOR_BUFFER) {
        return None;
    }

    // Copy entry
    let entry_bytes = &SECTOR_BUFFER[offset..offset + DIR_ENTRY_SIZE];
    Some(core::ptr::read(entry_bytes.as_ptr() as *const FatDirEntry))
}

/// Write a directory entry at the given index
unsafe fn write_dir_entry(
    mount: &Fat32Mount,
    dir_cluster: u32,
    index: u32,
    entry: &FatDirEntry,
) -> bool {
    let entries_per_sector = mount.bytes_per_sector / DIR_ENTRY_SIZE as u32;
    let entries_per_cluster = entries_per_sector * mount.sectors_per_cluster;

    let cluster_index = index / entries_per_cluster;
    let entry_in_cluster = index % entries_per_cluster;

    // Find the right cluster
    let cluster = match get_cluster_at_offset(mount, dir_cluster, (cluster_index * mount.cluster_size) as u64) {
        Some(c) => c,
        None => return false,
    };

    // Calculate sector and offset within cluster
    let sector_in_cluster = entry_in_cluster / entries_per_sector;
    let entry_in_sector = entry_in_cluster % entries_per_sector;

    let sector = mount.cluster_to_sector(cluster) + sector_in_cluster;
    let offset = (entry_in_sector * DIR_ENTRY_SIZE as u32) as usize;

    let read_fn = match mount.read_sector {
        Some(f) => f,
        None => return false,
    };
    let write_fn = match mount.write_sector {
        Some(f) => f,
        None => return false,
    };

    // Read current sector
    if !read_fn(mount.device, sector as u64, &mut SECTOR_BUFFER) {
        return false;
    }

    // Write entry to buffer
    let entry_bytes = core::slice::from_raw_parts(
        entry as *const FatDirEntry as *const u8,
        DIR_ENTRY_SIZE,
    );
    SECTOR_BUFFER[offset..offset + DIR_ENTRY_SIZE].copy_from_slice(entry_bytes);

    // Write sector back
    write_fn(mount.device, sector as u64, &SECTOR_BUFFER)
}

/// Find a free directory entry slot, returns the index
unsafe fn find_free_dir_entry(
    mount: &Fat32Mount,
    dir_cluster: u32,
) -> Option<u32> {
    let mut index = 0u32;
    let max_entries = 1024u32; // Reasonable limit

    loop {
        if index >= max_entries {
            return None; // Directory full
        }

        if let Some(entry) = read_dir_entry(mount, dir_cluster, index) {
            if entry.is_free() || entry.is_last() {
                return Some(index);
            }
            index += 1;
        } else {
            // Could not read entry - might need to extend directory
            return None;
        }
    }
}

/// Find a file in a directory
unsafe fn find_in_directory(
    mount: &Fat32Mount,
    dir_cluster: u32,
    name: &str,
) -> Option<(FatDirEntry, u32)> {
    let mut index = 0u32;

    // Convert name to 8.3 format for comparison
    let (short_name, short_ext) = crate::fs::path::string_to_short_name(name);

    loop {
        let entry = read_dir_entry(mount, dir_cluster, index)?;

        if entry.is_last() {
            break;
        }

        if entry.is_free() || entry.is_lfn() || entry.is_volume_label() {
            index += 1;
            continue;
        }

        // Check if name matches
        if entry.name_matches(
            core::str::from_utf8(&short_name).unwrap_or(""),
            core::str::from_utf8(&short_ext).unwrap_or("")
        ) {
            return Some((entry, index));
        }

        index += 1;
    }

    None
}

// ============================================================================
// VFS Interface
// ============================================================================

/// Mount a FAT32 file system
pub unsafe fn fat32_mount(fs_index: u16, device: *mut u8) -> FsStatus {
    let _guard = FAT32_LOCK.lock();

    // Find a free mount slot
    let mount_idx = match FAT32_MOUNTS.iter().position(|m| !m.mounted) {
        Some(i) => i,
        None => return FsStatus::TooManyFiles,
    };

    let mount = &mut FAT32_MOUNTS[mount_idx];

    // For now, we can't actually read from device without block device support
    // This would normally read the boot sector
    // For demonstration, we'll initialize with dummy values

    mount.mounted = true;
    mount.fs_index = fs_index;
    mount.device = device;
    mount.bytes_per_sector = 512;
    mount.sectors_per_cluster = 8;
    mount.cluster_size = 4096;
    mount.root_cluster = 2;

    FsStatus::Success
}

/// Unmount a FAT32 file system
pub unsafe fn fat32_unmount(fs_index: u16) -> FsStatus {
    let _guard = FAT32_LOCK.lock();

    for mount in FAT32_MOUNTS.iter_mut() {
        if mount.mounted && mount.fs_index == fs_index {
            mount.mounted = false;
            *mount = Fat32Mount::empty();
            return FsStatus::Success;
        }
    }

    FsStatus::NotMounted
}

/// Get FAT32 file system info
pub unsafe fn fat32_statfs(fs_index: u16) -> VfsFsInfo {
    let _guard = FAT32_LOCK.lock();

    for mount in FAT32_MOUNTS.iter() {
        if mount.mounted && mount.fs_index == fs_index {
            return VfsFsInfo {
                fs_type: FsType::Fat32,
                block_size: mount.cluster_size,
                total_blocks: mount.total_clusters as u64,
                free_blocks: mount.free_clusters.load(Ordering::SeqCst) as u64,
                total_files: 0, // FAT32 doesn't track this
                free_files: 0,
                label: [0; 16],
            };
        }
    }

    VfsFsInfo::empty()
}

/// Lookup a path component
pub unsafe fn fat32_lookup(
    fs_index: u16,
    parent: u64,
    name: &str,
) -> Result<u64, FsStatus> {
    let _guard = FAT32_LOCK.lock();

    for mount in FAT32_MOUNTS.iter() {
        if mount.mounted && mount.fs_index == fs_index {
            let parent_cluster = if parent == 0 {
                mount.root_cluster
            } else {
                parent as u32
            };

            if let Some((entry, entry_idx)) = find_in_directory(mount, parent_cluster, name) {
                let first_cluster = entry.first_cluster();

                // Register this file for size tracking (if not already registered)
                if find_open_file(fs_index, first_cluster).is_none() {
                    register_open_file(
                        fs_index,
                        first_cluster,
                        parent_cluster,
                        entry_idx,
                        entry.file_size,
                    );
                }

                // Return the first cluster as the node ID
                return Ok(first_cluster as u64);
            } else {
                return Err(FsStatus::NotFound);
            }
        }
    }

    Err(FsStatus::NotMounted)
}

/// Read directory entries
pub unsafe fn fat32_readdir(
    fs_index: u16,
    dir_id: u64,
    offset: u32,
    entry: &mut DirEntry,
) -> FsStatus {
    let _guard = FAT32_LOCK.lock();

    for mount in FAT32_MOUNTS.iter() {
        if mount.mounted && mount.fs_index == fs_index {
            let dir_cluster = if dir_id == 0 {
                mount.root_cluster
            } else {
                dir_id as u32
            };

            // Skip non-file entries
            let mut index = offset;
            loop {
                if let Some(fat_entry) = read_dir_entry(mount, dir_cluster, index) {
                    if fat_entry.is_last() {
                        return FsStatus::NoMoreEntries;
                    }

                    if fat_entry.is_free() || fat_entry.is_lfn() || fat_entry.is_volume_label() {
                        index += 1;
                        continue;
                    }

                    // Skip . and ..
                    if fat_entry.is_dot() {
                        index += 1;
                        continue;
                    }

                    // Copy entry info
                    let full_name = fat_entry.full_name();
                    let name_len = full_name.iter().position(|&b| b == 0).unwrap_or(13);
                    entry.name[..name_len].copy_from_slice(&full_name[..name_len]);
                    entry.name_len = name_len as u8;

                    entry.file_type = if fat_entry.is_directory() {
                        FileType::Directory
                    } else {
                        FileType::Regular
                    };

                    entry.size = fat_entry.file_size as u64;
                    entry.attributes = fat_entry.attr as u32;

                    // Set next_offset for continued iteration
                    entry.next_offset = index + 1;

                    return FsStatus::Success;
                } else {
                    return FsStatus::NoMoreEntries;
                }
            }
        }
    }

    FsStatus::NotMounted
}

/// Get file attributes
pub unsafe fn fat32_getattr(fs_index: u16, node_id: u64) -> Result<FileInfo, FsStatus> {
    let _guard = FAT32_LOCK.lock();

    let first_cluster = node_id as u32;

    // Look up the file in our open files table
    let file = match find_open_file(fs_index, first_cluster) {
        Some(f) => f,
        None => return Err(FsStatus::InvalidHandle),
    };

    // Find the mount
    for mount in FAT32_MOUNTS.iter() {
        if mount.mounted && mount.fs_index == fs_index {
            // Read the directory entry to get full info
            let entry = match read_dir_entry(mount, file.dir_cluster, file.entry_index) {
                Some(e) => e,
                None => return Err(FsStatus::IoError),
            };

            // Determine file type
            let file_type = if entry.is_directory() {
                FileType::Directory
            } else {
                FileType::Regular
            };

            // Convert FAT timestamps to simple ticks
            // FAT date: bits 15-9 = year-1980, bits 8-5 = month, bits 4-0 = day
            // FAT time: bits 15-11 = hours, bits 10-5 = minutes, bits 4-0 = seconds/2
            let created = fat_datetime_to_ticks(entry.create_date, entry.create_time);
            let modified = fat_datetime_to_ticks(entry.modify_date, entry.modify_time);
            let accessed = fat_datetime_to_ticks(entry.access_date, 0);

            // Calculate blocks allocated
            let cluster_size = mount.cluster_size as u64;
            let blocks = if file.file_size == 0 {
                0
            } else {
                ((file.file_size as u64 + cluster_size - 1) / cluster_size) * (cluster_size / 512)
            };

            return Ok(FileInfo {
                size: file.file_size as u64,
                file_type,
                attributes: entry.attr as u32,
                created,
                accessed,
                modified,
                nlink: 1,
                block_size: mount.cluster_size,
                blocks,
            });
        }
    }

    Err(FsStatus::NotMounted)
}

/// Convert FAT date and time to simple ticks (seconds since epoch)
fn fat_datetime_to_ticks(date: u16, time: u16) -> u64 {
    // FAT date format: bits 15-9 = year-1980, bits 8-5 = month, bits 4-0 = day
    let year = ((date >> 9) & 0x7F) as u64 + 1980;
    let month = ((date >> 5) & 0x0F) as u64;
    let day = (date & 0x1F) as u64;

    // FAT time format: bits 15-11 = hours, bits 10-5 = minutes, bits 4-0 = seconds/2
    let hours = ((time >> 11) & 0x1F) as u64;
    let minutes = ((time >> 5) & 0x3F) as u64;
    let seconds = ((time & 0x1F) as u64) * 2;

    // Simple conversion: approximate days since 1980 + time of day
    // Not accounting for leap years properly, just a rough approximation
    let days_since_1980 = (year - 1980) * 365 + (month - 1) * 30 + day;
    let seconds_of_day = hours * 3600 + minutes * 60 + seconds;

    days_since_1980 * 86400 + seconds_of_day
}

/// Read file data
pub unsafe fn fat32_read(
    fs_index: u16,
    node_id: u64,
    offset: u64,
    buf: &mut [u8],
) -> Result<usize, FsStatus> {
    let _guard = FAT32_LOCK.lock();

    for mount in FAT32_MOUNTS.iter() {
        if mount.mounted && mount.fs_index == fs_index {
            let start_cluster = node_id as u32;
            let read_fn = match mount.read_sector {
                Some(f) => f,
                None => return Err(FsStatus::IoError),
            };

            // Get the file size to limit the read
            let file_size = match find_open_file(fs_index, start_cluster) {
                Some(f) => f.file_size as u64,
                None => {
                    // File not in open file table - read without limit (fallback)
                    u64::MAX
                }
            };

            // Check if offset is beyond file size
            if offset >= file_size {
                return Ok(0);
            }

            // Calculate how many bytes we can actually read
            let remaining_in_file = (file_size - offset) as usize;
            let max_read = buf.len().min(remaining_in_file);

            if max_read == 0 {
                return Ok(0);
            }

            let mut bytes_read = 0;
            let mut current_offset = offset;

            while bytes_read < max_read {
                // Find cluster for current offset
                let cluster = match get_cluster_at_offset(mount, start_cluster, current_offset) {
                    Some(c) => c,
                    None => break, // End of cluster chain
                };

                // Calculate position within cluster
                let offset_in_cluster = (current_offset % mount.cluster_size as u64) as usize;
                let sector_in_cluster = offset_in_cluster / mount.bytes_per_sector as usize;
                let offset_in_sector = offset_in_cluster % mount.bytes_per_sector as usize;

                let sector = mount.cluster_to_sector(cluster) + sector_in_cluster as u32;

                // Read sector
                if !read_fn(mount.device, sector as u64, &mut SECTOR_BUFFER) {
                    return Err(FsStatus::IoError);
                }

                // Copy data - limit to max_read
                let bytes_in_sector = mount.bytes_per_sector as usize - offset_in_sector;
                let bytes_to_copy = bytes_in_sector.min(max_read - bytes_read);

                buf[bytes_read..bytes_read + bytes_to_copy]
                    .copy_from_slice(&SECTOR_BUFFER[offset_in_sector..offset_in_sector + bytes_to_copy]);

                bytes_read += bytes_to_copy;
                current_offset += bytes_to_copy as u64;
            }

            return Ok(bytes_read);
        }
    }

    Err(FsStatus::NotMounted)
}

/// Write file data
pub unsafe fn fat32_write(
    fs_index: u16,
    node_id: u64,
    offset: u64,
    buf: &[u8],
) -> Result<usize, FsStatus> {
    let _guard = FAT32_LOCK.lock();

    for mount in FAT32_MOUNTS.iter() {
        if mount.mounted && mount.fs_index == fs_index {
            let start_cluster = node_id as u32;
            let read_fn = match mount.read_sector {
                Some(f) => f,
                None => return Err(FsStatus::IoError),
            };
            let write_fn = match mount.write_sector {
                Some(f) => f,
                None => return Err(FsStatus::IoError),
            };

            let mut bytes_written = 0;
            let mut current_offset = offset;

            while bytes_written < buf.len() {
                // Find cluster for current offset
                let cluster = match get_cluster_at_offset(mount, start_cluster, current_offset) {
                    Some(c) => c,
                    None => break, // End of allocated clusters
                };

                // Calculate position within cluster
                let offset_in_cluster = (current_offset % mount.cluster_size as u64) as usize;
                let sector_in_cluster = offset_in_cluster / mount.bytes_per_sector as usize;
                let offset_in_sector = offset_in_cluster % mount.bytes_per_sector as usize;

                let sector = mount.cluster_to_sector(cluster) + sector_in_cluster as u32;

                // For partial sector writes, read first
                if offset_in_sector != 0 || (buf.len() - bytes_written) < mount.bytes_per_sector as usize {
                    if !read_fn(mount.device, sector as u64, &mut SECTOR_BUFFER) {
                        return Err(FsStatus::IoError);
                    }
                }

                // Copy data to sector buffer
                let bytes_in_sector = mount.bytes_per_sector as usize - offset_in_sector;
                let bytes_to_copy = bytes_in_sector.min(buf.len() - bytes_written);

                SECTOR_BUFFER[offset_in_sector..offset_in_sector + bytes_to_copy]
                    .copy_from_slice(&buf[bytes_written..bytes_written + bytes_to_copy]);

                // Write sector
                if !write_fn(mount.device, sector as u64, &SECTOR_BUFFER) {
                    return Err(FsStatus::IoError);
                }

                bytes_written += bytes_to_copy;
                current_offset += bytes_to_copy as u64;
            }

            // Update file size if we wrote past the current end
            if bytes_written > 0 {
                let new_end = (offset + bytes_written as u64) as u32;
                update_open_file_size(fs_index, start_cluster, new_end);
            }

            return Ok(bytes_written);
        }
    }

    Err(FsStatus::NotMounted)
}

/// Create a new file
pub unsafe fn fat32_create(
    fs_index: u16,
    parent: u64,
    name: &str,
    _attrs: u32,
) -> Result<u64, FsStatus> {
    let _guard = FAT32_LOCK.lock();

    for mount in FAT32_MOUNTS.iter() {
        if mount.mounted && mount.fs_index == fs_index {
            let parent_cluster = if parent == 0 {
                mount.root_cluster
            } else {
                parent as u32
            };

            // Check if file already exists
            if find_in_directory(mount, parent_cluster, name).is_some() {
                return Err(FsStatus::AlreadyExists);
            }

            // Find a free directory entry
            let entry_index = find_free_dir_entry(mount, parent_cluster)
                .ok_or(FsStatus::NoSpace)?;

            // Allocate a cluster for the new file
            let cluster = alloc_cluster(mount)
                .ok_or(FsStatus::NoSpace)?;

            // Convert filename to 8.3 format
            let (short_name, short_ext) = crate::fs::path::string_to_short_name(name);

            // Create directory entry
            let mut entry = FatDirEntry::empty();
            entry.name.copy_from_slice(&short_name);
            entry.ext.copy_from_slice(&short_ext);
            entry.attr = file_attr::ATTR_ARCHIVE;
            entry.set_first_cluster(cluster);
            entry.file_size = 0;

            // Set creation/modification time (simple timestamp)
            // DOS time: bits 15-11 = hour, 10-5 = minute, 4-0 = second/2
            // DOS date: bits 15-9 = year-1980, 8-5 = month, 4-0 = day
            // For now, use a fixed timestamp (2025-01-01 00:00:00)
            let date: u16 = ((2025 - 1980) << 9) | (1 << 5) | 1; // 2025-01-01
            let time: u16 = 0; // 00:00:00

            entry.create_date = date;
            entry.create_time = time;
            entry.modify_date = date;
            entry.modify_time = time;
            entry.access_date = date;

            // Write directory entry
            if !write_dir_entry(mount, parent_cluster, entry_index, &entry) {
                // Failed to write entry, free the cluster
                free_cluster_chain(mount, cluster);
                return Err(FsStatus::IoError);
            }

            // Register the new file for size tracking
            register_open_file(
                fs_index,
                cluster,
                parent_cluster,
                entry_index,
                0, // Initial size is 0
            );

            crate::serial_println!(
                "[FAT32] Created file '{}' cluster={} entry={}",
                name, cluster, entry_index
            );

            return Ok(cluster as u64);
        }
    }

    Err(FsStatus::NotMounted)
}

/// Close a file (flush metadata to disk)
pub unsafe fn fat32_close(fs_index: u16, node_id: u64) -> FsStatus {
    let _guard = FAT32_LOCK.lock();

    let first_cluster = node_id as u32;

    // Find and close the open file entry
    close_open_file(fs_index, first_cluster);

    FsStatus::Success
}

/// Sync/flush file data and metadata to disk
pub unsafe fn fat32_sync(fs_index: u16, node_id: u64) -> FsStatus {
    let _guard = FAT32_LOCK.lock();

    let first_cluster = node_id as u32;

    // Find the open file entry
    let file = match find_open_file(fs_index, first_cluster) {
        Some(f) => f,
        None => return FsStatus::InvalidHandle,
    };

    // Find the mount to get access to write functions
    for mount in FAT32_MOUNTS.iter() {
        if mount.mounted && mount.fs_index == fs_index {
            // Flush the file metadata (size) to disk
            if flush_open_file(mount, file) {
                crate::serial_println!("[FAT32] Synced file (cluster={}, size={})",
                    first_cluster, file.file_size);
                return FsStatus::Success;
            } else {
                return FsStatus::IoError;
            }
        }
    }

    FsStatus::NotMounted
}

/// Delete a file
pub unsafe fn fat32_unlink(
    fs_index: u16,
    parent: u64,
    name: &str,
) -> FsStatus {
    let _guard = FAT32_LOCK.lock();

    for mount in FAT32_MOUNTS.iter() {
        if mount.mounted && mount.fs_index == fs_index {
            let parent_cluster = if parent == 0 {
                mount.root_cluster
            } else {
                parent as u32
            };

            // Find the file in the directory
            if let Some((entry, entry_idx)) = find_in_directory(mount, parent_cluster, name) {
                // Don't delete directories with this function
                if entry.is_directory() {
                    return FsStatus::IsDirectory;
                }

                let first_cluster = entry.first_cluster();

                // Close any open handles to this file
                close_open_file(fs_index, first_cluster);

                // Mark directory entry as deleted
                let mut deleted_entry = entry;
                deleted_entry.name[0] = entry_status::FREE;

                if !write_dir_entry(mount, parent_cluster, entry_idx, &deleted_entry) {
                    return FsStatus::IoError;
                }

                // Free the cluster chain
                if first_cluster >= 2 {
                    free_cluster_chain(mount, first_cluster);
                }

                crate::serial_println!(
                    "[FAT32] Deleted file '{}' cluster={}",
                    name, first_cluster
                );

                return FsStatus::Success;
            } else {
                return FsStatus::NotFound;
            }
        }
    }

    FsStatus::NotMounted
}

/// Create a new directory
pub unsafe fn fat32_mkdir(
    fs_index: u16,
    parent: u64,
    name: &str,
) -> Result<u64, FsStatus> {
    let _guard = FAT32_LOCK.lock();

    for mount in FAT32_MOUNTS.iter() {
        if mount.mounted && mount.fs_index == fs_index {
            let parent_cluster = if parent == 0 {
                mount.root_cluster
            } else {
                parent as u32
            };

            // Check if directory already exists
            if find_in_directory(mount, parent_cluster, name).is_some() {
                return Err(FsStatus::AlreadyExists);
            }

            // Find a free directory entry in the parent
            let entry_index = find_free_dir_entry(mount, parent_cluster)
                .ok_or(FsStatus::NoSpace)?;

            // Allocate a cluster for the new directory
            let dir_cluster = alloc_cluster(mount)
                .ok_or(FsStatus::NoSpace)?;

            // Convert name to 8.3 format
            let (short_name, short_ext) = crate::fs::path::string_to_short_name(name);

            // Create timestamp
            let date: u16 = ((2025 - 1980) << 9) | (1 << 5) | 1; // 2025-01-01
            let time: u16 = 0; // 00:00:00

            // Create directory entry in parent
            let mut entry = FatDirEntry::empty();
            entry.name.copy_from_slice(&short_name);
            entry.ext.copy_from_slice(&short_ext);
            entry.attr = file_attr::ATTR_DIRECTORY;
            entry.set_first_cluster(dir_cluster);
            entry.file_size = 0; // Directories have size 0

            entry.create_date = date;
            entry.create_time = time;
            entry.modify_date = date;
            entry.modify_time = time;
            entry.access_date = date;

            // Write directory entry to parent
            if !write_dir_entry(mount, parent_cluster, entry_index, &entry) {
                free_cluster_chain(mount, dir_cluster);
                return Err(FsStatus::IoError);
            }

            // Initialize the new directory's cluster with "." and ".." entries
            // First, zero out the entire cluster
            let read_fn = mount.read_sector.unwrap();
            let write_fn = mount.write_sector.unwrap();
            let cluster_start = mount.cluster_to_sector(dir_cluster);

            for i in 0..mount.sectors_per_cluster {
                // Zero the sector
                for b in SECTOR_BUFFER.iter_mut() {
                    *b = 0;
                }
                if !(write_fn)(mount.device, (cluster_start + i) as u64, &SECTOR_BUFFER) {
                    // Failed to initialize, try to clean up
                    let mut deleted = entry;
                    deleted.name[0] = entry_status::FREE;
                    let _ = write_dir_entry(mount, parent_cluster, entry_index, &deleted);
                    free_cluster_chain(mount, dir_cluster);
                    return Err(FsStatus::IoError);
                }
            }

            // Now create "." entry (points to self)
            let mut dot_entry = FatDirEntry::empty();
            dot_entry.name = [b'.', b' ', b' ', b' ', b' ', b' ', b' ', b' '];
            dot_entry.ext = [b' ', b' ', b' '];
            dot_entry.attr = file_attr::ATTR_DIRECTORY;
            dot_entry.set_first_cluster(dir_cluster);
            dot_entry.create_date = date;
            dot_entry.create_time = time;
            dot_entry.modify_date = date;
            dot_entry.modify_time = time;
            dot_entry.access_date = date;

            // Create ".." entry (points to parent)
            let mut dotdot_entry = FatDirEntry::empty();
            dotdot_entry.name = [b'.', b'.', b' ', b' ', b' ', b' ', b' ', b' '];
            dotdot_entry.ext = [b' ', b' ', b' '];
            dotdot_entry.attr = file_attr::ATTR_DIRECTORY;
            // For root directory, ".." cluster is 0
            if parent_cluster == mount.root_cluster {
                dotdot_entry.set_first_cluster(0);
            } else {
                dotdot_entry.set_first_cluster(parent_cluster);
            }
            dotdot_entry.create_date = date;
            dotdot_entry.create_time = time;
            dotdot_entry.modify_date = date;
            dotdot_entry.modify_time = time;
            dotdot_entry.access_date = date;

            // Read the first sector of the new directory
            if !(read_fn)(mount.device, cluster_start as u64, &mut SECTOR_BUFFER) {
                return Err(FsStatus::IoError);
            }

            // Write "." and ".." entries
            let entries = &mut *(SECTOR_BUFFER.as_mut_ptr() as *mut [FatDirEntry; 16]);
            entries[0] = dot_entry;
            entries[1] = dotdot_entry;

            // Write back the sector
            if !(write_fn)(mount.device, cluster_start as u64, &SECTOR_BUFFER) {
                return Err(FsStatus::IoError);
            }

            crate::serial_println!(
                "[FAT32] Created directory '{}' cluster={} entry={}",
                name, dir_cluster, entry_index
            );

            return Ok(dir_cluster as u64);
        }
    }

    Err(FsStatus::NotMounted)
}

/// Check if a directory is empty (only contains "." and ".." entries)
unsafe fn is_directory_empty(mount: &Fat32Mount, dir_cluster: u32) -> bool {
    let read_fn = match mount.read_sector {
        Some(f) => f,
        None => return false,
    };

    let mut current_cluster = dir_cluster;
    let entries_per_sector = mount.bytes_per_sector as usize / DIR_ENTRY_SIZE;

    loop {
        let cluster_start = mount.cluster_to_sector(current_cluster);

        for sector_offset in 0..mount.sectors_per_cluster {
            let sector = cluster_start + sector_offset;

            if !read_fn(mount.device, sector as u64, &mut SECTOR_BUFFER) {
                return false;
            }

            let entries = &*(SECTOR_BUFFER.as_ptr() as *const [FatDirEntry; 16]);

            for i in 0..entries_per_sector.min(16) {
                let entry = &entries[i];

                // End of directory
                if entry.name[0] == entry_status::FREE_LAST {
                    return true;
                }

                // Skip deleted entries
                if entry.name[0] == entry_status::FREE {
                    continue;
                }

                // Skip LFN entries
                if entry.is_lfn() {
                    continue;
                }

                // Skip "." and ".." entries
                if entry.name[0] == b'.' {
                    // Check if it's "." or ".."
                    if entry.name[1] == b' ' || entry.name[1] == b'.' {
                        continue;
                    }
                }

                // Found a non-dot entry, directory is not empty
                return false;
            }
        }

        // Follow cluster chain
        let next = match read_fat_entry(mount, current_cluster) {
            Some(n) => n,
            None => break,
        };

        if cluster_values::is_eoc(next) {
            break;
        }

        current_cluster = next;
    }

    true
}

/// Remove a directory
pub unsafe fn fat32_rmdir(
    fs_index: u16,
    parent: u64,
    name: &str,
) -> FsStatus {
    let _guard = FAT32_LOCK.lock();

    for mount in FAT32_MOUNTS.iter() {
        if mount.mounted && mount.fs_index == fs_index {
            let parent_cluster = if parent == 0 {
                mount.root_cluster
            } else {
                parent as u32
            };

            // Find the directory entry
            if let Some((entry, entry_idx)) = find_in_directory(mount, parent_cluster, name) {
                // Must be a directory
                if !entry.is_directory() {
                    return FsStatus::NotDirectory;
                }

                let dir_cluster = entry.first_cluster();

                // Check if directory is empty
                if !is_directory_empty(mount, dir_cluster) {
                    return FsStatus::DirectoryNotEmpty;
                }

                // Mark directory entry as deleted
                let mut deleted_entry = entry;
                deleted_entry.name[0] = entry_status::FREE;

                if !write_dir_entry(mount, parent_cluster, entry_idx, &deleted_entry) {
                    return FsStatus::IoError;
                }

                // Free the cluster chain
                if dir_cluster >= 2 {
                    free_cluster_chain(mount, dir_cluster);
                }

                crate::serial_println!(
                    "[FAT32] Removed directory '{}' cluster={}",
                    name, dir_cluster
                );

                return FsStatus::Success;
            } else {
                return FsStatus::NotFound;
            }
        }
    }

    FsStatus::NotMounted
}

/// Rename/move a file or directory
pub unsafe fn fat32_rename(
    fs_index: u16,
    old_parent: u64,
    old_name: &str,
    new_parent: u64,
    new_name: &str,
) -> FsStatus {
    let _guard = FAT32_LOCK.lock();

    for mount in FAT32_MOUNTS.iter() {
        if mount.mounted && mount.fs_index == fs_index {
            let old_parent_cluster = if old_parent == 0 {
                mount.root_cluster
            } else {
                old_parent as u32
            };

            let new_parent_cluster = if new_parent == 0 {
                mount.root_cluster
            } else {
                new_parent as u32
            };

            // Find the source entry
            let (mut entry, old_entry_idx) = match find_in_directory(mount, old_parent_cluster, old_name) {
                Some(e) => e,
                None => return FsStatus::NotFound,
            };

            // Check if destination already exists
            if find_in_directory(mount, new_parent_cluster, new_name).is_some() {
                return FsStatus::AlreadyExists;
            }

            // Convert new name to 8.3 format
            let (short_name, short_ext) = crate::fs::path::string_to_short_name(new_name);

            // Check if it's a same-directory rename or a cross-directory move
            if old_parent_cluster == new_parent_cluster {
                // Same directory - just update the name in place
                entry.name.copy_from_slice(&short_name);
                entry.ext.copy_from_slice(&short_ext);

                // Update modification time
                let date: u16 = ((2025 - 1980) << 9) | (1 << 5) | 1;
                entry.modify_date = date;

                if !write_dir_entry(mount, old_parent_cluster, old_entry_idx, &entry) {
                    return FsStatus::IoError;
                }

                crate::serial_println!(
                    "[FAT32] Renamed '{}' to '{}' in same directory",
                    old_name, new_name
                );
            } else {
                // Cross-directory move:
                // 1. Create entry in new directory with new name
                // 2. Delete entry from old directory

                // Find a free slot in the destination directory
                let new_entry_idx = match find_free_dir_entry(mount, new_parent_cluster) {
                    Some(idx) => idx,
                    None => return FsStatus::NoSpace,
                };

                // Update the entry with new name
                entry.name.copy_from_slice(&short_name);
                entry.ext.copy_from_slice(&short_ext);

                // Update modification time
                let date: u16 = ((2025 - 1980) << 9) | (1 << 5) | 1;
                entry.modify_date = date;

                // Write to new location
                if !write_dir_entry(mount, new_parent_cluster, new_entry_idx, &entry) {
                    return FsStatus::IoError;
                }

                // If moving a directory, update the ".." entry to point to new parent
                if entry.is_directory() {
                    let dir_cluster = entry.first_cluster();
                    if dir_cluster >= 2 {
                        // Find and update the ".." entry
                        if let Some((mut dotdot, dotdot_idx)) = find_dotdot_entry(mount, dir_cluster) {
                            // Set ".." to point to new parent
                            let parent_cluster = if new_parent_cluster == mount.root_cluster {
                                0  // Root directory is represented as 0 in ".."
                            } else {
                                new_parent_cluster
                            };
                            dotdot.set_first_cluster(parent_cluster);
                            write_dir_entry(mount, dir_cluster, dotdot_idx, &dotdot);
                        }
                    }
                }

                // Delete from old location (mark as free)
                let mut deleted_entry = entry.clone();
                deleted_entry.name[0] = entry_status::FREE;
                if !write_dir_entry(mount, old_parent_cluster, old_entry_idx, &deleted_entry) {
                    // Rollback: delete from new location too
                    let mut rollback = entry.clone();
                    rollback.name[0] = entry_status::FREE;
                    write_dir_entry(mount, new_parent_cluster, new_entry_idx, &rollback);
                    return FsStatus::IoError;
                }

                crate::serial_println!(
                    "[FAT32] Moved '{}' to '{}' (cross-directory)",
                    old_name, new_name
                );
            }

            return FsStatus::Success;
        }
    }

    FsStatus::NotMounted
}

/// Find the ".." entry in a directory
unsafe fn find_dotdot_entry(
    mount: &Fat32Mount,
    dir_cluster: u32,
) -> Option<(FatDirEntry, u32)> {
    // ".." is typically the second entry (index 1) in a directory
    for index in 0..4 {
        if let Some(entry) = read_dir_entry(mount, dir_cluster, index) {
            if entry.is_dot() && entry.name[1] == b'.' {
                return Some((entry, index));
            }
        }
    }
    None
}

/// Truncate a file to a specific size
pub unsafe fn fat32_truncate(fs_index: u16, node_id: u64, new_size: u64) -> FsStatus {
    let _guard = FAT32_LOCK.lock();

    let first_cluster = node_id as u32;

    for mount in FAT32_MOUNTS.iter() {
        if mount.mounted && mount.fs_index == fs_index {
            // Find the open file entry
            let file = match find_open_file(fs_index, first_cluster) {
                Some(f) => f,
                None => return FsStatus::InvalidHandle,
            };

            let current_size = file.file_size as u64;
            let new_size_u32 = new_size as u32;

            // Nothing to do if size unchanged
            if new_size == current_size {
                return FsStatus::Success;
            }

            let cluster_size = mount.cluster_size as u64;

            if new_size < current_size {
                // Shrinking the file
                if new_size == 0 {
                    // Truncate to zero - free all clusters
                    if first_cluster >= 2 {
                        free_cluster_chain(mount, first_cluster);
                    }
                    // Update directory entry with size 0 and cluster 0
                    if let Some(mut entry) = read_dir_entry(mount, file.dir_cluster, file.entry_index) {
                        entry.file_size = 0;
                        entry.set_first_cluster(0);
                        if !write_dir_entry(mount, file.dir_cluster, file.entry_index, &entry) {
                            return FsStatus::IoError;
                        }
                    }
                    file.file_size = 0;
                    file.dirty = false;

                    crate::serial_println!(
                        "[FAT32] Truncated file to 0 bytes (freed all clusters)"
                    );
                } else {
                    // Calculate clusters needed for new size
                    let clusters_needed = ((new_size + cluster_size - 1) / cluster_size) as u32;

                    // Walk to the last cluster we want to keep
                    let mut cluster = first_cluster;
                    for _ in 1..clusters_needed {
                        if let Some(next) = read_fat_entry(mount, cluster) {
                            if cluster_values::is_eoc(next) {
                                break;
                            }
                            cluster = next;
                        } else {
                            return FsStatus::IoError;
                        }
                    }

                    // Get the next cluster (to be freed)
                    if let Some(next) = read_fat_entry(mount, cluster) {
                        if !cluster_values::is_eoc(next) {
                            // Free the chain starting from next
                            free_cluster_chain(mount, next);
                        }
                    }

                    // Mark current cluster as end of chain
                    if !write_fat_entry(mount, cluster, cluster_values::EOC) {
                        return FsStatus::IoError;
                    }

                    // Update directory entry
                    if let Some(mut entry) = read_dir_entry(mount, file.dir_cluster, file.entry_index) {
                        entry.file_size = new_size_u32;
                        if !write_dir_entry(mount, file.dir_cluster, file.entry_index, &entry) {
                            return FsStatus::IoError;
                        }
                    }

                    file.file_size = new_size_u32;
                    file.dirty = false;

                    crate::serial_println!(
                        "[FAT32] Truncated file from {} to {} bytes",
                        current_size, new_size
                    );
                }
            } else {
                // Extending the file
                let current_clusters = if current_size == 0 {
                    0
                } else {
                    ((current_size + cluster_size - 1) / cluster_size) as u32
                };
                let new_clusters = ((new_size + cluster_size - 1) / cluster_size) as u32;
                let clusters_to_add = new_clusters - current_clusters;

                if clusters_to_add > 0 {
                    if current_clusters == 0 {
                        // File has no clusters, allocate the first one
                        let new_cluster = match alloc_cluster(mount) {
                            Some(c) => c,
                            None => return FsStatus::NoSpace,
                        };

                        // Zero the new cluster
                        zero_cluster(mount, new_cluster);

                        // Update directory entry with new first cluster
                        if let Some(mut entry) = read_dir_entry(mount, file.dir_cluster, file.entry_index) {
                            entry.set_first_cluster(new_cluster);
                            entry.file_size = new_size_u32;
                            if !write_dir_entry(mount, file.dir_cluster, file.entry_index, &entry) {
                                free_cluster_chain(mount, new_cluster);
                                return FsStatus::IoError;
                            }
                        }

                        // Allocate remaining clusters
                        let mut last_cluster = new_cluster;
                        for _ in 1..new_clusters {
                            let next = match alloc_cluster(mount) {
                                Some(c) => c,
                                None => return FsStatus::NoSpace,
                            };
                            zero_cluster(mount, next);
                            write_fat_entry(mount, last_cluster, next);
                            last_cluster = next;
                        }
                    } else {
                        // Walk to the last cluster
                        let mut last_cluster = first_cluster;
                        loop {
                            if let Some(next) = read_fat_entry(mount, last_cluster) {
                                if cluster_values::is_eoc(next) {
                                    break;
                                }
                                last_cluster = next;
                            } else {
                                return FsStatus::IoError;
                            }
                        }

                        // Allocate and link new clusters
                        for _ in 0..clusters_to_add {
                            let new_cluster = match alloc_cluster(mount) {
                                Some(c) => c,
                                None => return FsStatus::NoSpace,
                            };
                            zero_cluster(mount, new_cluster);
                            write_fat_entry(mount, last_cluster, new_cluster);
                            last_cluster = new_cluster;
                        }

                        // Update directory entry
                        if let Some(mut entry) = read_dir_entry(mount, file.dir_cluster, file.entry_index) {
                            entry.file_size = new_size_u32;
                            if !write_dir_entry(mount, file.dir_cluster, file.entry_index, &entry) {
                                return FsStatus::IoError;
                            }
                        }
                    }
                } else {
                    // No new clusters needed, just update size
                    if let Some(mut entry) = read_dir_entry(mount, file.dir_cluster, file.entry_index) {
                        entry.file_size = new_size_u32;
                        if !write_dir_entry(mount, file.dir_cluster, file.entry_index, &entry) {
                            return FsStatus::IoError;
                        }
                    }
                }

                file.file_size = new_size_u32;
                file.dirty = false;

                crate::serial_println!(
                    "[FAT32] Extended file from {} to {} bytes",
                    current_size, new_size
                );
            }

            return FsStatus::Success;
        }
    }

    FsStatus::NotMounted
}

/// Zero a cluster (fill with zeros)
unsafe fn zero_cluster(mount: &Fat32Mount, cluster: u32) {
    let write_fn = match mount.write_sector {
        Some(f) => f,
        None => return,
    };

    // Zero the sector buffer
    SECTOR_BUFFER.fill(0);

    // Write zeros to all sectors in the cluster
    let start_sector = mount.cluster_to_sector(cluster);
    for i in 0..mount.sectors_per_cluster {
        write_fn(mount.device, (start_sector + i) as u64, &SECTOR_BUFFER);
    }
}

/// Get the size of an open file
pub unsafe fn fat32_getsize(fs_index: u16, node_id: u64) -> Result<u64, FsStatus> {
    let _guard = FAT32_LOCK.lock();

    let first_cluster = node_id as u32;

    // Look up the file in our open files table
    match find_open_file(fs_index, first_cluster) {
        Some(file) => Ok(file.file_size as u64),
        None => Err(FsStatus::InvalidHandle),
    }
}

/// Create a FAT32 operations structure
pub fn fat32_ops() -> FsOps {
    FsOps {
        mount: Some(fat32_mount),
        unmount: Some(fat32_unmount),
        statfs: Some(fat32_statfs),
        lookup: Some(fat32_lookup),
        readdir: Some(fat32_readdir),
        getattr: Some(fat32_getattr),
        read: Some(fat32_read),
        write: Some(fat32_write),
        create: Some(fat32_create),
        mkdir: Some(fat32_mkdir),
        unlink: Some(fat32_unlink),
        rmdir: Some(fat32_rmdir),
        truncate: Some(fat32_truncate),
        close: Some(fat32_close),
        rename: Some(fat32_rename),
        getsize: Some(fat32_getsize),
        sync: Some(fat32_sync),
    }
}

/// Get mount count
pub fn fat32_mount_count() -> u32 {
    unsafe {
        FAT32_MOUNTS.iter().filter(|m| m.mounted).count() as u32
    }
}

// ============================================================================
// Volume Integration
// ============================================================================

/// Mount a volume with callbacks from the block layer
///
/// This is the proper mount function that reads the boot sector
/// and initializes the FAT32 mount structure correctly.
pub unsafe fn mount_volume(
    fs_index: u16,
    device: *mut u8,
    read_fn: unsafe fn(*mut u8, u64, &mut [u8]) -> bool,
    write_fn: unsafe fn(*mut u8, u64, &[u8]) -> bool,
) -> FsStatus {
    let _guard = FAT32_LOCK.lock();

    // Find free mount slot
    let mount_idx = match FAT32_MOUNTS.iter().position(|m| !m.mounted) {
        Some(i) => i,
        None => return FsStatus::TooManyFiles,
    };

    // Read boot sector
    if !read_fn(device, 0, &mut SECTOR_BUFFER) {
        return FsStatus::IoError;
    }

    // Parse boot sector
    let bs = &*(SECTOR_BUFFER.as_ptr() as *const Fat32BootSector);

    // Validate boot sector
    if bs.jump[0] != 0xEB && bs.jump[0] != 0xE9 {
        return FsStatus::InvalidFileSystem;
    }

    if bs.signature != [0x55, 0xAA] {
        return FsStatus::InvalidFileSystem;
    }

    // Calculate file system parameters
    let bytes_per_sector = bs.bpb.bytes_per_sector as u32;
    let sectors_per_cluster = bs.bpb.sectors_per_cluster as u32;
    let reserved_sectors = bs.bpb.reserved_sectors as u32;
    let num_fats = bs.bpb.num_fats as u32;
    let fat_sectors = bs.ext_bpb.sectors_per_fat_32;
    let root_cluster = bs.ext_bpb.root_cluster;

    // First data sector = reserved + (num_fats * fat_size)
    let fat_start = reserved_sectors;
    let data_start = reserved_sectors + (num_fats * fat_sectors);

    // Calculate total clusters
    let total_sectors = if bs.bpb.total_sectors_16 != 0 {
        bs.bpb.total_sectors_16 as u32
    } else {
        bs.bpb.total_sectors_32
    };

    let data_sectors = total_sectors.saturating_sub(data_start);
    let total_clusters = data_sectors / sectors_per_cluster;

    // Initialize mount structure
    let mount = &mut FAT32_MOUNTS[mount_idx];
    mount.mounted = true;
    mount.fs_index = fs_index;
    mount.device = device;
    mount.boot_sector = *bs;
    mount.bytes_per_sector = bytes_per_sector;
    mount.sectors_per_cluster = sectors_per_cluster;
    mount.cluster_size = bytes_per_sector * sectors_per_cluster;
    mount.fat_start = fat_start;
    mount.fat_sectors = fat_sectors;
    mount.data_start = data_start;
    mount.root_cluster = root_cluster;
    mount.total_clusters = total_clusters;
    mount.read_sector = Some(read_fn);
    mount.write_sector = Some(write_fn);

    // Try to read FSInfo sector for free cluster info
    let fsinfo_sector = bs.ext_bpb.fs_info_sector as u64;
    if fsinfo_sector > 0 && read_fn(device, fsinfo_sector, &mut SECTOR_BUFFER) {
        let fsinfo = &*(SECTOR_BUFFER.as_ptr() as *const FsInfo);
        if fsinfo.is_valid() {
            mount.free_clusters.store(fsinfo.free_count, Ordering::SeqCst);
            mount.next_free.store(fsinfo.next_free, Ordering::SeqCst);
        }
    }

    crate::serial_println!(
        "[FAT32] Mounted fs_index={} clusters={} cluster_size={}",
        fs_index,
        total_clusters,
        mount.cluster_size
    );

    FsStatus::Success
}

/// Get a FAT32 mount by fs_index
pub fn get_mount(fs_index: u16) -> Option<&'static Fat32Mount> {
    unsafe {
        for mount in FAT32_MOUNTS.iter() {
            if mount.mounted && mount.fs_index == fs_index {
                return Some(mount);
            }
        }
    }
    None
}

/// Initialize FAT32 file operations
pub fn init() {
    crate::serial_println!("[FS] FAT32 file operations initialized");
}
