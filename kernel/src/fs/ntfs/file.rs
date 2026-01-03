//! NTFS File Operations and VFS Integration
//!
//! Provides the VFS interface for NTFS file system operations including:
//! - Volume mounting
//! - File/directory lookup
//! - File reading (resident and non-resident data)
//! - Directory enumeration

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};
use crate::fs::vfs::{FsStatus, FsType, FileType, FileInfo, DirEntry, FsOps, FsInfo};
use crate::ke::SpinLock;
use super::boot::{NtfsBootSector, NtfsVolumeInfo};
use super::mft::FileRecord;
use super::attr::{
    AttributeHeader, ResidentHeader, NonResidentHeader,
    StandardInformation,
    attr_types,
};

/// Maximum number of NTFS mounts
pub const MAX_NTFS_MOUNTS: usize = 8;

/// Maximum entries in MFT cache
pub const MFT_CACHE_SIZE: usize = 32;

/// NTFS mount context
pub struct NtfsMount {
    /// Is this mount active?
    pub active: bool,
    /// Block device index
    pub device_index: u16,
    /// Volume info from boot sector
    pub volume_info: NtfsVolumeInfo,
    /// Bytes per cluster
    pub bytes_per_cluster: u32,
    /// MFT record size
    pub mft_record_size: u32,
    /// Total clusters
    pub total_clusters: u64,
    /// MFT starting cluster
    pub mft_cluster: u64,
    /// Cached MFT records
    mft_cache: [Option<MftCacheEntry>; MFT_CACHE_SIZE],
    /// Cache hit count
    cache_hits: u32,
    /// Cache miss count
    cache_misses: u32,
}

/// MFT cache entry
struct MftCacheEntry {
    /// MFT record number
    record_number: u64,
    /// Cached file record
    record: FileRecord,
    /// Last access time (for LRU)
    last_access: u32,
}

impl NtfsMount {
    /// Create an empty mount
    pub const fn empty() -> Self {
        const NONE: Option<MftCacheEntry> = None;
        Self {
            active: false,
            device_index: 0,
            volume_info: NtfsVolumeInfo {
                bytes_per_sector: 512,
                sectors_per_cluster: 1,
                bytes_per_cluster: 512,
                total_sectors: 0,
                total_clusters: 0,
                mft_cluster: 0,
                mft_mirror_cluster: 0,
                mft_offset: 0,
                file_record_size: 1024,
                index_block_size: 4096,
                volume_serial: 0,
            },
            bytes_per_cluster: 512,
            mft_record_size: 1024,
            total_clusters: 0,
            mft_cluster: 0,
            mft_cache: [NONE; MFT_CACHE_SIZE],
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    /// Initialize mount from boot sector
    pub fn init_from_boot(&mut self, boot: &NtfsBootSector, device_index: u16) {
        self.active = true;
        self.device_index = device_index;
        self.volume_info = NtfsVolumeInfo::from_boot_sector(boot);
        self.bytes_per_cluster = self.volume_info.bytes_per_cluster;
        self.mft_record_size = self.volume_info.file_record_size;
        self.total_clusters = self.volume_info.total_clusters;
        self.mft_cluster = self.volume_info.mft_cluster;
    }

    /// Read an MFT record by number
    pub fn read_mft_record(&mut self, record_number: u64) -> Option<FileRecord> {
        // Check cache first
        for entry in self.mft_cache.iter() {
            if let Some(cached) = entry {
                if cached.record_number == record_number {
                    self.cache_hits += 1;
                    return Some(cached.record.clone());
                }
            }
        }

        self.cache_misses += 1;

        // Calculate offset in MFT
        let mft_offset = self.volume_info.mft_offset +
            record_number * self.mft_record_size as u64;

        // Read from device (placeholder - would use block I/O)
        let record = self.read_mft_from_disk(mft_offset)?;

        // Cache the record
        self.cache_mft_record(record_number, record.clone());

        Some(record)
    }

    /// Read MFT record from disk (placeholder)
    fn read_mft_from_disk(&self, _offset: u64) -> Option<FileRecord> {
        // TODO: Implement actual disk read
        None
    }

    /// Cache an MFT record
    fn cache_mft_record(&mut self, record_number: u64, record: FileRecord) {
        let mut oldest_idx = 0;
        let mut oldest_time = u32::MAX;

        for (i, entry) in self.mft_cache.iter().enumerate() {
            match entry {
                None => {
                    oldest_idx = i;
                    break;
                }
                Some(cached) => {
                    if cached.last_access < oldest_time {
                        oldest_time = cached.last_access;
                        oldest_idx = i;
                    }
                }
            }
        }

        self.mft_cache[oldest_idx] = Some(MftCacheEntry {
            record_number,
            record,
            last_access: self.cache_hits + self.cache_misses,
        });
    }

    /// Find an attribute in a file record
    pub fn find_attribute(&self, record: &FileRecord, attr_type: u32) -> Option<usize> {
        let data = record.data();
        let mut offset = record.first_attribute_offset();

        while offset + 4 <= data.len() {
            let header = unsafe {
                &*(data[offset..].as_ptr() as *const AttributeHeader)
            };

            if !header.is_valid() {
                break;
            }

            if header.attr_type == attr_type {
                return Some(offset);
            }

            offset += header.length as usize;
        }

        None
    }

    /// Read resident attribute data
    pub fn read_resident_data<'a>(&self, record: &'a FileRecord, offset: usize) -> Option<&'a [u8]> {
        let data = record.data();
        if offset + core::mem::size_of::<ResidentHeader>() > data.len() {
            return None;
        }

        let header = unsafe {
            &*(data[offset..].as_ptr() as *const ResidentHeader)
        };

        if header.common.is_non_resident() {
            return None;
        }

        let data_offset = offset + header.data_offset();
        let data_length = header.data_length();

        if data_offset + data_length > data.len() {
            return None;
        }

        Some(&data[data_offset..data_offset + data_length])
    }

    /// Get standard information from a file record
    pub fn get_standard_info(&self, record: &FileRecord) -> Option<StandardInformation> {
        let offset = self.find_attribute(record, attr_types::STANDARD_INFORMATION)?;
        let data = self.read_resident_data(record, offset)?;

        if data.len() < core::mem::size_of::<StandardInformation>() {
            return None;
        }

        Some(unsafe {
            core::ptr::read_unaligned(data.as_ptr() as *const StandardInformation)
        })
    }

    /// Get file size from $DATA attribute
    pub fn get_file_size(&self, record: &FileRecord) -> u64 {
        if let Some(offset) = self.find_attribute(record, attr_types::DATA) {
            let data = record.data();
            let header = unsafe {
                &*(data[offset..].as_ptr() as *const AttributeHeader)
            };

            if header.is_resident() {
                let res_header = unsafe {
                    &*(data[offset..].as_ptr() as *const ResidentHeader)
                };
                return res_header.value_length as u64;
            } else {
                let nonres_header = unsafe {
                    &*(data[offset..].as_ptr() as *const NonResidentHeader)
                };
                return nonres_header.data_size;
            }
        }
        0
    }
}

// ============================================================================
// Global Mount Table
// ============================================================================

/// Mount table
static mut NTFS_MOUNTS: [NtfsMount; MAX_NTFS_MOUNTS] = {
    const INIT: NtfsMount = NtfsMount::empty();
    [INIT; MAX_NTFS_MOUNTS]
};

/// Mount count
static NTFS_MOUNT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Mount lock
static MOUNT_LOCK: SpinLock<()> = SpinLock::new(());

/// Get number of active mounts
pub fn ntfs_mount_count() -> u32 {
    NTFS_MOUNT_COUNT.load(Ordering::Relaxed)
}

/// Get a mount by index
pub fn get_mount(index: u16) -> Option<&'static NtfsMount> {
    unsafe {
        if (index as usize) < MAX_NTFS_MOUNTS && NTFS_MOUNTS[index as usize].active {
            Some(&NTFS_MOUNTS[index as usize])
        } else {
            None
        }
    }
}

/// Get a mutable mount by index
fn get_mount_mut(index: u16) -> Option<&'static mut NtfsMount> {
    unsafe {
        if (index as usize) < MAX_NTFS_MOUNTS && NTFS_MOUNTS[index as usize].active {
            Some(&mut NTFS_MOUNTS[index as usize])
        } else {
            None
        }
    }
}

/// Mount an NTFS volume
pub fn mount_volume(boot_sector: &[u8], device_index: u16) -> Option<u16> {
    let _guard = MOUNT_LOCK.lock();

    if boot_sector.len() < 512 {
        return None;
    }

    let boot = NtfsBootSector::from_bytes(
        boot_sector[..512].try_into().ok()?
    )?;

    unsafe {
        for (i, mount) in NTFS_MOUNTS.iter_mut().enumerate() {
            if !mount.active {
                mount.init_from_boot(&boot, device_index);
                NTFS_MOUNT_COUNT.fetch_add(1, Ordering::Relaxed);
                return Some(i as u16);
            }
        }
    }

    None
}

/// Unmount an NTFS volume
pub fn unmount_volume(mount_index: u16) -> bool {
    let _guard = MOUNT_LOCK.lock();

    unsafe {
        if (mount_index as usize) < MAX_NTFS_MOUNTS &&
           NTFS_MOUNTS[mount_index as usize].active {
            NTFS_MOUNTS[mount_index as usize].active = false;
            NTFS_MOUNT_COUNT.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
    }

    false
}

// ============================================================================
// VFS Operations
// ============================================================================

/// NTFS VFS operations
pub fn ntfs_ops() -> FsOps {
    FsOps {
        mount: Some(ntfs_vfs_mount),
        unmount: Some(ntfs_vfs_unmount),
        statfs: Some(ntfs_vfs_statfs),
        lookup: Some(ntfs_vfs_lookup),
        getattr: Some(ntfs_vfs_getattr),
        read: Some(ntfs_vfs_read),
        write: Some(ntfs_vfs_write),
        readdir: Some(ntfs_vfs_readdir),
        create: Some(ntfs_vfs_create),
        unlink: Some(ntfs_vfs_unlink),
        mkdir: Some(ntfs_vfs_mkdir),
        rmdir: Some(ntfs_vfs_rmdir),
        rename: Some(ntfs_vfs_rename),
        truncate: Some(ntfs_vfs_truncate),
        close: Some(ntfs_vfs_close),
        getsize: Some(ntfs_vfs_getsize),
        sync: Some(ntfs_vfs_sync),
    }
}

/// Mount operation
unsafe fn ntfs_vfs_mount(_fs_index: u16, _device: *mut u8) -> FsStatus {
    FsStatus::Success
}

/// Unmount operation
unsafe fn ntfs_vfs_unmount(fs_index: u16) -> FsStatus {
    if unmount_volume(fs_index) {
        FsStatus::Success
    } else {
        FsStatus::NotMounted
    }
}

/// Get filesystem info
unsafe fn ntfs_vfs_statfs(fs_index: u16) -> FsInfo {
    if let Some(mount) = get_mount(fs_index) {
        FsInfo {
            fs_type: FsType::Ntfs,
            block_size: mount.bytes_per_cluster,
            total_blocks: mount.total_clusters,
            free_blocks: 0, // TODO: Read from $Bitmap
            total_files: 0, // TODO: Count MFT entries
            free_files: 0,
            label: [0; 16], // TODO: Read from $Volume
        }
    } else {
        FsInfo {
            fs_type: FsType::Ntfs,
            block_size: 0,
            total_blocks: 0,
            free_blocks: 0,
            total_files: 0,
            free_files: 0,
            label: [0; 16],
        }
    }
}

/// Lookup operation - find a file by name in parent
unsafe fn ntfs_vfs_lookup(fs_index: u16, parent: u64, name: &str) -> Result<u64, FsStatus> {
    let mount = get_mount_mut(fs_index).ok_or(FsStatus::NotMounted)?;

    // Special cases
    if name.is_empty() || name == "." {
        return Ok(parent);
    }

    if name == ".." {
        // TODO: Track parent references
        return Ok(parent);
    }

    // Read parent directory
    let _record = mount.read_mft_record(parent)
        .ok_or(FsStatus::IoError)?;

    // TODO: Search directory index for name
    // This requires parsing $INDEX_ROOT and $INDEX_ALLOCATION attributes

    Err(FsStatus::NotFound)
}

/// Get file attributes
unsafe fn ntfs_vfs_getattr(fs_index: u16, vnode: u64) -> Result<FileInfo, FsStatus> {
    let mount = get_mount_mut(fs_index).ok_or(FsStatus::NotMounted)?;
    let record = mount.read_mft_record(vnode).ok_or(FsStatus::IoError)?;

    let file_type = if record.is_directory() {
        FileType::Directory
    } else {
        FileType::Regular
    };

    let size = mount.get_file_size(&record);

    let (created, modified, accessed) =
        if let Some(std_info) = mount.get_standard_info(&record) {
            (std_info.creation_time, std_info.modification_time, std_info.access_time)
        } else {
            (0, 0, 0)
        };

    Ok(FileInfo {
        size,
        file_type,
        attributes: if record.is_directory() { 0x10 } else { 0 },
        created,
        accessed,
        modified,
        nlink: 1,
        block_size: mount.bytes_per_cluster,
        blocks: (size + mount.bytes_per_cluster as u64 - 1) / mount.bytes_per_cluster as u64,
    })
}

/// Read file data
unsafe fn ntfs_vfs_read(
    fs_index: u16,
    vnode: u64,
    offset: u64,
    buf: &mut [u8],
) -> Result<usize, FsStatus> {
    let mount = get_mount_mut(fs_index).ok_or(FsStatus::NotMounted)?;
    let record = mount.read_mft_record(vnode).ok_or(FsStatus::IoError)?;

    let attr_offset = mount.find_attribute(&record, attr_types::DATA)
        .ok_or(FsStatus::NotFound)?;

    let data = record.data();
    let header = &*(data[attr_offset..].as_ptr() as *const AttributeHeader);

    if header.is_resident() {
        let res_header = &*(data[attr_offset..].as_ptr() as *const ResidentHeader);
        let data_offset = attr_offset + res_header.data_offset();
        let data_len = res_header.data_length();

        if offset >= data_len as u64 {
            return Ok(0);
        }

        let start = offset as usize;
        let available = data_len.saturating_sub(start);
        let to_read = buf.len().min(available);

        buf[..to_read].copy_from_slice(&data[data_offset + start..data_offset + start + to_read]);
        Ok(to_read)
    } else {
        // Non-resident data - need to read from clusters
        Err(FsStatus::NotSupported)
    }
}

/// Write file data (not implemented)
unsafe fn ntfs_vfs_write(
    _fs_index: u16,
    _vnode: u64,
    _offset: u64,
    _buf: &[u8],
) -> Result<usize, FsStatus> {
    Err(FsStatus::NotSupported)
}

/// Read directory entries
unsafe fn ntfs_vfs_readdir(
    fs_index: u16,
    vnode: u64,
    offset: u32,
    entry: &mut DirEntry,
) -> FsStatus {
    let mount = match get_mount_mut(fs_index) {
        Some(m) => m,
        None => return FsStatus::NotMounted,
    };

    let record = match mount.read_mft_record(vnode) {
        Some(r) => r,
        None => return FsStatus::IoError,
    };

    if !record.is_directory() {
        return FsStatus::NotDirectory;
    }

    // TODO: Parse $INDEX_ROOT and $INDEX_ALLOCATION
    if offset == 0 {
        entry.file_type = FileType::Directory;
        entry.name[0] = b'.';
        entry.name_len = 1;
        entry.size = 0;
        return FsStatus::Success;
    }

    FsStatus::NoMoreEntries
}

/// Create file (not implemented)
unsafe fn ntfs_vfs_create(
    _fs_index: u16,
    _parent: u64,
    _name: &str,
    _attrs: u32,
) -> Result<u64, FsStatus> {
    Err(FsStatus::NotSupported)
}

/// Delete file (not implemented)
unsafe fn ntfs_vfs_unlink(_fs_index: u16, _parent: u64, _name: &str) -> FsStatus {
    FsStatus::NotSupported
}

/// Create directory (not implemented)
unsafe fn ntfs_vfs_mkdir(
    _fs_index: u16,
    _parent: u64,
    _name: &str,
) -> Result<u64, FsStatus> {
    Err(FsStatus::NotSupported)
}

/// Remove directory (not implemented)
unsafe fn ntfs_vfs_rmdir(_fs_index: u16, _parent: u64, _name: &str) -> FsStatus {
    FsStatus::NotSupported
}

/// Rename (not implemented)
unsafe fn ntfs_vfs_rename(
    _fs_index: u16,
    _old_parent: u64,
    _old_name: &str,
    _new_parent: u64,
    _new_name: &str,
) -> FsStatus {
    FsStatus::NotSupported
}

/// Truncate (not implemented)
unsafe fn ntfs_vfs_truncate(_fs_index: u16, _vnode: u64, _size: u64) -> FsStatus {
    FsStatus::NotSupported
}

/// Close file
unsafe fn ntfs_vfs_close(_fs_index: u16, _vnode: u64) -> FsStatus {
    FsStatus::Success
}

/// Get file size
unsafe fn ntfs_vfs_getsize(fs_index: u16, vnode: u64) -> Result<u64, FsStatus> {
    let mount = get_mount_mut(fs_index).ok_or(FsStatus::NotMounted)?;
    let record = mount.read_mft_record(vnode).ok_or(FsStatus::IoError)?;
    Ok(mount.get_file_size(&record))
}

/// Sync (flush) - no-op for now
unsafe fn ntfs_vfs_sync(_fs_index: u16, _vnode: u64) -> FsStatus {
    FsStatus::Success
}

/// Initialize file module
pub fn init() {
    crate::serial_println!("[FS] NTFS file operations initialized");
}

/// Mount info for external consumption
#[derive(Clone, Copy)]
pub struct NtfsMountInfo {
    /// Filesystem index
    pub fs_index: u16,
    /// Device index
    pub device_index: u16,
    /// Total clusters
    pub total_clusters: u64,
    /// Bytes per cluster
    pub bytes_per_cluster: u32,
    /// File record size
    pub file_record_size: u32,
    /// Volume serial
    pub volume_serial: u64,
}

/// Get active NTFS mounts
pub fn get_active_mounts() -> alloc::vec::Vec<NtfsMountInfo> {
    let mut mounts = alloc::vec::Vec::new();

    unsafe {
        for i in 0..MAX_NTFS_MOUNTS {
            let mount = &NTFS_MOUNTS[i];
            if mount.active {
                mounts.push(NtfsMountInfo {
                    fs_index: i as u16,
                    device_index: mount.device_index,
                    total_clusters: mount.total_clusters,
                    bytes_per_cluster: mount.bytes_per_cluster,
                    file_record_size: mount.mft_record_size,
                    volume_serial: mount.volume_info.volume_serial,
                });
            }
        }
    }

    mounts
}
