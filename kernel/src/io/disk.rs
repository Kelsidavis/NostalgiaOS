//! Disk Class Driver
//!
//! Provides high-level disk operations and partition management.
//! Maps physical disks and partitions to logical volumes.
//!
//! # Device Naming
//! - Physical disks: \Device\Harddisk0, \Device\Harddisk1, ...
//! - Partitions: \Device\HarddiskVolume1, \Device\HarddiskVolume2, ...
//! - Drive letters: C:\, D:\, E:\, ...

use crate::ke::SpinLock;
use super::block::{
    BlockStatus, SECTOR_SIZE,
    get_block_device, read_sectors, write_sectors, device_count,
};

/// Maximum partitions per disk
pub const MAX_PARTITIONS_PER_DISK: usize = 4;

/// Maximum total volumes
pub const MAX_VOLUMES: usize = 32;

/// Partition type codes
pub mod partition_type {
    pub const EMPTY: u8 = 0x00;
    pub const FAT12: u8 = 0x01;
    pub const FAT16_SMALL: u8 = 0x04;
    pub const EXTENDED: u8 = 0x05;
    pub const FAT16: u8 = 0x06;
    pub const NTFS: u8 = 0x07;
    pub const FAT32: u8 = 0x0B;
    pub const FAT32_LBA: u8 = 0x0C;
    pub const FAT16_LBA: u8 = 0x0E;
    pub const EXTENDED_LBA: u8 = 0x0F;
    pub const LINUX_SWAP: u8 = 0x82;
    pub const LINUX: u8 = 0x83;
    pub const LINUX_LVM: u8 = 0x8E;
    pub const GPT_PROTECTIVE: u8 = 0xEE;
    pub const EFI_SYSTEM: u8 = 0xEF;

    /// Get partition type name
    pub fn name(type_code: u8) -> &'static str {
        match type_code {
            EMPTY => "Empty",
            FAT12 => "FAT12",
            FAT16_SMALL | FAT16 | FAT16_LBA => "FAT16",
            EXTENDED | EXTENDED_LBA => "Extended",
            NTFS => "NTFS",
            FAT32 | FAT32_LBA => "FAT32",
            LINUX_SWAP => "Linux Swap",
            LINUX => "Linux",
            LINUX_LVM => "Linux LVM",
            GPT_PROTECTIVE => "GPT Protective",
            EFI_SYSTEM => "EFI System",
            _ => "Unknown",
        }
    }

    /// Check if this is a FAT partition
    pub fn is_fat(type_code: u8) -> bool {
        matches!(type_code, FAT12 | FAT16_SMALL | FAT16 | FAT16_LBA | FAT32 | FAT32_LBA)
    }
}

/// MBR partition entry (16 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MbrPartitionEntry {
    /// Boot indicator (0x80 = bootable)
    pub boot_flag: u8,
    /// Starting head
    pub start_head: u8,
    /// Starting sector (bits 0-5) and cylinder high (bits 6-7)
    pub start_sector_cyl: u8,
    /// Starting cylinder low
    pub start_cyl_low: u8,
    /// Partition type
    pub partition_type: u8,
    /// Ending head
    pub end_head: u8,
    /// Ending sector and cylinder high
    pub end_sector_cyl: u8,
    /// Ending cylinder low
    pub end_cyl_low: u8,
    /// Starting LBA
    pub start_lba: u32,
    /// Total sectors
    pub total_sectors: u32,
}

impl MbrPartitionEntry {
    pub const fn empty() -> Self {
        Self {
            boot_flag: 0,
            start_head: 0,
            start_sector_cyl: 0,
            start_cyl_low: 0,
            partition_type: 0,
            end_head: 0,
            end_sector_cyl: 0,
            end_cyl_low: 0,
            start_lba: 0,
            total_sectors: 0,
        }
    }

    /// Check if partition is valid
    pub fn is_valid(&self) -> bool {
        self.partition_type != partition_type::EMPTY && self.total_sectors > 0
    }

    /// Check if bootable
    pub fn is_bootable(&self) -> bool {
        self.boot_flag == 0x80
    }

    /// Check if extended partition
    pub fn is_extended(&self) -> bool {
        matches!(self.partition_type, partition_type::EXTENDED | partition_type::EXTENDED_LBA)
    }

    /// Get starting LBA (handle packed struct)
    pub fn get_start_lba(&self) -> u32 {
        unsafe {
            let ptr = core::ptr::addr_of!(self.start_lba);
            core::ptr::read_unaligned(ptr)
        }
    }

    /// Get total sectors (handle packed struct)
    pub fn get_total_sectors(&self) -> u32 {
        unsafe {
            let ptr = core::ptr::addr_of!(self.total_sectors);
            core::ptr::read_unaligned(ptr)
        }
    }
}

/// MBR structure (512 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Mbr {
    /// Boot code
    pub boot_code: [u8; 446],
    /// Partition table (4 entries)
    pub partitions: [MbrPartitionEntry; 4],
    /// Boot signature (0xAA55)
    pub signature: u16,
}

impl Mbr {
    /// Check if MBR is valid
    pub fn is_valid(&self) -> bool {
        unsafe {
            let ptr = core::ptr::addr_of!(self.signature);
            core::ptr::read_unaligned(ptr) == 0xAA55
        }
    }
}

/// Volume information
#[derive(Clone, Copy)]
pub struct Volume {
    /// Volume is active
    pub active: bool,
    /// Physical disk index
    pub disk_index: u8,
    /// Partition index on disk
    pub partition_index: u8,
    /// Volume number (for naming)
    pub volume_number: u8,
    /// Starting LBA on disk
    pub start_lba: u64,
    /// Total sectors
    pub total_sectors: u64,
    /// Partition type
    pub partition_type: u8,
    /// Is bootable
    pub bootable: bool,
    /// Sector size
    pub sector_size: u32,
    /// Volume label
    pub label: [u8; 16],
}

impl Volume {
    pub const fn empty() -> Self {
        Self {
            active: false,
            disk_index: 0,
            partition_index: 0,
            volume_number: 0,
            start_lba: 0,
            total_sectors: 0,
            partition_type: 0,
            bootable: false,
            sector_size: SECTOR_SIZE as u32,
            label: [0; 16],
        }
    }

    /// Get size in bytes
    pub fn size_bytes(&self) -> u64 {
        self.total_sectors * self.sector_size as u64
    }

    /// Get size in MB
    pub fn size_mb(&self) -> u64 {
        self.size_bytes() / (1024 * 1024)
    }

    /// Get partition type name
    pub fn type_name(&self) -> &'static str {
        partition_type::name(self.partition_type)
    }

    /// Get volume label as string
    pub fn label_str(&self) -> &str {
        let len = self.label.iter().position(|&b| b == 0).unwrap_or(16);
        core::str::from_utf8(&self.label[..len]).unwrap_or("")
    }

    /// Set volume label
    pub fn set_label(&mut self, label: &str) {
        let bytes = label.as_bytes();
        let len = bytes.len().min(15);
        self.label = [0; 16];
        self.label[..len].copy_from_slice(&bytes[..len]);
    }
}

impl Default for Volume {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Volume Table
// ============================================================================

/// Volume table
static mut VOLUMES: [Volume; MAX_VOLUMES] = {
    const INIT: Volume = Volume::empty();
    [INIT; MAX_VOLUMES]
};

/// Volume lock
static VOLUME_LOCK: SpinLock<()> = SpinLock::new(());

/// Next volume number
static mut NEXT_VOLUME: u8 = 1;

// ============================================================================
// Partition Detection
// ============================================================================

/// Sector buffer for MBR reading
static mut MBR_BUFFER: [u8; SECTOR_SIZE] = [0; SECTOR_SIZE];

/// Read MBR from disk
fn read_mbr(disk_index: u8) -> Option<Mbr> {
    unsafe {
        if read_sectors(disk_index, 0, 1, &mut MBR_BUFFER) != BlockStatus::Success {
            return None;
        }

        let mbr = core::ptr::read(MBR_BUFFER.as_ptr() as *const Mbr);
        if mbr.is_valid() {
            Some(mbr)
        } else {
            None
        }
    }
}

/// Scan partitions on a disk
fn scan_partitions(disk_index: u8) -> u32 {
    let mbr = match read_mbr(disk_index) {
        Some(m) => m,
        None => return 0,
    };

    let dev = match get_block_device(disk_index) {
        Some(d) => d,
        None => return 0,
    };

    let _guard = VOLUME_LOCK.lock();
    let mut count = 0u32;

    for (i, entry) in mbr.partitions.iter().enumerate() {
        if !entry.is_valid() {
            continue;
        }

        // Skip extended partitions for now
        if entry.is_extended() {
            crate::serial_println!(
                "[DISK] Disk {}: Partition {} is extended (not scanning logical partitions)",
                disk_index,
                i
            );
            continue;
        }

        // Find free volume slot
        unsafe {
            for vol in VOLUMES.iter_mut() {
                if !vol.active {
                    vol.active = true;
                    vol.disk_index = disk_index;
                    vol.partition_index = i as u8;
                    vol.volume_number = NEXT_VOLUME;
                    NEXT_VOLUME += 1;
                    vol.start_lba = entry.get_start_lba() as u64;
                    vol.total_sectors = entry.get_total_sectors() as u64;
                    vol.partition_type = entry.partition_type;
                    vol.bootable = entry.is_bootable();
                    vol.sector_size = dev.geometry.sector_size;

                    crate::serial_println!(
                        "[DISK] Volume {}: Disk {} Part {} - {} ({} MB)",
                        vol.volume_number,
                        disk_index,
                        i,
                        partition_type::name(entry.partition_type),
                        vol.size_mb()
                    );

                    count += 1;
                    break;
                }
            }
        }
    }

    count
}

// ============================================================================
// Volume Operations
// ============================================================================

/// Get volume by number
pub fn get_volume(volume_number: u8) -> Option<&'static Volume> {
    unsafe {
        for vol in VOLUMES.iter() {
            if vol.active && vol.volume_number == volume_number {
                return Some(vol);
            }
        }
    }
    None
}

/// Get volume by disk and partition
pub fn get_volume_by_partition(disk_index: u8, partition_index: u8) -> Option<&'static Volume> {
    unsafe {
        for vol in VOLUMES.iter() {
            if vol.active && vol.disk_index == disk_index && vol.partition_index == partition_index {
                return Some(vol);
            }
        }
    }
    None
}

/// Get first volume of a type
pub fn get_volume_by_type(partition_type: u8) -> Option<&'static Volume> {
    unsafe {
        for vol in VOLUMES.iter() {
            if vol.active && vol.partition_type == partition_type {
                return Some(vol);
            }
        }
    }
    None
}

/// Get bootable volume
pub fn get_bootable_volume() -> Option<&'static Volume> {
    unsafe {
        for vol in VOLUMES.iter() {
            if vol.active && vol.bootable {
                return Some(vol);
            }
        }
    }
    None
}

/// Count active volumes
pub fn volume_count() -> u32 {
    unsafe {
        VOLUMES.iter().filter(|v| v.active).count() as u32
    }
}

/// List all volumes
pub fn list_volumes() {
    crate::serial_println!("[DISK] Active volumes:");
    unsafe {
        for vol in VOLUMES.iter() {
            if vol.active {
                crate::serial_println!(
                    "  Volume {}: Disk {} Part {} - {} ({} MB) {}",
                    vol.volume_number,
                    vol.disk_index,
                    vol.partition_index,
                    partition_type::name(vol.partition_type),
                    vol.size_mb(),
                    if vol.bootable { "*" } else { "" }
                );
            }
        }
    }
}

// ============================================================================
// Volume I/O
// ============================================================================

/// Read sectors from volume
pub fn volume_read(volume_number: u8, offset_sectors: u64, count: u32, buf: &mut [u8]) -> BlockStatus {
    let vol = match get_volume(volume_number) {
        Some(v) => v,
        None => return BlockStatus::NotFound,
    };

    // Check bounds
    if offset_sectors + count as u64 > vol.total_sectors {
        return BlockStatus::InvalidParameter;
    }

    // Calculate absolute LBA
    let lba = vol.start_lba + offset_sectors;

    // Read from physical disk
    read_sectors(vol.disk_index, lba, count, buf)
}

/// Write sectors to volume
pub fn volume_write(volume_number: u8, offset_sectors: u64, count: u32, buf: &[u8]) -> BlockStatus {
    let vol = match get_volume(volume_number) {
        Some(v) => v,
        None => return BlockStatus::NotFound,
    };

    // Check bounds
    if offset_sectors + count as u64 > vol.total_sectors {
        return BlockStatus::InvalidParameter;
    }

    // Calculate absolute LBA
    let lba = vol.start_lba + offset_sectors;

    // Write to physical disk
    write_sectors(vol.disk_index, lba, count, buf)
}

/// Read single sector from volume
pub fn volume_read_sector(volume_number: u8, offset_sectors: u64, buf: &mut [u8; SECTOR_SIZE]) -> bool {
    volume_read(volume_number, offset_sectors, 1, buf) == BlockStatus::Success
}

/// Write single sector to volume
pub fn volume_write_sector(volume_number: u8, offset_sectors: u64, buf: &[u8; SECTOR_SIZE]) -> bool {
    volume_write(volume_number, offset_sectors, 1, buf) == BlockStatus::Success
}

// ============================================================================
// File System Integration
// ============================================================================

/// Get volume read callback for file system
pub fn get_volume_read_callback(volume_number: u8) -> Option<unsafe fn(*mut u8, u64, &mut [u8]) -> bool> {
    if get_volume(volume_number).is_some() {
        Some(volume_fs_read)
    } else {
        None
    }
}

/// Get volume write callback for file system
pub fn get_volume_write_callback(volume_number: u8) -> Option<unsafe fn(*mut u8, u64, &[u8]) -> bool> {
    if get_volume(volume_number).is_some() {
        Some(volume_fs_write)
    } else {
        None
    }
}

/// File system read callback
unsafe fn volume_fs_read(device: *mut u8, sector: u64, buf: &mut [u8]) -> bool {
    let volume_number = device as u8;
    volume_read(volume_number, sector, 1, buf) == BlockStatus::Success
}

/// File system write callback
unsafe fn volume_fs_write(device: *mut u8, sector: u64, buf: &[u8]) -> bool {
    let volume_number = device as u8;
    volume_write(volume_number, sector, 1, buf) == BlockStatus::Success
}

// ============================================================================
// Initialization
// ============================================================================

/// Scan all disks for partitions
pub fn scan_all_disks() -> u32 {
    let disk_count = device_count();
    let mut total_volumes = 0u32;

    crate::serial_println!("[DISK] Scanning {} disk(s) for partitions...", disk_count);

    for i in 0..disk_count {
        total_volumes += scan_partitions(i as u8);
    }

    if total_volumes == 0 {
        crate::serial_println!("[DISK] No partitions found");
    } else {
        crate::serial_println!("[DISK] Found {} volume(s)", total_volumes);
    }

    total_volumes
}

/// Initialize disk subsystem
pub fn init() {
    crate::serial_println!("[DISK] Disk subsystem initializing...");

    // Scan for partitions on all block devices
    let volumes = scan_all_disks();

    crate::serial_println!("[DISK] Disk subsystem initialized ({} volumes)", volumes);
}
