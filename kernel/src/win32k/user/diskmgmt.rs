//! Disk Management
//!
//! Implements the Disk Management MMC snap-in following Windows Server 2003.
//! Provides disk, partition, and volume management.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - diskmgmt.msc - Disk Management snap-in
//! - diskpart.exe - Disk partitioning utility
//! - Logical Disk Manager (LDM)

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum disks
const MAX_DISKS: usize = 16;

/// Maximum partitions per disk
const MAX_PARTITIONS: usize = 128;

/// Maximum volumes
const MAX_VOLUMES: usize = 26;

/// Maximum name length
const MAX_NAME: usize = 64;

/// Maximum label length
const MAX_LABEL: usize = 32;

// ============================================================================
// Disk Type
// ============================================================================

/// Disk type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiskType {
    /// Basic disk (MBR partitions)
    #[default]
    Basic = 0,
    /// Dynamic disk (LDM volumes)
    Dynamic = 1,
    /// GPT disk
    Gpt = 2,
}

impl DiskType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DiskType::Basic => "Basic",
            DiskType::Dynamic => "Dynamic",
            DiskType::Gpt => "GPT",
        }
    }
}

// ============================================================================
// Partition Type
// ============================================================================

/// Partition/volume type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PartitionType {
    /// Unknown/empty
    #[default]
    Unknown = 0x00,
    /// FAT12
    Fat12 = 0x01,
    /// FAT16 (<32MB)
    Fat16Small = 0x04,
    /// Extended partition
    Extended = 0x05,
    /// FAT16 (32MB-2GB)
    Fat16 = 0x06,
    /// NTFS
    Ntfs = 0x07,
    /// FAT32
    Fat32 = 0x0B,
    /// FAT32 (LBA)
    Fat32Lba = 0x0C,
    /// FAT16 (LBA)
    Fat16Lba = 0x0E,
    /// Extended (LBA)
    ExtendedLba = 0x0F,
    /// Hidden NTFS
    HiddenNtfs = 0x17,
    /// Dynamic disk
    LdmMetadata = 0x42,
    /// LDM data partition
    LdmData = 0x43,
    /// Linux swap
    LinuxSwap = 0x82,
    /// Linux native
    Linux = 0x83,
    /// Linux LVM
    LinuxLvm = 0x8E,
    /// EFI System
    EfiSystem = 0xEF,
}

impl PartitionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PartitionType::Unknown => "Unknown",
            PartitionType::Fat12 => "FAT12",
            PartitionType::Fat16Small => "FAT16",
            PartitionType::Extended => "Extended",
            PartitionType::Fat16 => "FAT16",
            PartitionType::Ntfs => "NTFS",
            PartitionType::Fat32 => "FAT32",
            PartitionType::Fat32Lba => "FAT32",
            PartitionType::Fat16Lba => "FAT16",
            PartitionType::ExtendedLba => "Extended",
            PartitionType::HiddenNtfs => "NTFS (Hidden)",
            PartitionType::LdmMetadata => "LDM Metadata",
            PartitionType::LdmData => "LDM Data",
            PartitionType::LinuxSwap => "Linux Swap",
            PartitionType::Linux => "Linux",
            PartitionType::LinuxLvm => "Linux LVM",
            PartitionType::EfiSystem => "EFI System",
        }
    }

    pub fn from_u8(val: u8) -> Self {
        match val {
            0x01 => PartitionType::Fat12,
            0x04 => PartitionType::Fat16Small,
            0x05 => PartitionType::Extended,
            0x06 => PartitionType::Fat16,
            0x07 => PartitionType::Ntfs,
            0x0B => PartitionType::Fat32,
            0x0C => PartitionType::Fat32Lba,
            0x0E => PartitionType::Fat16Lba,
            0x0F => PartitionType::ExtendedLba,
            0x17 => PartitionType::HiddenNtfs,
            0x42 => PartitionType::LdmMetadata,
            0x43 => PartitionType::LdmData,
            0x82 => PartitionType::LinuxSwap,
            0x83 => PartitionType::Linux,
            0x8E => PartitionType::LinuxLvm,
            0xEF => PartitionType::EfiSystem,
            _ => PartitionType::Unknown,
        }
    }
}

// ============================================================================
// Disk Status
// ============================================================================

/// Disk status
pub mod disk_status {
    /// Online
    pub const ONLINE: u32 = 0;
    /// Offline
    pub const OFFLINE: u32 = 1;
    /// Missing
    pub const MISSING: u32 = 2;
    /// Not initialized
    pub const NOT_INITIALIZED: u32 = 3;
    /// Foreign (from another computer)
    pub const FOREIGN: u32 = 4;
    /// Failed
    pub const FAILED: u32 = 5;
}

// ============================================================================
// Volume Status
// ============================================================================

/// Volume status
pub mod volume_status {
    /// Healthy
    pub const HEALTHY: u32 = 0;
    /// Failed
    pub const FAILED: u32 = 1;
    /// Failed redundancy
    pub const FAILED_REDUNDANCY: u32 = 2;
    /// At risk
    pub const AT_RISK: u32 = 3;
    /// Unknown
    pub const UNKNOWN: u32 = 4;
}

// ============================================================================
// Partition Entry
// ============================================================================

/// Partition entry
#[derive(Debug, Clone, Copy)]
pub struct PartitionEntry {
    /// Partition number
    pub number: u32,
    /// Partition type
    pub partition_type: PartitionType,
    /// Start sector (LBA)
    pub start_sector: u64,
    /// Size in sectors
    pub size_sectors: u64,
    /// Is bootable/active
    pub bootable: bool,
    /// Is primary (vs logical)
    pub is_primary: bool,
}

impl PartitionEntry {
    pub const fn new() -> Self {
        Self {
            number: 0,
            partition_type: PartitionType::Unknown,
            start_sector: 0,
            size_sectors: 0,
            bootable: false,
            is_primary: true,
        }
    }

    /// Get size in bytes
    pub fn size_bytes(&self) -> u64 {
        self.size_sectors * 512
    }

    /// Get size in MB
    pub fn size_mb(&self) -> u64 {
        self.size_bytes() / (1024 * 1024)
    }

    /// Get size in GB
    pub fn size_gb(&self) -> u64 {
        self.size_bytes() / (1024 * 1024 * 1024)
    }
}

impl Default for PartitionEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Disk Entry
// ============================================================================

/// Physical disk entry
#[derive(Debug, Clone, Copy)]
pub struct DiskEntry {
    /// Disk number
    pub disk_number: u32,
    /// Disk type
    pub disk_type: DiskType,
    /// Disk status
    pub status: u32,
    /// Total size in bytes
    pub total_size: u64,
    /// Unallocated space in bytes
    pub unallocated: u64,
    /// Model name
    pub model: [u8; MAX_NAME],
    /// Model length
    pub model_len: usize,
    /// Serial number
    pub serial: [u8; 32],
    /// Serial length
    pub serial_len: usize,
    /// Sector size
    pub sector_size: u32,
    /// Cylinders
    pub cylinders: u64,
    /// Heads
    pub heads: u32,
    /// Sectors per track
    pub sectors_per_track: u32,
    /// Partitions
    pub partitions: [PartitionEntry; 16],
    /// Partition count
    pub partition_count: usize,
}

impl DiskEntry {
    pub const fn new() -> Self {
        Self {
            disk_number: 0,
            disk_type: DiskType::Basic,
            status: disk_status::ONLINE,
            total_size: 0,
            unallocated: 0,
            model: [0u8; MAX_NAME],
            model_len: 0,
            serial: [0u8; 32],
            serial_len: 0,
            sector_size: 512,
            cylinders: 0,
            heads: 0,
            sectors_per_track: 0,
            partitions: [const { PartitionEntry::new() }; 16],
            partition_count: 0,
        }
    }

    pub fn set_model(&mut self, model: &[u8]) {
        let len = model.len().min(MAX_NAME);
        self.model[..len].copy_from_slice(&model[..len]);
        self.model_len = len;
    }

    pub fn set_serial(&mut self, serial: &[u8]) {
        let len = serial.len().min(32);
        self.serial[..len].copy_from_slice(&serial[..len]);
        self.serial_len = len;
    }

    pub fn add_partition(&mut self, part: PartitionEntry) -> bool {
        if self.partition_count >= 16 {
            return false;
        }
        self.partitions[self.partition_count] = part;
        self.partition_count += 1;
        true
    }

    /// Get size in GB
    pub fn size_gb(&self) -> u64 {
        self.total_size / (1024 * 1024 * 1024)
    }
}

impl Default for DiskEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Volume Entry
// ============================================================================

/// Logical volume entry
#[derive(Debug, Clone, Copy)]
pub struct VolumeEntry {
    /// Drive letter (A-Z, 0 = no letter)
    pub drive_letter: u8,
    /// Volume label
    pub label: [u8; MAX_LABEL],
    /// Label length
    pub label_len: usize,
    /// File system type
    pub file_system: PartitionType,
    /// Status
    pub status: u32,
    /// Total capacity in bytes
    pub capacity: u64,
    /// Free space in bytes
    pub free_space: u64,
    /// Disk number
    pub disk_number: u32,
    /// Partition number
    pub partition_number: u32,
    /// Is system volume
    pub is_system: bool,
    /// Is boot volume
    pub is_boot: bool,
    /// Is page file volume
    pub is_pagefile: bool,
}

impl VolumeEntry {
    pub const fn new() -> Self {
        Self {
            drive_letter: 0,
            label: [0u8; MAX_LABEL],
            label_len: 0,
            file_system: PartitionType::Unknown,
            status: volume_status::HEALTHY,
            capacity: 0,
            free_space: 0,
            disk_number: 0,
            partition_number: 0,
            is_system: false,
            is_boot: false,
            is_pagefile: false,
        }
    }

    pub fn set_label(&mut self, label: &[u8]) {
        let len = label.len().min(MAX_LABEL);
        self.label[..len].copy_from_slice(&label[..len]);
        self.label_len = len;
    }

    /// Get used space
    pub fn used_space(&self) -> u64 {
        self.capacity.saturating_sub(self.free_space)
    }

    /// Get usage percentage
    pub fn usage_percent(&self) -> u32 {
        if self.capacity == 0 {
            return 0;
        }
        ((self.used_space() * 100) / self.capacity) as u32
    }
}

impl Default for VolumeEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Disk Management State
// ============================================================================

/// Disk Management state
struct DiskMgmtState {
    /// Physical disks
    disks: [DiskEntry; MAX_DISKS],
    /// Disk count
    disk_count: usize,
    /// Logical volumes
    volumes: [VolumeEntry; MAX_VOLUMES],
    /// Volume count
    volume_count: usize,
}

impl DiskMgmtState {
    pub const fn new() -> Self {
        Self {
            disks: [const { DiskEntry::new() }; MAX_DISKS],
            disk_count: 0,
            volumes: [const { VolumeEntry::new() }; MAX_VOLUMES],
            volume_count: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static DISKMGMT_INITIALIZED: AtomicBool = AtomicBool::new(false);
static DISKMGMT_STATE: SpinLock<DiskMgmtState> = SpinLock::new(DiskMgmtState::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Disk Management
pub fn init() {
    if DISKMGMT_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = DISKMGMT_STATE.lock();

    // Add sample disks
    add_sample_disks(&mut state);

    // Add sample volumes
    add_sample_volumes(&mut state);

    crate::serial_println!("[WIN32K] Disk Management initialized");
}

/// Add sample disks
fn add_sample_disks(state: &mut DiskMgmtState) {
    // Primary disk - 80GB
    let mut disk0 = DiskEntry::new();
    disk0.disk_number = 0;
    disk0.disk_type = DiskType::Basic;
    disk0.status = disk_status::ONLINE;
    disk0.total_size = 80 * 1024 * 1024 * 1024; // 80GB
    disk0.set_model(b"WDC WD800JD-75MSA3");
    disk0.set_serial(b"WD-WMAM9W123456");
    disk0.sector_size = 512;
    disk0.cylinders = 9729;
    disk0.heads = 255;
    disk0.sectors_per_track = 63;

    // System partition (C:)
    let mut part1 = PartitionEntry::new();
    part1.number = 1;
    part1.partition_type = PartitionType::Ntfs;
    part1.start_sector = 63;
    part1.size_sectors = 78_140_097; // ~40GB
    part1.bootable = true;
    part1.is_primary = true;
    disk0.add_partition(part1);

    // Data partition (D:)
    let mut part2 = PartitionEntry::new();
    part2.number = 2;
    part2.partition_type = PartitionType::Ntfs;
    part2.start_sector = 78_140_160;
    part2.size_sectors = 78_124_032; // ~40GB
    part2.bootable = false;
    part2.is_primary = true;
    disk0.add_partition(part2);

    disk0.unallocated = 0;
    state.disks[0] = disk0;

    // Secondary disk - 40GB
    let mut disk1 = DiskEntry::new();
    disk1.disk_number = 1;
    disk1.disk_type = DiskType::Basic;
    disk1.status = disk_status::ONLINE;
    disk1.total_size = 40 * 1024 * 1024 * 1024; // 40GB
    disk1.set_model(b"SAMSUNG HD040GJ");
    disk1.set_serial(b"S0DFJ1FL123456");
    disk1.sector_size = 512;
    disk1.cylinders = 4864;
    disk1.heads = 255;
    disk1.sectors_per_track = 63;

    // Single NTFS partition (E:)
    let mut part3 = PartitionEntry::new();
    part3.number = 1;
    part3.partition_type = PartitionType::Ntfs;
    part3.start_sector = 63;
    part3.size_sectors = 78_140_097; // ~40GB
    part3.bootable = false;
    part3.is_primary = true;
    disk1.add_partition(part3);

    disk1.unallocated = 0;
    state.disks[1] = disk1;

    // CD-ROM (Disk 2) - represented as a disk
    let mut disk2 = DiskEntry::new();
    disk2.disk_number = 2;
    disk2.disk_type = DiskType::Basic;
    disk2.status = disk_status::ONLINE;
    disk2.total_size = 0; // Variable
    disk2.set_model(b"HL-DT-ST DVDRAM GSA-4163B");
    state.disks[2] = disk2;

    state.disk_count = 3;
}

/// Add sample volumes
fn add_sample_volumes(state: &mut DiskMgmtState) {
    // C: drive (System)
    let mut vol_c = VolumeEntry::new();
    vol_c.drive_letter = b'C';
    vol_c.set_label(b"System");
    vol_c.file_system = PartitionType::Ntfs;
    vol_c.status = volume_status::HEALTHY;
    vol_c.capacity = 40 * 1024 * 1024 * 1024; // 40GB
    vol_c.free_space = 25 * 1024 * 1024 * 1024; // 25GB free
    vol_c.disk_number = 0;
    vol_c.partition_number = 1;
    vol_c.is_system = true;
    vol_c.is_boot = true;
    vol_c.is_pagefile = true;
    state.volumes[0] = vol_c;

    // D: drive (Data)
    let mut vol_d = VolumeEntry::new();
    vol_d.drive_letter = b'D';
    vol_d.set_label(b"Data");
    vol_d.file_system = PartitionType::Ntfs;
    vol_d.status = volume_status::HEALTHY;
    vol_d.capacity = 40 * 1024 * 1024 * 1024; // 40GB
    vol_d.free_space = 35 * 1024 * 1024 * 1024; // 35GB free
    vol_d.disk_number = 0;
    vol_d.partition_number = 2;
    state.volumes[1] = vol_d;

    // E: drive (Backup)
    let mut vol_e = VolumeEntry::new();
    vol_e.drive_letter = b'E';
    vol_e.set_label(b"Backup");
    vol_e.file_system = PartitionType::Ntfs;
    vol_e.status = volume_status::HEALTHY;
    vol_e.capacity = 40 * 1024 * 1024 * 1024; // 40GB
    vol_e.free_space = 38 * 1024 * 1024 * 1024; // 38GB free
    vol_e.disk_number = 1;
    vol_e.partition_number = 1;
    state.volumes[2] = vol_e;

    state.volume_count = 3;
}

// ============================================================================
// Disk Enumeration
// ============================================================================

/// Get disk count
pub fn get_disk_count() -> usize {
    DISKMGMT_STATE.lock().disk_count
}

/// Get disk by index
pub fn get_disk(index: usize) -> Option<DiskEntry> {
    let state = DISKMGMT_STATE.lock();
    if index < state.disk_count {
        Some(state.disks[index])
    } else {
        None
    }
}

/// Get disk by number
pub fn get_disk_by_number(disk_number: u32) -> Option<DiskEntry> {
    let state = DISKMGMT_STATE.lock();
    for i in 0..state.disk_count {
        if state.disks[i].disk_number == disk_number {
            return Some(state.disks[i]);
        }
    }
    None
}

// ============================================================================
// Volume Enumeration
// ============================================================================

/// Get volume count
pub fn get_volume_count() -> usize {
    DISKMGMT_STATE.lock().volume_count
}

/// Get volume by index
pub fn get_volume(index: usize) -> Option<VolumeEntry> {
    let state = DISKMGMT_STATE.lock();
    if index < state.volume_count {
        Some(state.volumes[index])
    } else {
        None
    }
}

/// Get volume by drive letter
pub fn get_volume_by_letter(letter: u8) -> Option<VolumeEntry> {
    let state = DISKMGMT_STATE.lock();
    let upper = if letter >= b'a' && letter <= b'z' {
        letter - 32
    } else {
        letter
    };
    for i in 0..state.volume_count {
        if state.volumes[i].drive_letter == upper {
            return Some(state.volumes[i]);
        }
    }
    None
}

// ============================================================================
// Volume Operations
// ============================================================================

/// Change drive letter
pub fn change_drive_letter(volume_index: usize, new_letter: u8) -> bool {
    let mut state = DISKMGMT_STATE.lock();
    if volume_index >= state.volume_count {
        return false;
    }

    let upper = if new_letter >= b'a' && new_letter <= b'z' {
        new_letter - 32
    } else {
        new_letter
    };

    // Check if letter is already in use
    for i in 0..state.volume_count {
        if i != volume_index && state.volumes[i].drive_letter == upper {
            return false;
        }
    }

    state.volumes[volume_index].drive_letter = upper;
    true
}

/// Change volume label
pub fn change_volume_label(volume_index: usize, label: &[u8]) -> bool {
    let mut state = DISKMGMT_STATE.lock();
    if volume_index >= state.volume_count {
        return false;
    }

    state.volumes[volume_index].set_label(label);
    true
}

/// Remove drive letter
pub fn remove_drive_letter(volume_index: usize) -> bool {
    let mut state = DISKMGMT_STATE.lock();
    if volume_index >= state.volume_count {
        return false;
    }

    // Don't remove from system volume
    if state.volumes[volume_index].is_system {
        return false;
    }

    state.volumes[volume_index].drive_letter = 0;
    true
}

// ============================================================================
// Disk Operations
// ============================================================================

/// Set disk online/offline
pub fn set_disk_online(disk_index: usize, online: bool) -> bool {
    let mut state = DISKMGMT_STATE.lock();
    if disk_index >= state.disk_count {
        return false;
    }

    state.disks[disk_index].status = if online {
        disk_status::ONLINE
    } else {
        disk_status::OFFLINE
    };

    true
}

/// Initialize disk (set as Basic MBR)
pub fn initialize_disk(disk_index: usize, gpt: bool) -> bool {
    let mut state = DISKMGMT_STATE.lock();
    if disk_index >= state.disk_count {
        return false;
    }

    if state.disks[disk_index].status != disk_status::NOT_INITIALIZED {
        return false;
    }

    state.disks[disk_index].disk_type = if gpt { DiskType::Gpt } else { DiskType::Basic };
    state.disks[disk_index].status = disk_status::ONLINE;
    state.disks[disk_index].unallocated = state.disks[disk_index].total_size;

    true
}

/// Convert disk to dynamic
pub fn convert_to_dynamic(disk_index: usize) -> bool {
    let mut state = DISKMGMT_STATE.lock();
    if disk_index >= state.disk_count {
        return false;
    }

    if state.disks[disk_index].disk_type != DiskType::Basic {
        return false;
    }

    state.disks[disk_index].disk_type = DiskType::Dynamic;
    true
}

// ============================================================================
// Statistics
// ============================================================================

/// Disk Management statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct DiskMgmtStats {
    pub initialized: bool,
    pub disk_count: usize,
    pub volume_count: usize,
    pub total_capacity: u64,
    pub total_free: u64,
}

/// Get Disk Management statistics
pub fn get_stats() -> DiskMgmtStats {
    let state = DISKMGMT_STATE.lock();
    let mut total_capacity = 0u64;
    let mut total_free = 0u64;

    for i in 0..state.volume_count {
        total_capacity += state.volumes[i].capacity;
        total_free += state.volumes[i].free_space;
    }

    DiskMgmtStats {
        initialized: DISKMGMT_INITIALIZED.load(Ordering::Relaxed),
        disk_count: state.disk_count,
        volume_count: state.volume_count,
        total_capacity,
        total_free,
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Disk Management dialog handle
pub type HDISKMGMTDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Disk Management dialog
pub fn create_diskmgmt_dialog(_parent: super::super::HWND) -> HDISKMGMTDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}

/// View mode
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ViewMode {
    /// Top: volume list, Bottom: graphical
    #[default]
    VolumeList = 0,
    /// Top: disk list, Bottom: graphical
    DiskList = 1,
    /// Graphical only
    GraphicalOnly = 2,
}

/// Get view mode count
pub fn get_view_mode_count() -> u32 {
    3
}

/// Get view mode name
pub fn get_view_mode_name(mode: ViewMode) -> &'static str {
    match mode {
        ViewMode::VolumeList => "Volume List",
        ViewMode::DiskList => "Disk List",
        ViewMode::GraphicalOnly => "Graphical View",
    }
}
