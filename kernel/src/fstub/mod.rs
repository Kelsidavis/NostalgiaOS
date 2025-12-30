//! File System Stub (FSTUB) - Partition and Disk Support
//!
//! FSTUB provides low-level disk partition table handling:
//! - MBR (Master Boot Record) partition tables
//! - GPT (GUID Partition Table) for EFI/UEFI systems
//! - Disk geometry management
//! - Drive layout information
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │              File System Drivers                │
//! ├─────────────────────────────────────────────────┤
//! │                    FSTUB                        │
//! │  ┌───────────┐  ┌───────────┐  ┌───────────┐   │
//! │  │    MBR    │  │    GPT    │  │  Geometry │   │
//! │  │  Support  │  │  Support  │  │  Support  │   │
//! │  └───────────┘  └───────────┘  └───────────┘   │
//! ├─────────────────────────────────────────────────┤
//! │              Disk Class Driver                  │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! Based on Windows Server 2003 base/ntos/fstub/

pub mod geometry;
pub mod gpt;
pub mod mbr;

pub use geometry::*;
pub use gpt::*;
pub use mbr::*;

use crate::etw::Guid;
use alloc::string::String;
use alloc::vec::Vec;

extern crate alloc;

/// Pool tag for FSTUB allocations
pub const FSTUB_TAG: u32 = u32::from_le_bytes(*b"FstB");

/// Partition types (MBR)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionType {
    /// Empty partition
    Empty = 0x00,
    /// FAT12 primary
    Fat12 = 0x01,
    /// XENIX root
    XenixRoot = 0x02,
    /// XENIX usr
    XenixUsr = 0x03,
    /// FAT16 < 32MB
    Fat16Small = 0x04,
    /// Extended partition
    Extended = 0x05,
    /// FAT16 >= 32MB
    Fat16 = 0x06,
    /// NTFS or HPFS
    Ntfs = 0x07,
    /// FAT32
    Fat32 = 0x0B,
    /// FAT32 with LBA
    Fat32Lba = 0x0C,
    /// FAT16 with LBA
    Fat16Lba = 0x0E,
    /// Extended with LBA
    ExtendedLba = 0x0F,
    /// Hidden FAT12
    HiddenFat12 = 0x11,
    /// Hidden FAT16 < 32MB
    HiddenFat16Small = 0x14,
    /// Hidden FAT16
    HiddenFat16 = 0x16,
    /// Hidden NTFS
    HiddenNtfs = 0x17,
    /// Hidden FAT32
    HiddenFat32 = 0x1B,
    /// Hidden FAT32 LBA
    HiddenFat32Lba = 0x1C,
    /// Hidden FAT16 LBA
    HiddenFat16Lba = 0x1E,
    /// Dynamic disk
    LdmMetadata = 0x42,
    /// Dynamic disk data
    LdmData = 0x43,
    /// Linux swap
    LinuxSwap = 0x82,
    /// Linux native
    Linux = 0x83,
    /// Linux extended
    LinuxExtended = 0x85,
    /// Linux LVM
    LinuxLvm = 0x8E,
    /// FreeBSD
    FreeBsd = 0xA5,
    /// OpenBSD
    OpenBsd = 0xA6,
    /// NetBSD
    NetBsd = 0xA9,
    /// GPT protective MBR
    GptProtective = 0xEE,
    /// EFI System Partition
    EfiSystem = 0xEF,
}

impl PartitionType {
    /// Create from byte value
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => PartitionType::Empty,
            0x01 => PartitionType::Fat12,
            0x02 => PartitionType::XenixRoot,
            0x03 => PartitionType::XenixUsr,
            0x04 => PartitionType::Fat16Small,
            0x05 => PartitionType::Extended,
            0x06 => PartitionType::Fat16,
            0x07 => PartitionType::Ntfs,
            0x0B => PartitionType::Fat32,
            0x0C => PartitionType::Fat32Lba,
            0x0E => PartitionType::Fat16Lba,
            0x0F => PartitionType::ExtendedLba,
            0x11 => PartitionType::HiddenFat12,
            0x14 => PartitionType::HiddenFat16Small,
            0x16 => PartitionType::HiddenFat16,
            0x17 => PartitionType::HiddenNtfs,
            0x1B => PartitionType::HiddenFat32,
            0x1C => PartitionType::HiddenFat32Lba,
            0x1E => PartitionType::HiddenFat16Lba,
            0x42 => PartitionType::LdmMetadata,
            0x43 => PartitionType::LdmData,
            0x82 => PartitionType::LinuxSwap,
            0x83 => PartitionType::Linux,
            0x85 => PartitionType::LinuxExtended,
            0x8E => PartitionType::LinuxLvm,
            0xA5 => PartitionType::FreeBsd,
            0xA6 => PartitionType::OpenBsd,
            0xA9 => PartitionType::NetBsd,
            0xEE => PartitionType::GptProtective,
            0xEF => PartitionType::EfiSystem,
            _ => PartitionType::Empty,
        }
    }

    /// Get name of partition type
    pub fn name(self) -> &'static str {
        match self {
            PartitionType::Empty => "Empty",
            PartitionType::Fat12 => "FAT12",
            PartitionType::XenixRoot => "XENIX root",
            PartitionType::XenixUsr => "XENIX usr",
            PartitionType::Fat16Small => "FAT16 <32M",
            PartitionType::Extended => "Extended",
            PartitionType::Fat16 => "FAT16",
            PartitionType::Ntfs => "NTFS/HPFS",
            PartitionType::Fat32 => "FAT32",
            PartitionType::Fat32Lba => "FAT32 LBA",
            PartitionType::Fat16Lba => "FAT16 LBA",
            PartitionType::ExtendedLba => "Extended LBA",
            PartitionType::HiddenFat12 => "Hidden FAT12",
            PartitionType::HiddenFat16Small => "Hidden FAT16 <32M",
            PartitionType::HiddenFat16 => "Hidden FAT16",
            PartitionType::HiddenNtfs => "Hidden NTFS",
            PartitionType::HiddenFat32 => "Hidden FAT32",
            PartitionType::HiddenFat32Lba => "Hidden FAT32 LBA",
            PartitionType::HiddenFat16Lba => "Hidden FAT16 LBA",
            PartitionType::LdmMetadata => "LDM Metadata",
            PartitionType::LdmData => "LDM Data",
            PartitionType::LinuxSwap => "Linux Swap",
            PartitionType::Linux => "Linux",
            PartitionType::LinuxExtended => "Linux Extended",
            PartitionType::LinuxLvm => "Linux LVM",
            PartitionType::FreeBsd => "FreeBSD",
            PartitionType::OpenBsd => "OpenBSD",
            PartitionType::NetBsd => "NetBSD",
            PartitionType::GptProtective => "GPT Protective",
            PartitionType::EfiSystem => "EFI System",
        }
    }

    /// Check if this is an extended partition
    pub fn is_extended(self) -> bool {
        matches!(
            self,
            PartitionType::Extended | PartitionType::ExtendedLba
        )
    }

    /// Check if this is a hidden partition
    pub fn is_hidden(self) -> bool {
        matches!(
            self,
            PartitionType::HiddenFat12
                | PartitionType::HiddenFat16Small
                | PartitionType::HiddenFat16
                | PartitionType::HiddenNtfs
                | PartitionType::HiddenFat32
                | PartitionType::HiddenFat32Lba
                | PartitionType::HiddenFat16Lba
        )
    }
}

/// Partition style
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionStyle {
    /// MBR partition table
    Mbr,
    /// GPT partition table
    Gpt,
    /// Raw disk (no partition table)
    Raw,
}

/// Partition information
#[derive(Debug, Clone)]
pub struct PartitionInfo {
    /// Partition style
    pub style: PartitionStyle,
    /// Starting offset in bytes
    pub start_offset: u64,
    /// Partition length in bytes
    pub length: u64,
    /// Partition number (1-based)
    pub partition_number: u32,
    /// Rewrite partition flag
    pub rewrite_partition: bool,
    /// MBR-specific info
    pub mbr: Option<MbrPartitionInfo>,
    /// GPT-specific info
    pub gpt: Option<GptPartitionInfo>,
}

/// MBR-specific partition information
#[derive(Debug, Clone)]
pub struct MbrPartitionInfo {
    /// Partition type
    pub partition_type: PartitionType,
    /// Boot indicator (0x80 = bootable)
    pub boot_indicator: bool,
    /// Recognized partition
    pub recognized_partition: bool,
    /// Hidden sectors
    pub hidden_sectors: u32,
}

/// GPT-specific partition information
#[derive(Debug, Clone)]
pub struct GptPartitionInfo {
    /// Partition type GUID
    pub partition_type: Guid,
    /// Unique partition GUID
    pub partition_id: Guid,
    /// Partition attributes
    pub attributes: u64,
    /// Partition name
    pub name: String,
}

/// Drive layout information
#[derive(Debug, Clone)]
pub struct DriveLayout {
    /// Partition style
    pub style: PartitionStyle,
    /// Partition count
    pub partition_count: u32,
    /// MBR-specific info
    pub mbr: Option<DriveLayoutMbr>,
    /// GPT-specific info
    pub gpt: Option<DriveLayoutGpt>,
    /// Partition array
    pub partitions: Vec<PartitionInfo>,
}

/// MBR drive layout info
#[derive(Debug, Clone)]
pub struct DriveLayoutMbr {
    /// Disk signature
    pub signature: u32,
}

/// GPT drive layout info
#[derive(Debug, Clone)]
pub struct DriveLayoutGpt {
    /// Disk GUID
    pub disk_id: Guid,
    /// Starting usable LBA
    pub starting_usable_offset: u64,
    /// Usable length
    pub usable_length: u64,
    /// Max partition count
    pub max_partition_count: u32,
}

/// Read partition table from disk
pub fn fstub_read_partition_table(
    disk_data: &[u8],
    disk_size: u64,
    sector_size: u32,
) -> Result<DriveLayout, FstubError> {
    if disk_data.len() < 512 {
        return Err(FstubError::BufferTooSmall);
    }

    // Check for MBR signature
    if disk_data[510] != 0x55 || disk_data[511] != 0xAA {
        return Err(FstubError::InvalidSignature);
    }

    // Check for GPT (type 0xEE protective MBR)
    let mbr = Mbr::from_bytes(&disk_data[0..512])?;

    for entry in &mbr.partitions {
        if entry.partition_type == PartitionType::GptProtective as u8 {
            // This is a GPT disk
            if disk_data.len() < 1024 {
                return Err(FstubError::BufferTooSmall);
            }
            return gpt::read_gpt_layout(disk_data, disk_size, sector_size);
        }
    }

    // MBR disk
    mbr::read_mbr_layout(&mbr, disk_data, disk_size, sector_size)
}

/// Write partition table to disk
pub fn fstub_write_partition_table(
    layout: &DriveLayout,
    disk_data: &mut [u8],
    _sector_size: u32,
) -> Result<(), FstubError> {
    match layout.style {
        PartitionStyle::Mbr => mbr::write_mbr_layout(layout, disk_data),
        PartitionStyle::Gpt => gpt::write_gpt_layout(layout, disk_data),
        PartitionStyle::Raw => Err(FstubError::InvalidPartitionStyle),
    }
}

/// FSTUB error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FstubError {
    /// Buffer too small
    BufferTooSmall,
    /// Invalid signature
    InvalidSignature,
    /// Invalid partition table
    InvalidPartitionTable,
    /// Invalid partition style
    InvalidPartitionStyle,
    /// CRC mismatch
    CrcMismatch,
    /// Too many partitions
    TooManyPartitions,
    /// Partition not found
    PartitionNotFound,
    /// Disk too small
    DiskTooSmall,
    /// I/O error
    IoError,
}

/// Validate a partition entry
pub fn fstub_validate_partition(
    partition: &PartitionInfo,
    disk_size: u64,
) -> Result<(), FstubError> {
    // Check that partition is within disk bounds
    if partition.start_offset >= disk_size {
        return Err(FstubError::InvalidPartitionTable);
    }

    if partition.start_offset + partition.length > disk_size {
        return Err(FstubError::InvalidPartitionTable);
    }

    Ok(())
}

/// Get partition type name from MBR type byte
pub fn fstub_get_partition_type_name(partition_type: u8) -> &'static str {
    PartitionType::from_u8(partition_type).name()
}

/// Check if disk has GPT partition table
pub fn fstub_is_gpt_disk(disk_data: &[u8]) -> bool {
    if disk_data.len() < 512 {
        return false;
    }

    // Check MBR signature
    if disk_data[510] != 0x55 || disk_data[511] != 0xAA {
        return false;
    }

    // Check for GPT protective MBR
    if let Ok(mbr) = Mbr::from_bytes(&disk_data[0..512]) {
        for entry in &mbr.partitions {
            if entry.partition_type == PartitionType::GptProtective as u8 {
                return true;
            }
        }
    }

    false
}

/// Initialize FSTUB subsystem
pub fn fstub_initialize() -> bool {
    crate::serial_println!("[FSTUB] Partition/disk support initialized");
    true
}
