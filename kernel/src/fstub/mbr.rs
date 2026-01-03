//! Master Boot Record (MBR) Support
//!
//! Handles legacy MBR partition tables.

use super::{
    DriveLayout, DriveLayoutMbr, FstubError, MbrPartitionInfo, PartitionInfo, PartitionStyle,
    PartitionType,
};
use alloc::vec::Vec;

extern crate alloc;

/// MBR signature
pub const MBR_SIGNATURE: u16 = 0xAA55;

/// Maximum MBR partitions
pub const MAX_MBR_PARTITIONS: usize = 4;

/// MBR partition entry (on-disk format)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MbrPartitionEntry {
    /// Boot indicator (0x80 = active/bootable)
    pub boot_indicator: u8,
    /// Starting head
    pub start_head: u8,
    /// Starting sector (bits 0-5) and cylinder high bits (6-7)
    pub start_sector: u8,
    /// Starting cylinder low bits
    pub start_cylinder: u8,
    /// Partition type
    pub partition_type: u8,
    /// Ending head
    pub end_head: u8,
    /// Ending sector (bits 0-5) and cylinder high bits (6-7)
    pub end_sector: u8,
    /// Ending cylinder low bits
    pub end_cylinder: u8,
    /// Starting LBA
    pub starting_lba: u32,
    /// Size in LBA
    pub size_in_lba: u32,
}

impl MbrPartitionEntry {
    /// Check if this entry is empty
    pub fn is_empty(&self) -> bool {
        self.partition_type == 0 && self.starting_lba == 0 && self.size_in_lba == 0
    }

    /// Check if this is the bootable partition
    pub fn is_bootable(&self) -> bool {
        self.boot_indicator == 0x80
    }

    /// Get the partition type enum
    pub fn get_partition_type(&self) -> PartitionType {
        PartitionType::from_u8(self.partition_type)
    }

    /// Get starting CHS values
    pub fn get_start_chs(&self) -> (u16, u8, u8) {
        let cylinder = ((self.start_sector as u16 & 0xC0) << 2) | self.start_cylinder as u16;
        let head = self.start_head;
        let sector = self.start_sector & 0x3F;
        (cylinder, head, sector)
    }

    /// Get ending CHS values
    pub fn get_end_chs(&self) -> (u16, u8, u8) {
        let cylinder = ((self.end_sector as u16 & 0xC0) << 2) | self.end_cylinder as u16;
        let head = self.end_head;
        let sector = self.end_sector & 0x3F;
        (cylinder, head, sector)
    }

    /// Calculate CHS values from LBA
    pub fn set_chs_from_lba(
        &mut self,
        start_lba: u32,
        sectors: u32,
        sectors_per_track: u32,
        heads: u32,
    ) {
        // Calculate start CHS
        let (start_c, start_h, start_s) =
            lba_to_chs(start_lba, sectors_per_track, heads);
        self.start_cylinder = (start_c & 0xFF) as u8;
        self.start_head = start_h;
        self.start_sector = start_s | (((start_c >> 8) & 0x03) as u8) << 6;

        // Calculate end CHS
        let end_lba = start_lba + sectors - 1;
        let (end_c, end_h, end_s) = lba_to_chs(end_lba, sectors_per_track, heads);
        self.end_cylinder = (end_c & 0xFF) as u8;
        self.end_head = end_h;
        self.end_sector = end_s | (((end_c >> 8) & 0x03) as u8) << 6;
    }
}

/// Convert LBA to CHS
fn lba_to_chs(lba: u32, sectors_per_track: u32, heads: u32) -> (u16, u8, u8) {
    if sectors_per_track == 0 || heads == 0 {
        return (0, 0, 0);
    }

    let cylinder = lba / (sectors_per_track * heads);
    let temp = lba % (sectors_per_track * heads);
    let head = temp / sectors_per_track;
    let sector = (temp % sectors_per_track) + 1;

    // Cap cylinder at 1023 (10 bits)
    let cylinder = if cylinder > 1023 { 1023 } else { cylinder as u16 };

    (cylinder, head as u8, sector as u8)
}

/// Master Boot Record structure
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Mbr {
    /// Bootstrap code
    pub bootstrap_code: [u8; 440],
    /// Disk signature (Windows NT)
    pub disk_signature: u32,
    /// Reserved (usually 0x0000)
    pub reserved: u16,
    /// Partition table entries
    pub partitions: [MbrPartitionEntry; 4],
    /// Boot signature (0xAA55)
    pub signature: u16,
}

impl Mbr {
    /// Create a new empty MBR
    pub fn new() -> Self {
        Self {
            bootstrap_code: [0; 440],
            disk_signature: 0,
            reserved: 0,
            partitions: [MbrPartitionEntry::default(); 4],
            signature: MBR_SIGNATURE,
        }
    }

    /// Parse MBR from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, FstubError> {
        if data.len() < 512 {
            return Err(FstubError::BufferTooSmall);
        }

        // Check signature
        let sig = u16::from_le_bytes([data[510], data[511]]);
        if sig != MBR_SIGNATURE {
            return Err(FstubError::InvalidSignature);
        }

        let mut mbr = Mbr::new();

        // Copy bootstrap code
        mbr.bootstrap_code.copy_from_slice(&data[0..440]);

        // Read disk signature
        mbr.disk_signature = u32::from_le_bytes([data[440], data[441], data[442], data[443]]);
        mbr.reserved = u16::from_le_bytes([data[444], data[445]]);

        // Read partition entries
        for (i, entry) in mbr.partitions.iter_mut().enumerate() {
            let offset = 446 + i * 16;
            entry.boot_indicator = data[offset];
            entry.start_head = data[offset + 1];
            entry.start_sector = data[offset + 2];
            entry.start_cylinder = data[offset + 3];
            entry.partition_type = data[offset + 4];
            entry.end_head = data[offset + 5];
            entry.end_sector = data[offset + 6];
            entry.end_cylinder = data[offset + 7];
            entry.starting_lba =
                u32::from_le_bytes([data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11]]);
            entry.size_in_lba =
                u32::from_le_bytes([data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15]]);
        }

        mbr.signature = sig;

        Ok(mbr)
    }

    /// Write MBR to bytes
    pub fn to_bytes(&self, data: &mut [u8]) -> Result<(), FstubError> {
        if data.len() < 512 {
            return Err(FstubError::BufferTooSmall);
        }

        // Copy bootstrap code
        data[0..440].copy_from_slice(&self.bootstrap_code);

        // Write disk signature
        data[440..444].copy_from_slice(&self.disk_signature.to_le_bytes());
        data[444..446].copy_from_slice(&self.reserved.to_le_bytes());

        // Write partition entries
        for (i, entry) in self.partitions.iter().enumerate() {
            let offset = 446 + i * 16;
            data[offset] = entry.boot_indicator;
            data[offset + 1] = entry.start_head;
            data[offset + 2] = entry.start_sector;
            data[offset + 3] = entry.start_cylinder;
            data[offset + 4] = entry.partition_type;
            data[offset + 5] = entry.end_head;
            data[offset + 6] = entry.end_sector;
            data[offset + 7] = entry.end_cylinder;
            data[offset + 8..offset + 12].copy_from_slice(&entry.starting_lba.to_le_bytes());
            data[offset + 12..offset + 16].copy_from_slice(&entry.size_in_lba.to_le_bytes());
        }

        // Write signature
        data[510..512].copy_from_slice(&self.signature.to_le_bytes());

        Ok(())
    }

    /// Count valid partitions
    pub fn partition_count(&self) -> usize {
        self.partitions.iter().filter(|p| !p.is_empty()).count()
    }

    /// Get the bootable partition index
    pub fn bootable_partition(&self) -> Option<usize> {
        self.partitions.iter().position(|p| p.is_bootable())
    }
}

impl Default for Mbr {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Mbr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Copy values from packed struct to avoid alignment issues
        let disk_sig = self.disk_signature;
        let part_count = self.partition_count();
        f.debug_struct("Mbr")
            .field("disk_signature", &format_args!("{:#010x}", disk_sig))
            .field("partition_count", &part_count)
            .finish()
    }
}

/// Read MBR-based drive layout
pub fn read_mbr_layout(
    mbr: &Mbr,
    disk_data: &[u8],
    disk_size: u64,
    sector_size: u32,
) -> Result<DriveLayout, FstubError> {
    let mut partitions = Vec::new();
    let mut partition_number = 1u32;

    for (_i, entry) in mbr.partitions.iter().enumerate() {
        if entry.is_empty() {
            continue;
        }

        let start_offset = entry.starting_lba as u64 * sector_size as u64;
        let length = entry.size_in_lba as u64 * sector_size as u64;

        // Validate
        if start_offset >= disk_size || start_offset + length > disk_size {
            continue; // Skip invalid partitions
        }

        let partition_type = PartitionType::from_u8(entry.partition_type);

        partitions.push(PartitionInfo {
            style: PartitionStyle::Mbr,
            start_offset,
            length,
            partition_number,
            rewrite_partition: false,
            mbr: Some(MbrPartitionInfo {
                partition_type,
                boot_indicator: entry.is_bootable(),
                recognized_partition: entry.partition_type != 0,
                hidden_sectors: entry.starting_lba,
            }),
            gpt: None,
        });

        partition_number += 1;

        // Handle extended partitions
        if partition_type.is_extended() {
            // Read logical partitions from extended partition
            let extended_partitions =
                read_extended_partitions(disk_data, entry.starting_lba, sector_size, disk_size)?;
            for ext_part in extended_partitions {
                let mut ext_info = ext_part;
                ext_info.partition_number = partition_number;
                partitions.push(ext_info);
                partition_number += 1;
            }
        }
    }

    Ok(DriveLayout {
        style: PartitionStyle::Mbr,
        partition_count: partitions.len() as u32,
        mbr: Some(DriveLayoutMbr {
            signature: mbr.disk_signature,
        }),
        gpt: None,
        partitions,
    })
}

/// Read logical partitions from extended partition
fn read_extended_partitions(
    disk_data: &[u8],
    extended_lba: u32,
    sector_size: u32,
    disk_size: u64,
) -> Result<Vec<PartitionInfo>, FstubError> {
    let mut partitions = Vec::new();
    let mut current_lba = extended_lba;
    let mut iterations = 0;
    const MAX_LOGICAL_PARTITIONS: usize = 64;

    while iterations < MAX_LOGICAL_PARTITIONS {
        let offset = current_lba as usize * sector_size as usize;
        if offset + 512 > disk_data.len() {
            break;
        }

        let ebr = Mbr::from_bytes(&disk_data[offset..offset + 512])?;

        // First entry is the logical partition
        let entry = &ebr.partitions[0];
        if !entry.is_empty() {
            let start_offset =
                (current_lba + entry.starting_lba) as u64 * sector_size as u64;
            let length = entry.size_in_lba as u64 * sector_size as u64;

            if start_offset < disk_size && start_offset + length <= disk_size {
                partitions.push(PartitionInfo {
                    style: PartitionStyle::Mbr,
                    start_offset,
                    length,
                    partition_number: 0, // Will be set by caller
                    rewrite_partition: false,
                    mbr: Some(MbrPartitionInfo {
                        partition_type: PartitionType::from_u8(entry.partition_type),
                        boot_indicator: entry.is_bootable(),
                        recognized_partition: true,
                        hidden_sectors: current_lba + entry.starting_lba,
                    }),
                    gpt: None,
                });
            }
        }

        // Second entry points to next EBR
        let next_entry = &ebr.partitions[1];
        if next_entry.is_empty() || next_entry.partition_type == 0 {
            break;
        }

        current_lba = extended_lba + next_entry.starting_lba;
        iterations += 1;
    }

    Ok(partitions)
}

/// Write MBR-based drive layout
pub fn write_mbr_layout(layout: &DriveLayout, disk_data: &mut [u8]) -> Result<(), FstubError> {
    if disk_data.len() < 512 {
        return Err(FstubError::BufferTooSmall);
    }

    let mbr_info = layout.mbr.as_ref().ok_or(FstubError::InvalidPartitionStyle)?;

    let mut mbr = Mbr::new();
    mbr.disk_signature = mbr_info.signature;

    // Only write primary partitions (first 4)
    let mut entry_index = 0;
    for partition in layout.partitions.iter().take(4) {
        if let Some(ref mbr_part) = partition.mbr {
            let entry = &mut mbr.partitions[entry_index];
            entry.boot_indicator = if mbr_part.boot_indicator { 0x80 } else { 0x00 };
            entry.partition_type = mbr_part.partition_type as u8;
            entry.starting_lba = (partition.start_offset / 512) as u32;
            entry.size_in_lba = (partition.length / 512) as u32;

            // Set CHS (using LBA for large disks)
            entry.set_chs_from_lba(entry.starting_lba, entry.size_in_lba, 63, 255);

            entry_index += 1;
        }
    }

    mbr.to_bytes(disk_data)
}
