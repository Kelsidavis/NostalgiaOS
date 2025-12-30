//! Disk Geometry Support
//!
//! Handles disk geometry calculations and media type detection.

use alloc::string::String;

extern crate alloc;

/// Disk geometry information
#[derive(Debug, Clone, Copy, Default)]
pub struct DiskGeometry {
    /// Number of cylinders
    pub cylinders: u64,
    /// Tracks per cylinder
    pub tracks_per_cylinder: u32,
    /// Sectors per track
    pub sectors_per_track: u32,
    /// Bytes per sector
    pub bytes_per_sector: u32,
    /// Media type
    pub media_type: MediaType,
}

impl DiskGeometry {
    /// Create new disk geometry
    pub fn new(
        cylinders: u64,
        tracks_per_cylinder: u32,
        sectors_per_track: u32,
        bytes_per_sector: u32,
        media_type: MediaType,
    ) -> Self {
        Self {
            cylinders,
            tracks_per_cylinder,
            sectors_per_track,
            bytes_per_sector,
            media_type,
        }
    }

    /// Calculate total disk size in bytes
    pub fn total_size(&self) -> u64 {
        self.cylinders
            * self.tracks_per_cylinder as u64
            * self.sectors_per_track as u64
            * self.bytes_per_sector as u64
    }

    /// Calculate total sector count
    pub fn total_sectors(&self) -> u64 {
        self.cylinders * self.tracks_per_cylinder as u64 * self.sectors_per_track as u64
    }

    /// Convert LBA to CHS
    pub fn lba_to_chs(&self, lba: u64) -> (u64, u32, u32) {
        if self.sectors_per_track == 0 || self.tracks_per_cylinder == 0 {
            return (0, 0, 0);
        }

        let cylinder =
            lba / (self.sectors_per_track as u64 * self.tracks_per_cylinder as u64);
        let temp = lba % (self.sectors_per_track as u64 * self.tracks_per_cylinder as u64);
        let head = (temp / self.sectors_per_track as u64) as u32;
        let sector = (temp % self.sectors_per_track as u64 + 1) as u32;

        (cylinder, head, sector)
    }

    /// Convert CHS to LBA
    pub fn chs_to_lba(&self, cylinder: u64, head: u32, sector: u32) -> u64 {
        if sector == 0 {
            return 0;
        }

        cylinder * self.tracks_per_cylinder as u64 * self.sectors_per_track as u64
            + head as u64 * self.sectors_per_track as u64
            + (sector as u64 - 1)
    }

    /// Check if this is a removable media
    pub fn is_removable(&self) -> bool {
        matches!(
            self.media_type,
            MediaType::RemovableMedia
                | MediaType::F3_1pt44_512
                | MediaType::F3_2pt88_512
                | MediaType::F3_20pt8_512
                | MediaType::F3_720_512
                | MediaType::F5_360_512
                | MediaType::F5_320_512
                | MediaType::F5_320_1024
                | MediaType::F5_180_512
                | MediaType::F5_160_512
                | MediaType::F5_1pt2_512
        )
    }
}

/// Extended disk geometry with additional information
#[derive(Debug, Clone, Default)]
pub struct DiskGeometryEx {
    /// Basic geometry
    pub geometry: DiskGeometry,
    /// Disk size in bytes
    pub disk_size: u64,
    /// Partition information present
    pub has_partition_info: bool,
    /// Detection information present
    pub has_detection_info: bool,
}

impl DiskGeometryEx {
    /// Create from basic geometry
    pub fn from_geometry(geometry: DiskGeometry) -> Self {
        Self {
            disk_size: geometry.total_size(),
            geometry,
            has_partition_info: false,
            has_detection_info: false,
        }
    }
}

/// Media type enumeration
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MediaType {
    /// Unknown media type
    #[default]
    Unknown = 0,
    /// 5.25" 1.2MB floppy
    F5_1pt2_512 = 1,
    /// 3.5" 1.44MB floppy
    F3_1pt44_512 = 2,
    /// 3.5" 2.88MB floppy
    F3_2pt88_512 = 3,
    /// 3.5" 20.8MB floppy
    F3_20pt8_512 = 4,
    /// 3.5" 720KB floppy
    F3_720_512 = 5,
    /// 5.25" 360KB floppy
    F5_360_512 = 6,
    /// 5.25" 320KB floppy
    F5_320_512 = 7,
    /// 5.25" 320KB 1024 bytes/sector
    F5_320_1024 = 8,
    /// 5.25" 180KB floppy
    F5_180_512 = 9,
    /// 5.25" 160KB floppy
    F5_160_512 = 10,
    /// Removable media (other than floppy)
    RemovableMedia = 11,
    /// Fixed hard disk
    FixedMedia = 12,
    /// 3.5" 120MB floppy
    F3_120M_512 = 13,
    /// 3.5" 640MB magneto-optical
    F3_640_512 = 14,
    /// 5.25" 640KB floppy
    F5_640_512 = 15,
    /// 5.25" 720KB floppy
    F5_720_512 = 16,
    /// 3.5" 1.2MB floppy
    F3_1pt2_512 = 17,
    /// 3.5" 1.23MB floppy
    F3_1pt23_1024 = 18,
    /// 5.25" 1.23MB floppy
    F5_1pt23_1024 = 19,
    /// 3.5" 128MB magneto-optical
    F3_128Mb_512 = 20,
    /// 3.5" 230MB magneto-optical
    F3_230Mb_512 = 21,
    /// 8" 256KB floppy
    F8_256_128 = 22,
    /// 3.5" 200MB floppy
    F3_200Mb_512 = 23,
    /// 3.5" 240MB floppy
    F3_240M_512 = 24,
    /// 3.5" 32MB floppy
    F3_32M_512 = 25,
}

impl MediaType {
    /// Get media type name
    pub fn name(self) -> &'static str {
        match self {
            MediaType::Unknown => "Unknown",
            MediaType::F5_1pt2_512 => "5.25\" 1.2MB",
            MediaType::F3_1pt44_512 => "3.5\" 1.44MB",
            MediaType::F3_2pt88_512 => "3.5\" 2.88MB",
            MediaType::F3_20pt8_512 => "3.5\" 20.8MB",
            MediaType::F3_720_512 => "3.5\" 720KB",
            MediaType::F5_360_512 => "5.25\" 360KB",
            MediaType::F5_320_512 => "5.25\" 320KB",
            MediaType::F5_320_1024 => "5.25\" 320KB (1K)",
            MediaType::F5_180_512 => "5.25\" 180KB",
            MediaType::F5_160_512 => "5.25\" 160KB",
            MediaType::RemovableMedia => "Removable",
            MediaType::FixedMedia => "Fixed",
            MediaType::F3_120M_512 => "3.5\" 120MB",
            MediaType::F3_640_512 => "3.5\" 640MB MO",
            MediaType::F5_640_512 => "5.25\" 640KB",
            MediaType::F5_720_512 => "5.25\" 720KB",
            MediaType::F3_1pt2_512 => "3.5\" 1.2MB",
            MediaType::F3_1pt23_1024 => "3.5\" 1.23MB",
            MediaType::F5_1pt23_1024 => "5.25\" 1.23MB",
            MediaType::F3_128Mb_512 => "3.5\" 128MB MO",
            MediaType::F3_230Mb_512 => "3.5\" 230MB MO",
            MediaType::F8_256_128 => "8\" 256KB",
            MediaType::F3_200Mb_512 => "3.5\" 200MB",
            MediaType::F3_240M_512 => "3.5\" 240MB",
            MediaType::F3_32M_512 => "3.5\" 32MB",
        }
    }

    /// Create from u32
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => MediaType::F5_1pt2_512,
            2 => MediaType::F3_1pt44_512,
            3 => MediaType::F3_2pt88_512,
            4 => MediaType::F3_20pt8_512,
            5 => MediaType::F3_720_512,
            6 => MediaType::F5_360_512,
            7 => MediaType::F5_320_512,
            8 => MediaType::F5_320_1024,
            9 => MediaType::F5_180_512,
            10 => MediaType::F5_160_512,
            11 => MediaType::RemovableMedia,
            12 => MediaType::FixedMedia,
            13 => MediaType::F3_120M_512,
            14 => MediaType::F3_640_512,
            15 => MediaType::F5_640_512,
            16 => MediaType::F5_720_512,
            17 => MediaType::F3_1pt2_512,
            18 => MediaType::F3_1pt23_1024,
            19 => MediaType::F5_1pt23_1024,
            20 => MediaType::F3_128Mb_512,
            21 => MediaType::F3_230Mb_512,
            22 => MediaType::F8_256_128,
            23 => MediaType::F3_200Mb_512,
            24 => MediaType::F3_240M_512,
            25 => MediaType::F3_32M_512,
            _ => MediaType::Unknown,
        }
    }
}

/// Detection type for disk geometry
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DetectionType {
    /// No detection information
    #[default]
    None = 0,
    /// INT13 extended geometry
    Int13 = 1,
    /// Examine boot sector
    ExamineBootSector = 2,
}

/// Partition information for geometry
#[derive(Debug, Clone, Copy, Default)]
pub struct PartitionGeometryInfo {
    /// Partition size
    pub size: u64,
    /// Partition count
    pub partition_count: u32,
    /// Style (MBR/GPT)
    pub partition_style: u32,
    /// MBR signature (if MBR)
    pub mbr_signature: u32,
    /// GPT disk ID (if GPT) - using u128 for simplicity
    pub gpt_disk_id: [u8; 16],
}

/// Detection information for geometry
#[derive(Debug, Clone, Copy, Default)]
pub struct DetectionInfo {
    /// Size of this structure
    pub size: u32,
    /// Detection type
    pub detection_type: DetectionType,
    /// INT13 information (if applicable)
    pub int13: Option<Int13Info>,
}

/// INT13 detection information
#[derive(Debug, Clone, Copy, Default)]
pub struct Int13Info {
    /// Drive select (0x80 for first hard disk)
    pub drive_select: u8,
    /// Maximum cylinder
    pub max_cylinders: u32,
    /// Sectors per track
    pub sectors_per_track: u16,
    /// Maximum head
    pub max_heads: u16,
    /// Number of drives
    pub number_of_drives: u16,
}

/// Estimate geometry from disk size
pub fn estimate_geometry(disk_size: u64, sector_size: u32) -> DiskGeometry {
    let total_sectors = disk_size / sector_size as u64;

    // Standard geometry for modern disks
    let sectors_per_track: u32 = 63;
    let tracks_per_cylinder: u32 = 255;

    let cylinders = total_sectors / (sectors_per_track as u64 * tracks_per_cylinder as u64);

    DiskGeometry {
        cylinders: if cylinders == 0 { 1 } else { cylinders },
        tracks_per_cylinder,
        sectors_per_track,
        bytes_per_sector: sector_size,
        media_type: if disk_size < 100 * 1024 * 1024 {
            MediaType::RemovableMedia
        } else {
            MediaType::FixedMedia
        },
    }
}

/// Format disk size as human-readable string
pub fn format_disk_size(size: u64) -> String {
    if size >= 1024 * 1024 * 1024 * 1024 {
        let tb = size as f64 / (1024.0 * 1024.0 * 1024.0 * 1024.0);
        alloc::format!("{:.2} TB", tb)
    } else if size >= 1024 * 1024 * 1024 {
        let gb = size as f64 / (1024.0 * 1024.0 * 1024.0);
        alloc::format!("{:.2} GB", gb)
    } else if size >= 1024 * 1024 {
        let mb = size as f64 / (1024.0 * 1024.0);
        alloc::format!("{:.2} MB", mb)
    } else if size >= 1024 {
        let kb = size as f64 / 1024.0;
        alloc::format!("{:.2} KB", kb)
    } else {
        alloc::format!("{} B", size)
    }
}
