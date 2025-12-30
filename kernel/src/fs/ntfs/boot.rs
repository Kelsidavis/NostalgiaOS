//! NTFS Boot Sector and BIOS Parameter Block
//!
//! The NTFS boot sector contains critical volume information:
//! - BIOS Parameter Block (BPB) with sector/cluster sizes
//! - Extended BPB with NTFS-specific parameters
//! - Location of the Master File Table (MFT)
//!
//! # Boot Sector Layout
//!
//! ```text
//! Offset  Size  Description
//! 0x00    3     Jump instruction
//! 0x03    8     OEM ID ("NTFS    ")
//! 0x0B    2     Bytes per sector
//! 0x0D    1     Sectors per cluster
//! 0x0E    2     Reserved sectors (always 0)
//! 0x10    3     Always 0
//! 0x13    2     Not used by NTFS
//! 0x15    1     Media descriptor
//! 0x16    2     Always 0
//! 0x18    2     Sectors per track
//! 0x1A    2     Number of heads
//! 0x1C    4     Hidden sectors
//! 0x20    4     Not used by NTFS
//! 0x24    4     Not used by NTFS
//! 0x28    8     Total sectors
//! 0x30    8     MFT starting cluster
//! 0x38    8     MFT mirror starting cluster
//! 0x40    1     Clusters per file record (or negative power of 2)
//! 0x41    3     Not used
//! 0x44    1     Clusters per index block (or negative power of 2)
//! 0x45    3     Not used
//! 0x48    8     Volume serial number
//! 0x50    4     Checksum
//! 0x54    426   Bootstrap code
//! 0x1FE   2     End of sector marker (0xAA55)
//! ```

use core::mem;

/// NTFS boot sector signature in OEM ID field
pub const NTFS_SIGNATURE: &[u8; 8] = b"NTFS    ";

/// End of sector marker
pub const BOOT_SECTOR_MARKER: u16 = 0xAA55;

/// Standard sector size
pub const SECTOR_SIZE: u32 = 512;

/// NTFS BIOS Parameter Block
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct NtfsBpb {
    /// Bytes per sector (usually 512)
    pub bytes_per_sector: u16,
    /// Sectors per cluster (power of 2, 1-128)
    pub sectors_per_cluster: u8,
    /// Reserved sectors (always 0 for NTFS)
    pub reserved_sectors: u16,
    /// Always 0 for NTFS
    pub always_zero1: [u8; 3],
    /// Not used by NTFS
    pub not_used1: u16,
    /// Media descriptor (0xF8 for fixed disk)
    pub media_descriptor: u8,
    /// Always 0 for NTFS
    pub always_zero2: u16,
    /// Sectors per track (geometry)
    pub sectors_per_track: u16,
    /// Number of heads (geometry)
    pub number_of_heads: u16,
    /// Hidden sectors (before this volume)
    pub hidden_sectors: u32,
    /// Not used by NTFS
    pub not_used2: u32,
    /// Not used by NTFS (signature 0x80008000)
    pub not_used3: u32,
    /// Total sectors in volume
    pub total_sectors: u64,
    /// Starting cluster of MFT
    pub mft_cluster: u64,
    /// Starting cluster of MFT mirror
    pub mft_mirror_cluster: u64,
    /// Clusters per file record segment (or negative log2 if < 0)
    pub clusters_per_file_record: i8,
    /// Reserved
    pub reserved1: [u8; 3],
    /// Clusters per index block (or negative log2 if < 0)
    pub clusters_per_index_block: i8,
    /// Reserved
    pub reserved2: [u8; 3],
    /// Volume serial number
    pub volume_serial: u64,
    /// Checksum (not used)
    pub checksum: u32,
}

impl NtfsBpb {
    /// Get bytes per cluster
    pub fn bytes_per_cluster(&self) -> u32 {
        self.bytes_per_sector as u32 * self.sectors_per_cluster as u32
    }

    /// Get the actual file record size in bytes
    pub fn file_record_size(&self) -> u32 {
        if self.clusters_per_file_record >= 0 {
            // Positive: clusters per file record
            self.clusters_per_file_record as u32 * self.bytes_per_cluster()
        } else {
            // Negative: 2^(-n) bytes
            1u32 << (-self.clusters_per_file_record) as u32
        }
    }

    /// Get the actual index block size in bytes
    pub fn index_block_size(&self) -> u32 {
        if self.clusters_per_index_block >= 0 {
            self.clusters_per_index_block as u32 * self.bytes_per_cluster()
        } else {
            1u32 << (-self.clusters_per_index_block) as u32
        }
    }

    /// Get MFT byte offset from start of volume
    pub fn mft_offset(&self) -> u64 {
        self.mft_cluster * self.bytes_per_cluster() as u64
    }

    /// Get MFT mirror byte offset from start of volume
    pub fn mft_mirror_offset(&self) -> u64 {
        self.mft_mirror_cluster * self.bytes_per_cluster() as u64
    }

    /// Validate BPB parameters
    pub fn is_valid(&self) -> bool {
        // Check bytes per sector (must be power of 2, 512-4096)
        if self.bytes_per_sector < 512 || self.bytes_per_sector > 4096 {
            return false;
        }
        if !self.bytes_per_sector.is_power_of_two() {
            return false;
        }

        // Check sectors per cluster (must be power of 2)
        if self.sectors_per_cluster == 0 || !self.sectors_per_cluster.is_power_of_two() {
            return false;
        }

        // Check total sectors
        if self.total_sectors == 0 {
            return false;
        }

        // Check MFT location
        if self.mft_cluster == 0 || self.mft_cluster >= self.total_sectors {
            return false;
        }

        true
    }
}

/// Complete NTFS boot sector
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct NtfsBootSector {
    /// Jump instruction (EB xx 90)
    pub jump: [u8; 3],
    /// OEM ID ("NTFS    ")
    pub oem_id: [u8; 8],
    /// BIOS Parameter Block
    pub bpb: NtfsBpb,
    /// Bootstrap code
    pub bootstrap: [u8; 426],
    /// End of sector marker (0xAA55)
    pub signature: u16,
}

impl NtfsBootSector {
    /// Validate boot sector
    pub fn is_valid(&self) -> bool {
        // Check NTFS signature
        if &self.oem_id != NTFS_SIGNATURE {
            return false;
        }

        // Check end marker
        if self.signature != BOOT_SECTOR_MARKER {
            return false;
        }

        // Validate BPB
        self.bpb.is_valid()
    }

    /// Parse boot sector from raw bytes
    pub fn from_bytes(data: &[u8; 512]) -> Option<Self> {
        if data.len() < mem::size_of::<NtfsBootSector>() {
            return None;
        }

        // Safety: We've verified the slice is large enough
        let boot = unsafe {
            core::ptr::read_unaligned(data.as_ptr() as *const NtfsBootSector)
        };

        if boot.is_valid() {
            Some(boot)
        } else {
            None
        }
    }

    /// Get volume label (must be read from $Volume file)
    pub fn volume_serial_hex(&self) -> u64 {
        self.bpb.volume_serial
    }
}

/// Volume information parsed from boot sector
#[derive(Debug, Clone, Copy)]
pub struct NtfsVolumeInfo {
    /// Bytes per sector
    pub bytes_per_sector: u16,
    /// Sectors per cluster
    pub sectors_per_cluster: u8,
    /// Bytes per cluster
    pub bytes_per_cluster: u32,
    /// Total sectors in volume
    pub total_sectors: u64,
    /// Total clusters in volume
    pub total_clusters: u64,
    /// MFT starting cluster
    pub mft_cluster: u64,
    /// MFT mirror starting cluster
    pub mft_mirror_cluster: u64,
    /// MFT byte offset
    pub mft_offset: u64,
    /// File record size in bytes
    pub file_record_size: u32,
    /// Index block size in bytes
    pub index_block_size: u32,
    /// Volume serial number
    pub volume_serial: u64,
}

impl NtfsVolumeInfo {
    /// Extract volume info from boot sector
    pub fn from_boot_sector(boot: &NtfsBootSector) -> Self {
        let bytes_per_cluster = boot.bpb.bytes_per_cluster();
        let total_clusters = boot.bpb.total_sectors / boot.bpb.sectors_per_cluster as u64;

        Self {
            bytes_per_sector: boot.bpb.bytes_per_sector,
            sectors_per_cluster: boot.bpb.sectors_per_cluster,
            bytes_per_cluster,
            total_sectors: boot.bpb.total_sectors,
            total_clusters,
            mft_cluster: boot.bpb.mft_cluster,
            mft_mirror_cluster: boot.bpb.mft_mirror_cluster,
            mft_offset: boot.bpb.mft_offset(),
            file_record_size: boot.bpb.file_record_size(),
            index_block_size: boot.bpb.index_block_size(),
            volume_serial: boot.bpb.volume_serial,
        }
    }
}

/// Initialize boot sector module
pub fn init() {
    crate::serial_println!("[FS] NTFS boot sector parser initialized");
}

/// Detect if a volume is NTFS
pub fn detect_ntfs(sector_data: &[u8]) -> bool {
    if sector_data.len() < 512 {
        return false;
    }

    // Check OEM ID at offset 3
    if sector_data.len() >= 11 {
        if &sector_data[3..11] == NTFS_SIGNATURE {
            // Check boot signature at 510-511
            if sector_data.len() >= 512 {
                let sig = u16::from_le_bytes([sector_data[510], sector_data[511]]);
                return sig == BOOT_SECTOR_MARKER;
            }
        }
    }

    false
}
