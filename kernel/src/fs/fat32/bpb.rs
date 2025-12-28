//! FAT32 BIOS Parameter Block (BPB)
//!
//! The BPB is located in the boot sector (sector 0) and contains
//! essential file system parameters.
//!
//! # Boot Sector Layout (512 bytes)
//! - Bytes 0-2: Jump instruction
//! - Bytes 3-10: OEM name
//! - Bytes 11-35: BPB (BIOS Parameter Block)
//! - Bytes 36-89: Extended BPB (FAT32 specific)
//! - Bytes 90-509: Boot code
//! - Bytes 510-511: Signature (0x55, 0xAA)

/// FAT type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
    ExFat,
    Unknown,
}

/// BIOS Parameter Block (common to FAT12/16/32)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BiosParameterBlock {
    /// Bytes per sector (usually 512)
    pub bytes_per_sector: u16,
    /// Sectors per cluster (power of 2: 1, 2, 4, 8, 16, 32, 64, 128)
    pub sectors_per_cluster: u8,
    /// Reserved sectors (including boot sector)
    pub reserved_sectors: u16,
    /// Number of FATs (usually 2)
    pub num_fats: u8,
    /// Root directory entries (0 for FAT32)
    pub root_entry_count: u16,
    /// Total sectors (16-bit, 0 for FAT32)
    pub total_sectors_16: u16,
    /// Media type (0xF8 for fixed disk)
    pub media_type: u8,
    /// Sectors per FAT (16-bit, 0 for FAT32)
    pub sectors_per_fat_16: u16,
    /// Sectors per track
    pub sectors_per_track: u16,
    /// Number of heads
    pub num_heads: u16,
    /// Hidden sectors
    pub hidden_sectors: u32,
    /// Total sectors (32-bit)
    pub total_sectors_32: u32,
}

impl BiosParameterBlock {
    /// Validate the BPB
    pub fn is_valid(&self) -> bool {
        // Check bytes per sector (must be 512, 1024, 2048, or 4096)
        if !matches!(self.bytes_per_sector, 512 | 1024 | 2048 | 4096) {
            return false;
        }

        // Check sectors per cluster (must be power of 2, 1-128)
        if self.sectors_per_cluster == 0 || self.sectors_per_cluster > 128 {
            return false;
        }
        if !self.sectors_per_cluster.is_power_of_two() {
            return false;
        }

        // Must have at least 1 reserved sector (boot sector)
        if self.reserved_sectors == 0 {
            return false;
        }

        // Must have at least 1 FAT
        if self.num_fats == 0 {
            return false;
        }

        // Media type should be valid
        if !matches!(self.media_type, 0xF0 | 0xF8..=0xFF) {
            return false;
        }

        true
    }

    /// Get total sectors
    pub fn total_sectors(&self) -> u32 {
        if self.total_sectors_16 != 0 {
            self.total_sectors_16 as u32
        } else {
            self.total_sectors_32
        }
    }

    /// Get cluster size in bytes
    pub fn cluster_size(&self) -> u32 {
        self.bytes_per_sector as u32 * self.sectors_per_cluster as u32
    }
}

/// FAT32 Extended BIOS Parameter Block
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Fat32ExtendedBpb {
    /// Sectors per FAT (32-bit)
    pub sectors_per_fat_32: u32,
    /// Extended flags
    pub ext_flags: u16,
    /// File system version
    pub fs_version: u16,
    /// Root directory cluster
    pub root_cluster: u32,
    /// FSInfo sector number
    pub fs_info_sector: u16,
    /// Backup boot sector
    pub backup_boot_sector: u16,
    /// Reserved (must be zero)
    pub reserved: [u8; 12],
    /// Drive number
    pub drive_number: u8,
    /// Reserved
    pub reserved1: u8,
    /// Extended boot signature (0x29)
    pub boot_signature: u8,
    /// Volume serial number
    pub volume_serial: u32,
    /// Volume label (11 bytes, space-padded)
    pub volume_label: [u8; 11],
    /// File system type string ("FAT32   ")
    pub fs_type: [u8; 8],
}

impl Fat32ExtendedBpb {
    /// Validate the extended BPB
    pub fn is_valid(&self) -> bool {
        // Check boot signature
        if self.boot_signature != 0x29 {
            return false;
        }

        // Check FAT32 signature
        if &self.fs_type != b"FAT32   " {
            return false;
        }

        // Root cluster must be valid (typically 2)
        if self.root_cluster < 2 {
            return false;
        }

        true
    }

    /// Get volume label as string
    pub fn volume_label_str(&self) -> &str {
        let len = self.volume_label.iter()
            .rposition(|&b| b != b' ')
            .map(|p| p + 1)
            .unwrap_or(0);
        core::str::from_utf8(&self.volume_label[..len]).unwrap_or("")
    }

    /// Check if mirroring is disabled
    pub fn is_mirroring_disabled(&self) -> bool {
        (self.ext_flags & 0x0080) != 0
    }

    /// Get active FAT number (if mirroring disabled)
    pub fn active_fat(&self) -> u8 {
        if self.is_mirroring_disabled() {
            (self.ext_flags & 0x000F) as u8
        } else {
            0
        }
    }
}

/// Complete FAT32 Boot Sector
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Fat32BootSector {
    /// Jump instruction (EB xx 90 or E9 xx xx)
    pub jump: [u8; 3],
    /// OEM name (8 bytes)
    pub oem_name: [u8; 8],
    /// BIOS Parameter Block
    pub bpb: BiosParameterBlock,
    /// FAT32 Extended BPB
    pub ext_bpb: Fat32ExtendedBpb,
    /// Boot code
    pub boot_code: [u8; 420],
    /// Boot signature (0x55, 0xAA)
    pub signature: [u8; 2],
}

impl Fat32BootSector {
    /// Check if this is a valid FAT32 boot sector
    pub fn is_valid(&self) -> bool {
        // Check signature
        if self.signature != [0x55, 0xAA] {
            return false;
        }

        // Check jump instruction
        if self.jump[0] != 0xEB && self.jump[0] != 0xE9 {
            return false;
        }

        // Validate BPB
        if !self.bpb.is_valid() {
            return false;
        }

        // Must be FAT32 (sectors_per_fat_16 == 0)
        if self.bpb.sectors_per_fat_16 != 0 {
            return false;
        }

        // Validate extended BPB
        if !self.ext_bpb.is_valid() {
            return false;
        }

        true
    }

    /// Determine FAT type from BPB
    pub fn fat_type(&self) -> FatType {
        // FAT32 uses 32-bit sectors per FAT
        if self.bpb.sectors_per_fat_16 == 0 && self.ext_bpb.sectors_per_fat_32 > 0 {
            // Could be FAT32 or exFAT
            if &self.ext_bpb.fs_type == b"FAT32   " {
                return FatType::Fat32;
            }
        }

        // Calculate data sectors and clusters
        let root_dir_sectors = (self.bpb.root_entry_count as u32 * 32).div_ceil(self.bpb.bytes_per_sector as u32);

        let fat_size = if self.bpb.sectors_per_fat_16 != 0 {
            self.bpb.sectors_per_fat_16 as u32
        } else {
            self.ext_bpb.sectors_per_fat_32
        };

        let data_sectors = self.bpb.total_sectors()
            - (self.bpb.reserved_sectors as u32)
            - (self.bpb.num_fats as u32 * fat_size)
            - root_dir_sectors;

        let cluster_count = data_sectors / self.bpb.sectors_per_cluster as u32;

        if cluster_count < 4085 {
            FatType::Fat12
        } else if cluster_count < 65525 {
            FatType::Fat16
        } else {
            FatType::Fat32
        }
    }

    /// Get sectors per FAT
    pub fn sectors_per_fat(&self) -> u32 {
        if self.bpb.sectors_per_fat_16 != 0 {
            self.bpb.sectors_per_fat_16 as u32
        } else {
            self.ext_bpb.sectors_per_fat_32
        }
    }

    /// Get the first data sector
    pub fn first_data_sector(&self) -> u32 {
        let root_dir_sectors = (self.bpb.root_entry_count as u32 * 32).div_ceil(self.bpb.bytes_per_sector as u32);

        self.bpb.reserved_sectors as u32 +
            (self.bpb.num_fats as u32 * self.sectors_per_fat()) +
            root_dir_sectors
    }

    /// Get the first sector of the FAT
    pub fn fat_start_sector(&self) -> u32 {
        self.bpb.reserved_sectors as u32
    }

    /// Get sector number for a cluster
    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        self.first_data_sector() +
            (cluster - 2) * self.bpb.sectors_per_cluster as u32
    }

    /// Get total cluster count
    pub fn total_clusters(&self) -> u32 {
        let data_sectors = self.bpb.total_sectors() - self.first_data_sector();
        data_sectors / self.bpb.sectors_per_cluster as u32
    }
}

/// FSInfo structure (FAT32 only)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct FsInfo {
    /// Leading signature (0x41615252)
    pub lead_sig: u32,
    /// Reserved
    pub reserved1: [u8; 480],
    /// Structure signature (0x61417272)
    pub struct_sig: u32,
    /// Free cluster count (0xFFFFFFFF if unknown)
    pub free_count: u32,
    /// Next free cluster hint (0xFFFFFFFF if unknown)
    pub next_free: u32,
    /// Reserved
    pub reserved2: [u8; 12],
    /// Trailing signature (0xAA550000)
    pub trail_sig: u32,
}

impl FsInfo {
    /// Leading signature value
    pub const LEAD_SIG: u32 = 0x41615252;
    /// Structure signature value
    pub const STRUCT_SIG: u32 = 0x61417272;
    /// Trailing signature value
    pub const TRAIL_SIG: u32 = 0xAA550000;

    /// Check if FSInfo is valid
    pub fn is_valid(&self) -> bool {
        self.lead_sig == Self::LEAD_SIG &&
        self.struct_sig == Self::STRUCT_SIG &&
        self.trail_sig == Self::TRAIL_SIG
    }

    /// Check if free count is known
    pub fn has_free_count(&self) -> bool {
        self.free_count != 0xFFFFFFFF
    }

    /// Check if next free hint is known
    pub fn has_next_free(&self) -> bool {
        self.next_free != 0xFFFFFFFF
    }
}

/// FAT32 cluster entry values
pub mod cluster_values {
    /// Free cluster
    pub const FREE: u32 = 0x00000000;
    /// Reserved cluster
    pub const RESERVED: u32 = 0x00000001;
    /// Bad cluster
    pub const BAD: u32 = 0x0FFFFFF7;
    /// End of chain (minimum value)
    pub const EOC_MIN: u32 = 0x0FFFFFF8;
    /// End of chain (standard value)
    pub const EOC: u32 = 0x0FFFFFFF;

    /// Mask for 28-bit cluster number
    pub const CLUSTER_MASK: u32 = 0x0FFFFFFF;

    /// Check if cluster is end of chain
    pub fn is_eoc(cluster: u32) -> bool {
        (cluster & CLUSTER_MASK) >= EOC_MIN
    }

    /// Check if cluster is free
    pub fn is_free(cluster: u32) -> bool {
        (cluster & CLUSTER_MASK) == FREE
    }

    /// Check if cluster is bad
    pub fn is_bad(cluster: u32) -> bool {
        (cluster & CLUSTER_MASK) == BAD
    }

    /// Check if cluster is valid data cluster
    pub fn is_valid(cluster: u32) -> bool {
        let val = cluster & CLUSTER_MASK;
        (2..BAD).contains(&val)
    }
}

/// Initialize BPB subsystem
pub fn init() {
    crate::serial_println!("[FS] FAT32 BPB subsystem initialized");
}
