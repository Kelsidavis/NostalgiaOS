//! GUID Partition Table (GPT) Support
//!
//! Handles EFI/UEFI GPT partition tables.

use super::{
    DriveLayout, DriveLayoutGpt, FstubError, GptPartitionInfo, PartitionInfo, PartitionStyle,
};
use crate::etw::Guid;
use alloc::string::String;
use alloc::vec::Vec;

extern crate alloc;

/// EFI partition table signature "EFI PART"
pub const EFI_SIGNATURE: u64 = 0x5452415020494645;

/// Current GPT revision
pub const GPT_REVISION: u32 = 0x00010000;

/// GPT partition entry size
pub const GPT_ENTRY_SIZE: u32 = 128;

/// Well-known GPT partition type GUIDs
pub mod gpt_types {
    use crate::etw::Guid;

    /// Unused entry
    pub const UNUSED: Guid = Guid {
        data1: 0x00000000,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    };

    /// EFI System Partition
    pub const EFI_SYSTEM: Guid = Guid {
        data1: 0xC12A7328,
        data2: 0xF81F,
        data3: 0x11D2,
        data4: [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B],
    };

    /// Microsoft Reserved Partition
    pub const MICROSOFT_RESERVED: Guid = Guid {
        data1: 0xE3C9E316,
        data2: 0x0B5C,
        data3: 0x4DB8,
        data4: [0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE],
    };

    /// Microsoft Basic Data (NTFS, FAT)
    pub const MICROSOFT_BASIC_DATA: Guid = Guid {
        data1: 0xEBD0A0A2,
        data2: 0xB9E5,
        data3: 0x4433,
        data4: [0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7],
    };

    /// Microsoft LDM Metadata
    pub const MICROSOFT_LDM_METADATA: Guid = Guid {
        data1: 0x5808C8AA,
        data2: 0x7E8F,
        data3: 0x42E0,
        data4: [0x85, 0xD2, 0xE1, 0xE9, 0x04, 0x34, 0xCF, 0xB3],
    };

    /// Microsoft LDM Data
    pub const MICROSOFT_LDM_DATA: Guid = Guid {
        data1: 0xAF9B60A0,
        data2: 0x1431,
        data3: 0x4F62,
        data4: [0xBC, 0x68, 0x33, 0x11, 0x71, 0x4A, 0x69, 0xAD],
    };

    /// Microsoft Recovery
    pub const MICROSOFT_RECOVERY: Guid = Guid {
        data1: 0xDE94BBA4,
        data2: 0x06D1,
        data3: 0x4D40,
        data4: [0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC],
    };

    /// Linux Filesystem Data
    pub const LINUX_FILESYSTEM: Guid = Guid {
        data1: 0x0FC63DAF,
        data2: 0x8483,
        data3: 0x4772,
        data4: [0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4],
    };

    /// Linux Swap
    pub const LINUX_SWAP: Guid = Guid {
        data1: 0x0657FD6D,
        data2: 0xA4AB,
        data3: 0x43C4,
        data4: [0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F],
    };

    /// Linux LVM
    pub const LINUX_LVM: Guid = Guid {
        data1: 0xE6D6D379,
        data2: 0xF507,
        data3: 0x44C2,
        data4: [0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9, 0x28],
    };
}

/// GPT partition attributes
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct GptAttributes: u64 {
        /// Required partition
        const PLATFORM_REQUIRED = 0x0000_0000_0000_0001;
        /// EFI should ignore
        const EFI_IGNORE = 0x0000_0000_0000_0002;
        /// Legacy BIOS bootable
        const LEGACY_BIOS_BOOTABLE = 0x0000_0000_0000_0004;
        /// Read-only
        const READ_ONLY = 0x1000_0000_0000_0000;
        /// Shadow copy
        const SHADOW_COPY = 0x2000_0000_0000_0000;
        /// Hidden
        const HIDDEN = 0x4000_0000_0000_0000;
        /// No drive letter
        const NO_DRIVE_LETTER = 0x8000_0000_0000_0000;
    }
}

/// GPT header (parsed from on-disk format)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GptHeader {
    /// Signature "EFI PART"
    pub signature: u64,
    /// Revision
    pub revision: u32,
    /// Header size
    pub header_size: u32,
    /// Header CRC32
    pub header_crc32: u32,
    /// Reserved (must be 0)
    pub reserved: u32,
    /// Current LBA (location of this header)
    pub my_lba: u64,
    /// Alternate LBA (location of backup header)
    pub alternate_lba: u64,
    /// First usable LBA
    pub first_usable_lba: u64,
    /// Last usable LBA
    pub last_usable_lba: u64,
    /// Disk GUID
    pub disk_guid: Guid,
    /// Partition entry LBA
    pub partition_entry_lba: u64,
    /// Number of partition entries
    pub num_partition_entries: u32,
    /// Size of partition entry
    pub partition_entry_size: u32,
    /// Partition entries CRC32
    pub partition_entries_crc32: u32,
}

impl GptHeader {
    /// Parse GPT header from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, FstubError> {
        if data.len() < 92 {
            return Err(FstubError::BufferTooSmall);
        }

        let signature = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        if signature != EFI_SIGNATURE {
            return Err(FstubError::InvalidSignature);
        }

        Ok(Self {
            signature,
            revision: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            header_size: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            header_crc32: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            reserved: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            my_lba: u64::from_le_bytes([
                data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
            ]),
            alternate_lba: u64::from_le_bytes([
                data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
            ]),
            first_usable_lba: u64::from_le_bytes([
                data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47],
            ]),
            last_usable_lba: u64::from_le_bytes([
                data[48], data[49], data[50], data[51], data[52], data[53], data[54], data[55],
            ]),
            disk_guid: Guid::from_bytes(&data[56..72]),
            partition_entry_lba: u64::from_le_bytes([
                data[72], data[73], data[74], data[75], data[76], data[77], data[78], data[79],
            ]),
            num_partition_entries: u32::from_le_bytes([data[80], data[81], data[82], data[83]]),
            partition_entry_size: u32::from_le_bytes([data[84], data[85], data[86], data[87]]),
            partition_entries_crc32: u32::from_le_bytes([data[88], data[89], data[90], data[91]]),
        })
    }

    /// Validate the header
    pub fn validate(&self) -> Result<(), FstubError> {
        if self.signature != EFI_SIGNATURE {
            return Err(FstubError::InvalidSignature);
        }

        if self.header_size < 92 {
            return Err(FstubError::InvalidPartitionTable);
        }

        if self.partition_entry_size < 128 {
            return Err(FstubError::InvalidPartitionTable);
        }

        Ok(())
    }

    /// Write to bytes
    pub fn to_bytes(&self, data: &mut [u8]) -> Result<(), FstubError> {
        if data.len() < 92 {
            return Err(FstubError::BufferTooSmall);
        }

        data[0..8].copy_from_slice(&self.signature.to_le_bytes());
        data[8..12].copy_from_slice(&self.revision.to_le_bytes());
        data[12..16].copy_from_slice(&self.header_size.to_le_bytes());
        data[16..20].copy_from_slice(&self.header_crc32.to_le_bytes());
        data[20..24].copy_from_slice(&self.reserved.to_le_bytes());
        data[24..32].copy_from_slice(&self.my_lba.to_le_bytes());
        data[32..40].copy_from_slice(&self.alternate_lba.to_le_bytes());
        data[40..48].copy_from_slice(&self.first_usable_lba.to_le_bytes());
        data[48..56].copy_from_slice(&self.last_usable_lba.to_le_bytes());
        self.disk_guid.to_bytes(&mut data[56..72]);
        data[72..80].copy_from_slice(&self.partition_entry_lba.to_le_bytes());
        data[80..84].copy_from_slice(&self.num_partition_entries.to_le_bytes());
        data[84..88].copy_from_slice(&self.partition_entry_size.to_le_bytes());
        data[88..92].copy_from_slice(&self.partition_entries_crc32.to_le_bytes());

        Ok(())
    }
}

/// GPT partition entry (parsed from on-disk format)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GptPartitionEntry {
    /// Partition type GUID
    pub partition_type: Guid,
    /// Unique partition GUID
    pub unique_partition: Guid,
    /// Starting LBA
    pub starting_lba: u64,
    /// Ending LBA
    pub ending_lba: u64,
    /// Attributes
    pub attributes: u64,
    /// Partition name (UTF-16LE, 36 characters)
    pub name: [u16; 36],
}

impl GptPartitionEntry {
    /// Check if this entry is unused
    pub fn is_unused(&self) -> bool {
        self.partition_type == gpt_types::UNUSED
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, FstubError> {
        if data.len() < 128 {
            return Err(FstubError::BufferTooSmall);
        }

        let mut name = [0u16; 36];
        for i in 0..36 {
            name[i] = u16::from_le_bytes([data[56 + i * 2], data[56 + i * 2 + 1]]);
        }

        Ok(Self {
            partition_type: Guid::from_bytes(&data[0..16]),
            unique_partition: Guid::from_bytes(&data[16..32]),
            starting_lba: u64::from_le_bytes([
                data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
            ]),
            ending_lba: u64::from_le_bytes([
                data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47],
            ]),
            attributes: u64::from_le_bytes([
                data[48], data[49], data[50], data[51], data[52], data[53], data[54], data[55],
            ]),
            name,
        })
    }

    /// Get partition name as String
    pub fn get_name(&self) -> String {
        let end = self.name.iter().position(|&c| c == 0).unwrap_or(36);
        String::from_utf16_lossy(&self.name[..end])
    }

    /// Get partition type name
    pub fn get_type_name(&self) -> &'static str {
        if self.partition_type == gpt_types::UNUSED {
            "Unused"
        } else if self.partition_type == gpt_types::EFI_SYSTEM {
            "EFI System"
        } else if self.partition_type == gpt_types::MICROSOFT_RESERVED {
            "Microsoft Reserved"
        } else if self.partition_type == gpt_types::MICROSOFT_BASIC_DATA {
            "Basic Data"
        } else if self.partition_type == gpt_types::MICROSOFT_LDM_METADATA {
            "LDM Metadata"
        } else if self.partition_type == gpt_types::MICROSOFT_LDM_DATA {
            "LDM Data"
        } else if self.partition_type == gpt_types::MICROSOFT_RECOVERY {
            "Recovery"
        } else if self.partition_type == gpt_types::LINUX_FILESYSTEM {
            "Linux"
        } else if self.partition_type == gpt_types::LINUX_SWAP {
            "Linux Swap"
        } else if self.partition_type == gpt_types::LINUX_LVM {
            "Linux LVM"
        } else {
            "Unknown"
        }
    }

    /// Write to bytes
    pub fn to_bytes(&self, data: &mut [u8]) -> Result<(), FstubError> {
        if data.len() < 128 {
            return Err(FstubError::BufferTooSmall);
        }

        self.partition_type.to_bytes(&mut data[0..16]);
        self.unique_partition.to_bytes(&mut data[16..32]);
        data[32..40].copy_from_slice(&self.starting_lba.to_le_bytes());
        data[40..48].copy_from_slice(&self.ending_lba.to_le_bytes());
        data[48..56].copy_from_slice(&self.attributes.to_le_bytes());

        for i in 0..36 {
            data[56 + i * 2..56 + i * 2 + 2].copy_from_slice(&self.name[i].to_le_bytes());
        }

        Ok(())
    }
}

/// Read GPT drive layout
pub fn read_gpt_layout(
    disk_data: &[u8],
    disk_size: u64,
    sector_size: u32,
) -> Result<DriveLayout, FstubError> {
    // GPT header is at LBA 1 (after MBR)
    let header_offset = sector_size as usize;
    if disk_data.len() < header_offset + 92 {
        return Err(FstubError::BufferTooSmall);
    }

    let header = GptHeader::from_bytes(&disk_data[header_offset..])?;
    header.validate()?;

    // Read partition entries
    let entries_offset = header.partition_entry_lba as usize * sector_size as usize;
    let entries_size = header.num_partition_entries as usize * header.partition_entry_size as usize;

    if disk_data.len() < entries_offset + entries_size {
        return Err(FstubError::BufferTooSmall);
    }

    let mut partitions = Vec::new();
    let mut partition_number = 1u32;

    for i in 0..header.num_partition_entries as usize {
        let entry_offset = entries_offset + i * header.partition_entry_size as usize;
        let entry = GptPartitionEntry::from_bytes(&disk_data[entry_offset..])?;

        if entry.is_unused() {
            continue;
        }

        let start_offset = entry.starting_lba * sector_size as u64;
        let length = (entry.ending_lba - entry.starting_lba + 1) * sector_size as u64;

        if start_offset >= disk_size || start_offset + length > disk_size {
            continue;
        }

        partitions.push(PartitionInfo {
            style: PartitionStyle::Gpt,
            start_offset,
            length,
            partition_number,
            rewrite_partition: false,
            mbr: None,
            gpt: Some(GptPartitionInfo {
                partition_type: entry.partition_type,
                partition_id: entry.unique_partition,
                attributes: entry.attributes,
                name: entry.get_name(),
            }),
        });

        partition_number += 1;
    }

    let usable_length = (header.last_usable_lba - header.first_usable_lba + 1) * sector_size as u64;

    Ok(DriveLayout {
        style: PartitionStyle::Gpt,
        partition_count: partitions.len() as u32,
        mbr: None,
        gpt: Some(DriveLayoutGpt {
            disk_id: header.disk_guid,
            starting_usable_offset: header.first_usable_lba * sector_size as u64,
            usable_length,
            max_partition_count: header.num_partition_entries,
        }),
        partitions,
    })
}

/// Write GPT drive layout (placeholder - full implementation would be more complex)
pub fn write_gpt_layout(_layout: &DriveLayout, _disk_data: &mut [u8]) -> Result<(), FstubError> {
    // Full GPT write implementation would need to:
    // 1. Write protective MBR
    // 2. Write primary GPT header
    // 3. Write partition entries
    // 4. Calculate CRCs
    // 5. Write backup GPT at end of disk

    // For now, return not implemented
    Err(FstubError::IoError)
}

/// Simple CRC32 calculation (for GPT)
pub fn calculate_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for byte in data {
        let index = ((crc ^ *byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[index];
    }
    !crc
}

/// CRC32 lookup table
static CRC32_TABLE: [u32; 256] = [
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
    0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
    0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
    0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
    0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
    0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
    0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
    0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
    0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
    0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
    0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
    0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
    0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
    0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
    0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
    0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
    0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
    0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
    0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
    0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
    0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD706B3,
    0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
];
