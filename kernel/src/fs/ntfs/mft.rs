//! NTFS Master File Table (MFT)
//!
//! The MFT is the heart of NTFS, containing an entry (file record) for every
//! file and directory on the volume. The first 16 entries are reserved for
//! system files.
//!
//! # MFT Entry Structure
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────────┐
//! │                    File Record Header (42 bytes)                      │
//! │  - Signature "FILE"                                                   │
//! │  - Fixup array offset/count                                          │
//! │  - Sequence number                                                    │
//! │  - Flags (in use, directory)                                         │
//! │  - First attribute offset                                            │
//! └──────────────────────────────────────────────────────────────────────┘
//!                               │
//!                               ▼
//! ┌──────────────────────────────────────────────────────────────────────┐
//! │                    Attribute 1 (e.g., $STANDARD_INFORMATION)          │
//! ├──────────────────────────────────────────────────────────────────────┤
//! │                    Attribute 2 (e.g., $FILE_NAME)                     │
//! ├──────────────────────────────────────────────────────────────────────┤
//! │                    Attribute 3 (e.g., $DATA)                          │
//! ├──────────────────────────────────────────────────────────────────────┤
//! │                    ... more attributes ...                            │
//! ├──────────────────────────────────────────────────────────────────────┤
//! │                    End marker (0xFFFFFFFF)                           │
//! └──────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Well-Known MFT Entries
//!
//! | Index | Name       | Description                      |
//! |-------|------------|----------------------------------|
//! | 0     | $MFT       | Master File Table itself         |
//! | 1     | $MFTMirr   | MFT mirror (first 4 entries)     |
//! | 2     | $LogFile   | Transaction log                  |
//! | 3     | $Volume    | Volume information               |
//! | 4     | $AttrDef   | Attribute definitions            |
//! | 5     | .          | Root directory                   |
//! | 6     | $Bitmap    | Cluster allocation bitmap        |
//! | 7     | $Boot      | Boot sector                      |
//! | 8     | $BadClus   | Bad cluster list                 |
//! | 9     | $Secure    | Security descriptors             |
//! | 10    | $UpCase    | Uppercase table                  |
//! | 11    | $Extend    | Extended metadata directory      |


/// File record magic signature "FILE"
pub const FILE_RECORD_MAGIC: u32 = 0x454C4946; // "FILE" in little-endian

/// Bad file record magic "BAAD"
pub const BAAD_RECORD_MAGIC: u32 = 0x44414142; // "BAAD" in little-endian

/// End of attributes marker
pub const END_OF_ATTRIBUTES: u32 = 0xFFFFFFFF;

/// File record flags
pub const MFT_RECORD_IN_USE: u16 = 0x0001;
pub const MFT_RECORD_IS_DIRECTORY: u16 = 0x0002;
pub const MFT_RECORD_IS_EXTENSION: u16 = 0x0004;
pub const MFT_RECORD_HAS_SPECIAL_INDEX: u16 = 0x0008;

/// Well-known MFT entry indices
pub mod well_known_mft {
    /// $MFT - Master File Table
    pub const MFT: u64 = 0;
    /// $MFTMirr - MFT mirror
    pub const MFT_MIRR: u64 = 1;
    /// $LogFile - Transaction log
    pub const LOG_FILE: u64 = 2;
    /// $Volume - Volume information
    pub const VOLUME: u64 = 3;
    /// $AttrDef - Attribute definitions
    pub const ATTR_DEF: u64 = 4;
    /// Root directory (.)
    pub const ROOT_DIR: u64 = 5;
    /// $Bitmap - Cluster allocation bitmap
    pub const BITMAP: u64 = 6;
    /// $Boot - Boot sector
    pub const BOOT: u64 = 7;
    /// $BadClus - Bad cluster list
    pub const BAD_CLUS: u64 = 8;
    /// $Secure - Security descriptors
    pub const SECURE: u64 = 9;
    /// $UpCase - Uppercase table
    pub const UPCASE: u64 = 10;
    /// $Extend - Extended metadata directory
    pub const EXTEND: u64 = 11;
    /// First user file (after reserved entries)
    pub const FIRST_USER_FILE: u64 = 24;
}

/// MFT Reference (48-bit file number + 16-bit sequence number)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MftRef {
    /// Low 32 bits of file number
    pub file_number_low: u32,
    /// High 16 bits of file number
    pub file_number_high: u16,
    /// Sequence number (increments on file deletion/reuse)
    pub sequence_number: u16,
}

impl MftRef {
    /// Create a new MFT reference
    pub const fn new(file_number: u64, sequence: u16) -> Self {
        Self {
            file_number_low: file_number as u32,
            file_number_high: (file_number >> 32) as u16,
            sequence_number: sequence,
        }
    }

    /// Get the file number
    pub fn file_number(&self) -> u64 {
        (self.file_number_high as u64) << 32 | self.file_number_low as u64
    }

    /// Create from raw 64-bit value
    pub fn from_u64(val: u64) -> Self {
        Self {
            file_number_low: val as u32,
            file_number_high: (val >> 32) as u16,
            sequence_number: (val >> 48) as u16,
        }
    }

    /// Convert to raw 64-bit value
    pub fn to_u64(&self) -> u64 {
        self.file_number_low as u64
            | (self.file_number_high as u64) << 32
            | (self.sequence_number as u64) << 48
    }

    /// Check if this is a valid reference (not empty)
    pub fn is_valid(&self) -> bool {
        self.file_number_low != 0 || self.file_number_high != 0
    }
}

/// File record header (beginning of every MFT entry)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct FileRecordHeader {
    /// Magic signature ("FILE" or "BAAD")
    pub magic: u32,
    /// Offset to fixup array
    pub fixup_offset: u16,
    /// Number of fixup entries
    pub fixup_count: u16,
    /// $LogFile sequence number (LSN)
    pub lsn: u64,
    /// Sequence number
    pub sequence_number: u16,
    /// Hard link count
    pub hard_link_count: u16,
    /// Offset to first attribute
    pub first_attribute_offset: u16,
    /// Flags (in use, directory, etc.)
    pub flags: u16,
    /// Real size of file record
    pub used_size: u32,
    /// Allocated size of file record
    pub allocated_size: u32,
    /// Base file record (0 if this is the base)
    pub base_record: MftRef,
    /// Next attribute ID
    pub next_attribute_id: u16,
    /// Padding (XP+)
    pub padding: u16,
    /// MFT record number (XP+)
    pub mft_record_number: u32,
}

impl FileRecordHeader {
    /// Check if this record has valid magic
    pub fn is_valid(&self) -> bool {
        self.magic == FILE_RECORD_MAGIC
    }

    /// Check if record is in use
    pub fn is_in_use(&self) -> bool {
        (self.flags & MFT_RECORD_IN_USE) != 0
    }

    /// Check if record is a directory
    pub fn is_directory(&self) -> bool {
        (self.flags & MFT_RECORD_IS_DIRECTORY) != 0
    }

    /// Check if this is a base record
    pub fn is_base_record(&self) -> bool {
        !self.base_record.is_valid()
    }
}

/// Maximum file record size (typically 1KB or 4KB)
pub const MAX_FILE_RECORD_SIZE: usize = 4096;

/// Default file record size
pub const DEFAULT_FILE_RECORD_SIZE: usize = 1024;

/// File record (MFT entry) wrapper
pub struct FileRecord {
    /// Raw data buffer
    data: [u8; MAX_FILE_RECORD_SIZE],
    /// Actual size of this record
    size: usize,
    /// Whether the record has been fixed up
    fixed_up: bool,
}

impl FileRecord {
    /// Create an empty file record
    pub const fn empty() -> Self {
        Self {
            data: [0; MAX_FILE_RECORD_SIZE],
            size: DEFAULT_FILE_RECORD_SIZE,
            fixed_up: false,
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(data: &[u8], record_size: usize) -> Option<Self> {
        if data.len() < record_size || record_size > MAX_FILE_RECORD_SIZE {
            return None;
        }

        let mut record = Self::empty();
        record.data[..record_size].copy_from_slice(&data[..record_size]);
        record.size = record_size;
        record.fixed_up = false;

        // Validate magic
        if !record.header().is_valid() {
            return None;
        }

        Some(record)
    }

    /// Get the file record header
    pub fn header(&self) -> &FileRecordHeader {
        unsafe {
            &*(self.data.as_ptr() as *const FileRecordHeader)
        }
    }

    /// Get raw data
    pub fn data(&self) -> &[u8] {
        &self.data[..self.size]
    }

    /// Apply fixup array to repair sector boundaries
    ///
    /// NTFS stores a fixup array that must be applied to repair
    /// the last two bytes of each sector (which were replaced with
    /// a signature for integrity checking).
    pub fn apply_fixup(&mut self) -> bool {
        if self.fixed_up {
            return true;
        }

        let header = self.header();
        let fixup_offset = header.fixup_offset as usize;
        let fixup_count = header.fixup_count as usize;

        if fixup_count < 2 || fixup_offset + fixup_count * 2 > self.size {
            return false;
        }

        // Read signature (first entry in fixup array)
        let signature = u16::from_le_bytes([
            self.data[fixup_offset],
            self.data[fixup_offset + 1],
        ]);

        // Apply fixups (one per sector, starting from entry 1)
        let bytes_per_sector = 512;
        for i in 1..fixup_count {
            let sector_end = i * bytes_per_sector - 2;
            if sector_end >= self.size {
                break;
            }

            // Verify signature
            let sector_sig = u16::from_le_bytes([
                self.data[sector_end],
                self.data[sector_end + 1],
            ]);
            if sector_sig != signature {
                return false;
            }

            // Replace with original bytes from fixup array
            let fixup_entry = fixup_offset + i * 2;
            self.data[sector_end] = self.data[fixup_entry];
            self.data[sector_end + 1] = self.data[fixup_entry + 1];
        }

        self.fixed_up = true;
        true
    }

    /// Get offset to first attribute
    pub fn first_attribute_offset(&self) -> usize {
        self.header().first_attribute_offset as usize
    }

    /// Check if record is in use
    pub fn is_in_use(&self) -> bool {
        self.header().is_in_use()
    }

    /// Check if record is a directory
    pub fn is_directory(&self) -> bool {
        self.header().is_directory()
    }

    /// Get MFT record number
    pub fn record_number(&self) -> u64 {
        self.header().mft_record_number as u64
    }

    /// Get sequence number
    pub fn sequence_number(&self) -> u16 {
        self.header().sequence_number
    }
}

impl Clone for FileRecord {
    fn clone(&self) -> Self {
        let mut record = Self::empty();
        record.data[..self.size].copy_from_slice(&self.data[..self.size]);
        record.size = self.size;
        record.fixed_up = self.fixed_up;
        record
    }
}

/// MFT statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct MftStats {
    /// Total records in MFT
    pub total_records: u64,
    /// Records in use
    pub in_use_records: u64,
    /// Directory records
    pub directory_records: u64,
    /// File records
    pub file_records: u64,
}

/// Initialize MFT module
pub fn init() {
    crate::serial_println!("[FS] NTFS MFT parser initialized");
}

/// Get well-known MFT entry name
pub fn mft_entry_name(index: u64) -> &'static str {
    match index {
        well_known_mft::MFT => "$MFT",
        well_known_mft::MFT_MIRR => "$MFTMirr",
        well_known_mft::LOG_FILE => "$LogFile",
        well_known_mft::VOLUME => "$Volume",
        well_known_mft::ATTR_DEF => "$AttrDef",
        well_known_mft::ROOT_DIR => ".",
        well_known_mft::BITMAP => "$Bitmap",
        well_known_mft::BOOT => "$Boot",
        well_known_mft::BAD_CLUS => "$BadClus",
        well_known_mft::SECURE => "$Secure",
        well_known_mft::UPCASE => "$UpCase",
        well_known_mft::EXTEND => "$Extend",
        _ => "<file>",
    }
}
