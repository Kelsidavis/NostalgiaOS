//! NTFS Attributes
//!
//! Every file in NTFS is represented by a set of attributes stored in the MFT.
//! Each attribute has a type, name (optional), and data (resident or non-resident).
//!
//! # Attribute Types
//!
//! | Type   | Name                      | Description                    |
//! |--------|---------------------------|--------------------------------|
//! | 0x10   | $STANDARD_INFORMATION     | Timestamps, flags              |
//! | 0x20   | $ATTRIBUTE_LIST           | List of attribute locations    |
//! | 0x30   | $FILE_NAME                | File name (8.3 and long)       |
//! | 0x40   | $OBJECT_ID                | Object identifier              |
//! | 0x50   | $SECURITY_DESCRIPTOR      | Security information           |
//! | 0x60   | $VOLUME_NAME              | Volume label                   |
//! | 0x70   | $VOLUME_INFORMATION       | Volume version                 |
//! | 0x80   | $DATA                     | File contents                  |
//! | 0x90   | $INDEX_ROOT               | Index root for directories     |
//! | 0xA0   | $INDEX_ALLOCATION         | Index allocation for dirs      |
//! | 0xB0   | $BITMAP                   | Bitmap for indexes/MFT         |
//! | 0xC0   | $REPARSE_POINT            | Reparse point data             |
//! | 0xD0   | $EA_INFORMATION           | Extended attributes info       |
//! | 0xE0   | $EA                       | Extended attributes            |
//! | 0x100  | $LOGGED_UTILITY_STREAM    | Logged stream                  |
//!
//! # Attribute Structure
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                 Attribute Header (common to all)                     │
//! │  - Type (4 bytes)                                                    │
//! │  - Record length (4 bytes)                                          │
//! │  - Non-resident flag (1 byte)                                       │
//! │  - Name length/offset (for named attributes)                        │
//! │  - Flags (compressed, encrypted, sparse)                            │
//! │  - Instance (unique within file record)                             │
//! └─────────────────────────────────────────────────────────────────────┘
//!                              │
//!          ┌───────────────────┴───────────────────┐
//!          ▼                                       ▼
//! ┌─────────────────────┐              ┌─────────────────────┐
//! │  Resident Data       │              │  Non-Resident Data   │
//! │  - Data length       │              │  - VCN range         │
//! │  - Data offset       │              │  - Data runs         │
//! │  - Indexed flag      │              │  - Actual/alloc size │
//! │  - Data bytes inline │              │  - Compression unit  │
//! └─────────────────────┘              └─────────────────────┘
//! ```


/// Attribute type codes
pub mod attr_types {
    /// Standard timestamps, flags, etc.
    pub const STANDARD_INFORMATION: u32 = 0x10;
    /// List of attributes when they don't fit in one record
    pub const ATTRIBUTE_LIST: u32 = 0x20;
    /// File name (one or more per file)
    pub const FILE_NAME: u32 = 0x30;
    /// Object identifier (GUID)
    pub const OBJECT_ID: u32 = 0x40;
    /// Security descriptor
    pub const SECURITY_DESCRIPTOR: u32 = 0x50;
    /// Volume name (label)
    pub const VOLUME_NAME: u32 = 0x60;
    /// Volume information
    pub const VOLUME_INFORMATION: u32 = 0x70;
    /// File data stream
    pub const DATA: u32 = 0x80;
    /// Directory index root
    pub const INDEX_ROOT: u32 = 0x90;
    /// Directory index allocation
    pub const INDEX_ALLOCATION: u32 = 0xA0;
    /// Bitmap for index or MFT
    pub const BITMAP: u32 = 0xB0;
    /// Reparse point
    pub const REPARSE_POINT: u32 = 0xC0;
    /// EA information
    pub const EA_INFORMATION: u32 = 0xD0;
    /// Extended attributes
    pub const EA: u32 = 0xE0;
    /// Logged utility stream
    pub const LOGGED_UTILITY_STREAM: u32 = 0x100;
    /// End of attributes marker
    pub const END: u32 = 0xFFFFFFFF;
}

/// File name namespace types
pub mod file_name_types {
    /// POSIX (case-sensitive, allows any Unicode)
    pub const POSIX: u8 = 0;
    /// Win32 (case-insensitive, restricted chars)
    pub const WIN32: u8 = 1;
    /// DOS 8.3 name
    pub const DOS: u8 = 2;
    /// Win32 and DOS (when name fits 8.3)
    pub const WIN32_AND_DOS: u8 = 3;
}

/// Attribute flags
pub mod attr_flags {
    /// Attribute is compressed
    pub const COMPRESSED: u16 = 0x0001;
    /// Attribute is encrypted
    pub const ENCRYPTED: u16 = 0x4000;
    /// Attribute is sparse
    pub const SPARSE: u16 = 0x8000;
}

/// File attribute flags (from $STANDARD_INFORMATION)
pub mod file_flags {
    pub const READONLY: u32 = 0x0001;
    pub const HIDDEN: u32 = 0x0002;
    pub const SYSTEM: u32 = 0x0004;
    pub const ARCHIVE: u32 = 0x0020;
    pub const DEVICE: u32 = 0x0040;
    pub const NORMAL: u32 = 0x0080;
    pub const TEMPORARY: u32 = 0x0100;
    pub const SPARSE_FILE: u32 = 0x0200;
    pub const REPARSE_POINT: u32 = 0x0400;
    pub const COMPRESSED: u32 = 0x0800;
    pub const OFFLINE: u32 = 0x1000;
    pub const NOT_CONTENT_INDEXED: u32 = 0x2000;
    pub const ENCRYPTED: u32 = 0x4000;
    pub const DIRECTORY: u32 = 0x10000000;
}

/// Common attribute header (first 16 bytes of every attribute)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct AttributeHeader {
    /// Attribute type code
    pub attr_type: u32,
    /// Total length of attribute (including header)
    pub length: u32,
    /// Non-resident flag (0 = resident, 1 = non-resident)
    pub non_resident: u8,
    /// Attribute name length (in characters)
    pub name_length: u8,
    /// Offset to attribute name
    pub name_offset: u16,
    /// Attribute flags (compressed, encrypted, sparse)
    pub flags: u16,
    /// Attribute instance (unique within file record)
    pub instance: u16,
}

impl AttributeHeader {
    /// Check if this is a valid attribute (not end marker)
    pub fn is_valid(&self) -> bool {
        self.attr_type != attr_types::END && self.length > 0
    }

    /// Check if attribute is resident
    pub fn is_resident(&self) -> bool {
        self.non_resident == 0
    }

    /// Check if attribute is non-resident
    pub fn is_non_resident(&self) -> bool {
        self.non_resident != 0
    }

    /// Check if attribute is compressed
    pub fn is_compressed(&self) -> bool {
        (self.flags & attr_flags::COMPRESSED) != 0
    }

    /// Check if attribute is encrypted
    pub fn is_encrypted(&self) -> bool {
        (self.flags & attr_flags::ENCRYPTED) != 0
    }

    /// Check if attribute is sparse
    pub fn is_sparse(&self) -> bool {
        (self.flags & attr_flags::SPARSE) != 0
    }

    /// Check if attribute has a name
    pub fn has_name(&self) -> bool {
        self.name_length > 0
    }
}

/// Resident attribute header (follows common header)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ResidentHeader {
    /// Common header
    pub common: AttributeHeader,
    /// Length of attribute value
    pub value_length: u32,
    /// Offset to attribute value
    pub value_offset: u16,
    /// Indexed flag
    pub indexed: u8,
    /// Padding
    pub padding: u8,
}

impl ResidentHeader {
    /// Get offset to data value
    pub fn data_offset(&self) -> usize {
        self.value_offset as usize
    }

    /// Get data length
    pub fn data_length(&self) -> usize {
        self.value_length as usize
    }
}

/// Non-resident attribute header (follows common header)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct NonResidentHeader {
    /// Common header
    pub common: AttributeHeader,
    /// Starting Virtual Cluster Number (VCN)
    pub start_vcn: u64,
    /// Ending VCN
    pub end_vcn: u64,
    /// Offset to data runs
    pub data_runs_offset: u16,
    /// Compression unit size (log2, 0 = uncompressed)
    pub compression_unit: u16,
    /// Padding
    pub padding: u32,
    /// Allocated size (on disk, cluster-aligned)
    pub allocated_size: u64,
    /// Actual data size
    pub data_size: u64,
    /// Initialized data size
    pub initialized_size: u64,
}

impl NonResidentHeader {
    /// Get offset to data runs
    pub fn data_runs_offset(&self) -> usize {
        self.data_runs_offset as usize
    }

    /// Get actual data size
    pub fn size(&self) -> u64 {
        self.data_size
    }

    /// Check if data is compressed
    pub fn is_compressed(&self) -> bool {
        self.compression_unit != 0
    }
}

/// $STANDARD_INFORMATION attribute
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct StandardInformation {
    /// File creation time (100-ns since 1601)
    pub creation_time: u64,
    /// File modification time
    pub modification_time: u64,
    /// MFT modification time
    pub mft_modification_time: u64,
    /// File access time
    pub access_time: u64,
    /// File attributes (flags)
    pub file_attributes: u32,
    /// Maximum versions (0 = disabled)
    pub max_versions: u32,
    /// Version number
    pub version: u32,
    /// Class ID
    pub class_id: u32,
    // NTFS 3.0+ fields:
    /// Owner ID
    pub owner_id: u32,
    /// Security ID (index into $Secure)
    pub security_id: u32,
    /// Quota charged
    pub quota_charged: u64,
    /// Update Sequence Number (USN)
    pub usn: u64,
}

impl StandardInformation {
    /// Check if file is read-only
    pub fn is_readonly(&self) -> bool {
        (self.file_attributes & file_flags::READONLY) != 0
    }

    /// Check if file is hidden
    pub fn is_hidden(&self) -> bool {
        (self.file_attributes & file_flags::HIDDEN) != 0
    }

    /// Check if file is a system file
    pub fn is_system(&self) -> bool {
        (self.file_attributes & file_flags::SYSTEM) != 0
    }

    /// Check if file is a directory
    pub fn is_directory(&self) -> bool {
        (self.file_attributes & file_flags::DIRECTORY) != 0
    }
}

/// Maximum file name length in NTFS
pub const MAX_FILE_NAME_LENGTH: usize = 255;

/// $FILE_NAME attribute (variable length)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct FileName {
    /// Parent directory MFT reference
    pub parent_ref: super::mft::MftRef,
    /// File creation time
    pub creation_time: u64,
    /// File modification time
    pub modification_time: u64,
    /// MFT modification time
    pub mft_modification_time: u64,
    /// File access time
    pub access_time: u64,
    /// Allocated size (for directories: size of index)
    pub allocated_size: u64,
    /// Real file size
    pub data_size: u64,
    /// File attributes
    pub file_attributes: u32,
    /// Reparse point tag (if reparse point)
    pub reparse_tag: u32,
    /// File name length (in characters)
    pub name_length: u8,
    /// File name type (POSIX, Win32, DOS, Win32_and_DOS)
    pub name_type: u8,
    // File name follows (UTF-16LE, variable length)
}

impl FileName {
    /// Get name type as string
    pub fn name_type_str(&self) -> &'static str {
        match self.name_type {
            file_name_types::POSIX => "POSIX",
            file_name_types::WIN32 => "Win32",
            file_name_types::DOS => "DOS",
            file_name_types::WIN32_AND_DOS => "Win32+DOS",
            _ => "Unknown",
        }
    }

    /// Check if this is a DOS 8.3 name
    pub fn is_dos_name(&self) -> bool {
        self.name_type == file_name_types::DOS
    }

    /// Check if this is a Win32 long name
    pub fn is_win32_name(&self) -> bool {
        self.name_type == file_name_types::WIN32 || self.name_type == file_name_types::WIN32_AND_DOS
    }
}

/// Data run (describes extent of clusters for non-resident data)
#[derive(Clone, Copy, Debug)]
pub struct DataRun {
    /// Starting Logical Cluster Number (LCN)
    pub lcn: i64,
    /// Number of clusters in this run
    pub length: u64,
    /// Is this a sparse run (hole)?
    pub is_sparse: bool,
}

impl DataRun {
    /// Create a new data run
    pub const fn new(lcn: i64, length: u64) -> Self {
        Self {
            lcn,
            length,
            is_sparse: lcn == 0,
        }
    }

    /// Create a sparse run (hole)
    pub const fn sparse(length: u64) -> Self {
        Self {
            lcn: 0,
            length,
            is_sparse: true,
        }
    }
}

/// Maximum number of data runs per attribute
pub const MAX_DATA_RUNS: usize = 64;

/// Data run list
pub struct DataRunList {
    /// Runs
    runs: [DataRun; MAX_DATA_RUNS],
    /// Number of valid runs
    count: usize,
    /// Total clusters
    total_clusters: u64,
}

impl DataRunList {
    /// Create an empty run list
    pub const fn empty() -> Self {
        Self {
            runs: [DataRun::new(0, 0); MAX_DATA_RUNS],
            count: 0,
            total_clusters: 0,
        }
    }

    /// Parse data runs from raw bytes
    ///
    /// Data run format:
    /// - First byte: length_size (low 4 bits) | offset_size (high 4 bits)
    /// - Length bytes (variable, little-endian)
    /// - Offset bytes (variable, little-endian, signed delta)
    pub fn parse(data: &[u8]) -> Option<Self> {
        let mut list = Self::empty();
        let mut pos = 0;
        let mut current_lcn: i64 = 0;

        while pos < data.len() && list.count < MAX_DATA_RUNS {
            let header = data[pos];
            if header == 0 {
                break; // End of runs
            }

            let length_size = (header & 0x0F) as usize;
            let offset_size = ((header >> 4) & 0x0F) as usize;
            pos += 1;

            if pos + length_size + offset_size > data.len() {
                break; // Incomplete run
            }

            // Read length (unsigned)
            let mut length: u64 = 0;
            for i in 0..length_size {
                length |= (data[pos + i] as u64) << (i * 8);
            }
            pos += length_size;

            // Read offset (signed delta)
            let mut offset: i64 = 0;
            if offset_size > 0 {
                for i in 0..offset_size {
                    offset |= (data[pos + i] as i64) << (i * 8);
                }
                // Sign extend
                let sign_bit = 1i64 << (offset_size * 8 - 1);
                if offset & sign_bit != 0 {
                    offset |= !((1i64 << (offset_size * 8)) - 1);
                }
                pos += offset_size;
                current_lcn += offset;
            }

            // Add run
            if offset_size == 0 {
                // Sparse run
                list.runs[list.count] = DataRun::sparse(length);
            } else {
                list.runs[list.count] = DataRun::new(current_lcn, length);
            }
            list.total_clusters += length;
            list.count += 1;
        }

        Some(list)
    }

    /// Get number of runs
    pub fn count(&self) -> usize {
        self.count
    }

    /// Get total clusters
    pub fn total_clusters(&self) -> u64 {
        self.total_clusters
    }

    /// Get a run by index
    pub fn get(&self, index: usize) -> Option<&DataRun> {
        if index < self.count {
            Some(&self.runs[index])
        } else {
            None
        }
    }

    /// Iterate over runs
    pub fn iter(&self) -> impl Iterator<Item = &DataRun> {
        self.runs[..self.count].iter()
    }

    /// Find the run containing a given VCN
    pub fn find_vcn(&self, vcn: u64) -> Option<(usize, &DataRun, u64)> {
        let mut current_vcn = 0u64;
        for (i, run) in self.runs[..self.count].iter().enumerate() {
            if vcn >= current_vcn && vcn < current_vcn + run.length {
                let offset_in_run = vcn - current_vcn;
                return Some((i, run, offset_in_run));
            }
            current_vcn += run.length;
        }
        None
    }
}

/// Attribute type info
#[derive(Clone, Copy)]
pub struct AttributeType {
    pub type_code: u32,
    pub name: &'static str,
}

/// Get attribute type name
pub fn attr_type_name(type_code: u32) -> &'static str {
    match type_code {
        attr_types::STANDARD_INFORMATION => "$STANDARD_INFORMATION",
        attr_types::ATTRIBUTE_LIST => "$ATTRIBUTE_LIST",
        attr_types::FILE_NAME => "$FILE_NAME",
        attr_types::OBJECT_ID => "$OBJECT_ID",
        attr_types::SECURITY_DESCRIPTOR => "$SECURITY_DESCRIPTOR",
        attr_types::VOLUME_NAME => "$VOLUME_NAME",
        attr_types::VOLUME_INFORMATION => "$VOLUME_INFORMATION",
        attr_types::DATA => "$DATA",
        attr_types::INDEX_ROOT => "$INDEX_ROOT",
        attr_types::INDEX_ALLOCATION => "$INDEX_ALLOCATION",
        attr_types::BITMAP => "$BITMAP",
        attr_types::REPARSE_POINT => "$REPARSE_POINT",
        attr_types::EA_INFORMATION => "$EA_INFORMATION",
        attr_types::EA => "$EA",
        attr_types::LOGGED_UTILITY_STREAM => "$LOGGED_UTILITY_STREAM",
        _ => "<unknown>",
    }
}

/// Initialize attribute module
pub fn init() {
    crate::serial_println!("[FS] NTFS attribute parser initialized");
}
