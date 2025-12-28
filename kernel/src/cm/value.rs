//! Registry Value Types
//!
//! Registry values store data associated with registry keys.
//! Each value has a name, type, and data.
//!
//! # Value Types
//! - REG_NONE: No type
//! - REG_SZ: Null-terminated string
//! - REG_EXPAND_SZ: Expandable string (with environment variables)
//! - REG_BINARY: Binary data
//! - REG_DWORD: 32-bit integer (little-endian)
//! - REG_DWORD_BIG_ENDIAN: 32-bit integer (big-endian)
//! - REG_LINK: Symbolic link
//! - REG_MULTI_SZ: Multiple null-terminated strings
//! - REG_QWORD: 64-bit integer

/// Maximum value name length (characters)
pub const MAX_VALUE_NAME_LENGTH: usize = 64;

/// Maximum value data size (bytes)
pub const MAX_VALUE_DATA_SIZE: usize = 256;

/// Registry value types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[derive(Default)]
pub enum RegType {
    /// No type
    #[default]
    None = 0,
    /// Null-terminated string
    Sz = 1,
    /// Expandable string (with %VARIABLE% references)
    ExpandSz = 2,
    /// Binary data
    Binary = 3,
    /// 32-bit little-endian integer
    Dword = 4,
    /// 32-bit big-endian integer
    DwordBigEndian = 5,
    /// Symbolic link (Unicode string)
    Link = 6,
    /// Array of null-terminated strings
    MultiSz = 7,
    /// Resource list
    ResourceList = 8,
    /// Full resource descriptor
    FullResourceDescriptor = 9,
    /// Resource requirements list
    ResourceRequirementsList = 10,
    /// 64-bit little-endian integer
    Qword = 11,
}

impl RegType {
    /// Create from raw value
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Sz),
            2 => Some(Self::ExpandSz),
            3 => Some(Self::Binary),
            4 => Some(Self::Dword),
            5 => Some(Self::DwordBigEndian),
            6 => Some(Self::Link),
            7 => Some(Self::MultiSz),
            8 => Some(Self::ResourceList),
            9 => Some(Self::FullResourceDescriptor),
            10 => Some(Self::ResourceRequirementsList),
            11 => Some(Self::Qword),
            _ => None,
        }
    }

    /// Check if type is a string type
    pub fn is_string(&self) -> bool {
        matches!(self, Self::Sz | Self::ExpandSz | Self::Link)
    }

    /// Check if type is an integer type
    pub fn is_integer(&self) -> bool {
        matches!(self, Self::Dword | Self::DwordBigEndian | Self::Qword)
    }
}


/// Registry value name (fixed-size for static allocation)
#[derive(Clone, Copy)]
pub struct CmValueName {
    /// Name characters (UTF-8)
    pub chars: [u8; MAX_VALUE_NAME_LENGTH],
    /// Name length in bytes
    pub length: u8,
}

impl CmValueName {
    /// Create an empty name
    pub const fn empty() -> Self {
        Self {
            chars: [0; MAX_VALUE_NAME_LENGTH],
            length: 0,
        }
    }

    /// Create from a string slice
    pub fn new_from(s: &str) -> Self {
        let mut name = Self::empty();
        let bytes = s.as_bytes();
        let len = bytes.len().min(MAX_VALUE_NAME_LENGTH);
        name.chars[..len].copy_from_slice(&bytes[..len]);
        name.length = len as u8;
        name
    }

    /// Get as string slice
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.chars[..self.length as usize]).unwrap_or("")
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Compare with string
    pub fn equals(&self, s: &str) -> bool {
        self.as_str() == s
    }

    /// Compare case-insensitive
    pub fn equals_ignore_case(&self, s: &str) -> bool {
        let self_str = self.as_str();
        if self_str.len() != s.len() {
            return false;
        }
        self_str.chars().zip(s.chars()).all(|(a, b)| {
            a.eq_ignore_ascii_case(&b)
        })
    }
}

impl Default for CmValueName {
    fn default() -> Self {
        Self::empty()
    }
}

/// Registry value data (fixed-size for static allocation)
#[derive(Clone, Copy)]
pub struct CmValueData {
    /// Raw data bytes
    pub bytes: [u8; MAX_VALUE_DATA_SIZE],
    /// Data size in bytes
    pub size: u16,
}

impl CmValueData {
    /// Create empty data
    pub const fn empty() -> Self {
        Self {
            bytes: [0; MAX_VALUE_DATA_SIZE],
            size: 0,
        }
    }

    /// Create from bytes
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut value = Self::empty();
        let len = data.len().min(MAX_VALUE_DATA_SIZE);
        value.bytes[..len].copy_from_slice(&data[..len]);
        value.size = len as u16;
        value
    }

    /// Create from string (null-terminated)
    pub fn from_string(s: &str) -> Self {
        let mut value = Self::empty();
        let bytes = s.as_bytes();
        let len = bytes.len().min(MAX_VALUE_DATA_SIZE - 1);
        value.bytes[..len].copy_from_slice(&bytes[..len]);
        value.bytes[len] = 0; // Null terminator
        value.size = (len + 1) as u16;
        value
    }

    /// Create from u32
    pub fn from_dword(v: u32) -> Self {
        let mut value = Self::empty();
        value.bytes[0..4].copy_from_slice(&v.to_le_bytes());
        value.size = 4;
        value
    }

    /// Create from u64
    pub fn from_qword(v: u64) -> Self {
        let mut value = Self::empty();
        value.bytes[0..8].copy_from_slice(&v.to_le_bytes());
        value.size = 8;
        value
    }

    /// Get as string (for REG_SZ)
    pub fn as_string(&self) -> Option<&str> {
        if self.size == 0 {
            return Some("");
        }
        // Find null terminator
        let len = self.bytes[..self.size as usize]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.size as usize);
        core::str::from_utf8(&self.bytes[..len]).ok()
    }

    /// Get as u32 (for REG_DWORD)
    pub fn as_dword(&self) -> Option<u32> {
        if self.size >= 4 {
            Some(u32::from_le_bytes([
                self.bytes[0],
                self.bytes[1],
                self.bytes[2],
                self.bytes[3],
            ]))
        } else {
            None
        }
    }

    /// Get as u64 (for REG_QWORD)
    pub fn as_qword(&self) -> Option<u64> {
        if self.size >= 8 {
            Some(u64::from_le_bytes([
                self.bytes[0],
                self.bytes[1],
                self.bytes[2],
                self.bytes[3],
                self.bytes[4],
                self.bytes[5],
                self.bytes[6],
                self.bytes[7],
            ]))
        } else {
            None
        }
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.size as usize]
    }
}

impl Default for CmValueData {
    fn default() -> Self {
        Self::empty()
    }
}

/// Registry value (name + type + data)
#[derive(Clone, Copy)]
pub struct CmKeyValue {
    /// Value name
    pub name: CmValueName,
    /// Value type
    pub value_type: RegType,
    /// Value data
    pub data: CmValueData,
    /// Flags
    pub flags: u16,
    /// Reserved
    _reserved: u16,
}

impl CmKeyValue {
    /// Create an empty value
    pub const fn empty() -> Self {
        Self {
            name: CmValueName::empty(),
            value_type: RegType::None,
            data: CmValueData::empty(),
            flags: 0,
            _reserved: 0,
        }
    }

    /// Create a new value
    pub fn new(name: &str, value_type: RegType, data: CmValueData) -> Self {
        Self {
            name: CmValueName::new_from(name),
            value_type,
            data,
            flags: 0,
            _reserved: 0,
        }
    }

    /// Create a string value
    pub fn new_string(name: &str, value: &str) -> Self {
        Self::new(name, RegType::Sz, CmValueData::from_string(value))
    }

    /// Create a DWORD value
    pub fn new_dword(name: &str, value: u32) -> Self {
        Self::new(name, RegType::Dword, CmValueData::from_dword(value))
    }

    /// Create a QWORD value
    pub fn new_qword(name: &str, value: u64) -> Self {
        Self::new(name, RegType::Qword, CmValueData::from_qword(value))
    }

    /// Create a binary value
    pub fn new_binary(name: &str, data: &[u8]) -> Self {
        Self::new(name, RegType::Binary, CmValueData::from_bytes(data))
    }

    /// Check if value is in use
    pub fn is_valid(&self) -> bool {
        !self.name.is_empty()
    }

    /// Clear the value
    pub fn clear(&mut self) {
        *self = Self::empty();
    }

    /// Get string value
    pub fn get_string(&self) -> Option<&str> {
        if self.value_type.is_string() {
            self.data.as_string()
        } else {
            None
        }
    }

    /// Get DWORD value
    pub fn get_dword(&self) -> Option<u32> {
        if self.value_type == RegType::Dword {
            self.data.as_dword()
        } else {
            None
        }
    }

    /// Get QWORD value
    pub fn get_qword(&self) -> Option<u64> {
        if self.value_type == RegType::Qword {
            self.data.as_qword()
        } else {
            None
        }
    }
}

impl Default for CmKeyValue {
    fn default() -> Self {
        Self::empty()
    }
}

/// Value flags
pub mod value_flags {
    /// Value is volatile (not persisted)
    pub const VALUE_VOLATILE: u16 = 0x0001;
    /// Value was created by system
    pub const VALUE_SYSTEM: u16 = 0x0002;
}

/// Initialize value subsystem
pub fn init() {
    crate::serial_println!("[CM] Value subsystem initialized");
}
