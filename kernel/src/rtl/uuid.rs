//! UUID/GUID Generation and Utilities
//!
//! RFC 4122 - A Universally Unique IDentifier (UUID) URN Namespace
//! Implements UUID generation and formatting compatible with Windows GUIDs.

use super::random::{kernel_random, kernel_random_bytes};

/// UUID/GUID structure (128 bits)
/// Compatible with Windows GUID and RFC 4122 UUID
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Uuid {
    /// First 32 bits (time_low)
    pub data1: u32,
    /// Next 16 bits (time_mid)
    pub data2: u16,
    /// Next 16 bits (time_hi_and_version)
    pub data3: u16,
    /// Final 64 bits (clock_seq_hi_and_reserved, clock_seq_low, node)
    pub data4: [u8; 8],
}

impl Uuid {
    /// Create a new UUID from components
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self { data1, data2, data3, data4 }
    }

    /// Create a nil (all zeros) UUID
    pub const fn nil() -> Self {
        Self {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        }
    }

    /// Check if this is a nil UUID
    pub fn is_nil(&self) -> bool {
        self.data1 == 0 && self.data2 == 0 && self.data3 == 0 &&
        self.data4 == [0; 8]
    }

    /// Create a UUID from raw bytes (16 bytes)
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self {
            data1: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            data2: u16::from_be_bytes([bytes[4], bytes[5]]),
            data3: u16::from_be_bytes([bytes[6], bytes[7]]),
            data4: [
                bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15],
            ],
        }
    }

    /// Create a UUID from little-endian bytes (Windows GUID format)
    pub fn from_bytes_le(bytes: [u8; 16]) -> Self {
        Self {
            data1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            data2: u16::from_le_bytes([bytes[4], bytes[5]]),
            data3: u16::from_le_bytes([bytes[6], bytes[7]]),
            data4: [
                bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15],
            ],
        }
    }

    /// Convert to raw bytes (big-endian, RFC 4122 format)
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&self.data1.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.data2.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.data3.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.data4);
        bytes
    }

    /// Convert to bytes (little-endian, Windows GUID format)
    pub fn to_bytes_le(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&self.data1.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.data2.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.data3.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.data4);
        bytes
    }

    /// Get the UUID version (4 bits from data3)
    pub fn version(&self) -> u8 {
        ((self.data3 >> 12) & 0x0F) as u8
    }

    /// Get the UUID variant
    pub fn variant(&self) -> UuidVariant {
        let byte = self.data4[0];
        if byte & 0x80 == 0 {
            UuidVariant::Ncs
        } else if byte & 0xC0 == 0x80 {
            UuidVariant::Rfc4122
        } else if byte & 0xE0 == 0xC0 {
            UuidVariant::Microsoft
        } else {
            UuidVariant::Future
        }
    }

    /// Generate a version 4 (random) UUID
    pub fn new_v4() -> Self {
        let mut bytes = [0u8; 16];
        kernel_random_bytes(&mut bytes);

        // Set version to 4
        bytes[6] = (bytes[6] & 0x0F) | 0x40;

        // Set variant to RFC 4122
        bytes[8] = (bytes[8] & 0x3F) | 0x80;

        Self::from_bytes(bytes)
    }

    /// Generate a version 1 (time-based) UUID
    /// Uses current tick count as time and random node ID
    pub fn new_v1() -> Self {
        // Get time (100-ns intervals since Oct 15, 1582)
        // For simplicity, use tick count as pseudo-time
        let time = crate::hal::apic::get_tick_count();

        // Get clock sequence (random)
        let clock_seq = (kernel_random() & 0x3FFF) as u16;

        // Generate random node ID (48 bits)
        let mut node = [0u8; 6];
        kernel_random_bytes(&mut node);
        // Set multicast bit to indicate random node
        node[0] |= 0x01;

        let time_low = (time & 0xFFFFFFFF) as u32;
        let time_mid = ((time >> 32) & 0xFFFF) as u16;
        let time_hi = ((time >> 48) & 0x0FFF) as u16 | 0x1000; // Version 1

        let clock_seq_hi = ((clock_seq >> 8) & 0x3F) as u8 | 0x80; // Variant
        let clock_seq_low = (clock_seq & 0xFF) as u8;

        Self {
            data1: time_low,
            data2: time_mid,
            data3: time_hi,
            data4: [
                clock_seq_hi, clock_seq_low,
                node[0], node[1], node[2], node[3], node[4], node[5],
            ],
        }
    }

    /// Format UUID as string: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    pub fn format(&self, buf: &mut [u8; 36]) {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let bytes = self.to_bytes();

        // Format: 8-4-4-4-12
        let mut pos = 0;

        // First 4 bytes (8 hex chars)
        for i in 0..4 {
            buf[pos] = HEX[(bytes[i] >> 4) as usize];
            buf[pos + 1] = HEX[(bytes[i] & 0xF) as usize];
            pos += 2;
        }
        buf[pos] = b'-';
        pos += 1;

        // Next 2 bytes (4 hex chars)
        for i in 4..6 {
            buf[pos] = HEX[(bytes[i] >> 4) as usize];
            buf[pos + 1] = HEX[(bytes[i] & 0xF) as usize];
            pos += 2;
        }
        buf[pos] = b'-';
        pos += 1;

        // Next 2 bytes (4 hex chars)
        for i in 6..8 {
            buf[pos] = HEX[(bytes[i] >> 4) as usize];
            buf[pos + 1] = HEX[(bytes[i] & 0xF) as usize];
            pos += 2;
        }
        buf[pos] = b'-';
        pos += 1;

        // Next 2 bytes (4 hex chars)
        for i in 8..10 {
            buf[pos] = HEX[(bytes[i] >> 4) as usize];
            buf[pos + 1] = HEX[(bytes[i] & 0xF) as usize];
            pos += 2;
        }
        buf[pos] = b'-';
        pos += 1;

        // Final 6 bytes (12 hex chars)
        for i in 10..16 {
            buf[pos] = HEX[(bytes[i] >> 4) as usize];
            buf[pos + 1] = HEX[(bytes[i] & 0xF) as usize];
            pos += 2;
        }
    }

    /// Format UUID in Windows registry format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
    pub fn format_braced(&self, buf: &mut [u8; 38]) {
        buf[0] = b'{';
        let mut inner = [0u8; 36];
        self.format(&mut inner);
        buf[1..37].copy_from_slice(&inner);
        buf[37] = b'}';
    }

    /// Parse UUID from string (with or without braces/hyphens)
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let s = s.strip_prefix('{').unwrap_or(s);
        let s = s.strip_suffix('}').unwrap_or(s);

        // Remove hyphens and parse as hex
        let mut bytes = [0u8; 16];
        let mut byte_idx = 0;
        let mut chars = s.chars().peekable();

        while byte_idx < 16 {
            // Skip hyphens
            while chars.peek() == Some(&'-') {
                chars.next();
            }

            let high = chars.next()?.to_digit(16)? as u8;
            let low = chars.next()?.to_digit(16)? as u8;
            bytes[byte_idx] = (high << 4) | low;
            byte_idx += 1;
        }

        Some(Self::from_bytes(bytes))
    }
}

impl Default for Uuid {
    fn default() -> Self {
        Self::nil()
    }
}

impl core::fmt::Debug for Uuid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [0u8; 36];
        self.format(&mut buf);
        let s = core::str::from_utf8(&buf).unwrap_or("invalid");
        write!(f, "{}", s)
    }
}

impl core::fmt::Display for Uuid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [0u8; 36];
        self.format(&mut buf);
        let s = core::str::from_utf8(&buf).unwrap_or("invalid");
        write!(f, "{}", s)
    }
}

/// UUID variant
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UuidVariant {
    /// NCS backward compatibility
    Ncs,
    /// RFC 4122 (standard)
    Rfc4122,
    /// Microsoft backward compatibility
    Microsoft,
    /// Reserved for future definition
    Future,
}

/// Well-known UUIDs
pub mod well_known {
    use super::Uuid;

    /// Namespace UUID for DNS names (RFC 4122)
    pub const NAMESPACE_DNS: Uuid = Uuid::new(
        0x6ba7b810, 0x9dad, 0x11d1,
        [0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8]
    );

    /// Namespace UUID for URLs (RFC 4122)
    pub const NAMESPACE_URL: Uuid = Uuid::new(
        0x6ba7b811, 0x9dad, 0x11d1,
        [0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8]
    );

    /// Namespace UUID for ISO OIDs (RFC 4122)
    pub const NAMESPACE_OID: Uuid = Uuid::new(
        0x6ba7b812, 0x9dad, 0x11d1,
        [0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8]
    );

    /// Namespace UUID for X.500 DNs (RFC 4122)
    pub const NAMESPACE_X500: Uuid = Uuid::new(
        0x6ba7b814, 0x9dad, 0x11d1,
        [0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8]
    );
}

/// Generate a new random (v4) UUID
pub fn create_uuid() -> Uuid {
    Uuid::new_v4()
}

/// Generate a new time-based (v1) UUID
pub fn create_sequential_uuid() -> Uuid {
    Uuid::new_v1()
}

// ============================================================================
// Windows API Compatible Functions
// ============================================================================

/// RtlGUIDFromString equivalent - parse GUID from string
pub fn rtl_guid_from_string(s: &str) -> Option<Uuid> {
    Uuid::parse(s)
}

/// RtlStringFromGUID equivalent - format GUID to string
pub fn rtl_string_from_guid(guid: &Uuid, buf: &mut [u8; 38]) {
    guid.format_braced(buf);
}

/// ExUuidCreate equivalent - create a new UUID
pub fn ex_uuid_create() -> Uuid {
    Uuid::new_v4()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nil_uuid() {
        let nil = Uuid::nil();
        assert!(nil.is_nil());
        assert_eq!(nil.to_bytes(), [0u8; 16]);
    }

    #[test]
    fn test_uuid_format() {
        let uuid = Uuid::new(
            0x550e8400, 0xe29b, 0x41d4,
            [0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00]
        );
        let mut buf = [0u8; 36];
        uuid.format(&mut buf);
        assert_eq!(&buf, b"550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_uuid_parse() {
        let s = "550e8400-e29b-41d4-a716-446655440000";
        let uuid = Uuid::parse(s).unwrap();
        assert_eq!(uuid.data1, 0x550e8400);
        assert_eq!(uuid.data2, 0xe29b);
        assert_eq!(uuid.data3, 0x41d4);
    }

    #[test]
    fn test_uuid_v4_version() {
        let uuid = Uuid::new_v4();
        assert_eq!(uuid.version(), 4);
        assert_eq!(uuid.variant(), UuidVariant::Rfc4122);
    }
}
