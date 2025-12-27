//! FAT32 Directory Entry Structures
//!
//! Directory entries are 32 bytes each and contain:
//! - File name (8.3 format or LFN entries)
//! - Attributes
//! - Timestamps
//! - First cluster
//! - File size
//!
//! # Long File Names (LFN)
//! LFN entries precede the short entry and store up to 13 characters each.
//! They are stored in reverse order.

use super::bpb::cluster_values;

/// Directory entry size
pub const DIR_ENTRY_SIZE: usize = 32;

/// Maximum LFN entries
pub const MAX_LFN_ENTRIES: usize = 20;

/// Characters per LFN entry
pub const LFN_CHARS_PER_ENTRY: usize = 13;

/// Maximum LFN length
pub const MAX_LFN_LENGTH: usize = MAX_LFN_ENTRIES * LFN_CHARS_PER_ENTRY;

/// File attributes
pub mod file_attr {
    pub const ATTR_READ_ONLY: u8 = 0x01;
    pub const ATTR_HIDDEN: u8 = 0x02;
    pub const ATTR_SYSTEM: u8 = 0x04;
    pub const ATTR_VOLUME_ID: u8 = 0x08;
    pub const ATTR_DIRECTORY: u8 = 0x10;
    pub const ATTR_ARCHIVE: u8 = 0x20;
    /// Long file name entry marker
    pub const ATTR_LFN: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;
    /// Mask for LFN detection
    pub const ATTR_LFN_MASK: u8 = 0x3F;
}

/// Special first byte values
pub mod entry_status {
    /// Entry is free
    pub const FREE: u8 = 0xE5;
    /// Entry is free and all following entries are free
    pub const FREE_LAST: u8 = 0x00;
    /// First byte was 0xE5, stored as 0x05
    pub const KANJI: u8 = 0x05;
    /// Dot entry (. or ..)
    pub const DOT: u8 = 0x2E;
}

/// Short directory entry (8.3 format)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct FatDirEntry {
    /// File name (8 characters, space-padded)
    pub name: [u8; 8],
    /// File extension (3 characters, space-padded)
    pub ext: [u8; 3],
    /// File attributes
    pub attr: u8,
    /// Reserved (used for lowercase flags in NT)
    pub nt_res: u8,
    /// Creation time (tenths of second)
    pub create_time_tenth: u8,
    /// Creation time
    pub create_time: u16,
    /// Creation date
    pub create_date: u16,
    /// Last access date
    pub access_date: u16,
    /// High 16 bits of first cluster
    pub cluster_hi: u16,
    /// Last modification time
    pub modify_time: u16,
    /// Last modification date
    pub modify_date: u16,
    /// Low 16 bits of first cluster
    pub cluster_lo: u16,
    /// File size in bytes
    pub file_size: u32,
}

impl FatDirEntry {
    /// Create empty entry
    pub const fn empty() -> Self {
        Self {
            name: [0x20; 8],  // Space-padded
            ext: [0x20; 3],
            attr: 0,
            nt_res: 0,
            create_time_tenth: 0,
            create_time: 0,
            create_date: 0,
            access_date: 0,
            cluster_hi: 0,
            modify_time: 0,
            modify_date: 0,
            cluster_lo: 0,
            file_size: 0,
        }
    }

    /// Check if entry is free
    pub fn is_free(&self) -> bool {
        self.name[0] == entry_status::FREE || self.name[0] == entry_status::FREE_LAST
    }

    /// Check if this is the last entry
    pub fn is_last(&self) -> bool {
        self.name[0] == entry_status::FREE_LAST
    }

    /// Check if this is a long file name entry
    pub fn is_lfn(&self) -> bool {
        (self.attr & file_attr::ATTR_LFN_MASK) == file_attr::ATTR_LFN
    }

    /// Check if this is a directory
    pub fn is_directory(&self) -> bool {
        (self.attr & file_attr::ATTR_DIRECTORY) != 0
    }

    /// Check if this is a volume label
    pub fn is_volume_label(&self) -> bool {
        (self.attr & file_attr::ATTR_VOLUME_ID) != 0 && !self.is_lfn()
    }

    /// Check if this is read-only
    pub fn is_readonly(&self) -> bool {
        (self.attr & file_attr::ATTR_READ_ONLY) != 0
    }

    /// Check if this is hidden
    pub fn is_hidden(&self) -> bool {
        (self.attr & file_attr::ATTR_HIDDEN) != 0
    }

    /// Check if this is a system file
    pub fn is_system(&self) -> bool {
        (self.attr & file_attr::ATTR_SYSTEM) != 0
    }

    /// Check if archive flag is set
    pub fn is_archive(&self) -> bool {
        (self.attr & file_attr::ATTR_ARCHIVE) != 0
    }

    /// Check if this is a dot entry (. or ..)
    pub fn is_dot(&self) -> bool {
        self.name[0] == entry_status::DOT
    }

    /// Get the first cluster number
    pub fn first_cluster(&self) -> u32 {
        ((self.cluster_hi as u32) << 16) | (self.cluster_lo as u32)
    }

    /// Set the first cluster number
    pub fn set_first_cluster(&mut self, cluster: u32) {
        self.cluster_hi = (cluster >> 16) as u16;
        self.cluster_lo = (cluster & 0xFFFF) as u16;
    }

    /// Get file name as string (without extension)
    pub fn name_str(&self) -> &str {
        let mut name = &self.name[..];

        // Handle 0x05 -> 0xE5 translation
        // (We'd need to handle this specially)

        // Find end (trailing spaces)
        while !name.is_empty() && name[name.len() - 1] == b' ' {
            name = &name[..name.len() - 1];
        }

        core::str::from_utf8(name).unwrap_or("")
    }

    /// Get extension as string
    pub fn ext_str(&self) -> &str {
        let mut ext = &self.ext[..];
        while !ext.is_empty() && ext[ext.len() - 1] == b' ' {
            ext = &ext[..ext.len() - 1];
        }
        core::str::from_utf8(ext).unwrap_or("")
    }

    /// Get full 8.3 name with dot
    pub fn full_name(&self) -> [u8; 13] {
        let mut result = [0u8; 13];
        let mut pos = 0;

        // Copy name
        for &b in self.name.iter() {
            if b == b' ' {
                break;
            }
            // Handle 0x05 -> 0xE5
            result[pos] = if b == entry_status::KANJI { 0xE5 } else { b };
            pos += 1;
        }

        // Add dot and extension if present
        if self.ext[0] != b' ' {
            result[pos] = b'.';
            pos += 1;
            for &b in self.ext.iter() {
                if b == b' ' {
                    break;
                }
                result[pos] = b;
                pos += 1;
            }
        }

        result
    }

    /// Set name from 8.3 format
    pub fn set_name(&mut self, name: &[u8; 8], ext: &[u8; 3]) {
        self.name = *name;
        self.ext = *ext;
    }

    /// Check if name matches (case-insensitive)
    pub fn name_matches(&self, name: &str, ext: &str) -> bool {
        // Compare name
        let name_bytes = name.as_bytes();
        for (i, &b) in self.name.iter().enumerate() {
            let entry_char = if b == entry_status::KANJI { 0xE5 } else { b };
            let cmp_char = name_bytes.get(i).copied().unwrap_or(b' ');

            if entry_char.to_ascii_uppercase() != cmp_char.to_ascii_uppercase() {
                return false;
            }
        }

        // Compare extension
        let ext_bytes = ext.as_bytes();
        for (i, &b) in self.ext.iter().enumerate() {
            let cmp_char = ext_bytes.get(i).copied().unwrap_or(b' ');
            if b.to_ascii_uppercase() != cmp_char.to_ascii_uppercase() {
                return false;
            }
        }

        true
    }

    /// Mark entry as deleted
    pub fn delete(&mut self) {
        self.name[0] = entry_status::FREE;
    }
}

impl Default for FatDirEntry {
    fn default() -> Self {
        Self::empty()
    }
}

/// Long File Name (LFN) directory entry
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct LfnDirEntry {
    /// Sequence number (1-20, with bit 6 set for last entry)
    pub sequence: u8,
    /// Characters 1-5 (Unicode)
    pub name1: [u16; 5],
    /// Attributes (always ATTR_LFN)
    pub attr: u8,
    /// Type (always 0)
    pub entry_type: u8,
    /// Checksum of short name
    pub checksum: u8,
    /// Characters 6-11 (Unicode)
    pub name2: [u16; 6],
    /// First cluster (always 0)
    pub cluster: u16,
    /// Characters 12-13 (Unicode)
    pub name3: [u16; 2],
}

impl LfnDirEntry {
    /// Last LFN entry flag
    pub const LAST_ENTRY: u8 = 0x40;

    /// Maximum sequence number
    pub const MAX_SEQUENCE: u8 = 20;

    /// Create empty LFN entry
    pub const fn empty() -> Self {
        Self {
            sequence: 0,
            name1: [0xFFFF; 5],
            attr: file_attr::ATTR_LFN,
            entry_type: 0,
            checksum: 0,
            name2: [0xFFFF; 6],
            cluster: 0,
            name3: [0xFFFF; 2],
        }
    }

    /// Check if this is the last LFN entry
    pub fn is_last(&self) -> bool {
        (self.sequence & Self::LAST_ENTRY) != 0
    }

    /// Get sequence number (1-20)
    pub fn sequence_number(&self) -> u8 {
        self.sequence & 0x1F
    }

    /// Extract characters from this entry (up to 13 chars)
    pub fn extract_chars(&self) -> [u16; LFN_CHARS_PER_ENTRY] {
        let mut chars = [0u16; LFN_CHARS_PER_ENTRY];

        // Copy characters from the three fields using unaligned reads
        // This is necessary because the struct is packed
        unsafe {
            let name1_ptr = core::ptr::addr_of!(self.name1);
            let name2_ptr = core::ptr::addr_of!(self.name2);
            let name3_ptr = core::ptr::addr_of!(self.name3);

            let name1: [u16; 5] = core::ptr::read_unaligned(name1_ptr);
            let name2: [u16; 6] = core::ptr::read_unaligned(name2_ptr);
            let name3: [u16; 2] = core::ptr::read_unaligned(name3_ptr);

            chars[0..5].copy_from_slice(&name1);
            chars[5..11].copy_from_slice(&name2);
            chars[11..13].copy_from_slice(&name3);
        }

        chars
    }

    /// Set characters in this entry
    pub fn set_chars(&mut self, chars: &[u16]) {
        // Fill with 0xFFFF padding using local arrays
        let mut name1 = [0xFFFFu16; 5];
        let mut name2 = [0xFFFFu16; 6];
        let mut name3 = [0xFFFFu16; 2];

        let len = chars.len().min(LFN_CHARS_PER_ENTRY);

        for (i, &c) in chars.iter().take(len).enumerate() {
            match i {
                0..=4 => name1[i] = c,
                5..=10 => name2[i - 5] = c,
                11..=12 => name3[i - 11] = c,
                _ => break,
            }
        }

        // Add null terminator if room
        if len < LFN_CHARS_PER_ENTRY {
            match len {
                0..=4 => name1[len] = 0,
                5..=10 => name2[len - 5] = 0,
                11..=12 => name3[len - 11] = 0,
                _ => {}
            }
        }

        // Write using unaligned writes for packed struct
        unsafe {
            let name1_ptr = core::ptr::addr_of_mut!(self.name1);
            let name2_ptr = core::ptr::addr_of_mut!(self.name2);
            let name3_ptr = core::ptr::addr_of_mut!(self.name3);

            core::ptr::write_unaligned(name1_ptr, name1);
            core::ptr::write_unaligned(name2_ptr, name2);
            core::ptr::write_unaligned(name3_ptr, name3);
        }
    }
}

impl Default for LfnDirEntry {
    fn default() -> Self {
        Self::empty()
    }
}

/// Calculate checksum for short name
pub fn lfn_checksum(name: &[u8; 8], ext: &[u8; 3]) -> u8 {
    let mut sum: u8 = 0;

    for &b in name.iter() {
        sum = sum.rotate_right(1).wrapping_add(b);
    }
    for &b in ext.iter() {
        sum = sum.rotate_right(1).wrapping_add(b);
    }

    sum
}

/// Convert Unicode LFN to ASCII string
pub fn lfn_to_string(chars: &[u16]) -> [u8; MAX_LFN_LENGTH] {
    let mut result = [0u8; MAX_LFN_LENGTH];
    let mut pos = 0;

    for &c in chars {
        if c == 0 || c == 0xFFFF {
            break;
        }
        // Simple conversion (ASCII only)
        if c < 128 {
            result[pos] = c as u8;
            pos += 1;
            if pos >= MAX_LFN_LENGTH {
                break;
            }
        } else {
            // Non-ASCII: use replacement character
            result[pos] = b'?';
            pos += 1;
            if pos >= MAX_LFN_LENGTH {
                break;
            }
        }
    }

    result
}

/// Convert ASCII string to Unicode for LFN
pub fn string_to_lfn(s: &str) -> ([u16; MAX_LFN_LENGTH], usize) {
    let mut result = [0u16; MAX_LFN_LENGTH];
    let bytes = s.as_bytes();
    let len = bytes.len().min(MAX_LFN_LENGTH);

    for (i, &b) in bytes.iter().take(len).enumerate() {
        result[i] = b as u16;
    }

    (result, len)
}

/// Time and date conversion helpers
pub mod datetime {
    /// Convert FAT time to (hour, minute, second)
    pub fn decode_time(time: u16) -> (u8, u8, u8) {
        let second = ((time & 0x1F) * 2) as u8;
        let minute = ((time >> 5) & 0x3F) as u8;
        let hour = ((time >> 11) & 0x1F) as u8;
        (hour, minute, second)
    }

    /// Convert (hour, minute, second) to FAT time
    pub fn encode_time(hour: u8, minute: u8, second: u8) -> u16 {
        ((hour as u16 & 0x1F) << 11) |
        ((minute as u16 & 0x3F) << 5) |
        ((second as u16 / 2) & 0x1F)
    }

    /// Convert FAT date to (year, month, day)
    pub fn decode_date(date: u16) -> (u16, u8, u8) {
        let day = (date & 0x1F) as u8;
        let month = ((date >> 5) & 0x0F) as u8;
        let year = 1980 + ((date >> 9) & 0x7F) as u16;
        (year, month, day)
    }

    /// Convert (year, month, day) to FAT date
    pub fn encode_date(year: u16, month: u8, day: u8) -> u16 {
        let year_offset = year.saturating_sub(1980).min(127);
        ((year_offset as u16) << 9) |
        ((month as u16 & 0x0F) << 5) |
        (day as u16 & 0x1F)
    }
}

/// Initialize directory subsystem
pub fn init() {
    crate::serial_println!("[FS] FAT32 directory subsystem initialized");
}
