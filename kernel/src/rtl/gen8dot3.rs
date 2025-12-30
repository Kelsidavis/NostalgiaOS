//! 8.3 Short Name Generation
//!
//! This module implements the algorithm for generating DOS-compatible 8.3
//! short file names from long file names, following the Windows NT/2000/XP
//! algorithm.
//!
//! # 8.3 Name Format
//!
//! - Base name: 1-8 characters
//! - Extension: 0-3 characters (after the dot)
//! - Characters: A-Z, 0-9, and specific special characters
//!
//! # Generation Algorithm
//!
//! 1. Strip leading/trailing spaces and dots
//! 2. Convert to uppercase
//! 3. Replace illegal characters with underscore
//! 4. Take first 6 chars of base + "~N" where N is a sequence number
//! 5. Keep first 3 chars of extension

/// Maximum base name length (before ~N suffix)
pub const MAX_8DOT3_BASE: usize = 8;

/// Maximum extension length
pub const MAX_8DOT3_EXT: usize = 3;

/// Full 8.3 name length (8 + 1 + 3)
pub const MAX_8DOT3_NAME: usize = 12;

/// Context for generating multiple 8.3 names from the same long name
#[derive(Clone)]
pub struct Generate8dot3Context {
    /// Primary name portion (up to 6 chars, uppercase, no extension)
    pub name: [u16; 8],
    /// Length of the primary name
    pub name_length: usize,
    /// Extension portion (up to 3 chars, uppercase)
    pub extension: [u16; 4],
    /// Length of extension
    pub extension_length: usize,
    /// Current sequence number for tilde suffix
    pub sequence_number: u32,
    /// Checksum of the original long name
    pub checksum: u16,
    /// Use checksum in the name
    pub use_checksum: bool,
}

impl Default for Generate8dot3Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Generate8dot3Context {
    /// Create a new context
    pub const fn new() -> Self {
        Self {
            name: [0; 8],
            name_length: 0,
            extension: [0; 4],
            extension_length: 0,
            sequence_number: 1,
            checksum: 0,
            use_checksum: false,
        }
    }
}

/// Table of characters illegal in FAT file names
/// This is a bitmask for ASCII characters 0-127
const ILLEGAL_FAT_CHARS: [u32; 4] = [
    0xFFFFFFFF, // 0-31: all control characters are illegal
    0xFC009C04, // 32-63: space, ", *, +, ,, /, :, ;, <, =, >, ?
    0x38000000, // 64-95: [, \, ]
    0x10000000, // 96-127: |
];

/// Check if a character is legal in a FAT 8.3 name
#[inline]
fn is_legal_fat_char(ch: u16) -> bool {
    if ch > 127 {
        // Extended characters - simplified check
        // In a full implementation, this would check DBCS tables
        return ch >= 0x100 || (ch >= 0x80 && ch <= 0xFF);
    }

    let idx = (ch / 32) as usize;
    let bit = ch % 32;

    if idx < 4 {
        (ILLEGAL_FAT_CHARS[idx] & (1 << bit)) == 0
    } else {
        false
    }
}

/// Convert a character to uppercase
#[inline]
fn to_upper(ch: u16) -> u16 {
    if ch >= b'a' as u16 && ch <= b'z' as u16 {
        ch - 32
    } else {
        ch
    }
}

/// Compute checksum of a Unicode name
///
/// This is used to generate unique short names when there are conflicts.
pub fn rtl_compute_lfn_checksum(name: &[u16]) -> u16 {
    let mut checksum: u16 = 0;

    for &ch in name {
        // Rotate right by 1, then add character
        checksum = checksum.rotate_right(1).wrapping_add(ch);
    }

    checksum
}

/// Check if a name is already a legal DOS 8.3 name
///
/// Returns true if the name doesn't need conversion.
pub fn rtl_is_name_legal_dos8dot3(name: &[u16], spaces_in_name: &mut bool) -> bool {
    *spaces_in_name = false;

    if name.is_empty() || name.len() > 12 {
        return false;
    }

    let mut base_len = 0;
    let mut ext_len = 0;
    let mut in_extension = false;
    let mut dot_count = 0;

    for &ch in name {
        if ch == b'.' as u16 {
            if in_extension {
                return false; // Multiple dots
            }
            dot_count += 1;
            if dot_count > 1 {
                return false;
            }
            in_extension = true;
            continue;
        }

        if ch == b' ' as u16 {
            *spaces_in_name = true;
        }

        if !is_legal_fat_char(ch) {
            return false;
        }

        // Check for lowercase (would need conversion)
        if ch >= b'a' as u16 && ch <= b'z' as u16 {
            return false;
        }

        if in_extension {
            ext_len += 1;
            if ext_len > 3 {
                return false;
            }
        } else {
            base_len += 1;
            if base_len > 8 {
                return false;
            }
        }
    }

    // Must have at least one character in base name
    base_len > 0
}

/// Generate an 8.3 name from a long file name
///
/// # Arguments
///
/// * `name` - The long file name (Unicode)
/// * `allow_extended` - Allow extended (non-ASCII) characters
/// * `context` - Generation context (zeroed on first call)
/// * `name_8dot3` - Buffer for the resulting 8.3 name (at least 12 chars)
///
/// # Returns
///
/// The length of the generated 8.3 name.
pub fn rtl_generate_8dot3_name(
    name: &[u16],
    _allow_extended: bool,
    context: &mut Generate8dot3Context,
    name_8dot3: &mut [u16],
) -> usize {
    if name.is_empty() || name_8dot3.len() < MAX_8DOT3_NAME {
        return 0;
    }

    // First call - initialize the context
    if context.name_length == 0 {
        // Find the last dot for extension separation
        let mut last_dot_idx = None;
        for (i, &ch) in name.iter().enumerate() {
            if ch == b'.' as u16 {
                last_dot_idx = Some(i);
            }
        }

        // Extract the extension
        if let Some(dot_idx) = last_dot_idx {
            let ext_start = dot_idx + 1;
            let mut ext_len = 0;

            for &ch in name.iter().skip(ext_start) {
                if ext_len >= 3 {
                    break;
                }
                if is_legal_fat_char(ch) && ch != b'.' as u16 && ch != b' ' as u16 {
                    context.extension[ext_len] = to_upper(ch);
                    ext_len += 1;
                }
            }
            context.extension_length = ext_len;
        }

        // Extract the base name (before the last dot)
        let base_end = last_dot_idx.unwrap_or(name.len());
        let mut base_len = 0;

        // Skip leading spaces and dots
        let mut start = 0;
        while start < base_end && (name[start] == b' ' as u16 || name[start] == b'.' as u16) {
            start += 1;
        }

        for &ch in name.iter().skip(start).take(base_end - start) {
            if base_len >= 6 {
                break; // Leave room for ~N suffix
            }

            let ch = to_upper(ch);

            // Skip spaces and dots in the base name
            if ch == b' ' as u16 || ch == b'.' as u16 {
                continue;
            }

            // Replace illegal characters with underscore
            let final_ch = if is_legal_fat_char(ch) { ch } else { b'_' as u16 };

            context.name[base_len] = final_ch;
            base_len += 1;
        }

        context.name_length = base_len;
        context.checksum = rtl_compute_lfn_checksum(name);
        context.sequence_number = 1;

        // Decide whether to use checksum based on name length
        // Use checksum if base is short to add uniqueness
        context.use_checksum = base_len <= 2;
    }

    // Build the 8.3 name
    let mut pos = 0;

    // Copy base name
    let base_chars = if context.sequence_number <= 4 {
        context.name_length.min(6)
    } else {
        // After ~4, use shorter base to accommodate larger sequence numbers
        context.name_length.min(5)
    };

    for i in 0..base_chars {
        name_8dot3[pos] = context.name[i];
        pos += 1;
    }

    // Add checksum if enabled (for short names or high sequence numbers)
    if context.use_checksum && context.sequence_number > 4 {
        // Format: ~XXXX where XXXX is hex checksum
        name_8dot3[pos] = b'~' as u16;
        pos += 1;

        let hex_chars = [
            b'0' as u16, b'1' as u16, b'2' as u16, b'3' as u16,
            b'4' as u16, b'5' as u16, b'6' as u16, b'7' as u16,
            b'8' as u16, b'9' as u16, b'A' as u16, b'B' as u16,
            b'C' as u16, b'D' as u16, b'E' as u16, b'F' as u16,
        ];

        name_8dot3[pos] = hex_chars[((context.checksum >> 12) & 0xF) as usize];
        pos += 1;
        name_8dot3[pos] = hex_chars[((context.checksum >> 8) & 0xF) as usize];
        pos += 1;
        name_8dot3[pos] = hex_chars[((context.checksum >> 4) & 0xF) as usize];
        pos += 1;
        name_8dot3[pos] = hex_chars[(context.checksum & 0xF) as usize];
        pos += 1;
    } else {
        // Add ~N suffix
        name_8dot3[pos] = b'~' as u16;
        pos += 1;

        // Format the sequence number
        let seq = context.sequence_number;
        if seq >= 10 {
            name_8dot3[pos] = b'0' as u16 + (seq / 10) as u16;
            pos += 1;
            name_8dot3[pos] = b'0' as u16 + (seq % 10) as u16;
            pos += 1;
        } else {
            name_8dot3[pos] = b'0' as u16 + seq as u16;
            pos += 1;
        }
    }

    // Add extension if present
    if context.extension_length > 0 {
        name_8dot3[pos] = b'.' as u16;
        pos += 1;

        for i in 0..context.extension_length {
            name_8dot3[pos] = context.extension[i];
            pos += 1;
        }
    }

    // Increment sequence for next call
    context.sequence_number += 1;

    pos
}

/// Get the next 8.3 name variant
///
/// Call this after rtl_generate_8dot3_name to get the next variant
/// if the previous one conflicted with an existing name.
pub fn rtl_next_8dot3_name(
    context: &mut Generate8dot3Context,
    name_8dot3: &mut [u16],
) -> usize {
    if name_8dot3.len() < MAX_8DOT3_NAME {
        return 0;
    }

    // Build the 8.3 name with current sequence number
    let mut pos = 0;

    let base_chars = if context.sequence_number <= 4 {
        context.name_length.min(6)
    } else {
        context.name_length.min(5)
    };

    for i in 0..base_chars {
        name_8dot3[pos] = context.name[i];
        pos += 1;
    }

    // After many attempts, switch to checksum mode
    if context.sequence_number > 99 {
        context.use_checksum = true;
    }

    if context.use_checksum {
        let hex_chars = [
            b'0' as u16, b'1' as u16, b'2' as u16, b'3' as u16,
            b'4' as u16, b'5' as u16, b'6' as u16, b'7' as u16,
            b'8' as u16, b'9' as u16, b'A' as u16, b'B' as u16,
            b'C' as u16, b'D' as u16, b'E' as u16, b'F' as u16,
        ];

        // Use checksum + sequence: ~XXXN
        let combined = context.checksum.wrapping_add(context.sequence_number as u16);
        name_8dot3[pos] = b'~' as u16;
        pos += 1;
        name_8dot3[pos] = hex_chars[((combined >> 8) & 0xF) as usize];
        pos += 1;
        name_8dot3[pos] = hex_chars[((combined >> 4) & 0xF) as usize];
        pos += 1;
        name_8dot3[pos] = hex_chars[(combined & 0xF) as usize];
        pos += 1;
    } else {
        name_8dot3[pos] = b'~' as u16;
        pos += 1;

        let seq = context.sequence_number;
        if seq >= 10 {
            name_8dot3[pos] = b'0' as u16 + (seq / 10) as u16;
            pos += 1;
            name_8dot3[pos] = b'0' as u16 + (seq % 10) as u16;
            pos += 1;
        } else {
            name_8dot3[pos] = b'0' as u16 + seq as u16;
            pos += 1;
        }
    }

    if context.extension_length > 0 {
        name_8dot3[pos] = b'.' as u16;
        pos += 1;

        for i in 0..context.extension_length {
            name_8dot3[pos] = context.extension[i];
            pos += 1;
        }
    }

    context.sequence_number += 1;

    pos
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legal_8dot3() {
        let name = [b'T' as u16, b'E' as u16, b'S' as u16, b'T' as u16];
        let mut spaces = false;
        assert!(rtl_is_name_legal_dos8dot3(&name, &mut spaces));

        let name2 = [
            b'T' as u16, b'E' as u16, b'S' as u16, b'T' as u16,
            b'.' as u16, b'T' as u16, b'X' as u16, b'T' as u16,
        ];
        assert!(rtl_is_name_legal_dos8dot3(&name2, &mut spaces));
    }

    #[test]
    fn test_generate_8dot3() {
        let long_name: [u16; 16] = [
            b'L' as u16, b'o' as u16, b'n' as u16, b'g' as u16,
            b' ' as u16, b'F' as u16, b'i' as u16, b'l' as u16,
            b'e' as u16, b' ' as u16, b'N' as u16, b'a' as u16,
            b'm' as u16, b'e' as u16, b'.' as u16, b't' as u16,
        ];

        let mut context = Generate8dot3Context::new();
        let mut short_name = [0u16; 12];

        let len = rtl_generate_8dot3_name(&long_name, false, &mut context, &mut short_name);

        assert!(len > 0);
        assert!(len <= 12);
    }
}
