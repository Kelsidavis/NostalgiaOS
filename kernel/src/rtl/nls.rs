//! National Language Support (NLS)
//!
//! This module provides character set translation and case conversion
//! functions compatible with the Windows NT NLS subsystem.
//!
//! # Overview
//!
//! NLS provides:
//! - **Code Page Translation**: ANSI, OEM, and Unicode conversions
//! - **Case Conversion**: Upper and lowercase transformations
//! - **Multi-byte Support**: DBCS character handling
//! - **Character Classification**: Testing character properties
//!
//! # Code Pages
//!
//! The system uses three primary code pages:
//! - **ANSI Code Page (ACP)**: Default Windows code page (usually 1252)
//! - **OEM Code Page (OCP)**: DOS/console code page (usually 437)
//! - **Unicode**: Internal representation (UTF-16LE)

use core::sync::atomic::{AtomicU16, AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;

// ============================================================================
// Code Page Constants
// ============================================================================

/// Default ANSI code page (Latin 1 - Western European)
pub const CP_ACP: u16 = 0;
/// OEM code page (system default)
pub const CP_OEMCP: u16 = 1;
/// UTF-7 code page
pub const CP_UTF7: u16 = 65000;
/// UTF-8 code page
pub const CP_UTF8: u16 = 65001;

/// Code page 437 - US OEM
pub const CP_437: u16 = 437;
/// Code page 850 - Multilingual Latin 1
pub const CP_850: u16 = 850;
/// Code page 1252 - Windows Latin 1
pub const CP_1252: u16 = 1252;

/// Unicode null character
pub const UNICODE_NULL: u16 = 0x0000;
/// Unicode replacement character
pub const UNICODE_REPLACEMENT: u16 = 0xFFFD;
/// Default unicode character (for unmappable)
pub const UNICODE_DEFAULT_CHAR: u16 = 0x003F; // '?'

/// Maximum bytes in a multi-byte character
pub const MAX_MB_CHAR_SIZE: usize = 4;

// ============================================================================
// Global State
// ============================================================================

/// Current ANSI code page
static NLS_ANSI_CODE_PAGE: AtomicU16 = AtomicU16::new(CP_1252);
/// Current OEM code page
static NLS_OEM_CODE_PAGE: AtomicU16 = AtomicU16::new(CP_437);
/// Multi-byte code page tag
static NLS_MB_CODE_PAGE_TAG: AtomicBool = AtomicBool::new(false);
/// OEM multi-byte code page tag
static NLS_MB_OEM_CODE_PAGE_TAG: AtomicBool = AtomicBool::new(false);
/// NLS initialized flag
static NLS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// NLS statistics
#[derive(Debug, Clone, Copy)]
pub struct NlsStats {
    /// ANSI to Unicode conversions
    pub ansi_to_unicode: u64,
    /// Unicode to ANSI conversions
    pub unicode_to_ansi: u64,
    /// OEM to Unicode conversions
    pub oem_to_unicode: u64,
    /// Unicode to OEM conversions
    pub unicode_to_oem: u64,
    /// Upcase operations
    pub upcase_ops: u64,
    /// Downcase operations
    pub downcase_ops: u64,
    /// Invalid character mappings
    pub unmappable_chars: u64,
}

impl Default for NlsStats {
    fn default() -> Self {
        Self::new()
    }
}

impl NlsStats {
    pub const fn new() -> Self {
        Self {
            ansi_to_unicode: 0,
            unicode_to_ansi: 0,
            oem_to_unicode: 0,
            unicode_to_oem: 0,
            upcase_ops: 0,
            downcase_ops: 0,
            unmappable_chars: 0,
        }
    }
}

static mut NLS_STATS: NlsStats = NlsStats::new();
static NLS_LOCK: SpinLock<()> = SpinLock::new(());

// ============================================================================
// Upcase Table (ASCII + Latin-1 Supplement)
// ============================================================================

/// Unicode uppercase conversion table for 0x0000-0x00FF
#[rustfmt::skip]
static UPCASE_TABLE_BASIC: [u16; 256] = [
    // 0x00-0x0F (controls - no change)
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    // 0x10-0x1F (controls - no change)
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    // 0x20-0x2F (punctuation - no change)
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    // 0x30-0x3F (digits, punctuation - no change)
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    // 0x40-0x4F (@ and uppercase A-O - no change)
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    // 0x50-0x5F (uppercase P-Z, punctuation - no change)
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    // 0x60-0x6F (` and lowercase a-o -> uppercase A-O)
    0x60, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    // 0x70-0x7F (lowercase p-z -> uppercase P-Z, del)
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    // 0x80-0x8F (Latin-1 supplement controls - no change)
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    // 0x90-0x9F (Latin-1 supplement controls - no change)
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    // 0xA0-0xAF (Latin-1 supplement punctuation - no change)
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    // 0xB0-0xBF (Latin-1 supplement - no change)
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    // 0xC0-0xCF (uppercase Latin-1 letters - no change)
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    // 0xD0-0xDF (uppercase Latin-1 letters, times - no change)
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    // 0xE0-0xEF (lowercase Latin-1 -> uppercase)
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    // 0xF0-0xFF (lowercase Latin-1 -> uppercase, except divide)
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xF7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0x178,
];

// ============================================================================
// Code Page 1252 (Windows Latin-1) to Unicode Table
// ============================================================================

/// CP1252 to Unicode translation table for 0x80-0x9F
#[rustfmt::skip]
static CP1252_TO_UNICODE: [u16; 32] = [
    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,  // 0x80-0x87
    0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,  // 0x88-0x8F
    0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,  // 0x90-0x97
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,  // 0x98-0x9F
];

/// CP437 (OEM) to Unicode translation table for 0x80-0xFF
#[rustfmt::skip]
static CP437_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7,
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
    // 0x90-0x9F
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9,
    0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192,
    // 0xA0-0xAF
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA,
    0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
    // 0xB0-0xBF (box drawing characters)
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
    // 0xC0-0xCF (box drawing characters)
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F,
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
    // 0xD0-0xDF (box drawing characters)
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B,
    0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
    // 0xE0-0xEF (Greek letters)
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4,
    0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229,
    // 0xF0-0xFF (math symbols)
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248,
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0,
];

// ============================================================================
// Character Conversion Functions
// ============================================================================

/// Upcase a Unicode character
#[inline]
pub fn rtl_upcase_unicode_char(c: u16) -> u16 {
    if c < 0x100 {
        UPCASE_TABLE_BASIC[c as usize]
    } else {
        // Extended Unicode upcase ranges
        match c {
            // Latin Extended-A lowercase -> uppercase
            0x0101..=0x017F if c & 1 != 0 => c - 1,
            // Latin Extended-B
            0x0180..=0x024F => upcase_extended_latin_b(c),
            // Greek lowercase -> uppercase
            0x03B1..=0x03C9 => c - 0x20,
            // Cyrillic lowercase -> uppercase
            0x0430..=0x044F => c - 0x20,
            // Fullwidth lowercase -> uppercase
            0xFF41..=0xFF5A => c - 0x20,
            _ => c,
        }
    }
}

/// Upcase Latin Extended-B characters
fn upcase_extended_latin_b(c: u16) -> u16 {
    match c {
        0x0180 => 0x0243, // ƀ -> Ƀ
        0x0183 => 0x0182, // ƃ -> Ƃ
        0x0185 => 0x0184, // ƅ -> Ƅ
        0x0188 => 0x0187, // ƈ -> Ƈ
        0x018C => 0x018B, // ƌ -> Ƌ
        0x0192 => 0x0191, // ƒ -> Ƒ
        0x0199 => 0x0198, // ƙ -> Ƙ
        0x01A1 => 0x01A0, // ơ -> Ơ
        0x01A3 => 0x01A2, // ƣ -> Ƣ
        0x01A5 => 0x01A4, // ƥ -> Ƥ
        0x01A8 => 0x01A7, // ƨ -> Ƨ
        0x01AD => 0x01AC, // ƭ -> Ƭ
        0x01B0 => 0x01AF, // ư -> Ư
        0x01B4 => 0x01B3, // ƴ -> Ƴ
        0x01B6 => 0x01B5, // ƶ -> Ƶ
        0x01B9 => 0x01B8, // ƹ -> Ƹ
        0x01BD => 0x01BC, // ƽ -> Ƽ
        0x01C6 => 0x01C4, // ǆ -> Ǆ
        0x01C9 => 0x01C7, // ǉ -> Ǉ
        0x01CC => 0x01CA, // ǌ -> Ǌ
        0x01CE => 0x01CD, // ǎ -> Ǎ
        0x01D0 => 0x01CF, // ǐ -> Ǐ
        0x01D2 => 0x01D1, // ǒ -> Ǒ
        0x01D4 => 0x01D3, // ǔ -> Ǔ
        0x01D6 => 0x01D5, // ǖ -> Ǖ
        0x01D8 => 0x01D7, // ǘ -> Ǘ
        0x01DA => 0x01D9, // ǚ -> Ǚ
        0x01DC => 0x01DB, // ǜ -> Ǜ
        _ => c,
    }
}

/// Downcase a Unicode character
#[inline]
pub fn rtl_downcase_unicode_char(c: u16) -> u16 {
    if c < 0x100 {
        // Basic ASCII and Latin-1
        match c {
            0x41..=0x5A => c + 0x20, // A-Z -> a-z
            0xC0..=0xD6 => c + 0x20, // À-Ö -> à-ö
            0xD8..=0xDE => c + 0x20, // Ø-Þ -> ø-þ
            _ => c,
        }
    } else {
        // Extended Unicode downcase ranges
        match c {
            // Latin Extended-A uppercase -> lowercase
            0x0100..=0x017E if c & 1 == 0 => c + 1,
            // Greek uppercase -> lowercase
            0x0391..=0x03A9 => c + 0x20,
            // Cyrillic uppercase -> lowercase
            0x0410..=0x042F => c + 0x20,
            // Fullwidth uppercase -> lowercase
            0xFF21..=0xFF3A => c + 0x20,
            _ => c,
        }
    }
}

/// Convert ANSI character to Unicode (CP1252)
pub fn rtl_ansi_char_to_unicode(c: u8) -> u16 {
    if c < 0x80 {
        c as u16
    } else if c < 0xA0 {
        CP1252_TO_UNICODE[(c - 0x80) as usize]
    } else {
        c as u16
    }
}

/// Convert Unicode character to ANSI (CP1252)
pub fn rtl_unicode_char_to_ansi(c: u16) -> u8 {
    if c < 0x100 {
        // Direct mapping for Latin-1
        c as u8
    } else {
        // Search CP1252 special characters
        for (i, &uc) in CP1252_TO_UNICODE.iter().enumerate() {
            if uc == c {
                return (i + 0x80) as u8;
            }
        }
        UNICODE_DEFAULT_CHAR as u8 // '?'
    }
}

/// Convert OEM character to Unicode (CP437)
pub fn rtl_oem_char_to_unicode(c: u8) -> u16 {
    if c < 0x80 {
        c as u16
    } else {
        CP437_TO_UNICODE[(c - 0x80) as usize]
    }
}

/// Convert Unicode character to OEM (CP437)
pub fn rtl_unicode_char_to_oem(c: u16) -> u8 {
    if c < 0x80 {
        c as u8
    } else {
        // Search CP437 table
        for (i, &uc) in CP437_TO_UNICODE.iter().enumerate() {
            if uc == c {
                return (i + 0x80) as u8;
            }
        }
        UNICODE_DEFAULT_CHAR as u8 // '?'
    }
}

// ============================================================================
// String Conversion Functions
// ============================================================================

/// Convert multi-byte (ANSI) string to Unicode
pub fn rtl_multi_byte_to_unicode_n(
    unicode_string: &mut [u16],
    multi_byte_string: &[u8],
) -> Result<usize, i32> {
    let _guard = NLS_LOCK.lock();
    unsafe {
        NLS_STATS.ansi_to_unicode += 1;
    }

    let max_chars = unicode_string.len();
    let mut unicode_index = 0;
    let mut mb_index = 0;

    while mb_index < multi_byte_string.len() && unicode_index < max_chars {
        let byte = multi_byte_string[mb_index];
        unicode_string[unicode_index] = rtl_ansi_char_to_unicode(byte);
        unicode_index += 1;
        mb_index += 1;
    }

    Ok(unicode_index * 2) // Return bytes
}

/// Convert Unicode string to multi-byte (ANSI)
pub fn rtl_unicode_to_multi_byte_n(
    multi_byte_string: &mut [u8],
    unicode_string: &[u16],
) -> Result<usize, i32> {
    let _guard = NLS_LOCK.lock();
    unsafe {
        NLS_STATS.unicode_to_ansi += 1;
    }

    let max_bytes = multi_byte_string.len();
    let mut mb_index = 0;
    let mut unicode_index = 0;

    while unicode_index < unicode_string.len() && mb_index < max_bytes {
        let wchar = unicode_string[unicode_index];
        multi_byte_string[mb_index] = rtl_unicode_char_to_ansi(wchar);
        mb_index += 1;
        unicode_index += 1;
    }

    Ok(mb_index)
}

/// Convert OEM string to Unicode
pub fn rtl_oem_to_unicode_n(
    unicode_string: &mut [u16],
    oem_string: &[u8],
) -> Result<usize, i32> {
    let _guard = NLS_LOCK.lock();
    unsafe {
        NLS_STATS.oem_to_unicode += 1;
    }

    let max_chars = unicode_string.len();
    let mut unicode_index = 0;
    let mut oem_index = 0;

    while oem_index < oem_string.len() && unicode_index < max_chars {
        let byte = oem_string[oem_index];
        unicode_string[unicode_index] = rtl_oem_char_to_unicode(byte);
        unicode_index += 1;
        oem_index += 1;
    }

    Ok(unicode_index * 2)
}

/// Convert Unicode string to OEM
pub fn rtl_unicode_to_oem_n(
    oem_string: &mut [u8],
    unicode_string: &[u16],
) -> Result<usize, i32> {
    let _guard = NLS_LOCK.lock();
    unsafe {
        NLS_STATS.unicode_to_oem += 1;
    }

    let max_bytes = oem_string.len();
    let mut oem_index = 0;
    let mut unicode_index = 0;

    while unicode_index < unicode_string.len() && oem_index < max_bytes {
        let wchar = unicode_string[unicode_index];
        oem_string[oem_index] = rtl_unicode_char_to_oem(wchar);
        oem_index += 1;
        unicode_index += 1;
    }

    Ok(oem_index)
}

/// Upcase Unicode string in-place
pub fn rtl_upcase_unicode_string_in_place(s: &mut [u16]) {
    let _guard = NLS_LOCK.lock();
    unsafe {
        NLS_STATS.upcase_ops += 1;
    }

    for c in s.iter_mut() {
        *c = rtl_upcase_unicode_char(*c);
    }
}

/// Downcase Unicode string in-place
pub fn rtl_downcase_unicode_string_in_place(s: &mut [u16]) {
    let _guard = NLS_LOCK.lock();
    unsafe {
        NLS_STATS.downcase_ops += 1;
    }

    for c in s.iter_mut() {
        *c = rtl_downcase_unicode_char(*c);
    }
}

/// Upcase and convert Unicode to ANSI
pub fn rtl_upcase_unicode_to_multi_byte_n(
    multi_byte_string: &mut [u8],
    unicode_string: &[u16],
) -> Result<usize, i32> {
    let _guard = NLS_LOCK.lock();
    unsafe {
        NLS_STATS.unicode_to_ansi += 1;
        NLS_STATS.upcase_ops += 1;
    }

    let max_bytes = multi_byte_string.len();
    let mut mb_index = 0;
    let mut unicode_index = 0;

    while unicode_index < unicode_string.len() && mb_index < max_bytes {
        let wchar = rtl_upcase_unicode_char(unicode_string[unicode_index]);
        multi_byte_string[mb_index] = rtl_unicode_char_to_ansi(wchar);
        mb_index += 1;
        unicode_index += 1;
    }

    Ok(mb_index)
}

/// Upcase and convert Unicode to OEM
pub fn rtl_upcase_unicode_to_oem_n(
    oem_string: &mut [u8],
    unicode_string: &[u16],
) -> Result<usize, i32> {
    let _guard = NLS_LOCK.lock();
    unsafe {
        NLS_STATS.unicode_to_oem += 1;
        NLS_STATS.upcase_ops += 1;
    }

    let max_bytes = oem_string.len();
    let mut oem_index = 0;
    let mut unicode_index = 0;

    while unicode_index < unicode_string.len() && oem_index < max_bytes {
        let wchar = rtl_upcase_unicode_char(unicode_string[unicode_index]);
        oem_string[oem_index] = rtl_unicode_char_to_oem(wchar);
        oem_index += 1;
        unicode_index += 1;
    }

    Ok(oem_index)
}

// ============================================================================
// Size Calculation Functions
// ============================================================================

/// Calculate Unicode string size from multi-byte
pub fn rtl_multi_byte_to_unicode_size(multi_byte_len: usize) -> usize {
    // For non-DBCS code pages, it's 1:1 mapping
    if !NLS_MB_CODE_PAGE_TAG.load(Ordering::Acquire) {
        multi_byte_len * 2
    } else {
        // DBCS code pages may have variable length
        multi_byte_len * 2 // Conservative estimate
    }
}

/// Calculate multi-byte string size from Unicode
pub fn rtl_unicode_to_multi_byte_size(unicode_len: usize) -> usize {
    // For non-DBCS code pages, it's 1:1 mapping
    if !NLS_MB_CODE_PAGE_TAG.load(Ordering::Acquire) {
        unicode_len / 2
    } else {
        // DBCS code pages may need 2 bytes per character
        unicode_len // Conservative estimate
    }
}

// ============================================================================
// Character Classification
// ============================================================================

/// Check if character is alphabetic
#[inline]
pub fn rtl_is_alpha(c: u16) -> bool {
    matches!(c,
        0x41..=0x5A |  // A-Z
        0x61..=0x7A |  // a-z
        0xC0..=0xD6 |  // À-Ö
        0xD8..=0xF6 |  // Ø-ö
        0xF8..=0xFF |  // ø-ÿ
        0x100..=0x17F  // Latin Extended-A
    )
}

/// Check if character is uppercase
#[inline]
pub fn rtl_is_upper(c: u16) -> bool {
    matches!(c,
        0x41..=0x5A |  // A-Z
        0xC0..=0xD6 |  // À-Ö
        0xD8..=0xDE    // Ø-Þ
    )
}

/// Check if character is lowercase
#[inline]
pub fn rtl_is_lower(c: u16) -> bool {
    matches!(c,
        0x61..=0x7A |  // a-z
        0xDF..=0xF6 |  // ß-ö
        0xF8..=0xFF    // ø-ÿ
    )
}

/// Check if character is a digit
#[inline]
pub fn rtl_is_digit(c: u16) -> bool {
    (0x30..=0x39).contains(&c) // 0-9
}

/// Check if character is alphanumeric
#[inline]
pub fn rtl_is_alnum(c: u16) -> bool {
    rtl_is_alpha(c) || rtl_is_digit(c)
}

/// Check if character is whitespace
#[inline]
pub fn rtl_is_space(c: u16) -> bool {
    matches!(c,
        0x09..=0x0D |  // HT, LF, VT, FF, CR
        0x20 |         // Space
        0xA0 |         // Non-breaking space
        0x1680 |       // Ogham space mark
        0x2000..=0x200A | // Various spaces
        0x2028 |       // Line separator
        0x2029 |       // Paragraph separator
        0x202F |       // Narrow no-break space
        0x205F |       // Medium mathematical space
        0x3000         // Ideographic space
    )
}

// ============================================================================
// Code Page Functions
// ============================================================================

/// Get default ANSI code page
pub fn rtl_get_default_code_page() -> (u16, u16) {
    (
        NLS_ANSI_CODE_PAGE.load(Ordering::Acquire),
        NLS_OEM_CODE_PAGE.load(Ordering::Acquire),
    )
}

/// Set default code pages
pub fn rtl_set_default_code_pages(ansi_cp: u16, oem_cp: u16) {
    NLS_ANSI_CODE_PAGE.store(ansi_cp, Ordering::Release);
    NLS_OEM_CODE_PAGE.store(oem_cp, Ordering::Release);
}

/// Check if multi-byte code page is in use
pub fn rtl_is_mb_code_page() -> bool {
    NLS_MB_CODE_PAGE_TAG.load(Ordering::Acquire)
}

// ============================================================================
// Statistics
// ============================================================================

/// Get NLS statistics
pub fn get_stats() -> NlsStats {
    unsafe { NLS_STATS }
}

/// Reset NLS statistics
pub fn reset_stats() {
    let _guard = NLS_LOCK.lock();
    unsafe {
        NLS_STATS = NlsStats::new();
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize NLS subsystem
pub fn init() {
    if NLS_INITIALIZED.swap(true, Ordering::AcqRel) {
        return;
    }

    // Set default code pages
    NLS_ANSI_CODE_PAGE.store(CP_1252, Ordering::Release);
    NLS_OEM_CODE_PAGE.store(CP_437, Ordering::Release);
    NLS_MB_CODE_PAGE_TAG.store(false, Ordering::Release);
    NLS_MB_OEM_CODE_PAGE_TAG.store(false, Ordering::Release);

    unsafe {
        NLS_STATS = NlsStats::new();
    }

    crate::serial_println!("[NLS] National Language Support initialized (ACP={}, OCP={})",
        CP_1252, CP_437);
}

/// Check if NLS is initialized
pub fn is_initialized() -> bool {
    NLS_INITIALIZED.load(Ordering::Acquire)
}
