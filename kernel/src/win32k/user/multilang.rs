//! Multilingual Support
//!
//! Language bar and multilingual input support.
//! Based on Windows Server 2003 mlang.h and ctf.h.
//!
//! # Features
//!
//! - Locale handling
//! - Code page conversion
//! - Language detection
//! - Text services framework
//!
//! # References
//!
//! - `public/sdk/inc/mlang.h` - Multilingual API
//! - `public/sdk/inc/ctffunc.h` - Text services

use crate::ke::spinlock::SpinLock;

// ============================================================================
// Primary Language IDs (LANG_*)
// ============================================================================

/// Neutral language
pub const LANG_NEUTRAL: u16 = 0x00;

/// Invariant language
pub const LANG_INVARIANT: u16 = 0x7F;

/// Afrikaans
pub const LANG_AFRIKAANS: u16 = 0x36;

/// Albanian
pub const LANG_ALBANIAN: u16 = 0x1C;

/// Arabic
pub const LANG_ARABIC: u16 = 0x01;

/// Armenian
pub const LANG_ARMENIAN: u16 = 0x2B;

/// Basque
pub const LANG_BASQUE: u16 = 0x2D;

/// Bulgarian
pub const LANG_BULGARIAN: u16 = 0x02;

/// Catalan
pub const LANG_CATALAN: u16 = 0x03;

/// Chinese
pub const LANG_CHINESE: u16 = 0x04;

/// Croatian
pub const LANG_CROATIAN: u16 = 0x1A;

/// Czech
pub const LANG_CZECH: u16 = 0x05;

/// Danish
pub const LANG_DANISH: u16 = 0x06;

/// Dutch
pub const LANG_DUTCH: u16 = 0x13;

/// English
pub const LANG_ENGLISH: u16 = 0x09;

/// Estonian
pub const LANG_ESTONIAN: u16 = 0x25;

/// Finnish
pub const LANG_FINNISH: u16 = 0x0B;

/// French
pub const LANG_FRENCH: u16 = 0x0C;

/// German
pub const LANG_GERMAN: u16 = 0x07;

/// Greek
pub const LANG_GREEK: u16 = 0x08;

/// Hebrew
pub const LANG_HEBREW: u16 = 0x0D;

/// Hindi
pub const LANG_HINDI: u16 = 0x39;

/// Hungarian
pub const LANG_HUNGARIAN: u16 = 0x0E;

/// Icelandic
pub const LANG_ICELANDIC: u16 = 0x0F;

/// Indonesian
pub const LANG_INDONESIAN: u16 = 0x21;

/// Italian
pub const LANG_ITALIAN: u16 = 0x10;

/// Japanese
pub const LANG_JAPANESE: u16 = 0x11;

/// Korean
pub const LANG_KOREAN: u16 = 0x12;

/// Latvian
pub const LANG_LATVIAN: u16 = 0x26;

/// Lithuanian
pub const LANG_LITHUANIAN: u16 = 0x27;

/// Norwegian
pub const LANG_NORWEGIAN: u16 = 0x14;

/// Polish
pub const LANG_POLISH: u16 = 0x15;

/// Portuguese
pub const LANG_PORTUGUESE: u16 = 0x16;

/// Romanian
pub const LANG_ROMANIAN: u16 = 0x18;

/// Russian
pub const LANG_RUSSIAN: u16 = 0x19;

/// Serbian
pub const LANG_SERBIAN: u16 = 0x1A;

/// Slovak
pub const LANG_SLOVAK: u16 = 0x1B;

/// Slovenian
pub const LANG_SLOVENIAN: u16 = 0x24;

/// Spanish
pub const LANG_SPANISH: u16 = 0x0A;

/// Swedish
pub const LANG_SWEDISH: u16 = 0x1D;

/// Thai
pub const LANG_THAI: u16 = 0x1E;

/// Turkish
pub const LANG_TURKISH: u16 = 0x1F;

/// Ukrainian
pub const LANG_UKRAINIAN: u16 = 0x22;

/// Vietnamese
pub const LANG_VIETNAMESE: u16 = 0x2A;

// ============================================================================
// Sublanguage IDs (SUBLANG_*)
// ============================================================================

/// Neutral
pub const SUBLANG_NEUTRAL: u16 = 0x00;

/// Default
pub const SUBLANG_DEFAULT: u16 = 0x01;

/// System default
pub const SUBLANG_SYS_DEFAULT: u16 = 0x02;

/// Chinese Simplified
pub const SUBLANG_CHINESE_SIMPLIFIED: u16 = 0x02;

/// Chinese Traditional
pub const SUBLANG_CHINESE_TRADITIONAL: u16 = 0x01;

/// Chinese Hong Kong
pub const SUBLANG_CHINESE_HONGKONG: u16 = 0x03;

/// Chinese Singapore
pub const SUBLANG_CHINESE_SINGAPORE: u16 = 0x04;

/// English US
pub const SUBLANG_ENGLISH_US: u16 = 0x01;

/// English UK
pub const SUBLANG_ENGLISH_UK: u16 = 0x02;

/// English Australian
pub const SUBLANG_ENGLISH_AUS: u16 = 0x03;

/// English Canadian
pub const SUBLANG_ENGLISH_CAN: u16 = 0x04;

/// French
pub const SUBLANG_FRENCH: u16 = 0x01;

/// French Belgian
pub const SUBLANG_FRENCH_BELGIAN: u16 = 0x02;

/// French Canadian
pub const SUBLANG_FRENCH_CANADIAN: u16 = 0x03;

/// German
pub const SUBLANG_GERMAN: u16 = 0x01;

/// German Swiss
pub const SUBLANG_GERMAN_SWISS: u16 = 0x02;

/// German Austrian
pub const SUBLANG_GERMAN_AUSTRIAN: u16 = 0x03;

/// Spanish
pub const SUBLANG_SPANISH: u16 = 0x01;

/// Spanish Mexican
pub const SUBLANG_SPANISH_MEXICAN: u16 = 0x02;

// ============================================================================
// Code Page IDs
// ============================================================================

/// ANSI Latin 1
pub const CP_ACP: u32 = 0;

/// OEM
pub const CP_OEMCP: u32 = 1;

/// MAC
pub const CP_MACCP: u32 = 2;

/// Thread ACP
pub const CP_THREAD_ACP: u32 = 3;

/// Symbol
pub const CP_SYMBOL: u32 = 42;

/// UTF-7
pub const CP_UTF7: u32 = 65000;

/// UTF-8
pub const CP_UTF8: u32 = 65001;

/// Windows-1250 Central European
pub const CP_WINDOWS_1250: u32 = 1250;

/// Windows-1251 Cyrillic
pub const CP_WINDOWS_1251: u32 = 1251;

/// Windows-1252 Latin 1
pub const CP_WINDOWS_1252: u32 = 1252;

/// Windows-1253 Greek
pub const CP_WINDOWS_1253: u32 = 1253;

/// Windows-1254 Turkish
pub const CP_WINDOWS_1254: u32 = 1254;

/// Windows-1255 Hebrew
pub const CP_WINDOWS_1255: u32 = 1255;

/// Windows-1256 Arabic
pub const CP_WINDOWS_1256: u32 = 1256;

/// Windows-1257 Baltic
pub const CP_WINDOWS_1257: u32 = 1257;

/// Windows-1258 Vietnamese
pub const CP_WINDOWS_1258: u32 = 1258;

/// Shift-JIS (Japanese)
pub const CP_SHIFT_JIS: u32 = 932;

/// GB2312 (Simplified Chinese)
pub const CP_GB2312: u32 = 936;

/// Big5 (Traditional Chinese)
pub const CP_BIG5: u32 = 950;

/// EUC-KR (Korean)
pub const CP_EUC_KR: u32 = 949;

// ============================================================================
// Character Type Flags (CT_*)
// ============================================================================

/// Upper case
pub const C1_UPPER: u16 = 0x0001;

/// Lower case
pub const C1_LOWER: u16 = 0x0002;

/// Digit
pub const C1_DIGIT: u16 = 0x0004;

/// Space
pub const C1_SPACE: u16 = 0x0008;

/// Punctuation
pub const C1_PUNCT: u16 = 0x0010;

/// Control
pub const C1_CNTRL: u16 = 0x0020;

/// Blank
pub const C1_BLANK: u16 = 0x0040;

/// Hex digit
pub const C1_XDIGIT: u16 = 0x0080;

/// Alpha
pub const C1_ALPHA: u16 = 0x0100;

/// Defined
pub const C1_DEFINED: u16 = 0x0200;

// ============================================================================
// Constants
// ============================================================================

/// Maximum registered locales
pub const MAX_LOCALES: usize = 64;

/// Maximum code pages
pub const MAX_CODE_PAGES: usize = 32;

/// Maximum name length
pub const MAX_NAME_LEN: usize = 64;

// ============================================================================
// Locale Info
// ============================================================================

/// Locale information
#[derive(Clone, Copy)]
pub struct LocaleInfo {
    /// Is this slot in use
    pub in_use: bool,
    /// Locale ID
    pub lcid: u32,
    /// Primary language
    pub lang_id: u16,
    /// Sublanguage
    pub sublang_id: u16,
    /// Code page
    pub code_page: u32,
    /// Is bidirectional
    pub is_bidi: bool,
    /// Is CJK
    pub is_cjk: bool,
    /// Name
    pub name: [u8; MAX_NAME_LEN],
    /// Native name
    pub native_name: [u8; MAX_NAME_LEN],
}

impl LocaleInfo {
    /// Create empty locale
    pub const fn new() -> Self {
        Self {
            in_use: false,
            lcid: 0,
            lang_id: LANG_NEUTRAL,
            sublang_id: SUBLANG_NEUTRAL,
            code_page: CP_WINDOWS_1252,
            is_bidi: false,
            is_cjk: false,
            name: [0; MAX_NAME_LEN],
            native_name: [0; MAX_NAME_LEN],
        }
    }
}

// ============================================================================
// Code Page Info
// ============================================================================

/// Code page information
#[derive(Clone, Copy)]
pub struct CodePageInfo {
    /// Is this slot in use
    pub in_use: bool,
    /// Code page ID
    pub code_page: u32,
    /// Maximum character size
    pub max_char_size: u32,
    /// Default character
    pub default_char: u8,
    /// Lead byte ranges (up to 5 pairs)
    pub lead_bytes: [[u8; 2]; 5],
    /// Name
    pub name: [u8; MAX_NAME_LEN],
}

impl CodePageInfo {
    /// Create empty code page
    pub const fn new() -> Self {
        Self {
            in_use: false,
            code_page: 0,
            max_char_size: 1,
            default_char: b'?',
            lead_bytes: [[0; 2]; 5],
            name: [0; MAX_NAME_LEN],
        }
    }

    /// Check if byte is a lead byte
    pub fn is_lead_byte(&self, b: u8) -> bool {
        for pair in self.lead_bytes.iter() {
            if pair[0] == 0 && pair[1] == 0 {
                break;
            }
            if b >= pair[0] && b <= pair[1] {
                return true;
            }
        }
        false
    }
}

// ============================================================================
// Language Detection
// ============================================================================

/// Script detection result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptType {
    /// Unknown/neutral
    Unknown,
    /// Latin script
    Latin,
    /// Cyrillic script
    Cyrillic,
    /// Greek script
    Greek,
    /// Arabic script
    Arabic,
    /// Hebrew script
    Hebrew,
    /// Thai script
    Thai,
    /// Han script (CJK ideographs)
    Han,
    /// Hangul (Korean)
    Hangul,
    /// Hiragana (Japanese)
    Hiragana,
    /// Katakana (Japanese)
    Katakana,
}

// ============================================================================
// Global State
// ============================================================================

/// Global locale storage
static LOCALES: SpinLock<[LocaleInfo; MAX_LOCALES]> =
    SpinLock::new([const { LocaleInfo::new() }; MAX_LOCALES]);

/// Global code page storage
static CODE_PAGES: SpinLock<[CodePageInfo; MAX_CODE_PAGES]> =
    SpinLock::new([const { CodePageInfo::new() }; MAX_CODE_PAGES]);

/// System locale
static SYSTEM_LOCALE: SpinLock<u32> = SpinLock::new(0x0409); // en-US

/// User locale
static USER_LOCALE: SpinLock<u32> = SpinLock::new(0x0409); // en-US

/// Thread locale
static THREAD_LOCALE: SpinLock<u32> = SpinLock::new(0);

// ============================================================================
// Public API
// ============================================================================

/// Initialize multilingual support
pub fn init() {
    register_default_locales();
    register_default_code_pages();
    crate::serial_println!("[USER] Multilingual support initialized");
}

/// Register default locales
fn register_default_locales() {
    let defaults: &[(&[u8], u16, u16, u32)] = &[
        (b"English (United States)", LANG_ENGLISH, SUBLANG_ENGLISH_US, CP_WINDOWS_1252),
        (b"English (United Kingdom)", LANG_ENGLISH, SUBLANG_ENGLISH_UK, CP_WINDOWS_1252),
        (b"German (Germany)", LANG_GERMAN, SUBLANG_GERMAN, CP_WINDOWS_1252),
        (b"French (France)", LANG_FRENCH, SUBLANG_FRENCH, CP_WINDOWS_1252),
        (b"Spanish (Spain)", LANG_SPANISH, SUBLANG_SPANISH, CP_WINDOWS_1252),
        (b"Japanese (Japan)", LANG_JAPANESE, SUBLANG_DEFAULT, CP_SHIFT_JIS),
        (b"Chinese (Simplified)", LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED, CP_GB2312),
        (b"Chinese (Traditional)", LANG_CHINESE, SUBLANG_CHINESE_TRADITIONAL, CP_BIG5),
        (b"Korean (Korea)", LANG_KOREAN, SUBLANG_DEFAULT, CP_EUC_KR),
        (b"Russian (Russia)", LANG_RUSSIAN, SUBLANG_DEFAULT, CP_WINDOWS_1251),
        (b"Arabic (Saudi Arabia)", LANG_ARABIC, SUBLANG_DEFAULT, CP_WINDOWS_1256),
        (b"Hebrew (Israel)", LANG_HEBREW, SUBLANG_DEFAULT, CP_WINDOWS_1255),
    ];

    for &(name, lang, sublang, cp) in defaults.iter() {
        let _ = register_locale(name, lang, sublang, cp);
    }
}

/// Register default code pages
fn register_default_code_pages() {
    let defaults: &[(&[u8], u32, u32)] = &[
        (b"Windows-1252 Western", CP_WINDOWS_1252, 1),
        (b"Windows-1250 Central European", CP_WINDOWS_1250, 1),
        (b"Windows-1251 Cyrillic", CP_WINDOWS_1251, 1),
        (b"Windows-1253 Greek", CP_WINDOWS_1253, 1),
        (b"Windows-1254 Turkish", CP_WINDOWS_1254, 1),
        (b"Windows-1255 Hebrew", CP_WINDOWS_1255, 1),
        (b"Windows-1256 Arabic", CP_WINDOWS_1256, 1),
        (b"Shift-JIS Japanese", CP_SHIFT_JIS, 2),
        (b"GB2312 Chinese Simplified", CP_GB2312, 2),
        (b"Big5 Chinese Traditional", CP_BIG5, 2),
        (b"EUC-KR Korean", CP_EUC_KR, 2),
        (b"UTF-8", CP_UTF8, 4),
    ];

    for &(name, cp, max_size) in defaults.iter() {
        let _ = register_code_page(name, cp, max_size);
    }
}

/// Register locale
pub fn register_locale(name: &[u8], lang_id: u16, sublang_id: u16, code_page: u32) -> bool {
    let mut locales = LOCALES.lock();

    let lcid = make_lcid(lang_id, sublang_id);

    // Check if already exists
    for locale in locales.iter_mut() {
        if locale.in_use && locale.lcid == lcid {
            return true;
        }
    }

    // Add new
    for locale in locales.iter_mut() {
        if !locale.in_use {
            locale.in_use = true;
            locale.lcid = lcid;
            locale.lang_id = lang_id;
            locale.sublang_id = sublang_id;
            locale.code_page = code_page;
            locale.is_bidi = is_bidi_language(lang_id);
            locale.is_cjk = is_cjk_language(lang_id);

            let len = super::strhelp::str_len(name).min(MAX_NAME_LEN - 1);
            locale.name[..len].copy_from_slice(&name[..len]);
            locale.name[len] = 0;

            return true;
        }
    }

    false
}

/// Register code page
pub fn register_code_page(name: &[u8], code_page: u32, max_char_size: u32) -> bool {
    let mut pages = CODE_PAGES.lock();

    // Check if already exists
    for page in pages.iter_mut() {
        if page.in_use && page.code_page == code_page {
            return true;
        }
    }

    // Add new
    for page in pages.iter_mut() {
        if !page.in_use {
            page.in_use = true;
            page.code_page = code_page;
            page.max_char_size = max_char_size;
            page.default_char = b'?';

            // Set lead byte ranges for DBCS code pages
            match code_page {
                CP_SHIFT_JIS => {
                    page.lead_bytes[0] = [0x81, 0x9F];
                    page.lead_bytes[1] = [0xE0, 0xFC];
                }
                CP_GB2312 | CP_BIG5 => {
                    page.lead_bytes[0] = [0x81, 0xFE];
                }
                CP_EUC_KR => {
                    page.lead_bytes[0] = [0x81, 0xFE];
                }
                _ => {}
            }

            let len = super::strhelp::str_len(name).min(MAX_NAME_LEN - 1);
            page.name[..len].copy_from_slice(&name[..len]);
            page.name[len] = 0;

            return true;
        }
    }

    false
}

/// Make LCID from language and sublanguage
pub const fn make_lcid(lang_id: u16, sublang_id: u16) -> u32 {
    ((sublang_id as u32) << 10) | (lang_id as u32)
}

/// Get language ID from LCID
pub const fn lang_id_from_lcid(lcid: u32) -> u16 {
    (lcid & 0x3FF) as u16
}

/// Get sublanguage ID from LCID
pub const fn sublang_id_from_lcid(lcid: u32) -> u16 {
    ((lcid >> 10) & 0x3F) as u16
}

/// Check if language is bidirectional
pub fn is_bidi_language(lang_id: u16) -> bool {
    matches!(lang_id, LANG_ARABIC | LANG_HEBREW)
}

/// Check if language is CJK
pub fn is_cjk_language(lang_id: u16) -> bool {
    matches!(lang_id, LANG_CHINESE | LANG_JAPANESE | LANG_KOREAN)
}

/// Get system locale
pub fn get_system_default_lcid() -> u32 {
    *SYSTEM_LOCALE.lock()
}

/// Get user locale
pub fn get_user_default_lcid() -> u32 {
    *USER_LOCALE.lock()
}

/// Get thread locale
pub fn get_thread_locale() -> u32 {
    let lcid = *THREAD_LOCALE.lock();
    if lcid != 0 {
        lcid
    } else {
        get_user_default_lcid()
    }
}

/// Set thread locale
pub fn set_thread_locale(lcid: u32) -> bool {
    *THREAD_LOCALE.lock() = lcid;
    true
}

/// Get system language ID
pub fn get_system_default_lang_id() -> u16 {
    lang_id_from_lcid(get_system_default_lcid())
}

/// Get user language ID
pub fn get_user_default_lang_id() -> u16 {
    lang_id_from_lcid(get_user_default_lcid())
}

/// Get ACP (ANSI code page)
pub fn get_acp() -> u32 {
    let locales = LOCALES.lock();
    let lcid = get_user_default_lcid();

    for locale in locales.iter() {
        if locale.in_use && locale.lcid == lcid {
            return locale.code_page;
        }
    }

    CP_WINDOWS_1252
}

/// Get OEM code page
pub fn get_oem_cp() -> u32 {
    // Windows typically uses DOS code pages for OEM
    437 // US-DOS
}

/// Is code page valid
pub fn is_valid_code_page(code_page: u32) -> bool {
    let pages = CODE_PAGES.lock();

    for page in pages.iter() {
        if page.in_use && page.code_page == code_page {
            return true;
        }
    }

    false
}

/// Get code page info
pub fn get_cp_info(code_page: u32, info: &mut CodePageInfo) -> bool {
    let pages = CODE_PAGES.lock();

    for page in pages.iter() {
        if page.in_use && page.code_page == code_page {
            *info = *page;
            return true;
        }
    }

    false
}

/// Is lead byte (for DBCS code pages)
pub fn is_dbcs_lead_byte(code_page: u32, byte: u8) -> bool {
    let pages = CODE_PAGES.lock();

    for page in pages.iter() {
        if page.in_use && page.code_page == code_page {
            return page.is_lead_byte(byte);
        }
    }

    false
}

/// Detect script type from Unicode code point
pub fn detect_script(code_point: u32) -> ScriptType {
    match code_point {
        // Basic Latin + Latin Extended
        0x0041..=0x007A | 0x00C0..=0x024F => ScriptType::Latin,
        // Cyrillic
        0x0400..=0x04FF => ScriptType::Cyrillic,
        // Greek
        0x0370..=0x03FF => ScriptType::Greek,
        // Arabic
        0x0600..=0x06FF => ScriptType::Arabic,
        // Hebrew
        0x0590..=0x05FF => ScriptType::Hebrew,
        // Thai
        0x0E00..=0x0E7F => ScriptType::Thai,
        // CJK Unified Ideographs
        0x4E00..=0x9FFF => ScriptType::Han,
        // Hangul Syllables
        0xAC00..=0xD7AF => ScriptType::Hangul,
        // Hiragana
        0x3040..=0x309F => ScriptType::Hiragana,
        // Katakana
        0x30A0..=0x30FF => ScriptType::Katakana,
        _ => ScriptType::Unknown,
    }
}

/// Get locale info
pub fn get_locale_info(lcid: u32, info_type: u32, buffer: &mut [u8]) -> usize {
    let locales = LOCALES.lock();

    for locale in locales.iter() {
        if locale.in_use && locale.lcid == lcid {
            let data: &[u8] = match info_type {
                // LOCALE_ILANGUAGE - Language ID
                0x01 => {
                    // Return as hex string
                    buffer[0] = b'0';
                    buffer[1] = b'4';
                    buffer[2] = b'0';
                    buffer[3] = b'9';
                    buffer[4] = 0;
                    return 4;
                }
                // LOCALE_SLANGUAGE - Native language name
                0x02 => &locale.name,
                // LOCALE_SENGLANGUAGE - English language name
                0x1001 => &locale.name,
                // LOCALE_SABBREVLANGNAME - Abbreviated language name
                0x03 => b"ENU",
                // LOCALE_SCOUNTRY - Country name
                0x06 => b"United States",
                // LOCALE_SENGCOUNTRY - English country name
                0x1002 => b"United States",
                // LOCALE_SABBREVCTRYNAME - Abbreviated country name
                0x07 => b"USA",
                // LOCALE_IDEFAULTCODEPAGE - OEM code page
                0x0B => b"437",
                // LOCALE_IDEFAULTANSICODEPAGE - ANSI code page
                0x1004 => b"1252",
                _ => return 0,
            };

            let len = super::strhelp::str_len(data).min(buffer.len().saturating_sub(1));
            buffer[..len].copy_from_slice(&data[..len]);
            if len < buffer.len() {
                buffer[len] = 0;
            }
            return len;
        }
    }

    0
}

/// Convert character type (CT_CTYPE1)
pub fn get_string_type(locale: u32, info_type: u32, src: &[u8], dest: &mut [u16]) -> bool {
    let _ = locale;

    if info_type != 1 || dest.len() < src.len() {
        return false;
    }

    for (i, &ch) in src.iter().enumerate() {
        let mut flags = 0u16;

        if ch.is_ascii_uppercase() {
            flags |= C1_UPPER | C1_ALPHA;
        }
        if ch.is_ascii_lowercase() {
            flags |= C1_LOWER | C1_ALPHA;
        }
        if ch.is_ascii_digit() {
            flags |= C1_DIGIT;
        }
        if ch.is_ascii_whitespace() {
            flags |= C1_SPACE;
        }
        if ch.is_ascii_punctuation() {
            flags |= C1_PUNCT;
        }
        if ch < 0x20 {
            flags |= C1_CNTRL;
        }
        if ch == b' ' || ch == b'\t' {
            flags |= C1_BLANK;
        }
        if ch.is_ascii_hexdigit() {
            flags |= C1_XDIGIT;
        }
        if ch >= 0x20 {
            flags |= C1_DEFINED;
        }

        dest[i] = flags;
    }

    true
}

/// Multi-byte to wide char (simplified)
pub fn multi_byte_to_wide_char(
    code_page: u32,
    flags: u32,
    multi_byte_str: &[u8],
    wide_char_str: &mut [u16],
) -> i32 {
    let _ = (code_page, flags);

    // Simplified: just extend each byte
    let len = multi_byte_str.len().min(wide_char_str.len());

    for (i, &b) in multi_byte_str[..len].iter().enumerate() {
        wide_char_str[i] = b as u16;
    }

    len as i32
}

/// Wide char to multi-byte (simplified)
pub fn wide_char_to_multi_byte(
    code_page: u32,
    flags: u32,
    wide_char_str: &[u16],
    multi_byte_str: &mut [u8],
    default_char: Option<u8>,
    used_default_char: Option<&mut bool>,
) -> i32 {
    let _ = (code_page, flags);

    let default = default_char.unwrap_or(b'?');
    let len = wide_char_str.len().min(multi_byte_str.len());
    let mut used = false;

    for (i, &w) in wide_char_str[..len].iter().enumerate() {
        if w < 256 {
            multi_byte_str[i] = w as u8;
        } else {
            multi_byte_str[i] = default;
            used = true;
        }
    }

    if let Some(flag) = used_default_char {
        *flag = used;
    }

    len as i32
}

/// Is text Unicode
pub fn is_text_unicode(buffer: &[u8], tests: u32) -> (bool, u32) {
    let _ = tests;

    // Check for BOM
    if buffer.len() >= 2 {
        if buffer[0] == 0xFF && buffer[1] == 0xFE {
            return (true, 0x0001); // IS_TEXT_UNICODE_SIGNATURE
        }
        if buffer[0] == 0xFE && buffer[1] == 0xFF {
            return (true, 0x0002); // IS_TEXT_UNICODE_REVERSE_SIGNATURE
        }
    }

    // Check for null bytes (common in UTF-16)
    let mut has_null = false;
    for b in buffer.iter() {
        if *b == 0 {
            has_null = true;
            break;
        }
    }

    if has_null {
        (true, 0x0100) // IS_TEXT_UNICODE_NULL_BYTES
    } else {
        (false, 0)
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> MultiLangStats {
    let locales = LOCALES.lock();
    let pages = CODE_PAGES.lock();

    let mut locale_count = 0;
    let mut page_count = 0;

    for locale in locales.iter() {
        if locale.in_use {
            locale_count += 1;
        }
    }

    for page in pages.iter() {
        if page.in_use {
            page_count += 1;
        }
    }

    MultiLangStats {
        max_locales: MAX_LOCALES,
        registered_locales: locale_count,
        max_code_pages: MAX_CODE_PAGES,
        registered_code_pages: page_count,
        system_lcid: get_system_default_lcid(),
        user_lcid: get_user_default_lcid(),
    }
}

/// Multilingual statistics
#[derive(Debug, Clone, Copy)]
pub struct MultiLangStats {
    pub max_locales: usize,
    pub registered_locales: usize,
    pub max_code_pages: usize,
    pub registered_code_pages: usize,
    pub system_lcid: u32,
    pub user_lcid: u32,
}
