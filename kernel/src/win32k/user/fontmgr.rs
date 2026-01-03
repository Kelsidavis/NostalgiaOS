//! Font Management
//!
//! Implements Windows font management APIs for adding, removing, and
//! enumerating fonts.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/wingdi.h` - Font API definitions
//! - `windows/core/ntgdi/gre/fontsup.cxx` - Font support
//! - `windows/core/ntgdi/fondrv/` - Font driver

use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum installed fonts
const MAX_FONTS: usize = 256;

/// Maximum font family name length
const MAX_FAMILY_NAME: usize = 64;

/// Maximum font face name length
const MAX_FACE_NAME: usize = 64;

/// Maximum font file path length
const MAX_FONT_PATH: usize = 260;

/// Maximum font files
const MAX_FONT_FILES: usize = 128;

// ============================================================================
// Font Types
// ============================================================================

// Font resource flags
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct FontResourceFlags: u32 {
        /// Private font resource
        const FR_PRIVATE = 0x10;
        /// Not enumerable
        const FR_NOT_ENUM = 0x20;
    }
}

/// Font weights
pub mod weight {
    pub const FW_DONTCARE: u32 = 0;
    pub const FW_THIN: u32 = 100;
    pub const FW_EXTRALIGHT: u32 = 200;
    pub const FW_ULTRALIGHT: u32 = 200;
    pub const FW_LIGHT: u32 = 300;
    pub const FW_NORMAL: u32 = 400;
    pub const FW_REGULAR: u32 = 400;
    pub const FW_MEDIUM: u32 = 500;
    pub const FW_SEMIBOLD: u32 = 600;
    pub const FW_DEMIBOLD: u32 = 600;
    pub const FW_BOLD: u32 = 700;
    pub const FW_EXTRABOLD: u32 = 800;
    pub const FW_ULTRABOLD: u32 = 800;
    pub const FW_HEAVY: u32 = 900;
    pub const FW_BLACK: u32 = 900;
}

/// Font charsets
pub mod charset {
    pub const ANSI_CHARSET: u8 = 0;
    pub const DEFAULT_CHARSET: u8 = 1;
    pub const SYMBOL_CHARSET: u8 = 2;
    pub const SHIFTJIS_CHARSET: u8 = 128;
    pub const HANGEUL_CHARSET: u8 = 129;
    pub const HANGUL_CHARSET: u8 = 129;
    pub const GB2312_CHARSET: u8 = 134;
    pub const CHINESEBIG5_CHARSET: u8 = 136;
    pub const OEM_CHARSET: u8 = 255;
    pub const JOHAB_CHARSET: u8 = 130;
    pub const HEBREW_CHARSET: u8 = 177;
    pub const ARABIC_CHARSET: u8 = 178;
    pub const GREEK_CHARSET: u8 = 161;
    pub const TURKISH_CHARSET: u8 = 162;
    pub const VIETNAMESE_CHARSET: u8 = 163;
    pub const THAI_CHARSET: u8 = 222;
    pub const EASTEUROPE_CHARSET: u8 = 238;
    pub const RUSSIAN_CHARSET: u8 = 204;
    pub const MAC_CHARSET: u8 = 77;
    pub const BALTIC_CHARSET: u8 = 186;
}

/// Font pitch and family
pub mod pitch_family {
    pub const DEFAULT_PITCH: u8 = 0;
    pub const FIXED_PITCH: u8 = 1;
    pub const VARIABLE_PITCH: u8 = 2;
    pub const MONO_FONT: u8 = 8;

    pub const FF_DONTCARE: u8 = 0 << 4;
    pub const FF_ROMAN: u8 = 1 << 4;
    pub const FF_SWISS: u8 = 2 << 4;
    pub const FF_MODERN: u8 = 3 << 4;
    pub const FF_SCRIPT: u8 = 4 << 4;
    pub const FF_DECORATIVE: u8 = 5 << 4;
}

/// Font output precision
pub mod out_precision {
    pub const OUT_DEFAULT_PRECIS: u8 = 0;
    pub const OUT_STRING_PRECIS: u8 = 1;
    pub const OUT_CHARACTER_PRECIS: u8 = 2;
    pub const OUT_STROKE_PRECIS: u8 = 3;
    pub const OUT_TT_PRECIS: u8 = 4;
    pub const OUT_DEVICE_PRECIS: u8 = 5;
    pub const OUT_RASTER_PRECIS: u8 = 6;
    pub const OUT_TT_ONLY_PRECIS: u8 = 7;
    pub const OUT_OUTLINE_PRECIS: u8 = 8;
    pub const OUT_SCREEN_OUTLINE_PRECIS: u8 = 9;
    pub const OUT_PS_ONLY_PRECIS: u8 = 10;
}

/// Font clip precision
pub mod clip_precision {
    pub const CLIP_DEFAULT_PRECIS: u8 = 0;
    pub const CLIP_CHARACTER_PRECIS: u8 = 1;
    pub const CLIP_STROKE_PRECIS: u8 = 2;
    pub const CLIP_MASK: u8 = 0x0F;
    pub const CLIP_LH_ANGLES: u8 = 1 << 4;
    pub const CLIP_TT_ALWAYS: u8 = 2 << 4;
    pub const CLIP_DFA_DISABLE: u8 = 4 << 4;
    pub const CLIP_EMBEDDED: u8 = 8 << 4;
}

/// Font quality
pub mod quality {
    pub const DEFAULT_QUALITY: u8 = 0;
    pub const DRAFT_QUALITY: u8 = 1;
    pub const PROOF_QUALITY: u8 = 2;
    pub const NONANTIALIASED_QUALITY: u8 = 3;
    pub const ANTIALIASED_QUALITY: u8 = 4;
    pub const CLEARTYPE_QUALITY: u8 = 5;
    pub const CLEARTYPE_NATURAL_QUALITY: u8 = 6;
}

/// Font types for enumeration
pub mod font_type {
    pub const RASTER_FONTTYPE: u32 = 0x0001;
    pub const DEVICE_FONTTYPE: u32 = 0x0002;
    pub const TRUETYPE_FONTTYPE: u32 = 0x0004;
}

// ============================================================================
// Font Structures
// ============================================================================

/// Logical font definition
#[derive(Debug, Clone, Copy)]
pub struct LogFont {
    pub height: i32,
    pub width: i32,
    pub escapement: i32,
    pub orientation: i32,
    pub weight: u32,
    pub italic: bool,
    pub underline: bool,
    pub strikeout: bool,
    pub charset: u8,
    pub out_precision: u8,
    pub clip_precision: u8,
    pub quality: u8,
    pub pitch_and_family: u8,
    pub face_name: [u8; MAX_FACE_NAME],
}

impl LogFont {
    pub const fn new() -> Self {
        Self {
            height: 0,
            width: 0,
            escapement: 0,
            orientation: 0,
            weight: weight::FW_NORMAL,
            italic: false,
            underline: false,
            strikeout: false,
            charset: charset::DEFAULT_CHARSET,
            out_precision: out_precision::OUT_DEFAULT_PRECIS,
            clip_precision: clip_precision::CLIP_DEFAULT_PRECIS,
            quality: quality::DEFAULT_QUALITY,
            pitch_and_family: pitch_family::DEFAULT_PITCH | pitch_family::FF_DONTCARE,
            face_name: [0u8; MAX_FACE_NAME],
        }
    }

    pub fn set_face_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_FACE_NAME - 1);
        self.face_name[..len].copy_from_slice(&name[..len]);
        self.face_name[len] = 0;
    }
}

impl Default for LogFont {
    fn default() -> Self {
        Self::new()
    }
}

/// Text metric information
#[derive(Debug, Clone, Copy, Default)]
pub struct TextMetric {
    pub height: i32,
    pub ascent: i32,
    pub descent: i32,
    pub internal_leading: i32,
    pub external_leading: i32,
    pub ave_char_width: i32,
    pub max_char_width: i32,
    pub weight: u32,
    pub overhang: i32,
    pub digitized_aspect_x: i32,
    pub digitized_aspect_y: i32,
    pub first_char: u8,
    pub last_char: u8,
    pub default_char: u8,
    pub break_char: u8,
    pub italic: bool,
    pub underlined: bool,
    pub struck_out: bool,
    pub pitch_and_family: u8,
    pub charset: u8,
}

/// New text metric (extended)
#[derive(Debug, Clone, Copy, Default)]
pub struct NewTextMetric {
    pub tm: TextMetric,
    pub flags: u32,
    pub size_em: u32,
    pub cell_height: u32,
    pub ave_width: u32,
}

/// Font enumeration info
#[derive(Debug, Clone)]
pub struct EnumLogFontEx {
    pub log_font: LogFont,
    pub full_name: [u8; MAX_FACE_NAME],
    pub style: [u8; 32],
    pub script: [u8; 32],
}

impl EnumLogFontEx {
    pub const fn new() -> Self {
        Self {
            log_font: LogFont::new(),
            full_name: [0u8; MAX_FACE_NAME],
            style: [0u8; 32],
            script: [0u8; 32],
        }
    }
}

impl Default for EnumLogFontEx {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Font File State
// ============================================================================

/// Installed font file
#[derive(Debug)]
struct FontFile {
    in_use: bool,
    path: [u8; MAX_FONT_PATH],
    flags: FontResourceFlags,
    font_count: u32,
    owner_process: u32,
}

impl FontFile {
    const fn new() -> Self {
        Self {
            in_use: false,
            path: [0u8; MAX_FONT_PATH],
            flags: FontResourceFlags::empty(),
            font_count: 0,
            owner_process: 0,
        }
    }
}

// ============================================================================
// Font Entry State
// ============================================================================

/// Registered font entry
#[derive(Debug)]
struct FontEntry {
    in_use: bool,
    family_name: [u8; MAX_FAMILY_NAME],
    face_name: [u8; MAX_FACE_NAME],
    weight: u32,
    italic: bool,
    charset: u8,
    font_type: u32,
    file_index: usize,
    enumerable: bool,
}

impl FontEntry {
    const fn new() -> Self {
        Self {
            in_use: false,
            family_name: [0u8; MAX_FAMILY_NAME],
            face_name: [0u8; MAX_FACE_NAME],
            weight: weight::FW_NORMAL,
            italic: false,
            charset: charset::DEFAULT_CHARSET,
            font_type: font_type::TRUETYPE_FONTTYPE,
            file_index: 0,
            enumerable: true,
        }
    }
}

// ============================================================================
// Font Link State
// ============================================================================

/// Font linking entry for fallback fonts
#[derive(Debug)]
struct FontLink {
    in_use: bool,
    base_font: [u8; MAX_FACE_NAME],
    linked_font: [u8; MAX_FACE_NAME],
    charset: u8,
}

impl FontLink {
    const fn new() -> Self {
        Self {
            in_use: false,
            base_font: [0u8; MAX_FACE_NAME],
            linked_font: [0u8; MAX_FACE_NAME],
            charset: charset::DEFAULT_CHARSET,
        }
    }
}

/// Maximum font links
const MAX_FONT_LINKS: usize = 64;

// ============================================================================
// State
// ============================================================================

static FONT_MGR_INITIALIZED: AtomicBool = AtomicBool::new(false);
static FONT_FILES: SpinLock<[FontFile; MAX_FONT_FILES]> = SpinLock::new(
    [const { FontFile::new() }; MAX_FONT_FILES]
);
static FONTS: SpinLock<[FontEntry; MAX_FONTS]> = SpinLock::new(
    [const { FontEntry::new() }; MAX_FONTS]
);
static FONT_LINKS: SpinLock<[FontLink; MAX_FONT_LINKS]> = SpinLock::new(
    [const { FontLink::new() }; MAX_FONT_LINKS]
);
static FONT_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize font management subsystem
pub fn init() {
    if FONT_MGR_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[FONTMGR] Initializing font management...");

    // Register default system fonts
    register_default_fonts();

    crate::serial_println!("[FONTMGR] Font management initialized");
}

/// Register default system fonts
fn register_default_fonts() {
    // Register core Windows fonts
    let defaults: &[(&[u8], u32, bool, u8)] = &[
        (b"System", weight::FW_BOLD, false, charset::ANSI_CHARSET),
        (b"Terminal", weight::FW_NORMAL, false, charset::OEM_CHARSET),
        (b"Fixedsys", weight::FW_NORMAL, false, charset::ANSI_CHARSET),
        (b"Tahoma", weight::FW_NORMAL, false, charset::ANSI_CHARSET),
        (b"Tahoma", weight::FW_BOLD, false, charset::ANSI_CHARSET),
        (b"Microsoft Sans Serif", weight::FW_NORMAL, false, charset::ANSI_CHARSET),
        (b"Arial", weight::FW_NORMAL, false, charset::ANSI_CHARSET),
        (b"Arial", weight::FW_BOLD, false, charset::ANSI_CHARSET),
        (b"Arial", weight::FW_NORMAL, true, charset::ANSI_CHARSET),
        (b"Times New Roman", weight::FW_NORMAL, false, charset::ANSI_CHARSET),
        (b"Times New Roman", weight::FW_BOLD, false, charset::ANSI_CHARSET),
        (b"Courier New", weight::FW_NORMAL, false, charset::ANSI_CHARSET),
        (b"Courier New", weight::FW_BOLD, false, charset::ANSI_CHARSET),
        (b"Lucida Console", weight::FW_NORMAL, false, charset::ANSI_CHARSET),
        (b"Segoe UI", weight::FW_NORMAL, false, charset::ANSI_CHARSET),
        (b"Segoe UI", weight::FW_BOLD, false, charset::ANSI_CHARSET),
        (b"Marlett", weight::FW_NORMAL, false, charset::SYMBOL_CHARSET),
    ];

    let mut fonts = FONTS.lock();

    for (i, &(name, wt, italic, cs)) in defaults.iter().enumerate() {
        if i >= MAX_FONTS {
            break;
        }

        let font = &mut fonts[i];
        font.in_use = true;

        let len = name.len().min(MAX_FAMILY_NAME - 1);
        font.family_name[..len].copy_from_slice(&name[..len]);
        font.family_name[len] = 0;
        font.face_name[..len].copy_from_slice(&name[..len]);
        font.face_name[len] = 0;

        font.weight = wt;
        font.italic = italic;
        font.charset = cs;
        font.font_type = font_type::TRUETYPE_FONTTYPE;
        font.enumerable = true;

        FONT_COUNT.fetch_add(1, Ordering::SeqCst);
    }
}

// ============================================================================
// Font Resource Functions
// ============================================================================

/// Add a font resource from file
pub fn add_font_resource(path: &[u8]) -> u32 {
    add_font_resource_ex(path, FontResourceFlags::empty())
}

/// Add a font resource with flags
pub fn add_font_resource_ex(path: &[u8], flags: FontResourceFlags) -> u32 {
    let mut files = FONT_FILES.lock();

    // Find free slot
    let slot_idx = files.iter().position(|f| !f.in_use);
    let idx = match slot_idx {
        Some(i) => i,
        None => return 0,
    };

    let file = &mut files[idx];
    file.in_use = true;
    file.flags = flags;

    let path_len = path.len().min(MAX_FONT_PATH - 1);
    file.path[..path_len].copy_from_slice(&path[..path_len]);
    file.path[path_len] = 0;

    // In a real implementation, this would parse the font file
    // and add entries to the FONTS table
    file.font_count = 1;

    crate::serial_println!("[FONTMGR] Added font resource");

    file.font_count
}

/// Remove a font resource
pub fn remove_font_resource(path: &[u8]) -> bool {
    remove_font_resource_ex(path, FontResourceFlags::empty())
}

/// Remove a font resource with flags
pub fn remove_font_resource_ex(path: &[u8], flags: FontResourceFlags) -> bool {
    let _ = flags;

    let mut files = FONT_FILES.lock();

    for file in files.iter_mut() {
        if !file.in_use {
            continue;
        }

        if name_matches(&file.path, path) {
            file.in_use = false;
            crate::serial_println!("[FONTMGR] Removed font resource");
            return true;
        }
    }

    false
}

/// Add font memory resource
pub fn add_font_memory_resource_ex(
    data: &[u8],
    flags: FontResourceFlags,
) -> Option<u32> {
    let _ = (data, flags);

    // Would load font from memory
    crate::serial_println!("[FONTMGR] Added font from memory");

    Some(1)
}

/// Remove font memory resource
pub fn remove_font_memory_resource_ex(handle: u32) -> bool {
    let _ = handle;

    true
}

// ============================================================================
// Font Enumeration Functions
// ============================================================================

/// Font enumeration callback type
pub type EnumFontCallback = fn(
    log_font: &EnumLogFontEx,
    text_metric: &NewTextMetric,
    font_type: u32,
    lparam: usize,
) -> i32;

/// Enumerate font families
pub fn enum_font_families(
    family: Option<&[u8]>,
    callback: EnumFontCallback,
    lparam: usize,
) -> i32 {
    enum_font_families_ex(family, charset::DEFAULT_CHARSET, callback, lparam)
}

/// Enumerate font families (extended)
pub fn enum_font_families_ex(
    family: Option<&[u8]>,
    charset_filter: u8,
    callback: EnumFontCallback,
    lparam: usize,
) -> i32 {
    let fonts = FONTS.lock();

    let mut count = 0i32;

    for font in fonts.iter() {
        if !font.in_use || !font.enumerable {
            continue;
        }

        // Filter by family if specified
        if let Some(fam) = family {
            if !name_matches(&font.family_name, fam) {
                continue;
            }
        }

        // Filter by charset
        if charset_filter != charset::DEFAULT_CHARSET && font.charset != charset_filter {
            continue;
        }

        // Build enumeration structures
        let mut elf = EnumLogFontEx::new();
        elf.log_font.weight = font.weight;
        elf.log_font.italic = font.italic;
        elf.log_font.charset = font.charset;

        let face_len = str_len(&font.face_name);
        elf.log_font.face_name[..face_len].copy_from_slice(&font.face_name[..face_len]);
        elf.full_name[..face_len].copy_from_slice(&font.face_name[..face_len]);

        let ntm = NewTextMetric::default();

        // Call the callback
        let result = callback(&elf, &ntm, font.font_type, lparam);
        count += 1;

        if result == 0 {
            break;
        }
    }

    count
}

/// Get number of fonts for a family
pub fn get_font_family_count(family: &[u8]) -> u32 {
    let fonts = FONTS.lock();

    let mut count = 0u32;

    for font in fonts.iter() {
        if font.in_use && name_matches(&font.family_name, family) {
            count += 1;
        }
    }

    count
}

// ============================================================================
// Font Linking Functions
// ============================================================================

/// Add a font link for fallback
pub fn add_font_link(base_font: &[u8], linked_font: &[u8], charset_val: u8) -> bool {
    let mut links = FONT_LINKS.lock();

    // Find free slot
    let slot_idx = links.iter().position(|l| !l.in_use);
    let idx = match slot_idx {
        Some(i) => i,
        None => return false,
    };

    let link = &mut links[idx];
    link.in_use = true;

    let base_len = base_font.len().min(MAX_FACE_NAME - 1);
    link.base_font[..base_len].copy_from_slice(&base_font[..base_len]);
    link.base_font[base_len] = 0;

    let linked_len = linked_font.len().min(MAX_FACE_NAME - 1);
    link.linked_font[..linked_len].copy_from_slice(&linked_font[..linked_len]);
    link.linked_font[linked_len] = 0;

    link.charset = charset_val;

    true
}

/// Remove a font link
pub fn remove_font_link(base_font: &[u8], linked_font: &[u8]) -> bool {
    let mut links = FONT_LINKS.lock();

    for link in links.iter_mut() {
        if !link.in_use {
            continue;
        }

        if name_matches(&link.base_font, base_font)
            && name_matches(&link.linked_font, linked_font)
        {
            link.in_use = false;
            return true;
        }
    }

    false
}

/// Get linked fonts for a base font
pub fn get_font_links(base_font: &[u8], linked: &mut [[u8; MAX_FACE_NAME]]) -> usize {
    let links = FONT_LINKS.lock();

    let mut count = 0;

    for link in links.iter() {
        if !link.in_use {
            continue;
        }

        if name_matches(&link.base_font, base_font) {
            if count < linked.len() {
                let len = str_len(&link.linked_font);
                linked[count][..len].copy_from_slice(&link.linked_font[..len]);
                linked[count][len] = 0;
                count += 1;
            }
        }
    }

    count
}

// ============================================================================
// Font Substitution
// ============================================================================

/// Font substitution entry
#[derive(Debug)]
struct FontSubstitution {
    in_use: bool,
    original: [u8; MAX_FACE_NAME],
    substitute: [u8; MAX_FACE_NAME],
}

impl FontSubstitution {
    const fn new() -> Self {
        Self {
            in_use: false,
            original: [0u8; MAX_FACE_NAME],
            substitute: [0u8; MAX_FACE_NAME],
        }
    }
}

const MAX_SUBSTITUTIONS: usize = 64;

static SUBSTITUTIONS: SpinLock<[FontSubstitution; MAX_SUBSTITUTIONS]> = SpinLock::new(
    [const { FontSubstitution::new() }; MAX_SUBSTITUTIONS]
);

/// Add font substitution
pub fn add_font_substitution(original: &[u8], substitute: &[u8]) -> bool {
    let mut subs = SUBSTITUTIONS.lock();

    let slot_idx = subs.iter().position(|s| !s.in_use);
    let idx = match slot_idx {
        Some(i) => i,
        None => return false,
    };

    let sub = &mut subs[idx];
    sub.in_use = true;

    let orig_len = original.len().min(MAX_FACE_NAME - 1);
    sub.original[..orig_len].copy_from_slice(&original[..orig_len]);
    sub.original[orig_len] = 0;

    let sub_len = substitute.len().min(MAX_FACE_NAME - 1);
    sub.substitute[..sub_len].copy_from_slice(&substitute[..sub_len]);
    sub.substitute[sub_len] = 0;

    true
}

/// Get font substitution
pub fn get_font_substitution(original: &[u8], substitute: &mut [u8]) -> bool {
    let subs = SUBSTITUTIONS.lock();

    for sub in subs.iter() {
        if !sub.in_use {
            continue;
        }

        if name_matches(&sub.original, original) {
            let len = str_len(&sub.substitute);
            let copy_len = len.min(substitute.len());
            substitute[..copy_len].copy_from_slice(&sub.substitute[..copy_len]);
            if copy_len < substitute.len() {
                substitute[copy_len] = 0;
            }
            return true;
        }
    }

    false
}

// ============================================================================
// Font Info Functions
// ============================================================================

/// Get font data from a logical font
pub fn get_font_data(log_font: &LogFont) -> Option<TextMetric> {
    let fonts = FONTS.lock();

    // Find matching font
    for font in fonts.iter() {
        if !font.in_use {
            continue;
        }

        if !name_matches(&font.face_name, &log_font.face_name) {
            continue;
        }

        // Check weight and italic match (or close enough)
        let weight_diff = (font.weight as i32 - log_font.weight as i32).abs();
        if weight_diff > 100 {
            continue;
        }

        if font.italic != log_font.italic {
            continue;
        }

        // Build text metrics
        let height = if log_font.height != 0 {
            log_font.height.abs()
        } else {
            12 // Default height
        };

        return Some(TextMetric {
            height,
            ascent: height * 80 / 100,
            descent: height * 20 / 100,
            internal_leading: 0,
            external_leading: 0,
            ave_char_width: height * 40 / 100,
            max_char_width: height,
            weight: font.weight,
            overhang: 0,
            digitized_aspect_x: 96,
            digitized_aspect_y: 96,
            first_char: 0x20,
            last_char: 0xFF,
            default_char: 0x3F, // '?'
            break_char: 0x20,   // ' '
            italic: font.italic,
            underlined: log_font.underline,
            struck_out: log_font.strikeout,
            pitch_and_family: log_font.pitch_and_family,
            charset: font.charset,
        });
    }

    None
}

/// Check if font exists
pub fn font_exists(face_name: &[u8]) -> bool {
    let fonts = FONTS.lock();

    fonts.iter().any(|f| f.in_use && name_matches(&f.face_name, face_name))
}

/// Get default font for charset
pub fn get_default_font(charset_val: u8) -> Option<[u8; MAX_FACE_NAME]> {
    match charset_val {
        charset::ANSI_CHARSET => {
            let mut name = [0u8; MAX_FACE_NAME];
            let n = b"Tahoma";
            name[..n.len()].copy_from_slice(n);
            Some(name)
        }
        charset::SYMBOL_CHARSET => {
            let mut name = [0u8; MAX_FACE_NAME];
            let n = b"Symbol";
            name[..n.len()].copy_from_slice(n);
            Some(name)
        }
        charset::OEM_CHARSET => {
            let mut name = [0u8; MAX_FACE_NAME];
            let n = b"Terminal";
            name[..n.len()].copy_from_slice(n);
            Some(name)
        }
        _ => {
            let mut name = [0u8; MAX_FACE_NAME];
            let n = b"Arial";
            name[..n.len()].copy_from_slice(n);
            Some(name)
        }
    }
}

// ============================================================================
// Font Smoothing
// ============================================================================

/// Font smoothing type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FontSmoothingType {
    #[default]
    None = 0,
    Standard = 1,
    ClearType = 2,
}

static FONT_SMOOTHING: SpinLock<FontSmoothingType> = SpinLock::new(FontSmoothingType::ClearType);
static FONT_SMOOTHING_CONTRAST: SpinLock<u32> = SpinLock::new(1400);
static FONT_SMOOTHING_ORIENTATION: SpinLock<u32> = SpinLock::new(1); // RGB

/// Get font smoothing type
pub fn get_font_smoothing_type() -> FontSmoothingType {
    *FONT_SMOOTHING.lock()
}

/// Set font smoothing type
pub fn set_font_smoothing_type(smoothing: FontSmoothingType) {
    *FONT_SMOOTHING.lock() = smoothing;
}

/// Get ClearType contrast
pub fn get_cleartype_contrast() -> u32 {
    *FONT_SMOOTHING_CONTRAST.lock()
}

/// Set ClearType contrast
pub fn set_cleartype_contrast(contrast: u32) {
    *FONT_SMOOTHING_CONTRAST.lock() = contrast.min(2200).max(1000);
}

/// Get ClearType orientation (1=RGB, 2=BGR)
pub fn get_cleartype_orientation() -> u32 {
    *FONT_SMOOTHING_ORIENTATION.lock()
}

/// Set ClearType orientation
pub fn set_cleartype_orientation(orientation: u32) {
    if orientation == 1 || orientation == 2 {
        *FONT_SMOOTHING_ORIENTATION.lock() = orientation;
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn str_len(s: &[u8]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

fn name_matches(stored: &[u8], search: &[u8]) -> bool {
    let stored_len = str_len(stored);
    let search_len = str_len(search);

    if stored_len != search_len {
        return false;
    }

    for i in 0..stored_len {
        if stored[i].to_ascii_uppercase() != search[i].to_ascii_uppercase() {
            return false;
        }
    }

    true
}

// ============================================================================
// Statistics
// ============================================================================

/// Font management statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct FontStats {
    pub initialized: bool,
    pub font_count: u32,
    pub font_file_count: u32,
    pub font_link_count: u32,
    pub substitution_count: u32,
}

/// Get font management statistics
pub fn get_stats() -> FontStats {
    let files = FONT_FILES.lock();
    let links = FONT_LINKS.lock();
    let subs = SUBSTITUTIONS.lock();

    let file_count = files.iter().filter(|f| f.in_use).count() as u32;
    let link_count = links.iter().filter(|l| l.in_use).count() as u32;
    let sub_count = subs.iter().filter(|s| s.in_use).count() as u32;

    FontStats {
        initialized: FONT_MGR_INITIALIZED.load(Ordering::Relaxed),
        font_count: FONT_COUNT.load(Ordering::Relaxed),
        font_file_count: file_count,
        font_link_count: link_count,
        substitution_count: sub_count,
    }
}
