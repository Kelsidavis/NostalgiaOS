//! Fonts Control Panel
//!
//! Kernel-mode font management following Windows NT patterns.
//! Provides font enumeration, installation, removal, and preview.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/cpls/fonts/` - Fonts control panel

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// Constants
// ============================================================================

/// Maximum fonts
const MAX_FONTS: usize = 256;

/// Maximum font name length
const MAX_FONT_NAME: usize = 64;

/// Maximum font file path
const MAX_FONT_PATH: usize = 260;

/// Maximum font family name
const MAX_FAMILY_NAME: usize = 64;

/// Font types
pub mod font_type {
    /// TrueType font
    pub const TRUETYPE: u32 = 0x0004;
    /// OpenType font
    pub const OPENTYPE: u32 = 0x0008;
    /// Raster/bitmap font
    pub const RASTER: u32 = 0x0001;
    /// Vector font
    pub const VECTOR: u32 = 0x0002;
    /// Device font
    pub const DEVICE: u32 = 0x0010;
    /// PostScript font
    pub const POSTSCRIPT: u32 = 0x0020;
}

/// Font weights
pub mod font_weight {
    pub const THIN: u32 = 100;
    pub const EXTRALIGHT: u32 = 200;
    pub const LIGHT: u32 = 300;
    pub const REGULAR: u32 = 400;
    pub const MEDIUM: u32 = 500;
    pub const SEMIBOLD: u32 = 600;
    pub const BOLD: u32 = 700;
    pub const EXTRABOLD: u32 = 800;
    pub const BLACK: u32 = 900;
}

/// Font character sets
pub mod charset {
    pub const ANSI: u8 = 0;
    pub const DEFAULT: u8 = 1;
    pub const SYMBOL: u8 = 2;
    pub const SHIFTJIS: u8 = 128;
    pub const HANGEUL: u8 = 129;
    pub const GB2312: u8 = 134;
    pub const CHINESEBIG5: u8 = 136;
    pub const OEM: u8 = 255;
    pub const JOHAB: u8 = 130;
    pub const HEBREW: u8 = 177;
    pub const ARABIC: u8 = 178;
    pub const GREEK: u8 = 161;
    pub const TURKISH: u8 = 162;
    pub const VIETNAMESE: u8 = 163;
    pub const THAI: u8 = 222;
    pub const EASTEUROPE: u8 = 238;
    pub const RUSSIAN: u8 = 204;
    pub const BALTIC: u8 = 186;
}

/// Font pitch and family
pub mod pitch_family {
    pub const DEFAULT_PITCH: u8 = 0;
    pub const FIXED_PITCH: u8 = 1;
    pub const VARIABLE_PITCH: u8 = 2;

    pub const FF_DONTCARE: u8 = 0 << 4;
    pub const FF_ROMAN: u8 = 1 << 4;
    pub const FF_SWISS: u8 = 2 << 4;
    pub const FF_MODERN: u8 = 3 << 4;
    pub const FF_SCRIPT: u8 = 4 << 4;
    pub const FF_DECORATIVE: u8 = 5 << 4;
}

// ============================================================================
// Types
// ============================================================================

/// Font information
#[derive(Clone, Copy)]
pub struct FontInfo {
    /// Font name (display name)
    pub name: [u8; MAX_FONT_NAME],
    /// Name length
    pub name_len: u8,
    /// Family name
    pub family: [u8; MAX_FAMILY_NAME],
    /// Family length
    pub family_len: u8,
    /// File path
    pub path: [u8; MAX_FONT_PATH],
    /// Path length
    pub path_len: u16,
    /// Font type (font_type flags)
    pub font_type: u32,
    /// Weight
    pub weight: u32,
    /// Italic
    pub italic: bool,
    /// Underline
    pub underline: bool,
    /// Strikeout
    pub strikeout: bool,
    /// Character set
    pub charset: u8,
    /// Pitch and family
    pub pitch_family: u8,
    /// File size in bytes
    pub file_size: u64,
    /// Version string
    pub version: [u8; 32],
    /// Version length
    pub version_len: u8,
    /// Is hidden font
    pub hidden: bool,
}

impl FontInfo {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_FONT_NAME],
            name_len: 0,
            family: [0; MAX_FAMILY_NAME],
            family_len: 0,
            path: [0; MAX_FONT_PATH],
            path_len: 0,
            font_type: font_type::TRUETYPE,
            weight: font_weight::REGULAR,
            italic: false,
            underline: false,
            strikeout: false,
            charset: charset::ANSI,
            pitch_family: pitch_family::DEFAULT_PITCH,
            file_size: 0,
            version: [0; 32],
            version_len: 0,
            hidden: false,
        }
    }
}

/// Font filter for enumeration
#[derive(Clone, Copy)]
pub struct FontFilter {
    /// Include TrueType
    pub truetype: bool,
    /// Include OpenType
    pub opentype: bool,
    /// Include raster
    pub raster: bool,
    /// Include hidden
    pub hidden: bool,
    /// Character set filter (charset::DEFAULT for all)
    pub charset: u8,
}

impl FontFilter {
    pub const fn all() -> Self {
        Self {
            truetype: true,
            opentype: true,
            raster: true,
            hidden: false,
            charset: charset::DEFAULT,
        }
    }
}

/// Fonts dialog state
struct FontsDialog {
    /// Parent window
    parent: HWND,
    /// Selected font index
    selected: i32,
    /// View mode (0=large icons, 1=list, 2=details)
    view_mode: u32,
    /// Sort by (0=name, 1=type, 2=size)
    sort_by: u32,
    /// Current filter
    filter: FontFilter,
}

impl FontsDialog {
    const fn new() -> Self {
        Self {
            parent: UserHandle::NULL,
            selected: -1,
            view_mode: 0,
            sort_by: 0,
            filter: FontFilter::all(),
        }
    }
}

// ============================================================================
// Static State
// ============================================================================

/// Module initialized
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Installed fonts
static FONTS: SpinLock<[FontInfo; MAX_FONTS]> =
    SpinLock::new([const { FontInfo::new() }; MAX_FONTS]);

/// Font count
static FONT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Dialog state
static DIALOG: SpinLock<FontsDialog> = SpinLock::new(FontsDialog::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize fonts control panel
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Initialize default system fonts
    init_system_fonts();

    crate::serial_println!("[FONTSCPL] Fonts control panel initialized");
}

/// Initialize system fonts
fn init_system_fonts() {
    let mut fonts = FONTS.lock();
    let mut count = 0;

    // Core Windows fonts
    let system_fonts: &[(&[u8], &[u8], &[u8], u32, u32)] = &[
        (b"Arial", b"arial.ttf", b"Arial", font_type::TRUETYPE, font_weight::REGULAR),
        (b"Arial Bold", b"arialbd.ttf", b"Arial", font_type::TRUETYPE, font_weight::BOLD),
        (b"Arial Italic", b"ariali.ttf", b"Arial", font_type::TRUETYPE, font_weight::REGULAR),
        (b"Arial Bold Italic", b"arialbi.ttf", b"Arial", font_type::TRUETYPE, font_weight::BOLD),
        (b"Courier New", b"cour.ttf", b"Courier New", font_type::TRUETYPE, font_weight::REGULAR),
        (b"Courier New Bold", b"courbd.ttf", b"Courier New", font_type::TRUETYPE, font_weight::BOLD),
        (b"Georgia", b"georgia.ttf", b"Georgia", font_type::TRUETYPE, font_weight::REGULAR),
        (b"Georgia Bold", b"georgiab.ttf", b"Georgia", font_type::TRUETYPE, font_weight::BOLD),
        (b"Impact", b"impact.ttf", b"Impact", font_type::TRUETYPE, font_weight::REGULAR),
        (b"Lucida Console", b"lucon.ttf", b"Lucida Console", font_type::TRUETYPE, font_weight::REGULAR),
        (b"Lucida Sans Unicode", b"l_10646.ttf", b"Lucida Sans Unicode", font_type::TRUETYPE, font_weight::REGULAR),
        (b"Microsoft Sans Serif", b"micross.ttf", b"Microsoft Sans Serif", font_type::TRUETYPE, font_weight::REGULAR),
        (b"Palatino Linotype", b"pala.ttf", b"Palatino Linotype", font_type::TRUETYPE, font_weight::REGULAR),
        (b"Tahoma", b"tahoma.ttf", b"Tahoma", font_type::TRUETYPE, font_weight::REGULAR),
        (b"Tahoma Bold", b"tahomabd.ttf", b"Tahoma", font_type::TRUETYPE, font_weight::BOLD),
        (b"Times New Roman", b"times.ttf", b"Times New Roman", font_type::TRUETYPE, font_weight::REGULAR),
        (b"Times New Roman Bold", b"timesbd.ttf", b"Times New Roman", font_type::TRUETYPE, font_weight::BOLD),
        (b"Trebuchet MS", b"trebuc.ttf", b"Trebuchet MS", font_type::TRUETYPE, font_weight::REGULAR),
        (b"Trebuchet MS Bold", b"trebucbd.ttf", b"Trebuchet MS", font_type::TRUETYPE, font_weight::BOLD),
        (b"Verdana", b"verdana.ttf", b"Verdana", font_type::TRUETYPE, font_weight::REGULAR),
        (b"Verdana Bold", b"verdanab.ttf", b"Verdana", font_type::TRUETYPE, font_weight::BOLD),
        (b"Comic Sans MS", b"comic.ttf", b"Comic Sans MS", font_type::TRUETYPE, font_weight::REGULAR),
        (b"Webdings", b"webdings.ttf", b"Webdings", font_type::TRUETYPE | font_type::OPENTYPE, font_weight::REGULAR),
        (b"Wingdings", b"wingding.ttf", b"Wingdings", font_type::TRUETYPE, font_weight::REGULAR),
        (b"Symbol", b"symbol.ttf", b"Symbol", font_type::TRUETYPE, font_weight::REGULAR),
        (b"Marlett", b"marlett.ttf", b"Marlett", font_type::TRUETYPE, font_weight::REGULAR),
    ];

    for (name, file, family, ftype, weight) in system_fonts.iter() {
        if count >= MAX_FONTS {
            break;
        }

        let font = &mut fonts[count];

        let nlen = name.len().min(MAX_FONT_NAME);
        font.name[..nlen].copy_from_slice(&name[..nlen]);
        font.name_len = nlen as u8;

        let flen = family.len().min(MAX_FAMILY_NAME);
        font.family[..flen].copy_from_slice(&family[..flen]);
        font.family_len = flen as u8;

        // Build full path
        let prefix = b"C:\\Windows\\Fonts\\";
        let plen = prefix.len();
        font.path[..plen].copy_from_slice(prefix);
        let file_len = file.len().min(MAX_FONT_PATH - plen);
        font.path[plen..plen + file_len].copy_from_slice(&file[..file_len]);
        font.path_len = (plen + file_len) as u16;

        font.font_type = *ftype;
        font.weight = *weight;
        font.italic = name.windows(6).any(|w| w == b"Italic");
        font.charset = charset::ANSI;
        font.pitch_family = pitch_family::VARIABLE_PITCH | pitch_family::FF_SWISS;

        count += 1;
    }

    FONT_COUNT.store(count as u32, Ordering::Release);
}

// ============================================================================
// Font Enumeration
// ============================================================================

/// Get number of installed fonts
pub fn get_font_count() -> u32 {
    FONT_COUNT.load(Ordering::Acquire)
}

/// Get font info by index
pub fn get_font(index: usize, info: &mut FontInfo) -> bool {
    let fonts = FONTS.lock();
    let count = FONT_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    *info = fonts[index];
    true
}

/// Find font by name
pub fn find_font(name: &[u8]) -> Option<usize> {
    let fonts = FONTS.lock();
    let count = FONT_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = fonts[i].name_len as usize;
        if &fonts[i].name[..len] == name {
            return Some(i);
        }
    }
    None
}

/// Enumerate fonts matching a filter
pub fn enumerate_fonts(filter: &FontFilter, callback: impl Fn(&FontInfo) -> bool) {
    let fonts = FONTS.lock();
    let count = FONT_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let font = &fonts[i];

        // Apply filters
        if !filter.truetype && font.font_type & font_type::TRUETYPE != 0 {
            continue;
        }
        if !filter.opentype && font.font_type & font_type::OPENTYPE != 0 {
            continue;
        }
        if !filter.raster && font.font_type & font_type::RASTER != 0 {
            continue;
        }
        if !filter.hidden && font.hidden {
            continue;
        }
        if filter.charset != charset::DEFAULT && font.charset != filter.charset {
            continue;
        }

        if !callback(font) {
            break;
        }
    }
}

/// Get fonts by family name
pub fn get_fonts_by_family(family: &[u8], fonts_out: &mut [FontInfo]) -> usize {
    let fonts = FONTS.lock();
    let count = FONT_COUNT.load(Ordering::Acquire) as usize;

    let mut found = 0;
    for i in 0..count {
        let len = fonts[i].family_len as usize;
        if &fonts[i].family[..len] == family {
            if found < fonts_out.len() {
                fonts_out[found] = fonts[i];
            }
            found += 1;
        }
    }
    found
}

// ============================================================================
// Font Installation
// ============================================================================

/// Install a font from file
pub fn install_font(path: &[u8], name: &[u8]) -> bool {
    let mut fonts = FONTS.lock();
    let count = FONT_COUNT.load(Ordering::Acquire) as usize;

    if count >= MAX_FONTS {
        return false;
    }

    // Check for duplicate
    for i in 0..count {
        let len = fonts[i].name_len as usize;
        if &fonts[i].name[..len] == name {
            return false;
        }
    }

    let font = &mut fonts[count];

    let nlen = name.len().min(MAX_FONT_NAME);
    font.name[..nlen].copy_from_slice(&name[..nlen]);
    font.name_len = nlen as u8;

    let plen = path.len().min(MAX_FONT_PATH);
    font.path[..plen].copy_from_slice(&path[..plen]);
    font.path_len = plen as u16;

    // Determine font type from extension
    if path.ends_with(b".ttf") || path.ends_with(b".TTF") {
        font.font_type = font_type::TRUETYPE;
    } else if path.ends_with(b".otf") || path.ends_with(b".OTF") {
        font.font_type = font_type::OPENTYPE;
    } else if path.ends_with(b".fon") || path.ends_with(b".FON") {
        font.font_type = font_type::RASTER;
    }

    font.weight = font_weight::REGULAR;
    font.charset = charset::ANSI;

    FONT_COUNT.store((count + 1) as u32, Ordering::Release);

    true
}

/// Uninstall a font
pub fn uninstall_font(name: &[u8]) -> bool {
    let mut fonts = FONTS.lock();
    let count = FONT_COUNT.load(Ordering::Acquire) as usize;

    let mut found_index = None;
    for i in 0..count {
        let len = fonts[i].name_len as usize;
        if &fonts[i].name[..len] == name {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..(count - 1) {
            fonts[i] = fonts[i + 1];
        }
        fonts[count - 1] = FontInfo::new();
        FONT_COUNT.store((count - 1) as u32, Ordering::Release);
        return true;
    }

    false
}

/// Hide a font (don't show in font dialogs)
pub fn hide_font(name: &[u8], hidden: bool) -> bool {
    let mut fonts = FONTS.lock();
    let count = FONT_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = fonts[i].name_len as usize;
        if &fonts[i].name[..len] == name {
            fonts[i].hidden = hidden;
            return true;
        }
    }
    false
}

// ============================================================================
// Font Preview
// ============================================================================

/// Sample text for font preview
const SAMPLE_TEXT: &[u8] = b"The quick brown fox jumps over the lazy dog. 1234567890";

/// Get sample text for font preview
pub fn get_sample_text() -> &'static [u8] {
    SAMPLE_TEXT
}

/// Generate font preview (would return bitmap data in real implementation)
pub fn generate_preview(name: &[u8], _size: u32) -> bool {
    let fonts = FONTS.lock();
    let count = FONT_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = fonts[i].name_len as usize;
        if &fonts[i].name[..len] == name {
            // Would render sample text using this font
            return true;
        }
    }
    false
}

// ============================================================================
// Dialog API
// ============================================================================

/// Show fonts folder
pub fn show_fonts(parent: HWND) -> bool {
    let mut dialog = DIALOG.lock();

    dialog.parent = parent;
    dialog.selected = -1;
    dialog.view_mode = 0;
    dialog.sort_by = 0;
    dialog.filter = FontFilter::all();

    // Would show explorer-style fonts folder with:
    // - Font icons
    // - Preview on double-click
    // - Install/delete context menu

    true
}

/// Show font preview dialog
pub fn show_font_preview(parent: HWND, name: &[u8]) -> bool {
    let _ = (parent, name);
    // Would show font preview with sample text at various sizes
    true
}

/// Show install font dialog
pub fn show_install_dialog(parent: HWND) -> bool {
    let _ = parent;
    // Would show file open dialog for selecting fonts to install
    true
}

// ============================================================================
// Font Metrics
// ============================================================================

/// Get font metrics (for layout)
pub fn get_font_metrics(name: &[u8], size: u32, ascent: &mut i32,
                        descent: &mut i32, height: &mut i32) -> bool {
    let fonts = FONTS.lock();
    let count = FONT_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = fonts[i].name_len as usize;
        if &fonts[i].name[..len] == name {
            // Approximate metrics based on size
            *ascent = (size as i32 * 75) / 100;
            *descent = (size as i32 * 25) / 100;
            *height = *ascent + *descent;
            return true;
        }
    }
    false
}

/// Check if font supports a character
pub fn font_has_glyph(name: &[u8], ch: char) -> bool {
    let fonts = FONTS.lock();
    let count = FONT_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = fonts[i].name_len as usize;
        if &fonts[i].name[..len] == name {
            // Symbol fonts only support specific ranges
            if fonts[i].charset == charset::SYMBOL {
                return (ch as u32) < 256;
            }
            // For regular fonts, assume basic Latin + extended
            return (ch as u32) < 0x10000;
        }
    }
    false
}
