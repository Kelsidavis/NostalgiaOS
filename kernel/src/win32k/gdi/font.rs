//! Font Implementation
//!
//! Fonts are used for text rendering.
//!
//! # Font Types
//!
//! - **Raster**: Bitmap fonts at specific sizes
//! - **TrueType**: Scalable outline fonts
//! - **OpenType**: Advanced scalable fonts
//!
//! For now, we implement a simple 8x16 bitmap font for basic text rendering.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntgdi/gre/fontgdi.cxx`

use crate::ke::spinlock::SpinLock;
use super::super::{GdiHandle, GdiObjectType, Size};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of fonts
pub const MAX_FONTS: usize = 64;

/// Number of stock fonts
pub const STOCK_FONT_COUNT: usize = 3;

/// Default font width
pub const DEFAULT_FONT_WIDTH: i32 = 8;

/// Default font height
pub const DEFAULT_FONT_HEIGHT: i32 = 16;

// ============================================================================
// Types
// ============================================================================

/// Font weight
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FontWeight {
    DontCare = 0,
    Thin = 100,
    ExtraLight = 200,
    Light = 300,
    #[default]
    Normal = 400,
    Medium = 500,
    SemiBold = 600,
    Bold = 700,
    ExtraBold = 800,
    Heavy = 900,
}

/// Font family
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FontFamily {
    #[default]
    DontCare = 0,
    Roman = 1,       // Serif (Times)
    Swiss = 2,       // Sans-serif (Helvetica)
    Modern = 3,      // Monospace (Courier)
    Script = 4,      // Script/cursive
    Decorative = 5,  // Decorative
}

/// Character set
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CharSet {
    Ansi = 0,
    #[default]
    Default = 1,
    Symbol = 2,
    ShiftJis = 128,
    OEM = 255,
}

// ============================================================================
// Font Structure
// ============================================================================

/// Logical font descriptor
#[derive(Debug, Clone, Copy)]
pub struct LogFont {
    /// Height (negative = character height, positive = cell height)
    pub height: i32,

    /// Width (0 = default aspect ratio)
    pub width: i32,

    /// Escapement angle (tenths of degree)
    pub escapement: i32,

    /// Orientation angle (tenths of degree)
    pub orientation: i32,

    /// Weight
    pub weight: FontWeight,

    /// Italic
    pub italic: bool,

    /// Underline
    pub underline: bool,

    /// Strikeout
    pub strikeout: bool,

    /// Character set
    pub charset: CharSet,

    /// Font family
    pub family: FontFamily,

    /// Face name (up to 32 chars)
    pub face_name: [u8; 32],
}

impl Default for LogFont {
    fn default() -> Self {
        let mut face = [0u8; 32];
        // "System" font
        face[0] = b'S';
        face[1] = b'y';
        face[2] = b's';
        face[3] = b't';
        face[4] = b'e';
        face[5] = b'm';

        Self {
            height: DEFAULT_FONT_HEIGHT,
            width: DEFAULT_FONT_WIDTH,
            escapement: 0,
            orientation: 0,
            weight: FontWeight::Normal,
            italic: false,
            underline: false,
            strikeout: false,
            charset: CharSet::Default,
            family: FontFamily::Modern,
            face_name: face,
        }
    }
}

/// Font object
#[derive(Debug, Clone, Copy)]
pub struct Font {
    /// Logical font descriptor
    pub log_font: LogFont,

    /// Cell size (including internal leading)
    pub cell_size: Size,

    /// Reference count
    pub ref_count: u32,

    /// Is stock object
    pub stock: bool,

    /// Valid flag
    pub valid: bool,
}

impl Default for Font {
    fn default() -> Self {
        Self {
            log_font: LogFont::default(),
            cell_size: Size::new(DEFAULT_FONT_WIDTH, DEFAULT_FONT_HEIGHT),
            ref_count: 1,
            stock: false,
            valid: false,
        }
    }
}

// ============================================================================
// Built-in 8x16 Font
// ============================================================================

/// Get character bitmap from built-in font
/// Returns 16 bytes, one per row, each bit is a pixel
pub fn get_char_bitmap(c: u8) -> &'static [u8; 16] {
    // Use the kernel's built-in font
    static FONT_DATA: &[u8] = include_bytes!("../../font8x16.bin");

    const CHAR_HEIGHT: usize = 16;

    // Each character is 16 bytes (16 rows, 8 bits each)
    let index = (c as usize) * CHAR_HEIGHT;

    if index + CHAR_HEIGHT <= FONT_DATA.len() {
        unsafe {
            &*(FONT_DATA.as_ptr().add(index) as *const [u8; 16])
        }
    } else {
        // Return empty glyph for out-of-range characters
        static EMPTY: [u8; 16] = [0; 16];
        &EMPTY
    }
}

// ============================================================================
// Font Table
// ============================================================================

struct FontEntry {
    font: Option<Font>,
}

impl Default for FontEntry {
    fn default() -> Self {
        Self { font: None }
    }
}

static FONT_TABLE: SpinLock<FontTable> = SpinLock::new(FontTable::new());

struct FontTable {
    entries: [FontEntry; MAX_FONTS],
}

impl FontTable {
    const fn new() -> Self {
        const EMPTY: FontEntry = FontEntry { font: None };
        Self {
            entries: [EMPTY; MAX_FONTS],
        }
    }
}

// Stock font handles
static STOCK_FONTS: SpinLock<[GdiHandle; STOCK_FONT_COUNT]> =
    SpinLock::new([GdiHandle::NULL; STOCK_FONT_COUNT]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize font subsystem
pub fn init() {
    crate::serial_println!("[GDI/Font] Font manager initialized");
}

/// Create stock fonts
pub fn create_stock_fonts() {
    let fonts = [
        ("System", FontWeight::Normal, false),           // SYSTEM_FONT
        ("System", FontWeight::Normal, false),           // DEVICE_DEFAULT_FONT
        ("Fixedsys", FontWeight::Normal, true),          // SYSTEM_FIXED_FONT
    ];

    let mut stock = STOCK_FONTS.lock();
    let mut table = FONT_TABLE.lock();

    for (i, (name, weight, fixed)) in fonts.iter().enumerate() {
        let mut log_font = LogFont::default();
        log_font.weight = *weight;

        if *fixed {
            log_font.family = FontFamily::Modern;
        }

        // Copy face name
        for (j, &b) in name.as_bytes().iter().take(31).enumerate() {
            log_font.face_name[j] = b;
        }

        let font = Font {
            log_font,
            cell_size: Size::new(DEFAULT_FONT_WIDTH, DEFAULT_FONT_HEIGHT),
            ref_count: 1,
            stock: true,
            valid: true,
        };

        // Stock fonts start at index 1
        let index = (i + 1) as u16;
        table.entries[index as usize].font = Some(font);

        let handle = GdiHandle::new(index, GdiObjectType::Font);
        stock[i] = handle;

        super::inc_font_count();
    }

    crate::serial_println!("[GDI/Font] Created {} stock fonts", STOCK_FONT_COUNT);
}

/// Get stock font handle
pub fn get_stock_font(index: usize) -> GdiHandle {
    if index >= STOCK_FONT_COUNT {
        return GdiHandle::NULL;
    }

    let stock = STOCK_FONTS.lock();
    stock[index]
}

// ============================================================================
// Font Operations
// ============================================================================

/// Allocate a font slot
fn allocate_font_slot() -> Option<u16> {
    let table = FONT_TABLE.lock();

    // Start after stock fonts
    for i in (STOCK_FONT_COUNT + 1)..MAX_FONTS {
        if table.entries[i].font.is_none() {
            return Some(i as u16);
        }
    }

    None
}

/// Create a font from logical font descriptor
pub fn create_font_indirect(log_font: &LogFont) -> GdiHandle {
    let index = match allocate_font_slot() {
        Some(i) => i,
        None => return GdiHandle::NULL,
    };

    let font = Font {
        log_font: *log_font,
        cell_size: Size::new(
            if log_font.width > 0 { log_font.width } else { DEFAULT_FONT_WIDTH },
            if log_font.height > 0 { log_font.height.abs() } else { DEFAULT_FONT_HEIGHT },
        ),
        ref_count: 1,
        stock: false,
        valid: true,
    };

    let handle = GdiHandle::new(index, GdiObjectType::Font);

    {
        let mut table = FONT_TABLE.lock();
        table.entries[index as usize].font = Some(font);
    }

    super::inc_font_count();

    handle
}

/// Create a font with common parameters
pub fn create_font(
    height: i32,
    width: i32,
    weight: FontWeight,
    italic: bool,
    underline: bool,
    strikeout: bool,
    family: FontFamily,
    face_name: &str,
) -> GdiHandle {
    let mut log_font = LogFont::default();
    log_font.height = height;
    log_font.width = width;
    log_font.weight = weight;
    log_font.italic = italic;
    log_font.underline = underline;
    log_font.strikeout = strikeout;
    log_font.family = family;

    // Copy face name
    for (i, &b) in face_name.as_bytes().iter().take(31).enumerate() {
        log_font.face_name[i] = b;
    }

    create_font_indirect(&log_font)
}

/// Delete a font
pub fn delete_font(handle: GdiHandle) -> bool {
    if handle.object_type() != GdiObjectType::Font {
        return false;
    }

    let index = handle.index() as usize;
    if index >= MAX_FONTS {
        return false;
    }

    let mut table = FONT_TABLE.lock();

    if let Some(ref font) = table.entries[index].font {
        // Can't delete stock objects
        if font.stock {
            return false;
        }
    }

    if table.entries[index].font.is_some() {
        table.entries[index].font = None;
        super::dec_font_count();
        true
    } else {
        false
    }
}

/// Get font by handle
pub fn get_font(handle: GdiHandle) -> Option<Font> {
    if handle.object_type() != GdiObjectType::Font {
        return None;
    }

    let index = handle.index() as usize;
    if index >= MAX_FONTS {
        return None;
    }

    let table = FONT_TABLE.lock();
    table.entries[index].font
}

/// Get text extent (size of string when rendered)
pub fn get_text_extent(handle: GdiHandle, text: &str) -> Size {
    let font = match get_font(handle) {
        Some(f) => f,
        None => return Size::new(0, 0),
    };

    // Simple calculation: width = chars * cell_width, height = cell_height
    Size::new(
        font.cell_size.cx * text.len() as i32,
        font.cell_size.cy,
    )
}

/// Get font cell size
pub fn get_font_cell_size(handle: GdiHandle) -> Size {
    get_font(handle).map(|f| f.cell_size).unwrap_or(Size::new(8, 16))
}
