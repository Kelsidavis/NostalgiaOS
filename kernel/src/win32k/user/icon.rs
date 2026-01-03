//! Icon and Cursor Subsystem
//!
//! Implementation of Windows NT-style icons and cursors.
//! Provides icon loading, drawing, and management.
//!
//! # Components
//!
//! - **Icon objects**: HICON handles
//! - **Cursor objects**: HCURSOR handles
//! - **Standard icons**: System icons (IDI_*)
//! - **Standard cursors**: System cursors (IDC_*)
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/cursor.c`
//! - `windows/core/ntuser/kernel/icon.c`

use super::super::{UserHandle, UserObjectType, ColorRef};
use super::super::gdi::surface;
use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of icons
const MAX_ICONS: usize = 128;

/// Standard icon size
pub const ICON_SIZE_STANDARD: i32 = 32;

/// Small icon size
pub const ICON_SIZE_SMALL: i32 = 16;

// ============================================================================
// Icon Handle
// ============================================================================

/// Icon handle type
pub type HICON = UserHandle;

/// Cursor handle type (same as icon in Win32)
pub type HCURSOR = UserHandle;

// ============================================================================
// Standard Icons (IDI_*)
// ============================================================================

/// Standard icon identifiers
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardIcon {
    /// Default application icon
    Application = 32512,
    /// Error/Hand icon
    Error = 32513,
    /// Question mark icon
    Question = 32514,
    /// Warning/Exclamation icon
    Warning = 32515,
    /// Information icon
    Information = 32516,
    /// Windows logo icon
    WinLogo = 32517,
    /// Shield icon
    Shield = 32518,
}

// Aliases for compatibility
pub const IDI_HAND: StandardIcon = StandardIcon::Error;
pub const IDI_EXCLAMATION: StandardIcon = StandardIcon::Warning;
pub const IDI_ASTERISK: StandardIcon = StandardIcon::Information;

// ============================================================================
// Standard Cursors (IDC_*)
// ============================================================================

/// Standard cursor identifiers
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardCursor {
    /// Standard arrow cursor
    Arrow = 32512,
    /// I-beam cursor
    IBeam = 32513,
    /// Hourglass/wait cursor
    Wait = 32514,
    /// Crosshair cursor
    Cross = 32515,
    /// Up arrow cursor
    UpArrow = 32516,
    /// Resize NW-SE cursor
    SizeNWSE = 32642,
    /// Resize NE-SW cursor
    SizeNESW = 32643,
    /// Resize W-E cursor
    SizeWE = 32644,
    /// Resize N-S cursor
    SizeNS = 32645,
    /// Move cursor
    SizeAll = 32646,
    /// Disabled cursor
    No = 32648,
    /// Hand/pointer cursor
    Hand = 32649,
    /// App starting cursor
    AppStarting = 32650,
    /// Help cursor
    Help = 32651,
}

// ============================================================================
// Icon Data Structure
// ============================================================================

/// Icon data
#[derive(Clone, Copy)]
struct IconData {
    /// Icon handle
    handle: HICON,
    /// Width in pixels
    width: i32,
    /// Height in pixels
    height: i32,
    /// Hot spot X (for cursors)
    hotspot_x: i32,
    /// Hot spot Y (for cursors)
    hotspot_y: i32,
    /// Is this a cursor?
    is_cursor: bool,
    /// Is system icon?
    is_system: bool,
    /// Pixel data (RGBA, max 32x32)
    pixels: [u32; 1024],
    /// Mask data (1 bit per pixel)
    mask: [u8; 128],
    /// Is this slot in use?
    in_use: bool,
}

impl IconData {
    const fn empty() -> Self {
        Self {
            handle: UserHandle::NULL,
            width: 0,
            height: 0,
            hotspot_x: 0,
            hotspot_y: 0,
            is_cursor: false,
            is_system: false,
            pixels: [0; 1024],
            mask: [0; 128],
            in_use: false,
        }
    }
}

struct IconTable {
    icons: [IconData; MAX_ICONS],
    count: usize,
}

impl IconTable {
    const fn new() -> Self {
        Self {
            icons: [IconData::empty(); MAX_ICONS],
            count: 0,
        }
    }
}

static ICON_TABLE: SpinLock<IconTable> = SpinLock::new(IconTable::new());
static ICON_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NEXT_ICON_INDEX: AtomicU32 = AtomicU32::new(1);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize icon subsystem
pub fn init() {
    if ICON_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    // Create standard system icons
    create_standard_icons();

    // Create standard cursors
    create_standard_cursors();

    crate::serial_println!("[USER/Icon] Icon subsystem initialized");
    ICON_INITIALIZED.store(true, Ordering::Release);
}

/// Create standard system icons
fn create_standard_icons() {
    // Create application icon
    create_app_icon();

    // Create error icon
    create_error_icon();

    // Create question icon
    create_question_icon();

    // Create warning icon
    create_warning_icon();

    // Create information icon
    create_info_icon();
}

/// Create standard cursors
fn create_standard_cursors() {
    // Create arrow cursor
    create_arrow_cursor();

    // Create I-beam cursor
    create_ibeam_cursor();

    // Create wait cursor
    create_wait_cursor();

    // Create hand cursor
    create_hand_cursor();
}

// ============================================================================
// Icon Creation
// ============================================================================

/// Create an icon from pixel data
pub fn create_icon(
    width: i32,
    height: i32,
    pixels: &[u32],
    mask: &[u8],
) -> HICON {
    if width > 32 || height > 32 || width <= 0 || height <= 0 {
        return UserHandle::NULL;
    }

    let mut table = ICON_TABLE.lock();

    for icon in table.icons.iter_mut() {
        if !icon.in_use {
            let index = NEXT_ICON_INDEX.fetch_add(1, Ordering::Relaxed) as u16;
            let handle = UserHandle::new(index, UserObjectType::Cursor);

            icon.handle = handle;
            icon.width = width;
            icon.height = height;
            icon.hotspot_x = 0;
            icon.hotspot_y = 0;
            icon.is_cursor = false;
            icon.is_system = false;
            icon.in_use = true;

            // Copy pixel data
            let pixel_count = (width * height) as usize;
            let pixel_count = pixel_count.min(1024).min(pixels.len());
            icon.pixels[..pixel_count].copy_from_slice(&pixels[..pixel_count]);

            // Copy mask data
            let mask_count = ((width * height + 7) / 8) as usize;
            let mask_count = mask_count.min(128).min(mask.len());
            icon.mask[..mask_count].copy_from_slice(&mask[..mask_count]);

            table.count += 1;
            return handle;
        }
    }

    UserHandle::NULL
}

/// Create a cursor from pixel data
pub fn create_cursor(
    width: i32,
    height: i32,
    hotspot_x: i32,
    hotspot_y: i32,
    pixels: &[u32],
    mask: &[u8],
) -> HCURSOR {
    if width > 32 || height > 32 || width <= 0 || height <= 0 {
        return UserHandle::NULL;
    }

    let mut table = ICON_TABLE.lock();

    for icon in table.icons.iter_mut() {
        if !icon.in_use {
            let index = NEXT_ICON_INDEX.fetch_add(1, Ordering::Relaxed) as u16;
            let handle = UserHandle::new(index, UserObjectType::Cursor);

            icon.handle = handle;
            icon.width = width;
            icon.height = height;
            icon.hotspot_x = hotspot_x.clamp(0, width - 1);
            icon.hotspot_y = hotspot_y.clamp(0, height - 1);
            icon.is_cursor = true;
            icon.is_system = false;
            icon.in_use = true;

            let pixel_count = (width * height) as usize;
            let pixel_count = pixel_count.min(1024).min(pixels.len());
            icon.pixels[..pixel_count].copy_from_slice(&pixels[..pixel_count]);

            let mask_count = ((width * height + 7) / 8) as usize;
            let mask_count = mask_count.min(128).min(mask.len());
            icon.mask[..mask_count].copy_from_slice(&mask[..mask_count]);

            table.count += 1;
            return handle;
        }
    }

    UserHandle::NULL
}

/// Destroy an icon
pub fn destroy_icon(hicon: HICON) -> bool {
    let mut table = ICON_TABLE.lock();

    for icon in table.icons.iter_mut() {
        if icon.in_use && icon.handle == hicon {
            if icon.is_system {
                return false; // Cannot destroy system icons
            }
            icon.in_use = false;
            table.count -= 1;
            return true;
        }
    }

    false
}

/// Destroy a cursor (same as destroy_icon)
pub fn destroy_cursor(hcursor: HCURSOR) -> bool {
    destroy_icon(hcursor)
}

// ============================================================================
// Icon Loading
// ============================================================================

/// Load a standard icon
pub fn load_icon(icon_id: StandardIcon) -> HICON {
    let table = ICON_TABLE.lock();

    // Find system icon by ID
    for icon in table.icons.iter() {
        if icon.in_use && icon.is_system && !icon.is_cursor {
            // Match by checking stored ID (in hotspot_x for system icons)
            if icon.hotspot_x == icon_id as i32 {
                return icon.handle;
            }
        }
    }

    UserHandle::NULL
}

/// Load a standard cursor
pub fn load_cursor(cursor_id: StandardCursor) -> HCURSOR {
    let table = ICON_TABLE.lock();

    // Find system cursor by ID
    for icon in table.icons.iter() {
        if icon.in_use && icon.is_system && icon.is_cursor {
            // Match by checking stored ID
            if icon.hotspot_x as u32 == cursor_id as u32 {
                return icon.handle;
            }
        }
    }

    UserHandle::NULL
}

// ============================================================================
// Icon Drawing
// ============================================================================

/// Draw an icon at the specified position
pub fn draw_icon(
    hdc: super::super::HDC,
    x: i32,
    y: i32,
    hicon: HICON,
) -> bool {
    let table = ICON_TABLE.lock();

    let icon = match table.icons.iter().find(|i| i.in_use && i.handle == hicon) {
        Some(i) => i,
        None => return false,
    };

    let surface_handle = super::super::gdi::dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return false,
    };

    // Draw icon pixels with transparency
    for py in 0..icon.height {
        for px in 0..icon.width {
            let idx = (py * icon.width + px) as usize;
            if idx < 1024 {
                let pixel = icon.pixels[idx];
                let alpha = (pixel >> 24) & 0xFF;

                if alpha > 0 {
                    let r = ((pixel >> 16) & 0xFF) as u8;
                    let g = ((pixel >> 8) & 0xFF) as u8;
                    let b = (pixel & 0xFF) as u8;
                    surf.set_pixel(x + px, y + py, ColorRef::rgb(r, g, b));
                }
            }
        }
    }

    true
}

/// Draw an icon stretched to fit the rectangle
pub fn draw_icon_ex(
    hdc: super::super::HDC,
    x: i32,
    y: i32,
    hicon: HICON,
    cx: i32,
    cy: i32,
) -> bool {
    if cx == 0 || cy == 0 {
        return draw_icon(hdc, x, y, hicon);
    }

    let table = ICON_TABLE.lock();

    let icon = match table.icons.iter().find(|i| i.in_use && i.handle == hicon) {
        Some(i) => i,
        None => return false,
    };

    let surface_handle = super::super::gdi::dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return false,
    };

    // Simple nearest-neighbor scaling
    for dy in 0..cy {
        let src_y = (dy * icon.height / cy) as usize;
        for dx in 0..cx {
            let src_x = (dx * icon.width / cx) as usize;
            let idx = src_y * icon.width as usize + src_x;

            if idx < 1024 {
                let pixel = icon.pixels[idx];
                let alpha = (pixel >> 24) & 0xFF;

                if alpha > 0 {
                    let r = ((pixel >> 16) & 0xFF) as u8;
                    let g = ((pixel >> 8) & 0xFF) as u8;
                    let b = (pixel & 0xFF) as u8;
                    surf.set_pixel(x + dx, y + dy, ColorRef::rgb(r, g, b));
                }
            }
        }
    }

    true
}

// ============================================================================
// Icon Information
// ============================================================================

/// Get icon dimensions
pub fn get_icon_info(hicon: HICON) -> Option<(i32, i32, i32, i32)> {
    let table = ICON_TABLE.lock();

    for icon in table.icons.iter() {
        if icon.in_use && icon.handle == hicon {
            return Some((icon.width, icon.height, icon.hotspot_x, icon.hotspot_y));
        }
    }

    None
}

/// Get cursor hot spot
pub fn get_cursor_hotspot(hcursor: HCURSOR) -> Option<(i32, i32)> {
    get_icon_info(hcursor).map(|(_, _, hx, hy)| (hx, hy))
}

// ============================================================================
// Standard Icon Creation
// ============================================================================

fn create_system_icon(id: i32, size: i32, pixels: &[u32]) -> HICON {
    let mut table = ICON_TABLE.lock();

    for icon in table.icons.iter_mut() {
        if !icon.in_use {
            let index = NEXT_ICON_INDEX.fetch_add(1, Ordering::Relaxed) as u16;
            let handle = UserHandle::new(index, UserObjectType::Cursor);

            icon.handle = handle;
            icon.width = size;
            icon.height = size;
            icon.hotspot_x = id;  // Store ID for lookup
            icon.hotspot_y = 0;
            icon.is_cursor = false;
            icon.is_system = true;
            icon.in_use = true;

            let pixel_count = (size * size) as usize;
            let pixel_count = pixel_count.min(1024).min(pixels.len());
            icon.pixels[..pixel_count].copy_from_slice(&pixels[..pixel_count]);

            table.count += 1;
            return handle;
        }
    }

    UserHandle::NULL
}

fn create_system_cursor(id: u32, size: i32, _hx: i32, hy: i32, pixels: &[u32]) -> HCURSOR {
    let mut table = ICON_TABLE.lock();

    for icon in table.icons.iter_mut() {
        if !icon.in_use {
            let index = NEXT_ICON_INDEX.fetch_add(1, Ordering::Relaxed) as u16;
            let handle = UserHandle::new(index, UserObjectType::Cursor);

            icon.handle = handle;
            icon.width = size;
            icon.height = size;
            icon.hotspot_x = id as i32;  // Store ID for lookup
            icon.hotspot_y = hy;
            icon.is_cursor = true;
            icon.is_system = true;
            icon.in_use = true;

            let pixel_count = (size * size) as usize;
            let pixel_count = pixel_count.min(1024).min(pixels.len());
            icon.pixels[..pixel_count].copy_from_slice(&pixels[..pixel_count]);

            table.count += 1;
            return handle;
        }
    }

    UserHandle::NULL
}

fn create_app_icon() {
    // Simple 16x16 application icon (window shape)
    let mut pixels = [0u32; 256];
    let white = 0xFFFFFFFFu32;
    let blue = 0xFF0078D7u32;
    let _gray = 0xFFCCCCCCu32;

    // Draw window shape
    for y in 0..16 {
        for x in 0..16 {
            if x == 0 || x == 15 || y == 0 || y == 15 {
                pixels[y * 16 + x] = blue; // Border
            } else if y < 4 {
                pixels[y * 16 + x] = blue; // Title bar
            } else {
                pixels[y * 16 + x] = white; // Client area
            }
        }
    }

    create_system_icon(StandardIcon::Application as i32, 16, &pixels);
}

fn create_error_icon() {
    // Red circle with X
    let mut pixels = [0u32; 256];
    let red = 0xFFCC0000;
    let white = 0xFFFFFFFF;

    for y in 0..16 {
        for x in 0..16 {
            let dx = x as i32 - 7;
            let dy = y as i32 - 7;
            if dx * dx + dy * dy <= 49 {
                // Inside circle
                let on_x = (dx - dy).abs() <= 1 || (dx + dy).abs() <= 1;
                if on_x && dx.abs() > 2 && dy.abs() > 2 {
                    pixels[y * 16 + x] = white;
                } else {
                    pixels[y * 16 + x] = red;
                }
            }
        }
    }

    create_system_icon(StandardIcon::Error as i32, 16, &pixels);
}

fn create_question_icon() {
    // Blue circle with ?
    let mut pixels = [0u32; 256];
    let blue = 0xFF0078D7;
    let white = 0xFFFFFFFF;

    for y in 0..16 {
        for x in 0..16 {
            let dx = x as i32 - 7;
            let dy = y as i32 - 7;
            if dx * dx + dy * dy <= 49 {
                pixels[y * 16 + x] = blue;
            }
        }
    }
    // Draw ? mark
    for x in 5..11 {
        pixels[3 * 16 + x] = white;
    }
    pixels[4 * 16 + 10] = white;
    pixels[5 * 16 + 10] = white;
    pixels[6 * 16 + 9] = white;
    pixels[7 * 16 + 8] = white;
    pixels[8 * 16 + 7] = white;
    pixels[11 * 16 + 7] = white;

    create_system_icon(StandardIcon::Question as i32, 16, &pixels);
}

fn create_warning_icon() {
    // Yellow triangle with !
    let mut pixels = [0u32; 256];
    let yellow = 0xFFFFCC00;
    let black = 0xFF000000;

    for y in 0..16 {
        let half_width = y / 2;
        let center = 7;
        for x in (center - half_width).max(0)..=(center + half_width).min(15) {
            pixels[y as usize * 16 + x as usize] = yellow;
        }
    }
    // Draw !
    for y in 4..10 {
        pixels[y * 16 + 7] = black;
    }
    pixels[12 * 16 + 7] = black;

    create_system_icon(StandardIcon::Warning as i32, 16, &pixels);
}

fn create_info_icon() {
    // Blue circle with i
    let mut pixels = [0u32; 256];
    let blue = 0xFF0078D7;
    let white = 0xFFFFFFFF;

    for y in 0..16 {
        for x in 0..16 {
            let dx = x as i32 - 7;
            let dy = y as i32 - 7;
            if dx * dx + dy * dy <= 49 {
                pixels[y * 16 + x] = blue;
            }
        }
    }
    // Draw i
    pixels[3 * 16 + 7] = white;
    for y in 6..13 {
        pixels[y * 16 + 7] = white;
    }

    create_system_icon(StandardIcon::Information as i32, 16, &pixels);
}

fn create_arrow_cursor() {
    // Standard arrow cursor
    let mut pixels = [0u32; 256];
    let black = 0xFF000000;
    let white = 0xFFFFFFFF;

    // Arrow shape (16x16)
    let arrow = [
        "X...............",
        "XX..............",
        "XWX.............",
        "XWWX............",
        "XWWWX...........",
        "XWWWWX..........",
        "XWWWWWX.........",
        "XWWWWWWX........",
        "XWWWWWWWX.......",
        "XWWWWWWWWX......",
        "XWWWWWWWWWX.....",
        "XWWWWWXXXXXH....",
        "XWWXWWX.........",
        "XWXXWWX.........",
        "XX..XWWX........",
        "X....XXX........",
    ];

    for (y, row) in arrow.iter().enumerate() {
        for (x, c) in row.chars().enumerate() {
            pixels[y * 16 + x] = match c {
                'X' => black,
                'W' => white,
                _ => 0,
            };
        }
    }

    create_system_cursor(StandardCursor::Arrow as u32, 16, 0, 0, &pixels);
}

fn create_ibeam_cursor() {
    // I-beam cursor for text
    let mut pixels = [0u32; 256];
    let black = 0xFF000000;

    // I-beam shape
    for x in 4..12 {
        pixels[0 * 16 + x] = black;
        pixels[15 * 16 + x] = black;
    }
    for y in 1..15 {
        pixels[y * 16 + 7] = black;
    }

    create_system_cursor(StandardCursor::IBeam as u32, 16, 7, 7, &pixels);
}

fn create_wait_cursor() {
    // Hourglass cursor
    let mut pixels = [0u32; 256];
    let black = 0xFF000000u32;
    let _sand = 0xFFD4AA00u32;

    // Hourglass outline
    for x in 2..14 {
        pixels[0 * 16 + x] = black;
        pixels[15 * 16 + x] = black;
    }
    for y in 1..8 {
        let half = y;
        pixels[y * 16 + (2 + half as usize)] = black;
        pixels[y * 16 + (13 - half as usize)] = black;
    }
    for y in 8..15 {
        let half = 14 - y;
        pixels[y * 16 + (2 + half as usize)] = black;
        pixels[y * 16 + (13 - half as usize)] = black;
    }

    create_system_cursor(StandardCursor::Wait as u32, 16, 7, 7, &pixels);
}

fn create_hand_cursor() {
    // Hand/pointer cursor
    let mut pixels = [0u32; 256];
    let black = 0xFF000000;
    let white = 0xFFFFFFFF;

    // Simple hand shape
    let hand = [
        "......XX........",
        ".....XWWX.......",
        ".....XWWX.......",
        ".....XWWX.......",
        ".....XWWXXX.....",
        ".....XWWXWWXX...",
        ".XX..XWWXWWXWX..",
        "XWWXXWWWWWWWWX..",
        "XWWWWWWWWWWWWX..",
        ".XWWWWWWWWWWWX..",
        "..XWWWWWWWWWX...",
        "..XWWWWWWWWWX...",
        "...XWWWWWWWX....",
        "...XWWWWWWWX....",
        "....XWWWWWX.....",
        ".....XXXXX......",
    ];

    for (y, row) in hand.iter().enumerate() {
        for (x, c) in row.chars().enumerate() {
            pixels[y * 16 + x] = match c {
                'X' => black,
                'W' => white,
                _ => 0,
            };
        }
    }

    create_system_cursor(StandardCursor::Hand as u32, 16, 5, 0, &pixels);
}

// ============================================================================
// Statistics
// ============================================================================

/// Icon statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct IconStats {
    pub icon_count: usize,
}

/// Get icon statistics
pub fn get_stats() -> IconStats {
    let table = ICON_TABLE.lock();
    IconStats {
        icon_count: table.count,
    }
}
