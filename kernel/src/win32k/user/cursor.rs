//! Cursor/Mouse Pointer Rendering
//!
//! Manages cursor display, movement, and different cursor shapes.
//!
//! # Cursor Types
//!
//! - Arrow (default)
//! - IBeam (text selection)
//! - Wait (hourglass)
//! - Cross (crosshair)
//! - Hand (link)
//! - SizeNWSE, SizeNESW, SizeWE, SizeNS (resize)
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/cursor.c`

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{ColorRef, Point};
use super::super::gdi::surface;

// ============================================================================
// Constants
// ============================================================================

/// Cursor width in pixels
pub const CURSOR_WIDTH: usize = 16;

/// Cursor height in pixels
pub const CURSOR_HEIGHT: usize = 16;

/// Maximum number of cursors
pub const MAX_CURSORS: usize = 32;

// ============================================================================
// Standard Cursor IDs
// ============================================================================

/// Standard cursor identifiers (IDC_*)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StandardCursor {
    #[default]
    Arrow = 0,
    IBeam = 1,
    Wait = 2,
    Cross = 3,
    UpArrow = 4,
    SizeNWSE = 5,
    SizeNESW = 6,
    SizeWE = 7,
    SizeNS = 8,
    SizeAll = 9,
    No = 10,
    Hand = 11,
    AppStarting = 12,
    Help = 13,
}

// ============================================================================
// Cursor Bitmap Data
// ============================================================================

/// Arrow cursor bitmap (16x16, 1 = white, 2 = black, 0 = transparent)
static CURSOR_ARROW: [[u8; CURSOR_WIDTH]; CURSOR_HEIGHT] = [
    [2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [2,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [2,1,2,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [2,1,1,2,0,0,0,0,0,0,0,0,0,0,0,0],
    [2,1,1,1,2,0,0,0,0,0,0,0,0,0,0,0],
    [2,1,1,1,1,2,0,0,0,0,0,0,0,0,0,0],
    [2,1,1,1,1,1,2,0,0,0,0,0,0,0,0,0],
    [2,1,1,1,1,1,1,2,0,0,0,0,0,0,0,0],
    [2,1,1,1,1,1,1,1,2,0,0,0,0,0,0,0],
    [2,1,1,1,1,1,1,1,1,2,0,0,0,0,0,0],
    [2,1,1,1,1,1,2,2,2,2,2,0,0,0,0,0],
    [2,1,1,2,1,1,2,0,0,0,0,0,0,0,0,0],
    [2,1,2,0,2,1,1,2,0,0,0,0,0,0,0,0],
    [2,2,0,0,2,1,1,2,0,0,0,0,0,0,0,0],
    [2,0,0,0,0,2,1,1,2,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,2,2,2,0,0,0,0,0,0,0],
];

/// IBeam cursor bitmap
static CURSOR_IBEAM: [[u8; CURSOR_WIDTH]; CURSOR_HEIGHT] = [
    [0,0,0,2,2,2,2,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,2,2,2,2,2,0,0,0,0,0,0,0,0],
];

/// Wait/hourglass cursor bitmap
static CURSOR_WAIT: [[u8; CURSOR_WIDTH]; CURSOR_HEIGHT] = [
    [2,2,2,2,2,2,2,2,2,2,2,0,0,0,0,0],
    [2,1,1,1,1,1,1,1,1,1,2,0,0,0,0,0],
    [0,2,1,1,1,1,1,1,1,2,0,0,0,0,0,0],
    [0,0,2,1,1,1,1,1,2,0,0,0,0,0,0,0],
    [0,0,0,2,1,1,1,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,2,1,2,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,2,1,2,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,2,1,2,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,2,1,2,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,2,1,2,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,2,1,2,0,0,0,0,0,0,0,0,0],
    [0,0,0,2,1,1,1,2,0,0,0,0,0,0,0,0],
    [0,0,2,1,1,1,1,1,2,0,0,0,0,0,0,0],
    [0,2,1,1,1,1,1,1,1,2,0,0,0,0,0,0],
    [2,1,1,1,1,1,1,1,1,1,2,0,0,0,0,0],
    [2,2,2,2,2,2,2,2,2,2,2,0,0,0,0,0],
];

/// Cross/crosshair cursor bitmap
static CURSOR_CROSS: [[u8; CURSOR_WIDTH]; CURSOR_HEIGHT] = [
    [0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0],
    [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,0],
    [0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
];

/// Hand/link cursor bitmap
static CURSOR_HAND: [[u8; CURSOR_WIDTH]; CURSOR_HEIGHT] = [
    [0,0,0,0,0,0,2,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,1,1,2,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,1,1,2,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,1,1,2,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,1,1,2,2,2,0,0,0,0,0],
    [0,0,0,0,0,2,1,1,2,1,1,2,2,0,0,0],
    [0,2,2,0,0,2,1,1,2,1,1,2,1,2,0,0],
    [2,1,1,2,0,2,1,1,1,1,1,2,1,1,2,0],
    [2,1,1,1,2,2,1,1,1,1,1,1,1,1,2,0],
    [0,2,1,1,1,1,1,1,1,1,1,1,1,1,2,0],
    [0,0,2,1,1,1,1,1,1,1,1,1,1,1,2,0],
    [0,0,2,1,1,1,1,1,1,1,1,1,1,2,0,0],
    [0,0,0,2,1,1,1,1,1,1,1,1,1,2,0,0],
    [0,0,0,2,1,1,1,1,1,1,1,1,2,0,0,0],
    [0,0,0,0,2,1,1,1,1,1,1,1,2,0,0,0],
    [0,0,0,0,0,2,2,2,2,2,2,2,0,0,0,0],
];

/// Size horizontal (WE) cursor
static CURSOR_SIZE_WE: [[u8; CURSOR_WIDTH]; CURSOR_HEIGHT] = [
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,2,0,0,0,0,0,0,0,2,0,0,0,0],
    [0,0,2,1,0,0,0,0,0,0,0,1,2,0,0,0],
    [0,2,1,1,0,0,0,0,0,0,0,1,1,2,0,0],
    [2,1,1,1,1,1,1,1,1,1,1,1,1,1,2,0],
    [2,1,1,1,1,1,1,1,1,1,1,1,1,1,2,0],
    [0,2,1,1,0,0,0,0,0,0,0,1,1,2,0,0],
    [0,0,2,1,0,0,0,0,0,0,0,1,2,0,0,0],
    [0,0,0,2,0,0,0,0,0,0,0,2,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
];

/// Size vertical (NS) cursor
static CURSOR_SIZE_NS: [[u8; CURSOR_WIDTH]; CURSOR_HEIGHT] = [
    [0,0,0,0,0,0,0,2,2,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,2,1,1,2,0,0,0,0,0,0],
    [0,0,0,0,0,2,1,1,1,1,2,0,0,0,0,0],
    [0,0,0,0,2,1,1,1,1,1,1,2,0,0,0,0],
    [0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0],
    [0,0,0,0,2,1,1,1,1,1,1,2,0,0,0,0],
    [0,0,0,0,0,2,1,1,1,1,2,0,0,0,0,0],
    [0,0,0,0,0,0,2,1,1,2,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,2,2,0,0,0,0,0,0,0],
];

/// Size diagonal NW-SE cursor (top-left to bottom-right)
static CURSOR_SIZE_NWSE: [[u8; CURSOR_WIDTH]; CURSOR_HEIGHT] = [
    [2,2,2,2,2,2,0,0,0,0,0,0,0,0,0,0],
    [2,1,1,1,1,2,0,0,0,0,0,0,0,0,0,0],
    [2,1,1,1,2,0,0,0,0,0,0,0,0,0,0,0],
    [2,1,1,1,1,2,0,0,0,0,0,0,0,0,0,0],
    [2,1,2,1,1,1,2,0,0,0,0,0,0,0,0,0],
    [2,2,0,0,2,1,1,2,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,1,1,2,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,2,1,1,2,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,2,1,1,2,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,2,1,1,2,0,2,2,0],
    [0,0,0,0,0,0,0,0,0,2,1,1,1,2,1,2],
    [0,0,0,0,0,0,0,0,0,0,2,1,1,1,1,2],
    [0,0,0,0,0,0,0,0,0,0,0,2,1,1,1,2],
    [0,0,0,0,0,0,0,0,0,0,2,1,1,1,1,2],
    [0,0,0,0,0,0,0,0,0,0,2,1,1,1,1,2],
    [0,0,0,0,0,0,0,0,0,0,0,2,2,2,2,2],
];

/// Size diagonal NE-SW cursor (top-right to bottom-left)
static CURSOR_SIZE_NESW: [[u8; CURSOR_WIDTH]; CURSOR_HEIGHT] = [
    [0,0,0,0,0,0,0,0,0,0,2,2,2,2,2,2],
    [0,0,0,0,0,0,0,0,0,0,2,1,1,1,1,2],
    [0,0,0,0,0,0,0,0,0,0,0,2,1,1,1,2],
    [0,0,0,0,0,0,0,0,0,0,2,1,1,1,1,2],
    [0,0,0,0,0,0,0,0,0,2,1,1,1,2,1,2],
    [0,0,0,0,0,0,0,0,2,1,1,2,0,0,2,2],
    [0,0,0,0,0,0,0,2,1,1,2,0,0,0,0,0],
    [0,0,0,0,0,0,2,1,1,2,0,0,0,0,0,0],
    [0,0,0,0,0,2,1,1,2,0,0,0,0,0,0,0],
    [0,2,2,0,2,1,1,2,0,0,0,0,0,0,0,0],
    [2,1,2,1,1,1,2,0,0,0,0,0,0,0,0,0],
    [2,1,1,1,1,2,0,0,0,0,0,0,0,0,0,0],
    [2,1,1,1,2,0,0,0,0,0,0,0,0,0,0,0],
    [2,1,1,1,1,2,0,0,0,0,0,0,0,0,0,0],
    [2,1,1,1,1,2,0,0,0,0,0,0,0,0,0,0],
    [2,2,2,2,2,0,0,0,0,0,0,0,0,0,0,0],
];

// ============================================================================
// Cursor State
// ============================================================================

/// Current cursor position X
static CURSOR_X: AtomicI32 = AtomicI32::new(0);

/// Current cursor position Y
static CURSOR_Y: AtomicI32 = AtomicI32::new(0);

/// Current cursor type
static CURRENT_CURSOR: AtomicU32 = AtomicU32::new(StandardCursor::Arrow as u32);

/// Cursor visible flag
static CURSOR_VISIBLE: AtomicBool = AtomicBool::new(true);

/// Cursor show count (for nested ShowCursor calls)
static CURSOR_SHOW_COUNT: AtomicI32 = AtomicI32::new(0);

/// Background save buffer for cursor restoration
static CURSOR_BACKGROUND: SpinLock<CursorBackground> = SpinLock::new(CursorBackground::new());

struct CursorBackground {
    /// Saved pixels under cursor
    pixels: [[u32; CURSOR_WIDTH]; CURSOR_HEIGHT],
    /// Last drawn position
    last_x: i32,
    last_y: i32,
    /// Background is valid
    valid: bool,
}

impl CursorBackground {
    const fn new() -> Self {
        Self {
            pixels: [[0; CURSOR_WIDTH]; CURSOR_HEIGHT],
            last_x: -1,
            last_y: -1,
            valid: false,
        }
    }
}

// ============================================================================
// Cursor Operations
// ============================================================================

/// Initialize cursor system
pub fn init() {
    // Get screen center
    let (width, height) = surface::get_primary_dimensions();
    let cx = (width / 2) as i32;
    let cy = (height / 2) as i32;

    CURSOR_X.store(cx, Ordering::Relaxed);
    CURSOR_Y.store(cy, Ordering::Relaxed);
    CURSOR_VISIBLE.store(true, Ordering::Relaxed);
    CURSOR_SHOW_COUNT.store(0, Ordering::Relaxed);

    crate::serial_println!("[USER/Cursor] Cursor initialized at ({}, {})", cx, cy);
}

/// Get cursor bitmap for a standard cursor type
fn get_cursor_bitmap(cursor: StandardCursor) -> &'static [[u8; CURSOR_WIDTH]; CURSOR_HEIGHT] {
    match cursor {
        StandardCursor::Arrow => &CURSOR_ARROW,
        StandardCursor::IBeam => &CURSOR_IBEAM,
        StandardCursor::Wait => &CURSOR_WAIT,
        StandardCursor::Cross => &CURSOR_CROSS,
        StandardCursor::Hand => &CURSOR_HAND,
        StandardCursor::SizeWE => &CURSOR_SIZE_WE,
        StandardCursor::SizeNS => &CURSOR_SIZE_NS,
        StandardCursor::SizeNWSE => &CURSOR_SIZE_NWSE,
        StandardCursor::SizeNESW => &CURSOR_SIZE_NESW,
        // For unimplemented cursors, use arrow
        _ => &CURSOR_ARROW,
    }
}

/// Get cursor hotspot (click point relative to top-left)
fn get_cursor_hotspot(cursor: StandardCursor) -> Point {
    match cursor {
        StandardCursor::Arrow => Point::new(0, 0),
        StandardCursor::IBeam => Point::new(5, 8),
        StandardCursor::Wait => Point::new(5, 8),
        StandardCursor::Cross => Point::new(7, 7),
        StandardCursor::Hand => Point::new(6, 0),
        StandardCursor::SizeWE => Point::new(7, 7),
        StandardCursor::SizeNS => Point::new(7, 7),
        StandardCursor::SizeNWSE => Point::new(7, 7),
        StandardCursor::SizeNESW => Point::new(7, 7),
        StandardCursor::SizeAll => Point::new(7, 7),
        _ => Point::new(0, 0),
    }
}

/// Set cursor type
pub fn set_cursor(cursor: StandardCursor) -> StandardCursor {
    let old = CURRENT_CURSOR.swap(cursor as u32, Ordering::Relaxed);
    StandardCursor::try_from(old).unwrap_or(StandardCursor::Arrow)
}

/// Get current cursor type
pub fn get_cursor() -> StandardCursor {
    StandardCursor::try_from(CURRENT_CURSOR.load(Ordering::Relaxed))
        .unwrap_or(StandardCursor::Arrow)
}

impl TryFrom<u32> for StandardCursor {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(StandardCursor::Arrow),
            1 => Ok(StandardCursor::IBeam),
            2 => Ok(StandardCursor::Wait),
            3 => Ok(StandardCursor::Cross),
            4 => Ok(StandardCursor::UpArrow),
            5 => Ok(StandardCursor::SizeNWSE),
            6 => Ok(StandardCursor::SizeNESW),
            7 => Ok(StandardCursor::SizeWE),
            8 => Ok(StandardCursor::SizeNS),
            9 => Ok(StandardCursor::SizeAll),
            10 => Ok(StandardCursor::No),
            11 => Ok(StandardCursor::Hand),
            12 => Ok(StandardCursor::AppStarting),
            13 => Ok(StandardCursor::Help),
            _ => Err(()),
        }
    }
}

/// Set cursor position
pub fn set_cursor_pos(x: i32, y: i32) {
    // Clamp to screen bounds
    let (width, height) = surface::get_primary_dimensions();
    let x = x.max(0).min(width as i32 - 1);
    let y = y.max(0).min(height as i32 - 1);

    CURSOR_X.store(x, Ordering::Relaxed);
    CURSOR_Y.store(y, Ordering::Relaxed);
}

/// Get cursor position
pub fn get_cursor_pos() -> Point {
    Point::new(
        CURSOR_X.load(Ordering::Relaxed),
        CURSOR_Y.load(Ordering::Relaxed),
    )
}

/// Move cursor by delta
pub fn move_cursor(dx: i32, dy: i32) {
    let x = CURSOR_X.load(Ordering::Relaxed) + dx;
    let y = CURSOR_Y.load(Ordering::Relaxed) + dy;
    set_cursor_pos(x, y);
}

/// Show/hide cursor (returns previous show count)
pub fn show_cursor(show: bool) -> i32 {
    let old_count = if show {
        CURSOR_SHOW_COUNT.fetch_add(1, Ordering::Relaxed)
    } else {
        CURSOR_SHOW_COUNT.fetch_sub(1, Ordering::Relaxed)
    };

    let new_count = if show { old_count + 1 } else { old_count - 1 };
    CURSOR_VISIBLE.store(new_count >= 0, Ordering::Relaxed);

    old_count
}

/// Check if cursor is visible
pub fn is_cursor_visible() -> bool {
    CURSOR_VISIBLE.load(Ordering::Relaxed) && CURSOR_SHOW_COUNT.load(Ordering::Relaxed) >= 0
}

/// Hide cursor (restore background)
pub fn hide_cursor_internal() {
    let mut bg = CURSOR_BACKGROUND.lock();

    if !bg.valid {
        return;
    }

    // Use primary surface directly so cursor appears on top after buffer swap
    let surface_handle = surface::get_primary_surface();
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    // Restore background pixels
    for row in 0..CURSOR_HEIGHT {
        for col in 0..CURSOR_WIDTH {
            let x = bg.last_x + col as i32;
            let y = bg.last_y + row as i32;

            // Convert saved BGRA back to ColorRef
            let pixel = bg.pixels[row][col];
            let color = ColorRef::rgb(
                ((pixel >> 16) & 0xFF) as u8,
                ((pixel >> 8) & 0xFF) as u8,
                (pixel & 0xFF) as u8,
            );

            surf.set_pixel(x, y, color);
        }
    }

    bg.valid = false;
}

/// Draw cursor at current position
pub fn draw_cursor() {
    if !is_cursor_visible() {
        return;
    }

    // Use primary surface directly so cursor appears on top after buffer swap
    let surface_handle = surface::get_primary_surface();
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let cursor_type = get_cursor();
    let bitmap = get_cursor_bitmap(cursor_type);
    let hotspot = get_cursor_hotspot(cursor_type);

    let x = CURSOR_X.load(Ordering::Relaxed) - hotspot.x;
    let y = CURSOR_Y.load(Ordering::Relaxed) - hotspot.y;

    let mut bg = CURSOR_BACKGROUND.lock();

    // First, restore old background if valid
    if bg.valid {
        for row in 0..CURSOR_HEIGHT {
            for col in 0..CURSOR_WIDTH {
                let px = bg.last_x + col as i32;
                let py = bg.last_y + row as i32;

                let pixel = bg.pixels[row][col];
                let color = ColorRef::rgb(
                    ((pixel >> 16) & 0xFF) as u8,
                    ((pixel >> 8) & 0xFF) as u8,
                    (pixel & 0xFF) as u8,
                );

                surf.set_pixel(px, py, color);
            }
        }
    }

    // Save new background
    for row in 0..CURSOR_HEIGHT {
        for col in 0..CURSOR_WIDTH {
            let px = x + col as i32;
            let py = y + row as i32;

            if let Some(color) = surf.get_pixel(px, py) {
                bg.pixels[row][col] = color.to_bgra();
            } else {
                bg.pixels[row][col] = 0;
            }
        }
    }

    bg.last_x = x;
    bg.last_y = y;
    bg.valid = true;

    // Draw cursor
    for row in 0..CURSOR_HEIGHT {
        for col in 0..CURSOR_WIDTH {
            let pixel = bitmap[row][col];
            if pixel == 0 {
                continue; // Transparent
            }

            let color = if pixel == 1 {
                ColorRef::WHITE
            } else {
                ColorRef::BLACK
            };

            surf.set_pixel(x + col as i32, y + row as i32, color);
        }
    }
}

/// Update cursor (call this when mouse moves)
pub fn update_cursor() {
    draw_cursor();
}

/// Invalidate cursor background (prevents restoring old pixels)
pub fn invalidate_cursor_background() {
    let mut bg = CURSOR_BACKGROUND.lock();
    bg.valid = false;
}

/// Clip cursor to rectangle
pub fn clip_cursor(left: i32, top: i32, right: i32, bottom: i32) {
    let x = CURSOR_X.load(Ordering::Relaxed);
    let y = CURSOR_Y.load(Ordering::Relaxed);

    let new_x = x.max(left).min(right - 1);
    let new_y = y.max(top).min(bottom - 1);

    if new_x != x || new_y != y {
        set_cursor_pos(new_x, new_y);
    }
}
