//! Caret (Text Cursor) Subsystem
//!
//! Implementation of Windows NT-style caret for text editing.
//! Provides blinking text cursor support for edit controls.
//!
//! # Components
//!
//! - **Caret creation**: CreateCaret, DestroyCaret
//! - **Visibility**: ShowCaret, HideCaret
//! - **Position**: SetCaretPos, GetCaretPos
//! - **Blink timing**: SetCaretBlinkTime, GetCaretBlinkTime
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/caret.c`

use super::super::{HWND, UserHandle, Rect, Point};
use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Default caret blink time in milliseconds
const DEFAULT_BLINK_TIME: u32 = 530;

/// Caret blink timer ID
const CARET_TIMER_ID: usize = 0xFFFF;

/// Disable blinking (caret always visible)
const BLINK_DISABLED: u32 = u32::MAX;

// ============================================================================
// Caret State
// ============================================================================

/// Caret state for a window
#[derive(Clone, Copy)]
struct CaretState {
    /// Window that owns the caret
    hwnd: HWND,
    /// Caret X position (client coordinates)
    x: i32,
    /// Caret Y position (client coordinates)
    y: i32,
    /// Caret width
    width: i32,
    /// Caret height
    height: i32,
    /// Hide level (0 = visible, >0 = hidden)
    hide_level: i32,
    /// Is the caret logically "on" (not hidden by user)
    is_on: bool,
    /// Is the caret currently visible (drawn on screen)
    is_visible: bool,
    /// Caret blink state (true = drawn, false = erased)
    blink_state: bool,
    /// Bitmap handle (0 = solid, 1 = gray pattern)
    bitmap: u32,
    /// Is the caret active?
    active: bool,
}

impl CaretState {
    const fn empty() -> Self {
        Self {
            hwnd: UserHandle::NULL,
            x: 0,
            y: 0,
            width: 1,
            height: 16,
            hide_level: 1,
            is_on: false,
            is_visible: false,
            blink_state: false,
            bitmap: 0,
            active: false,
        }
    }
}

/// Global caret state (one caret per thread, but simplified for now)
static CARET: SpinLock<CaretState> = SpinLock::new(CaretState::empty());

/// Caret blink time in milliseconds
static CARET_BLINK_TIME: AtomicU32 = AtomicU32::new(DEFAULT_BLINK_TIME);

/// Last blink timestamp
static LAST_BLINK_TIME: AtomicU32 = AtomicU32::new(0);

static CARET_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize caret subsystem
pub fn init() {
    if CARET_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[USER/Caret] Caret subsystem initialized");
    CARET_INITIALIZED.store(true, Ordering::Release);
}

// ============================================================================
// Caret Management
// ============================================================================

/// Create a caret for a window
///
/// # Arguments
/// * `hwnd` - Window to own the caret
/// * `bitmap` - Bitmap for caret shape (0 = solid, 1 = gray)
/// * `width` - Caret width in pixels (0 = system default)
/// * `height` - Caret height in pixels (0 = system default)
///
/// # Returns
/// true on success
pub fn create_caret(hwnd: HWND, bitmap: u32, width: i32, height: i32) -> bool {
    if hwnd == HWND::NULL {
        return false;
    }

    let mut caret = CARET.lock();

    // Destroy existing caret if any
    if caret.active && caret.hwnd != HWND::NULL {
        internal_destroy_caret(&mut caret);
    }

    // Use system defaults for zero dimensions
    let actual_width = if width == 0 { 1 } else { width };
    let actual_height = if height == 0 { 16 } else { height }; // SM_CYBORDER default

    caret.hwnd = hwnd;
    caret.x = 0;
    caret.y = 0;
    caret.width = actual_width;
    caret.height = actual_height;
    caret.hide_level = 1; // Start hidden
    caret.is_on = true;
    caret.is_visible = false;
    caret.blink_state = false;
    caret.bitmap = bitmap;
    caret.active = true;

    crate::serial_println!("[USER/Caret] Created caret for window {:x} ({}x{})",
        hwnd.raw(), actual_width, actual_height);

    true
}

/// Destroy the caret
pub fn destroy_caret() -> bool {
    let mut caret = CARET.lock();

    if !caret.active {
        return false;
    }

    internal_destroy_caret(&mut caret);

    crate::serial_println!("[USER/Caret] Destroyed caret");

    true
}

/// Internal caret destruction
fn internal_destroy_caret(caret: &mut CaretState) {
    // Hide it first if visible
    if caret.is_visible {
        caret.is_visible = false;
        // Would need to repaint the area
    }

    caret.hwnd = HWND::NULL;
    caret.active = false;
    caret.hide_level = 0;
    caret.is_on = false;
}

/// Show the caret
///
/// Decrements the hide level. Caret becomes visible when hide level reaches 0.
pub fn show_caret(hwnd: HWND) -> bool {
    let mut caret = CARET.lock();

    // Must be for the correct window (or NULL to just check ownership)
    if !caret.active {
        return false;
    }

    if hwnd != HWND::NULL && caret.hwnd != hwnd {
        return false;
    }

    // Already at minimum hide level
    if caret.hide_level == 0 {
        // Already visible
        if !caret.is_visible && caret.is_on {
            caret.is_visible = true;
            caret.blink_state = true;
            // Would draw caret here
        }
        return true;
    }

    caret.hide_level -= 1;

    // Just became visible
    if caret.hide_level == 0 && caret.is_on {
        caret.is_visible = true;
        caret.blink_state = true;
        // Would draw caret here

        crate::serial_println!("[USER/Caret] Caret shown at ({}, {})", caret.x, caret.y);
    }

    true
}

/// Hide the caret
///
/// Increments the hide level. Must call ShowCaret() the same number of times
/// to make the caret visible again.
pub fn hide_caret(hwnd: HWND) -> bool {
    let mut caret = CARET.lock();

    if !caret.active {
        return false;
    }

    if hwnd != HWND::NULL && caret.hwnd != hwnd {
        return false;
    }

    // Was visible, now hiding
    if caret.hide_level == 0 && caret.is_visible {
        caret.is_visible = false;
        // Would erase caret here
        crate::serial_println!("[USER/Caret] Caret hidden");
    }

    caret.hide_level += 1;

    true
}

/// Set caret position
///
/// # Arguments
/// * `x` - X position in client coordinates
/// * `y` - Y position in client coordinates
pub fn set_caret_pos(x: i32, y: i32) -> bool {
    let mut caret = CARET.lock();

    if !caret.active {
        return false;
    }

    // No change needed
    if caret.x == x && caret.y == y {
        return true;
    }

    // If visible, need to redraw
    let was_visible = caret.is_visible;
    if was_visible {
        // Would erase caret at old position
        caret.is_visible = false;
    }

    caret.x = x;
    caret.y = y;

    // Reset blink state to "on"
    caret.blink_state = true;
    caret.is_on = true;

    // Redraw if was visible
    if was_visible && caret.hide_level == 0 {
        caret.is_visible = true;
        // Would draw caret at new position
    }

    true
}

/// Get caret position
///
/// # Returns
/// (x, y) position or (0, 0) if no caret
pub fn get_caret_pos() -> (i32, i32) {
    let caret = CARET.lock();

    if !caret.active {
        return (0, 0);
    }

    (caret.x, caret.y)
}

/// Get caret position as Point
pub fn get_caret_pos_point(point: &mut Point) -> bool {
    let caret = CARET.lock();

    if !caret.active {
        point.x = 0;
        point.y = 0;
        return false;
    }

    point.x = caret.x;
    point.y = caret.y;
    true
}

// ============================================================================
// Blink Timing
// ============================================================================

/// Set caret blink time
///
/// # Arguments
/// * `blink_time` - Blink time in milliseconds (0xFFFFFFFF to disable blinking)
pub fn set_caret_blink_time(blink_time: u32) -> bool {
    CARET_BLINK_TIME.store(blink_time, Ordering::Release);

    crate::serial_println!("[USER/Caret] Set blink time to {}ms", blink_time);

    true
}

/// Get caret blink time
pub fn get_caret_blink_time() -> u32 {
    CARET_BLINK_TIME.load(Ordering::Acquire)
}

/// Blink callback - should be called periodically by timer system
///
/// # Arguments
/// * `current_time` - Current time in milliseconds
pub fn caret_blink_tick(current_time: u32) {
    let blink_time = CARET_BLINK_TIME.load(Ordering::Acquire);

    // Blinking disabled?
    if blink_time == BLINK_DISABLED {
        return;
    }

    let last = LAST_BLINK_TIME.load(Ordering::Acquire);

    // Time to toggle?
    if current_time.wrapping_sub(last) >= blink_time {
        LAST_BLINK_TIME.store(current_time, Ordering::Release);

        let mut caret = CARET.lock();

        if caret.active && caret.hide_level == 0 {
            // Toggle blink state
            caret.blink_state = !caret.blink_state;
            caret.is_visible = caret.blink_state && caret.is_on;

            // Would redraw caret here
        }
    }
}

// ============================================================================
// Caret Information
// ============================================================================

/// Get the window that owns the caret
pub fn get_caret_owner() -> HWND {
    let caret = CARET.lock();
    if caret.active {
        caret.hwnd
    } else {
        HWND::NULL
    }
}

/// Get caret rectangle
pub fn get_caret_rect() -> Rect {
    let caret = CARET.lock();

    if !caret.active {
        return Rect::new(0, 0, 0, 0);
    }

    Rect::new(
        caret.x,
        caret.y,
        caret.x + caret.width,
        caret.y + caret.height,
    )
}

/// Check if caret is visible
pub fn is_caret_visible() -> bool {
    let caret = CARET.lock();
    caret.active && caret.is_visible
}

// ============================================================================
// Drawing Support
// ============================================================================

/// Get caret drawing information
///
/// Returns None if caret should not be drawn
pub fn get_caret_draw_info() -> Option<CaretDrawInfo> {
    let caret = CARET.lock();

    if !caret.active || !caret.is_visible {
        return None;
    }

    Some(CaretDrawInfo {
        hwnd: caret.hwnd,
        x: caret.x,
        y: caret.y,
        width: caret.width,
        height: caret.height,
        is_gray: caret.bitmap == 1,
    })
}

/// Information for drawing the caret
#[derive(Debug, Clone, Copy)]
pub struct CaretDrawInfo {
    pub hwnd: HWND,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub is_gray: bool,
}

/// Draw the caret (XOR operation)
///
/// This should be called by the paint system when drawing a window
/// that contains the caret.
pub fn draw_caret(dc: super::super::GdiHandle) {
    let info = match get_caret_draw_info() {
        Some(info) => info,
        None => return,
    };

    // Draw caret as inverted rectangle (XOR)
    // In a real implementation, this would use GDI operations
    // For now, we'll just note that we would draw

    crate::serial_println!("[USER/Caret] Drawing caret at ({}, {}) size {}x{}",
        info.x, info.y, info.width, info.height);
}

// ============================================================================
// Statistics
// ============================================================================

/// Caret statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct CaretStats {
    pub active: bool,
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub blink_time: u32,
}

/// Get caret statistics
pub fn get_stats() -> CaretStats {
    let caret = CARET.lock();

    CaretStats {
        active: caret.active,
        visible: caret.is_visible,
        x: caret.x,
        y: caret.y,
        width: caret.width,
        height: caret.height,
        blink_time: CARET_BLINK_TIME.load(Ordering::Acquire),
    }
}
