//! Trackbar (Slider) Control - Windows Common Controls
//!
//! Implements the Trackbar control following the Windows Common Controls architecture.
//! Trackbars allow users to select a value from a range using a sliding thumb.
//!
//! # Features
//!
//! - Horizontal and vertical orientation
//! - Tick marks (automatic or manual)
//! - Selection range highlighting
//! - Tooltips showing current value
//! - Page and line size for keyboard navigation
//!
//! # Window Class
//!
//! The trackbar control uses the "msctls_trackbar32" class name.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/commctrl.h` - Trackbar definitions

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, Rect};

// ============================================================================
// Trackbar Styles (TBS_*)
// ============================================================================

/// Automatic tick marks
pub const TBS_AUTOTICKS: u32 = 0x0001;
/// Vertical orientation
pub const TBS_VERT: u32 = 0x0002;
/// Horizontal orientation (default)
pub const TBS_HORZ: u32 = 0x0000;
/// Tick marks on top (horizontal)
pub const TBS_TOP: u32 = 0x0004;
/// Tick marks on bottom (horizontal, default)
pub const TBS_BOTTOM: u32 = 0x0000;
/// Tick marks on left (vertical)
pub const TBS_LEFT: u32 = 0x0004;
/// Tick marks on right (vertical, default)
pub const TBS_RIGHT: u32 = 0x0000;
/// Tick marks on both sides
pub const TBS_BOTH: u32 = 0x0008;
/// No tick marks
pub const TBS_NOTICKS: u32 = 0x0010;
/// Enable selection range
pub const TBS_ENABLESELRANGE: u32 = 0x0020;
/// Fixed length slider
pub const TBS_FIXEDLENGTH: u32 = 0x0040;
/// No thumb (slider button)
pub const TBS_NOTHUMB: u32 = 0x0080;
/// Enable tooltips
pub const TBS_TOOLTIPS: u32 = 0x0100;
/// Reversed (min=high, max=low)
pub const TBS_REVERSED: u32 = 0x0200;
/// Down is left, up is right
pub const TBS_DOWNISLEFT: u32 = 0x0400;

// ============================================================================
// Trackbar Messages (TBM_*)
// ============================================================================

/// WM_USER base for trackbar messages
const WM_USER: u32 = 0x0400;

/// Get current position
pub const TBM_GETPOS: u32 = WM_USER;
/// Get minimum value
pub const TBM_GETRANGEMIN: u32 = WM_USER + 1;
/// Get maximum value
pub const TBM_GETRANGEMAX: u32 = WM_USER + 2;
/// Get tick mark position
pub const TBM_GETTIC: u32 = WM_USER + 3;
/// Set a tick mark
pub const TBM_SETTIC: u32 = WM_USER + 4;
/// Set position
pub const TBM_SETPOS: u32 = WM_USER + 5;
/// Set range (min and max)
pub const TBM_SETRANGE: u32 = WM_USER + 6;
/// Set minimum value
pub const TBM_SETRANGEMIN: u32 = WM_USER + 7;
/// Set maximum value
pub const TBM_SETRANGEMAX: u32 = WM_USER + 8;
/// Clear all tick marks
pub const TBM_CLEARTICS: u32 = WM_USER + 9;
/// Set selection range
pub const TBM_SETSEL: u32 = WM_USER + 10;
/// Set selection start
pub const TBM_SETSELSTART: u32 = WM_USER + 11;
/// Set selection end
pub const TBM_SETSELEND: u32 = WM_USER + 12;
/// Get tick mark positions array
pub const TBM_GETPTICS: u32 = WM_USER + 14;
/// Get tick mark pixel position
pub const TBM_GETTICPOS: u32 = WM_USER + 15;
/// Get number of tick marks
pub const TBM_GETNUMTICS: u32 = WM_USER + 16;
/// Get selection start
pub const TBM_GETSELSTART: u32 = WM_USER + 17;
/// Get selection end
pub const TBM_GETSELEND: u32 = WM_USER + 18;
/// Clear selection
pub const TBM_CLEARSEL: u32 = WM_USER + 19;
/// Set tick mark frequency
pub const TBM_SETTICFREQ: u32 = WM_USER + 20;
/// Set page size
pub const TBM_SETPAGESIZE: u32 = WM_USER + 21;
/// Get page size
pub const TBM_GETPAGESIZE: u32 = WM_USER + 22;
/// Set line size
pub const TBM_SETLINESIZE: u32 = WM_USER + 23;
/// Get line size
pub const TBM_GETLINESIZE: u32 = WM_USER + 24;
/// Get thumb rectangle
pub const TBM_GETTHUMBRECT: u32 = WM_USER + 25;
/// Get channel rectangle
pub const TBM_GETCHANNELRECT: u32 = WM_USER + 26;
/// Set thumb length
pub const TBM_SETTHUMBLENGTH: u32 = WM_USER + 27;
/// Get thumb length
pub const TBM_GETTHUMBLENGTH: u32 = WM_USER + 28;
/// Set tooltip control
pub const TBM_SETTOOLTIPS: u32 = WM_USER + 29;
/// Get tooltip control
pub const TBM_GETTOOLTIPS: u32 = WM_USER + 30;
/// Set tooltip side
pub const TBM_SETTIPSIDE: u32 = WM_USER + 31;
/// Set buddy window
pub const TBM_SETBUDDY: u32 = WM_USER + 32;
/// Get buddy window
pub const TBM_GETBUDDY: u32 = WM_USER + 33;

// ============================================================================
// Tooltip Side Constants
// ============================================================================

/// Tooltip on top
pub const TBTS_TOP: u32 = 0;
/// Tooltip on left
pub const TBTS_LEFT: u32 = 1;
/// Tooltip on bottom
pub const TBTS_BOTTOM: u32 = 2;
/// Tooltip on right
pub const TBTS_RIGHT: u32 = 3;

// ============================================================================
// Trackbar Notification Codes (TB_*)
// ============================================================================

/// Line up (left arrow or up arrow)
pub const TB_LINEUP: u32 = 0;
/// Line down (right arrow or down arrow)
pub const TB_LINEDOWN: u32 = 1;
/// Page up (PgUp or click above thumb)
pub const TB_PAGEUP: u32 = 2;
/// Page down (PgDn or click below thumb)
pub const TB_PAGEDOWN: u32 = 3;
/// Thumb moved to position
pub const TB_THUMBPOSITION: u32 = 4;
/// Thumb is being dragged
pub const TB_THUMBTRACK: u32 = 5;
/// Top (Home key)
pub const TB_TOP: u32 = 6;
/// Bottom (End key)
pub const TB_BOTTOM: u32 = 7;
/// End of tracking
pub const TB_ENDTRACK: u32 = 8;

// ============================================================================
// Custom Draw Item Specs
// ============================================================================

/// Draw tick marks
pub const TBCD_TICS: u32 = 0x0001;
/// Draw thumb
pub const TBCD_THUMB: u32 = 0x0002;
/// Draw channel
pub const TBCD_CHANNEL: u32 = 0x0003;

// ============================================================================
// Configuration
// ============================================================================

/// Maximum trackbar controls
const MAX_TRACKBARS: usize = 128;

/// Maximum custom tick marks per trackbar
const MAX_TICS: usize = 128;

/// Default minimum value
const DEFAULT_MIN: i32 = 0;

/// Default maximum value
const DEFAULT_MAX: i32 = 100;

/// Default line size
const DEFAULT_LINE_SIZE: i32 = 1;

/// Default page size (10% of range)
const DEFAULT_PAGE_SIZE: i32 = 10;

/// Default thumb length
const DEFAULT_THUMB_LENGTH: i32 = 20;

/// Default channel height
const DEFAULT_CHANNEL_HEIGHT: i32 = 4;

// ============================================================================
// Structures
// ============================================================================

/// Trackbar control state
#[derive(Clone, Copy)]
struct TrackbarControl {
    /// Control in use
    in_use: bool,
    /// Window handle
    hwnd: HWND,
    /// Style flags
    style: u32,
    /// Current position
    position: i32,
    /// Minimum value
    range_min: i32,
    /// Maximum value
    range_max: i32,
    /// Selection start (if TBS_ENABLESELRANGE)
    sel_start: i32,
    /// Selection end
    sel_end: i32,
    /// Line size (arrow keys)
    line_size: i32,
    /// Page size (PgUp/PgDn)
    page_size: i32,
    /// Tick frequency (for TBS_AUTOTICKS)
    tic_freq: i32,
    /// Number of custom tick marks
    num_tics: usize,
    /// Custom tick mark positions
    tics: [i32; MAX_TICS],
    /// Thumb length
    thumb_length: i32,
    /// Tooltip side
    tip_side: u32,
    /// Left/top buddy window
    buddy_left: HWND,
    /// Right/bottom buddy window
    buddy_right: HWND,
    /// Currently dragging thumb
    dragging: bool,
    /// Has focus
    has_focus: bool,
}

impl TrackbarControl {
    const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: UserHandle(0),
            style: 0,
            position: DEFAULT_MIN,
            range_min: DEFAULT_MIN,
            range_max: DEFAULT_MAX,
            sel_start: 0,
            sel_end: 0,
            line_size: DEFAULT_LINE_SIZE,
            page_size: DEFAULT_PAGE_SIZE,
            tic_freq: 1,
            num_tics: 0,
            tics: [0; MAX_TICS],
            thumb_length: DEFAULT_THUMB_LENGTH,
            tip_side: TBTS_TOP,
            buddy_left: UserHandle(0),
            buddy_right: UserHandle(0),
            dragging: false,
            has_focus: false,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Trackbar subsystem initialized
static TRACKBAR_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Trackbar lock
static TRACKBAR_LOCK: SpinLock<()> = SpinLock::new(());

/// All trackbar controls
static TRACKBARS: SpinLock<[TrackbarControl; MAX_TRACKBARS]> =
    SpinLock::new([const { TrackbarControl::new() }; MAX_TRACKBARS]);

/// Trackbar count
static TRACKBAR_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize trackbar subsystem
pub fn init() {
    let _guard = TRACKBAR_LOCK.lock();

    if TRACKBAR_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[TRACKBAR] Initializing Trackbar Control...");

    TRACKBAR_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[TRACKBAR] Trackbar Control initialized");
}

// ============================================================================
// Trackbar Creation and Deletion
// ============================================================================

/// Create a trackbar control
pub fn create_trackbar(hwnd: HWND, style: u32) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut trackbars = TRACKBARS.lock();

    // Check if already exists
    for tb in trackbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            return false;
        }
    }

    // Find free slot
    for tb in trackbars.iter_mut() {
        if !tb.in_use {
            tb.in_use = true;
            tb.hwnd = hwnd;
            tb.style = style;
            tb.position = DEFAULT_MIN;
            tb.range_min = DEFAULT_MIN;
            tb.range_max = DEFAULT_MAX;
            tb.sel_start = 0;
            tb.sel_end = 0;
            tb.line_size = DEFAULT_LINE_SIZE;
            tb.page_size = DEFAULT_PAGE_SIZE;
            tb.tic_freq = 1;
            tb.num_tics = 0;
            tb.thumb_length = DEFAULT_THUMB_LENGTH;
            tb.tip_side = TBTS_TOP;
            tb.buddy_left = UserHandle(0);
            tb.buddy_right = UserHandle(0);
            tb.dragging = false;
            tb.has_focus = false;

            TRACKBAR_COUNT.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }

    false
}

/// Destroy a trackbar control
pub fn destroy_trackbar(hwnd: HWND) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut trackbars = TRACKBARS.lock();

    for tb in trackbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            tb.in_use = false;
            TRACKBAR_COUNT.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
    }

    false
}

// ============================================================================
// Position and Range
// ============================================================================

/// Get current position
pub fn get_pos(hwnd: HWND) -> i32 {
    if hwnd.0 == 0 {
        return 0;
    }

    let trackbars = TRACKBARS.lock();

    for tb in trackbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            return tb.position;
        }
    }

    0
}

/// Set current position
pub fn set_pos(hwnd: HWND, position: i32, redraw: bool) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let _ = redraw; // Would trigger repaint

    let mut trackbars = TRACKBARS.lock();

    for tb in trackbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            tb.position = position.clamp(tb.range_min, tb.range_max);
            return true;
        }
    }

    false
}

/// Get minimum value
pub fn get_range_min(hwnd: HWND) -> i32 {
    if hwnd.0 == 0 {
        return 0;
    }

    let trackbars = TRACKBARS.lock();

    for tb in trackbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            return tb.range_min;
        }
    }

    0
}

/// Get maximum value
pub fn get_range_max(hwnd: HWND) -> i32 {
    if hwnd.0 == 0 {
        return 0;
    }

    let trackbars = TRACKBARS.lock();

    for tb in trackbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            return tb.range_max;
        }
    }

    0
}

/// Set range
pub fn set_range(hwnd: HWND, min: i32, max: i32, redraw: bool) -> bool {
    if hwnd.0 == 0 || min >= max {
        return false;
    }

    let _ = redraw;

    let mut trackbars = TRACKBARS.lock();

    for tb in trackbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            tb.range_min = min;
            tb.range_max = max;

            // Clamp position to new range
            tb.position = tb.position.clamp(min, max);

            // Update page size to 10% of range
            let range = max - min;
            tb.page_size = (range / 10).max(1);

            return true;
        }
    }

    false
}

/// Set minimum value
pub fn set_range_min(hwnd: HWND, min: i32, redraw: bool) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let max = get_range_max(hwnd);
    if min >= max {
        return false;
    }

    set_range(hwnd, min, max, redraw)
}

/// Set maximum value
pub fn set_range_max(hwnd: HWND, max: i32, redraw: bool) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let min = get_range_min(hwnd);
    if min >= max {
        return false;
    }

    set_range(hwnd, min, max, redraw)
}

// ============================================================================
// Selection Range
// ============================================================================

/// Get selection start
pub fn get_sel_start(hwnd: HWND) -> i32 {
    if hwnd.0 == 0 {
        return 0;
    }

    let trackbars = TRACKBARS.lock();

    for tb in trackbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            return tb.sel_start;
        }
    }

    0
}

/// Get selection end
pub fn get_sel_end(hwnd: HWND) -> i32 {
    if hwnd.0 == 0 {
        return 0;
    }

    let trackbars = TRACKBARS.lock();

    for tb in trackbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            return tb.sel_end;
        }
    }

    0
}

/// Set selection range
pub fn set_sel(hwnd: HWND, start: i32, end: i32, redraw: bool) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let _ = redraw;

    let mut trackbars = TRACKBARS.lock();

    for tb in trackbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            tb.sel_start = start.clamp(tb.range_min, tb.range_max);
            tb.sel_end = end.clamp(tb.range_min, tb.range_max);

            // Ensure start <= end
            if tb.sel_start > tb.sel_end {
                core::mem::swap(&mut tb.sel_start, &mut tb.sel_end);
            }

            return true;
        }
    }

    false
}

/// Clear selection
pub fn clear_sel(hwnd: HWND, redraw: bool) -> bool {
    set_sel(hwnd, 0, 0, redraw)
}

// ============================================================================
// Tick Marks
// ============================================================================

/// Set tick mark frequency
pub fn set_tic_freq(hwnd: HWND, freq: i32) -> bool {
    if hwnd.0 == 0 || freq <= 0 {
        return false;
    }

    let mut trackbars = TRACKBARS.lock();

    for tb in trackbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            tb.tic_freq = freq;
            return true;
        }
    }

    false
}

/// Set a tick mark at position
pub fn set_tic(hwnd: HWND, position: i32) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut trackbars = TRACKBARS.lock();

    for tb in trackbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            if tb.num_tics >= MAX_TICS {
                return false;
            }

            // Don't add duplicates
            for i in 0..tb.num_tics {
                if tb.tics[i] == position {
                    return true;
                }
            }

            tb.tics[tb.num_tics] = position;
            tb.num_tics += 1;
            return true;
        }
    }

    false
}

/// Clear all tick marks
pub fn clear_tics(hwnd: HWND, redraw: bool) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let _ = redraw;

    let mut trackbars = TRACKBARS.lock();

    for tb in trackbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            tb.num_tics = 0;
            return true;
        }
    }

    false
}

/// Get number of tick marks
pub fn get_num_tics(hwnd: HWND) -> usize {
    if hwnd.0 == 0 {
        return 0;
    }

    let trackbars = TRACKBARS.lock();

    for tb in trackbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            // Include automatic ticks if TBS_AUTOTICKS
            if (tb.style & TBS_AUTOTICKS) != 0 {
                let range = tb.range_max - tb.range_min;
                let auto_tics = (range / tb.tic_freq) as usize + 1;
                return auto_tics + tb.num_tics;
            }
            return tb.num_tics + 2; // +2 for min and max
        }
    }

    0
}

/// Get tick mark position at index
pub fn get_tic(hwnd: HWND, index: usize) -> i32 {
    if hwnd.0 == 0 {
        return -1;
    }

    let trackbars = TRACKBARS.lock();

    for tb in trackbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            if index < tb.num_tics {
                return tb.tics[index];
            }
        }
    }

    -1
}

// ============================================================================
// Line and Page Size
// ============================================================================

/// Set line size
pub fn set_line_size(hwnd: HWND, size: i32) -> i32 {
    if hwnd.0 == 0 {
        return 0;
    }

    let mut trackbars = TRACKBARS.lock();

    for tb in trackbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            let old = tb.line_size;
            tb.line_size = size.max(1);
            return old;
        }
    }

    0
}

/// Get line size
pub fn get_line_size(hwnd: HWND) -> i32 {
    if hwnd.0 == 0 {
        return 0;
    }

    let trackbars = TRACKBARS.lock();

    for tb in trackbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            return tb.line_size;
        }
    }

    0
}

/// Set page size
pub fn set_page_size(hwnd: HWND, size: i32) -> i32 {
    if hwnd.0 == 0 {
        return 0;
    }

    let mut trackbars = TRACKBARS.lock();

    for tb in trackbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            let old = tb.page_size;
            tb.page_size = size.max(1);
            return old;
        }
    }

    0
}

/// Get page size
pub fn get_page_size(hwnd: HWND) -> i32 {
    if hwnd.0 == 0 {
        return 0;
    }

    let trackbars = TRACKBARS.lock();

    for tb in trackbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            return tb.page_size;
        }
    }

    0
}

// ============================================================================
// Thumb
// ============================================================================

/// Set thumb length
pub fn set_thumb_length(hwnd: HWND, length: i32) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut trackbars = TRACKBARS.lock();

    for tb in trackbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            tb.thumb_length = length.max(1);
            return true;
        }
    }

    false
}

/// Get thumb length
pub fn get_thumb_length(hwnd: HWND) -> i32 {
    if hwnd.0 == 0 {
        return 0;
    }

    let trackbars = TRACKBARS.lock();

    for tb in trackbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            return tb.thumb_length;
        }
    }

    0
}

/// Get thumb rectangle
pub fn get_thumb_rect(hwnd: HWND) -> Option<Rect> {
    if hwnd.0 == 0 {
        return None;
    }

    let trackbars = TRACKBARS.lock();

    for tb in trackbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            // Calculate thumb position based on value
            let range = tb.range_max - tb.range_min;
            if range <= 0 {
                return None;
            }

            let is_vertical = (tb.style & TBS_VERT) != 0;

            // Simplified calculation - would need actual window dimensions
            let channel_length = 200; // Placeholder
            let pos_ratio = (tb.position - tb.range_min) as f32 / range as f32;
            let thumb_pos = (pos_ratio * channel_length as f32) as i32;

            if is_vertical {
                return Some(Rect {
                    left: 5,
                    top: thumb_pos,
                    right: 25,
                    bottom: thumb_pos + tb.thumb_length,
                });
            } else {
                return Some(Rect {
                    left: thumb_pos,
                    top: 5,
                    right: thumb_pos + tb.thumb_length,
                    bottom: 25,
                });
            }
        }
    }

    None
}

/// Get channel rectangle
pub fn get_channel_rect(hwnd: HWND) -> Option<Rect> {
    if hwnd.0 == 0 {
        return None;
    }

    let trackbars = TRACKBARS.lock();

    for tb in trackbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            let is_vertical = (tb.style & TBS_VERT) != 0;

            // Simplified - would need actual window dimensions
            if is_vertical {
                return Some(Rect {
                    left: 12,
                    top: 0,
                    right: 18,
                    bottom: 200,
                });
            } else {
                return Some(Rect {
                    left: 0,
                    top: 12,
                    right: 200,
                    bottom: 18,
                });
            }
        }
    }

    None
}

// ============================================================================
// Buddy Windows
// ============================================================================

/// Set buddy window
pub fn set_buddy(hwnd: HWND, buddy: HWND, is_left: bool) -> HWND {
    if hwnd.0 == 0 {
        return UserHandle(0);
    }

    let mut trackbars = TRACKBARS.lock();

    for tb in trackbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            let old = if is_left { tb.buddy_left } else { tb.buddy_right };

            if is_left {
                tb.buddy_left = buddy;
            } else {
                tb.buddy_right = buddy;
            }

            return old;
        }
    }

    UserHandle(0)
}

/// Get buddy window
pub fn get_buddy(hwnd: HWND, is_left: bool) -> HWND {
    if hwnd.0 == 0 {
        return UserHandle(0);
    }

    let trackbars = TRACKBARS.lock();

    for tb in trackbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            return if is_left { tb.buddy_left } else { tb.buddy_right };
        }
    }

    UserHandle(0)
}

// ============================================================================
// Tooltip
// ============================================================================

/// Set tooltip side
pub fn set_tip_side(hwnd: HWND, side: u32) -> u32 {
    if hwnd.0 == 0 {
        return TBTS_TOP;
    }

    let mut trackbars = TRACKBARS.lock();

    for tb in trackbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            let old = tb.tip_side;
            tb.tip_side = side;
            return old;
        }
    }

    TBTS_TOP
}

// ============================================================================
// Message Handler
// ============================================================================

/// Process trackbar message
///
/// # Returns
/// (handled, result)
pub fn process_message(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> (bool, isize) {
    match msg {
        TBM_GETPOS => {
            (true, get_pos(hwnd) as isize)
        }
        TBM_SETPOS => {
            let redraw = wparam != 0;
            let pos = lparam as i32;
            (true, set_pos(hwnd, pos, redraw) as isize)
        }
        TBM_GETRANGEMIN => {
            (true, get_range_min(hwnd) as isize)
        }
        TBM_GETRANGEMAX => {
            (true, get_range_max(hwnd) as isize)
        }
        TBM_SETRANGE => {
            let redraw = wparam != 0;
            let min = (lparam & 0xFFFF) as i16 as i32;
            let max = ((lparam >> 16) & 0xFFFF) as i16 as i32;
            (true, set_range(hwnd, min, max, redraw) as isize)
        }
        TBM_SETRANGEMIN => {
            let redraw = wparam != 0;
            (true, set_range_min(hwnd, lparam as i32, redraw) as isize)
        }
        TBM_SETRANGEMAX => {
            let redraw = wparam != 0;
            (true, set_range_max(hwnd, lparam as i32, redraw) as isize)
        }
        TBM_GETSELSTART => {
            (true, get_sel_start(hwnd) as isize)
        }
        TBM_GETSELEND => {
            (true, get_sel_end(hwnd) as isize)
        }
        TBM_SETSEL => {
            let redraw = wparam != 0;
            let start = (lparam & 0xFFFF) as i16 as i32;
            let end = ((lparam >> 16) & 0xFFFF) as i16 as i32;
            (true, set_sel(hwnd, start, end, redraw) as isize)
        }
        TBM_SETSELSTART => {
            let redraw = wparam != 0;
            let start = lparam as i32;
            let end = get_sel_end(hwnd);
            (true, set_sel(hwnd, start, end, redraw) as isize)
        }
        TBM_SETSELEND => {
            let redraw = wparam != 0;
            let start = get_sel_start(hwnd);
            let end = lparam as i32;
            (true, set_sel(hwnd, start, end, redraw) as isize)
        }
        TBM_CLEARSEL => {
            let redraw = wparam != 0;
            (true, clear_sel(hwnd, redraw) as isize)
        }
        TBM_SETTIC => {
            (true, set_tic(hwnd, lparam as i32) as isize)
        }
        TBM_CLEARTICS => {
            let redraw = wparam != 0;
            (true, clear_tics(hwnd, redraw) as isize)
        }
        TBM_SETTICFREQ => {
            (true, set_tic_freq(hwnd, wparam as i32) as isize)
        }
        TBM_GETNUMTICS => {
            (true, get_num_tics(hwnd) as isize)
        }
        TBM_GETTIC => {
            (true, get_tic(hwnd, wparam) as isize)
        }
        TBM_SETLINESIZE => {
            (true, set_line_size(hwnd, lparam as i32) as isize)
        }
        TBM_GETLINESIZE => {
            (true, get_line_size(hwnd) as isize)
        }
        TBM_SETPAGESIZE => {
            (true, set_page_size(hwnd, lparam as i32) as isize)
        }
        TBM_GETPAGESIZE => {
            (true, get_page_size(hwnd) as isize)
        }
        TBM_SETTHUMBLENGTH => {
            (true, set_thumb_length(hwnd, wparam as i32) as isize)
        }
        TBM_GETTHUMBLENGTH => {
            (true, get_thumb_length(hwnd) as isize)
        }
        TBM_GETTHUMBRECT => {
            if get_thumb_rect(hwnd).is_some() {
                // Would write rect to lparam
                (true, 1)
            } else {
                (true, 0)
            }
        }
        TBM_GETCHANNELRECT => {
            if get_channel_rect(hwnd).is_some() {
                // Would write rect to lparam
                (true, 1)
            } else {
                (true, 0)
            }
        }
        TBM_SETBUDDY => {
            let is_left = wparam != 0;
            let buddy = UserHandle(lparam as u32);
            (true, set_buddy(hwnd, buddy, is_left).0 as isize)
        }
        TBM_GETBUDDY => {
            let is_left = wparam != 0;
            (true, get_buddy(hwnd, is_left).0 as isize)
        }
        TBM_SETTIPSIDE => {
            (true, set_tip_side(hwnd, wparam as u32) as isize)
        }
        _ => (false, 0),
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Get number of trackbar controls
pub fn get_trackbar_count() -> u32 {
    TRACKBAR_COUNT.load(Ordering::Relaxed)
}
