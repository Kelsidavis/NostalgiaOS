//! ProgressBar Control Implementation
//!
//! Implements the Windows ProgressBar control for displaying progress information.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/commctrl.h` - Control styles and messages
//! - `shell/comctl32/progress.c` - ProgressBar implementation

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, Rect, ColorRef};

// ============================================================================
// Progress Bar Class
// ============================================================================

/// Progress bar window class name
pub const PROGRESS_CLASS: &str = "msctls_progress32";

// ============================================================================
// Progress Bar Styles (PBS_*)
// ============================================================================

/// Smooth progress bar (continuous fill instead of blocks)
pub const PBS_SMOOTH: u32 = 0x01;

/// Vertical progress bar
pub const PBS_VERTICAL: u32 = 0x04;

/// Marquee mode (indeterminate progress animation)
pub const PBS_MARQUEE: u32 = 0x08;

// ============================================================================
// Progress Bar Messages (PBM_*)
// ============================================================================

/// WM_USER base for progress bar messages
const WM_USER: u32 = 0x0400;

/// Set range (16-bit: wParam=0, lParam=MAKELPARAM(low, high))
pub const PBM_SETRANGE: u32 = WM_USER + 1;

/// Set position (returns previous position)
pub const PBM_SETPOS: u32 = WM_USER + 2;

/// Delta position (add to current position)
pub const PBM_DELTAPOS: u32 = WM_USER + 3;

/// Set step increment
pub const PBM_SETSTEP: u32 = WM_USER + 4;

/// Step the position by step increment
pub const PBM_STEPIT: u32 = WM_USER + 5;

/// Set 32-bit range (wParam=low, lParam=high)
pub const PBM_SETRANGE32: u32 = WM_USER + 6;

/// Get range (wParam=return_low?, lParam=PPBRANGE or NULL)
pub const PBM_GETRANGE: u32 = WM_USER + 7;

/// Get current position
pub const PBM_GETPOS: u32 = WM_USER + 8;

/// Set bar color
pub const PBM_SETBARCOLOR: u32 = WM_USER + 9;

/// Set marquee mode (wParam=enable, lParam=update_interval_ms)
pub const PBM_SETMARQUEE: u32 = WM_USER + 10;

/// Set background color (CCM_SETBKCOLOR = 0x2001)
pub const PBM_SETBKCOLOR: u32 = 0x2001;

// ============================================================================
// Progress Bar Range Structure
// ============================================================================

/// Progress bar range
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PbRange {
    /// Low value
    pub low: i32,
    /// High value
    pub high: i32,
}

// ============================================================================
// Progress Bar State
// ============================================================================

/// Maximum number of progress bar controls
const MAX_PROGRESSBARS: usize = 128;

/// Progress bar control state
#[derive(Debug)]
pub struct ProgressBarControl {
    /// Control is in use
    in_use: bool,
    /// Associated window handle
    hwnd: HWND,
    /// Control styles
    style: u32,
    /// Minimum value
    range_min: i32,
    /// Maximum value
    range_max: i32,
    /// Current position
    position: i32,
    /// Step increment
    step: i32,
    /// Bar color (CLR_DEFAULT = 0xFFFFFFFF means use system color)
    bar_color: u32,
    /// Background color
    bk_color: u32,
    /// Marquee mode enabled
    marquee_enabled: bool,
    /// Marquee animation position
    marquee_position: i32,
    /// Marquee update interval (ms)
    marquee_interval: u32,
}

impl ProgressBarControl {
    const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: HWND::NULL,
            style: 0,
            range_min: 0,
            range_max: 100,
            position: 0,
            step: 10,
            bar_color: 0xFFFFFFFF, // CLR_DEFAULT
            bk_color: 0xFFFFFFFF,  // CLR_DEFAULT
            marquee_enabled: false,
            marquee_position: 0,
            marquee_interval: 30,
        }
    }

    fn reset(&mut self) {
        self.in_use = false;
        self.hwnd = HWND::NULL;
        self.style = 0;
        self.range_min = 0;
        self.range_max = 100;
        self.position = 0;
        self.step = 10;
        self.bar_color = 0xFFFFFFFF;
        self.bk_color = 0xFFFFFFFF;
        self.marquee_enabled = false;
        self.marquee_position = 0;
        self.marquee_interval = 30;
    }
}

// ============================================================================
// Global State
// ============================================================================

static PROGRESSBAR_INITIALIZED: AtomicBool = AtomicBool::new(false);
static PROGRESSBAR_COUNT: AtomicU32 = AtomicU32::new(0);
static PROGRESSBARS: SpinLock<[ProgressBarControl; MAX_PROGRESSBARS]> =
    SpinLock::new([const { ProgressBarControl::new() }; MAX_PROGRESSBARS]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize progress bar control subsystem
pub fn init() {
    if PROGRESSBAR_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[PROGRESSBAR] Initializing Progress Bar control...");

    PROGRESSBAR_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[PROGRESSBAR] Progress Bar control initialized");
}

// ============================================================================
// Progress Bar Creation/Destruction
// ============================================================================

/// Create a progress bar control
pub fn create_progressbar(hwnd: HWND, style: u32) -> Option<usize> {
    let mut bars = PROGRESSBARS.lock();

    // Find free slot
    for (index, bar) in bars.iter_mut().enumerate() {
        if !bar.in_use {
            bar.in_use = true;
            bar.hwnd = hwnd;
            bar.style = style;
            bar.range_min = 0;
            bar.range_max = 100;
            bar.position = 0;
            bar.step = 10;
            bar.bar_color = 0xFFFFFFFF;
            bar.bk_color = 0xFFFFFFFF;
            bar.marquee_enabled = (style & PBS_MARQUEE) != 0;
            bar.marquee_position = 0;
            bar.marquee_interval = 30;

            PROGRESSBAR_COUNT.fetch_add(1, Ordering::Relaxed);
            return Some(index);
        }
    }

    None
}

/// Destroy a progress bar control
pub fn destroy_progressbar(index: usize) -> bool {
    if index >= MAX_PROGRESSBARS {
        return false;
    }

    let mut bars = PROGRESSBARS.lock();
    if bars[index].in_use {
        bars[index].reset();
        PROGRESSBAR_COUNT.fetch_sub(1, Ordering::Relaxed);
        return true;
    }

    false
}

/// Find progress bar by window handle
pub fn find_progressbar(hwnd: HWND) -> Option<usize> {
    let bars = PROGRESSBARS.lock();
    for (index, bar) in bars.iter().enumerate() {
        if bar.in_use && bar.hwnd == hwnd {
            return Some(index);
        }
    }
    None
}

// ============================================================================
// Range Functions
// ============================================================================

/// Set progress bar range (16-bit)
pub fn set_range(index: usize, low: i16, high: i16) -> u32 {
    if index >= MAX_PROGRESSBARS {
        return 0;
    }

    let mut bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return 0;
    }

    let old_low = bars[index].range_min as u16;
    let old_high = bars[index].range_max as u16;

    bars[index].range_min = low as i32;
    bars[index].range_max = high as i32;

    // Clamp current position to new range
    if bars[index].position < bars[index].range_min {
        bars[index].position = bars[index].range_min;
    }
    if bars[index].position > bars[index].range_max {
        bars[index].position = bars[index].range_max;
    }

    // Return previous range as MAKELONG(low, high)
    ((old_high as u32) << 16) | (old_low as u32)
}

/// Set progress bar range (32-bit)
pub fn set_range32(index: usize, low: i32, high: i32) -> u32 {
    if index >= MAX_PROGRESSBARS {
        return 0;
    }

    let mut bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return 0;
    }

    let old_low = bars[index].range_min as u16;
    let old_high = bars[index].range_max as u16;

    bars[index].range_min = low;
    bars[index].range_max = high;

    // Clamp current position to new range
    if bars[index].position < bars[index].range_min {
        bars[index].position = bars[index].range_min;
    }
    if bars[index].position > bars[index].range_max {
        bars[index].position = bars[index].range_max;
    }

    // Return previous range as MAKELONG(low, high)
    ((old_high as u32) << 16) | (old_low as u32)
}

/// Get progress bar range
pub fn get_range(index: usize, return_low: bool) -> (i32, Option<PbRange>) {
    if index >= MAX_PROGRESSBARS {
        return (0, None);
    }

    let bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return (0, None);
    }

    let range = PbRange {
        low: bars[index].range_min,
        high: bars[index].range_max,
    };

    let value = if return_low {
        bars[index].range_min
    } else {
        bars[index].range_max
    };

    (value, Some(range))
}

// ============================================================================
// Position Functions
// ============================================================================

/// Set progress bar position
pub fn set_pos(index: usize, pos: i32) -> i32 {
    if index >= MAX_PROGRESSBARS {
        return 0;
    }

    let mut bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return 0;
    }

    let old_pos = bars[index].position;

    // Clamp position to range
    bars[index].position = pos.clamp(bars[index].range_min, bars[index].range_max);

    old_pos
}

/// Add delta to progress bar position
pub fn delta_pos(index: usize, delta: i32) -> i32 {
    if index >= MAX_PROGRESSBARS {
        return 0;
    }

    let mut bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return 0;
    }

    let old_pos = bars[index].position;
    let new_pos = old_pos.saturating_add(delta);

    // Clamp position to range
    bars[index].position = new_pos.clamp(bars[index].range_min, bars[index].range_max);

    old_pos
}

/// Get progress bar position
pub fn get_pos(index: usize) -> i32 {
    if index >= MAX_PROGRESSBARS {
        return 0;
    }

    let bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return 0;
    }

    bars[index].position
}

// ============================================================================
// Step Functions
// ============================================================================

/// Set step increment
pub fn set_step(index: usize, step: i32) -> i32 {
    if index >= MAX_PROGRESSBARS {
        return 0;
    }

    let mut bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return 0;
    }

    let old_step = bars[index].step;
    bars[index].step = step;
    old_step
}

/// Step the progress bar by step increment
pub fn step_it(index: usize) -> i32 {
    if index >= MAX_PROGRESSBARS {
        return 0;
    }

    let mut bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return 0;
    }

    let old_pos = bars[index].position;
    let new_pos = old_pos.saturating_add(bars[index].step);

    // Wrap around if exceeds max
    if new_pos > bars[index].range_max {
        bars[index].position = bars[index].range_min;
    } else {
        bars[index].position = new_pos;
    }

    old_pos
}

// ============================================================================
// Color Functions
// ============================================================================

/// Set bar color
pub fn set_bar_color(index: usize, color: u32) -> u32 {
    if index >= MAX_PROGRESSBARS {
        return 0xFFFFFFFF;
    }

    let mut bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return 0xFFFFFFFF;
    }

    let old_color = bars[index].bar_color;
    bars[index].bar_color = color;
    old_color
}

/// Set background color
pub fn set_bk_color(index: usize, color: u32) -> u32 {
    if index >= MAX_PROGRESSBARS {
        return 0xFFFFFFFF;
    }

    let mut bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return 0xFFFFFFFF;
    }

    let old_color = bars[index].bk_color;
    bars[index].bk_color = color;
    old_color
}

/// Get bar color
pub fn get_bar_color(index: usize) -> u32 {
    if index >= MAX_PROGRESSBARS {
        return 0xFFFFFFFF;
    }

    let bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return 0xFFFFFFFF;
    }

    bars[index].bar_color
}

/// Get background color
pub fn get_bk_color(index: usize) -> u32 {
    if index >= MAX_PROGRESSBARS {
        return 0xFFFFFFFF;
    }

    let bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return 0xFFFFFFFF;
    }

    bars[index].bk_color
}

// ============================================================================
// Marquee Functions
// ============================================================================

/// Set marquee mode
pub fn set_marquee(index: usize, enable: bool, interval_ms: u32) -> bool {
    if index >= MAX_PROGRESSBARS {
        return false;
    }

    let mut bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return false;
    }

    bars[index].marquee_enabled = enable;
    if interval_ms > 0 {
        bars[index].marquee_interval = interval_ms;
    }
    bars[index].marquee_position = 0;

    true
}

/// Update marquee animation (call periodically)
pub fn update_marquee(index: usize) {
    if index >= MAX_PROGRESSBARS {
        return;
    }

    let mut bars = PROGRESSBARS.lock();
    if !bars[index].in_use || !bars[index].marquee_enabled {
        return;
    }

    // Advance marquee position
    bars[index].marquee_position = (bars[index].marquee_position + 1) % 100;
}

// ============================================================================
// Drawing Support
// ============================================================================

/// Get progress percentage (0-100)
pub fn get_percent(index: usize) -> u32 {
    if index >= MAX_PROGRESSBARS {
        return 0;
    }

    let bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return 0;
    }

    let range = bars[index].range_max - bars[index].range_min;
    if range <= 0 {
        return 0;
    }

    let pos = bars[index].position - bars[index].range_min;
    ((pos as u64 * 100) / range as u64) as u32
}

/// Get fill width for a given control width
pub fn get_fill_width(index: usize, control_width: i32) -> i32 {
    if index >= MAX_PROGRESSBARS {
        return 0;
    }

    let bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return 0;
    }

    let range = bars[index].range_max - bars[index].range_min;
    if range <= 0 {
        return 0;
    }

    let pos = bars[index].position - bars[index].range_min;
    ((pos as i64 * control_width as i64) / range as i64) as i32
}

/// Get fill height for a given control height (vertical progress bar)
pub fn get_fill_height(index: usize, control_height: i32) -> i32 {
    if index >= MAX_PROGRESSBARS {
        return 0;
    }

    let bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return 0;
    }

    let range = bars[index].range_max - bars[index].range_min;
    if range <= 0 {
        return 0;
    }

    let pos = bars[index].position - bars[index].range_min;
    ((pos as i64 * control_height as i64) / range as i64) as i32
}

/// Check if progress bar is vertical
pub fn is_vertical(index: usize) -> bool {
    if index >= MAX_PROGRESSBARS {
        return false;
    }

    let bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return false;
    }

    (bars[index].style & PBS_VERTICAL) != 0
}

/// Check if progress bar is smooth
pub fn is_smooth(index: usize) -> bool {
    if index >= MAX_PROGRESSBARS {
        return false;
    }

    let bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return false;
    }

    (bars[index].style & PBS_SMOOTH) != 0
}

/// Check if marquee mode is enabled
pub fn is_marquee(index: usize) -> bool {
    if index >= MAX_PROGRESSBARS {
        return false;
    }

    let bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return false;
    }

    bars[index].marquee_enabled
}

/// Get marquee position (0-99)
pub fn get_marquee_position(index: usize) -> i32 {
    if index >= MAX_PROGRESSBARS {
        return 0;
    }

    let bars = PROGRESSBARS.lock();
    if !bars[index].in_use {
        return 0;
    }

    bars[index].marquee_position
}

// ============================================================================
// Message Processing
// ============================================================================

/// Process progress bar message
pub fn process_message(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> Option<isize> {
    let index = find_progressbar(hwnd)?;

    match msg {
        PBM_SETRANGE => {
            let low = (lparam as u32 & 0xFFFF) as i16;
            let high = ((lparam as u32 >> 16) & 0xFFFF) as i16;
            Some(set_range(index, low, high) as isize)
        }
        PBM_SETPOS => {
            Some(set_pos(index, wparam as i32) as isize)
        }
        PBM_DELTAPOS => {
            Some(delta_pos(index, wparam as i32) as isize)
        }
        PBM_SETSTEP => {
            Some(set_step(index, wparam as i32) as isize)
        }
        PBM_STEPIT => {
            Some(step_it(index) as isize)
        }
        PBM_SETRANGE32 => {
            let result = set_range32(index, wparam as i32, lparam as i32);
            Some(result as isize)
        }
        PBM_GETRANGE => {
            let (value, range) = get_range(index, wparam != 0);
            if lparam != 0 {
                // Write range to lparam pointer
                unsafe {
                    let ptr = lparam as *mut PbRange;
                    if let Some(r) = range {
                        *ptr = r;
                    }
                }
            }
            Some(value as isize)
        }
        PBM_GETPOS => {
            Some(get_pos(index) as isize)
        }
        PBM_SETBARCOLOR => {
            Some(set_bar_color(index, lparam as u32) as isize)
        }
        PBM_SETBKCOLOR => {
            Some(set_bk_color(index, lparam as u32) as isize)
        }
        PBM_SETMARQUEE => {
            let enable = wparam != 0;
            let interval = lparam as u32;
            Some(set_marquee(index, enable, interval) as isize)
        }
        _ => None,
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Progress bar statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ProgressBarStats {
    pub initialized: bool,
    pub count: u32,
}

/// Get progress bar statistics
pub fn get_stats() -> ProgressBarStats {
    ProgressBarStats {
        initialized: PROGRESSBAR_INITIALIZED.load(Ordering::Relaxed),
        count: PROGRESSBAR_COUNT.load(Ordering::Relaxed),
    }
}
