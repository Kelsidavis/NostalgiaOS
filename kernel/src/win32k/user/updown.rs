//! UpDown (Spin) Control Implementation
//!
//! Implements the Windows UpDown control for numeric input with increment/decrement buttons.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/commctrl.h` - Control styles and messages
//! - `shell/comctl32/updown.c` - UpDown implementation

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::HWND;

// ============================================================================
// UpDown Class
// ============================================================================

/// UpDown window class name
pub const UPDOWN_CLASS: &str = "msctls_updown32";

// ============================================================================
// UpDown Range Constants
// ============================================================================

/// Maximum value for 16-bit range
pub const UD_MAXVAL: i32 = 0x7fff;

/// Minimum value for 16-bit range
pub const UD_MINVAL: i32 = -UD_MAXVAL;

// ============================================================================
// UpDown Styles (UDS_*)
// ============================================================================

/// Wrap around at min/max
pub const UDS_WRAP: u32 = 0x0001;

/// Set buddy window's integer text
pub const UDS_SETBUDDYINT: u32 = 0x0002;

/// Align to right of buddy
pub const UDS_ALIGNRIGHT: u32 = 0x0004;

/// Align to left of buddy
pub const UDS_ALIGNLEFT: u32 = 0x0008;

/// Auto-select buddy (previous sibling)
pub const UDS_AUTOBUDDY: u32 = 0x0010;

/// Arrow keys change position
pub const UDS_ARROWKEYS: u32 = 0x0020;

/// Horizontal orientation
pub const UDS_HORZ: u32 = 0x0040;

/// No thousands separator
pub const UDS_NOTHOUSANDS: u32 = 0x0080;

/// Hot tracking
pub const UDS_HOTTRACK: u32 = 0x0100;

// ============================================================================
// UpDown Messages (UDM_*)
// ============================================================================

/// WM_USER base for updown messages
const WM_USER: u32 = 0x0400;

/// Set range (16-bit: wParam=0, lParam=MAKELPARAM(low, high))
/// Note: For UDM_SETRANGE, the range is stored as (upper, lower)
pub const UDM_SETRANGE: u32 = WM_USER + 101;

/// Get range (returns MAKELONG(low, high))
pub const UDM_GETRANGE: u32 = WM_USER + 102;

/// Set position (16-bit)
pub const UDM_SETPOS: u32 = WM_USER + 103;

/// Get position (16-bit)
pub const UDM_GETPOS: u32 = WM_USER + 104;

/// Set buddy window
pub const UDM_SETBUDDY: u32 = WM_USER + 105;

/// Get buddy window
pub const UDM_GETBUDDY: u32 = WM_USER + 106;

/// Set acceleration table
pub const UDM_SETACCEL: u32 = WM_USER + 107;

/// Get acceleration table
pub const UDM_GETACCEL: u32 = WM_USER + 108;

/// Set numeric base (10 or 16)
pub const UDM_SETBASE: u32 = WM_USER + 109;

/// Get numeric base
pub const UDM_GETBASE: u32 = WM_USER + 110;

/// Set range (32-bit: wParam=low, lParam=high)
pub const UDM_SETRANGE32: u32 = WM_USER + 111;

/// Get range (32-bit: wParam=&low, lParam=&high)
pub const UDM_GETRANGE32: u32 = WM_USER + 112;

/// Set position (32-bit)
pub const UDM_SETPOS32: u32 = WM_USER + 113;

/// Get position (32-bit: lParam=&error)
pub const UDM_GETPOS32: u32 = WM_USER + 114;

// ============================================================================
// UpDown Notification
// ============================================================================

/// Position change notification
/// UDN_FIRST is typically -721
pub const UDN_DELTAPOS: u32 = 0xFFFFFD2E; // (UDN_FIRST - 1) = -722

// ============================================================================
// Acceleration Structure
// ============================================================================

/// Acceleration entry for updown control
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UdAccel {
    /// Seconds before this acceleration kicks in
    pub n_sec: u32,
    /// Increment for this acceleration level
    pub n_inc: u32,
}

/// Maximum acceleration entries
const MAX_ACCEL_ENTRIES: usize = 8;

// ============================================================================
// UpDown Notification Structure
// ============================================================================

/// UpDown notification structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NmUpDown {
    /// Standard notification header
    pub hdr_hwnd_from: HWND,
    pub hdr_id_from: usize,
    pub hdr_code: u32,
    /// Current position
    pub i_pos: i32,
    /// Proposed change
    pub i_delta: i32,
}

// ============================================================================
// UpDown State
// ============================================================================

/// Maximum number of updown controls
const MAX_UPDOWNS: usize = 128;

/// UpDown control state
#[derive(Debug)]
pub struct UpDownControl {
    /// Control is in use
    in_use: bool,
    /// Associated window handle
    hwnd: HWND,
    /// Control styles
    style: u32,
    /// Buddy window handle
    buddy: HWND,
    /// Minimum value
    range_min: i32,
    /// Maximum value
    range_max: i32,
    /// Current position
    position: i32,
    /// Numeric base (10 or 16)
    base: u32,
    /// Acceleration table
    accel: [UdAccel; MAX_ACCEL_ENTRIES],
    /// Number of acceleration entries
    accel_count: usize,
    /// Hot tracking state
    hot_button: i32, // 0=none, 1=up, 2=down
    /// Pressed button
    pressed_button: i32,
}

impl UpDownControl {
    const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: HWND::NULL,
            style: 0,
            buddy: HWND::NULL,
            range_min: 0,
            range_max: 100,
            position: 0,
            base: 10,
            accel: [UdAccel { n_sec: 0, n_inc: 1 }; MAX_ACCEL_ENTRIES],
            accel_count: 1,
            hot_button: 0,
            pressed_button: 0,
        }
    }

    fn reset(&mut self) {
        self.in_use = false;
        self.hwnd = HWND::NULL;
        self.style = 0;
        self.buddy = HWND::NULL;
        self.range_min = 0;
        self.range_max = 100;
        self.position = 0;
        self.base = 10;
        self.accel = [UdAccel { n_sec: 0, n_inc: 1 }; MAX_ACCEL_ENTRIES];
        self.accel_count = 1;
        self.hot_button = 0;
        self.pressed_button = 0;
    }
}

// ============================================================================
// Global State
// ============================================================================

static UPDOWN_INITIALIZED: AtomicBool = AtomicBool::new(false);
static UPDOWN_COUNT: AtomicU32 = AtomicU32::new(0);
static UPDOWNS: SpinLock<[UpDownControl; MAX_UPDOWNS]> =
    SpinLock::new([const { UpDownControl::new() }; MAX_UPDOWNS]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize updown control subsystem
pub fn init() {
    if UPDOWN_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[UPDOWN] Initializing UpDown control...");

    UPDOWN_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[UPDOWN] UpDown control initialized");
}

// ============================================================================
// UpDown Creation/Destruction
// ============================================================================

/// Create an updown control
pub fn create_updown(hwnd: HWND, style: u32) -> Option<usize> {
    let mut controls = UPDOWNS.lock();

    // Find free slot
    for (index, control) in controls.iter_mut().enumerate() {
        if !control.in_use {
            control.in_use = true;
            control.hwnd = hwnd;
            control.style = style;
            control.buddy = HWND::NULL;
            control.range_min = 0;
            control.range_max = 100;
            control.position = 0;
            control.base = 10;
            control.accel = [UdAccel { n_sec: 0, n_inc: 1 }; MAX_ACCEL_ENTRIES];
            control.accel_count = 1;
            control.hot_button = 0;
            control.pressed_button = 0;

            UPDOWN_COUNT.fetch_add(1, Ordering::Relaxed);
            return Some(index);
        }
    }

    None
}

/// Destroy an updown control
pub fn destroy_updown(index: usize) -> bool {
    if index >= MAX_UPDOWNS {
        return false;
    }

    let mut controls = UPDOWNS.lock();
    if controls[index].in_use {
        controls[index].reset();
        UPDOWN_COUNT.fetch_sub(1, Ordering::Relaxed);
        return true;
    }

    false
}

/// Find updown by window handle
pub fn find_updown(hwnd: HWND) -> Option<usize> {
    let controls = UPDOWNS.lock();
    for (index, control) in controls.iter().enumerate() {
        if control.in_use && control.hwnd == hwnd {
            return Some(index);
        }
    }
    None
}

// ============================================================================
// Range Functions
// ============================================================================

/// Set updown range (16-bit)
/// Note: Windows stores range as (upper << 16) | lower
pub fn set_range(index: usize, lower: i16, upper: i16) -> bool {
    if index >= MAX_UPDOWNS {
        return false;
    }

    let mut controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return false;
    }

    controls[index].range_min = lower as i32;
    controls[index].range_max = upper as i32;

    // Clamp current position
    if controls[index].position < controls[index].range_min {
        controls[index].position = controls[index].range_min;
    }
    if controls[index].position > controls[index].range_max {
        controls[index].position = controls[index].range_max;
    }

    true
}

/// Get updown range (16-bit, returns MAKELONG(low, high))
pub fn get_range(index: usize) -> u32 {
    if index >= MAX_UPDOWNS {
        return 0;
    }

    let controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return 0;
    }

    let low = controls[index].range_min as u16;
    let high = controls[index].range_max as u16;
    ((high as u32) << 16) | (low as u32)
}

/// Set updown range (32-bit)
pub fn set_range32(index: usize, lower: i32, upper: i32) -> bool {
    if index >= MAX_UPDOWNS {
        return false;
    }

    let mut controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return false;
    }

    controls[index].range_min = lower;
    controls[index].range_max = upper;

    // Clamp current position
    if controls[index].position < controls[index].range_min {
        controls[index].position = controls[index].range_min;
    }
    if controls[index].position > controls[index].range_max {
        controls[index].position = controls[index].range_max;
    }

    true
}

/// Get updown range (32-bit)
pub fn get_range32(index: usize) -> (i32, i32) {
    if index >= MAX_UPDOWNS {
        return (0, 0);
    }

    let controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return (0, 0);
    }

    (controls[index].range_min, controls[index].range_max)
}

// ============================================================================
// Position Functions
// ============================================================================

/// Set updown position (16-bit)
pub fn set_pos(index: usize, pos: i16) -> i32 {
    if index >= MAX_UPDOWNS {
        return 0;
    }

    let mut controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return 0;
    }

    let old_pos = controls[index].position;
    let new_pos = (pos as i32).clamp(controls[index].range_min, controls[index].range_max);
    controls[index].position = new_pos;

    old_pos
}

/// Get updown position (16-bit, returns MAKELONG(pos, error))
pub fn get_pos(index: usize) -> u32 {
    if index >= MAX_UPDOWNS {
        return 1 << 16; // Error flag in high word
    }

    let controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return 1 << 16; // Error flag in high word
    }

    controls[index].position as u16 as u32
}

/// Set updown position (32-bit)
pub fn set_pos32(index: usize, pos: i32) -> i32 {
    if index >= MAX_UPDOWNS {
        return 0;
    }

    let mut controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return 0;
    }

    let old_pos = controls[index].position;
    let new_pos = pos.clamp(controls[index].range_min, controls[index].range_max);
    controls[index].position = new_pos;

    old_pos
}

/// Get updown position (32-bit)
pub fn get_pos32(index: usize) -> (i32, bool) {
    if index >= MAX_UPDOWNS {
        return (0, true); // error = true
    }

    let controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return (0, true);
    }

    (controls[index].position, false)
}

// ============================================================================
// Buddy Functions
// ============================================================================

/// Set buddy window
pub fn set_buddy(index: usize, buddy: HWND) -> HWND {
    if index >= MAX_UPDOWNS {
        return HWND::NULL;
    }

    let mut controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return HWND::NULL;
    }

    let old_buddy = controls[index].buddy;
    controls[index].buddy = buddy;
    old_buddy
}

/// Get buddy window
pub fn get_buddy(index: usize) -> HWND {
    if index >= MAX_UPDOWNS {
        return HWND::NULL;
    }

    let controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return HWND::NULL;
    }

    controls[index].buddy
}

/// Update buddy text with current position
pub fn update_buddy_text(index: usize) {
    if index >= MAX_UPDOWNS {
        return;
    }

    let controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return;
    }

    let _style = controls[index].style;
    let _buddy = controls[index].buddy;
    let _position = controls[index].position;
    let _base = controls[index].base;
    let _thousands = (_style & UDS_NOTHOUSANDS) == 0;

    // TODO: Format number and send WM_SETTEXT to buddy window
    // This requires integration with the message system
}

// ============================================================================
// Base Functions
// ============================================================================

/// Set numeric base (10 or 16)
pub fn set_base(index: usize, base: u32) -> u32 {
    if index >= MAX_UPDOWNS {
        return 0;
    }

    if base != 10 && base != 16 {
        return 0;
    }

    let mut controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return 0;
    }

    let old_base = controls[index].base;
    controls[index].base = base;
    old_base
}

/// Get numeric base
pub fn get_base(index: usize) -> u32 {
    if index >= MAX_UPDOWNS {
        return 0;
    }

    let controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return 0;
    }

    controls[index].base
}

// ============================================================================
// Acceleration Functions
// ============================================================================

/// Set acceleration table
pub fn set_accel(index: usize, entries: &[UdAccel]) -> bool {
    if index >= MAX_UPDOWNS || entries.is_empty() {
        return false;
    }

    let mut controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return false;
    }

    let count = entries.len().min(MAX_ACCEL_ENTRIES);
    for i in 0..count {
        controls[index].accel[i] = entries[i];
    }
    controls[index].accel_count = count;

    true
}

/// Get acceleration table
pub fn get_accel(index: usize, buffer: &mut [UdAccel]) -> usize {
    if index >= MAX_UPDOWNS {
        return 0;
    }

    let controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return 0;
    }

    let count = controls[index].accel_count.min(buffer.len());
    for i in 0..count {
        buffer[i] = controls[index].accel[i];
    }

    controls[index].accel_count
}

/// Get increment for given elapsed seconds
pub fn get_increment(index: usize, elapsed_secs: u32) -> u32 {
    if index >= MAX_UPDOWNS {
        return 1;
    }

    let controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return 1;
    }

    // Find the highest acceleration that applies
    let mut increment = 1u32;
    for i in 0..controls[index].accel_count {
        if elapsed_secs >= controls[index].accel[i].n_sec {
            increment = controls[index].accel[i].n_inc;
        }
    }

    increment
}

// ============================================================================
// Button Functions
// ============================================================================

/// Increment position (up arrow clicked)
pub fn increment(index: usize, amount: i32) -> bool {
    if index >= MAX_UPDOWNS {
        return false;
    }

    let mut controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return false;
    }

    let new_pos = controls[index].position.saturating_add(amount);

    if new_pos > controls[index].range_max {
        if (controls[index].style & UDS_WRAP) != 0 {
            controls[index].position = controls[index].range_min;
        } else {
            controls[index].position = controls[index].range_max;
        }
    } else {
        controls[index].position = new_pos;
    }

    true
}

/// Decrement position (down arrow clicked)
pub fn decrement(index: usize, amount: i32) -> bool {
    if index >= MAX_UPDOWNS {
        return false;
    }

    let mut controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return false;
    }

    let new_pos = controls[index].position.saturating_sub(amount);

    if new_pos < controls[index].range_min {
        if (controls[index].style & UDS_WRAP) != 0 {
            controls[index].position = controls[index].range_max;
        } else {
            controls[index].position = controls[index].range_min;
        }
    } else {
        controls[index].position = new_pos;
    }

    true
}

/// Set hot button (0=none, 1=up, 2=down)
pub fn set_hot_button(index: usize, button: i32) {
    if index >= MAX_UPDOWNS {
        return;
    }

    let mut controls = UPDOWNS.lock();
    if controls[index].in_use {
        controls[index].hot_button = button;
    }
}

/// Get hot button
pub fn get_hot_button(index: usize) -> i32 {
    if index >= MAX_UPDOWNS {
        return 0;
    }

    let controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return 0;
    }

    controls[index].hot_button
}

/// Set pressed button (0=none, 1=up, 2=down)
pub fn set_pressed_button(index: usize, button: i32) {
    if index >= MAX_UPDOWNS {
        return;
    }

    let mut controls = UPDOWNS.lock();
    if controls[index].in_use {
        controls[index].pressed_button = button;
    }
}

/// Get pressed button
pub fn get_pressed_button(index: usize) -> i32 {
    if index >= MAX_UPDOWNS {
        return 0;
    }

    let controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return 0;
    }

    controls[index].pressed_button
}

// ============================================================================
// Style Query Functions
// ============================================================================

/// Check if control is horizontal
pub fn is_horizontal(index: usize) -> bool {
    if index >= MAX_UPDOWNS {
        return false;
    }

    let controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return false;
    }

    (controls[index].style & UDS_HORZ) != 0
}

/// Check if control aligns to right of buddy
pub fn is_align_right(index: usize) -> bool {
    if index >= MAX_UPDOWNS {
        return false;
    }

    let controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return false;
    }

    (controls[index].style & UDS_ALIGNRIGHT) != 0
}

/// Check if control aligns to left of buddy
pub fn is_align_left(index: usize) -> bool {
    if index >= MAX_UPDOWNS {
        return false;
    }

    let controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return false;
    }

    (controls[index].style & UDS_ALIGNLEFT) != 0
}

/// Check if wrapping is enabled
pub fn is_wrap_enabled(index: usize) -> bool {
    if index >= MAX_UPDOWNS {
        return false;
    }

    let controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return false;
    }

    (controls[index].style & UDS_WRAP) != 0
}

/// Get control style
pub fn get_style(index: usize) -> u32 {
    if index >= MAX_UPDOWNS {
        return 0;
    }

    let controls = UPDOWNS.lock();
    if !controls[index].in_use {
        return 0;
    }

    controls[index].style
}

// ============================================================================
// Message Processing
// ============================================================================

/// Process updown message
pub fn process_message(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> Option<isize> {
    let index = find_updown(hwnd)?;

    match msg {
        UDM_SETRANGE => {
            // lParam: MAKELPARAM(upper, lower) - note: upper is in low word!
            let upper = (lparam as u32 & 0xFFFF) as i16;
            let lower = ((lparam as u32 >> 16) & 0xFFFF) as i16;
            set_range(index, lower, upper);
            Some(0)
        }
        UDM_GETRANGE => {
            Some(get_range(index) as isize)
        }
        UDM_SETPOS => {
            // wParam: new position
            Some(set_pos(index, wparam as i16) as isize)
        }
        UDM_GETPOS => {
            Some(get_pos(index) as isize)
        }
        UDM_SETBUDDY => {
            let buddy = HWND::from_raw(wparam as u32);
            let old = set_buddy(index, buddy);
            Some(old.raw() as isize)
        }
        UDM_GETBUDDY => {
            let buddy = get_buddy(index);
            Some(buddy.raw() as isize)
        }
        UDM_SETACCEL => {
            // wParam: count, lParam: pointer to UDACCEL array
            let count = wparam.min(MAX_ACCEL_ENTRIES);
            if lparam != 0 && count > 0 {
                unsafe {
                    let ptr = lparam as *const UdAccel;
                    let slice = core::slice::from_raw_parts(ptr, count);
                    set_accel(index, slice);
                }
            }
            Some(1)
        }
        UDM_GETACCEL => {
            // wParam: count, lParam: pointer to UDACCEL buffer
            if lparam != 0 && wparam > 0 {
                unsafe {
                    let ptr = lparam as *mut UdAccel;
                    let slice = core::slice::from_raw_parts_mut(ptr, wparam);
                    let count = get_accel(index, slice);
                    Some(count as isize)
                }
            } else {
                // Return number of entries
                let controls = UPDOWNS.lock();
                if controls[index].in_use {
                    Some(controls[index].accel_count as isize)
                } else {
                    Some(0)
                }
            }
        }
        UDM_SETBASE => {
            Some(set_base(index, wparam as u32) as isize)
        }
        UDM_GETBASE => {
            Some(get_base(index) as isize)
        }
        UDM_SETRANGE32 => {
            set_range32(index, wparam as i32, lparam as i32);
            Some(0)
        }
        UDM_GETRANGE32 => {
            let (low, high) = get_range32(index);
            // Write to pointers if provided
            if wparam != 0 {
                unsafe {
                    let ptr = wparam as *mut i32;
                    *ptr = low;
                }
            }
            if lparam != 0 {
                unsafe {
                    let ptr = lparam as *mut i32;
                    *ptr = high;
                }
            }
            Some(0)
        }
        UDM_SETPOS32 => {
            Some(set_pos32(index, wparam as i32) as isize)
        }
        UDM_GETPOS32 => {
            let (pos, error) = get_pos32(index);
            // Write error flag to lParam if provided
            if lparam != 0 {
                unsafe {
                    let ptr = lparam as *mut i32;
                    *ptr = if error { 1 } else { 0 };
                }
            }
            Some(pos as isize)
        }
        _ => None,
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// UpDown statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct UpDownStats {
    pub initialized: bool,
    pub count: u32,
}

/// Get updown statistics
pub fn get_stats() -> UpDownStats {
    UpDownStats {
        initialized: UPDOWN_INITIALIZED.load(Ordering::Relaxed),
        count: UPDOWN_COUNT.load(Ordering::Relaxed),
    }
}
