//! Input Handling
//!
//! Keyboard and mouse input processing and routing to windows.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/input.c`
//! - `windows/core/ntuser/kernel/keyboard.c`

use crate::ke::spinlock::SpinLock;
use super::super::HWND;
use super::message;

// ============================================================================
// Virtual Key Codes
// ============================================================================

/// Virtual key codes (VK_*)
pub mod vk {
    pub const LBUTTON: u8 = 0x01;
    pub const RBUTTON: u8 = 0x02;
    pub const CANCEL: u8 = 0x03;
    pub const MBUTTON: u8 = 0x04;
    pub const BACK: u8 = 0x08;
    pub const TAB: u8 = 0x09;
    pub const CLEAR: u8 = 0x0C;
    pub const RETURN: u8 = 0x0D;
    pub const SHIFT: u8 = 0x10;
    pub const CONTROL: u8 = 0x11;
    pub const MENU: u8 = 0x12;  // Alt
    pub const PAUSE: u8 = 0x13;
    pub const CAPITAL: u8 = 0x14;  // Caps Lock
    pub const ESCAPE: u8 = 0x1B;
    pub const SPACE: u8 = 0x20;
    pub const PRIOR: u8 = 0x21;  // Page Up
    pub const NEXT: u8 = 0x22;   // Page Down
    pub const END: u8 = 0x23;
    pub const HOME: u8 = 0x24;
    pub const LEFT: u8 = 0x25;
    pub const UP: u8 = 0x26;
    pub const RIGHT: u8 = 0x27;
    pub const DOWN: u8 = 0x28;
    pub const SELECT: u8 = 0x29;
    pub const PRINT: u8 = 0x2A;
    pub const EXECUTE: u8 = 0x2B;
    pub const SNAPSHOT: u8 = 0x2C;  // Print Screen
    pub const INSERT: u8 = 0x2D;
    pub const DELETE: u8 = 0x2E;
    pub const HELP: u8 = 0x2F;

    // 0-9 are 0x30-0x39
    // A-Z are 0x41-0x5A

    pub const LWIN: u8 = 0x5B;
    pub const RWIN: u8 = 0x5C;
    pub const APPS: u8 = 0x5D;

    // Numpad
    pub const NUMPAD0: u8 = 0x60;
    pub const NUMPAD9: u8 = 0x69;
    pub const MULTIPLY: u8 = 0x6A;
    pub const ADD: u8 = 0x6B;
    pub const SEPARATOR: u8 = 0x6C;
    pub const SUBTRACT: u8 = 0x6D;
    pub const DECIMAL: u8 = 0x6E;
    pub const DIVIDE: u8 = 0x6F;

    // Function keys
    pub const F1: u8 = 0x70;
    pub const F12: u8 = 0x7B;

    pub const NUMLOCK: u8 = 0x90;
    pub const SCROLL: u8 = 0x91;

    pub const LSHIFT: u8 = 0xA0;
    pub const RSHIFT: u8 = 0xA1;
    pub const LCONTROL: u8 = 0xA2;
    pub const RCONTROL: u8 = 0xA3;
    pub const LMENU: u8 = 0xA4;
    pub const RMENU: u8 = 0xA5;
}

// ============================================================================
// Input State
// ============================================================================

/// Keyboard state
struct KeyboardState {
    /// Key down state (256 keys)
    keys: [bool; 256],

    /// Key toggle state (for caps lock, etc.)
    toggles: [bool; 256],
}

impl KeyboardState {
    const fn new() -> Self {
        Self {
            keys: [false; 256],
            toggles: [false; 256],
        }
    }
}

/// Mouse state
struct MouseState {
    /// Current X position
    x: i32,

    /// Current Y position
    y: i32,

    /// Left button down
    left_down: bool,

    /// Right button down
    right_down: bool,

    /// Middle button down
    middle_down: bool,
}

impl MouseState {
    const fn new() -> Self {
        Self {
            x: 0,
            y: 0,
            left_down: false,
            right_down: false,
            middle_down: false,
        }
    }
}

/// Focus state
struct FocusState {
    /// Window with keyboard focus
    focus: HWND,

    /// Window that is active
    active: HWND,

    /// Window being captured
    capture: HWND,
}

impl FocusState {
    const fn new() -> Self {
        Self {
            focus: HWND::NULL,
            active: HWND::NULL,
            capture: HWND::NULL,
        }
    }
}

static KEYBOARD_STATE: SpinLock<KeyboardState> = SpinLock::new(KeyboardState::new());
static MOUSE_STATE: SpinLock<MouseState> = SpinLock::new(MouseState::new());
static FOCUS_STATE: SpinLock<FocusState> = SpinLock::new(FocusState::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize input system
pub fn init() {
    crate::serial_println!("[USER/Input] Input system initialized");
}

// ============================================================================
// Keyboard Input
// ============================================================================

/// Process keyboard input (called from keyboard interrupt)
pub fn process_key_event(scancode: u8, pressed: bool) {
    // Convert scancode to virtual key
    let vk = scancode_to_vk(scancode);

    // Update keyboard state
    {
        let mut state = KEYBOARD_STATE.lock();
        state.keys[vk as usize] = pressed;

        // Handle toggles (caps lock, num lock, scroll lock)
        if pressed {
            match vk {
                vk::CAPITAL | vk::NUMLOCK | vk::SCROLL => {
                    state.toggles[vk as usize] = !state.toggles[vk as usize];
                }
                _ => {}
            }
        }
    }

    // Get focus window
    let focus = get_focus();

    // Post keyboard message
    let msg = if pressed { message::WM_KEYDOWN } else { message::WM_KEYUP };
    let lparam = make_key_lparam(scancode, pressed);

    if focus.is_valid() {
        message::post_message(focus, msg, vk as usize, lparam);
    }
}

/// Convert scancode to virtual key code
fn scancode_to_vk(scancode: u8) -> u8 {
    // Basic US keyboard layout mapping
    match scancode {
        0x01 => vk::ESCAPE,
        0x02 => b'1',
        0x03 => b'2',
        0x04 => b'3',
        0x05 => b'4',
        0x06 => b'5',
        0x07 => b'6',
        0x08 => b'7',
        0x09 => b'8',
        0x0A => b'9',
        0x0B => b'0',
        0x0E => vk::BACK,
        0x0F => vk::TAB,
        0x10 => b'Q',
        0x11 => b'W',
        0x12 => b'E',
        0x13 => b'R',
        0x14 => b'T',
        0x15 => b'Y',
        0x16 => b'U',
        0x17 => b'I',
        0x18 => b'O',
        0x19 => b'P',
        0x1C => vk::RETURN,
        0x1D => vk::CONTROL,
        0x1E => b'A',
        0x1F => b'S',
        0x20 => b'D',
        0x21 => b'F',
        0x22 => b'G',
        0x23 => b'H',
        0x24 => b'J',
        0x25 => b'K',
        0x26 => b'L',
        0x2A => vk::LSHIFT,
        0x2C => b'Z',
        0x2D => b'X',
        0x2E => b'C',
        0x2F => b'V',
        0x30 => b'B',
        0x31 => b'N',
        0x32 => b'M',
        0x36 => vk::RSHIFT,
        0x38 => vk::MENU,
        0x39 => vk::SPACE,
        0x3A => vk::CAPITAL,
        0x3B => vk::F1,
        0x3C => vk::F1 + 1,
        0x3D => vk::F1 + 2,
        0x3E => vk::F1 + 3,
        0x3F => vk::F1 + 4,
        0x40 => vk::F1 + 5,
        0x41 => vk::F1 + 6,
        0x42 => vk::F1 + 7,
        0x43 => vk::F1 + 8,
        0x44 => vk::F1 + 9,
        0x47 => vk::HOME,
        0x48 => vk::UP,
        0x49 => vk::PRIOR,
        0x4B => vk::LEFT,
        0x4D => vk::RIGHT,
        0x4F => vk::END,
        0x50 => vk::DOWN,
        0x51 => vk::NEXT,
        0x52 => vk::INSERT,
        0x53 => vk::DELETE,
        _ => 0,
    }
}

/// Make lparam for keyboard message
fn make_key_lparam(scancode: u8, pressed: bool) -> isize {
    let repeat_count: u32 = 1;
    let scan_code: u32 = scancode as u32;
    let extended: u32 = 0;
    let context: u32 = 0;
    let previous: u32 = if pressed { 0 } else { 1 };
    let transition: u32 = if pressed { 0 } else { 1 };

    ((repeat_count & 0xFFFF) |
     ((scan_code & 0xFF) << 16) |
     ((extended & 1) << 24) |
     ((context & 1) << 29) |
     ((previous & 1) << 30) |
     ((transition & 1) << 31)) as isize
}

/// Get key state
pub fn get_key_state(vk: u8) -> i16 {
    let state = KEYBOARD_STATE.lock();

    let mut result: i16 = 0;

    // Bit 15: key is down
    if state.keys[vk as usize] {
        result |= 0x8000u16 as i16;
    }

    // Bit 0: key is toggled
    if state.toggles[vk as usize] {
        result |= 1;
    }

    result
}

/// Get async key state
pub fn get_async_key_state(vk: u8) -> i16 {
    get_key_state(vk)
}

// ============================================================================
// Mouse Input
// ============================================================================

/// Process mouse movement
pub fn process_mouse_move(x: i32, y: i32) {
    {
        let mut state = MOUSE_STATE.lock();
        state.x = x;
        state.y = y;
    }

    // Find window under cursor
    let hwnd = window_from_point(x, y);

    if hwnd.is_valid() {
        let lparam = ((y & 0xFFFF) << 16) | (x & 0xFFFF);
        message::post_message(hwnd, message::WM_MOUSEMOVE, 0, lparam as isize);
    }
}

/// Process mouse button event
pub fn process_mouse_button(button: u8, pressed: bool, x: i32, y: i32) {
    {
        let mut state = MOUSE_STATE.lock();
        state.x = x;
        state.y = y;

        match button {
            0 => state.left_down = pressed,
            1 => state.right_down = pressed,
            2 => state.middle_down = pressed,
            _ => {}
        }
    }

    let hwnd = window_from_point(x, y);

    if hwnd.is_valid() {
        let msg = match (button, pressed) {
            (0, true) => message::WM_LBUTTONDOWN,
            (0, false) => message::WM_LBUTTONUP,
            (1, true) => message::WM_RBUTTONDOWN,
            (1, false) => message::WM_RBUTTONUP,
            (2, true) => message::WM_MBUTTONDOWN,
            (2, false) => message::WM_MBUTTONUP,
            _ => return,
        };

        let lparam = ((y & 0xFFFF) << 16) | (x & 0xFFFF);
        message::post_message(hwnd, msg, 0, lparam as isize);
    }
}

/// Get cursor position
pub fn get_cursor_pos() -> (i32, i32) {
    let state = MOUSE_STATE.lock();
    (state.x, state.y)
}

/// Set cursor position
pub fn set_cursor_pos(x: i32, y: i32) {
    let mut state = MOUSE_STATE.lock();
    state.x = x;
    state.y = y;
}

/// Find window at point
fn window_from_point(_x: i32, _y: i32) -> HWND {
    // TODO: proper hit testing through window z-order
    // For now, return desktop window
    super::window::get_desktop_window()
}

// ============================================================================
// Focus Management
// ============================================================================

/// Set focus to a window
pub fn set_focus(hwnd: HWND) -> HWND {
    let mut state = FOCUS_STATE.lock();
    let old_focus = state.focus;

    if old_focus != hwnd {
        // Send kill focus to old window
        if old_focus.is_valid() {
            message::post_message(old_focus, message::WM_KILLFOCUS, hwnd.raw() as usize, 0);
        }

        state.focus = hwnd;

        // Send set focus to new window
        if hwnd.is_valid() {
            message::post_message(hwnd, message::WM_SETFOCUS, old_focus.raw() as usize, 0);
        }
    }

    old_focus
}

/// Get focused window
pub fn get_focus() -> HWND {
    let state = FOCUS_STATE.lock();
    state.focus
}

/// Set active window
pub fn set_active_window(hwnd: HWND) -> HWND {
    let mut state = FOCUS_STATE.lock();
    let old_active = state.active;

    if old_active != hwnd {
        state.active = hwnd;

        // Send activation messages
        if hwnd.is_valid() {
            message::post_message(hwnd, message::WM_ACTIVATE, 1, old_active.raw() as isize);
        }
        if old_active.is_valid() {
            message::post_message(old_active, message::WM_ACTIVATE, 0, hwnd.raw() as isize);
        }
    }

    old_active
}

/// Get active window
pub fn get_active_window() -> HWND {
    let state = FOCUS_STATE.lock();
    state.active
}

/// Set mouse capture
pub fn set_capture(hwnd: HWND) -> HWND {
    let mut state = FOCUS_STATE.lock();
    let old_capture = state.capture;
    state.capture = hwnd;
    old_capture
}

/// Release mouse capture
pub fn release_capture() -> bool {
    let mut state = FOCUS_STATE.lock();
    if state.capture.is_valid() {
        state.capture = HWND::NULL;
        true
    } else {
        false
    }
}

/// Get capture window
pub fn get_capture() -> HWND {
    let state = FOCUS_STATE.lock();
    state.capture
}
