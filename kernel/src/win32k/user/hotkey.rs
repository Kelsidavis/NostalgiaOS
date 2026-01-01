//! HotKey Control Implementation
//!
//! Windows HotKey control for entering keyboard shortcuts.
//! Based on Windows Server 2003 commctrl.h and msctls_hotkey32.
//!
//! # Features
//!
//! - Keyboard shortcut input and display
//! - Modifier key combinations (Shift, Ctrl, Alt)
//! - Invalid combination rules with fallback modifiers
//! - Virtual key code support
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - HKM_* messages, HKCOMB_* flags

use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle};

// ============================================================================
// HotKey Modifier Flags
// ============================================================================

/// Shift modifier flag
pub const HOTKEYF_SHIFT: u8 = 0x01;

/// Control modifier flag
pub const HOTKEYF_CONTROL: u8 = 0x02;

/// Alt modifier flag
pub const HOTKEYF_ALT: u8 = 0x04;

/// Extended key flag
pub const HOTKEYF_EXT: u8 = 0x08;

// ============================================================================
// Invalid Combination Flags (HKCOMB_*)
// ============================================================================

/// No modifiers invalid
pub const HKCOMB_NONE: u16 = 0x0001;

/// Shift only invalid
pub const HKCOMB_S: u16 = 0x0002;

/// Control only invalid
pub const HKCOMB_C: u16 = 0x0004;

/// Alt only invalid
pub const HKCOMB_A: u16 = 0x0008;

/// Shift+Control invalid
pub const HKCOMB_SC: u16 = 0x0010;

/// Shift+Alt invalid
pub const HKCOMB_SA: u16 = 0x0020;

/// Control+Alt invalid
pub const HKCOMB_CA: u16 = 0x0040;

/// Shift+Control+Alt invalid
pub const HKCOMB_SCA: u16 = 0x0080;

// ============================================================================
// HotKey Messages
// ============================================================================

/// WM_USER base for HotKey messages
pub const WM_USER: u32 = 0x0400;

/// Set the hotkey value
/// wParam: LOWORD = virtual key code, HIWORD = modifier flags
/// Returns: 0
pub const HKM_SETHOTKEY: u32 = WM_USER + 1;

/// Get the hotkey value
/// Returns: LOWORD = virtual key code, HIWORD = modifier flags
pub const HKM_GETHOTKEY: u32 = WM_USER + 2;

/// Set invalid combination rules
/// wParam: LOWORD = invalid combinations (HKCOMB_*), HIWORD = fallback modifiers
/// Returns: 0
pub const HKM_SETRULES: u32 = WM_USER + 3;

// ============================================================================
// Virtual Key Codes (commonly used with hotkeys)
// ============================================================================

/// Backspace key
pub const VK_BACK: u8 = 0x08;
/// Tab key
pub const VK_TAB: u8 = 0x09;
/// Return/Enter key
pub const VK_RETURN: u8 = 0x0D;
/// Shift key
pub const VK_SHIFT: u8 = 0x10;
/// Control key
pub const VK_CONTROL: u8 = 0x11;
/// Alt/Menu key
pub const VK_MENU: u8 = 0x12;
/// Escape key
pub const VK_ESCAPE: u8 = 0x1B;
/// Space key
pub const VK_SPACE: u8 = 0x20;
/// Delete key
pub const VK_DELETE: u8 = 0x2E;
/// F1 key
pub const VK_F1: u8 = 0x70;
/// F2 key
pub const VK_F2: u8 = 0x71;
/// F3 key
pub const VK_F3: u8 = 0x72;
/// F4 key
pub const VK_F4: u8 = 0x73;
/// F5 key
pub const VK_F5: u8 = 0x74;
/// F6 key
pub const VK_F6: u8 = 0x75;
/// F7 key
pub const VK_F7: u8 = 0x76;
/// F8 key
pub const VK_F8: u8 = 0x77;
/// F9 key
pub const VK_F9: u8 = 0x78;
/// F10 key
pub const VK_F10: u8 = 0x79;
/// F11 key
pub const VK_F11: u8 = 0x7A;
/// F12 key
pub const VK_F12: u8 = 0x7B;

// ============================================================================
// Notification Messages
// ============================================================================

/// Parent notification when hotkey changes
pub const EN_CHANGE: u32 = 0x0300;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of HotKey controls
pub const MAX_HOTKEY_CONTROLS: usize = 64;

/// HotKey control class name
pub const HOTKEY_CLASS: &str = "msctls_hotkey32";

// ============================================================================
// HotKey Control Structure
// ============================================================================

/// HotKey control state
#[derive(Clone)]
pub struct HotKeyControl {
    /// Control handle
    pub hwnd: HWND,
    /// Is this slot in use
    pub in_use: bool,
    /// Current virtual key code (0 = none)
    pub vk_code: u8,
    /// Current modifier flags (HOTKEYF_*)
    pub modifiers: u8,
    /// Invalid combination flags (HKCOMB_*)
    pub invalid_combinations: u16,
    /// Fallback modifiers for invalid combinations
    pub fallback_modifiers: u8,
    /// Is control focused
    pub has_focus: bool,
    /// Shift key is currently pressed
    pub shift_down: bool,
    /// Control key is currently pressed
    pub control_down: bool,
    /// Alt key is currently pressed
    pub alt_down: bool,
}

impl HotKeyControl {
    /// Create a new HotKey control
    pub const fn new() -> Self {
        Self {
            hwnd: UserHandle::NULL,
            in_use: false,
            vk_code: 0,
            modifiers: 0,
            invalid_combinations: 0,
            fallback_modifiers: 0,
            has_focus: false,
            shift_down: false,
            control_down: false,
            alt_down: false,
        }
    }

    /// Reset control to default state
    pub fn reset(&mut self) {
        self.hwnd = UserHandle::NULL;
        self.in_use = false;
        self.vk_code = 0;
        self.modifiers = 0;
        self.invalid_combinations = 0;
        self.fallback_modifiers = 0;
        self.has_focus = false;
        self.shift_down = false;
        self.control_down = false;
        self.alt_down = false;
    }

    /// Get the current hotkey value as a packed u32
    /// LOWORD = virtual key code, HIWORD = modifiers
    pub fn get_hotkey(&self) -> u32 {
        (self.vk_code as u32) | ((self.modifiers as u32) << 8)
    }

    /// Set the hotkey value from a packed u32
    pub fn set_hotkey(&mut self, value: u32) {
        self.vk_code = (value & 0xFF) as u8;
        self.modifiers = ((value >> 8) & 0xFF) as u8;
    }

    /// Set invalid combination rules
    pub fn set_rules(&mut self, invalid: u16, fallback: u8) {
        self.invalid_combinations = invalid;
        self.fallback_modifiers = fallback;
    }

    /// Check if a modifier combination is invalid
    pub fn is_combination_invalid(&self, modifiers: u8) -> bool {
        let has_shift = modifiers & HOTKEYF_SHIFT != 0;
        let has_control = modifiers & HOTKEYF_CONTROL != 0;
        let has_alt = modifiers & HOTKEYF_ALT != 0;

        match (has_shift, has_control, has_alt) {
            (false, false, false) => self.invalid_combinations & HKCOMB_NONE != 0,
            (true, false, false) => self.invalid_combinations & HKCOMB_S != 0,
            (false, true, false) => self.invalid_combinations & HKCOMB_C != 0,
            (false, false, true) => self.invalid_combinations & HKCOMB_A != 0,
            (true, true, false) => self.invalid_combinations & HKCOMB_SC != 0,
            (true, false, true) => self.invalid_combinations & HKCOMB_SA != 0,
            (false, true, true) => self.invalid_combinations & HKCOMB_CA != 0,
            (true, true, true) => self.invalid_combinations & HKCOMB_SCA != 0,
        }
    }

    /// Apply the hotkey with fallback if needed
    pub fn apply_with_fallback(&mut self, vk: u8, mods: u8) {
        self.vk_code = vk;

        if self.is_combination_invalid(mods) {
            // Use fallback modifiers
            self.modifiers = self.fallback_modifiers;
        } else {
            self.modifiers = mods;
        }
    }

    /// Handle key down event
    pub fn on_key_down(&mut self, vk: u8, extended: bool) -> bool {
        match vk {
            VK_SHIFT => {
                self.shift_down = true;
                true
            }
            VK_CONTROL => {
                self.control_down = true;
                true
            }
            VK_MENU => {
                self.alt_down = true;
                true
            }
            VK_BACK | VK_DELETE => {
                // Clear the hotkey
                self.vk_code = 0;
                self.modifiers = 0;
                true
            }
            VK_TAB | VK_RETURN | VK_ESCAPE => {
                // Don't capture these keys
                false
            }
            _ => {
                // Set the hotkey
                let mut mods = 0u8;
                if self.shift_down {
                    mods |= HOTKEYF_SHIFT;
                }
                if self.control_down {
                    mods |= HOTKEYF_CONTROL;
                }
                if self.alt_down {
                    mods |= HOTKEYF_ALT;
                }
                if extended {
                    mods |= HOTKEYF_EXT;
                }

                self.apply_with_fallback(vk, mods);
                true
            }
        }
    }

    /// Handle key up event
    pub fn on_key_up(&mut self, vk: u8) {
        match vk {
            VK_SHIFT => self.shift_down = false,
            VK_CONTROL => self.control_down = false,
            VK_MENU => self.alt_down = false,
            _ => {}
        }
    }

    /// Get display text for the hotkey
    pub fn get_display_text(&self, buffer: &mut [u8]) -> usize {
        if self.vk_code == 0 {
            let text = b"None";
            let len = core::cmp::min(text.len(), buffer.len());
            buffer[..len].copy_from_slice(&text[..len]);
            return len;
        }

        let mut pos = 0;

        // Add modifier names
        if self.modifiers & HOTKEYF_CONTROL != 0 {
            let text = b"Ctrl+";
            let len = core::cmp::min(text.len(), buffer.len() - pos);
            buffer[pos..pos + len].copy_from_slice(&text[..len]);
            pos += len;
        }

        if self.modifiers & HOTKEYF_ALT != 0 {
            let text = b"Alt+";
            let len = core::cmp::min(text.len(), buffer.len() - pos);
            buffer[pos..pos + len].copy_from_slice(&text[..len]);
            pos += len;
        }

        if self.modifiers & HOTKEYF_SHIFT != 0 {
            let text = b"Shift+";
            let len = core::cmp::min(text.len(), buffer.len() - pos);
            buffer[pos..pos + len].copy_from_slice(&text[..len]);
            pos += len;
        }

        // Add key name
        let key_name = get_key_name(self.vk_code);
        let len = core::cmp::min(key_name.len(), buffer.len() - pos);
        buffer[pos..pos + len].copy_from_slice(&key_name.as_bytes()[..len]);
        pos += len;

        pos
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global HotKey control storage
static HOTKEY_CONTROLS: SpinLock<[HotKeyControl; MAX_HOTKEY_CONTROLS]> =
    SpinLock::new([const { HotKeyControl::new() }; MAX_HOTKEY_CONTROLS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize HotKey control subsystem
pub fn init() {
    crate::serial_println!("[USER] HotKey control initialized");
}

/// Create a HotKey control
pub fn create_hotkey(hwnd: HWND) -> Option<usize> {
    let mut controls = HOTKEY_CONTROLS.lock();

    for (i, control) in controls.iter_mut().enumerate() {
        if !control.in_use {
            control.reset();
            control.hwnd = hwnd;
            control.in_use = true;
            return Some(i);
        }
    }

    None
}

/// Destroy a HotKey control
pub fn destroy_hotkey(index: usize) -> bool {
    let mut controls = HOTKEY_CONTROLS.lock();

    if index >= MAX_HOTKEY_CONTROLS {
        return false;
    }

    if controls[index].in_use {
        controls[index].reset();
        true
    } else {
        false
    }
}

/// Set the hotkey value
pub fn set_hotkey(index: usize, vk_code: u8, modifiers: u8) -> bool {
    let mut controls = HOTKEY_CONTROLS.lock();

    if index >= MAX_HOTKEY_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].vk_code = vk_code;
    controls[index].modifiers = modifiers;
    true
}

/// Get the hotkey value
pub fn get_hotkey(index: usize) -> Option<(u8, u8)> {
    let controls = HOTKEY_CONTROLS.lock();

    if index >= MAX_HOTKEY_CONTROLS || !controls[index].in_use {
        return None;
    }

    Some((controls[index].vk_code, controls[index].modifiers))
}

/// Set invalid combination rules
pub fn set_rules(index: usize, invalid: u16, fallback: u8) -> bool {
    let mut controls = HOTKEY_CONTROLS.lock();

    if index >= MAX_HOTKEY_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].set_rules(invalid, fallback);
    true
}

/// Handle key down for a HotKey control
pub fn handle_key_down(index: usize, vk: u8, extended: bool) -> bool {
    let mut controls = HOTKEY_CONTROLS.lock();

    if index >= MAX_HOTKEY_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].on_key_down(vk, extended)
}

/// Handle key up for a HotKey control
pub fn handle_key_up(index: usize, vk: u8) -> bool {
    let mut controls = HOTKEY_CONTROLS.lock();

    if index >= MAX_HOTKEY_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].on_key_up(vk);
    true
}

/// Set focus state
pub fn set_focus(index: usize, focused: bool) -> bool {
    let mut controls = HOTKEY_CONTROLS.lock();

    if index >= MAX_HOTKEY_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].has_focus = focused;
    if !focused {
        // Reset modifier tracking when losing focus
        controls[index].shift_down = false;
        controls[index].control_down = false;
        controls[index].alt_down = false;
    }
    true
}

/// Get display text for the hotkey
pub fn get_display_text(index: usize, buffer: &mut [u8]) -> usize {
    let controls = HOTKEY_CONTROLS.lock();

    if index >= MAX_HOTKEY_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].get_display_text(buffer)
}

/// Process HotKey control message
pub fn process_message(index: usize, msg: u32, wparam: usize, _lparam: isize) -> isize {
    match msg {
        HKM_SETHOTKEY => {
            let vk = (wparam & 0xFF) as u8;
            let mods = ((wparam >> 8) & 0xFF) as u8;
            set_hotkey(index, vk, mods);
            0
        }
        HKM_GETHOTKEY => {
            if let Some((vk, mods)) = get_hotkey(index) {
                (vk as isize) | ((mods as isize) << 8)
            } else {
                0
            }
        }
        HKM_SETRULES => {
            let invalid = (wparam & 0xFFFF) as u16;
            let fallback = ((wparam >> 16) & 0xFF) as u8;
            set_rules(index, invalid, fallback);
            0
        }
        _ => 0,
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get key name from virtual key code
fn get_key_name(vk: u8) -> &'static str {
    match vk {
        0x08 => "Backspace",
        0x09 => "Tab",
        0x0D => "Enter",
        0x13 => "Pause",
        0x14 => "Caps Lock",
        0x1B => "Escape",
        0x20 => "Space",
        0x21 => "Page Up",
        0x22 => "Page Down",
        0x23 => "End",
        0x24 => "Home",
        0x25 => "Left",
        0x26 => "Up",
        0x27 => "Right",
        0x28 => "Down",
        0x2C => "Print Screen",
        0x2D => "Insert",
        0x2E => "Delete",
        0x30 => "0",
        0x31 => "1",
        0x32 => "2",
        0x33 => "3",
        0x34 => "4",
        0x35 => "5",
        0x36 => "6",
        0x37 => "7",
        0x38 => "8",
        0x39 => "9",
        0x41 => "A",
        0x42 => "B",
        0x43 => "C",
        0x44 => "D",
        0x45 => "E",
        0x46 => "F",
        0x47 => "G",
        0x48 => "H",
        0x49 => "I",
        0x4A => "J",
        0x4B => "K",
        0x4C => "L",
        0x4D => "M",
        0x4E => "N",
        0x4F => "O",
        0x50 => "P",
        0x51 => "Q",
        0x52 => "R",
        0x53 => "S",
        0x54 => "T",
        0x55 => "U",
        0x56 => "V",
        0x57 => "W",
        0x58 => "X",
        0x59 => "Y",
        0x5A => "Z",
        0x5B => "Windows",
        0x5C => "Windows",
        0x5D => "Menu",
        0x60 => "Num 0",
        0x61 => "Num 1",
        0x62 => "Num 2",
        0x63 => "Num 3",
        0x64 => "Num 4",
        0x65 => "Num 5",
        0x66 => "Num 6",
        0x67 => "Num 7",
        0x68 => "Num 8",
        0x69 => "Num 9",
        0x6A => "Num *",
        0x6B => "Num +",
        0x6D => "Num -",
        0x6E => "Num .",
        0x6F => "Num /",
        0x70 => "F1",
        0x71 => "F2",
        0x72 => "F3",
        0x73 => "F4",
        0x74 => "F5",
        0x75 => "F6",
        0x76 => "F7",
        0x77 => "F8",
        0x78 => "F9",
        0x79 => "F10",
        0x7A => "F11",
        0x7B => "F12",
        0x90 => "Num Lock",
        0x91 => "Scroll Lock",
        0xBA => ";",
        0xBB => "=",
        0xBC => ",",
        0xBD => "-",
        0xBE => ".",
        0xBF => "/",
        0xC0 => "`",
        0xDB => "[",
        0xDC => "\\",
        0xDD => "]",
        0xDE => "'",
        _ => "?",
    }
}

/// Get statistics
pub fn get_stats() -> HotKeyStats {
    let controls = HOTKEY_CONTROLS.lock();

    let mut active_count = 0;
    for control in controls.iter() {
        if control.in_use {
            active_count += 1;
        }
    }

    HotKeyStats {
        max_controls: MAX_HOTKEY_CONTROLS,
        active_controls: active_count,
    }
}

/// HotKey statistics
#[derive(Debug, Clone, Copy)]
pub struct HotKeyStats {
    pub max_controls: usize,
    pub active_controls: usize,
}
