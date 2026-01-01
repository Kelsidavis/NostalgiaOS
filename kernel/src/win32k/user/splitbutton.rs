//! Split Button Control Implementation
//!
//! Windows Split Button for buttons with dropdown menus.
//! Based on Windows Vista+ button styles.
//!
//! # Features
//!
//! - Button with dropdown arrow
//! - Separate click zones (button and dropdown)
//! - Command link style
//! - Icon support
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - BS_SPLITBUTTON, BS_COMMANDLINK

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, Rect, Point};

// ============================================================================
// Button Styles (BS_*)
// ============================================================================

/// Push button
pub const BS_PUSHBUTTON: u32 = 0x00000000;

/// Default push button
pub const BS_DEFPUSHBUTTON: u32 = 0x00000001;

/// Check box
pub const BS_CHECKBOX: u32 = 0x00000002;

/// Auto check box
pub const BS_AUTOCHECKBOX: u32 = 0x00000003;

/// Radio button
pub const BS_RADIOBUTTON: u32 = 0x00000004;

/// 3-state check box
pub const BS_3STATE: u32 = 0x00000005;

/// Auto 3-state check box
pub const BS_AUTO3STATE: u32 = 0x00000006;

/// Group box
pub const BS_GROUPBOX: u32 = 0x00000007;

/// Auto radio button
pub const BS_AUTORADIOBUTTON: u32 = 0x00000009;

/// Owner draw button
pub const BS_OWNERDRAW: u32 = 0x0000000B;

/// Split button
pub const BS_SPLITBUTTON: u32 = 0x0000000C;

/// Default split button
pub const BS_DEFSPLITBUTTON: u32 = 0x0000000D;

/// Command link
pub const BS_COMMANDLINK: u32 = 0x0000000E;

/// Default command link
pub const BS_DEFCOMMANDLINK: u32 = 0x0000000F;

/// Left text
pub const BS_LEFTTEXT: u32 = 0x00000020;

/// Text style mask
pub const BS_TEXT: u32 = 0x00000000;

/// Icon style
pub const BS_ICON: u32 = 0x00000040;

/// Bitmap style
pub const BS_BITMAP: u32 = 0x00000080;

/// Left alignment
pub const BS_LEFT: u32 = 0x00000100;

/// Right alignment
pub const BS_RIGHT: u32 = 0x00000200;

/// Center alignment
pub const BS_CENTER: u32 = 0x00000300;

/// Top alignment
pub const BS_TOP: u32 = 0x00000400;

/// Bottom alignment
pub const BS_BOTTOM: u32 = 0x00000800;

/// Vertical center
pub const BS_VCENTER: u32 = 0x00000C00;

/// Push like style
pub const BS_PUSHLIKE: u32 = 0x00001000;

/// Multiline text
pub const BS_MULTILINE: u32 = 0x00002000;

/// Notify style
pub const BS_NOTIFY: u32 = 0x00004000;

/// Flat style
pub const BS_FLAT: u32 = 0x00008000;

// ============================================================================
// Split Button Info Flags (BCSIF_*)
// ============================================================================

/// Use glyph
pub const BCSIF_GLYPH: u32 = 0x0001;

/// Use image
pub const BCSIF_IMAGE: u32 = 0x0002;

/// Use style
pub const BCSIF_STYLE: u32 = 0x0004;

/// Use size
pub const BCSIF_SIZE: u32 = 0x0008;

// ============================================================================
// Split Button Styles (BCSS_*)
// ============================================================================

/// No split
pub const BCSS_NOSPLIT: u32 = 0x0001;

/// Stretch
pub const BCSS_STRETCH: u32 = 0x0002;

/// Align left
pub const BCSS_ALIGNLEFT: u32 = 0x0004;

/// Show image
pub const BCSS_IMAGE: u32 = 0x0008;

// ============================================================================
// Button Messages (BM_*, BCM_*)
// ============================================================================

/// Get check state
pub const BM_GETCHECK: u32 = 0x00F0;

/// Set check state
pub const BM_SETCHECK: u32 = 0x00F1;

/// Get button state
pub const BM_GETSTATE: u32 = 0x00F2;

/// Set button state
pub const BM_SETSTATE: u32 = 0x00F3;

/// Set button style
pub const BM_SETSTYLE: u32 = 0x00F4;

/// Click button
pub const BM_CLICK: u32 = 0x00F5;

/// Get button image
pub const BM_GETIMAGE: u32 = 0x00F6;

/// Set button image
pub const BM_SETIMAGE: u32 = 0x00F7;

/// Set dontclick
pub const BM_SETDONTCLICK: u32 = 0x00F8;

/// BCM first message
pub const BCM_FIRST: u32 = 0x1600;

/// Get ideal size
pub const BCM_GETIDEALSIZE: u32 = BCM_FIRST + 1;

/// Set image list
pub const BCM_SETIMAGELIST: u32 = BCM_FIRST + 2;

/// Get image list
pub const BCM_GETIMAGELIST: u32 = BCM_FIRST + 3;

/// Set text margin
pub const BCM_SETTEXTMARGIN: u32 = BCM_FIRST + 4;

/// Get text margin
pub const BCM_GETTEXTMARGIN: u32 = BCM_FIRST + 5;

/// Set dropdown state
pub const BCM_SETDROPDOWNSTATE: u32 = BCM_FIRST + 6;

/// Set split info
pub const BCM_SETSPLITINFO: u32 = BCM_FIRST + 7;

/// Get split info
pub const BCM_GETSPLITINFO: u32 = BCM_FIRST + 8;

/// Set note
pub const BCM_SETNOTE: u32 = BCM_FIRST + 9;

/// Get note
pub const BCM_GETNOTE: u32 = BCM_FIRST + 10;

/// Get note length
pub const BCM_GETNOTELENGTH: u32 = BCM_FIRST + 11;

/// Set shield
pub const BCM_SETSHIELD: u32 = BCM_FIRST + 12;

// ============================================================================
// Button Notifications (BN_*, BCN_*)
// ============================================================================

/// Button clicked
pub const BN_CLICKED: u32 = 0;

/// Paint notification
pub const BN_PAINT: u32 = 1;

/// Double click
pub const BN_DOUBLECLICKED: u32 = 5;

/// Push notification
pub const BN_PUSHED: u32 = BN_DOUBLECLICKED;

/// BCN first notification
pub const BCN_FIRST: u32 = 0xFFFFFFFE - 0x0100 + 1;

/// Hot item change
pub const BCN_HOTITEMCHANGE: u32 = BCN_FIRST + 1;

/// Dropdown notification
pub const BCN_DROPDOWN: u32 = BCN_FIRST + 2;

// ============================================================================
// Button States (BST_*)
// ============================================================================

/// Unchecked
pub const BST_UNCHECKED: u32 = 0x0000;

/// Checked
pub const BST_CHECKED: u32 = 0x0001;

/// Indeterminate
pub const BST_INDETERMINATE: u32 = 0x0002;

/// Pushed
pub const BST_PUSHED: u32 = 0x0004;

/// Focus
pub const BST_FOCUS: u32 = 0x0008;

/// Hot
pub const BST_HOT: u32 = 0x0200;

/// Dropdown pushed
pub const BST_DROPDOWNPUSHED: u32 = 0x0400;

// ============================================================================
// Constants
// ============================================================================

/// Maximum split buttons
pub const MAX_SPLIT_BUTTONS: usize = 64;

/// Maximum note length
pub const MAX_NOTE_LENGTH: usize = 256;

/// Maximum text length
pub const MAX_TEXT_LENGTH: usize = 128;

/// Default dropdown width
pub const DEFAULT_DROPDOWN_WIDTH: i32 = 16;

// ============================================================================
// Split Info
// ============================================================================

/// Split button info
#[derive(Clone, Copy)]
pub struct SplitInfo {
    /// Info mask
    pub mask: u32,
    /// Image list handle
    pub himl_glyph: usize,
    /// Split style
    pub split_style: u32,
    /// Split size
    pub size: (i32, i32),
}

impl SplitInfo {
    /// Create default split info
    pub const fn new() -> Self {
        Self {
            mask: 0,
            himl_glyph: 0,
            split_style: 0,
            size: (DEFAULT_DROPDOWN_WIDTH, 0),
        }
    }
}

// ============================================================================
// Split Button State
// ============================================================================

/// Split button control state
#[derive(Clone)]
pub struct SplitButton {
    /// Is this slot in use
    pub in_use: bool,
    /// Window handle
    pub hwnd: HWND,
    /// Parent window
    pub parent: HWND,
    /// Button style
    pub style: u32,
    /// Button text
    pub text: [u8; MAX_TEXT_LENGTH],
    pub text_len: usize,
    /// Note text (for command links)
    pub note: [u8; MAX_NOTE_LENGTH],
    pub note_len: usize,
    /// Button state
    pub state: u32,
    /// Check state
    pub check: u32,
    /// Split info
    pub split_info: SplitInfo,
    /// Text margin
    pub text_margin: Rect,
    /// Image list handle
    pub image_list: usize,
    /// Is default button
    pub is_default: bool,
    /// Show shield icon
    pub show_shield: bool,
    /// Dropdown is pushed
    pub dropdown_pushed: bool,
    /// Is hot
    pub is_hot: bool,
    /// Hot tracking part (0=button, 1=dropdown)
    pub hot_part: u32,
}

impl SplitButton {
    /// Create empty split button
    pub const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: UserHandle::NULL,
            parent: UserHandle::NULL,
            style: BS_SPLITBUTTON,
            text: [0u8; MAX_TEXT_LENGTH],
            text_len: 0,
            note: [0u8; MAX_NOTE_LENGTH],
            note_len: 0,
            state: 0,
            check: BST_UNCHECKED,
            split_info: SplitInfo::new(),
            text_margin: Rect { left: 4, top: 4, right: 4, bottom: 4 },
            image_list: 0,
            is_default: false,
            show_shield: false,
            dropdown_pushed: false,
            is_hot: false,
            hot_part: 0,
        }
    }

    /// Reset state
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Set text
    pub fn set_text(&mut self, text: &str) {
        let bytes = text.as_bytes();
        let len = bytes.len().min(MAX_TEXT_LENGTH - 1);
        self.text[..len].copy_from_slice(&bytes[..len]);
        self.text_len = len;
    }

    /// Get text
    pub fn get_text(&self) -> &[u8] {
        &self.text[..self.text_len]
    }

    /// Set note
    pub fn set_note(&mut self, note: &str) {
        let bytes = note.as_bytes();
        let len = bytes.len().min(MAX_NOTE_LENGTH - 1);
        self.note[..len].copy_from_slice(&bytes[..len]);
        self.note_len = len;
    }

    /// Get note
    pub fn get_note(&self) -> &[u8] {
        &self.note[..self.note_len]
    }

    /// Is split button style
    pub fn is_split_button(&self) -> bool {
        let style_type = self.style & 0x0F;
        style_type == BS_SPLITBUTTON || style_type == BS_DEFSPLITBUTTON
    }

    /// Is command link style
    pub fn is_command_link(&self) -> bool {
        let style_type = self.style & 0x0F;
        style_type == BS_COMMANDLINK || style_type == BS_DEFCOMMANDLINK
    }

    /// Hit test
    pub fn hit_test(&self, rect: &Rect, pt: &Point) -> u32 {
        if !self.is_split_button() {
            return 0; // Entire button
        }

        let dropdown_width = self.split_info.size.0;
        let dropdown_left = rect.right - dropdown_width;

        if pt.x >= dropdown_left {
            1 // Dropdown area
        } else {
            0 // Button area
        }
    }

    /// Set dropdown state
    pub fn set_dropdown_state(&mut self, pushed: bool) {
        self.dropdown_pushed = pushed;
        if pushed {
            self.state |= BST_DROPDOWNPUSHED;
        } else {
            self.state &= !BST_DROPDOWNPUSHED;
        }
    }

    /// Get ideal size
    pub fn get_ideal_size(&self) -> (i32, i32) {
        // Base size calculation (simplified)
        let text_width = (self.text_len as i32) * 8; // Approximate
        let text_height = 16; // Approximate

        let mut width = text_width + self.text_margin.left + self.text_margin.right;
        let mut height = text_height + self.text_margin.top + self.text_margin.bottom;

        // Add note height for command links
        if self.is_command_link() && self.note_len > 0 {
            height += 16; // Note line height
        }

        // Add dropdown width for split buttons
        if self.is_split_button() {
            width += self.split_info.size.0;
        }

        (width.max(75), height.max(23))
    }

    /// Process message
    pub fn process_message(&mut self, msg: u32, wparam: usize, lparam: isize) -> isize {
        match msg {
            BM_GETCHECK => self.check as isize,
            BM_SETCHECK => {
                self.check = wparam as u32;
                0
            }
            BM_GETSTATE => self.state as isize,
            BM_SETSTATE => {
                if wparam != 0 {
                    self.state |= BST_PUSHED;
                } else {
                    self.state &= !BST_PUSHED;
                }
                0
            }
            BM_SETSTYLE => {
                self.style = wparam as u32;
                0
            }
            BCM_SETDROPDOWNSTATE => {
                self.set_dropdown_state(wparam != 0);
                1
            }
            BCM_SETSHIELD => {
                self.show_shield = wparam != 0;
                1
            }
            BCM_GETIDEALSIZE => {
                let (w, h) = self.get_ideal_size();
                // Would write to SIZE* at lparam
                let _ = lparam;
                ((h << 16) | w) as isize
            }
            BCM_GETNOTELENGTH => self.note_len as isize,
            _ => 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global split button storage
static SPLIT_BUTTONS: SpinLock<[SplitButton; MAX_SPLIT_BUTTONS]> =
    SpinLock::new([const { SplitButton::new() }; MAX_SPLIT_BUTTONS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize SplitButton subsystem
pub fn init() {
    crate::serial_println!("[USER] SplitButton initialized");
}

/// Create split button
pub fn create(hwnd: HWND, parent: HWND, style: u32) -> usize {
    let mut buttons = SPLIT_BUTTONS.lock();

    for (i, btn) in buttons.iter_mut().enumerate() {
        if !btn.in_use {
            btn.reset();
            btn.in_use = true;
            btn.hwnd = hwnd;
            btn.parent = parent;
            btn.style = style;
            btn.is_default = (style & 0x0F) == BS_DEFSPLITBUTTON
                || (style & 0x0F) == BS_DEFCOMMANDLINK
                || (style & 0x0F) == BS_DEFPUSHBUTTON;
            return i + 1;
        }
    }

    0
}

/// Destroy split button
pub fn destroy(btn_idx: usize) -> bool {
    if btn_idx == 0 {
        return false;
    }

    let mut buttons = SPLIT_BUTTONS.lock();
    let idx = btn_idx - 1;

    if idx >= MAX_SPLIT_BUTTONS {
        return false;
    }

    if buttons[idx].in_use {
        buttons[idx].reset();
        true
    } else {
        false
    }
}

/// Set button text
pub fn set_text(btn_idx: usize, text: &str) -> bool {
    if btn_idx == 0 {
        return false;
    }

    let mut buttons = SPLIT_BUTTONS.lock();
    let idx = btn_idx - 1;

    if idx >= MAX_SPLIT_BUTTONS || !buttons[idx].in_use {
        return false;
    }

    buttons[idx].set_text(text);
    true
}

/// Set note text
pub fn set_note(btn_idx: usize, note: &str) -> bool {
    if btn_idx == 0 {
        return false;
    }

    let mut buttons = SPLIT_BUTTONS.lock();
    let idx = btn_idx - 1;

    if idx >= MAX_SPLIT_BUTTONS || !buttons[idx].in_use {
        return false;
    }

    buttons[idx].set_note(note);
    true
}

/// Get note length
pub fn get_note_length(btn_idx: usize) -> usize {
    if btn_idx == 0 {
        return 0;
    }

    let buttons = SPLIT_BUTTONS.lock();
    let idx = btn_idx - 1;

    if idx >= MAX_SPLIT_BUTTONS || !buttons[idx].in_use {
        return 0;
    }

    buttons[idx].note_len
}

/// Set check state
pub fn set_check(btn_idx: usize, check: u32) {
    if btn_idx == 0 {
        return;
    }

    let mut buttons = SPLIT_BUTTONS.lock();
    let idx = btn_idx - 1;

    if idx >= MAX_SPLIT_BUTTONS || !buttons[idx].in_use {
        return;
    }

    buttons[idx].check = check;
}

/// Get check state
pub fn get_check(btn_idx: usize) -> u32 {
    if btn_idx == 0 {
        return BST_UNCHECKED;
    }

    let buttons = SPLIT_BUTTONS.lock();
    let idx = btn_idx - 1;

    if idx >= MAX_SPLIT_BUTTONS || !buttons[idx].in_use {
        return BST_UNCHECKED;
    }

    buttons[idx].check
}

/// Set dropdown state
pub fn set_dropdown_state(btn_idx: usize, pushed: bool) {
    if btn_idx == 0 {
        return;
    }

    let mut buttons = SPLIT_BUTTONS.lock();
    let idx = btn_idx - 1;

    if idx >= MAX_SPLIT_BUTTONS || !buttons[idx].in_use {
        return;
    }

    buttons[idx].set_dropdown_state(pushed);
}

/// Set shield icon
pub fn set_shield(btn_idx: usize, show: bool) {
    if btn_idx == 0 {
        return;
    }

    let mut buttons = SPLIT_BUTTONS.lock();
    let idx = btn_idx - 1;

    if idx >= MAX_SPLIT_BUTTONS || !buttons[idx].in_use {
        return;
    }

    buttons[idx].show_shield = show;
}

/// Get ideal size
pub fn get_ideal_size(btn_idx: usize) -> (i32, i32) {
    if btn_idx == 0 {
        return (75, 23);
    }

    let buttons = SPLIT_BUTTONS.lock();
    let idx = btn_idx - 1;

    if idx >= MAX_SPLIT_BUTTONS || !buttons[idx].in_use {
        return (75, 23);
    }

    buttons[idx].get_ideal_size()
}

/// Get statistics
pub fn get_stats() -> SplitButtonStats {
    let buttons = SPLIT_BUTTONS.lock();

    let mut active_count = 0;
    let mut split_count = 0;
    let mut command_link_count = 0;

    for btn in buttons.iter() {
        if btn.in_use {
            active_count += 1;
            if btn.is_split_button() {
                split_count += 1;
            }
            if btn.is_command_link() {
                command_link_count += 1;
            }
        }
    }

    SplitButtonStats {
        max_buttons: MAX_SPLIT_BUTTONS,
        active_buttons: active_count,
        split_buttons: split_count,
        command_links: command_link_count,
    }
}

/// SplitButton statistics
#[derive(Debug, Clone, Copy)]
pub struct SplitButtonStats {
    pub max_buttons: usize,
    pub active_buttons: usize,
    pub split_buttons: usize,
    pub command_links: usize,
}
