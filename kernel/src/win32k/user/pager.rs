//! Pager Control Implementation
//!
//! Windows Pager control for scrolling contained child windows.
//! Based on Windows Server 2003 commctrl.h and SysPager.
//!
//! # Features
//!
//! - Horizontal or vertical scrolling
//! - Auto-scroll on mouse hover
//! - Configurable button size and appearance
//! - Position tracking
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - PGM_* messages, PGS_* styles

use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle, Rect};

// ============================================================================
// Pager Styles (PGS_*)
// ============================================================================

/// Vertical orientation (default)
pub const PGS_VERT: u32 = 0x00000000;

/// Horizontal orientation
pub const PGS_HORZ: u32 = 0x00000001;

/// Auto-scroll when mouse hovers over scroll buttons
pub const PGS_AUTOSCROLL: u32 = 0x00000002;

/// Enable drag and drop
pub const PGS_DRAGNDROP: u32 = 0x00000004;

// ============================================================================
// Pager Messages
// ============================================================================

/// Message base for Pager
pub const PGM_FIRST: u32 = 0x1400;

/// Set the child window
/// lParam: HWND of child
pub const PGM_SETCHILD: u32 = PGM_FIRST + 1;

/// Recalculate size
pub const PGM_RECALCSIZE: u32 = PGM_FIRST + 2;

/// Forward mouse messages to child
/// wParam: TRUE/FALSE
pub const PGM_FORWARDMOUSE: u32 = PGM_FIRST + 3;

/// Set background color
/// lParam: COLORREF
/// Returns: previous color
pub const PGM_SETBKCOLOR: u32 = PGM_FIRST + 4;

/// Get background color
/// Returns: COLORREF
pub const PGM_GETBKCOLOR: u32 = PGM_FIRST + 5;

/// Set border size
/// lParam: border size in pixels
/// Returns: previous border size
pub const PGM_SETBORDER: u32 = PGM_FIRST + 6;

/// Get border size
/// Returns: border size in pixels
pub const PGM_GETBORDER: u32 = PGM_FIRST + 7;

/// Set scroll position
/// lParam: position
/// Returns: previous position
pub const PGM_SETPOS: u32 = PGM_FIRST + 8;

/// Get scroll position
/// Returns: current position
pub const PGM_GETPOS: u32 = PGM_FIRST + 9;

/// Set button size
/// lParam: button size in pixels
/// Returns: previous button size
pub const PGM_SETBUTTONSIZE: u32 = PGM_FIRST + 10;

/// Get button size
/// Returns: button size in pixels
pub const PGM_GETBUTTONSIZE: u32 = PGM_FIRST + 11;

/// Get button state
/// lParam: PGB_TOPORLEFT or PGB_BOTTOMORRIGHT
/// Returns: state flags
pub const PGM_GETBUTTONSTATE: u32 = PGM_FIRST + 12;

// ============================================================================
// Button Identifiers
// ============================================================================

/// Top or left button
pub const PGB_TOPORLEFT: u32 = 0;

/// Bottom or right button
pub const PGB_BOTTOMORRIGHT: u32 = 1;

// ============================================================================
// Button States (PGF_*)
// ============================================================================

/// Button is invisible
pub const PGF_INVISIBLE: u32 = 0;

/// Button is normal
pub const PGF_NORMAL: u32 = 1;

/// Button is grayed
pub const PGF_GRAYED: u32 = 2;

/// Button is depressed
pub const PGF_DEPRESSED: u32 = 4;

/// Button is hot (mouse over)
pub const PGF_HOT: u32 = 8;

// ============================================================================
// Notifications (PGN_*)
// ============================================================================

/// First PGN notification code
pub const PGN_FIRST: u32 = 0u32.wrapping_sub(900);

/// Scroll occurred
pub const PGN_SCROLL: u32 = PGN_FIRST.wrapping_sub(1);

/// Calculate size of child
pub const PGN_CALCSIZE: u32 = PGN_FIRST.wrapping_sub(2);

/// Hot item changing
pub const PGN_HOTITEMCHANGE: u32 = PGN_FIRST.wrapping_sub(3);

// ============================================================================
// Scroll Direction (PGF_*)
// ============================================================================

/// Scroll left
pub const PGF_SCROLLLEFT: u32 = 1;

/// Scroll right
pub const PGF_SCROLLRIGHT: u32 = 2;

/// Scroll up
pub const PGF_SCROLLUP: u32 = 4;

/// Scroll down
pub const PGF_SCROLLDOWN: u32 = 8;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of Pager controls
pub const MAX_PAGER_CONTROLS: usize = 64;

/// Pager class name
pub const PAGER_CLASS: &str = "SysPager";

/// Default button size
pub const DEFAULT_BUTTON_SIZE: i32 = 12;

/// Default border size
pub const DEFAULT_BORDER: i32 = 0;

// ============================================================================
// Pager Control Structure
// ============================================================================

/// Pager control state
#[derive(Clone)]
pub struct PagerControl {
    /// Control handle
    pub hwnd: HWND,
    /// Is this slot in use
    pub in_use: bool,
    /// Control style flags
    pub style: u32,
    /// Display rectangle
    pub rect: Rect,

    // Child window
    /// Child window handle
    pub child: HWND,
    /// Child size (width for horz, height for vert)
    pub child_size: i32,

    // Scroll state
    /// Current scroll position
    pub position: i32,
    /// Maximum scroll position
    pub max_position: i32,

    // Appearance
    /// Button size in pixels
    pub button_size: i32,
    /// Border size in pixels
    pub border: i32,
    /// Background color
    pub background_color: u32,

    // Button state
    /// Top/left button state
    pub top_left_state: u32,
    /// Bottom/right button state
    pub bottom_right_state: u32,

    // Settings
    /// Forward mouse messages to child
    pub forward_mouse: bool,
    /// Auto-scroll timer active
    pub auto_scrolling: bool,
}

impl PagerControl {
    /// Create a new Pager control
    pub const fn new() -> Self {
        Self {
            hwnd: UserHandle::NULL,
            in_use: false,
            style: 0,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            child: UserHandle::NULL,
            child_size: 0,
            position: 0,
            max_position: 0,
            button_size: DEFAULT_BUTTON_SIZE,
            border: DEFAULT_BORDER,
            background_color: 0xD4D0C8, // Default button face color
            top_left_state: PGF_NORMAL,
            bottom_right_state: PGF_NORMAL,
            forward_mouse: false,
            auto_scrolling: false,
        }
    }

    /// Reset control to default state
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Check if horizontal orientation
    pub fn is_horizontal(&self) -> bool {
        self.style & PGS_HORZ != 0
    }

    /// Get the visible area size
    pub fn get_visible_size(&self) -> i32 {
        if self.is_horizontal() {
            let width = self.rect.right - self.rect.left;
            width - (self.button_size * 2) - (self.border * 2)
        } else {
            let height = self.rect.bottom - self.rect.top;
            height - (self.button_size * 2) - (self.border * 2)
        }
    }

    /// Calculate button rectangles
    pub fn get_button_rects(&self) -> (Rect, Rect) {
        if self.is_horizontal() {
            let top_left = Rect {
                left: self.rect.left + self.border,
                top: self.rect.top + self.border,
                right: self.rect.left + self.border + self.button_size,
                bottom: self.rect.bottom - self.border,
            };
            let bottom_right = Rect {
                left: self.rect.right - self.border - self.button_size,
                top: self.rect.top + self.border,
                right: self.rect.right - self.border,
                bottom: self.rect.bottom - self.border,
            };
            (top_left, bottom_right)
        } else {
            let top_left = Rect {
                left: self.rect.left + self.border,
                top: self.rect.top + self.border,
                right: self.rect.right - self.border,
                bottom: self.rect.top + self.border + self.button_size,
            };
            let bottom_right = Rect {
                left: self.rect.left + self.border,
                top: self.rect.bottom - self.border - self.button_size,
                right: self.rect.right - self.border,
                bottom: self.rect.bottom - self.border,
            };
            (top_left, bottom_right)
        }
    }

    /// Set child window
    pub fn set_child(&mut self, child: HWND) {
        self.child = child;
        self.recalc_size();
    }

    /// Recalculate sizes
    pub fn recalc_size(&mut self) {
        // In a real implementation, we would query the child's ideal size
        // For now, use a placeholder
        self.max_position = self.child_size.saturating_sub(self.get_visible_size());
        if self.max_position < 0 {
            self.max_position = 0;
        }

        // Clamp position
        if self.position > self.max_position {
            self.position = self.max_position;
        }

        // Update button states
        self.update_button_states();
    }

    /// Update button states based on position
    pub fn update_button_states(&mut self) {
        // Top/left button
        if self.position == 0 {
            self.top_left_state = PGF_GRAYED;
        } else {
            self.top_left_state = PGF_NORMAL;
        }

        // Bottom/right button
        if self.position >= self.max_position {
            self.bottom_right_state = PGF_GRAYED;
        } else {
            self.bottom_right_state = PGF_NORMAL;
        }

        // Hide buttons if content fits
        if self.child_size <= self.get_visible_size() {
            self.top_left_state = PGF_INVISIBLE;
            self.bottom_right_state = PGF_INVISIBLE;
        }
    }

    /// Scroll by a delta amount
    pub fn scroll(&mut self, delta: i32) -> bool {
        let old_pos = self.position;
        self.position = (self.position + delta).clamp(0, self.max_position);

        if self.position != old_pos {
            self.update_button_states();
            true
        } else {
            false
        }
    }

    /// Scroll to a specific position
    pub fn set_position(&mut self, pos: i32) -> i32 {
        let old_pos = self.position;
        self.position = pos.clamp(0, self.max_position);
        self.update_button_states();
        old_pos
    }

    /// Get button state
    pub fn get_button_state(&self, button: u32) -> u32 {
        match button {
            PGB_TOPORLEFT => self.top_left_state,
            PGB_BOTTOMORRIGHT => self.bottom_right_state,
            _ => 0,
        }
    }

    /// Set child size (called during size calculation)
    pub fn set_child_size(&mut self, size: i32) {
        self.child_size = size;
        self.recalc_size();
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global Pager control storage
static PAGER_CONTROLS: SpinLock<[PagerControl; MAX_PAGER_CONTROLS]> =
    SpinLock::new([const { PagerControl::new() }; MAX_PAGER_CONTROLS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize Pager control subsystem
pub fn init() {
    crate::serial_println!("[USER] Pager control initialized");
}

/// Create a Pager control
pub fn create_pager(hwnd: HWND, style: u32, rect: &Rect) -> Option<usize> {
    let mut controls = PAGER_CONTROLS.lock();

    for (i, control) in controls.iter_mut().enumerate() {
        if !control.in_use {
            control.reset();
            control.hwnd = hwnd;
            control.in_use = true;
            control.style = style;
            control.rect = *rect;
            return Some(i);
        }
    }

    None
}

/// Destroy a Pager control
pub fn destroy_pager(index: usize) -> bool {
    let mut controls = PAGER_CONTROLS.lock();

    if index >= MAX_PAGER_CONTROLS {
        return false;
    }

    if controls[index].in_use {
        controls[index].reset();
        true
    } else {
        false
    }
}

/// Set child window
pub fn set_child(index: usize, child: HWND) -> bool {
    let mut controls = PAGER_CONTROLS.lock();

    if index >= MAX_PAGER_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].set_child(child);
    true
}

/// Recalculate size
pub fn recalc_size(index: usize) -> bool {
    let mut controls = PAGER_CONTROLS.lock();

    if index >= MAX_PAGER_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].recalc_size();
    true
}

/// Set background color
pub fn set_bk_color(index: usize, color: u32) -> u32 {
    let mut controls = PAGER_CONTROLS.lock();

    if index >= MAX_PAGER_CONTROLS || !controls[index].in_use {
        return 0;
    }

    let old = controls[index].background_color;
    controls[index].background_color = color;
    old
}

/// Get background color
pub fn get_bk_color(index: usize) -> u32 {
    let controls = PAGER_CONTROLS.lock();

    if index >= MAX_PAGER_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].background_color
}

/// Set border size
pub fn set_border(index: usize, border: i32) -> i32 {
    let mut controls = PAGER_CONTROLS.lock();

    if index >= MAX_PAGER_CONTROLS || !controls[index].in_use {
        return 0;
    }

    let old = controls[index].border;
    controls[index].border = border;
    controls[index].recalc_size();
    old
}

/// Get border size
pub fn get_border(index: usize) -> i32 {
    let controls = PAGER_CONTROLS.lock();

    if index >= MAX_PAGER_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].border
}

/// Set position
pub fn set_position(index: usize, pos: i32) -> i32 {
    let mut controls = PAGER_CONTROLS.lock();

    if index >= MAX_PAGER_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].set_position(pos)
}

/// Get position
pub fn get_position(index: usize) -> i32 {
    let controls = PAGER_CONTROLS.lock();

    if index >= MAX_PAGER_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].position
}

/// Set button size
pub fn set_button_size(index: usize, size: i32) -> i32 {
    let mut controls = PAGER_CONTROLS.lock();

    if index >= MAX_PAGER_CONTROLS || !controls[index].in_use {
        return 0;
    }

    let old = controls[index].button_size;
    controls[index].button_size = size;
    controls[index].recalc_size();
    old
}

/// Get button size
pub fn get_button_size(index: usize) -> i32 {
    let controls = PAGER_CONTROLS.lock();

    if index >= MAX_PAGER_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].button_size
}

/// Get button state
pub fn get_button_state(index: usize, button: u32) -> u32 {
    let controls = PAGER_CONTROLS.lock();

    if index >= MAX_PAGER_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].get_button_state(button)
}

/// Set forward mouse
pub fn set_forward_mouse(index: usize, forward: bool) -> bool {
    let mut controls = PAGER_CONTROLS.lock();

    if index >= MAX_PAGER_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].forward_mouse = forward;
    true
}

/// Process Pager control message
pub fn process_message(index: usize, msg: u32, wparam: usize, lparam: isize) -> isize {
    match msg {
        PGM_SETCHILD => {
            // lparam contains child HWND
            // In a real implementation, we'd use lparam as the child handle
            let _child_hwnd = lparam as u32;
            // set_child(index, child_hwnd);
            0
        }
        PGM_RECALCSIZE => {
            recalc_size(index);
            0
        }
        PGM_FORWARDMOUSE => {
            set_forward_mouse(index, wparam != 0);
            0
        }
        PGM_SETBKCOLOR => {
            set_bk_color(index, lparam as u32) as isize
        }
        PGM_GETBKCOLOR => {
            get_bk_color(index) as isize
        }
        PGM_SETBORDER => {
            set_border(index, lparam as i32) as isize
        }
        PGM_GETBORDER => {
            get_border(index) as isize
        }
        PGM_SETPOS => {
            set_position(index, lparam as i32) as isize
        }
        PGM_GETPOS => {
            get_position(index) as isize
        }
        PGM_SETBUTTONSIZE => {
            set_button_size(index, lparam as i32) as isize
        }
        PGM_GETBUTTONSIZE => {
            get_button_size(index) as isize
        }
        PGM_GETBUTTONSTATE => {
            get_button_state(index, lparam as u32) as isize
        }
        _ => 0,
    }
}

/// Get statistics
pub fn get_stats() -> PagerStats {
    let controls = PAGER_CONTROLS.lock();

    let mut active_count = 0;
    for control in controls.iter() {
        if control.in_use {
            active_count += 1;
        }
    }

    PagerStats {
        max_controls: MAX_PAGER_CONTROLS,
        active_controls: active_count,
    }
}

/// Pager statistics
#[derive(Debug, Clone, Copy)]
pub struct PagerStats {
    pub max_controls: usize,
    pub active_controls: usize,
}
