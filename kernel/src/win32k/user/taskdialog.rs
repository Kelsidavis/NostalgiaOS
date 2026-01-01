//! TaskDialog Implementation
//!
//! Windows TaskDialog for enhanced message dialogs.
//! Based on Windows Vista+ task dialog API.
//!
//! # Features
//!
//! - Main instruction and content text
//! - Custom buttons and command links
//! - Icon support
//! - Expandable area
//! - Verification checkbox
//! - Progress bar
//! - Footer with icon
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - TaskDialog structures

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// TaskDialog Flags (TDF_*)
// ============================================================================

/// Enable hyperlinks
pub const TDF_ENABLE_HYPERLINKS: u32 = 0x0001;

/// Use command links (not buttons)
pub const TDF_USE_COMMAND_LINKS: u32 = 0x0002;

/// Use command links without icon
pub const TDF_USE_COMMAND_LINKS_NO_ICON: u32 = 0x0004;

/// Expand footer area
pub const TDF_EXPAND_FOOTER_AREA: u32 = 0x0008;

/// Expanded by default
pub const TDF_EXPANDED_BY_DEFAULT: u32 = 0x0010;

/// Verification flag checked
pub const TDF_VERIFICATION_FLAG_CHECKED: u32 = 0x0020;

/// Show progress bar
pub const TDF_SHOW_PROGRESS_BAR: u32 = 0x0040;

/// Show marquee progress bar
pub const TDF_SHOW_MARQUEE_PROGRESS_BAR: u32 = 0x0080;

/// Use callback timer
pub const TDF_CALLBACK_TIMER: u32 = 0x0100;

/// Position relative to window
pub const TDF_POSITION_RELATIVE_TO_WINDOW: u32 = 0x0200;

/// RTL layout
pub const TDF_RTL_LAYOUT: u32 = 0x0400;

/// No default radio button
pub const TDF_NO_DEFAULT_RADIO_BUTTON: u32 = 0x0800;

/// Can be minimized
pub const TDF_CAN_BE_MINIMIZED: u32 = 0x1000;

/// No set foreground
pub const TDF_NO_SET_FOREGROUND: u32 = 0x2000;

/// Size to content
pub const TDF_SIZE_TO_CONTENT: u32 = 0x4000;

// ============================================================================
// TaskDialog Common Buttons (TDCBF_*)
// ============================================================================

/// OK button
pub const TDCBF_OK_BUTTON: u32 = 0x0001;

/// Yes button
pub const TDCBF_YES_BUTTON: u32 = 0x0002;

/// No button
pub const TDCBF_NO_BUTTON: u32 = 0x0004;

/// Cancel button
pub const TDCBF_CANCEL_BUTTON: u32 = 0x0008;

/// Retry button
pub const TDCBF_RETRY_BUTTON: u32 = 0x0010;

/// Close button
pub const TDCBF_CLOSE_BUTTON: u32 = 0x0020;

// ============================================================================
// TaskDialog Icons (TD_*)
// ============================================================================

/// Warning icon
pub const TD_WARNING_ICON: u32 = 0xFFFF;

/// Error icon
pub const TD_ERROR_ICON: u32 = 0xFFFE;

/// Information icon
pub const TD_INFORMATION_ICON: u32 = 0xFFFD;

/// Shield icon
pub const TD_SHIELD_ICON: u32 = 0xFFFC;

// ============================================================================
// TaskDialog Messages (TDM_*)
// ============================================================================

/// Navigate page
pub const TDM_NAVIGATE_PAGE: u32 = 0x0465;

/// Click button
pub const TDM_CLICK_BUTTON: u32 = 0x0466;

/// Set marquee progress bar
pub const TDM_SET_MARQUEE_PROGRESS_BAR: u32 = 0x0467;

/// Set progress bar state
pub const TDM_SET_PROGRESS_BAR_STATE: u32 = 0x0468;

/// Set progress bar range
pub const TDM_SET_PROGRESS_BAR_RANGE: u32 = 0x0469;

/// Set progress bar pos
pub const TDM_SET_PROGRESS_BAR_POS: u32 = 0x046A;

/// Set progress bar marquee
pub const TDM_SET_PROGRESS_BAR_MARQUEE: u32 = 0x046B;

/// Set element text
pub const TDM_SET_ELEMENT_TEXT: u32 = 0x046C;

/// Click radio button
pub const TDM_CLICK_RADIO_BUTTON: u32 = 0x046D;

/// Enable button
pub const TDM_ENABLE_BUTTON: u32 = 0x046E;

/// Enable radio button
pub const TDM_ENABLE_RADIO_BUTTON: u32 = 0x046F;

/// Click verification
pub const TDM_CLICK_VERIFICATION: u32 = 0x0470;

/// Update element text
pub const TDM_UPDATE_ELEMENT_TEXT: u32 = 0x0471;

/// Set button elevation required
pub const TDM_SET_BUTTON_ELEVATION_REQUIRED_STATE: u32 = 0x0472;

/// Update icon
pub const TDM_UPDATE_ICON: u32 = 0x0473;

// ============================================================================
// TaskDialog Notifications (TDN_*)
// ============================================================================

/// Dialog created
pub const TDN_CREATED: u32 = 0;

/// Navigation completed
pub const TDN_NAVIGATED: u32 = 1;

/// Button clicked
pub const TDN_BUTTON_CLICKED: u32 = 2;

/// Hyperlink clicked
pub const TDN_HYPERLINK_CLICKED: u32 = 3;

/// Timer fired
pub const TDN_TIMER: u32 = 4;

/// Dialog destroyed
pub const TDN_DESTROYED: u32 = 5;

/// Radio button clicked
pub const TDN_RADIO_BUTTON_CLICKED: u32 = 6;

/// Dialog constructed
pub const TDN_DIALOG_CONSTRUCTED: u32 = 7;

/// Verification clicked
pub const TDN_VERIFICATION_CLICKED: u32 = 8;

/// Help requested
pub const TDN_HELP: u32 = 9;

/// Expand button clicked
pub const TDN_EXPANDO_BUTTON_CLICKED: u32 = 10;

// ============================================================================
// Constants
// ============================================================================

/// Maximum task dialogs
pub const MAX_TASK_DIALOGS: usize = 16;

/// Maximum buttons
pub const MAX_BUTTONS: usize = 8;

/// Maximum radio buttons
pub const MAX_RADIO_BUTTONS: usize = 8;

/// Maximum text length
pub const MAX_TEXT_LENGTH: usize = 512;

// ============================================================================
// TaskDialog Button
// ============================================================================

/// Task dialog button
#[derive(Clone)]
pub struct TaskDialogButton {
    /// Button ID
    pub id: i32,
    /// Button text
    pub text: [u8; 64],
    pub text_len: usize,
    /// Is enabled
    pub enabled: bool,
    /// Requires elevation (shows shield)
    pub elevation_required: bool,
}

impl TaskDialogButton {
    /// Create empty button
    pub const fn new() -> Self {
        Self {
            id: 0,
            text: [0u8; 64],
            text_len: 0,
            enabled: true,
            elevation_required: false,
        }
    }

    /// Set button text
    pub fn set_text(&mut self, text: &str) {
        let bytes = text.as_bytes();
        let len = bytes.len().min(63);
        self.text[..len].copy_from_slice(&bytes[..len]);
        self.text_len = len;
    }
}

// ============================================================================
// TaskDialog Config
// ============================================================================

/// Task dialog configuration
#[derive(Clone)]
pub struct TaskDialogConfig {
    /// Is this slot in use
    pub in_use: bool,
    /// Parent window
    pub parent: HWND,
    /// Dialog flags
    pub flags: u32,
    /// Common buttons
    pub common_buttons: u32,
    /// Window title
    pub title: [u8; MAX_TEXT_LENGTH],
    pub title_len: usize,
    /// Main instruction
    pub main_instruction: [u8; MAX_TEXT_LENGTH],
    pub main_instruction_len: usize,
    /// Content text
    pub content: [u8; MAX_TEXT_LENGTH],
    pub content_len: usize,
    /// Verification text
    pub verification_text: [u8; MAX_TEXT_LENGTH],
    pub verification_text_len: usize,
    /// Expanded information
    pub expanded_info: [u8; MAX_TEXT_LENGTH],
    pub expanded_info_len: usize,
    /// Expanded control text
    pub expanded_control_text: [u8; 64],
    pub expanded_control_text_len: usize,
    /// Collapsed control text
    pub collapsed_control_text: [u8; 64],
    pub collapsed_control_text_len: usize,
    /// Footer text
    pub footer: [u8; MAX_TEXT_LENGTH],
    pub footer_len: usize,
    /// Main icon
    pub main_icon: u32,
    /// Footer icon
    pub footer_icon: u32,
    /// Custom buttons
    pub buttons: [TaskDialogButton; MAX_BUTTONS],
    pub button_count: usize,
    /// Radio buttons
    pub radio_buttons: [TaskDialogButton; MAX_RADIO_BUTTONS],
    pub radio_button_count: usize,
    /// Default button ID
    pub default_button: i32,
    /// Default radio button ID
    pub default_radio_button: i32,
    /// Dialog window handle
    pub hwnd: HWND,
    /// Result - clicked button ID
    pub result_button: i32,
    /// Result - selected radio button ID
    pub result_radio: i32,
    /// Result - verification checked
    pub verification_checked: bool,
    /// Is expanded
    pub expanded: bool,
    /// Progress bar position
    pub progress_pos: i32,
    /// Progress bar range min
    pub progress_min: i32,
    /// Progress bar range max
    pub progress_max: i32,
    /// Progress bar state
    pub progress_state: i32,
    /// Marquee active
    pub marquee_active: bool,
}

impl TaskDialogConfig {
    /// Create empty config
    pub const fn new() -> Self {
        Self {
            in_use: false,
            parent: UserHandle::NULL,
            flags: 0,
            common_buttons: 0,
            title: [0u8; MAX_TEXT_LENGTH],
            title_len: 0,
            main_instruction: [0u8; MAX_TEXT_LENGTH],
            main_instruction_len: 0,
            content: [0u8; MAX_TEXT_LENGTH],
            content_len: 0,
            verification_text: [0u8; MAX_TEXT_LENGTH],
            verification_text_len: 0,
            expanded_info: [0u8; MAX_TEXT_LENGTH],
            expanded_info_len: 0,
            expanded_control_text: [0u8; 64],
            expanded_control_text_len: 0,
            collapsed_control_text: [0u8; 64],
            collapsed_control_text_len: 0,
            footer: [0u8; MAX_TEXT_LENGTH],
            footer_len: 0,
            main_icon: 0,
            footer_icon: 0,
            buttons: [const { TaskDialogButton::new() }; MAX_BUTTONS],
            button_count: 0,
            radio_buttons: [const { TaskDialogButton::new() }; MAX_RADIO_BUTTONS],
            radio_button_count: 0,
            default_button: 0,
            default_radio_button: 0,
            hwnd: UserHandle::NULL,
            result_button: 0,
            result_radio: 0,
            verification_checked: false,
            expanded: false,
            progress_pos: 0,
            progress_min: 0,
            progress_max: 100,
            progress_state: 0,
            marquee_active: false,
        }
    }

    /// Reset config
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Set title
    pub fn set_title(&mut self, title: &str) {
        let bytes = title.as_bytes();
        let len = bytes.len().min(MAX_TEXT_LENGTH - 1);
        self.title[..len].copy_from_slice(&bytes[..len]);
        self.title_len = len;
    }

    /// Set main instruction
    pub fn set_main_instruction(&mut self, text: &str) {
        let bytes = text.as_bytes();
        let len = bytes.len().min(MAX_TEXT_LENGTH - 1);
        self.main_instruction[..len].copy_from_slice(&bytes[..len]);
        self.main_instruction_len = len;
    }

    /// Set content
    pub fn set_content(&mut self, text: &str) {
        let bytes = text.as_bytes();
        let len = bytes.len().min(MAX_TEXT_LENGTH - 1);
        self.content[..len].copy_from_slice(&bytes[..len]);
        self.content_len = len;
    }

    /// Set footer
    pub fn set_footer(&mut self, text: &str) {
        let bytes = text.as_bytes();
        let len = bytes.len().min(MAX_TEXT_LENGTH - 1);
        self.footer[..len].copy_from_slice(&bytes[..len]);
        self.footer_len = len;
    }

    /// Add custom button
    pub fn add_button(&mut self, id: i32, text: &str) -> bool {
        if self.button_count >= MAX_BUTTONS {
            return false;
        }

        self.buttons[self.button_count].id = id;
        self.buttons[self.button_count].set_text(text);
        self.buttons[self.button_count].enabled = true;
        self.button_count += 1;
        true
    }

    /// Add radio button
    pub fn add_radio_button(&mut self, id: i32, text: &str) -> bool {
        if self.radio_button_count >= MAX_RADIO_BUTTONS {
            return false;
        }

        self.radio_buttons[self.radio_button_count].id = id;
        self.radio_buttons[self.radio_button_count].set_text(text);
        self.radio_buttons[self.radio_button_count].enabled = true;
        self.radio_button_count += 1;
        true
    }

    /// Click button
    pub fn click_button(&mut self, id: i32) {
        self.result_button = id;
    }

    /// Click radio button
    pub fn click_radio_button(&mut self, id: i32) {
        self.result_radio = id;
    }

    /// Enable/disable button
    pub fn enable_button(&mut self, id: i32, enable: bool) {
        for btn in self.buttons[..self.button_count].iter_mut() {
            if btn.id == id {
                btn.enabled = enable;
                break;
            }
        }
    }

    /// Set progress bar range
    pub fn set_progress_range(&mut self, min: i32, max: i32) {
        self.progress_min = min;
        self.progress_max = max;
    }

    /// Set progress bar position
    pub fn set_progress_pos(&mut self, pos: i32) -> i32 {
        let old = self.progress_pos;
        self.progress_pos = pos.max(self.progress_min).min(self.progress_max);
        old
    }

    /// Process message
    pub fn process_message(&mut self, msg: u32, wparam: usize, lparam: isize) -> isize {
        match msg {
            TDM_CLICK_BUTTON => {
                self.click_button(wparam as i32);
                1
            }
            TDM_CLICK_RADIO_BUTTON => {
                self.click_radio_button(wparam as i32);
                1
            }
            TDM_ENABLE_BUTTON => {
                self.enable_button(wparam as i32, lparam != 0);
                1
            }
            TDM_SET_PROGRESS_BAR_RANGE => {
                let min = (lparam & 0xFFFF) as i32;
                let max = ((lparam >> 16) & 0xFFFF) as i32;
                self.set_progress_range(min, max);
                1
            }
            TDM_SET_PROGRESS_BAR_POS => {
                self.set_progress_pos(wparam as i32) as isize
            }
            TDM_SET_PROGRESS_BAR_MARQUEE => {
                self.marquee_active = wparam != 0;
                1
            }
            TDM_CLICK_VERIFICATION => {
                self.verification_checked = wparam != 0;
                1
            }
            _ => 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global task dialog storage
static TASK_DIALOGS: SpinLock<[TaskDialogConfig; MAX_TASK_DIALOGS]> =
    SpinLock::new([const { TaskDialogConfig::new() }; MAX_TASK_DIALOGS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize TaskDialog subsystem
pub fn init() {
    crate::serial_println!("[USER] TaskDialog initialized");
}

/// Create a task dialog (returns handle/index)
pub fn create(parent: HWND, flags: u32, common_buttons: u32) -> usize {
    let mut dialogs = TASK_DIALOGS.lock();

    for (i, dlg) in dialogs.iter_mut().enumerate() {
        if !dlg.in_use {
            dlg.reset();
            dlg.in_use = true;
            dlg.parent = parent;
            dlg.flags = flags;
            dlg.common_buttons = common_buttons;
            dlg.expanded = (flags & TDF_EXPANDED_BY_DEFAULT) != 0;
            dlg.verification_checked = (flags & TDF_VERIFICATION_FLAG_CHECKED) != 0;
            return i + 1;
        }
    }

    0
}

/// Destroy task dialog
pub fn destroy(dlg_idx: usize) -> bool {
    if dlg_idx == 0 {
        return false;
    }

    let mut dialogs = TASK_DIALOGS.lock();
    let idx = dlg_idx - 1;

    if idx >= MAX_TASK_DIALOGS {
        return false;
    }

    if dialogs[idx].in_use {
        dialogs[idx].reset();
        true
    } else {
        false
    }
}

/// Set task dialog title
pub fn set_title(dlg_idx: usize, title: &str) -> bool {
    if dlg_idx == 0 {
        return false;
    }

    let mut dialogs = TASK_DIALOGS.lock();
    let idx = dlg_idx - 1;

    if idx >= MAX_TASK_DIALOGS || !dialogs[idx].in_use {
        return false;
    }

    dialogs[idx].set_title(title);
    true
}

/// Set main instruction
pub fn set_main_instruction(dlg_idx: usize, text: &str) -> bool {
    if dlg_idx == 0 {
        return false;
    }

    let mut dialogs = TASK_DIALOGS.lock();
    let idx = dlg_idx - 1;

    if idx >= MAX_TASK_DIALOGS || !dialogs[idx].in_use {
        return false;
    }

    dialogs[idx].set_main_instruction(text);
    true
}

/// Set content
pub fn set_content(dlg_idx: usize, text: &str) -> bool {
    if dlg_idx == 0 {
        return false;
    }

    let mut dialogs = TASK_DIALOGS.lock();
    let idx = dlg_idx - 1;

    if idx >= MAX_TASK_DIALOGS || !dialogs[idx].in_use {
        return false;
    }

    dialogs[idx].set_content(text);
    true
}

/// Set main icon
pub fn set_main_icon(dlg_idx: usize, icon: u32) -> bool {
    if dlg_idx == 0 {
        return false;
    }

    let mut dialogs = TASK_DIALOGS.lock();
    let idx = dlg_idx - 1;

    if idx >= MAX_TASK_DIALOGS || !dialogs[idx].in_use {
        return false;
    }

    dialogs[idx].main_icon = icon;
    true
}

/// Add button
pub fn add_button(dlg_idx: usize, id: i32, text: &str) -> bool {
    if dlg_idx == 0 {
        return false;
    }

    let mut dialogs = TASK_DIALOGS.lock();
    let idx = dlg_idx - 1;

    if idx >= MAX_TASK_DIALOGS || !dialogs[idx].in_use {
        return false;
    }

    dialogs[idx].add_button(id, text)
}

/// Add radio button
pub fn add_radio_button(dlg_idx: usize, id: i32, text: &str) -> bool {
    if dlg_idx == 0 {
        return false;
    }

    let mut dialogs = TASK_DIALOGS.lock();
    let idx = dlg_idx - 1;

    if idx >= MAX_TASK_DIALOGS || !dialogs[idx].in_use {
        return false;
    }

    dialogs[idx].add_radio_button(id, text)
}

/// Show task dialog and get result
pub fn show(dlg_idx: usize) -> (i32, i32, bool) {
    if dlg_idx == 0 {
        return (0, 0, false);
    }

    let dialogs = TASK_DIALOGS.lock();
    let idx = dlg_idx - 1;

    if idx >= MAX_TASK_DIALOGS || !dialogs[idx].in_use {
        return (0, 0, false);
    }

    // In a real implementation, this would display the dialog
    // For now, return default values
    (
        dialogs[idx].result_button,
        dialogs[idx].result_radio,
        dialogs[idx].verification_checked,
    )
}

/// Simple task dialog (like MessageBox)
pub fn task_dialog(
    parent: HWND,
    title: &str,
    main_instruction: &str,
    content: &str,
    common_buttons: u32,
    icon: u32,
) -> i32 {
    let dlg = create(parent, 0, common_buttons);
    if dlg == 0 {
        return 0;
    }

    set_title(dlg, title);
    set_main_instruction(dlg, main_instruction);
    set_content(dlg, content);
    set_main_icon(dlg, icon);

    let (result, _, _) = show(dlg);
    destroy(dlg);

    result
}

/// Get statistics
pub fn get_stats() -> TaskDialogStats {
    let dialogs = TASK_DIALOGS.lock();

    let mut active_count = 0;

    for dlg in dialogs.iter() {
        if dlg.in_use {
            active_count += 1;
        }
    }

    TaskDialogStats {
        max_dialogs: MAX_TASK_DIALOGS,
        active_dialogs: active_count,
    }
}

/// TaskDialog statistics
#[derive(Debug, Clone, Copy)]
pub struct TaskDialogStats {
    pub max_dialogs: usize,
    pub active_dialogs: usize,
}
