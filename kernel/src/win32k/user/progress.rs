//! Progress Dialog
//!
//! Provides progress dialog support following the Windows shell32
//! IProgressDialog pattern.
//!
//! # References
//!
//! - Windows Server 2003 shell32 progress dialog
//! - IProgressDialog COM interface

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle};

// ============================================================================
// Constants
// ============================================================================

/// Maximum title length
pub const MAX_TITLE: usize = 128;

/// Maximum line text length
pub const MAX_LINE: usize = 256;

/// Progress dialog flags (PROGDLG_*)
pub mod progdlg_flags {
    /// Normal progress
    pub const NORMAL: u32 = 0x00000000;
    /// Modal dialog
    pub const MODAL: u32 = 0x00000001;
    /// Auto time remaining
    pub const AUTOTIME: u32 = 0x00000002;
    /// No time remaining
    pub const NOTIME: u32 = 0x00000004;
    /// No minimize button
    pub const NOMINIMIZE: u32 = 0x00000008;
    /// No progress bar
    pub const NOPROGRESSBAR: u32 = 0x00000010;
    /// Marquee mode (indeterminate)
    pub const MARQUEEPROGRESS: u32 = 0x00000020;
    /// No cancel button
    pub const NOCANCEL: u32 = 0x00000040;
}

/// Timer operation flags (PDTIMER_*)
pub mod timer_flags {
    /// Reset timer
    pub const RESET: u32 = 0x00000001;
    /// Pause timer
    pub const PAUSE: u32 = 0x00000002;
    /// Resume timer
    pub const RESUME: u32 = 0x00000003;
}

/// Progress dialog state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProgressState {
    #[default]
    /// Normal state
    Normal = 0,
    /// Paused
    Paused = 1,
    /// Error state
    Error = 2,
    /// Indeterminate (marquee)
    Indeterminate = 3,
}

// ============================================================================
// Structures
// ============================================================================

/// Progress dialog configuration
#[derive(Debug, Clone, Copy)]
pub struct ProgressConfig {
    /// Parent window
    pub hwnd_parent: HWND,
    /// Flags
    pub flags: u32,
    /// Title length
    pub title_len: u8,
    /// Title text
    pub title: [u8; MAX_TITLE],
    /// Cancel text length
    pub cancel_len: u8,
    /// Cancel button text
    pub cancel_text: [u8; 32],
    /// Animation resource ID
    pub animation: u32,
}

impl ProgressConfig {
    pub const fn new() -> Self {
        Self {
            hwnd_parent: UserHandle::NULL,
            flags: progdlg_flags::AUTOTIME,
            title_len: 0,
            title: [0; MAX_TITLE],
            cancel_len: 0,
            cancel_text: [0; 32],
            animation: 0,
        }
    }

    /// Set title
    pub fn set_title(&mut self, title: &[u8]) {
        self.title_len = title.len().min(MAX_TITLE) as u8;
        self.title[..self.title_len as usize].copy_from_slice(&title[..self.title_len as usize]);
    }

    /// Set cancel button text
    pub fn set_cancel_text(&mut self, text: &[u8]) {
        self.cancel_len = text.len().min(32) as u8;
        self.cancel_text[..self.cancel_len as usize].copy_from_slice(&text[..self.cancel_len as usize]);
    }
}

/// Progress dialog instance
#[derive(Debug, Clone, Copy)]
pub struct ProgressDialog {
    /// Dialog is active
    pub active: bool,
    /// Dialog handle
    pub hwnd: HWND,
    /// Dialog ID
    pub id: u32,
    /// Configuration
    pub config: ProgressConfig,
    /// Current progress (0-10000 for 0-100.00%)
    pub progress: u32,
    /// Total value
    pub total: u64,
    /// Completed value
    pub completed: u64,
    /// State
    pub state: ProgressState,
    /// User cancelled
    pub cancelled: bool,
    /// Line 1 length
    pub line1_len: u8,
    /// Line 1 text
    pub line1: [u8; MAX_LINE],
    /// Line 2 length
    pub line2_len: u8,
    /// Line 2 text
    pub line2: [u8; MAX_LINE],
    /// Line 3 length
    pub line3_len: u8,
    /// Line 3 text
    pub line3: [u8; MAX_LINE],
    /// Start time (for time remaining)
    pub start_time: u64,
    /// Timer paused
    pub timer_paused: bool,
}

impl ProgressDialog {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            id: 0,
            config: ProgressConfig::new(),
            progress: 0,
            total: 100,
            completed: 0,
            state: ProgressState::Normal,
            cancelled: false,
            line1_len: 0,
            line1: [0; MAX_LINE],
            line2_len: 0,
            line2: [0; MAX_LINE],
            line3_len: 0,
            line3: [0; MAX_LINE],
            start_time: 0,
            timer_paused: false,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static PROGRESS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static PROGRESS_LOCK: SpinLock<()> = SpinLock::new(());
static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

const MAX_DIALOGS: usize = 8;
static DIALOGS: SpinLock<[ProgressDialog; MAX_DIALOGS]> =
    SpinLock::new([const { ProgressDialog::new() }; MAX_DIALOGS]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize progress dialog subsystem
pub fn init() {
    let _guard = PROGRESS_LOCK.lock();

    if PROGRESS_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[PROGRESS] Initializing progress dialog...");

    PROGRESS_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[PROGRESS] Progress dialog initialized");
}

// ============================================================================
// Progress Dialog API
// ============================================================================

/// Create and show a progress dialog
pub fn create_progress_dialog(config: &ProgressConfig) -> Option<u32> {
    if !PROGRESS_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let mut dialogs = DIALOGS.lock();

    // Find free slot
    for dialog in dialogs.iter_mut() {
        if !dialog.active {
            let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);

            dialog.active = true;
            dialog.id = id;
            dialog.config = *config;
            dialog.progress = 0;
            dialog.total = 100;
            dialog.completed = 0;
            dialog.state = ProgressState::Normal;
            dialog.cancelled = false;
            dialog.line1_len = 0;
            dialog.line2_len = 0;
            dialog.line3_len = 0;
            dialog.start_time = get_current_time();
            dialog.timer_paused = false;

            // Create dialog window
            dialog.hwnd = create_progress_window(config);

            return Some(id);
        }
    }

    None
}

/// Close a progress dialog
pub fn close_progress_dialog(dialog_id: u32) -> bool {
    if !PROGRESS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut dialogs = DIALOGS.lock();

    for dialog in dialogs.iter_mut() {
        if dialog.active && dialog.id == dialog_id {
            if dialog.hwnd != UserHandle::NULL {
                super::window::destroy_window(dialog.hwnd);
            }
            dialog.active = false;
            dialog.hwnd = UserHandle::NULL;
            return true;
        }
    }

    false
}

/// Set progress value (0-10000 for 0-100.00%)
pub fn set_progress(dialog_id: u32, completed: u64, total: u64) -> bool {
    if !PROGRESS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut dialogs = DIALOGS.lock();

    for dialog in dialogs.iter_mut() {
        if dialog.active && dialog.id == dialog_id {
            dialog.completed = completed;
            dialog.total = total.max(1);
            dialog.progress = ((completed * 10000) / dialog.total).min(10000) as u32;
            return true;
        }
    }

    false
}

/// Set progress percentage directly (0-100)
pub fn set_progress_percent(dialog_id: u32, percent: u32) -> bool {
    set_progress(dialog_id, percent.min(100) as u64, 100)
}

/// Set line text (line 1, 2, or 3)
pub fn set_line(dialog_id: u32, line: u8, text: &[u8], compact_path: bool) -> bool {
    if !PROGRESS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut dialogs = DIALOGS.lock();

    for dialog in dialogs.iter_mut() {
        if dialog.active && dialog.id == dialog_id {
            let text_to_use = if compact_path {
                // Would compact path to fit display width
                text
            } else {
                text
            };

            let len = text_to_use.len().min(MAX_LINE) as u8;

            match line {
                1 => {
                    dialog.line1_len = len;
                    dialog.line1[..len as usize].copy_from_slice(&text_to_use[..len as usize]);
                }
                2 => {
                    dialog.line2_len = len;
                    dialog.line2[..len as usize].copy_from_slice(&text_to_use[..len as usize]);
                }
                3 => {
                    dialog.line3_len = len;
                    dialog.line3[..len as usize].copy_from_slice(&text_to_use[..len as usize]);
                }
                _ => return false,
            }
            return true;
        }
    }

    false
}

/// Set title
pub fn set_title(dialog_id: u32, title: &[u8]) -> bool {
    if !PROGRESS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut dialogs = DIALOGS.lock();

    for dialog in dialogs.iter_mut() {
        if dialog.active && dialog.id == dialog_id {
            dialog.config.set_title(title);
            return true;
        }
    }

    false
}

/// Set cancel message
pub fn set_cancel_msg(dialog_id: u32, message: &[u8]) -> bool {
    if !PROGRESS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut dialogs = DIALOGS.lock();

    for dialog in dialogs.iter_mut() {
        if dialog.active && dialog.id == dialog_id {
            dialog.config.set_cancel_text(message);
            return true;
        }
    }

    false
}

/// Check if user cancelled
pub fn has_user_cancelled(dialog_id: u32) -> bool {
    if !PROGRESS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let dialogs = DIALOGS.lock();

    for dialog in dialogs.iter() {
        if dialog.active && dialog.id == dialog_id {
            return dialog.cancelled;
        }
    }

    false
}

/// Set progress state
pub fn set_progress_state(dialog_id: u32, state: ProgressState) -> bool {
    if !PROGRESS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut dialogs = DIALOGS.lock();

    for dialog in dialogs.iter_mut() {
        if dialog.active && dialog.id == dialog_id {
            dialog.state = state;
            return true;
        }
    }

    false
}

/// Control timer
pub fn timer_control(dialog_id: u32, flags: u32) -> bool {
    if !PROGRESS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut dialogs = DIALOGS.lock();

    for dialog in dialogs.iter_mut() {
        if dialog.active && dialog.id == dialog_id {
            match flags {
                timer_flags::RESET => {
                    dialog.start_time = get_current_time();
                    dialog.timer_paused = false;
                }
                timer_flags::PAUSE => {
                    dialog.timer_paused = true;
                }
                timer_flags::RESUME => {
                    dialog.timer_paused = false;
                }
                _ => return false,
            }
            return true;
        }
    }

    false
}

/// Get dialog info
pub fn get_dialog_info(dialog_id: u32) -> Option<ProgressDialog> {
    if !PROGRESS_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let dialogs = DIALOGS.lock();

    for dialog in dialogs.iter() {
        if dialog.active && dialog.id == dialog_id {
            return Some(*dialog);
        }
    }

    None
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create progress dialog window
fn create_progress_window(_config: &ProgressConfig) -> HWND {
    // Would create actual window
    UserHandle::NULL
}

/// Get current time
fn get_current_time() -> u64 {
    // Would return actual time
    0
}

/// Calculate time remaining
pub fn calculate_time_remaining(dialog_id: u32) -> Option<u64> {
    let dialogs = DIALOGS.lock();

    for dialog in dialogs.iter() {
        if dialog.active && dialog.id == dialog_id {
            if dialog.completed == 0 || dialog.timer_paused {
                return None;
            }

            let elapsed = get_current_time().saturating_sub(dialog.start_time);
            if elapsed == 0 {
                return None;
            }

            let rate = dialog.completed as f64 / elapsed as f64;
            if rate <= 0.0 {
                return None;
            }

            let remaining = dialog.total.saturating_sub(dialog.completed);
            return Some((remaining as f64 / rate) as u64);
        }
    }

    None
}

/// Format time remaining as string
pub fn format_time_remaining(seconds: u64, buffer: &mut [u8]) -> usize {
    if seconds < 60 {
        // "X seconds remaining"
        let s: &[u8] = if seconds == 1 { b" second remaining" } else { b" seconds remaining" };
        let num_len = format_number(seconds, buffer);
        let s_len = s.len().min(buffer.len() - num_len);
        buffer[num_len..num_len + s_len].copy_from_slice(&s[..s_len]);
        num_len + s_len
    } else if seconds < 3600 {
        // "X minutes remaining"
        let minutes = seconds / 60;
        let s: &[u8] = if minutes == 1 { b" minute remaining" } else { b" minutes remaining" };
        let num_len = format_number(minutes, buffer);
        let s_len = s.len().min(buffer.len() - num_len);
        buffer[num_len..num_len + s_len].copy_from_slice(&s[..s_len]);
        num_len + s_len
    } else {
        // "X hours remaining"
        let hours = seconds / 3600;
        let s: &[u8] = if hours == 1 { b" hour remaining" } else { b" hours remaining" };
        let num_len = format_number(hours, buffer);
        let s_len = s.len().min(buffer.len() - num_len);
        buffer[num_len..num_len + s_len].copy_from_slice(&s[..s_len]);
        num_len + s_len
    }
}

/// Format number into buffer
fn format_number(mut n: u64, buffer: &mut [u8]) -> usize {
    if n == 0 {
        if !buffer.is_empty() {
            buffer[0] = b'0';
            return 1;
        }
        return 0;
    }

    let mut temp = [0u8; 20];
    let mut len = 0;

    while n > 0 && len < 20 {
        temp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }

    let copy_len = len.min(buffer.len());
    for i in 0..copy_len {
        buffer[i] = temp[len - 1 - i];
    }

    copy_len
}

// ============================================================================
// Dialog Procedure
// ============================================================================

/// Progress dialog window procedure
pub fn progress_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    _lparam: isize,
) -> isize {
    match msg {
        super::message::WM_COMMAND => {
            handle_progress_command(hwnd, wparam as u32)
        }
        super::message::WM_CLOSE => {
            // Mark as cancelled
            mark_cancelled(hwnd);
            0
        }
        _ => 0,
    }
}

/// Handle progress dialog commands
fn handle_progress_command(hwnd: HWND, command: u32) -> isize {
    let id = command as u16;

    match id {
        2 => {
            // Cancel button
            mark_cancelled(hwnd);
            0
        }
        _ => 0,
    }
}

/// Mark dialog as cancelled
fn mark_cancelled(hwnd: HWND) {
    let mut dialogs = DIALOGS.lock();

    for dialog in dialogs.iter_mut() {
        if dialog.active && dialog.hwnd == hwnd {
            dialog.cancelled = true;
            break;
        }
    }
}

// ============================================================================
// Simple Progress API
// ============================================================================

/// Simple progress dialog (blocking)
pub fn show_simple_progress(
    parent: HWND,
    title: &[u8],
    message: &[u8],
    total: u64,
) -> Option<u32> {
    let mut config = ProgressConfig::new();
    config.hwnd_parent = parent;
    config.set_title(title);
    config.flags = progdlg_flags::AUTOTIME;

    let id = create_progress_dialog(&config)?;
    set_line(id, 1, message, false);
    set_progress(id, 0, total);

    Some(id)
}

/// Update simple progress
pub fn update_simple_progress(dialog_id: u32, completed: u64, message: Option<&[u8]>) -> bool {
    let dialogs = DIALOGS.lock();

    let total = dialogs.iter()
        .find(|d| d.active && d.id == dialog_id)
        .map(|d| d.total)
        .unwrap_or(100);

    drop(dialogs);

    set_progress(dialog_id, completed, total);

    if let Some(msg) = message {
        set_line(dialog_id, 2, msg, false);
    }

    !has_user_cancelled(dialog_id)
}
