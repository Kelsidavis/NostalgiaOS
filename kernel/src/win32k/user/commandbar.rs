//! Command Bar Control
//!
//! Provides command bar/address bar control following Windows
//! Explorer patterns.
//!
//! # References
//!
//! - Windows Server 2003 Explorer address bar
//! - Common controls rebar integration

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle, Rect};

// ============================================================================
// Constants
// ============================================================================

/// Maximum path/URL length
pub const MAX_PATH: usize = 260;
pub const MAX_URL: usize = 2048;

/// Command bar styles
pub mod cbs_style {
    /// Show Go button
    pub const SHOW_GOBUTTON: u32 = 0x00000001;
    /// Show dropdown
    pub const DROPDOWN: u32 = 0x00000002;
    /// Auto-complete enabled
    pub const AUTOCOMPLETE: u32 = 0x00000004;
    /// File system paths
    pub const FILESYSTEM: u32 = 0x00000008;
    /// URLs
    pub const URL: u32 = 0x00000010;
    /// History dropdown
    pub const HISTORY: u32 = 0x00000020;
    /// Favorites dropdown
    pub const FAVORITES: u32 = 0x00000040;
    /// Show icon
    pub const SHOWICON: u32 = 0x00000080;
    /// Flat style
    pub const FLAT: u32 = 0x00000100;
}

/// Command bar notifications
pub mod cbn_notify {
    /// User pressed Enter or Go
    pub const NAVIGATE: u32 = 1;
    /// Text changed
    pub const TEXTCHANGED: u32 = 2;
    /// Dropdown opened
    pub const DROPDOWN: u32 = 3;
    /// Dropdown closed
    pub const CLOSEUP: u32 = 4;
    /// Selection changed in dropdown
    pub const SELCHANGE: u32 = 5;
}

/// Auto-complete flags
pub mod ac_flags {
    /// Auto-complete file system
    pub const FILESYSTEM: u32 = 0x00000001;
    /// Auto-complete URLs
    pub const URLHISTORY: u32 = 0x00000002;
    /// Auto-complete MRU
    pub const URLMRU: u32 = 0x00000004;
    /// Auto-append
    pub const AUTOSUGGEST: u32 = 0x00000008;
    /// Auto-suggest from dropdown
    pub const AUTOAPPEND: u32 = 0x00000010;
}

// ============================================================================
// Structures
// ============================================================================

/// Command bar instance
#[derive(Clone, Copy)]
pub struct CommandBar {
    /// Control is active
    pub active: bool,
    /// Window handle
    pub hwnd: HWND,
    /// Parent window
    pub hwnd_parent: HWND,
    /// Styles
    pub style: u32,
    /// Auto-complete flags
    pub ac_flags: u32,
    /// Current text length
    pub text_len: u16,
    /// Current text
    pub text: [u8; MAX_URL],
    /// Selected icon
    pub icon: u32,
    /// Dropdown is open
    pub dropdown_open: bool,
    /// History item count
    pub history_count: u8,
    /// Currently focused
    pub focused: bool,
}

impl CommandBar {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            hwnd_parent: UserHandle::NULL,
            style: cbs_style::AUTOCOMPLETE | cbs_style::DROPDOWN | cbs_style::HISTORY,
            ac_flags: ac_flags::FILESYSTEM | ac_flags::URLHISTORY | ac_flags::AUTOSUGGEST,
            text_len: 0,
            text: [0; MAX_URL],
            icon: 0,
            dropdown_open: false,
            history_count: 0,
            focused: false,
        }
    }

    /// Set text
    pub fn set_text(&mut self, text: &[u8]) {
        self.text_len = text.len().min(MAX_URL) as u16;
        let len = self.text_len as usize;
        self.text[..len].copy_from_slice(&text[..len]);
    }

    /// Get text
    pub fn get_text(&self) -> &[u8] {
        &self.text[..self.text_len as usize]
    }
}

/// History entry
#[derive(Clone, Copy)]
pub struct HistoryEntry {
    /// Entry is valid
    pub valid: bool,
    /// Entry type (0=path, 1=URL)
    pub entry_type: u8,
    /// Icon index
    pub icon: u16,
    /// Text length
    pub text_len: u16,
    /// Text
    pub text: [u8; MAX_URL],
    /// Title length (for URLs)
    pub title_len: u8,
    /// Title
    pub title: [u8; 128],
    /// Access count
    pub access_count: u16,
    /// Last access time
    pub last_access: u64,
}

impl HistoryEntry {
    const fn new() -> Self {
        Self {
            valid: false,
            entry_type: 0,
            icon: 0,
            text_len: 0,
            text: [0; MAX_URL],
            title_len: 0,
            title: [0; 128],
            access_count: 0,
            last_access: 0,
        }
    }
}

/// Auto-complete suggestion
#[derive(Clone, Copy)]
pub struct AutoCompleteSuggestion {
    /// Suggestion is valid
    pub valid: bool,
    /// Match score (higher = better)
    pub score: u16,
    /// Text length
    pub text_len: u16,
    /// Suggestion text
    pub text: [u8; MAX_URL],
    /// Icon index
    pub icon: u16,
}

impl AutoCompleteSuggestion {
    const fn new() -> Self {
        Self {
            valid: false,
            score: 0,
            text_len: 0,
            text: [0; MAX_URL],
            icon: 0,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static CB_INITIALIZED: AtomicBool = AtomicBool::new(false);
static CB_LOCK: SpinLock<()> = SpinLock::new(());
static NEXT_CB_ID: AtomicU32 = AtomicU32::new(1);

const MAX_COMMANDBARS: usize = 8;
static COMMANDBARS: SpinLock<[CommandBar; MAX_COMMANDBARS]> =
    SpinLock::new([const { CommandBar::new() }; MAX_COMMANDBARS]);

const MAX_HISTORY: usize = 64;
static HISTORY: SpinLock<[HistoryEntry; MAX_HISTORY]> =
    SpinLock::new([const { HistoryEntry::new() }; MAX_HISTORY]);

const MAX_SUGGESTIONS: usize = 16;
static SUGGESTIONS: SpinLock<[AutoCompleteSuggestion; MAX_SUGGESTIONS]> =
    SpinLock::new([const { AutoCompleteSuggestion::new() }; MAX_SUGGESTIONS]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize command bar subsystem
pub fn init() {
    let _guard = CB_LOCK.lock();

    if CB_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[COMMANDBAR] Initializing command bar...");

    CB_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[COMMANDBAR] Command bar initialized");
}

// ============================================================================
// Command Bar API
// ============================================================================

/// Create a command bar
pub fn create_command_bar(parent: HWND, style: u32) -> Option<usize> {
    if !CB_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let mut bars = COMMANDBARS.lock();

    for (i, bar) in bars.iter_mut().enumerate() {
        if !bar.active {
            bar.active = true;
            bar.hwnd_parent = parent;
            bar.style = style;
            bar.text_len = 0;
            bar.dropdown_open = false;
            bar.history_count = 0;

            // Would create actual window
            bar.hwnd = UserHandle::NULL;

            return Some(i);
        }
    }

    None
}

/// Destroy a command bar
pub fn destroy_command_bar(index: usize) -> bool {
    let mut bars = COMMANDBARS.lock();

    if index >= MAX_COMMANDBARS {
        return false;
    }

    let bar = &mut bars[index];

    if !bar.active {
        return false;
    }

    if bar.hwnd != UserHandle::NULL {
        super::window::destroy_window(bar.hwnd);
    }

    bar.active = false;
    bar.hwnd = UserHandle::NULL;

    true
}

/// Set command bar text
pub fn set_text(index: usize, text: &[u8]) -> bool {
    let mut bars = COMMANDBARS.lock();

    if index >= MAX_COMMANDBARS || !bars[index].active {
        return false;
    }

    bars[index].set_text(text);

    // Update auto-complete suggestions
    if (bars[index].style & cbs_style::AUTOCOMPLETE) != 0 {
        drop(bars);
        update_suggestions(index);
    }

    true
}

/// Get command bar text
pub fn get_text(index: usize, buffer: &mut [u8]) -> usize {
    let bars = COMMANDBARS.lock();

    if index >= MAX_COMMANDBARS || !bars[index].active {
        return 0;
    }

    let len = (bars[index].text_len as usize).min(buffer.len());
    buffer[..len].copy_from_slice(&bars[index].text[..len]);
    len
}

/// Navigate to current text
pub fn navigate(index: usize) -> bool {
    let bars = COMMANDBARS.lock();

    if index >= MAX_COMMANDBARS || !bars[index].active {
        return false;
    }

    let text_len = bars[index].text_len;
    let mut path = [0u8; MAX_URL];
    path[..text_len as usize].copy_from_slice(&bars[index].text[..text_len as usize]);
    let parent = bars[index].hwnd_parent;

    drop(bars);

    // Add to history
    add_history_entry(&path[..text_len as usize], 0);

    // Notify parent
    if parent != UserHandle::NULL {
        super::message::post_message(
            parent,
            super::message::WM_COMMAND,
            cbn_notify::NAVIGATE as usize,
            0,
        );
    }

    true
}

/// Show dropdown
pub fn show_dropdown(index: usize) -> bool {
    let mut bars = COMMANDBARS.lock();

    if index >= MAX_COMMANDBARS || !bars[index].active {
        return false;
    }

    if (bars[index].style & cbs_style::DROPDOWN) == 0 {
        return false;
    }

    bars[index].dropdown_open = true;

    // Would show dropdown window
    true
}

/// Hide dropdown
pub fn hide_dropdown(index: usize) -> bool {
    let mut bars = COMMANDBARS.lock();

    if index >= MAX_COMMANDBARS || !bars[index].active {
        return false;
    }

    bars[index].dropdown_open = false;

    // Would hide dropdown window
    true
}

/// Set icon
pub fn set_icon(index: usize, icon: u32) -> bool {
    let mut bars = COMMANDBARS.lock();

    if index >= MAX_COMMANDBARS || !bars[index].active {
        return false;
    }

    bars[index].icon = icon;
    true
}

// ============================================================================
// History
// ============================================================================

/// Add history entry
pub fn add_history_entry(text: &[u8], entry_type: u8) -> bool {
    let mut history = HISTORY.lock();

    // Check if already exists
    for entry in history.iter_mut() {
        if entry.valid && entry.text_len as usize == text.len() {
            if &entry.text[..entry.text_len as usize] == text {
                // Update access count and time
                entry.access_count = entry.access_count.saturating_add(1);
                entry.last_access = get_current_time();
                return true;
            }
        }
    }

    // Find free slot or oldest entry
    let mut oldest_idx = 0;
    let mut oldest_time = u64::MAX;

    for (i, entry) in history.iter().enumerate() {
        if !entry.valid {
            oldest_idx = i;
            break;
        }
        if entry.last_access < oldest_time {
            oldest_time = entry.last_access;
            oldest_idx = i;
        }
    }

    // Add new entry
    let entry = &mut history[oldest_idx];
    entry.valid = true;
    entry.entry_type = entry_type;
    entry.text_len = text.len().min(MAX_URL) as u16;
    let len = entry.text_len as usize;
    entry.text[..len].copy_from_slice(&text[..len]);
    entry.access_count = 1;
    entry.last_access = get_current_time();

    true
}

/// Get history entries
pub fn get_history() -> ([HistoryEntry; MAX_HISTORY], usize) {
    let history = HISTORY.lock();
    let count = history.iter().filter(|e| e.valid).count();
    (*history, count)
}

/// Clear history
pub fn clear_history() {
    let mut history = HISTORY.lock();
    for entry in history.iter_mut() {
        entry.valid = false;
    }
}

// ============================================================================
// Auto-Complete
// ============================================================================

/// Update suggestions for current text
fn update_suggestions(index: usize) {
    let bars = COMMANDBARS.lock();

    if index >= MAX_COMMANDBARS || !bars[index].active {
        return;
    }

    let prefix_len = bars[index].text_len as usize;
    if prefix_len == 0 {
        drop(bars);
        clear_suggestions();
        return;
    }

    // Copy prefix to local buffer
    let mut prefix_buf = [0u8; MAX_URL];
    prefix_buf[..prefix_len].copy_from_slice(&bars[index].text[..prefix_len]);
    let prefix = &prefix_buf[..prefix_len];
    let ac_flags = bars[index].ac_flags;

    drop(bars);

    let mut suggestions = SUGGESTIONS.lock();

    // Clear existing
    for suggestion in suggestions.iter_mut() {
        suggestion.valid = false;
    }

    let mut count = 0;

    // Search history
    if (ac_flags & ac_flags::URLHISTORY) != 0 || (ac_flags & ac_flags::URLMRU) != 0 {
        let history = HISTORY.lock();

        for entry in history.iter() {
            if !entry.valid || count >= MAX_SUGGESTIONS {
                break;
            }

            // Check if starts with prefix
            if entry.text_len >= prefix_len as u16 {
                let matches = prefix_matches(&entry.text[..prefix_len], prefix);
                if matches {
                    suggestions[count].valid = true;
                    suggestions[count].text_len = entry.text_len;
                    suggestions[count].text = entry.text;
                    suggestions[count].icon = entry.icon;
                    suggestions[count].score = entry.access_count;
                    count += 1;
                }
            }
        }
    }

    // Would also search file system if FILESYSTEM flag set
}

/// Check if text matches prefix (case-insensitive)
fn prefix_matches(text: &[u8], prefix: &[u8]) -> bool {
    if text.len() < prefix.len() {
        return false;
    }

    for (t, p) in text.iter().zip(prefix.iter()) {
        let t_lower = if *t >= b'A' && *t <= b'Z' { *t + 32 } else { *t };
        let p_lower = if *p >= b'A' && *p <= b'Z' { *p + 32 } else { *p };

        if t_lower != p_lower {
            return false;
        }
    }

    true
}

/// Get suggestions
pub fn get_suggestions() -> ([AutoCompleteSuggestion; MAX_SUGGESTIONS], usize) {
    let suggestions = SUGGESTIONS.lock();
    let count = suggestions.iter().filter(|s| s.valid).count();
    (*suggestions, count)
}

/// Clear suggestions
fn clear_suggestions() {
    let mut suggestions = SUGGESTIONS.lock();
    for suggestion in suggestions.iter_mut() {
        suggestion.valid = false;
    }
}

/// Select suggestion
pub fn select_suggestion(index: usize, suggestion_idx: usize) -> bool {
    let suggestions = SUGGESTIONS.lock();

    if suggestion_idx >= MAX_SUGGESTIONS || !suggestions[suggestion_idx].valid {
        return false;
    }

    let text_len = suggestions[suggestion_idx].text_len as usize;
    let mut text = [0u8; MAX_URL];
    text[..text_len].copy_from_slice(&suggestions[suggestion_idx].text[..text_len]);

    drop(suggestions);

    set_text(index, &text[..text_len])
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get current time
fn get_current_time() -> u64 {
    0
}

// ============================================================================
// Window Procedure
// ============================================================================

/// Command bar window procedure
pub fn commandbar_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    _lparam: isize,
) -> isize {
    match msg {
        super::message::WM_CHAR => {
            // Handle character input
            if let Some(index) = find_commandbar_by_hwnd(hwnd) {
                handle_char_input(index, wparam as u8);
            }
            0
        }
        super::message::WM_KEYDOWN => {
            // Handle key input
            if let Some(index) = find_commandbar_by_hwnd(hwnd) {
                handle_key_input(index, wparam as u32);
            }
            0
        }
        super::message::WM_SETFOCUS => {
            if let Some(index) = find_commandbar_by_hwnd(hwnd) {
                let mut bars = COMMANDBARS.lock();
                if bars[index].active {
                    bars[index].focused = true;
                }
            }
            0
        }
        super::message::WM_KILLFOCUS => {
            if let Some(index) = find_commandbar_by_hwnd(hwnd) {
                let mut bars = COMMANDBARS.lock();
                if bars[index].active {
                    bars[index].focused = false;
                    bars[index].dropdown_open = false;
                }
            }
            0
        }
        _ => 0,
    }
}

/// Find command bar by window handle
fn find_commandbar_by_hwnd(hwnd: HWND) -> Option<usize> {
    let bars = COMMANDBARS.lock();

    for (i, bar) in bars.iter().enumerate() {
        if bar.active && bar.hwnd == hwnd {
            return Some(i);
        }
    }

    None
}

/// Handle character input
fn handle_char_input(index: usize, ch: u8) {
    let mut bars = COMMANDBARS.lock();

    if index >= MAX_COMMANDBARS || !bars[index].active {
        return;
    }

    // Add character to text
    let len = bars[index].text_len as usize;
    if len < MAX_URL {
        bars[index].text[len] = ch;
        bars[index].text_len += 1;

        // Update suggestions
        if (bars[index].style & cbs_style::AUTOCOMPLETE) != 0 {
            drop(bars);
            update_suggestions(index);
        }
    }
}

/// Handle key input
fn handle_key_input(index: usize, key: u32) {
    match key {
        0x0D => {
            // Enter - navigate
            navigate(index);
        }
        0x1B => {
            // Escape - hide dropdown
            hide_dropdown(index);
        }
        0x26 => {
            // Up arrow - previous suggestion
            // Would handle
        }
        0x28 => {
            // Down arrow - next suggestion
            // Would handle
        }
        0x08 => {
            // Backspace
            let mut bars = COMMANDBARS.lock();
            if bars[index].active && bars[index].text_len > 0 {
                bars[index].text_len -= 1;
                drop(bars);
                update_suggestions(index);
            }
        }
        _ => {}
    }
}
