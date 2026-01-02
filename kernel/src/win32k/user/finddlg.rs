//! Find/Replace Dialog
//!
//! Provides Find and Replace dialogs following the Windows comdlg32
//! FindText/ReplaceText patterns.
//!
//! # References
//!
//! - Windows Server 2003 comdlg32 find/replace dialogs
//! - FINDREPLACE structure

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle};

// ============================================================================
// Constants
// ============================================================================

/// Maximum search text length
pub const MAX_FIND_LEN: usize = 256;

/// Maximum replace text length
pub const MAX_REPLACE_LEN: usize = 256;

/// Find/Replace flags (FR_*)
pub mod fr_flags {
    /// Search down
    pub const DOWN: u32 = 0x00000001;
    /// Whole word only
    pub const WHOLEWORD: u32 = 0x00000002;
    /// Match case
    pub const MATCHCASE: u32 = 0x00000004;
    /// Find next
    pub const FINDNEXT: u32 = 0x00000008;
    /// Replace
    pub const REPLACE: u32 = 0x00000010;
    /// Replace all
    pub const REPLACEALL: u32 = 0x00000020;
    /// Dialog is closing
    pub const DIALOGTERM: u32 = 0x00000040;
    /// Show help
    pub const SHOWHELP: u32 = 0x00000080;
    /// Enable hook
    pub const ENABLEHOOK: u32 = 0x00000100;
    /// Enable template
    pub const ENABLETEMPLATE: u32 = 0x00000200;
    /// No up/down radio buttons
    pub const NOUPDOWN: u32 = 0x00000400;
    /// No match case checkbox
    pub const NOMATCHCASE: u32 = 0x00000800;
    /// No whole word checkbox
    pub const NOWHOLEWORD: u32 = 0x00001000;
    /// Enable template handle
    pub const ENABLETEMPLATEHANDLE: u32 = 0x00002000;
    /// Hide up/down
    pub const HIDEUPDOWN: u32 = 0x00004000;
    /// Hide match case
    pub const HIDEMATCHCASE: u32 = 0x00008000;
    /// Hide whole word
    pub const HIDEWHOLEWORD: u32 = 0x00010000;
    /// Regular expression
    pub const REGEXP: u32 = 0x00020000;
}

/// Find dialog registered message
pub const FINDMSGSTRING: u32 = 0xC000 + 100; // Would be RegisterWindowMessage("commdlg_FindReplace")

/// Find/Replace dialog type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindDialogType {
    /// Find dialog
    Find = 0,
    /// Replace dialog
    Replace = 1,
}

/// Find/Replace action
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FindAction {
    #[default]
    None = 0,
    /// Find next
    FindNext = 1,
    /// Replace current
    Replace = 2,
    /// Replace all
    ReplaceAll = 3,
    /// Dialog closing
    DialogClose = 4,
}

// ============================================================================
// Structures
// ============================================================================

/// Find/Replace structure (FINDREPLACE equivalent)
#[derive(Debug, Clone, Copy)]
pub struct FindReplace {
    /// Structure size
    pub struct_size: u32,
    /// Owner window
    pub hwnd_owner: HWND,
    /// Instance handle
    pub instance: u32,
    /// Flags
    pub flags: u32,
    /// Find text length
    pub find_len: u16,
    /// Find text
    pub find_what: [u8; MAX_FIND_LEN],
    /// Replace text length
    pub replace_len: u16,
    /// Replace text
    pub replace_with: [u8; MAX_REPLACE_LEN],
    /// Custom data
    pub cust_data: usize,
    /// Hook function
    pub hook_fn: usize,
    /// Template name
    pub template_name: u32,
}

impl FindReplace {
    pub const fn new() -> Self {
        Self {
            struct_size: 0,
            hwnd_owner: UserHandle::NULL,
            instance: 0,
            flags: 0,
            find_len: 0,
            find_what: [0; MAX_FIND_LEN],
            replace_len: 0,
            replace_with: [0; MAX_REPLACE_LEN],
            cust_data: 0,
            hook_fn: 0,
            template_name: 0,
        }
    }

    /// Set find text
    pub fn set_find_text(&mut self, text: &[u8]) {
        self.find_len = text.len().min(MAX_FIND_LEN) as u16;
        self.find_what[..self.find_len as usize].copy_from_slice(&text[..self.find_len as usize]);
    }

    /// Get find text
    pub fn get_find_text(&self) -> &[u8] {
        &self.find_what[..self.find_len as usize]
    }

    /// Set replace text
    pub fn set_replace_text(&mut self, text: &[u8]) {
        self.replace_len = text.len().min(MAX_REPLACE_LEN) as u16;
        self.replace_with[..self.replace_len as usize].copy_from_slice(&text[..self.replace_len as usize]);
    }

    /// Get replace text
    pub fn get_replace_text(&self) -> &[u8] {
        &self.replace_with[..self.replace_len as usize]
    }
}

/// Find dialog state
#[derive(Debug, Clone, Copy)]
pub struct FindDialogState {
    /// Dialog is active
    pub active: bool,
    /// Dialog handle
    pub hwnd: HWND,
    /// Dialog type
    pub dialog_type: FindDialogType,
    /// Last action
    pub last_action: FindAction,
    /// Search direction (true = down)
    pub search_down: bool,
    /// Match case
    pub match_case: bool,
    /// Whole word
    pub whole_word: bool,
    /// Matches found
    pub matches_found: u32,
    /// Replacements made
    pub replacements_made: u32,
}

impl FindDialogState {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            dialog_type: FindDialogType::Find,
            last_action: FindAction::None,
            search_down: true,
            match_case: false,
            whole_word: false,
            matches_found: 0,
            replacements_made: 0,
        }
    }
}

/// Search history entry
#[derive(Debug, Clone, Copy)]
pub struct SearchHistoryEntry {
    /// Entry is valid
    pub valid: bool,
    /// Text length
    pub len: u16,
    /// Search text
    pub text: [u8; MAX_FIND_LEN],
    /// Use count
    pub use_count: u32,
}

impl SearchHistoryEntry {
    const fn new() -> Self {
        Self {
            valid: false,
            len: 0,
            text: [0; MAX_FIND_LEN],
            use_count: 0,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static FINDDLG_INITIALIZED: AtomicBool = AtomicBool::new(false);
static FINDDLG_LOCK: SpinLock<()> = SpinLock::new(());
static FIND_COUNT: AtomicU32 = AtomicU32::new(0);

static CURRENT_STATE: SpinLock<FindDialogState> = SpinLock::new(FindDialogState::new());
static CURRENT_FR: SpinLock<FindReplace> = SpinLock::new(FindReplace::new());

// Search history
const MAX_HISTORY: usize = 16;
static FIND_HISTORY: SpinLock<[SearchHistoryEntry; MAX_HISTORY]> =
    SpinLock::new([const { SearchHistoryEntry::new() }; MAX_HISTORY]);
static REPLACE_HISTORY: SpinLock<[SearchHistoryEntry; MAX_HISTORY]> =
    SpinLock::new([const { SearchHistoryEntry::new() }; MAX_HISTORY]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize find/replace dialog subsystem
pub fn init() {
    let _guard = FINDDLG_LOCK.lock();

    if FINDDLG_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[FINDDLG] Initializing find/replace dialog...");

    FINDDLG_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[FINDDLG] Find/replace dialog initialized");
}

// ============================================================================
// Find Dialog API
// ============================================================================

/// Show find dialog (modeless)
pub fn find_text(fr: &mut FindReplace) -> HWND {
    if !FINDDLG_INITIALIZED.load(Ordering::Acquire) {
        return UserHandle::NULL;
    }

    let mut state = CURRENT_STATE.lock();

    if state.active {
        // Return existing dialog handle
        return state.hwnd;
    }

    // Create dialog
    let hwnd = create_find_dialog(fr, false);

    if hwnd == UserHandle::NULL {
        return UserHandle::NULL;
    }

    state.active = true;
    state.hwnd = hwnd;
    state.dialog_type = FindDialogType::Find;
    state.last_action = FindAction::None;
    state.search_down = (fr.flags & fr_flags::DOWN) != 0;
    state.match_case = (fr.flags & fr_flags::MATCHCASE) != 0;
    state.whole_word = (fr.flags & fr_flags::WHOLEWORD) != 0;

    *CURRENT_FR.lock() = *fr;

    FIND_COUNT.fetch_add(1, Ordering::Relaxed);

    hwnd
}

/// Show replace dialog (modeless)
pub fn replace_text(fr: &mut FindReplace) -> HWND {
    if !FINDDLG_INITIALIZED.load(Ordering::Acquire) {
        return UserHandle::NULL;
    }

    let mut state = CURRENT_STATE.lock();

    if state.active {
        return state.hwnd;
    }

    let hwnd = create_find_dialog(fr, true);

    if hwnd == UserHandle::NULL {
        return UserHandle::NULL;
    }

    state.active = true;
    state.hwnd = hwnd;
    state.dialog_type = FindDialogType::Replace;
    state.last_action = FindAction::None;
    state.search_down = (fr.flags & fr_flags::DOWN) != 0;
    state.match_case = (fr.flags & fr_flags::MATCHCASE) != 0;
    state.whole_word = (fr.flags & fr_flags::WHOLEWORD) != 0;

    *CURRENT_FR.lock() = *fr;

    FIND_COUNT.fetch_add(1, Ordering::Relaxed);

    hwnd
}

/// Close find/replace dialog
pub fn close_find_dialog() {
    let mut state = CURRENT_STATE.lock();

    if state.active {
        if state.hwnd != UserHandle::NULL {
            super::window::destroy_window(state.hwnd);
        }

        state.active = false;
        state.hwnd = UserHandle::NULL;
    }
}

/// Get current find/replace data
pub fn get_find_replace() -> FindReplace {
    *CURRENT_FR.lock()
}

/// Get dialog state
pub fn get_dialog_state() -> FindDialogState {
    *CURRENT_STATE.lock()
}

// ============================================================================
// Search Operations
// ============================================================================

/// Perform find next
pub fn do_find_next(fr: &FindReplace) -> bool {
    if fr.find_len == 0 {
        return false;
    }

    // Add to history
    add_to_find_history(&fr.find_what[..fr.find_len as usize]);

    // Update state
    let mut state = CURRENT_STATE.lock();
    state.last_action = FindAction::FindNext;

    // Notify owner window
    if fr.hwnd_owner != UserHandle::NULL {
        super::message::post_message(
            fr.hwnd_owner,
            FINDMSGSTRING,
            fr_flags::FINDNEXT as usize,
            0,
        );
    }

    true
}

/// Perform replace
pub fn do_replace(fr: &FindReplace) -> bool {
    if fr.find_len == 0 {
        return false;
    }

    // Add to history
    add_to_find_history(&fr.find_what[..fr.find_len as usize]);
    if fr.replace_len > 0 {
        add_to_replace_history(&fr.replace_with[..fr.replace_len as usize]);
    }

    // Update state
    let mut state = CURRENT_STATE.lock();
    state.last_action = FindAction::Replace;
    state.replacements_made += 1;

    // Notify owner window
    if fr.hwnd_owner != UserHandle::NULL {
        super::message::post_message(
            fr.hwnd_owner,
            FINDMSGSTRING,
            fr_flags::REPLACE as usize,
            0,
        );
    }

    true
}

/// Perform replace all
pub fn do_replace_all(fr: &FindReplace) -> u32 {
    if fr.find_len == 0 {
        return 0;
    }

    // Add to history
    add_to_find_history(&fr.find_what[..fr.find_len as usize]);
    if fr.replace_len > 0 {
        add_to_replace_history(&fr.replace_with[..fr.replace_len as usize]);
    }

    // Update state
    let mut state = CURRENT_STATE.lock();
    state.last_action = FindAction::ReplaceAll;

    // Notify owner window
    if fr.hwnd_owner != UserHandle::NULL {
        super::message::post_message(
            fr.hwnd_owner,
            FINDMSGSTRING,
            fr_flags::REPLACEALL as usize,
            0,
        );
    }

    state.replacements_made
}

// ============================================================================
// History Management
// ============================================================================

/// Add to find history
fn add_to_find_history(text: &[u8]) {
    let mut history = FIND_HISTORY.lock();
    add_to_history(&mut *history, text);
}

/// Add to replace history
fn add_to_replace_history(text: &[u8]) {
    let mut history = REPLACE_HISTORY.lock();
    add_to_history(&mut *history, text);
}

/// Add entry to history array
fn add_to_history(history: &mut [SearchHistoryEntry; MAX_HISTORY], text: &[u8]) {
    // Check if already in history
    for entry in history.iter_mut() {
        if entry.valid && entry.len as usize == text.len() &&
           entry.text[..entry.len as usize] == *text {
            entry.use_count += 1;
            return;
        }
    }

    // Find empty slot or oldest entry
    let mut target = 0;
    let mut min_count = u32::MAX;

    for (i, entry) in history.iter().enumerate() {
        if !entry.valid {
            target = i;
            break;
        }
        if entry.use_count < min_count {
            min_count = entry.use_count;
            target = i;
        }
    }

    // Add entry
    let entry = &mut history[target];
    entry.valid = true;
    entry.len = text.len().min(MAX_FIND_LEN) as u16;
    entry.text[..entry.len as usize].copy_from_slice(&text[..entry.len as usize]);
    entry.use_count = 1;
}

/// Get find history
pub fn get_find_history() -> ([SearchHistoryEntry; MAX_HISTORY], usize) {
    let history = FIND_HISTORY.lock();
    let count = history.iter().filter(|e| e.valid).count();
    (*history, count)
}

/// Get replace history
pub fn get_replace_history() -> ([SearchHistoryEntry; MAX_HISTORY], usize) {
    let history = REPLACE_HISTORY.lock();
    let count = history.iter().filter(|e| e.valid).count();
    (*history, count)
}

/// Clear all history
pub fn clear_history() {
    {
        let mut history = FIND_HISTORY.lock();
        for entry in history.iter_mut() {
            entry.valid = false;
        }
    }
    {
        let mut history = REPLACE_HISTORY.lock();
        for entry in history.iter_mut() {
            entry.valid = false;
        }
    }
}

// ============================================================================
// Dialog Creation
// ============================================================================

/// Create find dialog window
fn create_find_dialog(_fr: &FindReplace, _is_replace: bool) -> HWND {
    // Would create the actual dialog window
    UserHandle::NULL
}

// ============================================================================
// Dialog Procedure
// ============================================================================

/// Find dialog window procedure
pub fn find_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    _lparam: isize,
) -> isize {
    match msg {
        super::message::WM_COMMAND => {
            handle_find_command(hwnd, wparam as u32)
        }
        super::message::WM_CLOSE => {
            close_find_dialog();
            0
        }
        _ => 0,
    }
}

/// Handle find dialog commands
fn handle_find_command(hwnd: HWND, command: u32) -> isize {
    let id = command as u16;

    match id {
        1 => {
            // Find Next button
            let fr = CURRENT_FR.lock();
            if fr.find_len > 0 {
                drop(fr);
                let fr = get_find_replace();
                do_find_next(&fr);
            }
            0
        }
        2 => {
            // Cancel button
            close_find_dialog();
            0
        }
        3 => {
            // Replace button
            let fr = get_find_replace();
            do_replace(&fr);
            0
        }
        4 => {
            // Replace All button
            let fr = get_find_replace();
            do_replace_all(&fr);
            0
        }
        100 => {
            // Match case checkbox
            let mut state = CURRENT_STATE.lock();
            state.match_case = !state.match_case;
            let mut fr = CURRENT_FR.lock();
            if state.match_case {
                fr.flags |= fr_flags::MATCHCASE;
            } else {
                fr.flags &= !fr_flags::MATCHCASE;
            }
            0
        }
        101 => {
            // Whole word checkbox
            let mut state = CURRENT_STATE.lock();
            state.whole_word = !state.whole_word;
            let mut fr = CURRENT_FR.lock();
            if state.whole_word {
                fr.flags |= fr_flags::WHOLEWORD;
            } else {
                fr.flags &= !fr_flags::WHOLEWORD;
            }
            0
        }
        102 => {
            // Search up radio
            let mut state = CURRENT_STATE.lock();
            state.search_down = false;
            let mut fr = CURRENT_FR.lock();
            fr.flags &= !fr_flags::DOWN;
            0
        }
        103 => {
            // Search down radio
            let mut state = CURRENT_STATE.lock();
            state.search_down = true;
            let mut fr = CURRENT_FR.lock();
            fr.flags |= fr_flags::DOWN;
            0
        }
        _ => {
            let _ = hwnd;
            0
        }
    }
}

// ============================================================================
// Text Search Utilities
// ============================================================================

/// Find text in buffer (simple search)
pub fn find_in_buffer(
    buffer: &[u8],
    pattern: &[u8],
    start: usize,
    search_down: bool,
    match_case: bool,
    whole_word: bool,
) -> Option<usize> {
    if pattern.is_empty() || buffer.len() < pattern.len() {
        return None;
    }

    if search_down {
        find_forward(buffer, pattern, start, match_case, whole_word)
    } else {
        find_backward(buffer, pattern, start, match_case, whole_word)
    }
}

/// Find forward
fn find_forward(
    buffer: &[u8],
    pattern: &[u8],
    start: usize,
    match_case: bool,
    whole_word: bool,
) -> Option<usize> {
    let end = buffer.len().saturating_sub(pattern.len());

    for i in start..=end {
        if matches_at(buffer, pattern, i, match_case) {
            if !whole_word || is_whole_word(buffer, i, pattern.len()) {
                return Some(i);
            }
        }
    }

    None
}

/// Find backward
fn find_backward(
    buffer: &[u8],
    pattern: &[u8],
    start: usize,
    match_case: bool,
    whole_word: bool,
) -> Option<usize> {
    let max_start = start.min(buffer.len().saturating_sub(pattern.len()));

    for i in (0..=max_start).rev() {
        if matches_at(buffer, pattern, i, match_case) {
            if !whole_word || is_whole_word(buffer, i, pattern.len()) {
                return Some(i);
            }
        }
    }

    None
}

/// Check if pattern matches at position
fn matches_at(buffer: &[u8], pattern: &[u8], pos: usize, match_case: bool) -> bool {
    if pos + pattern.len() > buffer.len() {
        return false;
    }

    for (i, &p) in pattern.iter().enumerate() {
        let b = buffer[pos + i];
        if match_case {
            if b != p {
                return false;
            }
        } else {
            let b_lower = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
            let p_lower = if p >= b'A' && p <= b'Z' { p + 32 } else { p };
            if b_lower != p_lower {
                return false;
            }
        }
    }

    true
}

/// Check if match is a whole word
fn is_whole_word(buffer: &[u8], pos: usize, len: usize) -> bool {
    // Check character before
    if pos > 0 {
        let before = buffer[pos - 1];
        if is_word_char(before) {
            return false;
        }
    }

    // Check character after
    let end = pos + len;
    if end < buffer.len() {
        let after = buffer[end];
        if is_word_char(after) {
            return false;
        }
    }

    true
}

/// Check if character is a word character
fn is_word_char(c: u8) -> bool {
    (c >= b'a' && c <= b'z') ||
    (c >= b'A' && c <= b'Z') ||
    (c >= b'0' && c <= b'9') ||
    c == b'_'
}

/// Count occurrences of pattern in buffer
pub fn count_occurrences(
    buffer: &[u8],
    pattern: &[u8],
    match_case: bool,
    whole_word: bool,
) -> usize {
    let mut count = 0;
    let mut pos = 0;

    while let Some(found) = find_in_buffer(buffer, pattern, pos, true, match_case, whole_word) {
        count += 1;
        pos = found + 1;
    }

    count
}
