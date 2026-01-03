//! Edit Control
//!
//! Implementation of Windows NT-style Edit control for text input.
//! Supports single-line and multi-line text editing with selection,
//! undo/redo, and password masking.
//!
//! # Features
//!
//! - Single-line and multi-line modes
//! - Text selection with mouse and keyboard
//! - Copy/Cut/Paste support
//! - Undo/Redo
//! - Password masking
//! - Read-only mode
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/client/editctl.c`

use super::super::{HWND, UserHandle};
use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// Edit Control Messages (EM_*)
// ============================================================================

pub const EM_GETSEL: u32 = 0x00B0;
pub const EM_SETSEL: u32 = 0x00B1;
pub const EM_GETRECT: u32 = 0x00B2;
pub const EM_SETRECT: u32 = 0x00B3;
pub const EM_SETRECTNP: u32 = 0x00B4;
pub const EM_SCROLL: u32 = 0x00B5;
pub const EM_LINESCROLL: u32 = 0x00B6;
pub const EM_SCROLLCARET: u32 = 0x00B7;
pub const EM_GETMODIFY: u32 = 0x00B8;
pub const EM_SETMODIFY: u32 = 0x00B9;
pub const EM_GETLINECOUNT: u32 = 0x00BA;
pub const EM_LINEINDEX: u32 = 0x00BB;
pub const EM_SETHANDLE: u32 = 0x00BC;
pub const EM_GETHANDLE: u32 = 0x00BD;
pub const EM_GETTHUMB: u32 = 0x00BE;
pub const EM_LINELENGTH: u32 = 0x00C1;
pub const EM_REPLACESEL: u32 = 0x00C2;
pub const EM_GETLINE: u32 = 0x00C4;
pub const EM_LIMITTEXT: u32 = 0x00C5;
pub const EM_CANUNDO: u32 = 0x00C6;
pub const EM_UNDO: u32 = 0x00C7;
pub const EM_FMTLINES: u32 = 0x00C8;
pub const EM_LINEFROMCHAR: u32 = 0x00C9;
pub const EM_SETTABSTOPS: u32 = 0x00CB;
pub const EM_SETPASSWORDCHAR: u32 = 0x00CC;
pub const EM_EMPTYUNDOBUFFER: u32 = 0x00CD;
pub const EM_GETFIRSTVISIBLELINE: u32 = 0x00CE;
pub const EM_SETREADONLY: u32 = 0x00CF;
pub const EM_SETWORDBREAKPROC: u32 = 0x00D0;
pub const EM_GETWORDBREAKPROC: u32 = 0x00D1;
pub const EM_GETPASSWORDCHAR: u32 = 0x00D2;
pub const EM_SETMARGINS: u32 = 0x00D3;
pub const EM_GETMARGINS: u32 = 0x00D4;
pub const EM_SETLIMITTEXT: u32 = EM_LIMITTEXT;
pub const EM_GETLIMITTEXT: u32 = 0x00D5;
pub const EM_POSFROMCHAR: u32 = 0x00D6;
pub const EM_CHARFROMPOS: u32 = 0x00D7;

// ============================================================================
// Edit Control Styles (ES_*)
// ============================================================================

/// Left-aligned text (default)
pub const ES_LEFT: u32 = 0x0000;
/// Center-aligned text
pub const ES_CENTER: u32 = 0x0001;
/// Right-aligned text
pub const ES_RIGHT: u32 = 0x0002;
/// Multi-line edit control
pub const ES_MULTILINE: u32 = 0x0004;
/// Convert to uppercase
pub const ES_UPPERCASE: u32 = 0x0008;
/// Convert to lowercase
pub const ES_LOWERCASE: u32 = 0x0010;
/// Password mode (display asterisks)
pub const ES_PASSWORD: u32 = 0x0020;
/// Auto vertical scroll
pub const ES_AUTOVSCROLL: u32 = 0x0040;
/// Auto horizontal scroll
pub const ES_AUTOHSCROLL: u32 = 0x0080;
/// Don't hide selection when losing focus
pub const ES_NOHIDESEL: u32 = 0x0100;
/// OEM character conversion
pub const ES_OEMCONVERT: u32 = 0x0400;
/// Read-only mode
pub const ES_READONLY: u32 = 0x0800;
/// Want Return key (multi-line)
pub const ES_WANTRETURN: u32 = 0x1000;
/// Numbers only
pub const ES_NUMBER: u32 = 0x2000;

// ============================================================================
// Edit Control Notifications (EN_*)
// ============================================================================

pub const EN_SETFOCUS: u32 = 0x0100;
pub const EN_KILLFOCUS: u32 = 0x0200;
pub const EN_CHANGE: u32 = 0x0300;
pub const EN_UPDATE: u32 = 0x0400;
pub const EN_ERRSPACE: u32 = 0x0500;
pub const EN_MAXTEXT: u32 = 0x0501;
pub const EN_HSCROLL: u32 = 0x0601;
pub const EN_VSCROLL: u32 = 0x0602;

// ============================================================================
// Constants
// ============================================================================

/// Maximum text length
const MAX_TEXT_LENGTH: usize = 32768;

/// Maximum undo buffer size
const MAX_UNDO_SIZE: usize = 1024;

/// Maximum edit control instances
const MAX_EDIT_CONTROLS: usize = 64;

/// Default password character
const DEFAULT_PASSWORD_CHAR: char = '*';

// ============================================================================
// Undo Entry
// ============================================================================

/// Undo operation type
#[derive(Clone, Copy, PartialEq, Eq)]
enum UndoType {
    None,
    Insert,
    Delete,
    Replace,
}

/// Undo entry
#[derive(Clone, Copy)]
struct UndoEntry {
    /// Type of operation
    op_type: UndoType,
    /// Position where operation occurred
    position: usize,
    /// Length of affected text
    length: usize,
    /// Saved text (for delete/replace)
    saved_text: [u8; MAX_UNDO_SIZE],
    /// Saved text length
    saved_len: usize,
}

impl UndoEntry {
    const fn empty() -> Self {
        Self {
            op_type: UndoType::None,
            position: 0,
            length: 0,
            saved_text: [0; MAX_UNDO_SIZE],
            saved_len: 0,
        }
    }
}

// ============================================================================
// Edit Control State
// ============================================================================

/// Edit control state
#[derive(Clone)]
struct EditState {
    /// Owner window
    hwnd: HWND,
    /// Parent window
    hwnd_parent: HWND,
    /// Control style
    style: u32,
    /// Text buffer
    text: [u8; MAX_TEXT_LENGTH],
    /// Text length
    text_len: usize,
    /// Maximum text length
    max_length: usize,
    /// Selection start position
    sel_start: usize,
    /// Selection end position
    sel_end: usize,
    /// Caret position
    caret_pos: usize,
    /// First visible character (horizontal scroll)
    first_visible: usize,
    /// First visible line (vertical scroll)
    first_visible_line: usize,
    /// Left margin
    left_margin: i32,
    /// Right margin
    right_margin: i32,
    /// Password character
    password_char: char,
    /// Has been modified?
    modified: bool,
    /// Has focus?
    has_focus: bool,
    /// Read-only mode?
    readonly: bool,
    /// Undo buffer
    undo: UndoEntry,
    /// Is slot in use?
    in_use: bool,
}

impl EditState {
    const fn empty() -> Self {
        Self {
            hwnd: UserHandle::NULL,
            hwnd_parent: UserHandle::NULL,
            style: 0,
            text: [0; MAX_TEXT_LENGTH],
            text_len: 0,
            max_length: MAX_TEXT_LENGTH,
            sel_start: 0,
            sel_end: 0,
            caret_pos: 0,
            first_visible: 0,
            first_visible_line: 0,
            left_margin: 2,
            right_margin: 2,
            password_char: '*',
            modified: false,
            has_focus: false,
            readonly: false,
            undo: UndoEntry::empty(),
            in_use: false,
        }
    }
}

/// Edit control storage
static EDIT_CONTROLS: SpinLock<[EditState; MAX_EDIT_CONTROLS]> = SpinLock::new({
    const EMPTY: EditState = EditState::empty();
    [EMPTY; MAX_EDIT_CONTROLS]
});

static EDIT_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize edit control subsystem
pub fn init() {
    if EDIT_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[USER/Edit] Edit control subsystem initialized");
    EDIT_INITIALIZED.store(true, Ordering::Release);
}

// ============================================================================
// Edit Control Management
// ============================================================================

/// Create an edit control
pub fn create_edit(hwnd: HWND, parent: HWND, style: u32) -> bool {
    let mut edits = EDIT_CONTROLS.lock();

    for edit in edits.iter_mut() {
        if !edit.in_use {
            edit.hwnd = hwnd;
            edit.hwnd_parent = parent;
            edit.style = style;
            edit.text_len = 0;
            edit.max_length = MAX_TEXT_LENGTH;
            edit.sel_start = 0;
            edit.sel_end = 0;
            edit.caret_pos = 0;
            edit.first_visible = 0;
            edit.first_visible_line = 0;
            edit.modified = false;
            edit.has_focus = false;
            edit.readonly = (style & ES_READONLY) != 0;
            edit.password_char = if (style & ES_PASSWORD) != 0 {
                DEFAULT_PASSWORD_CHAR
            } else {
                '\0'
            };
            edit.in_use = true;

            crate::serial_println!("[USER/Edit] Created edit control for window {:x}", hwnd.raw());
            return true;
        }
    }

    false
}

/// Destroy an edit control
pub fn destroy_edit(hwnd: HWND) -> bool {
    let mut edits = EDIT_CONTROLS.lock();

    for edit in edits.iter_mut() {
        if edit.in_use && edit.hwnd == hwnd {
            edit.in_use = false;
            edit.text_len = 0;
            crate::serial_println!("[USER/Edit] Destroyed edit control {:x}", hwnd.raw());
            return true;
        }
    }

    false
}

// ============================================================================
// Text Operations
// ============================================================================

/// Set edit control text
pub fn set_text(hwnd: HWND, text: &str) -> bool {
    let mut edits = EDIT_CONTROLS.lock();

    for edit in edits.iter_mut() {
        if edit.in_use && edit.hwnd == hwnd {
            let bytes = text.as_bytes();
            let mut write_pos = 0;

            for &byte in bytes {
                if write_pos >= edit.max_length {
                    break;
                }

                // Filter numbers only if ES_NUMBER
                if (edit.style & ES_NUMBER) != 0 && !byte.is_ascii_digit() {
                    continue;
                }

                // Apply case conversion
                let converted = if (edit.style & ES_UPPERCASE) != 0 {
                    byte.to_ascii_uppercase()
                } else if (edit.style & ES_LOWERCASE) != 0 {
                    byte.to_ascii_lowercase()
                } else {
                    byte
                };

                edit.text[write_pos] = converted;
                write_pos += 1;
            }

            edit.text_len = write_pos;
            edit.caret_pos = write_pos;
            edit.sel_start = 0;
            edit.sel_end = 0;
            edit.modified = true;

            return true;
        }
    }

    false
}

/// Get edit control text
pub fn get_text(hwnd: HWND, buffer: &mut [u8]) -> usize {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            let len = edit.text_len.min(buffer.len());
            buffer[..len].copy_from_slice(&edit.text[..len]);
            return len;
        }
    }

    0
}

/// Get edit control text length
pub fn get_text_length(hwnd: HWND) -> usize {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            return edit.text_len;
        }
    }

    0
}

/// Set text limit
pub fn set_limit_text(hwnd: HWND, limit: usize) -> bool {
    let mut edits = EDIT_CONTROLS.lock();

    for edit in edits.iter_mut() {
        if edit.in_use && edit.hwnd == hwnd {
            edit.max_length = limit.min(MAX_TEXT_LENGTH);
            return true;
        }
    }

    false
}

/// Get text limit
pub fn get_limit_text(hwnd: HWND) -> usize {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            return edit.max_length;
        }
    }

    0
}

// ============================================================================
// Selection Operations
// ============================================================================

/// Get selection range
pub fn get_sel(hwnd: HWND) -> (usize, usize) {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            return (edit.sel_start, edit.sel_end);
        }
    }

    (0, 0)
}

/// Set selection range
pub fn set_sel(hwnd: HWND, start: i32, end: i32) -> bool {
    let mut edits = EDIT_CONTROLS.lock();

    for edit in edits.iter_mut() {
        if edit.in_use && edit.hwnd == hwnd {
            let start = if start < 0 { 0 } else { (start as usize).min(edit.text_len) };
            let end = if end < 0 { edit.text_len } else { (end as usize).min(edit.text_len) };

            edit.sel_start = start.min(end);
            edit.sel_end = start.max(end);
            edit.caret_pos = edit.sel_end;

            return true;
        }
    }

    false
}

/// Replace selected text
pub fn replace_sel(hwnd: HWND, text: &str, can_undo: bool) -> bool {
    let mut edits = EDIT_CONTROLS.lock();

    for edit in edits.iter_mut() {
        if edit.in_use && edit.hwnd == hwnd {
            if edit.readonly {
                return false;
            }

            let sel_start = edit.sel_start.min(edit.sel_end);
            let sel_end = edit.sel_start.max(edit.sel_end);

            // Save undo information
            if can_undo && sel_start != sel_end {
                let len = (sel_end - sel_start).min(MAX_UNDO_SIZE);
                edit.undo.op_type = UndoType::Replace;
                edit.undo.position = sel_start;
                edit.undo.length = len;
                edit.undo.saved_text[..len].copy_from_slice(&edit.text[sel_start..sel_start + len]);
                edit.undo.saved_len = len;
            }

            // Delete selected text
            let remaining = edit.text_len - sel_end;
            for i in 0..remaining {
                edit.text[sel_start + i] = edit.text[sel_end + i];
            }
            edit.text_len = sel_start + remaining;

            // Insert new text
            let insert_len = text.len().min(edit.max_length - edit.text_len);
            if insert_len > 0 {
                // Make room for new text
                for i in (0..edit.text_len - sel_start).rev() {
                    edit.text[sel_start + insert_len + i] = edit.text[sel_start + i];
                }
                // Insert text
                edit.text[sel_start..sel_start + insert_len].copy_from_slice(&text.as_bytes()[..insert_len]);
                edit.text_len += insert_len;
            }

            edit.caret_pos = sel_start + insert_len;
            edit.sel_start = edit.caret_pos;
            edit.sel_end = edit.caret_pos;
            edit.modified = true;

            return true;
        }
    }

    false
}

// ============================================================================
// Caret/Cursor Operations
// ============================================================================

/// Get caret position
pub fn get_caret_pos(hwnd: HWND) -> usize {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            return edit.caret_pos;
        }
    }

    0
}

/// Set caret position
pub fn set_caret_pos(hwnd: HWND, pos: usize) -> bool {
    let mut edits = EDIT_CONTROLS.lock();

    for edit in edits.iter_mut() {
        if edit.in_use && edit.hwnd == hwnd {
            edit.caret_pos = pos.min(edit.text_len);
            return true;
        }
    }

    false
}

/// Scroll caret into view
pub fn scroll_caret(hwnd: HWND) -> bool {
    let mut edits = EDIT_CONTROLS.lock();

    for edit in edits.iter_mut() {
        if edit.in_use && edit.hwnd == hwnd {
            // Ensure caret is visible
            if edit.caret_pos < edit.first_visible {
                edit.first_visible = edit.caret_pos;
            }
            // Would need width info to determine if scrolling right is needed
            return true;
        }
    }

    false
}

// ============================================================================
// Character/Position Mapping
// ============================================================================

/// Get position from character index
pub fn pos_from_char(hwnd: HWND, index: usize) -> (i32, i32) {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            // Simple calculation assuming fixed-width font
            let char_width = 8;
            let x = ((index - edit.first_visible) as i32) * char_width + edit.left_margin;
            let y = 2; // Single line

            return (x, y);
        }
    }

    (0, 0)
}

/// Get character index from position
pub fn char_from_pos(hwnd: HWND, x: i32, _y: i32) -> usize {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            let char_width = 8;
            let adjusted_x = x - edit.left_margin;
            let char_index = (adjusted_x / char_width).max(0) as usize + edit.first_visible;
            return char_index.min(edit.text_len);
        }
    }

    0
}

// ============================================================================
// Undo/Redo
// ============================================================================

/// Check if undo is available
pub fn can_undo(hwnd: HWND) -> bool {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            return edit.undo.op_type != UndoType::None;
        }
    }

    false
}

/// Perform undo
pub fn undo(hwnd: HWND) -> bool {
    let mut edits = EDIT_CONTROLS.lock();

    for edit in edits.iter_mut() {
        if edit.in_use && edit.hwnd == hwnd {
            if edit.undo.op_type == UndoType::None {
                return false;
            }

            match edit.undo.op_type {
                UndoType::Delete | UndoType::Replace => {
                    // Re-insert deleted text
                    let pos = edit.undo.position;
                    let len = edit.undo.saved_len;

                    if edit.text_len + len <= edit.max_length {
                        // Make room
                        for i in (0..edit.text_len - pos).rev() {
                            edit.text[pos + len + i] = edit.text[pos + i];
                        }
                        // Insert saved text
                        edit.text[pos..pos + len].copy_from_slice(&edit.undo.saved_text[..len]);
                        edit.text_len += len;
                        edit.caret_pos = pos + len;
                    }
                }
                UndoType::Insert => {
                    // Remove inserted text
                    let pos = edit.undo.position;
                    let len = edit.undo.length;

                    for i in 0..(edit.text_len - pos - len) {
                        edit.text[pos + i] = edit.text[pos + len + i];
                    }
                    edit.text_len -= len;
                    edit.caret_pos = pos;
                }
                _ => {}
            }

            edit.undo.op_type = UndoType::None;
            edit.modified = true;

            return true;
        }
    }

    false
}

/// Empty undo buffer
pub fn empty_undo_buffer(hwnd: HWND) -> bool {
    let mut edits = EDIT_CONTROLS.lock();

    for edit in edits.iter_mut() {
        if edit.in_use && edit.hwnd == hwnd {
            edit.undo.op_type = UndoType::None;
            return true;
        }
    }

    false
}

// ============================================================================
// Modify Flag
// ============================================================================

/// Get modify flag
pub fn get_modify(hwnd: HWND) -> bool {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            return edit.modified;
        }
    }

    false
}

/// Set modify flag
pub fn set_modify(hwnd: HWND, modified: bool) -> bool {
    let mut edits = EDIT_CONTROLS.lock();

    for edit in edits.iter_mut() {
        if edit.in_use && edit.hwnd == hwnd {
            edit.modified = modified;
            return true;
        }
    }

    false
}

// ============================================================================
// Read-only Mode
// ============================================================================

/// Set read-only mode
pub fn set_readonly(hwnd: HWND, readonly: bool) -> bool {
    let mut edits = EDIT_CONTROLS.lock();

    for edit in edits.iter_mut() {
        if edit.in_use && edit.hwnd == hwnd {
            edit.readonly = readonly;
            return true;
        }
    }

    false
}

/// Get read-only mode
pub fn get_readonly(hwnd: HWND) -> bool {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            return edit.readonly;
        }
    }

    false
}

// ============================================================================
// Password Character
// ============================================================================

/// Set password character
pub fn set_password_char(hwnd: HWND, ch: char) -> bool {
    let mut edits = EDIT_CONTROLS.lock();

    for edit in edits.iter_mut() {
        if edit.in_use && edit.hwnd == hwnd {
            edit.password_char = ch;
            return true;
        }
    }

    false
}

/// Get password character
pub fn get_password_char(hwnd: HWND) -> char {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            return edit.password_char;
        }
    }

    '\0'
}

// ============================================================================
// Margins
// ============================================================================

/// Set margins
pub fn set_margins(hwnd: HWND, left: i32, right: i32) -> bool {
    let mut edits = EDIT_CONTROLS.lock();

    for edit in edits.iter_mut() {
        if edit.in_use && edit.hwnd == hwnd {
            if left >= 0 {
                edit.left_margin = left;
            }
            if right >= 0 {
                edit.right_margin = right;
            }
            return true;
        }
    }

    false
}

/// Get margins
pub fn get_margins(hwnd: HWND) -> (i32, i32) {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            return (edit.left_margin, edit.right_margin);
        }
    }

    (0, 0)
}

// ============================================================================
// Multi-line Support
// ============================================================================

/// Get line count
pub fn get_line_count(hwnd: HWND) -> usize {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            if (edit.style & ES_MULTILINE) == 0 {
                return 1;
            }

            // Count newlines
            let mut count = 1;
            for i in 0..edit.text_len {
                if edit.text[i] == b'\n' {
                    count += 1;
                }
            }
            return count;
        }
    }

    0
}

/// Get line index (character position of line start)
pub fn line_index(hwnd: HWND, line: i32) -> i32 {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            if (edit.style & ES_MULTILINE) == 0 {
                return 0;
            }

            let target_line = if line < 0 {
                // Get line containing caret
                let mut current_line = 0;
                for i in 0..edit.caret_pos {
                    if edit.text[i] == b'\n' {
                        current_line += 1;
                    }
                }
                current_line
            } else {
                line as usize
            };

            let mut current_line = 0;
            for i in 0..edit.text_len {
                if current_line == target_line {
                    return i as i32;
                }
                if edit.text[i] == b'\n' {
                    current_line += 1;
                }
            }

            return -1;
        }
    }

    -1
}

/// Get line length
pub fn line_length(hwnd: HWND, char_index: i32) -> i32 {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            if (edit.style & ES_MULTILINE) == 0 {
                return edit.text_len as i32;
            }

            let index = if char_index < 0 {
                edit.caret_pos
            } else {
                (char_index as usize).min(edit.text_len)
            };

            // Find line start
            let mut line_start = 0;
            for i in (0..index).rev() {
                if edit.text[i] == b'\n' {
                    line_start = i + 1;
                    break;
                }
            }

            // Find line end
            let mut line_end = edit.text_len;
            for i in index..edit.text_len {
                if edit.text[i] == b'\n' {
                    line_end = i;
                    break;
                }
            }

            return (line_end - line_start) as i32;
        }
    }

    0
}

/// Get line from character index
pub fn line_from_char(hwnd: HWND, char_index: i32) -> i32 {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            if (edit.style & ES_MULTILINE) == 0 {
                return 0;
            }

            let index = if char_index < 0 {
                edit.caret_pos
            } else {
                (char_index as usize).min(edit.text_len)
            };

            let mut line = 0;
            for i in 0..index {
                if edit.text[i] == b'\n' {
                    line += 1;
                }
            }

            return line;
        }
    }

    0
}

/// Get first visible line
pub fn get_first_visible_line(hwnd: HWND) -> usize {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            return edit.first_visible_line;
        }
    }

    0
}

// ============================================================================
// Keyboard Input
// ============================================================================

/// Process character input
pub fn process_char(hwnd: HWND, ch: char) -> bool {
    let mut edits = EDIT_CONTROLS.lock();

    for edit in edits.iter_mut() {
        if edit.in_use && edit.hwnd == hwnd {
            if edit.readonly {
                return false;
            }

            // Handle special characters
            match ch {
                '\x08' => {
                    // Backspace
                    if edit.sel_start != edit.sel_end {
                        // Delete selection
                        drop(edits);
                        return replace_sel(hwnd, "", true);
                    } else if edit.caret_pos > 0 {
                        // Delete character before caret
                        edit.caret_pos -= 1;
                        for i in edit.caret_pos..edit.text_len - 1 {
                            edit.text[i] = edit.text[i + 1];
                        }
                        edit.text_len -= 1;
                        edit.modified = true;
                    }
                    return true;
                }
                '\x7F' => {
                    // Delete
                    if edit.sel_start != edit.sel_end {
                        drop(edits);
                        return replace_sel(hwnd, "", true);
                    } else if edit.caret_pos < edit.text_len {
                        for i in edit.caret_pos..edit.text_len - 1 {
                            edit.text[i] = edit.text[i + 1];
                        }
                        edit.text_len -= 1;
                        edit.modified = true;
                    }
                    return true;
                }
                '\r' | '\n' => {
                    if (edit.style & ES_MULTILINE) == 0 {
                        return false; // Don't handle Enter in single-line
                    }
                    // Insert newline
                    if edit.text_len < edit.max_length {
                        for i in (edit.caret_pos..edit.text_len).rev() {
                            edit.text[i + 1] = edit.text[i];
                        }
                        edit.text[edit.caret_pos] = b'\n';
                        edit.text_len += 1;
                        edit.caret_pos += 1;
                        edit.modified = true;
                    }
                    return true;
                }
                _ => {
                    // Regular character
                    if ch.is_ascii() && edit.text_len < edit.max_length {
                        // Apply case conversion
                        let actual_char = if (edit.style & ES_UPPERCASE) != 0 {
                            ch.to_ascii_uppercase()
                        } else if (edit.style & ES_LOWERCASE) != 0 {
                            ch.to_ascii_lowercase()
                        } else {
                            ch
                        };

                        // Check ES_NUMBER
                        if (edit.style & ES_NUMBER) != 0 && !ch.is_ascii_digit() {
                            return false;
                        }

                        // Delete selection first
                        if edit.sel_start != edit.sel_end {
                            let sel_start = edit.sel_start.min(edit.sel_end);
                            let sel_end = edit.sel_start.max(edit.sel_end);
                            let remaining = edit.text_len - sel_end;
                            for i in 0..remaining {
                                edit.text[sel_start + i] = edit.text[sel_end + i];
                            }
                            edit.text_len = sel_start + remaining;
                            edit.caret_pos = sel_start;
                            edit.sel_start = edit.caret_pos;
                            edit.sel_end = edit.caret_pos;
                        }

                        // Insert character
                        for i in (edit.caret_pos..edit.text_len).rev() {
                            edit.text[i + 1] = edit.text[i];
                        }
                        edit.text[edit.caret_pos] = actual_char as u8;
                        edit.text_len += 1;
                        edit.caret_pos += 1;
                        edit.sel_start = edit.caret_pos;
                        edit.sel_end = edit.caret_pos;
                        edit.modified = true;

                        return true;
                    }
                }
            }

            return false;
        }
    }

    false
}

// ============================================================================
// Message Handler
// ============================================================================

/// Handle edit control message
pub fn handle_message(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> isize {
    match msg {
        EM_GETSEL => {
            let (start, end) = get_sel(hwnd);
            ((end as u32) << 16 | (start as u32 & 0xFFFF)) as isize
        }
        EM_SETSEL => {
            set_sel(hwnd, wparam as i32, lparam as i32);
            0
        }
        EM_GETMODIFY => get_modify(hwnd) as isize,
        EM_SETMODIFY => {
            set_modify(hwnd, wparam != 0);
            0
        }
        EM_GETLINECOUNT => get_line_count(hwnd) as isize,
        EM_LINEINDEX => line_index(hwnd, wparam as i32) as isize,
        EM_LINELENGTH => line_length(hwnd, wparam as i32) as isize,
        EM_LINEFROMCHAR => line_from_char(hwnd, wparam as i32) as isize,
        EM_GETFIRSTVISIBLELINE => get_first_visible_line(hwnd) as isize,
        EM_LIMITTEXT => {
            set_limit_text(hwnd, wparam);
            0
        }
        EM_GETLIMITTEXT => get_limit_text(hwnd) as isize,
        EM_CANUNDO => can_undo(hwnd) as isize,
        EM_UNDO => undo(hwnd) as isize,
        EM_EMPTYUNDOBUFFER => {
            empty_undo_buffer(hwnd);
            0
        }
        EM_SETREADONLY => {
            set_readonly(hwnd, wparam != 0);
            1
        }
        EM_SETPASSWORDCHAR => {
            set_password_char(hwnd, char::from_u32(wparam as u32).unwrap_or('*'));
            0
        }
        EM_GETPASSWORDCHAR => get_password_char(hwnd) as isize,
        EM_SETMARGINS => {
            let left = if wparam & 1 != 0 { (lparam & 0xFFFF) as i32 } else { -1 };
            let right = if wparam & 2 != 0 { (lparam >> 16) as i32 } else { -1 };
            set_margins(hwnd, left, right);
            0
        }
        EM_GETMARGINS => {
            let (left, right) = get_margins(hwnd);
            ((right as u32) << 16 | (left as u32 & 0xFFFF)) as isize
        }
        EM_SCROLLCARET => {
            scroll_caret(hwnd);
            0
        }
        EM_POSFROMCHAR => {
            let (x, y) = pos_from_char(hwnd, wparam);
            ((y as u32) << 16 | (x as u32 & 0xFFFF)) as isize
        }
        EM_CHARFROMPOS => char_from_pos(hwnd, (lparam & 0xFFFF) as i32, (lparam >> 16) as i32) as isize,
        _ => 0,
    }
}

// ============================================================================
// Focus Management
// ============================================================================

/// Set focus state
pub fn set_focus(hwnd: HWND, has_focus: bool) {
    let mut edits = EDIT_CONTROLS.lock();

    for edit in edits.iter_mut() {
        if edit.in_use && edit.hwnd == hwnd {
            edit.has_focus = has_focus;
            return;
        }
    }
}

/// Get focus state
pub fn has_focus(hwnd: HWND) -> bool {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            return edit.has_focus;
        }
    }

    false
}

// ============================================================================
// Drawing Support
// ============================================================================

/// Get display text (handles password masking)
pub fn get_display_text(hwnd: HWND, buffer: &mut [u8]) -> usize {
    let edits = EDIT_CONTROLS.lock();

    for edit in edits.iter() {
        if edit.in_use && edit.hwnd == hwnd {
            let len = edit.text_len.min(buffer.len());

            if edit.password_char != '\0' {
                // Return password characters
                for i in 0..len {
                    buffer[i] = edit.password_char as u8;
                }
            } else {
                buffer[..len].copy_from_slice(&edit.text[..len]);
            }

            return len;
        }
    }

    0
}

// ============================================================================
// Statistics
// ============================================================================

/// Edit control statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct EditStats {
    pub edit_count: usize,
    pub total_text_length: usize,
}

/// Get edit control statistics
pub fn get_stats() -> EditStats {
    let edits = EDIT_CONTROLS.lock();

    let mut edit_count = 0;
    let mut total_text_length = 0;

    for edit in edits.iter() {
        if edit.in_use {
            edit_count += 1;
            total_text_length += edit.text_len;
        }
    }

    EditStats {
        edit_count,
        total_text_length,
    }
}
