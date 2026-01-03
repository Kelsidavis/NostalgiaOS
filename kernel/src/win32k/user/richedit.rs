//! Rich Edit Control Implementation
//!
//! Windows Rich Edit for formatted text editing.
//! Based on Windows Server 2003 richedit.h.
//!
//! # Features
//!
//! - Character formatting (bold, italic, underline)
//! - Paragraph formatting (alignment, indentation)
//! - Multiple undo/redo
//! - Text selection
//! - Find/Replace
//!
//! # References
//!
//! - `public/sdk/inc/richedit.h` - Rich Edit structures and messages

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, Point, ColorRef};

// ============================================================================
// Rich Edit Styles (ES_*)
// ============================================================================

/// Auto horizontal scroll
pub const ES_AUTOHSCROLL: u32 = 0x0080;

/// Auto vertical scroll
pub const ES_AUTOVSCROLL: u32 = 0x0040;

/// Center text
pub const ES_CENTER: u32 = 0x0001;

/// Left align text
pub const ES_LEFT: u32 = 0x0000;

/// Multiline edit
pub const ES_MULTILINE: u32 = 0x0004;

/// No hide selection
pub const ES_NOHIDESEL: u32 = 0x0100;

/// Read only
pub const ES_READONLY: u32 = 0x0800;

/// Right align text
pub const ES_RIGHT: u32 = 0x0002;

/// Want return key
pub const ES_WANTRETURN: u32 = 0x1000;

/// Disable no scroll
pub const ES_DISABLENOSCROLL: u32 = 0x2000;

/// Save selection
pub const ES_SAVESEL: u32 = 0x8000;

/// Sunken border
pub const ES_SUNKEN: u32 = 0x4000;

/// Selection bar
pub const ES_SELECTIONBAR: u32 = 0x01000000;

// ============================================================================
// Rich Edit Messages (EM_*)
// ============================================================================

/// First Rich Edit message
pub const EM_FIRST: u32 = 0x0400;

/// Get selection
pub const EM_GETSEL: u32 = 0x00B0;

/// Set selection
pub const EM_SETSEL: u32 = 0x00B1;

/// Get scroll position
pub const EM_GETSCROLLPOS: u32 = EM_FIRST + 221;

/// Set scroll position
pub const EM_SETSCROLLPOS: u32 = EM_FIRST + 222;

/// Get text length
pub const EM_GETTEXTLENGTHEX: u32 = EM_FIRST + 95;

/// Get text range
pub const EM_GETTEXTRANGE: u32 = EM_FIRST + 75;

/// Can undo
pub const EM_CANUNDO: u32 = 0x00C6;

/// Undo
pub const EM_UNDO: u32 = 0x00C7;

/// Can redo
pub const EM_CANREDO: u32 = EM_FIRST + 85;

/// Redo
pub const EM_REDO: u32 = EM_FIRST + 84;

/// Set undo limit
pub const EM_SETUNDOLIMIT: u32 = EM_FIRST + 82;

/// Get char format
pub const EM_GETCHARFORMAT: u32 = EM_FIRST + 58;

/// Set char format
pub const EM_SETCHARFORMAT: u32 = EM_FIRST + 68;

/// Get paragraph format
pub const EM_GETPARAFORMAT: u32 = EM_FIRST + 61;

/// Set paragraph format
pub const EM_SETPARAFORMAT: u32 = EM_FIRST + 71;

/// Set background color
pub const EM_SETBKGNDCOLOR: u32 = EM_FIRST + 67;

/// Get modify flag
pub const EM_GETMODIFY: u32 = 0x00B8;

/// Set modify flag
pub const EM_SETMODIFY: u32 = 0x00B9;

/// Get text mode
pub const EM_GETTEXTMODE: u32 = EM_FIRST + 90;

/// Set text mode
pub const EM_SETTEXTMODE: u32 = EM_FIRST + 89;

/// Find text
pub const EM_FINDTEXT: u32 = EM_FIRST + 56;

/// Find text extended
pub const EM_FINDTEXTEX: u32 = EM_FIRST + 79;

/// Replace selection
pub const EM_REPLACESEL: u32 = 0x00C2;

/// Stream in
pub const EM_STREAMIN: u32 = EM_FIRST + 73;

/// Stream out
pub const EM_STREAMOUT: u32 = EM_FIRST + 74;

/// Get event mask
pub const EM_GETEVENTMASK: u32 = EM_FIRST + 59;

/// Set event mask
pub const EM_SETEVENTMASK: u32 = EM_FIRST + 69;

/// Request resize
pub const EM_REQUESTRESIZE: u32 = EM_FIRST + 65;

/// Get selection type
pub const EM_SELECTIONTYPE: u32 = EM_FIRST + 66;

/// Get line count
pub const EM_GETLINECOUNT: u32 = 0x00BA;

/// Scroll caret
pub const EM_SCROLLCARET: u32 = 0x00B7;

/// Limit text
pub const EM_LIMITTEXT: u32 = 0x00C5;

/// Set readonly
pub const EM_SETREADONLY: u32 = 0x00CF;

// ============================================================================
// Character Format Flags (CFM_* / CFE_*)
// ============================================================================

/// Bold mask
pub const CFM_BOLD: u32 = 0x00000001;

/// Italic mask
pub const CFM_ITALIC: u32 = 0x00000002;

/// Underline mask
pub const CFM_UNDERLINE: u32 = 0x00000004;

/// Strikeout mask
pub const CFM_STRIKEOUT: u32 = 0x00000008;

/// Protected mask
pub const CFM_PROTECTED: u32 = 0x00000010;

/// Link mask
pub const CFM_LINK: u32 = 0x00000020;

/// Size mask
pub const CFM_SIZE: u32 = 0x80000000;

/// Color mask
pub const CFM_COLOR: u32 = 0x40000000;

/// Face name mask
pub const CFM_FACE: u32 = 0x20000000;

/// Offset mask
pub const CFM_OFFSET: u32 = 0x10000000;

/// Charset mask
pub const CFM_CHARSET: u32 = 0x08000000;

/// Bold effect
pub const CFE_BOLD: u32 = CFM_BOLD;

/// Italic effect
pub const CFE_ITALIC: u32 = CFM_ITALIC;

/// Underline effect
pub const CFE_UNDERLINE: u32 = CFM_UNDERLINE;

/// Strikeout effect
pub const CFE_STRIKEOUT: u32 = CFM_STRIKEOUT;

/// Protected effect
pub const CFE_PROTECTED: u32 = CFM_PROTECTED;

/// Link effect
pub const CFE_LINK: u32 = CFM_LINK;

/// Auto color
pub const CFE_AUTOCOLOR: u32 = 0x40000000;

// ============================================================================
// Paragraph Format Flags (PFM_* / PFE_*)
// ============================================================================

/// Start indent mask
pub const PFM_STARTINDENT: u32 = 0x00000001;

/// Right indent mask
pub const PFM_RIGHTINDENT: u32 = 0x00000002;

/// Offset mask
pub const PFM_OFFSET: u32 = 0x00000004;

/// Alignment mask
pub const PFM_ALIGNMENT: u32 = 0x00000008;

/// Tab stops mask
pub const PFM_TABSTOPS: u32 = 0x00000010;

/// Numbering mask
pub const PFM_NUMBERING: u32 = 0x00000020;

/// Space before mask
pub const PFM_SPACEBEFORE: u32 = 0x00000040;

/// Space after mask
pub const PFM_SPACEAFTER: u32 = 0x00000080;

/// Line spacing mask
pub const PFM_LINESPACING: u32 = 0x00000100;

// Alignment values
/// Left alignment
pub const PFA_LEFT: u16 = 1;

/// Right alignment
pub const PFA_RIGHT: u16 = 2;

/// Center alignment
pub const PFA_CENTER: u16 = 3;

/// Justify alignment
pub const PFA_JUSTIFY: u16 = 4;

// ============================================================================
// Selection Types (SEL_*)
// ============================================================================

/// Empty selection
pub const SEL_EMPTY: u32 = 0x0000;

/// Text selected
pub const SEL_TEXT: u32 = 0x0001;

/// Object selected
pub const SEL_OBJECT: u32 = 0x0002;

/// Multiple chars selected
pub const SEL_MULTICHAR: u32 = 0x0004;

/// Multiple objects selected
pub const SEL_MULTIOBJECT: u32 = 0x0008;

// ============================================================================
// Event Masks (ENM_*)
// ============================================================================

/// No events
pub const ENM_NONE: u32 = 0x00000000;

/// Change events
pub const ENM_CHANGE: u32 = 0x00000001;

/// Update events
pub const ENM_UPDATE: u32 = 0x00000002;

/// Scroll events
pub const ENM_SCROLL: u32 = 0x00000004;

/// Key events
pub const ENM_KEYEVENTS: u32 = 0x00010000;

/// Mouse events
pub const ENM_MOUSEEVENTS: u32 = 0x00020000;

/// Request resize
pub const ENM_REQUESTRESIZE: u32 = 0x00040000;

/// Selection change
pub const ENM_SELCHANGE: u32 = 0x00080000;

/// Protected text
pub const ENM_PROTECTED: u32 = 0x00200000;

/// Link
pub const ENM_LINK: u32 = 0x04000000;

// ============================================================================
// Constants
// ============================================================================

/// Maximum rich edit controls
pub const MAX_RICH_EDITS: usize = 32;

/// Maximum text length
pub const MAX_TEXT_LENGTH: usize = 65536;

/// Maximum undo stack
pub const MAX_UNDO_STACK: usize = 100;

/// Maximum face name length
pub const MAX_FACE_NAME: usize = 32;

// ============================================================================
// Character Format Structure
// ============================================================================

/// Character format
#[derive(Clone, Copy)]
pub struct CharFormat {
    /// Mask of valid fields
    pub mask: u32,
    /// Effects
    pub effects: u32,
    /// Height in twips
    pub height: i32,
    /// Character offset
    pub offset: i32,
    /// Text color
    pub text_color: ColorRef,
    /// Character set
    pub charset: u8,
    /// Pitch and family
    pub pitch_family: u8,
    /// Face name
    pub face_name: [u8; MAX_FACE_NAME],
    pub face_name_len: usize,
}

impl CharFormat {
    /// Create default char format
    pub const fn new() -> Self {
        Self {
            mask: 0,
            effects: 0,
            height: 200, // 10pt in twips
            offset: 0,
            text_color: ColorRef(0),
            charset: 0,
            pitch_family: 0,
            face_name: [0u8; MAX_FACE_NAME],
            face_name_len: 0,
        }
    }

    /// Set face name
    pub fn set_face_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_FACE_NAME - 1);
        self.face_name[..len].copy_from_slice(&bytes[..len]);
        self.face_name_len = len;
        self.mask |= CFM_FACE;
    }

    /// Check if bold
    pub fn is_bold(&self) -> bool {
        (self.effects & CFE_BOLD) != 0
    }

    /// Check if italic
    pub fn is_italic(&self) -> bool {
        (self.effects & CFE_ITALIC) != 0
    }

    /// Check if underlined
    pub fn is_underlined(&self) -> bool {
        (self.effects & CFE_UNDERLINE) != 0
    }
}

// ============================================================================
// Paragraph Format Structure
// ============================================================================

/// Paragraph format
#[derive(Clone, Copy)]
pub struct ParaFormat {
    /// Mask of valid fields
    pub mask: u32,
    /// Numbering style
    pub numbering: u16,
    /// Alignment
    pub alignment: u16,
    /// Starting indent
    pub start_indent: i32,
    /// Right indent
    pub right_indent: i32,
    /// Hanging indent offset
    pub offset: i32,
    /// Tab stops count
    pub tab_count: u16,
    /// Tab stops
    pub tab_stops: [i32; 32],
    /// Space before paragraph
    pub space_before: i32,
    /// Space after paragraph
    pub space_after: i32,
    /// Line spacing
    pub line_spacing: i32,
}

impl ParaFormat {
    /// Create default paragraph format
    pub const fn new() -> Self {
        Self {
            mask: 0,
            numbering: 0,
            alignment: PFA_LEFT,
            start_indent: 0,
            right_indent: 0,
            offset: 0,
            tab_count: 0,
            tab_stops: [0i32; 32],
            space_before: 0,
            space_after: 0,
            line_spacing: 0,
        }
    }
}

// ============================================================================
// Undo Entry
// ============================================================================

/// Undo operation type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UndoType {
    #[default]
    None = 0,
    Insert = 1,
    Delete = 2,
    Replace = 3,
    Format = 4,
}

/// Undo entry
#[derive(Clone)]
pub struct UndoEntry {
    /// Operation type
    pub op_type: UndoType,
    /// Start position
    pub start: usize,
    /// End position
    pub end: usize,
    /// Old text (for delete/replace)
    pub old_text: [u8; 256],
    pub old_len: usize,
    /// New text (for insert/replace)
    pub new_text: [u8; 256],
    pub new_len: usize,
}

impl UndoEntry {
    /// Create empty undo entry
    pub const fn new() -> Self {
        Self {
            op_type: UndoType::None,
            start: 0,
            end: 0,
            old_text: [0u8; 256],
            old_len: 0,
            new_text: [0u8; 256],
            new_len: 0,
        }
    }
}

// ============================================================================
// Rich Edit Control State
// ============================================================================

/// Rich edit control state
#[derive(Clone)]
pub struct RichEditControl {
    /// Is this slot in use
    pub in_use: bool,
    /// Control handle
    pub hwnd: HWND,
    /// Parent handle
    pub parent: HWND,
    /// Control style
    pub style: u32,
    /// Text buffer
    pub text: [u8; MAX_TEXT_LENGTH],
    pub text_len: usize,
    /// Selection start
    pub sel_start: usize,
    /// Selection end
    pub sel_end: usize,
    /// Default char format
    pub default_char_format: CharFormat,
    /// Default para format
    pub default_para_format: ParaFormat,
    /// Event mask
    pub event_mask: u32,
    /// Background color
    pub bk_color: ColorRef,
    /// Modified flag
    pub modified: bool,
    /// Read only flag
    pub readonly: bool,
    /// Undo stack
    pub undo_stack: [UndoEntry; MAX_UNDO_STACK],
    pub undo_pos: usize,
    pub undo_count: usize,
    /// Redo available
    pub redo_count: usize,
    /// Maximum undo
    pub undo_limit: usize,
    /// Maximum text length
    pub text_limit: usize,
    /// Line count
    pub line_count: usize,
    /// Scroll position
    pub scroll_pos: Point,
}

impl RichEditControl {
    /// Create new rich edit control
    pub const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: UserHandle::NULL,
            parent: UserHandle::NULL,
            style: 0,
            text: [0u8; MAX_TEXT_LENGTH],
            text_len: 0,
            sel_start: 0,
            sel_end: 0,
            default_char_format: CharFormat::new(),
            default_para_format: ParaFormat::new(),
            event_mask: ENM_NONE,
            bk_color: ColorRef(0xFFFFFF), // White
            modified: false,
            readonly: false,
            undo_stack: [const { UndoEntry::new() }; MAX_UNDO_STACK],
            undo_pos: 0,
            undo_count: 0,
            redo_count: 0,
            undo_limit: MAX_UNDO_STACK,
            text_limit: MAX_TEXT_LENGTH,
            line_count: 1,
            scroll_pos: Point { x: 0, y: 0 },
        }
    }

    /// Reset control
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Get text
    pub fn get_text(&self) -> &[u8] {
        &self.text[..self.text_len]
    }

    /// Set text
    pub fn set_text(&mut self, text: &str) {
        let bytes = text.as_bytes();
        let len = bytes.len().min(self.text_limit);
        self.text[..len].copy_from_slice(&bytes[..len]);
        self.text_len = len;
        self.sel_start = 0;
        self.sel_end = 0;
        self.update_line_count();
        self.modified = true;
    }

    /// Get selection
    pub fn get_sel(&self) -> (usize, usize) {
        (self.sel_start, self.sel_end)
    }

    /// Set selection
    pub fn set_sel(&mut self, start: usize, end: usize) {
        self.sel_start = start.min(self.text_len);
        self.sel_end = end.min(self.text_len);
    }

    /// Get selected text
    pub fn get_selected_text(&self) -> &[u8] {
        let start = self.sel_start.min(self.sel_end);
        let end = self.sel_start.max(self.sel_end);
        &self.text[start..end]
    }

    /// Insert text at current position
    pub fn insert_text(&mut self, text: &str) -> bool {
        if self.readonly {
            return false;
        }

        let bytes = text.as_bytes();
        let insert_len = bytes.len();

        if self.text_len + insert_len > self.text_limit {
            return false;
        }

        let pos = self.sel_start.min(self.sel_end);

        // Push undo entry
        self.push_undo(UndoType::Insert, pos, pos + insert_len, &[], bytes);

        // Make room for new text
        for i in (pos..self.text_len).rev() {
            self.text[i + insert_len] = self.text[i];
        }

        // Insert new text
        self.text[pos..pos + insert_len].copy_from_slice(bytes);
        self.text_len += insert_len;

        // Update cursor
        self.sel_start = pos + insert_len;
        self.sel_end = self.sel_start;

        self.update_line_count();
        self.modified = true;

        true
    }

    /// Delete selected text
    pub fn delete_selection(&mut self) -> bool {
        if self.readonly {
            return false;
        }

        let start = self.sel_start.min(self.sel_end);
        let end = self.sel_start.max(self.sel_end);

        if start == end {
            return false;
        }

        // Copy text for undo before modifying
        let mut old_text = [0u8; 256];
        let old_len = (end - start).min(256);
        old_text[..old_len].copy_from_slice(&self.text[start..start + old_len]);

        // Push undo entry
        self.push_undo(UndoType::Delete, start, end, &old_text[..old_len], &[]);

        // Remove text
        let delete_len = end - start;
        for i in end..self.text_len {
            self.text[i - delete_len] = self.text[i];
        }
        self.text_len -= delete_len;

        // Update cursor
        self.sel_start = start;
        self.sel_end = start;

        self.update_line_count();
        self.modified = true;

        true
    }

    /// Replace selection with text
    pub fn replace_selection(&mut self, text: &str) -> bool {
        if self.readonly {
            return false;
        }

        let start = self.sel_start.min(self.sel_end);
        let end = self.sel_start.max(self.sel_end);
        let bytes = text.as_bytes();

        // Copy text for undo before modifying
        let mut old_text = [0u8; 256];
        let old_len = (end - start).min(256);
        old_text[..old_len].copy_from_slice(&self.text[start..start + old_len]);

        // Push undo entry
        self.push_undo(UndoType::Replace, start, end, &old_text[..old_len], bytes);

        // Delete old selection
        let delete_len = end - start;
        for i in end..self.text_len {
            self.text[i - delete_len] = self.text[i];
        }
        self.text_len -= delete_len;

        // Check if new text fits
        if self.text_len + bytes.len() > self.text_limit {
            return false;
        }

        // Make room for new text
        for i in (start..self.text_len).rev() {
            self.text[i + bytes.len()] = self.text[i];
        }

        // Insert new text
        self.text[start..start + bytes.len()].copy_from_slice(bytes);
        self.text_len += bytes.len();

        // Update cursor
        self.sel_start = start + bytes.len();
        self.sel_end = self.sel_start;

        self.update_line_count();
        self.modified = true;

        true
    }

    /// Update line count
    fn update_line_count(&mut self) {
        self.line_count = 1;
        for &b in &self.text[..self.text_len] {
            if b == b'\n' {
                self.line_count += 1;
            }
        }
    }

    /// Push undo entry
    fn push_undo(&mut self, op_type: UndoType, start: usize, end: usize, old: &[u8], new: &[u8]) {
        if self.undo_limit == 0 {
            return;
        }

        // Clear redo stack
        self.redo_count = 0;

        let entry = &mut self.undo_stack[self.undo_pos % self.undo_limit];
        entry.op_type = op_type;
        entry.start = start;
        entry.end = end;
        entry.old_len = old.len().min(256);
        entry.old_text[..entry.old_len].copy_from_slice(&old[..entry.old_len]);
        entry.new_len = new.len().min(256);
        entry.new_text[..entry.new_len].copy_from_slice(&new[..entry.new_len]);

        self.undo_pos += 1;
        if self.undo_count < self.undo_limit {
            self.undo_count += 1;
        }
    }

    /// Can undo
    pub fn can_undo(&self) -> bool {
        self.undo_count > 0
    }

    /// Can redo
    pub fn can_redo(&self) -> bool {
        self.redo_count > 0
    }

    /// Undo
    pub fn undo(&mut self) -> bool {
        if !self.can_undo() {
            return false;
        }

        self.undo_pos -= 1;
        self.undo_count -= 1;
        let entry = &self.undo_stack[self.undo_pos % self.undo_limit];

        // Reverse the operation
        match entry.op_type {
            UndoType::Insert => {
                // Delete the inserted text
                let len = entry.new_len;
                for i in entry.start + len..self.text_len {
                    self.text[i - len] = self.text[i];
                }
                self.text_len -= len;
            }
            UndoType::Delete => {
                // Re-insert the deleted text
                let old_text = entry.old_text;
                let len = entry.old_len;
                for i in (entry.start..self.text_len).rev() {
                    self.text[i + len] = self.text[i];
                }
                self.text[entry.start..entry.start + len].copy_from_slice(&old_text[..len]);
                self.text_len += len;
            }
            UndoType::Replace => {
                // Delete new text, insert old text
                let new_len = entry.new_len;
                let old_len = entry.old_len;
                let old_text = entry.old_text;

                // Remove new text
                for i in entry.start + new_len..self.text_len {
                    self.text[i - new_len] = self.text[i];
                }
                self.text_len -= new_len;

                // Insert old text
                for i in (entry.start..self.text_len).rev() {
                    self.text[i + old_len] = self.text[i];
                }
                self.text[entry.start..entry.start + old_len].copy_from_slice(&old_text[..old_len]);
                self.text_len += old_len;
            }
            _ => return false,
        }

        self.redo_count += 1;
        self.update_line_count();
        true
    }

    /// Redo
    pub fn redo(&mut self) -> bool {
        if !self.can_redo() {
            return false;
        }

        let entry = &self.undo_stack[self.undo_pos % self.undo_limit];

        // Re-apply the operation
        match entry.op_type {
            UndoType::Insert => {
                let new_text = entry.new_text;
                let len = entry.new_len;
                for i in (entry.start..self.text_len).rev() {
                    self.text[i + len] = self.text[i];
                }
                self.text[entry.start..entry.start + len].copy_from_slice(&new_text[..len]);
                self.text_len += len;
            }
            UndoType::Delete => {
                let len = entry.end - entry.start;
                for i in entry.end..self.text_len {
                    self.text[i - len] = self.text[i];
                }
                self.text_len -= len;
            }
            UndoType::Replace => {
                let old_len = entry.old_len;
                let new_len = entry.new_len;
                let new_text = entry.new_text;

                // Remove old text
                for i in entry.start + old_len..self.text_len {
                    self.text[i - old_len] = self.text[i];
                }
                self.text_len -= old_len;

                // Insert new text
                for i in (entry.start..self.text_len).rev() {
                    self.text[i + new_len] = self.text[i];
                }
                self.text[entry.start..entry.start + new_len].copy_from_slice(&new_text[..new_len]);
                self.text_len += new_len;
            }
            _ => return false,
        }

        self.undo_pos += 1;
        self.undo_count += 1;
        self.redo_count -= 1;
        self.update_line_count();
        true
    }

    /// Find text
    pub fn find_text(&self, needle: &str, start_from: usize) -> Option<usize> {
        let needle_bytes = needle.as_bytes();
        if needle_bytes.is_empty() || start_from >= self.text_len {
            return None;
        }

        let text = &self.text[start_from..self.text_len];
        for i in 0..text.len().saturating_sub(needle_bytes.len() - 1) {
            if &text[i..i + needle_bytes.len()] == needle_bytes {
                return Some(start_from + i);
            }
        }

        None
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global rich edit storage
static RICH_EDITS: SpinLock<[RichEditControl; MAX_RICH_EDITS]> =
    SpinLock::new([const { RichEditControl::new() }; MAX_RICH_EDITS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize RichEdit subsystem
pub fn init() {
    crate::serial_println!("[USER] RichEdit initialized");
}

/// Create a rich edit control
pub fn create(hwnd: HWND, parent: HWND, style: u32) -> usize {
    let mut controls = RICH_EDITS.lock();

    for (i, ctrl) in controls.iter_mut().enumerate() {
        if !ctrl.in_use {
            ctrl.reset();
            ctrl.in_use = true;
            ctrl.hwnd = hwnd;
            ctrl.parent = parent;
            ctrl.style = style;
            ctrl.readonly = (style & ES_READONLY) != 0;
            return i + 1;
        }
    }

    0
}

/// Destroy a rich edit control
pub fn destroy(ctrl_idx: usize) -> bool {
    if ctrl_idx == 0 {
        return false;
    }

    let mut controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS {
        return false;
    }

    if controls[idx].in_use {
        controls[idx].reset();
        true
    } else {
        false
    }
}

/// Set text
pub fn set_text(ctrl_idx: usize, text: &str) -> bool {
    if ctrl_idx == 0 {
        return false;
    }

    let mut controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return false;
    }

    controls[idx].set_text(text);
    true
}

/// Get text length
pub fn get_text_length(ctrl_idx: usize) -> usize {
    if ctrl_idx == 0 {
        return 0;
    }

    let controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return 0;
    }

    controls[idx].text_len
}

/// Get selection
pub fn get_sel(ctrl_idx: usize) -> (usize, usize) {
    if ctrl_idx == 0 {
        return (0, 0);
    }

    let controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return (0, 0);
    }

    controls[idx].get_sel()
}

/// Set selection
pub fn set_sel(ctrl_idx: usize, start: usize, end: usize) {
    if ctrl_idx == 0 {
        return;
    }

    let mut controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return;
    }

    controls[idx].set_sel(start, end);
}

/// Replace selection
pub fn replace_sel(ctrl_idx: usize, text: &str) -> bool {
    if ctrl_idx == 0 {
        return false;
    }

    let mut controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return false;
    }

    controls[idx].replace_selection(text)
}

/// Can undo
pub fn can_undo(ctrl_idx: usize) -> bool {
    if ctrl_idx == 0 {
        return false;
    }

    let controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return false;
    }

    controls[idx].can_undo()
}

/// Undo
pub fn undo(ctrl_idx: usize) -> bool {
    if ctrl_idx == 0 {
        return false;
    }

    let mut controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return false;
    }

    controls[idx].undo()
}

/// Can redo
pub fn can_redo(ctrl_idx: usize) -> bool {
    if ctrl_idx == 0 {
        return false;
    }

    let controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return false;
    }

    controls[idx].can_redo()
}

/// Redo
pub fn redo(ctrl_idx: usize) -> bool {
    if ctrl_idx == 0 {
        return false;
    }

    let mut controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return false;
    }

    controls[idx].redo()
}

/// Set undo limit
pub fn set_undo_limit(ctrl_idx: usize, limit: usize) {
    if ctrl_idx == 0 {
        return;
    }

    let mut controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return;
    }

    controls[idx].undo_limit = limit.min(MAX_UNDO_STACK);
}

/// Get line count
pub fn get_line_count(ctrl_idx: usize) -> usize {
    if ctrl_idx == 0 {
        return 0;
    }

    let controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return 0;
    }

    controls[idx].line_count
}

/// Set background color
pub fn set_bk_color(ctrl_idx: usize, color: ColorRef) -> ColorRef {
    if ctrl_idx == 0 {
        return ColorRef(0);
    }

    let mut controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return ColorRef(0);
    }

    let old = controls[idx].bk_color;
    controls[idx].bk_color = color;
    old
}

/// Get/set event mask
pub fn set_event_mask(ctrl_idx: usize, mask: u32) -> u32 {
    if ctrl_idx == 0 {
        return 0;
    }

    let mut controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return 0;
    }

    let old = controls[idx].event_mask;
    controls[idx].event_mask = mask;
    old
}

/// Find text
pub fn find_text(ctrl_idx: usize, needle: &str, start: usize) -> i32 {
    if ctrl_idx == 0 {
        return -1;
    }

    let controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return -1;
    }

    match controls[idx].find_text(needle, start) {
        Some(pos) => pos as i32,
        None => -1,
    }
}

/// Set readonly
pub fn set_readonly(ctrl_idx: usize, readonly: bool) -> bool {
    if ctrl_idx == 0 {
        return false;
    }

    let mut controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return false;
    }

    controls[idx].readonly = readonly;
    true
}

/// Get modify flag
pub fn get_modify(ctrl_idx: usize) -> bool {
    if ctrl_idx == 0 {
        return false;
    }

    let controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return false;
    }

    controls[idx].modified
}

/// Set modify flag
pub fn set_modify(ctrl_idx: usize, modified: bool) {
    if ctrl_idx == 0 {
        return;
    }

    let mut controls = RICH_EDITS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_RICH_EDITS || !controls[idx].in_use {
        return;
    }

    controls[idx].modified = modified;
}

/// Get statistics
pub fn get_stats() -> RichEditStats {
    let controls = RICH_EDITS.lock();

    let mut active_count = 0;
    let mut total_chars = 0;

    for ctrl in controls.iter() {
        if ctrl.in_use {
            active_count += 1;
            total_chars += ctrl.text_len;
        }
    }

    RichEditStats {
        max_controls: MAX_RICH_EDITS,
        active_controls: active_count,
        total_characters: total_chars,
    }
}

/// RichEdit statistics
#[derive(Debug, Clone, Copy)]
pub struct RichEditStats {
    pub max_controls: usize,
    pub active_controls: usize,
    pub total_characters: usize,
}
