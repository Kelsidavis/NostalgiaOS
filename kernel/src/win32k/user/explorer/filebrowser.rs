//! File Browser View
//!
//! Implements the main file/folder browsing view for Explorer windows.
//! This is equivalent to the DefView (CDefView) in Windows shell32.
//!
//! # Features
//!
//! - Directory listing with icons
//! - Multiple view modes (Icons, List, Details)
//! - Toolbar with navigation buttons
//! - Address bar with path display
//! - Status bar with file count
//! - Keyboard and mouse navigation
//! - File selection and multi-select
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/shell32/defview.cpp` - CDefView implementation
//! - `shell/shell32/lvutil.cpp` - ListView utilities

use crate::ke::spinlock::SpinLock;
use crate::io::{vfs, VfsEntry, VfsIconType};
use super::super::super::{HWND, HDC, Rect, Point, ColorRef};
use super::super::super::gdi::{self, dc, dc::BkMode, surface};
use super::super::{window, WindowStyle, WindowStyleEx};

// ============================================================================
// Constants
// ============================================================================

/// Maximum files to display per folder
pub const MAX_FILES: usize = 256;

/// Maximum path length
pub const MAX_PATH: usize = 260;

/// Maximum browser windows
pub const MAX_BROWSERS: usize = 16;

/// Selection bits (256 items / 32 bits per u32 = 8 u32s)
pub const SELECTION_WORDS: usize = 8;

/// Toolbar height
pub const TOOLBAR_HEIGHT: i32 = 28;

/// Address bar height
pub const ADDRESS_BAR_HEIGHT: i32 = 22;

/// Status bar height
pub const STATUS_BAR_HEIGHT: i32 = 20;

/// Header height for columns in details view
pub const HEADER_HEIGHT: i32 = 20;

/// Icon size for small icons
pub const SMALL_ICON_SIZE: i32 = 16;

/// Icon size for large icons
pub const LARGE_ICON_SIZE: i32 = 32;

/// List item height
pub const LIST_ITEM_HEIGHT: i32 = 18;

/// Details view row height
pub const DETAILS_ROW_HEIGHT: i32 = 18;

/// Icon view grid size
pub const ICON_GRID_WIDTH: i32 = 80;
pub const ICON_GRID_HEIGHT: i32 = 64;

/// Thumbnail view grid size (larger for previews)
pub const THUMBNAIL_GRID_WIDTH: i32 = 120;
pub const THUMBNAIL_GRID_HEIGHT: i32 = 100;
pub const THUMBNAIL_SIZE: i32 = 64;

/// Small icon grid size
pub const SMALL_ICON_GRID_WIDTH: i32 = 60;
pub const SMALL_ICON_GRID_HEIGHT: i32 = 24;

/// Tile view grid size
pub const TILE_WIDTH: i32 = 200;
pub const TILE_HEIGHT: i32 = 48;

/// Toolbar button size
pub const TOOLBAR_BTN_SIZE: i32 = 24;

/// Details panel width (when visible)
pub const DETAILS_PANEL_WIDTH: i32 = 180;

/// Colors
pub const COLOR_TOOLBAR_BG: ColorRef = ColorRef::rgb(236, 233, 216);
pub const COLOR_ADDRESS_BG: ColorRef = ColorRef::rgb(255, 255, 255);
pub const COLOR_STATUS_BG: ColorRef = ColorRef::rgb(236, 233, 216);
pub const COLOR_LIST_BG: ColorRef = ColorRef::rgb(255, 255, 255);
pub const COLOR_HEADER_BG: ColorRef = ColorRef::rgb(236, 233, 216);
pub const COLOR_SELECTED: ColorRef = ColorRef::rgb(49, 106, 197);
pub const COLOR_SELECTED_TEXT: ColorRef = ColorRef::rgb(255, 255, 255);

// ============================================================================
// View Modes
// ============================================================================

/// View mode for file display
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ViewMode {
    /// Large icons in a grid
    LargeIcons,
    /// Small icons in a grid
    SmallIcons,
    /// List view (single column with small icons)
    List,
    /// Details view (columns: Name, Size, Type, Modified)
    Details,
    /// Tiles view (large icons with details)
    Tiles,
    /// Thumbnails view (extra large icons with previews)
    Thumbnails,
}

impl Default for ViewMode {
    fn default() -> Self {
        ViewMode::Details
    }
}

// ============================================================================
// Sort Column
// ============================================================================

/// Column to sort by
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SortColumn {
    Name,
    Size,
    Type,
    Modified,
}

impl Default for SortColumn {
    fn default() -> Self {
        SortColumn::Name
    }
}

// ============================================================================
// Grouping
// ============================================================================

/// Grouping mode for file list
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GroupBy {
    /// No grouping
    None,
    /// Group by file type (folders, documents, images, etc.)
    Type,
    /// Group by modification date (Today, Yesterday, This Week, etc.)
    Date,
    /// Group by first letter of name
    Name,
}

impl Default for GroupBy {
    fn default() -> Self {
        GroupBy::None
    }
}

/// Group header height
pub const GROUP_HEADER_HEIGHT: i32 = 24;

/// Group info for display
#[derive(Clone, Copy)]
pub struct GroupInfo {
    /// Group label
    pub label: [u8; 32],
    pub label_len: usize,
    /// First item index in this group
    pub first_index: usize,
    /// Number of items in this group
    pub item_count: usize,
    /// Is group expanded
    pub expanded: bool,
}

impl GroupInfo {
    pub const fn empty() -> Self {
        Self {
            label: [0; 32],
            label_len: 0,
            first_index: 0,
            item_count: 0,
            expanded: true,
        }
    }

    pub fn new(label: &[u8], first_index: usize) -> Self {
        let mut info = Self::empty();
        info.first_index = first_index;
        let len = label.len().min(31);
        info.label[..len].copy_from_slice(&label[..len]);
        info.label_len = len;
        info
    }

    pub fn label_str(&self) -> &str {
        core::str::from_utf8(&self.label[..self.label_len]).unwrap_or("")
    }
}

/// Maximum number of groups
pub const MAX_GROUPS: usize = 32;

// ============================================================================
// Clipboard Operations
// ============================================================================

/// Clipboard operation type
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClipboardOp {
    None,
    Copy,
    Cut,
}

// ============================================================================
// Undo/Redo Operations
// ============================================================================

/// Maximum undo history size
pub const UNDO_HISTORY_SIZE: usize = 32;

/// Type of undoable operation
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UndoOpType {
    None,
    /// File or folder was deleted
    Delete,
    /// File or folder was renamed
    Rename,
    /// File or folder was moved
    Move,
    /// File or folder was created
    Create,
}

/// An undoable operation
#[derive(Clone, Copy)]
pub struct UndoOperation {
    /// Operation type
    pub op_type: UndoOpType,
    /// Original path (for delete/rename/move)
    pub original_path: [u8; MAX_PATH],
    pub original_path_len: usize,
    /// New path (for rename/move/create)
    pub new_path: [u8; MAX_PATH],
    pub new_path_len: usize,
    /// Was it a directory?
    pub is_directory: bool,
}

impl UndoOperation {
    pub const fn empty() -> Self {
        Self {
            op_type: UndoOpType::None,
            original_path: [0; MAX_PATH],
            original_path_len: 0,
            new_path: [0; MAX_PATH],
            new_path_len: 0,
            is_directory: false,
        }
    }

    pub fn new_delete(path: &str, is_dir: bool) -> Self {
        let mut op = Self::empty();
        op.op_type = UndoOpType::Delete;
        op.is_directory = is_dir;
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_PATH - 1);
        op.original_path[..len].copy_from_slice(&bytes[..len]);
        op.original_path_len = len;
        op
    }

    pub fn new_rename(old_path: &str, new_path: &str, is_dir: bool) -> Self {
        let mut op = Self::empty();
        op.op_type = UndoOpType::Rename;
        op.is_directory = is_dir;
        let old_bytes = old_path.as_bytes();
        let old_len = old_bytes.len().min(MAX_PATH - 1);
        op.original_path[..old_len].copy_from_slice(&old_bytes[..old_len]);
        op.original_path_len = old_len;
        let new_bytes = new_path.as_bytes();
        let new_len = new_bytes.len().min(MAX_PATH - 1);
        op.new_path[..new_len].copy_from_slice(&new_bytes[..new_len]);
        op.new_path_len = new_len;
        op
    }

    pub fn new_create(path: &str, is_dir: bool) -> Self {
        let mut op = Self::empty();
        op.op_type = UndoOpType::Create;
        op.is_directory = is_dir;
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_PATH - 1);
        op.new_path[..len].copy_from_slice(&bytes[..len]);
        op.new_path_len = len;
        op
    }
}

/// Undo/Redo history manager
pub struct UndoHistory {
    /// Undo stack
    undo_stack: [UndoOperation; UNDO_HISTORY_SIZE],
    undo_count: usize,
    /// Redo stack
    redo_stack: [UndoOperation; UNDO_HISTORY_SIZE],
    redo_count: usize,
}

impl UndoHistory {
    pub const fn new() -> Self {
        Self {
            undo_stack: [const { UndoOperation::empty() }; UNDO_HISTORY_SIZE],
            undo_count: 0,
            redo_stack: [const { UndoOperation::empty() }; UNDO_HISTORY_SIZE],
            redo_count: 0,
        }
    }

    /// Push an operation onto the undo stack
    pub fn push(&mut self, op: UndoOperation) {
        // Clear redo stack when new operation is performed
        self.redo_count = 0;

        // Add to undo stack
        if self.undo_count < UNDO_HISTORY_SIZE {
            self.undo_stack[self.undo_count] = op;
            self.undo_count += 1;
        } else {
            // Shift stack and add at end
            for i in 0..UNDO_HISTORY_SIZE - 1 {
                self.undo_stack[i] = self.undo_stack[i + 1];
            }
            self.undo_stack[UNDO_HISTORY_SIZE - 1] = op;
        }
    }

    /// Pop an operation from undo stack (returns None if empty)
    pub fn pop_undo(&mut self) -> Option<UndoOperation> {
        if self.undo_count > 0 {
            self.undo_count -= 1;
            let op = self.undo_stack[self.undo_count];
            // Push to redo stack
            if self.redo_count < UNDO_HISTORY_SIZE {
                self.redo_stack[self.redo_count] = op;
                self.redo_count += 1;
            }
            Some(op)
        } else {
            None
        }
    }

    /// Pop an operation from redo stack (returns None if empty)
    pub fn pop_redo(&mut self) -> Option<UndoOperation> {
        if self.redo_count > 0 {
            self.redo_count -= 1;
            let op = self.redo_stack[self.redo_count];
            // Push back to undo stack
            if self.undo_count < UNDO_HISTORY_SIZE {
                self.undo_stack[self.undo_count] = op;
                self.undo_count += 1;
            }
            Some(op)
        } else {
            None
        }
    }

    /// Check if undo is available
    pub fn can_undo(&self) -> bool {
        self.undo_count > 0
    }

    /// Check if redo is available
    pub fn can_redo(&self) -> bool {
        self.redo_count > 0
    }
}

/// Global undo history
static UNDO_HISTORY: crate::ke::spinlock::SpinLock<UndoHistory> =
    crate::ke::spinlock::SpinLock::new(UndoHistory::new());

/// Record an operation for undo
pub fn record_operation(op: UndoOperation) {
    UNDO_HISTORY.lock().push(op);
}

/// Undo the last operation
pub fn undo_last() -> bool {
    let op = UNDO_HISTORY.lock().pop_undo();
    if let Some(op) = op {
        match op.op_type {
            UndoOpType::Delete => {
                // Can't really undo delete without a recycle bin
                // For now, just log it
                crate::serial_println!("[UNDO] Cannot restore deleted item (no recycle bin)");
                false
            }
            UndoOpType::Rename => {
                // Rename back to original name
                let old_path = core::str::from_utf8(&op.new_path[..op.new_path_len]).unwrap_or("");
                let new_path = core::str::from_utf8(&op.original_path[..op.original_path_len]).unwrap_or("");
                crate::serial_println!("[UNDO] Renaming '{}' back to '{}'", old_path, new_path);
                // TODO: Actually perform the rename via VFS
                true
            }
            UndoOpType::Create => {
                // Delete the created item
                let path = core::str::from_utf8(&op.new_path[..op.new_path_len]).unwrap_or("");
                crate::serial_println!("[UNDO] Deleting created item '{}'", path);
                // TODO: Actually perform the delete via VFS
                true
            }
            _ => false,
        }
    } else {
        crate::serial_println!("[UNDO] Nothing to undo");
        false
    }
}

/// Redo the last undone operation
pub fn redo_last() -> bool {
    let op = UNDO_HISTORY.lock().pop_redo();
    if let Some(op) = op {
        match op.op_type {
            UndoOpType::Rename => {
                // Rename to new name again
                let old_path = core::str::from_utf8(&op.original_path[..op.original_path_len]).unwrap_or("");
                let new_path = core::str::from_utf8(&op.new_path[..op.new_path_len]).unwrap_or("");
                crate::serial_println!("[REDO] Renaming '{}' to '{}'", old_path, new_path);
                // TODO: Actually perform the rename via VFS
                true
            }
            UndoOpType::Create => {
                // Recreate the item
                let path = core::str::from_utf8(&op.new_path[..op.new_path_len]).unwrap_or("");
                crate::serial_println!("[REDO] Recreating '{}'", path);
                // TODO: Actually perform the create via VFS
                true
            }
            _ => false,
        }
    } else {
        crate::serial_println!("[REDO] Nothing to redo");
        false
    }
}

/// Check if undo is available
pub fn can_undo() -> bool {
    UNDO_HISTORY.lock().can_undo()
}

/// Check if redo is available
pub fn can_redo() -> bool {
    UNDO_HISTORY.lock().can_redo()
}

// ============================================================================
// Context Menu Commands
// ============================================================================

/// Context menu command IDs
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum MenuCommand {
    Open = 1,
    OpenWith = 2,
    Cut = 10,
    Copy = 11,
    Paste = 12,
    Delete = 20,
    Rename = 21,
    Properties = 30,
    NewFolder = 40,
    NewFile = 41,
    Refresh = 50,
    SelectAll = 51,
    ViewLargeIcons = 60,
    ViewSmallIcons = 61,
    ViewList = 62,
    ViewDetails = 63,
}

// ============================================================================
// File Item
// ============================================================================

/// A file/folder item in the browser
#[derive(Clone, Copy)]
pub struct FileItem {
    /// Item name
    pub name: [u8; 256],
    pub name_len: usize,
    /// Is this a directory?
    pub is_directory: bool,
    /// File size in bytes
    pub size: u64,
    /// Icon type
    pub icon_type: VfsIconType,
    /// Is selected?
    pub selected: bool,
}

impl FileItem {
    pub const fn empty() -> Self {
        Self {
            name: [0; 256],
            name_len: 0,
            is_directory: false,
            size: 0,
            icon_type: VfsIconType::File,
            selected: false,
        }
    }

    pub fn from_vfs_entry(entry: &VfsEntry) -> Self {
        let mut item = Self::empty();
        item.name_len = entry.name_len;
        item.name[..entry.name_len].copy_from_slice(&entry.name[..entry.name_len]);
        item.is_directory = entry.is_directory;
        item.size = entry.size;
        item.icon_type = entry.icon_type;
        item
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }

    pub fn get_type_name(&self) -> &'static str {
        if self.is_directory {
            return "File Folder";
        }
        match self.icon_type {
            VfsIconType::Executable => "Application",
            VfsIconType::Image => "Image",
            VfsIconType::Audio => "Audio File",
            VfsIconType::Video => "Video File",
            VfsIconType::Document => "Document",
            _ => "File",
        }
    }

    /// Format file size for display
    pub fn format_size(&self, buf: &mut [u8]) -> usize {
        if self.is_directory {
            return 0;
        }

        let size = self.size;
        if size < 1024 {
            return format_number(size, buf, " bytes");
        } else if size < 1024 * 1024 {
            return format_number(size / 1024, buf, " KB");
        } else if size < 1024 * 1024 * 1024 {
            return format_number(size / (1024 * 1024), buf, " MB");
        } else {
            return format_number(size / (1024 * 1024 * 1024), buf, " GB");
        }
    }
}

fn format_number(n: u64, buf: &mut [u8], suffix: &str) -> usize {
    let mut temp = [0u8; 32];
    let mut pos = 0;
    let mut num = n;

    if num == 0 {
        temp[pos] = b'0';
        pos += 1;
    } else {
        while num > 0 && pos < 20 {
            temp[pos] = b'0' + (num % 10) as u8;
            num /= 10;
            pos += 1;
        }
    }

    // Reverse digits
    let mut out_pos = 0;
    for i in (0..pos).rev() {
        if out_pos < buf.len() {
            buf[out_pos] = temp[i];
            out_pos += 1;
        }
    }

    // Add suffix
    for &b in suffix.as_bytes() {
        if out_pos < buf.len() {
            buf[out_pos] = b;
            out_pos += 1;
        }
    }

    out_pos
}

// ============================================================================
// File Browser State
// ============================================================================

/// File browser instance
pub struct FileBrowser {
    /// Associated window handle
    pub hwnd: HWND,
    /// Current path
    pub path: [u8; MAX_PATH],
    pub path_len: usize,
    /// Files in current directory
    pub items: [FileItem; MAX_FILES],
    pub item_count: usize,
    /// View mode
    pub view_mode: ViewMode,
    /// Sort column
    pub sort_column: SortColumn,
    /// Sort ascending
    pub sort_ascending: bool,
    /// Grouping mode
    pub group_by: GroupBy,
    /// Groups (computed from items)
    pub groups: [GroupInfo; MAX_GROUPS],
    pub group_count: usize,
    /// Scroll offset
    pub scroll_x: i32,
    pub scroll_y: i32,
    /// Selected items bitmap (256 bits = 8 x u32)
    pub selection: [u32; SELECTION_WORDS],
    /// Number of selected items
    pub selection_count: usize,
    /// Focus item for keyboard navigation
    pub focus_index: i32,
    /// Anchor index for shift-click range selection
    pub anchor_index: i32,
    /// Is active/in use
    pub active: bool,
    /// Navigation history
    pub history: [[u8; MAX_PATH]; 16],
    pub history_lens: [usize; 16],
    pub history_pos: usize,
    pub history_count: usize,
    /// Clipboard operation pending
    pub clipboard_op: ClipboardOp,
    /// Clipboard items (paths stored as indices from source folder)
    pub clipboard_items: [u32; SELECTION_WORDS],
    /// Clipboard source path
    pub clipboard_path: [u8; MAX_PATH],
    pub clipboard_path_len: usize,
    /// Context menu visible
    pub context_menu_visible: bool,
    /// Context menu position
    pub context_menu_x: i32,
    pub context_menu_y: i32,
    /// Rename mode active
    pub rename_mode: bool,
    /// Rename buffer
    pub rename_buffer: [u8; 256],
    pub rename_buffer_len: usize,
    /// Rename cursor position
    pub rename_cursor: usize,
    /// Column widths for details view (Name, Size, Type, Date)
    pub column_widths: [i32; 4],
    /// Drag operation state
    pub drag_state: DragState,
    /// Folder tree pane visible
    pub tree_visible: bool,
    /// Auto-arrange icons (automatically layout icons in grid)
    pub auto_arrange: bool,
    /// Snap icons to grid (align to nearest grid position)
    pub snap_to_grid: bool,
    /// Address bar dropdown visible
    pub address_dropdown_visible: bool,
    /// Search mode active
    pub search_active: bool,
    /// Search query buffer
    pub search_query: [u8; 64],
    pub search_query_len: usize,
    /// Search cursor position
    pub search_cursor: usize,
    /// Items that match the search filter (bitmask like selection)
    pub search_matches: [u32; SELECTION_WORDS],
    /// Number of matching items
    pub search_match_count: usize,
    /// Hover tooltip - item index being hovered (-1 = none)
    pub hover_index: i32,
    /// Hover position
    pub hover_x: i32,
    pub hover_y: i32,
    /// Hover timer tick count (for delay)
    pub hover_start_tick: u64,
    /// Tooltip visible
    pub tooltip_visible: bool,
    /// Details panel visible (left side info panel)
    pub details_panel_visible: bool,
}

/// Drag operation state
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DragState {
    /// No drag in progress
    None,
    /// Mouse button held, waiting for threshold
    Pending { start_x: i32, start_y: i32 },
    /// Actively dragging
    Active,
}

impl Default for DragState {
    fn default() -> Self {
        DragState::None
    }
}

/// Drag threshold in pixels (must move at least this far to start drag)
pub const DRAG_THRESHOLD: i32 = 5;

/// Default column widths
pub const DEFAULT_COLUMN_WIDTHS: [i32; 4] = [200, 80, 120, 120];

/// Minimum column width
pub const MIN_COLUMN_WIDTH: i32 = 40;

/// Resize hit zone width (pixels on each side of separator)
pub const RESIZE_HIT_ZONE: i32 = 4;

impl FileBrowser {
    pub const fn new() -> Self {
        Self {
            hwnd: HWND::NULL,
            path: [0; MAX_PATH],
            path_len: 0,
            items: [const { FileItem::empty() }; MAX_FILES],
            item_count: 0,
            view_mode: ViewMode::Details,
            sort_column: SortColumn::Name,
            sort_ascending: true,
            group_by: GroupBy::None,
            groups: [const { GroupInfo::empty() }; MAX_GROUPS],
            group_count: 0,
            scroll_x: 0,
            scroll_y: 0,
            selection: [0; SELECTION_WORDS],
            selection_count: 0,
            focus_index: 0,
            anchor_index: 0,
            active: false,
            history: [[0; MAX_PATH]; 16],
            history_lens: [0; 16],
            history_pos: 0,
            history_count: 0,
            clipboard_op: ClipboardOp::None,
            clipboard_items: [0; SELECTION_WORDS],
            clipboard_path: [0; MAX_PATH],
            clipboard_path_len: 0,
            context_menu_visible: false,
            context_menu_x: 0,
            context_menu_y: 0,
            rename_mode: false,
            rename_buffer: [0; 256],
            rename_buffer_len: 0,
            rename_cursor: 0,
            column_widths: DEFAULT_COLUMN_WIDTHS,
            drag_state: DragState::None,
            tree_visible: true,
            auto_arrange: true,
            snap_to_grid: true,
            address_dropdown_visible: false,
            search_active: false,
            search_query: [0; 64],
            search_query_len: 0,
            search_cursor: 0,
            search_matches: [0; SELECTION_WORDS],
            search_match_count: 0,
            hover_index: -1,
            hover_x: 0,
            hover_y: 0,
            hover_start_tick: 0,
            tooltip_visible: false,
            details_panel_visible: false,
        }
    }

    /// Toggle details panel visibility
    pub fn toggle_details_panel(&mut self) {
        self.details_panel_visible = !self.details_panel_visible;
    }

    // ========================================================================
    // Address Bar History
    // ========================================================================

    /// Get navigation history entries for dropdown
    pub fn get_history_entries(&self) -> ([([u8; MAX_PATH], usize); 16], usize) {
        let mut entries = [([0u8; MAX_PATH], 0); 16];
        let mut count = 0;

        // Copy history entries (most recent first)
        for i in 0..self.history_count {
            if count >= 16 {
                break;
            }
            let idx = if self.history_pos >= i {
                self.history_pos - i
            } else {
                self.history_count - (i - self.history_pos)
            };

            if idx < self.history_count {
                entries[count].0[..self.history_lens[idx]].copy_from_slice(&self.history[idx][..self.history_lens[idx]]);
                entries[count].1 = self.history_lens[idx];
                count += 1;
            }
        }

        (entries, count)
    }

    /// Toggle address dropdown visibility
    pub fn toggle_address_dropdown(&mut self) {
        self.address_dropdown_visible = !self.address_dropdown_visible;
    }

    /// Hide address dropdown
    pub fn hide_address_dropdown(&mut self) {
        self.address_dropdown_visible = false;
    }

    // ========================================================================
    // Search
    // ========================================================================

    /// Toggle search mode
    pub fn toggle_search(&mut self) {
        self.search_active = !self.search_active;
        if !self.search_active {
            // Clear search when deactivating
            self.clear_search();
        }
    }

    /// Clear search query and results
    pub fn clear_search(&mut self) {
        self.search_query_len = 0;
        self.search_cursor = 0;
        self.search_match_count = 0;
        for i in 0..SELECTION_WORDS {
            self.search_matches[i] = 0;
        }
    }

    /// Get search query as string
    pub fn search_query_str(&self) -> &str {
        core::str::from_utf8(&self.search_query[..self.search_query_len]).unwrap_or("")
    }

    /// Add character to search query
    pub fn search_add_char(&mut self, c: char) {
        if self.search_query_len < 63 {
            let mut buf = [0u8; 4];
            let s = c.encode_utf8(&mut buf);
            let bytes = s.as_bytes();
            if self.search_query_len + bytes.len() < 64 {
                self.search_query[self.search_query_len..self.search_query_len + bytes.len()]
                    .copy_from_slice(bytes);
                self.search_query_len += bytes.len();
                self.search_cursor = self.search_query_len;
                self.update_search_results();
            }
        }
    }

    /// Remove character from search query (backspace)
    pub fn search_backspace(&mut self) {
        if self.search_query_len > 0 {
            self.search_query_len -= 1;
            self.search_cursor = self.search_query_len;
            self.update_search_results();
        }
    }

    /// Update search results based on current query
    pub fn update_search_results(&mut self) {
        // Clear previous matches
        for i in 0..SELECTION_WORDS {
            self.search_matches[i] = 0;
        }
        self.search_match_count = 0;

        if self.search_query_len == 0 {
            // Empty search - all items match
            for i in 0..self.item_count {
                self.set_search_match(i, true);
            }
            return;
        }

        // Convert search query to lowercase for case-insensitive search
        let query = self.search_query_str().to_ascii_lowercase();

        // Check each item for match
        for i in 0..self.item_count {
            let item_name = self.items[i].name_str().to_ascii_lowercase();
            if item_name.contains(&query) {
                self.set_search_match(i, true);
            }
        }
    }

    /// Check if item matches search
    pub fn is_search_match(&self, index: usize) -> bool {
        if !self.search_active || self.search_query_len == 0 {
            return true; // All items match when search is inactive or empty
        }
        if index >= MAX_FILES {
            return false;
        }
        let word = index / 32;
        let bit = index % 32;
        (self.search_matches[word] & (1 << bit)) != 0
    }

    /// Set search match status for an item
    fn set_search_match(&mut self, index: usize, matches: bool) {
        if index >= MAX_FILES {
            return;
        }
        let word = index / 32;
        let bit = index % 32;
        if matches {
            self.search_matches[word] |= 1 << bit;
            self.search_match_count += 1;
        } else {
            self.search_matches[word] &= !(1 << bit);
        }
    }

    // ========================================================================
    // Hover Tooltips
    // ========================================================================

    /// Tooltip hover delay in milliseconds
    pub const TOOLTIP_DELAY_MS: u64 = 500;

    /// Update hover state on mouse move
    pub fn update_hover(&mut self, content_rect: &Rect, x: i32, y: i32) {
        // Get current tick count
        let current_tick = crate::hal::timer::hal_query_performance_counter() / 1_000_000; // Convert to ms approx

        // Hit test to find item under cursor
        let new_hover = if let Some(index) = self.hit_test(content_rect, x, y) {
            index as i32
        } else {
            -1
        };

        // If hovering a different item, reset hover timer
        if new_hover != self.hover_index {
            self.hover_index = new_hover;
            self.hover_x = x;
            self.hover_y = y;
            self.hover_start_tick = current_tick;
            self.tooltip_visible = false;
        } else if !self.tooltip_visible && new_hover >= 0 {
            // Check if enough time has passed to show tooltip
            if current_tick.saturating_sub(self.hover_start_tick) >= Self::TOOLTIP_DELAY_MS {
                self.tooltip_visible = true;
            }
        }
    }

    /// Clear hover state (mouse left window)
    pub fn clear_hover(&mut self) {
        self.hover_index = -1;
        self.tooltip_visible = false;
    }

    /// Get tooltip text for hovered item
    pub fn get_tooltip_text(&self) -> Option<([u8; 256], usize)> {
        if !self.tooltip_visible || self.hover_index < 0 || self.hover_index >= self.item_count as i32 {
            return None;
        }

        let item = &self.items[self.hover_index as usize];
        let mut buf = [0u8; 256];
        let mut pos = 0;

        // Name
        let name_label = b"Name: ";
        let name_len = name_label.len();
        if pos + name_len < 256 {
            buf[pos..pos + name_len].copy_from_slice(name_label);
            pos += name_len;
        }
        if pos + item.name_len < 255 {
            buf[pos..pos + item.name_len].copy_from_slice(&item.name[..item.name_len]);
            pos += item.name_len;
        }
        if pos < 255 {
            buf[pos] = b'\n';
            pos += 1;
        }

        // Type
        let type_label = b"Type: ";
        let type_len = type_label.len();
        if pos + type_len < 256 {
            buf[pos..pos + type_len].copy_from_slice(type_label);
            pos += type_len;
        }
        let type_str: &[u8] = if item.is_directory {
            b"File Folder"
        } else {
            match item.icon_type {
                VfsIconType::Document => b"Text Document",
                VfsIconType::Image => b"Image File",
                VfsIconType::Audio => b"Audio File",
                VfsIconType::Video => b"Video File",
                VfsIconType::Executable => b"Application",
                _ => b"File",
            }
        };
        if pos + type_str.len() < 255 {
            buf[pos..pos + type_str.len()].copy_from_slice(type_str);
            pos += type_str.len();
        }
        if pos < 255 {
            buf[pos] = b'\n';
            pos += 1;
        }

        // Size (only for files)
        if !item.is_directory {
            let size_label = b"Size: ";
            if pos + size_label.len() < 256 {
                buf[pos..pos + size_label.len()].copy_from_slice(size_label);
                pos += size_label.len();
            }

            // Format size using FileItem method
            let mut size_buf = [0u8; 32];
            let size_len = item.format_size(&mut size_buf);
            if size_len > 0 && pos + size_len < 256 {
                buf[pos..pos + size_len].copy_from_slice(&size_buf[..size_len]);
                pos += size_len;
            }
        }

        Some((buf, pos))
    }

    // ========================================================================
    // Drag and Drop
    // ========================================================================

    /// Start potential drag operation (mouse down on selected item)
    pub fn start_potential_drag(&mut self, x: i32, y: i32) {
        if self.selection_count > 0 {
            self.drag_state = DragState::Pending { start_x: x, start_y: y };
        }
    }

    /// Check if drag should start based on mouse movement
    pub fn check_drag_threshold(&mut self, x: i32, y: i32) -> bool {
        if let DragState::Pending { start_x, start_y } = self.drag_state {
            let dx = (x - start_x).abs();
            let dy = (y - start_y).abs();
            if dx > DRAG_THRESHOLD || dy > DRAG_THRESHOLD {
                self.drag_state = DragState::Active;
                crate::serial_println!("[BROWSER] Drag started with {} items", self.selection_count);
                return true;
            }
        }
        false
    }

    /// Cancel any drag operation
    pub fn cancel_drag(&mut self) {
        if self.drag_state != DragState::None {
            self.drag_state = DragState::None;
        }
    }

    /// Check if drag is active
    pub fn is_dragging(&self) -> bool {
        self.drag_state == DragState::Active
    }

    /// Get selected item paths for drag operation
    pub fn get_drag_items(&self) -> ([u8; MAX_PATH], usize, usize) {
        // Returns: (combined paths buffer, total length, item count)
        // For simplicity, return the current path and selection count
        // A more complete implementation would build full paths for each selected item
        let mut buf = [0u8; MAX_PATH];
        buf[..self.path_len].copy_from_slice(&self.path[..self.path_len]);
        (buf, self.path_len, self.selection_count)
    }

    // ========================================================================
    // Column Resize
    // ========================================================================

    /// Get the x position of a column separator (right edge of column)
    pub fn get_column_separator_x(&self, col_index: usize) -> i32 {
        let mut x = 0;
        for i in 0..=col_index {
            if i < 4 {
                x += self.column_widths[i];
            }
        }
        x
    }

    /// Hit test for column separator - returns column index if near separator
    pub fn hit_test_column_separator(&self, x: i32) -> Option<usize> {
        let mut col_x = 0;
        for i in 0..4 {
            col_x += self.column_widths[i];
            // Check if x is within the resize zone around the separator
            if x >= col_x - RESIZE_HIT_ZONE && x <= col_x + RESIZE_HIT_ZONE {
                return Some(i);
            }
        }
        None
    }

    /// Resize a column to a new width
    pub fn resize_column(&mut self, col_index: usize, new_width: i32) {
        if col_index < 4 {
            self.column_widths[col_index] = new_width.max(MIN_COLUMN_WIDTH);
        }
    }

    // ========================================================================
    // Selection Management
    // ========================================================================

    /// Check if item at index is selected
    pub fn is_selected(&self, index: usize) -> bool {
        if index >= MAX_FILES {
            return false;
        }
        let word = index / 32;
        let bit = index % 32;
        (self.selection[word] & (1 << bit)) != 0
    }

    /// Set selection state for item at index
    pub fn set_selected(&mut self, index: usize, selected: bool) {
        if index >= MAX_FILES {
            return;
        }
        let word = index / 32;
        let bit = index % 32;
        let was_selected = (self.selection[word] & (1 << bit)) != 0;

        if selected {
            self.selection[word] |= 1 << bit;
            if !was_selected {
                self.selection_count += 1;
            }
        } else {
            self.selection[word] &= !(1 << bit);
            if was_selected && self.selection_count > 0 {
                self.selection_count -= 1;
            }
        }
    }

    /// Toggle selection for item at index
    pub fn toggle_selected(&mut self, index: usize) {
        let selected = self.is_selected(index);
        self.set_selected(index, !selected);
    }

    /// Clear all selections
    pub fn clear_selection(&mut self) {
        for i in 0..SELECTION_WORDS {
            self.selection[i] = 0;
        }
        self.selection_count = 0;
    }

    /// Get the first selected item index, if any
    pub fn get_first_selected(&self) -> Option<usize> {
        for i in 0..self.item_count {
            if self.is_selected(i) {
                return Some(i);
            }
        }
        None
    }

    /// Select all items
    pub fn select_all(&mut self) {
        self.clear_selection();
        for i in 0..self.item_count {
            self.set_selected(i, true);
        }
    }

    /// Invert selection (toggle all items)
    pub fn invert_selection(&mut self) {
        self.selection_count = 0;
        for i in 0..self.item_count {
            // Toggle selection bit
            let word = i / 32;
            let bit = i % 32;
            self.selection[word] ^= 1 << bit;
            // Count if now selected
            if (self.selection[word] & (1 << bit)) != 0 {
                self.selection_count += 1;
            }
        }
        crate::serial_println!("[BROWSER] Inverted selection: {} items now selected", self.selection_count);
    }

    /// Select all items of the same type as the focused item
    pub fn select_by_type(&mut self) {
        if self.focus_index < 0 || self.focus_index >= self.item_count as i32 {
            return;
        }

        let focused = &self.items[self.focus_index as usize];
        let target_is_dir = focused.is_directory;
        let target_type = focused.icon_type;

        self.clear_selection();

        for i in 0..self.item_count {
            let item = &self.items[i];
            let matches = if target_is_dir {
                // If focused is a directory, select all directories
                item.is_directory
            } else {
                // If focused is a file, select all files of same type
                !item.is_directory && item.icon_type == target_type
            };

            if matches {
                self.set_selected(i, true);
            }
        }

        crate::serial_println!("[BROWSER] Selected {} items by type", self.selection_count);
    }

    /// Select range from anchor to index (inclusive)
    pub fn select_range(&mut self, from: usize, to: usize) {
        let start = from.min(to);
        let end = from.max(to);
        for i in start..=end.min(self.item_count.saturating_sub(1)) {
            self.set_selected(i, true);
        }
    }

    /// Get first selected index (-1 if none)
    pub fn first_selected(&self) -> i32 {
        for i in 0..self.item_count {
            if self.is_selected(i) {
                return i as i32;
            }
        }
        -1
    }

    /// Handle single click selection (optionally with modifiers)
    pub fn handle_selection_click(&mut self, index: usize, ctrl: bool, shift: bool) {
        if index >= self.item_count {
            return;
        }

        if shift && self.anchor_index >= 0 {
            // Shift+click: range selection from anchor
            if !ctrl {
                self.clear_selection();
            }
            self.select_range(self.anchor_index as usize, index);
        } else if ctrl {
            // Ctrl+click: toggle individual selection
            self.toggle_selected(index);
        } else {
            // Regular click: single selection
            self.clear_selection();
            self.set_selected(index, true);
            self.anchor_index = index as i32;
        }

        self.focus_index = index as i32;
    }

    /// Get path as string
    pub fn path_str(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }

    /// Set current path
    pub fn set_path(&mut self, path: &str) {
        let len = path.len().min(MAX_PATH - 1);
        self.path[..len].copy_from_slice(&path.as_bytes()[..len]);
        self.path_len = len;
    }

    /// Navigate to a path
    pub fn navigate(&mut self, path: &str) {
        // Add current path to history before navigating
        if self.path_len > 0 {
            self.push_history();
        }

        self.set_path(path);
        self.refresh();
        self.clear_selection();
        self.focus_index = 0;
        self.anchor_index = 0;
        self.scroll_y = 0;
    }

    // ========================================================================
    // Clipboard Operations
    // ========================================================================

    /// Copy selected items to clipboard
    pub fn copy_selection(&mut self) {
        if self.selection_count == 0 {
            return;
        }

        // Store selection in clipboard
        self.clipboard_op = ClipboardOp::Copy;
        self.clipboard_items = self.selection;
        self.clipboard_path[..self.path_len].copy_from_slice(&self.path[..self.path_len]);
        self.clipboard_path_len = self.path_len;

        crate::serial_println!("[BROWSER] Copied {} items", self.selection_count);
    }

    /// Cut selected items to clipboard
    pub fn cut_selection(&mut self) {
        if self.selection_count == 0 {
            return;
        }

        self.clipboard_op = ClipboardOp::Cut;
        self.clipboard_items = self.selection;
        self.clipboard_path[..self.path_len].copy_from_slice(&self.path[..self.path_len]);
        self.clipboard_path_len = self.path_len;

        crate::serial_println!("[BROWSER] Cut {} items", self.selection_count);
    }

    /// Check if clipboard has items
    pub fn has_clipboard(&self) -> bool {
        self.clipboard_op != ClipboardOp::None
    }

    /// Paste clipboard items to current folder
    pub fn paste(&mut self) -> bool {
        use crate::io::{vfs_copy_file, vfs_delete_file};

        if self.clipboard_op == ClipboardOp::None {
            return false;
        }

        let is_cut = self.clipboard_op == ClipboardOp::Cut;
        let src_path = core::str::from_utf8(&self.clipboard_path[..self.clipboard_path_len]).unwrap_or("");
        let dst_path = core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("");

        crate::serial_println!("[BROWSER] Paste from '{}' to '{}'", src_path, dst_path);

        // We need to get the source browser to find the items
        // For now, iterate over clipboard bitmap and try to copy each item
        let mut success_count = 0;
        for word_idx in 0..SELECTION_WORDS {
            let mut bits = self.clipboard_items[word_idx];
            while bits != 0 {
                let bit_idx = bits.trailing_zeros() as usize;
                let item_idx = word_idx * 32 + bit_idx;
                bits &= !(1 << bit_idx);

                // Build source file path
                let mut src_file_path = [0u8; MAX_PATH];
                let mut src_len = 0;
                for b in src_path.bytes() {
                    if src_len < MAX_PATH - 1 {
                        src_file_path[src_len] = b;
                        src_len += 1;
                    }
                }
                // Append /filename (we don't have the filename here, skip for now)
                // This is a simplified implementation
                crate::serial_println!("[BROWSER] Would copy item {}", item_idx);
                success_count += 1;
            }
        }

        // If cut, clear clipboard after successful paste
        if is_cut && success_count > 0 {
            self.clipboard_op = ClipboardOp::None;
            self.clipboard_items = [0; SELECTION_WORDS];
        }

        self.refresh();
        true
    }

    // ========================================================================
    // File Operations
    // ========================================================================

    /// Delete selected items
    pub fn delete_selection(&mut self) -> bool {
        use crate::io::vfs_delete_file;

        if self.selection_count == 0 {
            return false;
        }

        let current_path = core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("");
        crate::serial_println!("[BROWSER] Delete {} items in '{}'", self.selection_count, current_path);

        let mut deleted_count = 0;
        for i in 0..self.item_count {
            if self.is_selected(i) {
                let item = &self.items[i];
                let item_name = item.name_str();

                // Build full path: current_path + "/" + item_name
                let mut full_path = [0u8; MAX_PATH];
                let mut len = 0;

                // Copy current path
                for b in current_path.bytes() {
                    if len < MAX_PATH - 1 {
                        full_path[len] = b;
                        len += 1;
                    }
                }

                // Add separator if needed
                if len > 0 && len < MAX_PATH - 1 && full_path[len - 1] != b'/' && full_path[len - 1] != b'\\' {
                    full_path[len] = b'/';
                    len += 1;
                }

                // Add item name
                for b in item_name.bytes() {
                    if len < MAX_PATH - 1 {
                        full_path[len] = b;
                        len += 1;
                    }
                }

                let full_path_str = core::str::from_utf8(&full_path[..len]).unwrap_or("");

                if vfs_delete_file(full_path_str) {
                    crate::serial_println!("[BROWSER] Deleted: {}", full_path_str);
                    // Record undo operation for each deleted item
                    record_operation(UndoOperation::new_delete(full_path_str, item.is_directory));
                    deleted_count += 1;
                } else {
                    crate::serial_println!("[BROWSER] Failed to delete: {}", full_path_str);
                }
            }
        }

        crate::serial_println!("[BROWSER] Deleted {}/{} items", deleted_count, self.selection_count);
        self.clear_selection();
        self.refresh();
        true
    }

    /// Start rename mode for focused item
    pub fn start_rename(&mut self) -> bool {
        if self.focus_index < 0 || self.focus_index >= self.item_count as i32 {
            return false;
        }

        let item = &self.items[self.focus_index as usize];
        self.rename_buffer_len = item.name_len;
        self.rename_buffer[..item.name_len].copy_from_slice(&item.name[..item.name_len]);
        self.rename_cursor = item.name_len;
        self.rename_mode = true;

        crate::serial_println!("[BROWSER] Rename mode started");
        true
    }

    /// Cancel rename mode
    pub fn cancel_rename(&mut self) {
        self.rename_mode = false;
        self.rename_buffer_len = 0;
        self.rename_cursor = 0;
    }

    /// Confirm rename
    pub fn confirm_rename(&mut self) -> bool {
        use crate::io::vfs_rename_file;

        if !self.rename_mode || self.focus_index < 0 {
            return false;
        }

        let new_name = core::str::from_utf8(&self.rename_buffer[..self.rename_buffer_len]).unwrap_or("");
        if new_name.is_empty() {
            self.cancel_rename();
            return false;
        }

        let item = &self.items[self.focus_index as usize];
        let old_name = item.name_str();

        // Don't rename if name hasn't changed
        if old_name == new_name {
            self.cancel_rename();
            return false;
        }

        let current_path = core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("");

        // Build old full path
        let mut old_path = [0u8; MAX_PATH];
        let mut old_len = 0;
        for b in current_path.bytes() {
            if old_len < MAX_PATH - 1 {
                old_path[old_len] = b;
                old_len += 1;
            }
        }
        if old_len > 0 && old_len < MAX_PATH - 1 && old_path[old_len - 1] != b'/' && old_path[old_len - 1] != b'\\' {
            old_path[old_len] = b'/';
            old_len += 1;
        }
        for b in old_name.bytes() {
            if old_len < MAX_PATH - 1 {
                old_path[old_len] = b;
                old_len += 1;
            }
        }

        // Build new full path
        let mut new_path = [0u8; MAX_PATH];
        let mut new_len = 0;
        for b in current_path.bytes() {
            if new_len < MAX_PATH - 1 {
                new_path[new_len] = b;
                new_len += 1;
            }
        }
        if new_len > 0 && new_len < MAX_PATH - 1 && new_path[new_len - 1] != b'/' && new_path[new_len - 1] != b'\\' {
            new_path[new_len] = b'/';
            new_len += 1;
        }
        for b in new_name.bytes() {
            if new_len < MAX_PATH - 1 {
                new_path[new_len] = b;
                new_len += 1;
            }
        }

        let old_path_str = core::str::from_utf8(&old_path[..old_len]).unwrap_or("");
        let new_path_str = core::str::from_utf8(&new_path[..new_len]).unwrap_or("");

        crate::serial_println!("[BROWSER] Rename '{}' to '{}'", old_path_str, new_path_str);

        let success = vfs_rename_file(old_path_str, new_path_str);
        if success {
            crate::serial_println!("[BROWSER] Rename successful");
            // Record undo operation
            let is_dir = self.items[self.focus_index as usize].is_directory;
            record_operation(UndoOperation::new_rename(old_path_str, new_path_str, is_dir));
        } else {
            crate::serial_println!("[BROWSER] Rename failed");
        }

        self.cancel_rename();
        self.refresh();
        success
    }

    /// Handle rename text input
    pub fn handle_rename_char(&mut self, c: char) {
        if !self.rename_mode {
            return;
        }

        // Basic text input handling
        if c >= ' ' && c <= '~' && self.rename_buffer_len < 255 {
            // Insert character at cursor
            self.rename_buffer[self.rename_cursor] = c as u8;
            self.rename_cursor += 1;
            if self.rename_cursor > self.rename_buffer_len {
                self.rename_buffer_len = self.rename_cursor;
            }
        }
    }

    /// Handle rename backspace
    pub fn handle_rename_backspace(&mut self) {
        if !self.rename_mode || self.rename_cursor == 0 {
            return;
        }

        self.rename_cursor -= 1;
        // Shift remaining characters left
        for i in self.rename_cursor..self.rename_buffer_len.saturating_sub(1) {
            self.rename_buffer[i] = self.rename_buffer[i + 1];
        }
        if self.rename_buffer_len > 0 {
            self.rename_buffer_len -= 1;
        }
    }

    // ========================================================================
    // Scrolling
    // ========================================================================

    /// Handle mouse wheel scroll
    pub fn handle_scroll(&mut self, delta: i32) {
        // Negative delta = scroll down, positive = scroll up
        self.scroll_y -= delta * DETAILS_ROW_HEIGHT * 3; // 3 lines per wheel notch

        // Clamp scroll position
        let max_scroll = self.get_max_scroll_y();
        if self.scroll_y < 0 {
            self.scroll_y = 0;
        }
        if self.scroll_y > max_scroll {
            self.scroll_y = max_scroll;
        }
    }

    /// Get maximum scroll Y value
    fn get_max_scroll_y(&self) -> i32 {
        let total_height = match self.view_mode {
            ViewMode::Details | ViewMode::List => self.item_count as i32 * DETAILS_ROW_HEIGHT,
            ViewMode::Thumbnails => (self.item_count as i32 / 3 + 1) * THUMBNAIL_GRID_HEIGHT,
            _ => (self.item_count as i32 / 4 + 1) * ICON_GRID_HEIGHT,
        };
        // Return max scroll, which is total content height minus visible height (estimated)
        (total_height - 300).max(0)
    }

    /// Push current path to history
    fn push_history(&mut self) {
        if self.history_count < 16 {
            self.history_pos = self.history_count;
            self.history_count += 1;
        } else {
            // Shift history
            for i in 0..15 {
                self.history[i] = self.history[i + 1];
                self.history_lens[i] = self.history_lens[i + 1];
            }
            self.history_pos = 15;
        }
        self.history[self.history_pos][..self.path_len].copy_from_slice(&self.path[..self.path_len]);
        self.history_lens[self.history_pos] = self.path_len;
    }

    /// Navigate back in history
    pub fn go_back(&mut self) -> bool {
        if self.history_pos > 0 {
            self.history_pos -= 1;
            let len = self.history_lens[self.history_pos];
            self.path[..len].copy_from_slice(&self.history[self.history_pos][..len]);
            self.path_len = len;
            self.refresh();
            self.clear_selection();
            self.scroll_y = 0;
            return true;
        }
        false
    }

    /// Navigate forward in history
    pub fn go_forward(&mut self) -> bool {
        if self.history_pos + 1 < self.history_count {
            self.history_pos += 1;
            let len = self.history_lens[self.history_pos];
            self.path[..len].copy_from_slice(&self.history[self.history_pos][..len]);
            self.path_len = len;
            self.refresh();
            self.clear_selection();
            self.scroll_y = 0;
            return true;
        }
        false
    }

    /// Navigate up one directory
    pub fn go_up(&mut self) -> bool {
        if self.path_len == 0 {
            return false;
        }

        // Find last backslash
        let path = self.path_str();
        if let Some(pos) = path.rfind('\\') {
            if pos <= 2 {
                // At root (e.g., "C:\")
                self.navigate("");
            } else {
                let parent = &path[..pos];
                let parent_owned: [u8; MAX_PATH] = {
                    let mut buf = [0u8; MAX_PATH];
                    buf[..parent.len()].copy_from_slice(parent.as_bytes());
                    buf
                };
                self.path_len = parent.len();
                self.path[..self.path_len].copy_from_slice(&parent_owned[..self.path_len]);
                self.push_history();
                self.refresh();
                self.clear_selection();
                self.scroll_y = 0;
            }
            return true;
        }

        // No backslash - go to root
        self.navigate("");
        true
    }

    /// Refresh file listing
    pub fn refresh(&mut self) {
        let mut vfs_entries = [VfsEntry::empty(); MAX_FILES];

        // Get path info before we start mutating self
        let path_len = self.path_len;
        let count = if path_len == 0 {
            // Show drives (My Computer)
            vfs::read_directory("", &mut vfs_entries)
        } else {
            // Copy path bytes for the vfs call
            let path = core::str::from_utf8(&self.path[..path_len]).unwrap_or("");
            vfs::read_directory(path, &mut vfs_entries)
        };

        self.item_count = count.min(MAX_FILES);
        for i in 0..self.item_count {
            self.items[i] = FileItem::from_vfs_entry(&vfs_entries[i]);
        }

        // Sort items
        self.sort_items();

        // Compute groups if grouping is enabled
        self.compute_groups();

        crate::serial_println!("[BROWSER] Loaded {} items", self.item_count);
    }

    /// Select an item by name and return its index
    pub fn select_by_name(&mut self, name: &str) -> Option<usize> {
        for i in 0..self.item_count {
            let item_name = self.items[i].name_str();
            // Case-insensitive comparison
            if item_name.eq_ignore_ascii_case(name) {
                // Clear previous selection and select this item
                self.clear_selection();
                self.set_selected(i, true);
                self.focus_index = i as i32;

                // Scroll to make item visible
                self.ensure_visible(i);

                crate::serial_println!("[BROWSER] Selected item '{}' at index {}", name, i);
                return Some(i);
            }
        }
        crate::serial_println!("[BROWSER] Could not find item '{}'", name);
        None
    }

    /// Ensure an item is visible (scroll if needed)
    fn ensure_visible(&mut self, index: usize) {
        // Calculate visible range based on view mode
        let items_per_row = match self.view_mode {
            ViewMode::Details | ViewMode::List => 1,
            ViewMode::LargeIcons => 4,
            ViewMode::SmallIcons => 6,
            ViewMode::Tiles => 3,
            ViewMode::Thumbnails => 4,
        };

        let row_height = match self.view_mode {
            ViewMode::Details => DETAILS_ROW_HEIGHT,
            ViewMode::LargeIcons => ICON_GRID_HEIGHT,
            ViewMode::SmallIcons => SMALL_ICON_GRID_HEIGHT,
            ViewMode::List => LIST_ITEM_HEIGHT,
            ViewMode::Tiles => TILE_HEIGHT,
            ViewMode::Thumbnails => THUMBNAIL_GRID_HEIGHT,
        };

        let row = (index / items_per_row as usize) as i32;
        let item_top = row * row_height;
        let item_bottom = item_top + row_height;

        // Check if we need to scroll
        let content_height = 300; // Approximate content area height

        if item_top < self.scroll_y {
            // Item is above visible area - scroll up
            self.scroll_y = item_top;
        } else if item_bottom > self.scroll_y + content_height {
            // Item is below visible area - scroll down
            self.scroll_y = item_bottom - content_height;
        }

        // Clamp scroll position
        if self.scroll_y < 0 {
            self.scroll_y = 0;
        }
    }

    /// Sort items by current sort column
    fn sort_items(&mut self) {
        // Simple bubble sort (good enough for small lists)
        for i in 0..self.item_count {
            for j in i + 1..self.item_count {
                let swap = match self.sort_column {
                    SortColumn::Name => {
                        let cmp = compare_names(&self.items[i], &self.items[j]);
                        if self.sort_ascending { cmp > 0 } else { cmp < 0 }
                    }
                    SortColumn::Size => {
                        if self.sort_ascending {
                            self.items[i].size > self.items[j].size
                        } else {
                            self.items[i].size < self.items[j].size
                        }
                    }
                    SortColumn::Type => {
                        let cmp = compare_types(&self.items[i], &self.items[j]);
                        if self.sort_ascending { cmp > 0 } else { cmp < 0 }
                    }
                    SortColumn::Modified => {
                        // TODO: Add modification time to VfsEntry
                        false
                    }
                };

                // Always sort directories first
                let dir_swap = !self.items[i].is_directory && self.items[j].is_directory;

                if dir_swap || (self.items[i].is_directory == self.items[j].is_directory && swap) {
                    let temp = self.items[i];
                    self.items[i] = self.items[j];
                    self.items[j] = temp;
                }
            }
        }
    }

    /// Compute groups based on current grouping mode
    fn compute_groups(&mut self) {
        self.group_count = 0;

        if self.group_by == GroupBy::None || self.item_count == 0 {
            return;
        }

        match self.group_by {
            GroupBy::Type => self.compute_groups_by_type(),
            GroupBy::Date => self.compute_groups_by_date(),
            GroupBy::Name => self.compute_groups_by_name(),
            GroupBy::None => {}
        }
    }

    /// Compute groups by file type
    fn compute_groups_by_type(&mut self) {
        // Group order: Folders, Documents, Images, Audio, Video, Applications, Other
        let mut folder_start = usize::MAX;
        let mut doc_start = usize::MAX;
        let mut image_start = usize::MAX;
        let mut audio_start = usize::MAX;
        let mut video_start = usize::MAX;
        let mut app_start = usize::MAX;
        let mut other_start = usize::MAX;

        for i in 0..self.item_count {
            let item = &self.items[i];
            if item.is_directory {
                if folder_start == usize::MAX { folder_start = i; }
            } else {
                match item.icon_type {
                    VfsIconType::Document => {
                        if doc_start == usize::MAX { doc_start = i; }
                    }
                    VfsIconType::Image => {
                        if image_start == usize::MAX { image_start = i; }
                    }
                    VfsIconType::Audio => {
                        if audio_start == usize::MAX { audio_start = i; }
                    }
                    VfsIconType::Video => {
                        if video_start == usize::MAX { video_start = i; }
                    }
                    VfsIconType::Executable => {
                        if app_start == usize::MAX { app_start = i; }
                    }
                    _ => {
                        if other_start == usize::MAX { other_start = i; }
                    }
                }
            }
        }

        // Add groups in order
        if folder_start != usize::MAX && self.group_count < MAX_GROUPS {
            self.groups[self.group_count] = GroupInfo::new(b"Folders", folder_start);
            self.group_count += 1;
        }
        if doc_start != usize::MAX && self.group_count < MAX_GROUPS {
            self.groups[self.group_count] = GroupInfo::new(b"Documents", doc_start);
            self.group_count += 1;
        }
        if image_start != usize::MAX && self.group_count < MAX_GROUPS {
            self.groups[self.group_count] = GroupInfo::new(b"Images", image_start);
            self.group_count += 1;
        }
        if audio_start != usize::MAX && self.group_count < MAX_GROUPS {
            self.groups[self.group_count] = GroupInfo::new(b"Audio", audio_start);
            self.group_count += 1;
        }
        if video_start != usize::MAX && self.group_count < MAX_GROUPS {
            self.groups[self.group_count] = GroupInfo::new(b"Video", video_start);
            self.group_count += 1;
        }
        if app_start != usize::MAX && self.group_count < MAX_GROUPS {
            self.groups[self.group_count] = GroupInfo::new(b"Applications", app_start);
            self.group_count += 1;
        }
        if other_start != usize::MAX && self.group_count < MAX_GROUPS {
            self.groups[self.group_count] = GroupInfo::new(b"Other", other_start);
            self.group_count += 1;
        }

        // Calculate item counts per group
        self.update_group_counts();
    }

    /// Compute groups by modification date
    fn compute_groups_by_date(&mut self) {
        // For now, just group all items together (VFS doesn't have date info yet)
        // In future: Today, Yesterday, This Week, Last Week, This Month, Older
        if self.item_count > 0 && self.group_count < MAX_GROUPS {
            self.groups[self.group_count] = GroupInfo::new(b"All Files", 0);
            self.groups[self.group_count].item_count = self.item_count;
            self.group_count += 1;
        }
    }

    /// Compute groups by first letter of name
    fn compute_groups_by_name(&mut self) {
        let mut current_letter: u8 = 0;

        for i in 0..self.item_count {
            let item = &self.items[i];
            let first_char = if item.name_len > 0 {
                item.name[0].to_ascii_uppercase()
            } else {
                b'?'
            };

            // Start new group if letter changed
            if first_char != current_letter {
                if self.group_count >= MAX_GROUPS {
                    break;
                }

                let label = [first_char, 0];
                self.groups[self.group_count] = GroupInfo::new(&label[..1], i);
                self.group_count += 1;
                current_letter = first_char;
            }
        }

        self.update_group_counts();
    }

    /// Update item counts for each group
    fn update_group_counts(&mut self) {
        for i in 0..self.group_count {
            let start = self.groups[i].first_index;
            let end = if i + 1 < self.group_count {
                self.groups[i + 1].first_index
            } else {
                self.item_count
            };
            self.groups[i].item_count = end - start;
        }
    }

    /// Set grouping mode
    pub fn set_group_by(&mut self, mode: GroupBy) {
        if self.group_by != mode {
            self.group_by = mode;
            self.sort_items(); // Re-sort for proper grouping
            self.compute_groups();
        }
    }

    /// Toggle grouping mode (cycle through options)
    pub fn toggle_grouping(&mut self) {
        self.group_by = match self.group_by {
            GroupBy::None => GroupBy::Type,
            GroupBy::Type => GroupBy::Date,
            GroupBy::Date => GroupBy::Name,
            GroupBy::Name => GroupBy::None,
        };
        self.sort_items();
        self.compute_groups();
    }

    /// Toggle auto-arrange mode
    pub fn toggle_auto_arrange(&mut self) {
        self.auto_arrange = !self.auto_arrange;
        crate::serial_println!("[BROWSER] Auto-arrange: {}", self.auto_arrange);
    }

    /// Toggle snap-to-grid mode
    pub fn toggle_snap_to_grid(&mut self) {
        self.snap_to_grid = !self.snap_to_grid;
        crate::serial_println!("[BROWSER] Snap to grid: {}", self.snap_to_grid);
    }

    /// Set sort column - if same column, toggle direction; otherwise set ascending
    pub fn set_sort_column(&mut self, column: SortColumn) {
        if self.sort_column == column {
            // Toggle direction
            self.sort_ascending = !self.sort_ascending;
        } else {
            // New column, default to ascending
            self.sort_column = column;
            self.sort_ascending = true;
        }
        self.sort_items();
    }

    /// Open focused/selected item (double-click)
    pub fn open_selected(&mut self) -> Option<([u8; MAX_PATH], usize, bool)> {
        // Use focus_index for double-click action
        if self.focus_index < 0 || self.focus_index >= self.item_count as i32 {
            return None;
        }

        let item = &self.items[self.focus_index as usize];

        if item.is_directory {
            // Navigate into directory
            let mut new_path = [0u8; MAX_PATH];
            let mut new_len = 0;

            if self.path_len > 0 {
                new_path[..self.path_len].copy_from_slice(&self.path[..self.path_len]);
                new_len = self.path_len;
                if new_len < MAX_PATH - 1 && new_path[new_len - 1] != b'\\' {
                    new_path[new_len] = b'\\';
                    new_len += 1;
                }
            }

            if new_len + item.name_len < MAX_PATH {
                new_path[new_len..new_len + item.name_len].copy_from_slice(&item.name[..item.name_len]);
                new_len += item.name_len;
            }

            Some((new_path, new_len, true))
        } else {
            // Return file path for execution
            let mut file_path = [0u8; MAX_PATH];
            let mut file_len = 0;

            if self.path_len > 0 {
                file_path[..self.path_len].copy_from_slice(&self.path[..self.path_len]);
                file_len = self.path_len;
                if file_len < MAX_PATH - 1 && file_path[file_len - 1] != b'\\' {
                    file_path[file_len] = b'\\';
                    file_len += 1;
                }
            }

            if file_len + item.name_len < MAX_PATH {
                file_path[file_len..file_len + item.name_len].copy_from_slice(&item.name[..item.name_len]);
                file_len += item.name_len;
            }

            Some((file_path, file_len, false))
        }
    }

    /// Execute a file using shell associations
    pub fn execute_file(&self, path: &[u8], path_len: usize) -> bool {
        use super::super::shellexec;

        crate::serial_println!("[BROWSER] Executing file: {}",
            core::str::from_utf8(&path[..path_len]).unwrap_or("<invalid>"));

        let result = shellexec::shell_open(&path[..path_len]);

        if result > shellexec::SE_ERR_NOASSOC {
            crate::serial_println!("[BROWSER] File execution succeeded");
            true
        } else {
            crate::serial_println!("[BROWSER] File execution failed: {}", result);
            // Show message about no associated program
            false
        }
    }

    /// Get content area rectangle (excluding toolbar, address bar, status bar, and tree pane)
    pub fn get_content_rect(&self, hwnd: HWND) -> Rect {
        if let Some(win) = window::get_window(hwnd) {
            let client = win.client_rect;
            // Account for tree pane on the left
            let tree_width = if self.tree_visible {
                super::foldertree::TREE_PANE_WIDTH
            } else {
                0
            };
            Rect::new(
                client.left + tree_width,
                client.top + TOOLBAR_HEIGHT + ADDRESS_BAR_HEIGHT,
                client.right,
                client.bottom - STATUS_BAR_HEIGHT,
            )
        } else {
            Rect::new(0, 0, 400, 300)
        }
    }

    /// Get tree pane rectangle
    pub fn get_tree_rect(&self, hwnd: HWND) -> Rect {
        if let Some(win) = window::get_window(hwnd) {
            let client = win.client_rect;
            Rect::new(
                client.left,
                client.top + TOOLBAR_HEIGHT + ADDRESS_BAR_HEIGHT,
                client.left + super::foldertree::TREE_PANE_WIDTH,
                client.bottom - STATUS_BAR_HEIGHT,
            )
        } else {
            Rect::new(0, 0, 0, 0)
        }
    }

    /// Get visible item range based on scroll position
    pub fn get_visible_range(&self, content_height: i32) -> (usize, usize) {
        match self.view_mode {
            ViewMode::Details | ViewMode::List => {
                let first = (self.scroll_y / DETAILS_ROW_HEIGHT) as usize;
                let visible = ((content_height / DETAILS_ROW_HEIGHT) + 2) as usize;
                let last = (first + visible).min(self.item_count);
                (first, last)
            }
            ViewMode::Thumbnails => {
                // Thumbnail grid - fewer items per row
                let first_row = (self.scroll_y / THUMBNAIL_GRID_HEIGHT) as usize;
                let visible_rows = ((content_height / THUMBNAIL_GRID_HEIGHT) + 2) as usize;
                let items_per_row = 3; // Wider thumbnails, fewer per row
                let first = first_row * items_per_row;
                let last = ((first_row + visible_rows) * items_per_row).min(self.item_count);
                (first, last)
            }
            ViewMode::LargeIcons | ViewMode::SmallIcons | ViewMode::Tiles => {
                // For icon views, we'd need to calculate based on grid
                (0, self.item_count)
            }
        }
    }

    /// Hit test - find item at position
    pub fn hit_test(&self, content_rect: &Rect, x: i32, y: i32) -> Option<usize> {
        if x < content_rect.left || x > content_rect.right ||
           y < content_rect.top || y > content_rect.bottom {
            return None;
        }

        let rel_x = x - content_rect.left;
        let rel_y = y - content_rect.top + self.scroll_y;

        match self.view_mode {
            ViewMode::Details | ViewMode::List => {
                let row = rel_y / DETAILS_ROW_HEIGHT;
                if row >= 0 && (row as usize) < self.item_count {
                    Some(row as usize)
                } else {
                    None
                }
            }
            ViewMode::Thumbnails => {
                // Thumbnail grid hit testing
                let col = (rel_x - 10) / THUMBNAIL_GRID_WIDTH;
                let row = (rel_y - 10) / THUMBNAIL_GRID_HEIGHT;
                let content_width = content_rect.right - content_rect.left;
                let items_per_row = ((content_width - 20) / THUMBNAIL_GRID_WIDTH).max(1);
                let index = (row * items_per_row + col) as usize;
                if col >= 0 && col < items_per_row && index < self.item_count {
                    Some(index)
                } else {
                    None
                }
            }
            ViewMode::LargeIcons | ViewMode::SmallIcons | ViewMode::Tiles => {
                // Grid-based hit testing for large icons
                let col = (rel_x - 10) / ICON_GRID_WIDTH;
                let row = (rel_y - 10) / ICON_GRID_HEIGHT;
                let content_width = content_rect.right - content_rect.left;
                let items_per_row = ((content_width - 20) / ICON_GRID_WIDTH).max(1);
                let index = (row * items_per_row + col) as usize;
                if col >= 0 && col < items_per_row && index < self.item_count {
                    Some(index)
                } else {
                    None
                }
            }
        }
    }
}

fn compare_names(a: &FileItem, b: &FileItem) -> i32 {
    let a_name = a.name_str().to_ascii_lowercase();
    let b_name = b.name_str().to_ascii_lowercase();

    for (ac, bc) in a_name.chars().zip(b_name.chars()) {
        if ac < bc {
            return -1;
        }
        if ac > bc {
            return 1;
        }
    }

    if a.name_len < b.name_len {
        -1
    } else if a.name_len > b.name_len {
        1
    } else {
        0
    }
}

fn compare_types(a: &FileItem, b: &FileItem) -> i32 {
    let a_type = a.get_type_name();
    let b_type = b.get_type_name();

    for (ac, bc) in a_type.chars().zip(b_type.chars()) {
        if ac < bc {
            return -1;
        }
        if ac > bc {
            return 1;
        }
    }

    0
}

// ============================================================================
// Global Browser Registry
// ============================================================================

static BROWSERS: SpinLock<[FileBrowser; MAX_BROWSERS]> =
    SpinLock::new([const { FileBrowser::new() }; MAX_BROWSERS]);

/// Create or get browser for window
pub fn get_browser_for_window(hwnd: HWND) -> Option<usize> {
    let browsers = BROWSERS.lock();
    for (i, browser) in browsers.iter().enumerate() {
        if browser.active && browser.hwnd == hwnd {
            return Some(i);
        }
    }
    None
}

/// Create a new browser for a window
pub fn create_browser(hwnd: HWND, initial_path: &str) -> Option<usize> {
    let mut browsers = BROWSERS.lock();

    // Find free slot
    for (i, browser) in browsers.iter_mut().enumerate() {
        if !browser.active {
            browser.active = true;
            browser.hwnd = hwnd;
            browser.tree_visible = true; // Show tree by default
            browser.set_path(initial_path);
            browser.refresh();

            // Also create folder tree for this window
            drop(browsers); // Release lock before calling foldertree
            super::foldertree::get_or_create_tree(hwnd);

            return Some(i);
        }
    }

    None
}

/// Destroy browser for window
pub fn destroy_browser(hwnd: HWND) {
    // Remove folder tree first
    super::foldertree::remove_tree(hwnd);

    let mut browsers = BROWSERS.lock();
    for browser in browsers.iter_mut() {
        if browser.active && browser.hwnd == hwnd {
            browser.active = false;
            browser.hwnd = HWND::NULL;
            break;
        }
    }
}

/// Execute action on browser
pub fn with_browser<F, R>(hwnd: HWND, f: F) -> Option<R>
where
    F: FnOnce(&mut FileBrowser) -> R,
{
    let mut browsers = BROWSERS.lock();
    for browser in browsers.iter_mut() {
        if browser.active && browser.hwnd == hwnd {
            return Some(f(browser));
        }
    }
    None
}

// ============================================================================
// Drawing Functions
// ============================================================================

/// Paint the file browser content
pub fn paint_browser(hwnd: HWND, hdc: HDC) {
    let mut browsers = BROWSERS.lock();

    for browser in browsers.iter_mut() {
        if browser.active && browser.hwnd == hwnd {
            paint_browser_internal(browser, hdc);
            return;
        }
    }

    // No browser - paint placeholder
    paint_placeholder(hwnd, hdc);
}

fn paint_browser_internal(browser: &FileBrowser, hdc: HDC) {
    let win = match window::get_window(browser.hwnd) {
        Some(w) => w,
        None => return,
    };

    // Get the surface from the DC
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let offset = dc::get_dc(hdc)
        .map(|d| d.viewport_org)
        .unwrap_or(Point::new(0, 0));

    let metrics = win.get_frame_metrics();
    let border = metrics.border_width;
    let caption = if win.has_caption() { metrics.caption_height } else { 0 };

    // Client area (screen coordinates)
    let client_x = offset.x + border;
    let client_y = offset.y + border + caption;
    let client_w = win.rect.width() - border * 2;
    let client_h = win.rect.height() - border * 2 - caption;

    // Logical coordinates (window-relative for text_out)
    let log_x = border;
    let log_y = border + caption;

    // Paint toolbar
    paint_toolbar_surf(&surf, hdc, client_x, client_y, client_w, log_x, log_y, browser);

    // Paint address bar
    let toolbar_y = client_y + TOOLBAR_HEIGHT;
    let log_toolbar_y = log_y + TOOLBAR_HEIGHT;
    paint_address_bar_surf(&surf, hdc, client_x, toolbar_y, client_w, log_x, log_toolbar_y, browser);

    // Content area (below address bar)
    let content_y = toolbar_y + ADDRESS_BAR_HEIGHT;
    let log_content_y = log_toolbar_y + ADDRESS_BAR_HEIGHT;
    let content_h = client_h - TOOLBAR_HEIGHT - ADDRESS_BAR_HEIGHT - STATUS_BAR_HEIGHT;

    // Tree pane width (0 if hidden)
    let tree_width = if browser.tree_visible {
        super::foldertree::TREE_PANE_WIDTH
    } else {
        0
    };

    // Paint folder tree pane if visible
    if browser.tree_visible {
        let tree_rect = Rect::new(client_x, content_y, client_x + tree_width, content_y + content_h);
        super::foldertree::paint_tree(browser.hwnd, hdc, &surf, &tree_rect);
    }

    // Details panel width (0 if hidden)
    let details_width = if browser.details_panel_visible {
        DETAILS_PANEL_WIDTH
    } else {
        0
    };

    // Main content area (between tree and details panel)
    let main_x = client_x + tree_width;
    let main_w = client_w - tree_width - details_width;
    let main_log_x = log_x + tree_width;

    // Paint column headers (for details view)
    if browser.view_mode == ViewMode::Details {
        paint_headers_surf(&surf, hdc, main_x, content_y, main_w, main_log_x, log_content_y, browser);
        let header_bottom = content_y + HEADER_HEIGHT;
        let log_header_bottom = log_content_y + HEADER_HEIGHT;
        paint_file_list_surf(&surf, hdc, main_x, header_bottom, main_w, content_h - HEADER_HEIGHT, main_log_x, log_header_bottom, browser);
    } else {
        paint_file_list_surf(&surf, hdc, main_x, content_y, main_w, content_h, main_log_x, log_content_y, browser);
    }

    // Paint details panel if visible
    if browser.details_panel_visible {
        let details_x = main_x + main_w;
        let details_log_x = main_log_x + main_w;
        paint_details_panel_surf(&surf, hdc, details_x, content_y, details_width, content_h, details_log_x, log_content_y, browser);
    }

    // Paint status bar
    let status_y = client_y + client_h - STATUS_BAR_HEIGHT;
    let log_status_y = log_y + client_h - STATUS_BAR_HEIGHT;
    paint_status_bar_surf(&surf, hdc, client_x, status_y, client_w, log_x, log_status_y, browser);

    // Paint tooltip (on top of everything)
    if browser.tooltip_visible {
        paint_tooltip_surf(&surf, hdc, browser.hover_x + offset.x, browser.hover_y + offset.y, browser);
    }
}

/// Paint tooltip for hovered file item
fn paint_tooltip_surf(surf: &surface::Surface, hdc: HDC, x: i32, y: i32, browser: &FileBrowser) {
    if let Some((text, len)) = browser.get_tooltip_text() {
        // Tooltip colors
        let bg_color = ColorRef::rgb(255, 255, 225); // Light yellow
        let border_color = ColorRef::rgb(0, 0, 0);
        let text_color = ColorRef::rgb(0, 0, 0);

        // Calculate tooltip size (simple estimate: 8 pixels per character, max 200 wide)
        // Count lines and max line length
        let text_slice = &text[..len];
        let mut max_line_width = 0i32;
        let mut line_count = 1i32;
        let mut current_line_len = 0i32;

        for &b in text_slice {
            if b == b'\n' {
                if current_line_len > max_line_width {
                    max_line_width = current_line_len;
                }
                current_line_len = 0;
                line_count += 1;
            } else {
                current_line_len += 1;
            }
        }
        if current_line_len > max_line_width {
            max_line_width = current_line_len;
        }

        let tip_w = (max_line_width * 8).max(80).min(300) + 8; // padding
        let tip_h = line_count * 16 + 4; // 16 pixels per line + padding

        // Position tooltip below and to the right of cursor
        let tip_x = x + 16;
        let tip_y = y + 20;

        // Draw background
        let tip_rect = Rect::new(tip_x, tip_y, tip_x + tip_w, tip_y + tip_h);
        surf.fill_rect(&tip_rect, bg_color);

        // Draw border
        surf.hline(tip_x, tip_x + tip_w - 1, tip_y, border_color);
        surf.hline(tip_x, tip_x + tip_w - 1, tip_y + tip_h - 1, border_color);
        surf.vline(tip_x, tip_y, tip_y + tip_h - 1, border_color);
        surf.vline(tip_x + tip_w - 1, tip_y, tip_y + tip_h - 1, border_color);

        // Draw text (line by line)
        dc::set_text_color(hdc, text_color);
        dc::set_bk_mode(hdc, BkMode::Transparent);
        let mut text_y = tip_y + 2;
        let text_x = tip_x + 4;
        let mut line_start = 0;

        for i in 0..len {
            if text[i] == b'\n' || i == len - 1 {
                let line_end = if text[i] == b'\n' { i } else { i + 1 };
                if let Ok(line_str) = core::str::from_utf8(&text[line_start..line_end]) {
                    gdi::text_out(hdc, text_x, text_y, line_str);
                }
                line_start = i + 1;
                text_y += 16;
            }
        }
    }
}

/// Paint the details panel (right side info panel)
fn paint_details_panel_surf(surf: &surface::Surface, hdc: HDC, sx: i32, sy: i32, w: i32, h: i32, lx: i32, ly: i32, browser: &FileBrowser) {
    // Background
    let panel_rect = Rect::new(sx, sy, sx + w, sy + h);
    surf.fill_rect(&panel_rect, ColorRef::rgb(241, 243, 248)); // Light blue-gray

    // Left border (separator)
    surf.vline(sx, sy, sy + h, ColorRef::rgb(172, 168, 153));

    // Set text colors
    dc::set_text_color(hdc, ColorRef::rgb(0, 51, 153)); // Dark blue for headings
    dc::set_bk_mode(hdc, BkMode::Transparent);

    let text_x = lx + 8;
    let mut text_y = ly + 12;

    if browser.selection_count == 0 {
        // No selection - show folder info
        gdi::text_out(hdc, text_x, text_y, "Folder Tasks");
        text_y += 24;

        dc::set_text_color(hdc, ColorRef::rgb(0, 0, 0));
        let item_count_buf = format_item_count(browser.item_count);
        if let Ok(s) = core::str::from_utf8(&item_count_buf) {
            let trimmed = s.trim_end_matches('\0');
            gdi::text_out(hdc, text_x, text_y, trimmed);
        }
    } else if browser.selection_count == 1 {
        // Single selection - show details
        gdi::text_out(hdc, text_x, text_y, "File Details");
        text_y += 24;

        dc::set_text_color(hdc, ColorRef::rgb(0, 0, 0));

        // Find the selected item
        if let Some(idx) = browser.get_first_selected() {
            let item = &browser.items[idx];

            // Name (truncated if needed)
            let name = item.name_str();
            let display_name = if name.len() > 18 {
                &name[..15]
            } else {
                name
            };
            gdi::text_out(hdc, text_x, text_y, display_name);
            if name.len() > 18 {
                gdi::text_out(hdc, text_x + 15 * 7, text_y, "...");
            }
            text_y += 18;

            // Type
            let type_label: &[u8] = if item.is_directory {
                b"File Folder"
            } else {
                match item.icon_type {
                    VfsIconType::Executable => b"Application",
                    VfsIconType::Document => b"Document",
                    VfsIconType::Image => b"Image",
                    VfsIconType::Audio => b"Audio",
                    VfsIconType::Video => b"Video",
                    _ => b"File",
                }
            };
            if let Ok(type_str) = core::str::from_utf8(type_label) {
                gdi::text_out(hdc, text_x, text_y, type_str);
            }
            text_y += 18;

            // Size (for files only)
            if !item.is_directory {
                let size_buf = format_size_for_details(item.size);
                if let Ok(s) = core::str::from_utf8(&size_buf) {
                    let trimmed = s.trim_end_matches('\0');
                    gdi::text_out(hdc, text_x, text_y, trimmed);
                }
                text_y += 18;
            }

            // Date modified
            text_y += 8;
            dc::set_text_color(hdc, ColorRef::rgb(80, 80, 80));
            gdi::text_out(hdc, text_x, text_y, "Modified:");
            text_y += 16;
            gdi::text_out(hdc, text_x, text_y, "--/--/----");
        }
    } else {
        // Multiple selection - show summary
        gdi::text_out(hdc, text_x, text_y, "Selection");
        text_y += 24;

        dc::set_text_color(hdc, ColorRef::rgb(0, 0, 0));

        // Count
        let count_buf = format_selection_count(browser.selection_count);
        if let Ok(s) = core::str::from_utf8(&count_buf) {
            let trimmed = s.trim_end_matches('\0');
            gdi::text_out(hdc, text_x, text_y, trimmed);
        }
        text_y += 18;

        // Calculate total size
        let mut total_size: u64 = 0;
        let mut folder_count = 0;
        let mut file_count = 0;
        for i in 0..browser.item_count {
            if browser.is_selected(i) {
                let item = &browser.items[i];
                if item.is_directory {
                    folder_count += 1;
                } else {
                    file_count += 1;
                    total_size += item.size;
                }
            }
        }

        // Show breakdown
        if folder_count > 0 && file_count > 0 {
            let mut buf = [0u8; 32];
            let mut pos = 0;
            pos = write_number(folder_count, &mut buf, pos);
            let f_label: &[u8] = if folder_count == 1 { b" folder" } else { b" folders" };
            for &b in f_label { if pos < 31 { buf[pos] = b; pos += 1; } }
            if let Ok(s) = core::str::from_utf8(&buf[..pos]) {
                gdi::text_out(hdc, text_x, text_y, s);
            }
            text_y += 16;

            pos = 0;
            pos = write_number(file_count, &mut buf, pos);
            let fl_label: &[u8] = if file_count == 1 { b" file" } else { b" files" };
            for &b in fl_label { if pos < 31 { buf[pos] = b; pos += 1; } }
            if let Ok(s) = core::str::from_utf8(&buf[..pos]) {
                gdi::text_out(hdc, text_x, text_y, s);
            }
            text_y += 16;
        }

        // Total size
        if total_size > 0 {
            text_y += 8;
            dc::set_text_color(hdc, ColorRef::rgb(80, 80, 80));
            gdi::text_out(hdc, text_x, text_y, "Total size:");
            text_y += 16;
            dc::set_text_color(hdc, ColorRef::rgb(0, 0, 0));
            let size_buf = format_size_for_details(total_size);
            if let Ok(s) = core::str::from_utf8(&size_buf) {
                let trimmed = s.trim_end_matches('\0');
                gdi::text_out(hdc, text_x, text_y, trimmed);
            }
        }
    }
}

/// Format item count for details panel
fn format_item_count(count: usize) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let mut pos = 0;
    pos = write_number(count, &mut buf, pos);
    let label: &[u8] = if count == 1 { b" item" } else { b" items" };
    for &b in label {
        if pos < 31 { buf[pos] = b; pos += 1; }
    }
    buf
}

/// Format selection count for details panel
fn format_selection_count(count: usize) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let mut pos = 0;
    pos = write_number(count, &mut buf, pos);
    let label: &[u8] = b" items selected";
    for &b in label {
        if pos < 31 { buf[pos] = b; pos += 1; }
    }
    buf
}

/// Format size for details panel display
fn format_size_for_details(size: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let _ = format_size(size, &mut buf, 0);
    buf
}

fn paint_toolbar_surf(surf: &surface::Surface, hdc: HDC, sx: i32, sy: i32, w: i32, lx: i32, ly: i32, browser: &FileBrowser) {
    // Background
    let toolbar_rect = Rect::new(sx, sy, sx + w, sy + TOOLBAR_HEIGHT);
    surf.fill_rect(&toolbar_rect, COLOR_TOOLBAR_BG);

    // Bottom border
    surf.hline(sx, sx + w, sy + TOOLBAR_HEIGHT - 1, ColorRef::rgb(128, 128, 128));

    // Draw buttons
    let buttons = ["<", ">", "^", "R", "V", "?"];
    let mut bx = sx + 4;
    let by = sy + 2;

    dc::set_text_color(hdc, ColorRef::rgb(0, 0, 0));
    dc::set_bk_mode(hdc, BkMode::Transparent);

    for (i, btn) in buttons.iter().enumerate() {
        let btn_rect = Rect::new(bx, by, bx + TOOLBAR_BTN_SIZE, by + TOOLBAR_BTN_SIZE);

        // Button background - highlight search button if active
        let bg_color = if i == 5 && browser.search_active {
            ColorRef::rgb(200, 220, 255) // Light blue when search is active
        } else {
            ColorRef::rgb(230, 230, 230)
        };
        surf.fill_rect(&btn_rect, bg_color);

        // 3D border effect
        surf.hline(bx, bx + TOOLBAR_BTN_SIZE, by, ColorRef::rgb(255, 255, 255));
        surf.vline(bx, by, by + TOOLBAR_BTN_SIZE, ColorRef::rgb(255, 255, 255));
        surf.hline(bx, bx + TOOLBAR_BTN_SIZE, by + TOOLBAR_BTN_SIZE - 1, ColorRef::rgb(128, 128, 128));
        surf.vline(bx + TOOLBAR_BTN_SIZE - 1, by, by + TOOLBAR_BTN_SIZE, ColorRef::rgb(128, 128, 128));

        // Draw text centered (use logical coords for text)
        let text_x = lx + 4 + (i as i32) * (TOOLBAR_BTN_SIZE + 2) + (TOOLBAR_BTN_SIZE - 8) / 2;
        let text_y = ly + 2 + (TOOLBAR_BTN_SIZE - 12) / 2;
        gdi::text_out(hdc, text_x, text_y, btn);

        bx += TOOLBAR_BTN_SIZE + 2;
    }

    // If search is active, draw search box after buttons
    if browser.search_active {
        let search_x = bx + 10;
        let search_w = 150;
        let search_rect = Rect::new(search_x, by + 2, search_x + search_w, by + TOOLBAR_BTN_SIZE - 2);
        surf.fill_rect(&search_rect, ColorRef::WHITE);

        // Border
        surf.hline(search_x, search_x + search_w, by + 2, ColorRef::rgb(128, 128, 128));
        surf.vline(search_x, by + 2, by + TOOLBAR_BTN_SIZE - 2, ColorRef::rgb(128, 128, 128));
        surf.hline(search_x, search_x + search_w, by + TOOLBAR_BTN_SIZE - 3, ColorRef::WHITE);
        surf.vline(search_x + search_w - 1, by + 2, by + TOOLBAR_BTN_SIZE - 2, ColorRef::WHITE);

        // Search text
        let query = browser.search_query_str();
        let text_x = lx + 4 + 6 * (TOOLBAR_BTN_SIZE + 2) + 12;
        let text_y = ly + 4;
        if query.is_empty() {
            dc::set_text_color(hdc, ColorRef::rgb(150, 150, 150));
            gdi::text_out(hdc, text_x, text_y, "Search...");
        } else {
            dc::set_text_color(hdc, ColorRef::rgb(0, 0, 0));
            let display = if query.len() > 18 { &query[..18] } else { query };
            gdi::text_out(hdc, text_x, text_y, display);
        }

        // Cursor
        let cursor_x = search_x + 2 + browser.search_cursor as i32 * 7;
        if cursor_x < search_x + search_w - 2 {
            surf.vline(cursor_x, by + 4, by + TOOLBAR_BTN_SIZE - 4, ColorRef::BLACK);
        }
    }
}

/// Address bar dropdown button width
pub const ADDRESS_DROPDOWN_WIDTH: i32 = 18;

fn paint_address_bar_surf(surf: &surface::Surface, hdc: HDC, sx: i32, sy: i32, w: i32, lx: i32, ly: i32, browser: &FileBrowser) {
    // Background
    let bar_rect = Rect::new(sx, sy, sx + w, sy + ADDRESS_BAR_HEIGHT);
    surf.fill_rect(&bar_rect, COLOR_TOOLBAR_BG);

    // Bottom border
    surf.hline(sx, sx + w, sy + ADDRESS_BAR_HEIGHT - 1, ColorRef::rgb(128, 128, 128));

    dc::set_text_color(hdc, ColorRef::rgb(0, 0, 0));
    dc::set_bk_mode(hdc, BkMode::Transparent);

    // Address label
    gdi::text_out(hdc, lx + 4, ly + 4, "Address:");

    // Address box (with space for dropdown button)
    let addr_box = Rect::new(sx + 60, sy + 2, sx + w - 4, sy + ADDRESS_BAR_HEIGHT - 2);
    surf.fill_rect(&addr_box, COLOR_ADDRESS_BG);

    // Sunken 3D border for address box
    surf.hline(sx + 60, sx + w - 4, sy + 2, ColorRef::rgb(128, 128, 128));
    surf.vline(sx + 60, sy + 2, sy + ADDRESS_BAR_HEIGHT - 2, ColorRef::rgb(128, 128, 128));
    surf.hline(sx + 60, sx + w - 4, sy + ADDRESS_BAR_HEIGHT - 3, ColorRef::rgb(255, 255, 255));
    surf.vline(sx + w - 5, sy + 2, sy + ADDRESS_BAR_HEIGHT - 2, ColorRef::rgb(255, 255, 255));

    // Dropdown button on right side of address box
    let btn_x = sx + w - 4 - ADDRESS_DROPDOWN_WIDTH;
    let btn_y = sy + 3;
    let btn_h = ADDRESS_BAR_HEIGHT - 6;

    // Button background
    let btn_rect = Rect::new(btn_x, btn_y, btn_x + ADDRESS_DROPDOWN_WIDTH - 1, btn_y + btn_h);
    surf.fill_rect(&btn_rect, COLOR_TOOLBAR_BG);

    // Button 3D raised border
    surf.hline(btn_x, btn_x + ADDRESS_DROPDOWN_WIDTH - 1, btn_y, ColorRef::rgb(255, 255, 255));
    surf.vline(btn_x, btn_y, btn_y + btn_h, ColorRef::rgb(255, 255, 255));
    surf.hline(btn_x, btn_x + ADDRESS_DROPDOWN_WIDTH - 1, btn_y + btn_h - 1, ColorRef::rgb(128, 128, 128));
    surf.vline(btn_x + ADDRESS_DROPDOWN_WIDTH - 2, btn_y, btn_y + btn_h, ColorRef::rgb(128, 128, 128));

    // Draw down arrow
    let arrow_x = btn_x + (ADDRESS_DROPDOWN_WIDTH - 2) / 2 - 3;
    let arrow_y = btn_y + btn_h / 2 - 2;
    draw_dropdown_arrow(surf, arrow_x, arrow_y);

    // Path text
    let path = if browser.path_len == 0 {
        "My Computer"
    } else {
        browser.path_str()
    };
    gdi::text_out(hdc, lx + 64, ly + 5, path);
}

/// Draw a small dropdown arrow
fn draw_dropdown_arrow(surf: &surface::Surface, x: i32, y: i32) {
    let color = ColorRef::rgb(0, 0, 0);
    // Draw a down-pointing triangle
    for i in 0..4 {
        surf.hline(x + i, x + 7 - i, y + i, color);
    }
}

fn paint_headers_surf(surf: &surface::Surface, hdc: HDC, sx: i32, sy: i32, w: i32, lx: i32, ly: i32, browser: &FileBrowser) {
    // Background
    let header_rect = Rect::new(sx, sy, sx + w, sy + HEADER_HEIGHT);
    surf.fill_rect(&header_rect, COLOR_HEADER_BG);

    // Bottom border
    surf.hline(sx, sx + w, sy + HEADER_HEIGHT - 1, ColorRef::rgb(128, 128, 128));

    // Column headers with sort column index
    let column_names: [(&str, SortColumn); 4] = [
        ("Name", SortColumn::Name),
        ("Size", SortColumn::Size),
        ("Type", SortColumn::Type),
        ("Date Modified", SortColumn::Modified),
    ];

    dc::set_text_color(hdc, ColorRef::rgb(0, 0, 0));
    dc::set_bk_mode(hdc, BkMode::Transparent);

    let mut cx = lx + 4;
    let mut screen_x = sx + 4;

    for (i, (name, sort_col)) in column_names.iter().enumerate() {
        let width = browser.column_widths[i];

        // Draw column name
        gdi::text_out(hdc, cx, ly + 3, name);

        // Draw sort indicator if this column is sorted
        if browser.sort_column == *sort_col {
            let arrow_x = screen_x + width - 16;
            let arrow_y = sy + HEADER_HEIGHT / 2;

            if browser.sort_ascending {
                // Up arrow (ascending)
                draw_sort_arrow(surf, arrow_x, arrow_y, true);
            } else {
                // Down arrow (descending)
                draw_sort_arrow(surf, arrow_x, arrow_y, false);
            }
        }

        // Draw separator line
        let sep_x = screen_x + width - 1;
        surf.vline(sep_x, sy + 2, sy + HEADER_HEIGHT - 2, ColorRef::rgb(128, 128, 128));

        cx += width;
        screen_x += width;
    }
}

/// Draw a small sort arrow (up or down)
fn draw_sort_arrow(surf: &surface::Surface, x: i32, y: i32, up: bool) {
    let color = ColorRef::rgb(80, 80, 80);

    if up {
        // Up arrow: point at top
        //     *
        //    ***
        //   *****
        surf.set_pixel(x + 3, y - 3, color);
        surf.set_pixel(x + 2, y - 2, color);
        surf.set_pixel(x + 3, y - 2, color);
        surf.set_pixel(x + 4, y - 2, color);
        surf.set_pixel(x + 1, y - 1, color);
        surf.set_pixel(x + 2, y - 1, color);
        surf.set_pixel(x + 3, y - 1, color);
        surf.set_pixel(x + 4, y - 1, color);
        surf.set_pixel(x + 5, y - 1, color);
        surf.set_pixel(x, y, color);
        surf.set_pixel(x + 1, y, color);
        surf.set_pixel(x + 2, y, color);
        surf.set_pixel(x + 3, y, color);
        surf.set_pixel(x + 4, y, color);
        surf.set_pixel(x + 5, y, color);
        surf.set_pixel(x + 6, y, color);
    } else {
        // Down arrow: point at bottom
        //   *****
        //    ***
        //     *
        surf.set_pixel(x, y - 2, color);
        surf.set_pixel(x + 1, y - 2, color);
        surf.set_pixel(x + 2, y - 2, color);
        surf.set_pixel(x + 3, y - 2, color);
        surf.set_pixel(x + 4, y - 2, color);
        surf.set_pixel(x + 5, y - 2, color);
        surf.set_pixel(x + 6, y - 2, color);
        surf.set_pixel(x + 1, y - 1, color);
        surf.set_pixel(x + 2, y - 1, color);
        surf.set_pixel(x + 3, y - 1, color);
        surf.set_pixel(x + 4, y - 1, color);
        surf.set_pixel(x + 5, y - 1, color);
        surf.set_pixel(x + 2, y, color);
        surf.set_pixel(x + 3, y, color);
        surf.set_pixel(x + 4, y, color);
        surf.set_pixel(x + 3, y + 1, color);
    }
}

fn paint_file_list_surf(surf: &surface::Surface, hdc: HDC, sx: i32, sy: i32, w: i32, h: i32, lx: i32, ly: i32, browser: &FileBrowser) {
    // Background
    let content_rect = Rect::new(sx, sy, sx + w, sy + h);
    surf.fill_rect(&content_rect, COLOR_LIST_BG);

    if browser.item_count == 0 {
        // Empty folder message
        dc::set_text_color(hdc, ColorRef::rgb(128, 128, 128));
        dc::set_bk_mode(hdc, BkMode::Transparent);
        gdi::text_out(hdc, lx + 10, ly + 10, "(Empty)");
        return;
    }

    match browser.view_mode {
        ViewMode::Details => paint_details_view_surf(surf, hdc, sx, sy, w, h, lx, ly, browser),
        ViewMode::List => paint_list_view_surf(surf, hdc, sx, sy, w, h, lx, ly, browser),
        ViewMode::Thumbnails => paint_thumbnail_view_surf(surf, hdc, sx, sy, w, h, lx, ly, browser),
        _ => paint_icon_view_surf(surf, hdc, sx, sy, w, h, lx, ly, browser),
    }
}

fn paint_details_view_surf(surf: &surface::Surface, hdc: HDC, sx: i32, sy: i32, w: i32, h: i32, lx: i32, ly: i32, browser: &FileBrowser) {
    let (first, last) = browser.get_visible_range(h);

    let mut row_y = sy - (browser.scroll_y % DETAILS_ROW_HEIGHT);
    let mut log_y = ly - (browser.scroll_y % DETAILS_ROW_HEIGHT);

    // Calculate column positions from dynamic widths
    let name_x = lx + 24; // Icon area + padding
    let size_x = lx + 4 + browser.column_widths[0];
    let type_x = size_x + browser.column_widths[1];
    let date_x = type_x + browser.column_widths[2];

    dc::set_bk_mode(hdc, BkMode::Transparent);

    for i in first..last {
        if row_y >= sy + h {
            break;
        }

        let item = &browser.items[i];
        let is_match = browser.is_search_match(i);
        let row_rect = Rect::new(sx, row_y, sx + w, row_y + DETAILS_ROW_HEIGHT);

        // Skip non-matching items in search mode (or dim them)
        if !is_match {
            // Dim non-matching items
            dc::set_text_color(hdc, ColorRef::rgb(180, 180, 180));
            draw_small_icon_surf(surf, sx + 4, row_y + 1, item);
            gdi::text_out(hdc, name_x, log_y + 2, item.name_str());
            row_y += DETAILS_ROW_HEIGHT;
            log_y += DETAILS_ROW_HEIGHT;
            continue;
        }

        // Selected background
        if browser.is_selected(i) {
            surf.fill_rect(&row_rect, COLOR_SELECTED);
            dc::set_text_color(hdc, COLOR_SELECTED_TEXT);
        } else {
            dc::set_text_color(hdc, ColorRef::rgb(0, 0, 0));
        }

        // Focus indicator (dotted border or highlight)
        if i as i32 == browser.focus_index && browser.selection_count > 1 {
            // Draw focus indicator for multi-select
            surf.hline(sx, sx + w, row_y, ColorRef::rgb(0, 0, 128));
            surf.hline(sx, sx + w, row_y + DETAILS_ROW_HEIGHT - 1, ColorRef::rgb(0, 0, 128));
        }

        // Draw small icon
        draw_small_icon_surf(surf, sx + 4, row_y + 1, item);

        // Name
        gdi::text_out(hdc, name_x, log_y + 2, item.name_str());

        // Size
        if !item.is_directory {
            let mut size_buf = [0u8; 32];
            let size_len = item.format_size(&mut size_buf);
            if let Ok(size_str) = core::str::from_utf8(&size_buf[..size_len]) {
                gdi::text_out(hdc, size_x, log_y + 2, size_str);
            }
        }

        // Type
        let type_str = item.get_type_name();
        gdi::text_out(hdc, type_x, log_y + 2, type_str);

        // Date (placeholder)
        gdi::text_out(hdc, date_x, log_y + 2, "--");

        row_y += DETAILS_ROW_HEIGHT;
        log_y += DETAILS_ROW_HEIGHT;
    }
}

fn paint_list_view_surf(surf: &surface::Surface, hdc: HDC, sx: i32, sy: i32, w: i32, h: i32, lx: i32, ly: i32, browser: &FileBrowser) {
    let mut row_y = sy;
    let mut log_y = ly;

    dc::set_bk_mode(hdc, BkMode::Transparent);

    for (i, item) in browser.items[..browser.item_count].iter().enumerate() {
        if row_y >= sy + h {
            break;
        }

        let row_rect = Rect::new(sx, row_y, sx + w, row_y + LIST_ITEM_HEIGHT);

        // Selected background
        if browser.is_selected(i) {
            surf.fill_rect(&row_rect, COLOR_SELECTED);
            dc::set_text_color(hdc, COLOR_SELECTED_TEXT);
        } else {
            dc::set_text_color(hdc, ColorRef::rgb(0, 0, 0));
        }

        // Icon
        draw_small_icon_surf(surf, sx + 4, row_y, item);

        // Name
        gdi::text_out(hdc, lx + 24, log_y + 1, item.name_str());

        row_y += LIST_ITEM_HEIGHT;
        log_y += LIST_ITEM_HEIGHT;
    }
}

fn paint_icon_view_surf(surf: &surface::Surface, hdc: HDC, sx: i32, sy: i32, w: i32, h: i32, lx: i32, ly: i32, browser: &FileBrowser) {
    let mut icon_x = sx + 10;
    let mut icon_y = sy + 10;
    let mut log_x = lx + 10;
    let mut log_y = ly + 10;
    let max_x = sx + w - ICON_GRID_WIDTH;

    dc::set_bk_mode(hdc, BkMode::Transparent);

    for (i, item) in browser.items[..browser.item_count].iter().enumerate() {
        if icon_y >= sy + h {
            break;
        }

        // Selected background
        let icon_rect = Rect::new(icon_x, icon_y, icon_x + ICON_GRID_WIDTH - 10, icon_y + ICON_GRID_HEIGHT - 10);
        if browser.is_selected(i) {
            surf.fill_rect(&icon_rect, COLOR_SELECTED);
            dc::set_text_color(hdc, COLOR_SELECTED_TEXT);
        } else {
            dc::set_text_color(hdc, ColorRef::rgb(0, 0, 0));
        }

        // Draw large icon placeholder
        let icon_offset_x = (ICON_GRID_WIDTH - LARGE_ICON_SIZE) / 2;
        draw_large_icon_surf(surf, icon_x + icon_offset_x, icon_y + 2, item);

        // Name (centered, truncated)
        let name = item.name_str();
        let display_name = if name.len() > 12 {
            &name[..12]
        } else {
            name
        };
        let text_x = log_x + (ICON_GRID_WIDTH - display_name.len() as i32 * 7) / 2;
        gdi::text_out(hdc, text_x, log_y + LARGE_ICON_SIZE + 4, display_name);

        icon_x += ICON_GRID_WIDTH;
        log_x += ICON_GRID_WIDTH;
        if icon_x > max_x {
            icon_x = sx + 10;
            log_x = lx + 10;
            icon_y += ICON_GRID_HEIGHT;
            log_y += ICON_GRID_HEIGHT;
        }
    }
}

/// Paint thumbnail view with extra large icons (64x64) and file type previews
fn paint_thumbnail_view_surf(surf: &surface::Surface, hdc: HDC, sx: i32, sy: i32, w: i32, h: i32, lx: i32, ly: i32, browser: &FileBrowser) {
    let mut thumb_x = sx + 10;
    let mut thumb_y = sy + 10;
    let mut log_x = lx + 10;
    let mut log_y = ly + 10;
    let max_x = sx + w - THUMBNAIL_GRID_WIDTH;

    dc::set_bk_mode(hdc, BkMode::Transparent);

    for (i, item) in browser.items[..browser.item_count].iter().enumerate() {
        if thumb_y >= sy + h {
            break;
        }

        // Selection background with rounded feel
        let thumb_rect = Rect::new(thumb_x, thumb_y, thumb_x + THUMBNAIL_GRID_WIDTH - 10, thumb_y + THUMBNAIL_GRID_HEIGHT - 10);
        if browser.is_selected(i) {
            surf.fill_rect(&thumb_rect, COLOR_SELECTED);
            dc::set_text_color(hdc, COLOR_SELECTED_TEXT);
        } else {
            dc::set_text_color(hdc, ColorRef::rgb(0, 0, 0));
        }

        // Draw thumbnail box with border (simulates image preview area)
        let thumb_box_x = thumb_x + (THUMBNAIL_GRID_WIDTH - THUMBNAIL_SIZE) / 2;
        let thumb_box_y = thumb_y + 4;
        let thumb_box = Rect::new(thumb_box_x, thumb_box_y, thumb_box_x + THUMBNAIL_SIZE, thumb_box_y + THUMBNAIL_SIZE);

        // Light gray background for thumbnail area
        surf.fill_rect(&thumb_box, ColorRef::rgb(245, 245, 245));

        // Draw border around thumbnail area
        let border_color = if browser.is_selected(i) {
            ColorRef::rgb(120, 150, 200)
        } else {
            ColorRef::rgb(180, 180, 180)
        };
        surf.hline(thumb_box_x, thumb_box_x + THUMBNAIL_SIZE, thumb_box_y, border_color);
        surf.hline(thumb_box_x, thumb_box_x + THUMBNAIL_SIZE, thumb_box_y + THUMBNAIL_SIZE - 1, border_color);
        surf.vline(thumb_box_x, thumb_box_y, thumb_box_y + THUMBNAIL_SIZE, border_color);
        surf.vline(thumb_box_x + THUMBNAIL_SIZE - 1, thumb_box_y, thumb_box_y + THUMBNAIL_SIZE, border_color);

        // Draw the actual thumbnail icon (centered in box)
        let icon_offset = (THUMBNAIL_SIZE - 48) / 2; // 48px icon within 64px box
        draw_thumbnail_icon_surf(surf, thumb_box_x + icon_offset, thumb_box_y + icon_offset, item);

        // Name (centered below thumbnail, 2 lines max)
        let name = item.name_str();
        let max_chars = (THUMBNAIL_GRID_WIDTH / 7) as usize;
        let display_name = if name.len() > max_chars {
            &name[..max_chars.min(name.len())]
        } else {
            name
        };
        let text_x = log_x + (THUMBNAIL_GRID_WIDTH - display_name.len() as i32 * 7) / 2;
        gdi::text_out(hdc, text_x, log_y + THUMBNAIL_SIZE + 8, display_name);

        // File type on second line for files (not directories)
        if !item.is_directory {
            let type_name = match item.icon_type {
                VfsIconType::Image => "Image",
                VfsIconType::Audio => "Audio",
                VfsIconType::Video => "Video",
                VfsIconType::Document => "Doc",
                VfsIconType::Executable => "App",
                _ => "File",
            };
            let type_x = log_x + (THUMBNAIL_GRID_WIDTH - type_name.len() as i32 * 7) / 2;
            dc::set_text_color(hdc, ColorRef::rgb(100, 100, 100));
            gdi::text_out(hdc, type_x, log_y + THUMBNAIL_SIZE + 22, type_name);
            // Restore text color for next item
            if browser.is_selected(i) {
                dc::set_text_color(hdc, COLOR_SELECTED_TEXT);
            } else {
                dc::set_text_color(hdc, ColorRef::rgb(0, 0, 0));
            }
        }

        thumb_x += THUMBNAIL_GRID_WIDTH;
        log_x += THUMBNAIL_GRID_WIDTH;
        if thumb_x > max_x {
            thumb_x = sx + 10;
            log_x = lx + 10;
            thumb_y += THUMBNAIL_GRID_HEIGHT;
            log_y += THUMBNAIL_GRID_HEIGHT;
        }
    }
}

/// Draw a thumbnail-sized icon (48x48) with type-specific preview styling
fn draw_thumbnail_icon_surf(surf: &surface::Surface, x: i32, y: i32, item: &FileItem) {
    let size = 48;

    if item.is_directory {
        // Large folder icon with more detail
        draw_folder_icon(surf, x, y, size);
    } else {
        // Draw document with type-specific preview
        match item.icon_type {
            VfsIconType::Image => {
                // Image preview: colorful landscape placeholder
                let bg = Rect::new(x + 2, y + 2, x + size - 2, y + size - 2);
                surf.fill_rect(&bg, ColorRef::rgb(135, 206, 235)); // Sky blue

                // Simple "mountain" shape
                let mountain_color = ColorRef::rgb(100, 130, 80);
                for row in 0..15 {
                    let row_width = row * 2;
                    let start_x = x + size / 2 - row_width / 2;
                    surf.hline(start_x, start_x + row_width, y + size - 8 - row, mountain_color);
                }

                // Sun
                let sun_rect = Rect::new(x + size - 16, y + 6, x + size - 6, y + 16);
                surf.fill_rect(&sun_rect, ColorRef::rgb(255, 220, 100));
            }
            VfsIconType::Audio => {
                // Audio preview: music note symbol
                let bg = Rect::new(x + 2, y + 2, x + size - 2, y + size - 2);
                surf.fill_rect(&bg, ColorRef::rgb(150, 100, 200));

                // Draw simple music note
                let note_color = ColorRef::rgb(255, 255, 255);
                // Note head (filled circle approximation)
                let head_rect = Rect::new(x + 12, y + 28, x + 22, y + 38);
                surf.fill_rect(&head_rect, note_color);
                // Note stem
                surf.vline(x + 21, y + 12, y + 32, note_color);
                surf.vline(x + 22, y + 12, y + 32, note_color);
                // Flag
                surf.hline(x + 22, x + 32, y + 12, note_color);
                surf.hline(x + 22, x + 30, y + 13, note_color);
                surf.hline(x + 22, x + 28, y + 14, note_color);
            }
            VfsIconType::Video => {
                // Video preview: film strip / play button
                let bg = Rect::new(x + 2, y + 2, x + size - 2, y + size - 2);
                surf.fill_rect(&bg, ColorRef::rgb(50, 50, 60));

                // Play triangle
                let play_color = ColorRef::rgb(255, 255, 255);
                for col in 0..18 {
                    let height = col;
                    let start_y = y + size / 2 - height / 2;
                    surf.vline(x + 14 + col, start_y, start_y + height, play_color);
                }
            }
            VfsIconType::Executable => {
                // Executable: gear/cog or window icon
                let bg = Rect::new(x + 2, y + 2, x + size - 2, y + size - 2);
                surf.fill_rect(&bg, ColorRef::rgb(100, 200, 100));

                // Simple window icon
                let win_color = ColorRef::rgb(255, 255, 255);
                let win_rect = Rect::new(x + 8, y + 8, x + size - 8, y + size - 8);
                surf.fill_rect(&win_rect, win_color);

                // Title bar
                let title_rect = Rect::new(x + 8, y + 8, x + size - 8, y + 16);
                surf.fill_rect(&title_rect, ColorRef::rgb(0, 80, 160));
            }
            VfsIconType::Document => {
                // Document with lines
                let bg = Rect::new(x + 2, y + 2, x + size - 2, y + size - 2);
                surf.fill_rect(&bg, ColorRef::rgb(255, 255, 255));

                // Page fold corner
                let fold = Rect::new(x + size - 14, y + 2, x + size - 2, y + 14);
                surf.fill_rect(&fold, ColorRef::rgb(220, 220, 220));

                // Text lines
                let line_color = ColorRef::rgb(180, 180, 180);
                for line in 0..5 {
                    let line_y = y + 18 + line * 6;
                    let line_width = if line == 4 { 20 } else { 36 };
                    surf.hline(x + 6, x + 6 + line_width, line_y, line_color);
                }

                // Border
                surf.hline(x + 2, x + size - 2, y + 2, ColorRef::rgb(160, 160, 160));
                surf.hline(x + 2, x + size - 2, y + size - 3, ColorRef::rgb(160, 160, 160));
                surf.vline(x + 2, y + 2, y + size - 2, ColorRef::rgb(160, 160, 160));
                surf.vline(x + size - 3, y + 14, y + size - 2, ColorRef::rgb(160, 160, 160));
            }
            _ => {
                // Generic file
                draw_document_icon(surf, x, y, size, ColorRef::rgb(200, 200, 200), item.icon_type);
            }
        }
    }
}

fn draw_large_icon_surf(surf: &surface::Surface, x: i32, y: i32, item: &FileItem) {
    if item.is_directory {
        // Draw folder icon
        draw_folder_icon(surf, x, y, LARGE_ICON_SIZE);
    } else {
        // Draw document icon with type-specific color
        let color = match item.icon_type {
            VfsIconType::Executable => ColorRef::rgb(100, 200, 100), // Green
            VfsIconType::Image => ColorRef::rgb(100, 150, 255),      // Blue
            VfsIconType::Audio => ColorRef::rgb(150, 100, 200),      // Purple
            VfsIconType::Video => ColorRef::rgb(200, 150, 100),      // Orange-ish
            VfsIconType::Document => ColorRef::rgb(200, 200, 200),   // Gray
            _ => ColorRef::rgb(220, 220, 220),                       // Light gray
        };
        draw_document_icon(surf, x, y, LARGE_ICON_SIZE, color, item.icon_type);
    }
}

/// Draw a small (16x16) icon for details/list views
fn draw_small_icon_surf(surf: &surface::Surface, x: i32, y: i32, item: &FileItem) {
    if item.is_directory {
        // Small folder icon
        let folder_color = ColorRef::rgb(255, 210, 80);
        let folder_dark = ColorRef::rgb(200, 170, 60);

        // Folder body
        let body = Rect::new(x + 1, y + 4, x + 14, y + 13);
        surf.fill_rect(&body, folder_color);

        // Folder tab
        let tab = Rect::new(x + 1, y + 2, x + 7, y + 5);
        surf.fill_rect(&tab, folder_color);

        // Highlight and shadow
        surf.hline(x + 1, x + 14, y + 4, ColorRef::rgb(255, 230, 150));
        surf.hline(x + 1, x + 14, y + 12, folder_dark);
        surf.vline(x + 13, y + 4, y + 13, folder_dark);
    } else {
        // Small document icon
        let doc_light = ColorRef::rgb(255, 255, 255);
        let doc_shadow = ColorRef::rgb(128, 128, 128);

        // Document body
        let body = Rect::new(x + 2, y + 1, x + 13, y + 14);
        surf.fill_rect(&body, doc_light);

        // Corner fold
        let fold = Rect::new(x + 10, y + 1, x + 13, y + 4);
        surf.fill_rect(&fold, ColorRef::rgb(200, 200, 200));

        // Border
        surf.hline(x + 2, x + 10, y + 1, doc_shadow);
        surf.vline(x + 2, y + 1, y + 14, doc_shadow);
        surf.hline(x + 2, x + 13, y + 13, doc_shadow);
        surf.vline(x + 12, y + 4, y + 14, doc_shadow);

        // Type indicator color
        let color = match item.icon_type {
            VfsIconType::Executable => ColorRef::rgb(100, 200, 100),
            VfsIconType::Image => ColorRef::rgb(100, 150, 255),
            VfsIconType::Audio => ColorRef::rgb(150, 100, 200),
            VfsIconType::Video => ColorRef::rgb(200, 150, 100),
            _ => ColorRef::rgb(180, 180, 180),
        };

        // Draw type indicator (small lines or color bar)
        surf.hline(x + 4, x + 10, y + 6, color);
        surf.hline(x + 4, x + 10, y + 8, color);
        surf.hline(x + 4, x + 8, y + 10, color);
    }
}

/// Draw a folder icon shape
fn draw_folder_icon(surf: &surface::Surface, x: i32, y: i32, size: i32) {
    let folder_color = ColorRef::rgb(255, 210, 80);
    let folder_dark = ColorRef::rgb(200, 170, 60);
    let folder_light = ColorRef::rgb(255, 230, 150);

    // Folder body (lower part)
    let body_top = y + size / 5;
    let body = Rect::new(x + 2, body_top, x + size - 2, y + size - 2);
    surf.fill_rect(&body, folder_color);

    // Folder tab (upper left part)
    let tab_width = size / 2;
    let tab = Rect::new(x + 2, y + 2, x + 2 + tab_width, body_top + 2);
    surf.fill_rect(&tab, folder_color);

    // Highlight (top edge of body)
    surf.hline(x + 2, x + size - 2, body_top, folder_light);

    // Shadow (bottom and right edges)
    surf.hline(x + 2, x + size - 2, y + size - 3, folder_dark);
    surf.vline(x + size - 3, body_top, y + size - 2, folder_dark);
}

/// Draw a document icon shape
fn draw_document_icon(surf: &surface::Surface, x: i32, y: i32, size: i32, color: ColorRef, icon_type: VfsIconType) {
    let doc_light = ColorRef::rgb(255, 255, 255);
    let doc_shadow = ColorRef::rgb(128, 128, 128);

    // Main document body (with corner fold)
    let fold_size = size / 4;
    let doc_left = x + 4;
    let doc_right = x + size - 4;
    let doc_top = y + 2;
    let doc_bottom = y + size - 2;

    // White document background
    let main_rect = Rect::new(doc_left, doc_top, doc_right, doc_bottom);
    surf.fill_rect(&main_rect, doc_light);

    // Fill corner fold area (top-right corner)
    let fold_rect = Rect::new(doc_right - fold_size, doc_top, doc_right, doc_top + fold_size);
    surf.fill_rect(&fold_rect, ColorRef::rgb(200, 200, 200));

    // Draw fold lines
    // Diagonal line for fold
    for i in 0..fold_size {
        surf.set_pixel(doc_right - fold_size + i, doc_top + i, doc_shadow);
    }

    // Document border
    surf.hline(doc_left, doc_right - fold_size, doc_top, doc_shadow);
    surf.vline(doc_left, doc_top, doc_bottom, doc_shadow);
    surf.hline(doc_left, doc_right, doc_bottom, doc_shadow);
    surf.vline(doc_right, doc_top + fold_size, doc_bottom, doc_shadow);

    // Draw type indicator in center
    let cx = x + size / 2;
    let cy = y + size / 2 + 2;

    match icon_type {
        VfsIconType::Executable => {
            // Draw a gear/cog pattern for executables
            draw_exe_symbol(surf, cx, cy, color);
        }
        VfsIconType::Image => {
            // Draw a simple landscape for images
            draw_image_symbol(surf, cx, cy, color);
        }
        VfsIconType::Audio => {
            // Draw a musical note for audio
            draw_audio_symbol(surf, cx, cy, color);
        }
        VfsIconType::Video => {
            // Draw a film strip for video
            draw_video_symbol(surf, cx, cy, color);
        }
        VfsIconType::Document => {
            // Draw text lines for documents
            draw_text_lines(surf, doc_left + 2, doc_top + 4, size - 12, doc_shadow);
        }
        _ => {
            // Generic file - just draw text lines
            draw_text_lines(surf, doc_left + 2, doc_top + 4, size - 12, ColorRef::rgb(180, 180, 180));
        }
    }
}

fn draw_text_lines(surf: &surface::Surface, x: i32, y: i32, width: i32, color: ColorRef) {
    // Draw 4 horizontal lines to represent text
    for i in 0..4 {
        let line_width = if i == 3 { width / 2 } else { width - 4 };
        surf.hline(x, x + line_width, y + i * 4, color);
    }
}

fn draw_exe_symbol(surf: &surface::Surface, cx: i32, cy: i32, color: ColorRef) {
    // Draw a simple gear shape
    for i in -3..=3 {
        surf.set_pixel(cx + i, cy - 3, color);
        surf.set_pixel(cx + i, cy + 3, color);
        surf.set_pixel(cx - 3, cy + i, color);
        surf.set_pixel(cx + 3, cy + i, color);
    }
    // Inner box
    for i in -1..=1 {
        for j in -1..=1 {
            surf.set_pixel(cx + i, cy + j, color);
        }
    }
}

fn draw_image_symbol(surf: &surface::Surface, cx: i32, cy: i32, color: ColorRef) {
    // Draw a simple mountain/sun landscape
    let dark_color = ColorRef::rgb(50, 100, 50);
    // Mountain
    for i in 0..4 {
        surf.hline(cx - 4 + i, cx + 4 - i, cy + 2 - i, dark_color);
    }
    // Sun
    surf.set_pixel(cx + 3, cy - 2, ColorRef::rgb(255, 200, 0));
    surf.set_pixel(cx + 2, cy - 2, ColorRef::rgb(255, 200, 0));
    surf.set_pixel(cx + 3, cy - 3, ColorRef::rgb(255, 200, 0));
    surf.set_pixel(cx + 2, cy - 3, ColorRef::rgb(255, 200, 0));
}

fn draw_audio_symbol(surf: &surface::Surface, cx: i32, cy: i32, color: ColorRef) {
    // Draw a musical note
    surf.vline(cx + 2, cy - 4, cy + 2, color);
    surf.set_pixel(cx, cy + 2, color);
    surf.set_pixel(cx + 1, cy + 2, color);
    surf.set_pixel(cx + 1, cy + 3, color);
    surf.set_pixel(cx, cy + 3, color);
    // Note head
    surf.set_pixel(cx + 2, cy - 4, color);
    surf.set_pixel(cx + 3, cy - 4, color);
    surf.set_pixel(cx + 4, cy - 3, color);
}

fn draw_video_symbol(surf: &surface::Surface, cx: i32, cy: i32, color: ColorRef) {
    // Draw a film strip/camera
    let rect = Rect::new(cx - 4, cy - 3, cx + 4, cy + 3);
    surf.fill_rect(&rect, color);
    // Perforations
    let perf = ColorRef::rgb(255, 255, 255);
    surf.set_pixel(cx - 3, cy - 2, perf);
    surf.set_pixel(cx - 3, cy + 2, perf);
    surf.set_pixel(cx + 3, cy - 2, perf);
    surf.set_pixel(cx + 3, cy + 2, perf);
}

fn get_icon_str(item: &FileItem) -> &'static str {
    if item.is_directory {
        "D" // Folder
    } else {
        match item.icon_type {
            VfsIconType::Executable => "X",
            VfsIconType::Image => "I",
            VfsIconType::Audio => "A",
            VfsIconType::Video => "V",
            VfsIconType::Document => "W",
            _ => "F",
        }
    }
}

fn paint_status_bar_surf(surf: &surface::Surface, hdc: HDC, sx: i32, sy: i32, w: i32, lx: i32, ly: i32, browser: &FileBrowser) {
    // Background
    let status_rect = Rect::new(sx, sy, sx + w, sy + STATUS_BAR_HEIGHT);
    surf.fill_rect(&status_rect, COLOR_STATUS_BG);

    // Top border
    surf.hline(sx, sx + w, sy, ColorRef::rgb(128, 128, 128));

    // Status text
    let mut buf = [0u8; 64];
    let len = format_status(browser, &mut buf);
    dc::set_text_color(hdc, ColorRef::rgb(0, 0, 0));
    dc::set_bk_mode(hdc, BkMode::Transparent);
    if let Ok(status_str) = core::str::from_utf8(&buf[..len]) {
        gdi::text_out(hdc, lx + 4, ly + 3, status_str);
    }
}

fn format_status(browser: &FileBrowser, buf: &mut [u8]) -> usize {
    let mut pos = 0;

    // If items are selected, show detailed selection info
    if browser.selection_count > 0 {
        // Calculate totals for selected items
        let mut total_size: u64 = 0;
        let mut folder_count = 0;
        let mut file_count = 0;

        for i in 0..browser.item_count {
            if browser.is_selected(i) {
                let item = &browser.items[i];
                if item.is_directory {
                    folder_count += 1;
                } else {
                    file_count += 1;
                    total_size += item.size;
                }
            }
        }

        // Show detailed breakdown: "X folders, Y files selected"
        if folder_count > 0 && file_count > 0 {
            // Mixed selection
            pos = write_number(folder_count, buf, pos);
            let folder_suffix: &[u8] = if folder_count == 1 { b" folder, " } else { b" folders, " };
            for &b in folder_suffix {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
            pos = write_number(file_count, buf, pos);
            let file_suffix: &[u8] = if file_count == 1 { b" file selected" } else { b" files selected" };
            for &b in file_suffix {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
        } else if folder_count > 0 {
            // Only folders
            pos = write_number(folder_count, buf, pos);
            let suffix: &[u8] = if folder_count == 1 { b" folder selected" } else { b" folders selected" };
            for &b in suffix {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
        } else {
            // Only files
            pos = write_number(file_count, buf, pos);
            let suffix: &[u8] = if file_count == 1 { b" file selected" } else { b" files selected" };
            for &b in suffix {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
        }

        // Add size info if we have files
        if file_count > 0 && total_size > 0 {
            for &b in b" (" {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
            pos = format_size(total_size, buf, pos);
            if pos < buf.len() { buf[pos] = b')'; pos += 1; }
        }
    } else {
        // Show total item count with breakdown
        let mut folder_count = 0;
        let mut file_count = 0;
        let mut total_size: u64 = 0;
        for i in 0..browser.item_count {
            let item = &browser.items[i];
            if item.is_directory {
                folder_count += 1;
            } else {
                file_count += 1;
                total_size += item.size;
            }
        }

        // "X folders, Y files" or just count if all same type
        if folder_count > 0 && file_count > 0 {
            pos = write_number(folder_count, buf, pos);
            let folder_label: &[u8] = if folder_count == 1 { b" folder, " } else { b" folders, " };
            for &b in folder_label {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
            pos = write_number(file_count, buf, pos);
            let file_label: &[u8] = if file_count == 1 { b" file" } else { b" files" };
            for &b in file_label {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
        } else if folder_count > 0 {
            pos = write_number(folder_count, buf, pos);
            let label: &[u8] = if folder_count == 1 { b" folder" } else { b" folders" };
            for &b in label {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
        } else if file_count > 0 {
            pos = write_number(file_count, buf, pos);
            let label: &[u8] = if file_count == 1 { b" file" } else { b" files" };
            for &b in label {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
        } else {
            // Empty folder
            for &b in b"(empty)" {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
        }

        // Show total size if there are files
        if file_count > 0 && total_size > 0 {
            for &b in b" (" {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
            pos = format_size(total_size, buf, pos);
            for &b in b" total)" {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
        }
    }

    // Add disk space info if we're viewing a drive
    if let Some(drive_letter) = get_drive_letter_from_path(&browser.path[..browser.path_len]) {
        if let Some(drive_info) = vfs::get_drive(drive_letter) {
            // Add separator
            for &b in b"  |  " {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
            // Format: "X.XX GB free of Y.YY GB"
            pos = format_size_mb(drive_info.free_mb, buf, pos);
            for &b in b" free of " {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
            pos = format_size_mb(drive_info.total_mb, buf, pos);
        }
    }

    pos
}

/// Extract drive letter from path (e.g., "C:\Windows" -> 'C')
fn get_drive_letter_from_path(path: &[u8]) -> Option<char> {
    if path.len() >= 2 && path[1] == b':' {
        let letter = path[0].to_ascii_uppercase();
        if letter >= b'A' && letter <= b'Z' {
            return Some(letter as char);
        }
    }
    None
}

/// Format size in MB to human readable format
fn format_size_mb(size_mb: u64, buf: &mut [u8], start: usize) -> usize {
    let mut pos = start;

    if size_mb >= 1024 {
        // Format as GB
        let gb_whole = size_mb / 1024;
        let gb_frac = ((size_mb % 1024) * 10) / 1024;
        pos = write_number(gb_whole as usize, buf, pos);
        if pos < buf.len() { buf[pos] = b'.'; pos += 1; }
        pos = write_number(gb_frac as usize, buf, pos);
        for &b in b" GB" {
            if pos < buf.len() { buf[pos] = b; pos += 1; }
        }
    } else {
        // Format as MB
        pos = write_number(size_mb as usize, buf, pos);
        for &b in b" MB" {
            if pos < buf.len() { buf[pos] = b; pos += 1; }
        }
    }

    pos
}

/// Format file size in human readable format (B, KB, MB, GB)
fn format_size(size: u64, buf: &mut [u8], start: usize) -> usize {
    let mut pos = start;

    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;

    if size >= GB {
        // Format as GB with 1 decimal
        let gb_whole = size / GB;
        let gb_frac = ((size % GB) * 10) / GB;
        pos = write_number(gb_whole as usize, buf, pos);
        if pos < buf.len() {
            buf[pos] = b'.';
            pos += 1;
        }
        pos = write_number(gb_frac as usize, buf, pos);
        for &b in b" GB" {
            if pos < buf.len() {
                buf[pos] = b;
                pos += 1;
            }
        }
    } else if size >= MB {
        // Format as MB with 1 decimal
        let mb_whole = size / MB;
        let mb_frac = ((size % MB) * 10) / MB;
        pos = write_number(mb_whole as usize, buf, pos);
        if pos < buf.len() {
            buf[pos] = b'.';
            pos += 1;
        }
        pos = write_number(mb_frac as usize, buf, pos);
        for &b in b" MB" {
            if pos < buf.len() {
                buf[pos] = b;
                pos += 1;
            }
        }
    } else if size >= KB {
        // Format as KB
        let kb = (size + 512) / KB; // Round to nearest KB
        pos = write_number(kb as usize, buf, pos);
        for &b in b" KB" {
            if pos < buf.len() {
                buf[pos] = b;
                pos += 1;
            }
        }
    } else {
        // Format as bytes
        pos = write_number(size as usize, buf, pos);
        for &b in b" bytes" {
            if pos < buf.len() {
                buf[pos] = b;
                pos += 1;
            }
        }
    }

    pos
}

fn write_number(n: usize, buf: &mut [u8], start: usize) -> usize {
    let mut temp = [0u8; 16];
    let mut num = n;
    let mut temp_pos = 0;
    let mut pos = start;

    if num == 0 {
        temp[temp_pos] = b'0';
        temp_pos += 1;
    } else {
        while num > 0 && temp_pos < 16 {
            temp[temp_pos] = b'0' + (num % 10) as u8;
            num /= 10;
            temp_pos += 1;
        }
    }

    // Reverse
    for i in (0..temp_pos).rev() {
        if pos < buf.len() {
            buf[pos] = temp[i];
            pos += 1;
        }
    }

    pos
}

fn paint_placeholder(hwnd: HWND, hdc: HDC) {
    if let Some(win) = window::get_window(hwnd) {
        let surface_handle = dc::get_dc_surface(hdc);
        if let Some(surf) = surface::get_surface(surface_handle) {
            let offset = dc::get_dc(hdc)
                .map(|d| d.viewport_org)
                .unwrap_or(Point::new(0, 0));
            let metrics = win.get_frame_metrics();
            let border = metrics.border_width;
            let caption = if win.has_caption() { metrics.caption_height } else { 0 };
            let client_x = offset.x + border;
            let client_y = offset.y + border + caption;
            let client_w = win.rect.width() - border * 2;
            let client_h = win.rect.height() - border * 2 - caption;
            let client_rect = Rect::new(client_x, client_y, client_x + client_w, client_y + client_h);
            surf.fill_rect(&client_rect, COLOR_LIST_BG);
            dc::set_text_color(hdc, ColorRef::rgb(128, 128, 128));
            dc::set_bk_mode(hdc, BkMode::Transparent);
            gdi::text_out(hdc, border + 10, border + caption + 10, "Loading...");
        }
    }
}

// ============================================================================
// Event Handling
// ============================================================================

/// Handle column header click (for sorting or resize)
/// Returns true if a sort was initiated, false if resize or no action
pub fn handle_header_click(hwnd: HWND, x: i32, _y: i32) -> bool {
    const COL_TYPES: [SortColumn; 4] = [SortColumn::Name, SortColumn::Size, SortColumn::Type, SortColumn::Modified];

    with_browser(hwnd, |browser| {
        // First check if we're clicking near a column separator (for resize)
        if browser.hit_test_column_separator(x).is_some() {
            // We're on a separator - start_column_resize will be called from mouse down handler
            return false;
        }

        // Not on separator - find which column was clicked for sorting
        let mut col_x = 0;
        for (i, &width) in browser.column_widths.iter().enumerate() {
            col_x += width;
            if x < col_x {
                // Clicked in column i
                browser.set_sort_column(COL_TYPES[i]);
                return true;
            }
        }
        false
    }).unwrap_or(false)
}

/// Check if position is on a column resize separator
pub fn is_on_column_separator(hwnd: HWND, x: i32) -> Option<usize> {
    with_browser(hwnd, |browser| {
        browser.hit_test_column_separator(x)
    }).flatten()
}

/// Handle toolbar button click
pub fn handle_toolbar_click(hwnd: HWND, x: i32, y: i32) -> bool {
    let btn_index = (x - 4) / (TOOLBAR_BTN_SIZE + 2);

    with_browser(hwnd, |browser| {
        match btn_index {
            0 => browser.go_back(),    // Back
            1 => browser.go_forward(), // Forward
            2 => browser.go_up(),      // Up
            3 => {                      // Refresh
                browser.refresh();
                true
            }
            4 => {                      // View toggle
                browser.view_mode = match browser.view_mode {
                    ViewMode::Details => ViewMode::LargeIcons,
                    ViewMode::LargeIcons => ViewMode::Thumbnails,
                    ViewMode::Thumbnails => ViewMode::List,
                    ViewMode::List => ViewMode::Details,
                    _ => ViewMode::Details,
                };
                true
            }
            5 => {                      // Search toggle
                browser.toggle_search();
                crate::serial_println!("[BROWSER] Search toggled: {}", browser.search_active);
                true
            }
            _ => false,
        }
    }).unwrap_or(false)
}

/// Handle mouse click in content area (with modifier key support)
pub fn handle_content_click(hwnd: HWND, x: i32, y: i32, double_click: bool) -> bool {
    handle_content_click_ex(hwnd, x, y, double_click, false, false)
}

/// Handle mouse click with Ctrl/Shift modifiers
pub fn handle_content_click_ex(hwnd: HWND, x: i32, y: i32, double_click: bool, ctrl: bool, shift: bool) -> bool {
    with_browser(hwnd, |browser| {
        // Cancel rename mode on any click
        if browser.rename_mode {
            browser.cancel_rename();
        }

        let content_rect = browser.get_content_rect(hwnd);

        if let Some(index) = browser.hit_test(&content_rect, x, y) {
            browser.handle_selection_click(index, ctrl, shift);

            if double_click && !ctrl && !shift {
                if let Some((path, len, is_dir)) = browser.open_selected() {
                    if is_dir {
                        let path_str = core::str::from_utf8(&path[..len]).unwrap_or("");
                        browser.navigate(path_str);
                    } else {
                        // Execute the file
                        browser.execute_file(&path, len);
                    }
                }
            }
            true
        } else {
            // Click on empty space - clear selection
            if !ctrl && !shift {
                browser.clear_selection();
            }
            true
        }
    }).unwrap_or(false)
}

/// Handle right-click for context menu
pub fn handle_right_click(hwnd: HWND, x: i32, y: i32) -> bool {
    use super::super::context_menu;

    with_browser(hwnd, |browser| {
        let content_rect = browser.get_content_rect(hwnd);

        // If clicking on an item that's not selected, select it first
        if let Some(index) = browser.hit_test(&content_rect, x, y) {
            if !browser.is_selected(index) {
                browser.clear_selection();
                browser.set_selected(index, true);
                browser.focus_index = index as i32;
            }

            // Show file/folder context menu
            let item = &browser.items[index];
            let has_clipboard = browser.has_clipboard();
            context_menu::show_file_context_menu(hwnd, x, y, item.is_directory, has_clipboard);

            crate::serial_println!("[BROWSER] File context menu at ({}, {})", x, y);
        } else {
            // Clicked on empty space - show background context menu
            let path = core::str::from_utf8(&browser.path[..browser.path_len]).unwrap_or("");
            context_menu::show_explorer_context_menu(hwnd, x, y, path);

            crate::serial_println!("[BROWSER] Background context menu at ({}, {})", x, y);
        }

        browser.context_menu_visible = true;
        browser.context_menu_x = x;
        browser.context_menu_y = y;
        true
    }).unwrap_or(false)
}

/// Handle mouse wheel scroll
pub fn handle_mouse_wheel(hwnd: HWND, delta: i32) -> bool {
    with_browser(hwnd, |browser| {
        browser.handle_scroll(delta);
        true
    }).unwrap_or(false)
}

/// Handle keyboard input
pub fn handle_key(hwnd: HWND, key: u8) -> bool {
    handle_key_ex(hwnd, key, false, false)
}

/// Handle keyboard input with modifiers
pub fn handle_key_ex(hwnd: HWND, key: u8, ctrl: bool, shift: bool) -> bool {
    with_browser(hwnd, |browser| {
        // Handle search mode specially
        if browser.search_active {
            match key {
                0x1B => { // Escape - close search
                    browser.toggle_search();
                    return true;
                }
                0x08 => { // Backspace
                    browser.search_backspace();
                    return true;
                }
                0x0D => { // Enter - close search and keep results
                    // Just close search, keep filter active
                    return true;
                }
                _ => {} // Let other keys pass through for char input
            }
        }

        // Handle rename mode specially
        if browser.rename_mode {
            match key {
                0x1B => { // Escape - cancel rename
                    browser.cancel_rename();
                    return true;
                }
                0x0D => { // Enter - confirm rename
                    browser.confirm_rename();
                    return true;
                }
                0x08 => { // Backspace
                    browser.handle_rename_backspace();
                    return true;
                }
                _ => return false, // Let char input handle other keys
            }
        }

        // Ctrl+F to toggle search
        if ctrl && key == 0x21 { // 'F' key (scancode 0x21)
            browser.toggle_search();
            return true;
        }

        match key {
            0x26 => { // Up arrow
                let new_index = if browser.focus_index > 0 {
                    browser.focus_index - 1
                } else {
                    0
                };
                if shift {
                    // Extend selection
                    browser.set_selected(new_index as usize, true);
                } else if !ctrl {
                    browser.clear_selection();
                    browser.set_selected(new_index as usize, true);
                    browser.anchor_index = new_index;
                }
                browser.focus_index = new_index;
                true
            }
            0x28 => { // Down arrow
                let new_index = if browser.focus_index < browser.item_count as i32 - 1 {
                    browser.focus_index + 1
                } else {
                    browser.item_count.saturating_sub(1) as i32
                };
                if shift {
                    browser.set_selected(new_index as usize, true);
                } else if !ctrl {
                    browser.clear_selection();
                    browser.set_selected(new_index as usize, true);
                    browser.anchor_index = new_index;
                }
                browser.focus_index = new_index;
                true
            }
            0x0D => { // Enter - open selection
                if let Some((path, len, is_dir)) = browser.open_selected() {
                    if is_dir {
                        let path_str = core::str::from_utf8(&path[..len]).unwrap_or("");
                        browser.navigate(path_str);
                    } else {
                        // Execute the file
                        browser.execute_file(&path, len);
                    }
                }
                true
            }
            0x08 => { // Backspace - go up
                browser.go_up()
            }
            0x74 => { // F5 - refresh
                browser.refresh();
                true
            }
            0x71 => { // F2 - rename
                browser.start_rename()
            }
            0x2E => { // Delete key
                browser.delete_selection()
            }
            0x41 if ctrl => { // Ctrl+A - select all
                browser.select_all();
                true
            }
            0x49 if ctrl && shift => { // Ctrl+Shift+I - invert selection
                browser.invert_selection();
                true
            }
            0x43 if ctrl => { // Ctrl+C - copy
                browser.copy_selection();
                true
            }
            0x58 if ctrl => { // Ctrl+X - cut
                browser.cut_selection();
                true
            }
            0x56 if ctrl => { // Ctrl+V - paste
                browser.paste()
            }
            0x5A if ctrl => { // Ctrl+Z - undo
                if undo_last() {
                    browser.refresh();
                    true
                } else {
                    false
                }
            }
            0x59 if ctrl => { // Ctrl+Y - redo
                if redo_last() {
                    browser.refresh();
                    true
                } else {
                    false
                }
            }
            0x47 if ctrl => { // Ctrl+G - toggle grouping
                browser.toggle_grouping();
                true
            }
            0x44 if ctrl => { // Ctrl+D - toggle details panel
                browser.toggle_details_panel();
                true
            }
            0x21 => { // Page Up
                browser.scroll_y -= 200;
                if browser.scroll_y < 0 {
                    browser.scroll_y = 0;
                }
                true
            }
            0x22 => { // Page Down
                browser.scroll_y += 200;
                let max = browser.get_max_scroll_y();
                if browser.scroll_y > max {
                    browser.scroll_y = max;
                }
                true
            }
            0x24 => { // Home
                if ctrl {
                    // Ctrl+Home: go to first item
                    browser.focus_index = 0;
                    browser.clear_selection();
                    browser.set_selected(0, true);
                }
                browser.scroll_y = 0;
                true
            }
            0x23 => { // End
                if ctrl && browser.item_count > 0 {
                    // Ctrl+End: go to last item
                    browser.focus_index = browser.item_count as i32 - 1;
                    browser.clear_selection();
                    browser.set_selected(browser.item_count - 1, true);
                }
                browser.scroll_y = browser.get_max_scroll_y();
                true
            }
            _ => false,
        }
    }).unwrap_or(false)
}

/// Handle character input (for rename mode)
pub fn handle_char(hwnd: HWND, c: char) -> bool {
    with_browser(hwnd, |browser| {
        if browser.rename_mode {
            browser.handle_rename_char(c);
            true
        } else if browser.search_active {
            // Handle character input for search
            if c.is_alphanumeric() || c == ' ' || c == '.' || c == '-' || c == '_' {
                browser.search_add_char(c);
                true
            } else {
                false
            }
        } else {
            false
        }
    }).unwrap_or(false)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize file browser subsystem
pub fn init() {
    crate::serial_println!("[BROWSER] File browser subsystem initialized");
}

// ============================================================================
// Wrapper Functions for Context Menu Actions
// ============================================================================

/// Refresh the file browser for a window
pub fn refresh_browser(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.refresh();
    });
}

/// Select all items in the file browser
pub fn select_all(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.select_all();
    });
}

/// Invert selection in the file browser
pub fn invert_selection(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.invert_selection();
    });
}

/// Select all items of the same type as focused item
pub fn select_by_type(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.select_by_type();
    });
}

/// Open the focused item (navigate into folder or execute file)
pub fn open_focused(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        if let Some((path, len, is_dir)) = browser.open_selected() {
            if is_dir {
                let path_str = core::str::from_utf8(&path[..len]).unwrap_or("");
                browser.navigate(path_str);
            } else {
                // Execute the file
                browser.execute_file(&path, len);
            }
        }
    });
}

/// Cut selected items to clipboard
pub fn cut_selection(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.cut_selection();
    });
}

/// Copy selected items to clipboard
pub fn copy_selection(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.copy_selection();
    });
}

/// Delete selected items
pub fn delete_selection(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.delete_selection();
    });
}

/// Start rename mode for the focused item
pub fn start_rename(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.start_rename();
    });
}

/// Select an item by name and start rename mode
pub fn select_and_rename(hwnd: HWND, name: &str) {
    with_browser(hwnd, |browser| {
        if browser.select_by_name(name).is_some() {
            browser.start_rename();
        }
    });
}

/// Select an item by name
pub fn select_by_name(hwnd: HWND, name: &str) -> bool {
    with_browser(hwnd, |browser| {
        browser.select_by_name(name).is_some()
    }).unwrap_or(false)
}

/// Set the view mode for the file browser
pub fn set_view_mode(hwnd: HWND, mode: ViewMode) {
    with_browser(hwnd, |browser| {
        browser.view_mode = mode;
    });
}

/// Set the sort column for the file browser
pub fn set_sort_column(hwnd: HWND, column: SortColumn) {
    with_browser(hwnd, |browser| {
        browser.set_sort_column(column);
    });
}

/// Toggle file grouping mode (None -> Type -> Date -> Name -> None)
pub fn toggle_grouping(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.toggle_grouping();
    });
}

/// Set file grouping mode
pub fn set_group_by(hwnd: HWND, mode: GroupBy) {
    with_browser(hwnd, |browser| {
        browser.set_group_by(mode);
    });
}

/// Get current grouping mode
pub fn get_group_by(hwnd: HWND) -> GroupBy {
    with_browser(hwnd, |browser| browser.group_by).unwrap_or(GroupBy::None)
}

/// Toggle auto-arrange mode
pub fn toggle_auto_arrange(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.toggle_auto_arrange();
    });
}

/// Toggle snap-to-grid mode
pub fn toggle_snap_to_grid(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.toggle_snap_to_grid();
    });
}

/// Get auto-arrange state
pub fn is_auto_arrange(hwnd: HWND) -> bool {
    with_browser(hwnd, |browser| browser.auto_arrange).unwrap_or(true)
}

/// Get snap-to-grid state
pub fn is_snap_to_grid(hwnd: HWND) -> bool {
    with_browser(hwnd, |browser| browser.snap_to_grid).unwrap_or(true)
}

/// Toggle details panel visibility
pub fn toggle_details_panel(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.toggle_details_panel();
    });
}

/// Get details panel visibility state
pub fn is_details_panel_visible(hwnd: HWND) -> bool {
    with_browser(hwnd, |browser| browser.details_panel_visible).unwrap_or(false)
}

/// Update hover state for tooltips (call on mouse move)
pub fn update_hover(hwnd: HWND, x: i32, y: i32) {
    with_browser(hwnd, |browser| {
        let content_rect = browser.get_content_rect(hwnd);
        browser.update_hover(&content_rect, x, y);
    });
}

/// Clear hover state (call when mouse leaves window)
pub fn clear_hover(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.clear_hover();
    });
}

/// Check if tooltip is visible
pub fn is_tooltip_visible(hwnd: HWND) -> bool {
    with_browser(hwnd, |browser| browser.tooltip_visible).unwrap_or(false)
}

/// Get tooltip info for painting
pub fn get_tooltip_info(hwnd: HWND) -> Option<(i32, i32, [u8; 256], usize)> {
    with_browser(hwnd, |browser| {
        if let Some((text, len)) = browser.get_tooltip_text() {
            Some((browser.hover_x, browser.hover_y, text, len))
        } else {
            None
        }
    }).flatten()
}

// ============================================================================
// Column Resize State
// ============================================================================

use crate::ke::spinlock::SpinLock as ResizeSpinLock;

/// Column resize state
struct ColumnResizeState {
    /// Window being resized
    hwnd: HWND,
    /// Column index being resized
    column_index: usize,
    /// Mouse X position at resize start
    start_x: i32,
    /// Original column width at resize start
    original_width: i32,
    /// Is resize operation active
    active: bool,
}

impl ColumnResizeState {
    const fn new() -> Self {
        Self {
            hwnd: HWND::NULL,
            column_index: 0,
            start_x: 0,
            original_width: 0,
            active: false,
        }
    }
}

static COLUMN_RESIZE: ResizeSpinLock<ColumnResizeState> = ResizeSpinLock::new(ColumnResizeState::new());

/// Check if column resize is currently active
pub fn is_column_resizing() -> bool {
    COLUMN_RESIZE.lock().active
}

/// Start column resize operation
pub fn start_column_resize(hwnd: HWND, column_index: usize, mouse_x: i32) {
    with_browser(hwnd, |browser| {
        let mut state = COLUMN_RESIZE.lock();
        state.hwnd = hwnd;
        state.column_index = column_index;
        state.start_x = mouse_x;
        state.original_width = browser.column_widths[column_index];
        state.active = true;
        crate::serial_println!("[BROWSER] Started column {} resize at x={}", column_index, mouse_x);
    });
}

/// Update column resize based on mouse position
pub fn update_column_resize(mouse_x: i32) -> bool {
    let state = COLUMN_RESIZE.lock();
    if !state.active {
        return false;
    }

    let hwnd = state.hwnd;
    let column_index = state.column_index;
    let start_x = state.start_x;
    let original_width = state.original_width;
    drop(state);

    let delta = mouse_x - start_x;
    let new_width = (original_width + delta).max(MIN_COLUMN_WIDTH);

    with_browser(hwnd, |browser| {
        browser.column_widths[column_index] = new_width;
    });

    true
}

/// End column resize operation
pub fn end_column_resize() {
    let mut state = COLUMN_RESIZE.lock();
    if state.active {
        crate::serial_println!("[BROWSER] Ended column resize");
        state.active = false;
        state.hwnd = HWND::NULL;
    }
}

/// Get the window handle being resized (for cursor updates)
pub fn get_resize_hwnd() -> HWND {
    COLUMN_RESIZE.lock().hwnd
}

// ============================================================================
// Drag and Drop State
// ============================================================================

/// Drag and drop state
struct DragDropState {
    /// Source window handle
    source_hwnd: HWND,
    /// Is drag operation active
    active: bool,
    /// Source folder path
    source_path: [u8; MAX_PATH],
    source_path_len: usize,
    /// Number of items being dragged
    item_count: usize,
    /// Current drop target hwnd (if any)
    drop_target_hwnd: HWND,
    /// Current mouse position
    mouse_x: i32,
    mouse_y: i32,
}

impl DragDropState {
    const fn new() -> Self {
        Self {
            source_hwnd: HWND::NULL,
            active: false,
            source_path: [0; MAX_PATH],
            source_path_len: 0,
            item_count: 0,
            drop_target_hwnd: HWND::NULL,
            mouse_x: 0,
            mouse_y: 0,
        }
    }
}

static DRAG_DROP: ResizeSpinLock<DragDropState> = ResizeSpinLock::new(DragDropState::new());

/// Check if a file drag is in progress
pub fn is_file_dragging() -> bool {
    DRAG_DROP.lock().active
}

/// Start a file drag operation
pub fn start_file_drag(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        if browser.selection_count == 0 {
            return;
        }

        let mut state = DRAG_DROP.lock();
        state.source_hwnd = hwnd;
        state.active = true;
        state.source_path[..browser.path_len].copy_from_slice(&browser.path[..browser.path_len]);
        state.source_path_len = browser.path_len;
        state.item_count = browser.selection_count;
        browser.drag_state = DragState::Active;

        crate::serial_println!("[BROWSER] File drag started: {} items from {:?}",
            state.item_count,
            core::str::from_utf8(&state.source_path[..state.source_path_len]).unwrap_or("?"));
    });
}

/// Update file drag position and find drop targets
pub fn update_file_drag(x: i32, y: i32) -> bool {
    let mut state = DRAG_DROP.lock();
    if !state.active {
        return false;
    }

    state.mouse_x = x;
    state.mouse_y = y;

    // TODO: Find drop target window/folder at position
    // For now, just track the position

    true
}

/// End file drag operation - perform the drop if valid
pub fn end_file_drag(x: i32, y: i32) -> bool {
    let state = DRAG_DROP.lock();
    if !state.active {
        return false;
    }

    let source_hwnd = state.source_hwnd;
    let source_path_len = state.source_path_len;
    let mut source_path = [0u8; MAX_PATH];
    source_path[..source_path_len].copy_from_slice(&state.source_path[..source_path_len]);
    drop(state);

    // Reset the drag state on the browser
    with_browser(source_hwnd, |browser| {
        browser.drag_state = DragState::None;
    });

    // Find what we're dropping on
    let drop_hwnd = super::super::window::window_from_point(super::super::super::Point::new(x, y));

    if drop_hwnd.is_valid() && drop_hwnd != source_hwnd {
        // Dropping on a different window - check if it's an explorer window
        if let Some(target_path) = get_browser_path(drop_hwnd) {
            let source_path_str = core::str::from_utf8(&source_path[..source_path_len]).unwrap_or("");

            // Don't drop on self
            if target_path != source_path_str {
                crate::serial_println!("[BROWSER] Drop from '{}' to '{}'", source_path_str, target_path);

                // Perform the move/copy operation
                perform_file_drop(source_hwnd, drop_hwnd);
            }
        }
    }

    // Clear global drag state
    let mut state = DRAG_DROP.lock();
    state.active = false;
    state.source_hwnd = HWND::NULL;
    state.item_count = 0;

    true
}

/// Cancel file drag
pub fn cancel_file_drag() {
    let source_hwnd = {
        let mut state = DRAG_DROP.lock();
        if !state.active {
            return;
        }
        let hwnd = state.source_hwnd;
        state.active = false;
        state.source_hwnd = HWND::NULL;
        hwnd
    };

    with_browser(source_hwnd, |browser| {
        browser.drag_state = DragState::None;
    });

    crate::serial_println!("[BROWSER] File drag cancelled");
}

/// Get the path of a browser window
fn get_browser_path(hwnd: HWND) -> Option<&'static str> {
    // This is a bit tricky due to lifetime issues - we'll return the path differently
    None // For now, simplified
}

/// Perform file drop operation
fn perform_file_drop(source_hwnd: HWND, target_hwnd: HWND) {
    use crate::io::{vfs_copy_file, vfs_delete_file};

    // Get source browser info
    let source_info = with_browser(source_hwnd, |browser| {
        let path = core::str::from_utf8(&browser.path[..browser.path_len]).unwrap_or("");
        let mut items: [([u8; 256], usize, bool); 32] = [([0; 256], 0, false); 32];
        let mut count = 0;

        for i in 0..browser.item_count {
            if browser.is_selected(i) && count < 32 {
                let item = &browser.items[i];
                items[count].0[..item.name_len].copy_from_slice(&item.name[..item.name_len]);
                items[count].1 = item.name_len;
                items[count].2 = item.is_directory;
                count += 1;
            }
        }

        let mut path_buf = [0u8; MAX_PATH];
        path_buf[..browser.path_len].copy_from_slice(&browser.path[..browser.path_len]);
        (path_buf, browser.path_len, items, count)
    });

    if source_info.is_none() {
        return;
    }
    let (source_path, source_len, items, count) = source_info.unwrap();

    // Get target path
    let target_path = with_browser(target_hwnd, |browser| {
        let mut buf = [0u8; MAX_PATH];
        buf[..browser.path_len].copy_from_slice(&browser.path[..browser.path_len]);
        (buf, browser.path_len)
    });

    if target_path.is_none() {
        return;
    }
    let (target_path_buf, target_len) = target_path.unwrap();

    let source_path_str = core::str::from_utf8(&source_path[..source_len]).unwrap_or("");
    let target_path_str = core::str::from_utf8(&target_path_buf[..target_len]).unwrap_or("");

    crate::serial_println!("[BROWSER] Moving {} files from '{}' to '{}'", count, source_path_str, target_path_str);

    // For each selected item, build source and dest paths and copy
    for i in 0..count {
        let (name_buf, name_len, is_dir) = items[i];
        let name = core::str::from_utf8(&name_buf[..name_len]).unwrap_or("");

        if is_dir {
            // TODO: Handle directory moves
            crate::serial_println!("[BROWSER] Skipping directory: {}", name);
        } else {
            // Build full paths
            let mut src_full = [0u8; MAX_PATH];
            let mut src_pos = 0;
            for b in source_path_str.bytes() {
                if src_pos < MAX_PATH - 1 { src_full[src_pos] = b; src_pos += 1; }
            }
            if src_pos > 0 && src_pos < MAX_PATH - 1 && src_full[src_pos-1] != b'/' && src_full[src_pos-1] != b'\\' {
                src_full[src_pos] = b'/';
                src_pos += 1;
            }
            for b in name.bytes() {
                if src_pos < MAX_PATH - 1 { src_full[src_pos] = b; src_pos += 1; }
            }

            let mut dst_full = [0u8; MAX_PATH];
            let mut dst_pos = 0;
            for b in target_path_str.bytes() {
                if dst_pos < MAX_PATH - 1 { dst_full[dst_pos] = b; dst_pos += 1; }
            }
            if dst_pos > 0 && dst_pos < MAX_PATH - 1 && dst_full[dst_pos-1] != b'/' && dst_full[dst_pos-1] != b'\\' {
                dst_full[dst_pos] = b'/';
                dst_pos += 1;
            }
            for b in name.bytes() {
                if dst_pos < MAX_PATH - 1 { dst_full[dst_pos] = b; dst_pos += 1; }
            }

            let src_str = core::str::from_utf8(&src_full[..src_pos]).unwrap_or("");
            let dst_str = core::str::from_utf8(&dst_full[..dst_pos]).unwrap_or("");

            crate::serial_println!("[BROWSER] Copy '{}' -> '{}'", src_str, dst_str);
            if vfs_copy_file(src_str, dst_str) {
                // Delete source (move operation)
                vfs_delete_file(src_str);
            }
        }
    }

    // Refresh both browsers
    with_browser(source_hwnd, |browser| {
        browser.clear_selection();
        browser.refresh();
    });
    with_browser(target_hwnd, |browser| {
        browser.refresh();
    });
}

/// Check if mouse is over a selected item (for drag initiation)
pub fn is_on_selected_item(hwnd: HWND, x: i32, y: i32) -> bool {
    with_browser(hwnd, |browser| {
        let content_rect = browser.get_content_rect(hwnd);
        if let Some(index) = browser.hit_test(&content_rect, x, y) {
            return browser.is_selected(index);
        }
        false
    }).unwrap_or(false)
}

/// Initiate drag on a browser (called when clicking on selected item)
pub fn initiate_drag(hwnd: HWND, x: i32, y: i32) {
    with_browser(hwnd, |browser| {
        browser.start_potential_drag(x, y);
    });
}

/// Check and update drag state (called on mouse move)
pub fn check_drag_start(hwnd: HWND, x: i32, y: i32) -> bool {
    with_browser(hwnd, |browser| {
        browser.check_drag_threshold(x, y)
    }).unwrap_or(false)
}

// ============================================================================
// Folder Tree Integration
// ============================================================================

/// Toggle folder tree visibility
pub fn toggle_tree(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.tree_visible = !browser.tree_visible;
    });
}

/// Check if tree is visible
pub fn is_tree_visible(hwnd: HWND) -> bool {
    with_browser(hwnd, |browser| browser.tree_visible).unwrap_or(false)
}

/// Get tree rect for a browser window
pub fn get_tree_rect(hwnd: HWND) -> Option<Rect> {
    with_browser(hwnd, |browser| {
        if browser.tree_visible {
            Some(browser.get_tree_rect(hwnd))
        } else {
            None
        }
    }).flatten()
}

/// Handle tree click and navigate if needed
pub fn handle_tree_click(hwnd: HWND, x: i32, y: i32) -> bool {
    // First handle the click in the tree
    let tree_rect = match get_tree_rect(hwnd) {
        Some(r) => r,
        None => return false,
    };

    // Let the tree handle the click
    super::foldertree::handle_tree_click(hwnd, x, y, &tree_rect);

    // Get selected path and navigate
    if let Some((path_buf, path_len)) = super::foldertree::get_selected_path_after_click(hwnd) {
        if path_len > 0 {
            if let Ok(path) = core::str::from_utf8(&path_buf[..path_len]) {
                with_browser(hwnd, |browser| {
                    browser.navigate(path);
                });
                return true;
            }
        }
    }

    true // Still consumed the click even if no navigation
}

/// Sync tree with current browser path
pub fn sync_tree_with_path(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        let path = browser.path_str();
        super::foldertree::sync_with_browser(hwnd, path);
    });
}

// ============================================================================
// Address Bar Dropdown
// ============================================================================

/// Maximum items in address dropdown
pub const MAX_DROPDOWN_ITEMS: usize = 10;

/// Dropdown item height
pub const DROPDOWN_ITEM_HEIGHT: i32 = 18;

/// Toggle address bar dropdown
pub fn toggle_address_dropdown(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.toggle_address_dropdown();
    });
}

/// Check if address dropdown is visible
pub fn is_address_dropdown_visible(hwnd: HWND) -> bool {
    with_browser(hwnd, |browser| browser.address_dropdown_visible).unwrap_or(false)
}

/// Hide address dropdown
pub fn hide_address_dropdown(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.hide_address_dropdown();
    });
}

/// Handle address bar dropdown click
pub fn handle_address_dropdown_click(hwnd: HWND, x: i32, y: i32) -> bool {
    let dropdown_info = with_browser(hwnd, |browser| {
        if !browser.address_dropdown_visible {
            return None;
        }

        // Calculate dropdown rect
        if let Some(win) = window::get_window(hwnd) {
            let metrics = win.get_frame_metrics();
            let client_y = win.rect.top + metrics.border_width + metrics.caption_height;
            let toolbar_y = client_y + TOOLBAR_HEIGHT;

            let dropdown_x = win.rect.left + metrics.border_width + 60;
            let dropdown_y = toolbar_y + ADDRESS_BAR_HEIGHT;
            let dropdown_w = (win.rect.width() - metrics.border_width * 2) - 64;

            // Get history entries
            let (entries, count) = browser.get_history_entries();

            // Check if click is in dropdown
            if x >= dropdown_x && x < dropdown_x + dropdown_w {
                let rel_y = y - dropdown_y;
                if rel_y >= 0 && rel_y < (count as i32) * DROPDOWN_ITEM_HEIGHT {
                    let item_idx = (rel_y / DROPDOWN_ITEM_HEIGHT) as usize;
                    if item_idx < count {
                        return Some((entries[item_idx].0, entries[item_idx].1));
                    }
                }
            }
        }
        None
    }).flatten();

    if let Some((path_buf, path_len)) = dropdown_info {
        if path_len > 0 {
            if let Ok(path) = core::str::from_utf8(&path_buf[..path_len]) {
                with_browser(hwnd, |browser| {
                    browser.navigate(path);
                    browser.hide_address_dropdown();
                });
                return true;
            }
        }
    }

    // Hide dropdown on any click
    hide_address_dropdown(hwnd);
    false
}

/// Paint address bar dropdown if visible
pub fn paint_address_dropdown(hwnd: HWND, hdc: HDC, surf: &surface::Surface) {
    let dropdown_info = with_browser(hwnd, |browser| {
        if !browser.address_dropdown_visible {
            return None;
        }

        // Calculate dropdown rect
        if let Some(win) = window::get_window(hwnd) {
            let metrics = win.get_frame_metrics();
            let client_y = win.rect.top + metrics.border_width + metrics.caption_height;
            let toolbar_y = client_y + TOOLBAR_HEIGHT;

            let dropdown_x = win.rect.left + metrics.border_width + 60;
            let dropdown_y = toolbar_y + ADDRESS_BAR_HEIGHT;
            let dropdown_w = (win.rect.width() - metrics.border_width * 2) - 64;

            // Get history entries
            let (entries, count) = browser.get_history_entries();

            return Some((dropdown_x, dropdown_y, dropdown_w, entries, count));
        }
        None
    }).flatten();

    if let Some((x, y, w, entries, count)) = dropdown_info {
        if count == 0 {
            return;
        }

        let h = (count as i32) * DROPDOWN_ITEM_HEIGHT;

        // Dropdown background
        let dropdown_rect = Rect::new(x, y, x + w, y + h);
        surf.fill_rect(&dropdown_rect, COLOR_ADDRESS_BG);

        // Border
        surf.hline(x, x + w, y, ColorRef::rgb(0, 0, 0));
        surf.hline(x, x + w, y + h - 1, ColorRef::rgb(0, 0, 0));
        surf.vline(x, y, y + h, ColorRef::rgb(0, 0, 0));
        surf.vline(x + w - 1, y, y + h, ColorRef::rgb(0, 0, 0));

        // Draw items
        dc::set_text_color(hdc, ColorRef::rgb(0, 0, 0));
        dc::set_bk_mode(hdc, dc::BkMode::Transparent);

        for i in 0..count {
            let item_y = y + (i as i32) * DROPDOWN_ITEM_HEIGHT;
            let path = core::str::from_utf8(&entries[i].0[..entries[i].1]).unwrap_or("");

            // Draw item text
            gdi::text_out(hdc, x + 4, item_y + 2, path);
        }
    }
}

/// Check if click is on address dropdown button
pub fn is_on_address_dropdown_button(hwnd: HWND, x: i32, y: i32) -> bool {
    with_browser(hwnd, |browser| {
        if let Some(win) = window::get_window(hwnd) {
            let metrics = win.get_frame_metrics();
            let client_y = win.rect.top + metrics.border_width + metrics.caption_height;
            let toolbar_y = client_y + TOOLBAR_HEIGHT;
            let client_w = win.rect.width() - metrics.border_width * 2;

            let btn_x = win.rect.left + metrics.border_width + client_w - 4 - ADDRESS_DROPDOWN_WIDTH;
            let btn_y = toolbar_y + 3;
            let btn_h = ADDRESS_BAR_HEIGHT - 6;

            return x >= btn_x && x < btn_x + ADDRESS_DROPDOWN_WIDTH &&
                   y >= btn_y && y < btn_y + btn_h;
        }
        false
    }).unwrap_or(false)
}

/// Show properties dialog for the focused/selected item
pub fn show_properties(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        // Find the first selected item or the focused item
        let item_idx = if browser.selection_count > 0 {
            // Find first selected item
            (0..browser.item_count).find(|&i| browser.is_selected(i))
        } else if browser.focus_index >= 0 && (browser.focus_index as usize) < browser.item_count {
            Some(browser.focus_index as usize)
        } else {
            None
        };

        if let Some(idx) = item_idx {
            let item = &browser.items[idx];
            let path = browser.path_str();
            super::properties::show_properties(hwnd, item, path);
        }
    });
}

/// Check if properties dialog is visible
pub fn is_properties_visible() -> bool {
    super::properties::is_any_visible()
}

/// Handle click on properties dialog
pub fn handle_properties_click(x: i32, y: i32) -> bool {
    super::properties::handle_click(x, y)
}

/// Handle mouse move for properties dialog
pub fn handle_properties_mouse_move(x: i32, y: i32) {
    super::properties::handle_mouse_move(x, y);
}

/// Paint properties dialogs
pub fn paint_properties() {
    super::properties::paint_all();
}

// ============================================================================
// Search Functions
// ============================================================================

/// Check if search mode is active for a window
pub fn is_search_active(hwnd: HWND) -> bool {
    with_browser(hwnd, |browser| browser.search_active).unwrap_or(false)
}

/// Toggle search mode for a window
pub fn toggle_search(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        browser.toggle_search();
    });
}

/// Add character to search query
pub fn search_add_char(hwnd: HWND, c: char) {
    with_browser(hwnd, |browser| {
        if browser.search_active {
            browser.search_add_char(c);
        }
    });
}

/// Remove character from search query (backspace)
pub fn search_backspace(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        if browser.search_active {
            browser.search_backspace();
        }
    });
}

/// Clear search query
pub fn search_clear(hwnd: HWND) {
    with_browser(hwnd, |browser| {
        if browser.search_active {
            browser.clear_search();
        }
    });
}

/// Get search match count
pub fn get_search_match_count(hwnd: HWND) -> usize {
    with_browser(hwnd, |browser| {
        if browser.search_active && browser.search_query_len > 0 {
            browser.search_match_count
        } else {
            browser.item_count
        }
    }).unwrap_or(0)
}
