//! Drag and Drop Support
//!
//! OLE drag and drop support for windows.
//! Based on Windows Server 2003 ole2.h and shellapi.h.
//!
//! # Features
//!
//! - Drop target registration
//! - Drag source support
//! - Drag image support
//! - Shell drag-drop helpers
//!
//! # References
//!
//! - `public/sdk/inc/ole2.h` - OLE drag/drop
//! - `public/sdk/inc/shellapi.h` - DragAcceptFiles

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, Point};

// ============================================================================
// Drop Effect Constants (DROPEFFECT_*)
// ============================================================================

/// No drop
pub const DROPEFFECT_NONE: u32 = 0;

/// Copy
pub const DROPEFFECT_COPY: u32 = 1;

/// Move
pub const DROPEFFECT_MOVE: u32 = 2;

/// Link
pub const DROPEFFECT_LINK: u32 = 4;

/// Scroll
pub const DROPEFFECT_SCROLL: u32 = 0x80000000;

// ============================================================================
// Drag/Drop Key State (MK_*)
// ============================================================================

/// Left button
pub const MK_LBUTTON: u32 = 0x0001;

/// Right button
pub const MK_RBUTTON: u32 = 0x0002;

/// Shift key
pub const MK_SHIFT: u32 = 0x0004;

/// Control key
pub const MK_CONTROL: u32 = 0x0008;

/// Middle button
pub const MK_MBUTTON: u32 = 0x0010;

/// Alt key
pub const MK_ALT: u32 = 0x0020;

// ============================================================================
// Clipboard Formats for Drag/Drop
// ============================================================================

/// CF_HDROP format
pub const CF_HDROP: u32 = 15;

/// Shell ID list format name
pub const CFSTR_SHELLIDLIST: &[u8] = b"Shell IDList Array";

/// File name format name
pub const CFSTR_FILENAMEA: &[u8] = b"FileName";

/// File name (wide) format name
pub const CFSTR_FILENAMEW: &[u8] = b"FileNameW";

/// File descriptor format name
pub const CFSTR_FILEDESCRIPTORA: &[u8] = b"FileGroupDescriptor";

/// File contents format name
pub const CFSTR_FILECONTENTS: &[u8] = b"FileContents";

// ============================================================================
// Constants
// ============================================================================

/// Maximum registered drop targets
pub const MAX_DROP_TARGETS: usize = 64;

/// Maximum files in a drag operation
pub const MAX_DRAG_FILES: usize = 32;

/// Maximum path length
pub const MAX_PATH: usize = 260;

// ============================================================================
// Drop Target Entry
// ============================================================================

/// Drop target registration
#[derive(Clone, Copy)]
pub struct DropTargetEntry {
    /// Is this slot in use
    pub in_use: bool,
    /// Window handle
    pub hwnd: HWND,
    /// Accepts files
    pub accept_files: bool,
    /// Drop target interface (simulated)
    pub drop_target: usize,
    /// Current effect
    pub current_effect: u32,
    /// Is drag over
    pub is_drag_over: bool,
}

impl DropTargetEntry {
    /// Create empty entry
    pub const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: UserHandle::NULL,
            accept_files: false,
            drop_target: 0,
            current_effect: DROPEFFECT_NONE,
            is_drag_over: false,
        }
    }
}

// ============================================================================
// HDROP Structure (File Drop Handle)
// ============================================================================

/// File drop data
#[derive(Clone)]
pub struct DropFiles {
    /// Is this in use
    pub in_use: bool,
    /// Drop point
    pub pt: Point,
    /// Is non-client area
    pub non_client: bool,
    /// Is wide string
    pub wide: bool,
    /// File paths
    pub files: [[u8; MAX_PATH]; MAX_DRAG_FILES],
    /// File count
    pub file_count: usize,
}

impl DropFiles {
    /// Create empty drop files
    pub const fn new() -> Self {
        Self {
            in_use: false,
            pt: Point { x: 0, y: 0 },
            non_client: false,
            wide: false,
            files: [[0; MAX_PATH]; MAX_DRAG_FILES],
            file_count: 0,
        }
    }

    /// Add a file to the drop
    pub fn add_file(&mut self, path: &[u8]) -> bool {
        if self.file_count >= MAX_DRAG_FILES {
            return false;
        }

        let len = super::strhelp::str_len(path).min(MAX_PATH - 1);
        self.files[self.file_count][..len].copy_from_slice(&path[..len]);
        self.files[self.file_count][len] = 0;
        self.file_count += 1;

        true
    }

    /// Get file by index
    pub fn get_file(&self, index: usize) -> Option<&[u8]> {
        if index < self.file_count {
            Some(&self.files[index])
        } else {
            None
        }
    }
}

/// HDROP handle type
pub type HDROP = usize;

/// Null HDROP
pub const NULL_HDROP: HDROP = 0;

// ============================================================================
// Drag Image Info
// ============================================================================

/// Drag image information
#[derive(Clone, Copy)]
pub struct DragImageInfo {
    /// Is drag active
    pub active: bool,
    /// Image position
    pub pt: Point,
    /// Image offset (hotspot)
    pub offset: Point,
    /// Image width
    pub width: i32,
    /// Image height
    pub height: i32,
    /// Is showing
    pub visible: bool,
}

impl DragImageInfo {
    /// Create empty drag image
    pub const fn new() -> Self {
        Self {
            active: false,
            pt: Point { x: 0, y: 0 },
            offset: Point { x: 0, y: 0 },
            width: 0,
            height: 0,
            visible: false,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global drop target storage
static DROP_TARGETS: SpinLock<[DropTargetEntry; MAX_DROP_TARGETS]> =
    SpinLock::new([const { DropTargetEntry::new() }; MAX_DROP_TARGETS]);

/// Global drop files storage
static DROP_FILES: SpinLock<[DropFiles; 8]> =
    SpinLock::new([const { DropFiles::new() }; 8]);

/// Current drag operation
static DRAG_STATE: SpinLock<DragState> = SpinLock::new(DragState::new());

/// Drag image state
static DRAG_IMAGE: SpinLock<DragImageInfo> = SpinLock::new(DragImageInfo::new());

/// Drag operation state
#[derive(Clone, Copy)]
struct DragState {
    /// Is dragging
    active: bool,
    /// Source window
    source_hwnd: HWND,
    /// Current target window
    target_hwnd: HWND,
    /// Allowed effects
    allowed_effects: u32,
    /// Current effect
    current_effect: u32,
    /// Key state
    key_state: u32,
    /// Current position
    pt: Point,
}

impl DragState {
    const fn new() -> Self {
        Self {
            active: false,
            source_hwnd: UserHandle::NULL,
            target_hwnd: UserHandle::NULL,
            allowed_effects: DROPEFFECT_NONE,
            current_effect: DROPEFFECT_NONE,
            key_state: 0,
            pt: Point { x: 0, y: 0 },
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Initialize drag-drop support
pub fn init() {
    crate::serial_println!("[USER] Drag-drop support initialized");
}

/// Register a window as accepting file drops (simple API)
pub fn drag_accept_files(hwnd: HWND, accept: bool) -> bool {
    let mut targets = DROP_TARGETS.lock();

    // Check if already registered
    for entry in targets.iter_mut() {
        if entry.in_use && entry.hwnd == hwnd {
            entry.accept_files = accept;
            if !accept && entry.drop_target == 0 {
                entry.in_use = false;
            }
            return true;
        }
    }

    if !accept {
        return true;
    }

    // Register new target
    for entry in targets.iter_mut() {
        if !entry.in_use {
            entry.in_use = true;
            entry.hwnd = hwnd;
            entry.accept_files = true;
            entry.drop_target = 0;
            entry.current_effect = DROPEFFECT_COPY;
            entry.is_drag_over = false;
            return true;
        }
    }

    false
}

/// Register drop target (OLE style)
pub fn register_drag_drop(hwnd: HWND, drop_target: usize) -> i32 {
    let mut targets = DROP_TARGETS.lock();

    // Check if already registered
    for entry in targets.iter() {
        if entry.in_use && entry.hwnd == hwnd {
            return -2147221247; // DRAGDROP_E_ALREADYREGISTERED
        }
    }

    // Register new target
    for entry in targets.iter_mut() {
        if !entry.in_use {
            entry.in_use = true;
            entry.hwnd = hwnd;
            entry.accept_files = true;
            entry.drop_target = drop_target;
            entry.current_effect = DROPEFFECT_NONE;
            entry.is_drag_over = false;
            return 0; // S_OK
        }
    }

    -2147024882 // E_OUTOFMEMORY
}

/// Revoke drop target registration
pub fn revoke_drag_drop(hwnd: HWND) -> i32 {
    let mut targets = DROP_TARGETS.lock();

    for entry in targets.iter_mut() {
        if entry.in_use && entry.hwnd == hwnd {
            *entry = DropTargetEntry::new();
            return 0; // S_OK
        }
    }

    -2147221248 // DRAGDROP_E_NOTREGISTERED
}

/// Start a drag operation
pub fn do_drag_drop(
    _data_object: usize,
    _drop_source: usize,
    allowed_effects: u32,
    effect: &mut u32,
) -> i32 {
    let mut state = DRAG_STATE.lock();

    if state.active {
        *effect = DROPEFFECT_NONE;
        return -2147221245; // DRAGDROP_E_INVALIDHWND
    }

    state.active = true;
    state.allowed_effects = allowed_effects;
    state.current_effect = DROPEFFECT_NONE;
    state.key_state = 0;

    // In a real implementation, this would enter a modal drag loop
    // For now, simulate immediate cancel
    state.active = false;
    *effect = DROPEFFECT_NONE;

    1 // DRAGDROP_S_CANCEL
}

/// Create HDROP from file list
pub fn create_drop_files(files: &[&[u8]], pt: Point, non_client: bool) -> HDROP {
    let mut drops = DROP_FILES.lock();

    for (i, drop) in drops.iter_mut().enumerate() {
        if !drop.in_use {
            drop.in_use = true;
            drop.pt = pt;
            drop.non_client = non_client;
            drop.wide = false;
            drop.file_count = 0;

            for file in files {
                if !drop.add_file(file) {
                    break;
                }
            }

            return i + 1;
        }
    }

    NULL_HDROP
}

/// Query number of files in HDROP
pub fn drag_query_file_count(hdrop: HDROP) -> usize {
    if hdrop == NULL_HDROP || hdrop > 8 {
        return 0;
    }

    let drops = DROP_FILES.lock();
    let idx = hdrop - 1;

    if drops[idx].in_use {
        drops[idx].file_count
    } else {
        0
    }
}

/// Query file from HDROP
pub fn drag_query_file(hdrop: HDROP, index: usize, buffer: &mut [u8]) -> usize {
    if hdrop == NULL_HDROP || hdrop > 8 {
        return 0;
    }

    let drops = DROP_FILES.lock();
    let idx = hdrop - 1;

    if !drops[idx].in_use {
        return 0;
    }

    if let Some(file) = drops[idx].get_file(index) {
        let len = super::strhelp::str_len(file);
        let copy_len = len.min(buffer.len().saturating_sub(1));
        buffer[..copy_len].copy_from_slice(&file[..copy_len]);
        if copy_len < buffer.len() {
            buffer[copy_len] = 0;
        }
        copy_len
    } else {
        0
    }
}

/// Query drop point
pub fn drag_query_point(hdrop: HDROP, pt: &mut Point) -> bool {
    if hdrop == NULL_HDROP || hdrop > 8 {
        return false;
    }

    let drops = DROP_FILES.lock();
    let idx = hdrop - 1;

    if drops[idx].in_use {
        *pt = drops[idx].pt;
        !drops[idx].non_client
    } else {
        false
    }
}

/// Finish drag operation (free HDROP)
pub fn drag_finish(hdrop: HDROP) {
    if hdrop == NULL_HDROP || hdrop > 8 {
        return;
    }

    let mut drops = DROP_FILES.lock();
    let idx = hdrop - 1;
    drops[idx] = DropFiles::new();
}

/// Check if window accepts drops
pub fn is_drop_target(hwnd: HWND) -> bool {
    let targets = DROP_TARGETS.lock();

    for entry in targets.iter() {
        if entry.in_use && entry.hwnd == hwnd {
            return true;
        }
    }

    false
}

/// Find drop target at point
pub fn find_drop_target_at_point(_pt: Point) -> HWND {
    // In a real implementation, this would do hit testing
    // For now, return NULL
    UserHandle::NULL
}

// ============================================================================
// Drag Image API
// ============================================================================

/// Begin drag image
pub fn image_list_begin_drag(
    _himl: usize,
    _index: usize,
    hotspot_x: i32,
    hotspot_y: i32,
) -> bool {
    let mut image = DRAG_IMAGE.lock();

    image.active = true;
    image.offset = Point { x: hotspot_x, y: hotspot_y };
    image.visible = false;

    true
}

/// End drag image
pub fn image_list_end_drag() {
    let mut image = DRAG_IMAGE.lock();
    *image = DragImageInfo::new();
}

/// Enter drag (show image)
pub fn image_list_drag_enter(hwnd: HWND, x: i32, y: i32) -> bool {
    let _ = hwnd;
    let mut image = DRAG_IMAGE.lock();

    if !image.active {
        return false;
    }

    image.pt = Point { x, y };
    image.visible = true;

    true
}

/// Leave drag (hide image)
pub fn image_list_drag_leave(hwnd: HWND) -> bool {
    let _ = hwnd;
    let mut image = DRAG_IMAGE.lock();

    image.visible = false;

    true
}

/// Move drag image
pub fn image_list_drag_move(x: i32, y: i32) -> bool {
    let mut image = DRAG_IMAGE.lock();

    if !image.active {
        return false;
    }

    image.pt = Point { x, y };

    true
}

/// Show/hide drag image
pub fn image_list_drag_show_nolock(show: bool) -> bool {
    let mut image = DRAG_IMAGE.lock();

    if !image.active {
        return false;
    }

    image.visible = show;

    true
}

/// Get drag image position
pub fn get_drag_image_position() -> Option<Point> {
    let image = DRAG_IMAGE.lock();

    if image.active {
        Some(image.pt)
    } else {
        None
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> DragDropStats {
    let targets = DROP_TARGETS.lock();
    let drops = DROP_FILES.lock();
    let state = DRAG_STATE.lock();

    let mut target_count = 0;
    let mut drop_count = 0;

    for entry in targets.iter() {
        if entry.in_use {
            target_count += 1;
        }
    }

    for drop in drops.iter() {
        if drop.in_use {
            drop_count += 1;
        }
    }

    DragDropStats {
        max_targets: MAX_DROP_TARGETS,
        registered_targets: target_count,
        active_drops: drop_count,
        is_dragging: state.active,
    }
}

/// Drag-drop statistics
#[derive(Debug, Clone, Copy)]
pub struct DragDropStats {
    pub max_targets: usize,
    pub registered_targets: usize,
    pub active_drops: usize,
    pub is_dragging: bool,
}
