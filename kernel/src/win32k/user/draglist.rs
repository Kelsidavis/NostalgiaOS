//! DragList Implementation
//!
//! Windows DragList for drag-and-drop list reordering.
//! Based on Windows Server 2003 commctrl.h.
//!
//! # Features
//!
//! - Drag items within listbox
//! - Insert cursor feedback
//! - Automatic scrolling
//! - Notification messages
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - DL_* messages and notifications

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, Point};

// ============================================================================
// DragList Messages (DL_*)
// ============================================================================

/// Drag list message base
pub const DL_BEGINDRAG: u32 = 0x0485; // WM_USER + 133

/// Dragging notification
pub const DL_DRAGGING: u32 = 0x0486;

/// Dropped notification
pub const DL_DROPPED: u32 = 0x0487;

/// Cancel drag notification
pub const DL_CANCELDRAG: u32 = 0x0488;

// ============================================================================
// Drag Cursor Types (DL_*)
// ============================================================================

/// Move cursor - can drop here
pub const DL_MOVECURSOR: u32 = 0;

/// Copy cursor (with Ctrl key)
pub const DL_COPYCURSOR: u32 = 1;

/// Stop cursor - cannot drop here
pub const DL_STOPCURSOR: u32 = 2;

// ============================================================================
// Constants
// ============================================================================

/// Maximum drag lists
pub const MAX_DRAG_LISTS: usize = 32;

/// Scroll timer interval (ms)
pub const DRAG_SCROLL_INTERVAL: u32 = 50;

/// Scroll margin (pixels from edge to start scrolling)
pub const DRAG_SCROLL_MARGIN: i32 = 10;

// ============================================================================
// Drag State
// ============================================================================

/// Drag list state
#[derive(Clone)]
pub struct DragListState {
    /// Listbox is registered for drag
    pub in_use: bool,
    /// Listbox window handle
    pub hwnd_list: HWND,
    /// Parent window handle (receives notifications)
    pub hwnd_parent: HWND,
    /// Currently dragging
    pub dragging: bool,
    /// Drag started
    pub drag_started: bool,
    /// Start item index
    pub start_index: i32,
    /// Current item index (where cursor is)
    pub current_index: i32,
    /// Start point
    pub start_point: Point,
    /// Current point
    pub current_point: Point,
    /// Last cursor shown
    pub cursor_type: u32,
    /// Scrolling timer active
    pub scroll_timer_active: bool,
    /// Scroll direction (negative = up, positive = down)
    pub scroll_direction: i32,
    /// Item height (cached)
    pub item_height: i32,
    /// Visible item count (cached)
    pub visible_count: i32,
}

impl DragListState {
    /// Create new drag list state
    pub const fn new() -> Self {
        Self {
            in_use: false,
            hwnd_list: UserHandle::NULL,
            hwnd_parent: UserHandle::NULL,
            dragging: false,
            drag_started: false,
            start_index: -1,
            current_index: -1,
            start_point: Point { x: 0, y: 0 },
            current_point: Point { x: 0, y: 0 },
            cursor_type: DL_MOVECURSOR,
            scroll_timer_active: false,
            scroll_direction: 0,
            item_height: 16,
            visible_count: 10,
        }
    }

    /// Reset state
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Begin drag operation
    pub fn begin_drag(&mut self, index: i32, x: i32, y: i32) -> bool {
        if index < 0 {
            return false;
        }

        self.drag_started = true;
        self.dragging = true;
        self.start_index = index;
        self.current_index = index;
        self.start_point.x = x;
        self.start_point.y = y;
        self.current_point.x = x;
        self.current_point.y = y;
        self.cursor_type = DL_MOVECURSOR;

        true
    }

    /// Update drag position
    pub fn update_drag(&mut self, x: i32, y: i32) -> i32 {
        if !self.dragging {
            return -1;
        }

        self.current_point.x = x;
        self.current_point.y = y;

        // Calculate which item the cursor is over
        // This is simplified - real implementation would use LB_ITEMFROMPOINT
        let item_index = y / self.item_height.max(1);

        self.current_index = item_index;
        item_index
    }

    /// End drag operation
    pub fn end_drag(&mut self) -> (i32, i32) {
        let result = (self.start_index, self.current_index);
        self.dragging = false;
        self.scroll_timer_active = false;
        result
    }

    /// Cancel drag operation
    pub fn cancel_drag(&mut self) {
        self.dragging = false;
        self.current_index = self.start_index;
        self.scroll_timer_active = false;
    }

    /// Check if should auto-scroll
    pub fn check_scroll(&mut self, client_height: i32) -> i32 {
        if !self.dragging {
            return 0;
        }

        let y = self.current_point.y;

        if y < DRAG_SCROLL_MARGIN {
            // Scroll up
            self.scroll_direction = -1;
            -1
        } else if y > client_height - DRAG_SCROLL_MARGIN {
            // Scroll down
            self.scroll_direction = 1;
            1
        } else {
            self.scroll_direction = 0;
            0
        }
    }

    /// Get insert position (between items)
    pub fn get_insert_index(&self) -> i32 {
        if !self.dragging {
            return -1;
        }

        // Calculate insert position based on whether cursor is in upper or lower half of item
        let y_in_item = self.current_point.y % self.item_height.max(1);
        let half = self.item_height / 2;

        if y_in_item < half {
            self.current_index
        } else {
            self.current_index + 1
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global drag list storage
static DRAG_LISTS: SpinLock<[DragListState; MAX_DRAG_LISTS]> =
    SpinLock::new([const { DragListState::new() }; MAX_DRAG_LISTS]);

/// Currently active drag (only one at a time)
static ACTIVE_DRAG: SpinLock<Option<usize>> = SpinLock::new(None);

// ============================================================================
// DRAGLISTINFO Structure
// ============================================================================

/// Drag list info for notifications
#[derive(Debug, Clone, Copy)]
pub struct DragListInfo {
    /// Notification code (DL_*)
    pub notification: u32,
    /// Listbox handle
    pub hwnd_list: HWND,
    /// Item being dragged
    pub item_id: i32,
    /// Cursor position (client coords)
    pub pt: Point,
}

impl DragListInfo {
    /// Create new drag list info
    pub const fn new() -> Self {
        Self {
            notification: 0,
            hwnd_list: UserHandle::NULL,
            item_id: -1,
            pt: Point { x: 0, y: 0 },
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Initialize DragList subsystem
pub fn init() {
    crate::serial_println!("[USER] DragList initialized");
}

/// Make a listbox a drag list box
pub fn make_drag_list(hwnd_list: HWND, hwnd_parent: HWND) -> bool {
    let mut lists = DRAG_LISTS.lock();

    for (_i, state) in lists.iter_mut().enumerate() {
        if !state.in_use {
            state.reset();
            state.in_use = true;
            state.hwnd_list = hwnd_list;
            state.hwnd_parent = hwnd_parent;
            return true;
        }

        // Already registered
        if state.hwnd_list == hwnd_list {
            return true;
        }
    }

    false
}

/// Get the drag list index for a listbox
fn find_drag_list(hwnd_list: HWND) -> Option<usize> {
    let lists = DRAG_LISTS.lock();

    for (i, state) in lists.iter().enumerate() {
        if state.in_use && state.hwnd_list == hwnd_list {
            return Some(i);
        }
    }

    None
}

/// Begin dragging an item
pub fn begin_drag(hwnd_list: HWND, index: i32, x: i32, y: i32) -> bool {
    let idx = match find_drag_list(hwnd_list) {
        Some(i) => i,
        None => return false,
    };

    let mut lists = DRAG_LISTS.lock();
    if !lists[idx].in_use {
        return false;
    }

    if lists[idx].begin_drag(index, x, y) {
        *ACTIVE_DRAG.lock() = Some(idx);
        true
    } else {
        false
    }
}

/// Handle drag movement
pub fn dragging(hwnd_list: HWND, x: i32, y: i32) -> DragListInfo {
    let idx = match find_drag_list(hwnd_list) {
        Some(i) => i,
        None => return DragListInfo::new(),
    };

    let mut lists = DRAG_LISTS.lock();
    if !lists[idx].in_use || !lists[idx].dragging {
        return DragListInfo::new();
    }

    let item_id = lists[idx].update_drag(x, y);

    DragListInfo {
        notification: DL_DRAGGING,
        hwnd_list,
        item_id,
        pt: Point { x, y },
    }
}

/// Complete drag operation (drop)
pub fn dropped(hwnd_list: HWND) -> DragListInfo {
    let idx = match find_drag_list(hwnd_list) {
        Some(i) => i,
        None => return DragListInfo::new(),
    };

    let mut lists = DRAG_LISTS.lock();
    if !lists[idx].in_use || !lists[idx].dragging {
        return DragListInfo::new();
    }

    let (_, current) = lists[idx].end_drag();
    *ACTIVE_DRAG.lock() = None;

    DragListInfo {
        notification: DL_DROPPED,
        hwnd_list,
        item_id: current,
        pt: lists[idx].current_point,
    }
}

/// Cancel drag operation
pub fn cancel_drag(hwnd_list: HWND) -> DragListInfo {
    let idx = match find_drag_list(hwnd_list) {
        Some(i) => i,
        None => return DragListInfo::new(),
    };

    let mut lists = DRAG_LISTS.lock();
    if !lists[idx].in_use {
        return DragListInfo::new();
    }

    lists[idx].cancel_drag();
    *ACTIVE_DRAG.lock() = None;

    DragListInfo {
        notification: DL_CANCELDRAG,
        hwnd_list,
        item_id: -1,
        pt: lists[idx].current_point,
    }
}

/// Get insert index (for drawing insertion mark)
pub fn get_insert_index(hwnd_list: HWND) -> i32 {
    let idx = match find_drag_list(hwnd_list) {
        Some(i) => i,
        None => return -1,
    };

    let lists = DRAG_LISTS.lock();
    if !lists[idx].in_use || !lists[idx].dragging {
        return -1;
    }

    lists[idx].get_insert_index()
}

/// Check if should scroll
pub fn check_scroll(hwnd_list: HWND, client_height: i32) -> i32 {
    let idx = match find_drag_list(hwnd_list) {
        Some(i) => i,
        None => return 0,
    };

    let mut lists = DRAG_LISTS.lock();
    if !lists[idx].in_use {
        return 0;
    }

    lists[idx].check_scroll(client_height)
}

/// Draw insert mark at position
pub fn draw_insert(hwnd_list: HWND, item_index: i32) {
    // In a real implementation, this would draw a horizontal line
    // between items to show where the dragged item will be inserted
    let _ = (hwnd_list, item_index);
}

/// Get the cursor type for current drag position
pub fn get_cursor_type(hwnd_list: HWND) -> u32 {
    let idx = match find_drag_list(hwnd_list) {
        Some(i) => i,
        None => return DL_STOPCURSOR,
    };

    let lists = DRAG_LISTS.lock();
    if !lists[idx].in_use || !lists[idx].dragging {
        return DL_STOPCURSOR;
    }

    lists[idx].cursor_type
}

/// Set the cursor type
pub fn set_cursor_type(hwnd_list: HWND, cursor_type: u32) {
    let idx = match find_drag_list(hwnd_list) {
        Some(i) => i,
        None => return,
    };

    let mut lists = DRAG_LISTS.lock();
    if !lists[idx].in_use {
        return;
    }

    lists[idx].cursor_type = cursor_type;
}

/// Check if currently dragging
pub fn is_dragging(hwnd_list: HWND) -> bool {
    let idx = match find_drag_list(hwnd_list) {
        Some(i) => i,
        None => return false,
    };

    let lists = DRAG_LISTS.lock();
    lists[idx].in_use && lists[idx].dragging
}

/// Get drag start index
pub fn get_start_index(hwnd_list: HWND) -> i32 {
    let idx = match find_drag_list(hwnd_list) {
        Some(i) => i,
        None => return -1,
    };

    let lists = DRAG_LISTS.lock();
    if !lists[idx].in_use {
        return -1;
    }

    lists[idx].start_index
}

/// Get current drag index
pub fn get_current_index(hwnd_list: HWND) -> i32 {
    let idx = match find_drag_list(hwnd_list) {
        Some(i) => i,
        None => return -1,
    };

    let lists = DRAG_LISTS.lock();
    if !lists[idx].in_use {
        return -1;
    }

    lists[idx].current_index
}

/// Set item height for calculations
pub fn set_item_height(hwnd_list: HWND, height: i32) {
    let idx = match find_drag_list(hwnd_list) {
        Some(i) => i,
        None => return,
    };

    let mut lists = DRAG_LISTS.lock();
    if !lists[idx].in_use {
        return;
    }

    lists[idx].item_height = height.max(1);
}

/// Unregister a drag list box
pub fn destroy(hwnd_list: HWND) -> bool {
    let idx = match find_drag_list(hwnd_list) {
        Some(i) => i,
        None => return false,
    };

    let mut lists = DRAG_LISTS.lock();

    // Cancel any active drag
    if lists[idx].dragging {
        lists[idx].cancel_drag();
        *ACTIVE_DRAG.lock() = None;
    }

    lists[idx].reset();
    true
}

/// Get statistics
pub fn get_stats() -> DragListStats {
    let lists = DRAG_LISTS.lock();

    let mut active_count = 0;
    let mut dragging_count = 0;

    for state in lists.iter() {
        if state.in_use {
            active_count += 1;
            if state.dragging {
                dragging_count += 1;
            }
        }
    }

    DragListStats {
        max_lists: MAX_DRAG_LISTS,
        registered_lists: active_count,
        currently_dragging: dragging_count,
    }
}

/// DragList statistics
#[derive(Debug, Clone, Copy)]
pub struct DragListStats {
    pub max_lists: usize,
    pub registered_lists: usize,
    pub currently_dragging: usize,
}
