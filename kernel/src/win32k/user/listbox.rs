//! ListBox Control
//!
//! Implementation of Windows NT-style ListBox control.
//! Provides scrollable list of selectable items.
//!
//! # Features
//!
//! - Single and multiple selection modes
//! - Sorted and unsorted lists
//! - Variable and fixed item height
//! - Horizontal scrolling support
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/comctl32/v6/listbox.c`

use super::super::{HWND, UserHandle, Rect, Point, ColorRef};
use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// ListBox Messages (LB_*)
// ============================================================================

pub const LB_ADDSTRING: u32 = 0x0180;
pub const LB_INSERTSTRING: u32 = 0x0181;
pub const LB_DELETESTRING: u32 = 0x0182;
pub const LB_SELITEMRANGEEX: u32 = 0x0183;
pub const LB_RESETCONTENT: u32 = 0x0184;
pub const LB_SETSEL: u32 = 0x0185;
pub const LB_SETCURSEL: u32 = 0x0186;
pub const LB_GETSEL: u32 = 0x0187;
pub const LB_GETCURSEL: u32 = 0x0188;
pub const LB_GETTEXT: u32 = 0x0189;
pub const LB_GETTEXTLEN: u32 = 0x018A;
pub const LB_GETCOUNT: u32 = 0x018B;
pub const LB_SELECTSTRING: u32 = 0x018C;
pub const LB_DIR: u32 = 0x018D;
pub const LB_GETTOPINDEX: u32 = 0x018E;
pub const LB_FINDSTRING: u32 = 0x018F;
pub const LB_GETSELCOUNT: u32 = 0x0190;
pub const LB_GETSELITEMS: u32 = 0x0191;
pub const LB_SETTABSTOPS: u32 = 0x0192;
pub const LB_GETHORIZONTALEXTENT: u32 = 0x0193;
pub const LB_SETHORIZONTALEXTENT: u32 = 0x0194;
pub const LB_SETCOLUMNWIDTH: u32 = 0x0195;
pub const LB_ADDFILE: u32 = 0x0196;
pub const LB_SETTOPINDEX: u32 = 0x0197;
pub const LB_GETITEMRECT: u32 = 0x0198;
pub const LB_GETITEMDATA: u32 = 0x0199;
pub const LB_SETITEMDATA: u32 = 0x019A;
pub const LB_SELITEMRANGE: u32 = 0x019B;
pub const LB_SETANCHORINDEX: u32 = 0x019C;
pub const LB_GETANCHORINDEX: u32 = 0x019D;
pub const LB_SETCARETINDEX: u32 = 0x019E;
pub const LB_GETCARETINDEX: u32 = 0x019F;
pub const LB_SETITEMHEIGHT: u32 = 0x01A0;
pub const LB_GETITEMHEIGHT: u32 = 0x01A1;
pub const LB_FINDSTRINGEXACT: u32 = 0x01A2;
pub const LB_SETLOCALE: u32 = 0x01A5;
pub const LB_GETLOCALE: u32 = 0x01A6;
pub const LB_SETCOUNT: u32 = 0x01A7;

/// ListBox error return value
pub const LB_ERR: i32 = -1;
pub const LB_ERRSPACE: i32 = -2;
pub const LB_OKAY: i32 = 0;

// ============================================================================
// ListBox Styles (LBS_*)
// ============================================================================

/// Notify parent of actions
pub const LBS_NOTIFY: u32 = 0x0001;
/// Sort items alphabetically
pub const LBS_SORT: u32 = 0x0002;
/// Don't redraw when adding items
pub const LBS_NOREDRAW: u32 = 0x0004;
/// Allow multiple selection
pub const LBS_MULTIPLESEL: u32 = 0x0008;
/// Owner-draw with fixed item height
pub const LBS_OWNERDRAWFIXED: u32 = 0x0010;
/// Owner-draw with variable item height
pub const LBS_OWNERDRAWVARIABLE: u32 = 0x0020;
/// Has string data
pub const LBS_HASSTRINGS: u32 = 0x0040;
/// Use tab stops
pub const LBS_USETABSTOPS: u32 = 0x0080;
/// Don't size to integral height
pub const LBS_NOINTEGRALHEIGHT: u32 = 0x0100;
/// Multi-column listbox
pub const LBS_MULTICOLUMN: u32 = 0x0200;
/// Send keyboard input to parent
pub const LBS_WANTKEYBOARDINPUT: u32 = 0x0400;
/// Extended selection mode
pub const LBS_EXTENDEDSEL: u32 = 0x0800;
/// Disable rather than hide scroll bars
pub const LBS_DISABLENOSCROLL: u32 = 0x1000;
/// No data (virtual listbox)
pub const LBS_NODATA: u32 = 0x2000;
/// No selection allowed
pub const LBS_NOSEL: u32 = 0x4000;
/// Part of a combo box
pub const LBS_COMBOBOX: u32 = 0x8000;

// ============================================================================
// ListBox Notifications (LBN_*)
// ============================================================================

pub const LBN_ERRSPACE: u32 = u32::MAX; // -1
pub const LBN_SELCHANGE: u32 = 1;
pub const LBN_DBLCLK: u32 = 2;
pub const LBN_SELCANCEL: u32 = 3;
pub const LBN_SETFOCUS: u32 = 4;
pub const LBN_KILLFOCUS: u32 = 5;

// ============================================================================
// Constants
// ============================================================================

/// Maximum items in a listbox
const MAX_ITEMS: usize = 256;

/// Maximum item text length
const MAX_ITEM_TEXT: usize = 256;

/// Maximum listbox instances
const MAX_LISTBOXES: usize = 32;

/// Default item height
const DEFAULT_ITEM_HEIGHT: i32 = 16;

// ============================================================================
// ListBox Item
// ============================================================================

/// ListBox item
#[derive(Clone)]
struct ListBoxItem {
    /// Item text
    text: [u8; MAX_ITEM_TEXT],
    /// Text length
    text_len: usize,
    /// Item data (application-defined)
    data: usize,
    /// Item height (for variable height)
    height: i32,
    /// Is item selected?
    selected: bool,
    /// Is slot in use?
    in_use: bool,
}

impl ListBoxItem {
    const fn empty() -> Self {
        Self {
            text: [0; MAX_ITEM_TEXT],
            text_len: 0,
            data: 0,
            height: DEFAULT_ITEM_HEIGHT,
            selected: false,
            in_use: false,
        }
    }
}

// ============================================================================
// ListBox State
// ============================================================================

/// ListBox state
#[derive(Clone)]
struct ListBoxState {
    /// Owner window
    hwnd: HWND,
    /// Parent window
    hwnd_parent: HWND,
    /// ListBox style
    style: u32,
    /// Items
    items: [ListBoxItem; MAX_ITEMS],
    /// Number of items
    count: usize,
    /// Top visible item index
    top_index: i32,
    /// Current selection (single-select mode)
    cur_sel: i32,
    /// Anchor index (for extended selection)
    anchor_index: i32,
    /// Caret index
    caret_index: i32,
    /// Item height (fixed height mode)
    item_height: i32,
    /// Horizontal extent (for scrolling)
    horizontal_extent: i32,
    /// Column width (multi-column mode)
    column_width: i32,
    /// Has focus?
    has_focus: bool,
    /// Should redraw?
    redraw: bool,
    /// Is slot in use?
    in_use: bool,
}

impl ListBoxState {
    const fn empty() -> Self {
        Self {
            hwnd: UserHandle::NULL,
            hwnd_parent: UserHandle::NULL,
            style: 0,
            items: [ListBoxItem::empty(); MAX_ITEMS],
            count: 0,
            top_index: 0,
            cur_sel: -1,
            anchor_index: 0,
            caret_index: 0,
            item_height: DEFAULT_ITEM_HEIGHT,
            horizontal_extent: 0,
            column_width: 0,
            has_focus: false,
            redraw: true,
            in_use: false,
        }
    }
}

// Need to implement Copy for the const initialization
impl Copy for ListBoxItem {}
impl Copy for ListBoxState {}

/// ListBox storage
static LISTBOXES: SpinLock<[ListBoxState; MAX_LISTBOXES]> = SpinLock::new([ListBoxState::empty(); MAX_LISTBOXES]);

static LISTBOX_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize listbox subsystem
pub fn init() {
    if LISTBOX_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[USER/ListBox] ListBox subsystem initialized");
    LISTBOX_INITIALIZED.store(true, Ordering::Release);
}

// ============================================================================
// ListBox Management
// ============================================================================

/// Create a listbox
pub fn create_listbox(hwnd: HWND, parent: HWND, style: u32) -> bool {
    let mut listboxes = LISTBOXES.lock();

    for lb in listboxes.iter_mut() {
        if !lb.in_use {
            lb.hwnd = hwnd;
            lb.hwnd_parent = parent;
            lb.style = style;
            lb.count = 0;
            lb.top_index = 0;
            lb.cur_sel = -1;
            lb.anchor_index = 0;
            lb.caret_index = 0;
            lb.item_height = DEFAULT_ITEM_HEIGHT;
            lb.redraw = (style & LBS_NOREDRAW) == 0;
            lb.in_use = true;

            crate::serial_println!("[USER/ListBox] Created listbox for window {:x}", hwnd.raw());
            return true;
        }
    }

    false
}

/// Destroy a listbox
pub fn destroy_listbox(hwnd: HWND) -> bool {
    let mut listboxes = LISTBOXES.lock();

    for lb in listboxes.iter_mut() {
        if lb.in_use && lb.hwnd == hwnd {
            lb.in_use = false;
            lb.count = 0;
            crate::serial_println!("[USER/ListBox] Destroyed listbox {:x}", hwnd.raw());
            return true;
        }
    }

    false
}

/// Find listbox by window handle
fn find_listbox_index(hwnd: HWND) -> Option<usize> {
    let listboxes = LISTBOXES.lock();
    for (i, lb) in listboxes.iter().enumerate() {
        if lb.in_use && lb.hwnd == hwnd {
            return Some(i);
        }
    }
    None
}

// ============================================================================
// Item Management
// ============================================================================

/// Add a string to the listbox
pub fn add_string(hwnd: HWND, text: &str) -> i32 {
    let mut listboxes = LISTBOXES.lock();

    for lb in listboxes.iter_mut() {
        if lb.in_use && lb.hwnd == hwnd {
            if lb.count >= MAX_ITEMS {
                return LB_ERRSPACE;
            }

            let index = if (lb.style & LBS_SORT) != 0 {
                // Find insertion point for sorted list
                find_sorted_insert_pos(lb, text)
            } else {
                lb.count as i32
            };

            // Shift items down if inserting in middle
            if (index as usize) < lb.count {
                for i in (index as usize..lb.count).rev() {
                    lb.items[i + 1] = lb.items[i];
                }
            }

            // Insert the new item
            let item = &mut lb.items[index as usize];
            let len = text.len().min(MAX_ITEM_TEXT - 1);
            item.text[..len].copy_from_slice(&text.as_bytes()[..len]);
            item.text_len = len;
            item.data = 0;
            item.height = lb.item_height;
            item.selected = false;
            item.in_use = true;

            lb.count += 1;

            return index;
        }
    }

    LB_ERR
}

/// Insert string at specific index
pub fn insert_string(hwnd: HWND, index: i32, text: &str) -> i32 {
    let mut listboxes = LISTBOXES.lock();

    for lb in listboxes.iter_mut() {
        if lb.in_use && lb.hwnd == hwnd {
            if lb.count >= MAX_ITEMS {
                return LB_ERRSPACE;
            }

            let insert_index = if index < 0 {
                lb.count
            } else {
                (index as usize).min(lb.count)
            };

            // Shift items down
            for i in (insert_index..lb.count).rev() {
                lb.items[i + 1] = lb.items[i];
            }

            // Insert the new item
            let item = &mut lb.items[insert_index];
            let len = text.len().min(MAX_ITEM_TEXT - 1);
            item.text[..len].copy_from_slice(&text.as_bytes()[..len]);
            item.text_len = len;
            item.data = 0;
            item.height = lb.item_height;
            item.selected = false;
            item.in_use = true;

            lb.count += 1;

            return insert_index as i32;
        }
    }

    LB_ERR
}

/// Find sorted insertion position
fn find_sorted_insert_pos(lb: &ListBoxState, text: &str) -> i32 {
    for i in 0..lb.count {
        let item_text = core::str::from_utf8(&lb.items[i].text[..lb.items[i].text_len])
            .unwrap_or("");
        if text < item_text {
            return i as i32;
        }
    }
    lb.count as i32
}

/// Delete a string from the listbox
pub fn delete_string(hwnd: HWND, index: i32) -> i32 {
    let mut listboxes = LISTBOXES.lock();

    for lb in listboxes.iter_mut() {
        if lb.in_use && lb.hwnd == hwnd {
            if index < 0 || index as usize >= lb.count {
                return LB_ERR;
            }

            // Shift items up
            for i in (index as usize)..(lb.count - 1) {
                lb.items[i] = lb.items[i + 1];
            }

            lb.count -= 1;
            lb.items[lb.count].in_use = false;

            // Adjust selection if needed
            if lb.cur_sel >= lb.count as i32 {
                lb.cur_sel = lb.count as i32 - 1;
            }

            return lb.count as i32;
        }
    }

    LB_ERR
}

/// Reset listbox content
pub fn reset_content(hwnd: HWND) -> bool {
    let mut listboxes = LISTBOXES.lock();

    for lb in listboxes.iter_mut() {
        if lb.in_use && lb.hwnd == hwnd {
            for item in lb.items.iter_mut() {
                item.in_use = false;
                item.selected = false;
            }
            lb.count = 0;
            lb.cur_sel = -1;
            lb.top_index = 0;
            return true;
        }
    }

    false
}

/// Get item count
pub fn get_count(hwnd: HWND) -> i32 {
    let listboxes = LISTBOXES.lock();

    for lb in listboxes.iter() {
        if lb.in_use && lb.hwnd == hwnd {
            return lb.count as i32;
        }
    }

    LB_ERR
}

/// Get item text
pub fn get_text(hwnd: HWND, index: i32, buffer: &mut [u8]) -> i32 {
    let listboxes = LISTBOXES.lock();

    for lb in listboxes.iter() {
        if lb.in_use && lb.hwnd == hwnd {
            if index < 0 || index as usize >= lb.count {
                return LB_ERR;
            }

            let item = &lb.items[index as usize];
            let len = item.text_len.min(buffer.len());
            buffer[..len].copy_from_slice(&item.text[..len]);
            return len as i32;
        }
    }

    LB_ERR
}

/// Get item text length
pub fn get_text_len(hwnd: HWND, index: i32) -> i32 {
    let listboxes = LISTBOXES.lock();

    for lb in listboxes.iter() {
        if lb.in_use && lb.hwnd == hwnd {
            if index < 0 || index as usize >= lb.count {
                return LB_ERR;
            }

            return lb.items[index as usize].text_len as i32;
        }
    }

    LB_ERR
}

// ============================================================================
// Selection Management
// ============================================================================

/// Get current selection (single-select)
pub fn get_cur_sel(hwnd: HWND) -> i32 {
    let listboxes = LISTBOXES.lock();

    for lb in listboxes.iter() {
        if lb.in_use && lb.hwnd == hwnd {
            return lb.cur_sel;
        }
    }

    LB_ERR
}

/// Set current selection (single-select)
pub fn set_cur_sel(hwnd: HWND, index: i32) -> i32 {
    let mut listboxes = LISTBOXES.lock();

    for lb in listboxes.iter_mut() {
        if lb.in_use && lb.hwnd == hwnd {
            // Clear previous selection
            if lb.cur_sel >= 0 && (lb.cur_sel as usize) < lb.count {
                lb.items[lb.cur_sel as usize].selected = false;
            }

            if index < 0 {
                lb.cur_sel = -1;
                return LB_OKAY;
            }

            if index as usize >= lb.count {
                return LB_ERR;
            }

            lb.cur_sel = index;
            lb.items[index as usize].selected = true;
            lb.caret_index = index;

            return index;
        }
    }

    LB_ERR
}

/// Get selection state of an item (multi-select)
pub fn get_sel(hwnd: HWND, index: i32) -> i32 {
    let listboxes = LISTBOXES.lock();

    for lb in listboxes.iter() {
        if lb.in_use && lb.hwnd == hwnd {
            if index < 0 || index as usize >= lb.count {
                return LB_ERR;
            }

            return if lb.items[index as usize].selected { 1 } else { 0 };
        }
    }

    LB_ERR
}

/// Set selection state of an item (multi-select)
pub fn set_sel(hwnd: HWND, select: bool, index: i32) -> i32 {
    let mut listboxes = LISTBOXES.lock();

    for lb in listboxes.iter_mut() {
        if lb.in_use && lb.hwnd == hwnd {
            if (lb.style & LBS_MULTIPLESEL) == 0 && (lb.style & LBS_EXTENDEDSEL) == 0 {
                return LB_ERR;
            }

            if index == -1 {
                // Select/deselect all
                for item in lb.items[..lb.count].iter_mut() {
                    item.selected = select;
                }
                return LB_OKAY;
            }

            if index < 0 || index as usize >= lb.count {
                return LB_ERR;
            }

            lb.items[index as usize].selected = select;
            return LB_OKAY;
        }
    }

    LB_ERR
}

/// Get selected item count (multi-select)
pub fn get_sel_count(hwnd: HWND) -> i32 {
    let listboxes = LISTBOXES.lock();

    for lb in listboxes.iter() {
        if lb.in_use && lb.hwnd == hwnd {
            if (lb.style & LBS_MULTIPLESEL) == 0 && (lb.style & LBS_EXTENDEDSEL) == 0 {
                return LB_ERR;
            }

            let count = lb.items[..lb.count].iter().filter(|i| i.selected).count();
            return count as i32;
        }
    }

    LB_ERR
}

/// Get selected items (multi-select)
pub fn get_sel_items(hwnd: HWND, buffer: &mut [i32]) -> i32 {
    let listboxes = LISTBOXES.lock();

    for lb in listboxes.iter() {
        if lb.in_use && lb.hwnd == hwnd {
            if (lb.style & LBS_MULTIPLESEL) == 0 && (lb.style & LBS_EXTENDEDSEL) == 0 {
                return LB_ERR;
            }

            let mut count = 0;
            for (i, item) in lb.items[..lb.count].iter().enumerate() {
                if item.selected && count < buffer.len() {
                    buffer[count] = i as i32;
                    count += 1;
                }
            }

            return count as i32;
        }
    }

    LB_ERR
}

// ============================================================================
// Scrolling
// ============================================================================

/// Get top index
pub fn get_top_index(hwnd: HWND) -> i32 {
    let listboxes = LISTBOXES.lock();

    for lb in listboxes.iter() {
        if lb.in_use && lb.hwnd == hwnd {
            return lb.top_index;
        }
    }

    LB_ERR
}

/// Set top index
pub fn set_top_index(hwnd: HWND, index: i32) -> i32 {
    let mut listboxes = LISTBOXES.lock();

    for lb in listboxes.iter_mut() {
        if lb.in_use && lb.hwnd == hwnd {
            if index < 0 || index as usize >= lb.count {
                return LB_ERR;
            }

            lb.top_index = index;
            return LB_OKAY;
        }
    }

    LB_ERR
}

// ============================================================================
// Item Data
// ============================================================================

/// Get item data
pub fn get_item_data(hwnd: HWND, index: i32) -> isize {
    let listboxes = LISTBOXES.lock();

    for lb in listboxes.iter() {
        if lb.in_use && lb.hwnd == hwnd {
            if index < 0 || index as usize >= lb.count {
                return LB_ERR as isize;
            }

            return lb.items[index as usize].data as isize;
        }
    }

    LB_ERR as isize
}

/// Set item data
pub fn set_item_data(hwnd: HWND, index: i32, data: usize) -> i32 {
    let mut listboxes = LISTBOXES.lock();

    for lb in listboxes.iter_mut() {
        if lb.in_use && lb.hwnd == hwnd {
            if index < 0 || index as usize >= lb.count {
                return LB_ERR;
            }

            lb.items[index as usize].data = data;
            return LB_OKAY;
        }
    }

    LB_ERR
}

// ============================================================================
// Item Height
// ============================================================================

/// Get item height
pub fn get_item_height(hwnd: HWND, index: i32) -> i32 {
    let listboxes = LISTBOXES.lock();

    for lb in listboxes.iter() {
        if lb.in_use && lb.hwnd == hwnd {
            if (lb.style & LBS_OWNERDRAWVARIABLE) != 0 {
                if index < 0 || index as usize >= lb.count {
                    return LB_ERR;
                }
                return lb.items[index as usize].height;
            } else {
                return lb.item_height;
            }
        }
    }

    LB_ERR
}

/// Set item height
pub fn set_item_height(hwnd: HWND, index: i32, height: i32) -> i32 {
    let mut listboxes = LISTBOXES.lock();

    for lb in listboxes.iter_mut() {
        if lb.in_use && lb.hwnd == hwnd {
            if height < 1 || height > 255 {
                return LB_ERR;
            }

            if (lb.style & LBS_OWNERDRAWVARIABLE) != 0 {
                if index < 0 || index as usize >= lb.count {
                    return LB_ERR;
                }
                lb.items[index as usize].height = height;
            } else {
                lb.item_height = height;
            }

            return LB_OKAY;
        }
    }

    LB_ERR
}

// ============================================================================
// Find/Select String
// ============================================================================

/// Find a string (case-insensitive prefix match)
pub fn find_string(hwnd: HWND, start: i32, text: &str) -> i32 {
    let listboxes = LISTBOXES.lock();

    for lb in listboxes.iter() {
        if lb.in_use && lb.hwnd == hwnd {
            let start_idx = if start < 0 { 0 } else { (start + 1) as usize };
            let text_lower = text.to_ascii_lowercase();

            // Search from start to end
            for i in start_idx..lb.count {
                let item_text = core::str::from_utf8(&lb.items[i].text[..lb.items[i].text_len])
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if item_text.starts_with(&text_lower) {
                    return i as i32;
                }
            }

            // Wrap around
            for i in 0..start_idx.min(lb.count) {
                let item_text = core::str::from_utf8(&lb.items[i].text[..lb.items[i].text_len])
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if item_text.starts_with(&text_lower) {
                    return i as i32;
                }
            }

            return LB_ERR;
        }
    }

    LB_ERR
}

/// Find exact string match
pub fn find_string_exact(hwnd: HWND, start: i32, text: &str) -> i32 {
    let listboxes = LISTBOXES.lock();

    for lb in listboxes.iter() {
        if lb.in_use && lb.hwnd == hwnd {
            let start_idx = if start < 0 { 0 } else { (start + 1) as usize };
            let text_lower = text.to_ascii_lowercase();

            for i in start_idx..lb.count {
                let item_text = core::str::from_utf8(&lb.items[i].text[..lb.items[i].text_len])
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if item_text == text_lower {
                    return i as i32;
                }
            }

            for i in 0..start_idx.min(lb.count) {
                let item_text = core::str::from_utf8(&lb.items[i].text[..lb.items[i].text_len])
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if item_text == text_lower {
                    return i as i32;
                }
            }

            return LB_ERR;
        }
    }

    LB_ERR
}

/// Select string (find and select)
pub fn select_string(hwnd: HWND, start: i32, text: &str) -> i32 {
    let index = find_string(hwnd, start, text);
    if index != LB_ERR {
        set_cur_sel(hwnd, index);
    }
    index
}

// ============================================================================
// Item Rectangle
// ============================================================================

/// Get item rectangle
pub fn get_item_rect(hwnd: HWND, index: i32, rect: &mut Rect) -> i32 {
    let listboxes = LISTBOXES.lock();

    for lb in listboxes.iter() {
        if lb.in_use && lb.hwnd == hwnd {
            if index < 0 || index as usize >= lb.count {
                return LB_ERR;
            }

            // Calculate item rectangle based on position
            let visible_index = index - lb.top_index;
            let y = visible_index * lb.item_height;

            rect.left = 0;
            rect.top = y;
            rect.right = 100; // Would be listbox width
            rect.bottom = y + lb.item_height;

            return LB_OKAY;
        }
    }

    LB_ERR
}

// ============================================================================
// Caret/Anchor Index
// ============================================================================

/// Get caret index
pub fn get_caret_index(hwnd: HWND) -> i32 {
    let listboxes = LISTBOXES.lock();

    for lb in listboxes.iter() {
        if lb.in_use && lb.hwnd == hwnd {
            return lb.caret_index;
        }
    }

    LB_ERR
}

/// Set caret index
pub fn set_caret_index(hwnd: HWND, index: i32) -> i32 {
    let mut listboxes = LISTBOXES.lock();

    for lb in listboxes.iter_mut() {
        if lb.in_use && lb.hwnd == hwnd {
            if index < 0 || index as usize >= lb.count {
                return LB_ERR;
            }

            lb.caret_index = index;
            return LB_OKAY;
        }
    }

    LB_ERR
}

/// Get anchor index
pub fn get_anchor_index(hwnd: HWND) -> i32 {
    let listboxes = LISTBOXES.lock();

    for lb in listboxes.iter() {
        if lb.in_use && lb.hwnd == hwnd {
            return lb.anchor_index;
        }
    }

    LB_ERR
}

/// Set anchor index
pub fn set_anchor_index(hwnd: HWND, index: i32) -> i32 {
    let mut listboxes = LISTBOXES.lock();

    for lb in listboxes.iter_mut() {
        if lb.in_use && lb.hwnd == hwnd {
            if index < 0 || index as usize >= lb.count {
                return LB_ERR;
            }

            lb.anchor_index = index;
            return LB_OKAY;
        }
    }

    LB_ERR
}

// ============================================================================
// Message Handler
// ============================================================================

/// Handle listbox message
pub fn handle_message(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> isize {
    match msg {
        LB_ADDSTRING => {
            // lparam is pointer to string - simplified for now
            add_string(hwnd, "") as isize
        }
        LB_DELETESTRING => delete_string(hwnd, wparam as i32) as isize,
        LB_RESETCONTENT => {
            reset_content(hwnd);
            0
        }
        LB_GETCOUNT => get_count(hwnd) as isize,
        LB_GETCURSEL => get_cur_sel(hwnd) as isize,
        LB_SETCURSEL => set_cur_sel(hwnd, wparam as i32) as isize,
        LB_GETSEL => get_sel(hwnd, wparam as i32) as isize,
        LB_SETSEL => set_sel(hwnd, wparam != 0, lparam as i32) as isize,
        LB_GETSELCOUNT => get_sel_count(hwnd) as isize,
        LB_GETTOPINDEX => get_top_index(hwnd) as isize,
        LB_SETTOPINDEX => set_top_index(hwnd, wparam as i32) as isize,
        LB_GETITEMDATA => get_item_data(hwnd, wparam as i32),
        LB_SETITEMDATA => set_item_data(hwnd, wparam as i32, lparam as usize) as isize,
        LB_GETITEMHEIGHT => get_item_height(hwnd, wparam as i32) as isize,
        LB_SETITEMHEIGHT => set_item_height(hwnd, wparam as i32, lparam as i32) as isize,
        LB_GETCARETINDEX => get_caret_index(hwnd) as isize,
        LB_SETCARETINDEX => set_caret_index(hwnd, wparam as i32) as isize,
        LB_GETANCHORINDEX => get_anchor_index(hwnd) as isize,
        LB_SETANCHORINDEX => set_anchor_index(hwnd, wparam as i32) as isize,
        _ => 0,
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// ListBox statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ListBoxStats {
    pub listbox_count: usize,
    pub total_items: usize,
}

/// Get listbox statistics
pub fn get_stats() -> ListBoxStats {
    let listboxes = LISTBOXES.lock();

    let mut listbox_count = 0;
    let mut total_items = 0;

    for lb in listboxes.iter() {
        if lb.in_use {
            listbox_count += 1;
            total_items += lb.count;
        }
    }

    ListBoxStats {
        listbox_count,
        total_items,
    }
}
