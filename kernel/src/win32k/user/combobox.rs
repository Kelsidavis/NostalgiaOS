//! ComboBox Control
//!
//! Implementation of Windows NT-style ComboBox control.
//! Combines an edit control with a dropdown list.
//!
//! # Types
//!
//! - **Simple**: Edit + always-visible list
//! - **Dropdown**: Edit + dropdown list
//! - **DropdownList**: Static text + dropdown list (no edit)
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/comctl32/v6/combo.c`

use super::super::{HWND, UserHandle, Rect, Point};
use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// ComboBox Messages (CB_*)
// ============================================================================

pub const CB_GETEDITSEL: u32 = 0x0140;
pub const CB_LIMITTEXT: u32 = 0x0141;
pub const CB_SETEDITSEL: u32 = 0x0142;
pub const CB_ADDSTRING: u32 = 0x0143;
pub const CB_DELETESTRING: u32 = 0x0144;
pub const CB_DIR: u32 = 0x0145;
pub const CB_GETCOUNT: u32 = 0x0146;
pub const CB_GETCURSEL: u32 = 0x0147;
pub const CB_GETLBTEXT: u32 = 0x0148;
pub const CB_GETLBTEXTLEN: u32 = 0x0149;
pub const CB_INSERTSTRING: u32 = 0x014A;
pub const CB_RESETCONTENT: u32 = 0x014B;
pub const CB_FINDSTRING: u32 = 0x014C;
pub const CB_SELECTSTRING: u32 = 0x014D;
pub const CB_SETCURSEL: u32 = 0x014E;
pub const CB_SHOWDROPDOWN: u32 = 0x014F;
pub const CB_GETITEMDATA: u32 = 0x0150;
pub const CB_SETITEMDATA: u32 = 0x0151;
pub const CB_GETDROPPEDCONTROLRECT: u32 = 0x0152;
pub const CB_SETITEMHEIGHT: u32 = 0x0153;
pub const CB_GETITEMHEIGHT: u32 = 0x0154;
pub const CB_SETEXTENDEDUI: u32 = 0x0155;
pub const CB_GETEXTENDEDUI: u32 = 0x0156;
pub const CB_GETDROPPEDSTATE: u32 = 0x0157;
pub const CB_FINDSTRINGEXACT: u32 = 0x0158;
pub const CB_SETLOCALE: u32 = 0x0159;
pub const CB_GETLOCALE: u32 = 0x015A;
pub const CB_GETTOPINDEX: u32 = 0x015B;
pub const CB_SETTOPINDEX: u32 = 0x015C;
pub const CB_GETHORIZONTALEXTENT: u32 = 0x015D;
pub const CB_SETHORIZONTALEXTENT: u32 = 0x015E;
pub const CB_GETDROPPEDWIDTH: u32 = 0x015F;
pub const CB_SETDROPPEDWIDTH: u32 = 0x0160;
pub const CB_INITSTORAGE: u32 = 0x0161;

/// ComboBox error values
pub const CB_OKAY: i32 = 0;
pub const CB_ERR: i32 = -1;
pub const CB_ERRSPACE: i32 = -2;

// ============================================================================
// ComboBox Styles (CBS_*)
// ============================================================================

/// Simple combo box (list always visible)
pub const CBS_SIMPLE: u32 = 0x0001;
/// Dropdown combo box (edit + dropdown)
pub const CBS_DROPDOWN: u32 = 0x0002;
/// Dropdown list (no edit, just dropdown)
pub const CBS_DROPDOWNLIST: u32 = 0x0003;
/// Owner-draw fixed height
pub const CBS_OWNERDRAWFIXED: u32 = 0x0010;
/// Owner-draw variable height
pub const CBS_OWNERDRAWVARIABLE: u32 = 0x0020;
/// Auto horizontal scroll in edit
pub const CBS_AUTOHSCROLL: u32 = 0x0040;
/// OEM character conversion
pub const CBS_OEMCONVERT: u32 = 0x0080;
/// Sort items
pub const CBS_SORT: u32 = 0x0100;
/// Has string data
pub const CBS_HASSTRINGS: u32 = 0x0200;
/// No integral height
pub const CBS_NOINTEGRALHEIGHT: u32 = 0x0400;
/// Disable instead of hide scrollbar
pub const CBS_DISABLENOSCROLL: u32 = 0x0800;
/// Convert to uppercase
pub const CBS_UPPERCASE: u32 = 0x2000;
/// Convert to lowercase
pub const CBS_LOWERCASE: u32 = 0x4000;

// ============================================================================
// ComboBox Notifications (CBN_*)
// ============================================================================

pub const CBN_ERRSPACE: u32 = u32::MAX; // -1
pub const CBN_SELCHANGE: u32 = 1;
pub const CBN_DBLCLK: u32 = 2;
pub const CBN_SETFOCUS: u32 = 3;
pub const CBN_KILLFOCUS: u32 = 4;
pub const CBN_EDITCHANGE: u32 = 5;
pub const CBN_EDITUPDATE: u32 = 6;
pub const CBN_DROPDOWN: u32 = 7;
pub const CBN_CLOSEUP: u32 = 8;
pub const CBN_SELENDOK: u32 = 9;
pub const CBN_SELENDCANCEL: u32 = 10;

// ============================================================================
// Constants
// ============================================================================

/// Maximum items in a combobox
const MAX_ITEMS: usize = 256;

/// Maximum item text length
const MAX_ITEM_TEXT: usize = 256;

/// Maximum combobox instances
const MAX_COMBOBOXES: usize = 32;

/// Default item height
const DEFAULT_ITEM_HEIGHT: i32 = 16;

/// Default dropdown height
const DEFAULT_DROPDOWN_HEIGHT: i32 = 200;

// ============================================================================
// ComboBox Item
// ============================================================================

/// ComboBox item
#[derive(Clone, Copy)]
struct ComboBoxItem {
    /// Item text
    text: [u8; MAX_ITEM_TEXT],
    /// Text length
    text_len: usize,
    /// Item data (application-defined)
    data: usize,
    /// Item height (for variable height)
    height: i32,
    /// Is slot in use?
    in_use: bool,
}

impl ComboBoxItem {
    const fn empty() -> Self {
        Self {
            text: [0; MAX_ITEM_TEXT],
            text_len: 0,
            data: 0,
            height: DEFAULT_ITEM_HEIGHT,
            in_use: false,
        }
    }
}

// ============================================================================
// ComboBox State
// ============================================================================

/// ComboBox type
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ComboBoxType {
    Simple,
    Dropdown,
    DropdownList,
}

/// ComboBox state
#[derive(Clone, Copy)]
struct ComboBoxState {
    /// Owner window
    hwnd: HWND,
    /// Parent window
    hwnd_parent: HWND,
    /// ComboBox style
    style: u32,
    /// ComboBox type
    cb_type: ComboBoxType,
    /// Items
    items: [ComboBoxItem; MAX_ITEMS],
    /// Number of items
    count: usize,
    /// Current selection
    cur_sel: i32,
    /// Top visible item in dropdown
    top_index: i32,
    /// Item height
    item_height: i32,
    /// Edit text (for dropdown types)
    edit_text: [u8; MAX_ITEM_TEXT],
    /// Edit text length
    edit_len: usize,
    /// Is dropdown visible?
    dropped: bool,
    /// Dropdown width
    drop_width: i32,
    /// Dropdown height
    drop_height: i32,
    /// Extended UI mode
    extended_ui: bool,
    /// Has focus?
    has_focus: bool,
    /// Is slot in use?
    in_use: bool,
}

impl ComboBoxState {
    const fn empty() -> Self {
        Self {
            hwnd: UserHandle::NULL,
            hwnd_parent: UserHandle::NULL,
            style: 0,
            cb_type: ComboBoxType::Dropdown,
            items: [ComboBoxItem::empty(); MAX_ITEMS],
            count: 0,
            cur_sel: -1,
            top_index: 0,
            item_height: DEFAULT_ITEM_HEIGHT,
            edit_text: [0; MAX_ITEM_TEXT],
            edit_len: 0,
            dropped: false,
            drop_width: 0,
            drop_height: DEFAULT_DROPDOWN_HEIGHT,
            extended_ui: false,
            has_focus: false,
            in_use: false,
        }
    }
}

/// ComboBox storage
static COMBOBOXES: SpinLock<[ComboBoxState; MAX_COMBOBOXES]> = SpinLock::new([ComboBoxState::empty(); MAX_COMBOBOXES]);

static COMBOBOX_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize combobox subsystem
pub fn init() {
    if COMBOBOX_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[USER/ComboBox] ComboBox subsystem initialized");
    COMBOBOX_INITIALIZED.store(true, Ordering::Release);
}

// ============================================================================
// ComboBox Management
// ============================================================================

/// Create a combobox
pub fn create_combobox(hwnd: HWND, parent: HWND, style: u32) -> bool {
    let mut comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter_mut() {
        if !cb.in_use {
            cb.hwnd = hwnd;
            cb.hwnd_parent = parent;
            cb.style = style;

            // Determine type
            let type_bits = style & 0x0003;
            cb.cb_type = match type_bits {
                0x0001 => ComboBoxType::Simple,
                0x0002 => ComboBoxType::Dropdown,
                0x0003 => ComboBoxType::DropdownList,
                _ => ComboBoxType::Dropdown,
            };

            cb.count = 0;
            cb.cur_sel = -1;
            cb.top_index = 0;
            cb.item_height = DEFAULT_ITEM_HEIGHT;
            cb.dropped = cb.cb_type == ComboBoxType::Simple;
            cb.in_use = true;

            crate::serial_println!("[USER/ComboBox] Created combobox for window {:x}", hwnd.raw());
            return true;
        }
    }

    false
}

/// Destroy a combobox
pub fn destroy_combobox(hwnd: HWND) -> bool {
    let mut comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter_mut() {
        if cb.in_use && cb.hwnd == hwnd {
            cb.in_use = false;
            cb.count = 0;
            crate::serial_println!("[USER/ComboBox] Destroyed combobox {:x}", hwnd.raw());
            return true;
        }
    }

    false
}

// ============================================================================
// Item Management
// ============================================================================

/// Add a string to the combobox
pub fn add_string(hwnd: HWND, text: &str) -> i32 {
    let mut comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter_mut() {
        if cb.in_use && cb.hwnd == hwnd {
            if cb.count >= MAX_ITEMS {
                return CB_ERRSPACE;
            }

            let index = if (cb.style & CBS_SORT) != 0 {
                find_sorted_insert_pos(cb, text)
            } else {
                cb.count as i32
            };

            // Shift items down if inserting in middle
            if (index as usize) < cb.count {
                for i in (index as usize..cb.count).rev() {
                    cb.items[i + 1] = cb.items[i];
                }
            }

            // Insert the new item
            let item = &mut cb.items[index as usize];
            let len = text.len().min(MAX_ITEM_TEXT - 1);
            item.text[..len].copy_from_slice(&text.as_bytes()[..len]);
            item.text_len = len;
            item.data = 0;
            item.height = cb.item_height;
            item.in_use = true;

            cb.count += 1;

            return index;
        }
    }

    CB_ERR
}

/// Find sorted insertion position
fn find_sorted_insert_pos(cb: &ComboBoxState, text: &str) -> i32 {
    for i in 0..cb.count {
        let item_text = core::str::from_utf8(&cb.items[i].text[..cb.items[i].text_len])
            .unwrap_or("");
        if text < item_text {
            return i as i32;
        }
    }
    cb.count as i32
}

/// Insert string at specific index
pub fn insert_string(hwnd: HWND, index: i32, text: &str) -> i32 {
    let mut comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter_mut() {
        if cb.in_use && cb.hwnd == hwnd {
            if cb.count >= MAX_ITEMS {
                return CB_ERRSPACE;
            }

            let insert_index = if index < 0 {
                cb.count
            } else {
                (index as usize).min(cb.count)
            };

            // Shift items down
            for i in (insert_index..cb.count).rev() {
                cb.items[i + 1] = cb.items[i];
            }

            // Insert the new item
            let item = &mut cb.items[insert_index];
            let len = text.len().min(MAX_ITEM_TEXT - 1);
            item.text[..len].copy_from_slice(&text.as_bytes()[..len]);
            item.text_len = len;
            item.data = 0;
            item.height = cb.item_height;
            item.in_use = true;

            cb.count += 1;

            return insert_index as i32;
        }
    }

    CB_ERR
}

/// Delete a string from the combobox
pub fn delete_string(hwnd: HWND, index: i32) -> i32 {
    let mut comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter_mut() {
        if cb.in_use && cb.hwnd == hwnd {
            if index < 0 || index as usize >= cb.count {
                return CB_ERR;
            }

            // Shift items up
            for i in (index as usize)..(cb.count - 1) {
                cb.items[i] = cb.items[i + 1];
            }

            cb.count -= 1;
            cb.items[cb.count].in_use = false;

            // Adjust selection if needed
            if cb.cur_sel >= cb.count as i32 {
                cb.cur_sel = cb.count as i32 - 1;
            }

            return cb.count as i32;
        }
    }

    CB_ERR
}

/// Reset combobox content
pub fn reset_content(hwnd: HWND) -> bool {
    let mut comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter_mut() {
        if cb.in_use && cb.hwnd == hwnd {
            for item in cb.items.iter_mut() {
                item.in_use = false;
            }
            cb.count = 0;
            cb.cur_sel = -1;
            cb.top_index = 0;
            cb.edit_len = 0;
            return true;
        }
    }

    false
}

/// Get item count
pub fn get_count(hwnd: HWND) -> i32 {
    let comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter() {
        if cb.in_use && cb.hwnd == hwnd {
            return cb.count as i32;
        }
    }

    CB_ERR
}

/// Get item text
pub fn get_lb_text(hwnd: HWND, index: i32, buffer: &mut [u8]) -> i32 {
    let comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter() {
        if cb.in_use && cb.hwnd == hwnd {
            if index < 0 || index as usize >= cb.count {
                return CB_ERR;
            }

            let item = &cb.items[index as usize];
            let len = item.text_len.min(buffer.len());
            buffer[..len].copy_from_slice(&item.text[..len]);
            return len as i32;
        }
    }

    CB_ERR
}

/// Get item text length
pub fn get_lb_text_len(hwnd: HWND, index: i32) -> i32 {
    let comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter() {
        if cb.in_use && cb.hwnd == hwnd {
            if index < 0 || index as usize >= cb.count {
                return CB_ERR;
            }

            return cb.items[index as usize].text_len as i32;
        }
    }

    CB_ERR
}

// ============================================================================
// Selection Management
// ============================================================================

/// Get current selection
pub fn get_cur_sel(hwnd: HWND) -> i32 {
    let comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter() {
        if cb.in_use && cb.hwnd == hwnd {
            return cb.cur_sel;
        }
    }

    CB_ERR
}

/// Set current selection
pub fn set_cur_sel(hwnd: HWND, index: i32) -> i32 {
    let mut comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter_mut() {
        if cb.in_use && cb.hwnd == hwnd {
            if index < -1 || index as usize >= cb.count {
                return CB_ERR;
            }

            cb.cur_sel = index;

            // Update edit text for dropdown types
            if cb.cb_type != ComboBoxType::Simple && index >= 0 {
                let item = &cb.items[index as usize];
                cb.edit_text[..item.text_len].copy_from_slice(&item.text[..item.text_len]);
                cb.edit_len = item.text_len;
            }

            return index;
        }
    }

    CB_ERR
}

// ============================================================================
// Dropdown Management
// ============================================================================

/// Show/hide dropdown
pub fn show_dropdown(hwnd: HWND, show: bool) -> bool {
    let mut comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter_mut() {
        if cb.in_use && cb.hwnd == hwnd {
            if cb.cb_type == ComboBoxType::Simple {
                return true; // Always visible
            }

            cb.dropped = show;

            if show {
                crate::serial_println!("[USER/ComboBox] Dropdown shown for {:x}", hwnd.raw());
            } else {
                crate::serial_println!("[USER/ComboBox] Dropdown hidden for {:x}", hwnd.raw());
            }

            return true;
        }
    }

    false
}

/// Get dropdown state
pub fn get_dropped_state(hwnd: HWND) -> bool {
    let comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter() {
        if cb.in_use && cb.hwnd == hwnd {
            return cb.dropped;
        }
    }

    false
}

/// Get dropped control rect
pub fn get_dropped_control_rect(hwnd: HWND, rect: &mut Rect) -> bool {
    let comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter() {
        if cb.in_use && cb.hwnd == hwnd {
            // Return the dropdown list rectangle
            rect.left = 0;
            rect.top = cb.item_height; // Below the edit/button area
            rect.right = if cb.drop_width > 0 { cb.drop_width } else { 100 };
            rect.bottom = rect.top + cb.drop_height;
            return true;
        }
    }

    false
}

/// Set dropdown width
pub fn set_dropped_width(hwnd: HWND, width: i32) -> i32 {
    let mut comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter_mut() {
        if cb.in_use && cb.hwnd == hwnd {
            if width < 0 {
                return CB_ERR;
            }
            cb.drop_width = width;
            return width;
        }
    }

    CB_ERR
}

/// Get dropdown width
pub fn get_dropped_width(hwnd: HWND) -> i32 {
    let comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter() {
        if cb.in_use && cb.hwnd == hwnd {
            return cb.drop_width;
        }
    }

    CB_ERR
}

// ============================================================================
// Item Data
// ============================================================================

/// Get item data
pub fn get_item_data(hwnd: HWND, index: i32) -> isize {
    let comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter() {
        if cb.in_use && cb.hwnd == hwnd {
            if index < 0 || index as usize >= cb.count {
                return CB_ERR as isize;
            }

            return cb.items[index as usize].data as isize;
        }
    }

    CB_ERR as isize
}

/// Set item data
pub fn set_item_data(hwnd: HWND, index: i32, data: usize) -> i32 {
    let mut comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter_mut() {
        if cb.in_use && cb.hwnd == hwnd {
            if index < 0 || index as usize >= cb.count {
                return CB_ERR;
            }

            cb.items[index as usize].data = data;
            return CB_OKAY;
        }
    }

    CB_ERR
}

// ============================================================================
// Item Height
// ============================================================================

/// Get item height
pub fn get_item_height(hwnd: HWND, index: i32) -> i32 {
    let comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter() {
        if cb.in_use && cb.hwnd == hwnd {
            if index == -1 {
                // Get edit control height
                return cb.item_height;
            }

            if (cb.style & CBS_OWNERDRAWVARIABLE) != 0 {
                if index < 0 || index as usize >= cb.count {
                    return CB_ERR;
                }
                return cb.items[index as usize].height;
            } else {
                return cb.item_height;
            }
        }
    }

    CB_ERR
}

/// Set item height
pub fn set_item_height(hwnd: HWND, index: i32, height: i32) -> i32 {
    let mut comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter_mut() {
        if cb.in_use && cb.hwnd == hwnd {
            if height < 1 || height > 255 {
                return CB_ERR;
            }

            if index == -1 {
                // Set edit control height
                cb.item_height = height;
                return CB_OKAY;
            }

            if (cb.style & CBS_OWNERDRAWVARIABLE) != 0 {
                if index < 0 || index as usize >= cb.count {
                    return CB_ERR;
                }
                cb.items[index as usize].height = height;
            } else {
                cb.item_height = height;
            }

            return CB_OKAY;
        }
    }

    CB_ERR
}

// ============================================================================
// Find/Select String
// ============================================================================

/// Find a string
pub fn find_string(hwnd: HWND, start: i32, text: &str) -> i32 {
    let comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter() {
        if cb.in_use && cb.hwnd == hwnd {
            let start_idx = if start < 0 { 0 } else { (start + 1) as usize };
            let text_lower = text.to_ascii_lowercase();

            // Search from start to end
            for i in start_idx..cb.count {
                let item_text = core::str::from_utf8(&cb.items[i].text[..cb.items[i].text_len])
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if item_text.starts_with(&text_lower) {
                    return i as i32;
                }
            }

            // Wrap around
            for i in 0..start_idx.min(cb.count) {
                let item_text = core::str::from_utf8(&cb.items[i].text[..cb.items[i].text_len])
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if item_text.starts_with(&text_lower) {
                    return i as i32;
                }
            }

            return CB_ERR;
        }
    }

    CB_ERR
}

/// Find exact string
pub fn find_string_exact(hwnd: HWND, start: i32, text: &str) -> i32 {
    let comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter() {
        if cb.in_use && cb.hwnd == hwnd {
            let start_idx = if start < 0 { 0 } else { (start + 1) as usize };
            let text_lower = text.to_ascii_lowercase();

            for i in start_idx..cb.count {
                let item_text = core::str::from_utf8(&cb.items[i].text[..cb.items[i].text_len])
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if item_text == text_lower {
                    return i as i32;
                }
            }

            for i in 0..start_idx.min(cb.count) {
                let item_text = core::str::from_utf8(&cb.items[i].text[..cb.items[i].text_len])
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if item_text == text_lower {
                    return i as i32;
                }
            }

            return CB_ERR;
        }
    }

    CB_ERR
}

/// Select string (find and select)
pub fn select_string(hwnd: HWND, start: i32, text: &str) -> i32 {
    let index = find_string(hwnd, start, text);
    if index != CB_ERR {
        set_cur_sel(hwnd, index);
    }
    index
}

// ============================================================================
// Extended UI
// ============================================================================

/// Set extended UI mode
pub fn set_extended_ui(hwnd: HWND, extended: bool) -> i32 {
    let mut comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter_mut() {
        if cb.in_use && cb.hwnd == hwnd {
            cb.extended_ui = extended;
            return CB_OKAY;
        }
    }

    CB_ERR
}

/// Get extended UI mode
pub fn get_extended_ui(hwnd: HWND) -> bool {
    let comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter() {
        if cb.in_use && cb.hwnd == hwnd {
            return cb.extended_ui;
        }
    }

    false
}

// ============================================================================
// Top Index
// ============================================================================

/// Get top index
pub fn get_top_index(hwnd: HWND) -> i32 {
    let comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter() {
        if cb.in_use && cb.hwnd == hwnd {
            return cb.top_index;
        }
    }

    CB_ERR
}

/// Set top index
pub fn set_top_index(hwnd: HWND, index: i32) -> i32 {
    let mut comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter_mut() {
        if cb.in_use && cb.hwnd == hwnd {
            if index < 0 || index as usize >= cb.count {
                return CB_ERR;
            }

            cb.top_index = index;
            return CB_OKAY;
        }
    }

    CB_ERR
}

// ============================================================================
// Edit Control
// ============================================================================

/// Limit edit text length
pub fn limit_text(hwnd: HWND, limit: u32) -> bool {
    let comboboxes = COMBOBOXES.lock();

    for cb in comboboxes.iter() {
        if cb.in_use && cb.hwnd == hwnd {
            // Would limit the edit control text
            return true;
        }
    }

    false
}

// ============================================================================
// Message Handler
// ============================================================================

/// Handle combobox message
pub fn handle_message(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> isize {
    match msg {
        CB_ADDSTRING => add_string(hwnd, "") as isize,
        CB_DELETESTRING => delete_string(hwnd, wparam as i32) as isize,
        CB_RESETCONTENT => {
            reset_content(hwnd);
            0
        }
        CB_GETCOUNT => get_count(hwnd) as isize,
        CB_GETCURSEL => get_cur_sel(hwnd) as isize,
        CB_SETCURSEL => set_cur_sel(hwnd, wparam as i32) as isize,
        CB_SHOWDROPDOWN => {
            show_dropdown(hwnd, wparam != 0);
            0
        }
        CB_GETDROPPEDSTATE => get_dropped_state(hwnd) as isize,
        CB_GETITEMDATA => get_item_data(hwnd, wparam as i32),
        CB_SETITEMDATA => set_item_data(hwnd, wparam as i32, lparam as usize) as isize,
        CB_GETITEMHEIGHT => get_item_height(hwnd, wparam as i32) as isize,
        CB_SETITEMHEIGHT => set_item_height(hwnd, wparam as i32, lparam as i32) as isize,
        CB_GETTOPINDEX => get_top_index(hwnd) as isize,
        CB_SETTOPINDEX => set_top_index(hwnd, wparam as i32) as isize,
        CB_SETEXTENDEDUI => set_extended_ui(hwnd, wparam != 0) as isize,
        CB_GETEXTENDEDUI => get_extended_ui(hwnd) as isize,
        CB_SETDROPPEDWIDTH => set_dropped_width(hwnd, wparam as i32) as isize,
        CB_GETDROPPEDWIDTH => get_dropped_width(hwnd) as isize,
        CB_LIMITTEXT => {
            limit_text(hwnd, wparam as u32);
            0
        }
        _ => 0,
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// ComboBox statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ComboBoxStats {
    pub combobox_count: usize,
    pub total_items: usize,
}

/// Get combobox statistics
pub fn get_stats() -> ComboBoxStats {
    let comboboxes = COMBOBOXES.lock();

    let mut combobox_count = 0;
    let mut total_items = 0;

    for cb in comboboxes.iter() {
        if cb.in_use {
            combobox_count += 1;
            total_items += cb.count;
        }
    }

    ComboBoxStats {
        combobox_count,
        total_items,
    }
}
