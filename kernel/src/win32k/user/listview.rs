//! ListView Control Implementation
//!
//! Implements the Windows ListView control for displaying lists of items.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/commctrl.h` - Control styles and messages
//! - `shell/comctl32/listview.c` - ListView implementation

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, Rect, Point};

// ============================================================================
// ListView Class
// ============================================================================

/// ListView window class name
pub const LISTVIEW_CLASS: &str = "SysListView32";

// ============================================================================
// ListView Styles (LVS_*)
// ============================================================================

/// Icon view (default)
pub const LVS_ICON: u32 = 0x0000;

/// Report/details view
pub const LVS_REPORT: u32 = 0x0001;

/// Small icon view
pub const LVS_SMALLICON: u32 = 0x0002;

/// List view
pub const LVS_LIST: u32 = 0x0003;

/// View type mask
pub const LVS_TYPEMASK: u32 = 0x0003;

/// Single selection only
pub const LVS_SINGLESEL: u32 = 0x0004;

/// Always show selection
pub const LVS_SHOWSELALWAYS: u32 = 0x0008;

/// Sort ascending
pub const LVS_SORTASCENDING: u32 = 0x0010;

/// Sort descending
pub const LVS_SORTDESCENDING: u32 = 0x0020;

/// Share image lists
pub const LVS_SHAREIMAGELISTS: u32 = 0x0040;

/// No label wrap
pub const LVS_NOLABELWRAP: u32 = 0x0080;

/// Auto-arrange icons
pub const LVS_AUTOARRANGE: u32 = 0x0100;

/// Allow label editing
pub const LVS_EDITLABELS: u32 = 0x0200;

/// Owner data (virtual list)
pub const LVS_OWNERDATA: u32 = 0x1000;

/// No scroll bars
pub const LVS_NOSCROLL: u32 = 0x2000;

/// Align top
pub const LVS_ALIGNTOP: u32 = 0x0000;

/// Align left
pub const LVS_ALIGNLEFT: u32 = 0x0800;

/// Owner-draw fixed
pub const LVS_OWNERDRAWFIXED: u32 = 0x0400;

/// No column header
pub const LVS_NOCOLUMNHEADER: u32 = 0x4000;

/// No sort header
pub const LVS_NOSORTHEADER: u32 = 0x8000;

// ============================================================================
// ListView Item Flags (LVIF_*)
// ============================================================================

/// Text is valid
pub const LVIF_TEXT: u32 = 0x0001;

/// Image is valid
pub const LVIF_IMAGE: u32 = 0x0002;

/// lParam is valid
pub const LVIF_PARAM: u32 = 0x0004;

/// State is valid
pub const LVIF_STATE: u32 = 0x0008;

/// Indent is valid
pub const LVIF_INDENT: u32 = 0x0010;

// ============================================================================
// ListView Item States (LVIS_*)
// ============================================================================

/// Item has focus
pub const LVIS_FOCUSED: u32 = 0x0001;

/// Item is selected
pub const LVIS_SELECTED: u32 = 0x0002;

/// Item is cut
pub const LVIS_CUT: u32 = 0x0004;

/// Item is drop highlighted
pub const LVIS_DROPHILITED: u32 = 0x0008;

/// Item is activating
pub const LVIS_ACTIVATING: u32 = 0x0020;

/// Overlay image mask
pub const LVIS_OVERLAYMASK: u32 = 0x0F00;

/// State image mask
pub const LVIS_STATEIMAGEMASK: u32 = 0xF000;

// ============================================================================
// ListView Column Flags (LVCF_*)
// ============================================================================

/// Format is valid
pub const LVCF_FMT: u32 = 0x0001;

/// Width is valid
pub const LVCF_WIDTH: u32 = 0x0002;

/// Text is valid
pub const LVCF_TEXT: u32 = 0x0004;

/// Subitem is valid
pub const LVCF_SUBITEM: u32 = 0x0008;

/// Image is valid
pub const LVCF_IMAGE: u32 = 0x0010;

/// Order is valid
pub const LVCF_ORDER: u32 = 0x0020;

// ============================================================================
// ListView Column Format (LVCFMT_*)
// ============================================================================

/// Left-aligned
pub const LVCFMT_LEFT: u32 = 0x0000;

/// Right-aligned
pub const LVCFMT_RIGHT: u32 = 0x0001;

/// Centered
pub const LVCFMT_CENTER: u32 = 0x0002;

/// Justify mask
pub const LVCFMT_JUSTIFYMASK: u32 = 0x0003;

/// Show image
pub const LVCFMT_IMAGE: u32 = 0x0800;

/// Bitmap on right
pub const LVCFMT_BITMAP_ON_RIGHT: u32 = 0x1000;

/// Column has image
pub const LVCFMT_COL_HAS_IMAGES: u32 = 0x8000;

// ============================================================================
// ListView Hit Test Flags (LVHT_*)
// ============================================================================

/// Not on any item
pub const LVHT_NOWHERE: u32 = 0x0001;

/// On item icon
pub const LVHT_ONITEMICON: u32 = 0x0002;

/// On item label
pub const LVHT_ONITEMLABEL: u32 = 0x0004;

/// On item state icon
pub const LVHT_ONITEMSTATEICON: u32 = 0x0008;

/// On item (icon, label, or state icon)
pub const LVHT_ONITEM: u32 = LVHT_ONITEMICON | LVHT_ONITEMLABEL | LVHT_ONITEMSTATEICON;

/// Above client area
pub const LVHT_ABOVE: u32 = 0x0008;

/// Below client area
pub const LVHT_BELOW: u32 = 0x0010;

/// To right of client area
pub const LVHT_TORIGHT: u32 = 0x0020;

/// To left of client area
pub const LVHT_TOLEFT: u32 = 0x0040;

// ============================================================================
// ListView Messages (LVM_*)
// ============================================================================

/// LVM message base
const LVM_FIRST: u32 = 0x1000;

/// Get background color
pub const LVM_GETBKCOLOR: u32 = LVM_FIRST + 0;

/// Set background color
pub const LVM_SETBKCOLOR: u32 = LVM_FIRST + 1;

/// Get image list
pub const LVM_GETIMAGELIST: u32 = LVM_FIRST + 2;

/// Set image list
pub const LVM_SETIMAGELIST: u32 = LVM_FIRST + 3;

/// Get item count
pub const LVM_GETITEMCOUNT: u32 = LVM_FIRST + 4;

/// Get item (ANSI)
pub const LVM_GETITEMA: u32 = LVM_FIRST + 5;

/// Set item (ANSI)
pub const LVM_SETITEMA: u32 = LVM_FIRST + 6;

/// Insert item (ANSI)
pub const LVM_INSERTITEMA: u32 = LVM_FIRST + 7;

/// Delete item
pub const LVM_DELETEITEM: u32 = LVM_FIRST + 8;

/// Delete all items
pub const LVM_DELETEALLITEMS: u32 = LVM_FIRST + 9;

/// Get callback mask
pub const LVM_GETCALLBACKMASK: u32 = LVM_FIRST + 10;

/// Set callback mask
pub const LVM_SETCALLBACKMASK: u32 = LVM_FIRST + 11;

/// Get next item
pub const LVM_GETNEXTITEM: u32 = LVM_FIRST + 12;

/// Find item (ANSI)
pub const LVM_FINDITEMA: u32 = LVM_FIRST + 13;

/// Get item rectangle
pub const LVM_GETITEMRECT: u32 = LVM_FIRST + 14;

/// Set item position
pub const LVM_SETITEMPOSITION: u32 = LVM_FIRST + 15;

/// Get item position
pub const LVM_GETITEMPOSITION: u32 = LVM_FIRST + 16;

/// Get string width (ANSI)
pub const LVM_GETSTRINGWIDTHA: u32 = LVM_FIRST + 17;

/// Hit test
pub const LVM_HITTEST: u32 = LVM_FIRST + 18;

/// Ensure visible
pub const LVM_ENSUREVISIBLE: u32 = LVM_FIRST + 19;

/// Scroll
pub const LVM_SCROLL: u32 = LVM_FIRST + 20;

/// Redraw items
pub const LVM_REDRAWITEMS: u32 = LVM_FIRST + 21;

/// Arrange items
pub const LVM_ARRANGE: u32 = LVM_FIRST + 22;

/// Get column (ANSI)
pub const LVM_GETCOLUMNA: u32 = LVM_FIRST + 25;

/// Set column (ANSI)
pub const LVM_SETCOLUMNA: u32 = LVM_FIRST + 26;

/// Insert column (ANSI)
pub const LVM_INSERTCOLUMNA: u32 = LVM_FIRST + 27;

/// Delete column
pub const LVM_DELETECOLUMN: u32 = LVM_FIRST + 28;

/// Get column width
pub const LVM_GETCOLUMNWIDTH: u32 = LVM_FIRST + 29;

/// Set column width
pub const LVM_SETCOLUMNWIDTH: u32 = LVM_FIRST + 30;

/// Get header control
pub const LVM_GETHEADER: u32 = LVM_FIRST + 31;

/// Get view rect
pub const LVM_GETVIEWRECT: u32 = LVM_FIRST + 34;

/// Get text color
pub const LVM_GETTEXTCOLOR: u32 = LVM_FIRST + 35;

/// Set text color
pub const LVM_SETTEXTCOLOR: u32 = LVM_FIRST + 36;

/// Get text background color
pub const LVM_GETTEXTBKCOLOR: u32 = LVM_FIRST + 37;

/// Set text background color
pub const LVM_SETTEXTBKCOLOR: u32 = LVM_FIRST + 38;

/// Get top index
pub const LVM_GETTOPINDEX: u32 = LVM_FIRST + 39;

/// Get count per page
pub const LVM_GETCOUNTPERPAGE: u32 = LVM_FIRST + 40;

/// Get origin
pub const LVM_GETORIGIN: u32 = LVM_FIRST + 41;

/// Update item
pub const LVM_UPDATE: u32 = LVM_FIRST + 42;

/// Set item state
pub const LVM_SETITEMSTATE: u32 = LVM_FIRST + 43;

/// Get item state
pub const LVM_GETITEMSTATE: u32 = LVM_FIRST + 44;

/// Get selected count
pub const LVM_GETSELECTEDCOUNT: u32 = LVM_FIRST + 50;

/// Set column order array
pub const LVM_SETCOLUMNORDERARRAY: u32 = LVM_FIRST + 58;

/// Get column order array
pub const LVM_GETCOLUMNORDERARRAY: u32 = LVM_FIRST + 59;

/// Get item (Unicode)
pub const LVM_GETITEMW: u32 = LVM_FIRST + 75;

/// Set item (Unicode)
pub const LVM_SETITEMW: u32 = LVM_FIRST + 76;

/// Insert item (Unicode)
pub const LVM_INSERTITEMW: u32 = LVM_FIRST + 77;

// ============================================================================
// ListView Image List Types
// ============================================================================

/// Normal image list
pub const LVSIL_NORMAL: u32 = 0;

/// Small image list
pub const LVSIL_SMALL: u32 = 1;

/// State image list
pub const LVSIL_STATE: u32 = 2;

// ============================================================================
// ListView Item/Column Structures
// ============================================================================

/// Maximum text length per item
const MAX_LV_TEXT: usize = 256;

/// Maximum items per list
const MAX_LV_ITEMS: usize = 256;

/// Maximum columns per list
const MAX_LV_COLUMNS: usize = 16;

/// Maximum subitems per item
const MAX_LV_SUBITEMS: usize = 16;

/// ListView subitem
#[derive(Debug, Clone)]
pub struct LvSubItem {
    /// Text
    pub text: [u8; MAX_LV_TEXT],
    /// Text length
    pub text_len: usize,
    /// Image index
    pub image: i32,
}

impl LvSubItem {
    const fn new() -> Self {
        Self {
            text: [0u8; MAX_LV_TEXT],
            text_len: 0,
            image: -1,
        }
    }

    fn set_text(&mut self, text: &[u8]) {
        let len = text.len().min(MAX_LV_TEXT - 1);
        self.text[..len].copy_from_slice(&text[..len]);
        self.text[len] = 0;
        self.text_len = len;
    }
}

/// ListView item
#[derive(Debug, Clone)]
pub struct LvItem {
    /// Item mask
    pub mask: u32,
    /// Item state
    pub state: u32,
    /// State mask
    pub state_mask: u32,
    /// Item text
    pub text: [u8; MAX_LV_TEXT],
    /// Text length
    pub text_len: usize,
    /// Image index
    pub image: i32,
    /// Application data
    pub lparam: isize,
    /// Indent level
    pub indent: i32,
    /// Subitems (for report view)
    pub subitems: [LvSubItem; MAX_LV_SUBITEMS],
    /// Number of subitems
    pub subitem_count: usize,
    /// Item position (for icon views)
    pub pos: Point,
    /// Item rectangle
    pub rect: Rect,
}

impl LvItem {
    const fn new() -> Self {
        Self {
            mask: 0,
            state: 0,
            state_mask: 0,
            text: [0u8; MAX_LV_TEXT],
            text_len: 0,
            image: -1,
            lparam: 0,
            indent: 0,
            subitems: [const { LvSubItem::new() }; MAX_LV_SUBITEMS],
            subitem_count: 0,
            pos: Point { x: 0, y: 0 },
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
        }
    }

    fn reset(&mut self) {
        self.mask = 0;
        self.state = 0;
        self.state_mask = 0;
        self.text = [0u8; MAX_LV_TEXT];
        self.text_len = 0;
        self.image = -1;
        self.lparam = 0;
        self.indent = 0;
        for sub in &mut self.subitems {
            *sub = LvSubItem::new();
        }
        self.subitem_count = 0;
        self.pos = Point { x: 0, y: 0 };
        self.rect = Rect { left: 0, top: 0, right: 0, bottom: 0 };
    }

    fn set_text(&mut self, text: &[u8]) {
        let len = text.len().min(MAX_LV_TEXT - 1);
        self.text[..len].copy_from_slice(&text[..len]);
        self.text[len] = 0;
        self.text_len = len;
    }
}

/// ListView column
#[derive(Debug, Clone)]
pub struct LvColumn {
    /// Column mask
    pub mask: u32,
    /// Format
    pub fmt: u32,
    /// Width
    pub width: i32,
    /// Text
    pub text: [u8; MAX_LV_TEXT],
    /// Text length
    pub text_len: usize,
    /// Subitem index
    pub subitem: i32,
    /// Image index
    pub image: i32,
    /// Display order
    pub order: i32,
}

impl LvColumn {
    const fn new() -> Self {
        Self {
            mask: 0,
            fmt: LVCFMT_LEFT,
            width: 100,
            text: [0u8; MAX_LV_TEXT],
            text_len: 0,
            subitem: 0,
            image: -1,
            order: 0,
        }
    }

    fn reset(&mut self) {
        self.mask = 0;
        self.fmt = LVCFMT_LEFT;
        self.width = 100;
        self.text = [0u8; MAX_LV_TEXT];
        self.text_len = 0;
        self.subitem = 0;
        self.image = -1;
        self.order = 0;
    }

    fn set_text(&mut self, text: &[u8]) {
        let len = text.len().min(MAX_LV_TEXT - 1);
        self.text[..len].copy_from_slice(&text[..len]);
        self.text[len] = 0;
        self.text_len = len;
    }
}

/// ListView hit test info
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LvHitTestInfo {
    /// Point to test
    pub pt: Point,
    /// Hit test flags
    pub flags: u32,
    /// Item index
    pub item: i32,
    /// Subitem index
    pub subitem: i32,
}

// ============================================================================
// ListView Control State
// ============================================================================

/// Maximum number of listview controls
const MAX_LISTVIEWS: usize = 32;

/// ListView control state
pub struct ListViewControl {
    /// Control is in use
    in_use: bool,
    /// Associated window handle
    hwnd: HWND,
    /// Control styles
    style: u32,
    /// Items
    items: [LvItem; MAX_LV_ITEMS],
    /// Number of items
    item_count: usize,
    /// Columns
    columns: [LvColumn; MAX_LV_COLUMNS],
    /// Number of columns
    column_count: usize,
    /// Background color
    bk_color: u32,
    /// Text color
    text_color: u32,
    /// Text background color
    text_bk_color: u32,
    /// Normal image list
    image_list_normal: u32,
    /// Small image list
    image_list_small: u32,
    /// State image list
    image_list_state: u32,
    /// Focused item
    focus_item: i32,
    /// Top visible item index
    top_index: i32,
    /// Items per page
    count_per_page: i32,
    /// Scroll position
    scroll_x: i32,
    scroll_y: i32,
    /// Item height (for report view)
    item_height: i32,
    /// Header control handle
    header: HWND,
    /// Callback mask
    callback_mask: u32,
}

impl ListViewControl {
    const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: HWND::NULL,
            style: 0,
            items: [const { LvItem::new() }; MAX_LV_ITEMS],
            item_count: 0,
            columns: [const { LvColumn::new() }; MAX_LV_COLUMNS],
            column_count: 0,
            bk_color: 0xFFFFFF, // White
            text_color: 0x000000, // Black
            text_bk_color: 0xFFFFFFFF, // CLR_NONE
            image_list_normal: 0,
            image_list_small: 0,
            image_list_state: 0,
            focus_item: -1,
            top_index: 0,
            count_per_page: 10,
            scroll_x: 0,
            scroll_y: 0,
            item_height: 16,
            header: HWND::NULL,
            callback_mask: 0,
        }
    }

    fn reset(&mut self) {
        self.in_use = false;
        self.hwnd = HWND::NULL;
        self.style = 0;
        for item in &mut self.items {
            item.reset();
        }
        self.item_count = 0;
        for col in &mut self.columns {
            col.reset();
        }
        self.column_count = 0;
        self.bk_color = 0xFFFFFF;
        self.text_color = 0x000000;
        self.text_bk_color = 0xFFFFFFFF;
        self.image_list_normal = 0;
        self.image_list_small = 0;
        self.image_list_state = 0;
        self.focus_item = -1;
        self.top_index = 0;
        self.count_per_page = 10;
        self.scroll_x = 0;
        self.scroll_y = 0;
        self.item_height = 16;
        self.header = HWND::NULL;
        self.callback_mask = 0;
    }
}

// ============================================================================
// Global State
// ============================================================================

static LISTVIEW_INITIALIZED: AtomicBool = AtomicBool::new(false);
static LISTVIEW_COUNT: AtomicU32 = AtomicU32::new(0);
static LISTVIEWS: SpinLock<[ListViewControl; MAX_LISTVIEWS]> =
    SpinLock::new([const { ListViewControl::new() }; MAX_LISTVIEWS]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize listview control subsystem
pub fn init() {
    if LISTVIEW_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[LISTVIEW] Initializing ListView control...");

    LISTVIEW_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[LISTVIEW] ListView control initialized");
}

// ============================================================================
// ListView Creation/Destruction
// ============================================================================

/// Create a listview control
pub fn create_listview(hwnd: HWND, style: u32) -> Option<usize> {
    let mut lists = LISTVIEWS.lock();

    for (index, list) in lists.iter_mut().enumerate() {
        if !list.in_use {
            list.in_use = true;
            list.hwnd = hwnd;
            list.style = style;
            list.item_count = 0;
            list.column_count = 0;
            list.bk_color = 0xFFFFFF;
            list.text_color = 0x000000;
            list.text_bk_color = 0xFFFFFFFF;
            list.focus_item = -1;
            list.top_index = 0;
            list.count_per_page = 10;
            list.item_height = 16;

            LISTVIEW_COUNT.fetch_add(1, Ordering::Relaxed);
            return Some(index);
        }
    }

    None
}

/// Destroy a listview control
pub fn destroy_listview(index: usize) -> bool {
    if index >= MAX_LISTVIEWS {
        return false;
    }

    let mut lists = LISTVIEWS.lock();
    if lists[index].in_use {
        lists[index].reset();
        LISTVIEW_COUNT.fetch_sub(1, Ordering::Relaxed);
        return true;
    }

    false
}

/// Find listview by window handle
pub fn find_listview(hwnd: HWND) -> Option<usize> {
    let lists = LISTVIEWS.lock();
    for (index, list) in lists.iter().enumerate() {
        if list.in_use && list.hwnd == hwnd {
            return Some(index);
        }
    }
    None
}

// ============================================================================
// Item Management
// ============================================================================

/// Insert an item
pub fn insert_item(index: usize, position: i32, text: &[u8], image: i32, lparam: isize) -> i32 {
    if index >= MAX_LISTVIEWS {
        return -1;
    }

    let mut lists = LISTVIEWS.lock();
    if !lists[index].in_use || lists[index].item_count >= MAX_LV_ITEMS {
        return -1;
    }

    let pos = if position < 0 || position as usize > lists[index].item_count {
        lists[index].item_count
    } else {
        position as usize
    };

    // Shift items down
    let count = lists[index].item_count;
    for i in (pos..count).rev() {
        lists[index].items[i + 1] = lists[index].items[i].clone();
    }

    // Insert new item
    lists[index].items[pos].reset();
    lists[index].items[pos].set_text(text);
    lists[index].items[pos].image = image;
    lists[index].items[pos].lparam = lparam;
    lists[index].items[pos].mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
    lists[index].item_count += 1;

    pos as i32
}

/// Delete an item
pub fn delete_item(index: usize, position: i32) -> bool {
    if index >= MAX_LISTVIEWS {
        return false;
    }

    let mut lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return false;
    }

    let pos = position as usize;
    if pos >= lists[index].item_count {
        return false;
    }

    // Shift items up
    let count = lists[index].item_count;
    for i in pos..(count - 1) {
        lists[index].items[i] = lists[index].items[i + 1].clone();
    }
    lists[index].items[count - 1].reset();
    lists[index].item_count -= 1;

    // Update focus
    if lists[index].focus_item == position {
        lists[index].focus_item = -1;
    } else if lists[index].focus_item > position {
        lists[index].focus_item -= 1;
    }

    true
}

/// Delete all items
pub fn delete_all_items(index: usize) -> bool {
    if index >= MAX_LISTVIEWS {
        return false;
    }

    let mut lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return false;
    }

    for i in 0..lists[index].item_count {
        lists[index].items[i].reset();
    }
    lists[index].item_count = 0;
    lists[index].focus_item = -1;
    lists[index].top_index = 0;

    true
}

/// Get item count
pub fn get_item_count(index: usize) -> i32 {
    if index >= MAX_LISTVIEWS {
        return 0;
    }

    let lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return 0;
    }

    lists[index].item_count as i32
}

/// Get item text
pub fn get_item_text(index: usize, item: i32, subitem: i32, buffer: &mut [u8]) -> usize {
    if index >= MAX_LISTVIEWS {
        return 0;
    }

    let lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return 0;
    }

    let item_idx = item as usize;
    if item_idx >= lists[index].item_count {
        return 0;
    }

    if subitem == 0 {
        // Main item text
        let len = lists[index].items[item_idx].text_len.min(buffer.len());
        buffer[..len].copy_from_slice(&lists[index].items[item_idx].text[..len]);
        len
    } else {
        // Subitem text
        let sub_idx = (subitem - 1) as usize;
        if sub_idx >= lists[index].items[item_idx].subitem_count {
            return 0;
        }
        let len = lists[index].items[item_idx].subitems[sub_idx].text_len.min(buffer.len());
        buffer[..len].copy_from_slice(&lists[index].items[item_idx].subitems[sub_idx].text[..len]);
        len
    }
}

/// Set item text
pub fn set_item_text(index: usize, item: i32, subitem: i32, text: &[u8]) -> bool {
    if index >= MAX_LISTVIEWS {
        return false;
    }

    let mut lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return false;
    }

    let item_idx = item as usize;
    if item_idx >= lists[index].item_count {
        return false;
    }

    if subitem == 0 {
        lists[index].items[item_idx].set_text(text);
    } else {
        let sub_idx = (subitem - 1) as usize;
        if sub_idx >= MAX_LV_SUBITEMS {
            return false;
        }
        // Expand subitem count if needed
        if sub_idx >= lists[index].items[item_idx].subitem_count {
            lists[index].items[item_idx].subitem_count = sub_idx + 1;
        }
        lists[index].items[item_idx].subitems[sub_idx].set_text(text);
    }

    true
}

/// Get item state
pub fn get_item_state(index: usize, item: i32, mask: u32) -> u32 {
    if index >= MAX_LISTVIEWS {
        return 0;
    }

    let lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return 0;
    }

    let item_idx = item as usize;
    if item_idx >= lists[index].item_count {
        return 0;
    }

    lists[index].items[item_idx].state & mask
}

/// Set item state
pub fn set_item_state(index: usize, item: i32, state: u32, mask: u32) -> bool {
    if index >= MAX_LISTVIEWS {
        return false;
    }

    let mut lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return false;
    }

    // If item is -1, set state for all items
    if item < 0 {
        for i in 0..lists[index].item_count {
            lists[index].items[i].state = (lists[index].items[i].state & !mask) | (state & mask);
        }
        return true;
    }

    let item_idx = item as usize;
    if item_idx >= lists[index].item_count {
        return false;
    }

    lists[index].items[item_idx].state = (lists[index].items[item_idx].state & !mask) | (state & mask);
    true
}

/// Get selected count
pub fn get_selected_count(index: usize) -> i32 {
    if index >= MAX_LISTVIEWS {
        return 0;
    }

    let lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return 0;
    }

    let mut count = 0;
    for i in 0..lists[index].item_count {
        if (lists[index].items[i].state & LVIS_SELECTED) != 0 {
            count += 1;
        }
    }
    count
}

/// Get next item with given flags
pub fn get_next_item(index: usize, start: i32, flags: u32) -> i32 {
    if index >= MAX_LISTVIEWS {
        return -1;
    }

    let lists = LISTVIEWS.lock();
    if !lists[index].in_use || lists[index].item_count == 0 {
        return -1;
    }

    let start_idx = if start < 0 { 0 } else { (start + 1) as usize };

    for i in start_idx..lists[index].item_count {
        let state = lists[index].items[i].state;

        // Check various flags
        let matches = if flags == 0 {
            true // No filter
        } else if (flags & LVIS_SELECTED) != 0 && (state & LVIS_SELECTED) != 0 {
            true
        } else if (flags & LVIS_FOCUSED) != 0 && (state & LVIS_FOCUSED) != 0 {
            true
        } else {
            false
        };

        if matches {
            return i as i32;
        }
    }

    -1
}

// ============================================================================
// Column Management
// ============================================================================

/// Insert a column
pub fn insert_column(index: usize, position: i32, width: i32, text: &[u8], fmt: u32) -> i32 {
    if index >= MAX_LISTVIEWS {
        return -1;
    }

    let mut lists = LISTVIEWS.lock();
    if !lists[index].in_use || lists[index].column_count >= MAX_LV_COLUMNS {
        return -1;
    }

    let pos = if position < 0 || position as usize > lists[index].column_count {
        lists[index].column_count
    } else {
        position as usize
    };

    // Shift columns down
    let count = lists[index].column_count;
    for i in (pos..count).rev() {
        lists[index].columns[i + 1] = lists[index].columns[i].clone();
        lists[index].columns[i + 1].order = (i + 1) as i32;
    }

    // Insert new column
    lists[index].columns[pos].reset();
    lists[index].columns[pos].width = width;
    lists[index].columns[pos].set_text(text);
    lists[index].columns[pos].fmt = fmt;
    lists[index].columns[pos].order = pos as i32;
    lists[index].columns[pos].subitem = pos as i32;
    lists[index].columns[pos].mask = LVCF_WIDTH | LVCF_TEXT | LVCF_FMT | LVCF_SUBITEM;
    lists[index].column_count += 1;

    pos as i32
}

/// Delete a column
pub fn delete_column(index: usize, position: i32) -> bool {
    if index >= MAX_LISTVIEWS {
        return false;
    }

    let mut lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return false;
    }

    let pos = position as usize;
    if pos >= lists[index].column_count {
        return false;
    }

    // Shift columns up
    let count = lists[index].column_count;
    for i in pos..(count - 1) {
        lists[index].columns[i] = lists[index].columns[i + 1].clone();
        lists[index].columns[i].order = i as i32;
    }
    lists[index].columns[count - 1].reset();
    lists[index].column_count -= 1;

    true
}

/// Get column width
pub fn get_column_width(index: usize, column: i32) -> i32 {
    if index >= MAX_LISTVIEWS {
        return 0;
    }

    let lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return 0;
    }

    let col_idx = column as usize;
    if col_idx >= lists[index].column_count {
        return 0;
    }

    lists[index].columns[col_idx].width
}

/// Set column width
pub fn set_column_width(index: usize, column: i32, width: i32) -> bool {
    if index >= MAX_LISTVIEWS {
        return false;
    }

    let mut lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return false;
    }

    let col_idx = column as usize;
    if col_idx >= lists[index].column_count {
        return false;
    }

    lists[index].columns[col_idx].width = width;
    true
}

// ============================================================================
// Color Functions
// ============================================================================

/// Get background color
pub fn get_bk_color(index: usize) -> u32 {
    if index >= MAX_LISTVIEWS {
        return 0xFFFFFF;
    }

    let lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return 0xFFFFFF;
    }

    lists[index].bk_color
}

/// Set background color
pub fn set_bk_color(index: usize, color: u32) -> bool {
    if index >= MAX_LISTVIEWS {
        return false;
    }

    let mut lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return false;
    }

    lists[index].bk_color = color;
    true
}

/// Get text color
pub fn get_text_color(index: usize) -> u32 {
    if index >= MAX_LISTVIEWS {
        return 0x000000;
    }

    let lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return 0x000000;
    }

    lists[index].text_color
}

/// Set text color
pub fn set_text_color(index: usize, color: u32) -> bool {
    if index >= MAX_LISTVIEWS {
        return false;
    }

    let mut lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return false;
    }

    lists[index].text_color = color;
    true
}

// ============================================================================
// Image List Functions
// ============================================================================

/// Set image list
pub fn set_image_list(index: usize, list_type: u32, image_list: u32) -> u32 {
    if index >= MAX_LISTVIEWS {
        return 0;
    }

    let mut lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return 0;
    }

    match list_type {
        LVSIL_NORMAL => {
            let old = lists[index].image_list_normal;
            lists[index].image_list_normal = image_list;
            old
        }
        LVSIL_SMALL => {
            let old = lists[index].image_list_small;
            lists[index].image_list_small = image_list;
            old
        }
        LVSIL_STATE => {
            let old = lists[index].image_list_state;
            lists[index].image_list_state = image_list;
            old
        }
        _ => 0,
    }
}

/// Get image list
pub fn get_image_list(index: usize, list_type: u32) -> u32 {
    if index >= MAX_LISTVIEWS {
        return 0;
    }

    let lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return 0;
    }

    match list_type {
        LVSIL_NORMAL => lists[index].image_list_normal,
        LVSIL_SMALL => lists[index].image_list_small,
        LVSIL_STATE => lists[index].image_list_state,
        _ => 0,
    }
}

// ============================================================================
// Scroll/View Functions
// ============================================================================

/// Get top index
pub fn get_top_index(index: usize) -> i32 {
    if index >= MAX_LISTVIEWS {
        return 0;
    }

    let lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return 0;
    }

    lists[index].top_index
}

/// Get count per page
pub fn get_count_per_page(index: usize) -> i32 {
    if index >= MAX_LISTVIEWS {
        return 0;
    }

    let lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return 0;
    }

    lists[index].count_per_page
}

/// Scroll
pub fn scroll(index: usize, dx: i32, dy: i32) -> bool {
    if index >= MAX_LISTVIEWS {
        return false;
    }

    let mut lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return false;
    }

    lists[index].scroll_x += dx;
    lists[index].scroll_y += dy;

    // Update top index based on scroll
    let new_top = lists[index].scroll_y / lists[index].item_height.max(1);
    lists[index].top_index = new_top.max(0);

    true
}

/// Ensure visible
pub fn ensure_visible(index: usize, item: i32) -> bool {
    if index >= MAX_LISTVIEWS {
        return false;
    }

    let mut lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return false;
    }

    let item_idx = item as usize;
    if item_idx >= lists[index].item_count {
        return false;
    }

    // Check if item is visible
    let top = lists[index].top_index as usize;
    let bottom = top + lists[index].count_per_page as usize;

    if item_idx < top {
        lists[index].top_index = item;
        lists[index].scroll_y = item * lists[index].item_height;
    } else if item_idx >= bottom {
        lists[index].top_index = (item - lists[index].count_per_page + 1).max(0);
        lists[index].scroll_y = lists[index].top_index * lists[index].item_height;
    }

    true
}

// ============================================================================
// Hit Testing
// ============================================================================

/// Hit test
pub fn hit_test(index: usize, pt: Point) -> LvHitTestInfo {
    let mut info = LvHitTestInfo {
        pt,
        flags: LVHT_NOWHERE,
        item: -1,
        subitem: 0,
    };

    if index >= MAX_LISTVIEWS {
        return info;
    }

    let lists = LISTVIEWS.lock();
    if !lists[index].in_use {
        return info;
    }

    let view = lists[index].style & LVS_TYPEMASK;

    if view == LVS_REPORT {
        // Report view - rows and columns
        let item_idx = lists[index].top_index + (pt.y / lists[index].item_height);
        if item_idx >= 0 && (item_idx as usize) < lists[index].item_count {
            info.item = item_idx;
            info.flags = LVHT_ONITEMLABEL;

            // Determine subitem
            let mut x = 0;
            for col in 0..lists[index].column_count {
                let col_width = lists[index].columns[col].width;
                if pt.x >= x && pt.x < x + col_width {
                    info.subitem = col as i32;
                    break;
                }
                x += col_width;
            }
        }
    } else {
        // Icon/list views - simplified hit test
        for i in 0..lists[index].item_count {
            let rect = lists[index].items[i].rect;
            if pt.x >= rect.left && pt.x < rect.right &&
               pt.y >= rect.top && pt.y < rect.bottom {
                info.item = i as i32;
                info.flags = LVHT_ONITEM;
                break;
            }
        }
    }

    info
}

// ============================================================================
// Message Processing
// ============================================================================

/// Process listview message
pub fn process_message(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> Option<isize> {
    let index = find_listview(hwnd)?;

    match msg {
        LVM_GETITEMCOUNT => {
            Some(get_item_count(index) as isize)
        }
        LVM_DELETEITEM => {
            Some(delete_item(index, wparam as i32) as isize)
        }
        LVM_DELETEALLITEMS => {
            Some(delete_all_items(index) as isize)
        }
        LVM_GETBKCOLOR => {
            Some(get_bk_color(index) as isize)
        }
        LVM_SETBKCOLOR => {
            Some(set_bk_color(index, lparam as u32) as isize)
        }
        LVM_GETTEXTCOLOR => {
            Some(get_text_color(index) as isize)
        }
        LVM_SETTEXTCOLOR => {
            Some(set_text_color(index, lparam as u32) as isize)
        }
        LVM_SETIMAGELIST => {
            Some(set_image_list(index, wparam as u32, lparam as u32) as isize)
        }
        LVM_GETIMAGELIST => {
            Some(get_image_list(index, wparam as u32) as isize)
        }
        LVM_GETTOPINDEX => {
            Some(get_top_index(index) as isize)
        }
        LVM_GETCOUNTPERPAGE => {
            Some(get_count_per_page(index) as isize)
        }
        LVM_SCROLL => {
            let dx = wparam as i32;
            let dy = lparam as i32;
            Some(scroll(index, dx, dy) as isize)
        }
        LVM_ENSUREVISIBLE => {
            Some(ensure_visible(index, wparam as i32) as isize)
        }
        LVM_GETITEMSTATE => {
            Some(get_item_state(index, wparam as i32, lparam as u32) as isize)
        }
        LVM_GETSELECTEDCOUNT => {
            Some(get_selected_count(index) as isize)
        }
        LVM_GETNEXTITEM => {
            Some(get_next_item(index, wparam as i32, lparam as u32) as isize)
        }
        LVM_DELETECOLUMN => {
            Some(delete_column(index, wparam as i32) as isize)
        }
        LVM_GETCOLUMNWIDTH => {
            Some(get_column_width(index, wparam as i32) as isize)
        }
        LVM_SETCOLUMNWIDTH => {
            Some(set_column_width(index, wparam as i32, lparam as i32) as isize)
        }
        LVM_HITTEST => {
            if lparam != 0 {
                unsafe {
                    let info_in = &*(lparam as *const LvHitTestInfo);
                    let result = hit_test(index, info_in.pt);
                    let info_out = &mut *(lparam as *mut LvHitTestInfo);
                    info_out.flags = result.flags;
                    info_out.item = result.item;
                    info_out.subitem = result.subitem;
                    Some(result.item as isize)
                }
            } else {
                Some(-1)
            }
        }
        _ => None,
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// ListView statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ListViewStats {
    pub initialized: bool,
    pub count: u32,
}

/// Get listview statistics
pub fn get_stats() -> ListViewStats {
    ListViewStats {
        initialized: LISTVIEW_INITIALIZED.load(Ordering::Relaxed),
        count: LISTVIEW_COUNT.load(Ordering::Relaxed),
    }
}
