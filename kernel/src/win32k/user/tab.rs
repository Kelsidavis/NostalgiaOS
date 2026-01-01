//! Tab Control Implementation
//!
//! Implements the Windows Tab control for organizing content into tabbed pages.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/commctrl.h` - Control styles and messages
//! - `shell/comctl32/tab.c` - Tab control implementation

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, Rect, Point};

// ============================================================================
// Tab Control Class
// ============================================================================

/// Tab control window class name
pub const TAB_CLASS: &str = "SysTabControl32";

// ============================================================================
// Tab Control Styles (TCS_*)
// ============================================================================

/// Tabs at top (default)
pub const TCS_TABS: u32 = 0x0000;

/// Single line of tabs (default)
pub const TCS_SINGLELINE: u32 = 0x0000;

/// Right-justify tabs (default)
pub const TCS_RIGHTJUSTIFY: u32 = 0x0000;

/// Scroll tabs if they don't fit
pub const TCS_SCROLLOPPOSITE: u32 = 0x0001;

/// Tabs at bottom (or right if TCS_VERTICAL)
pub const TCS_BOTTOM: u32 = 0x0002;

/// Same as TCS_BOTTOM for vertical tabs
pub const TCS_RIGHT: u32 = 0x0002;

/// Allow multi-select in button mode
pub const TCS_MULTISELECT: u32 = 0x0004;

/// Flat button separators
pub const TCS_FLATBUTTONS: u32 = 0x0008;

/// Force icon to left
pub const TCS_FORCEICONLEFT: u32 = 0x0010;

/// Force label to left
pub const TCS_FORCELABELLEFT: u32 = 0x0020;

/// Hot tracking
pub const TCS_HOTTRACK: u32 = 0x0040;

/// Vertical tab strip (tabs on left or right)
pub const TCS_VERTICAL: u32 = 0x0080;

/// Button-style tabs
pub const TCS_BUTTONS: u32 = 0x0100;

/// Multiple rows of tabs
pub const TCS_MULTILINE: u32 = 0x0200;

/// Fixed-width tabs
pub const TCS_FIXEDWIDTH: u32 = 0x0400;

/// Right-ragged tabs (no stretching)
pub const TCS_RAGGEDRIGHT: u32 = 0x0800;

/// Focus on button down
pub const TCS_FOCUSONBUTTONDOWN: u32 = 0x1000;

/// Owner-draw tabs (fixed size)
pub const TCS_OWNERDRAWFIXED: u32 = 0x2000;

/// Enable tooltips
pub const TCS_TOOLTIPS: u32 = 0x4000;

/// Never receive focus
pub const TCS_FOCUSNEVER: u32 = 0x8000;

// ============================================================================
// Tab Control Extended Styles
// ============================================================================

/// Flat separators between tabs
pub const TCS_EX_FLATSEPARATORS: u32 = 0x00000001;

/// Register for drag-drop
pub const TCS_EX_REGISTERDROP: u32 = 0x00000002;

// ============================================================================
// Tab Control Messages (TCM_*)
// ============================================================================

/// TCM message base
const TCM_FIRST: u32 = 0x1300;

/// Get image list
pub const TCM_GETIMAGELIST: u32 = TCM_FIRST + 2;

/// Set image list
pub const TCM_SETIMAGELIST: u32 = TCM_FIRST + 3;

/// Get item count
pub const TCM_GETITEMCOUNT: u32 = TCM_FIRST + 4;

/// Get item (ANSI)
pub const TCM_GETITEMA: u32 = TCM_FIRST + 5;

/// Get item (Unicode)
pub const TCM_GETITEMW: u32 = TCM_FIRST + 60;

/// Set item (ANSI)
pub const TCM_SETITEMA: u32 = TCM_FIRST + 6;

/// Set item (Unicode)
pub const TCM_SETITEMW: u32 = TCM_FIRST + 61;

/// Insert item (ANSI)
pub const TCM_INSERTITEMA: u32 = TCM_FIRST + 7;

/// Insert item (Unicode)
pub const TCM_INSERTITEMW: u32 = TCM_FIRST + 62;

/// Delete item
pub const TCM_DELETEITEM: u32 = TCM_FIRST + 8;

/// Delete all items
pub const TCM_DELETEALLITEMS: u32 = TCM_FIRST + 9;

/// Get item rectangle
pub const TCM_GETITEMRECT: u32 = TCM_FIRST + 10;

/// Get current selection
pub const TCM_GETCURSEL: u32 = TCM_FIRST + 11;

/// Set current selection
pub const TCM_SETCURSEL: u32 = TCM_FIRST + 12;

/// Hit test
pub const TCM_HITTEST: u32 = TCM_FIRST + 13;

/// Set item extra data size
pub const TCM_SETITEMEXTRA: u32 = TCM_FIRST + 14;

/// Adjust rect (tab->display or display->tab)
pub const TCM_ADJUSTRECT: u32 = TCM_FIRST + 40;

/// Set item size (fixed-width mode)
pub const TCM_SETITEMSIZE: u32 = TCM_FIRST + 41;

/// Remove image from image list
pub const TCM_REMOVEIMAGE: u32 = TCM_FIRST + 42;

/// Set tab padding
pub const TCM_SETPADDING: u32 = TCM_FIRST + 43;

/// Get row count
pub const TCM_GETROWCOUNT: u32 = TCM_FIRST + 44;

/// Get tooltip control
pub const TCM_GETTOOLTIPS: u32 = TCM_FIRST + 45;

/// Set tooltip control
pub const TCM_SETTOOLTIPS: u32 = TCM_FIRST + 46;

/// Get current focus
pub const TCM_GETCURFOCUS: u32 = TCM_FIRST + 47;

/// Set current focus
pub const TCM_SETCURFOCUS: u32 = TCM_FIRST + 48;

/// Set minimum tab width
pub const TCM_SETMINTABWIDTH: u32 = TCM_FIRST + 49;

/// Deselect all (multi-select mode)
pub const TCM_DESELECTALL: u32 = TCM_FIRST + 50;

/// Highlight item
pub const TCM_HIGHLIGHTITEM: u32 = TCM_FIRST + 51;

/// Set extended style
pub const TCM_SETEXTENDEDSTYLE: u32 = TCM_FIRST + 52;

/// Get extended style
pub const TCM_GETEXTENDEDSTYLE: u32 = TCM_FIRST + 53;

// ============================================================================
// Tab Item Flags (TCIF_*)
// ============================================================================

/// Text member is valid
pub const TCIF_TEXT: u32 = 0x0001;

/// Image member is valid
pub const TCIF_IMAGE: u32 = 0x0002;

/// RTL reading order
pub const TCIF_RTLREADING: u32 = 0x0004;

/// lParam member is valid
pub const TCIF_PARAM: u32 = 0x0008;

/// State member is valid
pub const TCIF_STATE: u32 = 0x0010;

// ============================================================================
// Tab Item States (TCIS_*)
// ============================================================================

/// Button is pressed
pub const TCIS_BUTTONPRESSED: u32 = 0x0001;

/// Item is highlighted
pub const TCIS_HIGHLIGHTED: u32 = 0x0002;

// ============================================================================
// Tab Hit Test Flags (TCHT_*)
// ============================================================================

/// Not on any item
pub const TCHT_NOWHERE: u32 = 0x0001;

/// On item icon
pub const TCHT_ONITEMICON: u32 = 0x0002;

/// On item label
pub const TCHT_ONITEMLABEL: u32 = 0x0004;

/// On item (icon or label)
pub const TCHT_ONITEM: u32 = TCHT_ONITEMICON | TCHT_ONITEMLABEL;

// ============================================================================
// Tab Notifications
// ============================================================================

/// TCN notification base
const TCN_FIRST: u32 = 0xFFFFFDDA; // -550

/// Key down notification
pub const TCN_KEYDOWN: u32 = TCN_FIRST - 0;

/// Selection changed
pub const TCN_SELCHANGE: u32 = TCN_FIRST - 1;

/// Selection changing
pub const TCN_SELCHANGING: u32 = TCN_FIRST - 2;

/// Get object notification
pub const TCN_GETOBJECT: u32 = TCN_FIRST - 3;

/// Focus changed
pub const TCN_FOCUSCHANGE: u32 = TCN_FIRST - 4;

// ============================================================================
// Tab Item Structure
// ============================================================================

/// Maximum text length per tab
const MAX_TAB_TEXT: usize = 64;

/// Maximum tabs per control
const MAX_TABS_PER_CONTROL: usize = 32;

/// Tab item
#[derive(Debug, Clone)]
pub struct TabItem {
    /// Item mask (what fields are valid)
    pub mask: u32,
    /// Item state
    pub state: u32,
    /// Item state mask
    pub state_mask: u32,
    /// Item text
    pub text: [u8; MAX_TAB_TEXT],
    /// Text length
    pub text_len: usize,
    /// Image index (-1 for no image)
    pub image: i32,
    /// Application-defined data
    pub lparam: isize,
    /// Calculated tab rectangle
    pub rect: Rect,
    /// Row index (for multiline)
    pub row: i32,
}

impl TabItem {
    const fn new() -> Self {
        Self {
            mask: 0,
            state: 0,
            state_mask: 0,
            text: [0u8; MAX_TAB_TEXT],
            text_len: 0,
            image: -1,
            lparam: 0,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            row: 0,
        }
    }

    fn reset(&mut self) {
        self.mask = 0;
        self.state = 0;
        self.state_mask = 0;
        self.text = [0u8; MAX_TAB_TEXT];
        self.text_len = 0;
        self.image = -1;
        self.lparam = 0;
        self.rect = Rect { left: 0, top: 0, right: 0, bottom: 0 };
        self.row = 0;
    }

    fn set_text(&mut self, text: &[u8]) {
        let len = text.len().min(MAX_TAB_TEXT - 1);
        self.text[..len].copy_from_slice(&text[..len]);
        self.text[len] = 0;
        self.text_len = len;
    }
}

// ============================================================================
// Tab Hit Test Info
// ============================================================================

/// Tab hit test information
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TcHitTestInfo {
    /// Point to test
    pub pt: Point,
    /// Hit test result flags
    pub flags: u32,
}

// ============================================================================
// Tab Control State
// ============================================================================

/// Maximum number of tab controls
const MAX_TAB_CONTROLS: usize = 64;

/// Tab control state
pub struct TabControl {
    /// Control is in use
    in_use: bool,
    /// Associated window handle
    hwnd: HWND,
    /// Control styles
    style: u32,
    /// Extended styles
    ex_style: u32,
    /// Tab items
    items: [TabItem; MAX_TABS_PER_CONTROL],
    /// Number of items
    item_count: usize,
    /// Currently selected item (-1 for none)
    cur_sel: i32,
    /// Currently focused item (-1 for none)
    cur_focus: i32,
    /// Image list handle
    image_list: u32,
    /// Tooltip window handle
    tooltip: HWND,
    /// Item extra bytes
    item_extra: usize,
    /// Fixed item width (if TCS_FIXEDWIDTH)
    item_width: i32,
    /// Fixed item height
    item_height: i32,
    /// Horizontal padding
    pad_x: i32,
    /// Vertical padding
    pad_y: i32,
    /// Minimum tab width
    min_tab_width: i32,
    /// Number of rows
    row_count: i32,
    /// Hot item (hot tracking)
    hot_item: i32,
}

impl TabControl {
    const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: HWND::NULL,
            style: 0,
            ex_style: 0,
            items: [const { TabItem::new() }; MAX_TABS_PER_CONTROL],
            item_count: 0,
            cur_sel: -1,
            cur_focus: -1,
            image_list: 0,
            tooltip: HWND::NULL,
            item_extra: 0,
            item_width: 0,
            item_height: 20,
            pad_x: 6,
            pad_y: 3,
            min_tab_width: 0,
            row_count: 1,
            hot_item: -1,
        }
    }

    fn reset(&mut self) {
        self.in_use = false;
        self.hwnd = HWND::NULL;
        self.style = 0;
        self.ex_style = 0;
        for item in &mut self.items {
            item.reset();
        }
        self.item_count = 0;
        self.cur_sel = -1;
        self.cur_focus = -1;
        self.image_list = 0;
        self.tooltip = HWND::NULL;
        self.item_extra = 0;
        self.item_width = 0;
        self.item_height = 20;
        self.pad_x = 6;
        self.pad_y = 3;
        self.min_tab_width = 0;
        self.row_count = 1;
        self.hot_item = -1;
    }
}

// ============================================================================
// Global State
// ============================================================================

static TAB_INITIALIZED: AtomicBool = AtomicBool::new(false);
static TAB_COUNT: AtomicU32 = AtomicU32::new(0);
static TABS: SpinLock<[TabControl; MAX_TAB_CONTROLS]> =
    SpinLock::new([const { TabControl::new() }; MAX_TAB_CONTROLS]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize tab control subsystem
pub fn init() {
    if TAB_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[TAB] Initializing Tab control...");

    TAB_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[TAB] Tab control initialized");
}

// ============================================================================
// Tab Control Creation/Destruction
// ============================================================================

/// Create a tab control
pub fn create_tab(hwnd: HWND, style: u32) -> Option<usize> {
    let mut tabs = TABS.lock();

    for (index, tab) in tabs.iter_mut().enumerate() {
        if !tab.in_use {
            tab.in_use = true;
            tab.hwnd = hwnd;
            tab.style = style;
            tab.ex_style = 0;
            tab.item_count = 0;
            tab.cur_sel = -1;
            tab.cur_focus = -1;
            tab.image_list = 0;
            tab.tooltip = HWND::NULL;
            tab.item_extra = 0;
            tab.item_width = 0;
            tab.item_height = 20;
            tab.pad_x = 6;
            tab.pad_y = 3;
            tab.min_tab_width = 0;
            tab.row_count = 1;
            tab.hot_item = -1;

            TAB_COUNT.fetch_add(1, Ordering::Relaxed);
            return Some(index);
        }
    }

    None
}

/// Destroy a tab control
pub fn destroy_tab(index: usize) -> bool {
    if index >= MAX_TAB_CONTROLS {
        return false;
    }

    let mut tabs = TABS.lock();
    if tabs[index].in_use {
        tabs[index].reset();
        TAB_COUNT.fetch_sub(1, Ordering::Relaxed);
        return true;
    }

    false
}

/// Find tab control by window handle
pub fn find_tab(hwnd: HWND) -> Option<usize> {
    let tabs = TABS.lock();
    for (index, tab) in tabs.iter().enumerate() {
        if tab.in_use && tab.hwnd == hwnd {
            return Some(index);
        }
    }
    None
}

// ============================================================================
// Item Management
// ============================================================================

/// Insert a tab item
pub fn insert_item(index: usize, position: i32, text: &[u8], image: i32, lparam: isize) -> i32 {
    if index >= MAX_TAB_CONTROLS {
        return -1;
    }

    let mut tabs = TABS.lock();
    if !tabs[index].in_use {
        return -1;
    }

    if tabs[index].item_count >= MAX_TABS_PER_CONTROL {
        return -1;
    }

    let pos = if position < 0 || position as usize > tabs[index].item_count {
        tabs[index].item_count
    } else {
        position as usize
    };

    // Shift items down
    for i in (pos..tabs[index].item_count).rev() {
        tabs[index].items[i + 1] = tabs[index].items[i].clone();
    }

    // Insert new item
    tabs[index].items[pos].reset();
    tabs[index].items[pos].set_text(text);
    tabs[index].items[pos].image = image;
    tabs[index].items[pos].lparam = lparam;
    tabs[index].items[pos].mask = TCIF_TEXT | TCIF_IMAGE | TCIF_PARAM;
    tabs[index].item_count += 1;

    // Update selection if needed
    if tabs[index].cur_sel >= pos as i32 {
        tabs[index].cur_sel += 1;
    }

    pos as i32
}

/// Delete a tab item
pub fn delete_item(index: usize, position: i32) -> bool {
    if index >= MAX_TAB_CONTROLS {
        return false;
    }

    let mut tabs = TABS.lock();
    if !tabs[index].in_use {
        return false;
    }

    let pos = position as usize;
    if pos >= tabs[index].item_count {
        return false;
    }

    // Shift items up
    let count = tabs[index].item_count;
    for i in pos..(count - 1) {
        tabs[index].items[i] = tabs[index].items[i + 1].clone();
    }
    tabs[index].items[count - 1].reset();
    tabs[index].item_count -= 1;

    // Update selection
    if tabs[index].cur_sel == position {
        if tabs[index].item_count == 0 {
            tabs[index].cur_sel = -1;
        } else if tabs[index].cur_sel >= tabs[index].item_count as i32 {
            tabs[index].cur_sel = tabs[index].item_count as i32 - 1;
        }
    } else if tabs[index].cur_sel > position {
        tabs[index].cur_sel -= 1;
    }

    true
}

/// Delete all tab items
pub fn delete_all_items(index: usize) -> bool {
    if index >= MAX_TAB_CONTROLS {
        return false;
    }

    let mut tabs = TABS.lock();
    if !tabs[index].in_use {
        return false;
    }

    for i in 0..tabs[index].item_count {
        tabs[index].items[i].reset();
    }
    tabs[index].item_count = 0;
    tabs[index].cur_sel = -1;
    tabs[index].cur_focus = -1;
    tabs[index].row_count = 1;

    true
}

/// Get item count
pub fn get_item_count(index: usize) -> i32 {
    if index >= MAX_TAB_CONTROLS {
        return 0;
    }

    let tabs = TABS.lock();
    if !tabs[index].in_use {
        return 0;
    }

    tabs[index].item_count as i32
}

/// Get item text
pub fn get_item_text(index: usize, position: i32, buffer: &mut [u8]) -> usize {
    if index >= MAX_TAB_CONTROLS {
        return 0;
    }

    let tabs = TABS.lock();
    if !tabs[index].in_use {
        return 0;
    }

    let pos = position as usize;
    if pos >= tabs[index].item_count {
        return 0;
    }

    let len = tabs[index].items[pos].text_len.min(buffer.len());
    buffer[..len].copy_from_slice(&tabs[index].items[pos].text[..len]);
    len
}

/// Set item text
pub fn set_item_text(index: usize, position: i32, text: &[u8]) -> bool {
    if index >= MAX_TAB_CONTROLS {
        return false;
    }

    let mut tabs = TABS.lock();
    if !tabs[index].in_use {
        return false;
    }

    let pos = position as usize;
    if pos >= tabs[index].item_count {
        return false;
    }

    tabs[index].items[pos].set_text(text);
    true
}

/// Get item image
pub fn get_item_image(index: usize, position: i32) -> i32 {
    if index >= MAX_TAB_CONTROLS {
        return -1;
    }

    let tabs = TABS.lock();
    if !tabs[index].in_use {
        return -1;
    }

    let pos = position as usize;
    if pos >= tabs[index].item_count {
        return -1;
    }

    tabs[index].items[pos].image
}

/// Set item image
pub fn set_item_image(index: usize, position: i32, image: i32) -> bool {
    if index >= MAX_TAB_CONTROLS {
        return false;
    }

    let mut tabs = TABS.lock();
    if !tabs[index].in_use {
        return false;
    }

    let pos = position as usize;
    if pos >= tabs[index].item_count {
        return false;
    }

    tabs[index].items[pos].image = image;
    true
}

/// Get item lparam
pub fn get_item_param(index: usize, position: i32) -> isize {
    if index >= MAX_TAB_CONTROLS {
        return 0;
    }

    let tabs = TABS.lock();
    if !tabs[index].in_use {
        return 0;
    }

    let pos = position as usize;
    if pos >= tabs[index].item_count {
        return 0;
    }

    tabs[index].items[pos].lparam
}

/// Get item rectangle
pub fn get_item_rect(index: usize, position: i32) -> Option<Rect> {
    if index >= MAX_TAB_CONTROLS {
        return None;
    }

    let tabs = TABS.lock();
    if !tabs[index].in_use {
        return None;
    }

    let pos = position as usize;
    if pos >= tabs[index].item_count {
        return None;
    }

    Some(tabs[index].items[pos].rect)
}

// ============================================================================
// Selection Functions
// ============================================================================

/// Get current selection
pub fn get_cur_sel(index: usize) -> i32 {
    if index >= MAX_TAB_CONTROLS {
        return -1;
    }

    let tabs = TABS.lock();
    if !tabs[index].in_use {
        return -1;
    }

    tabs[index].cur_sel
}

/// Set current selection
pub fn set_cur_sel(index: usize, sel: i32) -> i32 {
    if index >= MAX_TAB_CONTROLS {
        return -1;
    }

    let mut tabs = TABS.lock();
    if !tabs[index].in_use {
        return -1;
    }

    let old_sel = tabs[index].cur_sel;

    if sel < 0 || sel as usize >= tabs[index].item_count {
        tabs[index].cur_sel = -1;
    } else {
        tabs[index].cur_sel = sel;
    }

    old_sel
}

/// Get current focus
pub fn get_cur_focus(index: usize) -> i32 {
    if index >= MAX_TAB_CONTROLS {
        return -1;
    }

    let tabs = TABS.lock();
    if !tabs[index].in_use {
        return -1;
    }

    tabs[index].cur_focus
}

/// Set current focus
pub fn set_cur_focus(index: usize, focus: i32) {
    if index >= MAX_TAB_CONTROLS {
        return;
    }

    let mut tabs = TABS.lock();
    if !tabs[index].in_use {
        return;
    }

    if focus < 0 || focus as usize >= tabs[index].item_count {
        tabs[index].cur_focus = -1;
    } else {
        tabs[index].cur_focus = focus;
    }
}

// ============================================================================
// Hit Testing
// ============================================================================

/// Hit test
pub fn hit_test(index: usize, pt: Point) -> (i32, u32) {
    if index >= MAX_TAB_CONTROLS {
        return (-1, TCHT_NOWHERE);
    }

    let tabs = TABS.lock();
    if !tabs[index].in_use {
        return (-1, TCHT_NOWHERE);
    }

    for i in 0..tabs[index].item_count {
        let rect = tabs[index].items[i].rect;
        if pt.x >= rect.left && pt.x < rect.right &&
           pt.y >= rect.top && pt.y < rect.bottom {
            return (i as i32, TCHT_ONITEM);
        }
    }

    (-1, TCHT_NOWHERE)
}

// ============================================================================
// Layout Functions
// ============================================================================

/// Get row count
pub fn get_row_count(index: usize) -> i32 {
    if index >= MAX_TAB_CONTROLS {
        return 0;
    }

    let tabs = TABS.lock();
    if !tabs[index].in_use {
        return 0;
    }

    tabs[index].row_count
}

/// Set item size (for fixed-width mode)
pub fn set_item_size(index: usize, width: i32, height: i32) -> (i32, i32) {
    if index >= MAX_TAB_CONTROLS {
        return (0, 0);
    }

    let mut tabs = TABS.lock();
    if !tabs[index].in_use {
        return (0, 0);
    }

    let old_width = tabs[index].item_width;
    let old_height = tabs[index].item_height;

    tabs[index].item_width = width;
    tabs[index].item_height = height;

    (old_width, old_height)
}

/// Set padding
pub fn set_padding(index: usize, cx: i32, cy: i32) {
    if index >= MAX_TAB_CONTROLS {
        return;
    }

    let mut tabs = TABS.lock();
    if tabs[index].in_use {
        tabs[index].pad_x = cx;
        tabs[index].pad_y = cy;
    }
}

/// Set minimum tab width
pub fn set_min_tab_width(index: usize, width: i32) -> i32 {
    if index >= MAX_TAB_CONTROLS {
        return -1;
    }

    let mut tabs = TABS.lock();
    if !tabs[index].in_use {
        return -1;
    }

    let old = tabs[index].min_tab_width;
    tabs[index].min_tab_width = width;
    old
}

/// Adjust rectangle (convert between tab and display area)
pub fn adjust_rect(index: usize, larger: bool, rect: &mut Rect) {
    if index >= MAX_TAB_CONTROLS {
        return;
    }

    let tabs = TABS.lock();
    if !tabs[index].in_use {
        return;
    }

    let tab_height = tabs[index].item_height + tabs[index].pad_y * 2;

    if larger {
        // Tab rect -> display rect (shrink)
        if (tabs[index].style & TCS_BOTTOM) != 0 {
            rect.bottom -= tab_height;
        } else {
            rect.top += tab_height;
        }
        rect.left += 2;
        rect.right -= 2;
        rect.bottom -= 2;
    } else {
        // Display rect -> tab rect (expand)
        if (tabs[index].style & TCS_BOTTOM) != 0 {
            rect.bottom += tab_height;
        } else {
            rect.top -= tab_height;
        }
        rect.left -= 2;
        rect.right += 2;
        rect.bottom += 2;
    }
}

// ============================================================================
// Image List Functions
// ============================================================================

/// Set image list
pub fn set_image_list(index: usize, image_list: u32) -> u32 {
    if index >= MAX_TAB_CONTROLS {
        return 0;
    }

    let mut tabs = TABS.lock();
    if !tabs[index].in_use {
        return 0;
    }

    let old = tabs[index].image_list;
    tabs[index].image_list = image_list;
    old
}

/// Get image list
pub fn get_image_list(index: usize) -> u32 {
    if index >= MAX_TAB_CONTROLS {
        return 0;
    }

    let tabs = TABS.lock();
    if !tabs[index].in_use {
        return 0;
    }

    tabs[index].image_list
}

// ============================================================================
// Tooltip Functions
// ============================================================================

/// Set tooltip window
pub fn set_tooltips(index: usize, tooltip: HWND) {
    if index >= MAX_TAB_CONTROLS {
        return;
    }

    let mut tabs = TABS.lock();
    if tabs[index].in_use {
        tabs[index].tooltip = tooltip;
    }
}

/// Get tooltip window
pub fn get_tooltips(index: usize) -> HWND {
    if index >= MAX_TAB_CONTROLS {
        return HWND::NULL;
    }

    let tabs = TABS.lock();
    if !tabs[index].in_use {
        return HWND::NULL;
    }

    tabs[index].tooltip
}

// ============================================================================
// Extended Style Functions
// ============================================================================

/// Set extended style
pub fn set_extended_style(index: usize, mask: u32, style: u32) -> u32 {
    if index >= MAX_TAB_CONTROLS {
        return 0;
    }

    let mut tabs = TABS.lock();
    if !tabs[index].in_use {
        return 0;
    }

    let old = tabs[index].ex_style;
    tabs[index].ex_style = (tabs[index].ex_style & !mask) | (style & mask);
    old
}

/// Get extended style
pub fn get_extended_style(index: usize) -> u32 {
    if index >= MAX_TAB_CONTROLS {
        return 0;
    }

    let tabs = TABS.lock();
    if !tabs[index].in_use {
        return 0;
    }

    tabs[index].ex_style
}

// ============================================================================
// Message Processing
// ============================================================================

/// Process tab control message
pub fn process_message(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> Option<isize> {
    let index = find_tab(hwnd)?;

    match msg {
        TCM_GETITEMCOUNT => {
            Some(get_item_count(index) as isize)
        }
        TCM_GETCURSEL => {
            Some(get_cur_sel(index) as isize)
        }
        TCM_SETCURSEL => {
            Some(set_cur_sel(index, wparam as i32) as isize)
        }
        TCM_GETCURFOCUS => {
            Some(get_cur_focus(index) as isize)
        }
        TCM_SETCURFOCUS => {
            set_cur_focus(index, wparam as i32);
            Some(0)
        }
        TCM_DELETEITEM => {
            Some(delete_item(index, wparam as i32) as isize)
        }
        TCM_DELETEALLITEMS => {
            Some(delete_all_items(index) as isize)
        }
        TCM_GETROWCOUNT => {
            Some(get_row_count(index) as isize)
        }
        TCM_SETIMAGELIST => {
            Some(set_image_list(index, lparam as u32) as isize)
        }
        TCM_GETIMAGELIST => {
            Some(get_image_list(index) as isize)
        }
        TCM_GETTOOLTIPS => {
            Some(get_tooltips(index).raw() as isize)
        }
        TCM_SETTOOLTIPS => {
            set_tooltips(index, HWND::from_raw(wparam as u32));
            Some(0)
        }
        TCM_SETITEMSIZE => {
            let width = (lparam as u32 & 0xFFFF) as i32;
            let height = ((lparam as u32 >> 16) & 0xFFFF) as i32;
            let (old_w, old_h) = set_item_size(index, width, height);
            Some(((old_h as u32) << 16 | (old_w as u32 & 0xFFFF)) as isize)
        }
        TCM_SETPADDING => {
            let cx = (lparam as u32 & 0xFFFF) as i32;
            let cy = ((lparam as u32 >> 16) & 0xFFFF) as i32;
            set_padding(index, cx, cy);
            Some(0)
        }
        TCM_SETMINTABWIDTH => {
            Some(set_min_tab_width(index, lparam as i32) as isize)
        }
        TCM_SETEXTENDEDSTYLE => {
            let mask = if wparam == 0 { 0xFFFFFFFF } else { wparam as u32 };
            Some(set_extended_style(index, mask, lparam as u32) as isize)
        }
        TCM_GETEXTENDEDSTYLE => {
            Some(get_extended_style(index) as isize)
        }
        TCM_HITTEST => {
            if lparam != 0 {
                unsafe {
                    let info = &*(lparam as *const TcHitTestInfo);
                    let (item, flags) = hit_test(index, info.pt);
                    let info_mut = &mut *(lparam as *mut TcHitTestInfo);
                    info_mut.flags = flags;
                    Some(item as isize)
                }
            } else {
                Some(-1)
            }
        }
        TCM_GETITEMRECT => {
            if lparam != 0 {
                if let Some(rect) = get_item_rect(index, wparam as i32) {
                    unsafe {
                        let ptr = lparam as *mut Rect;
                        *ptr = rect;
                    }
                    Some(1)
                } else {
                    Some(0)
                }
            } else {
                Some(0)
            }
        }
        TCM_ADJUSTRECT => {
            if lparam != 0 {
                unsafe {
                    let rect = &mut *(lparam as *mut Rect);
                    adjust_rect(index, wparam != 0, rect);
                }
            }
            Some(0)
        }
        _ => None,
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Tab control statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct TabStats {
    pub initialized: bool,
    pub count: u32,
}

/// Get tab control statistics
pub fn get_stats() -> TabStats {
    TabStats {
        initialized: TAB_INITIALIZED.load(Ordering::Relaxed),
        count: TAB_COUNT.load(Ordering::Relaxed),
    }
}
