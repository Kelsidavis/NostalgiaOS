//! Header Control Implementation
//!
//! Implements the Windows Header control for column headers in list views.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/commctrl.h` - Control styles and messages
//! - `shell/comctl32/header.c` - Header control implementation

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, Rect, Point};

// ============================================================================
// Header Control Class
// ============================================================================

/// Header control window class name
pub const HEADER_CLASS: &str = "SysHeader32";

// ============================================================================
// Header Control Styles (HDS_*)
// ============================================================================

/// Horizontal header (default)
pub const HDS_HORZ: u32 = 0x0000;

/// Button-style headers
pub const HDS_BUTTONS: u32 = 0x0002;

/// Hot tracking
pub const HDS_HOTTRACK: u32 = 0x0004;

/// Hidden header (zero height)
pub const HDS_HIDDEN: u32 = 0x0008;

/// Allow drag-drop reordering
pub const HDS_DRAGDROP: u32 = 0x0040;

/// Full drag (show item while dragging)
pub const HDS_FULLDRAG: u32 = 0x0080;

/// Show filter bar
pub const HDS_FILTERBAR: u32 = 0x0100;

/// Flat appearance
pub const HDS_FLAT: u32 = 0x0200;

// ============================================================================
// Header Item Flags (HDI_*)
// ============================================================================

/// Width/cxy member is valid
pub const HDI_WIDTH: u32 = 0x0001;

/// Same as HDI_WIDTH
pub const HDI_HEIGHT: u32 = HDI_WIDTH;

/// Text member is valid
pub const HDI_TEXT: u32 = 0x0002;

/// Format member is valid
pub const HDI_FORMAT: u32 = 0x0004;

/// lParam member is valid
pub const HDI_LPARAM: u32 = 0x0008;

/// Bitmap member is valid
pub const HDI_BITMAP: u32 = 0x0010;

/// Image index member is valid
pub const HDI_IMAGE: u32 = 0x0020;

/// DI_SETITEM return value
pub const HDI_DI_SETITEM: u32 = 0x0040;

/// Order member is valid
pub const HDI_ORDER: u32 = 0x0080;

/// Filter member is valid
pub const HDI_FILTER: u32 = 0x0100;

// ============================================================================
// Header Format Flags (HDF_*)
// ============================================================================

/// Left-aligned text
pub const HDF_LEFT: u32 = 0x0000;

/// Right-aligned text
pub const HDF_RIGHT: u32 = 0x0001;

/// Centered text
pub const HDF_CENTER: u32 = 0x0002;

/// Alignment mask
pub const HDF_JUSTIFYMASK: u32 = 0x0003;

/// RTL reading order
pub const HDF_RTLREADING: u32 = 0x0004;

/// Owner-draw
pub const HDF_OWNERDRAW: u32 = 0x8000;

/// String content
pub const HDF_STRING: u32 = 0x4000;

/// Bitmap content
pub const HDF_BITMAP: u32 = 0x2000;

/// Bitmap on right
pub const HDF_BITMAP_ON_RIGHT: u32 = 0x1000;

/// Image from image list
pub const HDF_IMAGE: u32 = 0x0800;

/// Sort up arrow
pub const HDF_SORTUP: u32 = 0x0400;

/// Sort down arrow
pub const HDF_SORTDOWN: u32 = 0x0200;

// ============================================================================
// Header Hit Test Flags (HHT_*)
// ============================================================================

/// Not on header
pub const HHT_NOWHERE: u32 = 0x0001;

/// On header item
pub const HHT_ONHEADER: u32 = 0x0002;

/// On divider between items
pub const HHT_ONDIVIDER: u32 = 0x0004;

/// On divider (open hand cursor)
pub const HHT_ONDIVOPEN: u32 = 0x0008;

/// On filter area
pub const HHT_ONFILTER: u32 = 0x0010;

/// On filter button
pub const HHT_ONFILTERBUTTON: u32 = 0x0020;

/// Above header
pub const HHT_ABOVE: u32 = 0x0100;

/// Below header
pub const HHT_BELOW: u32 = 0x0200;

/// To right of header
pub const HHT_TORIGHT: u32 = 0x0400;

/// To left of header
pub const HHT_TOLEFT: u32 = 0x0800;

// ============================================================================
// Header Messages (HDM_*)
// ============================================================================

/// HDM message base
const HDM_FIRST: u32 = 0x1200;

/// Get item count
pub const HDM_GETITEMCOUNT: u32 = HDM_FIRST + 0;

/// Insert item (ANSI)
pub const HDM_INSERTITEMA: u32 = HDM_FIRST + 1;

/// Insert item (Unicode)
pub const HDM_INSERTITEMW: u32 = HDM_FIRST + 10;

/// Delete item
pub const HDM_DELETEITEM: u32 = HDM_FIRST + 2;

/// Get item (ANSI)
pub const HDM_GETITEMA: u32 = HDM_FIRST + 3;

/// Get item (Unicode)
pub const HDM_GETITEMW: u32 = HDM_FIRST + 11;

/// Set item (ANSI)
pub const HDM_SETITEMA: u32 = HDM_FIRST + 4;

/// Set item (Unicode)
pub const HDM_SETITEMW: u32 = HDM_FIRST + 12;

/// Layout header
pub const HDM_LAYOUT: u32 = HDM_FIRST + 5;

/// Hit test
pub const HDM_HITTEST: u32 = HDM_FIRST + 6;

/// Get item rectangle
pub const HDM_GETITEMRECT: u32 = HDM_FIRST + 7;

/// Set image list
pub const HDM_SETIMAGELIST: u32 = HDM_FIRST + 8;

/// Get image list
pub const HDM_GETIMAGELIST: u32 = HDM_FIRST + 9;

/// Convert order to index
pub const HDM_ORDERTOINDEX: u32 = HDM_FIRST + 15;

/// Create drag image
pub const HDM_CREATEDRAGIMAGE: u32 = HDM_FIRST + 16;

/// Get order array
pub const HDM_GETORDERARRAY: u32 = HDM_FIRST + 17;

/// Set order array
pub const HDM_SETORDERARRAY: u32 = HDM_FIRST + 18;

/// Set hot divider
pub const HDM_SETHOTDIVIDER: u32 = HDM_FIRST + 19;

/// Set bitmap margin
pub const HDM_SETBITMAPMARGIN: u32 = HDM_FIRST + 20;

/// Get bitmap margin
pub const HDM_GETBITMAPMARGIN: u32 = HDM_FIRST + 21;

/// Set filter change timeout
pub const HDM_SETFILTERCHANGETIMEOUT: u32 = HDM_FIRST + 22;

/// Edit filter
pub const HDM_EDITFILTER: u32 = HDM_FIRST + 23;

/// Clear filter
pub const HDM_CLEARFILTER: u32 = HDM_FIRST + 24;

// ============================================================================
// Header Notifications (HDN_*)
// ============================================================================

/// HDN notification base
const HDN_FIRST: u32 = 0xFFFFFED4; // -300

/// Item changing (ANSI)
pub const HDN_ITEMCHANGINGA: u32 = HDN_FIRST - 0;

/// Item changing (Unicode)
pub const HDN_ITEMCHANGINGW: u32 = HDN_FIRST - 20;

/// Item changed (ANSI)
pub const HDN_ITEMCHANGEDA: u32 = HDN_FIRST - 1;

/// Item changed (Unicode)
pub const HDN_ITEMCHANGEDW: u32 = HDN_FIRST - 21;

/// Item clicked (ANSI)
pub const HDN_ITEMCLICKA: u32 = HDN_FIRST - 2;

/// Item clicked (Unicode)
pub const HDN_ITEMCLICKW: u32 = HDN_FIRST - 22;

/// Item double-clicked (ANSI)
pub const HDN_ITEMDBLCLICKA: u32 = HDN_FIRST - 3;

/// Item double-clicked (Unicode)
pub const HDN_ITEMDBLCLICKW: u32 = HDN_FIRST - 23;

/// Divider double-clicked (ANSI)
pub const HDN_DIVIDERDBLCLICKA: u32 = HDN_FIRST - 5;

/// Divider double-clicked (Unicode)
pub const HDN_DIVIDERDBLCLICKW: u32 = HDN_FIRST - 25;

/// Begin tracking (ANSI)
pub const HDN_BEGINTRACKA: u32 = HDN_FIRST - 6;

/// Begin tracking (Unicode)
pub const HDN_BEGINTRACKW: u32 = HDN_FIRST - 26;

/// End tracking (ANSI)
pub const HDN_ENDTRACKA: u32 = HDN_FIRST - 7;

/// End tracking (Unicode)
pub const HDN_ENDTRACKW: u32 = HDN_FIRST - 27;

/// Tracking (ANSI)
pub const HDN_TRACKA: u32 = HDN_FIRST - 8;

/// Tracking (Unicode)
pub const HDN_TRACKW: u32 = HDN_FIRST - 28;

/// Begin drag
pub const HDN_BEGINDRAG: u32 = HDN_FIRST - 10;

/// End drag
pub const HDN_ENDDRAG: u32 = HDN_FIRST - 11;

/// Filter changed
pub const HDN_FILTERCHANGE: u32 = HDN_FIRST - 12;

/// Filter button clicked
pub const HDN_FILTERBTNCLICK: u32 = HDN_FIRST - 13;

// ============================================================================
// Header Item Structure
// ============================================================================

/// Maximum text length per header item
const MAX_HEADER_TEXT: usize = 64;

/// Maximum items per header control
const MAX_HEADER_ITEMS: usize = 32;

/// Header item
#[derive(Debug, Clone)]
pub struct HeaderItem {
    /// Item mask
    pub mask: u32,
    /// Width (cxy)
    pub width: i32,
    /// Text
    pub text: [u8; MAX_HEADER_TEXT],
    /// Text length
    pub text_len: usize,
    /// Format flags
    pub fmt: u32,
    /// Application data
    pub lparam: isize,
    /// Image index
    pub image: i32,
    /// Display order
    pub order: i32,
    /// Calculated rectangle
    pub rect: Rect,
}

impl HeaderItem {
    const fn new() -> Self {
        Self {
            mask: 0,
            width: 100,
            text: [0u8; MAX_HEADER_TEXT],
            text_len: 0,
            fmt: HDF_LEFT | HDF_STRING,
            lparam: 0,
            image: -1,
            order: 0,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
        }
    }

    fn reset(&mut self) {
        self.mask = 0;
        self.width = 100;
        self.text = [0u8; MAX_HEADER_TEXT];
        self.text_len = 0;
        self.fmt = HDF_LEFT | HDF_STRING;
        self.lparam = 0;
        self.image = -1;
        self.order = 0;
        self.rect = Rect { left: 0, top: 0, right: 0, bottom: 0 };
    }

    fn set_text(&mut self, text: &[u8]) {
        let len = text.len().min(MAX_HEADER_TEXT - 1);
        self.text[..len].copy_from_slice(&text[..len]);
        self.text[len] = 0;
        self.text_len = len;
    }
}

// ============================================================================
// Header Hit Test Info
// ============================================================================

/// Header hit test information
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HdHitTestInfo {
    /// Point to test
    pub pt: Point,
    /// Hit test result flags
    pub flags: u32,
    /// Item index
    pub item: i32,
}

// ============================================================================
// Header Control State
// ============================================================================

/// Maximum number of header controls
const MAX_HEADER_CONTROLS: usize = 64;

/// Divider hit test width
const DIVIDER_WIDTH: i32 = 4;

/// Header control state
pub struct HeaderControl {
    /// Control is in use
    in_use: bool,
    /// Associated window handle
    hwnd: HWND,
    /// Control styles
    style: u32,
    /// Header items
    items: [HeaderItem; MAX_HEADER_ITEMS],
    /// Number of items
    item_count: usize,
    /// Image list handle
    image_list: u32,
    /// Hot item (mouse over)
    hot_item: i32,
    /// Pressed item
    pressed_item: i32,
    /// Tracking item (resizing)
    tracking_item: i32,
    /// Hot divider position
    hot_divider: i32,
    /// Bitmap margin
    bitmap_margin: i32,
    /// Header height
    height: i32,
}

impl HeaderControl {
    const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: HWND::NULL,
            style: 0,
            items: [const { HeaderItem::new() }; MAX_HEADER_ITEMS],
            item_count: 0,
            image_list: 0,
            hot_item: -1,
            pressed_item: -1,
            tracking_item: -1,
            hot_divider: -1,
            bitmap_margin: 3,
            height: 20,
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
        self.image_list = 0;
        self.hot_item = -1;
        self.pressed_item = -1;
        self.tracking_item = -1;
        self.hot_divider = -1;
        self.bitmap_margin = 3;
        self.height = 20;
    }

    /// Recalculate item positions
    fn layout(&mut self, width: i32) {
        let mut x = 0;
        for i in 0..self.item_count {
            self.items[i].rect.left = x;
            self.items[i].rect.top = 0;
            self.items[i].rect.right = x + self.items[i].width;
            self.items[i].rect.bottom = self.height;
            x = self.items[i].rect.right;
        }
        // Ignore width parameter for now - items use their own widths
        let _ = width;
    }
}

// ============================================================================
// Global State
// ============================================================================

static HEADER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static HEADER_COUNT: AtomicU32 = AtomicU32::new(0);
static HEADERS: SpinLock<[HeaderControl; MAX_HEADER_CONTROLS]> =
    SpinLock::new([const { HeaderControl::new() }; MAX_HEADER_CONTROLS]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize header control subsystem
pub fn init() {
    if HEADER_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[HEADER] Initializing Header control...");

    HEADER_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[HEADER] Header control initialized");
}

// ============================================================================
// Header Control Creation/Destruction
// ============================================================================

/// Create a header control
pub fn create_header(hwnd: HWND, style: u32) -> Option<usize> {
    let mut headers = HEADERS.lock();

    for (index, header) in headers.iter_mut().enumerate() {
        if !header.in_use {
            header.in_use = true;
            header.hwnd = hwnd;
            header.style = style;
            header.item_count = 0;
            header.image_list = 0;
            header.hot_item = -1;
            header.pressed_item = -1;
            header.tracking_item = -1;
            header.hot_divider = -1;
            header.bitmap_margin = 3;
            header.height = if (style & HDS_HIDDEN) != 0 { 0 } else { 20 };

            HEADER_COUNT.fetch_add(1, Ordering::Relaxed);
            return Some(index);
        }
    }

    None
}

/// Destroy a header control
pub fn destroy_header(index: usize) -> bool {
    if index >= MAX_HEADER_CONTROLS {
        return false;
    }

    let mut headers = HEADERS.lock();
    if headers[index].in_use {
        headers[index].reset();
        HEADER_COUNT.fetch_sub(1, Ordering::Relaxed);
        return true;
    }

    false
}

/// Find header control by window handle
pub fn find_header(hwnd: HWND) -> Option<usize> {
    let headers = HEADERS.lock();
    for (index, header) in headers.iter().enumerate() {
        if header.in_use && header.hwnd == hwnd {
            return Some(index);
        }
    }
    None
}

// ============================================================================
// Item Management
// ============================================================================

/// Insert a header item
pub fn insert_item(index: usize, position: i32, width: i32, text: &[u8], fmt: u32) -> i32 {
    if index >= MAX_HEADER_CONTROLS {
        return -1;
    }

    let mut headers = HEADERS.lock();
    if !headers[index].in_use {
        return -1;
    }

    if headers[index].item_count >= MAX_HEADER_ITEMS {
        return -1;
    }

    let pos = if position < 0 || position as usize > headers[index].item_count {
        headers[index].item_count
    } else {
        position as usize
    };

    // Shift items down
    for i in (pos..headers[index].item_count).rev() {
        headers[index].items[i + 1] = headers[index].items[i].clone();
        headers[index].items[i + 1].order = (i + 1) as i32;
    }

    // Insert new item
    headers[index].items[pos].reset();
    headers[index].items[pos].width = width;
    headers[index].items[pos].set_text(text);
    headers[index].items[pos].fmt = fmt;
    headers[index].items[pos].order = pos as i32;
    headers[index].items[pos].mask = HDI_WIDTH | HDI_TEXT | HDI_FORMAT;
    headers[index].item_count += 1;

    // Recalculate layout
    headers[index].layout(0);

    pos as i32
}

/// Delete a header item
pub fn delete_item(index: usize, position: i32) -> bool {
    if index >= MAX_HEADER_CONTROLS {
        return false;
    }

    let mut headers = HEADERS.lock();
    if !headers[index].in_use {
        return false;
    }

    let pos = position as usize;
    if pos >= headers[index].item_count {
        return false;
    }

    // Shift items up
    let count = headers[index].item_count;
    for i in pos..(count - 1) {
        headers[index].items[i] = headers[index].items[i + 1].clone();
        headers[index].items[i].order = i as i32;
    }
    headers[index].items[count - 1].reset();
    headers[index].item_count -= 1;

    // Recalculate layout
    headers[index].layout(0);

    true
}

/// Get item count
pub fn get_item_count(index: usize) -> i32 {
    if index >= MAX_HEADER_CONTROLS {
        return 0;
    }

    let headers = HEADERS.lock();
    if !headers[index].in_use {
        return 0;
    }

    headers[index].item_count as i32
}

/// Get item width
pub fn get_item_width(index: usize, position: i32) -> i32 {
    if index >= MAX_HEADER_CONTROLS {
        return 0;
    }

    let headers = HEADERS.lock();
    if !headers[index].in_use {
        return 0;
    }

    let pos = position as usize;
    if pos >= headers[index].item_count {
        return 0;
    }

    headers[index].items[pos].width
}

/// Set item width
pub fn set_item_width(index: usize, position: i32, width: i32) -> bool {
    if index >= MAX_HEADER_CONTROLS {
        return false;
    }

    let mut headers = HEADERS.lock();
    if !headers[index].in_use {
        return false;
    }

    let pos = position as usize;
    if pos >= headers[index].item_count {
        return false;
    }

    headers[index].items[pos].width = width;
    headers[index].layout(0);
    true
}

/// Get item text
pub fn get_item_text(index: usize, position: i32, buffer: &mut [u8]) -> usize {
    if index >= MAX_HEADER_CONTROLS {
        return 0;
    }

    let headers = HEADERS.lock();
    if !headers[index].in_use {
        return 0;
    }

    let pos = position as usize;
    if pos >= headers[index].item_count {
        return 0;
    }

    let len = headers[index].items[pos].text_len.min(buffer.len());
    buffer[..len].copy_from_slice(&headers[index].items[pos].text[..len]);
    len
}

/// Set item text
pub fn set_item_text(index: usize, position: i32, text: &[u8]) -> bool {
    if index >= MAX_HEADER_CONTROLS {
        return false;
    }

    let mut headers = HEADERS.lock();
    if !headers[index].in_use {
        return false;
    }

    let pos = position as usize;
    if pos >= headers[index].item_count {
        return false;
    }

    headers[index].items[pos].set_text(text);
    true
}

/// Get item format
pub fn get_item_format(index: usize, position: i32) -> u32 {
    if index >= MAX_HEADER_CONTROLS {
        return 0;
    }

    let headers = HEADERS.lock();
    if !headers[index].in_use {
        return 0;
    }

    let pos = position as usize;
    if pos >= headers[index].item_count {
        return 0;
    }

    headers[index].items[pos].fmt
}

/// Set item format
pub fn set_item_format(index: usize, position: i32, fmt: u32) -> bool {
    if index >= MAX_HEADER_CONTROLS {
        return false;
    }

    let mut headers = HEADERS.lock();
    if !headers[index].in_use {
        return false;
    }

    let pos = position as usize;
    if pos >= headers[index].item_count {
        return false;
    }

    headers[index].items[pos].fmt = fmt;
    true
}

/// Get item rectangle
pub fn get_item_rect(index: usize, position: i32) -> Option<Rect> {
    if index >= MAX_HEADER_CONTROLS {
        return None;
    }

    let headers = HEADERS.lock();
    if !headers[index].in_use {
        return None;
    }

    let pos = position as usize;
    if pos >= headers[index].item_count {
        return None;
    }

    Some(headers[index].items[pos].rect)
}

/// Get item order
pub fn get_item_order(index: usize, position: i32) -> i32 {
    if index >= MAX_HEADER_CONTROLS {
        return -1;
    }

    let headers = HEADERS.lock();
    if !headers[index].in_use {
        return -1;
    }

    let pos = position as usize;
    if pos >= headers[index].item_count {
        return -1;
    }

    headers[index].items[pos].order
}

// ============================================================================
// Hit Testing
// ============================================================================

/// Hit test
pub fn hit_test(index: usize, pt: Point) -> HdHitTestInfo {
    let mut info = HdHitTestInfo {
        pt,
        flags: HHT_NOWHERE,
        item: -1,
    };

    if index >= MAX_HEADER_CONTROLS {
        return info;
    }

    let headers = HEADERS.lock();
    if !headers[index].in_use {
        return info;
    }

    // Check if above/below header
    if pt.y < 0 {
        info.flags = HHT_ABOVE;
        return info;
    }
    if pt.y >= headers[index].height {
        info.flags = HHT_BELOW;
        return info;
    }

    // Check each item
    for i in 0..headers[index].item_count {
        let rect = headers[index].items[i].rect;

        // Check divider (area between items)
        if pt.x >= rect.right - DIVIDER_WIDTH && pt.x < rect.right + DIVIDER_WIDTH {
            info.flags = HHT_ONDIVIDER;
            info.item = i as i32;
            return info;
        }

        // Check item body
        if pt.x >= rect.left && pt.x < rect.right {
            info.flags = HHT_ONHEADER;
            info.item = i as i32;
            return info;
        }
    }

    // Check if to left or right of all items
    if headers[index].item_count > 0 {
        let first_left = headers[index].items[0].rect.left;
        let last_right = headers[index].items[headers[index].item_count - 1].rect.right;

        if pt.x < first_left {
            info.flags = HHT_TOLEFT;
        } else if pt.x >= last_right {
            info.flags = HHT_TORIGHT;
        }
    }

    info
}

// ============================================================================
// Order Functions
// ============================================================================

/// Order to index
pub fn order_to_index(index: usize, order: i32) -> i32 {
    if index >= MAX_HEADER_CONTROLS {
        return -1;
    }

    let headers = HEADERS.lock();
    if !headers[index].in_use {
        return -1;
    }

    for i in 0..headers[index].item_count {
        if headers[index].items[i].order == order {
            return i as i32;
        }
    }

    -1
}

/// Get order array
pub fn get_order_array(index: usize, buffer: &mut [i32]) -> bool {
    if index >= MAX_HEADER_CONTROLS {
        return false;
    }

    let headers = HEADERS.lock();
    if !headers[index].in_use {
        return false;
    }

    let count = headers[index].item_count.min(buffer.len());
    for i in 0..count {
        buffer[i] = headers[index].items[i].order;
    }

    true
}

/// Set order array
pub fn set_order_array(index: usize, orders: &[i32]) -> bool {
    if index >= MAX_HEADER_CONTROLS {
        return false;
    }

    let mut headers = HEADERS.lock();
    if !headers[index].in_use {
        return false;
    }

    let count = headers[index].item_count.min(orders.len());
    for i in 0..count {
        headers[index].items[i].order = orders[i];
    }

    headers[index].layout(0);
    true
}

// ============================================================================
// Image List Functions
// ============================================================================

/// Set image list
pub fn set_image_list(index: usize, image_list: u32) -> u32 {
    if index >= MAX_HEADER_CONTROLS {
        return 0;
    }

    let mut headers = HEADERS.lock();
    if !headers[index].in_use {
        return 0;
    }

    let old = headers[index].image_list;
    headers[index].image_list = image_list;
    old
}

/// Get image list
pub fn get_image_list(index: usize) -> u32 {
    if index >= MAX_HEADER_CONTROLS {
        return 0;
    }

    let headers = HEADERS.lock();
    if !headers[index].in_use {
        return 0;
    }

    headers[index].image_list
}

// ============================================================================
// Tracking Functions
// ============================================================================

/// Set hot item
pub fn set_hot_item(index: usize, item: i32) {
    if index >= MAX_HEADER_CONTROLS {
        return;
    }

    let mut headers = HEADERS.lock();
    if headers[index].in_use {
        headers[index].hot_item = item;
    }
}

/// Get hot item
pub fn get_hot_item(index: usize) -> i32 {
    if index >= MAX_HEADER_CONTROLS {
        return -1;
    }

    let headers = HEADERS.lock();
    if !headers[index].in_use {
        return -1;
    }

    headers[index].hot_item
}

/// Set pressed item
pub fn set_pressed_item(index: usize, item: i32) {
    if index >= MAX_HEADER_CONTROLS {
        return;
    }

    let mut headers = HEADERS.lock();
    if headers[index].in_use {
        headers[index].pressed_item = item;
    }
}

/// Get pressed item
pub fn get_pressed_item(index: usize) -> i32 {
    if index >= MAX_HEADER_CONTROLS {
        return -1;
    }

    let headers = HEADERS.lock();
    if !headers[index].in_use {
        return -1;
    }

    headers[index].pressed_item
}

/// Set tracking item (for resize)
pub fn set_tracking_item(index: usize, item: i32) {
    if index >= MAX_HEADER_CONTROLS {
        return;
    }

    let mut headers = HEADERS.lock();
    if headers[index].in_use {
        headers[index].tracking_item = item;
    }
}

/// Get tracking item
pub fn get_tracking_item(index: usize) -> i32 {
    if index >= MAX_HEADER_CONTROLS {
        return -1;
    }

    let headers = HEADERS.lock();
    if !headers[index].in_use {
        return -1;
    }

    headers[index].tracking_item
}

/// Set hot divider
pub fn set_hot_divider(index: usize, position: i32) -> i32 {
    if index >= MAX_HEADER_CONTROLS {
        return -1;
    }

    let mut headers = HEADERS.lock();
    if !headers[index].in_use {
        return -1;
    }

    let old = headers[index].hot_divider;
    headers[index].hot_divider = position;
    old
}

// ============================================================================
// Bitmap Margin Functions
// ============================================================================

/// Set bitmap margin
pub fn set_bitmap_margin(index: usize, margin: i32) -> i32 {
    if index >= MAX_HEADER_CONTROLS {
        return 0;
    }

    let mut headers = HEADERS.lock();
    if !headers[index].in_use {
        return 0;
    }

    let old = headers[index].bitmap_margin;
    headers[index].bitmap_margin = margin;
    old
}

/// Get bitmap margin
pub fn get_bitmap_margin(index: usize) -> i32 {
    if index >= MAX_HEADER_CONTROLS {
        return 0;
    }

    let headers = HEADERS.lock();
    if !headers[index].in_use {
        return 0;
    }

    headers[index].bitmap_margin
}

// ============================================================================
// Message Processing
// ============================================================================

/// Process header control message
pub fn process_message(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> Option<isize> {
    let index = find_header(hwnd)?;

    match msg {
        HDM_GETITEMCOUNT => {
            Some(get_item_count(index) as isize)
        }
        HDM_DELETEITEM => {
            Some(delete_item(index, wparam as i32) as isize)
        }
        HDM_SETIMAGELIST => {
            Some(set_image_list(index, lparam as u32) as isize)
        }
        HDM_GETIMAGELIST => {
            Some(get_image_list(index) as isize)
        }
        HDM_ORDERTOINDEX => {
            Some(order_to_index(index, wparam as i32) as isize)
        }
        HDM_SETBITMAPMARGIN => {
            Some(set_bitmap_margin(index, wparam as i32) as isize)
        }
        HDM_GETBITMAPMARGIN => {
            Some(get_bitmap_margin(index) as isize)
        }
        HDM_SETHOTDIVIDER => {
            // wParam: is position (TRUE) or divider index (FALSE)
            // lParam: position or divider index
            let position = if wparam != 0 {
                // Convert x position to divider index
                // For now, just use as-is
                lparam as i32
            } else {
                lparam as i32
            };
            Some(set_hot_divider(index, position) as isize)
        }
        HDM_GETITEMRECT => {
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
        HDM_HITTEST => {
            if lparam != 0 {
                unsafe {
                    let info_in = &*(lparam as *const HdHitTestInfo);
                    let result = hit_test(index, info_in.pt);
                    let info_out = &mut *(lparam as *mut HdHitTestInfo);
                    info_out.flags = result.flags;
                    info_out.item = result.item;
                    Some(result.item as isize)
                }
            } else {
                Some(-1)
            }
        }
        HDM_GETORDERARRAY => {
            if lparam != 0 && wparam > 0 {
                unsafe {
                    let buffer = core::slice::from_raw_parts_mut(lparam as *mut i32, wparam);
                    Some(get_order_array(index, buffer) as isize)
                }
            } else {
                Some(0)
            }
        }
        HDM_SETORDERARRAY => {
            if lparam != 0 && wparam > 0 {
                unsafe {
                    let orders = core::slice::from_raw_parts(lparam as *const i32, wparam);
                    Some(set_order_array(index, orders) as isize)
                }
            } else {
                Some(0)
            }
        }
        _ => None,
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Header control statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct HeaderStats {
    pub initialized: bool,
    pub count: u32,
}

/// Get header control statistics
pub fn get_stats() -> HeaderStats {
    HeaderStats {
        initialized: HEADER_INITIALIZED.load(Ordering::Relaxed),
        count: HEADER_COUNT.load(Ordering::Relaxed),
    }
}
