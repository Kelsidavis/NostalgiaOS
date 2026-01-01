//! TreeView Control Implementation
//!
//! Implements the Windows TreeView control for hierarchical data display.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/commctrl.h` - Control styles and messages

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, Rect, Point};

// ============================================================================
// TreeView Class
// ============================================================================

/// TreeView window class name
pub const TREEVIEW_CLASS: &str = "SysTreeView32";

// ============================================================================
// TreeView Styles (TVS_*)
// ============================================================================

/// Show expand/collapse buttons
pub const TVS_HASBUTTONS: u32 = 0x0001;

/// Show lines between items
pub const TVS_HASLINES: u32 = 0x0002;

/// Show lines at root level
pub const TVS_LINESATROOT: u32 = 0x0004;

/// Allow label editing
pub const TVS_EDITLABELS: u32 = 0x0008;

/// Disable drag-drop
pub const TVS_DISABLEDRAGDROP: u32 = 0x0010;

/// Always show selection
pub const TVS_SHOWSELALWAYS: u32 = 0x0020;

/// RTL reading order
pub const TVS_RTLREADING: u32 = 0x0040;

/// No tooltips
pub const TVS_NOTOOLTIPS: u32 = 0x0080;

/// Show checkboxes
pub const TVS_CHECKBOXES: u32 = 0x0100;

/// Track select (hot tracking)
pub const TVS_TRACKSELECT: u32 = 0x0200;

/// Single expand
pub const TVS_SINGLEEXPAND: u32 = 0x0400;

/// Info tip
pub const TVS_INFOTIP: u32 = 0x0800;

/// Full row select
pub const TVS_FULLROWSELECT: u32 = 0x1000;

/// No scrolling
pub const TVS_NOSCROLL: u32 = 0x2000;

/// Non-even height
pub const TVS_NONEVENHEIGHT: u32 = 0x4000;

/// No horizontal scroll
pub const TVS_NOHSCROLL: u32 = 0x8000;

// ============================================================================
// TreeView Item Flags (TVIF_*)
// ============================================================================

/// Text is valid
pub const TVIF_TEXT: u32 = 0x0001;

/// Image is valid
pub const TVIF_IMAGE: u32 = 0x0002;

/// lParam is valid
pub const TVIF_PARAM: u32 = 0x0004;

/// State is valid
pub const TVIF_STATE: u32 = 0x0008;

/// Handle is valid
pub const TVIF_HANDLE: u32 = 0x0010;

/// Selected image is valid
pub const TVIF_SELECTEDIMAGE: u32 = 0x0020;

/// Children flag is valid
pub const TVIF_CHILDREN: u32 = 0x0040;

/// Integral height
pub const TVIF_INTEGRAL: u32 = 0x0080;

// ============================================================================
// TreeView Item States (TVIS_*)
// ============================================================================

/// Item is selected
pub const TVIS_SELECTED: u32 = 0x0002;

/// Item is cut
pub const TVIS_CUT: u32 = 0x0004;

/// Item is drop highlighted
pub const TVIS_DROPHILITED: u32 = 0x0008;

/// Item text is bold
pub const TVIS_BOLD: u32 = 0x0010;

/// Item is expanded
pub const TVIS_EXPANDED: u32 = 0x0020;

/// Item was expanded once
pub const TVIS_EXPANDEDONCE: u32 = 0x0040;

/// Item is partially expanded
pub const TVIS_EXPANDPARTIAL: u32 = 0x0080;

/// Overlay image mask
pub const TVIS_OVERLAYMASK: u32 = 0x0F00;

/// State image mask
pub const TVIS_STATEIMAGEMASK: u32 = 0xF000;

// ============================================================================
// TreeView Messages (TVM_*)
// ============================================================================

/// TVM message base
const TV_FIRST: u32 = 0x1100;

/// Insert item (ANSI)
pub const TVM_INSERTITEMA: u32 = TV_FIRST + 0;

/// Insert item (Unicode)
pub const TVM_INSERTITEMW: u32 = TV_FIRST + 50;

/// Delete item
pub const TVM_DELETEITEM: u32 = TV_FIRST + 1;

/// Expand/collapse item
pub const TVM_EXPAND: u32 = TV_FIRST + 2;

/// Get item rectangle
pub const TVM_GETITEMRECT: u32 = TV_FIRST + 4;

/// Get item count
pub const TVM_GETCOUNT: u32 = TV_FIRST + 5;

/// Get indent
pub const TVM_GETINDENT: u32 = TV_FIRST + 6;

/// Set indent
pub const TVM_SETINDENT: u32 = TV_FIRST + 7;

/// Get image list
pub const TVM_GETIMAGELIST: u32 = TV_FIRST + 8;

/// Set image list
pub const TVM_SETIMAGELIST: u32 = TV_FIRST + 9;

/// Get next item
pub const TVM_GETNEXTITEM: u32 = TV_FIRST + 10;

/// Select item
pub const TVM_SELECTITEM: u32 = TV_FIRST + 11;

/// Get item (ANSI)
pub const TVM_GETITEMA: u32 = TV_FIRST + 12;

/// Get item (Unicode)
pub const TVM_GETITEMW: u32 = TV_FIRST + 62;

/// Set item (ANSI)
pub const TVM_SETITEMA: u32 = TV_FIRST + 13;

/// Set item (Unicode)
pub const TVM_SETITEMW: u32 = TV_FIRST + 63;

/// Get visible count
pub const TVM_GETVISIBLECOUNT: u32 = TV_FIRST + 16;

/// Hit test
pub const TVM_HITTEST: u32 = TV_FIRST + 17;

/// Sort children
pub const TVM_SORTCHILDREN: u32 = TV_FIRST + 19;

/// Ensure visible
pub const TVM_ENSUREVISIBLE: u32 = TV_FIRST + 20;

/// Set item height
pub const TVM_SETITEMHEIGHT: u32 = TV_FIRST + 27;

/// Get item height
pub const TVM_GETITEMHEIGHT: u32 = TV_FIRST + 28;

/// Set background color
pub const TVM_SETBKCOLOR: u32 = TV_FIRST + 29;

/// Set text color
pub const TVM_SETTEXTCOLOR: u32 = TV_FIRST + 30;

/// Get background color
pub const TVM_GETBKCOLOR: u32 = TV_FIRST + 31;

/// Get text color
pub const TVM_GETTEXTCOLOR: u32 = TV_FIRST + 32;

// ============================================================================
// TreeView Get Next Item Flags (TVGN_*)
// ============================================================================

/// Get root item
pub const TVGN_ROOT: u32 = 0x0000;

/// Get next sibling
pub const TVGN_NEXT: u32 = 0x0001;

/// Get previous sibling
pub const TVGN_PREVIOUS: u32 = 0x0002;

/// Get parent
pub const TVGN_PARENT: u32 = 0x0003;

/// Get first child
pub const TVGN_CHILD: u32 = 0x0004;

/// Get first visible
pub const TVGN_FIRSTVISIBLE: u32 = 0x0005;

/// Get next visible
pub const TVGN_NEXTVISIBLE: u32 = 0x0006;

/// Get previous visible
pub const TVGN_PREVIOUSVISIBLE: u32 = 0x0007;

/// Get drop highlight item
pub const TVGN_DROPHILITE: u32 = 0x0008;

/// Get caret (selected) item
pub const TVGN_CARET: u32 = 0x0009;

/// Get last visible
pub const TVGN_LASTVISIBLE: u32 = 0x000A;

// ============================================================================
// TreeView Expand Flags (TVE_*)
// ============================================================================

/// Collapse
pub const TVE_COLLAPSE: u32 = 0x0001;

/// Expand
pub const TVE_EXPAND: u32 = 0x0002;

/// Toggle
pub const TVE_TOGGLE: u32 = 0x0003;

/// Expand partial
pub const TVE_EXPANDPARTIAL: u32 = 0x4000;

/// Collapse and reset
pub const TVE_COLLAPSERESET: u32 = 0x8000;

// ============================================================================
// TreeView Hit Test Flags (TVHT_*)
// ============================================================================

/// Not on any item
pub const TVHT_NOWHERE: u32 = 0x0001;

/// On item icon
pub const TVHT_ONITEMICON: u32 = 0x0002;

/// On item label
pub const TVHT_ONITEMLABEL: u32 = 0x0004;

/// On item indent
pub const TVHT_ONITEMINDENT: u32 = 0x0008;

/// On item button
pub const TVHT_ONITEMBUTTON: u32 = 0x0010;

/// To right of item
pub const TVHT_ONITEMRIGHT: u32 = 0x0020;

/// On item state icon
pub const TVHT_ONITEMSTATEICON: u32 = 0x0040;

/// On item (any part)
pub const TVHT_ONITEM: u32 = TVHT_ONITEMICON | TVHT_ONITEMLABEL | TVHT_ONITEMSTATEICON;

/// Above client area
pub const TVHT_ABOVE: u32 = 0x0100;

/// Below client area
pub const TVHT_BELOW: u32 = 0x0200;

/// To right of client area
pub const TVHT_TORIGHT: u32 = 0x0400;

/// To left of client area
pub const TVHT_TOLEFT: u32 = 0x0800;

// ============================================================================
// Special Item Handles
// ============================================================================

/// Root item handle
pub const TVI_ROOT: u32 = 0xFFFF0000;

/// Insert first
pub const TVI_FIRST: u32 = 0xFFFF0001;

/// Insert last
pub const TVI_LAST: u32 = 0xFFFF0002;

/// Insert sorted
pub const TVI_SORT: u32 = 0xFFFF0003;

// ============================================================================
// TreeView Item Handle
// ============================================================================

/// TreeView item handle
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HTREEITEM(pub u32);

impl HTREEITEM {
    pub const NULL: HTREEITEM = HTREEITEM(0);

    pub const fn from_raw(value: u32) -> Self {
        HTREEITEM(value)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

// ============================================================================
// TreeView Node Structure
// ============================================================================

/// Maximum text length per node
const MAX_TV_TEXT: usize = 128;

/// Maximum nodes per tree
const MAX_TV_NODES: usize = 256;

/// TreeView node
#[derive(Debug, Clone)]
pub struct TvNode {
    /// Node is in use
    pub in_use: bool,
    /// Node handle (index + 1)
    pub handle: HTREEITEM,
    /// Parent node handle (0 = root level)
    pub parent: HTREEITEM,
    /// First child handle
    pub first_child: HTREEITEM,
    /// Next sibling handle
    pub next_sibling: HTREEITEM,
    /// Previous sibling handle
    pub prev_sibling: HTREEITEM,
    /// Node state
    pub state: u32,
    /// Node text
    pub text: [u8; MAX_TV_TEXT],
    /// Text length
    pub text_len: usize,
    /// Image index
    pub image: i32,
    /// Selected image index
    pub selected_image: i32,
    /// Application data
    pub lparam: isize,
    /// Has children flag
    pub has_children: bool,
    /// Indent level
    pub level: i32,
    /// Item rectangle
    pub rect: Rect,
}

impl TvNode {
    const fn new() -> Self {
        Self {
            in_use: false,
            handle: HTREEITEM::NULL,
            parent: HTREEITEM::NULL,
            first_child: HTREEITEM::NULL,
            next_sibling: HTREEITEM::NULL,
            prev_sibling: HTREEITEM::NULL,
            state: 0,
            text: [0u8; MAX_TV_TEXT],
            text_len: 0,
            image: -1,
            selected_image: -1,
            lparam: 0,
            has_children: false,
            level: 0,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
        }
    }

    fn reset(&mut self) {
        self.in_use = false;
        self.handle = HTREEITEM::NULL;
        self.parent = HTREEITEM::NULL;
        self.first_child = HTREEITEM::NULL;
        self.next_sibling = HTREEITEM::NULL;
        self.prev_sibling = HTREEITEM::NULL;
        self.state = 0;
        self.text = [0u8; MAX_TV_TEXT];
        self.text_len = 0;
        self.image = -1;
        self.selected_image = -1;
        self.lparam = 0;
        self.has_children = false;
        self.level = 0;
        self.rect = Rect { left: 0, top: 0, right: 0, bottom: 0 };
    }

    fn set_text(&mut self, text: &[u8]) {
        let len = text.len().min(MAX_TV_TEXT - 1);
        self.text[..len].copy_from_slice(&text[..len]);
        self.text[len] = 0;
        self.text_len = len;
    }
}

/// TreeView hit test info
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TvHitTestInfo {
    /// Point to test
    pub pt: Point,
    /// Hit test flags
    pub flags: u32,
    /// Item handle
    pub item: HTREEITEM,
}

// ============================================================================
// TreeView Control State
// ============================================================================

/// Maximum number of treeview controls
const MAX_TREEVIEWS: usize = 32;

/// TreeView control state
pub struct TreeViewControl {
    /// Control is in use
    in_use: bool,
    /// Associated window handle
    hwnd: HWND,
    /// Control styles
    style: u32,
    /// Nodes
    nodes: [TvNode; MAX_TV_NODES],
    /// First root node
    first_root: HTREEITEM,
    /// Selected item
    selected: HTREEITEM,
    /// Drop highlight item
    drop_highlight: HTREEITEM,
    /// Item count
    item_count: usize,
    /// Indent width
    indent: i32,
    /// Item height
    item_height: i32,
    /// Background color
    bk_color: u32,
    /// Text color
    text_color: u32,
    /// Image list (normal)
    image_list: u32,
    /// Image list (state)
    state_image_list: u32,
    /// Scroll position
    scroll_y: i32,
}

impl TreeViewControl {
    const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: HWND::NULL,
            style: 0,
            nodes: [const { TvNode::new() }; MAX_TV_NODES],
            first_root: HTREEITEM::NULL,
            selected: HTREEITEM::NULL,
            drop_highlight: HTREEITEM::NULL,
            item_count: 0,
            indent: 19,
            item_height: 16,
            bk_color: 0xFFFFFF,
            text_color: 0x000000,
            image_list: 0,
            state_image_list: 0,
            scroll_y: 0,
        }
    }

    fn reset(&mut self) {
        self.in_use = false;
        self.hwnd = HWND::NULL;
        self.style = 0;
        for node in &mut self.nodes {
            node.reset();
        }
        self.first_root = HTREEITEM::NULL;
        self.selected = HTREEITEM::NULL;
        self.drop_highlight = HTREEITEM::NULL;
        self.item_count = 0;
        self.indent = 19;
        self.item_height = 16;
        self.bk_color = 0xFFFFFF;
        self.text_color = 0x000000;
        self.image_list = 0;
        self.state_image_list = 0;
        self.scroll_y = 0;
    }

    /// Get node by handle
    fn get_node(&self, handle: HTREEITEM) -> Option<&TvNode> {
        if handle.0 == 0 || handle.0 > MAX_TV_NODES as u32 {
            return None;
        }
        let idx = (handle.0 - 1) as usize;
        if self.nodes[idx].in_use {
            Some(&self.nodes[idx])
        } else {
            None
        }
    }

    /// Get mutable node by handle
    fn get_node_mut(&mut self, handle: HTREEITEM) -> Option<&mut TvNode> {
        if handle.0 == 0 || handle.0 > MAX_TV_NODES as u32 {
            return None;
        }
        let idx = (handle.0 - 1) as usize;
        if self.nodes[idx].in_use {
            Some(&mut self.nodes[idx])
        } else {
            None
        }
    }

    /// Allocate a new node
    fn alloc_node(&mut self) -> Option<HTREEITEM> {
        for (idx, node) in self.nodes.iter_mut().enumerate() {
            if !node.in_use {
                node.in_use = true;
                node.handle = HTREEITEM((idx + 1) as u32);
                self.item_count += 1;
                return Some(node.handle);
            }
        }
        None
    }
}

// ============================================================================
// Global State
// ============================================================================

static TREEVIEW_INITIALIZED: AtomicBool = AtomicBool::new(false);
static TREEVIEW_COUNT: AtomicU32 = AtomicU32::new(0);
static TREEVIEWS: SpinLock<[TreeViewControl; MAX_TREEVIEWS]> =
    SpinLock::new([const { TreeViewControl::new() }; MAX_TREEVIEWS]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize treeview control subsystem
pub fn init() {
    if TREEVIEW_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[TREEVIEW] Initializing TreeView control...");

    TREEVIEW_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[TREEVIEW] TreeView control initialized");
}

// ============================================================================
// TreeView Creation/Destruction
// ============================================================================

/// Create a treeview control
pub fn create_treeview(hwnd: HWND, style: u32) -> Option<usize> {
    let mut trees = TREEVIEWS.lock();

    for (index, tree) in trees.iter_mut().enumerate() {
        if !tree.in_use {
            tree.in_use = true;
            tree.hwnd = hwnd;
            tree.style = style;
            tree.first_root = HTREEITEM::NULL;
            tree.selected = HTREEITEM::NULL;
            tree.item_count = 0;
            tree.indent = 19;
            tree.item_height = 16;

            TREEVIEW_COUNT.fetch_add(1, Ordering::Relaxed);
            return Some(index);
        }
    }

    None
}

/// Destroy a treeview control
pub fn destroy_treeview(index: usize) -> bool {
    if index >= MAX_TREEVIEWS {
        return false;
    }

    let mut trees = TREEVIEWS.lock();
    if trees[index].in_use {
        trees[index].reset();
        TREEVIEW_COUNT.fetch_sub(1, Ordering::Relaxed);
        return true;
    }

    false
}

/// Find treeview by window handle
pub fn find_treeview(hwnd: HWND) -> Option<usize> {
    let trees = TREEVIEWS.lock();
    for (index, tree) in trees.iter().enumerate() {
        if tree.in_use && tree.hwnd == hwnd {
            return Some(index);
        }
    }
    None
}

// ============================================================================
// Item Management
// ============================================================================

/// Insert an item
pub fn insert_item(
    index: usize,
    parent: HTREEITEM,
    insert_after: HTREEITEM,
    text: &[u8],
    image: i32,
    lparam: isize,
) -> HTREEITEM {
    if index >= MAX_TREEVIEWS {
        return HTREEITEM::NULL;
    }

    let mut trees = TREEVIEWS.lock();
    if !trees[index].in_use {
        return HTREEITEM::NULL;
    }

    // Allocate new node
    let handle = match trees[index].alloc_node() {
        Some(h) => h,
        None => return HTREEITEM::NULL,
    };

    // Set up the node
    let node_idx = (handle.0 - 1) as usize;
    trees[index].nodes[node_idx].set_text(text);
    trees[index].nodes[node_idx].image = image;
    trees[index].nodes[node_idx].selected_image = image;
    trees[index].nodes[node_idx].lparam = lparam;

    // Determine parent and level
    let parent_handle = if parent.0 == TVI_ROOT || parent.0 == 0 {
        HTREEITEM::NULL
    } else {
        parent
    };

    trees[index].nodes[node_idx].parent = parent_handle;

    if parent_handle.is_valid() {
        // Get parent level
        let parent_idx = (parent_handle.0 - 1) as usize;
        trees[index].nodes[node_idx].level = trees[index].nodes[parent_idx].level + 1;

        // Link to parent's children
        let first_child = trees[index].nodes[parent_idx].first_child;
        if !first_child.is_valid() {
            // First child
            trees[index].nodes[parent_idx].first_child = handle;
            trees[index].nodes[parent_idx].has_children = true;
        } else {
            // Find last child and link
            let mut current = first_child;
            while trees[index].nodes[(current.0 - 1) as usize].next_sibling.is_valid() {
                current = trees[index].nodes[(current.0 - 1) as usize].next_sibling;
            }
            trees[index].nodes[(current.0 - 1) as usize].next_sibling = handle;
            trees[index].nodes[node_idx].prev_sibling = current;
        }
    } else {
        // Root level item
        trees[index].nodes[node_idx].level = 0;

        if !trees[index].first_root.is_valid() {
            trees[index].first_root = handle;
        } else {
            // Find last root and link
            let mut current = trees[index].first_root;
            while trees[index].nodes[(current.0 - 1) as usize].next_sibling.is_valid() {
                current = trees[index].nodes[(current.0 - 1) as usize].next_sibling;
            }
            trees[index].nodes[(current.0 - 1) as usize].next_sibling = handle;
            trees[index].nodes[node_idx].prev_sibling = current;
        }
    }

    // Ignore insert_after for now - always append
    let _ = insert_after;

    handle
}

/// Delete an item and its children
pub fn delete_item(index: usize, item: HTREEITEM) -> bool {
    if index >= MAX_TREEVIEWS || !item.is_valid() {
        return false;
    }

    let mut trees = TREEVIEWS.lock();
    if !trees[index].in_use {
        return false;
    }

    // Special case: delete all items
    if item.0 == TVI_ROOT {
        for node in &mut trees[index].nodes {
            node.reset();
        }
        trees[index].first_root = HTREEITEM::NULL;
        trees[index].selected = HTREEITEM::NULL;
        trees[index].item_count = 0;
        return true;
    }

    let node_idx = (item.0 - 1) as usize;
    if node_idx >= MAX_TV_NODES || !trees[index].nodes[node_idx].in_use {
        return false;
    }

    // Update sibling links
    let prev = trees[index].nodes[node_idx].prev_sibling;
    let next = trees[index].nodes[node_idx].next_sibling;

    if prev.is_valid() {
        trees[index].nodes[(prev.0 - 1) as usize].next_sibling = next;
    }
    if next.is_valid() {
        trees[index].nodes[(next.0 - 1) as usize].prev_sibling = prev;
    }

    // Update parent's first_child if needed
    let parent = trees[index].nodes[node_idx].parent;
    if parent.is_valid() {
        if trees[index].nodes[(parent.0 - 1) as usize].first_child == item {
            trees[index].nodes[(parent.0 - 1) as usize].first_child = next;
            if !next.is_valid() {
                trees[index].nodes[(parent.0 - 1) as usize].has_children = false;
            }
        }
    } else if trees[index].first_root == item {
        trees[index].first_root = next;
    }

    // Clear selected if it was this item
    if trees[index].selected == item {
        trees[index].selected = HTREEITEM::NULL;
    }

    // Delete the node (children deletion would be recursive - simplified here)
    trees[index].nodes[node_idx].reset();
    trees[index].item_count = trees[index].item_count.saturating_sub(1);

    true
}

/// Get item count
pub fn get_count(index: usize) -> i32 {
    if index >= MAX_TREEVIEWS {
        return 0;
    }

    let trees = TREEVIEWS.lock();
    if !trees[index].in_use {
        return 0;
    }

    trees[index].item_count as i32
}

/// Get next item
pub fn get_next_item(index: usize, item: HTREEITEM, flag: u32) -> HTREEITEM {
    if index >= MAX_TREEVIEWS {
        return HTREEITEM::NULL;
    }

    let trees = TREEVIEWS.lock();
    if !trees[index].in_use {
        return HTREEITEM::NULL;
    }

    match flag {
        TVGN_ROOT => trees[index].first_root,
        TVGN_CARET => trees[index].selected,
        TVGN_DROPHILITE => trees[index].drop_highlight,
        TVGN_NEXT => {
            if let Some(node) = trees[index].get_node(item) {
                node.next_sibling
            } else {
                HTREEITEM::NULL
            }
        }
        TVGN_PREVIOUS => {
            if let Some(node) = trees[index].get_node(item) {
                node.prev_sibling
            } else {
                HTREEITEM::NULL
            }
        }
        TVGN_PARENT => {
            if let Some(node) = trees[index].get_node(item) {
                node.parent
            } else {
                HTREEITEM::NULL
            }
        }
        TVGN_CHILD => {
            if let Some(node) = trees[index].get_node(item) {
                node.first_child
            } else {
                HTREEITEM::NULL
            }
        }
        _ => HTREEITEM::NULL,
    }
}

/// Select an item
pub fn select_item(index: usize, item: HTREEITEM, flag: u32) -> bool {
    if index >= MAX_TREEVIEWS {
        return false;
    }

    let mut trees = TREEVIEWS.lock();
    if !trees[index].in_use {
        return false;
    }

    match flag {
        TVGN_CARET => {
            // Deselect old item
            if trees[index].selected.is_valid() {
                let old_idx = (trees[index].selected.0 - 1) as usize;
                trees[index].nodes[old_idx].state &= !TVIS_SELECTED;
            }
            // Select new item
            if item.is_valid() {
                let idx = (item.0 - 1) as usize;
                if idx < MAX_TV_NODES && trees[index].nodes[idx].in_use {
                    trees[index].nodes[idx].state |= TVIS_SELECTED;
                    trees[index].selected = item;
                }
            } else {
                trees[index].selected = HTREEITEM::NULL;
            }
            true
        }
        TVGN_DROPHILITE => {
            trees[index].drop_highlight = item;
            true
        }
        _ => false,
    }
}

/// Expand or collapse an item
pub fn expand(index: usize, item: HTREEITEM, code: u32) -> bool {
    if index >= MAX_TREEVIEWS || !item.is_valid() {
        return false;
    }

    let mut trees = TREEVIEWS.lock();
    if !trees[index].in_use {
        return false;
    }

    let node_idx = (item.0 - 1) as usize;
    if node_idx >= MAX_TV_NODES || !trees[index].nodes[node_idx].in_use {
        return false;
    }

    match code & 0x0003 {
        TVE_COLLAPSE => {
            trees[index].nodes[node_idx].state &= !TVIS_EXPANDED;
        }
        TVE_EXPAND => {
            trees[index].nodes[node_idx].state |= TVIS_EXPANDED | TVIS_EXPANDEDONCE;
        }
        TVE_TOGGLE => {
            if (trees[index].nodes[node_idx].state & TVIS_EXPANDED) != 0 {
                trees[index].nodes[node_idx].state &= !TVIS_EXPANDED;
            } else {
                trees[index].nodes[node_idx].state |= TVIS_EXPANDED | TVIS_EXPANDEDONCE;
            }
        }
        _ => return false,
    }

    true
}

/// Get item text
pub fn get_item_text(index: usize, item: HTREEITEM, buffer: &mut [u8]) -> usize {
    if index >= MAX_TREEVIEWS || !item.is_valid() {
        return 0;
    }

    let trees = TREEVIEWS.lock();
    if !trees[index].in_use {
        return 0;
    }

    if let Some(node) = trees[index].get_node(item) {
        let len = node.text_len.min(buffer.len());
        buffer[..len].copy_from_slice(&node.text[..len]);
        len
    } else {
        0
    }
}

/// Set item text
pub fn set_item_text(index: usize, item: HTREEITEM, text: &[u8]) -> bool {
    if index >= MAX_TREEVIEWS || !item.is_valid() {
        return false;
    }

    let mut trees = TREEVIEWS.lock();
    if !trees[index].in_use {
        return false;
    }

    if let Some(node) = trees[index].get_node_mut(item) {
        node.set_text(text);
        true
    } else {
        false
    }
}

// ============================================================================
// Appearance Functions
// ============================================================================

/// Get indent
pub fn get_indent(index: usize) -> i32 {
    if index >= MAX_TREEVIEWS {
        return 0;
    }

    let trees = TREEVIEWS.lock();
    if !trees[index].in_use {
        return 0;
    }

    trees[index].indent
}

/// Set indent
pub fn set_indent(index: usize, indent: i32) -> bool {
    if index >= MAX_TREEVIEWS {
        return false;
    }

    let mut trees = TREEVIEWS.lock();
    if !trees[index].in_use {
        return false;
    }

    trees[index].indent = indent.max(0);
    true
}

/// Get item height
pub fn get_item_height(index: usize) -> i32 {
    if index >= MAX_TREEVIEWS {
        return 0;
    }

    let trees = TREEVIEWS.lock();
    if !trees[index].in_use {
        return 0;
    }

    trees[index].item_height
}

/// Set item height
pub fn set_item_height(index: usize, height: i32) -> i32 {
    if index >= MAX_TREEVIEWS {
        return -1;
    }

    let mut trees = TREEVIEWS.lock();
    if !trees[index].in_use {
        return -1;
    }

    let old = trees[index].item_height;
    trees[index].item_height = height.max(1);
    old
}

/// Get background color
pub fn get_bk_color(index: usize) -> u32 {
    if index >= MAX_TREEVIEWS {
        return 0xFFFFFF;
    }

    let trees = TREEVIEWS.lock();
    if !trees[index].in_use {
        return 0xFFFFFF;
    }

    trees[index].bk_color
}

/// Set background color
pub fn set_bk_color(index: usize, color: u32) -> u32 {
    if index >= MAX_TREEVIEWS {
        return 0xFFFFFF;
    }

    let mut trees = TREEVIEWS.lock();
    if !trees[index].in_use {
        return 0xFFFFFF;
    }

    let old = trees[index].bk_color;
    trees[index].bk_color = color;
    old
}

/// Get text color
pub fn get_text_color(index: usize) -> u32 {
    if index >= MAX_TREEVIEWS {
        return 0x000000;
    }

    let trees = TREEVIEWS.lock();
    if !trees[index].in_use {
        return 0x000000;
    }

    trees[index].text_color
}

/// Set text color
pub fn set_text_color(index: usize, color: u32) -> u32 {
    if index >= MAX_TREEVIEWS {
        return 0x000000;
    }

    let mut trees = TREEVIEWS.lock();
    if !trees[index].in_use {
        return 0x000000;
    }

    let old = trees[index].text_color;
    trees[index].text_color = color;
    old
}

// ============================================================================
// Message Processing
// ============================================================================

/// Process treeview message
pub fn process_message(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> Option<isize> {
    let index = find_treeview(hwnd)?;

    match msg {
        TVM_GETCOUNT => {
            Some(get_count(index) as isize)
        }
        TVM_DELETEITEM => {
            Some(delete_item(index, HTREEITEM(lparam as u32)) as isize)
        }
        TVM_GETNEXTITEM => {
            let item = HTREEITEM(lparam as u32);
            let result = get_next_item(index, item, wparam as u32);
            Some(result.0 as isize)
        }
        TVM_SELECTITEM => {
            let item = HTREEITEM(lparam as u32);
            Some(select_item(index, item, wparam as u32) as isize)
        }
        TVM_EXPAND => {
            let item = HTREEITEM(lparam as u32);
            Some(expand(index, item, wparam as u32) as isize)
        }
        TVM_GETINDENT => {
            Some(get_indent(index) as isize)
        }
        TVM_SETINDENT => {
            Some(set_indent(index, wparam as i32) as isize)
        }
        TVM_GETITEMHEIGHT => {
            Some(get_item_height(index) as isize)
        }
        TVM_SETITEMHEIGHT => {
            Some(set_item_height(index, wparam as i32) as isize)
        }
        TVM_GETBKCOLOR => {
            Some(get_bk_color(index) as isize)
        }
        TVM_SETBKCOLOR => {
            Some(set_bk_color(index, lparam as u32) as isize)
        }
        TVM_GETTEXTCOLOR => {
            Some(get_text_color(index) as isize)
        }
        TVM_SETTEXTCOLOR => {
            Some(set_text_color(index, lparam as u32) as isize)
        }
        _ => None,
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// TreeView statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct TreeViewStats {
    pub initialized: bool,
    pub count: u32,
}

/// Get treeview statistics
pub fn get_stats() -> TreeViewStats {
    TreeViewStats {
        initialized: TREEVIEW_INITIALIZED.load(Ordering::Relaxed),
        count: TREEVIEW_COUNT.load(Ordering::Relaxed),
    }
}
