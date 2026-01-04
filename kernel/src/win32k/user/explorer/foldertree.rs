//! Folder Tree View
//!
//! Implements the left-side folder tree pane for Windows Explorer.
//! Based on Windows Server 2003 shell/shell32/fstree.cpp.
//!
//! # Features
//! - Hierarchical folder tree with expand/collapse
//! - Synchronized with main file browser view
//! - Special folder support (Desktop, My Computer, etc.)
//! - Expand/collapse icons (+/-)

use super::super::super::{HWND, HDC, Rect, Point, ColorRef};
use super::super::super::gdi::{dc, surface};
use super::super::window;
use crate::io::{vfs, VfsEntry};

// ============================================================================
// Constants
// ============================================================================

/// Tree pane width
pub const TREE_PANE_WIDTH: i32 = 200;

/// Tree item height
pub const TREE_ITEM_HEIGHT: i32 = 20;

/// Indent per level
pub const TREE_INDENT: i32 = 20;

/// Icon size
pub const TREE_ICON_SIZE: i32 = 16;

/// Maximum tree depth
pub const MAX_TREE_DEPTH: usize = 16;

/// Maximum visible items
pub const MAX_TREE_ITEMS: usize = 128;

/// Maximum path length
pub const MAX_PATH: usize = 260;

// Colors
const COLOR_TREE_BG: ColorRef = ColorRef::rgb(255, 255, 255);
const COLOR_TREE_TEXT: ColorRef = ColorRef::rgb(0, 0, 0);
const COLOR_TREE_SELECTED: ColorRef = ColorRef::rgb(49, 106, 197);
const COLOR_TREE_SELECTED_TEXT: ColorRef = ColorRef::rgb(255, 255, 255);
const COLOR_TREE_LINE: ColorRef = ColorRef::rgb(128, 128, 128);
const COLOR_TREE_EXPAND: ColorRef = ColorRef::rgb(80, 80, 80);

// ============================================================================
// Tree Node Types
// ============================================================================

/// Type of tree node
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TreeNodeType {
    /// Desktop (root)
    Desktop,
    /// My Computer
    MyComputer,
    /// Drive (C:, D:, etc.)
    Drive,
    /// Regular folder
    Folder,
    /// Special folder (My Documents, etc.)
    SpecialFolder,
}

// ============================================================================
// Tree Node
// ============================================================================

/// A node in the folder tree
#[derive(Clone)]
pub struct TreeNode {
    /// Node type
    pub node_type: TreeNodeType,
    /// Display name
    pub name: [u8; 64],
    pub name_len: usize,
    /// Full path
    pub path: [u8; MAX_PATH],
    pub path_len: usize,
    /// Indent level (0 = root)
    pub level: usize,
    /// Is expanded
    pub expanded: bool,
    /// Has children (shows +/- button)
    pub has_children: bool,
    /// Is visible (parent is expanded)
    pub visible: bool,
    /// Parent index (-1 for root)
    pub parent_index: i32,
}

impl TreeNode {
    pub const fn empty() -> Self {
        Self {
            node_type: TreeNodeType::Folder,
            name: [0; 64],
            name_len: 0,
            path: [0; MAX_PATH],
            path_len: 0,
            level: 0,
            expanded: false,
            has_children: true,
            visible: true,
            parent_index: -1,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }

    pub fn path_str(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }
}

// ============================================================================
// Folder Tree
// ============================================================================

/// Folder tree state
pub struct FolderTree {
    /// Associated window handle
    pub hwnd: HWND,
    /// Tree nodes
    pub nodes: [TreeNode; MAX_TREE_ITEMS],
    pub node_count: usize,
    /// Selected node index
    pub selected_index: i32,
    /// Scroll offset
    pub scroll_y: i32,
    /// Is visible
    pub visible: bool,
    /// Tree pane width (resizable)
    pub width: i32,
}

impl FolderTree {
    pub const fn new() -> Self {
        Self {
            hwnd: HWND::NULL,
            nodes: [const { TreeNode::empty() }; MAX_TREE_ITEMS],
            node_count: 0,
            selected_index: 0,
            scroll_y: 0,
            visible: true,
            width: TREE_PANE_WIDTH,
        }
    }

    /// Initialize tree with default structure
    pub fn init(&mut self, hwnd: HWND) {
        self.hwnd = hwnd;
        self.node_count = 0;

        // Add Desktop (root)
        self.add_node(TreeNodeType::Desktop, "Desktop", "", 0, -1, true);

        // Add My Computer under Desktop - empty path shows drives
        let my_computer_idx = self.add_node(TreeNodeType::MyComputer, "My Computer", "", 1, 0, true);

        // Add drives under My Computer
        self.populate_drives(my_computer_idx as i32);

        // Expand Desktop and My Computer by default
        if self.node_count > 0 {
            self.nodes[0].expanded = true;
        }
        if self.node_count > 1 {
            self.nodes[1].expanded = true;
        }

        self.update_visibility();
    }

    /// Add a node to the tree
    fn add_node(&mut self, node_type: TreeNodeType, name: &str, path: &str, level: usize, parent: i32, has_children: bool) -> usize {
        if self.node_count >= MAX_TREE_ITEMS {
            return self.node_count;
        }

        let idx = self.node_count;
        let node = &mut self.nodes[idx];

        node.node_type = node_type;
        node.level = level;
        node.parent_index = parent;
        node.has_children = has_children;
        node.expanded = false;
        node.visible = level == 0;

        // Copy name
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(63);
        node.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        node.name_len = copy_len;

        // Copy path
        let path_bytes = path.as_bytes();
        let copy_len = path_bytes.len().min(MAX_PATH - 1);
        node.path[..copy_len].copy_from_slice(&path_bytes[..copy_len]);
        node.path_len = copy_len;

        self.node_count += 1;
        idx
    }

    /// Populate drives under My Computer
    fn populate_drives(&mut self, parent_idx: i32) {
        // Get drives using the vfs function
        let mut drive_entries = [const { VfsEntry::empty() }; 26];
        let drive_count = vfs::list_drives(&mut drive_entries);

        for i in 0..drive_count {
            let entry = &drive_entries[i];
            if entry.name[0] == 0 {
                continue;
            }

            // Extract drive letter from entry name (format: "Local Disk (C:)" or similar)
            let name_end = entry.name.iter().position(|&b| b == 0).unwrap_or(entry.name.len());
            let name = core::str::from_utf8(&entry.name[..name_end]).unwrap_or("");

            // Find drive letter in the name (last occurrence of X:)
            let mut drive_letter: Option<char> = None;
            for (j, b) in entry.name[..name_end].iter().enumerate() {
                if *b == b':' && j > 0 {
                    if let Some(&letter) = entry.name.get(j - 1) {
                        if letter.is_ascii_alphabetic() {
                            drive_letter = Some(letter as char);
                        }
                    }
                }
            }

            // Build path like "C:\"
            if let Some(letter) = drive_letter {
                let mut path_buf = [0u8; 8];
                path_buf[0] = letter.to_ascii_uppercase() as u8;
                path_buf[1] = b':';
                path_buf[2] = b'\\';

                let path_str = core::str::from_utf8(&path_buf[..3]).unwrap_or("");
                self.add_node(TreeNodeType::Drive, name, path_str, 2, parent_idx, true);
            }
        }
    }

    /// Update visibility of all nodes based on parent expansion state
    fn update_visibility(&mut self) {
        for i in 0..self.node_count {
            let parent_idx = self.nodes[i].parent_index;
            if parent_idx < 0 {
                self.nodes[i].visible = true;
            } else if (parent_idx as usize) < self.node_count {
                let parent = &self.nodes[parent_idx as usize];
                self.nodes[i].visible = parent.visible && parent.expanded;
            }
        }
    }

    /// Count visible nodes
    pub fn visible_count(&self) -> usize {
        self.nodes[..self.node_count].iter().filter(|n| n.visible).count()
    }

    /// Get visible node by visual index
    pub fn get_visible_node(&self, visual_idx: usize) -> Option<usize> {
        let mut count = 0;
        for i in 0..self.node_count {
            if self.nodes[i].visible {
                if count == visual_idx {
                    return Some(i);
                }
                count += 1;
            }
        }
        None
    }

    /// Toggle expansion of a node
    pub fn toggle_expand(&mut self, node_idx: usize) {
        if node_idx >= self.node_count {
            return;
        }

        let node = &mut self.nodes[node_idx];
        if !node.has_children {
            return;
        }

        if node.expanded {
            // Collapse: just hide children
            node.expanded = false;
        } else {
            // Expand: load children if needed
            node.expanded = true;
            self.load_children(node_idx);
        }

        self.update_visibility();
    }

    /// Load children of a node (lazy loading)
    fn load_children(&mut self, node_idx: usize) {
        // Check if children already loaded
        let level = self.nodes[node_idx].level;
        for i in 0..self.node_count {
            if self.nodes[i].parent_index == node_idx as i32 {
                return; // Already has children
            }
        }

        // Copy path to local buffer to avoid borrow issues
        let path_len = self.nodes[node_idx].path_len;
        if path_len == 0 {
            return;
        }
        let mut path_buf = [0u8; MAX_PATH];
        path_buf[..path_len].copy_from_slice(&self.nodes[node_idx].path[..path_len]);
        let path = core::str::from_utf8(&path_buf[..path_len]).unwrap_or("");

        // Read directory and add subfolders
        let mut entries = [const { VfsEntry::empty() }; 64];
        let entry_count = vfs::read_directory(path, &mut entries);
        let child_level = level + 1;

        for i in 0..entry_count {
            let entry = &entries[i];
            if entry.name[0] == 0 {
                break;
            }
            if !entry.is_directory {
                continue;
            }
            if self.node_count >= MAX_TREE_ITEMS {
                break;
            }

            let name_end = entry.name.iter().position(|&b| b == 0).unwrap_or(entry.name.len());
            let name = core::str::from_utf8(&entry.name[..name_end]).unwrap_or("");

            // Skip . and ..
            if name == "." || name == ".." {
                continue;
            }

            // Build full path
            let mut full_path = [0u8; MAX_PATH];
            let mut pos = 0;
            for b in path.bytes() {
                if pos < MAX_PATH - 1 {
                    full_path[pos] = b;
                    pos += 1;
                }
            }
            // Add separator if needed
            if pos > 0 && pos < MAX_PATH - 1 && full_path[pos-1] != b'/' && full_path[pos-1] != b'\\' {
                full_path[pos] = b'/';
                pos += 1;
            }
            for b in name.bytes() {
                if pos < MAX_PATH - 1 {
                    full_path[pos] = b;
                    pos += 1;
                }
            }

            let full_path_str = core::str::from_utf8(&full_path[..pos]).unwrap_or("");

            self.add_node(TreeNodeType::Folder, name, full_path_str, child_level, node_idx as i32, true);
        }

        // If no children were added, mark as no children
        let mut has_children = false;
        for i in 0..self.node_count {
            if self.nodes[i].parent_index == node_idx as i32 {
                has_children = true;
                break;
            }
        }
        self.nodes[node_idx].has_children = has_children;
    }

    /// Select node at position
    pub fn select_at(&mut self, y: i32) -> Option<usize> {
        let rel_y = y + self.scroll_y;
        let visual_idx = rel_y / TREE_ITEM_HEIGHT;

        if let Some(node_idx) = self.get_visible_node(visual_idx as usize) {
            self.selected_index = node_idx as i32;
            return Some(node_idx);
        }
        None
    }

    /// Check if click is on expand button
    pub fn hit_test_expand(&self, x: i32, y: i32) -> Option<usize> {
        let rel_y = y + self.scroll_y;
        let visual_idx = (rel_y / TREE_ITEM_HEIGHT) as usize;

        if let Some(node_idx) = self.get_visible_node(visual_idx) {
            let node = &self.nodes[node_idx];
            if !node.has_children {
                return None;
            }

            let indent = (node.level as i32) * TREE_INDENT;
            let expand_x = indent + 4;

            // Click on +/- button area (12x12)
            if x >= expand_x && x < expand_x + 12 {
                return Some(node_idx);
            }
        }
        None
    }

    /// Scroll the tree
    pub fn scroll(&mut self, delta: i32) {
        let max_scroll = ((self.visible_count() as i32) * TREE_ITEM_HEIGHT).saturating_sub(200);
        self.scroll_y = (self.scroll_y + delta).max(0).min(max_scroll.max(0));
    }

    /// Get path of selected node
    pub fn get_selected_path(&self) -> Option<&str> {
        if self.selected_index >= 0 && (self.selected_index as usize) < self.node_count {
            let path = self.nodes[self.selected_index as usize].path_str();
            if !path.is_empty() {
                return Some(path);
            }
        }
        None
    }

    /// Navigate to a path (expand parents and select)
    pub fn navigate_to(&mut self, path: &str) {
        // Find node with matching path
        for i in 0..self.node_count {
            if self.nodes[i].path_str() == path {
                self.selected_index = i as i32;

                // Expand all parents
                let mut parent = self.nodes[i].parent_index;
                while parent >= 0 && (parent as usize) < self.node_count {
                    self.nodes[parent as usize].expanded = true;
                    parent = self.nodes[parent as usize].parent_index;
                }

                self.update_visibility();
                return;
            }
        }
    }
}

// ============================================================================
// Global Tree State
// ============================================================================

use crate::ke::spinlock::SpinLock;

/// Maximum number of folder trees (one per explorer window)
const MAX_FOLDER_TREES: usize = 8;

/// Global folder trees storage
static FOLDER_TREES: SpinLock<[FolderTree; MAX_FOLDER_TREES]> = SpinLock::new([const { FolderTree::new() }; MAX_FOLDER_TREES]);

/// Get or create folder tree for a window
pub fn get_or_create_tree(hwnd: HWND) -> Option<usize> {
    let mut trees = FOLDER_TREES.lock();

    // Find existing
    for i in 0..MAX_FOLDER_TREES {
        if trees[i].hwnd == hwnd {
            return Some(i);
        }
    }

    // Find free slot
    for i in 0..MAX_FOLDER_TREES {
        if !trees[i].hwnd.is_valid() {
            trees[i].init(hwnd);
            return Some(i);
        }
    }

    None
}

/// Access tree with closure
pub fn with_tree<F, R>(hwnd: HWND, f: F) -> Option<R>
where
    F: FnOnce(&mut FolderTree) -> R,
{
    let mut trees = FOLDER_TREES.lock();
    for i in 0..MAX_FOLDER_TREES {
        if trees[i].hwnd == hwnd {
            return Some(f(&mut trees[i]));
        }
    }
    None
}

/// Remove tree for window
pub fn remove_tree(hwnd: HWND) {
    let mut trees = FOLDER_TREES.lock();
    for i in 0..MAX_FOLDER_TREES {
        if trees[i].hwnd == hwnd {
            trees[i] = FolderTree::new();
            break;
        }
    }
}

// ============================================================================
// Painting
// ============================================================================

/// Paint the folder tree
pub fn paint_tree(hwnd: HWND, hdc: HDC, surf: &surface::Surface, rect: &Rect) {
    with_tree(hwnd, |tree| {
        if !tree.visible {
            return;
        }

        // Background
        surf.fill_rect(rect, COLOR_TREE_BG);

        // Right border
        surf.vline(rect.right - 1, rect.top, rect.bottom, COLOR_TREE_LINE);

        // Draw visible nodes
        let mut visual_idx = 0;
        let mut y = rect.top - tree.scroll_y;

        for i in 0..tree.node_count {
            let node = &tree.nodes[i];
            if !node.visible {
                continue;
            }

            if y >= rect.bottom {
                break;
            }

            if y + TREE_ITEM_HEIGHT > rect.top {
                paint_tree_node(surf, hdc, rect, node, i, y, tree.selected_index == i as i32);
            }

            y += TREE_ITEM_HEIGHT;
            visual_idx += 1;
        }
    });
}

/// Paint a single tree node
fn paint_tree_node(surf: &surface::Surface, hdc: HDC, rect: &Rect, node: &TreeNode, _idx: usize, y: i32, selected: bool) {
    let indent = (node.level as i32) * TREE_INDENT;
    let x = rect.left + indent;

    // Selection highlight
    if selected {
        let sel_rect = Rect::new(rect.left, y, rect.right - 1, y + TREE_ITEM_HEIGHT);
        surf.fill_rect(&sel_rect, COLOR_TREE_SELECTED);
    }

    // Expand/collapse button
    if node.has_children {
        let btn_x = x + 2;
        let btn_y = y + (TREE_ITEM_HEIGHT - 9) / 2;

        // Draw box
        surf.hline(btn_x, btn_x + 8, btn_y, COLOR_TREE_LINE);
        surf.hline(btn_x, btn_x + 8, btn_y + 8, COLOR_TREE_LINE);
        surf.vline(btn_x, btn_y, btn_y + 9, COLOR_TREE_LINE);
        surf.vline(btn_x + 8, btn_y, btn_y + 9, COLOR_TREE_LINE);

        // Draw +/- symbol
        let center_y = btn_y + 4;
        surf.hline(btn_x + 2, btn_x + 7, center_y, COLOR_TREE_EXPAND); // Horizontal line

        if !node.expanded {
            // Vertical line for +
            let center_x = btn_x + 4;
            surf.vline(center_x, btn_y + 2, btn_y + 7, COLOR_TREE_EXPAND);
        }
    }

    // Draw folder icon
    let icon_x = x + 14;
    let icon_y = y + (TREE_ITEM_HEIGHT - 14) / 2;
    draw_tree_icon(surf, icon_x, icon_y, node.node_type);

    // Draw text
    let text_x = x + 32;
    let text_color = if selected { COLOR_TREE_SELECTED_TEXT } else { COLOR_TREE_TEXT };
    dc::set_text_color(hdc, text_color);
    dc::set_bk_mode(hdc, super::super::super::gdi::dc::BkMode::Transparent);

    use super::super::super::gdi;
    gdi::text_out(hdc, text_x, y + 3, node.name_str());
}

/// Draw tree node icon
fn draw_tree_icon(surf: &surface::Surface, x: i32, y: i32, node_type: TreeNodeType) {
    match node_type {
        TreeNodeType::Desktop => {
            // Monitor icon
            let frame = ColorRef::rgb(60, 60, 60);
            let screen = ColorRef::rgb(0, 120, 215);
            surf.fill_rect(&Rect::new(x, y, x + 14, y + 10), frame);
            surf.fill_rect(&Rect::new(x + 1, y + 1, x + 13, y + 9), screen);
            // Stand
            surf.fill_rect(&Rect::new(x + 5, y + 10, x + 9, y + 12), frame);
            surf.fill_rect(&Rect::new(x + 3, y + 12, x + 11, y + 14), frame);
        }
        TreeNodeType::MyComputer => {
            // Computer icon
            let case_color = ColorRef::rgb(180, 180, 180);
            let screen = ColorRef::rgb(0, 120, 215);
            surf.fill_rect(&Rect::new(x, y, x + 14, y + 10), case_color);
            surf.fill_rect(&Rect::new(x + 1, y + 1, x + 13, y + 9), screen);
            surf.fill_rect(&Rect::new(x + 2, y + 10, x + 12, y + 14), case_color);
        }
        TreeNodeType::Drive => {
            // Drive icon
            let drive_color = ColorRef::rgb(220, 220, 220);
            let label = ColorRef::rgb(0, 120, 215);
            surf.fill_rect(&Rect::new(x, y + 2, x + 14, y + 12), drive_color);
            surf.fill_rect(&Rect::new(x + 2, y + 4, x + 8, y + 7), label);
        }
        TreeNodeType::Folder | TreeNodeType::SpecialFolder => {
            // Folder icon
            let folder_color = ColorRef::rgb(255, 220, 100);
            let tab_color = ColorRef::rgb(230, 190, 80);
            // Tab
            surf.fill_rect(&Rect::new(x, y, x + 6, y + 3), tab_color);
            // Body
            surf.fill_rect(&Rect::new(x, y + 3, x + 14, y + 14), folder_color);
        }
    }
}

// ============================================================================
// Event Handlers
// ============================================================================

/// Handle tree click
pub fn handle_tree_click(hwnd: HWND, x: i32, y: i32, tree_rect: &Rect) -> Option<&'static str> {
    let local_x = x - tree_rect.left;
    let local_y = y - tree_rect.top;

    with_tree(hwnd, |tree| {
        // Check if clicking on expand button
        if let Some(node_idx) = tree.hit_test_expand(local_x, local_y) {
            tree.toggle_expand(node_idx);
            return None;
        }

        // Otherwise select node
        if let Some(node_idx) = tree.select_at(local_y) {
            // Return path for navigation - need to handle static lifetime
            return None; // Navigation handled separately
        }

        None
    }).flatten()
}

/// Get selected path after click
pub fn get_selected_path_after_click(hwnd: HWND) -> Option<([u8; MAX_PATH], usize)> {
    with_tree(hwnd, |tree| {
        if tree.selected_index >= 0 && (tree.selected_index as usize) < tree.node_count {
            let node = &tree.nodes[tree.selected_index as usize];
            // Return path even if empty (empty path = show drives/My Computer)
            let mut buf = [0u8; MAX_PATH];
            if node.path_len > 0 {
                buf[..node.path_len].copy_from_slice(&node.path[..node.path_len]);
            }
            return Some((buf, node.path_len));
        }
        None
    }).flatten()
}

/// Handle tree double-click (toggle expand)
pub fn handle_tree_double_click(hwnd: HWND, x: i32, y: i32, tree_rect: &Rect) {
    let local_y = y - tree_rect.top;

    with_tree(hwnd, |tree| {
        if let Some(node_idx) = tree.select_at(local_y) {
            tree.toggle_expand(node_idx);
        }
    });
}

/// Handle tree scroll
pub fn handle_tree_scroll(hwnd: HWND, delta: i32) {
    with_tree(hwnd, |tree| {
        tree.scroll(delta * TREE_ITEM_HEIGHT);
    });
}

/// Toggle tree visibility
pub fn toggle_tree_visibility(hwnd: HWND) {
    with_tree(hwnd, |tree| {
        tree.visible = !tree.visible;
    });
}

/// Check if tree is visible
pub fn is_tree_visible(hwnd: HWND) -> bool {
    with_tree(hwnd, |tree| tree.visible).unwrap_or(false)
}

/// Get tree width
pub fn get_tree_width(hwnd: HWND) -> i32 {
    with_tree(hwnd, |tree| {
        if tree.visible { tree.width } else { 0 }
    }).unwrap_or(0)
}

/// Sync tree with browser navigation
pub fn sync_with_browser(hwnd: HWND, path: &str) {
    with_tree(hwnd, |tree| {
        tree.navigate_to(path);
    });
}

/// Initialize folder tree subsystem
pub fn init() {
    crate::serial_println!("[FOLDERTREE] Folder tree subsystem initialized");
}
