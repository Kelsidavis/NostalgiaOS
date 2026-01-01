//! SysLink Control Implementation
//!
//! Windows SysLink control for displaying hyperlinks.
//! Based on Windows Server 2003 commctrl.h.
//!
//! # Features
//!
//! - Hyperlink text with clickable regions
//! - Multiple link items per control
//! - Link state tracking (focused, enabled, visited)
//! - URL association
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - LM_* messages, LWS_* styles

use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle, Rect, Point};

// ============================================================================
// SysLink Styles (LWS_*)
// ============================================================================

/// Transparent background
pub const LWS_TRANSPARENT: u32 = 0x0001;

/// Don't treat Return as click
pub const LWS_IGNORERETURN: u32 = 0x0002;

// ============================================================================
// Link Item Flags (LIF_*)
// ============================================================================

/// Item index is valid
pub const LIF_ITEMINDEX: u32 = 0x00000001;

/// State field is valid
pub const LIF_STATE: u32 = 0x00000002;

/// Item ID is valid
pub const LIF_ITEMID: u32 = 0x00000004;

/// URL is valid
pub const LIF_URL: u32 = 0x00000008;

// ============================================================================
// Link Item States (LIS_*)
// ============================================================================

/// Link is focused
pub const LIS_FOCUSED: u32 = 0x00000001;

/// Link is enabled
pub const LIS_ENABLED: u32 = 0x00000002;

/// Link has been visited
pub const LIS_VISITED: u32 = 0x00000004;

// ============================================================================
// SysLink Messages
// ============================================================================

/// WM_USER base
pub const WM_USER: u32 = 0x0400;

/// Hit test
/// lParam: PLHITTESTINFO
/// Returns: TRUE if hit
pub const LM_HITTEST: u32 = WM_USER + 0x300;

/// Get ideal height
/// Returns: height in pixels
pub const LM_GETIDEALHEIGHT: u32 = WM_USER + 0x301;

/// Set item properties
/// lParam: LITEM*
/// Returns: TRUE if successful
pub const LM_SETITEM: u32 = WM_USER + 0x302;

/// Get item properties
/// lParam: LITEM*
/// Returns: TRUE if successful
pub const LM_GETITEM: u32 = WM_USER + 0x303;

// ============================================================================
// Notifications (NM_*)
// ============================================================================

/// Link clicked notification
pub const NM_CLICK: u32 = 0u32.wrapping_sub(2);

/// Link activated via keyboard
pub const NM_RETURN: u32 = 0u32.wrapping_sub(4);

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of SysLink controls
pub const MAX_SYSLINK_CONTROLS: usize = 64;

/// Maximum link items per control
pub const MAX_LINK_ITEMS: usize = 16;

/// Maximum link ID text length
pub const MAX_LINKID_TEXT: usize = 48;

/// Maximum URL length
pub const MAX_URL_LENGTH: usize = 2083; // 2048 + 32 + "://" length

/// Maximum display text length
pub const MAX_LINK_TEXT: usize = 256;

/// SysLink class name
pub const SYSLINK_CLASS: &str = "SysLink";

// ============================================================================
// Link Item Structure
// ============================================================================

/// Link item information
#[derive(Clone)]
pub struct LinkItem {
    /// Item is in use
    pub in_use: bool,
    /// Mask of valid fields
    pub mask: u32,
    /// Item index
    pub item_index: i32,
    /// Item state (LIS_*)
    pub state: u32,
    /// State mask
    pub state_mask: u32,
    /// Item ID
    pub id: [u8; MAX_LINKID_TEXT],
    pub id_len: usize,
    /// URL
    pub url: [u8; MAX_URL_LENGTH],
    pub url_len: usize,
    /// Display text (parsed from control text)
    pub text: [u8; MAX_LINK_TEXT],
    pub text_len: usize,
    /// Hit rectangle
    pub rect: Rect,
}

impl LinkItem {
    /// Create a new link item
    pub const fn new() -> Self {
        Self {
            in_use: false,
            mask: 0,
            item_index: -1,
            state: LIS_ENABLED,
            state_mask: 0,
            id: [0u8; MAX_LINKID_TEXT],
            id_len: 0,
            url: [0u8; MAX_URL_LENGTH],
            url_len: 0,
            text: [0u8; MAX_LINK_TEXT],
            text_len: 0,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
        }
    }

    /// Reset item
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Set ID
    pub fn set_id(&mut self, id: &[u8]) {
        let len = core::cmp::min(id.len(), MAX_LINKID_TEXT);
        self.id[..len].copy_from_slice(&id[..len]);
        self.id_len = len;
    }

    /// Set URL
    pub fn set_url(&mut self, url: &[u8]) {
        let len = core::cmp::min(url.len(), MAX_URL_LENGTH);
        self.url[..len].copy_from_slice(&url[..len]);
        self.url_len = len;
    }

    /// Set text
    pub fn set_text(&mut self, text: &[u8]) {
        let len = core::cmp::min(text.len(), MAX_LINK_TEXT);
        self.text[..len].copy_from_slice(&text[..len]);
        self.text_len = len;
    }

    /// Check if point is in item rectangle
    pub fn hit_test(&self, pt: &Point) -> bool {
        pt.x >= self.rect.left && pt.x < self.rect.right &&
        pt.y >= self.rect.top && pt.y < self.rect.bottom
    }

    /// Check if focused
    pub fn is_focused(&self) -> bool {
        self.state & LIS_FOCUSED != 0
    }

    /// Check if enabled
    pub fn is_enabled(&self) -> bool {
        self.state & LIS_ENABLED != 0
    }

    /// Check if visited
    pub fn is_visited(&self) -> bool {
        self.state & LIS_VISITED != 0
    }

    /// Set focused state
    pub fn set_focused(&mut self, focused: bool) {
        if focused {
            self.state |= LIS_FOCUSED;
        } else {
            self.state &= !LIS_FOCUSED;
        }
    }

    /// Set visited state
    pub fn set_visited(&mut self, visited: bool) {
        if visited {
            self.state |= LIS_VISITED;
        } else {
            self.state &= !LIS_VISITED;
        }
    }
}

// ============================================================================
// SysLink Control Structure
// ============================================================================

/// SysLink control state
#[derive(Clone)]
pub struct SysLinkControl {
    /// Control handle
    pub hwnd: HWND,
    /// Is this slot in use
    pub in_use: bool,
    /// Control style flags
    pub style: u32,
    /// Display rectangle
    pub rect: Rect,
    /// Link items
    pub items: [LinkItem; MAX_LINK_ITEMS],
    /// Item count
    pub item_count: usize,
    /// Currently focused item
    pub focused_item: i32,
    /// Control text (with markup)
    pub text: [u8; 512],
    pub text_len: usize,
    /// Ideal height
    pub ideal_height: i32,
    /// Link color
    pub link_color: u32,
    /// Visited link color
    pub visited_color: u32,
}

impl SysLinkControl {
    /// Create a new SysLink control
    pub const fn new() -> Self {
        Self {
            hwnd: UserHandle::NULL,
            in_use: false,
            style: 0,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            items: [const { LinkItem::new() }; MAX_LINK_ITEMS],
            item_count: 0,
            focused_item: -1,
            text: [0u8; 512],
            text_len: 0,
            ideal_height: 16,
            link_color: 0x0000FF,     // Blue
            visited_color: 0x800080,  // Purple
        }
    }

    /// Reset control to default state
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Parse text and extract link items
    /// Format: Text <a href="url" id="id">link text</a> more text
    pub fn set_text(&mut self, text: &[u8]) {
        let len = core::cmp::min(text.len(), self.text.len());
        self.text[..len].copy_from_slice(&text[..len]);
        self.text_len = len;

        // Reset items
        for item in self.items.iter_mut() {
            item.reset();
        }
        self.item_count = 0;

        // Simple parser for <a> tags
        self.parse_links();
    }

    /// Simple link parser
    fn parse_links(&mut self) {
        let text = &self.text[..self.text_len];
        let mut i = 0;
        let mut x_pos = 0i32;

        while i < text.len() && self.item_count < MAX_LINK_ITEMS {
            // Look for <a
            if i + 2 < text.len() && text[i] == b'<' && (text[i + 1] == b'a' || text[i + 1] == b'A') {
                // Find the closing >
                let tag_start = i;
                while i < text.len() && text[i] != b'>' {
                    i += 1;
                }
                if i >= text.len() {
                    break;
                }
                i += 1; // Skip >

                // Find link text end </a>
                let link_text_start = i;
                while i + 4 <= text.len() {
                    if text[i] == b'<' && text[i + 1] == b'/' &&
                       (text[i + 2] == b'a' || text[i + 2] == b'A') && text[i + 3] == b'>' {
                        break;
                    }
                    i += 1;
                }

                let link_text_end = i;

                // Parse attributes from tag
                let tag = &text[tag_start..link_text_start.saturating_sub(1)];
                let link_text = &text[link_text_start..link_text_end];

                // Parse href and id from tag first (before mutable borrow of item)
                let mut url_bytes = [0u8; MAX_URL_LENGTH];
                let mut url_len = 0usize;
                let mut id_bytes = [0u8; MAX_LINKID_TEXT];
                let mut id_len = 0usize;

                // Look for href="..."
                if let Some(href_start) = find_attr(tag, b"href=\"") {
                    let url_start = href_start + 6;
                    if let Some(url_end) = find_char(&tag[url_start..], b'"') {
                        url_len = core::cmp::min(url_end, MAX_URL_LENGTH);
                        url_bytes[..url_len].copy_from_slice(&tag[url_start..url_start + url_len]);
                    }
                }

                // Look for id="..."
                if let Some(id_start) = find_attr(tag, b"id=\"") {
                    let id_val_start = id_start + 4;
                    if let Some(id_end) = find_char(&tag[id_val_start..], b'"') {
                        id_len = core::cmp::min(id_end, MAX_LINKID_TEXT);
                        id_bytes[..id_len].copy_from_slice(&tag[id_val_start..id_val_start + id_len]);
                    }
                }

                // Now create link item
                let idx = self.item_count;
                let item = &mut self.items[idx];
                item.in_use = true;
                item.item_index = idx as i32;
                item.set_text(link_text);

                if url_len > 0 {
                    item.set_url(&url_bytes[..url_len]);
                }
                if id_len > 0 {
                    item.set_id(&id_bytes[..id_len]);
                }

                // Set hit rectangle (simplified - fixed char width)
                let char_width = 8;
                let link_width = (link_text.len() as i32) * char_width;
                item.rect.left = self.rect.left + x_pos;
                item.rect.top = self.rect.top;
                item.rect.right = item.rect.left + link_width;
                item.rect.bottom = item.rect.top + 16;

                x_pos += link_width;
                self.item_count += 1;

                // Skip </a>
                i += 4;
            } else {
                // Regular text, advance position
                x_pos += 8;
                i += 1;
            }
        }
    }

    /// Hit test
    pub fn hit_test(&self, pt: &Point) -> i32 {
        for i in 0..self.item_count {
            if self.items[i].hit_test(pt) {
                return i as i32;
            }
        }
        -1
    }

    /// Get ideal height
    pub fn get_ideal_height(&self) -> i32 {
        self.ideal_height
    }

    /// Set item properties
    pub fn set_item(&mut self, index: usize, mask: u32, state: u32, state_mask: u32,
                    id: Option<&[u8]>, url: Option<&[u8]>) -> bool {
        if index >= self.item_count {
            return false;
        }

        let item = &mut self.items[index];
        item.mask = mask;

        if mask & LIF_STATE != 0 {
            item.state = (item.state & !state_mask) | (state & state_mask);
        }
        if mask & LIF_ITEMID != 0 {
            if let Some(id_bytes) = id {
                item.set_id(id_bytes);
            }
        }
        if mask & LIF_URL != 0 {
            if let Some(url_bytes) = url {
                item.set_url(url_bytes);
            }
        }

        true
    }

    /// Get item info
    pub fn get_item(&self, index: usize) -> Option<&LinkItem> {
        if index >= self.item_count {
            return None;
        }
        Some(&self.items[index])
    }

    /// Navigate focus to next/previous link
    pub fn navigate_focus(&mut self, forward: bool) -> bool {
        if self.item_count == 0 {
            return false;
        }

        // Clear current focus
        if self.focused_item >= 0 && (self.focused_item as usize) < self.item_count {
            self.items[self.focused_item as usize].set_focused(false);
        }

        if forward {
            self.focused_item += 1;
            if self.focused_item as usize >= self.item_count {
                self.focused_item = 0;
            }
        } else {
            self.focused_item -= 1;
            if self.focused_item < 0 {
                self.focused_item = (self.item_count - 1) as i32;
            }
        }

        self.items[self.focused_item as usize].set_focused(true);
        true
    }

    /// Click the focused item
    pub fn click_focused(&mut self) -> bool {
        if self.focused_item >= 0 && (self.focused_item as usize) < self.item_count {
            let item = &mut self.items[self.focused_item as usize];
            if item.is_enabled() {
                item.set_visited(true);
                return true;
            }
        }
        false
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Find attribute in tag
fn find_attr(tag: &[u8], attr: &[u8]) -> Option<usize> {
    if attr.len() > tag.len() {
        return None;
    }

    for i in 0..=tag.len() - attr.len() {
        let mut matches = true;
        for j in 0..attr.len() {
            let c1 = if tag[i + j] >= b'A' && tag[i + j] <= b'Z' {
                tag[i + j] + 32
            } else {
                tag[i + j]
            };
            let c2 = if attr[j] >= b'A' && attr[j] <= b'Z' {
                attr[j] + 32
            } else {
                attr[j]
            };
            if c1 != c2 {
                matches = false;
                break;
            }
        }
        if matches {
            return Some(i);
        }
    }
    None
}

/// Find character in slice
fn find_char(data: &[u8], c: u8) -> Option<usize> {
    for (i, &b) in data.iter().enumerate() {
        if b == c {
            return Some(i);
        }
    }
    None
}

// ============================================================================
// Global State
// ============================================================================

/// Global SysLink control storage
static SYSLINK_CONTROLS: SpinLock<[SysLinkControl; MAX_SYSLINK_CONTROLS]> =
    SpinLock::new([const { SysLinkControl::new() }; MAX_SYSLINK_CONTROLS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize SysLink control subsystem
pub fn init() {
    crate::serial_println!("[USER] SysLink control initialized");
}

/// Create a SysLink control
pub fn create_syslink(hwnd: HWND, style: u32, rect: &Rect) -> Option<usize> {
    let mut controls = SYSLINK_CONTROLS.lock();

    for (i, control) in controls.iter_mut().enumerate() {
        if !control.in_use {
            control.reset();
            control.hwnd = hwnd;
            control.in_use = true;
            control.style = style;
            control.rect = *rect;
            return Some(i);
        }
    }

    None
}

/// Destroy a SysLink control
pub fn destroy_syslink(index: usize) -> bool {
    let mut controls = SYSLINK_CONTROLS.lock();

    if index >= MAX_SYSLINK_CONTROLS {
        return false;
    }

    if controls[index].in_use {
        controls[index].reset();
        true
    } else {
        false
    }
}

/// Set text
pub fn set_text(index: usize, text: &[u8]) -> bool {
    let mut controls = SYSLINK_CONTROLS.lock();

    if index >= MAX_SYSLINK_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].set_text(text);
    true
}

/// Hit test
pub fn hit_test(index: usize, pt: &Point) -> i32 {
    let controls = SYSLINK_CONTROLS.lock();

    if index >= MAX_SYSLINK_CONTROLS || !controls[index].in_use {
        return -1;
    }

    controls[index].hit_test(pt)
}

/// Get ideal height
pub fn get_ideal_height(index: usize) -> i32 {
    let controls = SYSLINK_CONTROLS.lock();

    if index >= MAX_SYSLINK_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].ideal_height
}

/// Set item
pub fn set_item(index: usize, item_index: usize, mask: u32, state: u32, state_mask: u32) -> bool {
    let mut controls = SYSLINK_CONTROLS.lock();

    if index >= MAX_SYSLINK_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].set_item(item_index, mask, state, state_mask, None, None)
}

/// Get item count
pub fn get_item_count(index: usize) -> usize {
    let controls = SYSLINK_CONTROLS.lock();

    if index >= MAX_SYSLINK_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].item_count
}

/// Process SysLink control message
pub fn process_message(index: usize, msg: u32, _wparam: usize, lparam: isize) -> isize {
    match msg {
        LM_HITTEST => {
            // In real implementation, lparam points to LHITTESTINFO
            // For now, return -1 (no hit)
            -1
        }
        LM_GETIDEALHEIGHT => {
            get_ideal_height(index) as isize
        }
        LM_SETITEM => {
            // In real implementation, lparam points to LITEM
            let _item_ptr = lparam;
            0
        }
        LM_GETITEM => {
            // In real implementation, lparam points to LITEM to fill
            let _item_ptr = lparam;
            0
        }
        _ => 0,
    }
}

/// Get statistics
pub fn get_stats() -> SysLinkStats {
    let controls = SYSLINK_CONTROLS.lock();

    let mut active_count = 0;
    let mut total_items = 0;

    for control in controls.iter() {
        if control.in_use {
            active_count += 1;
            total_items += control.item_count;
        }
    }

    SysLinkStats {
        max_controls: MAX_SYSLINK_CONTROLS,
        active_controls: active_count,
        total_link_items: total_items,
    }
}

/// SysLink statistics
#[derive(Debug, Clone, Copy)]
pub struct SysLinkStats {
    pub max_controls: usize,
    pub active_controls: usize,
    pub total_link_items: usize,
}
