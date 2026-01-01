//! Window Enumeration Helpers
//!
//! Windows window enumeration functions.
//! Based on Windows Server 2003 user32.h.
//!
//! # Features
//!
//! - EnumWindows/EnumChildWindows
//! - FindWindow/FindWindowEx
//! - GetWindow navigation
//! - Window relationships
//!
//! # References
//!
//! - `public/sdk/inc/winuser.h` - Window enumeration

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};
use super::strhelp;

// ============================================================================
// GetWindow Commands (GW_*)
// ============================================================================

/// First child
pub const GW_HWNDFIRST: u32 = 0;

/// Last child
pub const GW_HWNDLAST: u32 = 1;

/// Next sibling
pub const GW_HWNDNEXT: u32 = 2;

/// Previous sibling
pub const GW_HWNDPREV: u32 = 3;

/// Owner window
pub const GW_OWNER: u32 = 4;

/// Child window
pub const GW_CHILD: u32 = 5;

/// Enabled popup
pub const GW_ENABLEDPOPUP: u32 = 6;

// ============================================================================
// GetAncestor Flags (GA_*)
// ============================================================================

/// Parent
pub const GA_PARENT: u32 = 1;

/// Root
pub const GA_ROOT: u32 = 2;

/// Root owner
pub const GA_ROOTOWNER: u32 = 3;

// ============================================================================
// Window Relationship Types
// ============================================================================

/// Window relationship types for IsChild, etc.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WindowRelation {
    /// No relationship
    None,
    /// Same window
    Same,
    /// Parent window
    Parent,
    /// Child window
    Child,
    /// Sibling window
    Sibling,
    /// Owner window
    Owner,
    /// Owned window
    Owned,
    /// Ancestor (grandparent, etc.)
    Ancestor,
    /// Descendant (grandchild, etc.)
    Descendant,
}

// ============================================================================
// Callback Types
// ============================================================================

/// Window enumeration callback
pub type EnumWindowsProc = fn(hwnd: HWND, lparam: isize) -> bool;

/// Window property enumeration callback
pub type PropEnumProc = fn(hwnd: HWND, name: &[u8], data: usize) -> bool;

// ============================================================================
// Simulated Window Database
// ============================================================================

/// Maximum tracked windows
pub const MAX_TRACKED_WINDOWS: usize = 256;

/// Window entry for enumeration
#[derive(Clone, Copy)]
pub struct WindowEntry {
    /// Is this slot in use
    pub in_use: bool,
    /// Window handle
    pub hwnd: HWND,
    /// Parent window
    pub parent: HWND,
    /// Owner window
    pub owner: HWND,
    /// First child
    pub child: HWND,
    /// Next sibling
    pub next: HWND,
    /// Previous sibling
    pub prev: HWND,
    /// Class name
    pub class_name: [u8; 64],
    /// Window text
    pub window_text: [u8; 128],
    /// Is visible
    pub visible: bool,
    /// Is enabled
    pub enabled: bool,
    /// Z-order
    pub z_order: u32,
}

impl WindowEntry {
    /// Create empty entry
    pub const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: UserHandle::NULL,
            parent: UserHandle::NULL,
            owner: UserHandle::NULL,
            child: UserHandle::NULL,
            next: UserHandle::NULL,
            prev: UserHandle::NULL,
            class_name: [0; 64],
            window_text: [0; 128],
            visible: true,
            enabled: true,
            z_order: 0,
        }
    }
}

/// Global window database
static WINDOWS: SpinLock<[WindowEntry; MAX_TRACKED_WINDOWS]> =
    SpinLock::new([const { WindowEntry::new() }; MAX_TRACKED_WINDOWS]);

// ============================================================================
// Internal Functions
// ============================================================================

/// Find window entry by handle
fn find_window_entry(hwnd: HWND) -> Option<usize> {
    if hwnd == UserHandle::NULL {
        return None;
    }

    let windows = WINDOWS.lock();
    for (i, entry) in windows.iter().enumerate() {
        if entry.in_use && entry.hwnd == hwnd {
            return Some(i);
        }
    }
    None
}

// ============================================================================
// Public API
// ============================================================================

/// Initialize window enumeration
pub fn init() {
    crate::serial_println!("[USER] Window enumeration initialized");
}

/// Register a window for enumeration
pub fn register_window(hwnd: HWND, parent: HWND, class_name: &[u8], window_text: &[u8]) -> bool {
    let mut windows = WINDOWS.lock();

    // Find free slot
    for entry in windows.iter_mut() {
        if !entry.in_use {
            entry.in_use = true;
            entry.hwnd = hwnd;
            entry.parent = parent;
            entry.owner = UserHandle::NULL;
            entry.child = UserHandle::NULL;
            entry.next = UserHandle::NULL;
            entry.prev = UserHandle::NULL;

            let class_len = strhelp::str_len(class_name).min(63);
            entry.class_name[..class_len].copy_from_slice(&class_name[..class_len]);
            entry.class_name[class_len] = 0;

            let text_len = strhelp::str_len(window_text).min(127);
            entry.window_text[..text_len].copy_from_slice(&window_text[..text_len]);
            entry.window_text[text_len] = 0;

            entry.visible = true;
            entry.enabled = true;
            entry.z_order = 0;

            return true;
        }
    }

    false
}

/// Unregister a window
pub fn unregister_window(hwnd: HWND) -> bool {
    let mut windows = WINDOWS.lock();

    for entry in windows.iter_mut() {
        if entry.in_use && entry.hwnd == hwnd {
            *entry = WindowEntry::new();
            return true;
        }
    }

    false
}

/// Enumerate top-level windows
pub fn enum_windows(callback: EnumWindowsProc, lparam: isize) -> bool {
    let windows = WINDOWS.lock();

    for entry in windows.iter() {
        if entry.in_use && entry.parent == UserHandle::NULL {
            if !callback(entry.hwnd, lparam) {
                return false;
            }
        }
    }

    true
}

/// Enumerate child windows
pub fn enum_child_windows(parent: HWND, callback: EnumWindowsProc, lparam: isize) -> bool {
    let windows = WINDOWS.lock();

    for entry in windows.iter() {
        if entry.in_use && entry.parent == parent {
            if !callback(entry.hwnd, lparam) {
                return false;
            }
        }
    }

    true
}

/// Enumerate thread windows
pub fn enum_thread_windows(_thread_id: u32, callback: EnumWindowsProc, lparam: isize) -> bool {
    // In a real implementation, this would filter by thread
    // For now, enumerate all windows
    enum_windows(callback, lparam)
}

/// Enumerate desktop windows
pub fn enum_desktop_windows(_desktop: usize, callback: EnumWindowsProc, lparam: isize) -> bool {
    // In a real implementation, this would filter by desktop
    enum_windows(callback, lparam)
}

/// Find window by class and title
pub fn find_window(class_name: Option<&[u8]>, window_text: Option<&[u8]>) -> HWND {
    find_window_ex(UserHandle::NULL, UserHandle::NULL, class_name, window_text)
}

/// Find window with more options
pub fn find_window_ex(
    parent: HWND,
    child_after: HWND,
    class_name: Option<&[u8]>,
    window_text: Option<&[u8]>,
) -> HWND {
    let windows = WINDOWS.lock();
    let mut found_after = child_after == UserHandle::NULL;

    for entry in windows.iter() {
        if !entry.in_use {
            continue;
        }

        // Check parent constraint
        if parent != UserHandle::NULL && entry.parent != parent {
            continue;
        }

        // Skip until we find child_after
        if !found_after {
            if entry.hwnd == child_after {
                found_after = true;
            }
            continue;
        }

        // Check class name
        if let Some(class) = class_name {
            if strhelp::str_cmp_i(&entry.class_name, class) != 0 {
                continue;
            }
        }

        // Check window text
        if let Some(text) = window_text {
            if strhelp::str_cmp_i(&entry.window_text, text) != 0 {
                continue;
            }
        }

        return entry.hwnd;
    }

    UserHandle::NULL
}

/// Get window by relationship
pub fn get_window(hwnd: HWND, cmd: u32) -> HWND {
    let idx = match find_window_entry(hwnd) {
        Some(i) => i,
        None => return UserHandle::NULL,
    };

    let windows = WINDOWS.lock();
    let entry = &windows[idx];

    match cmd {
        GW_HWNDFIRST => {
            // First sibling (or self if no siblings)
            if entry.parent != UserHandle::NULL {
                // Find first child of parent
                for e in windows.iter() {
                    if e.in_use && e.parent == entry.parent && e.prev == UserHandle::NULL {
                        return e.hwnd;
                    }
                }
            }
            entry.hwnd
        }
        GW_HWNDLAST => {
            // Last sibling
            if entry.parent != UserHandle::NULL {
                for e in windows.iter() {
                    if e.in_use && e.parent == entry.parent && e.next == UserHandle::NULL {
                        return e.hwnd;
                    }
                }
            }
            entry.hwnd
        }
        GW_HWNDNEXT => entry.next,
        GW_HWNDPREV => entry.prev,
        GW_OWNER => entry.owner,
        GW_CHILD => entry.child,
        GW_ENABLEDPOPUP => {
            // Find enabled popup owned by this window
            for e in windows.iter() {
                if e.in_use && e.owner == hwnd && e.enabled {
                    return e.hwnd;
                }
            }
            hwnd
        }
        _ => UserHandle::NULL,
    }
}

/// Get parent window
pub fn get_parent(hwnd: HWND) -> HWND {
    let idx = match find_window_entry(hwnd) {
        Some(i) => i,
        None => return UserHandle::NULL,
    };

    let windows = WINDOWS.lock();
    windows[idx].parent
}

/// Get ancestor window
pub fn get_ancestor(hwnd: HWND, flags: u32) -> HWND {
    match flags {
        GA_PARENT => get_parent(hwnd),
        GA_ROOT => {
            let mut current = hwnd;
            loop {
                let parent = get_parent(current);
                if parent == UserHandle::NULL {
                    return current;
                }
                current = parent;
            }
        }
        GA_ROOTOWNER => {
            let mut current = hwnd;
            loop {
                let owner = get_window(current, GW_OWNER);
                if owner == UserHandle::NULL {
                    return current;
                }
                current = owner;
            }
        }
        _ => UserHandle::NULL,
    }
}

/// Check if window is a child of another
pub fn is_child(parent: HWND, hwnd: HWND) -> bool {
    let mut current = hwnd;

    while current != UserHandle::NULL {
        let p = get_parent(current);
        if p == parent {
            return true;
        }
        current = p;
    }

    false
}

/// Get top window (first child)
pub fn get_top_window(hwnd: HWND) -> HWND {
    get_window(hwnd, GW_CHILD)
}

/// Get next window in Z-order
pub fn get_next_window(hwnd: HWND, cmd: u32) -> HWND {
    match cmd {
        GW_HWNDNEXT | GW_HWNDPREV => get_window(hwnd, cmd),
        _ => UserHandle::NULL,
    }
}

/// Get last active popup
pub fn get_last_active_popup(owner: HWND) -> HWND {
    let windows = WINDOWS.lock();

    let mut best = owner;
    let mut best_z = 0;

    for entry in windows.iter() {
        if entry.in_use && entry.owner == owner && entry.z_order > best_z {
            best = entry.hwnd;
            best_z = entry.z_order;
        }
    }

    best
}

/// Get window class name
pub fn get_class_name(hwnd: HWND, buffer: &mut [u8]) -> usize {
    let idx = match find_window_entry(hwnd) {
        Some(i) => i,
        None => return 0,
    };

    let windows = WINDOWS.lock();
    let len = strhelp::str_len(&windows[idx].class_name);
    let copy_len = len.min(buffer.len().saturating_sub(1));

    buffer[..copy_len].copy_from_slice(&windows[idx].class_name[..copy_len]);
    if copy_len < buffer.len() {
        buffer[copy_len] = 0;
    }

    copy_len
}

/// Get real class name (resolves superclasses)
pub fn real_get_class_name(hwnd: HWND, buffer: &mut [u8]) -> usize {
    // In our simplified model, this is the same as GetClassName
    get_class_name(hwnd, buffer)
}

/// Check if window class matches
pub fn is_window_class(hwnd: HWND, class_name: &[u8]) -> bool {
    let idx = match find_window_entry(hwnd) {
        Some(i) => i,
        None => return false,
    };

    let windows = WINDOWS.lock();
    strhelp::str_cmp_i(&windows[idx].class_name, class_name) == 0
}

/// Get window text length
pub fn get_window_text_length(hwnd: HWND) -> usize {
    let idx = match find_window_entry(hwnd) {
        Some(i) => i,
        None => return 0,
    };

    let windows = WINDOWS.lock();
    strhelp::str_len(&windows[idx].window_text)
}

/// Check if window exists
pub fn is_window(hwnd: HWND) -> bool {
    find_window_entry(hwnd).is_some()
}

/// Check if window is visible
pub fn is_window_visible(hwnd: HWND) -> bool {
    let idx = match find_window_entry(hwnd) {
        Some(i) => i,
        None => return false,
    };

    let windows = WINDOWS.lock();
    windows[idx].visible
}

/// Check if window is enabled
pub fn is_window_enabled(hwnd: HWND) -> bool {
    let idx = match find_window_entry(hwnd) {
        Some(i) => i,
        None => return false,
    };

    let windows = WINDOWS.lock();
    windows[idx].enabled
}

/// Set window visibility
pub fn set_window_visible(hwnd: HWND, visible: bool) -> bool {
    let idx = match find_window_entry(hwnd) {
        Some(i) => i,
        None => return false,
    };

    let mut windows = WINDOWS.lock();
    windows[idx].visible = visible;
    true
}

/// Set window enabled state
pub fn set_window_enabled(hwnd: HWND, enabled: bool) -> bool {
    let idx = match find_window_entry(hwnd) {
        Some(i) => i,
        None => return false,
    };

    let mut windows = WINDOWS.lock();
    windows[idx].enabled = enabled;
    true
}

/// Get window count
pub fn get_window_count() -> usize {
    let windows = WINDOWS.lock();
    windows.iter().filter(|e| e.in_use).count()
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> EnumWindowsStats {
    let windows = WINDOWS.lock();

    let mut total = 0;
    let mut visible = 0;
    let mut top_level = 0;

    for entry in windows.iter() {
        if entry.in_use {
            total += 1;
            if entry.visible {
                visible += 1;
            }
            if entry.parent == UserHandle::NULL {
                top_level += 1;
            }
        }
    }

    EnumWindowsStats {
        max_windows: MAX_TRACKED_WINDOWS,
        total_windows: total,
        visible_windows: visible,
        top_level_windows: top_level,
    }
}

/// Window enumeration statistics
#[derive(Debug, Clone, Copy)]
pub struct EnumWindowsStats {
    pub max_windows: usize,
    pub total_windows: usize,
    pub visible_windows: usize,
    pub top_level_windows: usize,
}
