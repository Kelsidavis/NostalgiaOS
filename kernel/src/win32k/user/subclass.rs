//! Window Subclassing Support
//!
//! Windows subclassing helpers for modifying window behavior.
//! Based on Windows Server 2003 commctrl.h.
//!
//! # Features
//!
//! - Safe window subclassing
//! - Multiple subclass procedures per window
//! - Reference data per subclass
//! - Automatic cleanup
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - SetWindowSubclass, etc.

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// Constants
// ============================================================================

/// Maximum subclassed windows
pub const MAX_SUBCLASSED_WINDOWS: usize = 128;

/// Maximum subclass entries per window
pub const MAX_SUBCLASS_PER_WINDOW: usize = 8;

/// Subclass procedure type
pub type SubclassProc = fn(hwnd: HWND, msg: u32, wparam: usize, lparam: isize, id: usize, ref_data: usize) -> isize;

// ============================================================================
// Subclass Entry
// ============================================================================

/// Single subclass entry
#[derive(Clone, Copy)]
pub struct SubclassEntry {
    /// Is this entry in use
    pub in_use: bool,
    /// Subclass ID
    pub id: usize,
    /// Subclass procedure
    pub proc_addr: usize,
    /// Reference data
    pub ref_data: usize,
}

impl SubclassEntry {
    /// Create empty entry
    pub const fn new() -> Self {
        Self {
            in_use: false,
            id: 0,
            proc_addr: 0,
            ref_data: 0,
        }
    }
}

// ============================================================================
// Subclassed Window
// ============================================================================

/// Subclassed window state
#[derive(Clone)]
pub struct SubclassedWindow {
    /// Is this slot in use
    pub in_use: bool,
    /// Window handle
    pub hwnd: HWND,
    /// Original window procedure
    pub original_proc: usize,
    /// Subclass entries
    pub entries: [SubclassEntry; MAX_SUBCLASS_PER_WINDOW],
    /// Entry count
    pub entry_count: usize,
    /// Currently processing (prevents recursion issues)
    pub processing: bool,
    /// Current processing index
    pub current_index: usize,
}

impl SubclassedWindow {
    /// Create empty subclassed window
    pub const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: UserHandle::NULL,
            original_proc: 0,
            entries: [const { SubclassEntry::new() }; MAX_SUBCLASS_PER_WINDOW],
            entry_count: 0,
            processing: false,
            current_index: 0,
        }
    }

    /// Reset state
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Find entry by ID
    pub fn find_entry(&self, id: usize) -> Option<usize> {
        for i in 0..self.entry_count {
            if self.entries[i].in_use && self.entries[i].id == id {
                return Some(i);
            }
        }
        None
    }

    /// Add subclass entry
    pub fn add_subclass(&mut self, id: usize, proc_addr: usize, ref_data: usize) -> bool {
        // Check if already exists
        if let Some(idx) = self.find_entry(id) {
            // Update existing
            self.entries[idx].proc_addr = proc_addr;
            self.entries[idx].ref_data = ref_data;
            return true;
        }

        // Add new entry
        if self.entry_count >= MAX_SUBCLASS_PER_WINDOW {
            return false;
        }

        // Find free slot
        for i in 0..MAX_SUBCLASS_PER_WINDOW {
            if !self.entries[i].in_use {
                self.entries[i].in_use = true;
                self.entries[i].id = id;
                self.entries[i].proc_addr = proc_addr;
                self.entries[i].ref_data = ref_data;
                self.entry_count += 1;
                return true;
            }
        }

        false
    }

    /// Remove subclass entry
    pub fn remove_subclass(&mut self, id: usize) -> bool {
        if let Some(idx) = self.find_entry(id) {
            self.entries[idx].in_use = false;
            self.entry_count -= 1;
            return true;
        }
        false
    }

    /// Get subclass ref data
    pub fn get_ref_data(&self, id: usize) -> Option<usize> {
        if let Some(idx) = self.find_entry(id) {
            return Some(self.entries[idx].ref_data);
        }
        None
    }

    /// Set subclass ref data
    pub fn set_ref_data(&mut self, id: usize, ref_data: usize) -> bool {
        if let Some(idx) = self.find_entry(id) {
            self.entries[idx].ref_data = ref_data;
            return true;
        }
        false
    }

    /// Call next subclass in chain
    pub fn call_next(&mut self, msg: u32, wparam: usize, lparam: isize) -> isize {
        // Find next active entry
        while self.current_index > 0 {
            self.current_index -= 1;
            if self.entries[self.current_index].in_use {
                let entry = &self.entries[self.current_index];
                let _proc_addr = entry.proc_addr;
                let _id = entry.id;
                let _ref_data = entry.ref_data;

                // In a real implementation, we would call the procedure here
                // For now, return 0 to simulate default handling
                return 0;
            }
        }

        // Call original window procedure
        // In a real implementation, this would call the original proc
        let _ = (msg, wparam, lparam);
        0
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global subclassed window storage
static SUBCLASSED_WINDOWS: SpinLock<[SubclassedWindow; MAX_SUBCLASSED_WINDOWS]> =
    SpinLock::new([const { SubclassedWindow::new() }; MAX_SUBCLASSED_WINDOWS]);

// ============================================================================
// Internal Functions
// ============================================================================

/// Find or create subclassed window entry
fn find_or_create_window(hwnd: HWND) -> Option<usize> {
    let mut windows = SUBCLASSED_WINDOWS.lock();

    // First, try to find existing
    for (i, win) in windows.iter().enumerate() {
        if win.in_use && win.hwnd == hwnd {
            return Some(i);
        }
    }

    // Create new entry
    for (i, win) in windows.iter_mut().enumerate() {
        if !win.in_use {
            win.reset();
            win.in_use = true;
            win.hwnd = hwnd;
            return Some(i);
        }
    }

    None
}

/// Find subclassed window
fn find_window(hwnd: HWND) -> Option<usize> {
    let windows = SUBCLASSED_WINDOWS.lock();

    for (i, win) in windows.iter().enumerate() {
        if win.in_use && win.hwnd == hwnd {
            return Some(i);
        }
    }

    None
}

// ============================================================================
// Public API
// ============================================================================

/// Initialize subclass subsystem
pub fn init() {
    crate::serial_println!("[USER] Subclass helpers initialized");
}

/// Set window subclass
pub fn set_window_subclass(
    hwnd: HWND,
    subclass_proc: usize,
    id: usize,
    ref_data: usize,
) -> bool {
    let idx = match find_or_create_window(hwnd) {
        Some(i) => i,
        None => return false,
    };

    let mut windows = SUBCLASSED_WINDOWS.lock();
    windows[idx].add_subclass(id, subclass_proc, ref_data)
}

/// Get window subclass
pub fn get_window_subclass(
    hwnd: HWND,
    _subclass_proc: usize,
    id: usize,
) -> Option<usize> {
    let idx = find_window(hwnd)?;
    let windows = SUBCLASSED_WINDOWS.lock();
    windows[idx].get_ref_data(id)
}

/// Remove window subclass
pub fn remove_window_subclass(
    hwnd: HWND,
    _subclass_proc: usize,
    id: usize,
) -> bool {
    let idx = match find_window(hwnd) {
        Some(i) => i,
        None => return false,
    };

    let mut windows = SUBCLASSED_WINDOWS.lock();
    let result = windows[idx].remove_subclass(id);

    // Clean up if no more subclasses
    if windows[idx].entry_count == 0 {
        windows[idx].reset();
    }

    result
}

/// Call default subclass procedure
pub fn def_subclass_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    let idx = match find_window(hwnd) {
        Some(i) => i,
        None => return 0,
    };

    let mut windows = SUBCLASSED_WINDOWS.lock();
    windows[idx].call_next(msg, wparam, lparam)
}

/// Check if window is subclassed
pub fn is_subclassed(hwnd: HWND) -> bool {
    find_window(hwnd).is_some()
}

/// Get subclass count for window
pub fn get_subclass_count(hwnd: HWND) -> usize {
    let idx = match find_window(hwnd) {
        Some(i) => i,
        None => return 0,
    };

    let windows = SUBCLASSED_WINDOWS.lock();
    windows[idx].entry_count
}

/// Remove all subclasses for window
pub fn remove_all_subclasses(hwnd: HWND) -> bool {
    let idx = match find_window(hwnd) {
        Some(i) => i,
        None => return false,
    };

    let mut windows = SUBCLASSED_WINDOWS.lock();
    windows[idx].reset();
    true
}

/// Get statistics
pub fn get_stats() -> SubclassStats {
    let windows = SUBCLASSED_WINDOWS.lock();

    let mut window_count = 0;
    let mut total_subclasses = 0;

    for win in windows.iter() {
        if win.in_use {
            window_count += 1;
            total_subclasses += win.entry_count;
        }
    }

    SubclassStats {
        max_windows: MAX_SUBCLASSED_WINDOWS,
        subclassed_windows: window_count,
        total_subclasses,
    }
}

/// Subclass statistics
#[derive(Debug, Clone, Copy)]
pub struct SubclassStats {
    pub max_windows: usize,
    pub subclassed_windows: usize,
    pub total_subclasses: usize,
}
