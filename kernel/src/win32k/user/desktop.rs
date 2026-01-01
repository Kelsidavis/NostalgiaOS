//! Desktop and Window Station
//!
//! Desktops are the root of the window hierarchy. Each window station
//! can have multiple desktops (e.g., Default, Winlogon, Screensaver).
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/winsta.c`

use crate::ke::spinlock::SpinLock;
use super::super::{Rect, ColorRef};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of desktops
pub const MAX_DESKTOPS: usize = 8;

/// Desktop names
pub const DESKTOP_DEFAULT: &str = "Default";
pub const DESKTOP_WINLOGON: &str = "Winlogon";

// ============================================================================
// Desktop Structure
// ============================================================================

/// Desktop object
#[derive(Debug, Clone)]
pub struct Desktop {
    /// Desktop name
    pub name: [u8; 32],

    /// Name length
    pub name_len: usize,

    /// Desktop dimensions
    pub rect: Rect,

    /// Background color
    pub background_color: ColorRef,

    /// Desktop is active
    pub active: bool,

    /// Desktop is visible
    pub visible: bool,

    /// Valid flag
    pub valid: bool,
}

impl Default for Desktop {
    fn default() -> Self {
        Self {
            name: [0; 32],
            name_len: 0,
            rect: Rect::new(0, 0, 0, 0),
            background_color: ColorRef::DESKTOP,
            active: false,
            visible: false,
            valid: false,
        }
    }
}

impl Desktop {
    /// Get desktop name as string
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }
}

// ============================================================================
// Desktop Table
// ============================================================================

struct DesktopEntry {
    desktop: Option<Desktop>,
}

impl Default for DesktopEntry {
    fn default() -> Self {
        Self { desktop: None }
    }
}

static DESKTOP_TABLE: SpinLock<DesktopTable> = SpinLock::new(DesktopTable::new());
static CURRENT_DESKTOP: SpinLock<usize> = SpinLock::new(0);

struct DesktopTable {
    entries: [DesktopEntry; MAX_DESKTOPS],
}

impl DesktopTable {
    const fn new() -> Self {
        const EMPTY: DesktopEntry = DesktopEntry { desktop: None };
        Self {
            entries: [EMPTY; MAX_DESKTOPS],
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize desktop system
pub fn init() {
    // Get screen dimensions
    let (width, height) = super::super::gdi::surface::get_primary_dimensions();

    // Create default desktop
    create_desktop(DESKTOP_DEFAULT, width as i32, height as i32);

    // Create winlogon desktop
    create_desktop(DESKTOP_WINLOGON, width as i32, height as i32);

    // Switch to default desktop
    switch_desktop(0);

    crate::serial_println!("[USER/Desktop] Desktop system initialized ({}x{})",
        width, height);
}

/// Create a desktop
fn create_desktop(name: &str, width: i32, height: i32) -> Option<usize> {
    let mut table = DESKTOP_TABLE.lock();

    // Find empty slot
    for (i, entry) in table.entries.iter_mut().enumerate() {
        if entry.desktop.is_none() {
            let mut desktop = Desktop::default();
            desktop.rect = Rect::new(0, 0, width, height);
            desktop.valid = true;

            // Copy name
            desktop.name_len = name.len().min(31);
            for (j, &b) in name.as_bytes().iter().take(desktop.name_len).enumerate() {
                desktop.name[j] = b;
            }

            entry.desktop = Some(desktop);
            return Some(i);
        }
    }

    None
}

/// Switch to a desktop
pub fn switch_desktop(index: usize) -> bool {
    let mut table = DESKTOP_TABLE.lock();

    if index >= MAX_DESKTOPS {
        return false;
    }

    // Deactivate current desktop
    let current = *CURRENT_DESKTOP.lock();
    if let Some(ref mut desktop) = table.entries[current].desktop {
        desktop.active = false;
        desktop.visible = false;
    }

    // Activate new desktop
    if let Some(ref mut desktop) = table.entries[index].desktop {
        desktop.active = true;
        desktop.visible = true;
        *CURRENT_DESKTOP.lock() = index;
        return true;
    }

    false
}

/// Get current desktop index
pub fn get_current_desktop() -> usize {
    *CURRENT_DESKTOP.lock()
}

/// Get desktop dimensions
pub fn get_desktop_rect() -> Rect {
    let table = DESKTOP_TABLE.lock();
    let current = *CURRENT_DESKTOP.lock();

    table.entries[current]
        .desktop
        .as_ref()
        .map(|d| d.rect)
        .unwrap_or(Rect::new(0, 0, 800, 600))
}

/// Get desktop background color
pub fn get_desktop_color() -> ColorRef {
    let table = DESKTOP_TABLE.lock();
    let current = *CURRENT_DESKTOP.lock();

    table.entries[current]
        .desktop
        .as_ref()
        .map(|d| d.background_color)
        .unwrap_or(ColorRef::DESKTOP)
}

/// Set desktop background color
pub fn set_desktop_color(color: ColorRef) {
    let mut table = DESKTOP_TABLE.lock();
    let current = *CURRENT_DESKTOP.lock();

    if let Some(ref mut desktop) = table.entries[current].desktop {
        desktop.background_color = color;
    }
}

/// Enumerate desktops
pub fn enumerate_desktops() -> [(bool, [u8; 32], usize); MAX_DESKTOPS] {
    let table = DESKTOP_TABLE.lock();
    let mut result = [(false, [0u8; 32], 0); MAX_DESKTOPS];

    for (i, entry) in table.entries.iter().enumerate() {
        if let Some(ref desktop) = entry.desktop {
            result[i] = (true, desktop.name, desktop.name_len);
        }
    }

    result
}
