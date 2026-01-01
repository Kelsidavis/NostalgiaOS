//! Notification Area (System Tray) Implementation
//!
//! Windows notification area icon support.
//! Based on Windows Server 2003 shell32.h.
//!
//! # Features
//!
//! - Notification icons
//! - Balloon tooltips
//! - Icon callbacks
//!
//! # References
//!
//! - `public/sdk/inc/shellapi.h` - Shell_NotifyIcon

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, Rect};
use super::icon::HICON;

// ============================================================================
// Notify Icon Message (NIM_*)
// ============================================================================

/// Add icon
pub const NIM_ADD: u32 = 0x00000000;

/// Modify icon
pub const NIM_MODIFY: u32 = 0x00000001;

/// Delete icon
pub const NIM_DELETE: u32 = 0x00000002;

/// Set focus
pub const NIM_SETFOCUS: u32 = 0x00000003;

/// Set version
pub const NIM_SETVERSION: u32 = 0x00000004;

// ============================================================================
// Notify Icon Flags (NIF_*)
// ============================================================================

/// Message callback
pub const NIF_MESSAGE: u32 = 0x00000001;

/// Icon
pub const NIF_ICON: u32 = 0x00000002;

/// Tip text
pub const NIF_TIP: u32 = 0x00000004;

/// State
pub const NIF_STATE: u32 = 0x00000008;

/// Info balloon
pub const NIF_INFO: u32 = 0x00000010;

/// GUID
pub const NIF_GUID: u32 = 0x00000020;

/// Realtime
pub const NIF_REALTIME: u32 = 0x00000040;

/// Showtip
pub const NIF_SHOWTIP: u32 = 0x00000080;

// ============================================================================
// Notify Icon State (NIS_*)
// ============================================================================

/// Hidden
pub const NIS_HIDDEN: u32 = 0x00000001;

/// Shared icon
pub const NIS_SHAREDICON: u32 = 0x00000002;

// ============================================================================
// Notify Icon Info Flags (NIIF_*)
// ============================================================================

/// No icon
pub const NIIF_NONE: u32 = 0x00000000;

/// Info icon
pub const NIIF_INFO: u32 = 0x00000001;

/// Warning icon
pub const NIIF_WARNING: u32 = 0x00000002;

/// Error icon
pub const NIIF_ERROR: u32 = 0x00000003;

/// User icon
pub const NIIF_USER: u32 = 0x00000004;

/// Icon mask
pub const NIIF_ICON_MASK: u32 = 0x0000000F;

/// No sound
pub const NIIF_NOSOUND: u32 = 0x00000010;

/// Large icon
pub const NIIF_LARGE_ICON: u32 = 0x00000020;

/// Respect quiet time
pub const NIIF_RESPECT_QUIET_TIME: u32 = 0x00000080;

// ============================================================================
// Notification Callbacks
// ============================================================================

/// Mouse messages for notification icons
pub const NIN_SELECT: u32 = 0x0400; // WM_USER + 0
pub const NIN_KEYSELECT: u32 = 0x0401;
pub const NIN_BALLOONSHOW: u32 = 0x0402;
pub const NIN_BALLOONHIDE: u32 = 0x0403;
pub const NIN_BALLOONTIMEOUT: u32 = 0x0404;
pub const NIN_BALLOONUSERCLICK: u32 = 0x0405;
pub const NIN_POPUPOPEN: u32 = 0x0406;
pub const NIN_POPUPCLOSE: u32 = 0x0407;

// ============================================================================
// Constants
// ============================================================================

/// Maximum tooltip length
pub const MAX_TIP_LEN: usize = 128;

/// Maximum info text length
pub const MAX_INFO_LEN: usize = 256;

/// Maximum info title length
pub const MAX_INFO_TITLE_LEN: usize = 64;

/// Maximum notification icons
pub const MAX_NOTIFY_ICONS: usize = 32;

/// Default balloon timeout (ms)
pub const DEFAULT_BALLOON_TIMEOUT: u32 = 5000;

// ============================================================================
// Notify Icon Data
// ============================================================================

/// Notify icon data
#[derive(Clone)]
pub struct NotifyIconData {
    /// Structure size
    pub cb_size: u32,
    /// Window handle
    pub hwnd: HWND,
    /// Icon ID
    pub id: u32,
    /// Flags
    pub flags: u32,
    /// Callback message
    pub callback_message: u32,
    /// Icon handle
    pub icon: HICON,
    /// Tooltip text
    pub tip: [u8; MAX_TIP_LEN],
    /// State
    pub state: u32,
    /// State mask
    pub state_mask: u32,
    /// Info text
    pub info: [u8; MAX_INFO_LEN],
    /// Balloon timeout
    pub timeout: u32,
    /// Info title
    pub info_title: [u8; MAX_INFO_TITLE_LEN],
    /// Info flags
    pub info_flags: u32,
    /// Balloon icon
    pub balloon_icon: HICON,
}

impl NotifyIconData {
    /// Create empty data
    pub const fn new() -> Self {
        Self {
            cb_size: 0,
            hwnd: UserHandle::NULL,
            id: 0,
            flags: 0,
            callback_message: 0,
            icon: UserHandle::NULL,
            tip: [0; MAX_TIP_LEN],
            state: 0,
            state_mask: 0,
            info: [0; MAX_INFO_LEN],
            timeout: DEFAULT_BALLOON_TIMEOUT,
            info_title: [0; MAX_INFO_TITLE_LEN],
            info_flags: NIIF_NONE,
            balloon_icon: UserHandle::NULL,
        }
    }
}

// ============================================================================
// Internal State
// ============================================================================

/// Notification icon entry
#[derive(Clone)]
struct NotifyIconEntry {
    /// Is this slot in use
    in_use: bool,
    /// Icon data
    data: NotifyIconData,
    /// Is visible
    visible: bool,
    /// Balloon showing
    balloon_showing: bool,
    /// Balloon show time
    balloon_start_time: u64,
}

impl NotifyIconEntry {
    const fn new() -> Self {
        Self {
            in_use: false,
            data: NotifyIconData::new(),
            visible: true,
            balloon_showing: false,
            balloon_start_time: 0,
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Global notification icon storage
static NOTIFY_ICONS: SpinLock<[NotifyIconEntry; MAX_NOTIFY_ICONS]> =
    SpinLock::new([const { NotifyIconEntry::new() }; MAX_NOTIFY_ICONS]);

// ============================================================================
// Internal Functions
// ============================================================================

/// Find icon by hwnd and id
fn find_icon(hwnd: HWND, id: u32) -> Option<usize> {
    let icons = NOTIFY_ICONS.lock();

    for (i, entry) in icons.iter().enumerate() {
        if entry.in_use && entry.data.hwnd == hwnd && entry.data.id == id {
            return Some(i);
        }
    }

    None
}

/// Find free slot
fn find_free_slot() -> Option<usize> {
    let icons = NOTIFY_ICONS.lock();

    for (i, entry) in icons.iter().enumerate() {
        if !entry.in_use {
            return Some(i);
        }
    }

    None
}

// ============================================================================
// Public API
// ============================================================================

/// Initialize notification area
pub fn init() {
    crate::serial_println!("[USER] Notification area initialized");
}

/// Add, modify, or delete a notification icon
pub fn shell_notify_icon(message: u32, data: &NotifyIconData) -> bool {
    match message {
        NIM_ADD => {
            // Check if already exists
            if find_icon(data.hwnd, data.id).is_some() {
                return false;
            }

            // Find free slot
            let slot = match find_free_slot() {
                Some(s) => s,
                None => return false,
            };

            let mut icons = NOTIFY_ICONS.lock();
            icons[slot].reset();
            icons[slot].in_use = true;
            icons[slot].data = data.clone();

            // Check visibility state
            icons[slot].visible = (data.state & NIS_HIDDEN) == 0;

            true
        }

        NIM_MODIFY => {
            let slot = match find_icon(data.hwnd, data.id) {
                Some(s) => s,
                None => return false,
            };

            let mut icons = NOTIFY_ICONS.lock();
            let entry = &mut icons[slot];

            // Update based on flags
            if (data.flags & NIF_MESSAGE) != 0 {
                entry.data.callback_message = data.callback_message;
            }

            if (data.flags & NIF_ICON) != 0 {
                entry.data.icon = data.icon;
            }

            if (data.flags & NIF_TIP) != 0 {
                entry.data.tip = data.tip;
            }

            if (data.flags & NIF_STATE) != 0 {
                let mask = data.state_mask;
                entry.data.state = (entry.data.state & !mask) | (data.state & mask);
                entry.visible = (entry.data.state & NIS_HIDDEN) == 0;
            }

            if (data.flags & NIF_INFO) != 0 {
                entry.data.info = data.info;
                entry.data.info_title = data.info_title;
                entry.data.info_flags = data.info_flags;
                entry.data.timeout = data.timeout;

                // Show balloon if there's info text
                if data.info[0] != 0 {
                    entry.balloon_showing = true;
                    entry.balloon_start_time = 0; // Would use actual time
                }
            }

            true
        }

        NIM_DELETE => {
            let slot = match find_icon(data.hwnd, data.id) {
                Some(s) => s,
                None => return false,
            };

            let mut icons = NOTIFY_ICONS.lock();
            icons[slot].reset();

            true
        }

        NIM_SETFOCUS => {
            // Set keyboard focus to notification area
            find_icon(data.hwnd, data.id).is_some()
        }

        NIM_SETVERSION => {
            // Set icon behavior version
            find_icon(data.hwnd, data.id).is_some()
        }

        _ => false,
    }
}

/// Get notification icon by index
pub fn get_icon_by_index(index: usize) -> Option<NotifyIconData> {
    let icons = NOTIFY_ICONS.lock();

    if index < MAX_NOTIFY_ICONS && icons[index].in_use {
        Some(icons[index].data.clone())
    } else {
        None
    }
}

/// Get visible icon count
pub fn get_visible_icon_count() -> usize {
    let icons = NOTIFY_ICONS.lock();
    let mut count = 0;

    for entry in icons.iter() {
        if entry.in_use && entry.visible {
            count += 1;
        }
    }

    count
}

/// Get total icon count
pub fn get_icon_count() -> usize {
    let icons = NOTIFY_ICONS.lock();
    let mut count = 0;

    for entry in icons.iter() {
        if entry.in_use {
            count += 1;
        }
    }

    count
}

/// Process balloon timeouts
pub fn process_balloon_timeouts(current_time: u64) {
    let mut icons = NOTIFY_ICONS.lock();

    for entry in icons.iter_mut() {
        if entry.in_use && entry.balloon_showing {
            let elapsed = current_time.saturating_sub(entry.balloon_start_time);
            if elapsed >= entry.data.timeout as u64 {
                entry.balloon_showing = false;
                // Would send NIN_BALLOONTIMEOUT message here
            }
        }
    }
}

/// Hide balloon for icon
pub fn hide_balloon(hwnd: HWND, id: u32) -> bool {
    let slot = match find_icon(hwnd, id) {
        Some(s) => s,
        None => return false,
    };

    let mut icons = NOTIFY_ICONS.lock();
    icons[slot].balloon_showing = false;

    true
}

/// Check if balloon is showing
pub fn is_balloon_showing(hwnd: HWND, id: u32) -> bool {
    let slot = match find_icon(hwnd, id) {
        Some(s) => s,
        None => return false,
    };

    let icons = NOTIFY_ICONS.lock();
    icons[slot].balloon_showing
}

/// Get notification area bounds (for drawing)
pub fn get_tray_bounds() -> Rect {
    // Return a default taskbar notification area rect
    // In a real implementation, this would query the taskbar
    Rect {
        left: 0,
        top: 0,
        right: 400,
        bottom: 30,
    }
}

/// Hit test in notification area
pub fn hit_test(x: i32, y: i32) -> Option<(HWND, u32)> {
    let icons = NOTIFY_ICONS.lock();
    let icon_width = 16;
    let icon_spacing = 2;
    let mut current_x = 0;

    for entry in icons.iter() {
        if entry.in_use && entry.visible {
            if x >= current_x && x < current_x + icon_width && y >= 0 && y < 16 {
                return Some((entry.data.hwnd, entry.data.id));
            }
            current_x += icon_width + icon_spacing;
        }
    }

    None
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> NotifyStats {
    let icons = NOTIFY_ICONS.lock();

    let mut total = 0;
    let mut visible = 0;
    let mut balloons = 0;

    for entry in icons.iter() {
        if entry.in_use {
            total += 1;
            if entry.visible {
                visible += 1;
            }
            if entry.balloon_showing {
                balloons += 1;
            }
        }
    }

    NotifyStats {
        max_icons: MAX_NOTIFY_ICONS,
        total_icons: total,
        visible_icons: visible,
        active_balloons: balloons,
    }
}

/// Notification area statistics
#[derive(Debug, Clone, Copy)]
pub struct NotifyStats {
    pub max_icons: usize,
    pub total_icons: usize,
    pub visible_icons: usize,
    pub active_balloons: usize,
}
