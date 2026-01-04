//! Task Band (Taskbar Window Buttons)
//!
//! This module implements CTaskBand - the toolbar containing buttons
//! for each open window.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/explorer/taskband.cpp`
//! - `shell/explorer/taskband.h`

use crate::ke::spinlock::SpinLock;
use super::super::super::{HWND, HDC, Rect, ColorRef};
use super::super::super::gdi::dc;
use super::super::{message, window, input, controls};
use super::tray::{TASKBAR_HEIGHT, START_BUTTON_WIDTH};
use super::traynot;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of task buttons
const MAX_TASK_ITEMS: usize = 32;

/// Minimum button width
const MIN_BUTTON_WIDTH: i32 = 60;

/// Maximum button width
const MAX_BUTTON_WIDTH: i32 = 160;

// ============================================================================
// Task Item Structure
// ============================================================================

/// Task item - represents a window button on the taskbar
#[derive(Debug, Clone, Copy)]
struct TaskItem {
    /// Item is valid/active
    valid: bool,
    /// Window handle
    hwnd: HWND,
    /// Button rectangle (relative to taskbar)
    rect: Rect,
    /// Window flags
    flags: u32,
}

impl TaskItem {
    const fn empty() -> Self {
        Self {
            valid: false,
            hwnd: HWND::NULL,
            rect: Rect::new(0, 0, 0, 0),
            flags: 0,
        }
    }
}

// ============================================================================
// Task Band State (CTaskBand equivalent)
// ============================================================================

/// CTaskBand state
struct CTaskBand {
    /// Task items array
    items: [TaskItem; MAX_TASK_ITEMS],
    /// Number of valid items
    count: usize,
    /// Available width for buttons
    available_width: i32,
}

impl CTaskBand {
    const fn new() -> Self {
        Self {
            items: [const { TaskItem::empty() }; MAX_TASK_ITEMS],
            count: 0,
            available_width: 0,
        }
    }
}

static TASK_BAND: SpinLock<CTaskBand> = SpinLock::new(CTaskBand::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the task band
pub fn init(screen_width: i32) {
    let mut band = TASK_BAND.lock();
    // Calculate available width: total width - start button - systray/clock
    band.available_width = screen_width - START_BUTTON_WIDTH - 10 - traynot::get_width() - 10;
}

// ============================================================================
// Task Management
// ============================================================================

/// Add a task (window) to the taskbar
pub fn add_task(hwnd: HWND) {
    let mut band = TASK_BAND.lock();

    // Check if already exists
    for item in band.items.iter() {
        if item.valid && item.hwnd == hwnd {
            return;
        }
    }

    // Find empty slot
    for item in band.items.iter_mut() {
        if !item.valid {
            item.valid = true;
            item.hwnd = hwnd;
            item.flags = 0;
            band.count += 1;
            break;
        }
    }

    // Recalculate button positions
    drop(band);
    recalculate_layout();
}

/// Remove a task from the taskbar
pub fn remove_task(hwnd: HWND) {
    let mut band = TASK_BAND.lock();

    for item in band.items.iter_mut() {
        if item.valid && item.hwnd == hwnd {
            item.valid = false;
            item.hwnd = HWND::NULL;
            band.count = band.count.saturating_sub(1);
            break;
        }
    }

    drop(band);
    recalculate_layout();
}

/// Recalculate button layout after add/remove
fn recalculate_layout() {
    let mut band = TASK_BAND.lock();

    if band.count == 0 {
        return;
    }

    // Calculate button width
    let total_width = band.available_width;
    let mut button_width = total_width / band.count as i32;
    button_width = button_width.clamp(MIN_BUTTON_WIDTH, MAX_BUTTON_WIDTH);

    // Position buttons
    let mut x = START_BUTTON_WIDTH + 10;
    for item in band.items.iter_mut() {
        if item.valid {
            item.rect = Rect::new(x, 4, x + button_width - 2, TASKBAR_HEIGHT - 4);
            x += button_width;
        }
    }
}

// ============================================================================
// Click Handling
// ============================================================================

/// Handle click on task band area
pub fn handle_click(x: i32, _y: i32) {
    let band = TASK_BAND.lock();

    for item in band.items.iter() {
        if !item.valid {
            continue;
        }

        if x >= item.rect.left && x < item.rect.right {
            let hwnd = item.hwnd;
            drop(band);

            // Check if this window is already active
            let is_active = input::get_active_window() == hwnd;
            let is_minimized = window::get_window(hwnd)
                .map(|w| w.minimized)
                .unwrap_or(false);

            if is_active && !is_minimized {
                // Already active and visible - minimize it
                message::send_message(hwnd, message::WM_SYSCOMMAND, message::syscmd::SC_MINIMIZE, 0);
            } else {
                // Restore and activate
                if is_minimized {
                    message::send_message(hwnd, message::WM_SYSCOMMAND, message::syscmd::SC_RESTORE, 0);
                }
                window::set_foreground_window(hwnd);
                input::set_active_window(hwnd);
            }

            super::paint_taskbar();
            return;
        }
    }
}

// ============================================================================
// Painting
// ============================================================================

/// Paint the task band
pub fn paint(hdc: HDC, taskbar_y: i32) {
    let band = TASK_BAND.lock();
    let active_hwnd = input::get_active_window();

    for item in band.items.iter() {
        if !item.valid {
            continue;
        }

        // Adjust rect for actual taskbar position
        let mut btn_rect = item.rect;
        btn_rect.top += taskbar_y;
        btn_rect.bottom += taskbar_y;

        // Get window title into local buffer
        let mut title_buf = [0u8; 64];
        let title_len = if let Some(wnd) = window::get_window(item.hwnd) {
            let len = wnd.title_len.min(title_buf.len());
            title_buf[..len].copy_from_slice(&wnd.title[..len]);
            len
        } else {
            let default = b"Window";
            title_buf[..default.len()].copy_from_slice(default);
            default.len()
        };
        let title_str = core::str::from_utf8(&title_buf[..title_len]).unwrap_or("Window");

        // Truncate title to fit button
        let max_chars = ((btn_rect.right - btn_rect.left) / 7) as usize;
        let display_title: &str = if title_str.len() > max_chars {
            &title_str[..max_chars.saturating_sub(2)]
        } else {
            title_str
        };

        // Determine button state
        let is_active = item.hwnd == active_hwnd;
        let state = if is_active {
            controls::ButtonState::Pressed
        } else {
            controls::ButtonState::Normal
        };

        controls::draw_button(
            hdc,
            &btn_rect,
            display_title,
            state,
            controls::ButtonStyle::PushButton,
        );
    }
}

/// Get task band button count
pub fn get_count() -> usize {
    TASK_BAND.lock().count
}
