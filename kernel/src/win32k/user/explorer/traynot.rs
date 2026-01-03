//! Tray Notification Area (System Tray)
//!
//! This module implements CTrayNotify - the notification area containing
//! system tray icons and the clock.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/explorer/traynot.cpp`
//! - `shell/explorer/traynot.h`
//! - `shell/explorer/trayclok.cpp`

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::super::{HWND, HDC, Rect, ColorRef};
use super::super::super::gdi::{dc, brush};
use super::super::controls;
use super::tray::TASKBAR_HEIGHT;

// ============================================================================
// Constants
// ============================================================================

/// Clock width
const CLOCK_WIDTH: i32 = 55;

/// System tray icon area width
const SYSTRAY_WIDTH: i32 = 20;

/// Total notification area width
const NOTIFY_WIDTH: i32 = CLOCK_WIDTH + SYSTRAY_WIDTH;

/// Date tooltip visible flag
static DATE_TOOLTIP_VISIBLE: AtomicBool = AtomicBool::new(false);

/// Last displayed time (to avoid redundant updates)
static LAST_DISPLAYED_TIME: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Notify Area State (CTrayNotify equivalent)
// ============================================================================

/// CTrayNotify state
struct CTrayNotify {
    /// Clock rectangle
    clock_rect: Rect,
    /// System tray rectangle
    systray_rect: Rect,
    /// Screen width for positioning
    screen_width: i32,
}

impl CTrayNotify {
    const fn new() -> Self {
        Self {
            clock_rect: Rect::new(0, 0, 0, 0),
            systray_rect: Rect::new(0, 0, 0, 0),
            screen_width: 0,
        }
    }
}

static TRAY_NOTIFY: SpinLock<CTrayNotify> = SpinLock::new(CTrayNotify::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the notification area
pub fn init(screen_width: i32) {
    let mut notify = TRAY_NOTIFY.lock();
    notify.screen_width = screen_width;

    // Position clock at right edge
    let clock_x = screen_width - CLOCK_WIDTH - 4;
    notify.clock_rect = Rect::new(clock_x, 4, clock_x + CLOCK_WIDTH, TASKBAR_HEIGHT - 4);

    // Position systray to left of clock
    let systray_x = clock_x - SYSTRAY_WIDTH - 2;
    notify.systray_rect = Rect::new(systray_x, 4, systray_x + SYSTRAY_WIDTH, TASKBAR_HEIGHT - 4);
}

/// Get the total width of the notification area
pub fn get_width() -> i32 {
    NOTIFY_WIDTH
}

// ============================================================================
// Clock Functions
// ============================================================================

/// Update the clock display (called periodically)
pub fn update_clock() {
    let current_time = crate::hal::rtc::get_system_time() as u32;

    // Only update if time changed (check every ~minute worth of ticks)
    let last_time = LAST_DISPLAYED_TIME.load(Ordering::Relaxed);
    if current_time / 60 != last_time / 60 {
        LAST_DISPLAYED_TIME.store(current_time, Ordering::Relaxed);
        paint_clock_only();
    }
}

/// Paint just the clock (for updates)
fn paint_clock_only() {
    if let Ok(hdc) = dc::create_display_dc() {
        let (_, height) = super::super::super::gdi::surface::get_primary_dimensions();
        let taskbar_y = height as i32 - TASKBAR_HEIGHT;
        paint_clock(hdc, taskbar_y);
        dc::delete_dc(hdc);
    }
}

/// Get current time string
fn get_time_string() -> [u8; 8] {
    let time = crate::hal::rtc::read_datetime();
    let mut buf = [0u8; 8];

    // Format as HH:MM AM/PM
    let hour_12 = if time.hour == 0 {
        12
    } else if time.hour > 12 {
        time.hour - 12
    } else {
        time.hour
    };

    let am_pm = if time.hour < 12 { b'A' } else { b'P' };

    buf[0] = b'0' + (hour_12 / 10);
    buf[1] = b'0' + (hour_12 % 10);
    buf[2] = b':';
    buf[3] = b'0' + (time.minute / 10);
    buf[4] = b'0' + (time.minute % 10);
    buf[5] = b' ';
    buf[6] = am_pm;
    buf[7] = b'M';

    buf
}

/// Get current date string
fn get_date_string() -> ([u8; 32], usize) {
    let time = crate::hal::rtc::read_datetime();
    let mut buf = [0u8; 32];
    let mut len = 0;

    // Day of week
    let dow = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
    let day_name = dow.get(time.day_of_week as usize).unwrap_or(&"Unknown");
    for c in day_name.bytes() {
        buf[len] = c;
        len += 1;
    }
    buf[len] = b',';
    len += 1;
    buf[len] = b' ';
    len += 1;

    // Month
    let months = ["", "January", "February", "March", "April", "May", "June",
                  "July", "August", "September", "October", "November", "December"];
    let month_name = months.get(time.month as usize).unwrap_or(&"Unknown");
    for c in month_name.bytes() {
        buf[len] = c;
        len += 1;
    }
    buf[len] = b' ';
    len += 1;

    // Day
    if time.day >= 10 {
        buf[len] = b'0' + (time.day / 10);
        len += 1;
    }
    buf[len] = b'0' + (time.day % 10);
    len += 1;
    buf[len] = b',';
    len += 1;
    buf[len] = b' ';
    len += 1;

    // Year
    let year = time.year as u32;
    buf[len] = b'0' + ((year / 1000) % 10) as u8;
    len += 1;
    buf[len] = b'0' + ((year / 100) % 10) as u8;
    len += 1;
    buf[len] = b'0' + ((year / 10) % 10) as u8;
    len += 1;
    buf[len] = b'0' + (year % 10) as u8;
    len += 1;

    (buf, len)
}

// ============================================================================
// Date Tooltip
// ============================================================================

/// Show the date tooltip (when clicking on clock)
pub fn show_date_tooltip() {
    DATE_TOOLTIP_VISIBLE.store(true, Ordering::SeqCst);

    if let Ok(hdc) = dc::create_display_dc() {
        let (width, height) = super::super::super::gdi::surface::get_primary_dimensions();
        let taskbar_y = height as i32 - TASKBAR_HEIGHT;

        // Get date string
        let (date_buf, date_len) = get_date_string();
        let date_str = core::str::from_utf8(&date_buf[..date_len]).unwrap_or("Unknown");

        // Calculate tooltip size based on text length
        let tooltip_width = (date_len as i32 * 7) + 16;
        let tooltip_height = 24;

        // Position tooltip above the clock
        let tooltip_x = width as i32 - tooltip_width - 10;
        let tooltip_y = taskbar_y - tooltip_height - 4;

        let tooltip_rect = Rect::new(
            tooltip_x,
            tooltip_y,
            tooltip_x + tooltip_width,
            tooltip_y + tooltip_height,
        );

        // Draw tooltip background (cream/yellow)
        if let Some(surf) = super::super::super::gdi::surface::get_surface(dc::get_dc_surface(hdc)) {
            surf.fill_rect(&tooltip_rect, ColorRef::rgb(255, 255, 225));

            // Draw border
            surf.hline(tooltip_rect.left, tooltip_rect.right, tooltip_rect.top, ColorRef::BLACK);
            surf.hline(tooltip_rect.left, tooltip_rect.right, tooltip_rect.bottom - 1, ColorRef::BLACK);
            surf.vline(tooltip_rect.left, tooltip_rect.top, tooltip_rect.bottom, ColorRef::BLACK);
            surf.vline(tooltip_rect.right - 1, tooltip_rect.top, tooltip_rect.bottom, ColorRef::BLACK);
        }

        // Draw date text
        dc::set_bk_mode(hdc, dc::BkMode::Transparent);
        dc::set_text_color(hdc, ColorRef::BLACK);
        super::super::super::gdi::text_out(hdc, tooltip_x + 8, tooltip_y + 5, date_str);

        dc::delete_dc(hdc);
    }

    // Auto-hide after a delay (will be hidden on next click)
}

/// Hide the date tooltip
pub fn hide_date_tooltip() {
    if DATE_TOOLTIP_VISIBLE.load(Ordering::SeqCst) {
        DATE_TOOLTIP_VISIBLE.store(false, Ordering::SeqCst);
        // Repaint to clear tooltip
        super::super::paint::repaint_all();
        super::paint_taskbar();
    }
}

/// Check if date tooltip is visible
pub fn is_date_tooltip_visible() -> bool {
    DATE_TOOLTIP_VISIBLE.load(Ordering::SeqCst)
}

// ============================================================================
// Painting
// ============================================================================

/// Paint the notification area
pub fn paint(hdc: HDC, taskbar_y: i32) {
    paint_systray(hdc, taskbar_y);
    paint_clock(hdc, taskbar_y);
}

/// Paint the system tray icons area
fn paint_systray(hdc: HDC, taskbar_y: i32) {
    let notify = TRAY_NOTIFY.lock();
    let mut rect = notify.systray_rect;
    rect.top += taskbar_y;
    rect.bottom += taskbar_y;
    drop(notify);

    // Draw sunken area for systray
    let bg_brush = brush::create_solid_brush(ColorRef::BUTTON_FACE);
    super::super::super::gdi::fill_rect(hdc, &rect, bg_brush);
    super::super::super::gdi::draw_edge_sunken(hdc, &rect);
}

/// Paint the clock
fn paint_clock(hdc: HDC, taskbar_y: i32) {
    let notify = TRAY_NOTIFY.lock();
    let mut rect = notify.clock_rect;
    rect.top += taskbar_y;
    rect.bottom += taskbar_y;
    drop(notify);

    // Draw sunken area for clock
    let bg_brush = brush::create_solid_brush(ColorRef::BUTTON_FACE);
    super::super::super::gdi::fill_rect(hdc, &rect, bg_brush);
    super::super::super::gdi::draw_edge_sunken(hdc, &rect);

    // Draw time
    let time_buf = get_time_string();
    let time_str = core::str::from_utf8(&time_buf).unwrap_or("??:?? ??");

    dc::set_bk_mode(hdc, dc::BkMode::Transparent);
    dc::set_text_color(hdc, ColorRef::BLACK);
    super::super::super::gdi::text_out(hdc, rect.left + 4, rect.top + 4, time_str);
}
