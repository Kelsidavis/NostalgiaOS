//! Tray Window (Taskbar)
//!
//! This module implements CTray - the main taskbar window that contains:
//! - Start button
//! - Task band (window buttons)
//! - Notification area (system tray + clock)
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/explorer/tray.cpp`
//! - `shell/explorer/tray.h`

use core::sync::atomic::{AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;
use crate::hal::{keyboard, mouse};
use super::super::super::{HWND, HDC, Rect, Point, ColorRef};
use super::super::super::gdi::{dc, brush};
use super::super::{message, window, input, controls, cursor, WindowStyle, WindowStyleEx, ShowCommand};
use super::{taskband, traynot, deskhost, startmenu};

// ============================================================================
// Constants
// ============================================================================

/// Taskbar height in pixels
pub const TASKBAR_HEIGHT: i32 = 30;

/// Start button width
pub const START_BUTTON_WIDTH: i32 = 60;

/// Tray window placement (like ABE_* in Windows)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StuckPlace {
    Bottom = 3,  // ABE_BOTTOM
    Left = 0,    // ABE_LEFT
    Top = 1,     // ABE_TOP
    Right = 2,   // ABE_RIGHT
}

// ============================================================================
// Tray State (CTray equivalent)
// ============================================================================

/// CTray state - main taskbar window manager
struct CTray {
    /// Main tray window handle
    hwnd: HWND,
    /// Start button rectangle
    start_rect: Rect,
    /// Taskbar placement
    stuck_place: StuckPlace,
    /// Always on top flag
    always_on_top: bool,
    /// Auto-hide enabled
    auto_hide: bool,
    /// Small icons in start menu
    sm_small_icons: bool,
}

impl CTray {
    const fn new() -> Self {
        Self {
            hwnd: HWND::NULL,
            start_rect: Rect::new(0, 0, 0, 0),
            stuck_place: StuckPlace::Bottom,
            always_on_top: true,
            auto_hide: false,
            sm_small_icons: false,
        }
    }
}

/// Global tray instance (equivalent to c_tray in Windows)
static C_TRAY: SpinLock<CTray> = SpinLock::new(CTray::new());

/// Tray window handle for quick access
static TRAY_HWND: SpinLock<HWND> = SpinLock::new(HWND::NULL);

// ============================================================================
// Window Dragging State
// ============================================================================

/// Window currently being dragged
static DRAGGING_WINDOW: SpinLock<HWND> = SpinLock::new(HWND::NULL);

/// Drag start position
static DRAG_START: SpinLock<Point> = SpinLock::new(Point::new(0, 0));

/// Window position at drag start
static DRAG_WINDOW_START: SpinLock<Point> = SpinLock::new(Point::new(0, 0));

// ============================================================================
// Window Resizing State
// ============================================================================

/// Window currently being resized
static RESIZING_WINDOW: SpinLock<HWND> = SpinLock::new(HWND::NULL);

/// Resize edge
static RESIZE_EDGE: SpinLock<isize> = SpinLock::new(0);

/// Resize start position
static RESIZE_START: SpinLock<Point> = SpinLock::new(Point::new(0, 0));

/// Window rect at resize start
static RESIZE_WINDOW_RECT: SpinLock<Rect> = SpinLock::new(Rect::new(0, 0, 0, 0));

/// Minimum window size
const MIN_WINDOW_WIDTH: i32 = 100;
const MIN_WINDOW_HEIGHT: i32 = 50;

// ============================================================================
// Double-Click Detection
// ============================================================================

/// Last click time
static LAST_CLICK_TIME: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Last click position
static LAST_CLICK_POS: SpinLock<Point> = SpinLock::new(Point::new(0, 0));

/// Double-click time threshold (in ticks)
const DOUBLE_CLICK_TIME: u32 = 500;

/// Double-click distance threshold
const DOUBLE_CLICK_DIST: i32 = 4;

// ============================================================================
// Initialization
// ============================================================================

/// Create the tray window (taskbar)
///
/// This is equivalent to CTray::Init() in Windows.
pub fn create_tray(rect: Rect, screen_width: i32) {
    // Create taskbar window
    let hwnd = window::create_window(
        "Shell_TrayWnd",
        "",
        WindowStyle::POPUP | WindowStyle::VISIBLE,
        WindowStyleEx::TOOLWINDOW | WindowStyleEx::TOPMOST,
        rect.left, rect.top,
        rect.right - rect.left, rect.bottom - rect.top,
        super::super::super::HWND::NULL,
        0, // menu
    );

    // Store tray handle
    {
        let mut tray = C_TRAY.lock();
        tray.hwnd = hwnd;
        tray.start_rect = Rect::new(2, 2, START_BUTTON_WIDTH, TASKBAR_HEIGHT - 2);
    }
    *TRAY_HWND.lock() = hwnd;

    // Initialize task band
    taskband::init(screen_width);

    // Initialize notification area (includes clock)
    traynot::init(screen_width);

    crate::serial_println!("[TRAY] Taskbar created: hwnd={:#x}", hwnd.raw());
}

/// Get the tray window handle
pub fn get_tray_hwnd() -> HWND {
    *TRAY_HWND.lock()
}

// ============================================================================
// Message Loop
// ============================================================================

/// Main explorer message loop
///
/// This is equivalent to SHDesktopMessageLoop() in Windows.
pub fn message_loop() {
    // Set screen size for mouse position clamping
    let (width, height) = super::super::super::gdi::surface::get_primary_dimensions();
    mouse::set_screen_size(width, height);

    // Paint initial desktop and taskbar
    super::paint_desktop();
    paint_taskbar();

    // Draw initial cursor
    cursor::draw_cursor();

    // Track time for periodic updates
    let mut tick_count: u64 = 0;
    let mut last_clock_update: u64 = 0;
    const CLOCK_UPDATE_INTERVAL: u64 = 5000;

    loop {
        tick_count = tick_count.wrapping_add(1);

        // Process keyboard events (raw scancodes)
        if let Some(scancode) = keyboard::try_read_scancode() {
            process_keyboard_input(scancode);
        }

        // Process mouse events
        if let Some(event) = mouse::poll_event() {
            process_mouse_event(event);
        }

        // Periodic clock update
        if tick_count - last_clock_update >= CLOCK_UPDATE_INTERVAL {
            last_clock_update = tick_count;
            traynot::update_clock();
        }

        // Small delay to prevent busy-waiting
        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }
}

// ============================================================================
// Keyboard Processing
// ============================================================================

fn process_keyboard_input(scancode: u8) {
    // Check for key release (high bit set)
    let pressed = (scancode & 0x80) == 0;
    let code = scancode & 0x7F;

    // Forward to input system
    input::process_key_event(code, pressed);
}

// ============================================================================
// Mouse Processing
// ============================================================================

fn process_mouse_event(event: mouse::MouseEvent) {
    // Get current position after the movement (mouse module tracks this)
    let (x, y) = mouse::get_position();

    // Update cursor position and redraw
    cursor::set_cursor_pos(x, y);
    cursor::draw_cursor();

    // Check for various drag/resize modes
    let dragging_hwnd = *DRAGGING_WINDOW.lock();
    let resizing_hwnd = *RESIZING_WINDOW.lock();
    let icon_dragging = deskhost::is_icon_dragging();

    if icon_dragging {
        // Dragging a desktop icon
        if event.dx != 0 || event.dy != 0 {
            deskhost::update_icon_drag(x, y);
        }
    } else if dragging_hwnd.is_valid() {
        // Dragging a window
        if event.dx != 0 || event.dy != 0 {
            handle_window_drag(x, y);
        }
    } else if resizing_hwnd.is_valid() {
        // Resizing a window
        if event.dx != 0 || event.dy != 0 {
            handle_window_resize(x, y);
        }
    } else {
        // Normal mouse movement
        if event.dx != 0 || event.dy != 0 {
            input::process_mouse_move(x, y);
            update_cursor_for_position(x, y);
        }
    }

    // Process button clicks
    process_mouse_buttons(event, x, y);
}

fn process_mouse_buttons(event: mouse::MouseEvent, x: i32, y: i32) {
    static mut LAST_LEFT: bool = false;
    static mut LAST_RIGHT: bool = false;
    static mut LAST_MIDDLE: bool = false;

    unsafe {
        // Left button
        if event.buttons.left != LAST_LEFT {
            let was_down = LAST_LEFT;
            LAST_LEFT = event.buttons.left;

            if event.buttons.left {
                handle_left_button_down(x, y);
            } else if was_down {
                handle_left_button_up(x, y);
            }
        }

        // Right button
        if event.buttons.right != LAST_RIGHT {
            let was_down = LAST_RIGHT;
            LAST_RIGHT = event.buttons.right;
            input::process_mouse_button(1, event.buttons.right, x, y);

            if !event.buttons.right && was_down {
                handle_right_click(x, y);
            }
        }

        // Middle button
        if event.buttons.middle != LAST_MIDDLE {
            LAST_MIDDLE = event.buttons.middle;
            input::process_mouse_button(2, event.buttons.middle, x, y);
        }
    }
}

fn handle_left_button_down(x: i32, y: i32) {
    input::process_mouse_button(0, true, x, y);

    // Check for context menus first
    if deskhost::is_icon_menu_visible() {
        deskhost::handle_icon_menu_click(x, y);
        return;
    }

    if deskhost::is_desktop_menu_visible() {
        deskhost::handle_desktop_menu_click(x, y);
        return;
    }

    // Check for double-click
    let current_time = crate::hal::rtc::get_system_time() as u32;
    let last_time = LAST_CLICK_TIME.load(Ordering::SeqCst);
    let last_pos = *LAST_CLICK_POS.lock();

    let is_double_click = (current_time.wrapping_sub(last_time) < DOUBLE_CLICK_TIME)
        && ((x - last_pos.x).abs() < DOUBLE_CLICK_DIST)
        && ((y - last_pos.y).abs() < DOUBLE_CLICK_DIST);

    LAST_CLICK_TIME.store(current_time, Ordering::SeqCst);
    *LAST_CLICK_POS.lock() = Point::new(x, y);

    // Check what was clicked
    let (_, height) = super::super::super::gdi::surface::get_primary_dimensions();
    let taskbar_y = height as i32 - TASKBAR_HEIGHT;

    if y >= taskbar_y {
        // Clicked on taskbar
        handle_taskbar_click(x, y);
    } else if startmenu::is_visible() {
        // Click outside start menu - hide it
        startmenu::handle_click(x, y);
    } else if is_double_click {
        // Double-click
        if let Some(icon_idx) = deskhost::get_icon_at_position(x, y) {
            deskhost::handle_icon_double_click(icon_idx);
        } else {
            try_caption_double_click(x, y);
        }
    } else {
        // Single click
        if let Some(icon_idx) = deskhost::get_icon_at_position(x, y) {
            deskhost::select_icon(Some(icon_idx));
            deskhost::start_icon_drag(icon_idx, x, y);
        } else {
            // Clicked on desktop but not on icon
            let hwnd = window::window_from_point(Point::new(x, y));
            if !hwnd.is_valid() || hwnd == window::get_desktop_window() {
                deskhost::select_icon(None);
            }
            try_start_window_drag(x, y);
        }
    }
}

fn handle_left_button_up(x: i32, y: i32) {
    input::process_mouse_button(0, false, x, y);

    // End any drag operations
    deskhost::end_icon_drag();
    end_window_drag();
    end_window_resize();
}

fn handle_right_click(x: i32, y: i32) {
    let (_, height) = super::super::super::gdi::surface::get_primary_dimensions();
    let taskbar_y = height as i32 - TASKBAR_HEIGHT;

    if y >= taskbar_y {
        // Right-click on taskbar - no menu for now
        return;
    }

    // Check if right-clicked on a desktop icon
    if let Some(icon_idx) = deskhost::get_icon_at_position(x, y) {
        deskhost::select_icon(Some(icon_idx));
        deskhost::show_icon_context_menu(x, y, icon_idx);
    } else {
        // Right-click on desktop background
        let hwnd = window::window_from_point(Point::new(x, y));
        let desktop_hwnd = deskhost::get_desktop_hwnd();
        if !hwnd.is_valid() || hwnd == desktop_hwnd || hwnd == window::get_desktop_window() {
            deskhost::show_desktop_context_menu(x, y);
        }
    }
}

// ============================================================================
// Taskbar Click Handling
// ============================================================================

fn handle_taskbar_click(x: i32, y: i32) {
    let tray = C_TRAY.lock();

    // Check Start button
    if x >= tray.start_rect.left && x < tray.start_rect.right + tray.start_rect.left {
        drop(tray);
        startmenu::toggle();
        return;
    }
    drop(tray);

    // Check clock area
    let (width, _) = super::super::super::gdi::surface::get_primary_dimensions();
    let clock_x_start = width as i32 - 60;
    if x >= clock_x_start {
        traynot::show_date_tooltip();
        return;
    }

    // Check task buttons
    taskband::handle_click(x, y);
}

// ============================================================================
// Window Drag/Resize
// ============================================================================

fn try_caption_double_click(x: i32, y: i32) {
    let hwnd = window::window_from_point(Point::new(x, y));
    if !hwnd.is_valid() {
        return;
    }

    let lparam = ((y as isize) << 16) | ((x as isize) & 0xFFFF);
    let hit = message::send_message(hwnd, message::WM_NCHITTEST, 0, lparam);

    if hit == message::hittest::HTCAPTION {
        if let Some(wnd) = window::get_window(hwnd) {
            if wnd.maximized {
                message::send_message(hwnd, message::WM_SYSCOMMAND, message::syscmd::SC_RESTORE, 0);
            } else {
                message::send_message(hwnd, message::WM_SYSCOMMAND, message::syscmd::SC_MAXIMIZE, 0);
            }
        }
    }
}

fn try_start_window_drag(x: i32, y: i32) {
    let hwnd = window::window_from_point(Point::new(x, y));
    if !hwnd.is_valid() {
        return;
    }

    let lparam = ((y as isize) << 16) | ((x as isize) & 0xFFFF);
    let hit = message::send_message(hwnd, message::WM_NCHITTEST, 0, lparam);

    match hit {
        message::hittest::HTCAPTION => {
            if let Some(wnd) = window::get_window(hwnd) {
                *DRAGGING_WINDOW.lock() = hwnd;
                *DRAG_START.lock() = Point::new(x, y);
                *DRAG_WINDOW_START.lock() = Point::new(wnd.rect.left, wnd.rect.top);
            }
            window::set_foreground_window(hwnd);
            input::set_active_window(hwnd);
            paint_taskbar();
        }
        message::hittest::HTCLOSE | message::hittest::HTMINBUTTON | message::hittest::HTMAXBUTTON => {
            message::send_message(hwnd, message::WM_NCLBUTTONDOWN, hit as usize, lparam);
        }
        message::hittest::HTCLIENT => {
            window::set_foreground_window(hwnd);
            input::set_active_window(hwnd);
            paint_taskbar();
        }
        hit if is_resize_edge(hit) => {
            if let Some(wnd) = window::get_window(hwnd) {
                *RESIZING_WINDOW.lock() = hwnd;
                *RESIZE_EDGE.lock() = hit;
                *RESIZE_START.lock() = Point::new(x, y);
                *RESIZE_WINDOW_RECT.lock() = wnd.rect;
            }
            window::set_foreground_window(hwnd);
            input::set_active_window(hwnd);
        }
        _ => {}
    }
}

fn is_resize_edge(hit: isize) -> bool {
    matches!(hit,
        message::hittest::HTLEFT |
        message::hittest::HTRIGHT |
        message::hittest::HTTOP |
        message::hittest::HTBOTTOM |
        message::hittest::HTTOPLEFT |
        message::hittest::HTTOPRIGHT |
        message::hittest::HTBOTTOMLEFT |
        message::hittest::HTBOTTOMRIGHT
    )
}

fn handle_window_drag(x: i32, y: i32) {
    let hwnd = *DRAGGING_WINDOW.lock();
    if !hwnd.is_valid() {
        return;
    }

    let drag_start = *DRAG_START.lock();
    let window_start = *DRAG_WINDOW_START.lock();

    let new_x = window_start.x + (x - drag_start.x);
    let new_y = window_start.y + (y - drag_start.y);

    if let Some(wnd) = window::get_window(hwnd) {
        let width = wnd.rect.right - wnd.rect.left;
        let height = wnd.rect.bottom - wnd.rect.top;
        window::move_window(hwnd, new_x, new_y, width, height, true);
    }
}

fn handle_window_resize(x: i32, y: i32) {
    let hwnd = *RESIZING_WINDOW.lock();
    if !hwnd.is_valid() {
        return;
    }

    let resize_start = *RESIZE_START.lock();
    let original_rect = *RESIZE_WINDOW_RECT.lock();
    let edge = *RESIZE_EDGE.lock();

    let dx = x - resize_start.x;
    let dy = y - resize_start.y;

    let mut new_rect = original_rect;

    // Adjust edges based on which edge is being dragged
    match edge {
        message::hittest::HTLEFT => {
            new_rect.left = (original_rect.left + dx).min(original_rect.right - MIN_WINDOW_WIDTH);
        }
        message::hittest::HTRIGHT => {
            new_rect.right = (original_rect.right + dx).max(original_rect.left + MIN_WINDOW_WIDTH);
        }
        message::hittest::HTTOP => {
            new_rect.top = (original_rect.top + dy).min(original_rect.bottom - MIN_WINDOW_HEIGHT);
        }
        message::hittest::HTBOTTOM => {
            new_rect.bottom = (original_rect.bottom + dy).max(original_rect.top + MIN_WINDOW_HEIGHT);
        }
        message::hittest::HTTOPLEFT => {
            new_rect.left = (original_rect.left + dx).min(original_rect.right - MIN_WINDOW_WIDTH);
            new_rect.top = (original_rect.top + dy).min(original_rect.bottom - MIN_WINDOW_HEIGHT);
        }
        message::hittest::HTTOPRIGHT => {
            new_rect.right = (original_rect.right + dx).max(original_rect.left + MIN_WINDOW_WIDTH);
            new_rect.top = (original_rect.top + dy).min(original_rect.bottom - MIN_WINDOW_HEIGHT);
        }
        message::hittest::HTBOTTOMLEFT => {
            new_rect.left = (original_rect.left + dx).min(original_rect.right - MIN_WINDOW_WIDTH);
            new_rect.bottom = (original_rect.bottom + dy).max(original_rect.top + MIN_WINDOW_HEIGHT);
        }
        message::hittest::HTBOTTOMRIGHT => {
            new_rect.right = (original_rect.right + dx).max(original_rect.left + MIN_WINDOW_WIDTH);
            new_rect.bottom = (original_rect.bottom + dy).max(original_rect.top + MIN_WINDOW_HEIGHT);
        }
        _ => {}
    }

    window::move_window(hwnd, new_rect.left, new_rect.top,
        new_rect.right - new_rect.left, new_rect.bottom - new_rect.top, true);
}

fn end_window_drag() {
    *DRAGGING_WINDOW.lock() = HWND::NULL;
}

fn end_window_resize() {
    *RESIZING_WINDOW.lock() = HWND::NULL;
}

fn update_cursor_for_position(x: i32, y: i32) {
    let hwnd = window::window_from_point(Point::new(x, y));
    if !hwnd.is_valid() {
        cursor::set_cursor(cursor::StandardCursor::Arrow);
        return;
    }

    let lparam = ((y as isize) << 16) | ((x as isize) & 0xFFFF);
    let hit = message::send_message(hwnd, message::WM_NCHITTEST, 0, lparam);

    let new_cursor = match hit {
        message::hittest::HTLEFT | message::hittest::HTRIGHT => cursor::StandardCursor::SizeWE,
        message::hittest::HTTOP | message::hittest::HTBOTTOM => cursor::StandardCursor::SizeNS,
        message::hittest::HTTOPLEFT | message::hittest::HTBOTTOMRIGHT => cursor::StandardCursor::SizeNWSE,
        message::hittest::HTTOPRIGHT | message::hittest::HTBOTTOMLEFT => cursor::StandardCursor::SizeNESW,
        _ => cursor::StandardCursor::Arrow,
    };

    cursor::set_cursor(new_cursor);
}

// ============================================================================
// Painting
// ============================================================================

/// Paint the entire taskbar
pub fn paint_taskbar() {
    if let Ok(hdc) = dc::create_display_dc() {
        let (_, height) = super::super::super::gdi::surface::get_primary_dimensions();
        let taskbar_y = height as i32 - TASKBAR_HEIGHT;

        // Paint taskbar background
        paint_taskbar_background(hdc, taskbar_y);

        // Paint Start button
        paint_start_button(hdc, taskbar_y);

        // Paint task buttons
        taskband::paint(hdc, taskbar_y);

        // Paint notification area (includes clock)
        traynot::paint(hdc, taskbar_y);

        dc::delete_dc(hdc);
    }
}

fn paint_taskbar_background(hdc: HDC, taskbar_y: i32) {
    let (width, height) = super::super::super::gdi::surface::get_primary_dimensions();
    let taskbar_rect = Rect::new(0, taskbar_y, width as i32, height as i32);

    let bg_brush = brush::create_solid_brush(ColorRef::BUTTON_FACE);
    super::super::super::gdi::fill_rect(hdc, &taskbar_rect, bg_brush);

    // Top highlight line
    if let Some(surf) = super::super::super::gdi::surface::get_surface(dc::get_dc_surface(hdc)) {
        surf.hline(0, width as i32, taskbar_y, ColorRef::WHITE);
    }
}

fn paint_start_button(hdc: HDC, taskbar_y: i32) {
    let tray = C_TRAY.lock();
    let mut btn_rect = tray.start_rect;
    btn_rect.top += taskbar_y;
    btn_rect.bottom += taskbar_y;
    drop(tray);

    controls::draw_button(
        hdc,
        &btn_rect,
        "Start",
        controls::ButtonState::Normal,
        controls::ButtonStyle::PushButton,
    );
}
