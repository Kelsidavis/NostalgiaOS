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
use super::super::context_menu;

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

    // Check if active window is a shell
    let active_hwnd = input::get_active_window();
    if active_hwnd.is_valid() && super::super::shell::is_shell(active_hwnd) {
        if pressed {
            // Convert scancode to character for shell
            let ch = scancode_to_char(code, is_shift_down());
            super::super::shell::shell_key(active_hwnd, code, ch);

            // Repaint shell window
            super::super::paint::repaint_all();
        }
        return;
    }

    // Forward to input system
    input::process_key_event(code, pressed);
}

/// Check if shift is currently held down
fn is_shift_down() -> bool {
    // Use virtual key codes and check bit 15 (0x8000) for key down state
    (input::get_key_state(super::super::input::vk::LSHIFT) & 0x8000u16 as i16 != 0) ||
    (input::get_key_state(super::super::input::vk::RSHIFT) & 0x8000u16 as i16 != 0)
}

/// Convert scancode to ASCII character
fn scancode_to_char(scancode: u8, shift: bool) -> char {
    if shift {
        match scancode {
            0x02 => '!', 0x03 => '@', 0x04 => '#', 0x05 => '$',
            0x06 => '%', 0x07 => '^', 0x08 => '&', 0x09 => '*',
            0x0A => '(', 0x0B => ')',
            0x0C => '_', 0x0D => '+',
            0x10 => 'Q', 0x11 => 'W', 0x12 => 'E', 0x13 => 'R',
            0x14 => 'T', 0x15 => 'Y', 0x16 => 'U', 0x17 => 'I',
            0x18 => 'O', 0x19 => 'P',
            0x1A => '{', 0x1B => '}',
            0x1E => 'A', 0x1F => 'S', 0x20 => 'D', 0x21 => 'F',
            0x22 => 'G', 0x23 => 'H', 0x24 => 'J', 0x25 => 'K',
            0x26 => 'L',
            0x27 => ':', 0x28 => '"',
            0x29 => '~',
            0x2B => '|',
            0x2C => 'Z', 0x2D => 'X', 0x2E => 'C', 0x2F => 'V',
            0x30 => 'B', 0x31 => 'N', 0x32 => 'M',
            0x33 => '<', 0x34 => '>', 0x35 => '?',
            0x39 => ' ',
            _ => '\0',
        }
    } else {
        match scancode {
            0x02 => '1', 0x03 => '2', 0x04 => '3', 0x05 => '4',
            0x06 => '5', 0x07 => '6', 0x08 => '7', 0x09 => '8',
            0x0A => '9', 0x0B => '0',
            0x0C => '-', 0x0D => '=',
            0x10 => 'q', 0x11 => 'w', 0x12 => 'e', 0x13 => 'r',
            0x14 => 't', 0x15 => 'y', 0x16 => 'u', 0x17 => 'i',
            0x18 => 'o', 0x19 => 'p',
            0x1A => '[', 0x1B => ']',
            0x1E => 'a', 0x1F => 's', 0x20 => 'd', 0x21 => 'f',
            0x22 => 'g', 0x23 => 'h', 0x24 => 'j', 0x25 => 'k',
            0x26 => 'l',
            0x27 => ';', 0x28 => '\'',
            0x29 => '`',
            0x2B => '\\',
            0x2C => 'z', 0x2D => 'x', 0x2E => 'c', 0x2F => 'v',
            0x30 => 'b', 0x31 => 'n', 0x32 => 'm',
            0x33 => ',', 0x34 => '.', 0x35 => '/',
            0x39 => ' ',
            _ => '\0',
        }
    }
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

    // Check if context menu is visible and handle mouse move
    if context_menu::is_menu_visible() {
        if event.dx != 0 || event.dy != 0 {
            context_menu::on_mouse_move(x, y);
        }
    }

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
    if context_menu::is_menu_visible() {
        let menu_result = context_menu::on_click(x, y);
        if menu_result != context_menu::menu_id::NONE {
            handle_context_menu_action(menu_result);
        }
        return;
    }

    if deskhost::is_icon_menu_visible() {
        deskhost::handle_icon_menu_click(x, y);
        return;
    }

    if deskhost::is_desktop_menu_visible() {
        deskhost::handle_desktop_menu_click(x, y);
        return;
    }

    // Check for navigation button clicks on explorer windows
    let hwnd = window::window_from_point(Point::new(x, y));
    if hwnd.is_valid() {
        if super::super::paint::hit_test_back_button(hwnd, x, y) {
            if window::can_go_back(hwnd) {
                crate::serial_println!("[TRAY] Back button clicked");
                window::navigate_back(hwnd);
                super::super::paint::repaint_all();
                paint_taskbar();
            }
            return;
        }
        if super::super::paint::hit_test_forward_button(hwnd, x, y) {
            if window::can_go_forward(hwnd) {
                crate::serial_println!("[TRAY] Forward button clicked");
                window::navigate_forward(hwnd);
                super::super::paint::repaint_all();
                paint_taskbar();
            }
            return;
        }
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
            // Check if double-clicked on a window content icon
            let hwnd = window::window_from_point(Point::new(x, y));
            if hwnd.is_valid() {
                if let Some(folder_name) = super::super::paint::get_content_icon_at_position(hwnd, x, y) {
                    // Navigate the existing window to the clicked folder
                    navigate_window_to_folder(hwnd, folder_name);
                    return;
                }
            }
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

    // Check if we were dragging/resizing and need to repaint
    let was_dragging = DRAGGING_WINDOW.lock().is_valid();
    let was_resizing = RESIZING_WINDOW.lock().is_valid();

    // End any drag operations
    deskhost::end_icon_drag();
    end_window_drag();
    end_window_resize();

    // Repaint if we were moving/resizing a window
    if was_dragging || was_resizing {
        super::super::paint::repaint_all();
        paint_taskbar();
    }
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
        // Check if right-click is in an explorer window
        let hwnd = window::window_from_point(Point::new(x, y));
        let desktop_hwnd = deskhost::get_desktop_hwnd();

        if hwnd.is_valid() && hwnd != desktop_hwnd && hwnd != window::get_desktop_window() {
            // Check if it's an explorer window (CabinetWClass)
            if let Some(wnd) = window::get_window(hwnd) {
                if wnd.class_name_str() == "CabinetWClass" {
                    // Get folder path from window user data
                    let folder_path = wnd.user_data_str();
                    context_menu::show_explorer_context_menu(hwnd, x, y, folder_path);
                    return;
                }
            }
        }

        // Right-click on desktop background
        if !hwnd.is_valid() || hwnd == desktop_hwnd || hwnd == window::get_desktop_window() {
            deskhost::show_desktop_context_menu(x, y);
        }
    }
}

// ============================================================================
// Context Menu Action Handling
// ============================================================================

fn handle_context_menu_action(action: u16) {
    let folder_path = context_menu::get_menu_folder_path();

    match action {
        context_menu::menu_id::REFRESH => {
            // Refresh the window content
            crate::serial_println!("[TRAY] Refresh requested for: {}", folder_path);
            super::super::paint::repaint_all();
            paint_taskbar();
        }
        context_menu::menu_id::NEW_FOLDER => {
            // Create a new folder
            crate::serial_println!("[TRAY] New Folder requested in: {}", folder_path);
            create_new_folder(folder_path);
        }
        context_menu::menu_id::NEW_TEXT_FILE => {
            // Create a new text file
            crate::serial_println!("[TRAY] New Text Document requested in: {}", folder_path);
            create_new_text_file(folder_path);
        }
        context_menu::menu_id::PROPERTIES => {
            // Show properties (not implemented yet)
            crate::serial_println!("[TRAY] Properties requested for: {}", folder_path);
        }
        _ => {}
    }
}

fn create_new_folder(folder_path: &str) {
    use crate::io::vfs_create_directory;

    // Generate a unique folder name
    static mut FOLDER_COUNT: u32 = 0;
    let count = unsafe {
        FOLDER_COUNT += 1;
        FOLDER_COUNT
    };

    // Build folder name - "New Folder" or "New Folder (2)" etc.
    let mut name_buf = [0u8; 32];
    let name = if count == 1 {
        "New Folder"
    } else {
        // Format "NEWFOLD~N" for 8.3 compatibility
        let mut pos = 0;
        for b in b"NEWFOLD" {
            if pos < 31 {
                name_buf[pos] = *b;
                pos += 1;
            }
        }
        // Add number suffix
        let num_str = if count < 10 {
            name_buf[pos] = b'0' + count as u8;
            pos += 1;
        } else {
            name_buf[pos] = b'0' + (count / 10) as u8;
            pos += 1;
            name_buf[pos] = b'0' + (count % 10) as u8;
            pos += 1;
        };
        core::str::from_utf8(&name_buf[..pos]).unwrap_or("NEWFOLD")
    };

    crate::serial_println!("[TRAY] Creating folder '{}' in: {}", name, folder_path);

    if vfs_create_directory(folder_path, name) {
        crate::serial_println!("[TRAY] Successfully created folder '{}'", name);
    } else {
        crate::serial_println!("[TRAY] Failed to create folder '{}'", name);
    }

    // Refresh the display
    super::super::paint::repaint_all();
    paint_taskbar();
}

fn create_new_text_file(folder_path: &str) {
    use crate::io::vfs_create_file;

    // Generate a unique file name
    static mut FILE_COUNT: u32 = 0;
    let count = unsafe {
        FILE_COUNT += 1;
        FILE_COUNT
    };

    // Build file name - "New Text Document.txt" or with number
    let mut name_buf = [0u8; 32];
    let name = if count == 1 {
        "NEWTXT.TXT"
    } else {
        // Format "NEWTX~N.TXT" for 8.3 compatibility
        let mut pos = 0;
        for b in b"NEWTX" {
            if pos < 28 {
                name_buf[pos] = *b;
                pos += 1;
            }
        }
        // Add number suffix
        if count < 10 {
            name_buf[pos] = b'0' + count as u8;
            pos += 1;
        } else {
            name_buf[pos] = b'0' + (count / 10) as u8;
            pos += 1;
            name_buf[pos] = b'0' + (count % 10) as u8;
            pos += 1;
        }
        // Add extension
        for b in b".TXT" {
            if pos < 31 {
                name_buf[pos] = *b;
                pos += 1;
            }
        }
        core::str::from_utf8(&name_buf[..pos]).unwrap_or("NEWTXT.TXT")
    };

    crate::serial_println!("[TRAY] Creating file '{}' in: {}", name, folder_path);

    if vfs_create_file(folder_path, name) {
        crate::serial_println!("[TRAY] Successfully created file '{}'", name);
    } else {
        crate::serial_println!("[TRAY] Failed to create file '{}'", name);
    }

    // Refresh the display
    super::super::paint::repaint_all();
    paint_taskbar();
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

    // Check clock area (use actual CLOCK_WIDTH)
    let (width, _) = super::super::super::gdi::surface::get_primary_dimensions();
    let clock_x_start = width as i32 - 75 - 2; // CLOCK_WIDTH + margin
    if x >= clock_x_start {
        traynot::toggle_date_tooltip();
        return;
    }

    // Check task buttons
    taskband::handle_click(x, y);
}

// ============================================================================
// Explorer Window Creation
// ============================================================================

/// Navigate an explorer window to a subfolder
fn navigate_window_to_folder(hwnd: super::super::super::HWND, folder_name: &str) {
    // Get current folder path
    let mut current_path_buf = [0u8; 128];
    let current_len = window::get_window_user_data(hwnd, &mut current_path_buf);
    let current_path = core::str::from_utf8(&current_path_buf[..current_len]).unwrap_or("");

    // Build new path (current_path/folder_name)
    let mut new_path = [0u8; 128];
    let mut path_len = 0;

    // Copy current path
    for &b in current_path.as_bytes() {
        if path_len < 127 {
            new_path[path_len] = b;
            path_len += 1;
        }
    }

    // Add separator
    if path_len > 0 && path_len < 127 {
        new_path[path_len] = b'/';
        path_len += 1;
    }

    // Add folder name
    for &b in folder_name.as_bytes() {
        if path_len < 127 {
            new_path[path_len] = b;
            path_len += 1;
        }
    }

    let new_path_str = core::str::from_utf8(&new_path[..path_len]).unwrap_or("");

    crate::serial_println!("[TRAY] Navigating to: {} (was: {})", new_path_str, current_path);

    // Update window title and path
    window::navigate_explorer_window(hwnd, new_path_str, folder_name);

    // Repaint the window
    super::super::paint::repaint_all();
}

fn open_explorer_window(folder_name: &str) {
    let hwnd = window::create_window(
        "CabinetWClass",
        folder_name,
        super::super::WindowStyle::OVERLAPPEDWINDOW | super::super::WindowStyle::VISIBLE,
        super::super::WindowStyleEx::empty(),
        250, 150, 400, 300,
        super::super::super::HWND::NULL,
        0, // menu
    );

    if hwnd.is_valid() {
        crate::serial_println!("[TRAY] Created window: {} hwnd={:#x}", folder_name, hwnd.raw());

        // Add to taskbar
        taskband::add_task(hwnd);

        // Make it the active window
        window::set_foreground_window(hwnd);
        input::set_active_window(hwnd);

        // Show and paint
        window::show_window(hwnd, super::super::ShowCommand::Show);

        // Repaint everything
        super::super::paint::repaint_all();
        paint_taskbar();
    }
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

        // Repaint to show window in new position
        super::super::paint::repaint_all();
        paint_taskbar();
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

    // Repaint to show window with new size
    super::super::paint::repaint_all();
    paint_taskbar();
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
