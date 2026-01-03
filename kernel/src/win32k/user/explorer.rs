//! Windows Explorer Shell
//!
//! The graphical shell provides the desktop experience including:
//! - Desktop window with icons
//! - Taskbar with Start button and window buttons
//! - Window message pump
//! - Alt-Tab window switching
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/shell/shell32/explorer.c`
//! - `windows/shell/explorer/desktop.c`

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use crate::hal::{keyboard, mouse};
use super::super::{HWND, HDC, Rect, Point, ColorRef};
use super::super::gdi::{dc, brush, pen};
use super::{message, window, input, controls, cursor, winlogon, WindowStyle, WindowStyleEx, ShowCommand};

// ============================================================================
// Constants
// ============================================================================

/// Taskbar height in pixels
pub const TASKBAR_HEIGHT: i32 = 30;

/// Start button width
pub const START_BUTTON_WIDTH: i32 = 60;

/// Clock width
pub const CLOCK_WIDTH: i32 = 75;

/// System tray width
pub const SYSTRAY_WIDTH: i32 = 100;

/// Maximum taskbar buttons
pub const MAX_TASKBAR_BUTTONS: usize = 32;

/// Shell state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellState {
    /// Shell not started
    NotStarted,
    /// Shell is initializing
    Initializing,
    /// Shell is running
    Running,
    /// Shell is shutting down
    ShuttingDown,
}

// ============================================================================
// Shell State
// ============================================================================

/// Global shell state
static SHELL_STATE: SpinLock<ShellState> = SpinLock::new(ShellState::NotStarted);

/// Shell running flag
static SHELL_RUNNING: AtomicBool = AtomicBool::new(false);

/// Desktop window handle
static DESKTOP_HWND: SpinLock<HWND> = SpinLock::new(HWND::NULL);

/// Taskbar window handle
static TASKBAR_HWND: SpinLock<HWND> = SpinLock::new(HWND::NULL);

/// Alt-Tab switcher active
static ALT_TAB_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Currently selected window in Alt-Tab
static ALT_TAB_INDEX: AtomicU32 = AtomicU32::new(0);

/// Start menu visible
static START_MENU_VISIBLE: AtomicBool = AtomicBool::new(false);

/// Start menu item count (right side items)
const START_MENU_ITEMS: usize = 8;

/// Start menu item height
const START_MENU_ITEM_HEIGHT: i32 = 24;

/// Start menu total width (sidebar + items)
const START_MENU_WIDTH: i32 = 220;

/// Start menu sidebar width (blue user panel)
const START_MENU_SIDEBAR_WIDTH: i32 = 54;

// ============================================================================
// Window Dragging State
// ============================================================================

/// Window currently being dragged (if any)
static DRAGGING_WINDOW: SpinLock<HWND> = SpinLock::new(HWND::NULL);

/// Drag start position (screen coordinates)
static DRAG_START: SpinLock<Point> = SpinLock::new(Point::new(0, 0));

/// Window position at drag start
static DRAG_WINDOW_START: SpinLock<Point> = SpinLock::new(Point::new(0, 0));

// ============================================================================
// Window Resizing State
// ============================================================================

/// Window currently being resized (if any)
static RESIZING_WINDOW: SpinLock<HWND> = SpinLock::new(HWND::NULL);

/// Resize edge (HTLEFT, HTRIGHT, HTTOP, HTBOTTOM, or corners)
static RESIZE_EDGE: SpinLock<isize> = SpinLock::new(0);

/// Resize start position (screen coordinates)
static RESIZE_START: SpinLock<Point> = SpinLock::new(Point::new(0, 0));

/// Window rect at resize start
static RESIZE_WINDOW_RECT: SpinLock<Rect> = SpinLock::new(Rect::new(0, 0, 0, 0));

/// Minimum window size
const MIN_WINDOW_WIDTH: i32 = 100;
const MIN_WINDOW_HEIGHT: i32 = 50;

// ============================================================================
// Double-Click Detection
// ============================================================================

/// Last click time (tick count)
static LAST_CLICK_TIME: AtomicU32 = AtomicU32::new(0);

/// Last click position
static LAST_CLICK_POS: SpinLock<Point> = SpinLock::new(Point::new(0, 0));

/// Double-click time threshold (in ticks)
const DOUBLE_CLICK_TIME: u32 = 500;

/// Double-click distance threshold
const DOUBLE_CLICK_DIST: i32 = 4;

/// Taskbar button entry
#[derive(Debug, Clone, Copy)]
struct TaskbarButtonEntry {
    /// Button is valid
    valid: bool,
    /// Associated window
    hwnd: HWND,
    /// Button rectangle
    rect: Rect,
}

impl TaskbarButtonEntry {
    const fn empty() -> Self {
        Self {
            valid: false,
            hwnd: HWND::NULL,
            rect: Rect::new(0, 0, 0, 0),
        }
    }
}

/// Taskbar state
struct TaskbarState {
    /// Taskbar buttons
    buttons: [TaskbarButtonEntry; MAX_TASKBAR_BUTTONS],
    /// Number of buttons
    button_count: usize,
    /// Start button rect
    start_rect: Rect,
    /// Clock rect
    clock_rect: Rect,
    /// System tray rect
    systray_rect: Rect,
}

impl TaskbarState {
    const fn new() -> Self {
        Self {
            buttons: [const { TaskbarButtonEntry::empty() }; MAX_TASKBAR_BUTTONS],
            button_count: 0,
            start_rect: Rect::new(0, 0, 0, 0),
            clock_rect: Rect::new(0, 0, 0, 0),
            systray_rect: Rect::new(0, 0, 0, 0),
        }
    }
}

static TASKBAR_STATE: SpinLock<TaskbarState> = SpinLock::new(TaskbarState::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the explorer shell
pub fn init() {
    crate::serial_println!("[EXPLORER] Initializing Windows Explorer shell...");

    {
        let mut state = SHELL_STATE.lock();
        *state = ShellState::Initializing;
    }

    // Get screen dimensions
    let (width, height) = super::super::gdi::surface::get_primary_dimensions();
    let width = width as i32;
    let height = height as i32;

    // Create desktop window (covers the whole screen except taskbar)
    let desktop_rect = Rect::new(0, 0, width, height - TASKBAR_HEIGHT);
    let desktop_hwnd = create_desktop_window(desktop_rect);
    {
        let mut hwnd = DESKTOP_HWND.lock();
        *hwnd = desktop_hwnd;
    }

    // Initialize desktop icons with default positions
    init_desktop_icons();

    // Create taskbar window
    let taskbar_rect = Rect::new(0, height - TASKBAR_HEIGHT, width, height);
    let taskbar_hwnd = create_taskbar_window(taskbar_rect);
    {
        let mut hwnd = TASKBAR_HWND.lock();
        *hwnd = taskbar_hwnd;
    }

    // Initialize taskbar layout
    init_taskbar_layout(width);

    {
        let mut state = SHELL_STATE.lock();
        *state = ShellState::Running;
    }

    SHELL_RUNNING.store(true, Ordering::SeqCst);

    crate::serial_println!("[EXPLORER] Shell initialized: desktop={:#x}, taskbar={:#x}",
        desktop_hwnd.raw(), taskbar_hwnd.raw());
}

/// Create the desktop window
fn create_desktop_window(rect: Rect) -> HWND {
    // Create window with desktop style
    let hwnd = window::create_window(
        "Desktop",
        "Desktop",
        WindowStyle::POPUP | WindowStyle::VISIBLE,
        WindowStyleEx::empty(),
        rect.left, rect.top,
        rect.width(), rect.height(),
        HWND::NULL,
        0,
    );

    if hwnd.is_valid() {
        // Set as desktop window
        window::with_window_mut(hwnd, |wnd| {
            wnd.is_desktop = true;
        });
    }

    hwnd
}

/// Create the taskbar window
fn create_taskbar_window(rect: Rect) -> HWND {
    // Create window with taskbar style
    let hwnd = window::create_window(
        "Shell_TrayWnd",
        "",
        WindowStyle::POPUP | WindowStyle::VISIBLE,
        WindowStyleEx::empty(),
        rect.left, rect.top,
        rect.width(), rect.height(),
        HWND::NULL,
        0,
    );

    hwnd
}

/// Initialize taskbar layout
fn init_taskbar_layout(screen_width: i32) {
    let mut state = TASKBAR_STATE.lock();

    // Start button on the left
    state.start_rect = Rect::new(2, 2, 2 + START_BUTTON_WIDTH, TASKBAR_HEIGHT - 2);

    // Clock on the right
    state.clock_rect = Rect::new(
        screen_width - CLOCK_WIDTH - 2, 2,
        screen_width - 2, TASKBAR_HEIGHT - 2
    );

    // System tray next to clock
    state.systray_rect = Rect::new(
        screen_width - CLOCK_WIDTH - SYSTRAY_WIDTH - 4, 2,
        screen_width - CLOCK_WIDTH - 4, TASKBAR_HEIGHT - 2
    );
}

// ============================================================================
// Message Pump
// ============================================================================

/// Run the shell message pump
///
/// This is the main loop that processes window messages and handles
/// input from the keyboard and mouse.
pub fn run_message_pump() {
    crate::serial_println!("[EXPLORER] Starting message pump...");

    // Set screen size for mouse position clamping
    let (width, height) = super::super::gdi::surface::get_primary_dimensions();
    mouse::set_screen_size(width, height);

    // Paint initial desktop and taskbar
    paint_desktop();
    paint_taskbar();

    // Draw initial cursor
    cursor::draw_cursor();

    // Track time for periodic updates
    let mut tick_count: u64 = 0;
    let mut last_clock_update: u64 = 0;
    const CLOCK_UPDATE_INTERVAL: u64 = 5000; // Update clock every ~5000 iterations

    while SHELL_RUNNING.load(Ordering::SeqCst) {
        tick_count = tick_count.wrapping_add(1);

        // Check for keyboard input
        if let Some(scancode) = keyboard::try_read_scancode() {
            process_keyboard_input(scancode);
        }

        // Check for mouse input
        if let Some(event) = mouse::poll_event() {
            process_mouse_input(event);
        }

        // Process pending messages
        process_messages();

        // Check for windows that need painting
        process_paint_requests();

        // Periodic clock update
        if tick_count - last_clock_update >= CLOCK_UPDATE_INTERVAL {
            last_clock_update = tick_count;
            update_clock();
        }

        // Small yield to prevent hogging CPU
        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }

    crate::serial_println!("[EXPLORER] Message pump exited");
}

/// Process mouse input event
fn process_mouse_input(event: mouse::MouseEvent) {
    // Get current position after the movement
    let (x, y) = mouse::get_position();

    // Update cursor position and redraw
    cursor::set_cursor_pos(x, y);
    cursor::draw_cursor();

    // Check if we're dragging a window
    let dragging_hwnd = *DRAGGING_WINDOW.lock();
    let resizing_hwnd = *RESIZING_WINDOW.lock();

    // Check if we're dragging a desktop icon
    let icon_dragging = is_icon_dragging();

    if icon_dragging {
        // We're dragging a desktop icon
        if event.dx != 0 || event.dy != 0 {
            update_icon_drag(x, y);
        }
    } else if dragging_hwnd.is_valid() {
        // We're in window drag mode - handle window movement
        if event.dx != 0 || event.dy != 0 {
            handle_window_drag(x, y);
        }
    } else if resizing_hwnd.is_valid() {
        // We're in resize mode - handle window resizing
        if event.dx != 0 || event.dy != 0 {
            handle_window_resize(x, y);
        }
    } else {
        // Normal mouse movement
        if event.dx != 0 || event.dy != 0 {
            input::process_mouse_move(x, y);

            // Update cursor based on what we're hovering over
            update_cursor_for_position(x, y);
        }
    }

    // Process button clicks
    static mut LAST_LEFT: bool = false;
    static mut LAST_RIGHT: bool = false;
    static mut LAST_MIDDLE: bool = false;

    unsafe {
        // Left button
        if event.buttons.left != LAST_LEFT {
            let was_down = LAST_LEFT;
            LAST_LEFT = event.buttons.left;

            if event.buttons.left {
                // Button pressed
                input::process_mouse_button(0, true, x, y);

                // Check if icon context menu is visible - handle or dismiss
                if ICON_MENU_VISIBLE.load(Ordering::SeqCst) {
                    handle_icon_menu_click(x, y);
                    return;
                }

                // Check if desktop context menu is visible - handle or dismiss
                if DESKTOP_MENU_VISIBLE.load(Ordering::SeqCst) {
                    handle_desktop_menu_click(x, y);
                    return;
                }

                // Check for double-click
                let current_time = crate::hal::rtc::get_system_time() as u32;
                let last_time = LAST_CLICK_TIME.load(Ordering::SeqCst);
                let last_pos = *LAST_CLICK_POS.lock();

                let is_double_click = (current_time.wrapping_sub(last_time) < DOUBLE_CLICK_TIME)
                    && ((x - last_pos.x).abs() < DOUBLE_CLICK_DIST)
                    && ((y - last_pos.y).abs() < DOUBLE_CLICK_DIST);

                // Update last click info
                LAST_CLICK_TIME.store(current_time, Ordering::SeqCst);
                *LAST_CLICK_POS.lock() = Point::new(x, y);

                // Check if we clicked on taskbar first
                let (_, height) = super::super::gdi::surface::get_primary_dimensions();
                let taskbar_y = height as i32 - TASKBAR_HEIGHT;
                if y >= taskbar_y {
                    handle_taskbar_click(x, y);
                } else if START_MENU_VISIBLE.load(Ordering::SeqCst) {
                    // Click outside start menu - hide it
                    handle_start_menu_click(x, y);
                } else if is_double_click {
                    // Check for double-click on desktop icon first
                    if let Some(icon_idx) = get_icon_at_position(x, y) {
                        handle_desktop_icon_double_click(icon_idx);
                    } else {
                        // Check for double-click on window caption (maximize/restore)
                        try_caption_double_click(x, y);
                    }
                } else {
                    // Check if we clicked on a desktop icon (single click = select + start drag)
                    if let Some(icon_idx) = get_icon_at_position(x, y) {
                        select_desktop_icon(Some(icon_idx));
                        // Start icon drag
                        start_icon_drag(icon_idx, x, y);
                    } else {
                        // Clicked on desktop but not on icon - deselect
                        let hwnd = window::window_from_point(Point::new(x, y));
                        if !hwnd.is_valid() || hwnd == window::get_desktop_window() {
                            select_desktop_icon(None);
                        }
                        // Check if we clicked on a window caption
                        try_start_window_drag(x, y);
                    }
                }
            } else if was_down {
                // Button released
                input::process_mouse_button(0, false, x, y);

                // End any icon drag operation
                end_icon_drag();

                // End any window drag or resize operation
                end_window_drag();
                end_window_resize();
            }
        }

        // Right button
        if event.buttons.right != LAST_RIGHT {
            let was_down = LAST_RIGHT;
            LAST_RIGHT = event.buttons.right;
            input::process_mouse_button(1, event.buttons.right, x, y);

            // Handle right-click release for context menu
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

/// Handle double-click on window caption (maximize/restore)
fn try_caption_double_click(x: i32, y: i32) {
    // Find window at this position
    let hwnd = window::window_from_point(Point::new(x, y));
    if !hwnd.is_valid() {
        return;
    }

    // Perform hit test
    let lparam = ((y as isize) << 16) | ((x as isize) & 0xFFFF);
    let hit = message::send_message(hwnd, message::WM_NCHITTEST, 0, lparam);

    if hit == message::hittest::HTCAPTION {
        // Double-click on caption - toggle maximize/restore
        crate::serial_println!("[EXPLORER] Double-click on caption, toggling maximize");

        if let Some(wnd) = window::get_window(hwnd) {
            if wnd.maximized {
                message::send_message(hwnd, message::WM_SYSCOMMAND, message::syscmd::SC_RESTORE, 0);
            } else {
                message::send_message(hwnd, message::WM_SYSCOMMAND, message::syscmd::SC_MAXIMIZE, 0);
            }
        }
    }
}

/// Try to start window drag if clicked on caption
fn try_start_window_drag(x: i32, y: i32) {
    // Find window at this position
    let hwnd = window::window_from_point(Point::new(x, y));
    if !hwnd.is_valid() {
        return;
    }

    // Perform hit test
    let lparam = ((y as isize) << 16) | ((x as isize) & 0xFFFF);
    let hit = message::send_message(hwnd, message::WM_NCHITTEST, 0, lparam);

    match hit {
        message::hittest::HTCAPTION => {
            // Start dragging this window
            crate::serial_println!("[EXPLORER] Starting drag for window {:#x}", hwnd.raw());

            if let Some(wnd) = window::get_window(hwnd) {
                *DRAGGING_WINDOW.lock() = hwnd;
                *DRAG_START.lock() = Point::new(x, y);
                *DRAG_WINDOW_START.lock() = Point::new(wnd.rect.left, wnd.rect.top);
            }

            // Bring window to front
            window::set_foreground_window(hwnd);
            input::set_active_window(hwnd);

            // Repaint taskbar to show active state
            paint_taskbar();
        }
        message::hittest::HTCLOSE | message::hittest::HTMINBUTTON | message::hittest::HTMAXBUTTON => {
            // Caption button clicked - send NC button down message
            message::send_message(hwnd, message::WM_NCLBUTTONDOWN, hit as usize, lparam);
        }
        message::hittest::HTCLIENT => {
            // Client area clicked - activate window
            window::set_foreground_window(hwnd);
            input::set_active_window(hwnd);

            // Repaint taskbar to show active state
            paint_taskbar();
        }
        // Handle resize edges
        message::hittest::HTLEFT | message::hittest::HTRIGHT |
        message::hittest::HTTOP | message::hittest::HTBOTTOM |
        message::hittest::HTTOPLEFT | message::hittest::HTTOPRIGHT |
        message::hittest::HTBOTTOMLEFT | message::hittest::HTBOTTOMRIGHT => {
            // Start resizing this window
            crate::serial_println!("[EXPLORER] Starting resize for window {:#x}, edge={}", hwnd.raw(), hit);

            if let Some(wnd) = window::get_window(hwnd) {
                *RESIZING_WINDOW.lock() = hwnd;
                *RESIZE_EDGE.lock() = hit;
                *RESIZE_START.lock() = Point::new(x, y);
                *RESIZE_WINDOW_RECT.lock() = wnd.rect;
            }

            // Bring window to front
            window::set_foreground_window(hwnd);
            input::set_active_window(hwnd);
            paint_taskbar();
        }
        _ => {}
    }
}

/// Handle window drag movement
fn handle_window_drag(x: i32, y: i32) {
    let hwnd = *DRAGGING_WINDOW.lock();
    if !hwnd.is_valid() {
        return;
    }

    let drag_start = *DRAG_START.lock();
    let window_start = *DRAG_WINDOW_START.lock();

    // Calculate delta
    let dx = x - drag_start.x;
    let dy = y - drag_start.y;

    // Calculate new window position
    let new_x = window_start.x + dx;
    let new_y = window_start.y + dy;

    // Get current window size
    if let Some(wnd) = window::get_window(hwnd) {
        let width = wnd.rect.width();
        let height = wnd.rect.height();

        // Clamp to screen bounds (allow some off-screen but keep title bar visible)
        let (_, screen_h) = super::super::gdi::surface::get_primary_dimensions();
        let min_y = 0;
        let max_y = screen_h as i32 - TASKBAR_HEIGHT - 20; // Keep caption visible

        let clamped_y = new_y.max(min_y).min(max_y);

        // Move window
        window::move_window(hwnd, new_x, clamped_y, width, height, true);

        // Repaint everything
        super::paint::repaint_all();
        paint_taskbar();

        // Redraw cursor on top
        cursor::draw_cursor();
    }
}

/// End window drag operation
fn end_window_drag() {
    let hwnd = {
        let mut dragging = DRAGGING_WINDOW.lock();
        let h = *dragging;
        *dragging = HWND::NULL;
        h
    };

    if hwnd.is_valid() {
        crate::serial_println!("[EXPLORER] Ended drag for window {:#x}", hwnd.raw());

        // Final repaint
        super::paint::repaint_all();
        paint_taskbar();
    }
}

/// Handle window resize movement
fn handle_window_resize(x: i32, y: i32) {
    let hwnd = *RESIZING_WINDOW.lock();
    if !hwnd.is_valid() {
        return;
    }

    let edge = *RESIZE_EDGE.lock();
    let resize_start = *RESIZE_START.lock();
    let original_rect = *RESIZE_WINDOW_RECT.lock();

    // Calculate delta from start
    let dx = x - resize_start.x;
    let dy = y - resize_start.y;

    // Calculate new rect based on which edge is being dragged
    let mut new_rect = original_rect;

    match edge {
        message::hittest::HTLEFT => {
            new_rect.left = original_rect.left + dx;
        }
        message::hittest::HTRIGHT => {
            new_rect.right = original_rect.right + dx;
        }
        message::hittest::HTTOP => {
            new_rect.top = original_rect.top + dy;
        }
        message::hittest::HTBOTTOM => {
            new_rect.bottom = original_rect.bottom + dy;
        }
        message::hittest::HTTOPLEFT => {
            new_rect.left = original_rect.left + dx;
            new_rect.top = original_rect.top + dy;
        }
        message::hittest::HTTOPRIGHT => {
            new_rect.right = original_rect.right + dx;
            new_rect.top = original_rect.top + dy;
        }
        message::hittest::HTBOTTOMLEFT => {
            new_rect.left = original_rect.left + dx;
            new_rect.bottom = original_rect.bottom + dy;
        }
        message::hittest::HTBOTTOMRIGHT => {
            new_rect.right = original_rect.right + dx;
            new_rect.bottom = original_rect.bottom + dy;
        }
        _ => return,
    }

    // Enforce minimum window size
    if new_rect.width() < MIN_WINDOW_WIDTH {
        if edge == message::hittest::HTLEFT ||
           edge == message::hittest::HTTOPLEFT ||
           edge == message::hittest::HTBOTTOMLEFT {
            new_rect.left = new_rect.right - MIN_WINDOW_WIDTH;
        } else {
            new_rect.right = new_rect.left + MIN_WINDOW_WIDTH;
        }
    }
    if new_rect.height() < MIN_WINDOW_HEIGHT {
        if edge == message::hittest::HTTOP ||
           edge == message::hittest::HTTOPLEFT ||
           edge == message::hittest::HTTOPRIGHT {
            new_rect.top = new_rect.bottom - MIN_WINDOW_HEIGHT;
        } else {
            new_rect.bottom = new_rect.top + MIN_WINDOW_HEIGHT;
        }
    }

    // Apply new size
    window::move_window(
        hwnd,
        new_rect.left,
        new_rect.top,
        new_rect.width(),
        new_rect.height(),
        true,
    );

    // Repaint everything
    super::paint::repaint_all();
    paint_taskbar();

    // Redraw cursor on top
    cursor::draw_cursor();
}

/// End window resize operation
fn end_window_resize() {
    let hwnd = {
        let mut resizing = RESIZING_WINDOW.lock();
        let h = *resizing;
        *resizing = HWND::NULL;
        h
    };

    if hwnd.is_valid() {
        crate::serial_println!("[EXPLORER] Ended resize for window {:#x}", hwnd.raw());

        // Clear resize edge
        *RESIZE_EDGE.lock() = 0;

        // Final repaint
        super::paint::repaint_all();
        paint_taskbar();
    }
}

/// Check if we're currently resizing a window
fn is_resizing() -> bool {
    RESIZING_WINDOW.lock().is_valid()
}

/// Update cursor based on what we're hovering over
fn update_cursor_for_position(x: i32, y: i32) {
    // Don't change cursor if we're dragging or resizing
    if DRAGGING_WINDOW.lock().is_valid() || RESIZING_WINDOW.lock().is_valid() {
        return;
    }

    // Check if we're over the taskbar
    let (_, height) = super::super::gdi::surface::get_primary_dimensions();
    let taskbar_y = height as i32 - TASKBAR_HEIGHT;
    if y >= taskbar_y {
        cursor::set_cursor(cursor::StandardCursor::Arrow);
        return;
    }

    // Find window at this position
    let hwnd = window::window_from_point(Point::new(x, y));
    if !hwnd.is_valid() {
        cursor::set_cursor(cursor::StandardCursor::Arrow);
        return;
    }

    // Perform hit test
    let lparam = ((y as isize) << 16) | ((x as isize) & 0xFFFF);
    let hit = message::send_message(hwnd, message::WM_NCHITTEST, 0, lparam);

    // Set cursor based on hit test result
    let new_cursor = match hit {
        message::hittest::HTLEFT | message::hittest::HTRIGHT => cursor::StandardCursor::SizeWE,
        message::hittest::HTTOP | message::hittest::HTBOTTOM => cursor::StandardCursor::SizeNS,
        message::hittest::HTTOPLEFT | message::hittest::HTBOTTOMRIGHT => cursor::StandardCursor::SizeNWSE,
        message::hittest::HTTOPRIGHT | message::hittest::HTBOTTOMLEFT => cursor::StandardCursor::SizeNESW,
        message::hittest::HTCLIENT => cursor::StandardCursor::Arrow, // Could be IBeam for text
        _ => cursor::StandardCursor::Arrow,
    };

    cursor::set_cursor(new_cursor);
}

// ============================================================================
// Right-Click Context Menu
// ============================================================================

/// Desktop context menu visible flag
static DESKTOP_MENU_VISIBLE: AtomicBool = AtomicBool::new(false);

/// Desktop context menu position
static DESKTOP_MENU_POS: SpinLock<Point> = SpinLock::new(Point::new(0, 0));

/// Desktop context menu items (background)
const DESKTOP_MENU_ITEMS: [&str; 6] = [
    "Refresh",
    "─────────────",
    "Paste",
    "Paste Shortcut",
    "─────────────",
    "Properties",
];

/// Icon context menu items
const ICON_MENU_ITEMS: [&str; 7] = [
    "Open",
    "Explore",
    "─────────────",
    "Cut",
    "Copy",
    "─────────────",
    "Properties",
];

/// Icon context menu visible flag
static ICON_MENU_VISIBLE: AtomicBool = AtomicBool::new(false);

/// Icon context menu position
static ICON_MENU_POS: SpinLock<Point> = SpinLock::new(Point::new(0, 0));

/// Icon context menu target (which icon was right-clicked)
static ICON_MENU_TARGET: SpinLock<Option<usize>> = SpinLock::new(None);

/// Desktop menu item height
const MENU_ITEM_HEIGHT: i32 = 20;
const MENU_WIDTH: i32 = 150;

/// Handle right-click
fn handle_right_click(x: i32, y: i32) {
    // Check if on taskbar - no context menu there for now
    let (_, height) = super::super::gdi::surface::get_primary_dimensions();
    let taskbar_y = height as i32 - TASKBAR_HEIGHT;
    if y >= taskbar_y {
        return;
    }

    // Check if right-clicked on a desktop icon
    if let Some(icon_idx) = get_icon_at_position(x, y) {
        // Select the icon and show icon context menu
        select_desktop_icon(Some(icon_idx));
        show_icon_context_menu(x, y, icon_idx);
        return;
    }

    // Check if we clicked on a window
    let hwnd = window::window_from_point(Point::new(x, y));

    // If clicked on desktop (no window or desktop window), show desktop context menu
    let desktop_hwnd = *DESKTOP_HWND.lock();
    if !hwnd.is_valid() || hwnd == desktop_hwnd {
        show_desktop_context_menu(x, y);
    }
}

/// Show desktop context menu
fn show_desktop_context_menu(x: i32, y: i32) {
    // Hide start menu if visible
    if START_MENU_VISIBLE.load(Ordering::SeqCst) {
        toggle_start_menu();
    }

    // Store menu position
    *DESKTOP_MENU_POS.lock() = Point::new(x, y);
    DESKTOP_MENU_VISIBLE.store(true, Ordering::SeqCst);

    // Paint the context menu
    paint_desktop_context_menu(x, y);
}

/// Paint the desktop context menu
fn paint_desktop_context_menu(x: i32, y: i32) {
    if let Ok(hdc) = dc::create_display_dc() {
        let menu_height = (DESKTOP_MENU_ITEMS.len() as i32) * MENU_ITEM_HEIGHT + 4;
        let menu_rect = Rect::new(x, y, x + MENU_WIDTH, y + menu_height);

        // Get surface
        let surface_handle = dc::get_dc_surface(hdc);
        if let Some(surf) = super::super::gdi::surface::get_surface(surface_handle) {
            // Draw menu background
            surf.fill_rect(&menu_rect, ColorRef::WINDOW_BG);

            // Draw 3D raised border
            // Top highlight
            surf.hline(menu_rect.left, menu_rect.right - 1, menu_rect.top, ColorRef::WHITE);
            surf.hline(menu_rect.left + 1, menu_rect.right - 2, menu_rect.top + 1, ColorRef::WHITE);
            // Left highlight
            surf.vline(menu_rect.left, menu_rect.top, menu_rect.bottom - 1, ColorRef::WHITE);
            surf.vline(menu_rect.left + 1, menu_rect.top + 1, menu_rect.bottom - 2, ColorRef::WHITE);
            // Bottom shadow
            surf.hline(menu_rect.left, menu_rect.right, menu_rect.bottom - 1, ColorRef::DARK_GRAY);
            surf.hline(menu_rect.left + 1, menu_rect.right - 1, menu_rect.bottom - 2, ColorRef::GRAY);
            // Right shadow
            surf.vline(menu_rect.right - 1, menu_rect.top, menu_rect.bottom, ColorRef::DARK_GRAY);
            surf.vline(menu_rect.right - 2, menu_rect.top + 1, menu_rect.bottom - 1, ColorRef::GRAY);

            // Draw menu items
            let mut item_y = y + 2;
            for item in DESKTOP_MENU_ITEMS.iter() {
                if item.starts_with('─') {
                    // Separator line
                    let sep_y = item_y + MENU_ITEM_HEIGHT / 2;
                    surf.hline(x + 2, x + MENU_WIDTH - 2, sep_y, ColorRef::GRAY);
                    surf.hline(x + 2, x + MENU_WIDTH - 2, sep_y + 1, ColorRef::WHITE);
                } else {
                    // Regular item
                    dc::set_text_color(hdc, ColorRef::BLACK);
                    super::super::gdi::draw::gdi_text_out(hdc, x + 20, item_y + 2, item);
                }
                item_y += MENU_ITEM_HEIGHT;
            }
        }

        dc::delete_dc(hdc);
    }
}

/// Handle click on desktop context menu
fn handle_desktop_menu_click(x: i32, y: i32) -> bool {
    if !DESKTOP_MENU_VISIBLE.load(Ordering::SeqCst) {
        return false;
    }

    let menu_pos = *DESKTOP_MENU_POS.lock();
    let menu_height = (DESKTOP_MENU_ITEMS.len() as i32) * MENU_ITEM_HEIGHT + 4;
    let menu_rect = Rect::new(
        menu_pos.x,
        menu_pos.y,
        menu_pos.x + MENU_WIDTH,
        menu_pos.y + menu_height,
    );

    // Check if click is inside menu
    if x >= menu_rect.left && x < menu_rect.right &&
       y >= menu_rect.top && y < menu_rect.bottom {
        // Determine which item was clicked
        let relative_y = y - menu_rect.top - 2;
        let item_index = (relative_y / MENU_ITEM_HEIGHT) as usize;

        if item_index < DESKTOP_MENU_ITEMS.len() {
            let item = DESKTOP_MENU_ITEMS[item_index];
            if !item.starts_with('─') {
                // Execute action
                match item {
                    "Refresh" => {
                        // Repaint desktop
                        super::paint::repaint_all();
                        paint_taskbar();
                    }
                    "Properties" => {
                        // Could show display properties
                        crate::serial_println!("[EXPLORER] Display Properties clicked");
                    }
                    _ => {}
                }
            }
        }

        // Hide menu
        hide_desktop_context_menu();
        return true;
    }

    // Click outside menu - hide it
    hide_desktop_context_menu();
    false
}

/// Hide desktop context menu
fn hide_desktop_context_menu() {
    if DESKTOP_MENU_VISIBLE.load(Ordering::SeqCst) {
        DESKTOP_MENU_VISIBLE.store(false, Ordering::SeqCst);
        // Invalidate cursor background so it doesn't restore menu pixels
        super::cursor::invalidate_cursor_background();
        // Repaint to clear menu
        super::paint::repaint_all();
        paint_taskbar();
        // Redraw cursor with fresh background
        super::cursor::draw_cursor();
    }
}

/// Check if context menu is visible
pub fn is_context_menu_visible() -> bool {
    DESKTOP_MENU_VISIBLE.load(Ordering::SeqCst) || ICON_MENU_VISIBLE.load(Ordering::SeqCst)
}

/// Show icon context menu
fn show_icon_context_menu(x: i32, y: i32, icon_idx: usize) {
    // Hide any other menus
    if START_MENU_VISIBLE.load(Ordering::SeqCst) {
        toggle_start_menu();
    }
    hide_desktop_context_menu();

    // Store menu position and target
    *ICON_MENU_POS.lock() = Point::new(x, y);
    *ICON_MENU_TARGET.lock() = Some(icon_idx);
    ICON_MENU_VISIBLE.store(true, Ordering::SeqCst);

    // Paint the icon context menu
    paint_icon_context_menu(x, y);
}

/// Paint the icon context menu
fn paint_icon_context_menu(x: i32, y: i32) {
    if let Ok(hdc) = dc::create_display_dc() {
        let menu_height = (ICON_MENU_ITEMS.len() as i32) * MENU_ITEM_HEIGHT + 4;
        let menu_rect = Rect::new(x, y, x + MENU_WIDTH, y + menu_height);

        // Get surface
        let surface_handle = dc::get_dc_surface(hdc);
        if let Some(surf) = super::super::gdi::surface::get_surface(surface_handle) {
            // Draw menu background
            surf.fill_rect(&menu_rect, ColorRef::WINDOW_BG);

            // Draw 3D raised border
            surf.hline(menu_rect.left, menu_rect.right - 1, menu_rect.top, ColorRef::WHITE);
            surf.hline(menu_rect.left + 1, menu_rect.right - 2, menu_rect.top + 1, ColorRef::WHITE);
            surf.vline(menu_rect.left, menu_rect.top, menu_rect.bottom - 1, ColorRef::WHITE);
            surf.vline(menu_rect.left + 1, menu_rect.top + 1, menu_rect.bottom - 2, ColorRef::WHITE);
            surf.hline(menu_rect.left, menu_rect.right, menu_rect.bottom - 1, ColorRef::DARK_GRAY);
            surf.hline(menu_rect.left + 1, menu_rect.right - 1, menu_rect.bottom - 2, ColorRef::GRAY);
            surf.vline(menu_rect.right - 1, menu_rect.top, menu_rect.bottom, ColorRef::DARK_GRAY);
            surf.vline(menu_rect.right - 2, menu_rect.top + 1, menu_rect.bottom - 1, ColorRef::GRAY);

            // Draw menu items
            let mut item_y = y + 2;
            for (i, item) in ICON_MENU_ITEMS.iter().enumerate() {
                if item.starts_with('─') {
                    // Separator line
                    let sep_y = item_y + MENU_ITEM_HEIGHT / 2;
                    surf.hline(x + 2, x + MENU_WIDTH - 2, sep_y, ColorRef::GRAY);
                    surf.hline(x + 2, x + MENU_WIDTH - 2, sep_y + 1, ColorRef::WHITE);
                } else {
                    // Regular item - bold the first item ("Open")
                    if i == 0 {
                        dc::set_text_color(hdc, ColorRef::BLACK);
                        // Draw text twice offset for bold effect
                        super::super::gdi::draw::gdi_text_out(hdc, x + 20, item_y + 2, item);
                        super::super::gdi::draw::gdi_text_out(hdc, x + 21, item_y + 2, item);
                    } else {
                        dc::set_text_color(hdc, ColorRef::BLACK);
                        super::super::gdi::draw::gdi_text_out(hdc, x + 20, item_y + 2, item);
                    }
                }
                item_y += MENU_ITEM_HEIGHT;
            }
        }

        dc::delete_dc(hdc);
    }
}

/// Handle click on icon context menu
fn handle_icon_menu_click(x: i32, y: i32) -> bool {
    if !ICON_MENU_VISIBLE.load(Ordering::SeqCst) {
        return false;
    }

    let menu_pos = *ICON_MENU_POS.lock();
    let target_icon = *ICON_MENU_TARGET.lock();
    let menu_height = (ICON_MENU_ITEMS.len() as i32) * MENU_ITEM_HEIGHT + 4;
    let menu_rect = Rect::new(
        menu_pos.x,
        menu_pos.y,
        menu_pos.x + MENU_WIDTH,
        menu_pos.y + menu_height,
    );

    // Check if click is inside menu
    if x >= menu_rect.left && x < menu_rect.right &&
       y >= menu_rect.top && y < menu_rect.bottom {
        // Determine which item was clicked
        let relative_y = y - menu_rect.top - 2;
        let item_index = (relative_y / MENU_ITEM_HEIGHT) as usize;

        if item_index < ICON_MENU_ITEMS.len() {
            let item = ICON_MENU_ITEMS[item_index];
            if !item.starts_with('─') {
                // Execute action
                match item {
                    "Open" => {
                        if let Some(idx) = target_icon {
                            handle_desktop_icon_double_click(idx);
                        }
                    }
                    "Explore" => {
                        if let Some(idx) = target_icon {
                            handle_desktop_icon_double_click(idx);
                        }
                    }
                    "Properties" => {
                        if let Some(idx) = target_icon {
                            let name = {
                                let state = DESKTOP_ICONS.lock();
                                if state.icons[idx].valid {
                                    Some(state.icons[idx].name)
                                } else {
                                    None
                                }
                            };
                            if let Some(n) = name {
                                crate::serial_println!("[EXPLORER] Properties for: {}", n);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Hide menu
        hide_icon_context_menu();
        return true;
    }

    // Click outside menu - hide it
    hide_icon_context_menu();
    false
}

/// Hide icon context menu
fn hide_icon_context_menu() {
    if ICON_MENU_VISIBLE.load(Ordering::SeqCst) {
        ICON_MENU_VISIBLE.store(false, Ordering::SeqCst);
        *ICON_MENU_TARGET.lock() = None;
        super::cursor::invalidate_cursor_background();
        super::paint::repaint_all();
        paint_taskbar();
        super::cursor::draw_cursor();
    }
}

/// Handle click on the taskbar
fn handle_taskbar_click(x: i32, y: i32) {
    let (_, height) = super::super::gdi::surface::get_primary_dimensions();
    let taskbar_y = height as i32 - TASKBAR_HEIGHT;

    // Check if click is on taskbar
    if y < taskbar_y {
        return;
    }

    let state = TASKBAR_STATE.lock();

    // Check Start button
    if x >= state.start_rect.left && x < state.start_rect.right {
        drop(state);
        toggle_start_menu();
        return;
    }

    // Check clock area
    let (width, _) = super::super::gdi::surface::get_primary_dimensions();
    let clock_x_start = width as i32 - 60;
    if x >= clock_x_start {
        drop(state);
        show_date_tooltip();
        return;
    }

    // Check taskbar buttons
    for button in state.buttons.iter() {
        if !button.valid {
            continue;
        }

        if x >= button.rect.left && x < button.rect.right {
            // Get window handle and current state
            let hwnd = button.hwnd;
            drop(state);

            // Check if this window is already active and visible (not minimized)
            let is_active = input::get_active_window() == hwnd;
            let is_minimized = window::get_window(hwnd)
                .map(|w| w.minimized)
                .unwrap_or(false);

            if is_active && !is_minimized {
                // Already active and visible - minimize it
                message::send_message(hwnd, message::WM_SYSCOMMAND, message::syscmd::SC_MINIMIZE, 0);
            } else {
                // Activate and restore/show the window
                if is_minimized {
                    message::send_message(hwnd, message::WM_SYSCOMMAND, message::syscmd::SC_RESTORE, 0);
                } else {
                    window::show_window(hwnd, ShowCommand::Show);
                }
                input::set_active_window(hwnd);
                window::set_foreground_window(hwnd);
                super::paint::repaint_all();
            }

            // Repaint taskbar to show active state
            paint_taskbar();
            return;
        }
    }
}

/// Process keyboard input from scancode
fn process_keyboard_input(scancode: u8) {
    // Check for key release (high bit set)
    let pressed = (scancode & 0x80) == 0;
    let code = scancode & 0x7F;

    // Check modifier key states
    let ctrl_down = (input::get_key_state(input::vk::CONTROL) & (-32768i16)) != 0;
    let alt_down = (input::get_key_state(input::vk::MENU) & (-32768i16)) != 0;

    // Handle Ctrl+Alt+Delete (SAS - Secure Attention Sequence)
    // Delete key scancode is 0x53
    if pressed && code == 0x53 && ctrl_down && alt_down {
        handle_ctrl_alt_del();
        return;
    }

    // Handle Alt+Tab
    if pressed && code == 0x0F { // Tab scancode
        if alt_down {
            handle_alt_tab();
            return;
        }
    }

    // Handle Alt key release during Alt+Tab
    if !pressed && code == 0x38 { // Alt scancode
        if ALT_TAB_ACTIVE.load(Ordering::SeqCst) {
            finish_alt_tab();
            return;
        }
    }

    // Route to input system
    input::process_key_event(code, pressed);
}

/// Handle Ctrl+Alt+Delete (Secure Attention Sequence)
fn handle_ctrl_alt_del() {
    crate::serial_println!("[EXPLORER] Ctrl+Alt+Del pressed - signaling SAS");

    // Signal SAS to Winlogon
    winlogon::signal_sas(winlogon::SasType::CtrlAltDel);

    // Process the SAS immediately
    winlogon::process_sas();
}

/// Process all pending messages
fn process_messages() {
    // Process up to 10 messages per iteration to prevent starvation
    for _ in 0..10 {
        let msg = message::get_message(HWND::NULL);
        if let Some(m) = msg {
            // Check for quit message
            if m.message == message::WM_QUIT {
                SHELL_RUNNING.store(false, Ordering::SeqCst);
                return;
            }

            // Translate and dispatch
            message::translate_message(&m);
            message::dispatch_message(&m);
        } else {
            break;
        }
    }
}

/// Process paint requests for dirty windows
fn process_paint_requests() {
    // Get list of windows that need painting
    let dirty_windows = window::get_dirty_windows();

    for hwnd in dirty_windows.iter() {
        if hwnd.is_valid() {
            // Paint the window frame
            super::paint::draw_window_frame(*hwnd);

            // Paint client content based on window class
            paint_window_client(*hwnd);

            // Clear the needs_paint flag
            window::with_window_mut(*hwnd, |wnd| {
                wnd.needs_paint = false;
            });
        }
    }
}

/// Paint window client area based on window class and type
fn paint_window_client(hwnd: HWND) {
    if let Some(wnd) = window::get_window(hwnd) {
        // Get window class name as string
        let class_name = core::str::from_utf8(&wnd.class_name)
            .unwrap_or("")
            .trim_end_matches('\0');

        // Get window title as string
        let title = core::str::from_utf8(&wnd.title[..wnd.title_len.min(64)])
            .unwrap_or("");

        // Paint based on window class
        match class_name {
            "EXPLORER_WINDOW" => paint_explorer_window_client(hwnd, title),
            "TestWindow" => paint_test_window_client(hwnd),
            "Desktop" => {
                // Desktop is painted separately by paint_desktop(), skip it here
            }
            _ => {
                // Unknown window class - just fill with white
                if let Ok(hdc) = dc::create_display_dc() {
                    let surface_handle = dc::get_dc_surface(hdc);
                    if let Some(surf) = super::super::gdi::surface::get_surface(surface_handle) {
                        let client_rect = Rect::new(
                            wnd.client_rect.left + wnd.rect.left,
                            wnd.client_rect.top + wnd.rect.top,
                            wnd.client_rect.right + wnd.rect.left,
                            wnd.client_rect.bottom + wnd.rect.top,
                        );
                        surf.fill_rect(&client_rect, ColorRef::WHITE);
                    }
                    dc::delete_dc(hdc);
                }
            }
        }
    }
}

/// Paint Explorer window client area (My Computer, My Documents, etc.)
fn paint_explorer_window_client(hwnd: HWND, title: &str) {
    if let Some(wnd) = window::get_window(hwnd) {
        if let Ok(hdc) = dc::create_display_dc() {
            let surface_handle = dc::get_dc_surface(hdc);
            if let Some(surf) = super::super::gdi::surface::get_surface(surface_handle) {
                // Calculate client area in screen coordinates
                let client_rect = Rect::new(
                    wnd.client_rect.left + wnd.rect.left,
                    wnd.client_rect.top + wnd.rect.top,
                    wnd.client_rect.right + wnd.rect.left,
                    wnd.client_rect.bottom + wnd.rect.top,
                );

                // Fill with white background
                surf.fill_rect(&client_rect, ColorRef::WHITE);

                // Paint content based on title
                if title.starts_with("My Computer") {
                    paint_my_computer_content(&surf, hdc, &client_rect);
                } else if title.starts_with("Recycle Bin") {
                    dc::set_text_color(hdc, ColorRef::BLACK);
                    dc::set_bk_mode(hdc, dc::BkMode::Transparent);
                    super::super::gdi::text_out(hdc, client_rect.left + 20, client_rect.top + 20,
                        "Recycle Bin is empty");
                } else if title.starts_with("My Documents") {
                    dc::set_text_color(hdc, ColorRef::BLACK);
                    dc::set_bk_mode(hdc, dc::BkMode::Transparent);
                    super::super::gdi::text_out(hdc, client_rect.left + 20, client_rect.top + 20,
                        "My Documents");
                    super::super::gdi::text_out(hdc, client_rect.left + 20, client_rect.top + 40,
                        "Your personal documents");
                } else if title.starts_with("Network Places") {
                    dc::set_text_color(hdc, ColorRef::BLACK);
                    dc::set_bk_mode(hdc, dc::BkMode::Transparent);
                    super::super::gdi::text_out(hdc, client_rect.left + 20, client_rect.top + 20,
                        "Network Places");
                    super::super::gdi::text_out(hdc, client_rect.left + 20, client_rect.top + 40,
                        "Network resources");
                }
            }
            dc::delete_dc(hdc);
        }
    }
}

/// Paint My Computer window content showing drives
fn paint_my_computer_content(surf: &super::super::gdi::surface::Surface, hdc: HDC, client_rect: &Rect) {
    // Draw drive list
    let drives = [
        ("C:", "Local Disk"),
        ("D:", "CD-ROM Drive"),
    ];

    let mut y = client_rect.top + 30;

    dc::set_text_color(hdc, ColorRef::BLACK);
    dc::set_bk_mode(hdc, dc::BkMode::Transparent);

    for (letter, label) in drives.iter() {
        let icon_x = client_rect.left + 30;

        // Draw hard drive icon
        surf.fill_rect(&Rect::new(icon_x, y, icon_x + 32, y + 24), ColorRef::rgb(192, 192, 192));
        surf.fill_rect(&Rect::new(icon_x + 2, y + 2, icon_x + 30, y + 6), ColorRef::rgb(0, 128, 0));
        surf.hline(icon_x, icon_x + 32, y + 12, ColorRef::GRAY);

        // Draw drive letter and label
        super::super::gdi::text_out(hdc, icon_x + 40, y, letter);
        super::super::gdi::text_out(hdc, icon_x + 70, y, label);

        y += 40;
    }
}

// ============================================================================
// Desktop Painting
// ============================================================================

/// Paint the desktop background
pub fn paint_desktop() {
    let hwnd = *DESKTOP_HWND.lock();
    if !hwnd.is_valid() {
        return;
    }

    if let Ok(hdc) = dc::create_display_dc() {
        let (width, height) = super::super::gdi::surface::get_primary_dimensions();
        let height = height as i32 - TASKBAR_HEIGHT;

        // Fill with classic Windows desktop teal color
        let desktop_rect = Rect::new(0, 0, width as i32, height);
        let bg_brush = brush::create_solid_brush(ColorRef::DESKTOP);
        super::super::gdi::fill_rect(hdc, &desktop_rect, bg_brush);

        // Draw desktop icons
        paint_desktop_icons(hdc);

        dc::delete_dc(hdc);
    }
}

// ============================================================================
// Desktop Icons
// ============================================================================

/// Desktop icon size (32x32 pixels)
const ICON_SIZE: i32 = 32;

/// Grid cell spacing - matches Windows XP default icon spacing
/// SM_CXICONSPACING = 75, SM_CYICONSPACING = 75
const ICON_GRID_X: i32 = 75;
const ICON_GRID_Y: i32 = 75;

/// Margin from desktop edges
const ICON_MARGIN_X: i32 = 10;
const ICON_MARGIN_Y: i32 = 10;

/// Maximum number of desktop icons
const MAX_DESKTOP_ICONS: usize = 64;

/// Icon types for different desktop items
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IconType {
    MyComputer,
    RecycleBin,
    MyDocuments,
    NetworkPlaces,
}

/// Desktop icon instance with position
#[derive(Clone, Copy)]
struct DesktopIconInstance {
    /// Icon is valid/active
    valid: bool,
    /// Icon name
    name: &'static str,
    /// Icon type (determines appearance)
    icon_type: IconType,
    /// Grid position (column, row) - NOT pixel position
    grid_x: i32,
    grid_y: i32,
}

impl DesktopIconInstance {
    const fn empty() -> Self {
        Self {
            valid: false,
            name: "",
            icon_type: IconType::MyComputer,
            grid_x: 0,
            grid_y: 0,
        }
    }

    /// Get pixel position from grid position
    fn get_pixel_pos(&self) -> (i32, i32) {
        let px = ICON_MARGIN_X + self.grid_x * ICON_GRID_X + (ICON_GRID_X - ICON_SIZE) / 2;
        let py = ICON_MARGIN_Y + self.grid_y * ICON_GRID_Y;
        (px, py)
    }

    /// Get bounding rectangle for hit testing
    fn get_bounds(&self) -> Rect {
        let (px, py) = self.get_pixel_pos();
        // Include icon + label area
        Rect::new(
            px - 10,
            py - 2,
            px + ICON_SIZE + 10,
            py + ICON_SIZE + 20,
        )
    }
}

/// Desktop icons state
struct DesktopIconsState {
    /// All desktop icons
    icons: [DesktopIconInstance; MAX_DESKTOP_ICONS],
    /// Number of active icons
    count: usize,
    /// Currently selected icon index (None = no selection)
    selected: Option<usize>,
    /// Icon being dragged (None = not dragging)
    dragging: Option<usize>,
    /// Drag start position (mouse)
    drag_start_mouse: Point,
    /// Drag start position (icon grid)
    drag_start_grid: (i32, i32),
}

impl DesktopIconsState {
    const fn new() -> Self {
        Self {
            icons: [const { DesktopIconInstance::empty() }; MAX_DESKTOP_ICONS],
            count: 0,
            selected: None,
            dragging: None,
            drag_start_mouse: Point::new(0, 0),
            drag_start_grid: (0, 0),
        }
    }
}

static DESKTOP_ICONS: SpinLock<DesktopIconsState> = SpinLock::new(DesktopIconsState::new());

/// Initialize desktop icons
fn init_desktop_icons() {
    let mut state = DESKTOP_ICONS.lock();

    // Create default icons in vertical column on left side
    let default_icons = [
        ("My Computer", IconType::MyComputer, 0, 0),
        ("My Documents", IconType::MyDocuments, 0, 1),
        ("Recycle Bin", IconType::RecycleBin, 0, 2),
        ("Network Places", IconType::NetworkPlaces, 0, 3),
    ];

    for (i, (name, icon_type, gx, gy)) in default_icons.iter().enumerate() {
        state.icons[i] = DesktopIconInstance {
            valid: true,
            name,
            icon_type: *icon_type,
            grid_x: *gx,
            grid_y: *gy,
        };
    }
    state.count = default_icons.len();
}

/// Snap a pixel position to the nearest grid cell
fn snap_to_grid(px: i32, py: i32) -> (i32, i32) {
    // Calculate grid position from pixel position
    let gx = ((px - ICON_MARGIN_X + ICON_GRID_X / 2) / ICON_GRID_X).max(0);
    let gy = ((py - ICON_MARGIN_Y + ICON_GRID_Y / 2) / ICON_GRID_Y).max(0);

    // Clamp to valid grid range
    let (width, height) = super::super::gdi::surface::get_primary_dimensions();
    let max_gx = ((width as i32 - ICON_MARGIN_X * 2) / ICON_GRID_X).max(0);
    let max_gy = ((height as i32 - TASKBAR_HEIGHT - ICON_MARGIN_Y * 2) / ICON_GRID_Y).max(0);

    (gx.min(max_gx), gy.min(max_gy))
}

/// Check if a grid position is occupied by another icon (caller must hold lock)
fn is_grid_occupied_locked(state: &DesktopIconsState, gx: i32, gy: i32, exclude_idx: Option<usize>) -> bool {
    for (i, icon) in state.icons.iter().enumerate() {
        if !icon.valid {
            continue;
        }
        if let Some(exclude) = exclude_idx {
            if i == exclude {
                continue;
            }
        }
        if icon.grid_x == gx && icon.grid_y == gy {
            return true;
        }
    }
    false
}

/// Find nearest free grid position (caller must hold lock)
fn find_free_grid_pos_locked(state: &DesktopIconsState, preferred_gx: i32, preferred_gy: i32, exclude_idx: Option<usize>) -> (i32, i32) {
    // Try preferred position first
    if !is_grid_occupied_locked(state, preferred_gx, preferred_gy, exclude_idx) {
        return (preferred_gx, preferred_gy);
    }

    // Search in expanding squares around preferred position
    let (width, height) = super::super::gdi::surface::get_primary_dimensions();
    let max_gx = ((width as i32 - ICON_MARGIN_X * 2) / ICON_GRID_X).max(0);
    let max_gy = ((height as i32 - TASKBAR_HEIGHT - ICON_MARGIN_Y * 2) / ICON_GRID_Y).max(0);

    for radius in 1i32..20 {
        for dy in -radius..=radius {
            for dx in -radius..=radius {
                if dx.abs() != radius && dy.abs() != radius {
                    continue; // Only check perimeter
                }
                let gx = preferred_gx + dx;
                let gy = preferred_gy + dy;
                if gx >= 0 && gx <= max_gx && gy >= 0 && gy <= max_gy {
                    if !is_grid_occupied_locked(state, gx, gy, exclude_idx) {
                        return (gx, gy);
                    }
                }
            }
        }
    }

    // Fallback to original position
    (preferred_gx, preferred_gy)
}

/// Select a desktop icon
fn select_desktop_icon(idx: Option<usize>) {
    let current = {
        let state = DESKTOP_ICONS.lock();
        state.selected
    };
    if current != idx {
        DESKTOP_ICONS.lock().selected = idx;
        // Repaint desktop to show selection
        paint_desktop();
    }
}

/// Paint desktop icons
fn paint_desktop_icons(hdc: HDC) {
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match super::super::gdi::surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let state = DESKTOP_ICONS.lock();
    let selected = state.selected;
    let dragging = state.dragging;

    for (idx, icon) in state.icons.iter().enumerate() {
        if !icon.valid {
            continue;
        }

        let (x, y) = icon.get_pixel_pos();
        let is_selected = selected == Some(idx);
        let is_dragging = dragging == Some(idx);

        // Draw selection highlight if selected (use Windows XP selection blue)
        if is_selected {
            let highlight_rect = Rect::new(
                x - 4,
                y - 2,
                x + ICON_SIZE + 4,
                y + ICON_SIZE + 20,
            );
            // Windows XP selection highlight: dark blue with dithered pattern
            surf.fill_rect(&highlight_rect, ColorRef::rgb(0, 84, 227));
        }

        // Skip drawing if being dragged (will be drawn at cursor position)
        if is_dragging {
            continue;
        }

        // Draw icon
        draw_desktop_icon(&surf, x, y, icon.icon_type);

        // Draw label with selection color
        let label_x = x + ICON_SIZE / 2;
        let label_y = y + ICON_SIZE + 4;
        draw_icon_label(&surf, label_x, label_y, icon.name, is_selected);
    }
}

/// Draw a single desktop icon
fn draw_desktop_icon(surf: &super::super::gdi::surface::Surface, x: i32, y: i32, icon_type: IconType) {
    // Use actual Windows XP icon bitmaps (32x32 RGBA)
    use super::desktop_icons::*;

    let (width, height, data) = match icon_type {
        IconType::MyComputer => (MY_COMPUTER_WIDTH, MY_COMPUTER_HEIGHT, &MY_COMPUTER_DATA[..]),
        IconType::RecycleBin => (RECYCLE_BIN_WIDTH, RECYCLE_BIN_HEIGHT, &RECYCLE_BIN_DATA[..]),
        IconType::MyDocuments => (MY_DOCUMENTS_WIDTH, MY_DOCUMENTS_HEIGHT, &MY_DOCUMENTS_DATA[..]),
        IconType::NetworkPlaces => (NETWORK_PLACES_WIDTH, NETWORK_PLACES_HEIGHT, &NETWORK_PLACES_DATA[..]),
    };

    // Draw icon with alpha blending
    for row in 0..height {
        for col in 0..width {
            let offset = (row * width + col) * 4;
            let r = data[offset];
            let g = data[offset + 1];
            let b = data[offset + 2];
            let a = data[offset + 3];

            // Skip fully transparent pixels
            if a == 0 {
                continue;
            }

            let px = x + col as i32;
            let py = y + row as i32;

            // Simple alpha blending with desktop background
            if a == 255 {
                // Fully opaque - just draw the pixel
                surf.set_pixel(px, py, ColorRef::rgb(r, g, b));
            } else {
                // Blend with desktop background (teal color)
                let bg_r = 0u8;
                let bg_g = 128u8;
                let bg_b = 128u8;

                let blended_r = ((r as u16 * a as u16 + bg_r as u16 * (255 - a) as u16) / 255) as u8;
                let blended_g = ((g as u16 * a as u16 + bg_g as u16 * (255 - a) as u16) / 255) as u8;
                let blended_b = ((b as u16 * a as u16 + bg_b as u16 * (255 - a) as u16) / 255) as u8;

                surf.set_pixel(px, py, ColorRef::rgb(blended_r, blended_g, blended_b));
            }
        }
    }
}

/// Draw icon label with shadow
fn draw_icon_label(surf: &super::super::gdi::surface::Surface, center_x: i32, y: i32, text: &str, selected: bool) {
    // Calculate text width (rough estimate: 6 pixels per character)
    let text_width = (text.len() as i32) * 6;
    let mut x = center_x - text_width / 2;

    // Prevent text from going off the left edge
    if x < 2 {
        x = 2;
    }

    if selected {
        // Selected: white text on blue (no shadow needed, background already blue)
        for (i, c) in text.chars().enumerate() {
            let char_x = x + (i as i32) * 6;
            draw_char(surf, char_x, y, c, ColorRef::WHITE);
        }
    } else {
        // Normal: white text with black shadow
        // Draw shadow
        for (i, c) in text.chars().enumerate() {
            let char_x = x + (i as i32) * 6 + 1;
            draw_char(surf, char_x, y + 1, c, ColorRef::BLACK);
        }
        // Draw text
        for (i, c) in text.chars().enumerate() {
            let char_x = x + (i as i32) * 6;
            draw_char(surf, char_x, y, c, ColorRef::WHITE);
        }
    }
}

/// Draw a single character (simple bitmap font)
fn draw_char(surf: &super::super::gdi::surface::Surface, x: i32, y: i32, c: char, color: ColorRef) {
    // Simple 5x7 font rendering
    let pattern = get_char_pattern(c);
    for (row, &bits) in pattern.iter().enumerate() {
        for col in 0..5 {
            if (bits >> (4 - col)) & 1 == 1 {
                surf.set_pixel(x + col, y + row as i32, color);
            }
        }
    }
}

/// Get 5x7 pattern for a character
fn get_char_pattern(c: char) -> [u8; 7] {
    match c.to_ascii_uppercase() {
        'A' => [0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
        'B' => [0b11110, 0b10001, 0b11110, 0b10001, 0b10001, 0b10001, 0b11110],
        'C' => [0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110],
        'D' => [0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110],
        'E' => [0b11111, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000, 0b11111],
        'F' => [0b11111, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000, 0b10000],
        'G' => [0b01110, 0b10001, 0b10000, 0b10111, 0b10001, 0b10001, 0b01110],
        'H' => [0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001, 0b10001],
        'I' => [0b01110, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110],
        'K' => [0b10001, 0b10010, 0b11100, 0b10010, 0b10001, 0b10001, 0b10001],
        'L' => [0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111],
        'M' => [0b10001, 0b11011, 0b10101, 0b10001, 0b10001, 0b10001, 0b10001],
        'N' => [0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001],
        'O' => [0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
        'P' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000],
        'R' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10010, 0b10001, 0b10001],
        'S' => [0b01110, 0b10001, 0b10000, 0b01110, 0b00001, 0b10001, 0b01110],
        'T' => [0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100],
        'U' => [0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
        'W' => [0b10001, 0b10001, 0b10001, 0b10101, 0b10101, 0b11011, 0b10001],
        'Y' => [0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100, 0b00100],
        ' ' => [0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000],
        _ => [0b00000, 0b00000, 0b00000, 0b00100, 0b00000, 0b00000, 0b00000], // dot for unknown
    }
}

// ============================================================================
// Desktop Icon Hit Testing and Interaction
// ============================================================================

/// Get the desktop icon at a position, if any
fn get_icon_at_position(x: i32, y: i32) -> Option<usize> {
    // Check if position is in the desktop area (not on a window)
    let hwnd = window::window_from_point(Point::new(x, y));
    let desktop_hwnd = *DESKTOP_HWND.lock();
    let system_desktop = window::get_desktop_window();

    // Allow clicks on desktop (either system desktop or explorer's desktop window)
    // or if no window found at this position
    if hwnd.is_valid() && hwnd != desktop_hwnd && hwnd != system_desktop {
        // Click is on some other window, not desktop
        return None;
    }

    // Check each icon's bounding rect
    let state = DESKTOP_ICONS.lock();

    for (idx, icon) in state.icons.iter().enumerate() {
        if !icon.valid {
            continue;
        }

        let bounds = icon.get_bounds();
        if x >= bounds.left && x < bounds.right &&
           y >= bounds.top && y < bounds.bottom {
            return Some(idx);
        }
    }

    None
}

/// Start dragging a desktop icon
fn start_icon_drag(icon_idx: usize, mouse_x: i32, mouse_y: i32) {
    let mut state = DESKTOP_ICONS.lock();
    if icon_idx < MAX_DESKTOP_ICONS && state.icons[icon_idx].valid {
        state.dragging = Some(icon_idx);
        state.selected = Some(icon_idx);
        state.drag_start_mouse = Point::new(mouse_x, mouse_y);
        state.drag_start_grid = (state.icons[icon_idx].grid_x, state.icons[icon_idx].grid_y);
        crate::serial_println!("[EXPLORER] Started dragging icon {} from grid ({}, {})",
            state.icons[icon_idx].name, state.drag_start_grid.0, state.drag_start_grid.1);
    }
}

/// Update icon position during drag
fn update_icon_drag(mouse_x: i32, mouse_y: i32) {
    let dragging = {
        let state = DESKTOP_ICONS.lock();
        state.dragging
    };

    if let Some(idx) = dragging {
        // Calculate new grid position based on mouse position
        let (new_gx, new_gy) = snap_to_grid(mouse_x - ICON_SIZE / 2, mouse_y - ICON_SIZE / 2);

        // Update icon position (will be finalized on drop)
        let mut state = DESKTOP_ICONS.lock();
        if state.icons[idx].valid {
            let old_gx = state.icons[idx].grid_x;
            let old_gy = state.icons[idx].grid_y;

            // Only update and repaint if position changed
            if new_gx != old_gx || new_gy != old_gy {
                state.icons[idx].grid_x = new_gx;
                state.icons[idx].grid_y = new_gy;
                drop(state);
                paint_desktop();
            }
        }
    }
}

/// End icon drag and snap to grid
fn end_icon_drag() {
    let mut needs_repaint = false;

    {
        let mut state = DESKTOP_ICONS.lock();
        if let Some(idx) = state.dragging {
            if state.icons[idx].valid {
                let gx = state.icons[idx].grid_x;
                let gy = state.icons[idx].grid_y;

                // Find a free position if current is occupied
                let (final_gx, final_gy) = find_free_grid_pos_locked(&state, gx, gy, Some(idx));

                state.icons[idx].grid_x = final_gx;
                state.icons[idx].grid_y = final_gy;

                crate::serial_println!("[EXPLORER] Dropped icon {} at grid ({}, {})",
                    state.icons[idx].name, final_gx, final_gy);
            }
            state.dragging = None;
            needs_repaint = true;
        }
    }

    // Repaint to show final position (outside lock)
    if needs_repaint {
        paint_desktop();
    }
}

/// Check if we're currently dragging an icon
fn is_icon_dragging() -> bool {
    DESKTOP_ICONS.lock().dragging.is_some()
}

/// Handle double-click on a desktop icon
fn handle_desktop_icon_double_click(icon_idx: usize) {
    let icon_info = {
        let state = DESKTOP_ICONS.lock();
        if icon_idx < MAX_DESKTOP_ICONS && state.icons[icon_idx].valid {
            Some((state.icons[icon_idx].name, state.icons[icon_idx].icon_type))
        } else {
            None
        }
    };

    if let Some((name, icon_type)) = icon_info {
        crate::serial_println!("[EXPLORER] Double-clicked on: {}", name);

        match icon_type {
            IconType::MyComputer => {
                // Open "My Computer" window - shows drives
                create_my_computer_window();
            }
            IconType::RecycleBin => {
                // Open Recycle Bin window
                create_simple_window("Recycle Bin", "Recycle Bin is empty");
            }
            IconType::MyDocuments => {
                // Open My Documents
                create_simple_window("My Documents", "Your documents folder");
            }
            IconType::NetworkPlaces => {
                // Open Network Places
                create_simple_window("Network Places", "Network resources");
            }
        }
    }
}

/// Create a simple window with title and content
fn create_simple_window(title: &str, _content: &str) {
    let hwnd = window::create_window(
        "EXPLORER_WINDOW",
        title,
        WindowStyle::OVERLAPPEDWINDOW | WindowStyle::VISIBLE,
        WindowStyleEx::empty(),
        200, 100, 400, 300,
        super::super::HWND::NULL,
        0, // menu
    );

    if hwnd.is_valid() {
        crate::serial_println!("[EXPLORER] Created window: {}", title);

        // Add to taskbar
        add_taskbar_button(hwnd);

        // Make it active
        window::set_foreground_window(hwnd);
        input::set_active_window(hwnd);

        // Mark for painting - the paint system will handle the content
        window::with_window_mut(hwnd, |wnd| {
            wnd.needs_paint = true;
        });

        paint_taskbar();
    }
}

/// Create My Computer window with drive list
fn create_my_computer_window() {
    let hwnd = window::create_window(
        "EXPLORER_WINDOW",
        "My Computer",
        WindowStyle::OVERLAPPEDWINDOW | WindowStyle::VISIBLE,
        WindowStyleEx::empty(),
        150, 80, 500, 400,
        super::super::HWND::NULL,
        0, // menu
    );

    if hwnd.is_valid() {
        // Add to taskbar
        add_taskbar_button(hwnd);

        // Make it active
        window::set_foreground_window(hwnd);
        input::set_active_window(hwnd);

        // Paint it
        super::paint::draw_window_frame(hwnd);

        // Paint My Computer content
        if let Some(wnd) = window::get_window(hwnd) {
            if let Ok(hdc) = dc::create_display_dc() {
                let surface_handle = dc::get_dc_surface(hdc);
                if let Some(surf) = super::super::gdi::surface::get_surface(surface_handle) {
                    // Fill client area
                    let client_rect = Rect::new(
                        wnd.client_rect.left + wnd.rect.left,
                        wnd.client_rect.top + wnd.rect.top,
                        wnd.client_rect.right + wnd.rect.left,
                        wnd.client_rect.bottom + wnd.rect.top,
                    );
                    surf.fill_rect(&client_rect, ColorRef::WHITE);

                    // Draw drive icons
                    let drives = [
                        ("C:", "Local Disk"),
                        ("D:", "CD-ROM Drive"),
                    ];

                    let mut y = client_rect.top + 20;
                    for (letter, label) in drives.iter() {
                        // Draw simple drive icon
                        let icon_x = client_rect.left + 30;

                        // Hard drive shape
                        surf.fill_rect(&Rect::new(icon_x, y, icon_x + 32, y + 24), ColorRef::rgb(192, 192, 192));
                        surf.fill_rect(&Rect::new(icon_x + 2, y + 2, icon_x + 30, y + 6), ColorRef::rgb(0, 128, 0));
                        surf.hline(icon_x, icon_x + 32, y + 12, ColorRef::GRAY);

                        // Drive label
                        dc::set_text_color(hdc, ColorRef::BLACK);
                        super::super::gdi::draw::gdi_text_out(hdc, icon_x + 40, y + 4, letter);
                        super::super::gdi::draw::gdi_text_out(hdc, icon_x + 70, y + 4, label);

                        y += 50;
                    }
                }
                dc::delete_dc(hdc);
            }
        }

        paint_taskbar();
    }
}

// ============================================================================
// Taskbar Painting
// ============================================================================

/// Paint the taskbar
pub fn paint_taskbar() {
    let hwnd = *TASKBAR_HWND.lock();
    if !hwnd.is_valid() {
        return;
    }

    if let Ok(hdc) = dc::create_display_dc() {
        let (width, height) = super::super::gdi::surface::get_primary_dimensions();
        let taskbar_y = height as i32 - TASKBAR_HEIGHT;

        // Taskbar background
        let taskbar_rect = Rect::new(0, taskbar_y, width as i32, height as i32);
        let bg_brush = brush::create_solid_brush(ColorRef::BUTTON_FACE);
        super::super::gdi::fill_rect(hdc, &taskbar_rect, bg_brush);

        // Top edge highlight
        let highlight_pen = pen::create_pen(pen::PenStyle::Solid, 1, ColorRef::WHITE);
        dc::select_object(hdc, highlight_pen);
        super::super::gdi::move_to(hdc, 0, taskbar_y);
        super::super::gdi::line_to(hdc, width as i32, taskbar_y);

        // Paint Start button
        paint_start_button(hdc, taskbar_y);

        // Paint clock
        paint_clock(hdc, taskbar_y);

        // Paint taskbar buttons
        paint_taskbar_buttons(hdc, taskbar_y);

        dc::delete_dc(hdc);
    }
}

/// Paint the Start button
fn paint_start_button(hdc: HDC, taskbar_y: i32) {
    let state = TASKBAR_STATE.lock();
    let mut btn_rect = state.start_rect;
    btn_rect.top += taskbar_y;
    btn_rect.bottom += taskbar_y;

    // Draw simple Start button with text
    controls::draw_button(
        hdc,
        &btn_rect,
        "Start",
        controls::ButtonState::Normal,
        controls::ButtonStyle::PushButton,
    );
}

/// Paint the system clock
fn paint_clock(hdc: HDC, taskbar_y: i32) {
    let state = TASKBAR_STATE.lock();
    let mut clock_rect = state.clock_rect;
    clock_rect.top += taskbar_y;
    clock_rect.bottom += taskbar_y;
    drop(state);

    // Draw sunken area for clock (also clears previous text)
    let bg_brush = brush::create_solid_brush(ColorRef::BUTTON_FACE);
    super::super::gdi::fill_rect(hdc, &clock_rect, bg_brush);
    super::super::gdi::draw_edge_sunken(hdc, &clock_rect);

    // Get current time from RTC
    let datetime = crate::hal::rtc::get_datetime();
    let hour = datetime.hour;
    let minute = datetime.minute;

    // Format time (12-hour format with AM/PM)
    let is_pm = hour >= 12;
    let h12 = if hour == 0 { 12 } else if hour > 12 { hour - 12 } else { hour };

    // Build time string characters
    let c0 = if h12 >= 10 { b'1' } else { b' ' };
    let c1 = b'0' + (h12 % 10);
    let c2 = b':';
    let c3 = b'0' + (minute / 10);
    let c4 = b'0' + (minute % 10);
    let c5 = if is_pm { b'P' } else { b'A' };
    let c6 = b'M';

    // Draw each character
    dc::set_text_color(hdc, ColorRef::BLACK);
    dc::set_bk_mode(hdc, dc::BkMode::Transparent);

    let text_x = clock_rect.left + 4;
    let text_y = clock_rect.top + 5;
    let char_width = 7; // Approximate character width

    // Draw time characters individually
    let chars = [c0, c1, c2, c3, c4, b' ', c5, c6];
    for (i, &ch) in chars.iter().enumerate() {
        let s = [ch];
        if let Ok(text) = core::str::from_utf8(&s) {
            super::super::gdi::text_out(hdc, text_x + (i as i32 * char_width), text_y, text);
        }
    }
}

/// Update the clock display
fn update_clock() {
    // Get screen dimensions
    let (_, height) = super::super::gdi::surface::get_primary_dimensions();
    let taskbar_y = height as i32 - TASKBAR_HEIGHT;

    // Create DC and repaint clock area
    if let Ok(hdc) = dc::create_display_dc() {
        paint_clock(hdc, taskbar_y);
        dc::delete_dc(hdc);
    }
}

/// Date tooltip visibility
static DATE_TOOLTIP_VISIBLE: AtomicBool = AtomicBool::new(false);

/// Show date tooltip near clock
fn show_date_tooltip() {
    // Toggle tooltip
    let was_visible = DATE_TOOLTIP_VISIBLE.swap(true, Ordering::SeqCst);

    if was_visible {
        // Hide it
        DATE_TOOLTIP_VISIBLE.store(false, Ordering::SeqCst);
        // Invalidate cursor background so it doesn't restore tooltip pixels
        super::cursor::invalidate_cursor_background();
        // Repaint to clear tooltip
        paint_desktop();
        paint_taskbar();
        // Redraw cursor with fresh background
        super::cursor::draw_cursor();
        return;
    }

    // Show date tooltip
    if let Ok(hdc) = dc::create_display_dc() {
        let (width, height) = super::super::gdi::surface::get_primary_dimensions();
        let taskbar_y = height as i32 - TASKBAR_HEIGHT;

        // Get current date from RTC
        let datetime = crate::hal::rtc::get_datetime();

        // Format date string (e.g., "Friday, January 2, 2026")
        let day_name = match datetime.day_of_week {
            1 => "Sunday",
            2 => "Monday",
            3 => "Tuesday",
            4 => "Wednesday",
            5 => "Thursday",
            6 => "Friday",
            7 => "Saturday",
            _ => "Unknown",
        };
        let month_name = match datetime.month {
            1 => "January",
            2 => "February",
            3 => "March",
            4 => "April",
            5 => "May",
            6 => "June",
            7 => "July",
            8 => "August",
            9 => "September",
            10 => "October",
            11 => "November",
            12 => "December",
            _ => "Unknown",
        };

        // Build date string first to calculate dynamic width
        let mut date_buf = [0u8; 64];
        let mut buf_pos = 0;

        // Copy day name
        let day_bytes = day_name.as_bytes();
        date_buf[buf_pos..buf_pos + day_bytes.len()].copy_from_slice(day_bytes);
        buf_pos += day_bytes.len();

        // Add ", "
        date_buf[buf_pos] = b',';
        date_buf[buf_pos + 1] = b' ';
        buf_pos += 2;

        // Copy month name
        let month_bytes = month_name.as_bytes();
        date_buf[buf_pos..buf_pos + month_bytes.len()].copy_from_slice(month_bytes);
        buf_pos += month_bytes.len();

        // Add space
        date_buf[buf_pos] = b' ';
        buf_pos += 1;

        // Add day number
        if datetime.day >= 10 {
            date_buf[buf_pos] = b'0' + (datetime.day / 10);
            buf_pos += 1;
        }
        date_buf[buf_pos] = b'0' + (datetime.day % 10);
        buf_pos += 1;

        // Add ", "
        date_buf[buf_pos] = b',';
        date_buf[buf_pos + 1] = b' ';
        buf_pos += 2;

        // Add year
        let year = datetime.year;
        date_buf[buf_pos] = b'0' + (year / 1000) as u8;
        date_buf[buf_pos + 1] = b'0' + ((year / 100) % 10) as u8;
        date_buf[buf_pos + 2] = b'0' + ((year / 10) % 10) as u8;
        date_buf[buf_pos + 3] = b'0' + (year % 10) as u8;
        buf_pos += 4;

        // Get the complete date string
        let date_str = core::str::from_utf8(&date_buf[..buf_pos]).unwrap_or("Invalid Date");

        // Calculate dynamic tooltip size based on string length
        // Average ~8 pixels per character + 16 pixels padding
        let tooltip_width = (date_str.len() as i32) * 8 + 16;
        let tooltip_height = 22;
        let tooltip_x = width as i32 - tooltip_width - 8;
        let tooltip_y = taskbar_y - tooltip_height - 2;

        let tooltip_rect = Rect::new(
            tooltip_x,
            tooltip_y,
            tooltip_x + tooltip_width,
            tooltip_y + tooltip_height,
        );

        // Draw tooltip background
        let bg_brush = brush::create_solid_brush(ColorRef::rgb(255, 255, 225)); // Pale yellow
        super::super::gdi::fill_rect(hdc, &tooltip_rect, bg_brush);

        // Draw border
        super::super::gdi::draw_edge_sunken(hdc, &tooltip_rect);

        // Draw text
        dc::set_text_color(hdc, ColorRef::BLACK);
        dc::set_bk_mode(hdc, dc::BkMode::Transparent);

        // Render the date string (already built above)
        super::super::gdi::text_out(hdc, tooltip_x + 8, tooltip_y + 4, date_str);

        dc::delete_dc(hdc);
    }
}

/// Paint taskbar buttons for open windows
fn paint_taskbar_buttons(hdc: HDC, taskbar_y: i32) {
    let state = TASKBAR_STATE.lock();

    for button in state.buttons.iter() {
        if !button.valid {
            continue;
        }

        let mut btn_rect = button.rect;
        btn_rect.top += taskbar_y;
        btn_rect.bottom += taskbar_y;

        // Get window title
        let title = window::get_window_text_str(button.hwnd);

        // Check if this window is active
        let is_active = input::get_active_window() == button.hwnd;
        let btn_state = if is_active {
            controls::ButtonState::Pressed
        } else {
            controls::ButtonState::Normal
        };

        controls::draw_button(hdc, &btn_rect, title, btn_state, controls::ButtonStyle::PushButton);
    }
}

// ============================================================================
// Taskbar Button Management
// ============================================================================

/// Add a window to the taskbar
pub fn add_taskbar_button(hwnd: HWND) {
    let mut state = TASKBAR_STATE.lock();

    // Find empty slot
    for button in state.buttons.iter_mut() {
        if !button.valid {
            button.valid = true;
            button.hwnd = hwnd;
            state.button_count += 1;
            break;
        }
    }

    // Recalculate button positions
    recalculate_taskbar_buttons(&mut state);
}

/// Remove a window from the taskbar
pub fn remove_taskbar_button(hwnd: HWND) {
    let mut state = TASKBAR_STATE.lock();

    for button in state.buttons.iter_mut() {
        if button.valid && button.hwnd == hwnd {
            button.valid = false;
            button.hwnd = HWND::NULL;
            state.button_count = state.button_count.saturating_sub(1);
            break;
        }
    }

    // Recalculate button positions
    recalculate_taskbar_buttons(&mut state);
}

/// Recalculate taskbar button positions
fn recalculate_taskbar_buttons(state: &mut TaskbarState) {
    if state.button_count == 0 {
        return;
    }

    // Available space for buttons
    let button_start = state.start_rect.right + 4;
    let button_end = state.systray_rect.left - 4;
    let available_width = button_end - button_start;

    // Calculate button width (max 150px each)
    let button_width = (available_width / state.button_count as i32).min(150).max(40);

    let mut x = button_start;
    for button in state.buttons.iter_mut() {
        if button.valid {
            button.rect = Rect::new(x, 2, x + button_width, TASKBAR_HEIGHT - 2);
            x += button_width + 2;
        }
    }
}

// ============================================================================
// Alt+Tab Window Switching
// ============================================================================

/// Handle Alt+Tab key press
fn handle_alt_tab() {
    if !ALT_TAB_ACTIVE.load(Ordering::SeqCst) {
        // Start Alt+Tab
        ALT_TAB_ACTIVE.store(true, Ordering::SeqCst);
        ALT_TAB_INDEX.store(0, Ordering::SeqCst);
        show_alt_tab_dialog();
    } else {
        // Cycle to next window
        let count = window::get_window_count();
        if count > 0 {
            let next = (ALT_TAB_INDEX.load(Ordering::SeqCst) + 1) % count;
            ALT_TAB_INDEX.store(next, Ordering::SeqCst);
            update_alt_tab_dialog();
        }
    }
}

/// Finish Alt+Tab and switch to selected window
fn finish_alt_tab() {
    ALT_TAB_ACTIVE.store(false, Ordering::SeqCst);

    let index = ALT_TAB_INDEX.load(Ordering::SeqCst);
    if let Some(hwnd) = window::get_window_at_index(index as usize) {
        // Activate the selected window
        input::set_active_window(hwnd);
        window::show_window(hwnd, ShowCommand::Show);
        window::set_foreground_window(hwnd);
    }

    // Hide Alt+Tab dialog
    hide_alt_tab_dialog();

    // Repaint desktop and taskbar
    paint_desktop();
    paint_taskbar();
}

/// Show the Alt+Tab dialog
fn show_alt_tab_dialog() {
    if let Ok(hdc) = dc::create_display_dc() {
        let (width, height) = super::super::gdi::surface::get_primary_dimensions();

        // Dialog size
        let dialog_width = 300;
        let dialog_height = 100;
        let dialog_x = (width as i32 - dialog_width) / 2;
        let dialog_y = (height as i32 - dialog_height) / 2;

        let dialog_rect = Rect::new(
            dialog_x, dialog_y,
            dialog_x + dialog_width, dialog_y + dialog_height
        );

        // Draw dialog background
        let bg_brush = brush::create_solid_brush(ColorRef::BUTTON_FACE);
        super::super::gdi::fill_rect(hdc, &dialog_rect, bg_brush);
        super::super::gdi::draw_edge_raised(hdc, &dialog_rect);

        // Draw title
        dc::set_text_color(hdc, ColorRef::BLACK);
        dc::set_bk_mode(hdc, dc::BkMode::Transparent);
        super::super::gdi::text_out(hdc, dialog_x + 10, dialog_y + 10, "Switch To:");

        // Draw currently selected window name
        let index = ALT_TAB_INDEX.load(Ordering::SeqCst);
        if let Some(hwnd) = window::get_window_at_index(index as usize) {
            let title = window::get_window_text_str(hwnd);
            super::super::gdi::text_out(hdc, dialog_x + 10, dialog_y + 40, title);
        }

        dc::delete_dc(hdc);
    }
}

/// Update the Alt+Tab dialog with new selection
fn update_alt_tab_dialog() {
    show_alt_tab_dialog(); // Just repaint for now
}

/// Hide the Alt+Tab dialog
fn hide_alt_tab_dialog() {
    // The dialog will be cleared when we repaint the desktop
}

// ============================================================================
// Shell Control
// ============================================================================

/// Stop the shell
pub fn stop() {
    SHELL_RUNNING.store(false, Ordering::SeqCst);

    {
        let mut state = SHELL_STATE.lock();
        *state = ShellState::ShuttingDown;
    }
}

/// Get shell state
pub fn get_state() -> ShellState {
    *SHELL_STATE.lock()
}

/// Check if shell is running
pub fn is_running() -> bool {
    SHELL_RUNNING.load(Ordering::SeqCst)
}

/// Get desktop window handle
pub fn get_desktop_hwnd() -> HWND {
    *DESKTOP_HWND.lock()
}

/// Get taskbar window handle
pub fn get_taskbar_hwnd() -> HWND {
    *TASKBAR_HWND.lock()
}

// ============================================================================
// Start Menu
// ============================================================================

/// Start menu item structure
struct StartMenuItem {
    name: &'static str,
    has_submenu: bool,
    is_separator: bool,
}

/// Start menu items (Windows 2003 style)
const START_MENU_ITEM_LIST: [StartMenuItem; START_MENU_ITEMS] = [
    StartMenuItem { name: "Programs", has_submenu: true, is_separator: false },
    StartMenuItem { name: "Documents", has_submenu: true, is_separator: false },
    StartMenuItem { name: "Settings", has_submenu: true, is_separator: false },
    StartMenuItem { name: "Search", has_submenu: true, is_separator: false },
    StartMenuItem { name: "Help and Support", has_submenu: false, is_separator: false },
    StartMenuItem { name: "Run...", has_submenu: false, is_separator: false },
    StartMenuItem { name: "Shut Down...", has_submenu: false, is_separator: false },
    StartMenuItem { name: "Log Off", has_submenu: false, is_separator: false },
];

/// Toggle Start menu visibility
fn toggle_start_menu() {
    let visible = START_MENU_VISIBLE.load(Ordering::SeqCst);
    if visible {
        hide_start_menu();
    } else {
        show_start_menu();
    }
}

/// Show the Start menu
fn show_start_menu() {
    START_MENU_VISIBLE.store(true, Ordering::SeqCst);
    crate::serial_println!("[EXPLORER] Showing Start menu");
    paint_start_menu();
}

/// Hide the Start menu
fn hide_start_menu() {
    START_MENU_VISIBLE.store(false, Ordering::SeqCst);
    crate::serial_println!("[EXPLORER] Hiding Start menu");

    // Invalidate cursor background so it doesn't restore menu pixels
    super::cursor::invalidate_cursor_background();

    // Repaint desktop to clear the menu
    paint_desktop();
    paint_taskbar();

    // Redraw cursor with fresh background
    super::cursor::draw_cursor();
}

/// Paint the Start menu with Windows 2003 styling
fn paint_start_menu() {
    if !START_MENU_VISIBLE.load(Ordering::SeqCst) {
        return;
    }

    if let Ok(hdc) = dc::create_display_dc() {
        let (_, height) = super::super::gdi::surface::get_primary_dimensions();
        let taskbar_y = height as i32 - TASKBAR_HEIGHT;

        // Calculate menu dimensions
        let menu_height = START_MENU_ITEMS as i32 * START_MENU_ITEM_HEIGHT + 40; // Extra for user header
        let menu_x = 2;
        let menu_y = taskbar_y - menu_height;

        let menu_rect = Rect::new(
            menu_x, menu_y,
            menu_x + START_MENU_WIDTH, taskbar_y
        );

        // Get surface for direct drawing
        let surface_handle = dc::get_dc_surface(hdc);
        if let Some(surf) = super::super::gdi::surface::get_surface(surface_handle) {
            // Draw menu background (gray)
            surf.fill_rect(&menu_rect, ColorRef::BUTTON_FACE);

            // Draw blue sidebar on the left (Windows 2003 style)
            let sidebar_rect = Rect::new(
                menu_x,
                menu_y,
                menu_x + START_MENU_SIDEBAR_WIDTH,
                taskbar_y,
            );
            // Gradient-like blue sidebar (simplified - use solid color)
            surf.fill_rect(&sidebar_rect, ColorRef::rgb(0, 51, 153)); // Dark blue

            // Draw user header area at top of sidebar
            let header_rect = Rect::new(
                menu_x,
                menu_y,
                menu_x + START_MENU_WIDTH,
                menu_y + 36,
            );
            surf.fill_rect(&header_rect, ColorRef::rgb(0, 51, 153)); // Match sidebar

            // Draw user icon
            let icon_x = menu_x + 6;
            let icon_y = menu_y + 6;

            // Draw simple user silhouette icon (24x24)
            for row in 0..24 {
                for col in 0..24 {
                    let px = icon_x + col as i32;
                    let py = icon_y + row as i32;

                    // Simple person icon design
                    let is_icon = if row >= 6 && row <= 10 {
                        // Head (circle approximation)
                        let dx = col as i32 - 12;
                        let dy = row as i32 - 8;
                        dx * dx + dy * dy <= 16
                    } else if row >= 12 && row <= 22 {
                        // Body (trapezoid)
                        let top_width = 8;
                        let bottom_width = 16;
                        let body_height = 10;
                        let row_offset = row - 12;
                        let width_at_row = top_width + (bottom_width - top_width) * row_offset as i32 / body_height;
                        let left_edge = 12 - width_at_row / 2;
                        let right_edge = 12 + width_at_row / 2;
                        col >= left_edge as usize && col <= right_edge as usize
                    } else {
                        false
                    };

                    if is_icon {
                        // Light blue/cyan user icon
                        surf.set_pixel(px, py, ColorRef::rgb(150, 200, 255));
                    }
                }
            }

            // Draw username
            dc::set_text_color(hdc, ColorRef::WHITE);
            dc::set_bk_mode(hdc, dc::BkMode::Transparent);
            super::super::gdi::text_out(hdc, menu_x + 36, menu_y + 10, "Administrator");

            // Draw 3D border around menu
            // Top and left highlight
            surf.hline(menu_rect.left, menu_rect.right - 1, menu_rect.top, ColorRef::WHITE);
            surf.vline(menu_rect.left, menu_rect.top, menu_rect.bottom - 1, ColorRef::WHITE);
            // Bottom and right shadow
            surf.hline(menu_rect.left, menu_rect.right, menu_rect.bottom - 1, ColorRef::DARK_GRAY);
            surf.vline(menu_rect.right - 1, menu_rect.top, menu_rect.bottom, ColorRef::DARK_GRAY);

            // Draw separator between header and items
            let sep_y = menu_y + 36;
            surf.hline(menu_x, menu_x + START_MENU_WIDTH, sep_y, ColorRef::BUTTON_SHADOW);
            surf.hline(menu_x, menu_x + START_MENU_WIDTH, sep_y + 1, ColorRef::WHITE);
        }

        // Draw menu items
        let items_start_y = menu_y + 38;
        let items_x = menu_x + START_MENU_SIDEBAR_WIDTH + 4;

        for (i, item) in START_MENU_ITEM_LIST.iter().enumerate() {
            let item_y = items_start_y + (i as i32 * START_MENU_ITEM_HEIGHT);

            // Draw separator before Shut Down (after Help)
            if i == 6 {
                if let Some(surf) = super::super::gdi::surface::get_surface(dc::get_dc_surface(hdc)) {
                    let sep_y2 = item_y - 2;
                    surf.hline(items_x, menu_x + START_MENU_WIDTH - 4, sep_y2, ColorRef::BUTTON_SHADOW);
                    surf.hline(items_x, menu_x + START_MENU_WIDTH - 4, sep_y2 + 1, ColorRef::WHITE);
                }
            }

            // Draw menu item icon
            if let Some(surf) = super::super::gdi::surface::get_surface(dc::get_dc_surface(hdc)) {
                use super::desktop_icons::*;

                // Select icon data based on menu item
                let (width, height, data) = match i {
                    0 => (PROGRAMS_WIDTH, PROGRAMS_HEIGHT, &PROGRAMS_DATA[..]),  // Programs
                    1 => (DOCUMENTS_WIDTH, DOCUMENTS_HEIGHT, &DOCUMENTS_DATA[..]),  // Documents
                    2 => (SETTINGS_WIDTH, SETTINGS_HEIGHT, &SETTINGS_DATA[..]),  // Settings
                    3 => (SEARCH_WIDTH, SEARCH_HEIGHT, &SEARCH_DATA[..]),  // Search
                    4 => (HELP_WIDTH, HELP_HEIGHT, &HELP_DATA[..]),  // Help
                    5 => (RUN_WIDTH, RUN_HEIGHT, &RUN_DATA[..]),  // Run
                    6 => (SHUTDOWN_WIDTH, SHUTDOWN_HEIGHT, &SHUTDOWN_DATA[..]),  // Shut Down
                    7 => (LOGOFF_WIDTH, LOGOFF_HEIGHT, &LOGOFF_DATA[..]),  // Log Off
                    _ => continue,  // Safety fallback
                };

                let icon_x = items_x + 2;
                let icon_y = item_y + 2;

                // Draw 16x16 icon (scaled down from 32x32)
                for row in 0..16 {
                    for col in 0..16 {
                        // Sample from 32x32 data (every other pixel)
                        let src_row = row * 2;
                        let src_col = col * 2;
                        let offset = (src_row * width + src_col) * 4;

                        if offset + 3 < data.len() {
                            let r = data[offset];
                            let g = data[offset + 1];
                            let b = data[offset + 2];
                            let a = data[offset + 3];

                            // Skip fully transparent pixels
                            if a == 0 {
                                continue;
                            }

                            let px = icon_x + col as i32;
                            let py = icon_y + row as i32;

                            if a == 255 {
                                surf.set_pixel(px, py, ColorRef::rgb(r, g, b));
                            } else {
                                // Blend with menu background (light gray)
                                let bg_r = 192u8;
                                let bg_g = 192u8;
                                let bg_b = 192u8;

                                let blended_r = ((r as u16 * a as u16 + bg_r as u16 * (255 - a) as u16) / 255) as u8;
                                let blended_g = ((g as u16 * a as u16 + bg_g as u16 * (255 - a) as u16) / 255) as u8;
                                let blended_b = ((b as u16 * a as u16 + bg_b as u16 * (255 - a) as u16) / 255) as u8;

                                surf.set_pixel(px, py, ColorRef::rgb(blended_r, blended_g, blended_b));
                            }
                        }
                    }
                }
            }

            // Draw item text (shifted right to make room for icon)
            dc::set_text_color(hdc, ColorRef::BLACK);
            super::super::gdi::text_out(hdc, items_x + 20, item_y + 4, item.name);

            // Draw submenu arrow if has submenu
            if item.has_submenu {
                if let Some(surf) = super::super::gdi::surface::get_surface(dc::get_dc_surface(hdc)) {
                    let arrow_x = menu_x + START_MENU_WIDTH - 12;
                    let arrow_y = item_y + 8;
                    // Draw simple right arrow
                    surf.set_pixel(arrow_x, arrow_y, ColorRef::BLACK);
                    surf.set_pixel(arrow_x + 1, arrow_y + 1, ColorRef::BLACK);
                    surf.set_pixel(arrow_x + 2, arrow_y + 2, ColorRef::BLACK);
                    surf.set_pixel(arrow_x + 1, arrow_y + 3, ColorRef::BLACK);
                    surf.set_pixel(arrow_x, arrow_y + 4, ColorRef::BLACK);
                }
            }
        }

        dc::delete_dc(hdc);
    }
}

/// Handle click on Start menu
pub fn handle_start_menu_click(x: i32, y: i32) -> bool {
    if !START_MENU_VISIBLE.load(Ordering::SeqCst) {
        return false;
    }

    let (_, height) = super::super::gdi::surface::get_primary_dimensions();
    let taskbar_y = height as i32 - TASKBAR_HEIGHT;
    let menu_height = START_MENU_ITEMS as i32 * START_MENU_ITEM_HEIGHT + 40;
    let menu_y = taskbar_y - menu_height;

    // Check if click is in menu area
    if x < 2 || x > 2 + START_MENU_WIDTH || y < menu_y || y >= taskbar_y {
        hide_start_menu();
        return true;
    }

    // Check if click is in items area (not in header)
    let items_start_y = menu_y + 38;
    if y < items_start_y {
        // Click in header - do nothing
        return true;
    }

    // Determine which item was clicked
    let relative_y = y - items_start_y;
    let item_index = relative_y / START_MENU_ITEM_HEIGHT;

    if item_index >= 0 && (item_index as usize) < START_MENU_ITEMS {
        let item = item_index as usize;
        crate::serial_println!("[EXPLORER] Start menu item clicked: {}", START_MENU_ITEM_LIST[item].name);

        match item {
            5 => {
                // Run... - disabled for now
                hide_start_menu();
                // Commented out: create_test_window();
                crate::serial_println!("[EXPLORER] Run... menu item clicked (not implemented)");
            }
            6 => {
                // Shut Down...
                hide_start_menu();
                crate::serial_println!("[EXPLORER] Initiating shutdown...");
                winlogon::shutdown(false);
                // Note: shutdown never returns
            }
            7 => {
                // Log Off
                hide_start_menu();
                crate::serial_println!("[EXPLORER] Initiating logoff...");
                winlogon::logoff();
            }
            _ => {
                // Items with submenus - just hide for now
                hide_start_menu();
                // TODO: Implement submenus for Programs, Documents, Settings, Search
            }
        }
    }

    true
}

// ============================================================================
// Test Window Creation
// ============================================================================

/// Counter for test window naming
static TEST_WINDOW_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);

/// Create a test window for desktop verification
fn create_test_window() {
    // Get unique window number
    let num = TEST_WINDOW_COUNT.fetch_add(1, Ordering::SeqCst);

    // Calculate position (cascade windows from top-left)
    let offset = ((num - 1) % 10) as i32 * 30;
    let x = 50 + offset;
    let y = 50 + offset;
    let width = 300;
    let height = 200;

    // Create window with proper overlapped style (has caption, system menu, min/max buttons)
    let hwnd = window::create_window(
        "TestWindow",
        "Test Window",
        WindowStyle::OVERLAPPEDWINDOW | WindowStyle::VISIBLE,
        WindowStyleEx::empty(),
        x, y,
        width, height,
        HWND::NULL,
        0,
    );

    if hwnd.is_valid() {
        crate::serial_println!("[EXPLORER] Created test window #{}: {:#x}", num, hwnd.raw());

        // Set window title with number
        let title_buf = &[
            b'T', b'e', b's', b't', b' ',
            b'W', b'i', b'n', b'd', b'o', b'w', b' ',
            b'#', b'0' + (num % 10) as u8,
        ];
        window::with_window_mut(hwnd, |wnd| {
            wnd.title_len = 14;
            for (i, &b) in title_buf.iter().enumerate() {
                wnd.title[i] = b;
            }
        });

        // Make it the active window
        window::set_foreground_window(hwnd);
        input::set_active_window(hwnd);

        // Paint the window
        super::paint::draw_window_frame(hwnd);

        // Paint window client area with a simple color
        paint_test_window_client(hwnd);

        // Add to taskbar and repaint
        add_taskbar_button(hwnd);
        paint_taskbar();
    } else {
        crate::serial_println!("[EXPLORER] Failed to create test window");
    }
}

/// Paint test window client area
fn paint_test_window_client(hwnd: HWND) {
    if let Some(wnd) = window::get_window(hwnd) {
        if let Ok(hdc) = dc::create_display_dc() {
            let metrics = wnd.get_frame_metrics();

            // Calculate client area in screen coordinates
            let client_x = wnd.rect.left + metrics.border_width;
            let client_y = wnd.rect.top + metrics.border_width + metrics.caption_height;
            let client_w = wnd.rect.width() - metrics.border_width * 2;
            let client_h = wnd.rect.height() - metrics.border_width * 2 - metrics.caption_height;

            let client_rect = Rect::new(
                client_x, client_y,
                client_x + client_w, client_y + client_h
            );

            // Fill with window background color
            let bg_brush = brush::create_solid_brush(ColorRef::WINDOW_BG);
            super::super::gdi::fill_rect(hdc, &client_rect, bg_brush);

            // Draw some text in the window
            dc::set_text_color(hdc, ColorRef::BLACK);
            dc::set_bk_mode(hdc, dc::BkMode::Transparent);
            super::super::gdi::text_out(hdc, client_x + 10, client_y + 10, "Test Window Content");
            super::super::gdi::text_out(hdc, client_x + 10, client_y + 30, "Click title bar to drag");
            super::super::gdi::text_out(hdc, client_x + 10, client_y + 50, "Click X to close");

            dc::delete_dc(hdc);
        }
    }
}
