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
use super::super::{HWND, HDC, Rect, Point, ColorRef, GdiHandle, UserHandle};
use super::super::gdi::{dc, brush, pen};
use super::{message, window, input, desktop, controls, cursor, winlogon, WindowStyle, WindowStyleEx, ShowCommand};

// ============================================================================
// Constants
// ============================================================================

/// Taskbar height in pixels
pub const TASKBAR_HEIGHT: i32 = 30;

/// Start button width
pub const START_BUTTON_WIDTH: i32 = 60;

/// Clock width
pub const CLOCK_WIDTH: i32 = 60;

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

/// Start menu item count
const START_MENU_ITEMS: usize = 6;

/// Start menu item height
const START_MENU_ITEM_HEIGHT: i32 = 24;

/// Start menu width
const START_MENU_WIDTH: i32 = 180;

// ============================================================================
// Window Dragging State
// ============================================================================

/// Window currently being dragged (if any)
static DRAGGING_WINDOW: SpinLock<HWND> = SpinLock::new(HWND::NULL);

/// Drag start position (screen coordinates)
static DRAG_START: SpinLock<Point> = SpinLock::new(Point::new(0, 0));

/// Window position at drag start
static DRAG_WINDOW_START: SpinLock<Point> = SpinLock::new(Point::new(0, 0));

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
    if dragging_hwnd.is_valid() {
        // We're in drag mode - handle window movement
        if event.dx != 0 || event.dy != 0 {
            handle_window_drag(x, y);
        }
    } else {
        // Normal mouse movement
        if event.dx != 0 || event.dy != 0 {
            input::process_mouse_move(x, y);
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

                // Check if we clicked on taskbar first
                let (_, height) = super::super::gdi::surface::get_primary_dimensions();
                let taskbar_y = height as i32 - TASKBAR_HEIGHT;
                if y >= taskbar_y {
                    handle_taskbar_click(x, y);
                } else if START_MENU_VISIBLE.load(Ordering::SeqCst) {
                    // Click outside start menu - hide it
                    handle_start_menu_click(x, y);
                } else {
                    // Check if we clicked on a window caption
                    try_start_window_drag(x, y);
                }
            } else if was_down {
                // Button released
                input::process_mouse_button(0, false, x, y);

                // End any drag operation
                end_window_drag();
            }
        }

        // Right button
        if event.buttons.right != LAST_RIGHT {
            LAST_RIGHT = event.buttons.right;
            input::process_mouse_button(1, event.buttons.right, x, y);
        }

        // Middle button
        if event.buttons.middle != LAST_MIDDLE {
            LAST_MIDDLE = event.buttons.middle;
            input::process_mouse_button(2, event.buttons.middle, x, y);
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
        }
        message::hittest::HTCLOSE | message::hittest::HTMINBUTTON | message::hittest::HTMAXBUTTON => {
            // Caption button clicked - send NC button down message
            message::send_message(hwnd, message::WM_NCLBUTTONDOWN, hit as usize, lparam);
        }
        message::hittest::HTCLIENT => {
            // Client area clicked - activate window
            window::set_foreground_window(hwnd);
            input::set_active_window(hwnd);
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

    // Check taskbar buttons
    for button in state.buttons.iter() {
        if !button.valid {
            continue;
        }

        if x >= button.rect.left && x < button.rect.right {
            // Activate this window
            let hwnd = button.hwnd;
            drop(state);

            input::set_active_window(hwnd);
            window::show_window(hwnd, ShowCommand::Show);
            window::set_foreground_window(hwnd);

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

            // Paint client content for test windows
            paint_test_window_client(*hwnd);

            // Clear the needs_paint flag
            window::with_window_mut(*hwnd, |wnd| {
                wnd.needs_paint = false;
            });
        }
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

        dc::delete_dc(hdc);
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

    // Format time (12-hour format)
    let h12 = if hour == 0 { 12 } else if hour > 12 { hour - 12 } else { hour };

    // Build time string characters
    let c0 = if h12 >= 10 { b'1' } else { b' ' };
    let c1 = b'0' + (h12 % 10);
    let c2 = b':';
    let c3 = b'0' + (minute / 10);
    let c4 = b'0' + (minute % 10);

    // Draw each character
    dc::set_text_color(hdc, ColorRef::BLACK);
    dc::set_bk_mode(hdc, dc::BkMode::Transparent);

    let text_x = clock_rect.left + 8;
    let text_y = clock_rect.top + 5;
    let char_width = 8; // Approximate character width

    // Draw time characters individually
    let chars = [c0, c1, c2, c3, c4];
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

/// Start menu item names
const START_MENU_ITEM_NAMES: [&str; START_MENU_ITEMS] = [
    "Programs",
    "Documents",
    "Settings",
    "Run...",
    "Shut Down...",
    "Log Off",
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

    // Repaint desktop to clear the menu
    paint_desktop();
    paint_taskbar();
}

/// Paint the Start menu
fn paint_start_menu() {
    if !START_MENU_VISIBLE.load(Ordering::SeqCst) {
        return;
    }

    if let Ok(hdc) = dc::create_display_dc() {
        let (_, height) = super::super::gdi::surface::get_primary_dimensions();
        let taskbar_y = height as i32 - TASKBAR_HEIGHT;

        // Calculate menu position (above Start button)
        let menu_height = START_MENU_ITEMS as i32 * START_MENU_ITEM_HEIGHT + 4;
        let menu_x = 2;
        let menu_y = taskbar_y - menu_height;

        let menu_rect = Rect::new(
            menu_x, menu_y,
            menu_x + START_MENU_WIDTH, taskbar_y
        );

        // Draw menu background
        let bg_brush = brush::create_solid_brush(ColorRef::BUTTON_FACE);
        super::super::gdi::fill_rect(hdc, &menu_rect, bg_brush);

        // Draw raised edge
        super::super::gdi::draw_edge_raised(hdc, &menu_rect);

        // Draw menu items
        dc::set_text_color(hdc, ColorRef::BLACK);
        dc::set_bk_mode(hdc, dc::BkMode::Transparent);

        for (i, name) in START_MENU_ITEM_NAMES.iter().enumerate() {
            let item_y = menu_y + 2 + (i as i32 * START_MENU_ITEM_HEIGHT);
            let item_rect = Rect::new(
                menu_x + 2, item_y,
                menu_x + START_MENU_WIDTH - 2, item_y + START_MENU_ITEM_HEIGHT
            );

            // Draw item text
            super::super::gdi::text_out(hdc, item_rect.left + 8, item_rect.top + 4, name);

            // Draw separator after Settings
            if i == 2 {
                let sep_y = item_y + START_MENU_ITEM_HEIGHT - 2;
                let sep_pen = pen::create_pen(pen::PenStyle::Solid, 1, ColorRef::BUTTON_SHADOW);
                dc::select_object(hdc, sep_pen);
                super::super::gdi::move_to(hdc, menu_x + 4, sep_y);
                super::super::gdi::line_to(hdc, menu_x + START_MENU_WIDTH - 4, sep_y);
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
    let menu_height = START_MENU_ITEMS as i32 * START_MENU_ITEM_HEIGHT + 4;
    let menu_y = taskbar_y - menu_height;

    // Check if click is in menu area
    if x < 2 || x > 2 + START_MENU_WIDTH || y < menu_y || y >= taskbar_y {
        hide_start_menu();
        return true;
    }

    // Determine which item was clicked
    let relative_y = y - menu_y - 2;
    let item_index = relative_y / START_MENU_ITEM_HEIGHT;

    if item_index >= 0 && (item_index as usize) < START_MENU_ITEMS {
        let item = item_index as usize;
        crate::serial_println!("[EXPLORER] Start menu item clicked: {}", START_MENU_ITEM_NAMES[item]);

        match item {
            3 => {
                // Run... - for now, create a test window
                hide_start_menu();
                create_test_window();
            }
            4 => {
                // Shut Down...
                hide_start_menu();
                crate::serial_println!("[EXPLORER] Initiating shutdown...");
                winlogon::shutdown(false);
            }
            5 => {
                // Log Off
                hide_start_menu();
                crate::serial_println!("[EXPLORER] Initiating logoff...");
                winlogon::logoff();
            }
            _ => {
                hide_start_menu();
                // TODO: Implement other menu items
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
