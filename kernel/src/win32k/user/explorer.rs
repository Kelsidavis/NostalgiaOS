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
use super::{message, window, input, desktop, controls, cursor, WindowStyle, WindowStyleEx, ShowCommand};

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

    while SHELL_RUNNING.load(Ordering::SeqCst) {
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

    // Process mouse movement
    if event.dx != 0 || event.dy != 0 {
        input::process_mouse_move(x, y);
    }

    // Process button clicks
    static mut LAST_LEFT: bool = false;
    static mut LAST_RIGHT: bool = false;
    static mut LAST_MIDDLE: bool = false;

    unsafe {
        // Left button
        if event.buttons.left != LAST_LEFT {
            LAST_LEFT = event.buttons.left;
            input::process_mouse_button(0, event.buttons.left, x, y);

            // Handle taskbar clicks
            if event.buttons.left {
                handle_taskbar_click(x, y);
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
        crate::serial_println!("[EXPLORER] Start button clicked");
        // TODO: Show Start menu
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

    // Check for Alt key (high bit set means key is down, 0x8000 as i16 is -32768)
    let alt_down = (input::get_key_state(input::vk::MENU) & (-32768i16)) != 0;

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
            message::post_message(*hwnd, message::WM_PAINT, 0, 0);
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

    // Draw sunken area for clock
    super::super::gdi::draw_edge_sunken(hdc, &clock_rect);

    // Get current time from RTC
    let datetime = crate::hal::rtc::get_datetime();
    let hour = datetime.hour;
    let minute = datetime.minute;

    // Format time string
    let time_str = format_time(hour, minute);

    // Draw time text centered
    dc::set_text_color(hdc, ColorRef::BLACK);
    dc::set_bk_mode(hdc, dc::BkMode::Transparent);
    let text_x = clock_rect.left + 5;
    let text_y = clock_rect.top + 5;
    super::super::gdi::text_out(hdc, text_x, text_y, &time_str);
}

/// Format time string
fn format_time(hour: u8, minute: u8) -> &'static str {
    // Use a static buffer approach
    // For simplicity, just return placeholder
    // In a full implementation, we'd use a proper formatting approach
    "12:00"
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
