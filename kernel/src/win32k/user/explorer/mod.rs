//! Windows Explorer Shell
//!
//! This module implements the Windows Explorer shell, providing the desktop
//! experience including taskbar, system tray, start menu, and desktop icons.
//!
//! # Architecture
//!
//! The explorer shell follows the Windows Server 2003 architecture:
//!
//! ```text
//! Explorer Process
//! ├── CTray (tray.rs) - Main taskbar window
//! │   ├── Start Button
//! │   ├── CTaskBand (taskband.rs) - Task buttons toolbar
//! │   └── CTrayNotify (traynot.rs) - Notification area
//! │       ├── System tray icons
//! │       └── Clock
//! ├── CDesktopHost (deskhost.rs) - Desktop window
//! │   └── Icon view with shell namespace
//! └── Start Menu (startmenu.rs) - Start menu popup
//! ```
//!
//! # References
//!
//! Based on Windows Server 2003 source:
//! - `shell/explorer/initcab.cpp` - Initialization
//! - `shell/explorer/tray.cpp` - CTray implementation
//! - `shell/explorer/taskband.cpp` - Task band
//! - `shell/explorer/traynot.cpp` - Notification area
//! - `shell/explorer/startmnu.cpp` - Start menu
//! - `shell/explorer/desktop2/deskhost.cpp` - Desktop host

pub mod tray;
pub mod taskband;
pub mod traynot;
pub mod deskhost;
pub mod startmenu;

use core::sync::atomic::{AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, Rect};

// ============================================================================
// Shell State
// ============================================================================

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

/// Global shell state
static SHELL_STATE: SpinLock<ShellState> = SpinLock::new(ShellState::NotStarted);

/// Shell running flag
static SHELL_RUNNING: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Public API
// ============================================================================

/// Initialize the explorer shell
///
/// This is the main entry point, equivalent to ExplorerWinMain() in Windows.
/// It creates the desktop and tray windows, then starts the message loop.
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
    // This is equivalent to SHCreateDesktop() in Windows
    let desktop_rect = Rect::new(0, 0, width, height - tray::TASKBAR_HEIGHT);
    deskhost::create_desktop(desktop_rect);

    // Create tray window (taskbar)
    // This is equivalent to c_tray.Init() in Windows
    let taskbar_rect = Rect::new(0, height - tray::TASKBAR_HEIGHT, width, height);
    tray::create_tray(taskbar_rect, width);

    {
        let mut state = SHELL_STATE.lock();
        *state = ShellState::Running;
    }

    SHELL_RUNNING.store(true, Ordering::SeqCst);

    crate::serial_println!("[EXPLORER] Shell initialized");
}

/// Run the explorer message loop
///
/// This is equivalent to SHDesktopMessageLoop() in Windows.
pub fn run_message_loop() {
    crate::serial_println!("[EXPLORER] Starting message pump...");
    tray::message_loop();
}

/// Check if the shell is running
pub fn is_running() -> bool {
    SHELL_RUNNING.load(Ordering::SeqCst)
}

/// Get the current shell state
pub fn get_state() -> ShellState {
    *SHELL_STATE.lock()
}

/// Repaint the desktop
pub fn paint_desktop() {
    deskhost::paint_desktop();
}

/// Repaint the taskbar
pub fn paint_taskbar() {
    tray::paint_taskbar();
}

/// Register a window with the taskbar
pub fn register_taskbar_window(hwnd: HWND) {
    taskband::add_task(hwnd);
}

/// Unregister a window from the taskbar
pub fn unregister_taskbar_window(hwnd: HWND) {
    taskband::remove_task(hwnd);
}

/// Check if context menu is visible
pub fn is_context_menu_visible() -> bool {
    deskhost::is_context_menu_visible()
}

// ============================================================================
// Legacy API Compatibility
// ============================================================================

/// Run the explorer message pump (legacy name for run_message_loop)
pub fn run_message_pump() {
    run_message_loop();
}

/// Add a taskbar button (legacy name for register_taskbar_window)
pub fn add_taskbar_button(hwnd: HWND) {
    register_taskbar_window(hwnd);
}

/// Remove a taskbar button (legacy name for unregister_taskbar_window)
pub fn remove_taskbar_button(hwnd: HWND) {
    unregister_taskbar_window(hwnd);
}

/// Stop the explorer shell
pub fn stop() {
    let mut state = SHELL_STATE.lock();
    *state = ShellState::ShuttingDown;
    SHELL_RUNNING.store(false, Ordering::SeqCst);
}

/// Get the desktop window handle
pub fn get_desktop_hwnd() -> HWND {
    deskhost::get_desktop_hwnd()
}

/// Get the taskbar window handle
pub fn get_taskbar_hwnd() -> HWND {
    tray::get_tray_hwnd()
}

/// Handle click on start menu (forwarded to startmenu module)
pub fn handle_start_menu_click(x: i32, y: i32) -> bool {
    startmenu::handle_click(x, y)
}
