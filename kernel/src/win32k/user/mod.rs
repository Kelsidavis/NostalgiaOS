//! USER - Window Manager Subsystem
//!
//! Kernel-mode window management following the Windows NT USER architecture.
//! Provides windows, message queues, input handling, and desktop management.
//!
//! # Components
//!
//! - **window**: Window objects and management
//! - **message**: Message queue and dispatch
//! - **class**: Window class registration
//! - **input**: Keyboard and mouse input
//! - **desktop**: Desktop and window station
//! - **paint**: Window painting (WM_PAINT)
//! - **timer**: Timer support for UI updates
//! - **cursor**: Cursor/mouse pointer rendering
//! - **controls**: Standard window controls
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/createw.c` - Window creation
//! - `windows/core/ntuser/kernel/sendmsg.c` - Message sending
//! - `windows/core/ntuser/kernel/input.c` - Input handling
//! - `windows/core/ntuser/kernel/timer.c` - Timer management

pub mod window;
pub mod message;
pub mod class;
pub mod input;
pub mod desktop;
pub mod paint;
pub mod cursor;
pub mod controls;
pub mod timer;
pub mod menu;
pub mod dialog;
pub mod icon;
pub mod clipboard;
pub mod metrics;
pub mod accelerator;
pub mod caret;
pub mod listbox;
pub mod combobox;
pub mod hooks;
pub mod edit;
pub mod resource;
pub mod toolbar;
pub mod statusbar;
pub mod trackbar;
pub mod progressbar;
pub mod updown;
pub mod tab;
pub mod header;
pub mod listview;
pub mod treeview;
pub mod tooltip;
pub mod hotkey;
pub mod animate;
pub mod monthcal;
pub mod datetimepick;
pub mod pager;
pub mod ipaddress;
pub mod rebar;
pub mod comboboxex;
pub mod syslink;

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::{UserHandle, HWND, Rect, Point};

// ============================================================================
// Constants
// ============================================================================

/// Maximum windows per desktop
pub const MAX_WINDOWS: usize = 1024;

/// Maximum window classes
pub const MAX_CLASSES: usize = 256;

/// Maximum message queue size
pub const MAX_QUEUE_SIZE: usize = 256;

// ============================================================================
// Window Styles
// ============================================================================

bitflags::bitflags! {
    /// Window styles (WS_*)
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct WindowStyle: u32 {
        /// Overlapped window (default)
        const OVERLAPPED = 0x00000000;
        /// Popup window
        const POPUP = 0x80000000;
        /// Child window
        const CHILD = 0x40000000;
        /// Initially minimized
        const MINIMIZE = 0x20000000;
        /// Initially visible
        const VISIBLE = 0x10000000;
        /// Initially disabled
        const DISABLED = 0x08000000;
        /// Clip siblings
        const CLIPSIBLINGS = 0x04000000;
        /// Clip children
        const CLIPCHILDREN = 0x02000000;
        /// Initially maximized
        const MAXIMIZE = 0x01000000;
        /// Has caption
        const CAPTION = 0x00C00000;
        /// Has border
        const BORDER = 0x00800000;
        /// Has dialog frame
        const DLGFRAME = 0x00400000;
        /// Has vertical scroll bar
        const VSCROLL = 0x00200000;
        /// Has horizontal scroll bar
        const HSCROLL = 0x00100000;
        /// Has system menu
        const SYSMENU = 0x00080000;
        /// Has thick frame (resizable)
        const THICKFRAME = 0x00040000;
        /// Group box start
        const GROUP = 0x00020000;
        /// Tab stop
        const TABSTOP = 0x00010000;
        /// Has minimize box
        const MINIMIZEBOX = 0x00020000;
        /// Has maximize box
        const MAXIMIZEBOX = 0x00010000;

        // Common combinations
        /// Overlapped window with all decorations
        const OVERLAPPEDWINDOW = Self::OVERLAPPED.bits() | Self::CAPTION.bits() |
            Self::SYSMENU.bits() | Self::THICKFRAME.bits() |
            Self::MINIMIZEBOX.bits() | Self::MAXIMIZEBOX.bits();
        /// Popup window with border and system menu
        const POPUPWINDOW = Self::POPUP.bits() | Self::BORDER.bits() | Self::SYSMENU.bits();
    }
}

bitflags::bitflags! {
    /// Extended window styles (WS_EX_*)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct WindowStyleEx: u32 {
        /// Dialog modal frame
        const DLGMODALFRAME = 0x00000001;
        /// No parent notify
        const NOPARENTNOTIFY = 0x00000004;
        /// Topmost
        const TOPMOST = 0x00000008;
        /// Accept drag files
        const ACCEPTFILES = 0x00000010;
        /// Transparent
        const TRANSPARENT = 0x00000020;
        /// MDI child
        const MDICHILD = 0x00000040;
        /// Tool window
        const TOOLWINDOW = 0x00000080;
        /// Has edge
        const WINDOWEDGE = 0x00000100;
        /// Has client edge
        const CLIENTEDGE = 0x00000200;
        /// Context help button
        const CONTEXTHELP = 0x00000400;
        /// Right-aligned text
        const RIGHT = 0x00001000;
        /// RTL reading order
        const RTLREADING = 0x00002000;
        /// Left scroll bar
        const LEFTSCROLLBAR = 0x00004000;
        /// Control parent
        const CONTROLPARENT = 0x00010000;
        /// Static edge
        const STATICEDGE = 0x00020000;
        /// Activate on show
        const APPWINDOW = 0x00040000;
        /// Layered window
        const LAYERED = 0x00080000;
        /// No inherit layout
        const NOINHERITLAYOUT = 0x00100000;
        /// Right-to-left layout
        const LAYOUTRTL = 0x00400000;
        /// Composited
        const COMPOSITED = 0x02000000;
        /// No activate
        const NOACTIVATE = 0x08000000;
    }
}

// ============================================================================
// Show Window Commands
// ============================================================================

/// Show window commands (SW_*)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShowCommand {
    #[default]
    Hide = 0,
    ShowNormal = 1,
    ShowMinimized = 2,
    ShowMaximized = 3,
    ShowNoActivate = 4,
    Show = 5,
    Minimize = 6,
    ShowMinNoActive = 7,
    ShowNA = 8,
    Restore = 9,
    ShowDefault = 10,
    ForceMinimize = 11,
}

// ============================================================================
// State
// ============================================================================

static USER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static USER_LOCK: SpinLock<()> = SpinLock::new(());

// Statistics
static WINDOW_COUNT: AtomicU32 = AtomicU32::new(0);
static CLASS_COUNT: AtomicU32 = AtomicU32::new(0);
static MESSAGE_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize USER subsystem
pub fn init() {
    let _guard = USER_LOCK.lock();

    if USER_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[USER] Initializing Window Manager...");

    // Initialize desktop
    desktop::init();

    // Initialize window class manager
    class::init();

    // Initialize window manager
    window::init();

    // Initialize message system
    message::init();

    // Initialize input system
    input::init();

    // Initialize paint system
    paint::init();

    // Initialize cursor system
    cursor::init();

    // Initialize controls
    controls::init();

    // Initialize timer system
    timer::init();

    // Initialize menu system
    menu::init();

    // Initialize dialog system
    dialog::init();

    // Initialize icon/cursor system
    icon::init();

    // Initialize clipboard system
    clipboard::init();

    // Initialize metrics system
    metrics::init();

    // Initialize accelerator table system
    accelerator::init();

    // Initialize caret system
    caret::init();

    // Initialize listbox system
    listbox::init();

    // Initialize combobox system
    combobox::init();

    // Initialize hooks system
    hooks::init();

    // Initialize edit control system
    edit::init();

    // Initialize resource manager
    resource::init();

    // Initialize toolbar control
    toolbar::init();

    // Initialize statusbar control
    statusbar::init();

    // Initialize trackbar control
    trackbar::init();

    // Initialize progressbar control
    progressbar::init();

    // Initialize updown control
    updown::init();

    // Initialize tab control
    tab::init();

    // Initialize header control
    header::init();

    // Initialize listview control
    listview::init();

    // Initialize treeview control
    treeview::init();

    // Initialize tooltip control
    tooltip::init();

    // Initialize hotkey control
    hotkey::init();

    // Initialize animate control
    animate::init();

    // Initialize month calendar control
    monthcal::init();

    // Initialize date time picker control
    datetimepick::init();

    // Initialize pager control
    pager::init();

    // Initialize IP address control
    ipaddress::init();

    // Initialize rebar control
    rebar::init();

    // Initialize comboboxex control
    comboboxex::init();

    // Initialize syslink control
    syslink::init();

    // Register built-in window classes
    register_builtin_classes();

    USER_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[USER] Window Manager initialized");
}

/// Register built-in window classes
fn register_builtin_classes() {
    // Register desktop window class
    class::register_system_class("Desktop", 0);

    // Register button class
    class::register_system_class("Button", 0);

    // Register static text class
    class::register_system_class("Static", 0);

    // Register edit control class
    class::register_system_class("Edit", 0);

    // Register listbox class
    class::register_system_class("ListBox", 0);

    // Register combobox class
    class::register_system_class("ComboBox", 0);

    // Register scrollbar class
    class::register_system_class("ScrollBar", 0);

    // Register dialog class
    class::register_system_class("Dialog", 0);

    crate::serial_println!("[USER] Registered built-in window classes");
}

// ============================================================================
// Statistics
// ============================================================================

/// USER statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct UserStats {
    pub initialized: bool,
    pub window_count: u32,
    pub class_count: u32,
    pub message_count: u32,
}

/// Get USER statistics
pub fn get_stats() -> UserStats {
    UserStats {
        initialized: USER_INITIALIZED.load(Ordering::Relaxed),
        window_count: WINDOW_COUNT.load(Ordering::Relaxed),
        class_count: CLASS_COUNT.load(Ordering::Relaxed),
        message_count: MESSAGE_COUNT.load(Ordering::Relaxed),
    }
}

pub fn inc_window_count() { WINDOW_COUNT.fetch_add(1, Ordering::Relaxed); }
pub fn dec_window_count() { WINDOW_COUNT.fetch_sub(1, Ordering::Relaxed); }
pub fn inc_class_count() { CLASS_COUNT.fetch_add(1, Ordering::Relaxed); }
pub fn dec_class_count() { CLASS_COUNT.fetch_sub(1, Ordering::Relaxed); }
pub fn inc_message_count() { MESSAGE_COUNT.fetch_add(1, Ordering::Relaxed); }

// ============================================================================
// High-Level Window API
// ============================================================================

/// Create a window
pub fn create_window(
    class_name: &str,
    window_name: &str,
    style: WindowStyle,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    parent: HWND,
    menu: u32,
) -> HWND {
    window::create_window(
        class_name,
        window_name,
        style,
        WindowStyleEx::empty(),
        x, y, width, height,
        parent,
        menu,
    )
}

/// Create an extended window
pub fn create_window_ex(
    ex_style: WindowStyleEx,
    class_name: &str,
    window_name: &str,
    style: WindowStyle,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    parent: HWND,
    menu: u32,
) -> HWND {
    window::create_window(
        class_name,
        window_name,
        style,
        ex_style,
        x, y, width, height,
        parent,
        menu,
    )
}

/// Destroy a window
pub fn destroy_window(hwnd: HWND) -> bool {
    window::destroy_window(hwnd)
}

/// Show/hide a window
pub fn show_window(hwnd: HWND, cmd: ShowCommand) -> bool {
    window::show_window(hwnd, cmd)
}

/// Update a window (process pending WM_PAINT)
pub fn update_window(hwnd: HWND) -> bool {
    paint::update_window(hwnd)
}

/// Invalidate a region of a window
pub fn invalidate_rect(hwnd: HWND, rect: Option<&Rect>, erase: bool) -> bool {
    paint::invalidate_rect(hwnd, rect, erase)
}

/// Get window rectangle
pub fn get_window_rect(hwnd: HWND) -> Option<Rect> {
    window::get_window_rect(hwnd)
}

/// Get client rectangle
pub fn get_client_rect(hwnd: HWND) -> Option<Rect> {
    window::get_client_rect(hwnd)
}

/// Move a window
pub fn move_window(hwnd: HWND, x: i32, y: i32, width: i32, height: i32, repaint: bool) -> bool {
    window::move_window(hwnd, x, y, width, height, repaint)
}

/// Set window position
pub fn set_window_pos(hwnd: HWND, x: i32, y: i32, width: i32, height: i32, flags: u32) -> bool {
    window::set_window_pos(hwnd, x, y, width, height, flags)
}

/// Get a message from the queue
pub fn get_message(hwnd: HWND) -> Option<message::Message> {
    message::get_message(hwnd)
}

/// Peek at a message (non-blocking)
pub fn peek_message(hwnd: HWND, remove: bool) -> Option<message::Message> {
    message::peek_message(hwnd, remove)
}

/// Post a message to a window
pub fn post_message(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> bool {
    message::post_message(hwnd, msg, wparam, lparam)
}

/// Send a message to a window (blocking)
pub fn send_message(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> isize {
    message::send_message(hwnd, msg, wparam, lparam)
}

/// Dispatch a message to window procedure
pub fn dispatch_message(msg: &message::Message) -> isize {
    message::dispatch_message(msg)
}

/// Translate virtual key messages
pub fn translate_message(msg: &message::Message) -> bool {
    message::translate_message(msg)
}

/// Begin painting (returns DC)
pub fn begin_paint(hwnd: HWND) -> Option<(super::gdi::dc::DeviceContext, paint::PaintStruct)> {
    paint::begin_paint(hwnd)
}

/// End painting
pub fn end_paint(hwnd: HWND, ps: &paint::PaintStruct) {
    paint::end_paint(hwnd, ps)
}

/// Get window DC
pub fn get_dc(hwnd: HWND) -> super::HDC {
    paint::get_window_dc(hwnd)
}

/// Release window DC
pub fn release_dc(hwnd: HWND, hdc: super::HDC) -> bool {
    paint::release_dc(hwnd, hdc)
}

/// Set focus to a window
pub fn set_focus(hwnd: HWND) -> HWND {
    input::set_focus(hwnd)
}

/// Get the focused window
pub fn get_focus() -> HWND {
    input::get_focus()
}

/// Set window text
pub fn set_window_text(hwnd: HWND, text: &str) -> bool {
    window::set_window_text(hwnd, text)
}

/// Get window text
pub fn get_window_text(hwnd: HWND, buffer: &mut [u8]) -> usize {
    window::get_window_text(hwnd, buffer)
}

// ============================================================================
// Timer API
// ============================================================================

/// Create a timer for a window
pub fn set_timer(hwnd: HWND, timer_id: usize, interval_ms: u32) -> usize {
    timer::set_timer(hwnd, timer_id, interval_ms, 0)
}

/// Create a timer with callback
pub fn set_timer_with_callback(hwnd: HWND, timer_id: usize, interval_ms: u32, callback: usize) -> usize {
    timer::set_timer(hwnd, timer_id, interval_ms, callback)
}

/// Destroy a timer
pub fn kill_timer(hwnd: HWND, timer_id: usize) -> bool {
    timer::kill_timer(hwnd, timer_id)
}

/// Get current tick count in milliseconds
pub fn get_tick_count() -> u64 {
    timer::get_tick_count()
}

/// Process expired timers (should be called from message loop)
pub fn process_timers() {
    timer::process_timers()
}

// ============================================================================
// Menu API
// ============================================================================

// Re-export menu types
pub use menu::{MenuFlags, MenuItemType, MenuItemState, TrackPopupFlags};

/// Create a menu
pub fn create_menu() -> super::HMENU {
    menu::create_menu()
}

/// Create a popup menu
pub fn create_popup_menu() -> super::HMENU {
    menu::create_popup_menu()
}

/// Destroy a menu
pub fn destroy_menu(hmenu: super::HMENU) -> bool {
    menu::destroy_menu(hmenu)
}

/// Append a menu item
pub fn append_menu(hmenu: super::HMENU, flags: MenuFlags, id: u32, text: &str) -> bool {
    menu::append_menu(hmenu, flags, id, text)
}

/// Insert a menu item
pub fn insert_menu(hmenu: super::HMENU, position: u32, flags: MenuFlags, id: u32, text: &str) -> bool {
    menu::insert_menu(hmenu, position, flags, id, text)
}

/// Remove a menu item
pub fn remove_menu(hmenu: super::HMENU, position: u32, flags: MenuFlags) -> bool {
    menu::remove_menu(hmenu, position, flags)
}

/// Check or uncheck a menu item
pub fn check_menu_item(hmenu: super::HMENU, id: u32, check: bool) -> bool {
    menu::check_menu_item(hmenu, id, check)
}

/// Enable or disable a menu item
pub fn enable_menu_item(hmenu: super::HMENU, id: u32, enable: bool) -> bool {
    menu::enable_menu_item(hmenu, id, enable)
}

/// Get menu item count
pub fn get_menu_item_count(hmenu: super::HMENU) -> i32 {
    menu::get_menu_item_count(hmenu)
}

/// Get submenu at position
pub fn get_sub_menu(hmenu: super::HMENU, position: i32) -> super::HMENU {
    menu::get_sub_menu(hmenu, position)
}

/// Track and display a popup menu
pub fn track_popup_menu(hmenu: super::HMENU, flags: TrackPopupFlags, x: i32, y: i32, hwnd: HWND) -> u32 {
    menu::track_popup_menu(hmenu, flags, x, y, hwnd)
}

/// Draw a menu bar
pub fn draw_menu_bar(hwnd: HWND, hmenu: super::HMENU, rect: &Rect) {
    menu::draw_menu_bar(hwnd, hmenu, rect)
}

/// Close active popup menu
pub fn close_popup_menu() {
    menu::close_popup_menu()
}

// ============================================================================
// Dialog API
// ============================================================================

// Re-export dialog types
pub use dialog::{DialogStyle, DialogTemplate, DialogControlClass, MessageBoxFlags};
pub use dialog::{IDOK, IDCANCEL, IDABORT, IDRETRY, IDIGNORE, IDYES, IDNO};

/// Create a modeless dialog
pub fn create_dialog(template: &DialogTemplate, parent: HWND) -> HWND {
    dialog::create_dialog(template, parent)
}

/// Create and run a modal dialog
pub fn dialog_box(template: &DialogTemplate, parent: HWND) -> i32 {
    dialog::dialog_box(template, parent)
}

/// End a modal dialog
pub fn end_dialog(hwnd: HWND, result: i32) -> bool {
    dialog::end_dialog(hwnd, result)
}

/// Get dialog control handle by ID
pub fn get_dlg_item(hwnd: HWND, id: i32) -> HWND {
    dialog::get_dlg_item(hwnd, id)
}

/// Set dialog control text
pub fn set_dlg_item_text(hwnd: HWND, id: i32, text: &str) -> bool {
    dialog::set_dlg_item_text(hwnd, id, text)
}

/// Display a message box
pub fn message_box(parent: HWND, text: &str, caption: &str, flags: MessageBoxFlags) -> i32 {
    dialog::message_box(parent, text, caption, flags)
}

// ============================================================================
// Icon API
// ============================================================================

// Re-export icon types
pub use icon::{HICON, HCURSOR, StandardIcon, StandardCursor};

/// Load a standard icon
pub fn load_icon(icon_id: StandardIcon) -> icon::HICON {
    icon::load_icon(icon_id)
}

/// Load a standard cursor
pub fn load_cursor(cursor_id: StandardCursor) -> icon::HCURSOR {
    icon::load_cursor(cursor_id)
}

/// Create an icon from pixel data
pub fn create_icon(width: i32, height: i32, pixels: &[u32], mask: &[u8]) -> icon::HICON {
    icon::create_icon(width, height, pixels, mask)
}

/// Destroy an icon
pub fn destroy_icon(hicon: icon::HICON) -> bool {
    icon::destroy_icon(hicon)
}

/// Draw an icon
pub fn draw_icon(hdc: super::HDC, x: i32, y: i32, hicon: icon::HICON) -> bool {
    icon::draw_icon(hdc, x, y, hicon)
}

// ============================================================================
// Clipboard API
// ============================================================================

// Re-export clipboard types
pub use clipboard::ClipboardFormat;

/// Open the clipboard for access
pub fn open_clipboard(hwnd: HWND) -> bool {
    clipboard::open_clipboard(hwnd)
}

/// Close the clipboard
pub fn close_clipboard() -> bool {
    clipboard::close_clipboard()
}

/// Empty the clipboard
pub fn empty_clipboard() -> bool {
    clipboard::empty_clipboard()
}

/// Set clipboard data
pub fn set_clipboard_data(format: ClipboardFormat, data: &[u8]) -> bool {
    clipboard::set_clipboard_data(format, data)
}

/// Get clipboard data
pub fn get_clipboard_data(format: ClipboardFormat, buffer: &mut [u8]) -> usize {
    clipboard::get_clipboard_data(format, buffer)
}

/// Set clipboard text
pub fn set_clipboard_text(text: &str) -> bool {
    clipboard::set_clipboard_text(text)
}

/// Get clipboard text
pub fn get_clipboard_text(buffer: &mut [u8]) -> usize {
    clipboard::get_clipboard_text(buffer)
}

/// Check if format is available
pub fn is_clipboard_format_available(format: ClipboardFormat) -> bool {
    clipboard::is_clipboard_format_available(format)
}

/// Register a custom clipboard format
pub fn register_clipboard_format(name: &str) -> u32 {
    clipboard::register_clipboard_format(name)
}

// ============================================================================
// System Metrics API
// ============================================================================

// Re-export metrics types
pub use metrics::{SystemMetric, SystemColor};

/// Get a system metric value
pub fn get_system_metrics(index: i32) -> i32 {
    metrics::get_system_metrics(index)
}

/// Get or set system parameters
pub fn system_parameters_info(action: u32, param: u32, data: usize, win_ini: u32) -> bool {
    metrics::system_parameters_info(action, param, data, win_ini)
}

/// Get a system color
pub fn get_sys_color(index: i32) -> u32 {
    metrics::get_sys_color(index)
}

/// Set system colors
pub fn set_sys_colors(indices: &[i32], colors: &[u32]) -> bool {
    metrics::set_sys_colors(indices, colors)
}

/// Get system color brush
pub fn get_sys_color_brush(index: i32) -> super::GdiHandle {
    metrics::get_sys_color_brush(index)
}

/// Set screen size
pub fn set_screen_size(width: i32, height: i32) {
    metrics::set_screen_size(width, height)
}

// ============================================================================
// Accelerator Table API
// ============================================================================

// Re-export accelerator types and constants
pub use accelerator::{
    Accel, HACCEL,
    FVIRTKEY, FNOINVERT, FSHIFT, FCONTROL, FALT,
    vk, cmd,
};

/// Create an accelerator table
pub fn create_accelerator_table(accels: &[Accel]) -> HACCEL {
    accelerator::create_accelerator_table(accels)
}

/// Destroy an accelerator table
pub fn destroy_accelerator_table(haccel: HACCEL) -> bool {
    accelerator::destroy_accelerator_table(haccel)
}

/// Copy accelerator table entries
pub fn copy_accelerator_table(haccel: HACCEL, buffer: &mut [Accel]) -> usize {
    accelerator::copy_accelerator_table(haccel, buffer)
}

/// Translate keyboard message using accelerator table
pub fn translate_accelerator(hwnd: HWND, haccel: HACCEL, msg: &message::MSG) -> bool {
    accelerator::translate_accelerator(hwnd, haccel, msg)
}

/// Update keyboard modifier state
pub fn update_keyboard_modifiers(shift: bool, control: bool, alt: bool) {
    accelerator::update_modifiers(shift, control, alt)
}

/// Create standard Edit menu accelerator table
pub fn create_standard_edit_accelerators() -> HACCEL {
    accelerator::create_standard_edit_accels()
}

/// Create standard File menu accelerator table
pub fn create_standard_file_accelerators() -> HACCEL {
    accelerator::create_standard_file_accels()
}

// ============================================================================
// Caret API
// ============================================================================

/// Create a caret for a window
pub fn create_caret(hwnd: HWND, bitmap: u32, width: i32, height: i32) -> bool {
    caret::create_caret(hwnd, bitmap, width, height)
}

/// Destroy the caret
pub fn destroy_caret() -> bool {
    caret::destroy_caret()
}

/// Show the caret
pub fn show_caret(hwnd: HWND) -> bool {
    caret::show_caret(hwnd)
}

/// Hide the caret
pub fn hide_caret(hwnd: HWND) -> bool {
    caret::hide_caret(hwnd)
}

/// Set caret position
pub fn set_caret_pos(x: i32, y: i32) -> bool {
    caret::set_caret_pos(x, y)
}

/// Get caret position
pub fn get_caret_pos(point: &mut Point) -> bool {
    caret::get_caret_pos_point(point)
}

/// Set caret blink time
pub fn set_caret_blink_time(blink_time: u32) -> bool {
    caret::set_caret_blink_time(blink_time)
}

/// Get caret blink time
pub fn get_caret_blink_time() -> u32 {
    caret::get_caret_blink_time()
}
