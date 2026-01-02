//! Mouse Settings Dialog
//!
//! Kernel-mode mouse properties control panel applet following Windows NT patterns.
//! Provides mouse button configuration, pointer speed, double-click, and wheel settings.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/cpls/main/mousectl.c` - Mouse control panel

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, Rect, Point};

// ============================================================================
// Constants
// ============================================================================

/// Maximum pointer schemes
const MAX_POINTER_SCHEMES: usize = 16;

/// Maximum cursors in a scheme
const MAX_CURSORS_PER_SCHEME: usize = 16;

/// Maximum cursor name length
const MAX_CURSOR_NAME: usize = 64;

/// Maximum scheme name length
const MAX_SCHEME_NAME: usize = 64;

/// Maximum pointer trail length
const MAX_POINTER_TRAIL: u32 = 7;

/// Mouse button identifiers
pub mod mouse_buttons {
    /// Left mouse button
    pub const LEFT: u32 = 0;
    /// Right mouse button
    pub const RIGHT: u32 = 1;
    /// Middle mouse button
    pub const MIDDLE: u32 = 2;
    /// X button 1
    pub const XBUTTON1: u32 = 3;
    /// X button 2
    pub const XBUTTON2: u32 = 4;
}

/// Standard cursor types
pub mod cursor_type {
    pub const ARROW: u32 = 0;
    pub const IBEAM: u32 = 1;
    pub const WAIT: u32 = 2;
    pub const CROSS: u32 = 3;
    pub const UPARROW: u32 = 4;
    pub const SIZE: u32 = 5;
    pub const ICON: u32 = 6;
    pub const SIZENWSE: u32 = 7;
    pub const SIZENESW: u32 = 8;
    pub const SIZEWE: u32 = 9;
    pub const SIZENS: u32 = 10;
    pub const SIZEALL: u32 = 11;
    pub const NO: u32 = 12;
    pub const HAND: u32 = 13;
    pub const APPSTARTING: u32 = 14;
    pub const HELP: u32 = 15;
}

/// Pointer scheme flags
pub mod scheme_flags {
    /// System scheme (built-in)
    pub const SYSTEM: u32 = 0x0001;
    /// User scheme
    pub const USER: u32 = 0x0002;
    /// High contrast scheme
    pub const HIGH_CONTRAST: u32 = 0x0004;
    /// Large pointers
    pub const LARGE: u32 = 0x0008;
    /// Extra large pointers
    pub const EXTRA_LARGE: u32 = 0x0010;
    /// Inverted colors
    pub const INVERTED: u32 = 0x0020;
}

/// System parameter indices for mouse
pub mod spi {
    /// Get/set mouse speed (1-20)
    pub const MOUSE_SPEED: u32 = 0x0070;
    /// Get/set mouse trails
    pub const MOUSE_TRAILS: u32 = 0x005E;
    /// Get/set double-click time
    pub const DOUBLE_CLICK_TIME: u32 = 0x001F;
    /// Get/set swap buttons
    pub const SWAP_BUTTONS: u32 = 0x0021;
    /// Get/set snap to default button
    pub const SNAP_TO_DEFAULT: u32 = 0x005F;
    /// Get/set mouse hover time
    pub const MOUSE_HOVER_TIME: u32 = 0x0066;
    /// Get/set mouse hover width
    pub const MOUSE_HOVER_WIDTH: u32 = 0x0062;
    /// Get/set mouse hover height
    pub const MOUSE_HOVER_HEIGHT: u32 = 0x0064;
    /// Get/set wheel scroll lines
    pub const WHEEL_SCROLL_LINES: u32 = 0x0068;
    /// Get/set wheel scroll chars
    pub const WHEEL_SCROLL_CHARS: u32 = 0x006C;
}

// ============================================================================
// Types
// ============================================================================

/// Cursor info in a pointer scheme
#[derive(Clone, Copy)]
pub struct CursorInfo {
    /// Cursor type
    pub cursor_type: u32,
    /// Cursor file name
    pub file_name: [u8; MAX_CURSOR_NAME],
    /// File name length
    pub file_name_len: u8,
    /// Is animated cursor (.ani)
    pub is_animated: bool,
    /// Custom hotspot X
    pub hotspot_x: i16,
    /// Custom hotspot Y
    pub hotspot_y: i16,
}

impl CursorInfo {
    pub const fn new() -> Self {
        Self {
            cursor_type: 0,
            file_name: [0; MAX_CURSOR_NAME],
            file_name_len: 0,
            is_animated: false,
            hotspot_x: 0,
            hotspot_y: 0,
        }
    }
}

/// Pointer scheme
#[derive(Clone, Copy)]
pub struct PointerScheme {
    /// Scheme name
    pub name: [u8; MAX_SCHEME_NAME],
    /// Name length
    pub name_len: u8,
    /// Scheme flags
    pub flags: u32,
    /// Cursors in this scheme
    pub cursors: [CursorInfo; MAX_CURSORS_PER_SCHEME],
    /// Number of cursors
    pub cursor_count: u8,
    /// Is active scheme
    pub is_active: bool,
}

impl PointerScheme {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_SCHEME_NAME],
            name_len: 0,
            flags: 0,
            cursors: [const { CursorInfo::new() }; MAX_CURSORS_PER_SCHEME],
            cursor_count: 0,
            is_active: false,
        }
    }
}

/// Mouse settings state
#[derive(Clone, Copy)]
pub struct MouseSettings {
    /// Mouse speed (1-20, 10 = default)
    pub speed: u32,
    /// Enhanced pointer precision (acceleration)
    pub enhanced_precision: bool,
    /// Swap left and right buttons
    pub swap_buttons: bool,
    /// Double-click speed (ms)
    pub double_click_time: u32,
    /// Click lock enabled
    pub click_lock: bool,
    /// Click lock time (ms)
    pub click_lock_time: u32,
    /// Show pointer trails
    pub pointer_trails: bool,
    /// Trail length (1-7)
    pub trail_length: u32,
    /// Hide pointer while typing
    pub hide_while_typing: bool,
    /// Show pointer location on Ctrl press
    pub show_location: bool,
    /// Snap to default button
    pub snap_to_default: bool,
    /// Wheel scroll lines (0 = page at a time)
    pub wheel_scroll_lines: u32,
    /// Wheel scroll chars for horizontal scroll
    pub wheel_scroll_chars: u32,
    /// Hover time (ms)
    pub hover_time: u32,
    /// Hover width (pixels)
    pub hover_width: u32,
    /// Hover height (pixels)
    pub hover_height: u32,
    /// Current pointer scheme index
    pub current_scheme: usize,
}

impl MouseSettings {
    pub const fn new() -> Self {
        Self {
            speed: 10,
            enhanced_precision: true,
            swap_buttons: false,
            double_click_time: 500,
            click_lock: false,
            click_lock_time: 1200,
            pointer_trails: false,
            trail_length: 1,
            hide_while_typing: true,
            show_location: false,
            snap_to_default: false,
            wheel_scroll_lines: 3,
            wheel_scroll_chars: 3,
            hover_time: 400,
            hover_width: 4,
            hover_height: 4,
            current_scheme: 0,
        }
    }
}

/// Mouse dialog state
#[derive(Clone)]
struct MouseDialog {
    /// Parent window
    parent: HWND,
    /// Current page (0=Buttons, 1=Pointers, 2=Options, 3=Wheel)
    current_page: u32,
    /// Settings modified
    modified: bool,
    /// Original settings for cancel
    original_settings: MouseSettings,
}

impl MouseDialog {
    const fn new() -> Self {
        Self {
            parent: UserHandle::NULL,
            current_page: 0,
            modified: false,
            original_settings: MouseSettings::new(),
        }
    }
}

// ============================================================================
// Static State
// ============================================================================

/// Module initialized
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Global mouse settings
static SETTINGS: SpinLock<MouseSettings> = SpinLock::new(MouseSettings::new());

/// Pointer schemes
static SCHEMES: SpinLock<[PointerScheme; MAX_POINTER_SCHEMES]> =
    SpinLock::new([const { PointerScheme::new() }; MAX_POINTER_SCHEMES]);

/// Scheme count
static SCHEME_COUNT: AtomicU32 = AtomicU32::new(0);

/// Active dialog
static DIALOG: SpinLock<MouseDialog> = SpinLock::new(MouseDialog::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize mouse settings
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Initialize default pointer schemes
    init_default_schemes();

    crate::serial_println!("[MOUSE] Mouse settings initialized");
}

/// Initialize default pointer schemes
fn init_default_schemes() {
    let mut schemes = SCHEMES.lock();
    let mut count = 0;

    // Windows Default
    {
        let scheme = &mut schemes[count];
        let name = b"Windows Default";
        let len = name.len();
        scheme.name[..len].copy_from_slice(name);
        scheme.name_len = len as u8;
        scheme.flags = scheme_flags::SYSTEM;
        scheme.is_active = true;
        init_default_cursors(&mut scheme.cursors, &mut scheme.cursor_count);
        count += 1;
    }

    // Windows Black
    {
        let scheme = &mut schemes[count];
        let name = b"Windows Black";
        let len = name.len();
        scheme.name[..len].copy_from_slice(name);
        scheme.name_len = len as u8;
        scheme.flags = scheme_flags::SYSTEM | scheme_flags::INVERTED;
        init_default_cursors(&mut scheme.cursors, &mut scheme.cursor_count);
        count += 1;
    }

    // Windows Black (large)
    {
        let scheme = &mut schemes[count];
        let name = b"Windows Black (large)";
        let len = name.len();
        scheme.name[..len].copy_from_slice(name);
        scheme.name_len = len as u8;
        scheme.flags = scheme_flags::SYSTEM | scheme_flags::INVERTED | scheme_flags::LARGE;
        init_default_cursors(&mut scheme.cursors, &mut scheme.cursor_count);
        count += 1;
    }

    // Windows Black (extra large)
    {
        let scheme = &mut schemes[count];
        let name = b"Windows Black (extra large)";
        let len = name.len();
        scheme.name[..len].copy_from_slice(name);
        scheme.name_len = len as u8;
        scheme.flags = scheme_flags::SYSTEM | scheme_flags::INVERTED | scheme_flags::EXTRA_LARGE;
        init_default_cursors(&mut scheme.cursors, &mut scheme.cursor_count);
        count += 1;
    }

    // Windows Inverted
    {
        let scheme = &mut schemes[count];
        let name = b"Windows Inverted";
        let len = name.len();
        scheme.name[..len].copy_from_slice(name);
        scheme.name_len = len as u8;
        scheme.flags = scheme_flags::SYSTEM | scheme_flags::INVERTED;
        init_default_cursors(&mut scheme.cursors, &mut scheme.cursor_count);
        count += 1;
    }

    // Windows Inverted (large)
    {
        let scheme = &mut schemes[count];
        let name = b"Windows Inverted (large)";
        let len = name.len();
        scheme.name[..len].copy_from_slice(name);
        scheme.name_len = len as u8;
        scheme.flags = scheme_flags::SYSTEM | scheme_flags::INVERTED | scheme_flags::LARGE;
        init_default_cursors(&mut scheme.cursors, &mut scheme.cursor_count);
        count += 1;
    }

    // Windows Standard (large)
    {
        let scheme = &mut schemes[count];
        let name = b"Windows Standard (large)";
        let len = name.len();
        scheme.name[..len].copy_from_slice(name);
        scheme.name_len = len as u8;
        scheme.flags = scheme_flags::SYSTEM | scheme_flags::LARGE;
        init_default_cursors(&mut scheme.cursors, &mut scheme.cursor_count);
        count += 1;
    }

    // Windows Standard (extra large)
    {
        let scheme = &mut schemes[count];
        let name = b"Windows Standard (extra large)";
        let len = name.len();
        scheme.name[..len].copy_from_slice(name);
        scheme.name_len = len as u8;
        scheme.flags = scheme_flags::SYSTEM | scheme_flags::EXTRA_LARGE;
        init_default_cursors(&mut scheme.cursors, &mut scheme.cursor_count);
        count += 1;
    }

    // (None)
    {
        let scheme = &mut schemes[count];
        let name = b"(None)";
        let len = name.len();
        scheme.name[..len].copy_from_slice(name);
        scheme.name_len = len as u8;
        scheme.flags = scheme_flags::SYSTEM;
        // No custom cursors - uses system defaults
        scheme.cursor_count = 0;
        count += 1;
    }

    SCHEME_COUNT.store(count as u32, Ordering::Release);
}

/// Initialize default cursor entries for a scheme
fn init_default_cursors(cursors: &mut [CursorInfo; MAX_CURSORS_PER_SCHEME], count: &mut u8) {
    let cursor_names: [(&[u8], u32); 16] = [
        (b"arrow.cur", cursor_type::ARROW),
        (b"ibeam.cur", cursor_type::IBEAM),
        (b"wait.ani", cursor_type::WAIT),
        (b"cross.cur", cursor_type::CROSS),
        (b"uparrow.cur", cursor_type::UPARROW),
        (b"size.cur", cursor_type::SIZE),
        (b"icon.cur", cursor_type::ICON),
        (b"sizenwse.cur", cursor_type::SIZENWSE),
        (b"sizenesw.cur", cursor_type::SIZENESW),
        (b"sizewe.cur", cursor_type::SIZEWE),
        (b"sizens.cur", cursor_type::SIZENS),
        (b"sizeall.cur", cursor_type::SIZEALL),
        (b"no.cur", cursor_type::NO),
        (b"hand.cur", cursor_type::HAND),
        (b"appstart.ani", cursor_type::APPSTARTING),
        (b"help.cur", cursor_type::HELP),
    ];

    for (i, (name, cursor_type)) in cursor_names.iter().enumerate() {
        let cursor = &mut cursors[i];
        cursor.cursor_type = *cursor_type;
        let len = name.len();
        cursor.file_name[..len].copy_from_slice(name);
        cursor.file_name_len = len as u8;
        cursor.is_animated = name.ends_with(b".ani");
    }

    *count = cursor_names.len() as u8;
}

// ============================================================================
// Settings Access
// ============================================================================

/// Get mouse speed (1-20)
pub fn get_mouse_speed() -> u32 {
    SETTINGS.lock().speed
}

/// Set mouse speed (1-20)
pub fn set_mouse_speed(speed: u32) -> bool {
    if speed < 1 || speed > 20 {
        return false;
    }
    SETTINGS.lock().speed = speed;
    true
}

/// Get double-click time in milliseconds
pub fn get_double_click_time() -> u32 {
    SETTINGS.lock().double_click_time
}

/// Set double-click time in milliseconds
pub fn set_double_click_time(time: u32) -> bool {
    if time < 200 || time > 900 {
        return false;
    }
    SETTINGS.lock().double_click_time = time;
    true
}

/// Check if buttons are swapped
pub fn get_swap_buttons() -> bool {
    SETTINGS.lock().swap_buttons
}

/// Set button swap
pub fn set_swap_buttons(swap: bool) {
    SETTINGS.lock().swap_buttons = swap;
}

/// Get pointer trails setting
pub fn get_pointer_trails() -> (bool, u32) {
    let settings = SETTINGS.lock();
    (settings.pointer_trails, settings.trail_length)
}

/// Set pointer trails
pub fn set_pointer_trails(enabled: bool, length: u32) -> bool {
    if length > MAX_POINTER_TRAIL {
        return false;
    }
    let mut settings = SETTINGS.lock();
    settings.pointer_trails = enabled;
    settings.trail_length = length;
    true
}

/// Get snap to default button setting
pub fn get_snap_to_default() -> bool {
    SETTINGS.lock().snap_to_default
}

/// Set snap to default button
pub fn set_snap_to_default(snap: bool) {
    SETTINGS.lock().snap_to_default = snap;
}

/// Get wheel scroll lines
pub fn get_wheel_scroll_lines() -> u32 {
    SETTINGS.lock().wheel_scroll_lines
}

/// Set wheel scroll lines (0 = one page at a time)
pub fn set_wheel_scroll_lines(lines: u32) {
    SETTINGS.lock().wheel_scroll_lines = lines;
}

/// Get wheel scroll chars (horizontal)
pub fn get_wheel_scroll_chars() -> u32 {
    SETTINGS.lock().wheel_scroll_chars
}

/// Set wheel scroll chars
pub fn set_wheel_scroll_chars(chars: u32) {
    SETTINGS.lock().wheel_scroll_chars = chars;
}

/// Get enhanced pointer precision
pub fn get_enhanced_precision() -> bool {
    SETTINGS.lock().enhanced_precision
}

/// Set enhanced pointer precision
pub fn set_enhanced_precision(enabled: bool) {
    SETTINGS.lock().enhanced_precision = enabled;
}

/// Get hide pointer while typing
pub fn get_hide_while_typing() -> bool {
    SETTINGS.lock().hide_while_typing
}

/// Set hide pointer while typing
pub fn set_hide_while_typing(hide: bool) {
    SETTINGS.lock().hide_while_typing = hide;
}

/// Get show pointer location on Ctrl
pub fn get_show_location() -> bool {
    SETTINGS.lock().show_location
}

/// Set show pointer location on Ctrl
pub fn set_show_location(show: bool) {
    SETTINGS.lock().show_location = show;
}

/// Get click lock settings
pub fn get_click_lock() -> (bool, u32) {
    let settings = SETTINGS.lock();
    (settings.click_lock, settings.click_lock_time)
}

/// Set click lock settings
pub fn set_click_lock(enabled: bool, time: u32) {
    let mut settings = SETTINGS.lock();
    settings.click_lock = enabled;
    settings.click_lock_time = time;
}

/// Get hover time in milliseconds
pub fn get_hover_time() -> u32 {
    SETTINGS.lock().hover_time
}

/// Set hover time
pub fn set_hover_time(time: u32) {
    SETTINGS.lock().hover_time = time;
}

/// Get hover dimensions
pub fn get_hover_dimensions() -> (u32, u32) {
    let settings = SETTINGS.lock();
    (settings.hover_width, settings.hover_height)
}

/// Set hover dimensions
pub fn set_hover_dimensions(width: u32, height: u32) {
    let mut settings = SETTINGS.lock();
    settings.hover_width = width;
    settings.hover_height = height;
}

// ============================================================================
// Pointer Scheme Management
// ============================================================================

/// Get number of pointer schemes
pub fn get_scheme_count() -> u32 {
    SCHEME_COUNT.load(Ordering::Acquire)
}

/// Get pointer scheme info by index
pub fn get_scheme_info(index: usize, name: &mut [u8], flags: &mut u32) -> bool {
    let schemes = SCHEMES.lock();
    let count = SCHEME_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    let scheme = &schemes[index];
    let name_len = scheme.name_len as usize;
    let copy_len = name.len().min(name_len);
    name[..copy_len].copy_from_slice(&scheme.name[..copy_len]);
    *flags = scheme.flags;

    true
}

/// Get active pointer scheme index
pub fn get_active_scheme() -> usize {
    let schemes = SCHEMES.lock();
    let count = SCHEME_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        if schemes[i].is_active {
            return i;
        }
    }
    0
}

/// Set active pointer scheme
pub fn set_active_scheme(index: usize) -> bool {
    let mut schemes = SCHEMES.lock();
    let count = SCHEME_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    // Deactivate current
    for i in 0..count {
        schemes[i].is_active = false;
    }

    // Activate new
    schemes[index].is_active = true;

    // Update settings
    SETTINGS.lock().current_scheme = index;

    // Apply cursors
    apply_scheme_cursors(&schemes[index]);

    true
}

/// Get cursor info from a scheme
pub fn get_scheme_cursor(scheme_index: usize, cursor_type: u32,
                         file_name: &mut [u8]) -> bool {
    let schemes = SCHEMES.lock();
    let count = SCHEME_COUNT.load(Ordering::Acquire) as usize;

    if scheme_index >= count {
        return false;
    }

    let scheme = &schemes[scheme_index];
    let cursor_count = scheme.cursor_count as usize;

    for i in 0..cursor_count {
        if scheme.cursors[i].cursor_type == cursor_type {
            let len = scheme.cursors[i].file_name_len as usize;
            let copy_len = file_name.len().min(len);
            file_name[..copy_len].copy_from_slice(&scheme.cursors[i].file_name[..copy_len]);
            return true;
        }
    }

    false
}

/// Set cursor in a scheme
pub fn set_scheme_cursor(scheme_index: usize, cursor_type: u32,
                         file_name: &[u8]) -> bool {
    let mut schemes = SCHEMES.lock();
    let count = SCHEME_COUNT.load(Ordering::Acquire) as usize;

    if scheme_index >= count {
        return false;
    }

    // Don't modify system schemes
    if schemes[scheme_index].flags & scheme_flags::SYSTEM != 0 {
        return false;
    }

    let scheme = &mut schemes[scheme_index];
    let cursor_count = scheme.cursor_count as usize;

    // Find existing cursor entry
    for i in 0..cursor_count {
        if scheme.cursors[i].cursor_type == cursor_type {
            let len = file_name.len().min(MAX_CURSOR_NAME);
            scheme.cursors[i].file_name[..len].copy_from_slice(&file_name[..len]);
            scheme.cursors[i].file_name_len = len as u8;
            scheme.cursors[i].is_animated = file_name.ends_with(b".ani");
            return true;
        }
    }

    // Add new cursor entry if space available
    if cursor_count < MAX_CURSORS_PER_SCHEME {
        let cursor = &mut scheme.cursors[cursor_count];
        cursor.cursor_type = cursor_type;
        let len = file_name.len().min(MAX_CURSOR_NAME);
        cursor.file_name[..len].copy_from_slice(&file_name[..len]);
        cursor.file_name_len = len as u8;
        cursor.is_animated = file_name.ends_with(b".ani");
        scheme.cursor_count += 1;
        return true;
    }

    false
}

/// Create a new user pointer scheme
pub fn create_scheme(name: &[u8]) -> Option<usize> {
    let mut schemes = SCHEMES.lock();
    let count = SCHEME_COUNT.load(Ordering::Acquire) as usize;

    if count >= MAX_POINTER_SCHEMES {
        return None;
    }

    let scheme = &mut schemes[count];
    let name_len = name.len().min(MAX_SCHEME_NAME);
    scheme.name[..name_len].copy_from_slice(&name[..name_len]);
    scheme.name_len = name_len as u8;
    scheme.flags = scheme_flags::USER;
    scheme.cursor_count = 0;
    scheme.is_active = false;

    SCHEME_COUNT.store((count + 1) as u32, Ordering::Release);

    Some(count)
}

/// Delete a user pointer scheme
pub fn delete_scheme(index: usize) -> bool {
    let mut schemes = SCHEMES.lock();
    let count = SCHEME_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    // Don't delete system schemes
    if schemes[index].flags & scheme_flags::SYSTEM != 0 {
        return false;
    }

    // Don't delete active scheme
    if schemes[index].is_active {
        return false;
    }

    // Shift remaining schemes
    for i in index..(count - 1) {
        schemes[i] = schemes[i + 1];
    }

    // Clear last slot
    schemes[count - 1] = PointerScheme::new();

    SCHEME_COUNT.store((count - 1) as u32, Ordering::Release);

    true
}

/// Apply scheme cursors to the system
fn apply_scheme_cursors(_scheme: &PointerScheme) {
    // In a real implementation, this would:
    // 1. Load cursor files from scheme
    // 2. Set system cursors via SetSystemCursor
    // 3. Update cursor cache
}

// ============================================================================
// Dialog API
// ============================================================================

/// Show mouse properties dialog
pub fn show_mouse_properties(parent: HWND) -> bool {
    let mut dialog = DIALOG.lock();

    // Store parent
    dialog.parent = parent;
    dialog.current_page = 0;
    dialog.modified = false;

    // Copy current settings for cancel
    dialog.original_settings = *SETTINGS.lock();

    // In a real implementation, this would create and show
    // a property sheet dialog with tabs for:
    // - Buttons (swap, double-click, click lock)
    // - Pointers (scheme selection, cursor customization)
    // - Pointer Options (speed, visibility, snap-to)
    // - Wheel (scroll settings)

    true
}

/// Apply pending mouse settings
pub fn apply_settings() -> bool {
    let dialog = DIALOG.lock();

    if !dialog.modified {
        return true;
    }

    // Settings are already applied in real-time via set_* functions
    // This just confirms the changes

    true
}

/// Cancel pending changes and restore original
pub fn cancel_settings() {
    let dialog = DIALOG.lock();

    if dialog.modified {
        // Restore original settings
        let mut settings = SETTINGS.lock();
        *settings = dialog.original_settings;
    }
}

// ============================================================================
// System Parameter Interface
// ============================================================================

/// Handle SPI_GETMOUSESPEED / SPI_SETMOUSESPEED
pub fn system_parameters_mouse(action: u32, param: u32, get: bool) -> u32 {
    match action {
        spi::MOUSE_SPEED => {
            if get {
                get_mouse_speed()
            } else {
                if set_mouse_speed(param) { 1 } else { 0 }
            }
        }
        spi::MOUSE_TRAILS => {
            if get {
                let (enabled, length) = get_pointer_trails();
                if enabled { length } else { 0 }
            } else {
                if param > 0 {
                    set_pointer_trails(true, param);
                } else {
                    set_pointer_trails(false, 1);
                }
                1
            }
        }
        spi::DOUBLE_CLICK_TIME => {
            if get {
                get_double_click_time()
            } else {
                if set_double_click_time(param) { 1 } else { 0 }
            }
        }
        spi::SWAP_BUTTONS => {
            if get {
                if get_swap_buttons() { 1 } else { 0 }
            } else {
                set_swap_buttons(param != 0);
                1
            }
        }
        spi::SNAP_TO_DEFAULT => {
            if get {
                if get_snap_to_default() { 1 } else { 0 }
            } else {
                set_snap_to_default(param != 0);
                1
            }
        }
        spi::MOUSE_HOVER_TIME => {
            if get {
                get_hover_time()
            } else {
                set_hover_time(param);
                1
            }
        }
        spi::WHEEL_SCROLL_LINES => {
            if get {
                get_wheel_scroll_lines()
            } else {
                set_wheel_scroll_lines(param);
                1
            }
        }
        spi::WHEEL_SCROLL_CHARS => {
            if get {
                get_wheel_scroll_chars()
            } else {
                set_wheel_scroll_chars(param);
                1
            }
        }
        _ => 0,
    }
}

// ============================================================================
// Button Mapping
// ============================================================================

/// Get effective button for an input button (handles swap)
pub fn get_effective_button(button: u32) -> u32 {
    if get_swap_buttons() {
        match button {
            mouse_buttons::LEFT => mouse_buttons::RIGHT,
            mouse_buttons::RIGHT => mouse_buttons::LEFT,
            _ => button,
        }
    } else {
        button
    }
}

/// Integer square root using Newton's method
fn integer_sqrt(n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Calculate mouse movement with speed and acceleration
pub fn calculate_movement(dx: i32, dy: i32) -> (i32, i32) {
    let settings = SETTINGS.lock();
    let speed = settings.speed;
    let precision = settings.enhanced_precision;
    drop(settings);

    // Speed factor (10 = 1.0, 1 = 0.1, 20 = 2.0)
    let factor = speed as i32;

    let mut out_dx = dx * factor / 10;
    let mut out_dy = dy * factor / 10;

    // Enhanced precision adds acceleration for larger movements
    if precision {
        // Integer approximation of magnitude = sqrt(dx^2 + dy^2)
        let sum_sq = dx * dx + dy * dy;
        let magnitude = integer_sqrt(sum_sq as u32) as i32;
        if magnitude > 4 {
            let accel = 1 + magnitude / 10;
            out_dx = out_dx * accel;
            out_dy = out_dy * accel;
        }
    }

    (out_dx, out_dy)
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Copy all mouse settings
pub fn copy_settings(dest: &mut MouseSettings) {
    *dest = *SETTINGS.lock();
}

/// Restore all mouse settings
pub fn restore_settings(src: &MouseSettings) {
    *SETTINGS.lock() = *src;
}

/// Reset to default settings
pub fn reset_to_defaults() {
    let mut settings = SETTINGS.lock();
    *settings = MouseSettings::new();

    // Set default scheme active
    let mut schemes = SCHEMES.lock();
    let count = SCHEME_COUNT.load(Ordering::Acquire) as usize;
    for i in 0..count {
        schemes[i].is_active = i == 0;
    }
}
