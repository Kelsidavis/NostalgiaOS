//! Display Settings Dialog
//!
//! Provides display properties and monitor configuration following
//! Windows patterns.
//!
//! # References
//!
//! - Windows Server 2003 Display Properties
//! - ChangeDisplaySettings/EnumDisplaySettings APIs

use core::sync::atomic::{AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle, Rect};

// ============================================================================
// Constants
// ============================================================================

/// Display mode flags
pub mod dm_flags {
    /// Orientation
    pub const ORIENTATION: u32 = 0x00000001;
    /// Paper size
    pub const PAPERSIZE: u32 = 0x00000002;
    /// Paper length
    pub const PAPERLENGTH: u32 = 0x00000004;
    /// Paper width
    pub const PAPERWIDTH: u32 = 0x00000008;
    /// Bits per pixel
    pub const BITSPERPEL: u32 = 0x00040000;
    /// Pels width (horizontal resolution)
    pub const PELSWIDTH: u32 = 0x00080000;
    /// Pels height (vertical resolution)
    pub const PELSHEIGHT: u32 = 0x00100000;
    /// Display flags
    pub const DISPLAYFLAGS: u32 = 0x00200000;
    /// Display frequency
    pub const DISPLAYFREQUENCY: u32 = 0x00400000;
    /// Position
    pub const POSITION: u32 = 0x00000020;
}

/// ChangeDisplaySettings flags (CDS_*)
pub mod cds_flags {
    /// Dynamic mode change
    pub const DYNAMIC: u32 = 0;
    /// Update registry
    pub const UPDATEREGISTRY: u32 = 0x00000001;
    /// Test if mode valid
    pub const TEST: u32 = 0x00000002;
    /// Full screen
    pub const FULLSCREEN: u32 = 0x00000004;
    /// Global changes
    pub const GLOBAL: u32 = 0x00000008;
    /// Set primary
    pub const SET_PRIMARY: u32 = 0x00000010;
    /// Video parameters
    pub const VIDEOPARAMETERS: u32 = 0x00000020;
    /// Reset mode
    pub const RESET: u32 = 0x40000000;
    /// No reset
    pub const NORESET: u32 = 0x10000000;
}

/// ChangeDisplaySettings return values
pub mod disp_change {
    /// Success
    pub const SUCCESSFUL: i32 = 0;
    /// Restart required
    pub const RESTART: i32 = 1;
    /// Failed
    pub const FAILED: i32 = -1;
    /// Bad mode
    pub const BADMODE: i32 = -2;
    /// Not updated (registry)
    pub const NOTUPDATED: i32 = -3;
    /// Bad flags
    pub const BADFLAGS: i32 = -4;
    /// Bad param
    pub const BADPARAM: i32 = -5;
    /// Bad dual view
    pub const BADDUALVIEW: i32 = -6;
}

/// Display orientation
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisplayOrientation {
    #[default]
    Default = 0,
    Rotate90 = 1,
    Rotate180 = 2,
    Rotate270 = 3,
}

// ============================================================================
// Structures
// ============================================================================

/// Device mode (DEVMODE equivalent)
#[derive(Clone, Copy)]
pub struct DevMode {
    /// Device name
    pub device_name: [u8; 32],
    /// Spec version
    pub spec_version: u16,
    /// Driver version
    pub driver_version: u16,
    /// Structure size
    pub size: u16,
    /// Driver extra
    pub driver_extra: u16,
    /// Fields bitmask
    pub fields: u32,
    /// Position X
    pub position_x: i32,
    /// Position Y
    pub position_y: i32,
    /// Display orientation
    pub display_orientation: u32,
    /// Display fixed output
    pub display_fixed_output: u32,
    /// Color resolution (bits per pixel)
    pub bits_per_pel: u16,
    /// Horizontal resolution
    pub pels_width: u32,
    /// Vertical resolution
    pub pels_height: u32,
    /// Display flags
    pub display_flags: u32,
    /// Display frequency
    pub display_frequency: u32,
}

impl DevMode {
    pub const fn new() -> Self {
        Self {
            device_name: [0; 32],
            spec_version: 0x0401,
            driver_version: 0,
            size: 0,
            driver_extra: 0,
            fields: 0,
            position_x: 0,
            position_y: 0,
            display_orientation: 0,
            display_fixed_output: 0,
            bits_per_pel: 32,
            pels_width: 1024,
            pels_height: 768,
            display_flags: 0,
            display_frequency: 60,
        }
    }
}

/// Monitor info
#[derive(Clone, Copy)]
pub struct MonitorInfo {
    /// Monitor is valid
    pub valid: bool,
    /// Is primary
    pub primary: bool,
    /// Monitor rectangle
    pub monitor_rect: Rect,
    /// Work area rectangle
    pub work_rect: Rect,
    /// Device name length
    pub device_name_len: u8,
    /// Device name
    pub device_name: [u8; 32],
    /// Current mode
    pub current_mode: DevMode,
    /// Mode count
    pub mode_count: u16,
}

impl MonitorInfo {
    const fn new() -> Self {
        Self {
            valid: false,
            primary: false,
            monitor_rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            work_rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            device_name_len: 0,
            device_name: [0; 32],
            current_mode: DevMode::new(),
            mode_count: 0,
        }
    }
}

/// Display mode entry
#[derive(Clone, Copy)]
pub struct DisplayMode {
    /// Mode is valid
    pub valid: bool,
    /// Width
    pub width: u32,
    /// Height
    pub height: u32,
    /// Bits per pixel
    pub bpp: u16,
    /// Refresh rate
    pub refresh: u32,
}

impl DisplayMode {
    const fn new() -> Self {
        Self {
            valid: false,
            width: 0,
            height: 0,
            bpp: 0,
            refresh: 0,
        }
    }
}

/// Display settings dialog state
#[derive(Clone, Copy)]
pub struct DisplayDialogState {
    /// Dialog is active
    pub active: bool,
    /// Dialog handle
    pub hwnd: HWND,
    /// Current tab (0=themes, 1=desktop, 2=screensaver, 3=appearance, 4=settings)
    pub current_tab: u8,
    /// Selected monitor
    pub selected_monitor: u8,
    /// Pending mode changes
    pub pending_changes: bool,
    /// Pending mode
    pub pending_mode: DevMode,
}

impl DisplayDialogState {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            current_tab: 0,
            selected_monitor: 0,
            pending_changes: false,
            pending_mode: DevMode::new(),
        }
    }
}

// ============================================================================
// State
// ============================================================================

static DISPLAY_INITIALIZED: AtomicBool = AtomicBool::new(false);
static DISPLAY_LOCK: SpinLock<()> = SpinLock::new(());

static DIALOG_STATE: SpinLock<DisplayDialogState> = SpinLock::new(DisplayDialogState::new());

// Monitors
const MAX_MONITORS: usize = 4;
static MONITORS: SpinLock<[MonitorInfo; MAX_MONITORS]> =
    SpinLock::new([const { MonitorInfo::new() }; MAX_MONITORS]);

// Display modes per monitor
const MAX_MODES: usize = 32;
static DISPLAY_MODES: SpinLock<[[DisplayMode; MAX_MODES]; MAX_MONITORS]> =
    SpinLock::new([[const { DisplayMode::new() }; MAX_MODES]; MAX_MONITORS]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize display settings subsystem
pub fn init() {
    let _guard = DISPLAY_LOCK.lock();

    if DISPLAY_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[DISPLAYSETTINGS] Initializing display settings...");

    // Initialize primary monitor
    init_primary_monitor();

    // Enumerate display modes
    enumerate_display_modes(0);

    DISPLAY_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[DISPLAYSETTINGS] Display settings initialized");
}

/// Initialize primary monitor
fn init_primary_monitor() {
    let mut monitors = MONITORS.lock();
    let monitor = &mut monitors[0];

    monitor.valid = true;
    monitor.primary = true;
    monitor.monitor_rect = Rect { left: 0, top: 0, right: 1024, bottom: 768 };
    monitor.work_rect = Rect { left: 0, top: 0, right: 1024, bottom: 738 }; // Minus taskbar

    let name = b"\\\\.\\DISPLAY1";
    monitor.device_name_len = name.len() as u8;
    monitor.device_name[..name.len()].copy_from_slice(name);

    monitor.current_mode = DevMode::new();
    monitor.current_mode.pels_width = 1024;
    monitor.current_mode.pels_height = 768;
    monitor.current_mode.bits_per_pel = 32;
    monitor.current_mode.display_frequency = 60;
}

/// Enumerate display modes for a monitor
fn enumerate_display_modes(monitor: usize) {
    let mut modes = DISPLAY_MODES.lock();

    // Common display modes
    let mode_list: &[(u32, u32, u16, u32)] = &[
        (640, 480, 16, 60),
        (640, 480, 32, 60),
        (800, 600, 16, 60),
        (800, 600, 32, 60),
        (800, 600, 32, 75),
        (1024, 768, 16, 60),
        (1024, 768, 32, 60),
        (1024, 768, 32, 75),
        (1152, 864, 32, 60),
        (1280, 720, 32, 60),
        (1280, 800, 32, 60),
        (1280, 1024, 32, 60),
        (1280, 1024, 32, 75),
        (1366, 768, 32, 60),
        (1440, 900, 32, 60),
        (1600, 900, 32, 60),
        (1600, 1200, 32, 60),
        (1680, 1050, 32, 60),
        (1920, 1080, 32, 60),
        (1920, 1200, 32, 60),
    ];

    for (i, (w, h, bpp, refresh)) in mode_list.iter().enumerate() {
        if i >= MAX_MODES {
            break;
        }

        modes[monitor][i].valid = true;
        modes[monitor][i].width = *w;
        modes[monitor][i].height = *h;
        modes[monitor][i].bpp = *bpp;
        modes[monitor][i].refresh = *refresh;
    }

    // Update mode count in monitor info
    let mut monitors = MONITORS.lock();
    if monitors[monitor].valid {
        monitors[monitor].mode_count = mode_list.len().min(MAX_MODES) as u16;
    }
}

// ============================================================================
// Display Settings API
// ============================================================================

/// Enumerate display settings
pub fn enum_display_settings(device_name: Option<&[u8]>, mode_num: u32, dev_mode: &mut DevMode) -> bool {
    if !DISPLAY_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    // Find monitor
    let monitor_idx = if let Some(name) = device_name {
        find_monitor_by_name(name).unwrap_or(0)
    } else {
        0 // Primary monitor
    };

    let modes = DISPLAY_MODES.lock();

    if mode_num as usize >= MAX_MODES {
        return false;
    }

    let mode = &modes[monitor_idx][mode_num as usize];

    if !mode.valid {
        return false;
    }

    dev_mode.pels_width = mode.width;
    dev_mode.pels_height = mode.height;
    dev_mode.bits_per_pel = mode.bpp;
    dev_mode.display_frequency = mode.refresh;
    dev_mode.fields = dm_flags::PELSWIDTH | dm_flags::PELSHEIGHT |
                      dm_flags::BITSPERPEL | dm_flags::DISPLAYFREQUENCY;

    true
}

/// Change display settings
pub fn change_display_settings(dev_mode: Option<&DevMode>, flags: u32) -> i32 {
    if !DISPLAY_INITIALIZED.load(Ordering::Acquire) {
        return disp_change::FAILED;
    }

    // Reset to default
    if dev_mode.is_none() {
        // Would restore default settings
        return disp_change::SUCCESSFUL;
    }

    let mode = dev_mode.unwrap();

    // Test mode
    if (flags & cds_flags::TEST) != 0 {
        return if is_mode_valid(mode) {
            disp_change::SUCCESSFUL
        } else {
            disp_change::BADMODE
        };
    }

    // Validate mode
    if !is_mode_valid(mode) {
        return disp_change::BADMODE;
    }

    // Apply mode
    let mut monitors = MONITORS.lock();
    let monitor = &mut monitors[0];

    monitor.current_mode.pels_width = mode.pels_width;
    monitor.current_mode.pels_height = mode.pels_height;
    monitor.current_mode.bits_per_pel = mode.bits_per_pel;
    monitor.current_mode.display_frequency = mode.display_frequency;

    monitor.monitor_rect.right = mode.pels_width as i32;
    monitor.monitor_rect.bottom = mode.pels_height as i32;
    monitor.work_rect.right = mode.pels_width as i32;
    monitor.work_rect.bottom = mode.pels_height as i32 - 30; // Taskbar

    // Update system metrics
    super::metrics::set_screen_size(mode.pels_width as i32, mode.pels_height as i32);

    // Would update registry if UPDATEREGISTRY flag set
    if (flags & cds_flags::UPDATEREGISTRY) != 0 {
        // Save to registry
    }

    disp_change::SUCCESSFUL
}

/// Check if mode is valid
fn is_mode_valid(mode: &DevMode) -> bool {
    let modes = DISPLAY_MODES.lock();

    for m in modes[0].iter() {
        if m.valid &&
           m.width == mode.pels_width &&
           m.height == mode.pels_height &&
           m.bpp == mode.bits_per_pel &&
           m.refresh == mode.display_frequency {
            return true;
        }
    }

    false
}

/// Get current display settings
pub fn get_display_settings() -> DevMode {
    let monitors = MONITORS.lock();
    monitors[0].current_mode
}

// ============================================================================
// Monitor API
// ============================================================================

/// Get monitor count
pub fn get_monitor_count() -> usize {
    let monitors = MONITORS.lock();
    monitors.iter().filter(|m| m.valid).count()
}

/// Get monitor info
pub fn get_monitor_info(index: usize) -> Option<MonitorInfo> {
    let monitors = MONITORS.lock();

    if index < MAX_MONITORS && monitors[index].valid {
        Some(monitors[index])
    } else {
        None
    }
}

/// Get primary monitor index
pub fn get_primary_monitor() -> usize {
    let monitors = MONITORS.lock();

    for (i, m) in monitors.iter().enumerate() {
        if m.valid && m.primary {
            return i;
        }
    }

    0
}

/// Set primary monitor
pub fn set_primary_monitor(index: usize) -> bool {
    let mut monitors = MONITORS.lock();

    if index >= MAX_MONITORS || !monitors[index].valid {
        return false;
    }

    // Clear primary from all
    for m in monitors.iter_mut() {
        m.primary = false;
    }

    monitors[index].primary = true;
    true
}

/// Find monitor by name
fn find_monitor_by_name(name: &[u8]) -> Option<usize> {
    let monitors = MONITORS.lock();

    for (i, m) in monitors.iter().enumerate() {
        if m.valid && m.device_name_len as usize == name.len() {
            if &m.device_name[..m.device_name_len as usize] == name {
                return Some(i);
            }
        }
    }

    None
}

/// Get monitor at point
pub fn monitor_from_point(x: i32, y: i32) -> Option<usize> {
    let monitors = MONITORS.lock();

    for (i, m) in monitors.iter().enumerate() {
        if m.valid {
            if x >= m.monitor_rect.left && x < m.monitor_rect.right &&
               y >= m.monitor_rect.top && y < m.monitor_rect.bottom {
                return Some(i);
            }
        }
    }

    // Return primary if not found
    Some(get_primary_monitor())
}

/// Get monitor from window
pub fn monitor_from_window(hwnd: HWND) -> Option<usize> {
    if let Some(rect) = super::window::get_window_rect(hwnd) {
        let center_x = (rect.left + rect.right) / 2;
        let center_y = (rect.top + rect.bottom) / 2;
        monitor_from_point(center_x, center_y)
    } else {
        Some(get_primary_monitor())
    }
}

// ============================================================================
// Display Properties Dialog
// ============================================================================

/// Show display properties dialog
pub fn show_display_properties(hwnd_owner: HWND, tab: u8) -> bool {
    if !DISPLAY_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = DIALOG_STATE.lock();

    if state.active {
        return false;
    }

    state.current_tab = tab;
    state.selected_monitor = 0;
    state.pending_changes = false;

    // Create dialog
    let hwnd = create_display_dialog(hwnd_owner);

    if hwnd == UserHandle::NULL {
        return false;
    }

    state.active = true;
    state.hwnd = hwnd;

    drop(state);

    // Run dialog
    let result = run_display_dialog(hwnd);

    // Clean up
    let mut state = DIALOG_STATE.lock();
    state.active = false;
    state.hwnd = UserHandle::NULL;

    result
}

/// Close display properties dialog
pub fn close_display_dialog() {
    let mut state = DIALOG_STATE.lock();

    if state.active {
        if state.hwnd != UserHandle::NULL {
            super::window::destroy_window(state.hwnd);
        }

        state.active = false;
        state.hwnd = UserHandle::NULL;
    }
}

/// Apply pending display changes
pub fn apply_display_changes() -> bool {
    let state = DIALOG_STATE.lock();

    if !state.pending_changes {
        return true;
    }

    let mode = state.pending_mode;
    drop(state);

    let result = change_display_settings(Some(&mode), cds_flags::UPDATEREGISTRY);

    if result == disp_change::SUCCESSFUL {
        let mut state = DIALOG_STATE.lock();
        state.pending_changes = false;
        true
    } else {
        false
    }
}

// ============================================================================
// Dialog Creation
// ============================================================================

/// Create display dialog window
fn create_display_dialog(_owner: HWND) -> HWND {
    // Would create property sheet dialog
    UserHandle::NULL
}

/// Run display dialog
fn run_display_dialog(_hwnd: HWND) -> bool {
    true
}

// ============================================================================
// Dialog Procedure
// ============================================================================

/// Display dialog window procedure
pub fn display_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    _lparam: isize,
) -> isize {
    match msg {
        super::message::WM_COMMAND => {
            handle_display_command(hwnd, wparam as u32)
        }
        super::message::WM_CLOSE => {
            close_display_dialog();
            0
        }
        _ => 0,
    }
}

/// Handle display dialog commands
fn handle_display_command(hwnd: HWND, command: u32) -> isize {
    let id = command as u16;

    match id {
        1 => {
            // OK - apply and close
            let state = DIALOG_STATE.lock();
            if state.active && state.hwnd == hwnd {
                drop(state);
                apply_display_changes();
                close_display_dialog();
            }
            0
        }
        2 => {
            // Cancel
            close_display_dialog();
            0
        }
        3 => {
            // Apply
            apply_display_changes();
            0
        }
        100 => {
            // Resolution slider changed
            // Would update pending mode
            0
        }
        101 => {
            // Color depth combo changed
            // Would update pending mode
            0
        }
        102 => {
            // Refresh rate combo changed
            // Would update pending mode
            0
        }
        103 => {
            // Advanced button
            show_advanced_display();
            0
        }
        104 => {
            // Identify monitors button
            identify_monitors();
            0
        }
        _ => 0,
    }
}

/// Show advanced display settings
fn show_advanced_display() {
    // Would show adapter properties, monitor properties, etc.
}

/// Identify monitors (show monitor numbers)
fn identify_monitors() {
    // Would show overlay with monitor numbers
}

// ============================================================================
// Display Modes List
// ============================================================================

/// Get available display modes
pub fn get_display_modes(monitor: usize) -> ([DisplayMode; MAX_MODES], usize) {
    let modes = DISPLAY_MODES.lock();

    if monitor >= MAX_MONITORS {
        return ([DisplayMode::new(); MAX_MODES], 0);
    }

    let count = modes[monitor].iter().filter(|m| m.valid).count();
    (modes[monitor], count)
}

/// Format display mode as string
pub fn format_display_mode(mode: &DisplayMode, buffer: &mut [u8]) -> usize {
    let mut pos = 0;

    // Width
    pos += format_number(mode.width as u64, &mut buffer[pos..]);

    // x
    if pos < buffer.len() {
        buffer[pos] = b'x';
        pos += 1;
    }

    // Height
    pos += format_number(mode.height as u64, &mut buffer[pos..]);

    // Space
    if pos < buffer.len() {
        buffer[pos] = b' ';
        pos += 1;
    }

    // BPP
    pos += format_number(mode.bpp as u64, &mut buffer[pos..]);

    // bit
    let suffix = b"-bit ";
    let copy_len = suffix.len().min(buffer.len() - pos);
    buffer[pos..pos + copy_len].copy_from_slice(&suffix[..copy_len]);
    pos += copy_len;

    // Refresh
    pos += format_number(mode.refresh as u64, &mut buffer[pos..]);

    // Hz
    let hz = b" Hz";
    let copy_len = hz.len().min(buffer.len() - pos);
    buffer[pos..pos + copy_len].copy_from_slice(&hz[..copy_len]);
    pos + copy_len
}

/// Format number
fn format_number(mut n: u64, buffer: &mut [u8]) -> usize {
    if n == 0 {
        if !buffer.is_empty() {
            buffer[0] = b'0';
            return 1;
        }
        return 0;
    }

    let mut temp = [0u8; 20];
    let mut len = 0;

    while n > 0 && len < 20 {
        temp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }

    let copy_len = len.min(buffer.len());
    for i in 0..copy_len {
        buffer[i] = temp[len - 1 - i];
    }

    copy_len
}
