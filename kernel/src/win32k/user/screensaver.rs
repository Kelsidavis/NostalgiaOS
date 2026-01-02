//! Screen Saver Support
//!
//! Provides screen saver management and configuration following
//! Windows patterns.
//!
//! # References
//!
//! - Windows Server 2003 screen saver APIs
//! - SystemParametersInfo SPI_SETSCREENSAVE*

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle};

// ============================================================================
// Constants
// ============================================================================

/// Maximum path length
pub const MAX_PATH: usize = 260;

/// Screen saver flags
pub mod ss_flags {
    /// Screen saver is enabled
    pub const ENABLED: u32 = 0x00000001;
    /// Require password on resume
    pub const SECURE: u32 = 0x00000002;
    /// Low power mode active
    pub const LOW_POWER: u32 = 0x00000004;
    /// Power off mode active
    pub const POWER_OFF: u32 = 0x00000008;
    /// Currently running
    pub const RUNNING: u32 = 0x00000010;
    /// Preview mode
    pub const PREVIEW: u32 = 0x00000020;
}

/// Screen saver command line modes
pub mod ss_mode {
    /// Show configuration dialog
    pub const CONFIG: &[u8] = b"/c";
    /// Show in preview window
    pub const PREVIEW: &[u8] = b"/p";
    /// Full screen mode
    pub const FULL: &[u8] = b"/s";
    /// Change password (deprecated)
    pub const PASSWORD: &[u8] = b"/a";
}

// ============================================================================
// Structures
// ============================================================================

/// Screen saver settings
#[derive(Clone, Copy)]
pub struct ScreenSaverSettings {
    /// Flags
    pub flags: u32,
    /// Timeout in seconds
    pub timeout: u32,
    /// Low power timeout in seconds
    pub low_power_timeout: u32,
    /// Power off timeout in seconds
    pub power_off_timeout: u32,
    /// Screen saver path length
    pub path_len: u16,
    /// Screen saver executable path
    pub path: [u8; MAX_PATH],
    /// Screen saver name length
    pub name_len: u8,
    /// Screen saver name
    pub name: [u8; 64],
}

impl ScreenSaverSettings {
    pub const fn new() -> Self {
        Self {
            flags: 0,
            timeout: 600, // 10 minutes default
            low_power_timeout: 0,
            power_off_timeout: 0,
            path_len: 0,
            path: [0; MAX_PATH],
            name_len: 0,
            name: [0; 64],
        }
    }

    /// Set screen saver path
    pub fn set_path(&mut self, path: &[u8]) {
        self.path_len = path.len().min(MAX_PATH) as u16;
        let len = self.path_len as usize;
        self.path[..len].copy_from_slice(&path[..len]);
    }

    /// Set screen saver name
    pub fn set_name(&mut self, name: &[u8]) {
        self.name_len = name.len().min(64) as u8;
        let len = self.name_len as usize;
        self.name[..len].copy_from_slice(&name[..len]);
    }
}

/// Screen saver entry
#[derive(Clone, Copy)]
pub struct ScreenSaverEntry {
    /// Entry is valid
    pub valid: bool,
    /// Name length
    pub name_len: u8,
    /// Display name
    pub name: [u8; 64],
    /// Path length
    pub path_len: u16,
    /// Executable path
    pub path: [u8; MAX_PATH],
    /// Has settings dialog
    pub has_config: bool,
}

impl ScreenSaverEntry {
    const fn new() -> Self {
        Self {
            valid: false,
            name_len: 0,
            name: [0; 64],
            path_len: 0,
            path: [0; MAX_PATH],
            has_config: false,
        }
    }
}

/// Screen saver state
#[derive(Clone, Copy)]
pub struct ScreenSaverState {
    /// Screen saver is running
    pub running: bool,
    /// In preview mode
    pub preview: bool,
    /// Preview window handle
    pub preview_hwnd: HWND,
    /// Full screen window handle
    pub fullscreen_hwnd: HWND,
    /// Time when activated
    pub activated_time: u64,
    /// Last input time
    pub last_input_time: u64,
}

impl ScreenSaverState {
    const fn new() -> Self {
        Self {
            running: false,
            preview: false,
            preview_hwnd: UserHandle::NULL,
            fullscreen_hwnd: UserHandle::NULL,
            activated_time: 0,
            last_input_time: 0,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static SS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static SS_LOCK: SpinLock<()> = SpinLock::new(());
static SS_ACTIVE: AtomicBool = AtomicBool::new(false);
static IDLE_TIME: AtomicU32 = AtomicU32::new(0);

static SETTINGS: SpinLock<ScreenSaverSettings> = SpinLock::new(ScreenSaverSettings::new());
static STATE: SpinLock<ScreenSaverState> = SpinLock::new(ScreenSaverState::new());

// Available screen savers
const MAX_SCREENSAVERS: usize = 16;
static SCREENSAVERS: SpinLock<[ScreenSaverEntry; MAX_SCREENSAVERS]> =
    SpinLock::new([const { ScreenSaverEntry::new() }; MAX_SCREENSAVERS]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize screen saver subsystem
pub fn init() {
    let _guard = SS_LOCK.lock();

    if SS_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[SCREENSAVER] Initializing screen saver...");

    // Initialize built-in screen savers
    init_builtin_screensavers();

    SS_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[SCREENSAVER] Screen saver initialized");
}

/// Initialize built-in screen savers
fn init_builtin_screensavers() {
    let entries: &[(&[u8], &[u8])] = &[
        (b"(None)", b""),
        (b"Blank", b"scrnsave.scr"),
        (b"Marquee", b"ssmarque.scr"),
        (b"Mystify", b"ssmyst.scr"),
        (b"Starfield", b"ssstars.scr"),
        (b"Beziers", b"ssbezier.scr"),
        (b"3D Pipes", b"sspipes.scr"),
        (b"3D FlowerBox", b"ssflwbox.scr"),
        (b"3D Flying Objects", b"ss3dfo.scr"),
        (b"3D Maze", b"ssmaze.scr"),
        (b"3D Text", b"ss3dtext.scr"),
    ];

    let mut screensavers = SCREENSAVERS.lock();

    for (i, (name, path)) in entries.iter().enumerate() {
        if i >= MAX_SCREENSAVERS {
            break;
        }

        let entry = &mut screensavers[i];
        entry.valid = true;
        entry.name_len = name.len().min(64) as u8;
        entry.name[..entry.name_len as usize].copy_from_slice(&name[..entry.name_len as usize]);
        entry.path_len = path.len().min(MAX_PATH) as u16;
        entry.path[..entry.path_len as usize].copy_from_slice(&path[..entry.path_len as usize]);
        entry.has_config = !path.is_empty();
    }
}

// ============================================================================
// Screen Saver API
// ============================================================================

/// Enable or disable screen saver
pub fn set_screen_saver_enabled(enabled: bool) -> bool {
    if !SS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut settings = SETTINGS.lock();

    if enabled {
        settings.flags |= ss_flags::ENABLED;
    } else {
        settings.flags &= !ss_flags::ENABLED;
    }

    true
}

/// Check if screen saver is enabled
pub fn is_screen_saver_enabled() -> bool {
    let settings = SETTINGS.lock();
    (settings.flags & ss_flags::ENABLED) != 0
}

/// Set screen saver timeout
pub fn set_screen_saver_timeout(seconds: u32) -> bool {
    if !SS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut settings = SETTINGS.lock();
    settings.timeout = seconds;
    true
}

/// Get screen saver timeout
pub fn get_screen_saver_timeout() -> u32 {
    SETTINGS.lock().timeout
}

/// Set password protection
pub fn set_screen_saver_secure(secure: bool) -> bool {
    if !SS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut settings = SETTINGS.lock();

    if secure {
        settings.flags |= ss_flags::SECURE;
    } else {
        settings.flags &= !ss_flags::SECURE;
    }

    true
}

/// Check if password protection is enabled
pub fn is_screen_saver_secure() -> bool {
    let settings = SETTINGS.lock();
    (settings.flags & ss_flags::SECURE) != 0
}

/// Set active screen saver
pub fn set_screen_saver(path: &[u8], name: &[u8]) -> bool {
    if !SS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut settings = SETTINGS.lock();
    settings.set_path(path);
    settings.set_name(name);

    true
}

/// Get current screen saver settings
pub fn get_screen_saver_settings() -> ScreenSaverSettings {
    *SETTINGS.lock()
}

/// Get screen saver state
pub fn get_screen_saver_state() -> ScreenSaverState {
    *STATE.lock()
}

// ============================================================================
// Screen Saver Activation
// ============================================================================

/// Activate screen saver
pub fn activate_screen_saver() -> bool {
    if !SS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let settings = SETTINGS.lock();

    if (settings.flags & ss_flags::ENABLED) == 0 {
        return false;
    }

    if settings.path_len == 0 {
        return false;
    }

    drop(settings);

    let mut state = STATE.lock();

    if state.running {
        return true; // Already running
    }

    state.running = true;
    state.preview = false;
    state.activated_time = get_current_time();

    SS_ACTIVE.store(true, Ordering::Release);

    // Would launch screen saver process
    true
}

/// Deactivate screen saver
pub fn deactivate_screen_saver() -> bool {
    if !SS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = STATE.lock();

    if !state.running {
        return true;
    }

    let settings = SETTINGS.lock();

    // Check if password is required
    if (settings.flags & ss_flags::SECURE) != 0 {
        // Would prompt for password
        drop(settings);
        drop(state);
        return verify_screen_saver_password();
    }

    drop(settings);

    state.running = false;
    state.preview = false;

    if state.fullscreen_hwnd != UserHandle::NULL {
        super::window::destroy_window(state.fullscreen_hwnd);
        state.fullscreen_hwnd = UserHandle::NULL;
    }

    SS_ACTIVE.store(false, Ordering::Release);

    true
}

/// Check if screen saver is running
pub fn is_screen_saver_running() -> bool {
    SS_ACTIVE.load(Ordering::Acquire)
}

/// Start preview mode
pub fn start_preview(preview_hwnd: HWND) -> bool {
    if !SS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = STATE.lock();

    state.preview = true;
    state.preview_hwnd = preview_hwnd;

    // Would start screen saver in preview window
    true
}

/// Stop preview mode
pub fn stop_preview() -> bool {
    let mut state = STATE.lock();

    state.preview = false;
    state.preview_hwnd = UserHandle::NULL;

    true
}

// ============================================================================
// Idle Time Tracking
// ============================================================================

/// Update idle time (call on input events)
pub fn reset_idle_time() {
    IDLE_TIME.store(0, Ordering::Release);

    let mut state = STATE.lock();
    state.last_input_time = get_current_time();
}

/// Get current idle time in seconds
pub fn get_idle_time() -> u32 {
    IDLE_TIME.load(Ordering::Acquire)
}

/// Tick idle time (call periodically, e.g., every second)
pub fn tick_idle_time() {
    if !SS_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    // Don't count if screen saver already running
    if SS_ACTIVE.load(Ordering::Acquire) {
        return;
    }

    let idle = IDLE_TIME.fetch_add(1, Ordering::AcqRel) + 1;

    let settings = SETTINGS.lock();

    if (settings.flags & ss_flags::ENABLED) == 0 {
        return;
    }

    if settings.timeout > 0 && idle >= settings.timeout {
        drop(settings);
        activate_screen_saver();
    }
}

// ============================================================================
// Screen Saver List
// ============================================================================

/// Get available screen savers
pub fn get_available_screen_savers() -> ([ScreenSaverEntry; MAX_SCREENSAVERS], usize) {
    let screensavers = SCREENSAVERS.lock();
    let count = screensavers.iter().filter(|s| s.valid).count();
    (*screensavers, count)
}

/// Find screen saver by name
pub fn find_screen_saver(name: &[u8]) -> Option<ScreenSaverEntry> {
    let screensavers = SCREENSAVERS.lock();

    for entry in screensavers.iter() {
        if entry.valid && entry.name_len as usize == name.len() {
            if &entry.name[..entry.name_len as usize] == name {
                return Some(*entry);
            }
        }
    }

    None
}

/// Register custom screen saver
pub fn register_screen_saver(name: &[u8], path: &[u8], has_config: bool) -> bool {
    let mut screensavers = SCREENSAVERS.lock();

    // Find free slot
    for entry in screensavers.iter_mut() {
        if !entry.valid {
            entry.valid = true;
            entry.name_len = name.len().min(64) as u8;
            entry.name[..entry.name_len as usize].copy_from_slice(&name[..entry.name_len as usize]);
            entry.path_len = path.len().min(MAX_PATH) as u16;
            entry.path[..entry.path_len as usize].copy_from_slice(&path[..entry.path_len as usize]);
            entry.has_config = has_config;
            return true;
        }
    }

    false
}

// ============================================================================
// Configuration Dialog
// ============================================================================

/// Show screen saver configuration dialog
pub fn show_screen_saver_config(hwnd_owner: HWND) -> bool {
    if !SS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    // Would show the Display Properties -> Screen Saver tab
    let _ = hwnd_owner;
    true
}

/// Show screen saver's own configuration
pub fn show_screen_saver_settings() -> bool {
    let settings = SETTINGS.lock();

    if settings.path_len == 0 {
        return false;
    }

    // Would launch screen saver with /c flag
    true
}

// ============================================================================
// Power Management
// ============================================================================

/// Set low power timeout
pub fn set_low_power_timeout(seconds: u32) -> bool {
    let mut settings = SETTINGS.lock();
    settings.low_power_timeout = seconds;

    if seconds > 0 {
        settings.flags |= ss_flags::LOW_POWER;
    } else {
        settings.flags &= !ss_flags::LOW_POWER;
    }

    true
}

/// Set power off timeout
pub fn set_power_off_timeout(seconds: u32) -> bool {
    let mut settings = SETTINGS.lock();
    settings.power_off_timeout = seconds;

    if seconds > 0 {
        settings.flags |= ss_flags::POWER_OFF;
    } else {
        settings.flags &= !ss_flags::POWER_OFF;
    }

    true
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get current time
fn get_current_time() -> u64 {
    // Would return system time
    0
}

/// Verify screen saver password
fn verify_screen_saver_password() -> bool {
    // Would show password dialog and verify
    true
}

// ============================================================================
// Dialog Procedure
// ============================================================================

/// Screen saver settings dialog procedure
pub fn screensaver_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    _lparam: isize,
) -> isize {
    match msg {
        super::message::WM_COMMAND => {
            handle_screensaver_command(hwnd, wparam as u32)
        }
        super::message::WM_CLOSE => {
            0
        }
        _ => 0,
    }
}

/// Handle screen saver dialog commands
fn handle_screensaver_command(_hwnd: HWND, command: u32) -> isize {
    let id = command as u16;

    match id {
        100 => {
            // Screen saver combo box selection changed
            let high = (command >> 16) as u16;
            if high == 1 { // CBN_SELCHANGE
                // Would update preview
            }
            0
        }
        101 => {
            // Settings button
            show_screen_saver_settings();
            0
        }
        102 => {
            // Preview button
            activate_screen_saver();
            0
        }
        103 => {
            // Password checkbox
            let settings = SETTINGS.lock();
            let current = (settings.flags & ss_flags::SECURE) != 0;
            drop(settings);
            set_screen_saver_secure(!current);
            0
        }
        _ => 0,
    }
}
