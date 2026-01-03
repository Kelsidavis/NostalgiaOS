//! Splash Screen Support
//!
//! Provides splash screen functionality for application startup
//! following common Windows patterns.
//!
//! # References
//!
//! - Windows application splash screen patterns
//! - Layered window techniques

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle, ColorRef};

// ============================================================================
// Constants
// ============================================================================

/// Maximum text length
pub const MAX_TEXT: usize = 256;

/// Splash screen flags
pub mod splash_flags {
    /// Center on screen
    pub const CENTER: u32 = 0x00000001;
    /// Center on parent
    pub const CENTER_PARENT: u32 = 0x00000002;
    /// Topmost
    pub const TOPMOST: u32 = 0x00000004;
    /// No taskbar button
    pub const NO_TASKBAR: u32 = 0x00000008;
    /// Fade in
    pub const FADE_IN: u32 = 0x00000010;
    /// Fade out
    pub const FADE_OUT: u32 = 0x00000020;
    /// Show progress
    pub const SHOW_PROGRESS: u32 = 0x00000040;
    /// Show status text
    pub const SHOW_STATUS: u32 = 0x00000080;
    /// Click to close
    pub const CLICK_CLOSE: u32 = 0x00000100;
    /// Auto close on timeout
    pub const AUTO_CLOSE: u32 = 0x00000200;
}

/// Splash animation type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SplashAnimation {
    #[default]
    None = 0,
    FadeIn = 1,
    FadeOut = 2,
    SlideIn = 3,
    ZoomIn = 4,
}

// ============================================================================
// Structures
// ============================================================================

/// Splash screen configuration
#[derive(Debug, Clone, Copy)]
pub struct SplashConfig {
    /// Parent window (for CENTER_PARENT)
    pub hwnd_parent: HWND,
    /// Flags
    pub flags: u32,
    /// Width
    pub width: u16,
    /// Height
    pub height: u16,
    /// X position (if not centered)
    pub x: i16,
    /// Y position
    pub y: i16,
    /// Background color
    pub bg_color: ColorRef,
    /// Text color
    pub text_color: ColorRef,
    /// Progress bar color
    pub progress_color: ColorRef,
    /// Bitmap resource ID
    pub bitmap_id: u32,
    /// Timeout in milliseconds (0 = no timeout)
    pub timeout: u32,
    /// Fade duration in milliseconds
    pub fade_duration: u32,
    /// Initial alpha (0-255)
    pub alpha: u8,
}

impl SplashConfig {
    pub const fn new() -> Self {
        Self {
            hwnd_parent: UserHandle::NULL,
            flags: splash_flags::CENTER | splash_flags::TOPMOST | splash_flags::NO_TASKBAR,
            width: 400,
            height: 300,
            x: 0,
            y: 0,
            bg_color: ColorRef::rgb(0, 0, 128), // Dark blue
            text_color: ColorRef::rgb(255, 255, 255), // White
            progress_color: ColorRef::rgb(0, 200, 0), // Green
            bitmap_id: 0,
            timeout: 0,
            fade_duration: 500,
            alpha: 255,
        }
    }
}

/// Splash screen instance
#[derive(Debug, Clone, Copy)]
pub struct SplashScreen {
    /// Screen is active
    pub active: bool,
    /// Window handle
    pub hwnd: HWND,
    /// Screen ID
    pub id: u32,
    /// Configuration
    pub config: SplashConfig,
    /// Current alpha (for fading)
    pub current_alpha: u8,
    /// Progress (0-100)
    pub progress: u8,
    /// Status text length
    pub status_len: u8,
    /// Status text
    pub status: [u8; MAX_TEXT],
    /// Version text length
    pub version_len: u8,
    /// Version text
    pub version: [u8; 64],
    /// Copyright text length
    pub copyright_len: u8,
    /// Copyright text
    pub copyright: [u8; 128],
    /// Animation state
    pub animation: SplashAnimation,
    /// Animation progress (0-100)
    pub anim_progress: u8,
    /// Start time
    pub start_time: u64,
}

impl SplashScreen {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            id: 0,
            config: SplashConfig::new(),
            current_alpha: 255,
            progress: 0,
            status_len: 0,
            status: [0; MAX_TEXT],
            version_len: 0,
            version: [0; 64],
            copyright_len: 0,
            copyright: [0; 128],
            animation: SplashAnimation::None,
            anim_progress: 0,
            start_time: 0,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static SPLASH_INITIALIZED: AtomicBool = AtomicBool::new(false);
static SPLASH_LOCK: SpinLock<()> = SpinLock::new(());
static NEXT_SPLASH_ID: AtomicU32 = AtomicU32::new(1);

const MAX_SPLASHES: usize = 4;
static SPLASHES: SpinLock<[SplashScreen; MAX_SPLASHES]> =
    SpinLock::new([const { SplashScreen::new() }; MAX_SPLASHES]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize splash screen subsystem
pub fn init() {
    let _guard = SPLASH_LOCK.lock();

    if SPLASH_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[SPLASH] Initializing splash screen...");

    SPLASH_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[SPLASH] Splash screen initialized");
}

// ============================================================================
// Splash Screen API
// ============================================================================

/// Create and show a splash screen
pub fn create_splash(config: &SplashConfig) -> Option<u32> {
    if !SPLASH_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let mut splashes = SPLASHES.lock();

    // Find free slot
    for splash in splashes.iter_mut() {
        if !splash.active {
            let id = NEXT_SPLASH_ID.fetch_add(1, Ordering::Relaxed);

            splash.active = true;
            splash.id = id;
            splash.config = *config;
            splash.progress = 0;
            splash.status_len = 0;
            splash.version_len = 0;
            splash.copyright_len = 0;
            splash.start_time = get_current_time();

            // Set up fade in if requested
            if (config.flags & splash_flags::FADE_IN) != 0 {
                splash.current_alpha = 0;
                splash.animation = SplashAnimation::FadeIn;
                splash.anim_progress = 0;
            } else {
                splash.current_alpha = config.alpha;
                splash.animation = SplashAnimation::None;
                splash.anim_progress = 100;
            }

            // Create window
            splash.hwnd = create_splash_window(config);

            return Some(id);
        }
    }

    None
}

/// Close a splash screen
pub fn close_splash(splash_id: u32) -> bool {
    if !SPLASH_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut splashes = SPLASHES.lock();

    for splash in splashes.iter_mut() {
        if splash.active && splash.id == splash_id {
            // Start fade out if requested
            if (splash.config.flags & splash_flags::FADE_OUT) != 0 &&
               splash.animation != SplashAnimation::FadeOut {
                splash.animation = SplashAnimation::FadeOut;
                splash.anim_progress = 0;
                // Would start fade out animation
                return true;
            }

            // Immediate close
            if splash.hwnd != UserHandle::NULL {
                super::window::destroy_window(splash.hwnd);
            }
            splash.active = false;
            splash.hwnd = UserHandle::NULL;
            return true;
        }
    }

    false
}

/// Set splash progress (0-100)
pub fn set_splash_progress(splash_id: u32, progress: u8) -> bool {
    if !SPLASH_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut splashes = SPLASHES.lock();

    for splash in splashes.iter_mut() {
        if splash.active && splash.id == splash_id {
            splash.progress = progress.min(100);
            return true;
        }
    }

    false
}

/// Set splash status text
pub fn set_splash_status(splash_id: u32, status: &[u8]) -> bool {
    if !SPLASH_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut splashes = SPLASHES.lock();

    for splash in splashes.iter_mut() {
        if splash.active && splash.id == splash_id {
            splash.status_len = status.len().min(MAX_TEXT) as u8;
            splash.status[..splash.status_len as usize]
                .copy_from_slice(&status[..splash.status_len as usize]);
            return true;
        }
    }

    false
}

/// Set version text
pub fn set_splash_version(splash_id: u32, version: &[u8]) -> bool {
    if !SPLASH_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut splashes = SPLASHES.lock();

    for splash in splashes.iter_mut() {
        if splash.active && splash.id == splash_id {
            splash.version_len = version.len().min(64) as u8;
            splash.version[..splash.version_len as usize]
                .copy_from_slice(&version[..splash.version_len as usize]);
            return true;
        }
    }

    false
}

/// Set copyright text
pub fn set_splash_copyright(splash_id: u32, copyright: &[u8]) -> bool {
    if !SPLASH_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut splashes = SPLASHES.lock();

    for splash in splashes.iter_mut() {
        if splash.active && splash.id == splash_id {
            splash.copyright_len = copyright.len().min(128) as u8;
            splash.copyright[..splash.copyright_len as usize]
                .copy_from_slice(&copyright[..splash.copyright_len as usize]);
            return true;
        }
    }

    false
}

/// Get splash screen info
pub fn get_splash_info(splash_id: u32) -> Option<SplashScreen> {
    if !SPLASH_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let splashes = SPLASHES.lock();

    for splash in splashes.iter() {
        if splash.active && splash.id == splash_id {
            return Some(*splash);
        }
    }

    None
}

/// Check if splash screen has timed out
pub fn has_splash_timed_out(splash_id: u32) -> bool {
    if !SPLASH_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let splashes = SPLASHES.lock();

    for splash in splashes.iter() {
        if splash.active && splash.id == splash_id {
            if splash.config.timeout == 0 {
                return false;
            }

            let elapsed = get_current_time().saturating_sub(splash.start_time);
            return elapsed >= splash.config.timeout as u64;
        }
    }

    false
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create splash window
fn create_splash_window(config: &SplashConfig) -> HWND {
    // Calculate position
    let (x, y) = if (config.flags & splash_flags::CENTER) != 0 {
        // Center on screen (SM_CXSCREEN = 0, SM_CYSCREEN = 1)
        let screen_width = super::metrics::get_system_metrics(0);
        let screen_height = super::metrics::get_system_metrics(1);
        (
            (screen_width - config.width as i32) / 2,
            (screen_height - config.height as i32) / 2,
        )
    } else if (config.flags & splash_flags::CENTER_PARENT) != 0 && config.hwnd_parent != UserHandle::NULL {
        // Center on parent
        if let Some(parent_rect) = super::window::get_window_rect(config.hwnd_parent) {
            let parent_cx = (parent_rect.left + parent_rect.right) / 2;
            let parent_cy = (parent_rect.top + parent_rect.bottom) / 2;
            (
                parent_cx - config.width as i32 / 2,
                parent_cy - config.height as i32 / 2,
            )
        } else {
            (config.x as i32, config.y as i32)
        }
    } else {
        (config.x as i32, config.y as i32)
    };

    // Would create layered window
    let _ = (x, y);
    UserHandle::NULL
}

/// Get current time
fn get_current_time() -> u64 {
    0
}

/// Update splash animation
pub fn update_splash_animation(splash_id: u32) -> bool {
    if !SPLASH_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut splashes = SPLASHES.lock();

    for splash in splashes.iter_mut() {
        if splash.active && splash.id == splash_id {
            match splash.animation {
                SplashAnimation::FadeIn => {
                    if splash.anim_progress < 100 {
                        splash.anim_progress += 5;
                        splash.current_alpha = (splash.config.alpha as u32 * splash.anim_progress as u32 / 100) as u8;
                    } else {
                        splash.animation = SplashAnimation::None;
                    }
                }
                SplashAnimation::FadeOut => {
                    if splash.anim_progress < 100 {
                        splash.anim_progress += 5;
                        let remaining = 100 - splash.anim_progress;
                        splash.current_alpha = (splash.config.alpha as u32 * remaining as u32 / 100) as u8;
                    } else {
                        // Close when fade complete
                        if splash.hwnd != UserHandle::NULL {
                            super::window::destroy_window(splash.hwnd);
                        }
                        splash.active = false;
                        splash.hwnd = UserHandle::NULL;
                    }
                }
                _ => {}
            }
            return true;
        }
    }

    false
}

// ============================================================================
// Dialog Procedure
// ============================================================================

/// Splash screen window procedure
pub fn splash_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    match msg {
        super::message::WM_LBUTTONDOWN | super::message::WM_RBUTTONDOWN => {
            // Check if click to close is enabled
            let splash_id = {
                let splashes = SPLASHES.lock();
                let mut found_id = None;
                for splash in splashes.iter() {
                    if splash.active && splash.hwnd == hwnd {
                        if (splash.config.flags & splash_flags::CLICK_CLOSE) != 0 {
                            found_id = Some(splash.id);
                        }
                        break;
                    }
                }
                found_id
            };
            if let Some(id) = splash_id {
                close_splash(id);
            }
            0
        }
        super::message::WM_TIMER => {
            // Handle timeout and animation
            let splashes = SPLASHES.lock();
            for splash in splashes.iter() {
                if splash.active && splash.hwnd == hwnd {
                    let id = splash.id;
                    let auto_close = (splash.config.flags & splash_flags::AUTO_CLOSE) != 0;
                    drop(splashes);

                    update_splash_animation(id);

                    if auto_close && has_splash_timed_out(id) {
                        close_splash(id);
                    }
                    return 0;
                }
            }
            0
        }
        super::message::WM_CLOSE => {
            let splashes = SPLASHES.lock();
            for splash in splashes.iter() {
                if splash.active && splash.hwnd == hwnd {
                    let id = splash.id;
                    drop(splashes);
                    close_splash(id);
                    return 0;
                }
            }
            0
        }
        _ => {
            let _ = (wparam, lparam);
            0
        }
    }
}

// ============================================================================
// Simple API
// ============================================================================

/// Show a simple splash screen
pub fn show_simple_splash(
    title: &[u8],
    version: &[u8],
    copyright: &[u8],
) -> Option<u32> {
    let config = SplashConfig::new();
    let id = create_splash(&config)?;

    set_splash_status(id, title);
    set_splash_version(id, version);
    set_splash_copyright(id, copyright);

    Some(id)
}

/// Show a splash with progress
pub fn show_progress_splash(title: &[u8]) -> Option<u32> {
    let mut config = SplashConfig::new();
    config.flags |= splash_flags::SHOW_PROGRESS | splash_flags::SHOW_STATUS;

    let id = create_splash(&config)?;
    set_splash_status(id, title);

    Some(id)
}
