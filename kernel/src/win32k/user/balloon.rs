//! Balloon Tooltip Support
//!
//! Provides balloon tooltip notifications following the Windows
//! common controls tooltip balloon style.
//!
//! # References
//!
//! - Windows Server 2003 comctl32 balloon tooltips
//! - Shell_NotifyIcon balloon notifications

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle, Rect, Point};

// ============================================================================
// Constants
// ============================================================================

/// Maximum text lengths
pub const MAX_TITLE: usize = 64;
pub const MAX_TEXT: usize = 256;

/// Balloon icon types (NIIF_*)
pub mod balloon_icon {
    /// No icon
    pub const NONE: u32 = 0x00000000;
    /// Information icon
    pub const INFO: u32 = 0x00000001;
    /// Warning icon
    pub const WARNING: u32 = 0x00000002;
    /// Error icon
    pub const ERROR: u32 = 0x00000003;
    /// User icon (custom)
    pub const USER: u32 = 0x00000004;
    /// Large icon version
    pub const LARGE_ICON: u32 = 0x00000020;
    /// No sound
    pub const NOSOUND: u32 = 0x00000010;
    /// Respect quiet time
    pub const RESPECT_QUIET_TIME: u32 = 0x00000080;
}

/// Balloon flags
pub mod balloon_flags {
    /// Show close button
    pub const CLOSE_BUTTON: u32 = 0x00000001;
    /// Clickable (send NIN_BALLOONUSERCLICK)
    pub const CLICKABLE: u32 = 0x00000002;
    /// Don't auto-dismiss
    pub const NO_TIMEOUT: u32 = 0x00000004;
    /// Realtime (replace existing)
    pub const REALTIME: u32 = 0x00000008;
}

/// Balloon notification messages
pub mod balloon_notify {
    /// Balloon shown
    pub const SHOWN: u32 = 0x0402; // NIN_BALLOONSHOW
    /// Balloon hidden
    pub const HIDDEN: u32 = 0x0403; // NIN_BALLOONHIDE
    /// Balloon timed out
    pub const TIMEOUT: u32 = 0x0404; // NIN_BALLOONTIMEOUT
    /// User clicked balloon
    pub const USERCLICK: u32 = 0x0405; // NIN_BALLOONUSERCLICK
}

/// Default timeout in milliseconds
pub const DEFAULT_TIMEOUT: u32 = 10000;

/// Minimum timeout
pub const MIN_TIMEOUT: u32 = 2000;

/// Maximum timeout
pub const MAX_TIMEOUT: u32 = 30000;

// ============================================================================
// Structures
// ============================================================================

/// Balloon tooltip configuration
#[derive(Clone, Copy)]
pub struct BalloonConfig {
    /// Owner window (for notifications)
    pub hwnd_owner: HWND,
    /// Icon type
    pub icon: u32,
    /// Custom icon handle (if icon == USER)
    pub hicon: u32,
    /// Flags
    pub flags: u32,
    /// Timeout in milliseconds
    pub timeout: u32,
    /// Anchor point (where the balloon points to)
    pub anchor: Point,
    /// Title length
    pub title_len: u8,
    /// Title text
    pub title: [u8; MAX_TITLE],
    /// Text length
    pub text_len: u16,
    /// Message text
    pub text: [u8; MAX_TEXT],
    /// Callback message (sent to owner)
    pub callback_msg: u32,
}

impl BalloonConfig {
    pub const fn new() -> Self {
        Self {
            hwnd_owner: UserHandle::NULL,
            icon: balloon_icon::NONE,
            hicon: 0,
            flags: 0,
            timeout: DEFAULT_TIMEOUT,
            anchor: Point { x: 0, y: 0 },
            title_len: 0,
            title: [0; MAX_TITLE],
            text_len: 0,
            text: [0; MAX_TEXT],
            callback_msg: 0,
        }
    }

    /// Set title
    pub fn set_title(&mut self, title: &[u8]) {
        self.title_len = title.len().min(MAX_TITLE) as u8;
        let len = self.title_len as usize;
        self.title[..len].copy_from_slice(&title[..len]);
    }

    /// Set text
    pub fn set_text(&mut self, text: &[u8]) {
        self.text_len = text.len().min(MAX_TEXT) as u16;
        let len = self.text_len as usize;
        self.text[..len].copy_from_slice(&text[..len]);
    }
}

/// Active balloon instance
#[derive(Clone, Copy)]
pub struct BalloonInstance {
    /// Balloon is active
    pub active: bool,
    /// Balloon ID
    pub id: u32,
    /// Window handle
    pub hwnd: HWND,
    /// Configuration
    pub config: BalloonConfig,
    /// Creation time
    pub created_time: u64,
    /// Display rectangle
    pub rect: Rect,
    /// Fade alpha (0-255)
    pub alpha: u8,
    /// Fading in
    pub fading_in: bool,
    /// Fading out
    pub fading_out: bool,
}

impl BalloonInstance {
    const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            hwnd: UserHandle::NULL,
            config: BalloonConfig::new(),
            created_time: 0,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            alpha: 255,
            fading_in: false,
            fading_out: false,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static BALLOON_INITIALIZED: AtomicBool = AtomicBool::new(false);
static BALLOON_LOCK: SpinLock<()> = SpinLock::new(());
static NEXT_BALLOON_ID: AtomicU32 = AtomicU32::new(1);

const MAX_BALLOONS: usize = 4;
static BALLOONS: SpinLock<[BalloonInstance; MAX_BALLOONS]> =
    SpinLock::new([const { BalloonInstance::new() }; MAX_BALLOONS]);

// Quiet time tracking
static IN_QUIET_TIME: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize balloon tooltip subsystem
pub fn init() {
    let _guard = BALLOON_LOCK.lock();

    if BALLOON_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[BALLOON] Initializing balloon tooltips...");

    BALLOON_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[BALLOON] Balloon tooltips initialized");
}

// ============================================================================
// Balloon API
// ============================================================================

/// Show a balloon tooltip
pub fn show_balloon(config: &BalloonConfig) -> Option<u32> {
    if !BALLOON_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    // Check quiet time
    if IN_QUIET_TIME.load(Ordering::Acquire) &&
       (config.icon != balloon_icon::ERROR) {
        return None;
    }

    let mut balloons = BALLOONS.lock();

    // Check for realtime flag - replace existing from same owner
    if (config.flags & balloon_flags::REALTIME) != 0 {
        for balloon in balloons.iter_mut() {
            if balloon.active && balloon.config.hwnd_owner == config.hwnd_owner {
                // Replace this balloon
                let id = NEXT_BALLOON_ID.fetch_add(1, Ordering::Relaxed);
                balloon.id = id;
                balloon.config = *config;
                balloon.created_time = get_current_time();
                balloon.alpha = 0;
                balloon.fading_in = true;
                balloon.fading_out = false;

                // Recalculate position
                balloon.rect = calculate_balloon_rect(&balloon.config);

                return Some(id);
            }
        }
    }

    // Find free slot
    for balloon in balloons.iter_mut() {
        if !balloon.active {
            let id = NEXT_BALLOON_ID.fetch_add(1, Ordering::Relaxed);

            balloon.active = true;
            balloon.id = id;
            balloon.config = *config;
            balloon.created_time = get_current_time();
            balloon.alpha = 0;
            balloon.fading_in = true;
            balloon.fading_out = false;

            // Calculate position
            balloon.rect = calculate_balloon_rect(&balloon.config);

            // Create window
            balloon.hwnd = create_balloon_window(balloon);

            // Notify owner
            if config.hwnd_owner != UserHandle::NULL && config.callback_msg != 0 {
                super::message::post_message(
                    config.hwnd_owner,
                    config.callback_msg,
                    balloon_notify::SHOWN as usize,
                    0,
                );
            }

            return Some(id);
        }
    }

    None
}

/// Hide a balloon by ID
pub fn hide_balloon(balloon_id: u32) -> bool {
    if !BALLOON_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut balloons = BALLOONS.lock();

    for balloon in balloons.iter_mut() {
        if balloon.active && balloon.id == balloon_id {
            // Start fade out
            balloon.fading_in = false;
            balloon.fading_out = true;
            return true;
        }
    }

    false
}

/// Hide all balloons
pub fn hide_all_balloons() {
    let mut balloons = BALLOONS.lock();

    for balloon in balloons.iter_mut() {
        if balloon.active {
            balloon.fading_in = false;
            balloon.fading_out = true;
        }
    }
}

/// Get balloon info
pub fn get_balloon_info(balloon_id: u32) -> Option<BalloonInstance> {
    let balloons = BALLOONS.lock();

    for balloon in balloons.iter() {
        if balloon.active && balloon.id == balloon_id {
            return Some(*balloon);
        }
    }

    None
}

/// Check if balloon is active
pub fn is_balloon_active(balloon_id: u32) -> bool {
    let balloons = BALLOONS.lock();

    for balloon in balloons.iter() {
        if balloon.active && balloon.id == balloon_id {
            return true;
        }
    }

    false
}

// ============================================================================
// Animation and Timing
// ============================================================================

/// Update balloon animations (call periodically)
pub fn update_balloons() {
    if !BALLOON_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    let current_time = get_current_time();
    let mut balloons = BALLOONS.lock();

    for balloon in balloons.iter_mut() {
        if !balloon.active {
            continue;
        }

        // Handle fade in
        if balloon.fading_in {
            if balloon.alpha < 255 {
                balloon.alpha = balloon.alpha.saturating_add(25);
            } else {
                balloon.fading_in = false;
            }
            continue;
        }

        // Handle fade out
        if balloon.fading_out {
            if balloon.alpha > 0 {
                balloon.alpha = balloon.alpha.saturating_sub(25);
            } else {
                // Destroy balloon
                destroy_balloon(balloon);
            }
            continue;
        }

        // Check timeout
        if (balloon.config.flags & balloon_flags::NO_TIMEOUT) == 0 {
            let elapsed = current_time.saturating_sub(balloon.created_time);
            if elapsed >= balloon.config.timeout as u64 {
                // Start fade out
                balloon.fading_out = true;

                // Notify owner
                if balloon.config.hwnd_owner != UserHandle::NULL &&
                   balloon.config.callback_msg != 0 {
                    super::message::post_message(
                        balloon.config.hwnd_owner,
                        balloon.config.callback_msg,
                        balloon_notify::TIMEOUT as usize,
                        0,
                    );
                }
            }
        }
    }
}

/// Destroy a balloon
fn destroy_balloon(balloon: &mut BalloonInstance) {
    if balloon.hwnd != UserHandle::NULL {
        super::window::destroy_window(balloon.hwnd);
    }

    // Notify owner
    if balloon.config.hwnd_owner != UserHandle::NULL &&
       balloon.config.callback_msg != 0 {
        super::message::post_message(
            balloon.config.hwnd_owner,
            balloon.config.callback_msg,
            balloon_notify::HIDDEN as usize,
            0,
        );
    }

    balloon.active = false;
    balloon.hwnd = UserHandle::NULL;
}

// ============================================================================
// Quiet Time
// ============================================================================

/// Enter quiet time (suppress non-critical notifications)
pub fn enter_quiet_time() {
    IN_QUIET_TIME.store(true, Ordering::Release);
}

/// Exit quiet time
pub fn exit_quiet_time() {
    IN_QUIET_TIME.store(false, Ordering::Release);
}

/// Check if in quiet time
pub fn is_quiet_time() -> bool {
    IN_QUIET_TIME.load(Ordering::Acquire)
}

// ============================================================================
// Position Calculation
// ============================================================================

/// Calculate balloon rectangle
fn calculate_balloon_rect(config: &BalloonConfig) -> Rect {
    // Default size based on content
    let width = 300;
    let height = if config.title_len > 0 { 100 } else { 70 };

    // Position above anchor point by default
    let x = config.anchor.x - width / 2;
    let y = config.anchor.y - height - 16; // 16 for tail

    Rect {
        left: x,
        top: y,
        right: x + width,
        bottom: y + height,
    }
}

/// Adjust balloon position for screen bounds
pub fn adjust_balloon_position(balloon_id: u32) -> bool {
    let mut balloons = BALLOONS.lock();

    for balloon in balloons.iter_mut() {
        if balloon.active && balloon.id == balloon_id {
            // Get screen bounds
            let screen_width = super::metrics::get_system_metrics(0); // SM_CXSCREEN
            let screen_height = super::metrics::get_system_metrics(1); // SM_CYSCREEN

            // Adjust if needed
            if balloon.rect.right > screen_width {
                let shift = balloon.rect.right - screen_width;
                balloon.rect.left -= shift;
                balloon.rect.right -= shift;
            }
            if balloon.rect.left < 0 {
                let shift = -balloon.rect.left;
                balloon.rect.left += shift;
                balloon.rect.right += shift;
            }
            if balloon.rect.bottom > screen_height {
                // Flip to above anchor
                let height = balloon.rect.bottom - balloon.rect.top;
                balloon.rect.bottom = balloon.config.anchor.y - 16;
                balloon.rect.top = balloon.rect.bottom - height;
            }

            return true;
        }
    }

    false
}

// ============================================================================
// Window Creation
// ============================================================================

/// Create balloon window
fn create_balloon_window(_balloon: &BalloonInstance) -> HWND {
    // Would create layered window for balloon
    UserHandle::NULL
}

/// Get current time
fn get_current_time() -> u64 {
    0
}

// ============================================================================
// Dialog Procedure
// ============================================================================

/// Balloon window procedure
pub fn balloon_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    match msg {
        super::message::WM_LBUTTONUP => {
            // User clicked balloon
            let balloon_id = find_balloon_by_hwnd(hwnd);
            if let Some(id) = balloon_id {
                handle_balloon_click(id);
            }
            0
        }
        super::message::WM_TIMER => {
            update_balloons();
            0
        }
        super::message::WM_CLOSE => {
            let balloon_id = find_balloon_by_hwnd(hwnd);
            if let Some(id) = balloon_id {
                hide_balloon(id);
            }
            0
        }
        _ => {
            let _ = (wparam, lparam);
            0
        }
    }
}

/// Find balloon by window handle
fn find_balloon_by_hwnd(hwnd: HWND) -> Option<u32> {
    let balloons = BALLOONS.lock();

    for balloon in balloons.iter() {
        if balloon.active && balloon.hwnd == hwnd {
            return Some(balloon.id);
        }
    }

    None
}

/// Handle balloon click
fn handle_balloon_click(balloon_id: u32) {
    let balloons = BALLOONS.lock();

    for balloon in balloons.iter() {
        if balloon.active && balloon.id == balloon_id {
            if (balloon.config.flags & balloon_flags::CLICKABLE) != 0 {
                // Notify owner
                if balloon.config.hwnd_owner != UserHandle::NULL &&
                   balloon.config.callback_msg != 0 {
                    super::message::post_message(
                        balloon.config.hwnd_owner,
                        balloon.config.callback_msg,
                        balloon_notify::USERCLICK as usize,
                        0,
                    );
                }
            }

            break;
        }
    }

    drop(balloons);

    // Hide after click
    hide_balloon(balloon_id);
}

// ============================================================================
// Simple API
// ============================================================================

/// Show info balloon
pub fn show_info_balloon(anchor: Point, title: &[u8], text: &[u8]) -> Option<u32> {
    let mut config = BalloonConfig::new();
    config.icon = balloon_icon::INFO;
    config.anchor = anchor;
    config.set_title(title);
    config.set_text(text);

    show_balloon(&config)
}

/// Show warning balloon
pub fn show_warning_balloon(anchor: Point, title: &[u8], text: &[u8]) -> Option<u32> {
    let mut config = BalloonConfig::new();
    config.icon = balloon_icon::WARNING;
    config.anchor = anchor;
    config.set_title(title);
    config.set_text(text);

    show_balloon(&config)
}

/// Show error balloon
pub fn show_error_balloon(anchor: Point, title: &[u8], text: &[u8]) -> Option<u32> {
    let mut config = BalloonConfig::new();
    config.icon = balloon_icon::ERROR;
    config.anchor = anchor;
    config.set_title(title);
    config.set_text(text);

    show_balloon(&config)
}
