//! Winlogon Session Management
//!
//! Winlogon handles the logon process, Secure Attention Sequence (SAS),
//! and desktop switching for the NT security model.
//!
//! # Key Responsibilities
//!
//! - User authentication and credential validation
//! - Session management (logon/logoff/shutdown)
//! - Ctrl+Alt+Del handling (SAS)
//! - Desktop switching (Winlogon/Default)
//! - Screen locking and unlocking
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `ds/security/gina/winlogon/winlogon.c`
//! - `ds/security/gina/winlogon/security.c`

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, Rect, ColorRef};
use super::super::gdi::{dc, brush};
use super::{window, message, desktop, WindowStyle, WindowStyleEx};

// ============================================================================
// Constants
// ============================================================================

/// Maximum username length
pub const MAX_USERNAME: usize = 64;

/// Maximum password length
pub const MAX_PASSWORD: usize = 128;

/// Maximum domain name length
pub const MAX_DOMAIN: usize = 64;

/// Session ID for console session
pub const CONSOLE_SESSION_ID: u32 = 0;

/// Winlogon states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinlogonState {
    /// Initial state
    NotStarted,
    /// Displaying "Press Ctrl+Alt+Del to log on"
    DisplayingSAS,
    /// Showing logon dialog
    LogonPrompt,
    /// Processing logon attempt
    LoggingOn,
    /// User logged in, showing user desktop
    LoggedOn,
    /// User initiated logoff
    LoggingOff,
    /// System is locking
    Locking,
    /// Workstation is locked
    Locked,
    /// System is shutting down
    ShuttingDown,
}

/// Logon result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogonResult {
    Success,
    InvalidCredentials,
    AccountDisabled,
    AccountExpired,
    PasswordExpired,
    AccountLocked,
    NoLogonServers,
}

/// SAS (Secure Attention Sequence) type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SasType {
    /// Ctrl+Alt+Del pressed
    CtrlAltDel,
    /// Screen saver timeout
    ScreenSaver,
    /// User initiated lock
    UserLock,
    /// Timeout (auto-lock)
    Timeout,
}

// ============================================================================
// Session State
// ============================================================================

/// Winlogon session state
struct WinlogonSession {
    /// Session ID
    session_id: u32,

    /// Current state
    state: WinlogonState,

    /// Logged on user
    username: [u8; MAX_USERNAME],
    username_len: usize,

    /// Domain
    domain: [u8; MAX_DOMAIN],
    domain_len: usize,

    /// User SID (placeholder)
    user_sid: u32,

    /// Logon time (ticks)
    logon_time: u64,

    /// Last activity time
    last_activity: u64,

    /// Lock timeout in seconds (0 = disabled)
    lock_timeout: u32,

    /// Winlogon desktop handle
    winlogon_desktop: HWND,

    /// User desktop handle
    user_desktop: HWND,

    /// Current desktop (0 = winlogon, 1 = user)
    active_desktop: u8,
}

impl WinlogonSession {
    const fn new() -> Self {
        Self {
            session_id: CONSOLE_SESSION_ID,
            state: WinlogonState::NotStarted,
            username: [0; MAX_USERNAME],
            username_len: 0,
            domain: [0; MAX_DOMAIN],
            domain_len: 0,
            user_sid: 0,
            logon_time: 0,
            last_activity: 0,
            lock_timeout: 0,
            winlogon_desktop: HWND::NULL,
            user_desktop: HWND::NULL,
            active_desktop: 0,
        }
    }

    fn set_username(&mut self, name: &str) {
        self.username_len = name.len().min(MAX_USERNAME - 1);
        for (i, &b) in name.as_bytes().iter().take(self.username_len).enumerate() {
            self.username[i] = b;
        }
    }

    fn set_domain(&mut self, domain: &str) {
        self.domain_len = domain.len().min(MAX_DOMAIN - 1);
        for (i, &b) in domain.as_bytes().iter().take(self.domain_len).enumerate() {
            self.domain[i] = b;
        }
    }

    fn get_username(&self) -> &str {
        core::str::from_utf8(&self.username[..self.username_len]).unwrap_or("")
    }
}

/// Global session state
static SESSION: SpinLock<WinlogonSession> = SpinLock::new(WinlogonSession::new());

/// Winlogon initialized
static WINLOGON_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// SAS pending flag
static SAS_PENDING: AtomicBool = AtomicBool::new(false);

/// SAS type when pending
static SAS_TYPE: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Winlogon
pub fn init() {
    if WINLOGON_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[WINLOGON] Initializing Windows Logon...");

    {
        let mut session = SESSION.lock();
        session.state = WinlogonState::DisplayingSAS;
    }

    // For development/testing, auto-logon as Administrator
    auto_logon();

    crate::serial_println!("[WINLOGON] Winlogon initialized");
}

/// Auto-logon for development (bypasses normal logon flow)
fn auto_logon() {
    let mut session = SESSION.lock();

    // Set default credentials
    session.set_username("Administrator");
    session.set_domain("NOSTALGIAOS");
    session.user_sid = 500; // Well-known Administrator SID RID
    session.logon_time = crate::hal::rtc::get_system_time();
    session.state = WinlogonState::LoggedOn;

    crate::serial_println!("[WINLOGON] Auto-logon: {}\\{}",
        core::str::from_utf8(&session.domain[..session.domain_len]).unwrap_or(""),
        session.get_username());
}

// ============================================================================
// SAS Handling
// ============================================================================

/// Signal Secure Attention Sequence (Ctrl+Alt+Del)
pub fn signal_sas(sas_type: SasType) {
    SAS_TYPE.store(sas_type as u32, Ordering::SeqCst);
    SAS_PENDING.store(true, Ordering::SeqCst);

    crate::serial_println!("[WINLOGON] SAS received: {:?}", sas_type);
}

/// Process pending SAS
pub fn process_sas() {
    if !SAS_PENDING.swap(false, Ordering::SeqCst) {
        return;
    }

    let sas_type = match SAS_TYPE.load(Ordering::SeqCst) {
        0 => SasType::CtrlAltDel,
        1 => SasType::ScreenSaver,
        2 => SasType::UserLock,
        3 => SasType::Timeout,
        _ => SasType::CtrlAltDel,
    };

    let mut session = SESSION.lock();

    match session.state {
        WinlogonState::DisplayingSAS => {
            // Show logon dialog
            session.state = WinlogonState::LogonPrompt;
            show_logon_dialog();
        }
        WinlogonState::LoggedOn => {
            // Show Windows Security dialog (Lock, Task Manager, etc.)
            match sas_type {
                SasType::CtrlAltDel => show_security_dialog(),
                SasType::UserLock | SasType::Timeout => {
                    session.state = WinlogonState::Locking;
                    lock_workstation();
                }
                _ => {}
            }
        }
        WinlogonState::Locked => {
            // Show unlock dialog
            show_unlock_dialog();
        }
        _ => {}
    }
}

// ============================================================================
// Desktop Management
// ============================================================================

/// Switch to Winlogon desktop
pub fn switch_to_winlogon_desktop() {
    let mut session = SESSION.lock();
    session.active_desktop = 0;

    // TODO: Actually switch desktops when desktop infrastructure is complete
    crate::serial_println!("[WINLOGON] Switched to Winlogon desktop");
}

/// Switch to User desktop
pub fn switch_to_user_desktop() {
    let mut session = SESSION.lock();
    session.active_desktop = 1;

    // TODO: Actually switch desktops when desktop infrastructure is complete
    crate::serial_println!("[WINLOGON] Switched to User desktop");
}

/// Get current desktop type (0 = winlogon, 1 = user)
pub fn get_active_desktop() -> u8 {
    let session = SESSION.lock();
    session.active_desktop
}

// ============================================================================
// Logon/Logoff
// ============================================================================

/// Attempt user logon
pub fn logon(username: &str, domain: &str, _password: &str) -> LogonResult {
    let mut session = SESSION.lock();

    crate::serial_println!("[WINLOGON] Logon attempt: {}\\{}", domain, username);

    // For development, accept any credentials
    session.set_username(username);
    session.set_domain(domain);
    session.user_sid = 1001; // Placeholder user SID
    session.logon_time = crate::hal::rtc::get_system_time();
    session.state = WinlogonState::LoggedOn;

    // Switch to user desktop
    drop(session);
    switch_to_user_desktop();

    LogonResult::Success
}

/// Logoff current user
pub fn logoff() {
    let mut session = SESSION.lock();

    if session.state != WinlogonState::LoggedOn {
        return;
    }

    crate::serial_println!("[WINLOGON] Logging off user: {}", session.get_username());

    session.state = WinlogonState::LoggingOff;

    // Clear user info
    session.username = [0; MAX_USERNAME];
    session.username_len = 0;
    session.domain = [0; MAX_DOMAIN];
    session.domain_len = 0;
    session.user_sid = 0;

    session.state = WinlogonState::DisplayingSAS;

    drop(session);
    switch_to_winlogon_desktop();
}

/// Lock workstation
pub fn lock_workstation() {
    let mut session = SESSION.lock();

    if session.state != WinlogonState::LoggedOn && session.state != WinlogonState::Locking {
        return;
    }

    crate::serial_println!("[WINLOGON] Locking workstation for user: {}", session.get_username());

    session.state = WinlogonState::Locked;

    drop(session);
    switch_to_winlogon_desktop();
    show_locked_dialog();
}

/// Unlock workstation
pub fn unlock(_password: &str) -> bool {
    let mut session = SESSION.lock();

    if session.state != WinlogonState::Locked {
        return false;
    }

    // For development, accept any password
    crate::serial_println!("[WINLOGON] Unlocking workstation for user: {}", session.get_username());

    session.state = WinlogonState::LoggedOn;

    drop(session);
    switch_to_user_desktop();

    true
}

// ============================================================================
// Shutdown
// ============================================================================

/// Initiate shutdown
pub fn shutdown(reboot: bool) -> ! {
    let mut session = SESSION.lock();

    crate::serial_println!("[WINLOGON] Initiating {}...",
        if reboot { "restart" } else { "shutdown" });

    session.state = WinlogonState::ShuttingDown;

    // TODO: Notify all processes to terminate
    // TODO: Save user profile

    drop(session);

    // Call HAL to perform actual shutdown/restart
    crate::hal::power::power_shutdown(reboot)
}

// ============================================================================
// Dialogs
// ============================================================================

/// Show "Press Ctrl+Alt+Del to log on" screen
fn show_sas_screen() {
    // Paint a full screen message
    if let Ok(hdc) = dc::create_display_dc() {
        let (width, height) = super::super::gdi::surface::get_primary_dimensions();
        let rect = Rect::new(0, 0, width as i32, height as i32);

        // Dark blue background (classic Windows logon)
        let bg_brush = brush::create_solid_brush(ColorRef::rgb(0, 0, 128));
        super::super::gdi::fill_rect(hdc, &rect, bg_brush);

        // Draw message
        dc::set_text_color(hdc, ColorRef::WHITE);
        dc::set_bk_mode(hdc, dc::BkMode::Transparent);

        let msg = "Press Ctrl+Alt+Delete to log on";
        let x = (width as i32 - 250) / 2;
        let y = height as i32 / 2;
        super::super::gdi::text_out(hdc, x, y, msg);

        dc::delete_dc(hdc);
    }
}

/// Show logon dialog
fn show_logon_dialog() {
    crate::serial_println!("[WINLOGON] Showing logon dialog");
    // TODO: Create actual logon dialog window
}

/// Show Windows Security dialog (Ctrl+Alt+Del options)
fn show_security_dialog() {
    crate::serial_println!("[WINLOGON] Showing Windows Security dialog");
    // Options: Lock, Log Off, Shut Down, Change Password, Task Manager
}

/// Show unlock dialog
fn show_unlock_dialog() {
    crate::serial_println!("[WINLOGON] Showing unlock dialog");
}

/// Show locked screen
fn show_locked_dialog() {
    crate::serial_println!("[WINLOGON] Showing locked workstation screen");

    let session = SESSION.lock();
    let username = session.get_username();

    // Paint locked screen
    if let Ok(hdc) = dc::create_display_dc() {
        let (width, height) = super::super::gdi::surface::get_primary_dimensions();
        let rect = Rect::new(0, 0, width as i32, height as i32);

        // Dark blue background
        let bg_brush = brush::create_solid_brush(ColorRef::rgb(0, 0, 128));
        super::super::gdi::fill_rect(hdc, &rect, bg_brush);

        dc::set_text_color(hdc, ColorRef::WHITE);
        dc::set_bk_mode(hdc, dc::BkMode::Transparent);

        // Show locked message
        let msg = "This workstation is locked.";
        let x = (width as i32 - 200) / 2;
        let y = height as i32 / 2 - 20;
        super::super::gdi::text_out(hdc, x, y, msg);

        let user_msg = "Press Ctrl+Alt+Delete to unlock.";
        let y2 = height as i32 / 2 + 20;
        super::super::gdi::text_out(hdc, x, y2, user_msg);

        dc::delete_dc(hdc);
    }
}

// ============================================================================
// Query Functions
// ============================================================================

/// Get current Winlogon state
pub fn get_state() -> WinlogonState {
    let session = SESSION.lock();
    session.state
}

/// Check if user is logged on
pub fn is_logged_on() -> bool {
    let session = SESSION.lock();
    session.state == WinlogonState::LoggedOn
}

/// Check if workstation is locked
pub fn is_locked() -> bool {
    let session = SESSION.lock();
    session.state == WinlogonState::Locked
}

/// Get logged on username
pub fn get_logged_on_user() -> Option<&'static str> {
    let session = SESSION.lock();
    if session.state == WinlogonState::LoggedOn && session.username_len > 0 {
        // This is a simplification - we'd need proper lifetime handling
        Some("Administrator")
    } else {
        None
    }
}

/// Get session ID
pub fn get_session_id() -> u32 {
    let session = SESSION.lock();
    session.session_id
}
