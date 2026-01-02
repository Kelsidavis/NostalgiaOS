//! CSR Session Management
//!
//! Manages Windows login sessions. Each session has its own window station,
//! desktop, and set of processes.

extern crate alloc;

use super::{CSR_STATE, SessionState, MAX_SESSIONS};
use crate::ke::spinlock::SpinLock;
use alloc::vec::Vec;
use alloc::string::String;

// ============================================================================
// Session Structures
// ============================================================================

/// CSR Session
#[derive(Debug, Clone)]
pub struct CsrSession {
    /// Session ID
    pub session_id: u32,
    /// Session state
    pub state: SessionState,
    /// Window station name
    pub winsta_name: String,
    /// Active desktop name
    pub desktop_name: String,
    /// User SID (if logged in)
    pub user_sid: Option<String>,
    /// Logon time
    pub logon_time: u64,
    /// Console session flag
    pub is_console: bool,
    /// Remote session flag
    pub is_remote: bool,
    /// Session flags
    pub flags: SessionFlags,
}

bitflags::bitflags! {
    /// Session flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SessionFlags: u32 {
        /// Session is initializing
        const INITIALIZING = 1 << 0;
        /// Session is disconnecting
        const DISCONNECTING = 1 << 1;
        /// Session logoff pending
        const LOGOFF_PENDING = 1 << 2;
        /// Session shutdown pending
        const SHUTDOWN_PENDING = 1 << 3;
        /// User is logged on
        const USER_LOGGED_ON = 1 << 4;
        /// Session is locked
        const LOCKED = 1 << 5;
        /// Fast user switching enabled
        const FUS_ENABLED = 1 << 6;
    }
}

impl CsrSession {
    /// Create a new session
    pub fn new(session_id: u32) -> Self {
        Self {
            session_id,
            state: SessionState::Creating,
            winsta_name: String::from("WinSta0"),
            desktop_name: String::from("Default"),
            user_sid: None,
            logon_time: 0,
            is_console: session_id == 0,
            is_remote: false,
            flags: SessionFlags::INITIALIZING,
        }
    }

    /// Activate the session
    pub fn activate(&mut self) {
        self.state = SessionState::Active;
        self.flags.remove(SessionFlags::INITIALIZING);
    }

    /// Disconnect the session (for Terminal Services)
    pub fn disconnect(&mut self) {
        self.state = SessionState::Disconnected;
        self.flags.insert(SessionFlags::DISCONNECTING);
    }

    /// Log on a user to the session
    pub fn logon_user(&mut self, user_sid: &str, logon_time: u64) {
        self.user_sid = Some(String::from(user_sid));
        self.logon_time = logon_time;
        self.flags.insert(SessionFlags::USER_LOGGED_ON);
    }

    /// Log off the current user
    pub fn logoff(&mut self) {
        self.user_sid = None;
        self.logon_time = 0;
        self.flags.remove(SessionFlags::USER_LOGGED_ON);
        self.flags.insert(SessionFlags::LOGOFF_PENDING);
    }

    /// Lock the session
    pub fn lock(&mut self) {
        self.flags.insert(SessionFlags::LOCKED);
    }

    /// Unlock the session
    pub fn unlock(&mut self) {
        self.flags.remove(SessionFlags::LOCKED);
    }
}

// ============================================================================
// Session ID Tracking
// ============================================================================

static ACTIVE_SESSION: SpinLock<u32> = SpinLock::new(0);
static NEXT_SESSION_ID: SpinLock<u32> = SpinLock::new(1);

// ============================================================================
// Session Functions
// ============================================================================

/// Initialize session management
pub fn init() {
    crate::serial_println!("[CSR] Session management initialized");
}

/// Create a new session
pub fn create_session(session_id: u32) -> bool {
    let mut state = CSR_STATE.lock();

    if state.sessions.len() >= MAX_SESSIONS {
        return false;
    }

    if state.sessions.contains_key(&session_id) {
        return false;
    }

    let mut session = CsrSession::new(session_id);
    session.activate();

    state.sessions.insert(session_id, session);

    crate::serial_println!("[CSR] Created session {}", session_id);
    true
}

/// Create a new session with auto-assigned ID
pub fn create_new_session() -> Option<u32> {
    let mut next_id = NEXT_SESSION_ID.lock();
    let session_id = *next_id;
    *next_id += 1;
    drop(next_id);

    if create_session(session_id) {
        Some(session_id)
    } else {
        None
    }
}

/// Destroy a session
pub fn destroy_session(session_id: u32) -> bool {
    // Don't destroy session 0
    if session_id == 0 {
        return false;
    }

    let mut state = CSR_STATE.lock();

    if let Some(session) = state.sessions.get_mut(&session_id) {
        session.state = SessionState::Destroying;
    } else {
        return false;
    }

    // Remove all processes from this session
    let pids_to_remove: Vec<u32> = state.processes.iter()
        .filter(|(_, p)| p.session_id == session_id)
        .map(|(pid, _)| *pid)
        .collect();

    for pid in pids_to_remove {
        state.processes.remove(&pid);
    }

    state.sessions.remove(&session_id);

    crate::serial_println!("[CSR] Destroyed session {}", session_id);
    true
}

/// Get session by ID
pub fn get_session(session_id: u32) -> Option<CsrSession> {
    let state = CSR_STATE.lock();
    state.sessions.get(&session_id).cloned()
}

/// Get all session IDs
pub fn get_all_sessions() -> Vec<u32> {
    let state = CSR_STATE.lock();
    state.sessions.keys().cloned().collect()
}

/// Set the active console session
pub fn set_active_session(session_id: u32) -> bool {
    let state = CSR_STATE.lock();
    if state.sessions.contains_key(&session_id) {
        drop(state);
        let mut active = ACTIVE_SESSION.lock();
        *active = session_id;
        crate::serial_println!("[CSR] Active session set to {}", session_id);
        true
    } else {
        false
    }
}

/// Get the active console session
pub fn get_active_session() -> u32 {
    *ACTIVE_SESSION.lock()
}

/// Get session count
pub fn get_session_count() -> usize {
    let state = CSR_STATE.lock();
    state.sessions.len()
}

/// Check if session exists
pub fn session_exists(session_id: u32) -> bool {
    let state = CSR_STATE.lock();
    state.sessions.contains_key(&session_id)
}

/// Lock a session (for screen saver / user lock)
pub fn lock_session(session_id: u32) -> bool {
    let mut state = CSR_STATE.lock();
    if let Some(session) = state.sessions.get_mut(&session_id) {
        session.lock();
        true
    } else {
        false
    }
}

/// Unlock a session
pub fn unlock_session(session_id: u32) -> bool {
    let mut state = CSR_STATE.lock();
    if let Some(session) = state.sessions.get_mut(&session_id) {
        session.unlock();
        true
    } else {
        false
    }
}

/// Logon user to session
pub fn session_logon(session_id: u32, user_sid: &str) -> bool {
    let mut state = CSR_STATE.lock();
    if let Some(session) = state.sessions.get_mut(&session_id) {
        session.logon_user(user_sid, 0); // TODO: actual timestamp
        true
    } else {
        false
    }
}

/// Logoff from session
pub fn session_logoff(session_id: u32) -> bool {
    let mut state = CSR_STATE.lock();
    if let Some(session) = state.sessions.get_mut(&session_id) {
        session.logoff();
        true
    } else {
        false
    }
}
