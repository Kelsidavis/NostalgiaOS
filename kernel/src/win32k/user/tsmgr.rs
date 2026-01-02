//! Terminal Services Manager
//!
//! Windows Server 2003 Terminal Services Manager snap-in implementation.
//! Provides terminal/remote desktop session management.
//!
//! # Features
//!
//! - Session management (view, disconnect, log off)
//! - User sessions
//! - Process management per session
//! - Server connections
//! - Remote control
//!
//! # References
//!
//! Based on Windows Server 2003 Terminal Services Manager snap-in

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::UserHandle;

/// HWND type alias
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum terminal servers
const MAX_SERVERS: usize = 16;

/// Maximum sessions per server
const MAX_SESSIONS: usize = 64;

/// Maximum processes per session
const MAX_PROCESSES: usize = 256;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum client info length
const MAX_CLIENT_LEN: usize = 128;

// ============================================================================
// Session State
// ============================================================================

/// Terminal session state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionState {
    /// Session is active (user logged in and connected)
    #[default]
    Active = 0,
    /// Session is connected but user not logged in
    Connected = 1,
    /// Session is connecting
    ConnectQuery = 2,
    /// Shadow session active
    Shadow = 3,
    /// Session disconnected (user logged in but not connected)
    Disconnected = 4,
    /// Session is idle
    Idle = 5,
    /// Session is listening for connections
    Listen = 6,
    /// Session is resetting
    Reset = 7,
    /// Session is down
    Down = 8,
    /// Session is initializing
    Init = 9,
}

impl SessionState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "Active",
            Self::Connected => "Connected",
            Self::ConnectQuery => "Connecting",
            Self::Shadow => "Shadow",
            Self::Disconnected => "Disconnected",
            Self::Idle => "Idle",
            Self::Listen => "Listen",
            Self::Reset => "Reset",
            Self::Down => "Down",
            Self::Init => "Initializing",
        }
    }
}

// ============================================================================
// Session Type
// ============================================================================

/// Session type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionType {
    /// Console session (session 0)
    #[default]
    Console = 0,
    /// Remote Desktop Protocol (RDP)
    Rdp = 1,
    /// ICA (Citrix)
    Ica = 2,
}

impl SessionType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Console => "Console",
            Self::Rdp => "RDP-Tcp",
            Self::Ica => "ICA-Tcp",
        }
    }
}

// ============================================================================
// Session Information
// ============================================================================

/// Terminal session information
#[derive(Clone, Copy)]
pub struct SessionInfo {
    /// Session ID
    pub session_id: u32,
    /// Session state
    pub state: SessionState,
    /// Session type
    pub session_type: SessionType,
    /// Username
    pub username: [u8; MAX_NAME_LEN],
    /// Username length
    pub username_len: u8,
    /// Domain
    pub domain: [u8; MAX_NAME_LEN],
    /// Domain length
    pub domain_len: u8,
    /// Window station name
    pub winstation: [u8; MAX_NAME_LEN],
    /// Window station name length
    pub winstation_len: u8,
    /// Client name
    pub client_name: [u8; MAX_CLIENT_LEN],
    /// Client name length
    pub client_name_len: u8,
    /// Client IP address
    pub client_ip: [u8; 4],
    /// Client build number
    pub client_build: u32,
    /// Color depth (bits per pixel)
    pub color_depth: u8,
    /// Horizontal resolution
    pub h_resolution: u16,
    /// Vertical resolution
    pub v_resolution: u16,
    /// Connect time (epoch seconds)
    pub connect_time: u64,
    /// Logon time (epoch seconds)
    pub logon_time: u64,
    /// Last input time (epoch seconds)
    pub last_input_time: u64,
    /// Idle time (seconds)
    pub idle_time: u64,
    /// Session is in use
    pub in_use: bool,
}

impl SessionInfo {
    pub const fn new() -> Self {
        Self {
            session_id: 0,
            state: SessionState::Idle,
            session_type: SessionType::Console,
            username: [0u8; MAX_NAME_LEN],
            username_len: 0,
            domain: [0u8; MAX_NAME_LEN],
            domain_len: 0,
            winstation: [0u8; MAX_NAME_LEN],
            winstation_len: 0,
            client_name: [0u8; MAX_CLIENT_LEN],
            client_name_len: 0,
            client_ip: [0u8; 4],
            client_build: 0,
            color_depth: 32,
            h_resolution: 1024,
            v_resolution: 768,
            connect_time: 0,
            logon_time: 0,
            last_input_time: 0,
            idle_time: 0,
            in_use: false,
        }
    }

    pub fn set_username(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.username[..len].copy_from_slice(&name[..len]);
        self.username_len = len as u8;
    }

    pub fn get_username(&self) -> &[u8] {
        &self.username[..self.username_len as usize]
    }

    pub fn set_domain(&mut self, domain: &[u8]) {
        let len = domain.len().min(MAX_NAME_LEN);
        self.domain[..len].copy_from_slice(&domain[..len]);
        self.domain_len = len as u8;
    }

    pub fn set_winstation(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.winstation[..len].copy_from_slice(&name[..len]);
        self.winstation_len = len as u8;
    }

    pub fn set_client_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_CLIENT_LEN);
        self.client_name[..len].copy_from_slice(&name[..len]);
        self.client_name_len = len as u8;
    }
}

// ============================================================================
// Session Process
// ============================================================================

/// Process running in a session
#[derive(Clone, Copy)]
pub struct SessionProcess {
    /// Process ID
    pub pid: u32,
    /// Session ID
    pub session_id: u32,
    /// Process name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: u8,
    /// User running the process
    pub username: [u8; MAX_NAME_LEN],
    /// Username length
    pub username_len: u8,
    /// CPU usage (percent * 100)
    pub cpu_usage: u16,
    /// Memory usage (KB)
    pub memory_kb: u32,
    /// Process is in use
    pub in_use: bool,
}

impl SessionProcess {
    pub const fn new() -> Self {
        Self {
            pid: 0,
            session_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            username: [0u8; MAX_NAME_LEN],
            username_len: 0,
            cpu_usage: 0,
            memory_kb: 0,
            in_use: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u8;
    }

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

// ============================================================================
// Terminal Server
// ============================================================================

/// Terminal server
pub struct TerminalServer {
    /// Server name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: u8,
    /// Server IP address
    pub ip_address: [u8; 4],
    /// Is local server
    pub is_local: bool,
    /// Is connected
    pub connected: bool,
    /// Sessions
    pub sessions: [SessionInfo; MAX_SESSIONS],
    /// Session count
    pub session_count: u32,
    /// Processes
    pub processes: [SessionProcess; MAX_PROCESSES],
    /// Process count
    pub process_count: u32,
    /// Total licenses
    pub total_licenses: u32,
    /// Available licenses
    pub available_licenses: u32,
    /// Server is in use
    pub in_use: bool,
}

impl TerminalServer {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            ip_address: [0u8; 4],
            is_local: false,
            connected: false,
            sessions: [const { SessionInfo::new() }; MAX_SESSIONS],
            session_count: 0,
            processes: [const { SessionProcess::new() }; MAX_PROCESSES],
            process_count: 0,
            total_licenses: 0,
            available_licenses: 0,
            in_use: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u8;
    }

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Create a new session
    pub fn create_session(&mut self, session_id: u32, session_type: SessionType) -> Option<usize> {
        for (i, session) in self.sessions.iter_mut().enumerate() {
            if !session.in_use {
                session.session_id = session_id;
                session.session_type = session_type;
                session.state = SessionState::Listen;
                session.in_use = true;
                self.session_count += 1;
                return Some(i);
            }
        }
        None
    }

    /// Find session by ID
    pub fn find_session(&self, session_id: u32) -> Option<usize> {
        for (i, session) in self.sessions.iter().enumerate() {
            if session.in_use && session.session_id == session_id {
                return Some(i);
            }
        }
        None
    }

    /// Disconnect a session
    pub fn disconnect_session(&mut self, session_id: u32) -> bool {
        if let Some(idx) = self.find_session(session_id) {
            self.sessions[idx].state = SessionState::Disconnected;
            true
        } else {
            false
        }
    }

    /// Log off a session
    pub fn logoff_session(&mut self, session_id: u32) -> bool {
        if let Some(idx) = self.find_session(session_id) {
            self.sessions[idx].in_use = false;
            self.session_count = self.session_count.saturating_sub(1);
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Manager State
// ============================================================================

/// Terminal Services Manager state
struct TsManagerState {
    /// Terminal servers
    servers: [TerminalServer; MAX_SERVERS],
    /// Server count
    server_count: u32,
    /// Selected server index
    selected_server: Option<usize>,
    /// Selected session index
    selected_session: Option<usize>,
    /// Dialog handle
    dialog_handle: HWND,
    /// View mode (0=servers, 1=sessions, 2=processes, 3=users)
    view_mode: u8,
    /// Next session ID
    next_session_id: u32,
}

impl TsManagerState {
    pub const fn new() -> Self {
        Self {
            servers: [const { TerminalServer::new() }; MAX_SERVERS],
            server_count: 0,
            selected_server: None,
            selected_session: None,
            dialog_handle: UserHandle::from_raw(0),
            view_mode: 0,
            next_session_id: 1,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static TS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static TS_MANAGER: SpinLock<TsManagerState> = SpinLock::new(TsManagerState::new());

// Statistics
static TOTAL_SESSIONS: AtomicU32 = AtomicU32::new(0);
static ACTIVE_SESSIONS: AtomicU32 = AtomicU32::new(0);
static DISCONNECTED_SESSIONS: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Terminal Services Manager
pub fn init() {
    if TS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = TS_MANAGER.lock();

    // Add local server
    let srv = &mut state.servers[0];
    srv.set_name(b"localhost");
    srv.ip_address = [127, 0, 0, 1];
    srv.is_local = true;
    srv.connected = true;
    srv.in_use = true;

    // Create console session (session 0)
    srv.create_session(0, SessionType::Console);
    let console_idx = 0;
    srv.sessions[console_idx].state = SessionState::Active;
    srv.sessions[console_idx].set_winstation(b"Console");
    srv.sessions[console_idx].set_username(b"Administrator");
    srv.sessions[console_idx].set_domain(b"WORKGROUP");

    // Create RDP listener
    let rdp_idx = srv.create_session(65536, SessionType::Rdp).unwrap_or(1);
    srv.sessions[rdp_idx].state = SessionState::Listen;
    srv.sessions[rdp_idx].set_winstation(b"RDP-Tcp");

    state.server_count = 1;

    TOTAL_SESSIONS.store(2, Ordering::Relaxed);
    ACTIVE_SESSIONS.store(1, Ordering::Relaxed);

    crate::serial_println!("[WIN32K] Terminal Services Manager initialized");
}

// ============================================================================
// Server Management
// ============================================================================

/// Add a terminal server connection
pub fn add_server(name: &[u8], ip: [u8; 4]) -> Option<usize> {
    let mut state = TS_MANAGER.lock();

    for (i, server) in state.servers.iter_mut().enumerate() {
        if !server.in_use {
            server.set_name(name);
            server.ip_address = ip;
            server.is_local = false;
            server.connected = false;
            server.in_use = true;
            state.server_count += 1;
            return Some(i);
        }
    }
    None
}

/// Connect to a terminal server
pub fn connect_server(index: usize) -> bool {
    let mut state = TS_MANAGER.lock();

    if index < MAX_SERVERS && state.servers[index].in_use {
        state.servers[index].connected = true;
        // In real implementation, would establish RPC connection
        true
    } else {
        false
    }
}

/// Disconnect from a terminal server
pub fn disconnect_server(index: usize) -> bool {
    let mut state = TS_MANAGER.lock();

    if index < MAX_SERVERS && state.servers[index].in_use && !state.servers[index].is_local {
        state.servers[index].connected = false;
        true
    } else {
        false
    }
}

/// Remove a terminal server
pub fn remove_server(index: usize) -> bool {
    let mut state = TS_MANAGER.lock();

    if index < MAX_SERVERS && state.servers[index].in_use && !state.servers[index].is_local {
        state.servers[index].in_use = false;
        state.server_count = state.server_count.saturating_sub(1);
        true
    } else {
        false
    }
}

// ============================================================================
// Session Management
// ============================================================================

/// Create a new session
pub fn create_session(server_index: usize, session_type: SessionType) -> Option<u32> {
    let mut state = TS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        let session_id = state.next_session_id;
        if state.servers[server_index].create_session(session_id, session_type).is_some() {
            state.next_session_id += 1;
            TOTAL_SESSIONS.fetch_add(1, Ordering::Relaxed);
            return Some(session_id);
        }
    }
    None
}

/// Disconnect a session
pub fn disconnect_session(server_index: usize, session_id: u32) -> bool {
    let mut state = TS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        if state.servers[server_index].disconnect_session(session_id) {
            ACTIVE_SESSIONS.fetch_sub(1, Ordering::Relaxed);
            DISCONNECTED_SESSIONS.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

/// Log off a session
pub fn logoff_session(server_index: usize, session_id: u32) -> bool {
    let mut state = TS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        if state.servers[server_index].logoff_session(session_id) {
            TOTAL_SESSIONS.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

/// Send message to session
pub fn send_message(server_index: usize, session_id: u32, _title: &[u8], _message: &[u8]) -> bool {
    let state = TS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        if state.servers[server_index].find_session(session_id).is_some() {
            // In real implementation, would send WTSSendMessage
            return true;
        }
    }
    false
}

/// Reset a session
pub fn reset_session(server_index: usize, session_id: u32) -> bool {
    let mut state = TS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        if let Some(idx) = state.servers[server_index].find_session(session_id) {
            state.servers[server_index].sessions[idx].state = SessionState::Reset;
            // In real implementation, would force session reset
            state.servers[server_index].sessions[idx].in_use = false;
            state.servers[server_index].session_count =
                state.servers[server_index].session_count.saturating_sub(1);
            TOTAL_SESSIONS.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

/// Connect to a session (for logon)
pub fn connect_to_session(server_index: usize, session_id: u32, username: &[u8], domain: &[u8]) -> bool {
    let mut state = TS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        if let Some(idx) = state.servers[server_index].find_session(session_id) {
            let session = &mut state.servers[server_index].sessions[idx];
            session.set_username(username);
            session.set_domain(domain);
            session.state = SessionState::Active;
            ACTIVE_SESSIONS.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

/// Shadow a session (remote control)
pub fn shadow_session(server_index: usize, session_id: u32, _interactive: bool) -> bool {
    let state = TS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        if let Some(idx) = state.servers[server_index].find_session(session_id) {
            if state.servers[server_index].sessions[idx].state == SessionState::Active {
                // In real implementation, would start shadow session
                return true;
            }
        }
    }
    false
}

// ============================================================================
// Process Management
// ============================================================================

/// Register a process in a session
pub fn register_process(server_index: usize, session_id: u32, pid: u32, name: &[u8]) -> Option<usize> {
    let mut state = TS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        for (i, proc) in state.servers[server_index].processes.iter_mut().enumerate() {
            if !proc.in_use {
                proc.pid = pid;
                proc.session_id = session_id;
                proc.set_name(name);
                proc.in_use = true;
                state.servers[server_index].process_count += 1;
                return Some(i);
            }
        }
    }
    None
}

/// Terminate a process
pub fn terminate_process(server_index: usize, pid: u32) -> bool {
    let mut state = TS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        for proc in state.servers[server_index].processes.iter_mut() {
            if proc.in_use && proc.pid == pid {
                proc.in_use = false;
                state.servers[server_index].process_count =
                    state.servers[server_index].process_count.saturating_sub(1);
                // In real implementation, would call TerminateProcess
                return true;
            }
        }
    }
    false
}

/// Get processes for a session
pub fn get_session_processes(server_index: usize, session_id: u32) -> u32 {
    let state = TS_MANAGER.lock();
    let mut count = 0u32;

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        for proc in state.servers[server_index].processes.iter() {
            if proc.in_use && proc.session_id == session_id {
                count += 1;
            }
        }
    }
    count
}

// ============================================================================
// Information Queries
// ============================================================================

/// Get session information
pub fn get_session_info(server_index: usize, session_id: u32) -> Option<(SessionState, SessionType, u64)> {
    let state = TS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        if let Some(idx) = state.servers[server_index].find_session(session_id) {
            let session = &state.servers[server_index].sessions[idx];
            return Some((session.state, session.session_type, session.idle_time));
        }
    }
    None
}

/// Get server session count
pub fn get_server_session_count(server_index: usize) -> Option<(u32, u32, u32)> {
    let state = TS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        let server = &state.servers[server_index];
        let mut active = 0u32;
        let mut disconnected = 0u32;

        for session in server.sessions.iter() {
            if session.in_use {
                match session.state {
                    SessionState::Active => active += 1,
                    SessionState::Disconnected => disconnected += 1,
                    _ => {}
                }
            }
        }

        return Some((server.session_count, active, disconnected));
    }
    None
}

// ============================================================================
// Dialog Management
// ============================================================================

/// Show Terminal Services Manager dialog
pub fn show_dialog(parent: HWND) -> HWND {
    let mut state = TS_MANAGER.lock();

    let handle = UserHandle::from_raw(0xDB01);
    state.dialog_handle = handle;
    state.selected_server = Some(0); // Select local server
    state.selected_session = None;
    state.view_mode = 1; // Sessions view

    let _ = parent;
    handle
}

/// Close Terminal Services Manager dialog
pub fn close_dialog() {
    let mut state = TS_MANAGER.lock();
    state.dialog_handle = UserHandle::from_raw(0);
}

/// Select a server
pub fn select_server(index: usize) {
    let mut state = TS_MANAGER.lock();
    if index < MAX_SERVERS && state.servers[index].in_use {
        state.selected_server = Some(index);
        state.selected_session = None;
    }
}

/// Select a session
pub fn select_session(session_id: u32) {
    let mut state = TS_MANAGER.lock();
    if let Some(srv_idx) = state.selected_server {
        if state.servers[srv_idx].find_session(session_id).is_some() {
            state.selected_session = Some(session_id as usize);
        }
    }
}

/// Set view mode
pub fn set_view_mode(mode: u8) {
    let mut state = TS_MANAGER.lock();
    state.view_mode = mode;
}

// ============================================================================
// Statistics
// ============================================================================

/// Terminal Services statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct TsStats {
    pub initialized: bool,
    pub server_count: u32,
    pub total_sessions: u32,
    pub active_sessions: u32,
    pub disconnected_sessions: u32,
}

/// Get Terminal Services statistics
pub fn get_stats() -> TsStats {
    let state = TS_MANAGER.lock();
    TsStats {
        initialized: TS_INITIALIZED.load(Ordering::Relaxed),
        server_count: state.server_count,
        total_sessions: TOTAL_SESSIONS.load(Ordering::Relaxed),
        active_sessions: ACTIVE_SESSIONS.load(Ordering::Relaxed),
        disconnected_sessions: DISCONNECTED_SESSIONS.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Licensing
// ============================================================================

/// Set license count for server
pub fn set_licenses(server_index: usize, total: u32, available: u32) -> bool {
    let mut state = TS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        state.servers[server_index].total_licenses = total;
        state.servers[server_index].available_licenses = available;
        true
    } else {
        false
    }
}

/// Get license info
pub fn get_license_info(server_index: usize) -> Option<(u32, u32)> {
    let state = TS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        Some((
            state.servers[server_index].total_licenses,
            state.servers[server_index].available_licenses,
        ))
    } else {
        None
    }
}
