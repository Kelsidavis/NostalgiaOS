//! Remote Desktop Configuration
//!
//! Implements Remote Desktop settings following Windows Server 2003.
//! Provides Terminal Services configuration and remote access settings.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - System Properties > Remote tab
//! - Terminal Services Configuration
//! - mstsc.exe - Remote Desktop Connection

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum remote users
const MAX_USERS: usize = 32;

/// Maximum user name length
const MAX_NAME: usize = 64;

/// Maximum connections
const MAX_CONNECTIONS: usize = 64;

/// Maximum hostname length
const MAX_HOSTNAME: usize = 256;

// ============================================================================
// Remote Desktop Mode
// ============================================================================

/// Remote Desktop mode
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RemoteMode {
    /// Remote Desktop disabled
    #[default]
    Disabled = 0,
    /// Allow connections from any version of Remote Desktop
    AllowAny = 1,
    /// Allow connections only from computers running Remote Desktop with NLA
    RequireNla = 2,
}

impl RemoteMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            RemoteMode::Disabled => "Don't allow remote connections",
            RemoteMode::AllowAny => "Allow connections from any version",
            RemoteMode::RequireNla => "Require Network Level Authentication",
        }
    }
}

// ============================================================================
// Connection Status
// ============================================================================

/// Connection status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionStatus {
    /// Disconnected
    #[default]
    Disconnected = 0,
    /// Connecting
    Connecting = 1,
    /// Connected
    Connected = 2,
    /// Idle
    Idle = 3,
    /// Disconnecting
    Disconnecting = 4,
}

impl ConnectionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionStatus::Disconnected => "Disconnected",
            ConnectionStatus::Connecting => "Connecting",
            ConnectionStatus::Connected => "Connected",
            ConnectionStatus::Idle => "Idle",
            ConnectionStatus::Disconnecting => "Disconnecting",
        }
    }
}

// ============================================================================
// Remote User
// ============================================================================

/// Remote user entry
#[derive(Debug, Clone, Copy)]
pub struct RemoteUser {
    /// User name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Domain
    pub domain: [u8; MAX_NAME],
    /// Domain length
    pub domain_len: usize,
    /// Is administrator
    pub is_admin: bool,
}

impl RemoteUser {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME],
            name_len: 0,
            domain: [0u8; MAX_NAME],
            domain_len: 0,
            is_admin: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_domain(&mut self, domain: &[u8]) {
        let len = domain.len().min(MAX_NAME);
        self.domain[..len].copy_from_slice(&domain[..len]);
        self.domain_len = len;
    }
}

impl Default for RemoteUser {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Remote Connection
// ============================================================================

/// Active remote connection
#[derive(Debug, Clone, Copy)]
pub struct RemoteConnection {
    /// Session ID
    pub session_id: u32,
    /// User name
    pub user_name: [u8; MAX_NAME],
    /// User name length
    pub user_name_len: usize,
    /// Client hostname
    pub client_host: [u8; MAX_HOSTNAME],
    /// Client host length
    pub client_host_len: usize,
    /// Client IP address
    pub client_ip: [u8; 4],
    /// Connection status
    pub status: ConnectionStatus,
    /// Connect time (timestamp)
    pub connect_time: u64,
    /// Idle time (seconds)
    pub idle_time: u32,
    /// Display resolution width
    pub resolution_width: u16,
    /// Display resolution height
    pub resolution_height: u16,
    /// Color depth (bits)
    pub color_depth: u8,
}

impl RemoteConnection {
    pub const fn new() -> Self {
        Self {
            session_id: 0,
            user_name: [0u8; MAX_NAME],
            user_name_len: 0,
            client_host: [0u8; MAX_HOSTNAME],
            client_host_len: 0,
            client_ip: [0; 4],
            status: ConnectionStatus::Disconnected,
            connect_time: 0,
            idle_time: 0,
            resolution_width: 0,
            resolution_height: 0,
            color_depth: 0,
        }
    }

    pub fn set_user_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.user_name[..len].copy_from_slice(&name[..len]);
        self.user_name_len = len;
    }

    pub fn set_client_host(&mut self, host: &[u8]) {
        let len = host.len().min(MAX_HOSTNAME);
        self.client_host[..len].copy_from_slice(&host[..len]);
        self.client_host_len = len;
    }
}

impl Default for RemoteConnection {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Remote Desktop Settings
// ============================================================================

/// Remote Desktop settings
#[derive(Debug, Clone, Copy)]
pub struct RemoteSettings {
    /// Remote Desktop mode
    pub mode: RemoteMode,
    /// Allow Remote Assistance
    pub allow_assistance: bool,
    /// Allow invitations for Remote Assistance
    pub allow_invitations: bool,
    /// Maximum invitation time (hours)
    pub max_invitation_time: u32,
    /// Port number (default 3389)
    pub port: u16,
    /// Maximum connections
    pub max_connections: u32,
    /// Disconnect idle sessions (minutes, 0 = never)
    pub idle_timeout: u32,
    /// End disconnected sessions (minutes, 0 = never)
    pub disconnect_timeout: u32,
    /// Require user authentication
    pub require_auth: bool,
    /// Allow clipboard redirection
    pub allow_clipboard: bool,
    /// Allow drive redirection
    pub allow_drives: bool,
    /// Allow printer redirection
    pub allow_printers: bool,
    /// Allow audio redirection
    pub allow_audio: bool,
}

impl RemoteSettings {
    pub const fn new() -> Self {
        Self {
            mode: RemoteMode::Disabled,
            allow_assistance: true,
            allow_invitations: true,
            max_invitation_time: 6,
            port: 3389,
            max_connections: 2,
            idle_timeout: 0,
            disconnect_timeout: 0,
            require_auth: true,
            allow_clipboard: true,
            allow_drives: false,
            allow_printers: true,
            allow_audio: false,
        }
    }
}

impl Default for RemoteSettings {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Remote Desktop State
// ============================================================================

/// Remote Desktop state
struct RemoteState {
    /// Settings
    settings: RemoteSettings,
    /// Allowed users
    users: [RemoteUser; MAX_USERS],
    /// User count
    user_count: usize,
    /// Active connections
    connections: [RemoteConnection; MAX_CONNECTIONS],
    /// Connection count
    connection_count: usize,
    /// Next session ID
    next_session_id: u32,
}

impl RemoteState {
    pub const fn new() -> Self {
        Self {
            settings: RemoteSettings::new(),
            users: [const { RemoteUser::new() }; MAX_USERS],
            user_count: 0,
            connections: [const { RemoteConnection::new() }; MAX_CONNECTIONS],
            connection_count: 0,
            next_session_id: 1,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static REMOTE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static REMOTE_STATE: SpinLock<RemoteState> = SpinLock::new(RemoteState::new());

// Statistics
static TOTAL_CONNECTIONS: AtomicU32 = AtomicU32::new(0);
static ACTIVE_SESSIONS: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Remote Desktop
pub fn init() {
    if REMOTE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = REMOTE_STATE.lock();

    // Default settings
    state.settings = RemoteSettings::new();

    // Add default users (Administrators have access by default)
    add_default_users(&mut state);

    crate::serial_println!("[WIN32K] Remote Desktop initialized");
}

/// Add default users
fn add_default_users(state: &mut RemoteState) {
    // Administrator always has access
    let mut admin = RemoteUser::new();
    admin.set_name(b"Administrator");
    admin.is_admin = true;
    state.users[0] = admin;
    state.user_count = 1;
}

// ============================================================================
// Settings Management
// ============================================================================

/// Get current settings
pub fn get_settings() -> RemoteSettings {
    REMOTE_STATE.lock().settings
}

/// Set Remote Desktop mode
pub fn set_mode(mode: RemoteMode) {
    REMOTE_STATE.lock().settings.mode = mode;
}

/// Get Remote Desktop mode
pub fn get_mode() -> RemoteMode {
    REMOTE_STATE.lock().settings.mode
}

/// Check if Remote Desktop is enabled
pub fn is_enabled() -> bool {
    REMOTE_STATE.lock().settings.mode != RemoteMode::Disabled
}

/// Set Remote Assistance enabled
pub fn set_assistance_enabled(enabled: bool) {
    REMOTE_STATE.lock().settings.allow_assistance = enabled;
}

/// Check if Remote Assistance is enabled
pub fn is_assistance_enabled() -> bool {
    REMOTE_STATE.lock().settings.allow_assistance
}

/// Set port number
pub fn set_port(port: u16) {
    REMOTE_STATE.lock().settings.port = port;
}

/// Get port number
pub fn get_port() -> u16 {
    REMOTE_STATE.lock().settings.port
}

/// Set maximum connections
pub fn set_max_connections(max: u32) {
    REMOTE_STATE.lock().settings.max_connections = max;
}

/// Set idle timeout (minutes)
pub fn set_idle_timeout(minutes: u32) {
    REMOTE_STATE.lock().settings.idle_timeout = minutes;
}

/// Set redirection settings
pub fn set_redirection(clipboard: bool, drives: bool, printers: bool, audio: bool) {
    let mut state = REMOTE_STATE.lock();
    state.settings.allow_clipboard = clipboard;
    state.settings.allow_drives = drives;
    state.settings.allow_printers = printers;
    state.settings.allow_audio = audio;
}

// ============================================================================
// User Management
// ============================================================================

/// Get allowed user count
pub fn get_user_count() -> usize {
    REMOTE_STATE.lock().user_count
}

/// Get user by index
pub fn get_user(index: usize) -> Option<RemoteUser> {
    let state = REMOTE_STATE.lock();
    if index < state.user_count {
        Some(state.users[index])
    } else {
        None
    }
}

/// Add allowed user
pub fn add_user(name: &[u8], domain: &[u8]) -> bool {
    let mut state = REMOTE_STATE.lock();
    if state.user_count >= MAX_USERS {
        return false;
    }

    let mut user = RemoteUser::new();
    user.set_name(name);
    user.set_domain(domain);

    let idx = state.user_count;
    state.users[idx] = user;
    state.user_count += 1;
    true
}

/// Remove allowed user
pub fn remove_user(index: usize) -> bool {
    let mut state = REMOTE_STATE.lock();
    if index >= state.user_count {
        return false;
    }

    // Don't remove administrator
    if state.users[index].is_admin {
        return false;
    }

    // Shift remaining users
    for i in index..state.user_count - 1 {
        state.users[i] = state.users[i + 1];
    }
    state.user_count -= 1;
    true
}

/// Check if user is allowed
pub fn is_user_allowed(name: &[u8]) -> bool {
    let state = REMOTE_STATE.lock();
    for i in 0..state.user_count {
        let user = &state.users[i];
        if user.name_len == name.len() && &user.name[..user.name_len] == name {
            return true;
        }
    }
    false
}

// ============================================================================
// Connection Management
// ============================================================================

/// Get active connection count
pub fn get_connection_count() -> usize {
    REMOTE_STATE.lock().connection_count
}

/// Get connection by index
pub fn get_connection(index: usize) -> Option<RemoteConnection> {
    let state = REMOTE_STATE.lock();
    if index < state.connection_count {
        Some(state.connections[index])
    } else {
        None
    }
}

/// Get connection by session ID
pub fn get_connection_by_session(session_id: u32) -> Option<RemoteConnection> {
    let state = REMOTE_STATE.lock();
    for i in 0..state.connection_count {
        if state.connections[i].session_id == session_id {
            return Some(state.connections[i]);
        }
    }
    None
}

/// Create new connection (for incoming RDP)
pub fn create_connection(user_name: &[u8], client_host: &[u8], client_ip: [u8; 4]) -> Option<u32> {
    let mut state = REMOTE_STATE.lock();

    // Check if enabled
    if state.settings.mode == RemoteMode::Disabled {
        return None;
    }

    // Check max connections
    if state.connection_count >= state.settings.max_connections as usize {
        return None;
    }

    if state.connection_count >= MAX_CONNECTIONS {
        return None;
    }

    let session_id = state.next_session_id;
    state.next_session_id += 1;

    let mut conn = RemoteConnection::new();
    conn.session_id = session_id;
    conn.set_user_name(user_name);
    conn.set_client_host(client_host);
    conn.client_ip = client_ip;
    conn.status = ConnectionStatus::Connected;
    conn.resolution_width = 1024;
    conn.resolution_height = 768;
    conn.color_depth = 24;

    let idx = state.connection_count;
    state.connections[idx] = conn;
    state.connection_count += 1;

    TOTAL_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    ACTIVE_SESSIONS.store(state.connection_count as u32, Ordering::Relaxed);

    Some(session_id)
}

/// Disconnect session
pub fn disconnect_session(session_id: u32) -> bool {
    let mut state = REMOTE_STATE.lock();

    let mut found_index = None;
    for i in 0..state.connection_count {
        if state.connections[i].session_id == session_id {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        // Shift remaining connections
        for i in index..state.connection_count - 1 {
            state.connections[i] = state.connections[i + 1];
        }
        state.connection_count -= 1;
        ACTIVE_SESSIONS.store(state.connection_count as u32, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// Send message to session
pub fn send_message_to_session(session_id: u32, _message: &[u8]) -> bool {
    let state = REMOTE_STATE.lock();
    for i in 0..state.connection_count {
        if state.connections[i].session_id == session_id {
            // Would send message to client
            return true;
        }
    }
    false
}

/// Log off session
pub fn logoff_session(session_id: u32) -> bool {
    disconnect_session(session_id)
}

// ============================================================================
// Statistics
// ============================================================================

/// Remote Desktop statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct RemoteStats {
    pub initialized: bool,
    pub enabled: bool,
    pub mode: RemoteMode,
    pub port: u16,
    pub user_count: usize,
    pub active_connections: usize,
    pub total_connections: u32,
}

/// Get Remote Desktop statistics
pub fn get_stats() -> RemoteStats {
    let state = REMOTE_STATE.lock();
    RemoteStats {
        initialized: REMOTE_INITIALIZED.load(Ordering::Relaxed),
        enabled: state.settings.mode != RemoteMode::Disabled,
        mode: state.settings.mode,
        port: state.settings.port,
        user_count: state.user_count,
        active_connections: state.connection_count,
        total_connections: TOTAL_CONNECTIONS.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Remote Desktop dialog handle
pub type HREMOTEDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Remote Desktop dialog
pub fn create_remote_dialog(_parent: super::super::HWND) -> HREMOTEDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}
