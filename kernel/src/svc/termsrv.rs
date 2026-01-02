//! Terminal Services (TermService)
//!
//! Terminal Services provides remote desktop capabilities, allowing users
//! to connect to and control Windows systems remotely. In Windows Server 2003,
//! this includes both Remote Desktop for Administration and Terminal Server
//! application sharing.
//!
//! # Features
//!
//! - **Remote Desktop**: Remote graphical desktop access
//! - **Session Management**: Multiple concurrent user sessions
//! - **RDP Protocol**: Remote Desktop Protocol support
//! - **Licensing**: Terminal Services licensing
//! - **Session Directory**: Load balancing and session reconnection
//!
//! # Session Types
//!
//! - Console session (Session 0)
//! - Remote desktop sessions
//! - Virtual channel sessions
//!
//! # Licensing Modes
//!
//! - Remote Desktop for Administration (2 concurrent connections)
//! - Per Device CAL
//! - Per User CAL

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum sessions
const MAX_SESSIONS: usize = 16;

/// Maximum virtual channels per session
const MAX_CHANNELS: usize = 32;

/// Maximum username length
const MAX_USERNAME: usize = 64;

/// Maximum client name length
const MAX_CLIENT_NAME: usize = 64;

/// Maximum domain length
const MAX_DOMAIN: usize = 64;

/// Session state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is active
    Active = 0,
    /// Session is connected
    Connected = 1,
    /// Session is connecting
    ConnectQuery = 2,
    /// Session has shadow
    Shadow = 3,
    /// Session is disconnected
    Disconnected = 4,
    /// Session is idle
    Idle = 5,
    /// Session is listening
    Listen = 6,
    /// Session is resetting
    Reset = 7,
    /// Session is down
    Down = 8,
    /// Session is initializing
    Init = 9,
}

impl SessionState {
    const fn empty() -> Self {
        SessionState::Down
    }
}

/// Protocol type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolType {
    /// Console session
    Console = 0,
    /// ICA protocol (Citrix)
    Ica = 1,
    /// RDP protocol
    Rdp = 2,
}

impl ProtocolType {
    const fn empty() -> Self {
        ProtocolType::Console
    }
}

/// Session information
#[repr(C)]
#[derive(Clone)]
pub struct SessionInfo {
    /// Session ID
    pub session_id: u32,
    /// Session state
    pub state: SessionState,
    /// Protocol type
    pub protocol: ProtocolType,
    /// Username
    pub username: [u8; MAX_USERNAME],
    /// Domain
    pub domain: [u8; MAX_DOMAIN],
    /// Client name
    pub client_name: [u8; MAX_CLIENT_NAME],
    /// Client IP address
    pub client_address: u32,
    /// Client build number
    pub client_build: u32,
    /// Color depth (bits)
    pub color_depth: u16,
    /// Horizontal resolution
    pub h_resolution: u16,
    /// Vertical resolution
    pub v_resolution: u16,
    /// Logon time
    pub logon_time: i64,
    /// Connect time
    pub connect_time: i64,
    /// Disconnect time
    pub disconnect_time: i64,
    /// Last input time
    pub last_input_time: i64,
    /// Entry is valid
    pub valid: bool,
}

impl SessionInfo {
    const fn empty() -> Self {
        SessionInfo {
            session_id: 0,
            state: SessionState::empty(),
            protocol: ProtocolType::empty(),
            username: [0; MAX_USERNAME],
            domain: [0; MAX_DOMAIN],
            client_name: [0; MAX_CLIENT_NAME],
            client_address: 0,
            client_build: 0,
            color_depth: 0,
            h_resolution: 0,
            v_resolution: 0,
            logon_time: 0,
            connect_time: 0,
            disconnect_time: 0,
            last_input_time: 0,
            valid: false,
        }
    }
}

/// Virtual channel
#[repr(C)]
#[derive(Clone)]
pub struct VirtualChannel {
    /// Channel name
    pub name: [u8; 8],
    /// Channel flags
    pub flags: u32,
    /// Session ID
    pub session_id: u32,
    /// Entry is valid
    pub valid: bool,
}

impl VirtualChannel {
    const fn empty() -> Self {
        VirtualChannel {
            name: [0; 8],
            flags: 0,
            session_id: 0,
            valid: false,
        }
    }
}

/// Licensing mode
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseMode {
    /// Remote Desktop for Administration
    RemoteAdmin = 0,
    /// Per Device
    PerDevice = 1,
    /// Per User
    PerUser = 2,
}

/// Terminal Services configuration
#[repr(C)]
#[derive(Clone)]
pub struct TermConfig {
    /// Service enabled
    pub enabled: bool,
    /// Licensing mode
    pub license_mode: LicenseMode,
    /// Allow remote connections
    pub allow_connections: bool,
    /// Max connections (0 = unlimited)
    pub max_connections: u32,
    /// Listening port
    pub listen_port: u16,
    /// Require NLA (Network Level Authentication)
    pub require_nla: bool,
    /// Allow clipboard redirection
    pub allow_clipboard: bool,
    /// Allow drive redirection
    pub allow_drives: bool,
    /// Allow printer redirection
    pub allow_printers: bool,
    /// Allow audio redirection
    pub allow_audio: bool,
    /// Idle timeout (minutes, 0 = disabled)
    pub idle_timeout: u32,
    /// Disconnected session limit (minutes)
    pub disconnect_timeout: u32,
}

impl TermConfig {
    const fn default() -> Self {
        TermConfig {
            enabled: true,
            license_mode: LicenseMode::RemoteAdmin,
            allow_connections: true,
            max_connections: 2, // Remote Admin mode
            listen_port: 3389,
            require_nla: false,
            allow_clipboard: true,
            allow_drives: true,
            allow_printers: true,
            allow_audio: true,
            idle_timeout: 0,
            disconnect_timeout: 0,
        }
    }
}

/// Terminal Services state
pub struct TermState {
    /// Service is running
    pub running: bool,
    /// Configuration
    pub config: TermConfig,
    /// Sessions
    pub sessions: [SessionInfo; MAX_SESSIONS],
    /// Session count
    pub session_count: usize,
    /// Virtual channels
    pub channels: [VirtualChannel; MAX_CHANNELS],
    /// Channel count
    pub channel_count: usize,
    /// Next session ID
    pub next_session_id: u32,
    /// Service start time
    pub start_time: i64,
    /// Listener active
    pub listening: bool,
}

impl TermState {
    const fn new() -> Self {
        TermState {
            running: false,
            config: TermConfig::default(),
            sessions: [const { SessionInfo::empty() }; MAX_SESSIONS],
            session_count: 0,
            channels: [const { VirtualChannel::empty() }; MAX_CHANNELS],
            channel_count: 0,
            next_session_id: 1,
            start_time: 0,
            listening: false,
        }
    }
}

/// Global state
static TERM_STATE: Mutex<TermState> = Mutex::new(TermState::new());

/// Statistics
static TOTAL_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static ACTIVE_SESSIONS: AtomicU64 = AtomicU64::new(0);
static FAILED_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize Terminal Services
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = TERM_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    // Create console session (Session 0)
    create_console_session(&mut state);

    // Start listener if connections allowed
    if state.config.allow_connections {
        state.listening = true;
    }

    crate::serial_println!("[TERMSRV] Terminal Services initialized");
}

/// Create console session
fn create_console_session(state: &mut TermState) {
    let session = &mut state.sessions[0];
    session.session_id = 0;
    session.state = SessionState::Active;
    session.protocol = ProtocolType::Console;

    let name = b"Console";
    session.client_name[..name.len()].copy_from_slice(name);

    session.color_depth = 32;
    session.h_resolution = 1024;
    session.v_resolution = 768;
    session.connect_time = crate::rtl::time::rtl_get_system_time();
    session.last_input_time = session.connect_time;
    session.valid = true;

    state.session_count = 1;
    ACTIVE_SESSIONS.fetch_add(1, Ordering::SeqCst);
}

/// Create a new session
pub fn create_session(
    protocol: ProtocolType,
    client_name: &[u8],
    client_address: u32,
) -> Result<u32, u32> {
    let mut state = TERM_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    if !state.config.allow_connections {
        return Err(0x80070005); // Access denied
    }

    // Check connection limit
    let active = state.sessions.iter().filter(|s| {
        s.valid && matches!(s.state, SessionState::Active | SessionState::Connected)
    }).count();

    if state.config.max_connections > 0 && active >= state.config.max_connections as usize {
        FAILED_CONNECTIONS.fetch_add(1, Ordering::SeqCst);
        return Err(0x80071392); // ERROR_CTX_LICENSE_NOT_AVAILABLE
    }

    // Find free slot
    let slot = state.sessions.iter().position(|s| !s.valid);
    let slot = match slot {
        Some(s) => s,
        None => {
            FAILED_CONNECTIONS.fetch_add(1, Ordering::SeqCst);
            return Err(0x8007000E);
        }
    };

    let session_id = state.next_session_id;
    state.next_session_id += 1;

    let now = crate::rtl::time::rtl_get_system_time();

    let session = &mut state.sessions[slot];
    session.session_id = session_id;
    session.state = SessionState::ConnectQuery;
    session.protocol = protocol;

    let name_len = client_name.len().min(MAX_CLIENT_NAME);
    session.client_name[..name_len].copy_from_slice(&client_name[..name_len]);

    session.client_address = client_address;
    session.connect_time = now;
    session.last_input_time = now;
    session.color_depth = 16; // Default
    session.h_resolution = 800;
    session.v_resolution = 600;
    session.valid = true;

    state.session_count += 1;
    TOTAL_CONNECTIONS.fetch_add(1, Ordering::SeqCst);
    ACTIVE_SESSIONS.fetch_add(1, Ordering::SeqCst);

    Ok(session_id)
}

/// Logon to session
pub fn logon_session(
    session_id: u32,
    username: &[u8],
    domain: &[u8],
) -> Result<(), u32> {
    let mut state = TERM_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let session = state.sessions.iter_mut()
        .find(|s| s.valid && s.session_id == session_id);

    let session = match session {
        Some(s) => s,
        None => return Err(0x80070057),
    };

    let user_len = username.len().min(MAX_USERNAME);
    session.username[..user_len].copy_from_slice(&username[..user_len]);

    let domain_len = domain.len().min(MAX_DOMAIN);
    session.domain[..domain_len].copy_from_slice(&domain[..domain_len]);

    session.state = SessionState::Active;
    session.logon_time = crate::rtl::time::rtl_get_system_time();

    Ok(())
}

/// Disconnect session
pub fn disconnect_session(session_id: u32) -> Result<(), u32> {
    let mut state = TERM_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Can't disconnect console
    if session_id == 0 {
        return Err(0x80070005);
    }

    let session = state.sessions.iter_mut()
        .find(|s| s.valid && s.session_id == session_id);

    let session = match session {
        Some(s) => s,
        None => return Err(0x80070057),
    };

    session.state = SessionState::Disconnected;
    session.disconnect_time = crate::rtl::time::rtl_get_system_time();

    Ok(())
}

/// Logoff session
pub fn logoff_session(session_id: u32) -> Result<(), u32> {
    let mut state = TERM_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Can't logoff console through this API
    if session_id == 0 {
        return Err(0x80070005);
    }

    let idx = state.sessions.iter().position(|s| s.valid && s.session_id == session_id);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.sessions[idx].valid = false;
    state.session_count = state.session_count.saturating_sub(1);
    ACTIVE_SESSIONS.fetch_sub(1, Ordering::SeqCst);

    // Close associated virtual channels
    let mut closed_channels = 0usize;
    for channel in state.channels.iter_mut() {
        if channel.valid && channel.session_id == session_id {
            channel.valid = false;
            closed_channels += 1;
        }
    }
    state.channel_count = state.channel_count.saturating_sub(closed_channels);

    Ok(())
}

/// Get session info
pub fn get_session_info(session_id: u32) -> Option<SessionInfo> {
    let state = TERM_STATE.lock();

    state.sessions.iter()
        .find(|s| s.valid && s.session_id == session_id)
        .cloned()
}

/// Enumerate sessions
pub fn enum_sessions() -> ([SessionInfo; MAX_SESSIONS], usize) {
    let state = TERM_STATE.lock();
    let mut result = [const { SessionInfo::empty() }; MAX_SESSIONS];
    let mut count = 0;

    for session in state.sessions.iter() {
        if session.valid && count < MAX_SESSIONS {
            result[count] = session.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Update session display settings
pub fn set_session_display(
    session_id: u32,
    h_res: u16,
    v_res: u16,
    color_depth: u16,
) -> Result<(), u32> {
    let mut state = TERM_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let session = state.sessions.iter_mut()
        .find(|s| s.valid && s.session_id == session_id);

    let session = match session {
        Some(s) => s,
        None => return Err(0x80070057),
    };

    session.h_resolution = h_res;
    session.v_resolution = v_res;
    session.color_depth = color_depth;

    Ok(())
}

/// Open virtual channel
pub fn open_virtual_channel(
    session_id: u32,
    channel_name: &[u8],
    flags: u32,
) -> Result<usize, u32> {
    let mut state = TERM_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Verify session exists
    let session_exists = state.sessions.iter()
        .any(|s| s.valid && s.session_id == session_id);

    if !session_exists {
        return Err(0x80070057);
    }

    let slot = state.channels.iter().position(|c| !c.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let channel = &mut state.channels[slot];
    let name_len = channel_name.len().min(8);
    channel.name[..name_len].copy_from_slice(&channel_name[..name_len]);
    channel.flags = flags;
    channel.session_id = session_id;
    channel.valid = true;

    state.channel_count += 1;

    Ok(slot)
}

/// Close virtual channel
pub fn close_virtual_channel(channel_idx: usize) -> Result<(), u32> {
    let mut state = TERM_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    if channel_idx >= MAX_CHANNELS || !state.channels[channel_idx].valid {
        return Err(0x80070057);
    }

    state.channels[channel_idx].valid = false;
    state.channel_count = state.channel_count.saturating_sub(1);

    Ok(())
}

/// Update session input time
pub fn update_session_activity(session_id: u32) {
    let mut state = TERM_STATE.lock();

    if let Some(session) = state.sessions.iter_mut()
        .find(|s| s.valid && s.session_id == session_id)
    {
        session.last_input_time = crate::rtl::time::rtl_get_system_time();
    }
}

/// Get configuration
pub fn get_config() -> TermConfig {
    let state = TERM_STATE.lock();
    state.config.clone()
}

/// Set configuration
pub fn set_config(config: &TermConfig) {
    let mut state = TERM_STATE.lock();
    state.config = config.clone();

    // Update listener state
    state.listening = config.allow_connections;
}

/// Set max connections
pub fn set_max_connections(max: u32) {
    let mut state = TERM_STATE.lock();
    state.config.max_connections = max;
}

/// Enable/disable connections
pub fn set_allow_connections(allow: bool) {
    let mut state = TERM_STATE.lock();
    state.config.allow_connections = allow;
    state.listening = allow;
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64) {
    (
        TOTAL_CONNECTIONS.load(Ordering::SeqCst),
        ACTIVE_SESSIONS.load(Ordering::SeqCst),
        FAILED_CONNECTIONS.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = TERM_STATE.lock();
    state.running
}

/// Get active session count
pub fn get_active_count() -> usize {
    let state = TERM_STATE.lock();
    state.sessions.iter().filter(|s| {
        s.valid && matches!(s.state, SessionState::Active | SessionState::Connected)
    }).count()
}

/// Stop the service
pub fn stop() {
    let mut state = TERM_STATE.lock();
    state.running = false;
    state.listening = false;

    // Disconnect all non-console sessions
    for session in state.sessions.iter_mut() {
        if session.valid && session.session_id != 0 {
            session.state = SessionState::Down;
        }
    }

    crate::serial_println!("[TERMSRV] Terminal Services stopped");
}
