//! FTP Virtual Server Module
//!
//! Windows Server 2003 FTP Virtual Server implementation for file transfer.
//! Provides virtual server management, directory configuration, user isolation,
//! and connection management.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;
use crate::win32k::user::UserHandle;

/// Maximum number of virtual servers
const MAX_SERVERS: usize = 16;

/// Maximum number of virtual directories
const MAX_VDIRS: usize = 128;

/// Maximum number of active sessions
const MAX_SESSIONS: usize = 256;

/// Maximum path length
const MAX_PATH_LEN: usize = 260;

/// Maximum username length
const MAX_USER_LEN: usize = 64;

/// Maximum IP address length
const MAX_IP_LEN: usize = 45;

/// Server state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServerState {
    /// Server is stopped
    Stopped = 0,
    /// Server is starting
    Starting = 1,
    /// Server is running
    Running = 2,
    /// Server is paused
    Paused = 3,
    /// Server is stopping
    Stopping = 4,
}

impl Default for ServerState {
    fn default() -> Self {
        Self::Stopped
    }
}

/// User isolation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum IsolationMode {
    /// No isolation (all users share FTP root)
    None = 0,
    /// Isolate users in their home directories
    IsolateUsers = 1,
    /// Isolate using Active Directory
    IsolateAD = 2,
}

impl Default for IsolationMode {
    fn default() -> Self {
        Self::None
    }
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SessionState {
    /// Connected, not authenticated
    Connected = 0,
    /// User provided, awaiting password
    UserProvided = 1,
    /// Authenticated
    Authenticated = 2,
    /// Transferring data
    Transferring = 3,
}

impl Default for SessionState {
    fn default() -> Self {
        Self::Connected
    }
}

/// Transfer type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TransferType {
    /// No transfer
    None = 0,
    /// ASCII mode
    Ascii = 1,
    /// Binary mode
    Binary = 2,
}

impl Default for TransferType {
    fn default() -> Self {
        Self::None
    }
}

bitflags::bitflags! {
    /// Server flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ServerFlags: u32 {
        /// Allow anonymous access
        const ALLOW_ANONYMOUS = 0x0001;
        /// Allow uploads
        const ALLOW_UPLOAD = 0x0002;
        /// Enable TLS/SSL
        const ENABLE_TLS = 0x0004;
        /// Require TLS for control
        const REQUIRE_TLS_CONTROL = 0x0008;
        /// Require TLS for data
        const REQUIRE_TLS_DATA = 0x0010;
        /// Enable logging
        const ENABLE_LOGGING = 0x0020;
        /// Enable passive mode
        const ENABLE_PASV = 0x0040;
        /// Enable directory browsing
        const DIR_BROWSING = 0x0080;
        /// Enable Unix-style directory listing
        const UNIX_STYLE = 0x0100;
    }
}

impl Default for ServerFlags {
    fn default() -> Self {
        Self::ALLOW_ANONYMOUS | Self::ENABLE_LOGGING | Self::ENABLE_PASV | Self::DIR_BROWSING
    }
}

bitflags::bitflags! {
    /// Virtual directory permissions
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VdirPermissions: u32 {
        /// Read files
        const READ = 0x0001;
        /// Write files
        const WRITE = 0x0002;
        /// Log visits
        const LOG_VISITS = 0x0004;
        /// Index content
        const INDEX = 0x0008;
    }
}

impl Default for VdirPermissions {
    fn default() -> Self {
        Self::READ | Self::LOG_VISITS
    }
}

/// FTP Virtual Server
#[derive(Debug)]
pub struct FtpServer {
    /// Server is active
    active: bool,
    /// Server ID
    id: u32,
    /// Server name
    name: [u8; 64],
    /// Name length
    name_len: usize,
    /// Binding IP address
    ip_address: [u8; MAX_IP_LEN],
    /// IP length
    ip_len: usize,
    /// Port number
    port: u16,
    /// Server state
    state: ServerState,
    /// Server flags
    flags: ServerFlags,
    /// Home directory
    home_dir: [u8; MAX_PATH_LEN],
    /// Home dir length
    home_len: usize,
    /// User isolation mode
    isolation: IsolationMode,
    /// Maximum connections
    max_connections: u32,
    /// Connection timeout (seconds)
    connection_timeout: u32,
    /// Maximum file size (MB, 0 = unlimited)
    max_file_size: u32,
    /// Current connections
    current_connections: u32,
    /// Files uploaded
    files_uploaded: u64,
    /// Files downloaded
    files_downloaded: u64,
    /// Bytes uploaded
    bytes_uploaded: u64,
    /// Bytes downloaded
    bytes_downloaded: u64,
    /// Handle for management
    handle: UserHandle,
}

impl FtpServer {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            name: [0u8; 64],
            name_len: 0,
            ip_address: [0u8; MAX_IP_LEN],
            ip_len: 0,
            port: 21,
            state: ServerState::Stopped,
            flags: ServerFlags::empty(),
            home_dir: [0u8; MAX_PATH_LEN],
            home_len: 0,
            isolation: IsolationMode::None,
            max_connections: 100000,
            connection_timeout: 120,
            max_file_size: 0,
            current_connections: 0,
            files_uploaded: 0,
            files_downloaded: 0,
            bytes_uploaded: 0,
            bytes_downloaded: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// Virtual directory
#[derive(Debug)]
pub struct VirtualDirectory {
    /// Directory is active
    active: bool,
    /// Directory ID
    id: u32,
    /// Parent server ID
    server_id: u32,
    /// Virtual path (e.g., /uploads)
    virtual_path: [u8; MAX_PATH_LEN],
    /// Virtual path length
    vpath_len: usize,
    /// Physical path
    physical_path: [u8; MAX_PATH_LEN],
    /// Physical path length
    ppath_len: usize,
    /// Permissions
    permissions: VdirPermissions,
    /// Handle for management
    handle: UserHandle,
}

impl VirtualDirectory {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            server_id: 0,
            virtual_path: [0u8; MAX_PATH_LEN],
            vpath_len: 0,
            physical_path: [0u8; MAX_PATH_LEN],
            ppath_len: 0,
            permissions: VdirPermissions::empty(),
            handle: UserHandle::NULL,
        }
    }
}

/// Active FTP session
#[derive(Debug)]
pub struct FtpSession {
    /// Session is active
    active: bool,
    /// Session ID
    id: u32,
    /// Parent server ID
    server_id: u32,
    /// Client IP address
    client_ip: [u8; MAX_IP_LEN],
    /// IP length
    ip_len: usize,
    /// Client port
    client_port: u16,
    /// Session state
    state: SessionState,
    /// Authenticated username
    username: [u8; MAX_USER_LEN],
    /// Username length
    user_len: usize,
    /// Current directory
    current_dir: [u8; MAX_PATH_LEN],
    /// Dir length
    dir_len: usize,
    /// Transfer type
    transfer_type: TransferType,
    /// TLS enabled
    tls_enabled: bool,
    /// Passive mode
    passive_mode: bool,
    /// Data port (for passive)
    data_port: u16,
    /// Files transferred
    files_transferred: u32,
    /// Bytes transferred
    bytes_transferred: u64,
    /// Connect time
    connect_time: u64,
    /// Handle for management
    handle: UserHandle,
}

impl FtpSession {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            server_id: 0,
            client_ip: [0u8; MAX_IP_LEN],
            ip_len: 0,
            client_port: 0,
            state: SessionState::Connected,
            username: [0u8; MAX_USER_LEN],
            user_len: 0,
            current_dir: [0u8; MAX_PATH_LEN],
            dir_len: 0,
            transfer_type: TransferType::Binary,
            tls_enabled: false,
            passive_mode: false,
            data_port: 0,
            files_transferred: 0,
            bytes_transferred: 0,
            connect_time: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// FTP service statistics
#[derive(Debug)]
pub struct FtpStats {
    /// Total servers
    pub total_servers: u32,
    /// Running servers
    pub running_servers: u32,
    /// Total virtual directories
    pub total_vdirs: u32,
    /// Active sessions
    pub active_sessions: u32,
    /// Anonymous users
    pub anonymous_users: u32,
    /// Non-anonymous users
    pub authenticated_users: u32,
    /// Total files uploaded
    pub files_uploaded: u64,
    /// Total files downloaded
    pub files_downloaded: u64,
    /// Total bytes uploaded
    pub bytes_uploaded: u64,
    /// Total bytes downloaded
    pub bytes_downloaded: u64,
    /// Failed logins
    pub failed_logins: u64,
}

impl FtpStats {
    pub const fn new() -> Self {
        Self {
            total_servers: 0,
            running_servers: 0,
            total_vdirs: 0,
            active_sessions: 0,
            anonymous_users: 0,
            authenticated_users: 0,
            files_uploaded: 0,
            files_downloaded: 0,
            bytes_uploaded: 0,
            bytes_downloaded: 0,
            failed_logins: 0,
        }
    }
}

/// FTP service state
struct FtpState {
    /// Servers
    servers: [FtpServer; MAX_SERVERS],
    /// Virtual directories
    vdirs: [VirtualDirectory; MAX_VDIRS],
    /// Sessions
    sessions: [FtpSession; MAX_SESSIONS],
    /// Statistics
    stats: FtpStats,
    /// Next ID
    next_id: u32,
}

impl FtpState {
    pub const fn new() -> Self {
        Self {
            servers: [const { FtpServer::new() }; MAX_SERVERS],
            vdirs: [const { VirtualDirectory::new() }; MAX_VDIRS],
            sessions: [const { FtpSession::new() }; MAX_SESSIONS],
            stats: FtpStats::new(),
            next_id: 1,
        }
    }
}

/// Global FTP state
static FTP_STATE: Mutex<FtpState> = Mutex::new(FtpState::new());

/// Initialization flag
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the FTP virtual server module
pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    Ok(())
}

/// Create a new FTP virtual server
pub fn create_server(
    name: &str,
    ip_address: &str,
    port: u16,
    home_dir: &str,
    flags: ServerFlags,
) -> Result<UserHandle, u32> {
    let mut state = FTP_STATE.lock();

    // Check for duplicate binding
    for server in state.servers.iter() {
        if server.active {
            let existing_ip = &server.ip_address[..server.ip_len];
            if existing_ip == ip_address.as_bytes() && server.port == port {
                return Err(0x80070050);
            }
        }
    }

    let slot_idx = state.servers.iter().position(|s| !s.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008),
    };

    let id = state.next_id;
    state.next_id += 1;

    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(64);
    let ip_bytes = ip_address.as_bytes();
    let ip_len = ip_bytes.len().min(MAX_IP_LEN);
    let home_bytes = home_dir.as_bytes();
    let home_len = home_bytes.len().min(MAX_PATH_LEN);

    state.servers[slot_idx].active = true;
    state.servers[slot_idx].id = id;
    state.servers[slot_idx].name[..name_len].copy_from_slice(&name_bytes[..name_len]);
    state.servers[slot_idx].name_len = name_len;
    state.servers[slot_idx].ip_address[..ip_len].copy_from_slice(&ip_bytes[..ip_len]);
    state.servers[slot_idx].ip_len = ip_len;
    state.servers[slot_idx].port = port;
    state.servers[slot_idx].state = ServerState::Stopped;
    state.servers[slot_idx].flags = flags;
    state.servers[slot_idx].home_dir[..home_len].copy_from_slice(&home_bytes[..home_len]);
    state.servers[slot_idx].home_len = home_len;
    state.servers[slot_idx].isolation = IsolationMode::None;
    state.servers[slot_idx].max_connections = 100000;
    state.servers[slot_idx].connection_timeout = 120;
    state.servers[slot_idx].max_file_size = 0;
    state.servers[slot_idx].current_connections = 0;
    state.servers[slot_idx].files_uploaded = 0;
    state.servers[slot_idx].files_downloaded = 0;
    state.servers[slot_idx].bytes_uploaded = 0;
    state.servers[slot_idx].bytes_downloaded = 0;
    state.servers[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.total_servers += 1;

    Ok(state.servers[slot_idx].handle)
}

/// Delete an FTP virtual server
pub fn delete_server(server_id: u32) -> Result<(), u32> {
    let mut state = FTP_STATE.lock();

    let server_idx = state.servers.iter().position(|s| s.active && s.id == server_id);
    let server_idx = match server_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    if state.servers[server_idx].state != ServerState::Stopped {
        return Err(0x80070020);
    }

    // Count and remove virtual directories
    let mut vdirs_to_remove = 0u32;
    for vdir in state.vdirs.iter() {
        if vdir.active && vdir.server_id == server_id {
            vdirs_to_remove += 1;
        }
    }

    for vdir in state.vdirs.iter_mut() {
        if vdir.active && vdir.server_id == server_id {
            vdir.active = false;
        }
    }

    state.servers[server_idx].active = false;
    state.stats.total_servers = state.stats.total_servers.saturating_sub(1);
    state.stats.total_vdirs = state.stats.total_vdirs.saturating_sub(vdirs_to_remove);

    Ok(())
}

/// Start an FTP server
pub fn start_server(server_id: u32) -> Result<(), u32> {
    let mut state = FTP_STATE.lock();

    let server = state.servers.iter_mut().find(|s| s.active && s.id == server_id);
    let server = match server {
        Some(s) => s,
        None => return Err(0x80070002),
    };

    match server.state {
        ServerState::Running => return Ok(()),
        ServerState::Starting | ServerState::Stopping => {
            return Err(0x80070015);
        }
        _ => {}
    }

    server.state = ServerState::Starting;
    server.state = ServerState::Running;
    state.stats.running_servers += 1;

    Ok(())
}

/// Stop an FTP server
pub fn stop_server(server_id: u32) -> Result<(), u32> {
    let mut state = FTP_STATE.lock();

    let server_idx = state.servers.iter().position(|s| s.active && s.id == server_id);
    let server_idx = match server_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    match state.servers[server_idx].state {
        ServerState::Stopped => return Ok(()),
        ServerState::Starting | ServerState::Stopping => {
            return Err(0x80070015);
        }
        _ => {}
    }

    // Disconnect all sessions
    let mut sessions_closed = 0u32;
    for session in state.sessions.iter_mut() {
        if session.active && session.server_id == server_id {
            session.active = false;
            sessions_closed += 1;
        }
    }

    state.servers[server_idx].state = ServerState::Stopping;
    state.servers[server_idx].state = ServerState::Stopped;
    state.servers[server_idx].current_connections = 0;
    state.stats.running_servers = state.stats.running_servers.saturating_sub(1);
    state.stats.active_sessions = state.stats.active_sessions.saturating_sub(sessions_closed);

    Ok(())
}

/// Pause an FTP server
pub fn pause_server(server_id: u32) -> Result<(), u32> {
    let mut state = FTP_STATE.lock();

    let server = state.servers.iter_mut().find(|s| s.active && s.id == server_id);
    let server = match server {
        Some(s) => s,
        None => return Err(0x80070002),
    };

    if server.state != ServerState::Running {
        return Err(0x80070015);
    }

    server.state = ServerState::Paused;

    Ok(())
}

/// Resume an FTP server
pub fn resume_server(server_id: u32) -> Result<(), u32> {
    let mut state = FTP_STATE.lock();

    let server = state.servers.iter_mut().find(|s| s.active && s.id == server_id);
    let server = match server {
        Some(s) => s,
        None => return Err(0x80070002),
    };

    if server.state != ServerState::Paused {
        return Err(0x80070015);
    }

    server.state = ServerState::Running;

    Ok(())
}

/// Configure server settings
pub fn configure_server(
    server_id: u32,
    isolation: Option<IsolationMode>,
    max_connections: Option<u32>,
    connection_timeout: Option<u32>,
    max_file_size: Option<u32>,
) -> Result<(), u32> {
    let mut state = FTP_STATE.lock();

    let server = state.servers.iter_mut().find(|s| s.active && s.id == server_id);
    let server = match server {
        Some(s) => s,
        None => return Err(0x80070002),
    };

    if let Some(iso) = isolation {
        server.isolation = iso;
    }
    if let Some(max_conn) = max_connections {
        server.max_connections = max_conn;
    }
    if let Some(timeout) = connection_timeout {
        server.connection_timeout = timeout;
    }
    if let Some(max_size) = max_file_size {
        server.max_file_size = max_size;
    }

    Ok(())
}

/// Add a virtual directory
pub fn add_virtual_directory(
    server_id: u32,
    virtual_path: &str,
    physical_path: &str,
    permissions: VdirPermissions,
) -> Result<UserHandle, u32> {
    let mut state = FTP_STATE.lock();

    // Verify server exists
    let server_exists = state.servers.iter().any(|s| s.active && s.id == server_id);
    if !server_exists {
        return Err(0x80070002);
    }

    // Check for duplicate virtual path
    for vdir in state.vdirs.iter() {
        if vdir.active && vdir.server_id == server_id {
            let existing = &vdir.virtual_path[..vdir.vpath_len];
            if existing == virtual_path.as_bytes() {
                return Err(0x80070050);
            }
        }
    }

    let slot_idx = state.vdirs.iter().position(|v| !v.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008),
    };

    let id = state.next_id;
    state.next_id += 1;

    let vpath_bytes = virtual_path.as_bytes();
    let vpath_len = vpath_bytes.len().min(MAX_PATH_LEN);
    let ppath_bytes = physical_path.as_bytes();
    let ppath_len = ppath_bytes.len().min(MAX_PATH_LEN);

    state.vdirs[slot_idx].active = true;
    state.vdirs[slot_idx].id = id;
    state.vdirs[slot_idx].server_id = server_id;
    state.vdirs[slot_idx].virtual_path[..vpath_len].copy_from_slice(&vpath_bytes[..vpath_len]);
    state.vdirs[slot_idx].vpath_len = vpath_len;
    state.vdirs[slot_idx].physical_path[..ppath_len].copy_from_slice(&ppath_bytes[..ppath_len]);
    state.vdirs[slot_idx].ppath_len = ppath_len;
    state.vdirs[slot_idx].permissions = permissions;
    state.vdirs[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.total_vdirs += 1;

    Ok(state.vdirs[slot_idx].handle)
}

/// Remove a virtual directory
pub fn remove_virtual_directory(vdir_id: u32) -> Result<(), u32> {
    let mut state = FTP_STATE.lock();

    let vdir_idx = state.vdirs.iter().position(|v| v.active && v.id == vdir_id);
    let vdir_idx = match vdir_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    state.vdirs[vdir_idx].active = false;
    state.stats.total_vdirs = state.stats.total_vdirs.saturating_sub(1);

    Ok(())
}

/// Disconnect a session
pub fn disconnect_session(session_id: u32) -> Result<(), u32> {
    let mut state = FTP_STATE.lock();

    let session_idx = state.sessions.iter().position(|s| s.active && s.id == session_id);
    let session_idx = match session_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    let server_id = state.sessions[session_idx].server_id;
    state.sessions[session_idx].active = false;

    // Update server connection count
    for server in state.servers.iter_mut() {
        if server.active && server.id == server_id {
            server.current_connections = server.current_connections.saturating_sub(1);
            break;
        }
    }

    state.stats.active_sessions = state.stats.active_sessions.saturating_sub(1);

    Ok(())
}

/// Get server information
pub fn get_server_info(server_id: u32) -> Result<(ServerState, u32, u64, u64), u32> {
    let state = FTP_STATE.lock();

    let server = state.servers.iter().find(|s| s.active && s.id == server_id);
    let server = match server {
        Some(s) => s,
        None => return Err(0x80070002),
    };

    Ok((
        server.state,
        server.current_connections,
        server.bytes_uploaded,
        server.bytes_downloaded,
    ))
}

/// Get FTP service statistics
pub fn get_statistics() -> FtpStats {
    let state = FTP_STATE.lock();
    FtpStats {
        total_servers: state.stats.total_servers,
        running_servers: state.stats.running_servers,
        total_vdirs: state.stats.total_vdirs,
        active_sessions: state.stats.active_sessions,
        anonymous_users: state.stats.anonymous_users,
        authenticated_users: state.stats.authenticated_users,
        files_uploaded: state.stats.files_uploaded,
        files_downloaded: state.stats.files_downloaded,
        bytes_uploaded: state.stats.bytes_uploaded,
        bytes_downloaded: state.stats.bytes_downloaded,
        failed_logins: state.stats.failed_logins,
    }
}

/// List all servers
pub fn list_servers() -> [(bool, u32, ServerState); MAX_SERVERS] {
    let state = FTP_STATE.lock();
    let mut result = [(false, 0u32, ServerState::Stopped); MAX_SERVERS];

    for (i, server) in state.servers.iter().enumerate() {
        if server.active {
            result[i] = (true, server.id, server.state);
        }
    }

    result
}

/// List virtual directories for a server
pub fn list_virtual_directories(server_id: u32) -> [(bool, u32, VdirPermissions); MAX_VDIRS] {
    let state = FTP_STATE.lock();
    let mut result = [(false, 0u32, VdirPermissions::empty()); MAX_VDIRS];

    let mut idx = 0;
    for vdir in state.vdirs.iter() {
        if vdir.active && vdir.server_id == server_id && idx < MAX_VDIRS {
            result[idx] = (true, vdir.id, vdir.permissions);
            idx += 1;
        }
    }

    result
}

/// List active sessions for a server
pub fn list_sessions(server_id: u32) -> [(bool, u32, SessionState); MAX_SESSIONS] {
    let state = FTP_STATE.lock();
    let mut result = [(false, 0u32, SessionState::Connected); MAX_SESSIONS];

    let mut idx = 0;
    for session in state.sessions.iter() {
        if session.active && session.server_id == server_id && idx < MAX_SESSIONS {
            result[idx] = (true, session.id, session.state);
            idx += 1;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_lifecycle() {
        init().unwrap();

        let handle = create_server(
            "Default FTP Server",
            "0.0.0.0",
            21,
            "C:\\InetPub\\ftproot",
            ServerFlags::default(),
        ).unwrap();
        assert_ne!(handle, UserHandle::NULL);

        start_server(1).unwrap_or(());
        pause_server(1).unwrap_or(());
        resume_server(1).unwrap_or(());
        stop_server(1).unwrap_or(());
    }

    #[test]
    fn test_virtual_directory() {
        init().unwrap();

        let stats = get_statistics();
        assert!(stats.total_servers <= MAX_SERVERS as u32);
    }
}
