//! Server Service (LanmanServer)
//!
//! The Server service is the SMB server component that allows the system
//! to share files, printers, named pipes, and other resources with
//! network clients using the SMB/CIFS protocol.
//!
//! # Features
//!
//! - **File Shares**: Share directories with network clients
//! - **Printer Shares**: Share printers with network clients
//! - **IPC Shares**: Support for inter-process communication
//! - **Session Management**: Track connected clients
//! - **Open Files**: Track open files on shares
//! - **Security**: ACL-based share permissions
//!
//! # APIs
//!
//! - NetShareAdd/Del/Enum: Manage shared resources
//! - NetSessionEnum/Del: Manage client sessions
//! - NetFileEnum/Close: Manage open files
//! - NetServerGetInfo/SetInfo: Server configuration
//!
//! # Administrative Shares
//!
//! - C$, D$, etc.: Administrative disk shares
//! - ADMIN$: Remote admin share (Windows directory)
//! - IPC$: Named pipe share

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum shares
const MAX_SHARES: usize = 64;

/// Maximum sessions
const MAX_SESSIONS: usize = 32;

/// Maximum open files
const MAX_OPEN_FILES: usize = 128;

/// Maximum share name length
const MAX_SHARE_NAME: usize = 64;

/// Maximum share path length
const MAX_SHARE_PATH: usize = 260;

/// Maximum share remark length
const MAX_SHARE_REMARK: usize = 128;

/// Maximum client name length
const MAX_CLIENT_NAME: usize = 64;

/// Maximum username length
const MAX_USERNAME: usize = 64;

/// Maximum file path length
const MAX_FILE_PATH: usize = 260;

/// Share types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareType {
    /// Disk share
    DiskTree = 0,
    /// Print queue
    PrintQueue = 1,
    /// Communication device
    Device = 2,
    /// Interprocess communication (IPC)
    Ipc = 3,
    /// Special/hidden share (add 0x80000000)
    Special = 0x80000000,
}

impl ShareType {
    const fn empty() -> Self {
        ShareType::DiskTree
    }
}

/// Share permissions
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharePermission {
    /// Read access
    Read = 0x0001,
    /// Write access
    Write = 0x0002,
    /// Create access
    Create = 0x0004,
    /// Execute access
    Execute = 0x0008,
    /// Delete access
    Delete = 0x0010,
    /// Change attributes
    Attrib = 0x0020,
    /// Change permissions
    Perm = 0x0040,
    /// Full control
    FullControl = 0x007F,
}

/// Share information
#[repr(C)]
#[derive(Clone)]
pub struct ShareInfo {
    /// Share name (e.g., "Public", "C$")
    pub name: [u8; MAX_SHARE_NAME],
    /// Share type
    pub share_type: ShareType,
    /// Remark/description
    pub remark: [u8; MAX_SHARE_REMARK],
    /// Local path
    pub path: [u8; MAX_SHARE_PATH],
    /// Permissions bitmask
    pub permissions: u32,
    /// Maximum connections (0 = unlimited)
    pub max_connections: u32,
    /// Current connection count
    pub current_connections: u32,
    /// Share flags
    pub flags: u32,
    /// Is hidden (ends with $)
    pub hidden: bool,
    /// Entry is valid
    pub valid: bool,
}

impl ShareInfo {
    const fn empty() -> Self {
        ShareInfo {
            name: [0; MAX_SHARE_NAME],
            share_type: ShareType::empty(),
            remark: [0; MAX_SHARE_REMARK],
            path: [0; MAX_SHARE_PATH],
            permissions: SharePermission::FullControl as u32,
            max_connections: 0,
            current_connections: 0,
            flags: 0,
            hidden: false,
            valid: false,
        }
    }
}

/// Session information
#[repr(C)]
#[derive(Clone)]
pub struct SessionInfo {
    /// Client computer name
    pub client_name: [u8; MAX_CLIENT_NAME],
    /// Username
    pub username: [u8; MAX_USERNAME],
    /// Number of open files
    pub num_opens: u32,
    /// Session time (seconds)
    pub session_time: u32,
    /// Idle time (seconds)
    pub idle_time: u32,
    /// User flags
    pub user_flags: u32,
    /// Client type name
    pub client_type: [u8; 32],
    /// Transport name
    pub transport: [u8; 64],
    /// Session start time
    pub start_time: i64,
    /// Last activity time
    pub last_activity: i64,
    /// Entry is valid
    pub valid: bool,
}

impl SessionInfo {
    const fn empty() -> Self {
        SessionInfo {
            client_name: [0; MAX_CLIENT_NAME],
            username: [0; MAX_USERNAME],
            num_opens: 0,
            session_time: 0,
            idle_time: 0,
            user_flags: 0,
            client_type: [0; 32],
            transport: [0; 64],
            start_time: 0,
            last_activity: 0,
            valid: false,
        }
    }
}

/// Open file information
#[repr(C)]
#[derive(Clone)]
pub struct FileInfo {
    /// File ID
    pub file_id: u64,
    /// File path
    pub path: [u8; MAX_FILE_PATH],
    /// Username who opened
    pub username: [u8; MAX_USERNAME],
    /// Number of locks
    pub num_locks: u32,
    /// Open permissions
    pub permissions: u32,
    /// Session index
    pub session_idx: usize,
    /// Share index
    pub share_idx: usize,
    /// Open time
    pub open_time: i64,
    /// Entry is valid
    pub valid: bool,
}

impl FileInfo {
    const fn empty() -> Self {
        FileInfo {
            file_id: 0,
            path: [0; MAX_FILE_PATH],
            username: [0; MAX_USERNAME],
            num_locks: 0,
            permissions: 0,
            session_idx: 0,
            share_idx: 0,
            open_time: 0,
            valid: false,
        }
    }
}

/// Server information (SERVER_INFO_100)
#[repr(C)]
#[derive(Clone)]
pub struct ServerInfo {
    /// Platform ID (500 = NT)
    pub platform_id: u32,
    /// Server name
    pub name: [u8; MAX_CLIENT_NAME],
    /// Major version
    pub version_major: u32,
    /// Minor version
    pub version_minor: u32,
    /// Server type flags
    pub server_type: u32,
    /// Comment/description
    pub comment: [u8; MAX_SHARE_REMARK],
    /// Users per license
    pub users_per_license: u32,
    /// Maximum users
    pub max_users: u32,
    /// Auto disconnect time (minutes)
    pub auto_disconnect: u32,
    /// Hidden server
    pub hidden: bool,
    /// Announce interval (seconds)
    pub announce: u32,
}

impl ServerInfo {
    const fn new() -> Self {
        ServerInfo {
            platform_id: 500, // NT
            name: [0; MAX_CLIENT_NAME],
            version_major: 5,
            version_minor: 2,
            server_type: 0x00009003, // SV_TYPE_WORKSTATION | SV_TYPE_SERVER | SV_TYPE_NT
            comment: [0; MAX_SHARE_REMARK],
            users_per_license: 0,
            max_users: 0,
            auto_disconnect: 15,
            hidden: false,
            announce: 720,
        }
    }
}

/// Server type flags
pub mod server_type {
    pub const WORKSTATION: u32 = 0x00000001;
    pub const SERVER: u32 = 0x00000002;
    pub const SQLSERVER: u32 = 0x00000004;
    pub const DOMAIN_CTRL: u32 = 0x00000008;
    pub const DOMAIN_BAKCTRL: u32 = 0x00000010;
    pub const TIME_SOURCE: u32 = 0x00000020;
    pub const AFP: u32 = 0x00000040;
    pub const NOVELL: u32 = 0x00000080;
    pub const DOMAIN_MEMBER: u32 = 0x00000100;
    pub const PRINTQ_SERVER: u32 = 0x00000200;
    pub const DIALIN_SERVER: u32 = 0x00000400;
    pub const NT: u32 = 0x00001000;
    pub const WFW: u32 = 0x00002000;
    pub const POTENTIAL_BROWSER: u32 = 0x00010000;
    pub const BACKUP_BROWSER: u32 = 0x00020000;
    pub const MASTER_BROWSER: u32 = 0x00040000;
    pub const DOMAIN_MASTER: u32 = 0x00080000;
    pub const LOCAL_LIST_ONLY: u32 = 0x40000000;
    pub const DOMAIN_ENUM: u32 = 0x80000000;
}

/// Server service state
pub struct ServerState {
    /// Service is running
    pub running: bool,
    /// Server info
    pub info: ServerInfo,
    /// Shares
    pub shares: [ShareInfo; MAX_SHARES],
    /// Share count
    pub share_count: usize,
    /// Sessions
    pub sessions: [SessionInfo; MAX_SESSIONS],
    /// Session count
    pub session_count: usize,
    /// Open files
    pub open_files: [FileInfo; MAX_OPEN_FILES],
    /// Open file count
    pub file_count: usize,
    /// Service start time
    pub start_time: i64,
    /// Next file ID
    pub next_file_id: u64,
}

impl ServerState {
    const fn new() -> Self {
        ServerState {
            running: false,
            info: ServerInfo::new(),
            shares: [const { ShareInfo::empty() }; MAX_SHARES],
            share_count: 0,
            sessions: [const { SessionInfo::empty() }; MAX_SESSIONS],
            session_count: 0,
            open_files: [const { FileInfo::empty() }; MAX_OPEN_FILES],
            file_count: 0,
            start_time: 0,
            next_file_id: 1,
        }
    }
}

/// Global server state
static SERVER_STATE: Mutex<ServerState> = Mutex::new(ServerState::new());

/// Statistics
static TOTAL_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static BYTES_RECEIVED: AtomicU64 = AtomicU64::new(0);
static BYTES_SENT: AtomicU64 = AtomicU64::new(0);
static FILES_OPENED: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize Server service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = SERVER_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    // Set default server name
    let default_name = b"NOSTALGIAOS";
    let name_len = default_name.len().min(MAX_CLIENT_NAME);
    state.info.name[..name_len].copy_from_slice(&default_name[..name_len]);

    // Create administrative shares
    create_admin_shares(&mut state);

    crate::serial_println!("[LANMANSRV] Server service initialized");
}

/// Create default administrative shares
fn create_admin_shares(state: &mut ServerState) {
    // IPC$ share
    let ipc_slot = 0;
    state.shares[ipc_slot].name[..4].copy_from_slice(b"IPC$");
    state.shares[ipc_slot].share_type = ShareType::Ipc;
    let ipc_remark = b"Remote IPC";
    state.shares[ipc_slot].remark[..ipc_remark.len()].copy_from_slice(ipc_remark);
    state.shares[ipc_slot].hidden = true;
    state.shares[ipc_slot].valid = true;
    state.share_count = 1;

    // ADMIN$ share
    let admin_slot = 1;
    state.shares[admin_slot].name[..6].copy_from_slice(b"ADMIN$");
    state.shares[admin_slot].share_type = ShareType::DiskTree;
    let admin_remark = b"Remote Admin";
    state.shares[admin_slot].remark[..admin_remark.len()].copy_from_slice(admin_remark);
    let admin_path = b"C:\\Windows";
    state.shares[admin_slot].path[..admin_path.len()].copy_from_slice(admin_path);
    state.shares[admin_slot].hidden = true;
    state.shares[admin_slot].valid = true;
    state.share_count = 2;

    // C$ share
    let c_slot = 2;
    state.shares[c_slot].name[..2].copy_from_slice(b"C$");
    state.shares[c_slot].share_type = ShareType::DiskTree;
    let c_remark = b"Default share";
    state.shares[c_slot].remark[..c_remark.len()].copy_from_slice(c_remark);
    let c_path = b"C:\\";
    state.shares[c_slot].path[..c_path.len()].copy_from_slice(c_path);
    state.shares[c_slot].hidden = true;
    state.shares[c_slot].valid = true;
    state.share_count = 3;
}

/// Get server information
pub fn get_info(level: u32) -> Option<ServerInfo> {
    let state = SERVER_STATE.lock();

    if !state.running {
        return None;
    }

    match level {
        100 | 101 | 102 => Some(state.info.clone()),
        _ => None,
    }
}

/// Set server information
pub fn set_info(info: &ServerInfo) -> Result<(), u32> {
    let mut state = SERVER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    state.info = info.clone();
    Ok(())
}

/// Add a share (NetShareAdd)
pub fn add_share(
    name: &[u8],
    share_type: ShareType,
    remark: &[u8],
    path: &[u8],
    permissions: u32,
    max_connections: u32,
) -> Result<usize, u32> {
    let mut state = SERVER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let name_len = name.len().min(MAX_SHARE_NAME);

    // Check for duplicate
    for share in state.shares.iter() {
        if share.valid && share.name[..name_len] == name[..name_len] {
            return Err(0x80070924); // NERR_DuplicateShare
        }
    }

    // Find free slot
    let slot = state.shares.iter().position(|s| !s.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let share = &mut state.shares[slot];
    share.name[..name_len].copy_from_slice(&name[..name_len]);
    share.share_type = share_type;

    let remark_len = remark.len().min(MAX_SHARE_REMARK);
    share.remark[..remark_len].copy_from_slice(&remark[..remark_len]);

    let path_len = path.len().min(MAX_SHARE_PATH);
    share.path[..path_len].copy_from_slice(&path[..path_len]);

    share.permissions = permissions;
    share.max_connections = max_connections;
    share.current_connections = 0;
    share.hidden = name.last() == Some(&b'$');
    share.valid = true;

    state.share_count += 1;

    Ok(slot)
}

/// Delete a share (NetShareDel)
pub fn delete_share(name: &[u8]) -> Result<(), u32> {
    let mut state = SERVER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let name_len = name.len().min(MAX_SHARE_NAME);

    let idx = state.shares.iter().position(|s| {
        s.valid && s.name[..name_len] == name[..name_len]
    });

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070906), // NERR_NetNameNotFound
    };

    // Check if share has active connections
    if state.shares[idx].current_connections > 0 {
        return Err(0x80070907); // NERR_UseNotFound (share in use)
    }

    state.shares[idx].valid = false;
    state.share_count = state.share_count.saturating_sub(1);

    Ok(())
}

/// Enumerate shares
pub fn enum_shares(include_hidden: bool) -> ([ShareInfo; MAX_SHARES], usize) {
    let state = SERVER_STATE.lock();
    let mut result = [const { ShareInfo::empty() }; MAX_SHARES];
    let mut count = 0;

    for share in state.shares.iter() {
        if share.valid && count < MAX_SHARES {
            if include_hidden || !share.hidden {
                result[count] = share.clone();
                count += 1;
            }
        }
    }

    (result, count)
}

/// Get share by name
pub fn get_share(name: &[u8]) -> Option<ShareInfo> {
    let state = SERVER_STATE.lock();
    let name_len = name.len().min(MAX_SHARE_NAME);

    state.shares.iter()
        .find(|s| s.valid && s.name[..name_len] == name[..name_len])
        .cloned()
}

/// Add a session
pub fn add_session(
    client_name: &[u8],
    username: &[u8],
    client_type: &[u8],
    transport: &[u8],
) -> Result<usize, u32> {
    let mut state = SERVER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.sessions.iter().position(|s| !s.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let now = crate::rtl::time::rtl_get_system_time();

    let session = &mut state.sessions[slot];

    let client_len = client_name.len().min(MAX_CLIENT_NAME);
    session.client_name[..client_len].copy_from_slice(&client_name[..client_len]);

    let user_len = username.len().min(MAX_USERNAME);
    session.username[..user_len].copy_from_slice(&username[..user_len]);

    let type_len = client_type.len().min(32);
    session.client_type[..type_len].copy_from_slice(&client_type[..type_len]);

    let transport_len = transport.len().min(64);
    session.transport[..transport_len].copy_from_slice(&transport[..transport_len]);

    session.num_opens = 0;
    session.session_time = 0;
    session.idle_time = 0;
    session.start_time = now;
    session.last_activity = now;
    session.valid = true;

    state.session_count += 1;
    TOTAL_CONNECTIONS.fetch_add(1, Ordering::SeqCst);

    Ok(slot)
}

/// Delete a session
pub fn delete_session(client_name: &[u8], username: &[u8]) -> Result<(), u32> {
    let mut state = SERVER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let client_len = client_name.len().min(MAX_CLIENT_NAME);
    let user_len = username.len().min(MAX_USERNAME);

    let idx = state.sessions.iter().position(|s| {
        s.valid
            && s.client_name[..client_len] == client_name[..client_len]
            && s.username[..user_len] == username[..user_len]
    });

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070908), // NERR_ClientNameNotFound
    };

    // Close all files for this session
    let session_idx = idx;
    let mut files_closed = 0usize;
    for file in state.open_files.iter_mut() {
        if file.valid && file.session_idx == session_idx {
            file.valid = false;
            files_closed += 1;
        }
    }
    state.file_count = state.file_count.saturating_sub(files_closed);

    state.sessions[idx].valid = false;
    state.session_count = state.session_count.saturating_sub(1);

    Ok(())
}

/// Enumerate sessions
pub fn enum_sessions() -> ([SessionInfo; MAX_SESSIONS], usize) {
    let state = SERVER_STATE.lock();
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

/// Open a file on a share
pub fn open_file(
    session_idx: usize,
    share_idx: usize,
    path: &[u8],
    permissions: u32,
) -> Result<u64, u32> {
    let mut state = SERVER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Validate session and share
    if session_idx >= MAX_SESSIONS || !state.sessions[session_idx].valid {
        return Err(0x80070057);
    }
    if share_idx >= MAX_SHARES || !state.shares[share_idx].valid {
        return Err(0x80070057);
    }

    let slot = state.open_files.iter().position(|f| !f.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let file_id = state.next_file_id;
    state.next_file_id += 1;

    let now = crate::rtl::time::rtl_get_system_time();

    // Copy username from session
    let username = state.sessions[session_idx].username;

    let file = &mut state.open_files[slot];
    file.file_id = file_id;

    let path_len = path.len().min(MAX_FILE_PATH);
    file.path[..path_len].copy_from_slice(&path[..path_len]);

    file.username = username;
    file.permissions = permissions;
    file.session_idx = session_idx;
    file.share_idx = share_idx;
    file.num_locks = 0;
    file.open_time = now;
    file.valid = true;

    state.file_count += 1;
    state.sessions[session_idx].num_opens += 1;

    FILES_OPENED.fetch_add(1, Ordering::SeqCst);

    Ok(file_id)
}

/// Close a file
pub fn close_file(file_id: u64) -> Result<(), u32> {
    let mut state = SERVER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.open_files.iter().position(|f| f.valid && f.file_id == file_id);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070006), // ERROR_INVALID_HANDLE
    };

    let session_idx = state.open_files[idx].session_idx;

    state.open_files[idx].valid = false;
    state.file_count = state.file_count.saturating_sub(1);

    if session_idx < MAX_SESSIONS && state.sessions[session_idx].valid {
        state.sessions[session_idx].num_opens =
            state.sessions[session_idx].num_opens.saturating_sub(1);
    }

    Ok(())
}

/// Enumerate open files
pub fn enum_files() -> ([FileInfo; MAX_OPEN_FILES], usize) {
    let state = SERVER_STATE.lock();
    let mut result = [const { FileInfo::empty() }; MAX_OPEN_FILES];
    let mut count = 0;

    for file in state.open_files.iter() {
        if file.valid && count < MAX_OPEN_FILES {
            result[count] = file.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Update session activity
pub fn update_session_activity(session_idx: usize) {
    let mut state = SERVER_STATE.lock();

    if session_idx < MAX_SESSIONS && state.sessions[session_idx].valid {
        let now = crate::rtl::time::rtl_get_system_time();
        state.sessions[session_idx].last_activity = now;
        state.sessions[session_idx].idle_time = 0;
    }
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64, u64) {
    (
        TOTAL_CONNECTIONS.load(Ordering::SeqCst),
        BYTES_RECEIVED.load(Ordering::SeqCst),
        BYTES_SENT.load(Ordering::SeqCst),
        FILES_OPENED.load(Ordering::SeqCst),
    )
}

/// Record bytes transferred
pub fn record_transfer(received: u64, sent: u64) {
    BYTES_RECEIVED.fetch_add(received, Ordering::SeqCst);
    BYTES_SENT.fetch_add(sent, Ordering::SeqCst);
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = SERVER_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = SERVER_STATE.lock();
    state.running = false;

    // Close all files
    for file in state.open_files.iter_mut() {
        file.valid = false;
    }
    state.file_count = 0;

    // Terminate all sessions
    for session in state.sessions.iter_mut() {
        session.valid = false;
    }
    state.session_count = 0;

    crate::serial_println!("[LANMANSRV] Server service stopped");
}

/// Get share count
pub fn get_share_count() -> usize {
    let state = SERVER_STATE.lock();
    state.share_count
}

/// Get session count
pub fn get_session_count() -> usize {
    let state = SERVER_STATE.lock();
    state.session_count
}

/// Get open file count
pub fn get_file_count() -> usize {
    let state = SERVER_STATE.lock();
    state.file_count
}

/// Set auto disconnect time
pub fn set_auto_disconnect(minutes: u32) {
    let mut state = SERVER_STATE.lock();
    state.info.auto_disconnect = minutes;
}

/// Get server name
pub fn get_server_name() -> [u8; MAX_CLIENT_NAME] {
    let state = SERVER_STATE.lock();
    state.info.name
}

/// Set server comment
pub fn set_comment(comment: &[u8]) {
    let mut state = SERVER_STATE.lock();
    let len = comment.len().min(MAX_SHARE_REMARK);
    state.info.comment = [0; MAX_SHARE_REMARK];
    state.info.comment[..len].copy_from_slice(&comment[..len]);
}
