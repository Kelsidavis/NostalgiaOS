//! Workstation Service (LanmanWorkstation)
//!
//! The Workstation service is the SMB client component that enables
//! the system to connect to remote file shares, printers, and other
//! network resources using the SMB/CIFS protocol.
//!
//! # Features
//!
//! - **Network Connections**: Manage connections to network shares
//! - **Drive Mappings**: Map network shares to drive letters
//! - **UNC Path Support**: Access files via \\server\share paths
//! - **Credential Management**: Cache network credentials
//! - **Session Management**: Maintain SMB sessions with servers
//!
//! # APIs
//!
//! - NetWkstaGetInfo: Get workstation configuration
//! - NetWkstaSetInfo: Set workstation configuration
//! - NetWkstaTransportEnum: Enumerate network transports
//! - NetUseAdd/Del/Enum: Manage network connections
//!
//! # Dependencies
//!
//! - MRxSmb (SMB Mini-Redirector)
//! - NetBIOS / NetBT
//! - TCP/IP network stack

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum network connections
const MAX_CONNECTIONS: usize = 64;

/// Maximum server name length
const MAX_SERVER_NAME: usize = 64;

/// Maximum share name length
const MAX_SHARE_NAME: usize = 64;

/// Maximum username length
const MAX_USERNAME: usize = 64;

/// Maximum domain length
const MAX_DOMAIN: usize = 64;

/// Maximum local device name
const MAX_LOCAL_NAME: usize = 8;

/// Maximum transports
const MAX_TRANSPORTS: usize = 8;

/// Maximum workstation users
const MAX_WKS_USERS: usize = 16;

/// Connection type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// Disk share
    Disk = 0,
    /// Print share
    Print = 1,
    /// Device share
    Device = 2,
    /// IPC share
    Ipc = 3,
}

impl ConnectionType {
    const fn empty() -> Self {
        ConnectionType::Disk
    }
}

/// Connection status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Connection is active
    Connected = 0,
    /// Connection is paused
    Paused = 1,
    /// Connection lost/disconnected
    Disconnected = 2,
    /// Network error
    Error = 3,
    /// Connecting in progress
    Connecting = 4,
    /// Reconnecting
    Reconnecting = 5,
}

impl ConnectionStatus {
    const fn empty() -> Self {
        ConnectionStatus::Disconnected
    }
}

/// Network connection (USE_INFO structure)
#[repr(C)]
#[derive(Clone)]
pub struct NetworkConnection {
    /// Local device name (e.g., "Z:")
    pub local_name: [u8; MAX_LOCAL_NAME],
    /// Remote share name (e.g., "\\server\share")
    pub remote_name: [u8; MAX_SERVER_NAME + MAX_SHARE_NAME + 4],
    /// Connection type
    pub conn_type: ConnectionType,
    /// Connection status
    pub status: ConnectionStatus,
    /// Reference count (open handles)
    pub ref_count: u32,
    /// Number of opens on this connection
    pub use_count: u32,
    /// Username for connection
    pub username: [u8; MAX_USERNAME],
    /// Domain for connection
    pub domain: [u8; MAX_DOMAIN],
    /// Connection flags
    pub flags: u32,
    /// Time connection was established
    pub connect_time: i64,
    /// Last activity time
    pub last_activity: i64,
    /// Entry is valid
    pub valid: bool,
}

impl NetworkConnection {
    const fn empty() -> Self {
        NetworkConnection {
            local_name: [0; MAX_LOCAL_NAME],
            remote_name: [0; MAX_SERVER_NAME + MAX_SHARE_NAME + 4],
            conn_type: ConnectionType::empty(),
            status: ConnectionStatus::empty(),
            ref_count: 0,
            use_count: 0,
            username: [0; MAX_USERNAME],
            domain: [0; MAX_DOMAIN],
            flags: 0,
            connect_time: 0,
            last_activity: 0,
            valid: false,
        }
    }
}

/// Network transport information
#[repr(C)]
#[derive(Clone)]
pub struct TransportInfo {
    /// Transport name
    pub name: [u8; 64],
    /// Number of virtual circuits
    pub vc_count: u32,
    /// Number of sessions
    pub session_count: u32,
    /// Bytes received
    pub bytes_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Quality of service
    pub quality_of_service: u32,
    /// Is WAN link
    pub wan_link: bool,
    /// Entry is valid
    pub valid: bool,
}

impl TransportInfo {
    const fn empty() -> Self {
        TransportInfo {
            name: [0; 64],
            vc_count: 0,
            session_count: 0,
            bytes_received: 0,
            bytes_sent: 0,
            quality_of_service: 0,
            wan_link: false,
            valid: false,
        }
    }
}

/// Workstation user info
#[repr(C)]
#[derive(Clone)]
pub struct WorkstationUser {
    /// Username
    pub username: [u8; MAX_USERNAME],
    /// Logon domain
    pub logon_domain: [u8; MAX_DOMAIN],
    /// Other domains
    pub oth_domains: [u8; 128],
    /// Logon server
    pub logon_server: [u8; MAX_SERVER_NAME],
    /// Entry is valid
    pub valid: bool,
}

impl WorkstationUser {
    const fn empty() -> Self {
        WorkstationUser {
            username: [0; MAX_USERNAME],
            logon_domain: [0; MAX_DOMAIN],
            oth_domains: [0; 128],
            logon_server: [0; MAX_SERVER_NAME],
            valid: false,
        }
    }
}

/// Workstation platform IDs
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformId {
    /// DOS
    Dos = 300,
    /// OS/2
    Os2 = 400,
    /// Windows NT
    Nt = 500,
    /// OSF
    Osf = 600,
    /// VMS
    Vms = 700,
}

/// Workstation information (WKSTA_INFO_100)
#[repr(C)]
#[derive(Clone)]
pub struct WorkstationInfo {
    /// Platform ID
    pub platform_id: u32,
    /// Computer name
    pub computer_name: [u8; MAX_SERVER_NAME],
    /// LAN group (domain/workgroup)
    pub lan_group: [u8; MAX_DOMAIN],
    /// Major version
    pub version_major: u32,
    /// Minor version
    pub version_minor: u32,
    /// LAN root directory
    pub lan_root: [u8; 128],
    /// Logged on users count
    pub logged_on_users: u32,
}

impl WorkstationInfo {
    const fn new() -> Self {
        WorkstationInfo {
            platform_id: PlatformId::Nt as u32,
            computer_name: [0; MAX_SERVER_NAME],
            lan_group: [0; MAX_DOMAIN],
            version_major: 5,
            version_minor: 2,
            lan_root: [0; 128],
            logged_on_users: 0,
        }
    }
}

/// Workstation service state
pub struct WorkstationState {
    /// Service is running
    pub running: bool,
    /// Workstation info
    pub info: WorkstationInfo,
    /// Network connections
    pub connections: [NetworkConnection; MAX_CONNECTIONS],
    /// Connection count
    pub connection_count: usize,
    /// Network transports
    pub transports: [TransportInfo; MAX_TRANSPORTS],
    /// Transport count
    pub transport_count: usize,
    /// Logged on users
    pub users: [WorkstationUser; MAX_WKS_USERS],
    /// User count
    pub user_count: usize,
    /// Service start time
    pub start_time: i64,
    /// Maximum collection count for enumeration
    pub max_collection_count: u32,
    /// Keep connection timeout (seconds)
    pub keep_conn: u32,
    /// Session timeout (seconds)
    pub sess_timeout: u32,
    /// Size of character buffers
    pub char_buf_size: u32,
    /// Maximum threads
    pub max_threads: u32,
    /// Use opportunistic locking
    pub use_oplocks: bool,
    /// Use encryption
    pub use_encryption: bool,
    /// Buffer named pipes
    pub buf_named_pipes: bool,
    /// Use unlock behind
    pub use_unlock_behind: bool,
    /// Use close behind
    pub use_close_behind: bool,
    /// Buffer files deny write
    pub buf_files_deny_write: bool,
    /// Force core create mode
    pub force_core_create_mode: bool,
}

impl WorkstationState {
    const fn new() -> Self {
        WorkstationState {
            running: false,
            info: WorkstationInfo::new(),
            connections: [const { NetworkConnection::empty() }; MAX_CONNECTIONS],
            connection_count: 0,
            transports: [const { TransportInfo::empty() }; MAX_TRANSPORTS],
            transport_count: 0,
            users: [const { WorkstationUser::empty() }; MAX_WKS_USERS],
            user_count: 0,
            start_time: 0,
            max_collection_count: 16,
            keep_conn: 600,
            sess_timeout: 60,
            char_buf_size: 512,
            max_threads: 17,
            use_oplocks: true,
            use_encryption: false,
            buf_named_pipes: true,
            use_unlock_behind: true,
            use_close_behind: true,
            buf_files_deny_write: true,
            force_core_create_mode: false,
        }
    }
}

/// Global workstation state
static WORKSTATION_STATE: Mutex<WorkstationState> = Mutex::new(WorkstationState::new());

/// Statistics
static TOTAL_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static ACTIVE_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static BYTES_RECEIVED: AtomicU64 = AtomicU64::new(0);
static BYTES_SENT: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize Workstation service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = WORKSTATION_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    // Set default computer name
    let default_name = b"NOSTALGIAOS";
    let name_len = default_name.len().min(MAX_SERVER_NAME);
    state.info.computer_name[..name_len].copy_from_slice(&default_name[..name_len]);

    // Set default workgroup
    let default_group = b"WORKGROUP";
    let group_len = default_group.len().min(MAX_DOMAIN);
    state.info.lan_group[..group_len].copy_from_slice(&default_group[..group_len]);

    // Register default transport (NetBT over TCP/IP)
    let netbt_name = b"\\Device\\NetBT_Tcpip";
    state.transports[0].name[..netbt_name.len()].copy_from_slice(netbt_name);
    state.transports[0].valid = true;
    state.transport_count = 1;

    crate::serial_println!("[LANMANWKS] Workstation service initialized");
}

/// Get workstation information
pub fn get_info(level: u32) -> Option<WorkstationInfo> {
    let state = WORKSTATION_STATE.lock();

    if !state.running {
        return None;
    }

    match level {
        100 | 101 | 102 => Some(state.info.clone()),
        _ => None,
    }
}

/// Set workstation information
pub fn set_info(info: &WorkstationInfo) -> Result<(), u32> {
    let mut state = WORKSTATION_STATE.lock();

    if !state.running {
        return Err(0x80070426); // ERROR_SERVICE_NOT_ACTIVE
    }

    state.info = info.clone();
    Ok(())
}

/// Add a network connection (NetUseAdd)
pub fn add_connection(
    local_name: Option<&[u8]>,
    remote_name: &[u8],
    username: Option<&[u8]>,
    domain: Option<&[u8]>,
    conn_type: ConnectionType,
    flags: u32,
) -> Result<usize, u32> {
    let mut state = WORKSTATION_STATE.lock();

    if !state.running {
        return Err(0x80070426); // ERROR_SERVICE_NOT_ACTIVE
    }

    // Check for duplicate local name
    if let Some(local) = local_name {
        for conn in state.connections.iter() {
            if conn.valid && conn.local_name[..local.len().min(MAX_LOCAL_NAME)] == local[..local.len().min(MAX_LOCAL_NAME)] {
                return Err(0x80070055); // ERROR_DUP_NAME
            }
        }
    }

    // Find free slot
    let slot = state.connections.iter().position(|c| !c.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E), // ERROR_OUTOFMEMORY
    };

    let now = crate::rtl::time::rtl_get_system_time();

    let conn = &mut state.connections[slot];

    // Copy local name if provided
    if let Some(local) = local_name {
        let len = local.len().min(MAX_LOCAL_NAME);
        conn.local_name[..len].copy_from_slice(&local[..len]);
    }

    // Copy remote name
    let remote_len = remote_name.len().min(MAX_SERVER_NAME + MAX_SHARE_NAME + 4);
    conn.remote_name[..remote_len].copy_from_slice(&remote_name[..remote_len]);

    // Copy username if provided
    if let Some(user) = username {
        let len = user.len().min(MAX_USERNAME);
        conn.username[..len].copy_from_slice(&user[..len]);
    }

    // Copy domain if provided
    if let Some(dom) = domain {
        let len = dom.len().min(MAX_DOMAIN);
        conn.domain[..len].copy_from_slice(&dom[..len]);
    }

    conn.conn_type = conn_type;
    conn.ref_count = 1;
    conn.use_count = 1;
    conn.flags = flags;
    conn.connect_time = now;
    conn.last_activity = now;
    conn.valid = true;
    // Simulate successful connection (in real impl would be async)
    conn.status = ConnectionStatus::Connected;

    state.connection_count += 1;

    TOTAL_CONNECTIONS.fetch_add(1, Ordering::SeqCst);
    ACTIVE_CONNECTIONS.fetch_add(1, Ordering::SeqCst);

    Ok(slot)
}

/// Delete a network connection (NetUseDel)
pub fn delete_connection(local_name: &[u8], force: bool) -> Result<(), u32> {
    let mut state = WORKSTATION_STATE.lock();

    if !state.running {
        return Err(0x80070426); // ERROR_SERVICE_NOT_ACTIVE
    }

    let local_len = local_name.len().min(MAX_LOCAL_NAME);

    // Find connection
    let conn_idx = state.connections.iter().position(|c| {
        c.valid && c.local_name[..local_len] == local_name[..local_len]
    });

    let conn_idx = match conn_idx {
        Some(idx) => idx,
        None => return Err(0x800704CA), // ERROR_DEVICE_NOT_CONNECTED
    };

    // Check if in use
    if !force && state.connections[conn_idx].use_count > 0 {
        return Err(0x80070488); // ERROR_DEVICE_IN_USE
    }

    state.connections[conn_idx].valid = false;
    state.connection_count = state.connection_count.saturating_sub(1);
    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::SeqCst);

    Ok(())
}

/// Enumerate network connections
pub fn enum_connections() -> ([NetworkConnection; MAX_CONNECTIONS], usize) {
    let state = WORKSTATION_STATE.lock();
    let mut result = [const { NetworkConnection::empty() }; MAX_CONNECTIONS];
    let mut count = 0;

    for conn in state.connections.iter() {
        if conn.valid && count < MAX_CONNECTIONS {
            result[count] = conn.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get connection by local name
pub fn get_connection(local_name: &[u8]) -> Option<NetworkConnection> {
    let state = WORKSTATION_STATE.lock();
    let local_len = local_name.len().min(MAX_LOCAL_NAME);

    state.connections.iter()
        .find(|c| c.valid && c.local_name[..local_len] == local_name[..local_len])
        .cloned()
}

/// Enumerate network transports
pub fn enum_transports() -> ([TransportInfo; MAX_TRANSPORTS], usize) {
    let state = WORKSTATION_STATE.lock();
    let mut result = [const { TransportInfo::empty() }; MAX_TRANSPORTS];
    let mut count = 0;

    for transport in state.transports.iter() {
        if transport.valid && count < MAX_TRANSPORTS {
            result[count] = transport.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Add a network transport
pub fn add_transport(name: &[u8], quality: u32, wan: bool) -> Result<usize, u32> {
    let mut state = WORKSTATION_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.transports.iter().position(|t| !t.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let name_len = name.len().min(64);
    state.transports[slot].name[..name_len].copy_from_slice(&name[..name_len]);
    state.transports[slot].quality_of_service = quality;
    state.transports[slot].wan_link = wan;
    state.transports[slot].valid = true;
    state.transport_count += 1;

    Ok(slot)
}

/// Delete a network transport
pub fn delete_transport(name: &[u8]) -> Result<(), u32> {
    let mut state = WORKSTATION_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let name_len = name.len().min(64);
    let idx = state.transports.iter().position(|t| {
        t.valid && t.name[..name_len] == name[..name_len]
    });

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070002), // ERROR_FILE_NOT_FOUND
    };

    state.transports[idx].valid = false;
    state.transport_count = state.transport_count.saturating_sub(1);

    Ok(())
}

/// Enumerate workstation users
pub fn enum_users() -> ([WorkstationUser; MAX_WKS_USERS], usize) {
    let state = WORKSTATION_STATE.lock();
    let mut result = [const { WorkstationUser::empty() }; MAX_WKS_USERS];
    let mut count = 0;

    for user in state.users.iter() {
        if user.valid && count < MAX_WKS_USERS {
            result[count] = user.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Register a logged-on user
pub fn register_user(
    username: &[u8],
    logon_domain: &[u8],
    logon_server: &[u8],
) -> Result<(), u32> {
    let mut state = WORKSTATION_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.users.iter().position(|u| !u.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let user = &mut state.users[slot];

    let uname_len = username.len().min(MAX_USERNAME);
    user.username[..uname_len].copy_from_slice(&username[..uname_len]);

    let domain_len = logon_domain.len().min(MAX_DOMAIN);
    user.logon_domain[..domain_len].copy_from_slice(&logon_domain[..domain_len]);

    let server_len = logon_server.len().min(MAX_SERVER_NAME);
    user.logon_server[..server_len].copy_from_slice(&logon_server[..server_len]);

    user.valid = true;
    state.user_count += 1;
    state.info.logged_on_users += 1;

    Ok(())
}

/// Unregister a logged-off user
pub fn unregister_user(username: &[u8]) -> Result<(), u32> {
    let mut state = WORKSTATION_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let uname_len = username.len().min(MAX_USERNAME);
    let idx = state.users.iter().position(|u| {
        u.valid && u.username[..uname_len] == username[..uname_len]
    });

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x800704F8), // ERROR_NO_SUCH_USER
    };

    state.users[idx].valid = false;
    state.user_count = state.user_count.saturating_sub(1);
    state.info.logged_on_users = state.info.logged_on_users.saturating_sub(1);

    Ok(())
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64, u64) {
    (
        TOTAL_CONNECTIONS.load(Ordering::SeqCst),
        ACTIVE_CONNECTIONS.load(Ordering::SeqCst),
        BYTES_RECEIVED.load(Ordering::SeqCst),
        BYTES_SENT.load(Ordering::SeqCst),
    )
}

/// Record bytes transferred
pub fn record_transfer(received: u64, sent: u64) {
    BYTES_RECEIVED.fetch_add(received, Ordering::SeqCst);
    BYTES_SENT.fetch_add(sent, Ordering::SeqCst);
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = WORKSTATION_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = WORKSTATION_STATE.lock();
    state.running = false;

    // Disconnect all connections
    for conn in state.connections.iter_mut() {
        if conn.valid {
            conn.status = ConnectionStatus::Disconnected;
        }
    }

    crate::serial_println!("[LANMANWKS] Workstation service stopped");
}

/// Get workstation configuration
pub fn get_config() -> (u32, u32, u32, u32) {
    let state = WORKSTATION_STATE.lock();
    (
        state.max_collection_count,
        state.keep_conn,
        state.sess_timeout,
        state.max_threads,
    )
}

/// Set keep connection timeout
pub fn set_keep_conn(seconds: u32) {
    let mut state = WORKSTATION_STATE.lock();
    state.keep_conn = seconds;
}

/// Set session timeout
pub fn set_sess_timeout(seconds: u32) {
    let mut state = WORKSTATION_STATE.lock();
    state.sess_timeout = seconds;
}

/// Update connection activity
pub fn update_connection_activity(local_name: &[u8]) {
    let mut state = WORKSTATION_STATE.lock();
    let local_len = local_name.len().min(MAX_LOCAL_NAME);

    if let Some(conn) = state.connections.iter_mut().find(|c| {
        c.valid && c.local_name[..local_len] == local_name[..local_len]
    }) {
        conn.last_activity = crate::rtl::time::rtl_get_system_time();
    }
}

/// Get computer name
pub fn get_computer_name() -> [u8; MAX_SERVER_NAME] {
    let state = WORKSTATION_STATE.lock();
    state.info.computer_name
}

/// Get domain/workgroup name
pub fn get_domain_name() -> [u8; MAX_DOMAIN] {
    let state = WORKSTATION_STATE.lock();
    state.info.lan_group
}
