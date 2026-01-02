//! Remote Registry Service
//!
//! The Remote Registry service allows remote access to the Windows
//! registry over the network. This enables:
//!
//! - **Remote Administration**: Modify settings on remote computers
//! - **System Management**: Group Policy and enterprise management
//! - **Scripting**: Remote registry access from scripts
//!
//! # Security
//!
//! Access is controlled by:
//! - User authentication (network logon)
//! - Registry key ACLs
//! - Remote Registry service permissions
//!
//! # Protocol
//!
//! Uses the Windows Remote Registry Protocol (MS-RRP) over RPC.

extern crate alloc;

use crate::ke::SpinLock;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum remote connections
pub const MAX_CONNECTIONS: usize = 32;

/// Maximum pending operations
pub const MAX_PENDING_OPS: usize = 64;

/// Maximum key path length
pub const MAX_KEY_PATH: usize = 512;

/// Maximum value name length
pub const MAX_VALUE_NAME: usize = 256;

/// Maximum value data size
pub const MAX_VALUE_DATA: usize = 4096;

// ============================================================================
// Types
// ============================================================================

/// Remote registry operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum OperationType {
    /// Open a registry key
    OpenKey = 0,
    /// Close a registry key
    CloseKey = 1,
    /// Create a registry key
    CreateKey = 2,
    /// Delete a registry key
    DeleteKey = 3,
    /// Enumerate subkeys
    EnumKey = 4,
    /// Enumerate values
    EnumValue = 5,
    /// Query key information
    QueryInfoKey = 6,
    /// Query value
    QueryValue = 7,
    /// Set value
    SetValue = 8,
    /// Delete value
    DeleteValue = 9,
    /// Flush key
    FlushKey = 10,
    /// Save key
    SaveKey = 11,
    /// Restore key
    RestoreKey = 12,
}

impl Default for OperationType {
    fn default() -> Self {
        Self::OpenKey
    }
}

/// Remote registry error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RemRegError {
    /// Success
    Ok = 0,
    /// Service not running
    NotRunning = 1,
    /// Access denied
    AccessDenied = 2,
    /// Key not found
    KeyNotFound = 3,
    /// Value not found
    ValueNotFound = 4,
    /// Invalid parameter
    InvalidParam = 5,
    /// Connection failed
    ConnectionFailed = 6,
    /// Connection limit reached
    TooManyConnections = 7,
    /// Operation failed
    OperationFailed = 8,
    /// Authentication failed
    AuthFailed = 9,
    /// Network error
    NetworkError = 10,
    /// Remote access disabled
    Disabled = 11,
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ConnectionState {
    /// Idle/closed
    Idle = 0,
    /// Connecting
    Connecting = 1,
    /// Connected
    Connected = 2,
    /// Authenticated
    Authenticated = 3,
    /// Disconnecting
    Disconnecting = 4,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::Idle
    }
}

/// Access rights for remote registry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct AccessRights(pub u32);

impl AccessRights {
    pub const NONE: u32 = 0;
    pub const KEY_QUERY_VALUE: u32 = 0x0001;
    pub const KEY_SET_VALUE: u32 = 0x0002;
    pub const KEY_CREATE_SUB_KEY: u32 = 0x0004;
    pub const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
    pub const KEY_NOTIFY: u32 = 0x0010;
    pub const KEY_CREATE_LINK: u32 = 0x0020;
    pub const KEY_READ: u32 = 0x20019; // STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY
    pub const KEY_WRITE: u32 = 0x20006; // STANDARD_RIGHTS_WRITE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY
    pub const KEY_ALL_ACCESS: u32 = 0xF003F;

    pub fn can_read(&self) -> bool {
        (self.0 & Self::KEY_QUERY_VALUE) != 0
    }

    pub fn can_write(&self) -> bool {
        (self.0 & Self::KEY_SET_VALUE) != 0
    }

    pub fn can_create(&self) -> bool {
        (self.0 & Self::KEY_CREATE_SUB_KEY) != 0
    }
}

// ============================================================================
// Remote Connection
// ============================================================================

/// A remote registry connection
#[derive(Clone)]
pub struct RemoteConnection {
    /// Entry is valid
    pub valid: bool,
    /// Connection ID
    pub id: u32,
    /// Remote computer name/IP
    pub remote_host: [u8; 64],
    /// Remote port
    pub remote_port: u16,
    /// Connection state
    pub state: ConnectionState,
    /// Authenticated user name
    pub user_name: [u8; 64],
    /// User SID (simplified)
    pub user_sid: u32,
    /// Session ID
    pub session_id: u32,
    /// Connection time (NT time)
    pub connect_time: i64,
    /// Last activity time
    pub last_activity: i64,
    /// Access rights granted
    pub access_rights: AccessRights,
    /// Operations performed
    pub op_count: u32,
}

impl RemoteConnection {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            id: 0,
            remote_host: [0; 64],
            remote_port: 0,
            state: ConnectionState::Idle,
            user_name: [0; 64],
            user_sid: 0,
            session_id: 0,
            connect_time: 0,
            last_activity: 0,
            access_rights: AccessRights(0),
            op_count: 0,
        }
    }

    pub fn remote_host_str(&self) -> &str {
        let len = self.remote_host.iter().position(|&b| b == 0).unwrap_or(64);
        core::str::from_utf8(&self.remote_host[..len]).unwrap_or("")
    }

    pub fn set_remote_host(&mut self, host: &str) {
        let bytes = host.as_bytes();
        let len = bytes.len().min(64);
        self.remote_host[..len].copy_from_slice(&bytes[..len]);
        if len < 64 {
            self.remote_host[len..].fill(0);
        }
    }

    pub fn user_name_str(&self) -> &str {
        let len = self.user_name.iter().position(|&b| b == 0).unwrap_or(64);
        core::str::from_utf8(&self.user_name[..len]).unwrap_or("")
    }

    pub fn set_user_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(64);
        self.user_name[..len].copy_from_slice(&bytes[..len]);
        if len < 64 {
            self.user_name[len..].fill(0);
        }
    }
}

// ============================================================================
// Pending Operation
// ============================================================================

/// A pending registry operation
#[derive(Clone)]
pub struct PendingOperation {
    /// Entry is valid
    pub valid: bool,
    /// Operation ID
    pub id: u32,
    /// Connection ID
    pub connection_id: u32,
    /// Operation type
    pub op_type: OperationType,
    /// Key path
    pub key_path: [u8; MAX_KEY_PATH],
    /// Key path length
    pub key_len: usize,
    /// Value name (if applicable)
    pub value_name: [u8; MAX_VALUE_NAME],
    /// Value name length
    pub value_len: usize,
    /// Request time
    pub request_time: i64,
    /// Completed
    pub completed: bool,
    /// Result code
    pub result: RemRegError,
}

impl PendingOperation {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            id: 0,
            connection_id: 0,
            op_type: OperationType::OpenKey,
            key_path: [0; MAX_KEY_PATH],
            key_len: 0,
            value_name: [0; MAX_VALUE_NAME],
            value_len: 0,
            request_time: 0,
            completed: false,
            result: RemRegError::Ok,
        }
    }

    pub fn key_path_str(&self) -> &str {
        core::str::from_utf8(&self.key_path[..self.key_len]).unwrap_or("")
    }

    pub fn set_key_path(&mut self, path: &str) {
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_KEY_PATH);
        self.key_path[..len].copy_from_slice(&bytes[..len]);
        self.key_len = len;
    }
}

// ============================================================================
// Service State
// ============================================================================

/// Remote registry service state
struct RemRegState {
    /// Service running
    running: bool,
    /// Remote access enabled
    enabled: bool,
    /// Connections
    connections: [RemoteConnection; MAX_CONNECTIONS],
    /// Connection count
    connection_count: usize,
    /// Pending operations
    operations: [PendingOperation; MAX_PENDING_OPS],
    /// Operation count
    op_count: usize,
    /// Next connection ID
    next_conn_id: u32,
    /// Next operation ID
    next_op_id: u32,
    /// Listening port
    listen_port: u16,
    /// Require authentication
    require_auth: bool,
    /// Allow anonymous read
    allow_anon_read: bool,
}

impl RemRegState {
    const fn new() -> Self {
        Self {
            running: false,
            enabled: true,
            connections: [const { RemoteConnection::empty() }; MAX_CONNECTIONS],
            connection_count: 0,
            operations: [const { PendingOperation::empty() }; MAX_PENDING_OPS],
            op_count: 0,
            next_conn_id: 1,
            next_op_id: 1,
            listen_port: 445, // SMB port
            require_auth: true,
            allow_anon_read: false,
        }
    }
}

static REMREG_STATE: SpinLock<RemRegState> = SpinLock::new(RemRegState::new());

/// Statistics
struct RemRegStats {
    /// Total connections
    total_connections: AtomicU64,
    /// Active connections
    active_connections: AtomicU64,
    /// Operations performed
    operations_performed: AtomicU64,
    /// Successful operations
    successful_ops: AtomicU64,
    /// Failed operations
    failed_ops: AtomicU64,
    /// Access denied
    access_denied: AtomicU64,
    /// Key queries
    key_queries: AtomicU64,
    /// Value queries
    value_queries: AtomicU64,
    /// Value sets
    value_sets: AtomicU64,
}

impl RemRegStats {
    const fn new() -> Self {
        Self {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            operations_performed: AtomicU64::new(0),
            successful_ops: AtomicU64::new(0),
            failed_ops: AtomicU64::new(0),
            access_denied: AtomicU64::new(0),
            key_queries: AtomicU64::new(0),
            value_queries: AtomicU64::new(0),
            value_sets: AtomicU64::new(0),
        }
    }
}

static REMREG_STATS: RemRegStats = RemRegStats::new();

// ============================================================================
// Connection Management
// ============================================================================

/// Accept a new remote connection
pub fn accept_connection(
    remote_host: &str,
    remote_port: u16,
) -> Result<u32, RemRegError> {
    let mut state = REMREG_STATE.lock();

    if !state.running {
        return Err(RemRegError::NotRunning);
    }

    if !state.enabled {
        return Err(RemRegError::Disabled);
    }

    if state.connection_count >= MAX_CONNECTIONS {
        return Err(RemRegError::TooManyConnections);
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_CONNECTIONS {
        if !state.connections[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(RemRegError::TooManyConnections),
    };

    let conn_id = state.next_conn_id;
    state.next_conn_id += 1;

    let conn = &mut state.connections[slot];
    conn.valid = true;
    conn.id = conn_id;
    conn.set_remote_host(remote_host);
    conn.remote_port = remote_port;
    conn.state = ConnectionState::Connecting;
    conn.connect_time = crate::rtl::time::rtl_get_system_time();
    conn.last_activity = conn.connect_time;
    conn.access_rights = AccessRights(0);
    conn.op_count = 0;

    state.connection_count += 1;

    REMREG_STATS.total_connections.fetch_add(1, Ordering::Relaxed);
    REMREG_STATS.active_connections.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[REMREG] New connection from {}:{} (ID {})",
        remote_host, remote_port, conn_id);

    Ok(conn_id)
}

/// Authenticate a connection
pub fn authenticate_connection(
    conn_id: u32,
    user_name: &str,
    _password: &str,
) -> Result<AccessRights, RemRegError> {
    let mut state = REMREG_STATE.lock();

    // Find connection
    let mut idx = None;
    for i in 0..MAX_CONNECTIONS {
        if state.connections[i].valid && state.connections[i].id == conn_id {
            idx = Some(i);
            break;
        }
    }

    let idx = match idx {
        Some(i) => i,
        None => return Err(RemRegError::ConnectionFailed),
    };

    // Simplified authentication - just check if user exists
    // In a real system, this would verify credentials against SAM/AD
    let access = if user_name.contains("Admin") || user_name.contains("admin") {
        AccessRights(AccessRights::KEY_ALL_ACCESS)
    } else {
        AccessRights(AccessRights::KEY_READ)
    };

    state.connections[idx].set_user_name(user_name);
    state.connections[idx].state = ConnectionState::Authenticated;
    state.connections[idx].access_rights = access;
    state.connections[idx].last_activity = crate::rtl::time::rtl_get_system_time();

    crate::serial_println!("[REMREG] Connection {} authenticated as '{}'",
        conn_id, user_name);

    Ok(access)
}

/// Close a connection
pub fn close_connection(conn_id: u32) -> Result<(), RemRegError> {
    let mut state = REMREG_STATE.lock();

    for i in 0..MAX_CONNECTIONS {
        if state.connections[i].valid && state.connections[i].id == conn_id {
            state.connections[i].valid = false;
            state.connections[i].state = ConnectionState::Idle;
            state.connection_count = state.connection_count.saturating_sub(1);

            REMREG_STATS.active_connections.fetch_sub(1, Ordering::Relaxed);

            crate::serial_println!("[REMREG] Connection {} closed", conn_id);
            return Ok(());
        }
    }

    Err(RemRegError::ConnectionFailed)
}

/// Get connection count
pub fn get_connection_count() -> usize {
    let state = REMREG_STATE.lock();
    state.connection_count
}

// ============================================================================
// Remote Registry Operations
// ============================================================================

/// Check if operation is allowed
fn check_access(
    conn: &RemoteConnection,
    op_type: OperationType,
) -> Result<(), RemRegError> {
    if conn.state != ConnectionState::Authenticated {
        return Err(RemRegError::AuthFailed);
    }

    match op_type {
        OperationType::QueryValue | OperationType::EnumKey |
        OperationType::EnumValue | OperationType::QueryInfoKey |
        OperationType::OpenKey => {
            if !conn.access_rights.can_read() {
                REMREG_STATS.access_denied.fetch_add(1, Ordering::Relaxed);
                return Err(RemRegError::AccessDenied);
            }
        }
        OperationType::SetValue | OperationType::CreateKey |
        OperationType::DeleteKey | OperationType::DeleteValue |
        OperationType::FlushKey | OperationType::SaveKey |
        OperationType::RestoreKey => {
            if !conn.access_rights.can_write() {
                REMREG_STATS.access_denied.fetch_add(1, Ordering::Relaxed);
                return Err(RemRegError::AccessDenied);
            }
        }
        OperationType::CloseKey => {}
    }

    Ok(())
}

/// Submit a registry operation
pub fn submit_operation(
    conn_id: u32,
    op_type: OperationType,
    key_path: &str,
    value_name: Option<&str>,
) -> Result<u32, RemRegError> {
    let mut state = REMREG_STATE.lock();

    if !state.running {
        return Err(RemRegError::NotRunning);
    }

    // Find connection
    let mut conn_idx = None;
    for i in 0..MAX_CONNECTIONS {
        if state.connections[i].valid && state.connections[i].id == conn_id {
            conn_idx = Some(i);
            break;
        }
    }

    let conn_idx = match conn_idx {
        Some(i) => i,
        None => return Err(RemRegError::ConnectionFailed),
    };

    // Check access
    check_access(&state.connections[conn_idx], op_type)?;

    // Find free operation slot
    let mut op_slot = None;
    for i in 0..MAX_PENDING_OPS {
        if !state.operations[i].valid {
            op_slot = Some(i);
            break;
        }
    }

    let op_slot = match op_slot {
        Some(s) => s,
        None => return Err(RemRegError::OperationFailed),
    };

    let op_id = state.next_op_id;
    state.next_op_id += 1;

    let request_time = crate::rtl::time::rtl_get_system_time();

    let op = &mut state.operations[op_slot];
    op.valid = true;
    op.id = op_id;
    op.connection_id = conn_id;
    op.op_type = op_type;
    op.set_key_path(key_path);
    if let Some(name) = value_name {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_VALUE_NAME);
        op.value_name[..len].copy_from_slice(&bytes[..len]);
        op.value_len = len;
    }
    op.request_time = request_time;
    op.completed = false;
    op.result = RemRegError::Ok;

    state.op_count += 1;
    state.connections[conn_idx].op_count += 1;
    state.connections[conn_idx].last_activity = request_time;

    REMREG_STATS.operations_performed.fetch_add(1, Ordering::Relaxed);

    // Track operation types
    match op_type {
        OperationType::QueryValue => {
            REMREG_STATS.value_queries.fetch_add(1, Ordering::Relaxed);
        }
        OperationType::QueryInfoKey | OperationType::EnumKey |
        OperationType::EnumValue | OperationType::OpenKey => {
            REMREG_STATS.key_queries.fetch_add(1, Ordering::Relaxed);
        }
        OperationType::SetValue => {
            REMREG_STATS.value_sets.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }

    Ok(op_id)
}

/// Complete an operation
pub fn complete_operation(op_id: u32, result: RemRegError) -> Result<(), RemRegError> {
    let mut state = REMREG_STATE.lock();

    for i in 0..MAX_PENDING_OPS {
        if state.operations[i].valid && state.operations[i].id == op_id {
            state.operations[i].completed = true;
            state.operations[i].result = result;

            if result == RemRegError::Ok {
                REMREG_STATS.successful_ops.fetch_add(1, Ordering::Relaxed);
            } else {
                REMREG_STATS.failed_ops.fetch_add(1, Ordering::Relaxed);
            }

            return Ok(());
        }
    }

    Err(RemRegError::OperationFailed)
}

/// Clear completed operations
pub fn clear_completed_operations() -> usize {
    let mut state = REMREG_STATE.lock();
    let mut cleared = 0;

    for i in 0..MAX_PENDING_OPS {
        if state.operations[i].valid && state.operations[i].completed {
            state.operations[i].valid = false;
            state.op_count = state.op_count.saturating_sub(1);
            cleared += 1;
        }
    }

    cleared
}

// ============================================================================
// Configuration
// ============================================================================

/// Enable/disable remote registry access
pub fn set_enabled(enabled: bool) {
    let mut state = REMREG_STATE.lock();
    state.enabled = enabled;
    crate::serial_println!("[REMREG] Remote access: {}",
        if enabled { "enabled" } else { "disabled" });
}

/// Check if remote registry is enabled
pub fn is_enabled() -> bool {
    let state = REMREG_STATE.lock();
    state.enabled
}

/// Set authentication requirement
pub fn set_require_auth(required: bool) {
    let mut state = REMREG_STATE.lock();
    state.require_auth = required;
}

/// Allow/disallow anonymous read access
pub fn set_allow_anonymous_read(allowed: bool) {
    let mut state = REMREG_STATE.lock();
    state.allow_anon_read = allowed;
}

// ============================================================================
// Statistics
// ============================================================================

/// Get remote registry statistics
pub fn get_statistics() -> (u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        REMREG_STATS.total_connections.load(Ordering::Relaxed),
        REMREG_STATS.active_connections.load(Ordering::Relaxed),
        REMREG_STATS.operations_performed.load(Ordering::Relaxed),
        REMREG_STATS.successful_ops.load(Ordering::Relaxed),
        REMREG_STATS.failed_ops.load(Ordering::Relaxed),
        REMREG_STATS.access_denied.load(Ordering::Relaxed),
        REMREG_STATS.key_queries.load(Ordering::Relaxed),
        REMREG_STATS.value_queries.load(Ordering::Relaxed),
        REMREG_STATS.value_sets.load(Ordering::Relaxed),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = REMREG_STATE.lock();
    state.running
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialized flag
static REMREG_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the Remote Registry service
pub fn init() {
    if REMREG_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[REMREG] Initializing Remote Registry Service...");

    {
        let mut state = REMREG_STATE.lock();
        state.running = true;
        state.enabled = true;
        state.require_auth = true;
        state.allow_anon_read = false;
        state.listen_port = 445;
    }

    crate::serial_println!("[REMREG] Remote Registry Service initialized");
    crate::serial_println!("[REMREG]   Port: 445");
    crate::serial_println!("[REMREG]   Authentication: required");
}
