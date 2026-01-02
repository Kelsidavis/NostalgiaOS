//! NETBT - NetBIOS over TCP/IP
//!
//! NetBIOS over TCP/IP (NBT) provides NetBIOS services over TCP/IP networks.
//! It implements RFC 1001 and RFC 1002.
//!
//! Services provided:
//! - NetBIOS Name Service (NBNS) - UDP port 137
//! - NetBIOS Datagram Service (NBDS) - UDP port 138
//! - NetBIOS Session Service (NBSS) - TCP port 139
//!
//! Name types:
//! - Unique names (single owner)
//! - Group names (multiple owners)

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// NetBIOS name length (15 chars + suffix)
pub const NETBIOS_NAME_LEN: usize = 16;

/// Maximum registered names
const MAX_REGISTERED_NAMES: usize = 256;

/// Maximum active sessions
const MAX_SESSIONS: usize = 256;

/// Maximum pending datagrams
const MAX_PENDING_DATAGRAMS: usize = 64;

/// NetBIOS ports
pub const NETBIOS_NS_PORT: u16 = 137;   // Name Service
pub const NETBIOS_DGM_PORT: u16 = 138;  // Datagram Service
pub const NETBIOS_SSN_PORT: u16 = 139;  // Session Service

// ============================================================================
// NetBIOS Name Types
// ============================================================================

/// NetBIOS name suffix (16th byte)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NetBiosSuffix {
    /// Workstation Service
    Workstation = 0x00,
    /// Messenger Service
    Messenger = 0x03,
    /// RAS Server Service
    RasServer = 0x06,
    /// Domain Master Browser
    DomainMasterBrowser = 0x1B,
    /// Domain Controller
    DomainController = 0x1C,
    /// Master Browser
    MasterBrowser = 0x1D,
    /// Browser Service Elections
    BrowserElections = 0x1E,
    /// NetDDE Service
    NetDde = 0x1F,
    /// File Server Service
    FileServer = 0x20,
    /// RAS Client Service
    RasClient = 0x21,
    /// Network Monitor Agent
    NetworkMonitor = 0xBE,
    /// Network Monitor Utility
    NetworkMonitorUtil = 0xBF,
}

/// NetBIOS name type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetBiosNameType {
    /// Unique name (single owner)
    Unique,
    /// Group name (multiple owners)
    Group,
}

/// NetBIOS name state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetBiosNameState {
    /// Name being registered
    Registering,
    /// Name registered and active
    Registered,
    /// Name in conflict
    Conflict,
    /// Name being released
    Releasing,
    /// Name released/inactive
    Released,
}

// ============================================================================
// NetBIOS Name
// ============================================================================

/// A NetBIOS name entry
#[derive(Clone)]
pub struct NetBiosName {
    /// The 16-byte NetBIOS name
    pub name: [u8; NETBIOS_NAME_LEN],
    /// Name type (unique or group)
    pub name_type: NetBiosNameType,
    /// Current state
    pub state: NetBiosNameState,
    /// IP address associated with name
    pub ip_address: [u8; 4],
    /// TTL in seconds
    pub ttl: u32,
    /// Registration time
    pub registered_time: u64,
    /// Refresh count
    pub refresh_count: u32,
    /// Owning process ID
    pub process_id: u32,
    /// Active flag
    pub active: bool,
}

impl Default for NetBiosName {
    fn default() -> Self {
        Self {
            name: [0x20; NETBIOS_NAME_LEN], // Space padded
            name_type: NetBiosNameType::Unique,
            state: NetBiosNameState::Released,
            ip_address: [0; 4],
            ttl: 0,
            registered_time: 0,
            refresh_count: 0,
            process_id: 0,
            active: false,
        }
    }
}

impl NetBiosName {
    /// Create a NetBIOS name from a string
    pub fn from_str(name: &str, suffix: u8) -> Self {
        let mut nb_name = [0x20u8; NETBIOS_NAME_LEN]; // Space padded

        let name_bytes = name.as_bytes();
        let copy_len = core::cmp::min(name_bytes.len(), 15);

        // Copy name and convert to uppercase
        for i in 0..copy_len {
            nb_name[i] = name_bytes[i].to_ascii_uppercase();
        }

        // Set suffix
        nb_name[15] = suffix;

        Self {
            name: nb_name,
            name_type: NetBiosNameType::Unique,
            state: NetBiosNameState::Released,
            ip_address: [0; 4],
            ttl: 0,
            registered_time: 0,
            refresh_count: 0,
            process_id: 0,
            active: false,
        }
    }

    /// Get the name as a string (without suffix)
    pub fn as_string(&self) -> String {
        let mut s = String::new();
        for i in 0..15 {
            if self.name[i] != 0x20 {
                s.push(self.name[i] as char);
            }
        }
        s
    }
}

// ============================================================================
// NetBIOS Session
// ============================================================================

/// NetBIOS session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session being established
    Connecting,
    /// Session established
    Connected,
    /// Session being closed
    Closing,
    /// Session closed
    Closed,
}

/// A NetBIOS session
#[derive(Clone)]
pub struct NetBiosSession {
    /// Session ID
    pub id: u64,
    /// Local name
    pub local_name: [u8; NETBIOS_NAME_LEN],
    /// Remote name
    pub remote_name: [u8; NETBIOS_NAME_LEN],
    /// Remote IP address
    pub remote_ip: [u8; 4],
    /// Remote port
    pub remote_port: u16,
    /// Session state
    pub state: SessionState,
    /// TCP socket handle
    pub socket_handle: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Owning process
    pub process_id: u32,
    /// Active flag
    pub active: bool,
}

impl Default for NetBiosSession {
    fn default() -> Self {
        Self {
            id: 0,
            local_name: [0x20; NETBIOS_NAME_LEN],
            remote_name: [0x20; NETBIOS_NAME_LEN],
            remote_ip: [0; 4],
            remote_port: 0,
            state: SessionState::Closed,
            socket_handle: 0,
            bytes_sent: 0,
            bytes_received: 0,
            process_id: 0,
            active: false,
        }
    }
}

// ============================================================================
// NetBIOS Datagram
// ============================================================================

/// NetBIOS datagram type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DatagramType {
    /// Direct unique datagram
    DirectUnique = 0x10,
    /// Direct group datagram
    DirectGroup = 0x11,
    /// Broadcast datagram
    Broadcast = 0x12,
    /// Datagram error
    Error = 0x13,
    /// Datagram query request
    QueryRequest = 0x14,
    /// Positive query response
    PositiveQueryResponse = 0x15,
    /// Negative query response
    NegativeQueryResponse = 0x16,
}

/// A pending NetBIOS datagram
#[derive(Clone)]
pub struct NetBiosDatagram {
    /// Datagram ID
    pub id: u64,
    /// Source name
    pub source_name: [u8; NETBIOS_NAME_LEN],
    /// Destination name
    pub dest_name: [u8; NETBIOS_NAME_LEN],
    /// Source IP
    pub source_ip: [u8; 4],
    /// Datagram type
    pub dgm_type: DatagramType,
    /// Data payload
    pub data: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

impl Default for NetBiosDatagram {
    fn default() -> Self {
        Self {
            id: 0,
            source_name: [0x20; NETBIOS_NAME_LEN],
            dest_name: [0x20; NETBIOS_NAME_LEN],
            source_ip: [0; 4],
            dgm_type: DatagramType::DirectUnique,
            data: Vec::new(),
            timestamp: 0,
        }
    }
}

// ============================================================================
// Name Service Operations
// ============================================================================

/// Name service operation codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NameServiceOpcode {
    /// Name query
    Query = 0,
    /// Name registration
    Registration = 5,
    /// Name release
    Release = 6,
    /// WACK (Wait for Acknowledgement)
    Wack = 7,
    /// Name refresh
    Refresh = 8,
}

/// Name service response codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NameServiceRcode {
    /// No error
    NoError = 0,
    /// Format error
    FormatError = 1,
    /// Server failure
    ServerFailure = 2,
    /// Name error (name does not exist)
    NameError = 3,
    /// Not implemented
    NotImplemented = 4,
    /// Refused
    Refused = 5,
    /// Active error (name already exists)
    ActiveError = 6,
    /// Conflict error
    ConflictError = 7,
}

// ============================================================================
// NETBT Statistics
// ============================================================================

/// NETBT statistics
#[derive(Debug)]
pub struct NetbtStatistics {
    /// Names registered
    pub names_registered: AtomicU64,
    /// Names released
    pub names_released: AtomicU64,
    /// Active names
    pub active_names: AtomicU32,
    /// Sessions established
    pub sessions_established: AtomicU64,
    /// Sessions closed
    pub sessions_closed: AtomicU64,
    /// Active sessions
    pub active_sessions: AtomicU32,
    /// Datagrams sent
    pub datagrams_sent: AtomicU64,
    /// Datagrams received
    pub datagrams_received: AtomicU64,
    /// Name queries sent
    pub name_queries_sent: AtomicU64,
    /// Name queries received
    pub name_queries_received: AtomicU64,
}

impl Default for NetbtStatistics {
    fn default() -> Self {
        Self {
            names_registered: AtomicU64::new(0),
            names_released: AtomicU64::new(0),
            active_names: AtomicU32::new(0),
            sessions_established: AtomicU64::new(0),
            sessions_closed: AtomicU64::new(0),
            active_sessions: AtomicU32::new(0),
            datagrams_sent: AtomicU64::new(0),
            datagrams_received: AtomicU64::new(0),
            name_queries_sent: AtomicU64::new(0),
            name_queries_received: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// NETBT Errors
// ============================================================================

/// NETBT error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum NetbtError {
    /// Success
    Success = 0,
    /// Not initialized
    NotInitialized = -1,
    /// Invalid parameter
    InvalidParameter = -2,
    /// Name not found
    NameNotFound = -3,
    /// Name already exists
    NameExists = -4,
    /// Name in conflict
    NameConflict = -5,
    /// Session not found
    SessionNotFound = -6,
    /// Session closed
    SessionClosed = -7,
    /// Too many names
    TooManyNames = -8,
    /// Too many sessions
    TooManySessions = -9,
    /// Network error
    NetworkError = -10,
    /// Timeout
    Timeout = -11,
    /// Buffer too small
    BufferTooSmall = -12,
    /// No data available
    NoData = -13,
}

// ============================================================================
// NETBT Configuration
// ============================================================================

/// NETBT node type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// B-node (broadcast only)
    BNode,
    /// P-node (point-to-point, WINS only)
    PNode,
    /// M-node (mixed, broadcast then WINS)
    MNode,
    /// H-node (hybrid, WINS then broadcast)
    HNode,
}

/// NETBT configuration
#[derive(Clone)]
pub struct NetbtConfig {
    /// Node type
    pub node_type: NodeType,
    /// Scope ID
    pub scope_id: Option<String>,
    /// Primary WINS server
    pub wins_primary: Option<[u8; 4]>,
    /// Secondary WINS server
    pub wins_secondary: Option<[u8; 4]>,
    /// Enable LMHOSTS lookup
    pub lmhosts_enabled: bool,
    /// Enable DNS for NetBIOS
    pub dns_enabled: bool,
    /// Broadcast address
    pub broadcast_addr: [u8; 4],
    /// Name registration TTL (seconds)
    pub name_ttl: u32,
}

impl Default for NetbtConfig {
    fn default() -> Self {
        Self {
            node_type: NodeType::HNode,
            scope_id: None,
            wins_primary: None,
            wins_secondary: None,
            lmhosts_enabled: true,
            dns_enabled: true,
            broadcast_addr: [255, 255, 255, 255],
            name_ttl: 300000, // ~3.5 days
        }
    }
}

// ============================================================================
// NETBT State
// ============================================================================

/// NETBT global state
pub struct NetbtState {
    /// Registered names
    pub names: [NetBiosName; MAX_REGISTERED_NAMES],
    /// Active sessions
    pub sessions: [NetBiosSession; MAX_SESSIONS],
    /// Pending datagrams (received)
    pub datagrams: [Option<NetBiosDatagram>; MAX_PENDING_DATAGRAMS],
    /// Configuration
    pub config: NetbtConfig,
    /// Next session ID
    pub next_session_id: u64,
    /// Next datagram ID
    pub next_datagram_id: u64,
    /// Local IP address
    pub local_ip: [u8; 4],
    /// Statistics
    pub statistics: NetbtStatistics,
    /// Initialized flag
    pub initialized: bool,
}

impl NetbtState {
    const fn new() -> Self {
        const DEFAULT_NAME: NetBiosName = NetBiosName {
            name: [0x20; NETBIOS_NAME_LEN],
            name_type: NetBiosNameType::Unique,
            state: NetBiosNameState::Released,
            ip_address: [0; 4],
            ttl: 0,
            registered_time: 0,
            refresh_count: 0,
            process_id: 0,
            active: false,
        };

        const DEFAULT_SESSION: NetBiosSession = NetBiosSession {
            id: 0,
            local_name: [0x20; NETBIOS_NAME_LEN],
            remote_name: [0x20; NETBIOS_NAME_LEN],
            remote_ip: [0; 4],
            remote_port: 0,
            state: SessionState::Closed,
            socket_handle: 0,
            bytes_sent: 0,
            bytes_received: 0,
            process_id: 0,
            active: false,
        };

        const NONE_DATAGRAM: Option<NetBiosDatagram> = None;

        Self {
            names: [DEFAULT_NAME; MAX_REGISTERED_NAMES],
            sessions: [DEFAULT_SESSION; MAX_SESSIONS],
            datagrams: [NONE_DATAGRAM; MAX_PENDING_DATAGRAMS],
            config: NetbtConfig {
                node_type: NodeType::HNode,
                scope_id: None,
                wins_primary: None,
                wins_secondary: None,
                lmhosts_enabled: true,
                dns_enabled: true,
                broadcast_addr: [255, 255, 255, 255],
                name_ttl: 300000,
            },
            next_session_id: 1,
            next_datagram_id: 1,
            local_ip: [0; 4],
            statistics: NetbtStatistics {
                names_registered: AtomicU64::new(0),
                names_released: AtomicU64::new(0),
                active_names: AtomicU32::new(0),
                sessions_established: AtomicU64::new(0),
                sessions_closed: AtomicU64::new(0),
                active_sessions: AtomicU32::new(0),
                datagrams_sent: AtomicU64::new(0),
                datagrams_received: AtomicU64::new(0),
                name_queries_sent: AtomicU64::new(0),
                name_queries_received: AtomicU64::new(0),
            },
            initialized: false,
        }
    }
}

/// Global NETBT state
static NETBT_STATE: SpinLock<NetbtState> = SpinLock::new(NetbtState::new());

// ============================================================================
// Name Registration and Resolution
// ============================================================================

/// Register a NetBIOS name
pub fn nbt_register_name(
    name: &str,
    suffix: u8,
    name_type: NetBiosNameType,
    ip_address: [u8; 4],
    process_id: u32,
) -> Result<(), NetbtError> {
    let mut state = NETBT_STATE.lock();

    if !state.initialized {
        return Err(NetbtError::NotInitialized);
    }

    let nb_name = NetBiosName::from_str(name, suffix);

    // Check if name already registered
    for idx in 0..MAX_REGISTERED_NAMES {
        if state.names[idx].active && state.names[idx].name == nb_name.name {
            if name_type == NetBiosNameType::Unique {
                return Err(NetbtError::NameExists);
            }
        }
    }

    // Find free slot
    let mut slot_idx = None;
    for idx in 0..MAX_REGISTERED_NAMES {
        if !state.names[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(NetbtError::TooManyNames)?;

    state.names[idx] = NetBiosName {
        name: nb_name.name,
        name_type,
        state: NetBiosNameState::Registered,
        ip_address,
        ttl: state.config.name_ttl,
        registered_time: 0, // TODO: system time
        refresh_count: 0,
        process_id,
        active: true,
    };

    state.statistics.names_registered.fetch_add(1, Ordering::Relaxed);
    state.statistics.active_names.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[NETBT] Registered name '{}' <{:02X}>", name, suffix);

    Ok(())
}

/// Release a NetBIOS name
pub fn nbt_release_name(name: &str, suffix: u8) -> Result<(), NetbtError> {
    let mut state = NETBT_STATE.lock();

    if !state.initialized {
        return Err(NetbtError::NotInitialized);
    }

    let nb_name = NetBiosName::from_str(name, suffix);

    for idx in 0..MAX_REGISTERED_NAMES {
        if state.names[idx].active && state.names[idx].name == nb_name.name {
            state.names[idx].state = NetBiosNameState::Released;
            state.names[idx].active = false;

            state.statistics.names_released.fetch_add(1, Ordering::Relaxed);
            state.statistics.active_names.fetch_sub(1, Ordering::Relaxed);

            crate::serial_println!("[NETBT] Released name '{}' <{:02X}>", name, suffix);
            return Ok(());
        }
    }

    Err(NetbtError::NameNotFound)
}

/// Resolve a NetBIOS name to IP address
pub fn nbt_resolve_name(name: &str, suffix: u8) -> Result<[u8; 4], NetbtError> {
    let mut state = NETBT_STATE.lock();

    if !state.initialized {
        return Err(NetbtError::NotInitialized);
    }

    let nb_name = NetBiosName::from_str(name, suffix);

    // Check local name cache first
    for idx in 0..MAX_REGISTERED_NAMES {
        if state.names[idx].active && state.names[idx].name == nb_name.name {
            return Ok(state.names[idx].ip_address);
        }
    }

    // TODO: Query WINS server or broadcast

    state.statistics.name_queries_sent.fetch_add(1, Ordering::Relaxed);

    Err(NetbtError::NameNotFound)
}

/// Get local registered names
pub fn nbt_get_names() -> Vec<(String, u8, [u8; 4])> {
    let state = NETBT_STATE.lock();
    let mut result = Vec::new();

    for idx in 0..MAX_REGISTERED_NAMES {
        if state.names[idx].active {
            let name_str = state.names[idx].as_string();
            let suffix = state.names[idx].name[15];
            let ip = state.names[idx].ip_address;
            result.push((name_str, suffix, ip));
        }
    }

    result
}

// ============================================================================
// Session Service
// ============================================================================

/// Establish a NetBIOS session
pub fn nbt_connect(
    local_name: &str,
    local_suffix: u8,
    remote_name: &str,
    remote_suffix: u8,
    remote_ip: [u8; 4],
    process_id: u32,
) -> Result<u64, NetbtError> {
    let mut state = NETBT_STATE.lock();

    if !state.initialized {
        return Err(NetbtError::NotInitialized);
    }

    // Find free session slot
    let mut slot_idx = None;
    for idx in 0..MAX_SESSIONS {
        if !state.sessions[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(NetbtError::TooManySessions)?;

    let session_id = state.next_session_id;
    state.next_session_id += 1;

    let local_nb = NetBiosName::from_str(local_name, local_suffix);
    let remote_nb = NetBiosName::from_str(remote_name, remote_suffix);

    state.sessions[idx] = NetBiosSession {
        id: session_id,
        local_name: local_nb.name,
        remote_name: remote_nb.name,
        remote_ip,
        remote_port: NETBIOS_SSN_PORT,
        state: SessionState::Connected, // Simplified
        socket_handle: 0, // TODO: Create actual TCP connection
        bytes_sent: 0,
        bytes_received: 0,
        process_id,
        active: true,
    };

    state.statistics.sessions_established.fetch_add(1, Ordering::Relaxed);
    state.statistics.active_sessions.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[NETBT] Session {} established: {} -> {}",
        session_id, local_name, remote_name);

    Ok(session_id)
}

/// Send data on a NetBIOS session
pub fn nbt_send(session_id: u64, data: &[u8]) -> Result<usize, NetbtError> {
    let mut state = NETBT_STATE.lock();

    if !state.initialized {
        return Err(NetbtError::NotInitialized);
    }

    for idx in 0..MAX_SESSIONS {
        if state.sessions[idx].active && state.sessions[idx].id == session_id {
            if state.sessions[idx].state != SessionState::Connected {
                return Err(NetbtError::SessionClosed);
            }

            // TODO: Actually send via TCP socket
            state.sessions[idx].bytes_sent += data.len() as u64;

            return Ok(data.len());
        }
    }

    Err(NetbtError::SessionNotFound)
}

/// Receive data on a NetBIOS session
pub fn nbt_receive(session_id: u64, buffer: &mut [u8]) -> Result<usize, NetbtError> {
    let mut state = NETBT_STATE.lock();

    if !state.initialized {
        return Err(NetbtError::NotInitialized);
    }

    for idx in 0..MAX_SESSIONS {
        if state.sessions[idx].active && state.sessions[idx].id == session_id {
            if state.sessions[idx].state != SessionState::Connected {
                return Err(NetbtError::SessionClosed);
            }

            // TODO: Actually receive from TCP socket
            // For now, return no data
            return Err(NetbtError::NoData);
        }
    }

    Err(NetbtError::SessionNotFound)
}

/// Close a NetBIOS session
pub fn nbt_disconnect(session_id: u64) -> Result<(), NetbtError> {
    let mut state = NETBT_STATE.lock();

    if !state.initialized {
        return Err(NetbtError::NotInitialized);
    }

    for idx in 0..MAX_SESSIONS {
        if state.sessions[idx].active && state.sessions[idx].id == session_id {
            state.sessions[idx].state = SessionState::Closed;
            state.sessions[idx].active = false;

            state.statistics.sessions_closed.fetch_add(1, Ordering::Relaxed);
            state.statistics.active_sessions.fetch_sub(1, Ordering::Relaxed);

            crate::serial_println!("[NETBT] Session {} closed", session_id);
            return Ok(());
        }
    }

    Err(NetbtError::SessionNotFound)
}

// ============================================================================
// Datagram Service
// ============================================================================

/// Send a NetBIOS datagram
pub fn nbt_send_datagram(
    source_name: &str,
    source_suffix: u8,
    dest_name: &str,
    dest_suffix: u8,
    data: &[u8],
    broadcast: bool,
) -> Result<(), NetbtError> {
    let mut state = NETBT_STATE.lock();

    if !state.initialized {
        return Err(NetbtError::NotInitialized);
    }

    // TODO: Actually send UDP datagram

    state.statistics.datagrams_sent.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[NETBT] Datagram sent: {} -> {} ({} bytes, broadcast={})",
        source_name, dest_name, data.len(), broadcast);

    Ok(())
}

/// Receive pending datagrams for a name
pub fn nbt_receive_datagram(
    name: &str,
    suffix: u8,
) -> Result<NetBiosDatagram, NetbtError> {
    let mut state = NETBT_STATE.lock();

    if !state.initialized {
        return Err(NetbtError::NotInitialized);
    }

    let nb_name = NetBiosName::from_str(name, suffix);

    // Look for pending datagrams for this name
    for idx in 0..MAX_PENDING_DATAGRAMS {
        if let Some(ref dgm) = state.datagrams[idx] {
            if dgm.dest_name == nb_name.name {
                let datagram = state.datagrams[idx].take().unwrap();
                state.statistics.datagrams_received.fetch_add(1, Ordering::Relaxed);
                return Ok(datagram);
            }
        }
    }

    Err(NetbtError::NoData)
}

// ============================================================================
// Configuration
// ============================================================================

/// Set NETBT configuration
pub fn nbt_set_config(config: NetbtConfig) -> Result<(), NetbtError> {
    let mut state = NETBT_STATE.lock();

    if !state.initialized {
        return Err(NetbtError::NotInitialized);
    }

    state.config = config;

    Ok(())
}

/// Get NETBT configuration
pub fn nbt_get_config() -> Result<NetbtConfig, NetbtError> {
    let state = NETBT_STATE.lock();

    if !state.initialized {
        return Err(NetbtError::NotInitialized);
    }

    Ok(state.config.clone())
}

/// Set local IP address
pub fn nbt_set_local_ip(ip: [u8; 4]) -> Result<(), NetbtError> {
    let mut state = NETBT_STATE.lock();

    if !state.initialized {
        return Err(NetbtError::NotInitialized);
    }

    state.local_ip = ip;

    Ok(())
}

// ============================================================================
// Statistics
// ============================================================================

/// Get NETBT statistics
pub fn nbt_get_statistics() -> NetbtStatistics {
    let state = NETBT_STATE.lock();

    NetbtStatistics {
        names_registered: AtomicU64::new(state.statistics.names_registered.load(Ordering::Relaxed)),
        names_released: AtomicU64::new(state.statistics.names_released.load(Ordering::Relaxed)),
        active_names: AtomicU32::new(state.statistics.active_names.load(Ordering::Relaxed)),
        sessions_established: AtomicU64::new(state.statistics.sessions_established.load(Ordering::Relaxed)),
        sessions_closed: AtomicU64::new(state.statistics.sessions_closed.load(Ordering::Relaxed)),
        active_sessions: AtomicU32::new(state.statistics.active_sessions.load(Ordering::Relaxed)),
        datagrams_sent: AtomicU64::new(state.statistics.datagrams_sent.load(Ordering::Relaxed)),
        datagrams_received: AtomicU64::new(state.statistics.datagrams_received.load(Ordering::Relaxed)),
        name_queries_sent: AtomicU64::new(state.statistics.name_queries_sent.load(Ordering::Relaxed)),
        name_queries_received: AtomicU64::new(state.statistics.name_queries_received.load(Ordering::Relaxed)),
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize NETBT
pub fn init() {
    crate::serial_println!("[NETBT] Initializing NetBIOS over TCP/IP...");

    {
        let mut state = NETBT_STATE.lock();
        state.initialized = true;
    }

    crate::serial_println!("[NETBT] NETBT initialized");
}
