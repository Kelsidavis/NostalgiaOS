//! Server Message Block (SMB) Protocol
//!
//! SMB/CIFS protocol implementation for Windows file sharing:
//!
//! - **SMB1 (CIFS)**: Legacy protocol (Windows NT/2000/XP)
//! - **SMB2**: Modern protocol (Vista+)
//! - **SMB3**: Secure protocol (Windows 8+)
//!
//! Protocol features:
//! - File and print sharing
//! - Named pipes (IPC$)
//! - Authentication (NTLM, Kerberos)
//! - Compound requests
//! - Opportunistic locking (oplocks)
//!
//! Runs over TCP port 445 or NetBIOS port 139.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use crate::ke::SpinLock;
use crate::hal::apic::get_tick_count;

// ============================================================================
// Constants
// ============================================================================

/// SMB port (direct hosting)
pub const SMB_PORT: u16 = 445;

/// NetBIOS session port (legacy)
pub const NETBIOS_SESSION_PORT: u16 = 139;

/// Maximum sessions
pub const MAX_SMB_SESSIONS: usize = 256;

/// Maximum tree connections per session
pub const MAX_TREE_CONNECTS: usize = 32;

/// Maximum open files per session
pub const MAX_OPEN_FILES: usize = 256;

/// Maximum shares
pub const MAX_SHARES: usize = 64;

/// Maximum share name length
pub const MAX_SHARE_NAME: usize = 64;

/// Maximum path length
pub const MAX_PATH_LENGTH: usize = 260;

/// SMB1 protocol signature
pub const SMB1_SIGNATURE: [u8; 4] = [0xFF, b'S', b'M', b'B'];

/// SMB2 protocol signature
pub const SMB2_SIGNATURE: [u8; 4] = [0xFE, b'S', b'M', b'B'];

/// SMB3 encryption transform signature
pub const SMB3_TRANSFORM_SIGNATURE: [u8; 4] = [0xFD, b'S', b'M', b'B'];

/// SMB header size
pub const SMB1_HEADER_SIZE: usize = 32;
pub const SMB2_HEADER_SIZE: usize = 64;

// ============================================================================
// SMB Commands
// ============================================================================

/// SMB1 commands
pub mod smb1_command {
    pub const SMB_COM_CREATE_DIRECTORY: u8 = 0x00;
    pub const SMB_COM_DELETE_DIRECTORY: u8 = 0x01;
    pub const SMB_COM_OPEN: u8 = 0x02;
    pub const SMB_COM_CREATE: u8 = 0x03;
    pub const SMB_COM_CLOSE: u8 = 0x04;
    pub const SMB_COM_FLUSH: u8 = 0x05;
    pub const SMB_COM_DELETE: u8 = 0x06;
    pub const SMB_COM_RENAME: u8 = 0x07;
    pub const SMB_COM_QUERY_INFORMATION: u8 = 0x08;
    pub const SMB_COM_SET_INFORMATION: u8 = 0x09;
    pub const SMB_COM_READ: u8 = 0x0A;
    pub const SMB_COM_WRITE: u8 = 0x0B;
    pub const SMB_COM_LOCK_BYTE_RANGE: u8 = 0x0C;
    pub const SMB_COM_UNLOCK_BYTE_RANGE: u8 = 0x0D;
    pub const SMB_COM_CREATE_TEMPORARY: u8 = 0x0E;
    pub const SMB_COM_CREATE_NEW: u8 = 0x0F;
    pub const SMB_COM_CHECK_DIRECTORY: u8 = 0x10;
    pub const SMB_COM_NEGOTIATE: u8 = 0x72;
    pub const SMB_COM_SESSION_SETUP_ANDX: u8 = 0x73;
    pub const SMB_COM_LOGOFF_ANDX: u8 = 0x74;
    pub const SMB_COM_TREE_CONNECT_ANDX: u8 = 0x75;
    pub const SMB_COM_TREE_DISCONNECT: u8 = 0x71;
    pub const SMB_COM_NT_CREATE_ANDX: u8 = 0xA2;
    pub const SMB_COM_NT_TRANSACT: u8 = 0xA0;
    pub const SMB_COM_TRANSACTION2: u8 = 0x32;
    pub const SMB_COM_TRANSACTION: u8 = 0x25;
    pub const SMB_COM_ECHO: u8 = 0x2B;
}

/// SMB2 commands
pub mod smb2_command {
    pub const SMB2_NEGOTIATE: u16 = 0x0000;
    pub const SMB2_SESSION_SETUP: u16 = 0x0001;
    pub const SMB2_LOGOFF: u16 = 0x0002;
    pub const SMB2_TREE_CONNECT: u16 = 0x0003;
    pub const SMB2_TREE_DISCONNECT: u16 = 0x0004;
    pub const SMB2_CREATE: u16 = 0x0005;
    pub const SMB2_CLOSE: u16 = 0x0006;
    pub const SMB2_FLUSH: u16 = 0x0007;
    pub const SMB2_READ: u16 = 0x0008;
    pub const SMB2_WRITE: u16 = 0x0009;
    pub const SMB2_LOCK: u16 = 0x000A;
    pub const SMB2_IOCTL: u16 = 0x000B;
    pub const SMB2_CANCEL: u16 = 0x000C;
    pub const SMB2_ECHO: u16 = 0x000D;
    pub const SMB2_QUERY_DIRECTORY: u16 = 0x000E;
    pub const SMB2_CHANGE_NOTIFY: u16 = 0x000F;
    pub const SMB2_QUERY_INFO: u16 = 0x0010;
    pub const SMB2_SET_INFO: u16 = 0x0011;
    pub const SMB2_OPLOCK_BREAK: u16 = 0x0012;
}

// ============================================================================
// Error Types
// ============================================================================

/// SMB error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SmbError {
    /// Success
    Success = 0,
    /// Invalid parameter
    InvalidParameter = 0xC000000D,
    /// Access denied
    AccessDenied = 0xC0000022,
    /// Object not found
    ObjectNotFound = 0xC0000034,
    /// Bad network name
    BadNetworkName = 0xC00000CC,
    /// Network name deleted
    NetworkNameDeleted = 0xC00000C9,
    /// User session deleted
    UserSessionDeleted = 0xC0000203,
    /// Invalid session
    InvalidSession = 0xC0000204,
    /// Invalid tree connect
    InvalidTreeConnect = 0xC000007E,
    /// File is a directory
    FileIsDirectory = 0xC00000BA,
    /// Not a directory
    NotADirectory = 0xC0000103,
    /// File closed
    FileClosed = 0xC0000128,
    /// Sharing violation
    SharingViolation = 0xC0000043,
    /// Lock conflict
    LockConflict = 0xC0000054,
    /// End of file
    EndOfFile = 0xC0000011,
    /// Disk full
    DiskFull = 0xC000007F,
    /// Buffer overflow
    BufferOverflow = 0x80000005,
    /// No more files
    NoMoreFiles = 0x80000006,
    /// Not initialized
    NotInitialized = 0xC0000001,
    /// Insufficient resources
    InsufficientResources = 0xC000009A,
    /// Invalid SMB
    InvalidSmb = 0xC00000F0,
}

/// NT status codes for SMB
pub mod nt_status {
    pub const STATUS_SUCCESS: u32 = 0x00000000;
    pub const STATUS_BUFFER_OVERFLOW: u32 = 0x80000005;
    pub const STATUS_NO_MORE_FILES: u32 = 0x80000006;
    pub const STATUS_INVALID_PARAMETER: u32 = 0xC000000D;
    pub const STATUS_NO_SUCH_FILE: u32 = 0xC000000F;
    pub const STATUS_END_OF_FILE: u32 = 0xC0000011;
    pub const STATUS_ACCESS_DENIED: u32 = 0xC0000022;
    pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC0000034;
    pub const STATUS_SHARING_VIOLATION: u32 = 0xC0000043;
    pub const STATUS_LOCK_NOT_GRANTED: u32 = 0xC0000054;
    pub const STATUS_BAD_NETWORK_NAME: u32 = 0xC00000CC;
}

// ============================================================================
// SMB Protocol Versions
// ============================================================================

/// SMB dialect/version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SmbDialect {
    /// SMB 1.0 (CIFS)
    Smb1 = 0x0000,
    /// SMB 2.0.2
    Smb202 = 0x0202,
    /// SMB 2.1
    Smb21 = 0x0210,
    /// SMB 3.0
    Smb30 = 0x0300,
    /// SMB 3.0.2
    Smb302 = 0x0302,
    /// SMB 3.1.1
    Smb311 = 0x0311,
    /// Wildcard (negotiate)
    Wildcard = 0x02FF,
}

// ============================================================================
// Data Structures
// ============================================================================

/// SMB session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionState {
    /// Not established
    NotEstablished = 0,
    /// In progress
    InProgress = 1,
    /// Valid
    Valid = 2,
    /// Expired
    Expired = 3,
}

/// SMB tree connect type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TreeConnectType {
    /// Disk share
    Disk = 0,
    /// Named pipe (IPC$)
    Pipe = 1,
    /// Print share
    Print = 2,
}

/// SMB session
#[derive(Debug, Clone)]
pub struct SmbSession {
    /// Session in use
    pub in_use: bool,
    /// Session ID
    pub session_id: u64,
    /// Session state
    pub state: SessionState,
    /// Negotiated dialect
    pub dialect: SmbDialect,
    /// User ID (UID for SMB1)
    pub uid: u16,
    /// Username
    pub username: [u8; 64],
    pub username_len: usize,
    /// Domain
    pub domain: [u8; 64],
    pub domain_len: usize,
    /// Session key
    pub session_key: [u8; 16],
    /// Session key valid
    pub session_key_valid: bool,
    /// Signing required
    pub signing_required: bool,
    /// Encryption required
    pub encryption_required: bool,
    /// Creation time
    pub creation_time: u64,
    /// Last activity
    pub last_activity: u64,
    /// Tree connects for this session
    pub tree_connects: [TreeConnect; MAX_TREE_CONNECTS],
    pub tree_connect_count: usize,
}

impl SmbSession {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            session_id: 0,
            state: SessionState::NotEstablished,
            dialect: SmbDialect::Smb1,
            uid: 0,
            username: [0u8; 64],
            username_len: 0,
            domain: [0u8; 64],
            domain_len: 0,
            session_key: [0u8; 16],
            session_key_valid: false,
            signing_required: false,
            encryption_required: false,
            creation_time: 0,
            last_activity: 0,
            tree_connects: [const { TreeConnect::empty() }; MAX_TREE_CONNECTS],
            tree_connect_count: 0,
        }
    }
}

/// Tree connect (share mapping)
#[derive(Debug, Clone)]
pub struct TreeConnect {
    /// Tree connect in use
    pub in_use: bool,
    /// Tree ID
    pub tree_id: u32,
    /// Share name
    pub share_name: [u8; MAX_SHARE_NAME],
    pub share_name_len: usize,
    /// Share type
    pub share_type: TreeConnectType,
    /// Access mask granted
    pub access_mask: u32,
    /// Creation time
    pub creation_time: u64,
}

impl TreeConnect {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            tree_id: 0,
            share_name: [0u8; MAX_SHARE_NAME],
            share_name_len: 0,
            share_type: TreeConnectType::Disk,
            access_mask: 0,
            creation_time: 0,
        }
    }
}

/// SMB share definition
#[derive(Debug, Clone)]
pub struct SmbShare {
    /// Share in use
    pub in_use: bool,
    /// Share name
    pub name: [u8; MAX_SHARE_NAME],
    pub name_len: usize,
    /// Local path
    pub path: [u8; MAX_PATH_LENGTH],
    pub path_len: usize,
    /// Share type
    pub share_type: TreeConnectType,
    /// Comment/description
    pub comment: [u8; 128],
    pub comment_len: usize,
    /// Maximum connections (0 = unlimited)
    pub max_connections: u32,
    /// Current connections
    pub current_connections: u32,
    /// Share flags
    pub flags: u32,
}

impl SmbShare {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            name: [0u8; MAX_SHARE_NAME],
            name_len: 0,
            path: [0u8; MAX_PATH_LENGTH],
            path_len: 0,
            share_type: TreeConnectType::Disk,
            comment: [0u8; 128],
            comment_len: 0,
            max_connections: 0,
            current_connections: 0,
            flags: 0,
        }
    }
}

/// Share flags
pub mod share_flags {
    /// Share is hidden (ends with $)
    pub const SHARE_HIDDEN: u32 = 0x00000001;
    /// Read-only share
    pub const SHARE_READONLY: u32 = 0x00000002;
    /// Guest access allowed
    pub const SHARE_GUEST_OK: u32 = 0x00000004;
    /// Share is temporary
    pub const SHARE_TEMPORARY: u32 = 0x00000008;
    /// DFS root
    pub const SHARE_DFS: u32 = 0x00000010;
}

/// SMB open file handle
#[derive(Debug, Clone)]
pub struct SmbFileHandle {
    /// Handle in use
    pub in_use: bool,
    /// File ID
    pub file_id: u64,
    /// Session ID
    pub session_id: u64,
    /// Tree ID
    pub tree_id: u32,
    /// File path
    pub path: [u8; MAX_PATH_LENGTH],
    pub path_len: usize,
    /// Access mask
    pub access_mask: u32,
    /// Share access
    pub share_access: u32,
    /// Create disposition
    pub create_disposition: u32,
    /// File attributes
    pub file_attributes: u32,
    /// Is directory
    pub is_directory: bool,
    /// Current position
    pub position: u64,
    /// Oplock level
    pub oplock_level: u8,
    /// Creation time
    pub creation_time: u64,
    /// Last access time
    pub last_access: u64,
}

impl SmbFileHandle {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            file_id: 0,
            session_id: 0,
            tree_id: 0,
            path: [0u8; MAX_PATH_LENGTH],
            path_len: 0,
            access_mask: 0,
            share_access: 0,
            create_disposition: 0,
            file_attributes: 0,
            is_directory: false,
            position: 0,
            oplock_level: 0,
            creation_time: 0,
            last_access: 0,
        }
    }
}

/// Access mask flags
pub mod access_mask {
    pub const FILE_READ_DATA: u32 = 0x00000001;
    pub const FILE_WRITE_DATA: u32 = 0x00000002;
    pub const FILE_APPEND_DATA: u32 = 0x00000004;
    pub const FILE_READ_EA: u32 = 0x00000008;
    pub const FILE_WRITE_EA: u32 = 0x00000010;
    pub const FILE_EXECUTE: u32 = 0x00000020;
    pub const FILE_DELETE_CHILD: u32 = 0x00000040;
    pub const FILE_READ_ATTRIBUTES: u32 = 0x00000080;
    pub const FILE_WRITE_ATTRIBUTES: u32 = 0x00000100;
    pub const DELETE: u32 = 0x00010000;
    pub const READ_CONTROL: u32 = 0x00020000;
    pub const WRITE_DAC: u32 = 0x00040000;
    pub const WRITE_OWNER: u32 = 0x00080000;
    pub const SYNCHRONIZE: u32 = 0x00100000;
    pub const GENERIC_ALL: u32 = 0x10000000;
    pub const GENERIC_EXECUTE: u32 = 0x20000000;
    pub const GENERIC_WRITE: u32 = 0x40000000;
    pub const GENERIC_READ: u32 = 0x80000000;
}

/// Share access flags
pub mod share_access {
    pub const FILE_SHARE_READ: u32 = 0x00000001;
    pub const FILE_SHARE_WRITE: u32 = 0x00000002;
    pub const FILE_SHARE_DELETE: u32 = 0x00000004;
}

/// Oplock levels
pub mod oplock_level {
    pub const OPLOCK_LEVEL_NONE: u8 = 0x00;
    pub const OPLOCK_LEVEL_II: u8 = 0x01;
    pub const OPLOCK_LEVEL_EXCLUSIVE: u8 = 0x08;
    pub const OPLOCK_LEVEL_BATCH: u8 = 0x09;
    pub const OPLOCK_LEVEL_LEASE: u8 = 0xFF;
}

/// SMB server configuration
#[derive(Debug, Clone)]
pub struct SmbConfig {
    /// Server name
    pub server_name: [u8; 64],
    pub server_name_len: usize,
    /// Domain/workgroup
    pub domain: [u8; 64],
    pub domain_len: usize,
    /// Allow SMB1
    pub allow_smb1: bool,
    /// Allow SMB2
    pub allow_smb2: bool,
    /// Allow SMB3
    pub allow_smb3: bool,
    /// Require signing
    pub require_signing: bool,
    /// Require encryption (SMB3)
    pub require_encryption: bool,
    /// Allow guest access
    pub allow_guest: bool,
    /// Maximum message size
    pub max_transact_size: u32,
    /// Maximum read size
    pub max_read_size: u32,
    /// Maximum write size
    pub max_write_size: u32,
}

impl SmbConfig {
    pub const fn new() -> Self {
        Self {
            server_name: [0u8; 64],
            server_name_len: 0,
            domain: [0u8; 64],
            domain_len: 0,
            allow_smb1: true,
            allow_smb2: true,
            allow_smb3: true,
            require_signing: false,
            require_encryption: false,
            allow_guest: false,
            max_transact_size: 65536,
            max_read_size: 65536,
            max_write_size: 65536,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// SMB server state
struct SmbState {
    /// Initialized flag
    initialized: bool,
    /// Configuration
    config: SmbConfig,
    /// Active sessions
    sessions: [SmbSession; MAX_SMB_SESSIONS],
    session_count: usize,
    /// Defined shares
    shares: [SmbShare; MAX_SHARES],
    share_count: usize,
    /// Open file handles
    file_handles: [SmbFileHandle; MAX_OPEN_FILES],
    file_handle_count: usize,
    /// Next session ID
    next_session_id: u64,
    /// Next tree ID
    next_tree_id: u32,
    /// Next file ID
    next_file_id: u64,
}

impl SmbState {
    const fn new() -> Self {
        Self {
            initialized: false,
            config: SmbConfig::new(),
            sessions: [const { SmbSession::empty() }; MAX_SMB_SESSIONS],
            session_count: 0,
            shares: [const { SmbShare::empty() }; MAX_SHARES],
            share_count: 0,
            file_handles: [const { SmbFileHandle::empty() }; MAX_OPEN_FILES],
            file_handle_count: 0,
            next_session_id: 1,
            next_tree_id: 1,
            next_file_id: 1,
        }
    }
}

static SMB_STATE: SpinLock<SmbState> = SpinLock::new(SmbState::new());

/// SMB statistics
struct SmbStats {
    /// Negotiate requests
    negotiate_requests: AtomicU64,
    /// Session setup requests
    session_setup_requests: AtomicU64,
    /// Tree connect requests
    tree_connect_requests: AtomicU64,
    /// Create/open requests
    create_requests: AtomicU64,
    /// Read requests
    read_requests: AtomicU64,
    /// Write requests
    write_requests: AtomicU64,
    /// Close requests
    close_requests: AtomicU64,
    /// Bytes read
    bytes_read: AtomicU64,
    /// Bytes written
    bytes_written: AtomicU64,
    /// Failed requests
    failed_requests: AtomicU64,
}

static SMB_STATS: SmbStats = SmbStats {
    negotiate_requests: AtomicU64::new(0),
    session_setup_requests: AtomicU64::new(0),
    tree_connect_requests: AtomicU64::new(0),
    create_requests: AtomicU64::new(0),
    read_requests: AtomicU64::new(0),
    write_requests: AtomicU64::new(0),
    close_requests: AtomicU64::new(0),
    bytes_read: AtomicU64::new(0),
    bytes_written: AtomicU64::new(0),
    failed_requests: AtomicU64::new(0),
};

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the SMB subsystem
pub fn init() {
    crate::serial_println!("[SMB] Initializing Server Message Block protocol...");

    let mut state = SMB_STATE.lock();

    if state.initialized {
        crate::serial_println!("[SMB] Already initialized");
        return;
    }

    // Set default configuration
    let server = b"NOSTALGOS";
    state.config.server_name[..server.len()].copy_from_slice(server);
    state.config.server_name_len = server.len();

    let domain = b"WORKGROUP";
    state.config.domain[..domain.len()].copy_from_slice(domain);
    state.config.domain_len = domain.len();

    // Create default shares
    create_default_shares(&mut state);

    state.initialized = true;

    crate::serial_println!("[SMB] Server Message Block initialized");
}

fn create_default_shares(state: &mut SmbState) {
    // IPC$ share (named pipes)
    if state.share_count < MAX_SHARES {
        let share = &mut state.shares[state.share_count];
        share.in_use = true;

        let name = b"IPC$";
        share.name[..name.len()].copy_from_slice(name);
        share.name_len = name.len();

        share.share_type = TreeConnectType::Pipe;

        let comment = b"Remote IPC";
        share.comment[..comment.len()].copy_from_slice(comment);
        share.comment_len = comment.len();

        share.flags = share_flags::SHARE_HIDDEN;

        state.share_count += 1;
    }

    // ADMIN$ share (admin share)
    if state.share_count < MAX_SHARES {
        let share = &mut state.shares[state.share_count];
        share.in_use = true;

        let name = b"ADMIN$";
        share.name[..name.len()].copy_from_slice(name);
        share.name_len = name.len();

        let path = b"\\Windows";
        share.path[..path.len()].copy_from_slice(path);
        share.path_len = path.len();

        share.share_type = TreeConnectType::Disk;

        let comment = b"Remote Admin";
        share.comment[..comment.len()].copy_from_slice(comment);
        share.comment_len = comment.len();

        share.flags = share_flags::SHARE_HIDDEN;

        state.share_count += 1;
    }

    // C$ share (default drive share)
    if state.share_count < MAX_SHARES {
        let share = &mut state.shares[state.share_count];
        share.in_use = true;

        let name = b"C$";
        share.name[..name.len()].copy_from_slice(name);
        share.name_len = name.len();

        let path = b"C:\\";
        share.path[..path.len()].copy_from_slice(path);
        share.path_len = path.len();

        share.share_type = TreeConnectType::Disk;

        let comment = b"Default share";
        share.comment[..comment.len()].copy_from_slice(comment);
        share.comment_len = comment.len();

        share.flags = share_flags::SHARE_HIDDEN;

        state.share_count += 1;
    }

    crate::serial_println!("[SMB] Created {} default shares", state.share_count);
}

// ============================================================================
// Share Management
// ============================================================================

/// Create a new share
pub fn smb_create_share(
    name: &[u8],
    path: &[u8],
    share_type: TreeConnectType,
    comment: &[u8],
) -> Result<(), SmbError> {
    let mut state = SMB_STATE.lock();

    if !state.initialized {
        return Err(SmbError::NotInitialized);
    }

    if name.len() > MAX_SHARE_NAME || path.len() > MAX_PATH_LENGTH {
        return Err(SmbError::InvalidParameter);
    }

    // Check if exists
    for i in 0..MAX_SHARES {
        if state.shares[i].in_use {
            let sname = &state.shares[i].name[..state.shares[i].name_len];
            if sname == name {
                return Err(SmbError::InvalidParameter);
            }
        }
    }

    if state.share_count >= MAX_SHARES {
        return Err(SmbError::InsufficientResources);
    }

    for i in 0..MAX_SHARES {
        if !state.shares[i].in_use {
            let share = &mut state.shares[i];
            share.in_use = true;

            share.name[..name.len()].copy_from_slice(name);
            share.name_len = name.len();

            share.path[..path.len()].copy_from_slice(path);
            share.path_len = path.len();

            share.share_type = share_type;

            let clen = comment.len().min(128);
            share.comment[..clen].copy_from_slice(&comment[..clen]);
            share.comment_len = clen;

            state.share_count += 1;
            return Ok(());
        }
    }

    Err(SmbError::InsufficientResources)
}

/// Delete a share
pub fn smb_delete_share(name: &[u8]) -> Result<(), SmbError> {
    let mut state = SMB_STATE.lock();

    if !state.initialized {
        return Err(SmbError::NotInitialized);
    }

    for i in 0..MAX_SHARES {
        if state.shares[i].in_use {
            let sname = &state.shares[i].name[..state.shares[i].name_len];
            if sname == name {
                state.shares[i] = SmbShare::empty();
                if state.share_count > 0 {
                    state.share_count -= 1;
                }
                return Ok(());
            }
        }
    }

    Err(SmbError::ObjectNotFound)
}

/// Enumerate shares
pub fn smb_enumerate_shares() -> Vec<SmbShare> {
    let state = SMB_STATE.lock();
    let mut shares = Vec::new();

    if !state.initialized {
        return shares;
    }

    for i in 0..MAX_SHARES {
        if state.shares[i].in_use {
            shares.push(state.shares[i].clone());
        }
    }

    shares
}

// ============================================================================
// Session Management
// ============================================================================

/// Create a new SMB session
pub fn smb_create_session(dialect: SmbDialect) -> Result<u64, SmbError> {
    let mut state = SMB_STATE.lock();

    if !state.initialized {
        return Err(SmbError::NotInitialized);
    }

    if state.session_count >= MAX_SMB_SESSIONS {
        return Err(SmbError::InsufficientResources);
    }

    let session_id = state.next_session_id;
    state.next_session_id += 1;

    for i in 0..MAX_SMB_SESSIONS {
        if !state.sessions[i].in_use {
            state.sessions[i].in_use = true;
            state.sessions[i].session_id = session_id;
            state.sessions[i].state = SessionState::InProgress;
            state.sessions[i].dialect = dialect;
            state.sessions[i].creation_time = get_tick_count();
            state.sessions[i].last_activity = state.sessions[i].creation_time;

            state.session_count += 1;
            SMB_STATS.session_setup_requests.fetch_add(1, Ordering::Relaxed);

            return Ok(session_id);
        }
    }

    Err(SmbError::InsufficientResources)
}

/// Complete session setup
pub fn smb_complete_session(
    session_id: u64,
    username: &[u8],
    domain: &[u8],
) -> Result<(), SmbError> {
    let mut state = SMB_STATE.lock();

    if !state.initialized {
        return Err(SmbError::NotInitialized);
    }

    for i in 0..MAX_SMB_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            let ulen = username.len().min(64);
            state.sessions[i].username[..ulen].copy_from_slice(&username[..ulen]);
            state.sessions[i].username_len = ulen;

            let dlen = domain.len().min(64);
            state.sessions[i].domain[..dlen].copy_from_slice(&domain[..dlen]);
            state.sessions[i].domain_len = dlen;

            state.sessions[i].state = SessionState::Valid;
            state.sessions[i].last_activity = get_tick_count();

            return Ok(());
        }
    }

    Err(SmbError::InvalidSession)
}

/// Delete a session
pub fn smb_delete_session(session_id: u64) -> Result<(), SmbError> {
    let mut state = SMB_STATE.lock();

    if !state.initialized {
        return Err(SmbError::NotInitialized);
    }

    for i in 0..MAX_SMB_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            state.sessions[i] = SmbSession::empty();
            if state.session_count > 0 {
                state.session_count -= 1;
            }
            return Ok(());
        }
    }

    Err(SmbError::InvalidSession)
}

// ============================================================================
// Tree Connect
// ============================================================================

/// Connect to a share (tree connect)
pub fn smb_tree_connect(session_id: u64, share_name: &[u8]) -> Result<u32, SmbError> {
    let mut state = SMB_STATE.lock();

    if !state.initialized {
        return Err(SmbError::NotInitialized);
    }

    SMB_STATS.tree_connect_requests.fetch_add(1, Ordering::Relaxed);

    // Find share
    let mut share_idx = None;
    for i in 0..MAX_SHARES {
        if state.shares[i].in_use {
            let name = &state.shares[i].name[..state.shares[i].name_len];
            if name == share_name {
                share_idx = Some(i);
                break;
            }
        }
    }

    let share_idx = match share_idx {
        Some(idx) => idx,
        None => {
            SMB_STATS.failed_requests.fetch_add(1, Ordering::Relaxed);
            return Err(SmbError::BadNetworkName);
        }
    };

    let share_type = state.shares[share_idx].share_type;
    let share_name_copy = state.shares[share_idx].name;
    let share_name_len = state.shares[share_idx].name_len;

    // Find session
    for i in 0..MAX_SMB_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            if state.sessions[i].state != SessionState::Valid {
                SMB_STATS.failed_requests.fetch_add(1, Ordering::Relaxed);
                return Err(SmbError::InvalidSession);
            }

            if state.sessions[i].tree_connect_count >= MAX_TREE_CONNECTS {
                return Err(SmbError::InsufficientResources);
            }

            let tree_id = state.next_tree_id;
            state.next_tree_id += 1;

            // Find free slot
            for j in 0..MAX_TREE_CONNECTS {
                if !state.sessions[i].tree_connects[j].in_use {
                    let tc = &mut state.sessions[i].tree_connects[j];
                    tc.in_use = true;
                    tc.tree_id = tree_id;
                    tc.share_name[..share_name_len].copy_from_slice(&share_name_copy[..share_name_len]);
                    tc.share_name_len = share_name_len;
                    tc.share_type = share_type;
                    tc.creation_time = get_tick_count();
                    tc.access_mask = access_mask::GENERIC_READ | access_mask::GENERIC_WRITE;

                    state.sessions[i].tree_connect_count += 1;

                    // Update share connection count
                    state.shares[share_idx].current_connections += 1;

                    return Ok(tree_id);
                }
            }

            return Err(SmbError::InsufficientResources);
        }
    }

    SMB_STATS.failed_requests.fetch_add(1, Ordering::Relaxed);
    Err(SmbError::InvalidSession)
}

/// Disconnect from a share
pub fn smb_tree_disconnect(session_id: u64, tree_id: u32) -> Result<(), SmbError> {
    let mut state = SMB_STATE.lock();

    if !state.initialized {
        return Err(SmbError::NotInitialized);
    }

    for i in 0..MAX_SMB_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            for j in 0..MAX_TREE_CONNECTS {
                if state.sessions[i].tree_connects[j].in_use
                    && state.sessions[i].tree_connects[j].tree_id == tree_id
                {
                    state.sessions[i].tree_connects[j] = TreeConnect::empty();
                    if state.sessions[i].tree_connect_count > 0 {
                        state.sessions[i].tree_connect_count -= 1;
                    }
                    return Ok(());
                }
            }
            return Err(SmbError::InvalidTreeConnect);
        }
    }

    Err(SmbError::InvalidSession)
}

// ============================================================================
// File Operations
// ============================================================================

/// Open/create a file
pub fn smb_create(
    session_id: u64,
    tree_id: u32,
    path: &[u8],
    desired_access: u32,
    share_access_flags: u32,
    is_directory: bool,
) -> Result<u64, SmbError> {
    let mut state = SMB_STATE.lock();

    if !state.initialized {
        return Err(SmbError::NotInitialized);
    }

    SMB_STATS.create_requests.fetch_add(1, Ordering::Relaxed);

    if path.len() > MAX_PATH_LENGTH {
        return Err(SmbError::InvalidParameter);
    }

    // Validate session and tree
    let mut session_valid = false;
    for i in 0..MAX_SMB_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            if state.sessions[i].state != SessionState::Valid {
                return Err(SmbError::InvalidSession);
            }
            for j in 0..MAX_TREE_CONNECTS {
                if state.sessions[i].tree_connects[j].in_use
                    && state.sessions[i].tree_connects[j].tree_id == tree_id
                {
                    session_valid = true;
                    break;
                }
            }
            break;
        }
    }

    if !session_valid {
        SMB_STATS.failed_requests.fetch_add(1, Ordering::Relaxed);
        return Err(SmbError::InvalidTreeConnect);
    }

    if state.file_handle_count >= MAX_OPEN_FILES {
        return Err(SmbError::InsufficientResources);
    }

    let file_id = state.next_file_id;
    state.next_file_id += 1;

    for i in 0..MAX_OPEN_FILES {
        if !state.file_handles[i].in_use {
            let handle = &mut state.file_handles[i];
            handle.in_use = true;
            handle.file_id = file_id;
            handle.session_id = session_id;
            handle.tree_id = tree_id;
            handle.path[..path.len()].copy_from_slice(path);
            handle.path_len = path.len();
            handle.access_mask = desired_access;
            handle.share_access = share_access_flags;
            handle.is_directory = is_directory;
            handle.creation_time = get_tick_count();
            handle.last_access = handle.creation_time;

            state.file_handle_count += 1;

            return Ok(file_id);
        }
    }

    Err(SmbError::InsufficientResources)
}

/// Close a file
pub fn smb_close(session_id: u64, file_id: u64) -> Result<(), SmbError> {
    let mut state = SMB_STATE.lock();

    if !state.initialized {
        return Err(SmbError::NotInitialized);
    }

    SMB_STATS.close_requests.fetch_add(1, Ordering::Relaxed);

    for i in 0..MAX_OPEN_FILES {
        if state.file_handles[i].in_use
            && state.file_handles[i].file_id == file_id
            && state.file_handles[i].session_id == session_id
        {
            state.file_handles[i] = SmbFileHandle::empty();
            if state.file_handle_count > 0 {
                state.file_handle_count -= 1;
            }
            return Ok(());
        }
    }

    Err(SmbError::FileClosed)
}

/// Read from a file
pub fn smb_read(
    session_id: u64,
    file_id: u64,
    offset: u64,
    length: u32,
) -> Result<Vec<u8>, SmbError> {
    let mut state = SMB_STATE.lock();

    if !state.initialized {
        return Err(SmbError::NotInitialized);
    }

    SMB_STATS.read_requests.fetch_add(1, Ordering::Relaxed);

    for i in 0..MAX_OPEN_FILES {
        if state.file_handles[i].in_use
            && state.file_handles[i].file_id == file_id
            && state.file_handles[i].session_id == session_id
        {
            // Check access
            if state.file_handles[i].access_mask & access_mask::FILE_READ_DATA == 0 {
                SMB_STATS.failed_requests.fetch_add(1, Ordering::Relaxed);
                return Err(SmbError::AccessDenied);
            }

            state.file_handles[i].last_access = get_tick_count();
            state.file_handles[i].position = offset + length as u64;

            // In a real implementation, this would read from the actual file
            // For now, return placeholder data
            let data = vec![0u8; length as usize];
            SMB_STATS.bytes_read.fetch_add(length as u64, Ordering::Relaxed);

            return Ok(data);
        }
    }

    SMB_STATS.failed_requests.fetch_add(1, Ordering::Relaxed);
    Err(SmbError::FileClosed)
}

/// Write to a file
pub fn smb_write(
    session_id: u64,
    file_id: u64,
    offset: u64,
    data: &[u8],
) -> Result<u32, SmbError> {
    let mut state = SMB_STATE.lock();

    if !state.initialized {
        return Err(SmbError::NotInitialized);
    }

    SMB_STATS.write_requests.fetch_add(1, Ordering::Relaxed);

    for i in 0..MAX_OPEN_FILES {
        if state.file_handles[i].in_use
            && state.file_handles[i].file_id == file_id
            && state.file_handles[i].session_id == session_id
        {
            // Check access
            if state.file_handles[i].access_mask & access_mask::FILE_WRITE_DATA == 0 {
                SMB_STATS.failed_requests.fetch_add(1, Ordering::Relaxed);
                return Err(SmbError::AccessDenied);
            }

            state.file_handles[i].last_access = get_tick_count();
            state.file_handles[i].position = offset + data.len() as u64;

            // In a real implementation, this would write to the actual file
            let written = data.len() as u32;
            SMB_STATS.bytes_written.fetch_add(written as u64, Ordering::Relaxed);

            return Ok(written);
        }
    }

    SMB_STATS.failed_requests.fetch_add(1, Ordering::Relaxed);
    Err(SmbError::FileClosed)
}

// ============================================================================
// Statistics
// ============================================================================

/// SMB statistics snapshot
#[derive(Debug, Clone, Default)]
pub struct SmbStatsSnapshot {
    pub negotiate_requests: u64,
    pub session_setup_requests: u64,
    pub tree_connect_requests: u64,
    pub create_requests: u64,
    pub read_requests: u64,
    pub write_requests: u64,
    pub close_requests: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub failed_requests: u64,
    pub active_sessions: usize,
    pub active_shares: usize,
    pub open_files: usize,
}

/// Get SMB statistics
pub fn smb_get_stats() -> SmbStatsSnapshot {
    let state = SMB_STATE.lock();

    SmbStatsSnapshot {
        negotiate_requests: SMB_STATS.negotiate_requests.load(Ordering::Relaxed),
        session_setup_requests: SMB_STATS.session_setup_requests.load(Ordering::Relaxed),
        tree_connect_requests: SMB_STATS.tree_connect_requests.load(Ordering::Relaxed),
        create_requests: SMB_STATS.create_requests.load(Ordering::Relaxed),
        read_requests: SMB_STATS.read_requests.load(Ordering::Relaxed),
        write_requests: SMB_STATS.write_requests.load(Ordering::Relaxed),
        close_requests: SMB_STATS.close_requests.load(Ordering::Relaxed),
        bytes_read: SMB_STATS.bytes_read.load(Ordering::Relaxed),
        bytes_written: SMB_STATS.bytes_written.load(Ordering::Relaxed),
        failed_requests: SMB_STATS.failed_requests.load(Ordering::Relaxed),
        active_sessions: state.session_count,
        active_shares: state.share_count,
        open_files: state.file_handle_count,
    }
}

/// Check if SMB is initialized
pub fn smb_is_initialized() -> bool {
    SMB_STATE.lock().initialized
}

/// Get dialect name
pub fn dialect_name(dialect: SmbDialect) -> &'static str {
    match dialect {
        SmbDialect::Smb1 => "SMB 1.0 (CIFS)",
        SmbDialect::Smb202 => "SMB 2.0.2",
        SmbDialect::Smb21 => "SMB 2.1",
        SmbDialect::Smb30 => "SMB 3.0",
        SmbDialect::Smb302 => "SMB 3.0.2",
        SmbDialect::Smb311 => "SMB 3.1.1",
        SmbDialect::Wildcard => "SMB2 Wildcard",
    }
}

/// Get share type name
pub fn share_type_name(share_type: TreeConnectType) -> &'static str {
    match share_type {
        TreeConnectType::Disk => "Disk",
        TreeConnectType::Pipe => "IPC (Pipe)",
        TreeConnectType::Print => "Printer",
    }
}
