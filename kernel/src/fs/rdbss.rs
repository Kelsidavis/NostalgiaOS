//! RDBSS - Redirected Drive Buffering Subsystem
//!
//! RDBSS provides the common buffering layer for network mini-redirectors.
//! It manages file control blocks, server connections, and I/O buffering
//! for network file systems like SMB.
//!
//! Key data structures:
//! - SRV_CALL: Server connection context
//! - NET_ROOT: Share/export on a server
//! - V_NET_ROOT: Virtual view of a net root (per-user)
//! - FCB: File Control Block (per-file)
//! - SRV_OPEN: Server-side open context
//! - FOBX: File Object Extension
//!
//! Mini-redirectors (like mrxsmb) use RDBSS for common operations.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// Maximum mini-redirectors
const MAX_MINI_REDIRECTORS: usize = 8;

/// Maximum server calls
const MAX_SRV_CALLS: usize = 64;

/// Maximum net roots per srv_call
const MAX_NET_ROOTS: usize = 32;

/// Maximum FCBs per net root
const MAX_FCBS: usize = 256;

/// Maximum SRV_OPENs per FCB
const MAX_SRV_OPENS: usize = 8;

/// Maximum name length
const MAX_NAME_LEN: usize = 260;

// ============================================================================
// Node Types
// ============================================================================

/// RDBSS node type codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum NodeType {
    /// Unknown/invalid
    Unknown = 0x0000,
    /// Mini-redirector dispatch table
    MrxDispatch = 0xEC00,
    /// Server call context
    SrvCall = 0xEC01,
    /// Net root (share)
    NetRoot = 0xEC02,
    /// Virtual net root
    VNetRoot = 0xEC03,
    /// File Control Block
    Fcb = 0xEC04,
    /// Server-side open
    SrvOpen = 0xEC05,
    /// File object extension
    Fobx = 0xEC06,
    /// RDBSS device object
    RdbssDevice = 0xEC07,
    /// Prefix table entry
    PrefixEntry = 0xEC08,
}

// ============================================================================
// Node Header
// ============================================================================

/// Common header for RDBSS structures
#[derive(Debug, Clone, Copy)]
pub struct NodeHeader {
    /// Node type code
    pub node_type: NodeType,
    /// Node size
    pub node_size: u16,
    /// Reference count
    pub ref_count: u32,
    /// Flags
    pub flags: u32,
}

impl Default for NodeHeader {
    fn default() -> Self {
        Self {
            node_type: NodeType::Unknown,
            node_size: 0,
            ref_count: 1,
            flags: 0,
        }
    }
}

// ============================================================================
// Mini-Redirector
// ============================================================================

/// Mini-redirector state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MrxState {
    /// Not initialized
    Uninitialized,
    /// Starting up
    Starting,
    /// Active
    Active,
    /// Stopping
    Stopping,
    /// Stopped
    Stopped,
}

/// Mini-redirector registration
#[derive(Clone)]
pub struct MiniRedirector {
    /// ID
    pub id: u32,
    /// Name (e.g., "SMB")
    pub name: [u8; 64],
    /// Name length
    pub name_len: usize,
    /// Device name
    pub device_name: [u8; MAX_NAME_LEN],
    /// Device name length
    pub device_name_len: usize,
    /// State
    pub state: MrxState,
    /// Priority (lower = higher)
    pub priority: u32,
    /// Version
    pub version: u32,
    /// Capabilities
    pub capabilities: MrxCapabilities,
    /// Statistics
    pub statistics: MrxStatistics,
    /// Active flag
    pub active: bool,
}

impl Default for MiniRedirector {
    fn default() -> Self {
        Self {
            id: 0,
            name: [0; 64],
            name_len: 0,
            device_name: [0; MAX_NAME_LEN],
            device_name_len: 0,
            state: MrxState::Uninitialized,
            priority: u32::MAX,
            version: 0,
            capabilities: MrxCapabilities::default(),
            statistics: MrxStatistics::default(),
            active: false,
        }
    }
}

/// Mini-redirector capabilities
#[derive(Debug, Clone, Copy, Default)]
pub struct MrxCapabilities {
    /// Supports paging I/O
    pub paging_io: bool,
    /// Supports caching
    pub caching: bool,
    /// Supports named pipes
    pub named_pipes: bool,
    /// Supports mailslots
    pub mailslots: bool,
    /// Supports security
    pub security: bool,
    /// Supports oplocks
    pub oplocks: bool,
    /// Supports byte range locks
    pub byte_locks: bool,
    /// Supports extended attributes
    pub extended_attrs: bool,
}

/// Mini-redirector statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct MrxStatistics {
    /// Server calls
    pub srv_calls: u64,
    /// Net roots
    pub net_roots: u64,
    /// FCBs allocated
    pub fcbs: u64,
    /// SRV_OPENs
    pub srv_opens: u64,
}

// ============================================================================
// Server Call (SRV_CALL)
// ============================================================================

/// Server call state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrvCallState {
    /// Initial state
    Init,
    /// Connection in progress
    Connecting,
    /// Connected
    Connected,
    /// Connection failed
    Failed,
    /// Disconnecting
    Disconnecting,
    /// Disconnected
    Disconnected,
}

/// Server call context
#[derive(Clone)]
pub struct SrvCall {
    /// Node header
    pub header: NodeHeader,
    /// Server call ID
    pub id: u32,
    /// Server name (\\server)
    pub server_name: [u8; MAX_NAME_LEN],
    /// Server name length
    pub server_name_len: usize,
    /// Domain name
    pub domain_name: [u8; 64],
    /// Domain name length
    pub domain_name_len: usize,
    /// State
    pub state: SrvCallState,
    /// Mini-redirector ID
    pub mrx_id: u32,
    /// Net roots count
    pub net_root_count: usize,
    /// Active flag
    pub active: bool,
}

impl Default for SrvCall {
    fn default() -> Self {
        Self {
            header: NodeHeader {
                node_type: NodeType::SrvCall,
                ..NodeHeader::default()
            },
            id: 0,
            server_name: [0; MAX_NAME_LEN],
            server_name_len: 0,
            domain_name: [0; 64],
            domain_name_len: 0,
            state: SrvCallState::Init,
            mrx_id: 0,
            net_root_count: 0,
            active: false,
        }
    }
}

// ============================================================================
// Net Root (NET_ROOT)
// ============================================================================

/// Net root type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetRootType {
    /// Disk share
    Disk,
    /// Print share
    Print,
    /// Named pipe
    Pipe,
    /// Mailslot
    Mailslot,
    /// Unknown
    Unknown,
}

/// Net root state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetRootState {
    /// Initial
    Init,
    /// Constructing
    Constructing,
    /// Good
    Good,
    /// Bad
    Bad,
    /// Closing
    Closing,
}

/// Net root (share)
#[derive(Clone)]
pub struct NetRoot {
    /// Node header
    pub header: NodeHeader,
    /// Net root ID
    pub id: u32,
    /// Name (share name)
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Server call ID
    pub srv_call_id: u32,
    /// Net root type
    pub root_type: NetRootType,
    /// State
    pub state: NetRootState,
    /// FCB count
    pub fcb_count: usize,
    /// Active flag
    pub active: bool,
}

impl Default for NetRoot {
    fn default() -> Self {
        Self {
            header: NodeHeader {
                node_type: NodeType::NetRoot,
                ..NodeHeader::default()
            },
            id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            srv_call_id: 0,
            root_type: NetRootType::Unknown,
            state: NetRootState::Init,
            fcb_count: 0,
            active: false,
        }
    }
}

// ============================================================================
// File Control Block (FCB)
// ============================================================================

/// FCB state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FcbState {
    /// Initial
    Init,
    /// Good
    Good,
    /// Bad
    Bad,
    /// Orphaned
    Orphaned,
    /// Closing
    Closing,
}

/// FCB type (file/directory)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FcbType {
    /// Regular file
    File,
    /// Directory
    Directory,
    /// Unknown
    Unknown,
}

/// File Control Block
#[derive(Clone)]
pub struct Fcb {
    /// Node header
    pub header: NodeHeader,
    /// FCB ID
    pub id: u32,
    /// File name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Net root ID
    pub net_root_id: u32,
    /// FCB type
    pub fcb_type: FcbType,
    /// State
    pub state: FcbState,
    /// File size
    pub file_size: u64,
    /// Allocation size
    pub allocation_size: u64,
    /// File attributes
    pub attributes: u32,
    /// Creation time
    pub creation_time: u64,
    /// Last access time
    pub last_access_time: u64,
    /// Last write time
    pub last_write_time: u64,
    /// SRV_OPEN count
    pub srv_open_count: usize,
    /// Open count
    pub open_count: u32,
    /// Active flag
    pub active: bool,
}

impl Default for Fcb {
    fn default() -> Self {
        Self {
            header: NodeHeader {
                node_type: NodeType::Fcb,
                ..NodeHeader::default()
            },
            id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            net_root_id: 0,
            fcb_type: FcbType::Unknown,
            state: FcbState::Init,
            file_size: 0,
            allocation_size: 0,
            attributes: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            srv_open_count: 0,
            open_count: 0,
            active: false,
        }
    }
}

// ============================================================================
// Server Open (SRV_OPEN)
// ============================================================================

/// SRV_OPEN state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrvOpenState {
    /// Initial
    Init,
    /// Good
    Good,
    /// Closing
    Closing,
    /// Closed
    Closed,
}

/// Server-side open context
#[derive(Clone)]
pub struct SrvOpen {
    /// Node header
    pub header: NodeHeader,
    /// SRV_OPEN ID
    pub id: u32,
    /// FCB ID
    pub fcb_id: u32,
    /// State
    pub state: SrvOpenState,
    /// Desired access
    pub desired_access: u32,
    /// Share access
    pub share_access: u32,
    /// Create options
    pub create_options: u32,
    /// FOBX count
    pub fobx_count: u32,
    /// Server file handle (from mini-rdr)
    pub srv_handle: u64,
    /// Active flag
    pub active: bool,
}

impl Default for SrvOpen {
    fn default() -> Self {
        Self {
            header: NodeHeader {
                node_type: NodeType::SrvOpen,
                ..NodeHeader::default()
            },
            id: 0,
            fcb_id: 0,
            state: SrvOpenState::Init,
            desired_access: 0,
            share_access: 0,
            create_options: 0,
            fobx_count: 0,
            srv_handle: 0,
            active: false,
        }
    }
}

// ============================================================================
// RDBSS Statistics
// ============================================================================

/// RDBSS statistics (matches Windows RDBSS_STATISTICS)
#[derive(Debug)]
pub struct RdbssStatistics {
    /// Paging read bytes requested
    pub paging_read_bytes: AtomicU64,
    /// Non-paging read bytes requested
    pub non_paging_read_bytes: AtomicU64,
    /// Cache read bytes requested
    pub cache_read_bytes: AtomicU64,
    /// Network read bytes requested
    pub network_read_bytes: AtomicU64,
    /// Paging write bytes requested
    pub paging_write_bytes: AtomicU64,
    /// Non-paging write bytes requested
    pub non_paging_write_bytes: AtomicU64,
    /// Cache write bytes requested
    pub cache_write_bytes: AtomicU64,
    /// Network write bytes requested
    pub network_write_bytes: AtomicU64,
    /// Initially failed operations
    pub initial_failures: AtomicU32,
    /// Failed completion operations
    pub completion_failures: AtomicU32,
    /// Read operations
    pub read_ops: AtomicU32,
    /// Random read operations
    pub random_read_ops: AtomicU32,
    /// Write operations
    pub write_ops: AtomicU32,
    /// Random write operations
    pub random_write_ops: AtomicU32,
    /// Number of SRV_CALLs
    pub srv_calls: AtomicU32,
    /// Number of SRV_OPENs
    pub srv_opens: AtomicU32,
    /// Number of NET_ROOTs
    pub net_roots: AtomicU32,
    /// Number of V_NET_ROOTs
    pub v_net_roots: AtomicU32,
}

impl Default for RdbssStatistics {
    fn default() -> Self {
        Self {
            paging_read_bytes: AtomicU64::new(0),
            non_paging_read_bytes: AtomicU64::new(0),
            cache_read_bytes: AtomicU64::new(0),
            network_read_bytes: AtomicU64::new(0),
            paging_write_bytes: AtomicU64::new(0),
            non_paging_write_bytes: AtomicU64::new(0),
            cache_write_bytes: AtomicU64::new(0),
            network_write_bytes: AtomicU64::new(0),
            initial_failures: AtomicU32::new(0),
            completion_failures: AtomicU32::new(0),
            read_ops: AtomicU32::new(0),
            random_read_ops: AtomicU32::new(0),
            write_ops: AtomicU32::new(0),
            random_write_ops: AtomicU32::new(0),
            srv_calls: AtomicU32::new(0),
            srv_opens: AtomicU32::new(0),
            net_roots: AtomicU32::new(0),
            v_net_roots: AtomicU32::new(0),
        }
    }
}

// ============================================================================
// RDBSS Errors
// ============================================================================

/// RDBSS error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum RdbssError {
    /// Success
    Success = 0,
    /// Not initialized
    NotInitialized = -1,
    /// Invalid parameter
    InvalidParameter = -2,
    /// Not found
    NotFound = -3,
    /// Already exists
    AlreadyExists = -4,
    /// No more entries
    NoMoreEntries = -5,
    /// Invalid state
    InvalidState = -6,
    /// Connection failed
    ConnectionFailed = -7,
    /// Disconnected
    Disconnected = -8,
    /// Access denied
    AccessDenied = -9,
    /// Resource busy
    ResourceBusy = -10,
}

// ============================================================================
// RDBSS Global State
// ============================================================================

/// RDBSS global state
pub struct RdbssState {
    /// Mini-redirectors
    pub mini_redirectors: [MiniRedirector; MAX_MINI_REDIRECTORS],
    /// Next MRX ID
    pub next_mrx_id: u32,
    /// Server calls
    pub srv_calls: [SrvCall; MAX_SRV_CALLS],
    /// Next SRV_CALL ID
    pub next_srv_call_id: u32,
    /// Statistics
    pub statistics: RdbssStatistics,
    /// Initialized flag
    pub initialized: bool,
}

impl RdbssState {
    const fn new() -> Self {
        Self {
            mini_redirectors: [const { MiniRedirector {
                id: 0,
                name: [0; 64],
                name_len: 0,
                device_name: [0; MAX_NAME_LEN],
                device_name_len: 0,
                state: MrxState::Uninitialized,
                priority: u32::MAX,
                version: 0,
                capabilities: MrxCapabilities {
                    paging_io: false,
                    caching: false,
                    named_pipes: false,
                    mailslots: false,
                    security: false,
                    oplocks: false,
                    byte_locks: false,
                    extended_attrs: false,
                },
                statistics: MrxStatistics {
                    srv_calls: 0,
                    net_roots: 0,
                    fcbs: 0,
                    srv_opens: 0,
                },
                active: false,
            }}; MAX_MINI_REDIRECTORS],
            next_mrx_id: 1,
            srv_calls: [const { SrvCall {
                header: NodeHeader {
                    node_type: NodeType::SrvCall,
                    node_size: 0,
                    ref_count: 1,
                    flags: 0,
                },
                id: 0,
                server_name: [0; MAX_NAME_LEN],
                server_name_len: 0,
                domain_name: [0; 64],
                domain_name_len: 0,
                state: SrvCallState::Init,
                mrx_id: 0,
                net_root_count: 0,
                active: false,
            }}; MAX_SRV_CALLS],
            next_srv_call_id: 1,
            statistics: RdbssStatistics {
                paging_read_bytes: AtomicU64::new(0),
                non_paging_read_bytes: AtomicU64::new(0),
                cache_read_bytes: AtomicU64::new(0),
                network_read_bytes: AtomicU64::new(0),
                paging_write_bytes: AtomicU64::new(0),
                non_paging_write_bytes: AtomicU64::new(0),
                cache_write_bytes: AtomicU64::new(0),
                network_write_bytes: AtomicU64::new(0),
                initial_failures: AtomicU32::new(0),
                completion_failures: AtomicU32::new(0),
                read_ops: AtomicU32::new(0),
                random_read_ops: AtomicU32::new(0),
                write_ops: AtomicU32::new(0),
                random_write_ops: AtomicU32::new(0),
                srv_calls: AtomicU32::new(0),
                srv_opens: AtomicU32::new(0),
                net_roots: AtomicU32::new(0),
                v_net_roots: AtomicU32::new(0),
            },
            initialized: false,
        }
    }
}

/// Global RDBSS state
static RDBSS_STATE: SpinLock<RdbssState> = SpinLock::new(RdbssState::new());

// ============================================================================
// Mini-Redirector Registration
// ============================================================================

/// Register a mini-redirector
pub fn rdbss_register_minirdr(
    name: &str,
    device_name: &str,
    capabilities: MrxCapabilities,
) -> Result<u32, RdbssError> {
    let mut state = RDBSS_STATE.lock();

    if !state.initialized {
        return Err(RdbssError::NotInitialized);
    }

    let name_bytes = name.as_bytes();
    let device_bytes = device_name.as_bytes();

    if name_bytes.len() > 64 || device_bytes.len() > MAX_NAME_LEN {
        return Err(RdbssError::InvalidParameter);
    }

    // Find free slot
    let mut slot_idx = None;
    for idx in 0..MAX_MINI_REDIRECTORS {
        if !state.mini_redirectors[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(RdbssError::NoMoreEntries)?;

    let mrx_id = state.next_mrx_id;
    state.next_mrx_id += 1;

    state.mini_redirectors[idx].id = mrx_id;
    state.mini_redirectors[idx].name_len = name_bytes.len();
    state.mini_redirectors[idx].name[..name_bytes.len()].copy_from_slice(name_bytes);
    state.mini_redirectors[idx].device_name_len = device_bytes.len();
    state.mini_redirectors[idx].device_name[..device_bytes.len()].copy_from_slice(device_bytes);
    state.mini_redirectors[idx].capabilities = capabilities;
    state.mini_redirectors[idx].state = MrxState::Active;
    state.mini_redirectors[idx].active = true;

    crate::serial_println!("[RDBSS] Registered mini-redirector '{}'", name);

    Ok(mrx_id)
}

/// Deregister a mini-redirector
pub fn rdbss_deregister_minirdr(mrx_id: u32) -> Result<(), RdbssError> {
    let mut state = RDBSS_STATE.lock();

    if !state.initialized {
        return Err(RdbssError::NotInitialized);
    }

    for idx in 0..MAX_MINI_REDIRECTORS {
        if state.mini_redirectors[idx].active && state.mini_redirectors[idx].id == mrx_id {
            state.mini_redirectors[idx].state = MrxState::Stopped;
            state.mini_redirectors[idx].active = false;
            return Ok(());
        }
    }

    Err(RdbssError::NotFound)
}

// ============================================================================
// Server Call Operations
// ============================================================================

/// Create a server call
pub fn rx_create_srv_call(
    mrx_id: u32,
    server_name: &str,
    domain: Option<&str>,
) -> Result<u32, RdbssError> {
    let mut state = RDBSS_STATE.lock();

    if !state.initialized {
        return Err(RdbssError::NotInitialized);
    }

    let server_bytes = server_name.as_bytes();
    if server_bytes.len() > MAX_NAME_LEN {
        return Err(RdbssError::InvalidParameter);
    }

    // Verify MRX exists
    let mut mrx_found = false;
    for idx in 0..MAX_MINI_REDIRECTORS {
        if state.mini_redirectors[idx].active && state.mini_redirectors[idx].id == mrx_id {
            mrx_found = true;
            break;
        }
    }
    if !mrx_found {
        return Err(RdbssError::NotFound);
    }

    // Find free slot
    let mut slot_idx = None;
    for idx in 0..MAX_SRV_CALLS {
        if !state.srv_calls[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(RdbssError::NoMoreEntries)?;

    let srv_call_id = state.next_srv_call_id;
    state.next_srv_call_id += 1;

    state.srv_calls[idx].id = srv_call_id;
    state.srv_calls[idx].server_name_len = server_bytes.len();
    state.srv_calls[idx].server_name[..server_bytes.len()].copy_from_slice(server_bytes);
    state.srv_calls[idx].mrx_id = mrx_id;
    state.srv_calls[idx].state = SrvCallState::Connected;
    state.srv_calls[idx].active = true;

    if let Some(dom) = domain {
        let dom_bytes = dom.as_bytes();
        let len = core::cmp::min(dom_bytes.len(), 64);
        state.srv_calls[idx].domain_name_len = len;
        state.srv_calls[idx].domain_name[..len].copy_from_slice(&dom_bytes[..len]);
    }

    state.statistics.srv_calls.fetch_add(1, Ordering::Relaxed);

    Ok(srv_call_id)
}

/// Finalize a server call
pub fn rx_finalize_srv_call(srv_call_id: u32) -> Result<(), RdbssError> {
    let mut state = RDBSS_STATE.lock();

    if !state.initialized {
        return Err(RdbssError::NotInitialized);
    }

    for idx in 0..MAX_SRV_CALLS {
        if state.srv_calls[idx].active && state.srv_calls[idx].id == srv_call_id {
            if state.srv_calls[idx].net_root_count > 0 {
                return Err(RdbssError::ResourceBusy);
            }
            state.srv_calls[idx].state = SrvCallState::Disconnected;
            state.srv_calls[idx].active = false;
            state.statistics.srv_calls.fetch_sub(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(RdbssError::NotFound)
}

// ============================================================================
// Query Functions
// ============================================================================

/// List registered mini-redirectors
pub fn rdbss_list_minirdrs() -> Vec<(u32, String, MrxState)> {
    let state = RDBSS_STATE.lock();
    let mut result = Vec::new();

    for idx in 0..MAX_MINI_REDIRECTORS {
        if state.mini_redirectors[idx].active {
            let name = core::str::from_utf8(
                &state.mini_redirectors[idx].name[..state.mini_redirectors[idx].name_len],
            )
            .map(String::from)
            .unwrap_or_default();

            result.push((
                state.mini_redirectors[idx].id,
                name,
                state.mini_redirectors[idx].state,
            ));
        }
    }

    result
}

/// List server calls
pub fn rdbss_list_srv_calls() -> Vec<(u32, String, SrvCallState)> {
    let state = RDBSS_STATE.lock();
    let mut result = Vec::new();

    for idx in 0..MAX_SRV_CALLS {
        if state.srv_calls[idx].active {
            let name = core::str::from_utf8(
                &state.srv_calls[idx].server_name[..state.srv_calls[idx].server_name_len],
            )
            .map(String::from)
            .unwrap_or_default();

            result.push((state.srv_calls[idx].id, name, state.srv_calls[idx].state));
        }
    }

    result
}

/// Get RDBSS statistics
pub fn rdbss_get_statistics() -> RdbssStatistics {
    let state = RDBSS_STATE.lock();

    RdbssStatistics {
        paging_read_bytes: AtomicU64::new(state.statistics.paging_read_bytes.load(Ordering::Relaxed)),
        non_paging_read_bytes: AtomicU64::new(state.statistics.non_paging_read_bytes.load(Ordering::Relaxed)),
        cache_read_bytes: AtomicU64::new(state.statistics.cache_read_bytes.load(Ordering::Relaxed)),
        network_read_bytes: AtomicU64::new(state.statistics.network_read_bytes.load(Ordering::Relaxed)),
        paging_write_bytes: AtomicU64::new(state.statistics.paging_write_bytes.load(Ordering::Relaxed)),
        non_paging_write_bytes: AtomicU64::new(state.statistics.non_paging_write_bytes.load(Ordering::Relaxed)),
        cache_write_bytes: AtomicU64::new(state.statistics.cache_write_bytes.load(Ordering::Relaxed)),
        network_write_bytes: AtomicU64::new(state.statistics.network_write_bytes.load(Ordering::Relaxed)),
        initial_failures: AtomicU32::new(state.statistics.initial_failures.load(Ordering::Relaxed)),
        completion_failures: AtomicU32::new(state.statistics.completion_failures.load(Ordering::Relaxed)),
        read_ops: AtomicU32::new(state.statistics.read_ops.load(Ordering::Relaxed)),
        random_read_ops: AtomicU32::new(state.statistics.random_read_ops.load(Ordering::Relaxed)),
        write_ops: AtomicU32::new(state.statistics.write_ops.load(Ordering::Relaxed)),
        random_write_ops: AtomicU32::new(state.statistics.random_write_ops.load(Ordering::Relaxed)),
        srv_calls: AtomicU32::new(state.statistics.srv_calls.load(Ordering::Relaxed)),
        srv_opens: AtomicU32::new(state.statistics.srv_opens.load(Ordering::Relaxed)),
        net_roots: AtomicU32::new(state.statistics.net_roots.load(Ordering::Relaxed)),
        v_net_roots: AtomicU32::new(state.statistics.v_net_roots.load(Ordering::Relaxed)),
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize RDBSS
pub fn init() {
    crate::serial_println!("[RDBSS] Initializing Redirected Drive Buffering Subsystem...");

    {
        let mut state = RDBSS_STATE.lock();
        state.initialized = true;
    }

    crate::serial_println!("[RDBSS] RDBSS initialized");
}
