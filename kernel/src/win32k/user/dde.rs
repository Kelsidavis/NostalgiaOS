//! Dynamic Data Exchange (DDE) Support
//!
//! DDE messaging and DDEML (DDE Management Library) support.
//! Based on Windows Server 2003 dde.h and ddeml.h.
//!
//! # Features
//!
//! - DDE message handling
//! - Conversation management
//! - Service/Topic registration
//! - Data exchange
//!
//! # References
//!
//! - `public/sdk/inc/dde.h` - DDE messages
//! - `public/sdk/inc/ddeml.h` - DDE Management Library

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// DDE Message Constants (WM_DDE_*)
// ============================================================================

/// Base DDE message
pub const WM_DDE_FIRST: u32 = 0x03E0;

/// Initiate DDE conversation
pub const WM_DDE_INITIATE: u32 = WM_DDE_FIRST;

/// Terminate DDE conversation
pub const WM_DDE_TERMINATE: u32 = WM_DDE_FIRST + 1;

/// Advise on data changes
pub const WM_DDE_ADVISE: u32 = WM_DDE_FIRST + 2;

/// Stop advise
pub const WM_DDE_UNADVISE: u32 = WM_DDE_FIRST + 3;

/// Acknowledge
pub const WM_DDE_ACK: u32 = WM_DDE_FIRST + 4;

/// Send data
pub const WM_DDE_DATA: u32 = WM_DDE_FIRST + 5;

/// Request data
pub const WM_DDE_REQUEST: u32 = WM_DDE_FIRST + 6;

/// Poke data
pub const WM_DDE_POKE: u32 = WM_DDE_FIRST + 7;

/// Execute command
pub const WM_DDE_EXECUTE: u32 = WM_DDE_FIRST + 8;

/// Last DDE message
pub const WM_DDE_LAST: u32 = WM_DDE_FIRST + 8;

// ============================================================================
// DDE Acknowledge Flags
// ============================================================================

/// fAck - positive acknowledgement
pub const DDE_FACK: u16 = 0x8000;

/// fBusy - busy
pub const DDE_FBUSY: u16 = 0x4000;

/// fDeferUpd - defer update
pub const DDE_FDEFERUPD: u16 = 0x4000;

/// fAckReq - acknowledgement required
pub const DDE_FACKREQ: u16 = 0x8000;

/// fRelease - release data
pub const DDE_FRELEASE: u16 = 0x2000;

/// fRequested - data was requested
pub const DDE_FREQUESTED: u16 = 0x1000;

/// fAppReturnCode - application return code
pub const DDE_FAPPSTATUS: u16 = 0x00FF;

// ============================================================================
// DDEML Return Values
// ============================================================================

/// No error
pub const DMLERR_NO_ERROR: u32 = 0;

/// First DDEML error
pub const DMLERR_FIRST: u32 = 0x4000;

/// Advise acknowledgement timeout
pub const DMLERR_ADVACKTIMEOUT: u32 = DMLERR_FIRST + 0;

/// Busy
pub const DMLERR_BUSY: u32 = DMLERR_FIRST + 1;

/// Data acknowledgement timeout
pub const DMLERR_DATAACKTIMEOUT: u32 = DMLERR_FIRST + 2;

/// DLL not initialized
pub const DMLERR_DLL_NOT_INITIALIZED: u32 = DMLERR_FIRST + 3;

/// DLL usage
pub const DMLERR_DLL_USAGE: u32 = DMLERR_FIRST + 4;

/// Execute acknowledgement timeout
pub const DMLERR_EXECACKTIMEOUT: u32 = DMLERR_FIRST + 5;

/// Invalid parameter
pub const DMLERR_INVALIDPARAMETER: u32 = DMLERR_FIRST + 6;

/// Low memory
pub const DMLERR_LOW_MEMORY: u32 = DMLERR_FIRST + 7;

/// Memory error
pub const DMLERR_MEMORY_ERROR: u32 = DMLERR_FIRST + 8;

/// Not processed
pub const DMLERR_NOTPROCESSED: u32 = DMLERR_FIRST + 9;

/// No conversation established
pub const DMLERR_NO_CONV_ESTABLISHED: u32 = DMLERR_FIRST + 10;

/// Poke acknowledgement timeout
pub const DMLERR_POKEACKTIMEOUT: u32 = DMLERR_FIRST + 11;

/// Post message failed
pub const DMLERR_POSTMSG_FAILED: u32 = DMLERR_FIRST + 12;

/// Reentrancy
pub const DMLERR_REENTRANCY: u32 = DMLERR_FIRST + 13;

/// Server died
pub const DMLERR_SERVER_DIED: u32 = DMLERR_FIRST + 14;

/// System error
pub const DMLERR_SYS_ERROR: u32 = DMLERR_FIRST + 15;

/// Unadvise acknowledgement timeout
pub const DMLERR_UNADVACKTIMEOUT: u32 = DMLERR_FIRST + 16;

/// Unfound queue ID
pub const DMLERR_UNFOUND_QUEUE_ID: u32 = DMLERR_FIRST + 17;

/// Last error
pub const DMLERR_LAST: u32 = DMLERR_FIRST + 17;

// ============================================================================
// DDEML Transaction Types (XTYP_*)
// ============================================================================

/// Error
pub const XTYP_ERROR: u32 = 0x0000 | 0x8000 | 0x0002;

/// Advise data
pub const XTYP_ADVDATA: u32 = 0x0010 | 0x4000;

/// Advise request
pub const XTYP_ADVREQ: u32 = 0x0020 | 0x2000 | 0x0002;

/// Advise start
pub const XTYP_ADVSTART: u32 = 0x0030 | 0x1000;

/// Advise stop
pub const XTYP_ADVSTOP: u32 = 0x0040 | 0x8000;

/// Execute
pub const XTYP_EXECUTE: u32 = 0x0050 | 0x4000 | 0x0002;

/// Connect
pub const XTYP_CONNECT: u32 = 0x0060 | 0x2000 | 0x0002;

/// Connect confirm
pub const XTYP_CONNECT_CONFIRM: u32 = 0x0070 | 0x8000 | 0x0002;

/// Disconnect
pub const XTYP_DISCONNECT: u32 = 0x00C0 | 0x8000 | 0x0002;

/// Poke
pub const XTYP_POKE: u32 = 0x0090 | 0x4000 | 0x0002;

/// Register
pub const XTYP_REGISTER: u32 = 0x00A0 | 0x8000 | 0x0002;

/// Request
pub const XTYP_REQUEST: u32 = 0x00B0 | 0x2000 | 0x0002;

/// Unregister
pub const XTYP_UNREGISTER: u32 = 0x00D0 | 0x8000 | 0x0002;

/// Wildconnect
pub const XTYP_WILDCONNECT: u32 = 0x00E0 | 0x2000 | 0x0002;

/// Xact complete
pub const XTYP_XACT_COMPLETE: u32 = 0x0080 | 0x8000;

// ============================================================================
// DDEML Application Command Flags (APPCMD_*)
// ============================================================================

/// Client only
pub const APPCMD_CLIENTONLY: u32 = 0x00000010;

/// Filter inits
pub const APPCMD_FILTERINITS: u32 = 0x00000020;

// ============================================================================
// DDEML Callback Filter Flags (CBF_*)
// ============================================================================

/// Fail connections
pub const CBF_FAIL_CONNECTIONS: u32 = 0x00002000;

/// Fail advises
pub const CBF_FAIL_ADVISES: u32 = 0x00004000;

/// Fail executes
pub const CBF_FAIL_EXECUTES: u32 = 0x00008000;

/// Fail pokes
pub const CBF_FAIL_POKES: u32 = 0x00010000;

/// Fail requests
pub const CBF_FAIL_REQUESTS: u32 = 0x00020000;

/// Fail all srvr xacts
pub const CBF_FAIL_ALLSVRXACTIONS: u32 = 0x0003F000;

/// Skip connect confirms
pub const CBF_SKIP_CONNECT_CONFIRMS: u32 = 0x00040000;

/// Skip registrations
pub const CBF_SKIP_REGISTRATIONS: u32 = 0x00080000;

/// Skip unregistrations
pub const CBF_SKIP_UNREGISTRATIONS: u32 = 0x00100000;

/// Skip disconnects
pub const CBF_SKIP_DISCONNECTS: u32 = 0x00200000;

/// Skip all notifications
pub const CBF_SKIP_ALLNOTIFICATIONS: u32 = 0x003C0000;

// ============================================================================
// Constants
// ============================================================================

/// Maximum DDE instances
pub const MAX_DDE_INSTANCES: usize = 32;

/// Maximum conversations
pub const MAX_CONVERSATIONS: usize = 64;

/// Maximum services
pub const MAX_SERVICES: usize = 32;

/// Maximum name length
pub const MAX_DDE_NAME: usize = 64;

// ============================================================================
// Handle Types
// ============================================================================

/// DDE instance handle
pub type DWORD = u32;

/// DDE conversation handle
pub type HCONV = usize;

/// DDE conversation list
pub type HCONVLIST = usize;

/// DDE data handle
pub type HDDEDATA = usize;

/// DDE string handle
pub type HSZ = usize;

/// Null handle
pub const NULL_HSZ: HSZ = 0;

/// Null HCONV
pub const NULL_HCONV: HCONV = 0;

/// Null HDDEDATA
pub const NULL_HDDEDATA: HDDEDATA = 0;

// ============================================================================
// DDE String Handle Storage
// ============================================================================

/// String handle entry
#[derive(Clone)]
pub struct StringHandle {
    /// Is this slot in use
    pub in_use: bool,
    /// Handle value
    pub handle: HSZ,
    /// Reference count
    pub ref_count: u32,
    /// String data
    pub data: [u8; MAX_DDE_NAME],
}

impl StringHandle {
    /// Create empty entry
    pub const fn new() -> Self {
        Self {
            in_use: false,
            handle: 0,
            ref_count: 0,
            data: [0; MAX_DDE_NAME],
        }
    }
}

// ============================================================================
// DDE Conversation
// ============================================================================

/// Conversation state
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConvState {
    /// Not connected
    Disconnected,
    /// Initiating
    Initiating,
    /// Connected
    Connected,
    /// Terminating
    Terminating,
}

/// DDE Conversation
#[derive(Clone)]
pub struct Conversation {
    /// Is this slot in use
    pub in_use: bool,
    /// Conversation handle
    pub handle: HCONV,
    /// Client window
    pub client_hwnd: HWND,
    /// Server window
    pub server_hwnd: HWND,
    /// Service name handle
    pub service: HSZ,
    /// Topic name handle
    pub topic: HSZ,
    /// State
    pub state: ConvState,
    /// Instance ID
    pub instance_id: DWORD,
}

impl Conversation {
    /// Create empty conversation
    pub const fn new() -> Self {
        Self {
            in_use: false,
            handle: 0,
            client_hwnd: UserHandle::NULL,
            server_hwnd: UserHandle::NULL,
            service: NULL_HSZ,
            topic: NULL_HSZ,
            state: ConvState::Disconnected,
            instance_id: 0,
        }
    }
}

// ============================================================================
// DDE Service Registration
// ============================================================================

/// Service registration
#[derive(Clone)]
pub struct ServiceRegistration {
    /// Is this slot in use
    pub in_use: bool,
    /// Service name handle
    pub service: HSZ,
    /// Instance ID
    pub instance_id: DWORD,
    /// Filter inits
    pub filter_inits: bool,
}

impl ServiceRegistration {
    /// Create empty registration
    pub const fn new() -> Self {
        Self {
            in_use: false,
            service: NULL_HSZ,
            instance_id: 0,
            filter_inits: false,
        }
    }
}

// ============================================================================
// DDE Instance
// ============================================================================

/// DDE Instance
#[derive(Clone)]
pub struct DdeInstance {
    /// Is this slot in use
    pub in_use: bool,
    /// Instance ID
    pub id: DWORD,
    /// Callback flags
    pub callback_flags: u32,
    /// Command flags
    pub cmd_flags: u32,
    /// Last error
    pub last_error: u32,
    /// Is client only
    pub client_only: bool,
}

impl DdeInstance {
    /// Create empty instance
    pub const fn new() -> Self {
        Self {
            in_use: false,
            id: 0,
            callback_flags: 0,
            cmd_flags: 0,
            last_error: DMLERR_NO_ERROR,
            client_only: false,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global instances
static INSTANCES: SpinLock<[DdeInstance; MAX_DDE_INSTANCES]> =
    SpinLock::new([const { DdeInstance::new() }; MAX_DDE_INSTANCES]);

/// Global conversations
static CONVERSATIONS: SpinLock<[Conversation; MAX_CONVERSATIONS]> =
    SpinLock::new([const { Conversation::new() }; MAX_CONVERSATIONS]);

/// Global services
static SERVICES: SpinLock<[ServiceRegistration; MAX_SERVICES]> =
    SpinLock::new([const { ServiceRegistration::new() }; MAX_SERVICES]);

/// Global string handles
static STRINGS: SpinLock<[StringHandle; 128]> =
    SpinLock::new([const { StringHandle::new() }; 128]);

/// Next instance ID
static NEXT_INSTANCE_ID: SpinLock<DWORD> = SpinLock::new(1);

/// Next string handle
static NEXT_HSZ: SpinLock<HSZ> = SpinLock::new(1);

/// Next conversation handle
static NEXT_HCONV: SpinLock<HCONV> = SpinLock::new(1);

// ============================================================================
// Public API
// ============================================================================

/// Initialize DDE support
pub fn init() {
    crate::serial_println!("[USER] DDE support initialized");
}

/// Initialize DDEML
pub fn dde_initialize(
    instance_id: &mut DWORD,
    cmd_flags: u32,
) -> u32 {
    let mut instances = INSTANCES.lock();
    let mut next_id = NEXT_INSTANCE_ID.lock();

    for inst in instances.iter_mut() {
        if !inst.in_use {
            let id = *next_id;
            *next_id += 1;

            inst.in_use = true;
            inst.id = id;
            inst.callback_flags = cmd_flags & 0x003FF000;
            inst.cmd_flags = cmd_flags & 0x000000FF;
            inst.last_error = DMLERR_NO_ERROR;
            inst.client_only = (cmd_flags & APPCMD_CLIENTONLY) != 0;

            *instance_id = id;
            return DMLERR_NO_ERROR;
        }
    }

    DMLERR_LOW_MEMORY
}

/// Uninitialize DDEML
pub fn dde_uninitialize(instance_id: DWORD) -> bool {
    let mut instances = INSTANCES.lock();

    for inst in instances.iter_mut() {
        if inst.in_use && inst.id == instance_id {
            *inst = DdeInstance::new();
            return true;
        }
    }

    false
}

/// Create string handle
pub fn dde_create_string_handle(instance_id: DWORD, string: &[u8], _code_page: u32) -> HSZ {
    let _ = instance_id;

    // Check if string already exists
    let mut strings = STRINGS.lock();

    for entry in strings.iter_mut() {
        if entry.in_use {
            let len = super::strhelp::str_len(&entry.data);
            if len == super::strhelp::str_len(string) &&
               super::strhelp::str_cmp_ni(&entry.data, string, len) == 0 {
                entry.ref_count += 1;
                return entry.handle;
            }
        }
    }

    // Create new
    let mut next = NEXT_HSZ.lock();

    for entry in strings.iter_mut() {
        if !entry.in_use {
            let handle = *next;
            *next += 1;

            entry.in_use = true;
            entry.handle = handle;
            entry.ref_count = 1;

            let len = super::strhelp::str_len(string).min(MAX_DDE_NAME - 1);
            entry.data[..len].copy_from_slice(&string[..len]);
            entry.data[len] = 0;

            return handle;
        }
    }

    NULL_HSZ
}

/// Free string handle
pub fn dde_free_string_handle(instance_id: DWORD, hsz: HSZ) -> bool {
    let _ = instance_id;

    if hsz == NULL_HSZ {
        return true;
    }

    let mut strings = STRINGS.lock();

    for entry in strings.iter_mut() {
        if entry.in_use && entry.handle == hsz {
            entry.ref_count = entry.ref_count.saturating_sub(1);
            if entry.ref_count == 0 {
                *entry = StringHandle::new();
            }
            return true;
        }
    }

    false
}

/// Keep string handle
pub fn dde_keep_string_handle(instance_id: DWORD, hsz: HSZ) -> bool {
    let _ = instance_id;

    if hsz == NULL_HSZ {
        return true;
    }

    let mut strings = STRINGS.lock();

    for entry in strings.iter_mut() {
        if entry.in_use && entry.handle == hsz {
            entry.ref_count += 1;
            return true;
        }
    }

    false
}

/// Query string
pub fn dde_query_string(instance_id: DWORD, hsz: HSZ, buffer: &mut [u8], _code_page: u32) -> u32 {
    let _ = instance_id;

    if hsz == NULL_HSZ {
        return 0;
    }

    let strings = STRINGS.lock();

    for entry in strings.iter() {
        if entry.in_use && entry.handle == hsz {
            let len = super::strhelp::str_len(&entry.data).min(buffer.len().saturating_sub(1));
            buffer[..len].copy_from_slice(&entry.data[..len]);
            if len < buffer.len() {
                buffer[len] = 0;
            }
            return len as u32;
        }
    }

    0
}

/// Compare string handles
pub fn dde_cmp_string_handles(hsz1: HSZ, hsz2: HSZ) -> i32 {
    if hsz1 == hsz2 {
        return 0;
    }

    if hsz1 == NULL_HSZ {
        return -1;
    }
    if hsz2 == NULL_HSZ {
        return 1;
    }

    let strings = STRINGS.lock();

    let mut str1: Option<&[u8]> = None;
    let mut str2: Option<&[u8]> = None;

    for entry in strings.iter() {
        if entry.in_use {
            if entry.handle == hsz1 {
                str1 = Some(&entry.data);
            }
            if entry.handle == hsz2 {
                str2 = Some(&entry.data);
            }
        }
    }

    match (str1, str2) {
        (Some(s1), Some(s2)) => super::strhelp::str_cmp(s1, s2),
        (Some(_), None) => 1,
        (None, Some(_)) => -1,
        (None, None) => 0,
    }
}

/// Register service name
pub fn dde_name_service(instance_id: DWORD, hsz_service: HSZ, afcmd: u32) -> HDDEDATA {
    // DNS_REGISTER = 0x0001, DNS_UNREGISTER = 0x0002
    let register = (afcmd & 0x0001) != 0;

    let mut services = SERVICES.lock();

    if register {
        // Check if already registered
        for svc in services.iter() {
            if svc.in_use && svc.instance_id == instance_id && svc.service == hsz_service {
                return 1; // Already registered
            }
        }

        // Register new
        for svc in services.iter_mut() {
            if !svc.in_use {
                svc.in_use = true;
                svc.service = hsz_service;
                svc.instance_id = instance_id;
                svc.filter_inits = (afcmd & 0x0004) != 0; // DNS_FILTEROFF
                return 1;
            }
        }

        0 // Failed
    } else {
        // Unregister
        for svc in services.iter_mut() {
            if svc.in_use && svc.instance_id == instance_id &&
               (hsz_service == NULL_HSZ || svc.service == hsz_service) {
                *svc = ServiceRegistration::new();
            }
        }
        1
    }
}

/// Connect to DDE server
pub fn dde_connect(
    instance_id: DWORD,
    hsz_service: HSZ,
    hsz_topic: HSZ,
    _context: usize,
) -> HCONV {
    let mut convs = CONVERSATIONS.lock();
    let mut next = NEXT_HCONV.lock();

    for conv in convs.iter_mut() {
        if !conv.in_use {
            let handle = *next;
            *next += 1;

            conv.in_use = true;
            conv.handle = handle;
            conv.client_hwnd = UserHandle::NULL;
            conv.server_hwnd = UserHandle::NULL;
            conv.service = hsz_service;
            conv.topic = hsz_topic;
            conv.state = ConvState::Connected;
            conv.instance_id = instance_id;

            return handle;
        }
    }

    NULL_HCONV
}

/// Connect to DDE server (list)
pub fn dde_connect_list(
    instance_id: DWORD,
    hsz_service: HSZ,
    hsz_topic: HSZ,
    _hconv_list: HCONVLIST,
    _context: usize,
) -> HCONVLIST {
    // Simplified: just create a single connection
    dde_connect(instance_id, hsz_service, hsz_topic, 0)
}

/// Disconnect from DDE server
pub fn dde_disconnect(hconv: HCONV) -> bool {
    if hconv == NULL_HCONV {
        return false;
    }

    let mut convs = CONVERSATIONS.lock();

    for conv in convs.iter_mut() {
        if conv.in_use && conv.handle == hconv {
            conv.state = ConvState::Disconnected;
            *conv = Conversation::new();
            return true;
        }
    }

    false
}

/// Query conversation info
pub fn dde_query_conv_info(hconv: HCONV, _transaction_id: u32) -> Option<(HSZ, HSZ, ConvState)> {
    if hconv == NULL_HCONV {
        return None;
    }

    let convs = CONVERSATIONS.lock();

    for conv in convs.iter() {
        if conv.in_use && conv.handle == hconv {
            return Some((conv.service, conv.topic, conv.state));
        }
    }

    None
}

/// Request data from server
pub fn dde_client_transaction(
    data: Option<&[u8]>,
    hconv: HCONV,
    hsz_item: HSZ,
    fmt: u32,
    xtype: u32,
    timeout: u32,
    result: &mut u32,
) -> HDDEDATA {
    let _ = (data, hsz_item, fmt, timeout);

    if hconv == NULL_HCONV {
        *result = 0;
        return NULL_HDDEDATA;
    }

    let convs = CONVERSATIONS.lock();

    for conv in convs.iter() {
        if conv.in_use && conv.handle == hconv {
            // Simplified: just acknowledge the transaction
            match xtype & 0x00F0 {
                0x0010 | 0x0020 | 0x0030 | 0x0040 => {
                    // ADVSTART, ADVSTOP, etc.
                    *result = DDE_FACK as u32;
                    return 1;
                }
                0x0050 => {
                    // EXECUTE
                    *result = DDE_FACK as u32;
                    return 1;
                }
                0x00B0 => {
                    // REQUEST
                    *result = DDE_FACK as u32;
                    return 1;
                }
                0x0090 => {
                    // POKE
                    *result = DDE_FACK as u32;
                    return 1;
                }
                _ => {}
            }
            break;
        }
    }

    *result = 0;
    NULL_HDDEDATA
}

/// Abandon transaction
pub fn dde_abandon_transaction(instance_id: DWORD, hconv: HCONV, transaction_id: u32) -> bool {
    let _ = (instance_id, hconv, transaction_id);
    true
}

/// Get last error
pub fn dde_get_last_error(instance_id: DWORD) -> u32 {
    let instances = INSTANCES.lock();

    for inst in instances.iter() {
        if inst.in_use && inst.id == instance_id {
            return inst.last_error;
        }
    }

    DMLERR_DLL_NOT_INITIALIZED
}

/// Post advise
pub fn dde_post_advise(instance_id: DWORD, hsz_topic: HSZ, hsz_item: HSZ) -> bool {
    let _ = (instance_id, hsz_topic, hsz_item);
    // Would notify all clients interested in this topic/item
    true
}

/// Enable callback
pub fn dde_enable_callback(instance_id: DWORD, hconv: HCONV, cmd: u32) -> bool {
    let _ = (instance_id, hconv, cmd);
    true
}

/// Get next conversation in list
pub fn dde_query_next_server(_hconv_list: HCONVLIST, hconv_prev: HCONV) -> HCONV {
    if hconv_prev == NULL_HCONV {
        // Return first
        let convs = CONVERSATIONS.lock();
        for conv in convs.iter() {
            if conv.in_use {
                return conv.handle;
            }
        }
    }
    NULL_HCONV
}

/// Impersonate client
pub fn dde_impersonate_client(hconv: HCONV) -> bool {
    let _ = hconv;
    true
}

/// Set user handle for conversation
pub fn dde_set_user_handle(hconv: HCONV, _id: u32, _user: usize) -> bool {
    let _ = hconv;
    true
}

// ============================================================================
// Low-Level DDE Functions
// ============================================================================

/// Pack DDE lParam
pub fn pack_dde_lparam(msg: u32, lo: u16, hi: u16) -> usize {
    let _ = msg;
    ((hi as usize) << 16) | (lo as usize)
}

/// Unpack DDE lParam
pub fn unpack_dde_lparam(msg: u32, lparam: usize) -> (u16, u16) {
    let _ = msg;
    ((lparam & 0xFFFF) as u16, ((lparam >> 16) & 0xFFFF) as u16)
}

/// Reuse DDE lParam
pub fn reuse_dde_lparam(lparam: usize, msg: u32, lo: u16, hi: u16) -> usize {
    let _ = lparam;
    pack_dde_lparam(msg, lo, hi)
}

/// Free DDE lParam
pub fn free_dde_lparam(_msg: u32, _lparam: usize) -> bool {
    true
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> DdeStats {
    let instances = INSTANCES.lock();
    let convs = CONVERSATIONS.lock();
    let services = SERVICES.lock();
    let strings = STRINGS.lock();

    let mut inst_count = 0;
    let mut conv_count = 0;
    let mut svc_count = 0;
    let mut str_count = 0;

    for inst in instances.iter() {
        if inst.in_use {
            inst_count += 1;
        }
    }

    for conv in convs.iter() {
        if conv.in_use {
            conv_count += 1;
        }
    }

    for svc in services.iter() {
        if svc.in_use {
            svc_count += 1;
        }
    }

    for s in strings.iter() {
        if s.in_use {
            str_count += 1;
        }
    }

    DdeStats {
        max_instances: MAX_DDE_INSTANCES,
        active_instances: inst_count,
        max_conversations: MAX_CONVERSATIONS,
        active_conversations: conv_count,
        max_services: MAX_SERVICES,
        registered_services: svc_count,
        active_string_handles: str_count,
    }
}

/// DDE statistics
#[derive(Debug, Clone, Copy)]
pub struct DdeStats {
    pub max_instances: usize,
    pub active_instances: usize,
    pub max_conversations: usize,
    pub active_conversations: usize,
    pub max_services: usize,
    pub registered_services: usize,
    pub active_string_handles: usize,
}
