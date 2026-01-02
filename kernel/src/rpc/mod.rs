//! Remote Procedure Call (RPC) Subsystem
//!
//! RPC provides a mechanism for inter-process and network communication,
//! enabling programs to call procedures in other processes or on remote systems.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    RPC Client                                │
//! │              (Client Stub Code)                              │
//! └─────────────────────────────────────────────────────────────┘
//!                            │
//!                   NDR Marshalling
//!                            ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                   RPC Runtime                                │
//! │        (Transport Selection, Security)                       │
//! └─────────────────────────────────────────────────────────────┘
//!                            │
//!              Protocol Sequence (ncalrpc, ncacn_np, ncacn_ip_tcp)
//!                            ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    RPC Server                                │
//! │              (Server Stub Code)                              │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Protocol Sequences
//!
//! - **ncalrpc**: Local RPC (ALPC/LPC)
//! - **ncacn_np**: Named Pipes over SMB
//! - **ncacn_ip_tcp**: TCP/IP
//! - **ncadg_ip_udp**: UDP/IP (connectionless)
//!
//! Based on Windows Server 2003 RPC implementation

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

// ============================================================================
// RPC Constants
// ============================================================================

/// Maximum RPC interfaces
pub const MAX_RPC_INTERFACES: usize = 256;

/// Maximum RPC bindings
pub const MAX_RPC_BINDINGS: usize = 512;

/// Maximum RPC endpoints
pub const MAX_RPC_ENDPOINTS: usize = 128;

/// Maximum pending RPC calls
pub const MAX_PENDING_CALLS: usize = 1024;

/// Maximum NDR buffer size
pub const MAX_NDR_BUFFER_SIZE: usize = 65536;

/// RPC version
pub const RPC_VERSION_MAJOR: u8 = 5;
pub const RPC_VERSION_MINOR: u8 = 0;

// ============================================================================
// RPC Protocol Sequences
// ============================================================================

/// RPC protocol sequences
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RpcProtocolSequence {
    /// Local RPC (ALPC/LPC)
    #[default]
    NcaLrpc = 0,
    /// Named Pipes
    NcacnNp = 1,
    /// TCP/IP
    NcacnIpTcp = 2,
    /// UDP/IP (datagram)
    NcadgIpUdp = 3,
    /// SPX
    NcacnSpx = 4,
    /// IPX
    NcadgIpx = 5,
    /// NetBIOS over TCP
    NcacnNbTcp = 6,
    /// NetBIOS over IPX
    NcacnNbIpx = 7,
    /// HTTP
    NcacnHttp = 8,
}

impl RpcProtocolSequence {
    /// Get protocol sequence string
    pub fn as_str(&self) -> &'static str {
        match self {
            RpcProtocolSequence::NcaLrpc => "ncalrpc",
            RpcProtocolSequence::NcacnNp => "ncacn_np",
            RpcProtocolSequence::NcacnIpTcp => "ncacn_ip_tcp",
            RpcProtocolSequence::NcadgIpUdp => "ncadg_ip_udp",
            RpcProtocolSequence::NcacnSpx => "ncacn_spx",
            RpcProtocolSequence::NcadgIpx => "ncadg_ipx",
            RpcProtocolSequence::NcacnNbTcp => "ncacn_nb_tcp",
            RpcProtocolSequence::NcacnNbIpx => "ncacn_nb_ipx",
            RpcProtocolSequence::NcacnHttp => "ncacn_http",
        }
    }

    /// Parse protocol sequence from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "ncalrpc" => Some(RpcProtocolSequence::NcaLrpc),
            "ncacn_np" => Some(RpcProtocolSequence::NcacnNp),
            "ncacn_ip_tcp" => Some(RpcProtocolSequence::NcacnIpTcp),
            "ncadg_ip_udp" => Some(RpcProtocolSequence::NcadgIpUdp),
            "ncacn_spx" => Some(RpcProtocolSequence::NcacnSpx),
            "ncadg_ipx" => Some(RpcProtocolSequence::NcadgIpx),
            "ncacn_nb_tcp" => Some(RpcProtocolSequence::NcacnNbTcp),
            "ncacn_nb_ipx" => Some(RpcProtocolSequence::NcacnNbIpx),
            "ncacn_http" => Some(RpcProtocolSequence::NcacnHttp),
            _ => None,
        }
    }

    /// Check if connection-oriented
    pub fn is_connection_oriented(&self) -> bool {
        match self {
            RpcProtocolSequence::NcadgIpUdp |
            RpcProtocolSequence::NcadgIpx => false,
            _ => true,
        }
    }
}

// ============================================================================
// RPC Status Codes
// ============================================================================

/// RPC status codes
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcStatus {
    /// Success
    Ok = 0,
    /// Invalid binding
    InvalidBinding = 0x000006A4,
    /// Wrong kind of binding
    WrongKindOfBinding = 0x000006A5,
    /// Invalid handle
    InvalidHandle = 0x000006A6,
    /// Binding has no auth info
    BindingHasNoAuth = 0x000006A7,
    /// Unknown authn service
    UnknownAuthnService = 0x000006A8,
    /// Unknown authn level
    UnknownAuthnLevel = 0x000006A9,
    /// Invalid auth identity
    InvalidAuthIdentity = 0x000006AA,
    /// Unknown authz service
    UnknownAuthzService = 0x000006AB,
    /// No protocol sequences
    NoProtseqs = 0x000006AC,
    /// Can't create endpoint
    CantCreateEndpoint = 0x000006AD,
    /// Out of resources
    OutOfResources = 0x000006AE,
    /// Server unavailable
    ServerUnavailable = 0x000006BA,
    /// Server too busy
    ServerTooBusy = 0x000006BB,
    /// Invalid network options
    InvalidNetworkOptions = 0x000006BC,
    /// No call active
    NoCallActive = 0x000006BD,
    /// Call failed
    CallFailed = 0x000006BE,
    /// Call failed DNE
    CallFailedDne = 0x000006BF,
    /// Protocol error
    ProtocolError = 0x000006C0,
    /// Unsupported transfer syntax
    UnsupportedTransSyn = 0x000006C2,
    /// Unsupported type
    UnsupportedType = 0x000006C4,
    /// Invalid tag
    InvalidTag = 0x000006C5,
    /// Invalid bound
    InvalidBound = 0x000006C6,
    /// No entry name
    NoEntryName = 0x000006C7,
    /// Invalid name syntax
    InvalidNameSyntax = 0x000006C8,
    /// Unsupported name syntax
    UnsupportedNameSyntax = 0x000006C9,
    /// UUID no address
    UuidNoAddress = 0x000006CB,
    /// Duplicate endpoint
    DuplicateEndpoint = 0x000006CC,
    /// Unknown auth type
    UnknownAuthType = 0x000006CD,
    /// Max calls too small
    MaxCallsTooSmall = 0x000006CE,
    /// String too long
    StringTooLong = 0x000006CF,
    /// RPC pipe discipline error
    PipeDisciplineError = 0x000006D0,
    /// Already listening
    AlreadyListening = 0x000006D3,
    /// No protseqs registered
    NoProtseqsRegistered = 0x000006D4,
    /// Not listening
    NotListening = 0x000006D5,
    /// Unknown manager type
    UnknownMgrType = 0x000006D6,
    /// Unknown interface
    UnknownIf = 0x000006D7,
    /// No bindings
    NoBindings = 0x000006D8,
    /// No protseqs
    NoProtseqs2 = 0x000006D9,
    /// Can't create endpoint 2
    CantCreateEndpoint2 = 0x000006DA,
    /// Object not found
    ObjectNotFound = 0x000006DB,
    /// Already registered
    AlreadyRegistered = 0x000006DC,
    /// Type already registered
    TypeAlreadyRegistered = 0x000006DD,
    /// Not cancelled
    NotCancelled = 0x000006E2,
    /// Invalid object
    InvalidObject = 0x0000076A,
    /// Call pending
    Pending = 0x000000FF,
}

// ============================================================================
// RPC UUID Structure
// ============================================================================

/// RPC UUID (128-bit GUID)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RpcUuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl RpcUuid {
    pub const fn nil() -> Self {
        Self {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        }
    }

    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self { data1, data2, data3, data4 }
    }

    /// Check if nil UUID
    pub fn is_nil(&self) -> bool {
        self.data1 == 0 && self.data2 == 0 && self.data3 == 0 &&
            self.data4 == [0; 8]
    }
}

// ============================================================================
// RPC Interface
// ============================================================================

/// RPC interface identifier
#[derive(Debug, Clone, Copy)]
pub struct RpcIfId {
    /// Interface UUID
    pub uuid: RpcUuid,
    /// Major version
    pub ver_major: u16,
    /// Minor version
    pub ver_minor: u16,
}

impl RpcIfId {
    pub const fn new(uuid: RpcUuid, ver_major: u16, ver_minor: u16) -> Self {
        Self { uuid, ver_major, ver_minor }
    }
}

/// RPC interface registration
pub struct RpcInterface {
    /// Interface ID
    pub interface_id: u32,
    /// Active flag
    pub active: bool,
    /// Interface identifier
    pub if_id: RpcIfId,
    /// Manager EPV (entry point vector)
    pub manager_epv: usize,
    /// Manager type UUID
    pub manager_type_uuid: RpcUuid,
    /// Flags
    pub flags: u32,
    /// Maximum calls
    pub max_calls: u32,
    /// Current call count
    pub current_calls: AtomicU32,
    /// Total calls handled
    pub total_calls: AtomicU64,
    /// Dispatch table
    pub dispatch_count: u32,
    /// Auto listen enabled
    pub auto_listen: bool,
}

impl RpcInterface {
    pub const fn empty() -> Self {
        Self {
            interface_id: 0,
            active: false,
            if_id: RpcIfId { uuid: RpcUuid::nil(), ver_major: 0, ver_minor: 0 },
            manager_epv: 0,
            manager_type_uuid: RpcUuid::nil(),
            flags: 0,
            max_calls: 0,
            current_calls: AtomicU32::new(0),
            total_calls: AtomicU64::new(0),
            dispatch_count: 0,
            auto_listen: false,
        }
    }
}

// ============================================================================
// RPC Binding
// ============================================================================

/// RPC binding handle
pub struct RpcBinding {
    /// Binding ID
    pub binding_id: u32,
    /// Active flag
    pub active: bool,
    /// Protocol sequence
    pub protocol_seq: RpcProtocolSequence,
    /// Network address
    pub network_addr: [u8; 256],
    /// Endpoint
    pub endpoint: [u8; 64],
    /// Object UUID
    pub object_uuid: RpcUuid,
    /// Authentication level
    pub auth_level: RpcAuthLevel,
    /// Authentication service
    pub auth_service: RpcAuthService,
    /// Reference count
    pub ref_count: AtomicU32,
    /// Is server binding
    pub is_server: bool,
    /// Connected
    pub connected: bool,
    /// Associated interface
    pub interface_id: u32,
    /// Call sequence number
    pub call_seq: AtomicU32,
}

impl RpcBinding {
    pub const fn empty() -> Self {
        Self {
            binding_id: 0,
            active: false,
            protocol_seq: RpcProtocolSequence::NcaLrpc,
            network_addr: [0; 256],
            endpoint: [0; 64],
            object_uuid: RpcUuid::nil(),
            auth_level: RpcAuthLevel::None,
            auth_service: RpcAuthService::None,
            ref_count: AtomicU32::new(0),
            is_server: false,
            connected: false,
            interface_id: 0,
            call_seq: AtomicU32::new(0),
        }
    }

    /// Set network address
    pub fn set_network_addr(&mut self, addr: &str) {
        let bytes = addr.as_bytes();
        let len = bytes.len().min(255);
        self.network_addr[..len].copy_from_slice(&bytes[..len]);
        self.network_addr[len] = 0;
    }

    /// Get network address
    pub fn network_addr_str(&self) -> &str {
        let len = self.network_addr.iter().position(|&c| c == 0).unwrap_or(self.network_addr.len());
        core::str::from_utf8(&self.network_addr[..len]).unwrap_or("")
    }

    /// Set endpoint
    pub fn set_endpoint(&mut self, ep: &str) {
        let bytes = ep.as_bytes();
        let len = bytes.len().min(63);
        self.endpoint[..len].copy_from_slice(&bytes[..len]);
        self.endpoint[len] = 0;
    }

    /// Get endpoint
    pub fn endpoint_str(&self) -> &str {
        let len = self.endpoint.iter().position(|&c| c == 0).unwrap_or(self.endpoint.len());
        core::str::from_utf8(&self.endpoint[..len]).unwrap_or("")
    }
}

// ============================================================================
// RPC Authentication
// ============================================================================

/// RPC authentication level
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RpcAuthLevel {
    /// No authentication
    #[default]
    None = 0,
    /// Default (same as Connect for most)
    Default = 1,
    /// Connect-level authentication
    Connect = 2,
    /// Call-level authentication
    Call = 3,
    /// Packet-level authentication
    Pkt = 4,
    /// Packet integrity
    PktIntegrity = 5,
    /// Packet privacy (encryption)
    PktPrivacy = 6,
}

/// RPC authentication service
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RpcAuthService {
    /// No authentication
    #[default]
    None = 0,
    /// DCE private key
    DcePrivate = 1,
    /// DCE public key
    DcePublic = 2,
    /// DEC public key
    DecPublic = 4,
    /// GSS negotiate
    GssNegotiate = 9,
    /// NTLM (WinNT)
    WinNt = 10,
    /// GSS Schannel (SSL/TLS)
    GssSchannel = 14,
    /// GSS Kerberos
    GssKerberos = 16,
    /// DPA
    Dpa = 17,
    /// MSN
    Msn = 18,
    /// Kernel (LRPC)
    Kernel = 20,
    /// Digest
    Digest = 21,
    /// Negotiate Extended
    NegotiateExtended = 30,
    /// PKU2U
    Pku2u = 31,
    /// MQ
    Mq = 100,
}

// ============================================================================
// RPC Endpoint
// ============================================================================

/// RPC endpoint registration
pub struct RpcEndpoint {
    /// Endpoint ID
    pub endpoint_id: u32,
    /// Active flag
    pub active: bool,
    /// Protocol sequence
    pub protocol_seq: RpcProtocolSequence,
    /// Endpoint string
    pub endpoint: [u8; 64],
    /// Interface ID (0 for all)
    pub interface_id: u32,
    /// Listening
    pub listening: bool,
    /// Connections accepted
    pub connections_accepted: AtomicU64,
}

impl RpcEndpoint {
    pub const fn empty() -> Self {
        Self {
            endpoint_id: 0,
            active: false,
            protocol_seq: RpcProtocolSequence::NcaLrpc,
            endpoint: [0; 64],
            interface_id: 0,
            listening: false,
            connections_accepted: AtomicU64::new(0),
        }
    }

    /// Set endpoint string
    pub fn set_endpoint(&mut self, ep: &str) {
        let bytes = ep.as_bytes();
        let len = bytes.len().min(63);
        self.endpoint[..len].copy_from_slice(&bytes[..len]);
        self.endpoint[len] = 0;
    }

    /// Get endpoint string
    pub fn endpoint_str(&self) -> &str {
        let len = self.endpoint.iter().position(|&c| c == 0).unwrap_or(self.endpoint.len());
        core::str::from_utf8(&self.endpoint[..len]).unwrap_or("")
    }
}

// ============================================================================
// RPC Call
// ============================================================================

/// RPC call state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RpcCallState {
    /// Idle
    #[default]
    Idle = 0,
    /// Sending request
    Sending = 1,
    /// Waiting for response
    Waiting = 2,
    /// Receiving response
    Receiving = 3,
    /// Completed
    Completed = 4,
    /// Failed
    Failed = 5,
    /// Cancelled
    Cancelled = 6,
}

/// RPC pending call
pub struct RpcCall {
    /// Call ID
    pub call_id: u32,
    /// Active flag
    pub active: bool,
    /// Call state
    pub state: RpcCallState,
    /// Binding ID
    pub binding_id: u32,
    /// Interface ID
    pub interface_id: u32,
    /// Operation number
    pub opnum: u32,
    /// Request buffer
    pub request_buffer: Vec<u8>,
    /// Response buffer
    pub response_buffer: Vec<u8>,
    /// Status
    pub status: RpcStatus,
    /// Call started timestamp
    pub started_time: u64,
    /// Call completed timestamp
    pub completed_time: u64,
}

impl RpcCall {
    pub fn empty() -> Self {
        Self {
            call_id: 0,
            active: false,
            state: RpcCallState::Idle,
            binding_id: 0,
            interface_id: 0,
            opnum: 0,
            request_buffer: Vec::new(),
            response_buffer: Vec::new(),
            status: RpcStatus::Ok,
            started_time: 0,
            completed_time: 0,
        }
    }
}

// ============================================================================
// RPC Global State
// ============================================================================

/// RPC subsystem state
struct RpcState {
    /// Registered interfaces
    interfaces: [RpcInterface; MAX_RPC_INTERFACES],
    /// Binding handles
    bindings: [RpcBinding; MAX_RPC_BINDINGS],
    /// Registered endpoints
    endpoints: [RpcEndpoint; MAX_RPC_ENDPOINTS],
    /// Next interface ID
    next_interface_id: u32,
    /// Next binding ID
    next_binding_id: u32,
    /// Next endpoint ID
    next_endpoint_id: u32,
    /// Server listening
    server_listening: bool,
}

const EMPTY_INTERFACE: RpcInterface = RpcInterface::empty();
const EMPTY_BINDING: RpcBinding = RpcBinding::empty();
const EMPTY_ENDPOINT: RpcEndpoint = RpcEndpoint::empty();

static RPC_STATE: Mutex<RpcState> = Mutex::new(RpcState {
    interfaces: [EMPTY_INTERFACE; MAX_RPC_INTERFACES],
    bindings: [EMPTY_BINDING; MAX_RPC_BINDINGS],
    endpoints: [EMPTY_ENDPOINT; MAX_RPC_ENDPOINTS],
    next_interface_id: 1,
    next_binding_id: 1,
    next_endpoint_id: 1,
    server_listening: false,
});

static RPC_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// RPC Server Functions
// ============================================================================

/// Register an RPC interface
pub fn rpc_server_register_if(
    if_id: RpcIfId,
    manager_type_uuid: Option<RpcUuid>,
    manager_epv: usize,
    flags: u32,
    max_calls: u32,
) -> Result<u32, RpcStatus> {
    let mut state = RPC_STATE.lock();
    let interface_id = state.next_interface_id;

    // Check for duplicate
    for iface in state.interfaces.iter() {
        if iface.active &&
           iface.if_id.uuid.data1 == if_id.uuid.data1 &&
           iface.if_id.uuid.data2 == if_id.uuid.data2 &&
           iface.if_id.uuid.data3 == if_id.uuid.data3 &&
           iface.if_id.uuid.data4 == if_id.uuid.data4 {
            return Err(RpcStatus::AlreadyRegistered);
        }
    }

    for idx in 0..MAX_RPC_INTERFACES {
        if !state.interfaces[idx].active {
            state.interfaces[idx] = RpcInterface {
                interface_id,
                active: true,
                if_id,
                manager_epv,
                manager_type_uuid: manager_type_uuid.unwrap_or(RpcUuid::nil()),
                flags,
                max_calls,
                current_calls: AtomicU32::new(0),
                total_calls: AtomicU64::new(0),
                dispatch_count: 0,
                auto_listen: false,
            };

            state.next_interface_id += 1;

            crate::serial_println!("[RPC] Registered interface {:08X}-{:04X}-{:04X} v{}.{} (ID={})",
                if_id.uuid.data1, if_id.uuid.data2, if_id.uuid.data3,
                if_id.ver_major, if_id.ver_minor, interface_id);

            return Ok(interface_id);
        }
    }

    Err(RpcStatus::OutOfResources)
}

/// Unregister an RPC interface
pub fn rpc_server_unregister_if(if_id: &RpcIfId) -> RpcStatus {
    let mut state = RPC_STATE.lock();

    for idx in 0..MAX_RPC_INTERFACES {
        let iface = &state.interfaces[idx];
        if iface.active &&
           iface.if_id.uuid.data1 == if_id.uuid.data1 &&
           iface.if_id.uuid.data2 == if_id.uuid.data2 &&
           iface.if_id.uuid.data3 == if_id.uuid.data3 &&
           iface.if_id.uuid.data4 == if_id.uuid.data4 {
            // Wait for outstanding calls to complete
            if state.interfaces[idx].current_calls.load(Ordering::Relaxed) > 0 {
                return RpcStatus::NoCallActive;
            }

            state.interfaces[idx].active = false;
            crate::serial_println!("[RPC] Unregistered interface {:08X}", if_id.uuid.data1);
            return RpcStatus::Ok;
        }
    }

    RpcStatus::UnknownIf
}

/// Use protocol sequence endpoint
pub fn rpc_server_use_protseq_ep(
    protocol_seq: RpcProtocolSequence,
    max_calls: u32,
    endpoint: &str,
) -> Result<u32, RpcStatus> {
    let mut state = RPC_STATE.lock();
    let endpoint_id = state.next_endpoint_id;

    // Check for duplicate
    for ep in state.endpoints.iter() {
        if ep.active && ep.protocol_seq == protocol_seq && ep.endpoint_str() == endpoint {
            return Err(RpcStatus::DuplicateEndpoint);
        }
    }

    for idx in 0..MAX_RPC_ENDPOINTS {
        if !state.endpoints[idx].active {
            state.endpoints[idx] = RpcEndpoint {
                endpoint_id,
                active: true,
                protocol_seq,
                endpoint: [0; 64],
                interface_id: 0,
                listening: false,
                connections_accepted: AtomicU64::new(0),
            };
            state.endpoints[idx].set_endpoint(endpoint);

            state.next_endpoint_id += 1;

            crate::serial_println!("[RPC] Registered endpoint {}:{} (ID={})",
                protocol_seq.as_str(), endpoint, endpoint_id);

            return Ok(endpoint_id);
        }
    }

    Err(RpcStatus::CantCreateEndpoint)
}

/// Start listening for RPC calls
pub fn rpc_server_listen(min_call_threads: u32) -> RpcStatus {
    let mut state = RPC_STATE.lock();

    if state.server_listening {
        return RpcStatus::AlreadyListening;
    }

    // Check if any endpoints are registered
    let has_endpoints = state.endpoints.iter().any(|e| e.active);
    if !has_endpoints {
        return RpcStatus::NoProtseqsRegistered;
    }

    // Mark all endpoints as listening
    for ep in state.endpoints.iter_mut() {
        if ep.active {
            ep.listening = true;
        }
    }

    state.server_listening = true;

    crate::serial_println!("[RPC] Server listening (min threads={})", min_call_threads);
    RpcStatus::Ok
}

/// Stop listening for RPC calls
pub fn rpc_server_stop_listening() -> RpcStatus {
    let mut state = RPC_STATE.lock();

    if !state.server_listening {
        return RpcStatus::NotListening;
    }

    // Stop listening on all endpoints
    for ep in state.endpoints.iter_mut() {
        if ep.active {
            ep.listening = false;
        }
    }

    state.server_listening = false;

    crate::serial_println!("[RPC] Server stopped listening");
    RpcStatus::Ok
}

// ============================================================================
// RPC Client Functions
// ============================================================================

/// Create binding from string binding
pub fn rpc_binding_from_string_binding(
    string_binding: &str,
) -> Result<u32, RpcStatus> {
    // Parse string binding: protocol_seq:network_addr[endpoint]
    // Example: ncacn_ip_tcp:192.168.1.1[1234]

    let mut state = RPC_STATE.lock();
    let binding_id = state.next_binding_id;

    // Simple parsing - find protocol sequence
    let parts: Vec<&str> = string_binding.splitn(2, ':').collect();
    if parts.len() < 2 {
        return Err(RpcStatus::InvalidBinding);
    }

    let protocol_seq = RpcProtocolSequence::from_str(parts[0])
        .ok_or(RpcStatus::NoProtseqs)?;

    // Parse network address and endpoint
    let addr_ep = parts[1];
    let (network_addr, endpoint) = if let Some(bracket_pos) = addr_ep.find('[') {
        let addr = &addr_ep[..bracket_pos];
        let ep = addr_ep[bracket_pos + 1..].trim_end_matches(']');
        (addr, ep)
    } else {
        (addr_ep, "")
    };

    for idx in 0..MAX_RPC_BINDINGS {
        if !state.bindings[idx].active {
            state.bindings[idx] = RpcBinding {
                binding_id,
                active: true,
                protocol_seq,
                network_addr: [0; 256],
                endpoint: [0; 64],
                object_uuid: RpcUuid::nil(),
                auth_level: RpcAuthLevel::None,
                auth_service: RpcAuthService::None,
                ref_count: AtomicU32::new(1),
                is_server: false,
                connected: false,
                interface_id: 0,
                call_seq: AtomicU32::new(0),
            };
            state.bindings[idx].set_network_addr(network_addr);
            state.bindings[idx].set_endpoint(endpoint);

            state.next_binding_id += 1;

            crate::serial_println!("[RPC] Created binding {} -> {}:{}[{}]",
                binding_id, protocol_seq.as_str(), network_addr, endpoint);

            return Ok(binding_id);
        }
    }

    Err(RpcStatus::OutOfResources)
}

/// Set binding object UUID
pub fn rpc_binding_set_object(binding_id: u32, object_uuid: RpcUuid) -> RpcStatus {
    let mut state = RPC_STATE.lock();

    for idx in 0..MAX_RPC_BINDINGS {
        if state.bindings[idx].active && state.bindings[idx].binding_id == binding_id {
            state.bindings[idx].object_uuid = object_uuid;
            return RpcStatus::Ok;
        }
    }

    RpcStatus::InvalidBinding
}

/// Set binding authentication info
pub fn rpc_binding_set_auth_info(
    binding_id: u32,
    auth_level: RpcAuthLevel,
    auth_service: RpcAuthService,
) -> RpcStatus {
    let mut state = RPC_STATE.lock();

    for idx in 0..MAX_RPC_BINDINGS {
        if state.bindings[idx].active && state.bindings[idx].binding_id == binding_id {
            state.bindings[idx].auth_level = auth_level;
            state.bindings[idx].auth_service = auth_service;
            return RpcStatus::Ok;
        }
    }

    RpcStatus::InvalidBinding
}

/// Free binding handle
pub fn rpc_binding_free(binding_id: u32) -> RpcStatus {
    let mut state = RPC_STATE.lock();

    for idx in 0..MAX_RPC_BINDINGS {
        if state.bindings[idx].active && state.bindings[idx].binding_id == binding_id {
            let refs = state.bindings[idx].ref_count.fetch_sub(1, Ordering::Relaxed);
            if refs <= 1 {
                state.bindings[idx].active = false;
                crate::serial_println!("[RPC] Freed binding {}", binding_id);
            }
            return RpcStatus::Ok;
        }
    }

    RpcStatus::InvalidBinding
}

// ============================================================================
// RPC Statistics and Diagnostics
// ============================================================================

/// RPC statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct RpcStats {
    /// Registered interfaces
    pub interface_count: usize,
    /// Active bindings
    pub binding_count: usize,
    /// Registered endpoints
    pub endpoint_count: usize,
    /// Server listening
    pub server_listening: bool,
    /// Total calls made
    pub total_calls: u64,
}

/// Get RPC statistics
pub fn rpc_get_stats() -> RpcStats {
    let state = RPC_STATE.lock();

    let mut stats = RpcStats {
        server_listening: state.server_listening,
        ..Default::default()
    };

    for iface in state.interfaces.iter() {
        if iface.active {
            stats.interface_count += 1;
            stats.total_calls += iface.total_calls.load(Ordering::Relaxed);
        }
    }

    for binding in state.bindings.iter() {
        if binding.active {
            stats.binding_count += 1;
        }
    }

    for ep in state.endpoints.iter() {
        if ep.active {
            stats.endpoint_count += 1;
        }
    }

    stats
}

/// RPC interface snapshot
#[derive(Debug, Clone)]
pub struct RpcInterfaceSnapshot {
    pub interface_id: u32,
    pub uuid_data1: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub current_calls: u32,
    pub total_calls: u64,
}

/// Get interface snapshots
pub fn rpc_get_interface_snapshots() -> Vec<RpcInterfaceSnapshot> {
    let state = RPC_STATE.lock();
    let mut snapshots = Vec::new();

    for iface in state.interfaces.iter() {
        if iface.active {
            snapshots.push(RpcInterfaceSnapshot {
                interface_id: iface.interface_id,
                uuid_data1: iface.if_id.uuid.data1,
                version_major: iface.if_id.ver_major,
                version_minor: iface.if_id.ver_minor,
                current_calls: iface.current_calls.load(Ordering::Relaxed),
                total_calls: iface.total_calls.load(Ordering::Relaxed),
            });
        }
    }

    snapshots
}

// ============================================================================
// RPC Initialization
// ============================================================================

/// Initialize RPC subsystem
pub fn init() {
    if RPC_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[RPC] Remote Procedure Call subsystem initialized");
    crate::serial_println!("[RPC]   Version: {}.{}", RPC_VERSION_MAJOR, RPC_VERSION_MINOR);
    crate::serial_println!("[RPC]   Max interfaces: {}", MAX_RPC_INTERFACES);
    crate::serial_println!("[RPC]   Max bindings: {}", MAX_RPC_BINDINGS);
}

/// Check if RPC is initialized
pub fn is_initialized() -> bool {
    RPC_INITIALIZED.load(Ordering::SeqCst)
}
