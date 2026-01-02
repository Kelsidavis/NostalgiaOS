//! Transport Driver Interface (TDI)
//!
//! TDI provides a kernel-mode interface for network I/O, enabling drivers
//! to communicate with transport protocols (TCP/IP, NetBEUI, etc.).
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     TDI Clients                              │
//! │  (AFD.SYS, Redirector, Server, Named Pipes)                 │
//! └─────────────────────────────────────────────────────────────┘
//!                            │
//!                    TDI Interface (IRPs)
//!                            ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                   TDI Transport Layer                        │
//! │              (TCPIP.SYS, NetBEUI, etc.)                     │
//! └─────────────────────────────────────────────────────────────┘
//!                            │
//!                      NDIS Interface
//!                            ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    NDIS Miniports                            │
//! │              (Network Adapter Drivers)                       │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # TDI Object Types
//!
//! - **Transport Address**: Represents a local network address
//! - **Connection Endpoint**: Represents a connection to remote endpoint
//! - **Control Channel**: For administrative operations
//!
//! Based on Windows Server 2003 TDI specification

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

// ============================================================================
// TDI Constants
// ============================================================================

/// Maximum TDI addresses
pub const MAX_TDI_ADDRESSES: usize = 256;

/// Maximum TDI connections
pub const MAX_TDI_CONNECTIONS: usize = 1024;

/// Maximum TDI control channels
pub const MAX_TDI_CONTROLS: usize = 64;

/// Maximum pending TDI requests
pub const MAX_TDI_REQUESTS: usize = 4096;

/// TDI buffer size
pub const TDI_BUFFER_SIZE: usize = 65536;

// ============================================================================
// TDI Address Types
// ============================================================================

/// TDI address type constants
pub mod address_type {
    /// IP address (AF_INET)
    pub const TDI_ADDRESS_TYPE_IP: u16 = 2;
    /// IPv6 address (AF_INET6)
    pub const TDI_ADDRESS_TYPE_IP6: u16 = 23;
    /// NetBIOS address
    pub const TDI_ADDRESS_TYPE_NETBIOS: u16 = 17;
    /// AppleTalk address
    pub const TDI_ADDRESS_TYPE_APPLETALK: u16 = 16;
    /// IPX address
    pub const TDI_ADDRESS_TYPE_IPX: u16 = 6;
    /// VNS address
    pub const TDI_ADDRESS_TYPE_VNS: u16 = 25;
    /// Unspecified
    pub const TDI_ADDRESS_TYPE_UNSPEC: u16 = 0;
}

// ============================================================================
// TDI Event Types
// ============================================================================

/// TDI event types for event handlers
pub mod event_type {
    /// Connect event (incoming connection)
    pub const TDI_EVENT_CONNECT: u32 = 0;
    /// Disconnect event
    pub const TDI_EVENT_DISCONNECT: u32 = 1;
    /// Error event
    pub const TDI_EVENT_ERROR: u32 = 2;
    /// Receive event
    pub const TDI_EVENT_RECEIVE: u32 = 3;
    /// Receive datagram event
    pub const TDI_EVENT_RECEIVE_DATAGRAM: u32 = 4;
    /// Receive expedited data event
    pub const TDI_EVENT_RECEIVE_EXPEDITED: u32 = 5;
    /// Send possible event
    pub const TDI_EVENT_SEND_POSSIBLE: u32 = 6;
    /// Chained receive event
    pub const TDI_EVENT_CHAINED_RECEIVE: u32 = 7;
    /// Chained receive datagram event
    pub const TDI_EVENT_CHAINED_RECEIVE_DATAGRAM: u32 = 8;
    /// Chained receive expedited event
    pub const TDI_EVENT_CHAINED_RECEIVE_EXPEDITED: u32 = 9;
    /// Error (extended) event
    pub const TDI_EVENT_ERROR_EX: u32 = 10;
}

// ============================================================================
// TDI Flags
// ============================================================================

/// TDI send/receive flags
pub mod tdi_flags {
    /// Normal send/receive
    pub const TDI_SEND_NORMAL: u32 = 0x00000000;
    /// Expedited (out-of-band) data
    pub const TDI_SEND_EXPEDITED: u32 = 0x00000020;
    /// Partial data (more coming)
    pub const TDI_SEND_PARTIAL: u32 = 0x00000040;
    /// Non-blocking send
    pub const TDI_SEND_NON_BLOCKING: u32 = 0x00000080;
    /// No response expected
    pub const TDI_SEND_NO_RESPONSE_EXPECTED: u32 = 0x00000100;

    /// Peek at data without removing
    pub const TDI_RECEIVE_PEEK: u32 = 0x00000002;
    /// Copy data (vs. move)
    pub const TDI_RECEIVE_COPY: u32 = 0x00000004;
    /// Return entire message
    pub const TDI_RECEIVE_ENTIRE_MESSAGE: u32 = 0x00000008;
    /// Normal receive
    pub const TDI_RECEIVE_NORMAL: u32 = 0x00000000;
    /// Expedited receive
    pub const TDI_RECEIVE_EXPEDITED: u32 = 0x00000020;
    /// Partial receive
    pub const TDI_RECEIVE_PARTIAL: u32 = 0x00000040;
    /// Non-blocking receive
    pub const TDI_RECEIVE_NON_BLOCKING: u32 = 0x00000080;
    /// At dispatch level
    pub const TDI_RECEIVE_AT_DISPATCH_LEVEL: u32 = 0x00000400;
}

/// TDI connection flags
pub mod connection_flags {
    /// Abortive disconnect
    pub const TDI_DISCONNECT_ABORT: u32 = 0x00000001;
    /// Release (graceful disconnect)
    pub const TDI_DISCONNECT_RELEASE: u32 = 0x00000002;
    /// Wait for completion
    pub const TDI_DISCONNECT_WAIT: u32 = 0x00000004;
}

// ============================================================================
// TDI Status Codes
// ============================================================================

/// TDI operation status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdiStatus {
    /// Operation successful
    Success = 0,
    /// Operation pending
    Pending = 0x00000103,
    /// Invalid parameter
    InvalidParameter = 0xC000000D,
    /// Invalid address
    InvalidAddress = 0xC0000141,
    /// Address already exists
    AddressAlreadyExists = 0xC000020A,
    /// Address not associated
    AddressNotAssociated = 0xC0000237,
    /// Connection refused
    ConnectionRefused = 0xC0000236,
    /// Connection reset
    ConnectionReset = 0xC000020D,
    /// Connection aborted
    ConnectionAborted = 0xC0000241,
    /// Network unreachable
    NetworkUnreachable = 0xC000023C,
    /// Host unreachable
    HostUnreachable = 0xC000023D,
    /// Connection timed out
    TimedOut = 0xC00000B5,
    /// Buffer too small
    BufferTooSmall = 0xC0000023,
    /// Insufficient resources
    InsufficientResources = 0xC000009A,
    /// Not supported
    NotSupported = 0xC00000BB,
    /// Not found
    NotFound = 0xC0000225,
    /// Already connected
    AlreadyConnected = 0xC000020B,
    /// Not connected
    NotConnected = 0xC0000238,
    /// Graceful disconnect
    GracefulDisconnect = 0xC0000243,
    /// Data not accepted
    DataNotAccepted = 0x00000001,
    /// Request canceled
    Cancelled = 0xC0000120,
}

// ============================================================================
// TDI Address Structures
// ============================================================================

/// IPv4 address for TDI
#[derive(Debug, Clone, Copy, Default)]
pub struct TdiAddressIp {
    /// Port number (network byte order)
    pub port: u16,
    /// IPv4 address (network byte order)
    pub address: u32,
}

impl TdiAddressIp {
    pub fn new(address: u32, port: u16) -> Self {
        Self { address, port }
    }

    pub fn any(port: u16) -> Self {
        Self { address: 0, port }
    }

    pub fn from_octets(a: u8, b: u8, c: u8, d: u8, port: u16) -> Self {
        let address = ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32);
        Self { address, port }
    }
}

/// IPv6 address for TDI
#[derive(Debug, Clone, Copy)]
pub struct TdiAddressIp6 {
    /// Port number
    pub port: u16,
    /// Flow info
    pub flow_info: u32,
    /// IPv6 address (16 bytes)
    pub address: [u8; 16],
    /// Scope ID
    pub scope_id: u32,
}

impl Default for TdiAddressIp6 {
    fn default() -> Self {
        Self {
            port: 0,
            flow_info: 0,
            address: [0; 16],
            scope_id: 0,
        }
    }
}

/// NetBIOS address for TDI
#[derive(Debug, Clone)]
pub struct TdiAddressNetbios {
    /// NetBIOS name type
    pub name_type: u16,
    /// NetBIOS name (16 bytes, space-padded)
    pub name: [u8; 16],
}

impl Default for TdiAddressNetbios {
    fn default() -> Self {
        Self {
            name_type: 0,
            name: [0x20; 16], // Space-padded
        }
    }
}

/// Generic TDI address union
#[derive(Debug, Clone)]
pub enum TdiAddress {
    /// IPv4 address
    Ip(TdiAddressIp),
    /// IPv6 address
    Ip6(TdiAddressIp6),
    /// NetBIOS address
    NetBios(TdiAddressNetbios),
    /// Unspecified
    Unspecified,
}

impl Default for TdiAddress {
    fn default() -> Self {
        TdiAddress::Unspecified
    }
}

// ============================================================================
// TDI Object Structures
// ============================================================================

/// TDI transport address object
pub struct TdiTransportAddress {
    /// Address ID
    pub address_id: u32,
    /// Active flag
    pub active: bool,
    /// Address type
    pub address_type: u16,
    /// Local address
    pub local_address: TdiAddress,
    /// Protocol (TCP/UDP/etc)
    pub protocol: u8,
    /// Reference count
    pub ref_count: AtomicU32,
    /// Associated connections count
    pub connection_count: u32,
    /// Event handlers
    pub event_handlers: [Option<TdiEventHandler>; 11],
    /// Context for client
    pub context: usize,
    /// Statistics
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
}

impl TdiTransportAddress {
    pub const fn empty() -> Self {
        Self {
            address_id: 0,
            active: false,
            address_type: 0,
            local_address: TdiAddress::Unspecified,
            protocol: 0,
            ref_count: AtomicU32::new(0),
            connection_count: 0,
            event_handlers: [None; 11],
            context: 0,
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
        }
    }
}

impl Clone for TdiTransportAddress {
    fn clone(&self) -> Self {
        Self {
            address_id: self.address_id,
            active: self.active,
            address_type: self.address_type,
            local_address: self.local_address.clone(),
            protocol: self.protocol,
            ref_count: AtomicU32::new(self.ref_count.load(Ordering::Relaxed)),
            connection_count: self.connection_count,
            event_handlers: self.event_handlers.clone(),
            context: self.context,
            bytes_sent: AtomicU64::new(self.bytes_sent.load(Ordering::Relaxed)),
            bytes_received: AtomicU64::new(self.bytes_received.load(Ordering::Relaxed)),
            packets_sent: AtomicU64::new(self.packets_sent.load(Ordering::Relaxed)),
            packets_received: AtomicU64::new(self.packets_received.load(Ordering::Relaxed)),
        }
    }
}

/// TDI event handler callback type
pub type TdiEventHandler = fn(context: usize, event_type: u32, data: &[u8]) -> TdiStatus;

/// TDI connection state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TdiConnectionState {
    /// Not connected
    #[default]
    Idle = 0,
    /// Connection in progress
    Connecting = 1,
    /// Connected
    Connected = 2,
    /// Disconnecting
    Disconnecting = 3,
    /// Listening for connections
    Listening = 4,
    /// Connection accepted, pending setup
    Accepting = 5,
}

/// TDI connection endpoint
pub struct TdiConnectionEndpoint {
    /// Connection ID
    pub connection_id: u32,
    /// Active flag
    pub active: bool,
    /// Connection state
    pub state: TdiConnectionState,
    /// Associated address ID
    pub address_id: u32,
    /// Remote address
    pub remote_address: TdiAddress,
    /// Protocol
    pub protocol: u8,
    /// Reference count
    pub ref_count: AtomicU32,
    /// Context for client
    pub context: usize,
    /// Send buffer
    pub send_buffer: Vec<u8>,
    /// Receive buffer
    pub receive_buffer: Vec<u8>,
    /// Pending send bytes
    pub pending_send: usize,
    /// Pending receive bytes
    pub pending_receive: usize,
    /// Statistics
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    /// Creation time
    pub created_time: u64,
    /// Connection time
    pub connected_time: u64,
}

impl TdiConnectionEndpoint {
    pub const fn empty() -> Self {
        Self {
            connection_id: 0,
            active: false,
            state: TdiConnectionState::Idle,
            address_id: 0,
            remote_address: TdiAddress::Unspecified,
            protocol: 0,
            ref_count: AtomicU32::new(0),
            context: 0,
            send_buffer: Vec::new(),
            receive_buffer: Vec::new(),
            pending_send: 0,
            pending_receive: 0,
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            created_time: 0,
            connected_time: 0,
        }
    }
}

/// TDI control channel
pub struct TdiControlChannel {
    /// Channel ID
    pub channel_id: u32,
    /// Active flag
    pub active: bool,
    /// Transport name
    pub transport_name: [u8; 32],
    /// Reference count
    pub ref_count: AtomicU32,
    /// Context
    pub context: usize,
}

impl TdiControlChannel {
    pub const fn empty() -> Self {
        Self {
            channel_id: 0,
            active: false,
            transport_name: [0; 32],
            ref_count: AtomicU32::new(0),
            context: 0,
        }
    }
}

// ============================================================================
// TDI Request Structure
// ============================================================================

/// TDI request types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdiRequestType {
    /// Open address
    OpenAddress = 1,
    /// Close address
    CloseAddress = 2,
    /// Open connection
    OpenConnection = 3,
    /// Close connection
    CloseConnection = 4,
    /// Associate address
    AssociateAddress = 5,
    /// Disassociate address
    DisassociateAddress = 6,
    /// Connect
    Connect = 7,
    /// Disconnect
    Disconnect = 8,
    /// Listen
    Listen = 9,
    /// Accept
    Accept = 10,
    /// Send
    Send = 11,
    /// Receive
    Receive = 12,
    /// Send datagram
    SendDatagram = 13,
    /// Receive datagram
    ReceiveDatagram = 14,
    /// Set event handler
    SetEventHandler = 15,
    /// Query information
    QueryInformation = 16,
    /// Set information
    SetInformation = 17,
    /// Action (transport-specific)
    Action = 18,
}

/// TDI pending request
pub struct TdiRequest {
    /// Request ID
    pub request_id: u32,
    /// Active flag
    pub active: bool,
    /// Request type
    pub request_type: TdiRequestType,
    /// Associated object ID (address/connection)
    pub object_id: u32,
    /// Request status
    pub status: TdiStatus,
    /// Completion callback
    pub completion: Option<fn(request_id: u32, status: TdiStatus, bytes: usize)>,
    /// Context
    pub context: usize,
    /// Bytes transferred
    pub bytes_transferred: usize,
    /// Request timestamp
    pub timestamp: u64,
}

impl TdiRequest {
    pub const fn empty() -> Self {
        Self {
            request_id: 0,
            active: false,
            request_type: TdiRequestType::OpenAddress,
            object_id: 0,
            status: TdiStatus::Success,
            completion: None,
            context: 0,
            bytes_transferred: 0,
            timestamp: 0,
        }
    }
}

// ============================================================================
// TDI Global State
// ============================================================================

/// TDI subsystem state
struct TdiState {
    /// Transport addresses
    addresses: [TdiTransportAddress; MAX_TDI_ADDRESSES],
    /// Connection endpoints
    connections: [TdiConnectionEndpoint; MAX_TDI_CONNECTIONS],
    /// Control channels
    controls: [TdiControlChannel; MAX_TDI_CONTROLS],
    /// Pending requests
    requests: [TdiRequest; MAX_TDI_REQUESTS],
    /// Next address ID
    next_address_id: u32,
    /// Next connection ID
    next_connection_id: u32,
    /// Next control ID
    next_control_id: u32,
    /// Next request ID
    next_request_id: u32,
}

// Const init arrays
const EMPTY_ADDRESS: TdiTransportAddress = TdiTransportAddress::empty();
const EMPTY_CONNECTION: TdiConnectionEndpoint = TdiConnectionEndpoint::empty();
const EMPTY_CONTROL: TdiControlChannel = TdiControlChannel::empty();
const EMPTY_REQUEST: TdiRequest = TdiRequest::empty();

static TDI_STATE: Mutex<TdiState> = Mutex::new(TdiState {
    addresses: [EMPTY_ADDRESS; MAX_TDI_ADDRESSES],
    connections: [EMPTY_CONNECTION; MAX_TDI_CONNECTIONS],
    controls: [EMPTY_CONTROL; MAX_TDI_CONTROLS],
    requests: [EMPTY_REQUEST; MAX_TDI_REQUESTS],
    next_address_id: 1,
    next_connection_id: 1,
    next_control_id: 1,
    next_request_id: 1,
});

/// TDI initialized flag
static TDI_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// TDI Statistics
// ============================================================================

/// TDI statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct TdiStats {
    /// Active addresses
    pub address_count: usize,
    /// Active connections
    pub connection_count: usize,
    /// Active control channels
    pub control_count: usize,
    /// Pending requests
    pub pending_requests: usize,
    /// Total bytes sent
    pub total_bytes_sent: u64,
    /// Total bytes received
    pub total_bytes_received: u64,
    /// Total connections made
    pub total_connections: u64,
    /// Failed connections
    pub failed_connections: u64,
}

static TDI_STATS: Mutex<TdiStats> = Mutex::new(TdiStats {
    address_count: 0,
    connection_count: 0,
    control_count: 0,
    pending_requests: 0,
    total_bytes_sent: 0,
    total_bytes_received: 0,
    total_connections: 0,
    failed_connections: 0,
});

// ============================================================================
// TDI Address Operations
// ============================================================================

/// Open a transport address
pub fn tdi_open_address(
    address_type: u16,
    address: TdiAddress,
    protocol: u8,
    context: usize,
) -> Result<u32, TdiStatus> {
    let mut state = TDI_STATE.lock();
    let address_id = state.next_address_id;

    // Find free slot
    for idx in 0..MAX_TDI_ADDRESSES {
        if !state.addresses[idx].active {
            state.addresses[idx] = TdiTransportAddress {
                address_id,
                active: true,
                address_type,
                local_address: address,
                protocol,
                ref_count: AtomicU32::new(1),
                connection_count: 0,
                event_handlers: [None; 11],
                context,
                bytes_sent: AtomicU64::new(0),
                bytes_received: AtomicU64::new(0),
                packets_sent: AtomicU64::new(0),
                packets_received: AtomicU64::new(0),
            };

            state.next_address_id += 1;

            // Update stats
            let mut stats = TDI_STATS.lock();
            stats.address_count += 1;
            drop(stats);

            crate::serial_println!("[TDI] Opened address {} (type={}, proto={})",
                address_id, address_type, protocol);

            return Ok(address_id);
        }
    }

    Err(TdiStatus::InsufficientResources)
}

/// Close a transport address
pub fn tdi_close_address(address_id: u32) -> TdiStatus {
    let mut state = TDI_STATE.lock();

    for idx in 0..MAX_TDI_ADDRESSES {
        if state.addresses[idx].active && state.addresses[idx].address_id == address_id {
            // Check for active connections
            if state.addresses[idx].connection_count > 0 {
                return TdiStatus::AddressNotAssociated;
            }

            state.addresses[idx].active = false;

            // Update stats
            let mut stats = TDI_STATS.lock();
            stats.address_count = stats.address_count.saturating_sub(1);
            drop(stats);

            crate::serial_println!("[TDI] Closed address {}", address_id);
            return TdiStatus::Success;
        }
    }

    TdiStatus::NotFound
}

/// Set event handler for address
pub fn tdi_set_event_handler(
    address_id: u32,
    event_type: u32,
    handler: Option<TdiEventHandler>,
) -> TdiStatus {
    let mut state = TDI_STATE.lock();

    for idx in 0..MAX_TDI_ADDRESSES {
        if state.addresses[idx].active && state.addresses[idx].address_id == address_id {
            if event_type as usize >= 11 {
                return TdiStatus::InvalidParameter;
            }

            state.addresses[idx].event_handlers[event_type as usize] = handler;
            return TdiStatus::Success;
        }
    }

    TdiStatus::NotFound
}

// ============================================================================
// TDI Connection Operations
// ============================================================================

/// Open a connection endpoint
pub fn tdi_open_connection(context: usize) -> Result<u32, TdiStatus> {
    let mut state = TDI_STATE.lock();
    let connection_id = state.next_connection_id;

    for idx in 0..MAX_TDI_CONNECTIONS {
        if !state.connections[idx].active {
            state.connections[idx] = TdiConnectionEndpoint {
                connection_id,
                active: true,
                state: TdiConnectionState::Idle,
                address_id: 0,
                remote_address: TdiAddress::Unspecified,
                protocol: 0,
                ref_count: AtomicU32::new(1),
                context,
                send_buffer: Vec::new(),
                receive_buffer: Vec::new(),
                pending_send: 0,
                pending_receive: 0,
                bytes_sent: AtomicU64::new(0),
                bytes_received: AtomicU64::new(0),
                created_time: crate::rtl::rtl_get_system_time() as u64,
                connected_time: 0,
            };

            state.next_connection_id += 1;

            let mut stats = TDI_STATS.lock();
            stats.connection_count += 1;
            drop(stats);

            crate::serial_println!("[TDI] Opened connection {}", connection_id);
            return Ok(connection_id);
        }
    }

    Err(TdiStatus::InsufficientResources)
}

/// Close a connection endpoint
pub fn tdi_close_connection(connection_id: u32) -> TdiStatus {
    let mut state = TDI_STATE.lock();

    for idx in 0..MAX_TDI_CONNECTIONS {
        if state.connections[idx].active && state.connections[idx].connection_id == connection_id {
            // Disconnect if connected
            if state.connections[idx].state == TdiConnectionState::Connected {
                // Would send disconnect here
            }

            // Disassociate from address
            let addr_id = state.connections[idx].address_id;
            if addr_id != 0 {
                for a_idx in 0..MAX_TDI_ADDRESSES {
                    if state.addresses[a_idx].active && state.addresses[a_idx].address_id == addr_id {
                        state.addresses[a_idx].connection_count =
                            state.addresses[a_idx].connection_count.saturating_sub(1);
                        break;
                    }
                }
            }

            state.connections[idx].active = false;
            state.connections[idx].send_buffer.clear();
            state.connections[idx].receive_buffer.clear();

            let mut stats = TDI_STATS.lock();
            stats.connection_count = stats.connection_count.saturating_sub(1);
            drop(stats);

            crate::serial_println!("[TDI] Closed connection {}", connection_id);
            return TdiStatus::Success;
        }
    }

    TdiStatus::NotFound
}

/// Associate connection with address
pub fn tdi_associate_address(connection_id: u32, address_id: u32) -> TdiStatus {
    let mut state = TDI_STATE.lock();

    // Find connection
    let mut conn_idx = None;
    for idx in 0..MAX_TDI_CONNECTIONS {
        if state.connections[idx].active && state.connections[idx].connection_id == connection_id {
            if state.connections[idx].address_id != 0 {
                return TdiStatus::AlreadyConnected;
            }
            conn_idx = Some(idx);
            break;
        }
    }

    let conn_idx = match conn_idx {
        Some(idx) => idx,
        None => return TdiStatus::NotFound,
    };

    // Find and verify address
    for idx in 0..MAX_TDI_ADDRESSES {
        if state.addresses[idx].active && state.addresses[idx].address_id == address_id {
            state.connections[conn_idx].address_id = address_id;
            state.connections[conn_idx].protocol = state.addresses[idx].protocol;
            state.addresses[idx].connection_count += 1;

            crate::serial_println!("[TDI] Associated connection {} with address {}",
                connection_id, address_id);
            return TdiStatus::Success;
        }
    }

    TdiStatus::InvalidAddress
}

/// Disassociate connection from address
pub fn tdi_disassociate_address(connection_id: u32) -> TdiStatus {
    let mut state = TDI_STATE.lock();

    for idx in 0..MAX_TDI_CONNECTIONS {
        if state.connections[idx].active && state.connections[idx].connection_id == connection_id {
            let addr_id = state.connections[idx].address_id;

            if addr_id == 0 {
                return TdiStatus::AddressNotAssociated;
            }

            // Must not be connected
            if state.connections[idx].state != TdiConnectionState::Idle {
                return TdiStatus::InvalidParameter;
            }

            // Decrement address connection count
            for a_idx in 0..MAX_TDI_ADDRESSES {
                if state.addresses[a_idx].active && state.addresses[a_idx].address_id == addr_id {
                    state.addresses[a_idx].connection_count =
                        state.addresses[a_idx].connection_count.saturating_sub(1);
                    break;
                }
            }

            state.connections[idx].address_id = 0;

            crate::serial_println!("[TDI] Disassociated connection {}", connection_id);
            return TdiStatus::Success;
        }
    }

    TdiStatus::NotFound
}

/// Connect to remote endpoint
pub fn tdi_connect(
    connection_id: u32,
    remote_address: TdiAddress,
    timeout_ms: Option<u32>,
) -> TdiStatus {
    let mut state = TDI_STATE.lock();

    for idx in 0..MAX_TDI_CONNECTIONS {
        if state.connections[idx].active && state.connections[idx].connection_id == connection_id {
            if state.connections[idx].address_id == 0 {
                return TdiStatus::AddressNotAssociated;
            }

            if state.connections[idx].state != TdiConnectionState::Idle {
                return TdiStatus::AlreadyConnected;
            }

            state.connections[idx].state = TdiConnectionState::Connecting;
            state.connections[idx].remote_address = remote_address;

            // In a real implementation, this would initiate TCP handshake
            // For now, simulate immediate connection
            state.connections[idx].state = TdiConnectionState::Connected;
            state.connections[idx].connected_time = crate::rtl::rtl_get_system_time() as u64;

            let mut stats = TDI_STATS.lock();
            stats.total_connections += 1;
            drop(stats);

            crate::serial_println!("[TDI] Connection {} connected", connection_id);
            return TdiStatus::Success;
        }
    }

    TdiStatus::NotFound
}

/// Disconnect from remote endpoint
pub fn tdi_disconnect(connection_id: u32, flags: u32) -> TdiStatus {
    let mut state = TDI_STATE.lock();

    for idx in 0..MAX_TDI_CONNECTIONS {
        if state.connections[idx].active && state.connections[idx].connection_id == connection_id {
            if state.connections[idx].state != TdiConnectionState::Connected {
                return TdiStatus::NotConnected;
            }

            state.connections[idx].state = TdiConnectionState::Disconnecting;

            // In a real implementation, would send FIN or RST based on flags
            let _abortive = (flags & connection_flags::TDI_DISCONNECT_ABORT) != 0;

            state.connections[idx].state = TdiConnectionState::Idle;
            state.connections[idx].remote_address = TdiAddress::Unspecified;

            crate::serial_println!("[TDI] Connection {} disconnected", connection_id);
            return TdiStatus::Success;
        }
    }

    TdiStatus::NotFound
}

/// Listen for incoming connections
pub fn tdi_listen(connection_id: u32, backlog: u32) -> TdiStatus {
    let mut state = TDI_STATE.lock();

    for idx in 0..MAX_TDI_CONNECTIONS {
        if state.connections[idx].active && state.connections[idx].connection_id == connection_id {
            if state.connections[idx].address_id == 0 {
                return TdiStatus::AddressNotAssociated;
            }

            if state.connections[idx].state != TdiConnectionState::Idle {
                return TdiStatus::InvalidParameter;
            }

            state.connections[idx].state = TdiConnectionState::Listening;

            crate::serial_println!("[TDI] Connection {} listening (backlog={})",
                connection_id, backlog);
            return TdiStatus::Success;
        }
    }

    TdiStatus::NotFound
}

// ============================================================================
// TDI Data Transfer Operations
// ============================================================================

/// Send data on connection
pub fn tdi_send(
    connection_id: u32,
    data: &[u8],
    flags: u32,
) -> Result<usize, TdiStatus> {
    let mut state = TDI_STATE.lock();

    for idx in 0..MAX_TDI_CONNECTIONS {
        if state.connections[idx].active && state.connections[idx].connection_id == connection_id {
            if state.connections[idx].state != TdiConnectionState::Connected {
                return Err(TdiStatus::NotConnected);
            }

            // In real implementation, would queue data for transmission
            let sent = data.len();
            state.connections[idx].bytes_sent.fetch_add(sent as u64, Ordering::Relaxed);

            // Update global stats
            let mut stats = TDI_STATS.lock();
            stats.total_bytes_sent += sent as u64;
            drop(stats);

            return Ok(sent);
        }
    }

    Err(TdiStatus::NotFound)
}

/// Receive data on connection
pub fn tdi_receive(
    connection_id: u32,
    buffer: &mut [u8],
    flags: u32,
) -> Result<usize, TdiStatus> {
    let mut state = TDI_STATE.lock();

    for idx in 0..MAX_TDI_CONNECTIONS {
        if state.connections[idx].active && state.connections[idx].connection_id == connection_id {
            if state.connections[idx].state != TdiConnectionState::Connected {
                return Err(TdiStatus::NotConnected);
            }

            // Copy from receive buffer
            let available = state.connections[idx].receive_buffer.len();
            let to_copy = available.min(buffer.len());

            if to_copy > 0 {
                buffer[..to_copy].copy_from_slice(&state.connections[idx].receive_buffer[..to_copy]);

                let peek = (flags & tdi_flags::TDI_RECEIVE_PEEK) != 0;
                if !peek {
                    state.connections[idx].receive_buffer.drain(..to_copy);
                }

                state.connections[idx].bytes_received.fetch_add(to_copy as u64, Ordering::Relaxed);

                let mut stats = TDI_STATS.lock();
                stats.total_bytes_received += to_copy as u64;
                drop(stats);
            }

            return Ok(to_copy);
        }
    }

    Err(TdiStatus::NotFound)
}

/// Send datagram (UDP)
pub fn tdi_send_datagram(
    address_id: u32,
    remote_address: &TdiAddress,
    data: &[u8],
) -> Result<usize, TdiStatus> {
    let mut state = TDI_STATE.lock();

    for idx in 0..MAX_TDI_ADDRESSES {
        if state.addresses[idx].active && state.addresses[idx].address_id == address_id {
            // In real implementation, would send via UDP
            let sent = data.len();
            state.addresses[idx].bytes_sent.fetch_add(sent as u64, Ordering::Relaxed);
            state.addresses[idx].packets_sent.fetch_add(1, Ordering::Relaxed);

            let mut stats = TDI_STATS.lock();
            stats.total_bytes_sent += sent as u64;
            drop(stats);

            return Ok(sent);
        }
    }

    Err(TdiStatus::NotFound)
}

/// Receive datagram (UDP)
pub fn tdi_receive_datagram(
    address_id: u32,
    buffer: &mut [u8],
    remote_address: &mut TdiAddress,
) -> Result<usize, TdiStatus> {
    let state = TDI_STATE.lock();

    for idx in 0..MAX_TDI_ADDRESSES {
        if state.addresses[idx].active && state.addresses[idx].address_id == address_id {
            // In real implementation, would receive from UDP queue
            // For now, return no data available
            return Ok(0);
        }
    }

    Err(TdiStatus::NotFound)
}

// ============================================================================
// TDI Query/Set Information
// ============================================================================

/// TDI information classes
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum TdiInformationClass {
    /// Address info
    AddressInfo = 1,
    /// Connection info
    ConnectionInfo = 2,
    /// Provider info
    ProviderInfo = 3,
    /// Provider statistics
    ProviderStats = 4,
}

/// Query TDI information
pub fn tdi_query_information(
    object_id: u32,
    info_class: TdiInformationClass,
) -> Result<Vec<u8>, TdiStatus> {
    let state = TDI_STATE.lock();

    match info_class {
        TdiInformationClass::AddressInfo => {
            for idx in 0..MAX_TDI_ADDRESSES {
                if state.addresses[idx].active && state.addresses[idx].address_id == object_id {
                    // Return address info as bytes
                    let info = TdiAddressInfo {
                        address_type: state.addresses[idx].address_type,
                        protocol: state.addresses[idx].protocol,
                        connection_count: state.addresses[idx].connection_count,
                    };

                    let bytes = unsafe {
                        core::slice::from_raw_parts(
                            &info as *const TdiAddressInfo as *const u8,
                            core::mem::size_of::<TdiAddressInfo>()
                        )
                    };
                    return Ok(bytes.to_vec());
                }
            }
        }
        TdiInformationClass::ConnectionInfo => {
            for idx in 0..MAX_TDI_CONNECTIONS {
                if state.connections[idx].active && state.connections[idx].connection_id == object_id {
                    let info = TdiConnectionInfo {
                        state: state.connections[idx].state as u8,
                        address_id: state.connections[idx].address_id,
                        bytes_sent: state.connections[idx].bytes_sent.load(Ordering::Relaxed),
                        bytes_received: state.connections[idx].bytes_received.load(Ordering::Relaxed),
                    };

                    let bytes = unsafe {
                        core::slice::from_raw_parts(
                            &info as *const TdiConnectionInfo as *const u8,
                            core::mem::size_of::<TdiConnectionInfo>()
                        )
                    };
                    return Ok(bytes.to_vec());
                }
            }
        }
        _ => return Err(TdiStatus::NotSupported),
    }

    Err(TdiStatus::NotFound)
}

/// TDI address info structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TdiAddressInfo {
    pub address_type: u16,
    pub protocol: u8,
    pub connection_count: u32,
}

/// TDI connection info structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TdiConnectionInfo {
    pub state: u8,
    pub address_id: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

// ============================================================================
// TDI Statistics and Diagnostics
// ============================================================================

/// Get TDI statistics
pub fn tdi_get_stats() -> TdiStats {
    *TDI_STATS.lock()
}

/// TDI address snapshot for diagnostics
#[derive(Debug, Clone)]
pub struct TdiAddressSnapshot {
    pub address_id: u32,
    pub address_type: u16,
    pub protocol: u8,
    pub connection_count: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Get TDI address snapshots
pub fn tdi_get_address_snapshots() -> Vec<TdiAddressSnapshot> {
    let state = TDI_STATE.lock();
    let mut snapshots = Vec::new();

    for addr in state.addresses.iter() {
        if addr.active {
            snapshots.push(TdiAddressSnapshot {
                address_id: addr.address_id,
                address_type: addr.address_type,
                protocol: addr.protocol,
                connection_count: addr.connection_count,
                bytes_sent: addr.bytes_sent.load(Ordering::Relaxed),
                bytes_received: addr.bytes_received.load(Ordering::Relaxed),
            });
        }
    }

    snapshots
}

/// TDI connection snapshot for diagnostics
#[derive(Debug, Clone)]
pub struct TdiConnectionSnapshot {
    pub connection_id: u32,
    pub state: TdiConnectionState,
    pub address_id: u32,
    pub protocol: u8,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Get TDI connection snapshots
pub fn tdi_get_connection_snapshots() -> Vec<TdiConnectionSnapshot> {
    let state = TDI_STATE.lock();
    let mut snapshots = Vec::new();

    for conn in state.connections.iter() {
        if conn.active {
            snapshots.push(TdiConnectionSnapshot {
                connection_id: conn.connection_id,
                state: conn.state,
                address_id: conn.address_id,
                protocol: conn.protocol,
                bytes_sent: conn.bytes_sent.load(Ordering::Relaxed),
                bytes_received: conn.bytes_received.load(Ordering::Relaxed),
            });
        }
    }

    snapshots
}

// ============================================================================
// TDI Initialization
// ============================================================================

/// Initialize TDI subsystem
pub fn init() {
    if TDI_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[TDI] Transport Driver Interface initialized");
    crate::serial_println!("[TDI]   Max addresses: {}", MAX_TDI_ADDRESSES);
    crate::serial_println!("[TDI]   Max connections: {}", MAX_TDI_CONNECTIONS);
}

/// Check if TDI is initialized
pub fn is_initialized() -> bool {
    TDI_INITIALIZED.load(Ordering::SeqCst)
}
