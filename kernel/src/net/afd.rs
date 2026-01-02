//! AFD (Ancillary Function Driver) for Winsock
//!
//! AFD provides the kernel-mode socket layer that Winsock (ws2_32.dll) uses.
//! It sits between user-mode Winsock and the TDI transport layer.
//!
//! Key responsibilities:
//! - Socket creation and management
//! - Bind, listen, connect, accept operations
//! - Send/receive data buffering
//! - Socket options management
//! - Async I/O and completion ports

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// Maximum number of sockets
const MAX_SOCKETS: usize = 4096;

/// Maximum number of pending connections for listen
const MAX_BACKLOG: usize = 128;

/// Default receive buffer size
const DEFAULT_RECV_BUFFER_SIZE: usize = 65536;

/// Default send buffer size
const DEFAULT_SEND_BUFFER_SIZE: usize = 65536;

/// Maximum pending I/O operations per socket
const MAX_PENDING_IO: usize = 64;

// ============================================================================
// Address Families
// ============================================================================

/// Address family types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AddressFamily {
    /// Unspecified
    Unspec = 0,
    /// Unix domain sockets
    Unix = 1,
    /// IPv4
    Inet = 2,
    /// IPX/SPX
    Ipx = 6,
    /// NetBIOS
    NetBios = 17,
    /// IPv6
    Inet6 = 23,
    /// IrDA
    Irda = 26,
    /// Bluetooth
    Bluetooth = 32,
}

impl From<u16> for AddressFamily {
    fn from(value: u16) -> Self {
        match value {
            0 => AddressFamily::Unspec,
            1 => AddressFamily::Unix,
            2 => AddressFamily::Inet,
            6 => AddressFamily::Ipx,
            17 => AddressFamily::NetBios,
            23 => AddressFamily::Inet6,
            26 => AddressFamily::Irda,
            32 => AddressFamily::Bluetooth,
            _ => AddressFamily::Unspec,
        }
    }
}

// ============================================================================
// Socket Types
// ============================================================================

/// Socket type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SocketType {
    /// Stream socket (TCP)
    Stream = 1,
    /// Datagram socket (UDP)
    Dgram = 2,
    /// Raw socket
    Raw = 3,
    /// Reliably-delivered message
    Rdm = 4,
    /// Sequenced packet stream
    SeqPacket = 5,
}

impl From<i32> for SocketType {
    fn from(value: i32) -> Self {
        match value {
            1 => SocketType::Stream,
            2 => SocketType::Dgram,
            3 => SocketType::Raw,
            4 => SocketType::Rdm,
            5 => SocketType::SeqPacket,
            _ => SocketType::Stream,
        }
    }
}

// ============================================================================
// Protocol Types
// ============================================================================

/// IP protocol numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Protocol {
    /// IP protocol
    Ip = 0,
    /// ICMP
    Icmp = 1,
    /// IGMP
    Igmp = 2,
    /// TCP
    Tcp = 6,
    /// UDP
    Udp = 17,
    /// ICMPv6
    Icmpv6 = 58,
    /// Raw IP
    Raw = 255,
}

impl From<i32> for Protocol {
    fn from(value: i32) -> Self {
        match value {
            0 => Protocol::Ip,
            1 => Protocol::Icmp,
            2 => Protocol::Igmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            58 => Protocol::Icmpv6,
            255 => Protocol::Raw,
            _ => Protocol::Ip,
        }
    }
}

// ============================================================================
// Socket States
// ============================================================================

/// Socket state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    /// Socket created but not bound
    Created,
    /// Socket bound to local address
    Bound,
    /// Socket listening for connections
    Listening,
    /// Connection in progress
    Connecting,
    /// Socket connected
    Connected,
    /// Connection closing
    Closing,
    /// Socket closed
    Closed,
    /// Socket in error state
    Error,
}

// ============================================================================
// Socket Addresses
// ============================================================================

/// IPv4 socket address
#[derive(Debug, Clone, Copy, Default)]
pub struct SockAddrIn {
    /// Address family (AF_INET)
    pub family: u16,
    /// Port number (network byte order)
    pub port: u16,
    /// IPv4 address
    pub addr: [u8; 4],
    /// Padding
    pub zero: [u8; 8],
}

/// IPv6 socket address
#[derive(Debug, Clone, Copy)]
pub struct SockAddrIn6 {
    /// Address family (AF_INET6)
    pub family: u16,
    /// Port number (network byte order)
    pub port: u16,
    /// Flow info
    pub flowinfo: u32,
    /// IPv6 address
    pub addr: [u8; 16],
    /// Scope ID
    pub scope_id: u32,
}

impl Default for SockAddrIn6 {
    fn default() -> Self {
        Self {
            family: AddressFamily::Inet6 as u16,
            port: 0,
            flowinfo: 0,
            addr: [0; 16],
            scope_id: 0,
        }
    }
}

/// Generic socket address
#[derive(Debug, Clone, Copy)]
pub enum SockAddr {
    /// IPv4 address
    V4(SockAddrIn),
    /// IPv6 address
    V6(SockAddrIn6),
    /// Unknown/unspecified
    Unknown,
}

impl Default for SockAddr {
    fn default() -> Self {
        SockAddr::Unknown
    }
}

// ============================================================================
// Socket Options
// ============================================================================

/// Socket option levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SocketLevel {
    /// Socket level options
    Socket = 0xFFFF,
    /// IP level options
    IpProto = 0,
    /// TCP level options
    Tcp = 6,
    /// UDP level options
    Udp = 17,
    /// IPv6 level options
    Ipv6 = 41,
}

/// Socket-level options (SOL_SOCKET)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SocketOption {
    /// Enable debugging
    Debug = 0x0001,
    /// Allow local address reuse
    ReuseAddr = 0x0004,
    /// Keep connections alive
    KeepAlive = 0x0008,
    /// Don't route
    DontRoute = 0x0010,
    /// Allow broadcast
    Broadcast = 0x0020,
    /// Use loopback
    UseLoopback = 0x0040,
    /// Linger on close
    Linger = 0x0080,
    /// OOB data inline
    OobInline = 0x0100,
    /// Exclusive address use
    ExclusiveAddrUse = 0x0104,
    /// Send buffer size
    SndBuf = 0x1001,
    /// Receive buffer size
    RcvBuf = 0x1002,
    /// Send low water mark
    SndLowat = 0x1003,
    /// Receive low water mark
    RcvLowat = 0x1004,
    /// Send timeout
    SndTimeo = 0x1005,
    /// Receive timeout
    RcvTimeo = 0x1006,
    /// Get error status
    Error = 0x1007,
    /// Get socket type
    Type = 0x1008,
    /// Conditional accept
    ConditionalAccept = 0x3002,
}

/// TCP-level options (IPPROTO_TCP)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum TcpOption {
    /// Disable Nagle algorithm
    NoDelay = 1,
    /// Maximum segment size
    MaxSeg = 2,
    /// Keep-alive interval
    KeepIdle = 3,
    /// Keep-alive probe interval
    KeepIntvl = 4,
    /// Keep-alive probe count
    KeepCnt = 5,
}

/// Socket options storage
#[derive(Debug, Clone)]
pub struct SocketOptions {
    /// SO_REUSEADDR
    pub reuse_addr: bool,
    /// SO_KEEPALIVE
    pub keep_alive: bool,
    /// SO_BROADCAST
    pub broadcast: bool,
    /// SO_DONTROUTE
    pub dont_route: bool,
    /// SO_OOBINLINE
    pub oob_inline: bool,
    /// SO_SNDBUF
    pub send_buffer_size: usize,
    /// SO_RCVBUF
    pub recv_buffer_size: usize,
    /// SO_SNDTIMEO (milliseconds)
    pub send_timeout: u32,
    /// SO_RCVTIMEO (milliseconds)
    pub recv_timeout: u32,
    /// SO_LINGER
    pub linger: Option<u16>,
    /// TCP_NODELAY
    pub tcp_nodelay: bool,
    /// TCP_KEEPIDLE (seconds)
    pub tcp_keepidle: u32,
    /// TCP_KEEPINTVL (seconds)
    pub tcp_keepintvl: u32,
    /// TCP_KEEPCNT
    pub tcp_keepcnt: u32,
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self {
            reuse_addr: false,
            keep_alive: false,
            broadcast: false,
            dont_route: false,
            oob_inline: false,
            send_buffer_size: DEFAULT_SEND_BUFFER_SIZE,
            recv_buffer_size: DEFAULT_RECV_BUFFER_SIZE,
            send_timeout: 0,
            recv_timeout: 0,
            linger: None,
            tcp_nodelay: false,
            tcp_keepidle: 7200,
            tcp_keepintvl: 75,
            tcp_keepcnt: 8,
        }
    }
}

// ============================================================================
// I/O Operations
// ============================================================================

/// I/O operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOperationType {
    /// Accept connection
    Accept,
    /// Connect to remote
    Connect,
    /// Receive data
    Recv,
    /// Send data
    Send,
    /// Receive from (UDP)
    RecvFrom,
    /// Send to (UDP)
    SendTo,
    /// Disconnect
    Disconnect,
}

/// I/O operation state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOperationState {
    /// Operation pending
    Pending,
    /// Operation completed successfully
    Completed,
    /// Operation failed
    Failed,
    /// Operation cancelled
    Cancelled,
}

/// Pending I/O operation
#[derive(Debug)]
pub struct IoOperation {
    /// Operation ID
    pub id: u64,
    /// Operation type
    pub op_type: IoOperationType,
    /// Operation state
    pub state: IoOperationState,
    /// Associated socket
    pub socket_id: u64,
    /// Buffer for data
    pub buffer: Vec<u8>,
    /// Bytes transferred
    pub bytes_transferred: usize,
    /// Error code (if failed)
    pub error: i32,
    /// Remote address (for recvfrom/sendto)
    pub remote_addr: Option<SockAddr>,
    /// Completion callback context
    pub context: u64,
}

// ============================================================================
// Socket Structure
// ============================================================================

/// AFD socket
pub struct AfdSocket {
    /// Socket ID (handle)
    pub id: u64,
    /// Address family
    pub family: AddressFamily,
    /// Socket type
    pub socket_type: SocketType,
    /// Protocol
    pub protocol: Protocol,
    /// Current state
    pub state: SocketState,
    /// Local address
    pub local_addr: SockAddr,
    /// Remote address (for connected sockets)
    pub remote_addr: SockAddr,
    /// Socket options
    pub options: SocketOptions,
    /// Receive buffer
    pub recv_buffer: VecDeque<u8>,
    /// Send buffer
    pub send_buffer: VecDeque<u8>,
    /// Pending accept connections
    pub accept_queue: VecDeque<u64>,
    /// Listen backlog
    pub backlog: usize,
    /// TDI address handle
    pub tdi_address: u64,
    /// TDI connection handle
    pub tdi_connection: u64,
    /// Non-blocking mode
    pub non_blocking: bool,
    /// Last error
    pub last_error: i32,
    /// Reference count
    pub ref_count: u32,
    /// Owning process ID
    pub process_id: u32,
    /// Creation time
    pub create_time: u64,
    /// Socket is active
    pub active: bool,
}

impl Default for AfdSocket {
    fn default() -> Self {
        Self {
            id: 0,
            family: AddressFamily::Unspec,
            socket_type: SocketType::Stream,
            protocol: Protocol::Ip,
            state: SocketState::Created,
            local_addr: SockAddr::Unknown,
            remote_addr: SockAddr::Unknown,
            options: SocketOptions::default(),
            recv_buffer: VecDeque::new(),
            send_buffer: VecDeque::new(),
            accept_queue: VecDeque::new(),
            backlog: 0,
            tdi_address: 0,
            tdi_connection: 0,
            non_blocking: false,
            last_error: 0,
            ref_count: 1,
            process_id: 0,
            create_time: 0,
            active: false,
        }
    }
}

// ============================================================================
// AFD Statistics
// ============================================================================

/// AFD statistics
#[derive(Debug)]
pub struct AfdStatistics {
    /// Total sockets created
    pub sockets_created: AtomicU64,
    /// Total sockets closed
    pub sockets_closed: AtomicU64,
    /// Active sockets
    pub sockets_active: AtomicU32,
    /// Bytes sent
    pub bytes_sent: AtomicU64,
    /// Bytes received
    pub bytes_received: AtomicU64,
    /// Connections accepted
    pub connections_accepted: AtomicU64,
    /// Connections established
    pub connections_established: AtomicU64,
    /// Send operations
    pub send_operations: AtomicU64,
    /// Receive operations
    pub recv_operations: AtomicU64,
    /// Pending I/O operations
    pub pending_io: AtomicU32,
}

impl Default for AfdStatistics {
    fn default() -> Self {
        Self {
            sockets_created: AtomicU64::new(0),
            sockets_closed: AtomicU64::new(0),
            sockets_active: AtomicU32::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            connections_accepted: AtomicU64::new(0),
            connections_established: AtomicU64::new(0),
            send_operations: AtomicU64::new(0),
            recv_operations: AtomicU64::new(0),
            pending_io: AtomicU32::new(0),
        }
    }
}

// ============================================================================
// AFD Error Codes
// ============================================================================

/// AFD/Winsock error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum WsaError {
    /// Success
    Success = 0,
    /// Permission denied
    EAcces = 10013,
    /// Address already in use
    EAddrInUse = 10048,
    /// Address not available
    EAddrNotAvail = 10049,
    /// Address family not supported
    EAfNoSupport = 10047,
    /// Operation would block
    EWouldBlock = 10035,
    /// Operation now in progress
    EInProgress = 10036,
    /// Operation already in progress
    EAlready = 10037,
    /// Socket is not a socket
    ENotSock = 10038,
    /// Destination address required
    EDestAddrReq = 10039,
    /// Message too long
    EMsgSize = 10040,
    /// Protocol not supported
    EProtoNoSupport = 10043,
    /// Socket type not supported
    ESockTNoSupport = 10044,
    /// Operation not supported
    EOpNotSupp = 10045,
    /// Protocol family not supported
    EPfNoSupport = 10046,
    /// Network is down
    ENetDown = 10050,
    /// Network is unreachable
    ENetUnreach = 10051,
    /// Network dropped connection
    ENetReset = 10052,
    /// Connection aborted
    EConnAborted = 10053,
    /// Connection reset
    EConnReset = 10054,
    /// No buffer space
    ENoBufs = 10055,
    /// Socket already connected
    EIsConn = 10056,
    /// Socket not connected
    ENotConn = 10057,
    /// Socket is shut down
    EShutdown = 10058,
    /// Connection timed out
    ETimedOut = 10060,
    /// Connection refused
    EConnRefused = 10061,
    /// Host is down
    EHostDown = 10064,
    /// Host unreachable
    EHostUnreach = 10065,
    /// Too many processes
    EProclim = 10067,
    /// Too many sockets
    EMFile = 10024,
    /// Invalid argument
    EInval = 10022,
    /// Bad file descriptor
    EBadF = 10009,
    /// Winsock not initialized
    ENotInitialised = 10093,
    /// Graceful shutdown in progress
    EDiscon = 10101,
}

// ============================================================================
// AFD State
// ============================================================================

/// AFD global state
pub struct AfdState {
    /// Socket table
    pub sockets: [AfdSocket; MAX_SOCKETS],
    /// Next socket ID
    pub next_socket_id: u64,
    /// Pending I/O operations
    pub pending_ops: [Option<IoOperation>; MAX_PENDING_IO],
    /// Next operation ID
    pub next_op_id: u64,
    /// Statistics
    pub statistics: AfdStatistics,
    /// Initialized flag
    pub initialized: bool,
}

impl AfdState {
    const fn new() -> Self {
        const DEFAULT_SOCKET: AfdSocket = AfdSocket {
            id: 0,
            family: AddressFamily::Unspec,
            socket_type: SocketType::Stream,
            protocol: Protocol::Ip,
            state: SocketState::Created,
            local_addr: SockAddr::Unknown,
            remote_addr: SockAddr::Unknown,
            options: SocketOptions {
                reuse_addr: false,
                keep_alive: false,
                broadcast: false,
                dont_route: false,
                oob_inline: false,
                send_buffer_size: DEFAULT_SEND_BUFFER_SIZE,
                recv_buffer_size: DEFAULT_RECV_BUFFER_SIZE,
                send_timeout: 0,
                recv_timeout: 0,
                linger: None,
                tcp_nodelay: false,
                tcp_keepidle: 7200,
                tcp_keepintvl: 75,
                tcp_keepcnt: 8,
            },
            recv_buffer: VecDeque::new(),
            send_buffer: VecDeque::new(),
            accept_queue: VecDeque::new(),
            backlog: 0,
            tdi_address: 0,
            tdi_connection: 0,
            non_blocking: false,
            last_error: 0,
            ref_count: 1,
            process_id: 0,
            create_time: 0,
            active: false,
        };

        const NONE_OP: Option<IoOperation> = None;

        Self {
            sockets: [DEFAULT_SOCKET; MAX_SOCKETS],
            next_socket_id: 1,
            pending_ops: [NONE_OP; MAX_PENDING_IO],
            next_op_id: 1,
            statistics: AfdStatistics {
                sockets_created: AtomicU64::new(0),
                sockets_closed: AtomicU64::new(0),
                sockets_active: AtomicU32::new(0),
                bytes_sent: AtomicU64::new(0),
                bytes_received: AtomicU64::new(0),
                connections_accepted: AtomicU64::new(0),
                connections_established: AtomicU64::new(0),
                send_operations: AtomicU64::new(0),
                recv_operations: AtomicU64::new(0),
                pending_io: AtomicU32::new(0),
            },
            initialized: false,
        }
    }
}

/// Global AFD state
static AFD_STATE: SpinLock<AfdState> = SpinLock::new(AfdState::new());

// ============================================================================
// Socket Operations
// ============================================================================

/// Create a new socket
pub fn afd_create_socket(
    family: AddressFamily,
    socket_type: SocketType,
    protocol: Protocol,
    process_id: u32,
) -> Result<u64, WsaError> {
    let mut state = AFD_STATE.lock();

    if !state.initialized {
        return Err(WsaError::ENotInitialised);
    }

    // Find free slot
    let mut slot_idx = None;
    for idx in 0..MAX_SOCKETS {
        if !state.sockets[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(WsaError::EMFile)?;

    let socket_id = state.next_socket_id;
    state.next_socket_id += 1;

    state.sockets[idx] = AfdSocket {
        id: socket_id,
        family,
        socket_type,
        protocol,
        state: SocketState::Created,
        local_addr: SockAddr::Unknown,
        remote_addr: SockAddr::Unknown,
        options: SocketOptions::default(),
        recv_buffer: VecDeque::with_capacity(DEFAULT_RECV_BUFFER_SIZE),
        send_buffer: VecDeque::with_capacity(DEFAULT_SEND_BUFFER_SIZE),
        accept_queue: VecDeque::new(),
        backlog: 0,
        tdi_address: 0,
        tdi_connection: 0,
        non_blocking: false,
        last_error: 0,
        ref_count: 1,
        process_id,
        create_time: 0, // TODO: Use system time
        active: true,
    };

    state.statistics.sockets_created.fetch_add(1, Ordering::Relaxed);
    state.statistics.sockets_active.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[AFD] Created socket {} (family={:?}, type={:?})",
        socket_id, family, socket_type);

    Ok(socket_id)
}

/// Close a socket
pub fn afd_close_socket(socket_id: u64) -> Result<(), WsaError> {
    let mut state = AFD_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WsaError::ENotSock)?;

    // Decrement reference count
    state.sockets[idx].ref_count = state.sockets[idx].ref_count.saturating_sub(1);

    if state.sockets[idx].ref_count == 0 {
        // Close TDI handles if present
        // TODO: Call tdi_close_address and tdi_close_connection

        state.sockets[idx].state = SocketState::Closed;
        state.sockets[idx].active = false;

        state.statistics.sockets_closed.fetch_add(1, Ordering::Relaxed);
        state.statistics.sockets_active.fetch_sub(1, Ordering::Relaxed);

        crate::serial_println!("[AFD] Closed socket {}", socket_id);
    }

    Ok(())
}

/// Bind socket to local address
pub fn afd_bind(socket_id: u64, addr: &SockAddr) -> Result<(), WsaError> {
    let mut state = AFD_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WsaError::ENotSock)?;

    if state.sockets[idx].state != SocketState::Created {
        return Err(WsaError::EInval);
    }

    // Check if address is already in use (if not SO_REUSEADDR)
    if !state.sockets[idx].options.reuse_addr {
        for i in 0..MAX_SOCKETS {
            if i != idx && state.sockets[i].active {
                if addresses_match(&state.sockets[i].local_addr, addr) {
                    return Err(WsaError::EAddrInUse);
                }
            }
        }
    }

    state.sockets[idx].local_addr = *addr;
    state.sockets[idx].state = SocketState::Bound;

    // TODO: Open TDI address

    crate::serial_println!("[AFD] Socket {} bound to address", socket_id);

    Ok(())
}

/// Start listening for connections
pub fn afd_listen(socket_id: u64, backlog: usize) -> Result<(), WsaError> {
    let mut state = AFD_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WsaError::ENotSock)?;

    // Must be bound and stream socket
    if state.sockets[idx].state != SocketState::Bound {
        return Err(WsaError::EInval);
    }

    if state.sockets[idx].socket_type != SocketType::Stream {
        return Err(WsaError::EOpNotSupp);
    }

    let actual_backlog = if backlog > MAX_BACKLOG { MAX_BACKLOG } else { backlog };

    state.sockets[idx].backlog = actual_backlog;
    state.sockets[idx].state = SocketState::Listening;

    crate::serial_println!("[AFD] Socket {} listening (backlog={})", socket_id, actual_backlog);

    Ok(())
}

/// Accept a connection
pub fn afd_accept(listen_socket_id: u64, process_id: u32) -> Result<u64, WsaError> {
    // First check if we have a pending connection
    let pending_socket_id;
    let family;
    let socket_type;
    let protocol;

    {
        let mut state = AFD_STATE.lock();

        let mut found_idx = None;
        for idx in 0..MAX_SOCKETS {
            if state.sockets[idx].active && state.sockets[idx].id == listen_socket_id {
                found_idx = Some(idx);
                break;
            }
        }

        let idx = found_idx.ok_or(WsaError::ENotSock)?;

        if state.sockets[idx].state != SocketState::Listening {
            return Err(WsaError::EInval);
        }

        // Check for pending connection
        if let Some(pending_id) = state.sockets[idx].accept_queue.pop_front() {
            pending_socket_id = Some(pending_id);
        } else {
            pending_socket_id = None;
        }

        family = state.sockets[idx].family;
        socket_type = state.sockets[idx].socket_type;
        protocol = state.sockets[idx].protocol;
    }

    if let Some(accepted_id) = pending_socket_id {
        // Mark as connected
        let mut state = AFD_STATE.lock();
        for idx in 0..MAX_SOCKETS {
            if state.sockets[idx].active && state.sockets[idx].id == accepted_id {
                state.sockets[idx].state = SocketState::Connected;
                break;
            }
        }

        state.statistics.connections_accepted.fetch_add(1, Ordering::Relaxed);

        crate::serial_println!("[AFD] Accepted connection on socket {}", listen_socket_id);
        return Ok(accepted_id);
    }

    // No pending connection, create new socket for incoming
    let new_socket_id = afd_create_socket(family, socket_type, protocol, process_id)?;

    {
        let mut state = AFD_STATE.lock();
        for idx in 0..MAX_SOCKETS {
            if state.sockets[idx].active && state.sockets[idx].id == new_socket_id {
                state.sockets[idx].state = SocketState::Connected;
                break;
            }
        }
        state.statistics.connections_accepted.fetch_add(1, Ordering::Relaxed);
    }

    Ok(new_socket_id)
}

/// Connect to remote address
pub fn afd_connect(socket_id: u64, addr: &SockAddr) -> Result<(), WsaError> {
    let mut state = AFD_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WsaError::ENotSock)?;

    // Check state
    match state.sockets[idx].state {
        SocketState::Created | SocketState::Bound => {}
        SocketState::Connecting => return Err(WsaError::EAlready),
        SocketState::Connected => return Err(WsaError::EIsConn),
        _ => return Err(WsaError::EInval),
    }

    state.sockets[idx].remote_addr = *addr;
    state.sockets[idx].state = SocketState::Connecting;

    // For now, immediately transition to connected
    // TODO: Implement actual TDI connection
    state.sockets[idx].state = SocketState::Connected;
    state.statistics.connections_established.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[AFD] Socket {} connected", socket_id);

    Ok(())
}

/// Send data on a socket
pub fn afd_send(socket_id: u64, data: &[u8], flags: u32) -> Result<usize, WsaError> {
    let mut state = AFD_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WsaError::ENotSock)?;

    // Must be connected for stream sockets
    if state.sockets[idx].socket_type == SocketType::Stream {
        if state.sockets[idx].state != SocketState::Connected {
            return Err(WsaError::ENotConn);
        }
    }

    // Check buffer space
    let available = state.sockets[idx].options.send_buffer_size
        .saturating_sub(state.sockets[idx].send_buffer.len());

    if available == 0 {
        if state.sockets[idx].non_blocking {
            return Err(WsaError::EWouldBlock);
        }
        // TODO: Block until space available
    }

    let send_len = core::cmp::min(data.len(), available);

    for byte in &data[..send_len] {
        state.sockets[idx].send_buffer.push_back(*byte);
    }

    state.statistics.bytes_sent.fetch_add(send_len as u64, Ordering::Relaxed);
    state.statistics.send_operations.fetch_add(1, Ordering::Relaxed);

    // TODO: Trigger TDI send

    Ok(send_len)
}

/// Receive data from a socket
pub fn afd_recv(socket_id: u64, buffer: &mut [u8], flags: u32) -> Result<usize, WsaError> {
    let mut state = AFD_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WsaError::ENotSock)?;

    // Must be connected for stream sockets
    if state.sockets[idx].socket_type == SocketType::Stream {
        match state.sockets[idx].state {
            SocketState::Connected | SocketState::Closing => {}
            _ => return Err(WsaError::ENotConn),
        }
    }

    // Check for data
    if state.sockets[idx].recv_buffer.is_empty() {
        if state.sockets[idx].state == SocketState::Closing {
            return Ok(0); // Graceful close
        }
        if state.sockets[idx].non_blocking {
            return Err(WsaError::EWouldBlock);
        }
        // TODO: Block until data available
    }

    let peek = (flags & 0x02) != 0; // MSG_PEEK

    let recv_len = core::cmp::min(buffer.len(), state.sockets[idx].recv_buffer.len());

    for i in 0..recv_len {
        if peek {
            if let Some(&byte) = state.sockets[idx].recv_buffer.get(i) {
                buffer[i] = byte;
            }
        } else {
            if let Some(byte) = state.sockets[idx].recv_buffer.pop_front() {
                buffer[i] = byte;
            }
        }
    }

    if !peek {
        state.statistics.bytes_received.fetch_add(recv_len as u64, Ordering::Relaxed);
    }
    state.statistics.recv_operations.fetch_add(1, Ordering::Relaxed);

    Ok(recv_len)
}

/// Send datagram to address
pub fn afd_sendto(
    socket_id: u64,
    data: &[u8],
    flags: u32,
    dest_addr: &SockAddr,
) -> Result<usize, WsaError> {
    let mut state = AFD_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WsaError::ENotSock)?;

    // Check socket type
    if state.sockets[idx].socket_type != SocketType::Dgram &&
       state.sockets[idx].socket_type != SocketType::Raw {
        return Err(WsaError::EOpNotSupp);
    }

    // TODO: Send via TDI
    state.statistics.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
    state.statistics.send_operations.fetch_add(1, Ordering::Relaxed);

    Ok(data.len())
}

/// Receive datagram with source address
pub fn afd_recvfrom(
    socket_id: u64,
    buffer: &mut [u8],
    flags: u32,
    src_addr: &mut SockAddr,
) -> Result<usize, WsaError> {
    let mut state = AFD_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WsaError::ENotSock)?;

    // Check for data
    if state.sockets[idx].recv_buffer.is_empty() {
        if state.sockets[idx].non_blocking {
            return Err(WsaError::EWouldBlock);
        }
        // TODO: Block until data available
    }

    let recv_len = core::cmp::min(buffer.len(), state.sockets[idx].recv_buffer.len());

    for i in 0..recv_len {
        if let Some(byte) = state.sockets[idx].recv_buffer.pop_front() {
            buffer[i] = byte;
        }
    }

    // Return remote address
    *src_addr = state.sockets[idx].remote_addr;

    state.statistics.bytes_received.fetch_add(recv_len as u64, Ordering::Relaxed);
    state.statistics.recv_operations.fetch_add(1, Ordering::Relaxed);

    Ok(recv_len)
}

/// Set socket option
pub fn afd_setsockopt(
    socket_id: u64,
    level: SocketLevel,
    option: i32,
    value: &[u8],
) -> Result<(), WsaError> {
    let mut state = AFD_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WsaError::ENotSock)?;

    match level {
        SocketLevel::Socket => {
            match option {
                x if x == SocketOption::ReuseAddr as i32 => {
                    if value.len() >= 4 {
                        let val = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                        state.sockets[idx].options.reuse_addr = val != 0;
                    }
                }
                x if x == SocketOption::KeepAlive as i32 => {
                    if value.len() >= 4 {
                        let val = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                        state.sockets[idx].options.keep_alive = val != 0;
                    }
                }
                x if x == SocketOption::Broadcast as i32 => {
                    if value.len() >= 4 {
                        let val = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                        state.sockets[idx].options.broadcast = val != 0;
                    }
                }
                x if x == SocketOption::SndBuf as i32 => {
                    if value.len() >= 4 {
                        let val = u32::from_le_bytes([value[0], value[1], value[2], value[3]]) as usize;
                        state.sockets[idx].options.send_buffer_size = val;
                    }
                }
                x if x == SocketOption::RcvBuf as i32 => {
                    if value.len() >= 4 {
                        let val = u32::from_le_bytes([value[0], value[1], value[2], value[3]]) as usize;
                        state.sockets[idx].options.recv_buffer_size = val;
                    }
                }
                x if x == SocketOption::SndTimeo as i32 => {
                    if value.len() >= 4 {
                        let val = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                        state.sockets[idx].options.send_timeout = val;
                    }
                }
                x if x == SocketOption::RcvTimeo as i32 => {
                    if value.len() >= 4 {
                        let val = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                        state.sockets[idx].options.recv_timeout = val;
                    }
                }
                _ => return Err(WsaError::EInval),
            }
        }
        SocketLevel::Tcp => {
            match option {
                x if x == TcpOption::NoDelay as i32 => {
                    if value.len() >= 4 {
                        let val = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                        state.sockets[idx].options.tcp_nodelay = val != 0;
                    }
                }
                _ => return Err(WsaError::EInval),
            }
        }
        _ => return Err(WsaError::EInval),
    }

    Ok(())
}

/// Get socket option
pub fn afd_getsockopt(
    socket_id: u64,
    level: SocketLevel,
    option: i32,
    value: &mut [u8],
) -> Result<usize, WsaError> {
    let state = AFD_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WsaError::ENotSock)?;

    match level {
        SocketLevel::Socket => {
            match option {
                x if x == SocketOption::ReuseAddr as i32 => {
                    if value.len() >= 4 {
                        let val: u32 = if state.sockets[idx].options.reuse_addr { 1 } else { 0 };
                        value[..4].copy_from_slice(&val.to_le_bytes());
                        return Ok(4);
                    }
                }
                x if x == SocketOption::Error as i32 => {
                    if value.len() >= 4 {
                        let val = state.sockets[idx].last_error as u32;
                        value[..4].copy_from_slice(&val.to_le_bytes());
                        return Ok(4);
                    }
                }
                x if x == SocketOption::Type as i32 => {
                    if value.len() >= 4 {
                        let val = state.sockets[idx].socket_type as u32;
                        value[..4].copy_from_slice(&val.to_le_bytes());
                        return Ok(4);
                    }
                }
                x if x == SocketOption::SndBuf as i32 => {
                    if value.len() >= 4 {
                        let val = state.sockets[idx].options.send_buffer_size as u32;
                        value[..4].copy_from_slice(&val.to_le_bytes());
                        return Ok(4);
                    }
                }
                x if x == SocketOption::RcvBuf as i32 => {
                    if value.len() >= 4 {
                        let val = state.sockets[idx].options.recv_buffer_size as u32;
                        value[..4].copy_from_slice(&val.to_le_bytes());
                        return Ok(4);
                    }
                }
                _ => return Err(WsaError::EInval),
            }
        }
        SocketLevel::Tcp => {
            match option {
                x if x == TcpOption::NoDelay as i32 => {
                    if value.len() >= 4 {
                        let val: u32 = if state.sockets[idx].options.tcp_nodelay { 1 } else { 0 };
                        value[..4].copy_from_slice(&val.to_le_bytes());
                        return Ok(4);
                    }
                }
                _ => return Err(WsaError::EInval),
            }
        }
        _ => return Err(WsaError::EInval),
    }

    Err(WsaError::EInval)
}

/// Set socket non-blocking mode
pub fn afd_set_nonblocking(socket_id: u64, non_blocking: bool) -> Result<(), WsaError> {
    let mut state = AFD_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WsaError::ENotSock)?;

    state.sockets[idx].non_blocking = non_blocking;

    Ok(())
}

/// Shutdown socket
pub fn afd_shutdown(socket_id: u64, how: i32) -> Result<(), WsaError> {
    let mut state = AFD_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WsaError::ENotSock)?;

    if state.sockets[idx].state != SocketState::Connected {
        return Err(WsaError::ENotConn);
    }

    // how: 0 = SD_RECEIVE, 1 = SD_SEND, 2 = SD_BOTH
    state.sockets[idx].state = SocketState::Closing;

    crate::serial_println!("[AFD] Socket {} shutdown (how={})", socket_id, how);

    Ok(())
}

/// Get socket name (local address)
pub fn afd_getsockname(socket_id: u64) -> Result<SockAddr, WsaError> {
    let state = AFD_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WsaError::ENotSock)?;

    Ok(state.sockets[idx].local_addr)
}

/// Get peer name (remote address)
pub fn afd_getpeername(socket_id: u64) -> Result<SockAddr, WsaError> {
    let state = AFD_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WsaError::ENotSock)?;

    if state.sockets[idx].state != SocketState::Connected {
        return Err(WsaError::ENotConn);
    }

    Ok(state.sockets[idx].remote_addr)
}

/// Select - check socket readiness
pub fn afd_select(
    read_sockets: &[u64],
    write_sockets: &[u64],
    except_sockets: &[u64],
    timeout_ms: Option<u32>,
) -> Result<(Vec<u64>, Vec<u64>, Vec<u64>), WsaError> {
    let state = AFD_STATE.lock();

    let mut readable = Vec::new();
    let mut writable = Vec::new();
    let mut except = Vec::new();

    // Check read sockets
    for &socket_id in read_sockets {
        for idx in 0..MAX_SOCKETS {
            if state.sockets[idx].active && state.sockets[idx].id == socket_id {
                // Readable if data in buffer or listening with pending connections
                if !state.sockets[idx].recv_buffer.is_empty() ||
                   (state.sockets[idx].state == SocketState::Listening &&
                    !state.sockets[idx].accept_queue.is_empty()) {
                    readable.push(socket_id);
                }
                break;
            }
        }
    }

    // Check write sockets
    for &socket_id in write_sockets {
        for idx in 0..MAX_SOCKETS {
            if state.sockets[idx].active && state.sockets[idx].id == socket_id {
                // Writable if buffer has space and connected
                if state.sockets[idx].state == SocketState::Connected {
                    let available = state.sockets[idx].options.send_buffer_size
                        .saturating_sub(state.sockets[idx].send_buffer.len());
                    if available > 0 {
                        writable.push(socket_id);
                    }
                }
                break;
            }
        }
    }

    // Check exception sockets
    for &socket_id in except_sockets {
        for idx in 0..MAX_SOCKETS {
            if state.sockets[idx].active && state.sockets[idx].id == socket_id {
                if state.sockets[idx].state == SocketState::Error {
                    except.push(socket_id);
                }
                break;
            }
        }
    }

    Ok((readable, writable, except))
}

/// Get AFD statistics
pub fn afd_get_statistics() -> AfdStatistics {
    let state = AFD_STATE.lock();

    AfdStatistics {
        sockets_created: AtomicU64::new(state.statistics.sockets_created.load(Ordering::Relaxed)),
        sockets_closed: AtomicU64::new(state.statistics.sockets_closed.load(Ordering::Relaxed)),
        sockets_active: AtomicU32::new(state.statistics.sockets_active.load(Ordering::Relaxed)),
        bytes_sent: AtomicU64::new(state.statistics.bytes_sent.load(Ordering::Relaxed)),
        bytes_received: AtomicU64::new(state.statistics.bytes_received.load(Ordering::Relaxed)),
        connections_accepted: AtomicU64::new(state.statistics.connections_accepted.load(Ordering::Relaxed)),
        connections_established: AtomicU64::new(state.statistics.connections_established.load(Ordering::Relaxed)),
        send_operations: AtomicU64::new(state.statistics.send_operations.load(Ordering::Relaxed)),
        recv_operations: AtomicU64::new(state.statistics.recv_operations.load(Ordering::Relaxed)),
        pending_io: AtomicU32::new(state.statistics.pending_io.load(Ordering::Relaxed)),
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if two addresses match
fn addresses_match(a: &SockAddr, b: &SockAddr) -> bool {
    match (a, b) {
        (SockAddr::V4(a4), SockAddr::V4(b4)) => {
            a4.port == b4.port && a4.addr == b4.addr
        }
        (SockAddr::V6(a6), SockAddr::V6(b6)) => {
            a6.port == b6.port && a6.addr == b6.addr
        }
        _ => false,
    }
}

/// Deliver data to a socket's receive buffer
pub fn afd_deliver_data(socket_id: u64, data: &[u8]) -> Result<(), WsaError> {
    let mut state = AFD_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WsaError::ENotSock)?;

    // Check buffer space
    let available = state.sockets[idx].options.recv_buffer_size
        .saturating_sub(state.sockets[idx].recv_buffer.len());

    let copy_len = core::cmp::min(data.len(), available);

    for byte in &data[..copy_len] {
        state.sockets[idx].recv_buffer.push_back(*byte);
    }

    Ok(())
}

/// Queue an incoming connection
pub fn afd_queue_connection(listen_socket_id: u64, new_socket_id: u64) -> Result<(), WsaError> {
    let mut state = AFD_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == listen_socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WsaError::ENotSock)?;

    if state.sockets[idx].state != SocketState::Listening {
        return Err(WsaError::EInval);
    }

    if state.sockets[idx].accept_queue.len() >= state.sockets[idx].backlog {
        return Err(WsaError::EConnRefused);
    }

    state.sockets[idx].accept_queue.push_back(new_socket_id);

    Ok(())
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize AFD subsystem
pub fn init() {
    crate::serial_println!("[AFD] Initializing Ancillary Function Driver...");

    {
        let mut state = AFD_STATE.lock();
        state.initialized = true;
    }

    crate::serial_println!("[AFD] AFD initialized");
}
