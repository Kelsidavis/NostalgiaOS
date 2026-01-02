//! WSK (Winsock Kernel) API
//!
//! WSK provides a kernel-mode socket programming interface for network
//! modules that need to perform network I/O operations. While introduced
//! in Windows Vista, this provides a clean kernel-mode socket API.
//!
//! WSK socket types:
//! - Basic socket (no I/O operations)
//! - Listening socket (server)
//! - Datagram socket (UDP)
//! - Connection-mode socket (TCP)
//! - Stream socket (bidirectional stream)

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// Maximum number of WSK sockets
const MAX_WSK_SOCKETS: usize = 1024;

/// Maximum pending data per socket
const MAX_PENDING_DATA: usize = 131072;

// ============================================================================
// WSK Socket Types
// ============================================================================

/// WSK socket type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WskSocketType {
    /// Basic socket - no I/O operations
    Basic = 0,
    /// Listening socket - accepts connections
    Listen = 1,
    /// Datagram socket - connectionless (UDP)
    Datagram = 2,
    /// Connection-mode socket - connection-oriented (TCP)
    Connection = 3,
    /// Stream socket - bidirectional stream
    Stream = 4,
}

// ============================================================================
// WSK Address Family
// ============================================================================

/// WSK address family
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum WskAddressFamily {
    /// IPv4
    Inet = 2,
    /// IPv6
    Inet6 = 23,
    /// NetBIOS
    NetBios = 17,
}

// ============================================================================
// WSK Socket State
// ============================================================================

/// WSK socket state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WskSocketState {
    /// Socket created but not bound
    Created,
    /// Socket bound to local address
    Bound,
    /// Socket listening
    Listening,
    /// Socket connecting
    Connecting,
    /// Socket connected
    Connected,
    /// Socket disconnecting
    Disconnecting,
    /// Socket closed
    Closed,
}

// ============================================================================
// WSK Address Structures
// ============================================================================

/// IPv4 address for WSK
#[derive(Debug, Clone, Copy, Default)]
pub struct WskSockAddrIn {
    /// Address family (AF_INET)
    pub family: u16,
    /// Port (network byte order)
    pub port: u16,
    /// IPv4 address
    pub addr: [u8; 4],
}

/// IPv6 address for WSK
#[derive(Debug, Clone, Copy)]
pub struct WskSockAddrIn6 {
    /// Address family (AF_INET6)
    pub family: u16,
    /// Port (network byte order)
    pub port: u16,
    /// Flow info
    pub flowinfo: u32,
    /// IPv6 address
    pub addr: [u8; 16],
    /// Scope ID
    pub scope_id: u32,
}

impl Default for WskSockAddrIn6 {
    fn default() -> Self {
        Self {
            family: WskAddressFamily::Inet6 as u16,
            port: 0,
            flowinfo: 0,
            addr: [0; 16],
            scope_id: 0,
        }
    }
}

/// Generic WSK socket address
#[derive(Debug, Clone, Copy)]
pub enum WskSockAddr {
    /// IPv4
    V4(WskSockAddrIn),
    /// IPv6
    V6(WskSockAddrIn6),
}

impl Default for WskSockAddr {
    fn default() -> Self {
        WskSockAddr::V4(WskSockAddrIn::default())
    }
}

// ============================================================================
// WSK Control Codes
// ============================================================================

/// WSK control codes for socket options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WskControlCode {
    /// Socket option
    SocketOption = 0,
    /// IP level option
    IpOption = 1,
    /// TCP level option
    TcpOption = 2,
    /// UDP level option
    UdpOption = 3,
    /// IPv6 level option
    Ipv6Option = 4,
}

// ============================================================================
// WSK Socket Options
// ============================================================================

/// WSK socket options
#[derive(Debug, Clone, Copy)]
pub struct WskSocketOptions {
    /// Receive buffer size
    pub recv_buffer_size: usize,
    /// Send buffer size
    pub send_buffer_size: usize,
    /// Non-blocking mode
    pub non_blocking: bool,
    /// Keep-alive enabled
    pub keep_alive: bool,
    /// TCP no-delay (disable Nagle)
    pub tcp_nodelay: bool,
    /// Reuse address
    pub reuse_addr: bool,
    /// Receive timeout (ms)
    pub recv_timeout: u32,
    /// Send timeout (ms)
    pub send_timeout: u32,
}

impl Default for WskSocketOptions {
    fn default() -> Self {
        Self {
            recv_buffer_size: 65536,
            send_buffer_size: 65536,
            non_blocking: false,
            keep_alive: false,
            tcp_nodelay: false,
            reuse_addr: false,
            recv_timeout: 0,
            send_timeout: 0,
        }
    }
}

// ============================================================================
// WSK IRP Context
// ============================================================================

/// WSK I/O request context
#[derive(Debug, Clone, Copy)]
pub struct WskIrpContext {
    /// Request ID
    pub request_id: u64,
    /// Completion callback
    pub completion_callback: Option<fn(u64, i32, usize)>,
    /// User context
    pub user_context: u64,
}

impl Default for WskIrpContext {
    fn default() -> Self {
        Self {
            request_id: 0,
            completion_callback: None,
            user_context: 0,
        }
    }
}

// ============================================================================
// WSK Event Callbacks
// ============================================================================

/// WSK event callback type
pub type WskReceiveCallback = fn(socket_id: u64, data: &[u8], flags: u32) -> i32;
pub type WskDisconnectCallback = fn(socket_id: u64, flags: u32) -> i32;
pub type WskAcceptCallback = fn(listen_socket_id: u64, new_socket_id: u64) -> i32;
pub type WskSendBacklogCallback = fn(socket_id: u64, ideal_backlog: usize) -> i32;

/// WSK event callbacks
#[derive(Clone, Copy)]
pub struct WskEventCallbacks {
    /// Receive event
    pub receive: Option<WskReceiveCallback>,
    /// Disconnect event
    pub disconnect: Option<WskDisconnectCallback>,
    /// Accept event (for listening sockets)
    pub accept: Option<WskAcceptCallback>,
    /// Send backlog change event
    pub send_backlog: Option<WskSendBacklogCallback>,
}

impl Default for WskEventCallbacks {
    fn default() -> Self {
        Self {
            receive: None,
            disconnect: None,
            accept: None,
            send_backlog: None,
        }
    }
}

// ============================================================================
// WSK Socket Structure
// ============================================================================

/// WSK socket
pub struct WskSocket {
    /// Socket ID
    pub id: u64,
    /// Socket type
    pub socket_type: WskSocketType,
    /// Address family
    pub family: WskAddressFamily,
    /// Protocol
    pub protocol: u32,
    /// Socket state
    pub state: WskSocketState,
    /// Local address
    pub local_addr: WskSockAddr,
    /// Remote address
    pub remote_addr: WskSockAddr,
    /// Socket options
    pub options: WskSocketOptions,
    /// Receive buffer
    pub recv_buffer: VecDeque<u8>,
    /// Send buffer
    pub send_buffer: VecDeque<u8>,
    /// Pending accept queue
    pub accept_queue: VecDeque<u64>,
    /// Event callbacks
    pub callbacks: WskEventCallbacks,
    /// Reference count
    pub ref_count: u32,
    /// Active flag
    pub active: bool,
    /// Associated AFD socket (if any)
    pub afd_socket: Option<u64>,
}

impl Default for WskSocket {
    fn default() -> Self {
        Self {
            id: 0,
            socket_type: WskSocketType::Basic,
            family: WskAddressFamily::Inet,
            protocol: 0,
            state: WskSocketState::Created,
            local_addr: WskSockAddr::default(),
            remote_addr: WskSockAddr::default(),
            options: WskSocketOptions::default(),
            recv_buffer: VecDeque::new(),
            send_buffer: VecDeque::new(),
            accept_queue: VecDeque::new(),
            callbacks: WskEventCallbacks::default(),
            ref_count: 1,
            active: false,
            afd_socket: None,
        }
    }
}

// ============================================================================
// WSK Provider NPI (Network Programming Interface)
// ============================================================================

/// WSK client dispatch table
pub struct WskClientDispatch {
    /// Version
    pub version: u16,
    /// Reserved
    pub reserved: u16,
    /// Client context
    pub client_context: u64,
}

/// WSK provider dispatch table
pub struct WskProviderDispatch {
    /// Version
    pub version: u16,
    /// Socket function
    pub wsk_socket: fn(client: u64, family: WskAddressFamily, socket_type: WskSocketType, protocol: u32) -> Result<u64, WskError>,
    /// Socket connect function
    pub wsk_socket_connect: fn(socket: u64, addr: &WskSockAddr) -> Result<(), WskError>,
    /// Control client function
    pub wsk_control_client: fn(client: u64, control_code: WskControlCode, data: &[u8]) -> Result<(), WskError>,
}

// ============================================================================
// WSK Errors
// ============================================================================

/// WSK error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum WskError {
    /// Success
    Success = 0,
    /// Invalid parameter
    InvalidParameter = -1,
    /// No memory
    NoMemory = -2,
    /// Not initialized
    NotInitialized = -3,
    /// Socket not found
    SocketNotFound = -4,
    /// Invalid state
    InvalidState = -5,
    /// Connection refused
    ConnectionRefused = -6,
    /// Connection reset
    ConnectionReset = -7,
    /// Network unreachable
    NetworkUnreachable = -8,
    /// Host unreachable
    HostUnreachable = -9,
    /// Timed out
    TimedOut = -10,
    /// Would block
    WouldBlock = -11,
    /// Already connected
    AlreadyConnected = -12,
    /// Not connected
    NotConnected = -13,
    /// Address in use
    AddressInUse = -14,
    /// Buffer too small
    BufferTooSmall = -15,
    /// Too many sockets
    TooManySockets = -16,
}

// ============================================================================
// WSK Statistics
// ============================================================================

/// WSK statistics
#[derive(Debug)]
pub struct WskStatistics {
    /// Sockets created
    pub sockets_created: AtomicU64,
    /// Sockets closed
    pub sockets_closed: AtomicU64,
    /// Active sockets
    pub active_sockets: AtomicU32,
    /// Bytes sent
    pub bytes_sent: AtomicU64,
    /// Bytes received
    pub bytes_received: AtomicU64,
    /// Connections accepted
    pub connections_accepted: AtomicU64,
    /// Connections established
    pub connections_established: AtomicU64,
}

impl Default for WskStatistics {
    fn default() -> Self {
        Self {
            sockets_created: AtomicU64::new(0),
            sockets_closed: AtomicU64::new(0),
            active_sockets: AtomicU32::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            connections_accepted: AtomicU64::new(0),
            connections_established: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// WSK State
// ============================================================================

/// WSK global state
pub struct WskState {
    /// Socket table
    pub sockets: [WskSocket; MAX_WSK_SOCKETS],
    /// Next socket ID
    pub next_socket_id: u64,
    /// Statistics
    pub statistics: WskStatistics,
    /// Initialized
    pub initialized: bool,
    /// Registered clients
    pub client_count: u32,
}

impl WskState {
    const fn new() -> Self {
        const DEFAULT_SOCKET: WskSocket = WskSocket {
            id: 0,
            socket_type: WskSocketType::Basic,
            family: WskAddressFamily::Inet,
            protocol: 0,
            state: WskSocketState::Created,
            local_addr: WskSockAddr::V4(WskSockAddrIn { family: 2, port: 0, addr: [0; 4] }),
            remote_addr: WskSockAddr::V4(WskSockAddrIn { family: 2, port: 0, addr: [0; 4] }),
            options: WskSocketOptions {
                recv_buffer_size: 65536,
                send_buffer_size: 65536,
                non_blocking: false,
                keep_alive: false,
                tcp_nodelay: false,
                reuse_addr: false,
                recv_timeout: 0,
                send_timeout: 0,
            },
            recv_buffer: VecDeque::new(),
            send_buffer: VecDeque::new(),
            accept_queue: VecDeque::new(),
            callbacks: WskEventCallbacks {
                receive: None,
                disconnect: None,
                accept: None,
                send_backlog: None,
            },
            ref_count: 1,
            active: false,
            afd_socket: None,
        };

        Self {
            sockets: [DEFAULT_SOCKET; MAX_WSK_SOCKETS],
            next_socket_id: 1,
            statistics: WskStatistics {
                sockets_created: AtomicU64::new(0),
                sockets_closed: AtomicU64::new(0),
                active_sockets: AtomicU32::new(0),
                bytes_sent: AtomicU64::new(0),
                bytes_received: AtomicU64::new(0),
                connections_accepted: AtomicU64::new(0),
                connections_established: AtomicU64::new(0),
            },
            initialized: false,
            client_count: 0,
        }
    }
}

/// Global WSK state
static WSK_STATE: SpinLock<WskState> = SpinLock::new(WskState::new());

// ============================================================================
// WSK Client Registration
// ============================================================================

/// Register a WSK client
pub fn wsk_register(
    client_dispatch: &WskClientDispatch,
) -> Result<u64, WskError> {
    let mut state = WSK_STATE.lock();

    if !state.initialized {
        return Err(WskError::NotInitialized);
    }

    let client_id = state.client_count as u64 + 1;
    state.client_count += 1;

    crate::serial_println!("[WSK] Registered client {} (version {})",
        client_id, client_dispatch.version);

    Ok(client_id)
}

/// Deregister a WSK client
pub fn wsk_deregister(client_id: u64) -> Result<(), WskError> {
    let mut state = WSK_STATE.lock();

    if state.client_count > 0 {
        state.client_count -= 1;
    }

    crate::serial_println!("[WSK] Deregistered client {}", client_id);

    Ok(())
}

// ============================================================================
// WSK Socket Operations
// ============================================================================

/// Create a WSK socket
pub fn wsk_socket(
    _client_id: u64,
    family: WskAddressFamily,
    socket_type: WskSocketType,
    protocol: u32,
) -> Result<u64, WskError> {
    let mut state = WSK_STATE.lock();

    if !state.initialized {
        return Err(WskError::NotInitialized);
    }

    // Find free slot
    let mut slot_idx = None;
    for idx in 0..MAX_WSK_SOCKETS {
        if !state.sockets[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(WskError::TooManySockets)?;

    let socket_id = state.next_socket_id;
    state.next_socket_id += 1;

    state.sockets[idx] = WskSocket {
        id: socket_id,
        socket_type,
        family,
        protocol,
        state: WskSocketState::Created,
        local_addr: WskSockAddr::default(),
        remote_addr: WskSockAddr::default(),
        options: WskSocketOptions::default(),
        recv_buffer: VecDeque::with_capacity(65536),
        send_buffer: VecDeque::with_capacity(65536),
        accept_queue: VecDeque::new(),
        callbacks: WskEventCallbacks::default(),
        ref_count: 1,
        active: true,
        afd_socket: None,
    };

    state.statistics.sockets_created.fetch_add(1, Ordering::Relaxed);
    state.statistics.active_sockets.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[WSK] Created socket {} (type={:?})", socket_id, socket_type);

    Ok(socket_id)
}

/// Close a WSK socket
pub fn wsk_close_socket(socket_id: u64) -> Result<(), WskError> {
    let mut state = WSK_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_WSK_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WskError::SocketNotFound)?;

    state.sockets[idx].ref_count = state.sockets[idx].ref_count.saturating_sub(1);

    if state.sockets[idx].ref_count == 0 {
        state.sockets[idx].state = WskSocketState::Closed;
        state.sockets[idx].active = false;
        state.statistics.sockets_closed.fetch_add(1, Ordering::Relaxed);
        state.statistics.active_sockets.fetch_sub(1, Ordering::Relaxed);

        crate::serial_println!("[WSK] Closed socket {}", socket_id);
    }

    Ok(())
}

/// Bind socket to local address
pub fn wsk_bind(socket_id: u64, addr: &WskSockAddr) -> Result<(), WskError> {
    let mut state = WSK_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_WSK_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WskError::SocketNotFound)?;

    if state.sockets[idx].state != WskSocketState::Created {
        return Err(WskError::InvalidState);
    }

    state.sockets[idx].local_addr = *addr;
    state.sockets[idx].state = WskSocketState::Bound;

    crate::serial_println!("[WSK] Socket {} bound", socket_id);

    Ok(())
}

/// Listen for connections (listening socket)
pub fn wsk_listen(socket_id: u64, backlog: u32) -> Result<(), WskError> {
    let mut state = WSK_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_WSK_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WskError::SocketNotFound)?;

    if state.sockets[idx].socket_type != WskSocketType::Listen &&
       state.sockets[idx].socket_type != WskSocketType::Stream {
        return Err(WskError::InvalidState);
    }

    if state.sockets[idx].state != WskSocketState::Bound {
        return Err(WskError::InvalidState);
    }

    state.sockets[idx].state = WskSocketState::Listening;

    crate::serial_println!("[WSK] Socket {} listening (backlog={})", socket_id, backlog);

    Ok(())
}

/// Accept a connection
pub fn wsk_accept(listen_socket_id: u64) -> Result<u64, WskError> {
    let (family, protocol, pending_id);

    {
        let mut state = WSK_STATE.lock();

        let mut found_idx = None;
        for idx in 0..MAX_WSK_SOCKETS {
            if state.sockets[idx].active && state.sockets[idx].id == listen_socket_id {
                found_idx = Some(idx);
                break;
            }
        }

        let idx = found_idx.ok_or(WskError::SocketNotFound)?;

        if state.sockets[idx].state != WskSocketState::Listening {
            return Err(WskError::InvalidState);
        }

        pending_id = state.sockets[idx].accept_queue.pop_front();
        family = state.sockets[idx].family;
        protocol = state.sockets[idx].protocol;
    }

    if let Some(accepted_id) = pending_id {
        let mut state = WSK_STATE.lock();
        for idx in 0..MAX_WSK_SOCKETS {
            if state.sockets[idx].active && state.sockets[idx].id == accepted_id {
                state.sockets[idx].state = WskSocketState::Connected;
                break;
            }
        }
        state.statistics.connections_accepted.fetch_add(1, Ordering::Relaxed);
        return Ok(accepted_id);
    }

    // Create new socket for accepted connection
    let new_socket_id = wsk_socket(0, family, WskSocketType::Connection, protocol)?;

    {
        let mut state = WSK_STATE.lock();
        for idx in 0..MAX_WSK_SOCKETS {
            if state.sockets[idx].active && state.sockets[idx].id == new_socket_id {
                state.sockets[idx].state = WskSocketState::Connected;
                break;
            }
        }
        state.statistics.connections_accepted.fetch_add(1, Ordering::Relaxed);
    }

    Ok(new_socket_id)
}

/// Connect to remote address
pub fn wsk_connect(socket_id: u64, addr: &WskSockAddr) -> Result<(), WskError> {
    let mut state = WSK_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_WSK_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WskError::SocketNotFound)?;

    match state.sockets[idx].state {
        WskSocketState::Created | WskSocketState::Bound => {}
        WskSocketState::Connected => return Err(WskError::AlreadyConnected),
        _ => return Err(WskError::InvalidState),
    }

    state.sockets[idx].remote_addr = *addr;
    state.sockets[idx].state = WskSocketState::Connected;
    state.statistics.connections_established.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[WSK] Socket {} connected", socket_id);

    Ok(())
}

/// Send data on a connection socket
pub fn wsk_send(socket_id: u64, data: &[u8], _flags: u32) -> Result<usize, WskError> {
    let mut state = WSK_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_WSK_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WskError::SocketNotFound)?;

    if state.sockets[idx].state != WskSocketState::Connected {
        return Err(WskError::NotConnected);
    }

    let available = state.sockets[idx].options.send_buffer_size
        .saturating_sub(state.sockets[idx].send_buffer.len());

    if available == 0 {
        if state.sockets[idx].options.non_blocking {
            return Err(WskError::WouldBlock);
        }
    }

    let send_len = core::cmp::min(data.len(), available);

    for byte in &data[..send_len] {
        state.sockets[idx].send_buffer.push_back(*byte);
    }

    state.statistics.bytes_sent.fetch_add(send_len as u64, Ordering::Relaxed);

    Ok(send_len)
}

/// Receive data from a connection socket
pub fn wsk_receive(socket_id: u64, buffer: &mut [u8], _flags: u32) -> Result<usize, WskError> {
    let mut state = WSK_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_WSK_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WskError::SocketNotFound)?;

    if state.sockets[idx].state != WskSocketState::Connected &&
       state.sockets[idx].state != WskSocketState::Disconnecting {
        return Err(WskError::NotConnected);
    }

    if state.sockets[idx].recv_buffer.is_empty() {
        if state.sockets[idx].state == WskSocketState::Disconnecting {
            return Ok(0);
        }
        if state.sockets[idx].options.non_blocking {
            return Err(WskError::WouldBlock);
        }
    }

    let recv_len = core::cmp::min(buffer.len(), state.sockets[idx].recv_buffer.len());

    for i in 0..recv_len {
        if let Some(byte) = state.sockets[idx].recv_buffer.pop_front() {
            buffer[i] = byte;
        }
    }

    state.statistics.bytes_received.fetch_add(recv_len as u64, Ordering::Relaxed);

    Ok(recv_len)
}

/// Send datagram
pub fn wsk_send_to(
    socket_id: u64,
    data: &[u8],
    dest_addr: &WskSockAddr,
    _flags: u32,
) -> Result<usize, WskError> {
    let mut state = WSK_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_WSK_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WskError::SocketNotFound)?;

    if state.sockets[idx].socket_type != WskSocketType::Datagram {
        return Err(WskError::InvalidState);
    }

    // TODO: Actually send via network
    state.statistics.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);

    Ok(data.len())
}

/// Receive datagram
pub fn wsk_receive_from(
    socket_id: u64,
    buffer: &mut [u8],
    src_addr: &mut WskSockAddr,
    _flags: u32,
) -> Result<usize, WskError> {
    let mut state = WSK_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_WSK_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WskError::SocketNotFound)?;

    if state.sockets[idx].socket_type != WskSocketType::Datagram {
        return Err(WskError::InvalidState);
    }

    if state.sockets[idx].recv_buffer.is_empty() {
        if state.sockets[idx].options.non_blocking {
            return Err(WskError::WouldBlock);
        }
    }

    let recv_len = core::cmp::min(buffer.len(), state.sockets[idx].recv_buffer.len());

    for i in 0..recv_len {
        if let Some(byte) = state.sockets[idx].recv_buffer.pop_front() {
            buffer[i] = byte;
        }
    }

    *src_addr = state.sockets[idx].remote_addr;
    state.statistics.bytes_received.fetch_add(recv_len as u64, Ordering::Relaxed);

    Ok(recv_len)
}

/// Disconnect socket
pub fn wsk_disconnect(socket_id: u64, _flags: u32) -> Result<(), WskError> {
    let mut state = WSK_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_WSK_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WskError::SocketNotFound)?;

    if state.sockets[idx].state != WskSocketState::Connected {
        return Err(WskError::NotConnected);
    }

    state.sockets[idx].state = WskSocketState::Disconnecting;

    crate::serial_println!("[WSK] Socket {} disconnecting", socket_id);

    Ok(())
}

/// Set socket option
pub fn wsk_control_socket(
    socket_id: u64,
    control_code: WskControlCode,
    option: u32,
    value: &[u8],
) -> Result<(), WskError> {
    let mut state = WSK_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_WSK_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WskError::SocketNotFound)?;

    match control_code {
        WskControlCode::SocketOption => {
            // Handle common socket options
            if option == 4 && value.len() >= 4 { // SO_REUSEADDR
                let val = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                state.sockets[idx].options.reuse_addr = val != 0;
            } else if option == 8 && value.len() >= 4 { // SO_KEEPALIVE
                let val = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                state.sockets[idx].options.keep_alive = val != 0;
            }
        }
        WskControlCode::TcpOption => {
            if option == 1 && value.len() >= 4 { // TCP_NODELAY
                let val = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                state.sockets[idx].options.tcp_nodelay = val != 0;
            }
        }
        _ => {}
    }

    Ok(())
}

/// Set event callbacks
pub fn wsk_set_event_callbacks(
    socket_id: u64,
    callbacks: WskEventCallbacks,
) -> Result<(), WskError> {
    let mut state = WSK_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_WSK_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WskError::SocketNotFound)?;

    state.sockets[idx].callbacks = callbacks;

    Ok(())
}

/// Get socket local address
pub fn wsk_get_local_address(socket_id: u64) -> Result<WskSockAddr, WskError> {
    let state = WSK_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_WSK_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WskError::SocketNotFound)?;

    Ok(state.sockets[idx].local_addr)
}

/// Get socket remote address
pub fn wsk_get_remote_address(socket_id: u64) -> Result<WskSockAddr, WskError> {
    let state = WSK_STATE.lock();

    let mut found_idx = None;
    for idx in 0..MAX_WSK_SOCKETS {
        if state.sockets[idx].active && state.sockets[idx].id == socket_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(WskError::SocketNotFound)?;

    if state.sockets[idx].state != WskSocketState::Connected {
        return Err(WskError::NotConnected);
    }

    Ok(state.sockets[idx].remote_addr)
}

/// Get WSK statistics
pub fn wsk_get_statistics() -> WskStatistics {
    let state = WSK_STATE.lock();

    WskStatistics {
        sockets_created: AtomicU64::new(state.statistics.sockets_created.load(Ordering::Relaxed)),
        sockets_closed: AtomicU64::new(state.statistics.sockets_closed.load(Ordering::Relaxed)),
        active_sockets: AtomicU32::new(state.statistics.active_sockets.load(Ordering::Relaxed)),
        bytes_sent: AtomicU64::new(state.statistics.bytes_sent.load(Ordering::Relaxed)),
        bytes_received: AtomicU64::new(state.statistics.bytes_received.load(Ordering::Relaxed)),
        connections_accepted: AtomicU64::new(state.statistics.connections_accepted.load(Ordering::Relaxed)),
        connections_established: AtomicU64::new(state.statistics.connections_established.load(Ordering::Relaxed)),
    }
}

/// Deliver data to a WSK socket
pub fn wsk_deliver_data(socket_id: u64, data: &[u8]) -> Result<(), WskError> {
    let callback;

    {
        let mut state = WSK_STATE.lock();

        let mut found_idx = None;
        for idx in 0..MAX_WSK_SOCKETS {
            if state.sockets[idx].active && state.sockets[idx].id == socket_id {
                found_idx = Some(idx);
                break;
            }
        }

        let idx = found_idx.ok_or(WskError::SocketNotFound)?;

        let available = state.sockets[idx].options.recv_buffer_size
            .saturating_sub(state.sockets[idx].recv_buffer.len());

        let copy_len = core::cmp::min(data.len(), available);

        for byte in &data[..copy_len] {
            state.sockets[idx].recv_buffer.push_back(*byte);
        }

        callback = state.sockets[idx].callbacks.receive;
    }

    // Invoke callback outside lock
    if let Some(cb) = callback {
        cb(socket_id, data, 0);
    }

    Ok(())
}

/// Queue incoming connection
pub fn wsk_queue_connection(listen_socket_id: u64, new_socket_id: u64) -> Result<(), WskError> {
    let callback;

    {
        let mut state = WSK_STATE.lock();

        let mut found_idx = None;
        for idx in 0..MAX_WSK_SOCKETS {
            if state.sockets[idx].active && state.sockets[idx].id == listen_socket_id {
                found_idx = Some(idx);
                break;
            }
        }

        let idx = found_idx.ok_or(WskError::SocketNotFound)?;

        if state.sockets[idx].state != WskSocketState::Listening {
            return Err(WskError::InvalidState);
        }

        state.sockets[idx].accept_queue.push_back(new_socket_id);
        callback = state.sockets[idx].callbacks.accept;
    }

    if let Some(cb) = callback {
        cb(listen_socket_id, new_socket_id);
    }

    Ok(())
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize WSK subsystem
pub fn init() {
    crate::serial_println!("[WSK] Initializing Winsock Kernel...");

    {
        let mut state = WSK_STATE.lock();
        state.initialized = true;
    }

    crate::serial_println!("[WSK] WSK initialized");
}
