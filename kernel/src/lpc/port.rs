//! LPC Port Implementation
//!
//! Ports are named communication endpoints. There are several types:
//!
//! - **Server Port**: Created by server, accepts connections
//! - **Client Port**: Created when client connects to server
//! - **Communication Port**: Bidirectional communication channel

use super::message::{LpcMessage, MAX_MESSAGE_SIZE};

/// Maximum number of ports
pub const MAX_PORTS: usize = 64;

/// Maximum port name length
pub const MAX_PORT_NAME_LENGTH: usize = 128;

/// Maximum pending connections
pub const MAX_CONNECTIONS_PER_PORT: usize = 8;

/// Maximum queued messages per port
pub const MAX_MESSAGES_PER_PORT: usize = 32;

/// Port type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LpcPortType {
    /// Server connection port (accepts connections)
    ServerConnection = 0,
    /// Client communication port (created on connect)
    ClientCommunication = 1,
    /// Server communication port (created on accept)
    ServerCommunication = 2,
    /// Unconnected port (datagram only)
    Unconnected = 3,
}

impl Default for LpcPortType {
    fn default() -> Self {
        Self::Unconnected
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LpcConnectionState {
    /// Not connected
    Disconnected = 0,
    /// Connection pending (waiting for accept)
    Pending = 1,
    /// Connected
    Connected = 2,
    /// Connection closed
    Closed = 3,
}

impl Default for LpcConnectionState {
    fn default() -> Self {
        Self::Disconnected
    }
}

/// Port flags
pub mod PortFlags {
    /// Port is in use
    pub const IN_USE: u16 = 0x0001;
    /// Port allows ALPC features
    pub const ALPC_PORT: u16 = 0x0002;
    /// Port is waitable
    pub const WAITABLE: u16 = 0x0004;
    /// Port has pending connections
    pub const HAS_PENDING: u16 = 0x0008;
    /// Port has pending messages
    pub const HAS_MESSAGES: u16 = 0x0010;
    /// Port is synchronous
    pub const SYNC_PORT: u16 = 0x0020;
}

/// Port name
#[derive(Clone, Copy)]
pub struct LpcPortName {
    pub chars: [u8; MAX_PORT_NAME_LENGTH],
    pub length: u8,
}

impl LpcPortName {
    pub const fn empty() -> Self {
        Self {
            chars: [0; MAX_PORT_NAME_LENGTH],
            length: 0,
        }
    }

    pub fn from_str(s: &str) -> Self {
        let mut name = Self::empty();
        let bytes = s.as_bytes();
        let len = bytes.len().min(MAX_PORT_NAME_LENGTH);
        name.chars[..len].copy_from_slice(&bytes[..len]);
        name.length = len as u8;
        name
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.chars[..self.length as usize]).unwrap_or("")
    }

    pub fn equals(&self, s: &str) -> bool {
        self.as_str() == s
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
}

impl Default for LpcPortName {
    fn default() -> Self {
        Self::empty()
    }
}

/// Connection information
#[derive(Clone, Copy, Default)]
pub struct LpcConnection {
    /// Connection state
    pub state: LpcConnectionState,
    /// Client port index (for server)
    pub client_port: u16,
    /// Server port index (for client)
    pub server_port: u16,
    /// Client process ID
    pub client_pid: u32,
    /// Server process ID
    pub server_pid: u32,
    /// Client thread ID
    pub client_tid: u32,
    /// Server thread ID
    pub server_tid: u32,
    /// Context data size
    pub context_size: u16,
    /// Reserved
    _reserved: u16,
}

impl LpcConnection {
    pub const fn new() -> Self {
        Self {
            state: LpcConnectionState::Disconnected,
            client_port: 0xFFFF,
            server_port: 0xFFFF,
            client_pid: 0,
            server_pid: 0,
            client_tid: 0,
            server_tid: 0,
            context_size: 0,
            _reserved: 0,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.state == LpcConnectionState::Connected
    }

    pub fn is_pending(&self) -> bool {
        self.state == LpcConnectionState::Pending
    }
}

/// Message queue entry
#[derive(Clone, Copy)]
struct MessageQueueEntry {
    /// Message is valid
    valid: bool,
    /// Message ID
    message_id: u32,
    /// Source port
    source_port: u16,
    /// Message data (inline for small messages)
    data: [u8; 256],
    /// Data length
    data_len: u16,
}

impl MessageQueueEntry {
    const fn empty() -> Self {
        Self {
            valid: false,
            message_id: 0,
            source_port: 0xFFFF,
            data: [0; 256],
            data_len: 0,
        }
    }
}

impl Default for MessageQueueEntry {
    fn default() -> Self {
        Self::empty()
    }
}

/// LPC Port
#[derive(Clone, Copy)]
pub struct LpcPort {
    /// Port name
    pub name: LpcPortName,
    /// Port type
    pub port_type: LpcPortType,
    /// Port flags
    pub flags: u16,
    /// Owner process ID
    pub owner_pid: u32,
    /// Owner thread ID
    pub owner_tid: u32,
    /// Connection information
    pub connection: LpcConnection,
    /// Maximum message size
    pub max_message_size: u32,
    /// Maximum connection info size
    pub max_connection_size: u32,
    /// Pending connections (for server ports)
    pending_connections: [LpcConnection; MAX_CONNECTIONS_PER_PORT],
    /// Number of pending connections
    pending_count: u8,
    /// Message queue
    message_queue: [MessageQueueEntry; MAX_MESSAGES_PER_PORT],
    /// Message queue head
    msg_head: u8,
    /// Message queue tail
    msg_tail: u8,
    /// Message queue count
    msg_count: u8,
    /// Next message ID
    next_message_id: u32,
    /// Messages sent
    pub messages_sent: u32,
    /// Messages received
    pub messages_received: u32,
}

impl LpcPort {
    pub const fn new() -> Self {
        Self {
            name: LpcPortName::empty(),
            port_type: LpcPortType::Unconnected,
            flags: 0,
            owner_pid: 0,
            owner_tid: 0,
            connection: LpcConnection::new(),
            max_message_size: MAX_MESSAGE_SIZE as u32,
            max_connection_size: 256,
            pending_connections: [LpcConnection::new(); MAX_CONNECTIONS_PER_PORT],
            pending_count: 0,
            message_queue: [MessageQueueEntry::empty(); MAX_MESSAGES_PER_PORT],
            msg_head: 0,
            msg_tail: 0,
            msg_count: 0,
            next_message_id: 1,
            messages_sent: 0,
            messages_received: 0,
        }
    }

    /// Check if port is in use
    pub fn is_in_use(&self) -> bool {
        (self.flags & PortFlags::IN_USE) != 0
    }

    /// Check if port is a server port
    pub fn is_server(&self) -> bool {
        self.port_type == LpcPortType::ServerConnection
    }

    /// Check if port is connected
    pub fn is_connected(&self) -> bool {
        self.connection.is_connected()
    }

    /// Check if port has pending connections
    pub fn has_pending_connections(&self) -> bool {
        self.pending_count > 0
    }

    /// Check if port has messages
    pub fn has_messages(&self) -> bool {
        self.msg_count > 0
    }

    /// Add a pending connection
    pub fn add_pending_connection(&mut self, conn: LpcConnection) -> bool {
        if self.pending_count as usize >= MAX_CONNECTIONS_PER_PORT {
            return false;
        }
        self.pending_connections[self.pending_count as usize] = conn;
        self.pending_count += 1;
        self.flags |= PortFlags::HAS_PENDING;
        true
    }

    /// Get next pending connection
    pub fn get_pending_connection(&mut self) -> Option<LpcConnection> {
        if self.pending_count == 0 {
            return None;
        }
        let conn = self.pending_connections[0];
        // Shift remaining connections
        for i in 0..(self.pending_count as usize - 1) {
            self.pending_connections[i] = self.pending_connections[i + 1];
        }
        self.pending_count -= 1;
        if self.pending_count == 0 {
            self.flags &= !PortFlags::HAS_PENDING;
        }
        Some(conn)
    }

    /// Queue a message
    pub fn queue_message(&mut self, source: u16, data: &[u8]) -> Option<u32> {
        if self.msg_count as usize >= MAX_MESSAGES_PER_PORT {
            return None;
        }
        let len = data.len().min(256);
        let entry = &mut self.message_queue[self.msg_tail as usize];
        entry.valid = true;
        entry.message_id = self.next_message_id;
        entry.source_port = source;
        entry.data[..len].copy_from_slice(&data[..len]);
        entry.data_len = len as u16;

        let msg_id = self.next_message_id;
        self.next_message_id += 1;
        self.msg_tail = ((self.msg_tail as usize + 1) % MAX_MESSAGES_PER_PORT) as u8;
        self.msg_count += 1;
        self.flags |= PortFlags::HAS_MESSAGES;
        Some(msg_id)
    }

    /// Dequeue a message
    pub fn dequeue_message(&mut self) -> Option<(u16, u32, [u8; 256], usize)> {
        if self.msg_count == 0 {
            return None;
        }
        let entry = &self.message_queue[self.msg_head as usize];
        if !entry.valid {
            return None;
        }
        let result = (entry.source_port, entry.message_id, entry.data, entry.data_len as usize);
        self.message_queue[self.msg_head as usize] = MessageQueueEntry::empty();
        self.msg_head = ((self.msg_head as usize + 1) % MAX_MESSAGES_PER_PORT) as u8;
        self.msg_count -= 1;
        if self.msg_count == 0 {
            self.flags &= !PortFlags::HAS_MESSAGES;
        }
        self.messages_received += 1;
        Some(result)
    }

    /// Clear the port
    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

impl Default for LpcPort {
    fn default() -> Self {
        Self::new()
    }
}

/// Port information (for queries)
#[derive(Clone, Copy, Default)]
pub struct LpcPortInfo {
    pub port_type: LpcPortType,
    pub connection_state: LpcConnectionState,
    pub owner_pid: u32,
    pub owner_tid: u32,
    pub max_message_size: u32,
    pub pending_connections: u8,
    pub pending_messages: u8,
}

/// Port statistics
#[derive(Clone, Copy, Default)]
pub struct LpcPortStats {
    pub allocated_ports: usize,
    pub server_ports: usize,
    pub client_ports: usize,
    pub connected_ports: usize,
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
}

// ============================================================================
// Global Port Table
// ============================================================================

/// Port table
static mut PORT_TABLE: [LpcPort; MAX_PORTS] = {
    const INIT: LpcPort = LpcPort::new();
    [INIT; MAX_PORTS]
};

/// Port allocation bitmap
static mut PORT_BITMAP: [u64; 1] = [0]; // 64 ports

/// Global statistics
static mut PORT_STATS: LpcPortStats = LpcPortStats {
    allocated_ports: 0,
    server_ports: 0,
    client_ports: 0,
    connected_ports: 0,
    total_messages_sent: 0,
    total_messages_received: 0,
};

// ============================================================================
// Port Operations
// ============================================================================

/// Create a new port
pub unsafe fn lpc_create_port(
    name: &str,
    port_type: LpcPortType,
    max_message_size: u32,
) -> Option<u16> {
    // Find free slot
    for i in 0..MAX_PORTS {
        if PORT_BITMAP[0] & (1 << i) == 0 {
            // Check for name conflict
            if !name.is_empty() {
                for j in 0..MAX_PORTS {
                    if (PORT_BITMAP[0] & (1 << j)) != 0 {
                        if PORT_TABLE[j].name.equals(name) {
                            return None; // Name already in use
                        }
                    }
                }
            }

            PORT_BITMAP[0] |= 1 << i;
            let port = &mut PORT_TABLE[i];
            port.clear();
            port.name = LpcPortName::from_str(name);
            port.port_type = port_type;
            port.flags = PortFlags::IN_USE;
            port.max_message_size = max_message_size;
            port.owner_pid = 0; // TODO: Get current process
            port.owner_tid = 0; // TODO: Get current thread

            PORT_STATS.allocated_ports += 1;
            if port_type == LpcPortType::ServerConnection {
                PORT_STATS.server_ports += 1;
            }

            crate::serial_println!("[LPC] Created port {} (type {:?}, name='{}')",
                i, port_type, name);
            return Some(i as u16);
        }
    }
    None
}

/// Close a port
pub unsafe fn lpc_close_port(port_index: u16) -> bool {
    let idx = port_index as usize;
    if idx >= MAX_PORTS {
        return false;
    }
    if (PORT_BITMAP[0] & (1 << idx)) == 0 {
        return false;
    }

    let port = &mut PORT_TABLE[idx];
    let port_type = port.port_type;

    // Clean up connection
    if port.connection.is_connected() {
        PORT_STATS.connected_ports = PORT_STATS.connected_ports.saturating_sub(1);
    }

    port.clear();
    PORT_BITMAP[0] &= !(1 << idx);
    PORT_STATS.allocated_ports = PORT_STATS.allocated_ports.saturating_sub(1);
    if port_type == LpcPortType::ServerConnection {
        PORT_STATS.server_ports = PORT_STATS.server_ports.saturating_sub(1);
    }

    crate::serial_println!("[LPC] Closed port {}", port_index);
    true
}

/// Connect to a named server port
pub unsafe fn lpc_connect_port(server_name: &str, context: &[u8]) -> Option<u16> {
    // Find the server port by name
    let mut server_idx = None;
    for i in 0..MAX_PORTS {
        if (PORT_BITMAP[0] & (1 << i)) != 0 {
            if PORT_TABLE[i].port_type == LpcPortType::ServerConnection
                && PORT_TABLE[i].name.equals(server_name)
            {
                server_idx = Some(i);
                break;
            }
        }
    }

    let server_idx = server_idx?;

    // Create client communication port
    let client_idx = lpc_create_port("", LpcPortType::ClientCommunication, MAX_MESSAGE_SIZE as u32)?;

    // Set up connection request
    let client_port = &mut PORT_TABLE[client_idx as usize];
    client_port.connection.state = LpcConnectionState::Pending;
    client_port.connection.server_port = server_idx as u16;
    client_port.connection.client_port = client_idx;
    client_port.connection.client_pid = 0; // TODO: Current process
    client_port.connection.context_size = context.len().min(256) as u16;

    // Add to server's pending connections
    let server_port = &mut PORT_TABLE[server_idx];
    let conn = LpcConnection {
        state: LpcConnectionState::Pending,
        client_port: client_idx,
        server_port: server_idx as u16,
        client_pid: 0,
        server_pid: server_port.owner_pid,
        client_tid: 0,
        server_tid: server_port.owner_tid,
        context_size: context.len().min(256) as u16,
        _reserved: 0,
    };

    if !server_port.add_pending_connection(conn) {
        // Failed to queue connection
        lpc_close_port(client_idx);
        return None;
    }

    crate::serial_println!("[LPC] Connection request from port {} to server '{}'",
        client_idx, server_name);

    Some(client_idx)
}

/// Listen for connections (for server ports)
pub unsafe fn lpc_listen_port(port_index: u16) -> Option<LpcConnection> {
    let idx = port_index as usize;
    if idx >= MAX_PORTS {
        return None;
    }
    if (PORT_BITMAP[0] & (1 << idx)) == 0 {
        return None;
    }

    let port = &mut PORT_TABLE[idx];
    if port.port_type != LpcPortType::ServerConnection {
        return None;
    }

    port.get_pending_connection()
}

/// Accept a connection
pub unsafe fn lpc_accept_connection(
    server_port: u16,
    client_port: u16,
    accept: bool,
) -> Option<u16> {
    let server_idx = server_port as usize;
    let client_idx = client_port as usize;

    if server_idx >= MAX_PORTS || client_idx >= MAX_PORTS {
        return None;
    }
    if (PORT_BITMAP[0] & (1 << server_idx)) == 0 || (PORT_BITMAP[0] & (1 << client_idx)) == 0 {
        return None;
    }

    if !accept {
        // Reject connection
        PORT_TABLE[client_idx].connection.state = LpcConnectionState::Closed;
        crate::serial_println!("[LPC] Connection rejected: client port {}", client_port);
        return None;
    }

    // Create server communication port
    let comm_port = lpc_create_port("", LpcPortType::ServerCommunication, MAX_MESSAGE_SIZE as u32)?;

    // Link ports
    let client = &mut PORT_TABLE[client_idx];
    client.connection.state = LpcConnectionState::Connected;
    client.connection.server_port = comm_port;

    let server_comm = &mut PORT_TABLE[comm_port as usize];
    server_comm.connection = LpcConnection {
        state: LpcConnectionState::Connected,
        client_port: client_port,
        server_port: comm_port,
        client_pid: client.owner_pid,
        server_pid: PORT_TABLE[server_idx].owner_pid,
        client_tid: client.owner_tid,
        server_tid: PORT_TABLE[server_idx].owner_tid,
        context_size: 0,
        _reserved: 0,
    };

    PORT_STATS.connected_ports += 2;
    PORT_STATS.client_ports += 1;

    crate::serial_println!("[LPC] Connection accepted: client {} <-> server comm {}",
        client_port, comm_port);

    Some(comm_port)
}

/// Get port information
pub unsafe fn lpc_get_port_info(port_index: u16) -> Option<LpcPortInfo> {
    let idx = port_index as usize;
    if idx >= MAX_PORTS {
        return None;
    }
    if (PORT_BITMAP[0] & (1 << idx)) == 0 {
        return None;
    }

    let port = &PORT_TABLE[idx];
    Some(LpcPortInfo {
        port_type: port.port_type,
        connection_state: port.connection.state,
        owner_pid: port.owner_pid,
        owner_tid: port.owner_tid,
        max_message_size: port.max_message_size,
        pending_connections: port.pending_count,
        pending_messages: port.msg_count,
    })
}

/// Get port statistics
pub fn lpc_get_port_stats() -> LpcPortStats {
    unsafe { PORT_STATS }
}

/// Get port by index (internal)
pub(super) unsafe fn get_port_mut(index: u16) -> Option<&'static mut LpcPort> {
    let idx = index as usize;
    if idx >= MAX_PORTS {
        return None;
    }
    if (PORT_BITMAP[0] & (1 << idx)) == 0 {
        return None;
    }
    Some(&mut PORT_TABLE[idx])
}

/// Update global message stats
pub(super) unsafe fn update_message_stats(sent: bool) {
    if sent {
        PORT_STATS.total_messages_sent += 1;
    } else {
        PORT_STATS.total_messages_received += 1;
    }
}

/// Initialize port subsystem
pub fn init() {
    crate::serial_println!("[LPC] Port subsystem initialized (max {} ports)", MAX_PORTS);
}
