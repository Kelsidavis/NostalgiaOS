//! LPC Message Implementation
//!
//! LPC messages are the data units transferred between ports.
//! Each message has a header followed by data.

use super::port::{get_port_mut, update_message_stats};

/// Maximum message size (header + data)
pub const MAX_MESSAGE_SIZE: usize = 512;

/// Maximum LPC data size (excluding header)
pub const MAX_LPC_DATA_SIZE: usize = MAX_MESSAGE_SIZE - core::mem::size_of::<LpcMessageHeader>();

/// Message type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum LpcMessageType {
    /// Invalid/unused
    #[default]
    Unused = 0,
    /// Request message
    Request = 1,
    /// Reply message
    Reply = 2,
    /// One-way datagram
    Datagram = 3,
    /// Connection request
    ConnectionRequest = 4,
    /// Connection reply
    ConnectionReply = 5,
    /// Client died notification
    ClientDied = 6,
    /// Port closed notification
    PortClosed = 7,
    /// Error message
    Error = 8,
    /// Debug message
    Debug = 9,
}


/// Message flags
#[allow(non_snake_case)]
pub mod LpcMessageFlags {
    /// Message expects a reply
    pub const REPLY_EXPECTED: u16 = 0x0001;
    /// Message is a reply
    pub const IS_REPLY: u16 = 0x0002;
    /// Message is urgent
    pub const URGENT: u16 = 0x0004;
    /// Message contains shared memory view
    pub const HAS_VIEW: u16 = 0x0008;
    /// Message contains security context
    pub const HAS_SECURITY: u16 = 0x0010;
    /// Message was cancelled
    pub const CANCELLED: u16 = 0x0020;
    /// Continuation message
    pub const CONTINUATION: u16 = 0x0040;
}

/// LPC Message Header
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct LpcMessageHeader {
    /// Total message length (header + data)
    pub length: u16,
    /// Data length only
    pub data_length: u16,
    /// Message type
    pub message_type: LpcMessageType,
    /// Message flags
    pub flags: u16,
    /// Reserved
    _reserved: u8,
    /// Message ID (for matching replies)
    pub message_id: u32,
    /// Client ID (process/thread)
    pub client_id: LpcClientId,
    /// View size (for ALPC views)
    pub view_size: u32,
}

impl LpcMessageHeader {
    pub const fn new() -> Self {
        Self {
            length: 0,
            data_length: 0,
            message_type: LpcMessageType::Unused,
            flags: 0,
            _reserved: 0,
            message_id: 0,
            client_id: LpcClientId::empty(),
            view_size: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.message_type != LpcMessageType::Unused
    }

    pub fn expects_reply(&self) -> bool {
        (self.flags & LpcMessageFlags::REPLY_EXPECTED) != 0
    }

    pub fn is_reply(&self) -> bool {
        (self.flags & LpcMessageFlags::IS_REPLY) != 0
    }
}

/// Client ID (identifies sender)
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct LpcClientId {
    /// Process ID
    pub process_id: u32,
    /// Thread ID
    pub thread_id: u32,
}

impl LpcClientId {
    pub const fn empty() -> Self {
        Self {
            process_id: 0,
            thread_id: 0,
        }
    }

    pub fn new(pid: u32, tid: u32) -> Self {
        Self {
            process_id: pid,
            thread_id: tid,
        }
    }
}

/// LPC Message (header + inline data)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct LpcMessage {
    /// Message header
    pub header: LpcMessageHeader,
    /// Inline data
    pub data: [u8; MAX_LPC_DATA_SIZE],
}

impl LpcMessage {
    pub const fn new() -> Self {
        Self {
            header: LpcMessageHeader::new(),
            data: [0; MAX_LPC_DATA_SIZE],
        }
    }

    /// Create a request message
    pub fn request(data: &[u8]) -> Self {
        let mut msg = Self::new();
        let len = data.len().min(MAX_LPC_DATA_SIZE);
        msg.data[..len].copy_from_slice(&data[..len]);
        msg.header.data_length = len as u16;
        msg.header.length = (core::mem::size_of::<LpcMessageHeader>() + len) as u16;
        msg.header.message_type = LpcMessageType::Request;
        msg.header.flags = LpcMessageFlags::REPLY_EXPECTED;
        msg
    }

    /// Create a reply message
    pub fn reply(request_id: u32, data: &[u8]) -> Self {
        let mut msg = Self::new();
        let len = data.len().min(MAX_LPC_DATA_SIZE);
        msg.data[..len].copy_from_slice(&data[..len]);
        msg.header.data_length = len as u16;
        msg.header.length = (core::mem::size_of::<LpcMessageHeader>() + len) as u16;
        msg.header.message_type = LpcMessageType::Reply;
        msg.header.flags = LpcMessageFlags::IS_REPLY;
        msg.header.message_id = request_id;
        msg
    }

    /// Create a datagram message
    pub fn datagram(data: &[u8]) -> Self {
        let mut msg = Self::new();
        let len = data.len().min(MAX_LPC_DATA_SIZE);
        msg.data[..len].copy_from_slice(&data[..len]);
        msg.header.data_length = len as u16;
        msg.header.length = (core::mem::size_of::<LpcMessageHeader>() + len) as u16;
        msg.header.message_type = LpcMessageType::Datagram;
        msg.header.flags = 0;
        msg
    }

    /// Get data slice
    pub fn get_data(&self) -> &[u8] {
        &self.data[..self.header.data_length as usize]
    }

    /// Set client ID
    pub fn set_client_id(&mut self, pid: u32, tid: u32) {
        self.header.client_id = LpcClientId::new(pid, tid);
    }
}

impl Default for LpcMessage {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Message Operations
// ============================================================================

/// Send a message to a port
pub unsafe fn lpc_send_message(
    port_index: u16,
    message: &LpcMessage,
) -> Option<u32> {
    let port = get_port_mut(port_index)?;

    // Must be connected to send
    if !port.is_connected() && port.port_type != super::port::LpcPortType::Unconnected {
        crate::serial_println!("[LPC] Cannot send: port {} not connected", port_index);
        return None;
    }

    // Get destination port
    let dest_port_idx = if port.connection.is_connected() {
        if port.port_type == super::port::LpcPortType::ClientCommunication {
            port.connection.server_port
        } else {
            port.connection.client_port
        }
    } else {
        port_index // Datagram to self?
    };

    let dest_port = get_port_mut(dest_port_idx)?;

    // Queue the message
    let msg_id = dest_port.queue_message(port_index, message.get_data())?;

    // Update stats
    port.messages_sent += 1;
    update_message_stats(true);

    crate::serial_println!("[LPC] Message {} sent from port {} to port {} ({} bytes)",
        msg_id, port_index, dest_port_idx, message.header.data_length);

    Some(msg_id)
}

/// Receive a message from a port
pub unsafe fn lpc_receive_message(port_index: u16) -> Option<LpcMessage> {
    let port = get_port_mut(port_index)?;

    let (source, msg_id, data, len) = port.dequeue_message()?;

    let mut msg = LpcMessage::new();
    msg.data[..len].copy_from_slice(&data[..len]);
    msg.header.data_length = len as u16;
    msg.header.length = (core::mem::size_of::<LpcMessageHeader>() + len) as u16;
    msg.header.message_id = msg_id;
    msg.header.message_type = LpcMessageType::Request;

    update_message_stats(false);

    crate::serial_println!("[LPC] Message {} received on port {} from port {} ({} bytes)",
        msg_id, port_index, source, len);

    Some(msg)
}

/// Reply to a message
pub unsafe fn lpc_reply_message(
    port_index: u16,
    request_id: u32,
    data: &[u8],
) -> bool {
    let port = match get_port_mut(port_index) {
        Some(p) => p,
        None => return false,
    };

    if !port.is_connected() {
        return false;
    }

    let reply = LpcMessage::reply(request_id, data);

    // Send to connected port
    let dest_idx = if port.port_type == super::port::LpcPortType::ServerCommunication {
        port.connection.client_port
    } else {
        port.connection.server_port
    };

    let dest_port = match get_port_mut(dest_idx) {
        Some(p) => p,
        None => return false,
    };
    match dest_port.queue_message(port_index, reply.get_data()) {
        Some(_) => {}
        None => return false,
    };

    port.messages_sent += 1;
    update_message_stats(true);

    crate::serial_println!("[LPC] Reply for message {} sent from port {} to port {} ({} bytes)",
        request_id, port_index, dest_idx, data.len());

    true
}

/// Send a one-way datagram
pub unsafe fn lpc_send_datagram(
    port_index: u16,
    dest_port: u16,
    data: &[u8],
) -> Option<u32> {
    let port = get_port_mut(port_index)?;

    let msg = LpcMessage::datagram(data);

    let dest = get_port_mut(dest_port)?;
    let msg_id = dest.queue_message(port_index, msg.get_data())?;

    port.messages_sent += 1;
    update_message_stats(true);

    crate::serial_println!("[LPC] Datagram {} sent from port {} to port {} ({} bytes)",
        msg_id, port_index, dest_port, data.len());

    Some(msg_id)
}

/// Initialize message subsystem
pub fn init() {
    crate::serial_println!("[LPC] Message subsystem initialized (max {} bytes/message)",
        MAX_MESSAGE_SIZE);
}
