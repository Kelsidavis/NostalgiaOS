//! Named Pipes (NPFS - Named Pipe File System)
//!
//! Named Pipes provide a powerful IPC mechanism in Windows NT:
//!
//! - **Bidirectional communication**: Both ends can read and write
//! - **Message or byte mode**: Discrete messages or byte stream
//! - **Multiple instances**: Multiple server-client connections per pipe name
//! - **Security**: ACLs on pipe instances
//! - **Blocking/overlapped**: Synchronous or asynchronous I/O
//!
//! # NT API
//!
//! - `NtCreateNamedPipeFile` - Create a server pipe instance
//! - `NtOpenFile` - Client connects to named pipe
//! - `NtReadFile` / `NtWriteFile` - Transfer data
//! - `NtFsControlFile` - Pipe control operations (listen, disconnect, peek)
//!
//! # Pipe States
//!
//! Server side: Disconnected → Listening → Connected → Disconnected
//! Client side: Connecting → Connected → Disconnected

use core::ptr;
use crate::ke::spinlock::SpinLock;
use crate::ke::event::{KEvent, EventType};

/// Maximum number of named pipes in the system
pub const MAX_NAMED_PIPES: usize = 64;

/// Maximum instances per pipe name
pub const MAX_PIPE_INSTANCES: usize = 8;

/// Maximum pending connections per pipe
pub const MAX_PENDING_CONNECTIONS: usize = 4;

/// Default pipe buffer size
pub const DEFAULT_BUFFER_SIZE: usize = 4096;

/// Maximum pipe name length
pub const MAX_PIPE_NAME: usize = 128;

/// Pipe type flags
pub mod pipe_type {
    /// Byte stream pipe
    pub const BYTE_TYPE: u32 = 0x0000;
    /// Message pipe
    pub const MESSAGE_TYPE: u32 = 0x0001;
    /// Read in byte mode
    pub const BYTE_READ: u32 = 0x0000;
    /// Read in message mode
    pub const MESSAGE_READ: u32 = 0x0002;
    /// Non-blocking mode
    pub const NOWAIT: u32 = 0x0004;
    /// Accept remote connections
    pub const ACCEPT_REMOTE_CLIENTS: u32 = 0x0008;
    /// Reject remote connections
    pub const REJECT_REMOTE_CLIENTS: u32 = 0x0010;
}

/// Pipe wait flags
pub mod pipe_wait {
    /// Wait forever for pipe
    pub const INFINITE: u64 = u64::MAX;
    /// Default timeout in milliseconds
    pub const DEFAULT_TIMEOUT_MS: u64 = 5000;
}

/// Pipe FSCTL codes
pub mod pipe_fsctl {
    /// Peek at pipe data
    pub const FSCTL_PIPE_PEEK: u32 = 0x0011400C;
    /// Wait for pipe to become available
    pub const FSCTL_PIPE_WAIT: u32 = 0x00110018;
    /// Disconnect pipe
    pub const FSCTL_PIPE_DISCONNECT: u32 = 0x00110004;
    /// Listen for connection
    pub const FSCTL_PIPE_LISTEN: u32 = 0x00110008;
    /// Transact (write then read)
    pub const FSCTL_PIPE_TRANSACT: u32 = 0x0011C017;
    /// Impersonate client
    pub const FSCTL_PIPE_IMPERSONATE: u32 = 0x0011001C;
    /// Get client computer name
    pub const FSCTL_PIPE_GET_CLIENT_COMPUTER_NAME: u32 = 0x00110418;
    /// Set client computer name
    pub const FSCTL_PIPE_SET_CLIENT_COMPUTER_NAME: u32 = 0x00110418;
    /// Query client process info
    pub const FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE: u32 = 0x00114003;
}

/// Pipe state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeState {
    /// Not connected
    Disconnected = 0,
    /// Server listening for client
    Listening = 1,
    /// Connected to peer
    Connected = 2,
    /// Closing
    Closing = 3,
}

/// Pipe end type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeEnd {
    /// Server end (created with NtCreateNamedPipeFile)
    Server = 0,
    /// Client end (connected via NtOpenFile)
    Client = 1,
}

/// Named Pipe instance
///
/// Each server CreateNamedPipe call creates an instance that can
/// accept one client connection.
#[repr(C)]
pub struct PipeInstance {
    /// State of this instance
    pub state: PipeState,
    /// Which end this represents
    pub end: PipeEnd,
    /// Pipe type and read mode flags
    pub type_flags: u32,
    /// Input buffer
    pub in_buffer: PipeBuffer,
    /// Output buffer
    pub out_buffer: PipeBuffer,
    /// Event for signaling data available
    pub data_event: KEvent,
    /// Event for signaling connection
    pub connect_event: KEvent,
    /// Reference to peer instance (if connected)
    pub peer: *mut PipeInstance,
    /// Reference count
    pub ref_count: u32,
    /// Is this instance in use?
    pub in_use: bool,
}

/// Message header for message-mode pipes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MessageHeader {
    /// Message length
    pub length: u16,
    /// Reserved flags
    pub flags: u16,
}

impl MessageHeader {
    pub const SIZE: usize = 4;

    pub const fn new(length: u16) -> Self {
        Self { length, flags: 0 }
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        let mut bytes = [0u8; 4];
        bytes[0..2].copy_from_slice(&self.length.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.flags.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        Some(Self {
            length: u16::from_le_bytes([bytes[0], bytes[1]]),
            flags: u16::from_le_bytes([bytes[2], bytes[3]]),
        })
    }
}

/// Ring buffer for pipe data
#[repr(C)]
pub struct PipeBuffer {
    /// Buffer data
    data: [u8; DEFAULT_BUFFER_SIZE],
    /// Read position
    read_pos: usize,
    /// Write position
    write_pos: usize,
    /// Current data count
    count: usize,
    /// Message mode (true = messages, false = bytes)
    message_mode: bool,
    /// Current message being read (for partial reads)
    current_message_remaining: usize,
}

impl PipeBuffer {
    /// Create a new empty buffer
    pub const fn new() -> Self {
        Self {
            data: [0u8; DEFAULT_BUFFER_SIZE],
            read_pos: 0,
            write_pos: 0,
            count: 0,
            message_mode: false,
            current_message_remaining: 0,
        }
    }

    /// Set message mode
    pub fn set_message_mode(&mut self, enabled: bool) {
        self.message_mode = enabled;
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if buffer is full
    pub fn is_full(&self) -> bool {
        self.count >= DEFAULT_BUFFER_SIZE
    }

    /// Get available space
    pub fn available(&self) -> usize {
        DEFAULT_BUFFER_SIZE - self.count
    }

    /// Get data count
    pub fn len(&self) -> usize {
        self.count
    }

    /// Write data to buffer (byte mode)
    pub fn write(&mut self, data: &[u8]) -> usize {
        let to_write = core::cmp::min(data.len(), self.available());

        for &byte in &data[..to_write] {
            self.data[self.write_pos] = byte;
            self.write_pos = (self.write_pos + 1) % DEFAULT_BUFFER_SIZE;
            self.count += 1;
        }

        to_write
    }

    /// Write a complete message (message mode)
    pub fn write_message(&mut self, data: &[u8]) -> Result<usize, PipeError> {
        // Need space for header + data
        let required = MessageHeader::SIZE + data.len();
        if required > self.available() {
            return Err(PipeError::BufferFull);
        }

        if data.len() > u16::MAX as usize {
            return Err(PipeError::MessageTooLarge);
        }

        // Write header
        let header = MessageHeader::new(data.len() as u16);
        let header_bytes = header.to_bytes();
        for &byte in &header_bytes {
            self.data[self.write_pos] = byte;
            self.write_pos = (self.write_pos + 1) % DEFAULT_BUFFER_SIZE;
            self.count += 1;
        }

        // Write data
        for &byte in data {
            self.data[self.write_pos] = byte;
            self.write_pos = (self.write_pos + 1) % DEFAULT_BUFFER_SIZE;
            self.count += 1;
        }

        Ok(data.len())
    }

    /// Read data from buffer (byte mode)
    pub fn read(&mut self, buffer: &mut [u8]) -> usize {
        let to_read = core::cmp::min(buffer.len(), self.count);

        for byte in buffer.iter_mut().take(to_read) {
            *byte = self.data[self.read_pos];
            self.read_pos = (self.read_pos + 1) % DEFAULT_BUFFER_SIZE;
            self.count -= 1;
        }

        to_read
    }

    /// Read a complete message (message mode)
    /// Returns (bytes read, more_data_in_message)
    pub fn read_message(&mut self, buffer: &mut [u8]) -> Result<(usize, bool), PipeError> {
        if self.count == 0 {
            return Ok((0, false));
        }

        // If we're continuing a partial message
        if self.current_message_remaining > 0 {
            let to_read = core::cmp::min(buffer.len(), self.current_message_remaining);
            let read = self.read(&mut buffer[..to_read]);
            self.current_message_remaining -= read;
            return Ok((read, self.current_message_remaining > 0));
        }

        // Read new message header
        if self.count < MessageHeader::SIZE {
            return Err(PipeError::IncompleteMessage);
        }

        let mut header_bytes = [0u8; 4];
        self.peek(&mut header_bytes);

        let header = MessageHeader::from_bytes(&header_bytes)
            .ok_or(PipeError::InvalidMessageHeader)?;

        // Skip the header
        self.read_pos = (self.read_pos + MessageHeader::SIZE) % DEFAULT_BUFFER_SIZE;
        self.count -= MessageHeader::SIZE;

        let message_len = header.length as usize;
        let to_read = core::cmp::min(buffer.len(), message_len);
        let read = self.read(&mut buffer[..to_read]);

        // Track remaining bytes in this message
        self.current_message_remaining = message_len - read;

        Ok((read, self.current_message_remaining > 0))
    }

    /// Peek at data without removing it
    pub fn peek(&self, buffer: &mut [u8]) -> usize {
        let to_peek = core::cmp::min(buffer.len(), self.count);
        let mut pos = self.read_pos;

        for byte in buffer.iter_mut().take(to_peek) {
            *byte = self.data[pos];
            pos = (pos + 1) % DEFAULT_BUFFER_SIZE;
        }

        to_peek
    }

    /// Peek at the next message's info (for message mode)
    pub fn peek_message_info(&self) -> Option<(u16, usize)> {
        if self.count < MessageHeader::SIZE {
            return None;
        }

        let mut header_bytes = [0u8; 4];
        self.peek(&mut header_bytes);

        let header = MessageHeader::from_bytes(&header_bytes)?;
        let message_len = header.length as usize;
        let available = if self.count >= MessageHeader::SIZE {
            (self.count - MessageHeader::SIZE).min(message_len)
        } else {
            0
        };

        Some((header.length, available))
    }

    /// Get message count in buffer
    pub fn message_count(&self) -> usize {
        let mut count = 0;
        let mut pos = self.read_pos;
        let mut remaining = self.count;

        while remaining >= MessageHeader::SIZE {
            // Read header at current position
            let mut header_bytes = [0u8; 4];
            for byte in header_bytes.iter_mut() {
                *byte = self.data[pos];
                pos = (pos + 1) % DEFAULT_BUFFER_SIZE;
            }

            if let Some(header) = MessageHeader::from_bytes(&header_bytes) {
                let message_len = header.length as usize;
                remaining -= MessageHeader::SIZE;

                if remaining >= message_len {
                    // Complete message
                    count += 1;
                    remaining -= message_len;
                    pos = (pos + message_len) % DEFAULT_BUFFER_SIZE;
                } else {
                    // Partial message
                    break;
                }
            } else {
                break;
            }
        }

        count
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.read_pos = 0;
        self.write_pos = 0;
        self.count = 0;
        self.current_message_remaining = 0;
    }
}

/// Pipe operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeError {
    /// Buffer is full
    BufferFull,
    /// Message too large for buffer
    MessageTooLarge,
    /// Incomplete message in buffer
    IncompleteMessage,
    /// Invalid message header
    InvalidMessageHeader,
    /// Pipe disconnected
    Disconnected,
    /// Pipe not connected
    NotConnected,
    /// Pipe is busy
    Busy,
    /// Invalid pipe state
    InvalidState,
    /// Timeout waiting for pipe
    Timeout,
    /// Invalid parameter
    InvalidParameter,
}

impl PipeInstance {
    /// Create a new instance
    pub const fn new() -> Self {
        Self {
            state: PipeState::Disconnected,
            end: PipeEnd::Server,
            type_flags: 0,
            in_buffer: PipeBuffer::new(),
            out_buffer: PipeBuffer::new(),
            data_event: KEvent::new(),
            connect_event: KEvent::new(),
            peer: ptr::null_mut(),
            ref_count: 0,
            in_use: false,
        }
    }

    /// Initialize instance as server
    pub fn init_server(&mut self, type_flags: u32) {
        self.state = PipeState::Disconnected;
        self.end = PipeEnd::Server;
        self.type_flags = type_flags;
        self.in_buffer.clear();
        self.out_buffer.clear();
        self.data_event.init(EventType::Notification, false);
        self.connect_event.init(EventType::Notification, false);
        self.peer = ptr::null_mut();
        self.ref_count = 1;
        self.in_use = true;
    }

    /// Initialize instance as client
    pub fn init_client(&mut self, type_flags: u32) {
        self.state = PipeState::Disconnected;
        self.end = PipeEnd::Client;
        self.type_flags = type_flags;
        self.in_buffer.clear();
        self.out_buffer.clear();
        self.data_event.init(EventType::Notification, false);
        self.connect_event.init(EventType::Notification, false);
        self.peer = ptr::null_mut();
        self.ref_count = 1;
        self.in_use = true;
    }

    /// Server: listen for a connection
    pub unsafe fn listen(&mut self) -> bool {
        if self.end != PipeEnd::Server || self.state != PipeState::Disconnected {
            return false;
        }

        self.state = PipeState::Listening;
        self.connect_event.reset();
        true
    }

    /// Connect two pipe instances
    pub unsafe fn connect(&mut self, peer: *mut PipeInstance) -> bool {
        if peer.is_null() {
            return false;
        }

        self.peer = peer;
        (*peer).peer = self as *mut PipeInstance;

        self.state = PipeState::Connected;
        (*peer).state = PipeState::Connected;

        // Signal connection events
        self.connect_event.set();
        (*peer).connect_event.set();

        true
    }

    /// Disconnect from peer
    pub unsafe fn disconnect(&mut self) {
        if !self.peer.is_null() {
            let peer = self.peer;
            (*peer).peer = ptr::null_mut();
            (*peer).state = PipeState::Disconnected;
            self.peer = ptr::null_mut();
        }
        self.state = PipeState::Disconnected;
        self.in_buffer.clear();
        self.out_buffer.clear();
    }

    /// Write data to peer's input buffer
    pub unsafe fn write(&mut self, data: &[u8]) -> isize {
        const STATUS_PIPE_DISCONNECTED: isize = 0xC00000B0u32 as isize;

        if self.state != PipeState::Connected || self.peer.is_null() {
            return STATUS_PIPE_DISCONNECTED;
        }

        let peer = &mut *self.peer;
        let written = peer.in_buffer.write(data);

        if written > 0 {
            // Signal peer that data is available
            peer.data_event.set();
        }

        written as isize
    }

    /// Read data from our input buffer
    pub fn read(&mut self, buffer: &mut [u8]) -> isize {
        let read = self.in_buffer.read(buffer);

        if self.in_buffer.is_empty() {
            unsafe { self.data_event.reset(); }
        }

        read as isize
    }

    /// Peek at data without removing
    pub fn peek(&self, buffer: &mut [u8]) -> usize {
        self.in_buffer.peek(buffer)
    }

    /// Check if data is available to read
    pub fn data_available(&self) -> usize {
        self.in_buffer.len()
    }

    /// Add reference
    pub fn reference(&mut self) {
        self.ref_count += 1;
    }

    /// Release reference
    pub fn dereference(&mut self) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        self.ref_count == 0
    }
}

/// Named Pipe entry (represents a pipe name with multiple instances)
#[repr(C)]
pub struct NamedPipe {
    /// Pipe name (like "\Device\NamedPipe\MyPipe")
    pub name: [u8; MAX_PIPE_NAME],
    /// Name length
    pub name_len: usize,
    /// Hash of name for quick lookup
    pub name_hash: u32,
    /// Pipe instances
    pub instances: [PipeInstance; MAX_PIPE_INSTANCES],
    /// Maximum allowed instances
    pub max_instances: u32,
    /// Current instance count
    pub instance_count: u32,
    /// Pipe type flags
    pub type_flags: u32,
    /// Is this entry in use?
    pub in_use: bool,
    /// Lock for this pipe
    lock: SpinLock<()>,
}

impl NamedPipe {
    /// Create a new empty pipe entry
    pub const fn new() -> Self {
        const INIT_INSTANCE: PipeInstance = PipeInstance::new();
        Self {
            name: [0u8; MAX_PIPE_NAME],
            name_len: 0,
            name_hash: 0,
            instances: [INIT_INSTANCE; MAX_PIPE_INSTANCES],
            max_instances: MAX_PIPE_INSTANCES as u32,
            instance_count: 0,
            type_flags: 0,
            in_use: false,
            lock: SpinLock::new(()),
        }
    }

    /// Initialize with a name
    pub fn init(&mut self, name: &[u8], max_instances: u32, type_flags: u32) {
        let len = core::cmp::min(name.len(), MAX_PIPE_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
        self.name_hash = hash_name(&name[..len]);
        self.max_instances = max_instances;
        self.type_flags = type_flags;
        self.instance_count = 0;
        self.in_use = true;
    }

    /// Check if name matches
    pub fn name_matches(&self, name: &[u8]) -> bool {
        if name.len() != self.name_len {
            return false;
        }
        &self.name[..self.name_len] == name
    }

    /// Allocate a new server instance
    pub fn allocate_server_instance(&mut self) -> Option<&mut PipeInstance> {
        if self.instance_count >= self.max_instances {
            return None;
        }

        for instance in self.instances.iter_mut() {
            if !instance.in_use {
                instance.init_server(self.type_flags);
                self.instance_count += 1;
                return Some(instance);
            }
        }
        None
    }

    /// Find a listening instance for client connection
    pub fn find_listening_instance(&mut self) -> Option<&mut PipeInstance> {
        for instance in self.instances.iter_mut() {
            if instance.in_use && instance.state == PipeState::Listening {
                return Some(instance);
            }
        }
        None
    }

    /// Free an instance
    pub fn free_instance(&mut self, instance_idx: usize) {
        if instance_idx < MAX_PIPE_INSTANCES && self.instances[instance_idx].in_use {
            unsafe {
                self.instances[instance_idx].disconnect();
            }
            self.instances[instance_idx].in_use = false;
            if self.instance_count > 0 {
                self.instance_count -= 1;
            }
        }
    }
}

/// Simple hash function for pipe names
fn hash_name(name: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &byte in name {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
    }
    hash
}

// ============================================================================
// Global Named Pipe Registry
// ============================================================================

/// Pool of named pipes
static mut PIPE_POOL: [NamedPipe; MAX_NAMED_PIPES] = {
    const INIT: NamedPipe = NamedPipe::new();
    [INIT; MAX_NAMED_PIPES]
};

/// Lock for pipe allocation
static PIPE_LOCK: SpinLock<()> = SpinLock::new(());

/// Create a named pipe (server side)
///
/// # Arguments
/// * `name` - Pipe name (e.g., "\Device\NamedPipe\MyPipe")
/// * `max_instances` - Maximum concurrent instances
/// * `type_flags` - Pipe type (byte/message mode)
///
/// # Returns
/// Pointer to the pipe instance, or null on failure
pub unsafe fn io_create_named_pipe(
    name: &[u8],
    max_instances: u32,
    type_flags: u32,
) -> *mut PipeInstance {
    let _guard = PIPE_LOCK.lock();

    // First, check if pipe name already exists
    let name_hash = hash_name(name);

    for pipe in PIPE_POOL.iter_mut() {
        if pipe.in_use && pipe.name_hash == name_hash && pipe.name_matches(name) {
            // Pipe exists, try to add an instance
            if let Some(instance) = pipe.allocate_server_instance() {
                return instance as *mut PipeInstance;
            }
            return ptr::null_mut(); // Max instances reached
        }
    }

    // Create new pipe entry
    for pipe in PIPE_POOL.iter_mut() {
        if !pipe.in_use {
            pipe.init(name, max_instances, type_flags);
            if let Some(instance) = pipe.allocate_server_instance() {
                return instance as *mut PipeInstance;
            }
            return ptr::null_mut();
        }
    }

    ptr::null_mut() // No free pipe entries
}

/// Open a named pipe (client side)
///
/// # Arguments
/// * `name` - Pipe name to connect to
///
/// # Returns
/// Pointer to client instance, or null if pipe not found or not listening
pub unsafe fn io_open_named_pipe(name: &[u8]) -> *mut PipeInstance {
    let _guard = PIPE_LOCK.lock();

    let name_hash = hash_name(name);

    for pipe in PIPE_POOL.iter_mut() {
        if pipe.in_use && pipe.name_hash == name_hash && pipe.name_matches(name) {
            // Find a listening server instance (by index)
            let mut server_idx: Option<usize> = None;
            for idx in 0..MAX_PIPE_INSTANCES {
                if pipe.instances[idx].in_use && pipe.instances[idx].state == PipeState::Listening {
                    server_idx = Some(idx);
                    break;
                }
            }

            let server_idx = match server_idx {
                Some(idx) => idx,
                None => return ptr::null_mut(), // No listening instance
            };

            // Find a free slot for client instance
            let mut client_idx: Option<usize> = None;
            for idx in 0..MAX_PIPE_INSTANCES {
                if !pipe.instances[idx].in_use {
                    client_idx = Some(idx);
                    break;
                }
            }

            let client_idx = match client_idx {
                Some(idx) => idx,
                None => return ptr::null_mut(), // No free slots
            };

            // Initialize client instance
            let type_flags = pipe.type_flags;
            pipe.instances[client_idx].init_client(type_flags);
            pipe.instance_count += 1;

            // Connect them
            let client = &mut pipe.instances[client_idx] as *mut PipeInstance;
            let server = &mut pipe.instances[server_idx] as *mut PipeInstance;
            (*client).connect(server);

            return client;
        }
    }

    ptr::null_mut() // Pipe not found
}

/// Close a pipe instance
pub unsafe fn io_close_pipe_instance(instance: *mut PipeInstance) {
    if instance.is_null() {
        return;
    }

    let _guard = PIPE_LOCK.lock();

    // Disconnect from peer
    (*instance).disconnect();

    // Dereference
    if (*instance).dereference() {
        (*instance).in_use = false;

        // Update parent pipe's instance count
        // (In a full implementation, we'd track the parent pipe)
    }
}

/// Write to a pipe
pub unsafe fn io_write_pipe(
    instance: *mut PipeInstance,
    buffer: *const u8,
    length: usize,
) -> isize {
    const STATUS_INVALID_PARAMETER: isize = 0xC000000Du32 as isize;

    if instance.is_null() || buffer.is_null() || length == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let data = core::slice::from_raw_parts(buffer, length);
    (*instance).write(data)
}

/// Read from a pipe
pub unsafe fn io_read_pipe(
    instance: *mut PipeInstance,
    buffer: *mut u8,
    length: usize,
) -> isize {
    const STATUS_INVALID_PARAMETER: isize = 0xC000000Du32 as isize;

    if instance.is_null() || buffer.is_null() || length == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let buf = core::slice::from_raw_parts_mut(buffer, length);
    (*instance).read(buf)
}

/// Server: listen for client connection
pub unsafe fn io_listen_pipe(instance: *mut PipeInstance) -> bool {
    if instance.is_null() {
        return false;
    }
    (*instance).listen()
}

/// Check for pending data
pub unsafe fn io_peek_pipe(
    instance: *mut PipeInstance,
    buffer: *mut u8,
    length: usize,
) -> usize {
    if instance.is_null() || buffer.is_null() || length == 0 {
        return 0;
    }

    let buf = core::slice::from_raw_parts_mut(buffer, length);
    (*instance).peek(buf)
}

/// Get pipe state
pub unsafe fn io_get_pipe_state(instance: *mut PipeInstance) -> PipeState {
    if instance.is_null() {
        return PipeState::Disconnected;
    }
    (*instance).state
}

/// Pipe statistics
#[repr(C)]
pub struct PipeStats {
    pub total_pipes: u32,
    pub active_pipes: u32,
    pub total_instances: u32,
    pub connected_instances: u32,
}

/// Get pipe subsystem statistics
pub fn get_pipe_stats() -> PipeStats {
    let mut stats = PipeStats {
        total_pipes: MAX_NAMED_PIPES as u32,
        active_pipes: 0,
        total_instances: 0,
        connected_instances: 0,
    };

    unsafe {
        for pipe in PIPE_POOL.iter() {
            if pipe.in_use {
                stats.active_pipes += 1;
                for instance in pipe.instances.iter() {
                    if instance.in_use {
                        stats.total_instances += 1;
                        if instance.state == PipeState::Connected {
                            stats.connected_instances += 1;
                        }
                    }
                }
            }
        }
    }

    stats
}

/// Named pipe snapshot for inspection
#[derive(Clone, Copy)]
pub struct PipeSnapshot {
    /// Pipe name
    pub name: [u8; 64],
    /// Name length
    pub name_len: u8,
    /// Max instances allowed
    pub max_instances: u32,
    /// Current instance count
    pub instance_count: u32,
    /// Pipe type flags
    pub type_flags: u32,
    /// Instances in listening state
    pub listening_count: u32,
    /// Instances in connected state
    pub connected_count: u32,
}

impl PipeSnapshot {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; 64],
            name_len: 0,
            max_instances: 0,
            instance_count: 0,
            type_flags: 0,
            listening_count: 0,
            connected_count: 0,
        }
    }
}

/// Get snapshots of all active named pipes
pub fn io_get_pipe_snapshots(max_count: usize) -> ([PipeSnapshot; 32], usize) {
    let mut snapshots = [PipeSnapshot::empty(); 32];
    let mut count = 0;

    let limit = max_count.min(32);

    unsafe {
        for pipe in PIPE_POOL.iter() {
            if count >= limit {
                break;
            }

            if pipe.in_use {
                let snap = &mut snapshots[count];

                // Copy name (up to 64 bytes)
                let name_len = pipe.name_len.min(64);
                snap.name[..name_len].copy_from_slice(&pipe.name[..name_len]);
                snap.name_len = name_len as u8;
                snap.max_instances = pipe.max_instances;
                snap.instance_count = pipe.instance_count;
                snap.type_flags = pipe.type_flags;

                // Count instance states
                snap.listening_count = 0;
                snap.connected_count = 0;
                for instance in pipe.instances.iter() {
                    if instance.in_use {
                        match instance.state {
                            PipeState::Listening => snap.listening_count += 1,
                            PipeState::Connected => snap.connected_count += 1,
                            _ => {}
                        }
                    }
                }

                count += 1;
            }
        }
    }

    (snapshots, count)
}

/// Get pipe type name
pub fn pipe_type_name(type_flags: u32) -> &'static str {
    if (type_flags & pipe_type::MESSAGE_TYPE) != 0 {
        "Message"
    } else {
        "Byte"
    }
}

// ============================================================================
// Enhanced Pipe Operations (NT-Style)
// ============================================================================

/// Transact on a pipe (atomic write then read)
///
/// This is the FSCTL_PIPE_TRANSACT operation - writes data to the pipe,
/// then reads the response. Common for RPC-style communication.
pub unsafe fn io_transact_pipe(
    instance: *mut PipeInstance,
    write_buffer: *const u8,
    write_length: usize,
    read_buffer: *mut u8,
    read_length: usize,
) -> Result<usize, PipeError> {
    if instance.is_null() {
        return Err(PipeError::InvalidParameter);
    }

    let inst = &mut *instance;

    // Must be connected
    if inst.state != PipeState::Connected || inst.peer.is_null() {
        return Err(PipeError::NotConnected);
    }

    // Write data to peer
    if !write_buffer.is_null() && write_length > 0 {
        let write_data = core::slice::from_raw_parts(write_buffer, write_length);
        let peer = &mut *inst.peer;

        // Use message mode if enabled
        if (inst.type_flags & pipe_type::MESSAGE_TYPE) != 0 {
            peer.in_buffer.write_message(write_data)?;
        } else {
            let written = peer.in_buffer.write(write_data);
            if written < write_data.len() {
                return Err(PipeError::BufferFull);
            }
        }
        peer.data_event.set();
    }

    // Read response
    if !read_buffer.is_null() && read_length > 0 {
        let read_buf = core::slice::from_raw_parts_mut(read_buffer, read_length);

        // For message mode, read a complete message
        if (inst.type_flags & pipe_type::MESSAGE_READ) != 0 {
            let (read, _more) = inst.in_buffer.read_message(read_buf)?;
            if inst.in_buffer.is_empty() {
                inst.data_event.reset();
            }
            Ok(read)
        } else {
            let read = inst.in_buffer.read(read_buf);
            if inst.in_buffer.is_empty() {
                inst.data_event.reset();
            }
            Ok(read)
        }
    } else {
        Ok(0)
    }
}

/// Write a message to pipe (message mode)
pub unsafe fn io_write_pipe_message(
    instance: *mut PipeInstance,
    buffer: *const u8,
    length: usize,
) -> Result<usize, PipeError> {
    if instance.is_null() || buffer.is_null() {
        return Err(PipeError::InvalidParameter);
    }

    let inst = &mut *instance;

    if inst.state != PipeState::Connected || inst.peer.is_null() {
        return Err(PipeError::NotConnected);
    }

    let data = core::slice::from_raw_parts(buffer, length);
    let peer = &mut *inst.peer;

    peer.in_buffer.write_message(data)?;
    peer.data_event.set();

    Ok(length)
}

/// Read a message from pipe (message mode)
/// Returns (bytes_read, more_data_remaining)
pub unsafe fn io_read_pipe_message(
    instance: *mut PipeInstance,
    buffer: *mut u8,
    length: usize,
) -> Result<(usize, bool), PipeError> {
    if instance.is_null() || buffer.is_null() {
        return Err(PipeError::InvalidParameter);
    }

    let inst = &mut *instance;
    let buf = core::slice::from_raw_parts_mut(buffer, length);

    let result = inst.in_buffer.read_message(buf)?;

    if inst.in_buffer.is_empty() {
        inst.data_event.reset();
    }

    Ok(result)
}

/// Wait for a named pipe to become available
///
/// This waits for a server instance to start listening.
pub unsafe fn io_wait_named_pipe(
    name: &[u8],
    _timeout_ms: u64,
) -> Result<(), PipeError> {
    let _guard = PIPE_LOCK.lock();

    let name_hash = hash_name(name);

    for pipe in PIPE_POOL.iter() {
        if pipe.in_use && pipe.name_hash == name_hash && pipe.name_matches(name) {
            // Check if any instance is listening or can accept connections
            for instance in pipe.instances.iter() {
                if instance.in_use && instance.state == PipeState::Listening {
                    return Ok(());
                }
            }

            // Pipe exists but no listening instance
            // In a full implementation, we would wait on an event
            return Err(PipeError::Busy);
        }
    }

    Err(PipeError::NotConnected)
}

/// Peek at named pipe data
#[repr(C)]
pub struct PipePeekInfo {
    /// Pipe state
    pub state: u32,
    /// Bytes available to read
    pub read_data_available: u32,
    /// Number of messages available (message mode)
    pub number_of_messages_left: u32,
    /// Size of next message (message mode)
    pub message_length: u32,
}

impl PipePeekInfo {
    pub const fn empty() -> Self {
        Self {
            state: 0,
            read_data_available: 0,
            number_of_messages_left: 0,
            message_length: 0,
        }
    }
}

/// Get pipe peek information
pub unsafe fn io_peek_named_pipe_info(
    instance: *mut PipeInstance,
) -> Result<PipePeekInfo, PipeError> {
    if instance.is_null() {
        return Err(PipeError::InvalidParameter);
    }

    let inst = &*instance;

    let mut info = PipePeekInfo::empty();
    info.state = inst.state as u32;
    info.read_data_available = inst.in_buffer.len() as u32;

    // Message mode info
    if (inst.type_flags & pipe_type::MESSAGE_TYPE) != 0 {
        info.number_of_messages_left = inst.in_buffer.message_count() as u32;
        if let Some((msg_len, _available)) = inst.in_buffer.peek_message_info() {
            info.message_length = msg_len as u32;
        }
    }

    Ok(info)
}

/// Handle FSCTL operation on pipe
pub unsafe fn io_fsctl_pipe(
    instance: *mut PipeInstance,
    fsctl_code: u32,
    _input_buffer: *const u8,
    _input_length: usize,
    output_buffer: *mut u8,
    output_length: usize,
) -> Result<usize, PipeError> {
    if instance.is_null() {
        return Err(PipeError::InvalidParameter);
    }

    match fsctl_code {
        pipe_fsctl::FSCTL_PIPE_PEEK => {
            // Return peek info
            let info = io_peek_named_pipe_info(instance)?;
            if output_length >= core::mem::size_of::<PipePeekInfo>() && !output_buffer.is_null() {
                let out_ptr = output_buffer as *mut PipePeekInfo;
                *out_ptr = info;
                Ok(core::mem::size_of::<PipePeekInfo>())
            } else {
                Ok(0)
            }
        }
        pipe_fsctl::FSCTL_PIPE_LISTEN => {
            if io_listen_pipe(instance) {
                Ok(0)
            } else {
                Err(PipeError::InvalidState)
            }
        }
        pipe_fsctl::FSCTL_PIPE_DISCONNECT => {
            (*instance).disconnect();
            Ok(0)
        }
        pipe_fsctl::FSCTL_PIPE_WAIT => {
            // Already handled by io_wait_named_pipe
            Ok(0)
        }
        _ => Err(PipeError::InvalidParameter),
    }
}

/// Set pipe read mode
pub unsafe fn io_set_pipe_read_mode(
    instance: *mut PipeInstance,
    message_mode: bool,
) -> Result<(), PipeError> {
    if instance.is_null() {
        return Err(PipeError::InvalidParameter);
    }

    let inst = &mut *instance;

    if message_mode {
        inst.type_flags |= pipe_type::MESSAGE_READ;
        inst.in_buffer.set_message_mode(true);
    } else {
        inst.type_flags &= !pipe_type::MESSAGE_READ;
        inst.in_buffer.set_message_mode(false);
    }

    Ok(())
}

/// Get pipe handle info
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PipeHandleInfo {
    /// Flags
    pub flags: u32,
    /// Read mode (byte or message)
    pub read_mode: u32,
    /// Max instances
    pub max_instances: u32,
    /// Inbound quota
    pub in_buffer_size: u32,
    /// Outbound quota
    pub out_buffer_size: u32,
}

impl PipeHandleInfo {
    pub const fn empty() -> Self {
        Self {
            flags: 0,
            read_mode: 0,
            max_instances: 0,
            in_buffer_size: 0,
            out_buffer_size: 0,
        }
    }
}

/// Get information about a pipe handle
pub unsafe fn io_get_pipe_handle_info(
    instance: *mut PipeInstance,
) -> Result<PipeHandleInfo, PipeError> {
    if instance.is_null() {
        return Err(PipeError::InvalidParameter);
    }

    let inst = &*instance;

    Ok(PipeHandleInfo {
        flags: inst.type_flags,
        read_mode: if (inst.type_flags & pipe_type::MESSAGE_READ) != 0 { 1 } else { 0 },
        max_instances: MAX_PIPE_INSTANCES as u32,
        in_buffer_size: DEFAULT_BUFFER_SIZE as u32,
        out_buffer_size: DEFAULT_BUFFER_SIZE as u32,
    })
}

/// Call a named pipe (client: open + transact + close)
///
/// Convenience function for simple RPC-style calls.
pub unsafe fn io_call_named_pipe(
    name: &[u8],
    write_buffer: *const u8,
    write_length: usize,
    read_buffer: *mut u8,
    read_length: usize,
    _timeout_ms: u64,
) -> Result<usize, PipeError> {
    // Open the pipe
    let instance = io_open_named_pipe(name);
    if instance.is_null() {
        return Err(PipeError::NotConnected);
    }

    // Transact
    let result = io_transact_pipe(
        instance,
        write_buffer,
        write_length,
        read_buffer,
        read_length,
    );

    // Close the pipe (even if transact failed)
    io_close_pipe_instance(instance);

    result
}

/// Pipe local info for queries
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PipeLocalInfo {
    /// Pipe type (byte or message)
    pub pipe_type: u32,
    /// Pipe end (server or client)
    pub pipe_end: u32,
    /// Max instances
    pub max_instances: u32,
    /// Current instances
    pub current_instances: u32,
    /// Inbound quota
    pub in_buffer_size: u32,
    /// Bytes in read buffer
    pub read_data_available: u32,
    /// Outbound quota
    pub out_buffer_size: u32,
    /// Bytes in write buffer
    pub write_data_available: u32,
}

impl PipeLocalInfo {
    pub const fn empty() -> Self {
        Self {
            pipe_type: 0,
            pipe_end: 0,
            max_instances: 0,
            current_instances: 0,
            in_buffer_size: 0,
            read_data_available: 0,
            out_buffer_size: 0,
            write_data_available: 0,
        }
    }
}

/// Query local pipe information
pub unsafe fn io_query_pipe_local_info(
    instance: *mut PipeInstance,
) -> Result<PipeLocalInfo, PipeError> {
    if instance.is_null() {
        return Err(PipeError::InvalidParameter);
    }

    let inst = &*instance;

    let pipe_type = if (inst.type_flags & pipe_type::MESSAGE_TYPE) != 0 { 1 } else { 0 };
    let pipe_end = inst.end as u32;

    Ok(PipeLocalInfo {
        pipe_type,
        pipe_end,
        max_instances: MAX_PIPE_INSTANCES as u32,
        current_instances: 1, // Would need to track parent pipe
        in_buffer_size: DEFAULT_BUFFER_SIZE as u32,
        read_data_available: inst.in_buffer.len() as u32,
        out_buffer_size: DEFAULT_BUFFER_SIZE as u32,
        write_data_available: inst.out_buffer.len() as u32,
    })
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the named pipe subsystem
pub fn init() {
    unsafe {
        for pipe in PIPE_POOL.iter_mut() {
            pipe.in_use = false;
            pipe.instance_count = 0;
        }
    }

    crate::serial_println!("[IO] Named pipe subsystem initialized");
}
