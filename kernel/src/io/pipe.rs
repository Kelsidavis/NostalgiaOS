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
}

impl PipeBuffer {
    /// Create a new empty buffer
    pub const fn new() -> Self {
        Self {
            data: [0u8; DEFAULT_BUFFER_SIZE],
            read_pos: 0,
            write_pos: 0,
            count: 0,
        }
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

    /// Write data to buffer
    pub fn write(&mut self, data: &[u8]) -> usize {
        let to_write = core::cmp::min(data.len(), self.available());

        for &byte in &data[..to_write] {
            self.data[self.write_pos] = byte;
            self.write_pos = (self.write_pos + 1) % DEFAULT_BUFFER_SIZE;
            self.count += 1;
        }

        to_write
    }

    /// Read data from buffer
    pub fn read(&mut self, buffer: &mut [u8]) -> usize {
        let to_read = core::cmp::min(buffer.len(), self.count);

        for byte in buffer.iter_mut().take(to_read) {
            *byte = self.data[self.read_pos];
            self.read_pos = (self.read_pos + 1) % DEFAULT_BUFFER_SIZE;
            self.count -= 1;
        }

        to_read
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

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.read_pos = 0;
        self.write_pos = 0;
        self.count = 0;
    }
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
        if self.state != PipeState::Connected || self.peer.is_null() {
            return -1; // STATUS_PIPE_DISCONNECTED
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
    if instance.is_null() || buffer.is_null() || length == 0 {
        return -1;
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
    if instance.is_null() || buffer.is_null() || length == 0 {
        return -1;
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
