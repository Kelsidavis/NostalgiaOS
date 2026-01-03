//! NPFS (Named Pipe File System)
//!
//! Named pipes are a key Windows IPC mechanism providing bidirectional
//! communication between processes, either locally or across the network.
//!
//! Named pipes are accessed via \Device\NamedPipe\<pipename>
//!
//! Pipe modes:
//! - Byte mode: Data flows as a stream of bytes
//! - Message mode: Data is sent as discrete messages
//!
//! Pipe types:
//! - Inbound: Server reads, client writes
//! - Outbound: Server writes, client reads
//! - Duplex: Both directions

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// Maximum number of named pipes
const MAX_NAMED_PIPES: usize = 32;

/// Maximum number of pipe instances per name
const MAX_PIPE_INSTANCES: usize = 8;

/// Maximum buffer size
const MAX_BUFFER_SIZE: usize = 4096;

/// Default buffer size
const DEFAULT_BUFFER_SIZE: usize = 1024;

/// Maximum pipe name length
const MAX_PIPE_NAME_LEN: usize = 128;

// ============================================================================
// Pipe Types and Modes
// ============================================================================

/// Pipe direction/type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PipeType {
    /// Inbound only (server reads)
    Inbound = 0x00000001,
    /// Outbound only (server writes)
    Outbound = 0x00000002,
    /// Duplex (bidirectional)
    Duplex = 0x00000003,
}

/// Pipe read mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PipeReadMode {
    /// Byte stream mode
    Byte = 0x00000000,
    /// Message mode
    Message = 0x00000002,
}

/// Pipe wait mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PipeWait {
    /// Blocking wait
    Wait = 0x00000000,
    /// Non-blocking (nowait)
    NoWait = 0x00000001,
}

/// Pipe state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeState {
    /// Pipe created, waiting for connection
    Disconnected,
    /// Pipe listening for client
    Listening,
    /// Pipe connected to client
    Connected,
    /// Pipe closing
    Closing,
    /// Pipe closed
    Closed,
}

/// Pipe end type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeEnd {
    /// Server end
    Server,
    /// Client end
    Client,
}

// ============================================================================
// Pipe Instance
// ============================================================================

/// A single instance of a named pipe
pub struct PipeInstance {
    /// Instance ID
    pub id: u64,
    /// Parent pipe ID
    pub pipe_id: u64,
    /// Instance number (0-based)
    pub instance_num: u32,
    /// Current state
    pub state: PipeState,
    /// Server-side file handle
    pub server_handle: u64,
    /// Client-side file handle
    pub client_handle: u64,
    /// Server to client buffer
    pub server_buffer: VecDeque<u8>,
    /// Client to server buffer
    pub client_buffer: VecDeque<u8>,
    /// Read mode
    pub read_mode: PipeReadMode,
    /// Wait mode
    pub wait_mode: PipeWait,
    /// Server process ID
    pub server_process: u32,
    /// Client process ID
    pub client_process: u32,
    /// Bytes read from this instance
    pub bytes_read: u64,
    /// Bytes written to this instance
    pub bytes_written: u64,
    /// Active flag
    pub active: bool,
}

impl Default for PipeInstance {
    fn default() -> Self {
        Self {
            id: 0,
            pipe_id: 0,
            instance_num: 0,
            state: PipeState::Disconnected,
            server_handle: 0,
            client_handle: 0,
            server_buffer: VecDeque::new(),
            client_buffer: VecDeque::new(),
            read_mode: PipeReadMode::Byte,
            wait_mode: PipeWait::Wait,
            server_process: 0,
            client_process: 0,
            bytes_read: 0,
            bytes_written: 0,
            active: false,
        }
    }
}

// ============================================================================
// Named Pipe
// ============================================================================

/// A named pipe definition
pub struct NamedPipe {
    /// Pipe ID
    pub id: u64,
    /// Pipe name (without \Device\NamedPipe prefix)
    pub name: [u8; MAX_PIPE_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Pipe type
    pub pipe_type: PipeType,
    /// Read mode
    pub read_mode: PipeReadMode,
    /// Maximum number of instances
    pub max_instances: u32,
    /// Current number of instances
    pub current_instances: u32,
    /// Outbound (server to client) buffer size
    pub out_buffer_size: usize,
    /// Inbound (client to server) buffer size
    pub in_buffer_size: usize,
    /// Default timeout (100ns units)
    pub default_timeout: u64,
    /// Creator process ID
    pub creator_process: u32,
    /// Creation time
    pub create_time: u64,
    /// Active flag
    pub active: bool,
    /// Instances
    pub instances: [PipeInstance; MAX_PIPE_INSTANCES],
}

impl NamedPipe {
    const fn new() -> Self {
        const DEFAULT_INSTANCE: PipeInstance = PipeInstance {
            id: 0,
            pipe_id: 0,
            instance_num: 0,
            state: PipeState::Disconnected,
            server_handle: 0,
            client_handle: 0,
            server_buffer: VecDeque::new(),
            client_buffer: VecDeque::new(),
            read_mode: PipeReadMode::Byte,
            wait_mode: PipeWait::Wait,
            server_process: 0,
            client_process: 0,
            bytes_read: 0,
            bytes_written: 0,
            active: false,
        };

        Self {
            id: 0,
            name: [0; MAX_PIPE_NAME_LEN],
            name_len: 0,
            pipe_type: PipeType::Duplex,
            read_mode: PipeReadMode::Byte,
            max_instances: 1,
            current_instances: 0,
            out_buffer_size: DEFAULT_BUFFER_SIZE,
            in_buffer_size: DEFAULT_BUFFER_SIZE,
            default_timeout: 50000000, // 5 seconds in 100ns units
            creator_process: 0,
            create_time: 0,
            active: false,
            instances: [DEFAULT_INSTANCE; MAX_PIPE_INSTANCES],
        }
    }
}

// ============================================================================
// NPFS Errors
// ============================================================================

/// NPFS error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum NpfsError {
    /// Success
    Success = 0,
    /// Pipe not found
    PipeNotFound = -1,
    /// Pipe busy (all instances in use)
    PipeBusy = -2,
    /// Pipe disconnected
    PipeDisconnected = -3,
    /// Pipe closing
    PipeClosing = -4,
    /// Invalid parameter
    InvalidParameter = -5,
    /// No memory
    NoMemory = -6,
    /// Access denied
    AccessDenied = -7,
    /// Pipe exists
    PipeExists = -8,
    /// Too many instances
    TooManyInstances = -9,
    /// Too many pipes
    TooManyPipes = -10,
    /// Buffer too small
    BufferTooSmall = -11,
    /// Would block
    WouldBlock = -12,
    /// Broken pipe
    BrokenPipe = -13,
    /// Invalid state
    InvalidState = -14,
    /// Invalid handle
    InvalidHandle = -15,
    /// More data available
    MoreData = -16,
}

// ============================================================================
// NPFS Statistics
// ============================================================================

/// NPFS statistics
#[derive(Debug)]
pub struct NpfsStatistics {
    /// Pipes created
    pub pipes_created: AtomicU64,
    /// Pipes closed
    pub pipes_closed: AtomicU64,
    /// Active pipes
    pub active_pipes: AtomicU32,
    /// Active instances
    pub active_instances: AtomicU32,
    /// Total connections
    pub connections: AtomicU64,
    /// Total disconnections
    pub disconnections: AtomicU64,
    /// Bytes written (total)
    pub bytes_written: AtomicU64,
    /// Bytes read (total)
    pub bytes_read: AtomicU64,
}

impl Default for NpfsStatistics {
    fn default() -> Self {
        Self {
            pipes_created: AtomicU64::new(0),
            pipes_closed: AtomicU64::new(0),
            active_pipes: AtomicU32::new(0),
            active_instances: AtomicU32::new(0),
            connections: AtomicU64::new(0),
            disconnections: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// NPFS State
// ============================================================================

/// NPFS global state
pub struct NpfsState {
    /// Named pipes
    pub pipes: [NamedPipe; MAX_NAMED_PIPES],
    /// Next pipe ID
    pub next_pipe_id: u64,
    /// Next instance ID
    pub next_instance_id: u64,
    /// Next handle ID
    pub next_handle_id: u64,
    /// Statistics
    pub statistics: NpfsStatistics,
    /// Initialized
    pub initialized: bool,
}

impl NpfsState {
    const fn new() -> Self {
        const DEFAULT_PIPE: NamedPipe = NamedPipe::new();

        Self {
            pipes: [DEFAULT_PIPE; MAX_NAMED_PIPES],
            next_pipe_id: 1,
            next_instance_id: 1,
            next_handle_id: 1,
            statistics: NpfsStatistics {
                pipes_created: AtomicU64::new(0),
                pipes_closed: AtomicU64::new(0),
                active_pipes: AtomicU32::new(0),
                active_instances: AtomicU32::new(0),
                connections: AtomicU64::new(0),
                disconnections: AtomicU64::new(0),
                bytes_written: AtomicU64::new(0),
                bytes_read: AtomicU64::new(0),
            },
            initialized: false,
        }
    }
}

/// Global NPFS state
static NPFS_STATE: SpinLock<NpfsState> = SpinLock::new(NpfsState::new());

// ============================================================================
// Named Pipe Operations
// ============================================================================

/// Create a named pipe (server side)
pub fn np_create_named_pipe(
    name: &str,
    pipe_type: PipeType,
    read_mode: PipeReadMode,
    max_instances: u32,
    out_buffer_size: usize,
    in_buffer_size: usize,
    default_timeout: u64,
    process_id: u32,
) -> Result<(u64, u64), NpfsError> {
    let mut state = NPFS_STATE.lock();

    if !state.initialized {
        return Err(NpfsError::InvalidState);
    }

    let name_bytes = name.as_bytes();
    if name_bytes.len() > MAX_PIPE_NAME_LEN {
        return Err(NpfsError::InvalidParameter);
    }

    // Check if pipe already exists
    let mut existing_idx = None;
    for idx in 0..MAX_NAMED_PIPES {
        if state.pipes[idx].active && state.pipes[idx].name_len == name_bytes.len() {
            let mut matches = true;
            for i in 0..name_bytes.len() {
                if state.pipes[idx].name[i] != name_bytes[i] {
                    matches = false;
                    break;
                }
            }
            if matches {
                existing_idx = Some(idx);
                break;
            }
        }
    }

    let (pipe_idx, is_new) = if let Some(idx) = existing_idx {
        // Existing pipe, create new instance
        if state.pipes[idx].current_instances >= state.pipes[idx].max_instances {
            return Err(NpfsError::TooManyInstances);
        }
        (idx, false)
    } else {
        // New pipe, find free slot
        let mut slot_idx = None;
        for idx in 0..MAX_NAMED_PIPES {
            if !state.pipes[idx].active {
                slot_idx = Some(idx);
                break;
            }
        }

        let idx = slot_idx.ok_or(NpfsError::TooManyPipes)?;
        (idx, true)
    };

    let pipe_id;
    let instance_id;
    let server_handle;

    if is_new {
        // Create new pipe
        pipe_id = state.next_pipe_id;
        state.next_pipe_id += 1;

        state.pipes[pipe_idx] = NamedPipe::new();
        state.pipes[pipe_idx].id = pipe_id;
        state.pipes[pipe_idx].name[..name_bytes.len()].copy_from_slice(name_bytes);
        state.pipes[pipe_idx].name_len = name_bytes.len();
        state.pipes[pipe_idx].pipe_type = pipe_type;
        state.pipes[pipe_idx].read_mode = read_mode;
        state.pipes[pipe_idx].max_instances = if max_instances == 0 { 1 } else { max_instances };
        state.pipes[pipe_idx].out_buffer_size = core::cmp::min(out_buffer_size, MAX_BUFFER_SIZE);
        state.pipes[pipe_idx].in_buffer_size = core::cmp::min(in_buffer_size, MAX_BUFFER_SIZE);
        state.pipes[pipe_idx].default_timeout = default_timeout;
        state.pipes[pipe_idx].creator_process = process_id;
        state.pipes[pipe_idx].active = true;

        state.statistics.pipes_created.fetch_add(1, Ordering::Relaxed);
        state.statistics.active_pipes.fetch_add(1, Ordering::Relaxed);
    } else {
        pipe_id = state.pipes[pipe_idx].id;
    }

    // Find free instance slot
    let mut instance_idx = None;
    for i in 0..MAX_PIPE_INSTANCES {
        if !state.pipes[pipe_idx].instances[i].active {
            instance_idx = Some(i);
            break;
        }
    }

    let inst_idx = instance_idx.ok_or(NpfsError::TooManyInstances)?;

    instance_id = state.next_instance_id;
    state.next_instance_id += 1;

    server_handle = state.next_handle_id;
    state.next_handle_id += 1;

    let out_size = state.pipes[pipe_idx].out_buffer_size;
    let in_size = state.pipes[pipe_idx].in_buffer_size;

    state.pipes[pipe_idx].instances[inst_idx] = PipeInstance {
        id: instance_id,
        pipe_id,
        instance_num: inst_idx as u32,
        state: PipeState::Disconnected,
        server_handle,
        client_handle: 0,
        server_buffer: VecDeque::with_capacity(out_size),
        client_buffer: VecDeque::with_capacity(in_size),
        read_mode,
        wait_mode: PipeWait::Wait,
        server_process: process_id,
        client_process: 0,
        bytes_read: 0,
        bytes_written: 0,
        active: true,
    };

    state.pipes[pipe_idx].current_instances += 1;
    state.statistics.active_instances.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[NPFS] Created pipe '{}' instance {} (handle={})",
        name, inst_idx, server_handle);

    Ok((pipe_id, server_handle))
}

/// Wait for a client to connect to a pipe instance (server side)
pub fn np_connect_named_pipe(server_handle: u64, wait: bool) -> Result<(), NpfsError> {
    let mut state = NPFS_STATE.lock();

    // Find the instance by server handle
    for pipe_idx in 0..MAX_NAMED_PIPES {
        if !state.pipes[pipe_idx].active {
            continue;
        }

        for inst_idx in 0..MAX_PIPE_INSTANCES {
            if state.pipes[pipe_idx].instances[inst_idx].active &&
               state.pipes[pipe_idx].instances[inst_idx].server_handle == server_handle {

                match state.pipes[pipe_idx].instances[inst_idx].state {
                    PipeState::Disconnected => {
                        state.pipes[pipe_idx].instances[inst_idx].state = PipeState::Listening;
                        if !wait {
                            return Err(NpfsError::WouldBlock);
                        }
                        // In a real implementation, we would block here
                        return Ok(());
                    }
                    PipeState::Connected => {
                        return Ok(()); // Already connected
                    }
                    _ => {
                        return Err(NpfsError::InvalidState);
                    }
                }
            }
        }
    }

    Err(NpfsError::InvalidHandle)
}

/// Disconnect a client from a pipe instance (server side)
pub fn np_disconnect_named_pipe(server_handle: u64) -> Result<(), NpfsError> {
    let mut state = NPFS_STATE.lock();

    for pipe_idx in 0..MAX_NAMED_PIPES {
        if !state.pipes[pipe_idx].active {
            continue;
        }

        for inst_idx in 0..MAX_PIPE_INSTANCES {
            if state.pipes[pipe_idx].instances[inst_idx].active &&
               state.pipes[pipe_idx].instances[inst_idx].server_handle == server_handle {

                if state.pipes[pipe_idx].instances[inst_idx].state != PipeState::Connected {
                    return Err(NpfsError::PipeDisconnected);
                }

                state.pipes[pipe_idx].instances[inst_idx].state = PipeState::Disconnected;
                state.pipes[pipe_idx].instances[inst_idx].client_handle = 0;
                state.pipes[pipe_idx].instances[inst_idx].client_process = 0;
                state.pipes[pipe_idx].instances[inst_idx].server_buffer.clear();
                state.pipes[pipe_idx].instances[inst_idx].client_buffer.clear();

                state.statistics.disconnections.fetch_add(1, Ordering::Relaxed);

                crate::serial_println!("[NPFS] Disconnected pipe instance");
                return Ok(());
            }
        }
    }

    Err(NpfsError::InvalidHandle)
}

/// Open a named pipe (client side)
pub fn np_open_named_pipe(
    name: &str,
    process_id: u32,
) -> Result<u64, NpfsError> {
    let mut state = NPFS_STATE.lock();

    if !state.initialized {
        return Err(NpfsError::InvalidState);
    }

    let name_bytes = name.as_bytes();

    // Find the pipe
    for pipe_idx in 0..MAX_NAMED_PIPES {
        if !state.pipes[pipe_idx].active {
            continue;
        }

        if state.pipes[pipe_idx].name_len != name_bytes.len() {
            continue;
        }

        let mut matches = true;
        for i in 0..name_bytes.len() {
            if state.pipes[pipe_idx].name[i] != name_bytes[i] {
                matches = false;
                break;
            }
        }

        if matches {
            // Found the pipe, find a listening instance
            for inst_idx in 0..MAX_PIPE_INSTANCES {
                if state.pipes[pipe_idx].instances[inst_idx].active &&
                   state.pipes[pipe_idx].instances[inst_idx].state == PipeState::Listening {

                    let client_handle = state.next_handle_id;
                    state.next_handle_id += 1;

                    state.pipes[pipe_idx].instances[inst_idx].state = PipeState::Connected;
                    state.pipes[pipe_idx].instances[inst_idx].client_handle = client_handle;
                    state.pipes[pipe_idx].instances[inst_idx].client_process = process_id;

                    state.statistics.connections.fetch_add(1, Ordering::Relaxed);

                    crate::serial_println!("[NPFS] Client connected to pipe '{}' (handle={})",
                        name, client_handle);

                    return Ok(client_handle);
                }
            }

            // No listening instance, pipe is busy
            return Err(NpfsError::PipeBusy);
        }
    }

    Err(NpfsError::PipeNotFound)
}

/// Write to a pipe
pub fn np_write_pipe(handle: u64, data: &[u8]) -> Result<usize, NpfsError> {
    let mut state = NPFS_STATE.lock();

    for pipe_idx in 0..MAX_NAMED_PIPES {
        if !state.pipes[pipe_idx].active {
            continue;
        }

        for inst_idx in 0..MAX_PIPE_INSTANCES {
            if !state.pipes[pipe_idx].instances[inst_idx].active {
                continue;
            }

            let is_server = state.pipes[pipe_idx].instances[inst_idx].server_handle == handle;
            let is_client = state.pipes[pipe_idx].instances[inst_idx].client_handle == handle;

            if !is_server && !is_client {
                continue;
            }

            if state.pipes[pipe_idx].instances[inst_idx].state != PipeState::Connected {
                return Err(NpfsError::PipeDisconnected);
            }

            // Get buffer size first (before mutable borrow)
            let max_size = if is_server {
                state.pipes[pipe_idx].out_buffer_size
            } else {
                state.pipes[pipe_idx].in_buffer_size
            };

            let wait_mode = state.pipes[pipe_idx].instances[inst_idx].wait_mode;

            // Now get the buffer mutably
            let buffer = if is_server {
                &mut state.pipes[pipe_idx].instances[inst_idx].server_buffer
            } else {
                &mut state.pipes[pipe_idx].instances[inst_idx].client_buffer
            };

            let available = max_size.saturating_sub(buffer.len());
            if available == 0 {
                if wait_mode == PipeWait::NoWait {
                    return Err(NpfsError::WouldBlock);
                }
                // Would block in real implementation
            }

            let write_len = core::cmp::min(data.len(), available);

            for byte in &data[..write_len] {
                buffer.push_back(*byte);
            }

            state.pipes[pipe_idx].instances[inst_idx].bytes_written += write_len as u64;
            state.statistics.bytes_written.fetch_add(write_len as u64, Ordering::Relaxed);

            return Ok(write_len);
        }
    }

    Err(NpfsError::InvalidHandle)
}

/// Read from a pipe
pub fn np_read_pipe(handle: u64, buffer: &mut [u8]) -> Result<usize, NpfsError> {
    let mut state = NPFS_STATE.lock();

    for pipe_idx in 0..MAX_NAMED_PIPES {
        if !state.pipes[pipe_idx].active {
            continue;
        }

        for inst_idx in 0..MAX_PIPE_INSTANCES {
            let inst = &mut state.pipes[pipe_idx].instances[inst_idx];
            if !inst.active {
                continue;
            }

            let is_server = inst.server_handle == handle;
            let is_client = inst.client_handle == handle;

            if !is_server && !is_client {
                continue;
            }

            if inst.state != PipeState::Connected {
                if inst.state == PipeState::Closing || inst.state == PipeState::Closed {
                    return Err(NpfsError::BrokenPipe);
                }
                return Err(NpfsError::PipeDisconnected);
            }

            // Determine which buffer to read from (opposite of write)
            let pipe_buffer = if is_server {
                &mut inst.client_buffer // Server reads from client buffer
            } else {
                &mut inst.server_buffer // Client reads from server buffer
            };

            if pipe_buffer.is_empty() {
                if inst.wait_mode == PipeWait::NoWait {
                    return Err(NpfsError::WouldBlock);
                }
                // Would block in real implementation
                return Ok(0);
            }

            let read_len = core::cmp::min(buffer.len(), pipe_buffer.len());

            for i in 0..read_len {
                if let Some(byte) = pipe_buffer.pop_front() {
                    buffer[i] = byte;
                }
            }

            inst.bytes_read += read_len as u64;
            state.statistics.bytes_read.fetch_add(read_len as u64, Ordering::Relaxed);

            return Ok(read_len);
        }
    }

    Err(NpfsError::InvalidHandle)
}

/// Peek at pipe data without removing it
pub fn np_peek_named_pipe(
    handle: u64,
    buffer: Option<&mut [u8]>,
) -> Result<(usize, usize, usize), NpfsError> {
    let state = NPFS_STATE.lock();

    for pipe_idx in 0..MAX_NAMED_PIPES {
        if !state.pipes[pipe_idx].active {
            continue;
        }

        for inst_idx in 0..MAX_PIPE_INSTANCES {
            let inst = &state.pipes[pipe_idx].instances[inst_idx];
            if !inst.active {
                continue;
            }

            let is_server = inst.server_handle == handle;
            let is_client = inst.client_handle == handle;

            if !is_server && !is_client {
                continue;
            }

            let pipe_buffer = if is_server {
                &inst.client_buffer
            } else {
                &inst.server_buffer
            };

            let bytes_available = pipe_buffer.len();
            let mut bytes_read = 0;

            if let Some(buf) = buffer {
                let read_len = core::cmp::min(buf.len(), bytes_available);
                for i in 0..read_len {
                    if let Some(&byte) = pipe_buffer.get(i) {
                        buf[i] = byte;
                    }
                }
                bytes_read = read_len;
            }

            // In message mode, return message count
            let messages_available = if bytes_available > 0 { 1 } else { 0 };

            return Ok((bytes_read, bytes_available, messages_available));
        }
    }

    Err(NpfsError::InvalidHandle)
}

/// Close a pipe handle
pub fn np_close_handle(handle: u64) -> Result<(), NpfsError> {
    let mut state = NPFS_STATE.lock();

    for pipe_idx in 0..MAX_NAMED_PIPES {
        if !state.pipes[pipe_idx].active {
            continue;
        }

        for inst_idx in 0..MAX_PIPE_INSTANCES {
            let inst = &mut state.pipes[pipe_idx].instances[inst_idx];
            if !inst.active {
                continue;
            }

            let is_server = inst.server_handle == handle;
            let is_client = inst.client_handle == handle;

            if is_server {
                // Close server handle - close the instance
                inst.state = PipeState::Closed;
                inst.active = false;

                state.pipes[pipe_idx].current_instances -= 1;
                state.statistics.active_instances.fetch_sub(1, Ordering::Relaxed);

                // If no more instances, close the pipe
                if state.pipes[pipe_idx].current_instances == 0 {
                    state.pipes[pipe_idx].active = false;
                    state.statistics.active_pipes.fetch_sub(1, Ordering::Relaxed);
                    state.statistics.pipes_closed.fetch_add(1, Ordering::Relaxed);
                }

                crate::serial_println!("[NPFS] Closed server handle {}", handle);
                return Ok(());
            } else if is_client {
                // Close client handle - disconnect
                inst.client_handle = 0;
                inst.client_process = 0;
                if inst.state == PipeState::Connected {
                    inst.state = PipeState::Disconnected;
                    state.statistics.disconnections.fetch_add(1, Ordering::Relaxed);
                }

                crate::serial_println!("[NPFS] Closed client handle {}", handle);
                return Ok(());
            }
        }
    }

    Err(NpfsError::InvalidHandle)
}

/// Get pipe information
pub fn np_get_pipe_info(handle: u64) -> Result<PipeInfo, NpfsError> {
    let state = NPFS_STATE.lock();

    for pipe_idx in 0..MAX_NAMED_PIPES {
        if !state.pipes[pipe_idx].active {
            continue;
        }

        for inst_idx in 0..MAX_PIPE_INSTANCES {
            let inst = &state.pipes[pipe_idx].instances[inst_idx];
            if !inst.active {
                continue;
            }

            if inst.server_handle == handle || inst.client_handle == handle {
                let pipe = &state.pipes[pipe_idx];

                return Ok(PipeInfo {
                    pipe_type: pipe.pipe_type,
                    read_mode: inst.read_mode,
                    max_instances: pipe.max_instances,
                    current_instances: pipe.current_instances,
                    out_buffer_size: pipe.out_buffer_size,
                    in_buffer_size: pipe.in_buffer_size,
                    state: inst.state,
                });
            }
        }
    }

    Err(NpfsError::InvalidHandle)
}

/// Pipe information
#[derive(Debug, Clone, Copy)]
pub struct PipeInfo {
    /// Pipe type
    pub pipe_type: PipeType,
    /// Read mode
    pub read_mode: PipeReadMode,
    /// Maximum instances
    pub max_instances: u32,
    /// Current instances
    pub current_instances: u32,
    /// Outbound buffer size
    pub out_buffer_size: usize,
    /// Inbound buffer size
    pub in_buffer_size: usize,
    /// Current state
    pub state: PipeState,
}

/// Set pipe state/mode
pub fn np_set_pipe_state(
    handle: u64,
    read_mode: Option<PipeReadMode>,
    wait_mode: Option<PipeWait>,
) -> Result<(), NpfsError> {
    let mut state = NPFS_STATE.lock();

    for pipe_idx in 0..MAX_NAMED_PIPES {
        if !state.pipes[pipe_idx].active {
            continue;
        }

        for inst_idx in 0..MAX_PIPE_INSTANCES {
            let inst = &mut state.pipes[pipe_idx].instances[inst_idx];
            if !inst.active {
                continue;
            }

            if inst.server_handle == handle || inst.client_handle == handle {
                if let Some(mode) = read_mode {
                    inst.read_mode = mode;
                }
                if let Some(wait) = wait_mode {
                    inst.wait_mode = wait;
                }
                return Ok(());
            }
        }
    }

    Err(NpfsError::InvalidHandle)
}

/// Get NPFS statistics
pub fn np_get_statistics() -> NpfsStatistics {
    let state = NPFS_STATE.lock();

    NpfsStatistics {
        pipes_created: AtomicU64::new(state.statistics.pipes_created.load(Ordering::Relaxed)),
        pipes_closed: AtomicU64::new(state.statistics.pipes_closed.load(Ordering::Relaxed)),
        active_pipes: AtomicU32::new(state.statistics.active_pipes.load(Ordering::Relaxed)),
        active_instances: AtomicU32::new(state.statistics.active_instances.load(Ordering::Relaxed)),
        connections: AtomicU64::new(state.statistics.connections.load(Ordering::Relaxed)),
        disconnections: AtomicU64::new(state.statistics.disconnections.load(Ordering::Relaxed)),
        bytes_written: AtomicU64::new(state.statistics.bytes_written.load(Ordering::Relaxed)),
        bytes_read: AtomicU64::new(state.statistics.bytes_read.load(Ordering::Relaxed)),
    }
}

/// List all named pipes
pub fn np_list_pipes() -> Vec<String> {
    let state = NPFS_STATE.lock();
    let mut result = Vec::new();

    for pipe_idx in 0..MAX_NAMED_PIPES {
        if state.pipes[pipe_idx].active {
            if let Ok(name) = core::str::from_utf8(&state.pipes[pipe_idx].name[..state.pipes[pipe_idx].name_len]) {
                result.push(String::from(name));
            }
        }
    }

    result
}

// ============================================================================
// Transact and Call operations
// ============================================================================

/// Transact on a named pipe (write then read in one operation)
pub fn np_transact_named_pipe(
    handle: u64,
    write_data: &[u8],
    read_buffer: &mut [u8],
) -> Result<usize, NpfsError> {
    // Write first
    np_write_pipe(handle, write_data)?;

    // Then read
    np_read_pipe(handle, read_buffer)
}

/// Call a named pipe (connect, transact, close)
pub fn np_call_named_pipe(
    name: &str,
    write_data: &[u8],
    read_buffer: &mut [u8],
    process_id: u32,
) -> Result<usize, NpfsError> {
    // Open the pipe
    let handle = np_open_named_pipe(name, process_id)?;

    // Transact
    let result = np_transact_named_pipe(handle, write_data, read_buffer);

    // Close
    let _ = np_close_handle(handle);

    result
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize NPFS
pub fn init() {
    crate::serial_println!("[NPFS] Initializing Named Pipe File System...");

    {
        let mut state = NPFS_STATE.lock();
        state.initialized = true;
    }

    crate::serial_println!("[NPFS] NPFS initialized");
}
