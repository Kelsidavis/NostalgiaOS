//! MSFS (Mailslot File System)
//!
//! Mailslots provide a simple one-way IPC mechanism in Windows.
//! Unlike named pipes, mailslots are:
//! - Unidirectional (server reads, clients write)
//! - Support broadcast to multiple recipients
//! - Support datagrams (message-based)
//! - Connectionless
//!
//! Mailslots are accessed via \Device\Mailslot\<mailslotname>

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// Maximum number of mailslots
const MAX_MAILSLOTS: usize = 256;

/// Maximum message size
const MAX_MESSAGE_SIZE: usize = 424;

/// Default message buffer count
const DEFAULT_MESSAGE_COUNT: usize = 16;

/// Maximum mailslot name length
const MAX_MAILSLOT_NAME_LEN: usize = 256;

// ============================================================================
// Mailslot Message
// ============================================================================

/// A single mailslot message
#[derive(Clone)]
pub struct MailslotMessage {
    /// Message data
    pub data: Vec<u8>,
    /// Sender process ID
    pub sender_process: u32,
    /// Timestamp (system ticks)
    pub timestamp: u64,
}

impl Default for MailslotMessage {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            sender_process: 0,
            timestamp: 0,
        }
    }
}

// ============================================================================
// Mailslot
// ============================================================================

/// A mailslot definition
pub struct Mailslot {
    /// Mailslot ID
    pub id: u64,
    /// Mailslot name (without \Device\Mailslot prefix)
    pub name: [u8; MAX_MAILSLOT_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Maximum message size
    pub max_message_size: usize,
    /// Read timeout (milliseconds, 0 = no wait, MAILSLOT_WAIT_FOREVER = block)
    pub read_timeout: u32,
    /// Message queue
    pub messages: VecDeque<MailslotMessage>,
    /// Maximum number of messages to buffer
    pub max_messages: usize,
    /// Server handle
    pub server_handle: u64,
    /// Creator process ID
    pub creator_process: u32,
    /// Creation time
    pub create_time: u64,
    /// Total messages received
    pub messages_received: u64,
    /// Total messages read
    pub messages_read: u64,
    /// Active flag
    pub active: bool,
}

impl Mailslot {
    const fn new() -> Self {
        Self {
            id: 0,
            name: [0; MAX_MAILSLOT_NAME_LEN],
            name_len: 0,
            max_message_size: MAX_MESSAGE_SIZE,
            read_timeout: 0,
            messages: VecDeque::new(),
            max_messages: DEFAULT_MESSAGE_COUNT,
            server_handle: 0,
            creator_process: 0,
            create_time: 0,
            messages_received: 0,
            messages_read: 0,
            active: false,
        }
    }
}

// ============================================================================
// MSFS Errors
// ============================================================================

/// MSFS error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum MsfsError {
    /// Success
    Success = 0,
    /// Mailslot not found
    MailslotNotFound = -1,
    /// Invalid parameter
    InvalidParameter = -2,
    /// No memory
    NoMemory = -3,
    /// Access denied
    AccessDenied = -4,
    /// Mailslot exists
    MailslotExists = -5,
    /// Too many mailslots
    TooManyMailslots = -6,
    /// Message too large
    MessageTooLarge = -7,
    /// Mailslot full (buffer full)
    MailslotFull = -8,
    /// No messages available
    NoMessages = -9,
    /// Invalid handle
    InvalidHandle = -10,
    /// Would block
    WouldBlock = -11,
    /// Timed out
    TimedOut = -12,
    /// Not initialized
    NotInitialized = -13,
}

/// Wait forever constant
pub const MAILSLOT_WAIT_FOREVER: u32 = 0xFFFFFFFF;

// ============================================================================
// MSFS Statistics
// ============================================================================

/// MSFS statistics
#[derive(Debug)]
pub struct MsfsStatistics {
    /// Mailslots created
    pub mailslots_created: AtomicU64,
    /// Mailslots closed
    pub mailslots_closed: AtomicU64,
    /// Active mailslots
    pub active_mailslots: AtomicU32,
    /// Messages sent (total)
    pub messages_sent: AtomicU64,
    /// Messages received (total)
    pub messages_received: AtomicU64,
    /// Bytes sent
    pub bytes_sent: AtomicU64,
    /// Bytes received
    pub bytes_received: AtomicU64,
}

impl Default for MsfsStatistics {
    fn default() -> Self {
        Self {
            mailslots_created: AtomicU64::new(0),
            mailslots_closed: AtomicU64::new(0),
            active_mailslots: AtomicU32::new(0),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// MSFS State
// ============================================================================

/// MSFS global state
pub struct MsfsState {
    /// Mailslots
    pub mailslots: [Mailslot; MAX_MAILSLOTS],
    /// Next mailslot ID
    pub next_mailslot_id: u64,
    /// Next handle ID
    pub next_handle_id: u64,
    /// Statistics
    pub statistics: MsfsStatistics,
    /// Initialized
    pub initialized: bool,
}

impl MsfsState {
    const fn new() -> Self {
        const DEFAULT_MAILSLOT: Mailslot = Mailslot::new();

        Self {
            mailslots: [DEFAULT_MAILSLOT; MAX_MAILSLOTS],
            next_mailslot_id: 1,
            next_handle_id: 1,
            statistics: MsfsStatistics {
                mailslots_created: AtomicU64::new(0),
                mailslots_closed: AtomicU64::new(0),
                active_mailslots: AtomicU32::new(0),
                messages_sent: AtomicU64::new(0),
                messages_received: AtomicU64::new(0),
                bytes_sent: AtomicU64::new(0),
                bytes_received: AtomicU64::new(0),
            },
            initialized: false,
        }
    }
}

/// Global MSFS state
static MSFS_STATE: SpinLock<MsfsState> = SpinLock::new(MsfsState::new());

// ============================================================================
// Mailslot Operations
// ============================================================================

/// Create a mailslot (server side)
pub fn ms_create_mailslot(
    name: &str,
    max_message_size: usize,
    read_timeout: u32,
    process_id: u32,
) -> Result<u64, MsfsError> {
    let mut state = MSFS_STATE.lock();

    if !state.initialized {
        return Err(MsfsError::NotInitialized);
    }

    let name_bytes = name.as_bytes();
    if name_bytes.len() > MAX_MAILSLOT_NAME_LEN {
        return Err(MsfsError::InvalidParameter);
    }

    // Check if mailslot already exists
    for idx in 0..MAX_MAILSLOTS {
        if state.mailslots[idx].active && state.mailslots[idx].name_len == name_bytes.len() {
            let mut matches = true;
            for i in 0..name_bytes.len() {
                if state.mailslots[idx].name[i] != name_bytes[i] {
                    matches = false;
                    break;
                }
            }
            if matches {
                return Err(MsfsError::MailslotExists);
            }
        }
    }

    // Find free slot
    let mut slot_idx = None;
    for idx in 0..MAX_MAILSLOTS {
        if !state.mailslots[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(MsfsError::TooManyMailslots)?;

    let mailslot_id = state.next_mailslot_id;
    state.next_mailslot_id += 1;

    let server_handle = state.next_handle_id;
    state.next_handle_id += 1;

    let actual_max_size = if max_message_size == 0 {
        MAX_MESSAGE_SIZE
    } else {
        core::cmp::min(max_message_size, MAX_MESSAGE_SIZE)
    };

    state.mailslots[idx] = Mailslot {
        id: mailslot_id,
        name: [0; MAX_MAILSLOT_NAME_LEN],
        name_len: name_bytes.len(),
        max_message_size: actual_max_size,
        read_timeout,
        messages: VecDeque::with_capacity(DEFAULT_MESSAGE_COUNT),
        max_messages: DEFAULT_MESSAGE_COUNT,
        server_handle,
        creator_process: process_id,
        create_time: 0, // TODO: system time
        messages_received: 0,
        messages_read: 0,
        active: true,
    };

    state.mailslots[idx].name[..name_bytes.len()].copy_from_slice(name_bytes);

    state.statistics.mailslots_created.fetch_add(1, Ordering::Relaxed);
    state.statistics.active_mailslots.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[MSFS] Created mailslot '{}' (handle={})", name, server_handle);

    Ok(server_handle)
}

/// Open a mailslot for writing (client side)
pub fn ms_open_mailslot(
    name: &str,
    _process_id: u32,
) -> Result<u64, MsfsError> {
    let mut state = MSFS_STATE.lock();

    if !state.initialized {
        return Err(MsfsError::NotInitialized);
    }

    let name_bytes = name.as_bytes();

    // Find the mailslot
    for idx in 0..MAX_MAILSLOTS {
        if !state.mailslots[idx].active {
            continue;
        }

        if state.mailslots[idx].name_len != name_bytes.len() {
            continue;
        }

        let mut matches = true;
        for i in 0..name_bytes.len() {
            if state.mailslots[idx].name[i] != name_bytes[i] {
                matches = false;
                break;
            }
        }

        if matches {
            // Found the mailslot, create a client handle
            let client_handle = state.next_handle_id;
            state.next_handle_id += 1;

            crate::serial_println!("[MSFS] Opened mailslot '{}' for writing (handle={})",
                name, client_handle);

            // Note: We encode the mailslot index in the handle for lookup
            // In a real implementation, we'd have a handle table
            return Ok(client_handle | ((idx as u64) << 32));
        }
    }

    Err(MsfsError::MailslotNotFound)
}

/// Write a message to a mailslot (client side)
pub fn ms_write_mailslot(
    handle: u64,
    data: &[u8],
    process_id: u32,
) -> Result<usize, MsfsError> {
    let mut state = MSFS_STATE.lock();

    if !state.initialized {
        return Err(MsfsError::NotInitialized);
    }

    // Extract mailslot index from handle (if encoded)
    let idx = ((handle >> 32) & 0xFFFFFFFF) as usize;

    if idx >= MAX_MAILSLOTS || !state.mailslots[idx].active {
        // Search by handle if not encoded
        let mut found_idx = None;
        for i in 0..MAX_MAILSLOTS {
            if state.mailslots[i].active && state.mailslots[i].server_handle == handle {
                found_idx = Some(i);
                break;
            }
        }

        if found_idx.is_none() {
            return Err(MsfsError::InvalidHandle);
        }
    }

    let mailslot_idx = if idx < MAX_MAILSLOTS && state.mailslots[idx].active {
        idx
    } else {
        // Find by server handle
        let mut found = None;
        for i in 0..MAX_MAILSLOTS {
            if state.mailslots[i].active && state.mailslots[i].server_handle == handle {
                found = Some(i);
                break;
            }
        }
        found.ok_or(MsfsError::InvalidHandle)?
    };

    // Check message size
    if data.len() > state.mailslots[mailslot_idx].max_message_size {
        return Err(MsfsError::MessageTooLarge);
    }

    // Check if mailslot is full
    if state.mailslots[mailslot_idx].messages.len() >= state.mailslots[mailslot_idx].max_messages {
        return Err(MsfsError::MailslotFull);
    }

    // Create message
    let message = MailslotMessage {
        data: data.to_vec(),
        sender_process: process_id,
        timestamp: 0, // TODO: system ticks
    };

    let data_len = data.len();
    state.mailslots[mailslot_idx].messages.push_back(message);
    state.mailslots[mailslot_idx].messages_received += 1;

    state.statistics.messages_sent.fetch_add(1, Ordering::Relaxed);
    state.statistics.bytes_sent.fetch_add(data_len as u64, Ordering::Relaxed);

    Ok(data_len)
}

/// Read a message from a mailslot (server side)
pub fn ms_read_mailslot(
    handle: u64,
    buffer: &mut [u8],
) -> Result<usize, MsfsError> {
    let mut state = MSFS_STATE.lock();

    if !state.initialized {
        return Err(MsfsError::NotInitialized);
    }

    // Find mailslot by server handle
    for idx in 0..MAX_MAILSLOTS {
        if !state.mailslots[idx].active {
            continue;
        }

        if state.mailslots[idx].server_handle != handle {
            continue;
        }

        // Found the mailslot
        if state.mailslots[idx].messages.is_empty() {
            if state.mailslots[idx].read_timeout == 0 {
                return Err(MsfsError::WouldBlock);
            }
            // In real implementation, would wait for timeout
            return Err(MsfsError::NoMessages);
        }

        // Get next message
        if let Some(message) = state.mailslots[idx].messages.pop_front() {
            let copy_len = core::cmp::min(buffer.len(), message.data.len());
            buffer[..copy_len].copy_from_slice(&message.data[..copy_len]);

            state.mailslots[idx].messages_read += 1;

            state.statistics.messages_received.fetch_add(1, Ordering::Relaxed);
            state.statistics.bytes_received.fetch_add(copy_len as u64, Ordering::Relaxed);

            return Ok(copy_len);
        }

        return Err(MsfsError::NoMessages);
    }

    Err(MsfsError::InvalidHandle)
}

/// Get mailslot information
pub fn ms_get_mailslot_info(handle: u64) -> Result<MailslotInfo, MsfsError> {
    let state = MSFS_STATE.lock();

    if !state.initialized {
        return Err(MsfsError::NotInitialized);
    }

    // Find mailslot by server handle
    for idx in 0..MAX_MAILSLOTS {
        if !state.mailslots[idx].active {
            continue;
        }

        if state.mailslots[idx].server_handle != handle {
            continue;
        }

        return Ok(MailslotInfo {
            max_message_size: state.mailslots[idx].max_message_size,
            next_size: state.mailslots[idx].messages.front()
                .map(|m| m.data.len())
                .unwrap_or(0),
            message_count: state.mailslots[idx].messages.len(),
            read_timeout: state.mailslots[idx].read_timeout,
        });
    }

    Err(MsfsError::InvalidHandle)
}

/// Mailslot information
#[derive(Debug, Clone, Copy)]
pub struct MailslotInfo {
    /// Maximum message size
    pub max_message_size: usize,
    /// Size of next message (0 if none)
    pub next_size: usize,
    /// Number of messages waiting
    pub message_count: usize,
    /// Read timeout
    pub read_timeout: u32,
}

/// Set mailslot read timeout
pub fn ms_set_timeout(handle: u64, timeout: u32) -> Result<(), MsfsError> {
    let mut state = MSFS_STATE.lock();

    if !state.initialized {
        return Err(MsfsError::NotInitialized);
    }

    for idx in 0..MAX_MAILSLOTS {
        if !state.mailslots[idx].active {
            continue;
        }

        if state.mailslots[idx].server_handle == handle {
            state.mailslots[idx].read_timeout = timeout;
            return Ok(());
        }
    }

    Err(MsfsError::InvalidHandle)
}

/// Close a mailslot handle
pub fn ms_close_handle(handle: u64) -> Result<(), MsfsError> {
    let mut state = MSFS_STATE.lock();

    if !state.initialized {
        return Err(MsfsError::NotInitialized);
    }

    // Check if this is a server handle
    for idx in 0..MAX_MAILSLOTS {
        if !state.mailslots[idx].active {
            continue;
        }

        if state.mailslots[idx].server_handle == handle {
            // Close the mailslot
            state.mailslots[idx].active = false;
            state.statistics.mailslots_closed.fetch_add(1, Ordering::Relaxed);
            state.statistics.active_mailslots.fetch_sub(1, Ordering::Relaxed);

            crate::serial_println!("[MSFS] Closed mailslot (handle={})", handle);
            return Ok(());
        }
    }

    // Client handles don't require cleanup in this implementation
    Ok(())
}

/// Broadcast message to all mailslots with matching name pattern
pub fn ms_broadcast(
    name_pattern: &str,
    data: &[u8],
    process_id: u32,
) -> Result<usize, MsfsError> {
    let mut state = MSFS_STATE.lock();

    if !state.initialized {
        return Err(MsfsError::NotInitialized);
    }

    let pattern_bytes = name_pattern.as_bytes();
    let mut count = 0;

    for idx in 0..MAX_MAILSLOTS {
        if !state.mailslots[idx].active {
            continue;
        }

        // Simple wildcard match (just "*" means all)
        let matches = if pattern_bytes == b"*" {
            true
        } else {
            // Exact match
            if state.mailslots[idx].name_len != pattern_bytes.len() {
                continue;
            }
            let mut m = true;
            for i in 0..pattern_bytes.len() {
                if state.mailslots[idx].name[i] != pattern_bytes[i] {
                    m = false;
                    break;
                }
            }
            m
        };

        if matches {
            // Check message size
            if data.len() > state.mailslots[idx].max_message_size {
                continue;
            }

            // Check if mailslot has room
            if state.mailslots[idx].messages.len() >= state.mailslots[idx].max_messages {
                continue;
            }

            let message = MailslotMessage {
                data: data.to_vec(),
                sender_process: process_id,
                timestamp: 0,
            };

            state.mailslots[idx].messages.push_back(message);
            state.mailslots[idx].messages_received += 1;
            count += 1;
        }
    }

    if count > 0 {
        state.statistics.messages_sent.fetch_add(count, Ordering::Relaxed);
        state.statistics.bytes_sent.fetch_add((data.len() * count as usize) as u64, Ordering::Relaxed);
    }

    Ok(count as usize)
}

/// Get MSFS statistics
pub fn ms_get_statistics() -> MsfsStatistics {
    let state = MSFS_STATE.lock();

    MsfsStatistics {
        mailslots_created: AtomicU64::new(state.statistics.mailslots_created.load(Ordering::Relaxed)),
        mailslots_closed: AtomicU64::new(state.statistics.mailslots_closed.load(Ordering::Relaxed)),
        active_mailslots: AtomicU32::new(state.statistics.active_mailslots.load(Ordering::Relaxed)),
        messages_sent: AtomicU64::new(state.statistics.messages_sent.load(Ordering::Relaxed)),
        messages_received: AtomicU64::new(state.statistics.messages_received.load(Ordering::Relaxed)),
        bytes_sent: AtomicU64::new(state.statistics.bytes_sent.load(Ordering::Relaxed)),
        bytes_received: AtomicU64::new(state.statistics.bytes_received.load(Ordering::Relaxed)),
    }
}

/// List all mailslots
pub fn ms_list_mailslots() -> Vec<String> {
    let state = MSFS_STATE.lock();
    let mut result = Vec::new();

    for idx in 0..MAX_MAILSLOTS {
        if state.mailslots[idx].active {
            if let Ok(name) = core::str::from_utf8(&state.mailslots[idx].name[..state.mailslots[idx].name_len]) {
                result.push(String::from(name));
            }
        }
    }

    result
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize MSFS
pub fn init() {
    crate::serial_println!("[MSFS] Initializing Mailslot File System...");

    {
        let mut state = MSFS_STATE.lock();
        state.initialized = true;
    }

    crate::serial_println!("[MSFS] MSFS initialized");
}
