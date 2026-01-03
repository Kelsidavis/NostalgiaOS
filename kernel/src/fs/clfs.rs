//! CLFS - Common Log File System
//!
//! CLFS provides a high-performance, general-purpose log file subsystem
//! used by transactional components in Windows. It provides:
//!
//! - Reliable, ordered log records
//! - Log sequence numbers (LSNs) for ordering
//! - Multiple log streams (containers)
//! - Automatic log space management
//! - Crash recovery support
//!
//! Key concepts:
//! - Log: A collection of containers with ordered records
//! - Container: Physical storage units for log data
//! - Stream: Logical view of records within a log
//! - LSN: Log Sequence Number for record identification
//! - Marshalling area: Buffer for log record I/O

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// Maximum number of logs
const MAX_LOGS: usize = 64;

/// Maximum containers per log
const MAX_CONTAINERS: usize = 32;

/// Maximum streams per log
const MAX_STREAMS: usize = 8;

/// Default container size (1 MB)
const DEFAULT_CONTAINER_SIZE: u64 = 1024 * 1024;

/// Maximum record size
const MAX_RECORD_SIZE: usize = 64 * 1024;

/// Default marshalling area size
const DEFAULT_MARSHAL_SIZE: usize = 64 * 1024;

/// Maximum log name length
const MAX_LOG_NAME: usize = 256;

// ============================================================================
// Log Sequence Number (LSN)
// ============================================================================

/// Log Sequence Number - uniquely identifies a log record
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct Lsn {
    /// Container index
    pub container: u32,
    /// Block offset within container
    pub block_offset: u32,
    /// Record offset within block
    pub record_offset: u32,
    /// Sequence number for ordering
    pub sequence: u32,
}

impl Lsn {
    /// Invalid/null LSN
    pub const NULL: Lsn = Lsn {
        container: u32::MAX,
        block_offset: u32::MAX,
        record_offset: u32::MAX,
        sequence: 0,
    };

    /// Create a new LSN
    pub const fn new(container: u32, block_offset: u32, record_offset: u32, sequence: u32) -> Self {
        Self {
            container,
            block_offset,
            record_offset,
            sequence,
        }
    }

    /// Check if LSN is valid (not null)
    pub fn is_valid(&self) -> bool {
        self.container != u32::MAX
    }

    /// Get as u128 for comparison
    pub fn as_u128(&self) -> u128 {
        ((self.container as u128) << 96)
            | ((self.block_offset as u128) << 64)
            | ((self.record_offset as u128) << 32)
            | (self.sequence as u128)
    }
}

impl Default for Lsn {
    fn default() -> Self {
        Self::NULL
    }
}

// ============================================================================
// Container Types
// ============================================================================

/// Container state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerState {
    /// Container is uninitialized
    Uninitialized,
    /// Container is active and accepting writes
    Active,
    /// Container is full
    Full,
    /// Container is being recycled
    Recycling,
    /// Container is offline
    Offline,
}

/// A log container (physical storage unit)
#[derive(Clone)]
pub struct LogContainer {
    /// Container ID
    pub id: u32,
    /// Container path
    pub path: [u8; MAX_LOG_NAME],
    /// Path length
    pub path_len: usize,
    /// Container size
    pub size: u64,
    /// Used space
    pub used: u64,
    /// Container state
    pub state: ContainerState,
    /// First LSN in container
    pub base_lsn: Lsn,
    /// Last LSN in container
    pub last_lsn: Lsn,
    /// Physical file offset
    pub file_offset: u64,
    /// Active flag
    pub active: bool,
}

impl Default for LogContainer {
    fn default() -> Self {
        Self {
            id: 0,
            path: [0; MAX_LOG_NAME],
            path_len: 0,
            size: DEFAULT_CONTAINER_SIZE,
            used: 0,
            state: ContainerState::Uninitialized,
            base_lsn: Lsn::NULL,
            last_lsn: Lsn::NULL,
            file_offset: 0,
            active: false,
        }
    }
}

// ============================================================================
// Stream Types
// ============================================================================

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is closed
    Closed,
    /// Stream is open for reading
    OpenRead,
    /// Stream is open for writing
    OpenWrite,
    /// Stream is open for read/write
    OpenReadWrite,
}

/// A log stream (logical view)
#[derive(Clone)]
pub struct LogStream {
    /// Stream ID
    pub id: u32,
    /// Stream name
    pub name: [u8; 64],
    /// Name length
    pub name_len: usize,
    /// Stream state
    pub state: StreamState,
    /// Base LSN (first valid record)
    pub base_lsn: Lsn,
    /// Last LSN (most recent record)
    pub last_lsn: Lsn,
    /// Current read position
    pub read_lsn: Lsn,
    /// Records written
    pub records_written: u64,
    /// Records read
    pub records_read: u64,
    /// Active flag
    pub active: bool,
}

impl Default for LogStream {
    fn default() -> Self {
        Self {
            id: 0,
            name: [0; 64],
            name_len: 0,
            state: StreamState::Closed,
            base_lsn: Lsn::NULL,
            last_lsn: Lsn::NULL,
            read_lsn: Lsn::NULL,
            records_written: 0,
            records_read: 0,
            active: false,
        }
    }
}

// ============================================================================
// Log Record Types
// ============================================================================

/// Record type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordType {
    /// Client data record
    Data = 0,
    /// Restart area record
    Restart = 1,
    /// Checkpoint record
    Checkpoint = 2,
    /// End-of-log marker
    EndOfLog = 3,
}

/// Log record header
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RecordHeader {
    /// Record type
    pub record_type: RecordType,
    /// Reserved flags
    pub flags: u16,
    /// Record size (including header)
    pub size: u32,
    /// Previous LSN
    pub previous_lsn: Lsn,
    /// Undo-next LSN (for transaction chains)
    pub undo_next_lsn: Lsn,
    /// Transaction ID (if applicable)
    pub transaction_id: u64,
}

impl Default for RecordHeader {
    fn default() -> Self {
        Self {
            record_type: RecordType::Data,
            flags: 0,
            size: 0,
            previous_lsn: Lsn::NULL,
            undo_next_lsn: Lsn::NULL,
            transaction_id: 0,
        }
    }
}

/// Log record (header + data)
#[derive(Clone)]
pub struct LogRecord {
    /// Record header
    pub header: RecordHeader,
    /// Record LSN (assigned when written)
    pub lsn: Lsn,
    /// Record data
    pub data: Vec<u8>,
}

// ============================================================================
// Marshalling Area
// ============================================================================

/// Marshalling area for buffering log I/O
#[derive(Clone)]
pub struct MarshallingArea {
    /// Area ID
    pub id: u32,
    /// Buffer size
    pub size: usize,
    /// Used bytes
    pub used: usize,
    /// Number of records buffered
    pub record_count: u32,
    /// Flush threshold
    pub flush_threshold: usize,
    /// Active flag
    pub active: bool,
}

impl Default for MarshallingArea {
    fn default() -> Self {
        Self {
            id: 0,
            size: DEFAULT_MARSHAL_SIZE,
            used: 0,
            record_count: 0,
            flush_threshold: DEFAULT_MARSHAL_SIZE / 2,
            active: false,
        }
    }
}

// ============================================================================
// Log Types
// ============================================================================

/// Log state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogState {
    /// Log is closed
    Closed,
    /// Log is opening
    Opening,
    /// Log is open
    Open,
    /// Log is closing
    Closing,
    /// Log has errors
    Error,
}

/// Log policy
#[derive(Debug, Clone, Copy)]
pub struct LogPolicy {
    /// Minimum number of containers
    pub min_containers: u32,
    /// Maximum number of containers
    pub max_containers: u32,
    /// Container size
    pub container_size: u64,
    /// Auto-grow enabled
    pub auto_grow: bool,
    /// Auto-shrink enabled
    pub auto_shrink: bool,
    /// Circular logging (reuse containers)
    pub circular: bool,
}

impl Default for LogPolicy {
    fn default() -> Self {
        Self {
            min_containers: 2,
            max_containers: MAX_CONTAINERS as u32,
            container_size: DEFAULT_CONTAINER_SIZE,
            auto_grow: true,
            auto_shrink: false,
            circular: true,
        }
    }
}

/// A CLFS log
#[derive(Clone)]
pub struct ClfsLog {
    /// Log ID
    pub id: u32,
    /// Log name
    pub name: [u8; MAX_LOG_NAME],
    /// Name length
    pub name_len: usize,
    /// Base log file path
    pub path: [u8; MAX_LOG_NAME],
    /// Path length
    pub path_len: usize,
    /// Log state
    pub state: LogState,
    /// Log policy
    pub policy: LogPolicy,
    /// Containers
    pub containers: [LogContainer; MAX_CONTAINERS],
    /// Number of containers
    pub container_count: usize,
    /// Streams
    pub streams: [LogStream; MAX_STREAMS],
    /// Number of streams
    pub stream_count: usize,
    /// Marshalling areas
    pub marshal_areas: [MarshallingArea; 4],
    /// Number of marshalling areas
    pub marshal_count: usize,
    /// Base LSN (oldest valid record)
    pub base_lsn: Lsn,
    /// Last flushed LSN
    pub flush_lsn: Lsn,
    /// End LSN (next write position)
    pub end_lsn: Lsn,
    /// Archive tail LSN
    pub archive_tail: Lsn,
    /// Next container ID
    pub next_container_id: u32,
    /// Next stream ID
    pub next_stream_id: u32,
    /// Total bytes written
    pub bytes_written: u64,
    /// Total bytes read
    pub bytes_read: u64,
    /// Active flag
    pub active: bool,
}

impl Default for ClfsLog {
    fn default() -> Self {
        Self {
            id: 0,
            name: [0; MAX_LOG_NAME],
            name_len: 0,
            path: [0; MAX_LOG_NAME],
            path_len: 0,
            state: LogState::Closed,
            policy: LogPolicy::default(),
            containers: core::array::from_fn(|_| LogContainer::default()),
            container_count: 0,
            streams: core::array::from_fn(|_| LogStream::default()),
            stream_count: 0,
            marshal_areas: core::array::from_fn(|_| MarshallingArea::default()),
            marshal_count: 0,
            base_lsn: Lsn::NULL,
            flush_lsn: Lsn::NULL,
            end_lsn: Lsn::new(0, 0, 0, 1),
            archive_tail: Lsn::NULL,
            next_container_id: 1,
            next_stream_id: 1,
            bytes_written: 0,
            bytes_read: 0,
            active: false,
        }
    }
}

// ============================================================================
// CLFS Statistics
// ============================================================================

/// CLFS statistics
#[derive(Debug)]
pub struct ClfsStatistics {
    /// Active logs
    pub active_logs: AtomicU32,
    /// Active containers
    pub active_containers: AtomicU32,
    /// Active streams
    pub active_streams: AtomicU32,
    /// Records written
    pub records_written: AtomicU64,
    /// Records read
    pub records_read: AtomicU64,
    /// Bytes written
    pub bytes_written: AtomicU64,
    /// Bytes read
    pub bytes_read: AtomicU64,
    /// Flush operations
    pub flush_ops: AtomicU64,
}

impl Default for ClfsStatistics {
    fn default() -> Self {
        Self {
            active_logs: AtomicU32::new(0),
            active_containers: AtomicU32::new(0),
            active_streams: AtomicU32::new(0),
            records_written: AtomicU64::new(0),
            records_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            flush_ops: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// CLFS Errors
// ============================================================================

/// CLFS error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ClfsError {
    /// Success
    Success = 0,
    /// Not initialized
    NotInitialized = -1,
    /// Invalid parameter
    InvalidParameter = -2,
    /// Log not found
    LogNotFound = -3,
    /// Log already exists
    LogExists = -4,
    /// Container not found
    ContainerNotFound = -5,
    /// Stream not found
    StreamNotFound = -6,
    /// Log full
    LogFull = -7,
    /// Invalid LSN
    InvalidLsn = -8,
    /// Record too large
    RecordTooLarge = -9,
    /// Log closed
    LogClosed = -10,
    /// I/O error
    IoError = -11,
    /// Too many logs
    TooManyLogs = -12,
    /// Too many containers
    TooManyContainers = -13,
    /// Too many streams
    TooManyStreams = -14,
    /// End of log
    EndOfLog = -15,
    /// Log corrupted
    Corrupted = -16,
}

// ============================================================================
// CLFS Global State
// ============================================================================

/// CLFS global state
pub struct ClfsState {
    /// Logs
    pub logs: [ClfsLog; MAX_LOGS],
    /// Next log ID
    pub next_log_id: u32,
    /// Statistics
    pub statistics: ClfsStatistics,
    /// Initialized flag
    pub initialized: bool,
}

impl ClfsState {
    const fn new() -> Self {
        Self {
            logs: [const { ClfsLog {
                id: 0,
                name: [0; MAX_LOG_NAME],
                name_len: 0,
                path: [0; MAX_LOG_NAME],
                path_len: 0,
                state: LogState::Closed,
                policy: LogPolicy {
                    min_containers: 2,
                    max_containers: MAX_CONTAINERS as u32,
                    container_size: DEFAULT_CONTAINER_SIZE,
                    auto_grow: true,
                    auto_shrink: false,
                    circular: true,
                },
                containers: [const { LogContainer {
                    id: 0,
                    path: [0; MAX_LOG_NAME],
                    path_len: 0,
                    size: DEFAULT_CONTAINER_SIZE,
                    used: 0,
                    state: ContainerState::Uninitialized,
                    base_lsn: Lsn::NULL,
                    last_lsn: Lsn::NULL,
                    file_offset: 0,
                    active: false,
                }}; MAX_CONTAINERS],
                container_count: 0,
                streams: [const { LogStream {
                    id: 0,
                    name: [0; 64],
                    name_len: 0,
                    state: StreamState::Closed,
                    base_lsn: Lsn::NULL,
                    last_lsn: Lsn::NULL,
                    read_lsn: Lsn::NULL,
                    records_written: 0,
                    records_read: 0,
                    active: false,
                }}; MAX_STREAMS],
                stream_count: 0,
                marshal_areas: [const { MarshallingArea {
                    id: 0,
                    size: DEFAULT_MARSHAL_SIZE,
                    used: 0,
                    record_count: 0,
                    flush_threshold: DEFAULT_MARSHAL_SIZE / 2,
                    active: false,
                }}; 4],
                marshal_count: 0,
                base_lsn: Lsn::NULL,
                flush_lsn: Lsn::NULL,
                end_lsn: Lsn { container: 0, block_offset: 0, record_offset: 0, sequence: 1 },
                archive_tail: Lsn::NULL,
                next_container_id: 1,
                next_stream_id: 1,
                bytes_written: 0,
                bytes_read: 0,
                active: false,
            }}; MAX_LOGS],
            next_log_id: 1,
            statistics: ClfsStatistics {
                active_logs: AtomicU32::new(0),
                active_containers: AtomicU32::new(0),
                active_streams: AtomicU32::new(0),
                records_written: AtomicU64::new(0),
                records_read: AtomicU64::new(0),
                bytes_written: AtomicU64::new(0),
                bytes_read: AtomicU64::new(0),
                flush_ops: AtomicU64::new(0),
            },
            initialized: false,
        }
    }
}

/// Global CLFS state
static CLFS_STATE: SpinLock<ClfsState> = SpinLock::new(ClfsState::new());

// ============================================================================
// Log Management
// ============================================================================

/// Create a new log
pub fn clfs_create_log(name: &str, path: &str, policy: Option<LogPolicy>) -> Result<u32, ClfsError> {
    let mut state = CLFS_STATE.lock();

    if !state.initialized {
        return Err(ClfsError::NotInitialized);
    }

    let name_bytes = name.as_bytes();
    let path_bytes = path.as_bytes();

    if name_bytes.len() > MAX_LOG_NAME || path_bytes.len() > MAX_LOG_NAME {
        return Err(ClfsError::InvalidParameter);
    }

    // Check for duplicate
    for idx in 0..MAX_LOGS {
        if state.logs[idx].active && state.logs[idx].name_len == name_bytes.len() {
            let mut matches = true;
            for i in 0..name_bytes.len() {
                if state.logs[idx].name[i] != name_bytes[i] {
                    matches = false;
                    break;
                }
            }
            if matches {
                return Err(ClfsError::LogExists);
            }
        }
    }

    // Find free slot
    let mut slot_idx = None;
    for idx in 0..MAX_LOGS {
        if !state.logs[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(ClfsError::TooManyLogs)?;

    let log_id = state.next_log_id;
    state.next_log_id += 1;

    state.logs[idx].id = log_id;
    state.logs[idx].name_len = name_bytes.len();
    state.logs[idx].name[..name_bytes.len()].copy_from_slice(name_bytes);
    state.logs[idx].path_len = path_bytes.len();
    state.logs[idx].path[..path_bytes.len()].copy_from_slice(path_bytes);
    state.logs[idx].policy = policy.unwrap_or_default();
    state.logs[idx].state = LogState::Open;
    state.logs[idx].active = true;

    // Create initial containers
    let container_size = state.logs[idx].policy.container_size;
    for c in 0..state.logs[idx].policy.min_containers as usize {
        if c >= MAX_CONTAINERS {
            break;
        }
        state.logs[idx].containers[c].id = state.logs[idx].next_container_id;
        state.logs[idx].next_container_id += 1;
        state.logs[idx].containers[c].size = container_size;
        state.logs[idx].containers[c].state = ContainerState::Active;
        state.logs[idx].containers[c].file_offset = c as u64 * container_size;
        state.logs[idx].containers[c].active = true;
        state.logs[idx].container_count += 1;
        state.statistics.active_containers.fetch_add(1, Ordering::Relaxed);
    }

    state.statistics.active_logs.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[CLFS] Created log '{}' with {} containers", name, state.logs[idx].container_count);

    Ok(log_id)
}

/// Close and delete a log
pub fn clfs_delete_log(log_id: u32) -> Result<(), ClfsError> {
    let mut state = CLFS_STATE.lock();

    if !state.initialized {
        return Err(ClfsError::NotInitialized);
    }

    for idx in 0..MAX_LOGS {
        if state.logs[idx].active && state.logs[idx].id == log_id {
            let container_count = state.logs[idx].container_count;
            let stream_count = state.logs[idx].stream_count;

            state.logs[idx].state = LogState::Closed;
            state.logs[idx].active = false;

            state.statistics.active_logs.fetch_sub(1, Ordering::Relaxed);
            state.statistics.active_containers.fetch_sub(container_count as u32, Ordering::Relaxed);
            state.statistics.active_streams.fetch_sub(stream_count as u32, Ordering::Relaxed);

            crate::serial_println!("[CLFS] Deleted log {}", log_id);
            return Ok(());
        }
    }

    Err(ClfsError::LogNotFound)
}

// ============================================================================
// Container Management
// ============================================================================

/// Add a container to a log
pub fn clfs_add_container(log_id: u32, path: &str, size: Option<u64>) -> Result<u32, ClfsError> {
    let mut state = CLFS_STATE.lock();

    if !state.initialized {
        return Err(ClfsError::NotInitialized);
    }

    let log_idx = find_log_index(&state, log_id)?;

    if state.logs[log_idx].container_count >= MAX_CONTAINERS {
        return Err(ClfsError::TooManyContainers);
    }

    let path_bytes = path.as_bytes();
    if path_bytes.len() > MAX_LOG_NAME {
        return Err(ClfsError::InvalidParameter);
    }

    // Find free container slot
    let mut container_idx = None;
    for c in 0..MAX_CONTAINERS {
        if !state.logs[log_idx].containers[c].active {
            container_idx = Some(c);
            break;
        }
    }

    let cidx = container_idx.ok_or(ClfsError::TooManyContainers)?;

    let container_id = state.logs[log_idx].next_container_id;
    state.logs[log_idx].next_container_id += 1;

    let container_size = size.unwrap_or(state.logs[log_idx].policy.container_size);

    state.logs[log_idx].containers[cidx].id = container_id;
    state.logs[log_idx].containers[cidx].path_len = path_bytes.len();
    state.logs[log_idx].containers[cidx].path[..path_bytes.len()].copy_from_slice(path_bytes);
    state.logs[log_idx].containers[cidx].size = container_size;
    state.logs[log_idx].containers[cidx].state = ContainerState::Active;
    state.logs[log_idx].containers[cidx].active = true;

    state.logs[log_idx].container_count += 1;
    state.statistics.active_containers.fetch_add(1, Ordering::Relaxed);

    Ok(container_id)
}

/// Remove a container from a log
pub fn clfs_remove_container(log_id: u32, container_id: u32) -> Result<(), ClfsError> {
    let mut state = CLFS_STATE.lock();

    if !state.initialized {
        return Err(ClfsError::NotInitialized);
    }

    let log_idx = find_log_index(&state, log_id)?;

    for cidx in 0..MAX_CONTAINERS {
        if state.logs[log_idx].containers[cidx].active
            && state.logs[log_idx].containers[cidx].id == container_id
        {
            state.logs[log_idx].containers[cidx].active = false;
            state.logs[log_idx].container_count -= 1;
            state.statistics.active_containers.fetch_sub(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(ClfsError::ContainerNotFound)
}

// ============================================================================
// Stream Management
// ============================================================================

/// Create a stream in a log
pub fn clfs_create_stream(log_id: u32, name: &str) -> Result<u32, ClfsError> {
    let mut state = CLFS_STATE.lock();

    if !state.initialized {
        return Err(ClfsError::NotInitialized);
    }

    let log_idx = find_log_index(&state, log_id)?;

    if state.logs[log_idx].stream_count >= MAX_STREAMS {
        return Err(ClfsError::TooManyStreams);
    }

    let name_bytes = name.as_bytes();
    if name_bytes.len() > 64 {
        return Err(ClfsError::InvalidParameter);
    }

    // Find free stream slot
    let mut stream_idx = None;
    for s in 0..MAX_STREAMS {
        if !state.logs[log_idx].streams[s].active {
            stream_idx = Some(s);
            break;
        }
    }

    let sidx = stream_idx.ok_or(ClfsError::TooManyStreams)?;

    let stream_id = state.logs[log_idx].next_stream_id;
    state.logs[log_idx].next_stream_id += 1;

    state.logs[log_idx].streams[sidx].id = stream_id;
    state.logs[log_idx].streams[sidx].name_len = name_bytes.len();
    state.logs[log_idx].streams[sidx].name[..name_bytes.len()].copy_from_slice(name_bytes);
    state.logs[log_idx].streams[sidx].state = StreamState::OpenReadWrite;
    state.logs[log_idx].streams[sidx].active = true;

    state.logs[log_idx].stream_count += 1;
    state.statistics.active_streams.fetch_add(1, Ordering::Relaxed);

    Ok(stream_id)
}

/// Close a stream
pub fn clfs_close_stream(log_id: u32, stream_id: u32) -> Result<(), ClfsError> {
    let mut state = CLFS_STATE.lock();

    if !state.initialized {
        return Err(ClfsError::NotInitialized);
    }

    let log_idx = find_log_index(&state, log_id)?;

    for sidx in 0..MAX_STREAMS {
        if state.logs[log_idx].streams[sidx].active
            && state.logs[log_idx].streams[sidx].id == stream_id
        {
            state.logs[log_idx].streams[sidx].state = StreamState::Closed;
            state.logs[log_idx].streams[sidx].active = false;
            state.logs[log_idx].stream_count -= 1;
            state.statistics.active_streams.fetch_sub(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(ClfsError::StreamNotFound)
}

// ============================================================================
// Record I/O
// ============================================================================

/// Reserve space for a record and get the LSN
pub fn clfs_reserve_record(log_id: u32, size: usize) -> Result<Lsn, ClfsError> {
    let mut state = CLFS_STATE.lock();

    if !state.initialized {
        return Err(ClfsError::NotInitialized);
    }

    if size > MAX_RECORD_SIZE {
        return Err(ClfsError::RecordTooLarge);
    }

    let log_idx = find_log_index(&state, log_id)?;

    if state.logs[log_idx].state != LogState::Open {
        return Err(ClfsError::LogClosed);
    }

    // Get current end LSN and advance
    let lsn = state.logs[log_idx].end_lsn;
    state.logs[log_idx].end_lsn.record_offset += size as u32;
    state.logs[log_idx].end_lsn.sequence += 1;

    // Check if we need to move to next block
    if state.logs[log_idx].end_lsn.record_offset >= 64 * 1024 {
        state.logs[log_idx].end_lsn.record_offset = 0;
        state.logs[log_idx].end_lsn.block_offset += 1;
    }

    Ok(lsn)
}

/// Write a record to the log
pub fn clfs_write_record(
    log_id: u32,
    data: &[u8],
    _record_type: RecordType,
    _previous_lsn: Option<Lsn>,
) -> Result<Lsn, ClfsError> {
    let mut state = CLFS_STATE.lock();

    if !state.initialized {
        return Err(ClfsError::NotInitialized);
    }

    let total_size = core::mem::size_of::<RecordHeader>() + data.len();
    if total_size > MAX_RECORD_SIZE {
        return Err(ClfsError::RecordTooLarge);
    }

    let log_idx = find_log_index(&state, log_id)?;

    if state.logs[log_idx].state != LogState::Open {
        return Err(ClfsError::LogClosed);
    }

    // Get LSN for this record
    let lsn = state.logs[log_idx].end_lsn;

    // Advance end LSN
    state.logs[log_idx].end_lsn.record_offset += total_size as u32;
    state.logs[log_idx].end_lsn.sequence += 1;

    // Check if we need to move to next block
    if state.logs[log_idx].end_lsn.record_offset >= 64 * 1024 {
        state.logs[log_idx].end_lsn.record_offset = 0;
        state.logs[log_idx].end_lsn.block_offset += 1;
    }

    // Update log statistics
    state.logs[log_idx].bytes_written += total_size as u64;
    state.statistics.records_written.fetch_add(1, Ordering::Relaxed);
    state.statistics.bytes_written.fetch_add(total_size as u64, Ordering::Relaxed);

    // Update last LSN for the first stream
    if state.logs[log_idx].stream_count > 0 {
        for sidx in 0..MAX_STREAMS {
            if state.logs[log_idx].streams[sidx].active {
                state.logs[log_idx].streams[sidx].last_lsn = lsn;
                state.logs[log_idx].streams[sidx].records_written += 1;
                break;
            }
        }
    }

    Ok(lsn)
}

/// Flush log to stable storage
pub fn clfs_flush_log(log_id: u32, target_lsn: Option<Lsn>) -> Result<Lsn, ClfsError> {
    let mut state = CLFS_STATE.lock();

    if !state.initialized {
        return Err(ClfsError::NotInitialized);
    }

    let log_idx = find_log_index(&state, log_id)?;

    let flush_lsn = target_lsn.unwrap_or(state.logs[log_idx].end_lsn);
    state.logs[log_idx].flush_lsn = flush_lsn;

    state.statistics.flush_ops.fetch_add(1, Ordering::Relaxed);

    Ok(flush_lsn)
}

/// Read a record from the log
pub fn clfs_read_record(log_id: u32, lsn: Lsn) -> Result<LogRecord, ClfsError> {
    let state = CLFS_STATE.lock();

    if !state.initialized {
        return Err(ClfsError::NotInitialized);
    }

    if !lsn.is_valid() {
        return Err(ClfsError::InvalidLsn);
    }

    let log_idx = find_log_index(&state, log_id)?;

    // Check if LSN is within valid range
    if lsn.as_u128() >= state.logs[log_idx].end_lsn.as_u128() {
        return Err(ClfsError::EndOfLog);
    }

    if lsn.as_u128() < state.logs[log_idx].base_lsn.as_u128() && state.logs[log_idx].base_lsn.is_valid() {
        return Err(ClfsError::InvalidLsn);
    }

    // Update statistics
    state.statistics.records_read.fetch_add(1, Ordering::Relaxed);

    // In a real implementation, we would read from the container
    // For now, return a placeholder record
    Ok(LogRecord {
        header: RecordHeader {
            record_type: RecordType::Data,
            flags: 0,
            size: 0,
            previous_lsn: Lsn::NULL,
            undo_next_lsn: Lsn::NULL,
            transaction_id: 0,
        },
        lsn,
        data: Vec::new(),
    })
}

// ============================================================================
// LSN Management
// ============================================================================

/// Get the base LSN (oldest valid record)
pub fn clfs_get_base_lsn(log_id: u32) -> Result<Lsn, ClfsError> {
    let state = CLFS_STATE.lock();

    if !state.initialized {
        return Err(ClfsError::NotInitialized);
    }

    let log_idx = find_log_index(&state, log_id)?;
    Ok(state.logs[log_idx].base_lsn)
}

/// Get the end LSN (next write position)
pub fn clfs_get_end_lsn(log_id: u32) -> Result<Lsn, ClfsError> {
    let state = CLFS_STATE.lock();

    if !state.initialized {
        return Err(ClfsError::NotInitialized);
    }

    let log_idx = find_log_index(&state, log_id)?;
    Ok(state.logs[log_idx].end_lsn)
}

/// Advance the base LSN (truncate old records)
pub fn clfs_advance_base_lsn(log_id: u32, new_base: Lsn) -> Result<(), ClfsError> {
    let mut state = CLFS_STATE.lock();

    if !state.initialized {
        return Err(ClfsError::NotInitialized);
    }

    let log_idx = find_log_index(&state, log_id)?;

    if new_base.as_u128() > state.logs[log_idx].end_lsn.as_u128() {
        return Err(ClfsError::InvalidLsn);
    }

    state.logs[log_idx].base_lsn = new_base;
    Ok(())
}

// ============================================================================
// Query Functions
// ============================================================================

/// List all logs
pub fn clfs_list_logs() -> Vec<(u32, String, LogState, usize)> {
    let state = CLFS_STATE.lock();
    let mut result = Vec::new();

    for idx in 0..MAX_LOGS {
        if state.logs[idx].active {
            let name = core::str::from_utf8(&state.logs[idx].name[..state.logs[idx].name_len])
                .map(String::from)
                .unwrap_or_default();

            result.push((
                state.logs[idx].id,
                name,
                state.logs[idx].state,
                state.logs[idx].container_count,
            ));
        }
    }

    result
}

/// Get log information
pub fn clfs_get_log_info(log_id: u32) -> Result<(String, LogState, LogPolicy, usize, usize), ClfsError> {
    let state = CLFS_STATE.lock();

    if !state.initialized {
        return Err(ClfsError::NotInitialized);
    }

    let log_idx = find_log_index(&state, log_id)?;

    let name = core::str::from_utf8(&state.logs[log_idx].name[..state.logs[log_idx].name_len])
        .map(String::from)
        .unwrap_or_default();

    Ok((
        name,
        state.logs[log_idx].state,
        state.logs[log_idx].policy,
        state.logs[log_idx].container_count,
        state.logs[log_idx].stream_count,
    ))
}

/// Get CLFS statistics
pub fn clfs_get_statistics() -> ClfsStatistics {
    let state = CLFS_STATE.lock();

    ClfsStatistics {
        active_logs: AtomicU32::new(state.statistics.active_logs.load(Ordering::Relaxed)),
        active_containers: AtomicU32::new(state.statistics.active_containers.load(Ordering::Relaxed)),
        active_streams: AtomicU32::new(state.statistics.active_streams.load(Ordering::Relaxed)),
        records_written: AtomicU64::new(state.statistics.records_written.load(Ordering::Relaxed)),
        records_read: AtomicU64::new(state.statistics.records_read.load(Ordering::Relaxed)),
        bytes_written: AtomicU64::new(state.statistics.bytes_written.load(Ordering::Relaxed)),
        bytes_read: AtomicU64::new(state.statistics.bytes_read.load(Ordering::Relaxed)),
        flush_ops: AtomicU64::new(state.statistics.flush_ops.load(Ordering::Relaxed)),
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn find_log_index(state: &ClfsState, log_id: u32) -> Result<usize, ClfsError> {
    for idx in 0..MAX_LOGS {
        if state.logs[idx].active && state.logs[idx].id == log_id {
            return Ok(idx);
        }
    }
    Err(ClfsError::LogNotFound)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize CLFS subsystem
pub fn init() {
    crate::serial_println!("[CLFS] Initializing Common Log File System...");

    {
        let mut state = CLFS_STATE.lock();
        state.initialized = true;
    }

    crate::serial_println!("[CLFS] CLFS initialized");
}
