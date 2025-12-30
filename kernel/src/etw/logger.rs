//! ETW Logger Session Management
//!
//! Manages trace logging sessions that collect events from providers.

use super::{
    buffer::TraceBuffer, ClockType, Guid, NtStatus, TraceHandle, WnodeHeader,
    INVALID_TRACE_HANDLE,
};
use crate::ke::SpinLock;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

extern crate alloc;

/// Logger session mode flags
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoggerMode {
    /// Sequential file mode
    Sequential = 0x00000001,
    /// Circular file mode
    Circular = 0x00000002,
    /// Real-time delivery mode
    RealTime = 0x00000100,
    /// Buffering mode (no file)
    Buffering = 0x00000400,
    /// Private logger mode
    Private = 0x00000800,
    /// Add file header
    AddHeader = 0x00001000,
    /// Use paged memory for buffers
    UsePagedMemory = 0x01000000,
    /// No per-processor buffering
    NoPerProcessorBuffering = 0x10000000,
}

/// Logger session information structure
#[repr(C)]
#[derive(Debug, Clone)]
pub struct LoggerInformation {
    /// Size of this structure
    pub size: u32,
    /// Logger session handle (returned)
    pub logger_handle: TraceHandle,
    /// Logger name (16-bit Unicode, null-terminated)
    pub logger_name: [u16; 64],
    /// Log file name (16-bit Unicode, null-terminated)
    pub log_file_name: [u16; 256],
    /// Logging mode flags
    pub log_file_mode: u32,
    /// Number of buffers
    pub number_of_buffers: u32,
    /// Size of each buffer in KB
    pub buffer_size: u32,
    /// Minimum number of buffers
    pub minimum_buffers: u32,
    /// Maximum number of buffers
    pub maximum_buffers: u32,
    /// Maximum file size in MB
    pub maximum_file_size: u32,
    /// Enable flags for kernel providers
    pub enable_flags: u32,
    /// Flush timer (seconds)
    pub flush_timer: u32,
    /// Age limit (minutes)
    pub age_limit: u32,
    /// Clock type for timestamps
    pub clock_type: ClockType,
    /// Buffers written
    pub buffers_written: u32,
    /// Events lost
    pub events_lost: u32,
    /// Log buffers lost
    pub log_buffers_lost: u32,
    /// Real time buffers lost
    pub real_time_buffers_lost: u32,
    /// Logger thread ID
    pub logger_thread_id: u32,
}

impl Default for LoggerInformation {
    fn default() -> Self {
        Self {
            size: core::mem::size_of::<LoggerInformation>() as u32,
            logger_handle: INVALID_TRACE_HANDLE,
            logger_name: [0u16; 64],
            log_file_name: [0u16; 256],
            log_file_mode: LoggerMode::RealTime as u32,
            number_of_buffers: 4,
            buffer_size: 64, // 64 KB
            minimum_buffers: 2,
            maximum_buffers: 16,
            maximum_file_size: 0, // No limit
            enable_flags: 0,
            flush_timer: 0,
            age_limit: 0,
            clock_type: ClockType::QueryPerformanceCounter,
            buffers_written: 0,
            events_lost: 0,
            log_buffers_lost: 0,
            real_time_buffers_lost: 0,
            logger_thread_id: 0,
        }
    }
}

/// Logger session statistics
#[derive(Debug, Default, Clone)]
pub struct LoggerStatistics {
    /// Events successfully logged
    pub events_logged: u64,
    /// Bytes logged
    pub bytes_logged: u64,
    /// Events dropped
    pub events_dropped: u64,
    /// Buffers allocated
    pub buffers_allocated: u32,
    /// Buffers used
    pub buffers_in_use: u32,
    /// Buffers flushed to file
    pub buffers_flushed: u32,
}

/// Logger session state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoggerState {
    /// Session is stopped
    Stopped = 0,
    /// Session is starting
    Starting = 1,
    /// Session is running
    Running = 2,
    /// Session is stopping
    Stopping = 3,
}

/// Logger session - manages a trace collection session
pub struct LoggerSession {
    /// Session ID
    id: u32,
    /// Session name
    name: [u16; 64],
    /// Session state
    state: AtomicU32,
    /// Is enabled
    enabled: AtomicBool,
    /// Clock type for timestamps
    clock_type: ClockType,
    /// Mode flags
    mode: u32,
    /// Enable flags for kernel providers
    enable_flags: u32,
    /// Trace buffers
    buffers: SpinLock<Vec<TraceBuffer>>,
    /// Current write buffer index
    current_buffer: AtomicU32,
    /// Registered provider GUIDs
    providers: SpinLock<BTreeSet<Guid>>,
    /// Statistics
    stats: SpinLock<LoggerStatistics>,
    /// Events logged counter
    events_logged: AtomicU64,
    /// Bytes logged counter
    bytes_logged: AtomicU64,
    /// Events dropped counter
    events_dropped: AtomicU64,
}

impl LoggerSession {
    /// Create a new logger session
    pub fn new(id: u32, info: &LoggerInformation) -> Result<Self, NtStatus> {
        let buffer_count = info.number_of_buffers as usize;
        let buffer_size = (info.buffer_size as usize) * 1024; // Convert KB to bytes

        // Allocate buffers
        let mut buffers = Vec::with_capacity(buffer_count);
        for i in 0..buffer_count {
            buffers.push(TraceBuffer::new(i as u32, buffer_size));
        }

        Ok(Self {
            id,
            name: info.logger_name,
            state: AtomicU32::new(LoggerState::Running as u32),
            enabled: AtomicBool::new(true),
            clock_type: info.clock_type,
            mode: info.log_file_mode,
            enable_flags: info.enable_flags,
            buffers: SpinLock::new(buffers),
            current_buffer: AtomicU32::new(0),
            providers: SpinLock::new(BTreeSet::new()),
            stats: SpinLock::new(LoggerStatistics::default()),
            events_logged: AtomicU64::new(0),
            bytes_logged: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
        })
    }

    /// Get session ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Check if session is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Check if provider is accepted by this session
    pub fn accepts_provider(&self, guid: &Guid) -> bool {
        let providers = self.providers.lock();
        providers.is_empty() || providers.contains(guid)
    }

    /// Enable a specific provider
    pub fn enable_provider(&self, guid: Guid) {
        let mut providers = self.providers.lock();
        providers.insert(guid);
    }

    /// Disable a specific provider
    pub fn disable_provider(&self, guid: &Guid) {
        let mut providers = self.providers.lock();
        providers.remove(guid);
    }

    /// Log an event
    pub fn log_event(&self, header: &WnodeHeader) -> Result<(), NtStatus> {
        if !self.is_enabled() {
            return Ok(());
        }

        let event_size = header.buffer_size as usize;
        let buffer_idx = self.current_buffer.load(Ordering::SeqCst) as usize;

        let mut buffers = self.buffers.lock();
        let buffer_count = buffers.len();

        if buffer_idx >= buffer_count {
            self.events_dropped.fetch_add(1, Ordering::SeqCst);
            return Err(NtStatus::InsufficientResources);
        }

        // Try to write to current buffer
        if buffers[buffer_idx].try_write(header) {
            self.events_logged.fetch_add(1, Ordering::SeqCst);
            self.bytes_logged
                .fetch_add(event_size as u64, Ordering::SeqCst);
            return Ok(());
        }

        // Buffer full, try next buffer
        let next_idx = (buffer_idx + 1) % buffer_count;
        self.current_buffer.store(next_idx as u32, Ordering::SeqCst);

        // Mark current buffer for flush
        buffers[buffer_idx].mark_for_flush();

        // Reset and try the new buffer
        buffers[next_idx].reset();

        if buffers[next_idx].try_write(header) {
            self.events_logged.fetch_add(1, Ordering::SeqCst);
            self.bytes_logged
                .fetch_add(event_size as u64, Ordering::SeqCst);
            Ok(())
        } else {
            self.events_dropped.fetch_add(1, Ordering::SeqCst);
            Err(NtStatus::InsufficientResources)
        }
    }

    /// Flush all buffers
    pub fn flush(&self) {
        let mut buffers = self.buffers.lock();
        for buffer in buffers.iter_mut() {
            buffer.flush();
        }

        let mut stats = self.stats.lock();
        stats.buffers_flushed += buffers.len() as u32;
    }

    /// Stop the logger session
    pub fn stop(&self) {
        self.state
            .store(LoggerState::Stopping as u32, Ordering::SeqCst);
        self.enabled.store(false, Ordering::SeqCst);
        self.flush();
        self.state
            .store(LoggerState::Stopped as u32, Ordering::SeqCst);
    }

    /// Fill logger information structure
    pub fn fill_info(&self, info: &mut LoggerInformation) {
        info.logger_handle = self.id as u64;
        info.log_file_mode = self.mode;
        info.enable_flags = self.enable_flags;
        info.clock_type = self.clock_type;

        let buffers = self.buffers.lock();
        info.number_of_buffers = buffers.len() as u32;

        info.events_lost = self.events_dropped.load(Ordering::SeqCst) as u32;
    }

    /// Get session statistics
    pub fn get_statistics(&self) -> LoggerStatistics {
        let mut stats = self.stats.lock().clone();
        stats.events_logged = self.events_logged.load(Ordering::SeqCst);
        stats.bytes_logged = self.bytes_logged.load(Ordering::SeqCst);
        stats.events_dropped = self.events_dropped.load(Ordering::SeqCst);
        stats
    }

    /// Get current state
    pub fn state(&self) -> LoggerState {
        match self.state.load(Ordering::SeqCst) {
            0 => LoggerState::Stopped,
            1 => LoggerState::Starting,
            2 => LoggerState::Running,
            3 => LoggerState::Stopping,
            _ => LoggerState::Stopped,
        }
    }
}

impl core::fmt::Debug for LoggerSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoggerSession")
            .field("id", &self.id)
            .field("enabled", &self.is_enabled())
            .field("state", &self.state())
            .field("events_logged", &self.events_logged.load(Ordering::SeqCst))
            .finish()
    }
}

/// Atomic state helper
#[repr(transparent)]
struct AtomicU32(core::sync::atomic::AtomicU32);

impl AtomicU32 {
    const fn new(val: u32) -> Self {
        Self(core::sync::atomic::AtomicU32::new(val))
    }

    fn load(&self, order: Ordering) -> u32 {
        self.0.load(order)
    }

    fn store(&self, val: u32, order: Ordering) {
        self.0.store(val, order)
    }
}
