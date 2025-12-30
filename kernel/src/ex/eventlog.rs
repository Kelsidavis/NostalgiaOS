//! Event Logging System
//!
//! Windows-style event logging for system events, errors, and informational messages.
//! Similar to the Windows Event Log service.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// Maximum number of events to retain in memory
pub const MAX_EVENTS: usize = 1000;

/// Maximum event message length
pub const MAX_MESSAGE_LEN: usize = 512;

/// Event type/severity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventType {
    /// Informational event
    Information = 0,
    /// Warning event
    Warning = 1,
    /// Error event
    Error = 2,
    /// Success audit (security)
    SuccessAudit = 3,
    /// Failure audit (security)
    FailureAudit = 4,
}

impl EventType {
    pub fn name(&self) -> &'static str {
        match self {
            EventType::Information => "INFO",
            EventType::Warning => "WARN",
            EventType::Error => "ERROR",
            EventType::SuccessAudit => "AUDIT_OK",
            EventType::FailureAudit => "AUDIT_FAIL",
        }
    }
}

/// Event source/category
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EventSource {
    /// Kernel core
    Kernel = 0,
    /// Memory manager
    Memory = 1,
    /// Process manager
    Process = 2,
    /// I/O manager
    Io = 3,
    /// Network subsystem
    Network = 4,
    /// File system
    FileSystem = 5,
    /// Security subsystem
    Security = 6,
    /// Hardware/drivers
    Hardware = 7,
    /// Application/user
    Application = 8,
    /// System services
    System = 9,
}

impl EventSource {
    pub fn name(&self) -> &'static str {
        match self {
            EventSource::Kernel => "Kernel",
            EventSource::Memory => "Memory",
            EventSource::Process => "Process",
            EventSource::Io => "I/O",
            EventSource::Network => "Network",
            EventSource::FileSystem => "FileSystem",
            EventSource::Security => "Security",
            EventSource::Hardware => "Hardware",
            EventSource::Application => "Application",
            EventSource::System => "System",
        }
    }
}

/// Event record
#[derive(Clone)]
pub struct EventRecord {
    /// Event ID (unique per source)
    pub event_id: u32,
    /// Event type/severity
    pub event_type: EventType,
    /// Event source
    pub source: EventSource,
    /// Timestamp (tick count)
    pub timestamp: u64,
    /// Message
    pub message: String,
    /// Optional data
    pub data: Option<Vec<u8>>,
}

impl EventRecord {
    /// Create a new event record
    pub fn new(
        event_id: u32,
        event_type: EventType,
        source: EventSource,
        message: String,
    ) -> Self {
        Self {
            event_id,
            event_type,
            source,
            timestamp: crate::hal::apic::get_tick_count(),
            message,
            data: None,
        }
    }

    /// Create with additional data
    pub fn with_data(
        event_id: u32,
        event_type: EventType,
        source: EventSource,
        message: String,
        data: Vec<u8>,
    ) -> Self {
        Self {
            event_id,
            event_type,
            source,
            timestamp: crate::hal::apic::get_tick_count(),
            message,
            data: Some(data),
        }
    }
}

/// Event log storage
struct EventLog {
    events: VecDeque<EventRecord>,
    next_sequence: u64,
}

impl EventLog {
    const fn new() -> Self {
        Self {
            events: VecDeque::new(),
            next_sequence: 1,
        }
    }

    fn add(&mut self, event: EventRecord) -> u64 {
        let seq = self.next_sequence;
        self.next_sequence += 1;

        // Maintain maximum size
        if self.events.len() >= MAX_EVENTS {
            self.events.pop_front();
        }

        self.events.push_back(event);
        seq
    }

    fn get_events(&self, count: usize) -> Vec<EventRecord> {
        self.events.iter().rev().take(count).cloned().collect()
    }

    fn get_by_source(&self, source: EventSource, count: usize) -> Vec<EventRecord> {
        self.events
            .iter()
            .rev()
            .filter(|e| e.source == source)
            .take(count)
            .cloned()
            .collect()
    }

    fn get_by_type(&self, event_type: EventType, count: usize) -> Vec<EventRecord> {
        self.events
            .iter()
            .rev()
            .filter(|e| e.event_type == event_type)
            .take(count)
            .cloned()
            .collect()
    }

    fn clear(&mut self) {
        self.events.clear();
    }

    fn count(&self) -> usize {
        self.events.len()
    }
}

/// Global event log
static EVENT_LOG: SpinLock<Option<EventLog>> = SpinLock::new(None);

/// Statistics
static TOTAL_EVENTS: AtomicU64 = AtomicU64::new(0);
static INFO_EVENTS: AtomicU32 = AtomicU32::new(0);
static WARNING_EVENTS: AtomicU32 = AtomicU32::new(0);
static ERROR_EVENTS: AtomicU32 = AtomicU32::new(0);

/// Initialize event logging
pub fn init() {
    let mut log = EVENT_LOG.lock();
    *log = Some(EventLog::new());
    crate::serial_println!("[EVENTLOG] Event logging initialized");
}

/// Log an event
pub fn log_event(event: EventRecord) -> u64 {
    // Update statistics
    TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);
    match event.event_type {
        EventType::Information => { INFO_EVENTS.fetch_add(1, Ordering::Relaxed); }
        EventType::Warning => { WARNING_EVENTS.fetch_add(1, Ordering::Relaxed); }
        EventType::Error => { ERROR_EVENTS.fetch_add(1, Ordering::Relaxed); }
        _ => {}
    }

    // Also output to serial for debugging
    crate::serial_println!(
        "[{}] [{}] Event {}: {}",
        event.source.name(),
        event.event_type.name(),
        event.event_id,
        event.message
    );

    // Store in log
    let mut log = EVENT_LOG.lock();
    if let Some(ref mut log) = *log {
        log.add(event)
    } else {
        0
    }
}

/// Log an information event
pub fn log_info(source: EventSource, event_id: u32, message: &str) -> u64 {
    log_event(EventRecord::new(
        event_id,
        EventType::Information,
        source,
        String::from(message),
    ))
}

/// Log a warning event
pub fn log_warning(source: EventSource, event_id: u32, message: &str) -> u64 {
    log_event(EventRecord::new(
        event_id,
        EventType::Warning,
        source,
        String::from(message),
    ))
}

/// Log an error event
pub fn log_error(source: EventSource, event_id: u32, message: &str) -> u64 {
    log_event(EventRecord::new(
        event_id,
        EventType::Error,
        source,
        String::from(message),
    ))
}

/// Log a formatted info message
pub fn log_info_fmt(source: EventSource, event_id: u32, message: String) -> u64 {
    log_event(EventRecord::new(
        event_id,
        EventType::Information,
        source,
        message,
    ))
}

/// Log a formatted warning message
pub fn log_warning_fmt(source: EventSource, event_id: u32, message: String) -> u64 {
    log_event(EventRecord::new(
        event_id,
        EventType::Warning,
        source,
        message,
    ))
}

/// Log a formatted error message
pub fn log_error_fmt(source: EventSource, event_id: u32, message: String) -> u64 {
    log_event(EventRecord::new(
        event_id,
        EventType::Error,
        source,
        message,
    ))
}

/// Get recent events
pub fn get_events(count: usize) -> Vec<EventRecord> {
    let log = EVENT_LOG.lock();
    if let Some(ref log) = *log {
        log.get_events(count)
    } else {
        Vec::new()
    }
}

/// Get events by source
pub fn get_events_by_source(source: EventSource, count: usize) -> Vec<EventRecord> {
    let log = EVENT_LOG.lock();
    if let Some(ref log) = *log {
        log.get_by_source(source, count)
    } else {
        Vec::new()
    }
}

/// Get events by type
pub fn get_events_by_type(event_type: EventType, count: usize) -> Vec<EventRecord> {
    let log = EVENT_LOG.lock();
    if let Some(ref log) = *log {
        log.get_by_type(event_type, count)
    } else {
        Vec::new()
    }
}

/// Clear event log
pub fn clear() {
    let mut log = EVENT_LOG.lock();
    if let Some(ref mut log) = *log {
        log.clear();
    }
}

/// Get event count
pub fn event_count() -> usize {
    let log = EVENT_LOG.lock();
    if let Some(ref log) = *log {
        log.count()
    } else {
        0
    }
}

/// Event log statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct EventLogStats {
    pub total_events: u64,
    pub stored_events: usize,
    pub info_events: u32,
    pub warning_events: u32,
    pub error_events: u32,
}

/// Get event log statistics
pub fn get_stats() -> EventLogStats {
    let stored = event_count();
    EventLogStats {
        total_events: TOTAL_EVENTS.load(Ordering::Relaxed),
        stored_events: stored,
        info_events: INFO_EVENTS.load(Ordering::Relaxed),
        warning_events: WARNING_EVENTS.load(Ordering::Relaxed),
        error_events: ERROR_EVENTS.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Common Event IDs
// ============================================================================

/// Kernel events (1-999)
pub mod kernel_events {
    pub const SYSTEM_STARTED: u32 = 1;
    pub const SYSTEM_SHUTDOWN: u32 = 2;
    pub const DRIVER_LOADED: u32 = 10;
    pub const DRIVER_UNLOADED: u32 = 11;
    pub const DRIVER_ERROR: u32 = 12;
}

/// Memory events (1000-1999)
pub mod memory_events {
    pub const LOW_MEMORY: u32 = 1001;
    pub const OUT_OF_MEMORY: u32 = 1002;
    pub const POOL_CORRUPTION: u32 = 1003;
    pub const PAGE_FAULT: u32 = 1004;
}

/// Process events (2000-2999)
pub mod process_events {
    pub const PROCESS_CREATED: u32 = 2001;
    pub const PROCESS_TERMINATED: u32 = 2002;
    pub const THREAD_CREATED: u32 = 2003;
    pub const THREAD_TERMINATED: u32 = 2004;
}

/// Network events (3000-3999)
pub mod network_events {
    pub const INTERFACE_UP: u32 = 3001;
    pub const INTERFACE_DOWN: u32 = 3002;
    pub const DHCP_SUCCESS: u32 = 3003;
    pub const DHCP_FAILURE: u32 = 3004;
    pub const CONNECTION_ESTABLISHED: u32 = 3005;
    pub const CONNECTION_CLOSED: u32 = 3006;
    pub const CONNECTION_REFUSED: u32 = 3007;
}

/// Security events (4000-4999)
pub mod security_events {
    pub const LOGIN_SUCCESS: u32 = 4001;
    pub const LOGIN_FAILURE: u32 = 4002;
    pub const ACCESS_DENIED: u32 = 4003;
    pub const PRIVILEGE_GRANTED: u32 = 4004;
}

/// Filesystem events (5000-5999)
pub mod fs_events {
    pub const VOLUME_MOUNTED: u32 = 5001;
    pub const VOLUME_UNMOUNTED: u32 = 5002;
    pub const FILE_ACCESS_ERROR: u32 = 5003;
    pub const DISK_FULL: u32 = 5004;
}
