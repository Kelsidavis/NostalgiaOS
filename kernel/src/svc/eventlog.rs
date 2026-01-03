//! Event Log Service
//!
//! The Windows Event Log service provides centralized logging for:
//!
//! - **Application Log**: Application events and errors
//! - **Security Log**: Auditing events (login, access, etc.)
//! - **System Log**: System component events
//! - **Directory Service**: Active Directory events
//! - **DNS Server**: DNS service events
//! - **File Replication Service**: FRS events
//!
//! # Event Structure
//!
//! Each event contains:
//! - Event ID: Identifies the event type
//! - Source: Application/service name
//! - Category: Optional categorization
//! - Type: Information, Warning, Error, etc.
//! - Timestamp: When the event occurred
//! - Description: Human-readable message
//!
//! # Registry Location
//!
//! Event logs are configured in:
//! `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<LogName>`

extern crate alloc;

use crate::ke::SpinLock;
use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum events per log
pub const MAX_EVENTS: usize = 64;

/// Maximum event logs
pub const MAX_LOGS: usize = 8;

/// Maximum event sources
pub const MAX_SOURCES: usize = 16;

/// Maximum event description length
pub const MAX_DESCRIPTION: usize = 256;

/// Maximum source name length
pub const MAX_SOURCE_NAME: usize = 32;

/// Maximum log name length
pub const MAX_LOG_NAME: usize = 32;

/// Maximum data size
pub const MAX_DATA_SIZE: usize = 64;

// ============================================================================
// Event Types
// ============================================================================

/// Event type/level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EventType {
    /// Success audit (security log)
    AuditSuccess = 0,
    /// Failure audit (security log)
    AuditFailure = 1,
    /// Error event
    Error = 2,
    /// Warning event
    Warning = 3,
    /// Informational event
    Information = 4,
    /// Verbose/debug event
    Verbose = 5,
}

impl Default for EventType {
    fn default() -> Self {
        Self::Information
    }
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuditSuccess => "Audit Success",
            Self::AuditFailure => "Audit Failure",
            Self::Error => "Error",
            Self::Warning => "Warning",
            Self::Information => "Information",
            Self::Verbose => "Verbose",
        }
    }
}

/// Well-known event logs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LogType {
    /// Application log
    Application = 0,
    /// Security log
    Security = 1,
    /// System log
    System = 2,
    /// Setup log
    Setup = 3,
    /// Forwarded Events
    ForwardedEvents = 4,
    /// Directory Service (AD)
    DirectoryService = 5,
    /// DNS Server
    DnsServer = 6,
    /// File Replication Service
    FileReplicationService = 7,
    /// Custom log
    Custom = 255,
}

impl Default for LogType {
    fn default() -> Self {
        Self::Application
    }
}

impl LogType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Application => "Application",
            Self::Security => "Security",
            Self::System => "System",
            Self::Setup => "Setup",
            Self::ForwardedEvents => "ForwardedEvents",
            Self::DirectoryService => "Directory Service",
            Self::DnsServer => "DNS Server",
            Self::FileReplicationService => "File Replication Service",
            Self::Custom => "Custom",
        }
    }
}

/// Event log error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EventLogError {
    /// Success
    Ok = 0,
    /// Service not running
    NotRunning = 1,
    /// Log not found
    LogNotFound = 2,
    /// Source not found
    SourceNotFound = 3,
    /// Event not found
    EventNotFound = 4,
    /// Log full
    LogFull = 5,
    /// Access denied
    AccessDenied = 6,
    /// Invalid parameter
    InvalidParam = 7,
    /// Source already registered
    SourceExists = 8,
    /// Log already exists
    LogExists = 9,
}

// ============================================================================
// Event Entry
// ============================================================================

/// An event log entry
#[derive(Clone)]
pub struct EventEntry {
    /// Entry is valid
    pub valid: bool,
    /// Event record number
    pub record_number: u32,
    /// Event ID
    pub event_id: u32,
    /// Event type
    pub event_type: EventType,
    /// Event category
    pub category: u16,
    /// Source name
    pub source: [u8; MAX_SOURCE_NAME],
    /// Computer name
    pub computer: [u8; 32],
    /// User SID (simplified as u32)
    pub user_sid: u32,
    /// Timestamp (NT time)
    pub timestamp: i64,
    /// Description
    pub description: [u8; MAX_DESCRIPTION],
    /// Description length
    pub desc_len: usize,
    /// Binary data
    pub data: [u8; MAX_DATA_SIZE],
    /// Data length
    pub data_len: usize,
}

impl EventEntry {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            record_number: 0,
            event_id: 0,
            event_type: EventType::Information,
            category: 0,
            source: [0; MAX_SOURCE_NAME],
            computer: [0; 32],
            user_sid: 0,
            timestamp: 0,
            description: [0; MAX_DESCRIPTION],
            desc_len: 0,
            data: [0; MAX_DATA_SIZE],
            data_len: 0,
        }
    }

    pub fn source_str(&self) -> &str {
        let len = self.source.iter().position(|&b| b == 0).unwrap_or(MAX_SOURCE_NAME);
        core::str::from_utf8(&self.source[..len]).unwrap_or("")
    }

    pub fn set_source(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_SOURCE_NAME);
        self.source[..len].copy_from_slice(&bytes[..len]);
        if len < MAX_SOURCE_NAME {
            self.source[len..].fill(0);
        }
    }

    pub fn description_str(&self) -> &str {
        core::str::from_utf8(&self.description[..self.desc_len]).unwrap_or("")
    }

    pub fn set_description(&mut self, desc: &str) {
        let bytes = desc.as_bytes();
        let len = bytes.len().min(MAX_DESCRIPTION);
        self.description[..len].copy_from_slice(&bytes[..len]);
        self.desc_len = len;
    }

    pub fn computer_str(&self) -> &str {
        let len = self.computer.iter().position(|&b| b == 0).unwrap_or(32);
        core::str::from_utf8(&self.computer[..len]).unwrap_or("")
    }

    pub fn set_computer(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(32);
        self.computer[..len].copy_from_slice(&bytes[..len]);
        if len < 32 {
            self.computer[len..].fill(0);
        }
    }
}

// ============================================================================
// Event Source
// ============================================================================

/// An event source registration
#[derive(Clone)]
pub struct EventSource {
    /// Entry is valid
    pub valid: bool,
    /// Source name
    pub name: [u8; MAX_SOURCE_NAME],
    /// Log this source writes to
    pub log_index: usize,
    /// Category count
    pub category_count: u32,
    /// Supports types
    pub types_supported: u32,
}

impl EventSource {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            name: [0; MAX_SOURCE_NAME],
            log_index: 0,
            category_count: 0,
            types_supported: 0xFFFF,
        }
    }

    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(MAX_SOURCE_NAME);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_SOURCE_NAME);
        self.name[..len].copy_from_slice(&bytes[..len]);
        if len < MAX_SOURCE_NAME {
            self.name[len..].fill(0);
        }
    }
}

// ============================================================================
// Event Log
// ============================================================================

/// An event log
#[derive(Clone)]
pub struct EventLog {
    /// Log is valid/active
    pub valid: bool,
    /// Log name
    pub name: [u8; MAX_LOG_NAME],
    /// Log type
    pub log_type: LogType,
    /// Events (circular buffer)
    pub events: [EventEntry; MAX_EVENTS],
    /// Write index (next position to write)
    pub write_index: usize,
    /// Event count
    pub event_count: usize,
    /// Next record number
    pub next_record: u32,
    /// Maximum log size (events)
    pub max_size: usize,
    /// Retention days (0 = forever)
    pub retention_days: u32,
    /// Overwrite old events when full
    pub overwrite_old: bool,
    /// Read-only
    pub read_only: bool,
}

impl EventLog {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            name: [0; MAX_LOG_NAME],
            log_type: LogType::Application,
            events: [const { EventEntry::empty() }; MAX_EVENTS],
            write_index: 0,
            event_count: 0,
            next_record: 1,
            max_size: MAX_EVENTS,
            retention_days: 0,
            overwrite_old: true,
            read_only: false,
        }
    }

    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(MAX_LOG_NAME);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_LOG_NAME);
        self.name[..len].copy_from_slice(&bytes[..len]);
        if len < MAX_LOG_NAME {
            self.name[len..].fill(0);
        }
    }
}

// ============================================================================
// Service State
// ============================================================================

/// Event log service state
struct EventLogState {
    /// Service running
    running: bool,
    /// Event logs
    logs: [EventLog; MAX_LOGS],
    /// Log count
    log_count: usize,
    /// Event sources
    sources: [EventSource; MAX_SOURCES],
    /// Source count
    source_count: usize,
    /// Computer name
    computer_name: [u8; 32],
}

impl EventLogState {
    const fn new() -> Self {
        Self {
            running: false,
            logs: [const { EventLog::empty() }; MAX_LOGS],
            log_count: 0,
            sources: [const { EventSource::empty() }; MAX_SOURCES],
            source_count: 0,
            computer_name: [0; 32],
        }
    }
}

static EVENTLOG_STATE: SpinLock<EventLogState> = SpinLock::new(EventLogState::new());

/// Statistics
struct EventLogStats {
    /// Events written
    events_written: AtomicU64,
    /// Events overwritten
    events_overwritten: AtomicU64,
    /// Events cleared
    events_cleared: AtomicU64,
    /// Error events
    error_events: AtomicU64,
    /// Warning events
    warning_events: AtomicU64,
    /// Information events
    info_events: AtomicU64,
    /// Audit events
    audit_events: AtomicU64,
}

impl EventLogStats {
    const fn new() -> Self {
        Self {
            events_written: AtomicU64::new(0),
            events_overwritten: AtomicU64::new(0),
            events_cleared: AtomicU64::new(0),
            error_events: AtomicU64::new(0),
            warning_events: AtomicU64::new(0),
            info_events: AtomicU64::new(0),
            audit_events: AtomicU64::new(0),
        }
    }
}

static EVENTLOG_STATS: EventLogStats = EventLogStats::new();

// ============================================================================
// Log Management
// ============================================================================

/// Create an event log
pub fn create_log(name: &str, log_type: LogType) -> Result<usize, EventLogError> {
    let mut state = EVENTLOG_STATE.lock();

    if !state.running {
        return Err(EventLogError::NotRunning);
    }

    // Check for duplicate
    for i in 0..MAX_LOGS {
        if state.logs[i].valid && state.logs[i].name_str() == name {
            return Err(EventLogError::LogExists);
        }
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_LOGS {
        if !state.logs[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(EventLogError::LogFull),
    };

    let log = &mut state.logs[slot];
    log.valid = true;
    log.set_name(name);
    log.log_type = log_type;
    log.write_index = 0;
    log.event_count = 0;
    log.next_record = 1;
    log.max_size = MAX_EVENTS;
    log.overwrite_old = true;
    log.read_only = false;

    state.log_count += 1;

    crate::serial_println!("[EVENTLOG] Created log '{}'", name);

    Ok(slot)
}

/// Open an event log by name
pub fn open_log(name: &str) -> Option<usize> {
    let state = EVENTLOG_STATE.lock();

    for i in 0..MAX_LOGS {
        if state.logs[i].valid && state.logs[i].name_str() == name {
            return Some(i);
        }
    }

    None
}

/// Open an event log by type
pub fn open_log_by_type(log_type: LogType) -> Option<usize> {
    let state = EVENTLOG_STATE.lock();

    for i in 0..MAX_LOGS {
        if state.logs[i].valid && state.logs[i].log_type == log_type {
            return Some(i);
        }
    }

    None
}

/// Clear an event log
pub fn clear_log(log_index: usize) -> Result<usize, EventLogError> {
    let mut state = EVENTLOG_STATE.lock();

    if log_index >= MAX_LOGS || !state.logs[log_index].valid {
        return Err(EventLogError::LogNotFound);
    }

    if state.logs[log_index].read_only {
        return Err(EventLogError::AccessDenied);
    }

    let cleared = state.logs[log_index].event_count;

    // Clear all events
    for i in 0..MAX_EVENTS {
        state.logs[log_index].events[i].valid = false;
    }
    state.logs[log_index].write_index = 0;
    state.logs[log_index].event_count = 0;

    EVENTLOG_STATS.events_cleared.fetch_add(cleared as u64, Ordering::Relaxed);

    crate::serial_println!("[EVENTLOG] Cleared {} events from '{}'",
        cleared, state.logs[log_index].name_str());

    Ok(cleared)
}

/// Get log count
pub fn get_log_count() -> usize {
    let state = EVENTLOG_STATE.lock();
    state.log_count
}

// ============================================================================
// Source Management
// ============================================================================

/// Register an event source
pub fn register_source(name: &str, log_name: &str) -> Result<usize, EventLogError> {
    let mut state = EVENTLOG_STATE.lock();

    if !state.running {
        return Err(EventLogError::NotRunning);
    }

    // Find the log
    let mut log_index = None;
    for i in 0..MAX_LOGS {
        if state.logs[i].valid && state.logs[i].name_str() == log_name {
            log_index = Some(i);
            break;
        }
    }

    let log_index = match log_index {
        Some(i) => i,
        None => return Err(EventLogError::LogNotFound),
    };

    // Check for duplicate
    for i in 0..MAX_SOURCES {
        if state.sources[i].valid && state.sources[i].name_str() == name {
            return Err(EventLogError::SourceExists);
        }
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_SOURCES {
        if !state.sources[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(EventLogError::LogFull),
    };

    let source = &mut state.sources[slot];
    source.valid = true;
    source.set_name(name);
    source.log_index = log_index;
    source.category_count = 0;
    source.types_supported = 0xFFFF;

    state.source_count += 1;

    Ok(slot)
}

/// Unregister an event source
pub fn unregister_source(name: &str) -> Result<(), EventLogError> {
    let mut state = EVENTLOG_STATE.lock();

    for i in 0..MAX_SOURCES {
        if state.sources[i].valid && state.sources[i].name_str() == name {
            state.sources[i].valid = false;
            state.source_count = state.source_count.saturating_sub(1);
            return Ok(());
        }
    }

    Err(EventLogError::SourceNotFound)
}

/// Get source count
pub fn get_source_count() -> usize {
    let state = EVENTLOG_STATE.lock();
    state.source_count
}

// ============================================================================
// Event Writing
// ============================================================================

/// Write an event to a log
pub fn write_event(
    log_index: usize,
    source: &str,
    event_id: u32,
    event_type: EventType,
    category: u16,
    description: &str,
) -> Result<u32, EventLogError> {
    let mut state = EVENTLOG_STATE.lock();

    if !state.running {
        return Err(EventLogError::NotRunning);
    }

    if log_index >= MAX_LOGS || !state.logs[log_index].valid {
        return Err(EventLogError::LogNotFound);
    }

    if state.logs[log_index].read_only {
        return Err(EventLogError::AccessDenied);
    }

    // Copy computer name before mutable borrow
    let mut computer = [0u8; 32];
    computer.copy_from_slice(&state.computer_name);

    let log = &mut state.logs[log_index];

    // Check if we need to overwrite
    let overwritten = if log.event_count >= log.max_size {
        if !log.overwrite_old {
            return Err(EventLogError::LogFull);
        }
        true
    } else {
        false
    };

    let write_idx = log.write_index;
    let record_num = log.next_record;

    let event = &mut log.events[write_idx];
    event.valid = true;
    event.record_number = record_num;
    event.event_id = event_id;
    event.event_type = event_type;
    event.category = category;
    event.set_source(source);
    event.computer = computer;
    event.user_sid = 0; // SYSTEM
    event.timestamp = crate::rtl::time::rtl_get_system_time();
    event.set_description(description);
    event.data_len = 0;

    log.write_index = (log.write_index + 1) % log.max_size;
    log.next_record += 1;
    if log.event_count < log.max_size {
        log.event_count += 1;
    }

    // Update statistics
    EVENTLOG_STATS.events_written.fetch_add(1, Ordering::Relaxed);

    if overwritten {
        EVENTLOG_STATS.events_overwritten.fetch_add(1, Ordering::Relaxed);
    }

    match event_type {
        EventType::Error => {
            EVENTLOG_STATS.error_events.fetch_add(1, Ordering::Relaxed);
        }
        EventType::Warning => {
            EVENTLOG_STATS.warning_events.fetch_add(1, Ordering::Relaxed);
        }
        EventType::Information | EventType::Verbose => {
            EVENTLOG_STATS.info_events.fetch_add(1, Ordering::Relaxed);
        }
        EventType::AuditSuccess | EventType::AuditFailure => {
            EVENTLOG_STATS.audit_events.fetch_add(1, Ordering::Relaxed);
        }
    }

    Ok(record_num)
}

/// Write event by source name (finds the log automatically)
pub fn report_event(
    source_name: &str,
    event_id: u32,
    event_type: EventType,
    category: u16,
    description: &str,
) -> Result<u32, EventLogError> {
    let state = EVENTLOG_STATE.lock();

    // Find source
    let mut log_index = None;
    for i in 0..MAX_SOURCES {
        if state.sources[i].valid && state.sources[i].name_str() == source_name {
            log_index = Some(state.sources[i].log_index);
            break;
        }
    }

    let log_index = match log_index {
        Some(i) => i,
        None => return Err(EventLogError::SourceNotFound),
    };

    drop(state);

    write_event(log_index, source_name, event_id, event_type, category, description)
}

// ============================================================================
// Event Reading
// ============================================================================

/// Get event count in a log
pub fn get_event_count(log_index: usize) -> usize {
    let state = EVENTLOG_STATE.lock();

    if log_index >= MAX_LOGS || !state.logs[log_index].valid {
        return 0;
    }

    state.logs[log_index].event_count
}

/// Get oldest record number
pub fn get_oldest_record(log_index: usize) -> u32 {
    let state = EVENTLOG_STATE.lock();

    if log_index >= MAX_LOGS || !state.logs[log_index].valid {
        return 0;
    }

    let log = &state.logs[log_index];
    if log.event_count == 0 {
        return 0;
    }

    // Find oldest valid event
    let start = if log.event_count >= log.max_size {
        log.write_index
    } else {
        0
    };

    if state.logs[log_index].events[start].valid {
        state.logs[log_index].events[start].record_number
    } else {
        0
    }
}

/// Get newest record number
pub fn get_newest_record(log_index: usize) -> u32 {
    let state = EVENTLOG_STATE.lock();

    if log_index >= MAX_LOGS || !state.logs[log_index].valid {
        return 0;
    }

    let log = &state.logs[log_index];
    if log.event_count == 0 {
        return 0;
    }

    log.next_record - 1
}

/// Read an event by record number
pub fn read_event(log_index: usize, record_number: u32) -> Option<EventEntry> {
    let state = EVENTLOG_STATE.lock();

    if log_index >= MAX_LOGS || !state.logs[log_index].valid {
        return None;
    }

    for i in 0..MAX_EVENTS {
        let event = &state.logs[log_index].events[i];
        if event.valid && event.record_number == record_number {
            return Some(event.clone());
        }
    }

    None
}

/// Read events by type
pub fn read_events_by_type(
    log_index: usize,
    event_type: EventType,
    out: &mut [EventEntry],
) -> usize {
    let state = EVENTLOG_STATE.lock();

    if log_index >= MAX_LOGS || !state.logs[log_index].valid {
        return 0;
    }

    let mut count = 0;
    for i in 0..MAX_EVENTS {
        if count >= out.len() {
            break;
        }
        let event = &state.logs[log_index].events[i];
        if event.valid && event.event_type == event_type {
            out[count] = event.clone();
            count += 1;
        }
    }

    count
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Log an error event
pub fn log_error(source: &str, event_id: u32, message: &str) -> Result<u32, EventLogError> {
    if let Some(log_idx) = open_log_by_type(LogType::Application) {
        write_event(log_idx, source, event_id, EventType::Error, 0, message)
    } else {
        Err(EventLogError::LogNotFound)
    }
}

/// Log a warning event
pub fn log_warning(source: &str, event_id: u32, message: &str) -> Result<u32, EventLogError> {
    if let Some(log_idx) = open_log_by_type(LogType::Application) {
        write_event(log_idx, source, event_id, EventType::Warning, 0, message)
    } else {
        Err(EventLogError::LogNotFound)
    }
}

/// Log an informational event
pub fn log_info(source: &str, event_id: u32, message: &str) -> Result<u32, EventLogError> {
    if let Some(log_idx) = open_log_by_type(LogType::Application) {
        write_event(log_idx, source, event_id, EventType::Information, 0, message)
    } else {
        Err(EventLogError::LogNotFound)
    }
}

/// Log a system event
pub fn log_system_event(source: &str, event_id: u32, event_type: EventType, message: &str) -> Result<u32, EventLogError> {
    if let Some(log_idx) = open_log_by_type(LogType::System) {
        write_event(log_idx, source, event_id, event_type, 0, message)
    } else {
        Err(EventLogError::LogNotFound)
    }
}

/// Log a security audit event
pub fn log_security_event(
    source: &str,
    event_id: u32,
    success: bool,
    message: &str,
) -> Result<u32, EventLogError> {
    if let Some(log_idx) = open_log_by_type(LogType::Security) {
        let event_type = if success {
            EventType::AuditSuccess
        } else {
            EventType::AuditFailure
        };
        write_event(log_idx, source, event_id, event_type, 0, message)
    } else {
        Err(EventLogError::LogNotFound)
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Get event log statistics
pub fn get_statistics() -> (u64, u64, u64, u64, u64, u64, u64) {
    (
        EVENTLOG_STATS.events_written.load(Ordering::Relaxed),
        EVENTLOG_STATS.events_overwritten.load(Ordering::Relaxed),
        EVENTLOG_STATS.events_cleared.load(Ordering::Relaxed),
        EVENTLOG_STATS.error_events.load(Ordering::Relaxed),
        EVENTLOG_STATS.warning_events.load(Ordering::Relaxed),
        EVENTLOG_STATS.info_events.load(Ordering::Relaxed),
        EVENTLOG_STATS.audit_events.load(Ordering::Relaxed),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = EVENTLOG_STATE.lock();
    state.running
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialized flag
static EVENTLOG_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the Event Log service
pub fn init() {
    if EVENTLOG_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[EVENTLOG] Initializing Event Log Service...");

    {
        let mut state = EVENTLOG_STATE.lock();
        state.running = true;

        // Set computer name
        let name = b"NOSTALGIAOS";
        state.computer_name[..name.len()].copy_from_slice(name);
    }

    // Create default logs
    let _ = create_log("Application", LogType::Application);
    let _ = create_log("Security", LogType::Security);
    let _ = create_log("System", LogType::System);
    let _ = create_log("Setup", LogType::Setup);

    // Register default sources
    let _ = register_source("Application", "Application");
    let _ = register_source("Security", "Security");
    let _ = register_source("System", "System");
    let _ = register_source("Service Control Manager", "System");
    let _ = register_source("EventLog", "System");
    let _ = register_source("Kernel", "System");
    let _ = register_source("Disk", "System");
    let _ = register_source("Ntfs", "System");
    let _ = register_source("Windows Update", "System");
    let _ = register_source("Print Spooler", "System");

    // Log startup event
    if let Some(log_idx) = open_log_by_type(LogType::System) {
        let _ = write_event(
            log_idx,
            "EventLog",
            6005,
            EventType::Information,
            0,
            "The Event Log service was started.",
        );
    }

    crate::serial_println!("[EVENTLOG] Event Log Service initialized");
    crate::serial_println!("[EVENTLOG]   Logs: 4");
    crate::serial_println!("[EVENTLOG]   Sources: 10");
}
