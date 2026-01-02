//! Event Viewer
//!
//! Implements the Event Viewer dialog following Windows Server 2003.
//! Provides event log viewing, filtering, and management.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - eventvwr.msc - Event Viewer MMC snap-in
//! - advapi32.dll - Event logging API
//! - Event Log service

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum event logs
const MAX_LOGS: usize = 8;

/// Maximum events per log
const MAX_EVENTS: usize = 1000;

/// Maximum log name length
const MAX_NAME: usize = 64;

/// Maximum source name length
const MAX_SOURCE: usize = 64;

/// Maximum message length
const MAX_MESSAGE: usize = 512;

/// Maximum computer name length
const MAX_COMPUTER: usize = 64;

/// Maximum user name length
const MAX_USER: usize = 64;

// ============================================================================
// Event Type
// ============================================================================

/// Event type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EventType {
    /// Error event
    Error = 1,
    /// Warning event
    Warning = 2,
    /// Information event
    #[default]
    Information = 4,
    /// Success audit
    AuditSuccess = 8,
    /// Failure audit
    AuditFailure = 16,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::Error => "Error",
            EventType::Warning => "Warning",
            EventType::Information => "Information",
            EventType::AuditSuccess => "Success Audit",
            EventType::AuditFailure => "Failure Audit",
        }
    }

    pub fn from_u32(val: u32) -> Self {
        match val {
            1 => EventType::Error,
            2 => EventType::Warning,
            4 => EventType::Information,
            8 => EventType::AuditSuccess,
            16 => EventType::AuditFailure,
            _ => EventType::Information,
        }
    }
}

// ============================================================================
// Event Category
// ============================================================================

/// Event category constants for common Windows categories
pub mod event_category {
    pub const NONE: u16 = 0;
    pub const DEVICES: u16 = 1;
    pub const DISK: u16 = 2;
    pub const PRINTERS: u16 = 3;
    pub const SERVICES: u16 = 4;
    pub const SHELL: u16 = 5;
    pub const SYSTEM: u16 = 6;
    pub const NETWORK: u16 = 7;
}

// ============================================================================
// Event Entry
// ============================================================================

/// Event log entry
#[derive(Clone, Copy)]
pub struct EventEntry {
    /// Event ID
    pub event_id: u32,
    /// Event type
    pub event_type: EventType,
    /// Category
    pub category: u16,
    /// Source name
    pub source: [u8; MAX_SOURCE],
    /// Source length
    pub source_len: usize,
    /// Message
    pub message: [u8; MAX_MESSAGE],
    /// Message length
    pub message_len: usize,
    /// Computer name
    pub computer: [u8; MAX_COMPUTER],
    /// Computer length
    pub computer_len: usize,
    /// User name (if applicable)
    pub user: [u8; MAX_USER],
    /// User length
    pub user_len: usize,
    /// Timestamp (seconds since epoch)
    pub timestamp: u64,
    /// Data bytes (raw event data, truncated)
    pub data: [u8; 64],
    /// Data length
    pub data_len: usize,
}

impl EventEntry {
    pub const fn new() -> Self {
        Self {
            event_id: 0,
            event_type: EventType::Information,
            category: 0,
            source: [0u8; MAX_SOURCE],
            source_len: 0,
            message: [0u8; MAX_MESSAGE],
            message_len: 0,
            computer: [0u8; MAX_COMPUTER],
            computer_len: 0,
            user: [0u8; MAX_USER],
            user_len: 0,
            timestamp: 0,
            data: [0u8; 64],
            data_len: 0,
        }
    }

    pub fn set_source(&mut self, source: &[u8]) {
        let len = source.len().min(MAX_SOURCE);
        self.source[..len].copy_from_slice(&source[..len]);
        self.source_len = len;
    }

    pub fn set_message(&mut self, msg: &[u8]) {
        let len = msg.len().min(MAX_MESSAGE);
        self.message[..len].copy_from_slice(&msg[..len]);
        self.message_len = len;
    }

    pub fn set_computer(&mut self, comp: &[u8]) {
        let len = comp.len().min(MAX_COMPUTER);
        self.computer[..len].copy_from_slice(&comp[..len]);
        self.computer_len = len;
    }

    pub fn set_user(&mut self, user: &[u8]) {
        let len = user.len().min(MAX_USER);
        self.user[..len].copy_from_slice(&user[..len]);
        self.user_len = len;
    }
}

impl Default for EventEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Event Log
// ============================================================================

/// Event log
#[derive(Clone)]
pub struct EventLog {
    /// Log name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Log file path
    pub file_path: [u8; 260],
    /// File path length
    pub file_path_len: usize,
    /// Maximum log size in KB
    pub max_size_kb: u32,
    /// Retention days (0 = overwrite as needed)
    pub retention_days: u32,
    /// Events (circular buffer)
    events: [EventEntry; MAX_EVENTS],
    /// Event count
    event_count: usize,
    /// Write position (for circular buffer)
    write_pos: usize,
}

impl EventLog {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME],
            name_len: 0,
            file_path: [0u8; 260],
            file_path_len: 0,
            max_size_kb: 512,
            retention_days: 7,
            events: [const { EventEntry::new() }; MAX_EVENTS],
            event_count: 0,
            write_pos: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_file_path(&mut self, path: &[u8]) {
        let len = path.len().min(260);
        self.file_path[..len].copy_from_slice(&path[..len]);
        self.file_path_len = len;
    }

    pub fn add_event(&mut self, event: EventEntry) {
        self.events[self.write_pos] = event;
        self.write_pos = (self.write_pos + 1) % MAX_EVENTS;
        if self.event_count < MAX_EVENTS {
            self.event_count += 1;
        }
    }

    pub fn get_event(&self, index: usize) -> Option<&EventEntry> {
        if index < self.event_count {
            // Calculate actual position in circular buffer
            let pos = if self.event_count < MAX_EVENTS {
                index
            } else {
                (self.write_pos + index) % MAX_EVENTS
            };
            Some(&self.events[pos])
        } else {
            None
        }
    }

    pub fn clear(&mut self) {
        self.event_count = 0;
        self.write_pos = 0;
    }
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Event Viewer State
// ============================================================================

/// Event Viewer state
struct EventViewerState {
    /// Event logs
    logs: [EventLog; MAX_LOGS],
    /// Log count
    log_count: usize,
    /// Currently selected log
    selected_log: usize,
}

impl EventViewerState {
    pub const fn new() -> Self {
        Self {
            logs: [const { EventLog::new() }; MAX_LOGS],
            log_count: 0,
            selected_log: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static EVENTLOG_INITIALIZED: AtomicBool = AtomicBool::new(false);
static EVENTLOG_STATE: SpinLock<EventViewerState> = SpinLock::new(EventViewerState::new());

// Statistics
static TOTAL_EVENTS: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Event Viewer
pub fn init() {
    if EVENTLOG_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = EVENTLOG_STATE.lock();

    // Create standard Windows logs
    create_standard_logs(&mut state);

    // Add sample events
    add_sample_events(&mut state);

    crate::serial_println!("[WIN32K] Event Viewer initialized");
}

/// Create standard Windows event logs
fn create_standard_logs(state: &mut EventViewerState) {
    // Application log
    let mut app_log = EventLog::new();
    app_log.set_name(b"Application");
    app_log.set_file_path(b"%SystemRoot%\\System32\\config\\AppEvent.Evt");
    app_log.max_size_kb = 512;
    state.logs[0] = app_log;

    // Security log
    let mut sec_log = EventLog::new();
    sec_log.set_name(b"Security");
    sec_log.set_file_path(b"%SystemRoot%\\System32\\config\\SecEvent.Evt");
    sec_log.max_size_kb = 512;
    state.logs[1] = sec_log;

    // System log
    let mut sys_log = EventLog::new();
    sys_log.set_name(b"System");
    sys_log.set_file_path(b"%SystemRoot%\\System32\\config\\SysEvent.Evt");
    sys_log.max_size_kb = 512;
    state.logs[2] = sys_log;

    state.log_count = 3;
}

/// Add sample events
fn add_sample_events(state: &mut EventViewerState) {
    let computer = b"SERVER2003";
    let mut base_time: u64 = 1104537600; // Jan 1, 2005

    // System log events
    add_event_to_log(state, 2, 6005, EventType::Information, b"EventLog",
        b"The Event log service was started.", computer, base_time);
    base_time += 1;

    add_event_to_log(state, 2, 6009, EventType::Information, b"EventLog",
        b"Microsoft (R) Windows (R) 5.02. 3790 Service Pack 1 Uniprocessor Free.", computer, base_time);
    base_time += 1;

    add_event_to_log(state, 2, 7036, EventType::Information, b"Service Control Manager",
        b"The Plug and Play service entered the running state.", computer, base_time);
    base_time += 1;

    add_event_to_log(state, 2, 7036, EventType::Information, b"Service Control Manager",
        b"The Remote Procedure Call (RPC) service entered the running state.", computer, base_time);
    base_time += 1;

    add_event_to_log(state, 2, 7036, EventType::Information, b"Service Control Manager",
        b"The DHCP Client service entered the running state.", computer, base_time);
    base_time += 1;

    add_event_to_log(state, 2, 4, EventType::Information, b"Dhcp",
        b"Your computer has obtained a network address: 192.168.1.100", computer, base_time);
    base_time += 1;

    // Application log events
    add_event_to_log(state, 0, 1000, EventType::Information, b"Application",
        b"Application started successfully.", computer, base_time);
    base_time += 1;

    add_event_to_log(state, 0, 1001, EventType::Warning, b"Application Hang",
        b"The application explorer.exe stopped responding and was restarted.", computer, base_time);
    base_time += 1;

    add_event_to_log(state, 0, 1002, EventType::Error, b"Application Error",
        b"Faulting application notepad.exe, version 5.1.2600.2180, faulting module ntdll.dll", computer, base_time);
    base_time += 1;

    // Security log events
    add_event_to_log(state, 1, 528, EventType::AuditSuccess, b"Security",
        b"Successful Logon: User Name: Administrator Domain: SERVER2003 Logon Type: 2", computer, base_time);
    base_time += 1;

    add_event_to_log(state, 1, 538, EventType::AuditSuccess, b"Security",
        b"User Logoff: User Name: Administrator Domain: SERVER2003", computer, base_time);
    base_time += 1;

    add_event_to_log(state, 1, 529, EventType::AuditFailure, b"Security",
        b"Logon Failure: Reason: Unknown user name or bad password User Name: guest", computer, base_time);

    TOTAL_EVENTS.store(12, Ordering::Relaxed);
}

/// Helper to add event to specific log
fn add_event_to_log(state: &mut EventViewerState, log_index: usize, event_id: u32,
    event_type: EventType, source: &[u8], message: &[u8], computer: &[u8], timestamp: u64)
{
    if log_index >= state.log_count {
        return;
    }

    let mut event = EventEntry::new();
    event.event_id = event_id;
    event.event_type = event_type;
    event.set_source(source);
    event.set_message(message);
    event.set_computer(computer);
    event.timestamp = timestamp;

    state.logs[log_index].add_event(event);
}

// ============================================================================
// Log Enumeration
// ============================================================================

/// Get log count
pub fn get_log_count() -> usize {
    EVENTLOG_STATE.lock().log_count
}

/// Get log name by index
pub fn get_log_name(index: usize) -> Option<([u8; MAX_NAME], usize)> {
    let state = EVENTLOG_STATE.lock();
    if index < state.log_count {
        Some((state.logs[index].name, state.logs[index].name_len))
    } else {
        None
    }
}

/// Get event count in log
pub fn get_event_count(log_index: usize) -> usize {
    let state = EVENTLOG_STATE.lock();
    if log_index < state.log_count {
        state.logs[log_index].event_count
    } else {
        0
    }
}

/// Get event from log
pub fn get_event(log_index: usize, event_index: usize) -> Option<EventEntry> {
    let state = EVENTLOG_STATE.lock();
    if log_index < state.log_count {
        state.logs[log_index].get_event(event_index).copied()
    } else {
        None
    }
}

/// Find log by name
pub fn find_log(name: &[u8]) -> Option<usize> {
    let state = EVENTLOG_STATE.lock();
    for i in 0..state.log_count {
        let log = &state.logs[i];
        if log.name_len == name.len() && &log.name[..log.name_len] == name {
            return Some(i);
        }
    }
    None
}

// ============================================================================
// Event Writing
// ============================================================================

/// Write event to log
pub fn write_event(log_index: usize, event_id: u32, event_type: EventType,
    source: &[u8], message: &[u8]) -> bool
{
    let mut state = EVENTLOG_STATE.lock();
    if log_index >= state.log_count {
        return false;
    }

    let mut event = EventEntry::new();
    event.event_id = event_id;
    event.event_type = event_type;
    event.set_source(source);
    event.set_message(message);
    event.set_computer(b"SERVER2003");
    event.timestamp = 0; // Would use current time

    state.logs[log_index].add_event(event);
    TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);

    true
}

/// Write event to log by name
pub fn write_event_by_name(log_name: &[u8], event_id: u32, event_type: EventType,
    source: &[u8], message: &[u8]) -> bool
{
    if let Some(index) = find_log(log_name) {
        write_event(index, event_id, event_type, source, message)
    } else {
        false
    }
}

// ============================================================================
// Log Management
// ============================================================================

/// Clear event log
pub fn clear_log(log_index: usize) -> bool {
    let mut state = EVENTLOG_STATE.lock();
    if log_index >= state.log_count {
        return false;
    }

    state.logs[log_index].clear();
    true
}

/// Set log maximum size
pub fn set_log_max_size(log_index: usize, size_kb: u32) -> bool {
    let mut state = EVENTLOG_STATE.lock();
    if log_index >= state.log_count {
        return false;
    }

    state.logs[log_index].max_size_kb = size_kb;
    true
}

/// Set log retention
pub fn set_log_retention(log_index: usize, days: u32) -> bool {
    let mut state = EVENTLOG_STATE.lock();
    if log_index >= state.log_count {
        return false;
    }

    state.logs[log_index].retention_days = days;
    true
}

// ============================================================================
// Filtering
// ============================================================================

/// Filter events by type
pub fn filter_by_type(log_index: usize, event_type: EventType) -> ([usize; 256], usize) {
    let state = EVENTLOG_STATE.lock();
    let mut indices = [0usize; 256];
    let mut count = 0;

    if log_index >= state.log_count {
        return (indices, 0);
    }

    let log = &state.logs[log_index];
    for i in 0..log.event_count {
        if let Some(event) = log.get_event(i) {
            if event.event_type == event_type && count < 256 {
                indices[count] = i;
                count += 1;
            }
        }
    }

    (indices, count)
}

/// Filter events by source
pub fn filter_by_source(log_index: usize, source: &[u8]) -> ([usize; 256], usize) {
    let state = EVENTLOG_STATE.lock();
    let mut indices = [0usize; 256];
    let mut count = 0;

    if log_index >= state.log_count {
        return (indices, 0);
    }

    let log = &state.logs[log_index];
    for i in 0..log.event_count {
        if let Some(event) = log.get_event(i) {
            if event.source_len == source.len() &&
               &event.source[..event.source_len] == source && count < 256 {
                indices[count] = i;
                count += 1;
            }
        }
    }

    (indices, count)
}

/// Filter events by event ID
pub fn filter_by_event_id(log_index: usize, event_id: u32) -> ([usize; 256], usize) {
    let state = EVENTLOG_STATE.lock();
    let mut indices = [0usize; 256];
    let mut count = 0;

    if log_index >= state.log_count {
        return (indices, 0);
    }

    let log = &state.logs[log_index];
    for i in 0..log.event_count {
        if let Some(event) = log.get_event(i) {
            if event.event_id == event_id && count < 256 {
                indices[count] = i;
                count += 1;
            }
        }
    }

    (indices, count)
}

// ============================================================================
// Statistics
// ============================================================================

/// Event Viewer statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct EventViewerStats {
    pub initialized: bool,
    pub log_count: usize,
    pub total_events: u32,
    pub error_count: u32,
    pub warning_count: u32,
    pub info_count: u32,
}

/// Get Event Viewer statistics
pub fn get_stats() -> EventViewerStats {
    let state = EVENTLOG_STATE.lock();
    let mut errors = 0u32;
    let mut warnings = 0u32;
    let mut infos = 0u32;

    for l in 0..state.log_count {
        let log = &state.logs[l];
        for i in 0..log.event_count {
            if let Some(event) = log.get_event(i) {
                match event.event_type {
                    EventType::Error => errors += 1,
                    EventType::Warning => warnings += 1,
                    EventType::Information => infos += 1,
                    _ => {}
                }
            }
        }
    }

    EventViewerStats {
        initialized: EVENTLOG_INITIALIZED.load(Ordering::Relaxed),
        log_count: state.log_count,
        total_events: TOTAL_EVENTS.load(Ordering::Relaxed),
        error_count: errors,
        warning_count: warnings,
        info_count: infos,
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Event Viewer dialog handle
pub type HEVENTVIEWERDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Event Viewer dialog
pub fn create_eventviewer_dialog(_parent: super::super::HWND) -> HEVENTVIEWERDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}

/// Log properties tab
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogPropertiesTab {
    /// General tab
    #[default]
    General = 0,
    /// Filter tab
    Filter = 1,
}

/// Get properties tab count
pub fn get_properties_tab_count() -> u32 {
    2
}

/// Get properties tab name
pub fn get_properties_tab_name(tab: LogPropertiesTab) -> &'static str {
    match tab {
        LogPropertiesTab::General => "General",
        LogPropertiesTab::Filter => "Filter",
    }
}
