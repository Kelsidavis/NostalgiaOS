//! Event Tracing for Windows (ETW) Subsystem
//!
//! ETW provides a low-overhead, high-throughput event tracing infrastructure
//! for kernel and user-mode components. This is used for performance analysis,
//! debugging, and system monitoring.
//!
//! # Architecture
//!
//! - **Logger Sessions**: Named trace sessions that collect events
//! - **Providers**: Components that generate trace events
//! - **Controllers**: Manage trace sessions (start, stop, query)
//! - **Consumers**: Read trace events from sessions
//!
//! # Reference
//!
//! Based on Windows Server 2003 WMI/ETW implementation from base/ntos/wmi/

mod buffer;
mod event;
mod logger;
mod provider;

pub use buffer::*;
pub use event::*;
pub use logger::*;
pub use provider::*;

use crate::ke::SpinLock;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

extern crate alloc;

/// GUID structure for identifying providers and events
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    pub const fn zero() -> Self {
        Self {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        }
    }

    /// Parse GUID from bytes (16 bytes, little-endian)
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.len() < 16 {
            return Self::zero();
        }

        Self {
            data1: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            data2: u16::from_le_bytes([data[4], data[5]]),
            data3: u16::from_le_bytes([data[6], data[7]]),
            data4: [
                data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
            ],
        }
    }

    /// Write GUID to bytes (16 bytes, little-endian)
    pub fn to_bytes(&self, data: &mut [u8]) {
        if data.len() < 16 {
            return;
        }

        data[0..4].copy_from_slice(&self.data1.to_le_bytes());
        data[4..6].copy_from_slice(&self.data2.to_le_bytes());
        data[6..8].copy_from_slice(&self.data3.to_le_bytes());
        data[8..16].copy_from_slice(&self.data4);
    }
}

impl PartialOrd for Guid {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Guid {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match self.data1.cmp(&other.data1) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.data2.cmp(&other.data2) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.data3.cmp(&other.data3) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        self.data4.cmp(&other.data4)
    }
}

/// Well-known provider GUIDs
pub mod providers {
    use super::Guid;

    /// Kernel trace provider - process events
    pub const KERNEL_PROCESS: Guid = Guid::new(
        0x3D6FA8D0,
        0xFE05,
        0x11D0,
        [0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xD7, 0xBA, 0x7C],
    );

    /// Kernel trace provider - thread events
    pub const KERNEL_THREAD: Guid = Guid::new(
        0x3D6FA8D1,
        0xFE05,
        0x11D0,
        [0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xD7, 0xBA, 0x7C],
    );

    /// Kernel trace provider - disk I/O events
    pub const KERNEL_DISK_IO: Guid = Guid::new(
        0x3D6FA8D4,
        0xFE05,
        0x11D0,
        [0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xD7, 0xBA, 0x7C],
    );

    /// Kernel trace provider - file I/O events
    pub const KERNEL_FILE_IO: Guid = Guid::new(
        0x90CBDC39,
        0x4A3E,
        0x11D1,
        [0x84, 0xF4, 0x00, 0x00, 0xF8, 0x04, 0x64, 0xE3],
    );

    /// Kernel trace provider - network events
    pub const KERNEL_NETWORK: Guid = Guid::new(
        0x9A280AC0,
        0xC8E0,
        0x11D1,
        [0x84, 0xE2, 0x00, 0xC0, 0x4F, 0xB9, 0x98, 0xA2],
    );

    /// Kernel trace provider - registry events
    pub const KERNEL_REGISTRY: Guid = Guid::new(
        0xAE53722E,
        0xC863,
        0x11D2,
        [0x86, 0x59, 0x00, 0xC0, 0x4F, 0xA3, 0x21, 0xA1],
    );

    /// Kernel trace provider - page fault events
    pub const KERNEL_PAGE_FAULT: Guid = Guid::new(
        0x3D6FA8D3,
        0xFE05,
        0x11D0,
        [0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xD7, 0xBA, 0x7C],
    );

    /// Kernel trace provider - memory events
    pub const KERNEL_MEMORY: Guid = Guid::new(
        0x3D6FA8D2,
        0xFE05,
        0x11D0,
        [0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xD7, 0xBA, 0x7C],
    );
}

/// Clock type for event timestamps
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClockType {
    /// Query performance counter
    #[default]
    QueryPerformanceCounter = 1,
    /// System time
    SystemTime = 2,
    /// CPU cycle counter
    CpuCycle = 3,
}

/// Trace handle (opaque)
pub type TraceHandle = u64;

/// Invalid trace handle constant
pub const INVALID_TRACE_HANDLE: TraceHandle = 0;

/// Maximum number of concurrent logger sessions
pub const MAX_LOGGER_SESSIONS: usize = 64;

/// Maximum provider name length
pub const MAX_PROVIDER_NAME: usize = 256;

/// Global ETW state
static ETW_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NEXT_LOGGER_ID: AtomicU32 = AtomicU32::new(1);

/// ETW subsystem global state
pub struct EtwState {
    /// Active logger sessions (ID -> Logger)
    loggers: SpinLock<BTreeMap<u32, Arc<LoggerSession>>>,
    /// Registered providers (GUID -> Provider)
    providers: SpinLock<BTreeMap<Guid, Arc<TraceProvider>>>,
    /// Named loggers for lookup
    named_loggers: SpinLock<BTreeMap<[u16; 64], u32>>,
}

impl EtwState {
    pub const fn new() -> Self {
        Self {
            loggers: SpinLock::new(BTreeMap::new()),
            providers: SpinLock::new(BTreeMap::new()),
            named_loggers: SpinLock::new(BTreeMap::new()),
        }
    }
}

static mut ETW_STATE: Option<EtwState> = None;

fn get_etw_state() -> &'static EtwState {
    unsafe { ETW_STATE.as_ref().expect("ETW not initialized") }
}

/// Initialize the ETW subsystem
pub fn etw_initialize() {
    if ETW_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return; // Already initialized
    }

    unsafe {
        ETW_STATE = Some(EtwState::new());
    }

    crate::serial_println!("[ETW] Event Tracing for Windows initialized");
}

/// Start a trace session
pub fn wmi_start_trace(info: &mut LoggerInformation) -> Result<TraceHandle, NtStatus> {
    let state = get_etw_state();

    // Allocate logger ID
    let logger_id = NEXT_LOGGER_ID.fetch_add(1, Ordering::SeqCst);
    if logger_id >= MAX_LOGGER_SESSIONS as u32 {
        return Err(NtStatus::InsufficientResources);
    }

    // Create logger session
    let session = Arc::new(LoggerSession::new(logger_id, info)?);

    // Register in global state
    {
        let mut loggers = state.loggers.lock();
        loggers.insert(logger_id, session.clone());
    }

    // Register name if provided (check if not all zeros)
    let has_name = info.logger_name.iter().any(|&c| c != 0);
    if has_name {
        let mut named = state.named_loggers.lock();
        named.insert(info.logger_name, logger_id);
    }

    info.logger_handle = logger_id as u64;
    Ok(logger_id as u64)
}

/// Query a trace session
pub fn wmi_query_trace(info: &mut LoggerInformation) -> Result<(), NtStatus> {
    let state = get_etw_state();

    let loggers = state.loggers.lock();
    let session = loggers
        .get(&(info.logger_handle as u32))
        .ok_or(NtStatus::InvalidHandle)?;

    session.fill_info(info);
    Ok(())
}

/// Stop a trace session
pub fn wmi_stop_trace(info: &LoggerInformation) -> Result<(), NtStatus> {
    let state = get_etw_state();

    let logger_id = info.logger_handle as u32;

    // Remove from loggers
    {
        let mut loggers = state.loggers.lock();
        let session = loggers.remove(&logger_id).ok_or(NtStatus::InvalidHandle)?;
        session.stop();
    }

    Ok(())
}

/// Flush trace buffers
pub fn wmi_flush_trace(info: &LoggerInformation) -> Result<(), NtStatus> {
    let state = get_etw_state();

    let loggers = state.loggers.lock();
    let session = loggers
        .get(&(info.logger_handle as u32))
        .ok_or(NtStatus::InvalidHandle)?;

    session.flush();
    Ok(())
}

/// Trace an event (fast path)
pub fn wmi_trace_event(header: &WnodeHeader) -> Result<(), NtStatus> {
    let state = get_etw_state();

    // Find logger for this event
    let loggers = state.loggers.lock();

    for (_id, session) in loggers.iter() {
        if session.is_enabled() && session.accepts_provider(&header.guid) {
            session.log_event(header)?;
        }
    }

    Ok(())
}

/// Register a trace provider
pub fn etw_register_provider(
    guid: &Guid,
    callback: ProviderEnableCallback,
    context: usize,
) -> Result<ProviderHandle, NtStatus> {
    let state = get_etw_state();

    let provider = Arc::new(TraceProvider::new(*guid, callback, context));
    let handle = provider.handle();

    {
        let mut providers = state.providers.lock();
        providers.insert(*guid, provider);
    }

    Ok(handle)
}

/// Unregister a trace provider
pub fn etw_unregister_provider(handle: ProviderHandle) -> Result<(), NtStatus> {
    let state = get_etw_state();

    let mut providers = state.providers.lock();

    // Find and remove provider by handle
    let mut to_remove = None;
    for (guid, provider) in providers.iter() {
        if provider.handle() == handle {
            to_remove = Some(*guid);
            break;
        }
    }

    if let Some(guid) = to_remove {
        providers.remove(&guid);
        Ok(())
    } else {
        Err(NtStatus::InvalidHandle)
    }
}

/// Write a trace event from a provider
pub fn etw_write_event(
    handle: ProviderHandle,
    _descriptor: &EventDescriptor,
    data: &[u8],
) -> Result<(), NtStatus> {
    let state = get_etw_state();

    // Find provider
    let providers = state.providers.lock();
    let provider = providers
        .values()
        .find(|p| p.handle() == handle)
        .ok_or(NtStatus::InvalidHandle)?;

    if !provider.is_enabled() {
        return Ok(()); // Provider not enabled, silently succeed
    }

    // Create event and log it
    let header = WnodeHeader {
        buffer_size: core::mem::size_of::<WnodeHeader>() as u32 + data.len() as u32,
        provider_id: 0,
        timestamp: crate::hal::rtc::get_system_time(),
        guid: provider.guid(),
        client_context: 0,
        flags: WnodeFlags::TRACED_GUID,
    };

    wmi_trace_event(&header)?;
    Ok(())
}

/// Get clock value for tracing
pub fn wmi_get_clock(clock_type: ClockType) -> i64 {
    match clock_type {
        ClockType::QueryPerformanceCounter => {
            // Use TSC as performance counter
            #[cfg(target_arch = "x86_64")]
            unsafe {
                core::arch::x86_64::_rdtsc() as i64
            }
            #[cfg(not(target_arch = "x86_64"))]
            0i64
        }
        ClockType::SystemTime => crate::hal::rtc::get_system_time() as i64,
        ClockType::CpuCycle => {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                core::arch::x86_64::_rdtsc() as i64
            }
            #[cfg(not(target_arch = "x86_64"))]
            0i64
        }
    }
}

/// Query trace information
pub fn wmi_query_trace_information(
    class: TraceInformationClass,
    info: &mut [u8],
) -> Result<usize, NtStatus> {
    let state = get_etw_state();

    match class {
        TraceInformationClass::AllLoggerHandlesClass => {
            let loggers = state.loggers.lock();
            let handles: Vec<u64> = loggers.keys().map(|&k| k as u64).collect();
            let size = handles.len() * 8;

            if info.len() < size {
                return Err(NtStatus::BufferTooSmall);
            }

            for (i, handle) in handles.iter().enumerate() {
                let offset = i * 8;
                info[offset..offset + 8].copy_from_slice(&handle.to_le_bytes());
            }

            Ok(size)
        }
        _ => Err(NtStatus::NotImplemented),
    }
}

/// Trace information class
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum TraceInformationClass {
    TraceIdClass = 0,
    TraceHandleClass = 1,
    TraceEnableFlagsClass = 2,
    TraceEnableLevelClass = 3,
    GlobalLoggerHandleClass = 4,
    EventLoggerHandleClass = 5,
    AllLoggerHandlesClass = 6,
    TraceHandleByNameClass = 7,
}

/// NT status codes for ETW
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtStatus {
    Success = 0,
    Unsuccessful = -1073741823,       // 0xC0000001
    NotImplemented = -1073741822,     // 0xC0000002
    InvalidInfoClass = -1073741821,   // 0xC0000003
    InfoLengthMismatch = -1073741820, // 0xC0000004
    InvalidHandle = -1073741816,      // 0xC0000008
    InvalidParameter = -1073741811,   // 0xC000000D
    AccessDenied = -1073741790,       // 0xC0000022
    BufferTooSmall = -1073741789,     // 0xC0000023
    ObjectNameNotFound = -1073741772, // 0xC0000034
    InsufficientResources = -1073741670, // 0xC000009A
}

/// ETW statistics
#[derive(Debug, Default)]
pub struct EtwStatistics {
    /// Number of active logger sessions
    pub active_sessions: u32,
    /// Number of registered providers
    pub registered_providers: u32,
    /// Total events logged
    pub total_events: u64,
    /// Total bytes logged
    pub total_bytes: u64,
    /// Events dropped (buffer full)
    pub events_dropped: u64,
}

/// Get ETW statistics
pub fn etw_get_statistics() -> EtwStatistics {
    let state = get_etw_state();

    let loggers = state.loggers.lock();
    let providers = state.providers.lock();

    let mut stats = EtwStatistics {
        active_sessions: loggers.len() as u32,
        registered_providers: providers.len() as u32,
        ..Default::default()
    };

    for session in loggers.values() {
        let session_stats = session.get_statistics();
        stats.total_events += session_stats.events_logged;
        stats.total_bytes += session_stats.bytes_logged;
        stats.events_dropped += session_stats.events_dropped;
    }

    stats
}
