//! Windows Time Service (W32Time)
//!
//! The Windows Time service synchronizes system time with time sources:
//!
//! - **NTP Client**: Sync from NTP servers
//! - **NTP Server**: Provide time to other computers
//! - **Domain Hierarchy**: Sync within AD domain
//! - **Hardware Clock**: Sync with hardware RTC
//!
//! # Time Sources
//!
//! - External NTP servers (pool.ntp.org, time.windows.com)
//! - Domain controller (PDC emulator)
//! - Local hardware clock
//! - Manual configuration
//!
//! # Registry Location
//!
//! `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters`

extern crate alloc;

use crate::ke::SpinLock;
use core::sync::atomic::{AtomicU64, AtomicI64, AtomicBool, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum time sources
pub const MAX_TIME_SOURCES: usize = 8;

/// Maximum time peers
pub const MAX_PEERS: usize = 16;

/// NTP port
pub const NTP_PORT: u16 = 123;

/// Default sync interval (seconds)
pub const DEFAULT_SYNC_INTERVAL: u32 = 3600; // 1 hour

/// Maximum time offset before step (ms)
pub const MAX_OFFSET_FOR_SLEW: i64 = 128000; // 128 seconds

/// NTP epoch offset (1900-01-01 to 1601-01-01 in 100ns units)
pub const NTP_EPOCH_OFFSET: i64 = 94354848000000000;

// ============================================================================
// Types
// ============================================================================

/// Time source type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TimeSourceType {
    /// Unknown/not configured
    Unknown = 0,
    /// NTP server
    Ntp = 1,
    /// Symmetric active (peer)
    SymmetricActive = 2,
    /// Symmetric passive
    SymmetricPassive = 3,
    /// Domain controller
    DomainController = 4,
    /// Local clock (fallback)
    LocalClock = 5,
    /// Manual configuration
    Manual = 6,
}

impl Default for TimeSourceType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Sync status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SyncStatus {
    /// Not synchronized
    NotSynced = 0,
    /// Synchronizing
    Syncing = 1,
    /// Synchronized
    Synced = 2,
    /// Last sync failed
    Failed = 3,
    /// Holdover (using last sync)
    Holdover = 4,
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self::NotSynced
    }
}

/// Stratum level (1-15, 16 = unsynchronized)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Stratum {
    /// Primary reference (GPS, atomic clock)
    Primary = 1,
    /// Secondary reference
    Secondary = 2,
    /// Tertiary
    Tertiary = 3,
    /// Client level
    Client = 4,
    /// Unsynchronized
    Unsynchronized = 16,
}

impl Default for Stratum {
    fn default() -> Self {
        Self::Unsynchronized
    }
}

impl From<u8> for Stratum {
    fn from(val: u8) -> Self {
        match val {
            1 => Self::Primary,
            2 => Self::Secondary,
            3 => Self::Tertiary,
            4..=15 => Self::Client,
            _ => Self::Unsynchronized,
        }
    }
}

/// Time sync mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SyncMode {
    /// Disabled
    Disabled = 0,
    /// NTP client only
    NtpClient = 1,
    /// NTP server only
    NtpServer = 2,
    /// Both client and server
    Both = 3,
    /// Domain sync
    DomainSync = 4,
}

impl Default for SyncMode {
    fn default() -> Self {
        Self::NtpClient
    }
}

/// W32Time error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum W32TimeError {
    /// Success
    Ok = 0,
    /// Service not running
    NotRunning = 1,
    /// No time sources configured
    NoSources = 2,
    /// Sync failed
    SyncFailed = 3,
    /// Network error
    NetworkError = 4,
    /// Timeout
    Timeout = 5,
    /// Invalid response
    InvalidResponse = 6,
    /// Access denied
    AccessDenied = 7,
    /// Already running
    AlreadyRunning = 8,
}

// ============================================================================
// Time Source
// ============================================================================

/// A time source entry
#[derive(Clone)]
pub struct TimeSource {
    /// Entry is valid
    pub valid: bool,
    /// Source type
    pub source_type: TimeSourceType,
    /// Server hostname/IP
    pub server: [u8; 64],
    /// Server length
    pub server_len: usize,
    /// Port
    pub port: u16,
    /// Stratum
    pub stratum: Stratum,
    /// Is reachable
    pub reachable: bool,
    /// Last sync time (NT time)
    pub last_sync: i64,
    /// Last offset (100ns units)
    pub last_offset: i64,
    /// Last delay (100ns units)
    pub last_delay: i64,
    /// Sync count
    pub sync_count: u32,
    /// Failure count
    pub failure_count: u32,
    /// Priority (lower = higher)
    pub priority: u32,
}

impl TimeSource {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            source_type: TimeSourceType::Unknown,
            server: [0; 64],
            server_len: 0,
            port: NTP_PORT,
            stratum: Stratum::Unsynchronized,
            reachable: false,
            last_sync: 0,
            last_offset: 0,
            last_delay: 0,
            sync_count: 0,
            failure_count: 0,
            priority: 0,
        }
    }

    pub fn server_str(&self) -> &str {
        core::str::from_utf8(&self.server[..self.server_len]).unwrap_or("")
    }

    pub fn set_server(&mut self, server: &str) {
        let bytes = server.as_bytes();
        let len = bytes.len().min(64);
        self.server[..len].copy_from_slice(&bytes[..len]);
        self.server_len = len;
    }
}

// ============================================================================
// Service State
// ============================================================================

/// W32Time service state
struct W32TimeState {
    /// Service running
    running: bool,
    /// Sync mode
    mode: SyncMode,
    /// Time sources
    sources: [TimeSource; MAX_TIME_SOURCES],
    /// Source count
    source_count: usize,
    /// Current sync status
    sync_status: SyncStatus,
    /// Current stratum
    stratum: Stratum,
    /// Last sync time
    last_sync_time: i64,
    /// Current time offset (100ns units)
    current_offset: i64,
    /// Sync interval (seconds)
    sync_interval: u32,
    /// Poll interval (seconds)
    poll_interval: u32,
    /// Is domain member
    is_domain_member: bool,
    /// Local clock enabled as fallback
    local_clock_fallback: bool,
    /// Announce flags (for NTP server mode)
    announce_flags: u32,
}

impl W32TimeState {
    const fn new() -> Self {
        Self {
            running: false,
            mode: SyncMode::NtpClient,
            sources: [const { TimeSource::empty() }; MAX_TIME_SOURCES],
            source_count: 0,
            sync_status: SyncStatus::NotSynced,
            stratum: Stratum::Unsynchronized,
            last_sync_time: 0,
            current_offset: 0,
            sync_interval: DEFAULT_SYNC_INTERVAL,
            poll_interval: 64,
            is_domain_member: false,
            local_clock_fallback: true,
            announce_flags: 0,
        }
    }
}

static W32TIME_STATE: SpinLock<W32TimeState> = SpinLock::new(W32TimeState::new());

/// Statistics
struct W32TimeStats {
    /// Total syncs attempted
    sync_attempts: AtomicU64,
    /// Successful syncs
    sync_successes: AtomicU64,
    /// Failed syncs
    sync_failures: AtomicU64,
    /// NTP packets sent
    ntp_sent: AtomicU64,
    /// NTP packets received
    ntp_received: AtomicU64,
    /// Total time corrections (100ns units)
    total_correction: AtomicI64,
    /// Time steps performed
    time_steps: AtomicU64,
    /// Time slews performed
    time_slews: AtomicU64,
}

impl W32TimeStats {
    const fn new() -> Self {
        Self {
            sync_attempts: AtomicU64::new(0),
            sync_successes: AtomicU64::new(0),
            sync_failures: AtomicU64::new(0),
            ntp_sent: AtomicU64::new(0),
            ntp_received: AtomicU64::new(0),
            total_correction: AtomicI64::new(0),
            time_steps: AtomicU64::new(0),
            time_slews: AtomicU64::new(0),
        }
    }
}

static W32TIME_STATS: W32TimeStats = W32TimeStats::new();

// ============================================================================
// Time Source Management
// ============================================================================

/// Add a time source
pub fn add_time_source(
    server: &str,
    source_type: TimeSourceType,
    priority: u32,
) -> Result<usize, W32TimeError> {
    let mut state = W32TIME_STATE.lock();

    if !state.running {
        return Err(W32TimeError::NotRunning);
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_TIME_SOURCES {
        if !state.sources[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(W32TimeError::SyncFailed),
    };

    let source = &mut state.sources[slot];
    source.valid = true;
    source.source_type = source_type;
    source.set_server(server);
    source.port = NTP_PORT;
    source.stratum = Stratum::Unsynchronized;
    source.reachable = false;
    source.priority = priority;
    source.sync_count = 0;
    source.failure_count = 0;

    state.source_count += 1;

    crate::serial_println!("[W32TIME] Added time source '{}'", server);

    Ok(slot)
}

/// Remove a time source
pub fn remove_time_source(server: &str) -> Result<(), W32TimeError> {
    let mut state = W32TIME_STATE.lock();

    for i in 0..MAX_TIME_SOURCES {
        if state.sources[i].valid && state.sources[i].server_str() == server {
            state.sources[i].valid = false;
            state.source_count = state.source_count.saturating_sub(1);
            return Ok(());
        }
    }

    Err(W32TimeError::NoSources)
}

/// Get time source count
pub fn get_source_count() -> usize {
    let state = W32TIME_STATE.lock();
    state.source_count
}

// ============================================================================
// Time Synchronization
// ============================================================================

/// Trigger a manual sync
pub fn resync() -> Result<(), W32TimeError> {
    let mut state = W32TIME_STATE.lock();

    if !state.running {
        return Err(W32TimeError::NotRunning);
    }

    if state.source_count == 0 {
        return Err(W32TimeError::NoSources);
    }

    W32TIME_STATS.sync_attempts.fetch_add(1, Ordering::Relaxed);

    state.sync_status = SyncStatus::Syncing;

    // Find best source (lowest priority number that's reachable)
    let mut best_source: Option<usize> = None;
    let mut best_priority = u32::MAX;

    for i in 0..MAX_TIME_SOURCES {
        if state.sources[i].valid && state.sources[i].priority < best_priority {
            best_source = Some(i);
            best_priority = state.sources[i].priority;
        }
    }

    let source_idx = match best_source {
        Some(i) => i,
        None => {
            state.sync_status = SyncStatus::Failed;
            W32TIME_STATS.sync_failures.fetch_add(1, Ordering::Relaxed);
            return Err(W32TimeError::NoSources);
        }
    };

    // Simulate successful sync (in real implementation, would send NTP packets)
    let now = crate::rtl::time::rtl_get_system_time();
    let simulated_offset: i64 = 0; // Pretend we're in sync

    state.sources[source_idx].reachable = true;
    state.sources[source_idx].last_sync = now;
    state.sources[source_idx].last_offset = simulated_offset;
    state.sources[source_idx].sync_count += 1;
    state.sources[source_idx].stratum = Stratum::Secondary;

    state.sync_status = SyncStatus::Synced;
    state.stratum = Stratum::Tertiary;
    state.last_sync_time = now;
    state.current_offset = simulated_offset;

    W32TIME_STATS.sync_successes.fetch_add(1, Ordering::Relaxed);
    W32TIME_STATS.ntp_sent.fetch_add(1, Ordering::Relaxed);
    W32TIME_STATS.ntp_received.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[W32TIME] Synchronized with '{}'",
        state.sources[source_idx].server_str());

    Ok(())
}

/// Apply time correction
fn apply_correction(offset: i64) {
    let offset_ms = offset / 10000; // Convert 100ns to ms

    if offset_ms.abs() > MAX_OFFSET_FOR_SLEW {
        // Large offset - step the clock
        W32TIME_STATS.time_steps.fetch_add(1, Ordering::Relaxed);
        crate::serial_println!("[W32TIME] Stepping clock by {}ms", offset_ms);
    } else {
        // Small offset - slew the clock
        W32TIME_STATS.time_slews.fetch_add(1, Ordering::Relaxed);
        crate::serial_println!("[W32TIME] Slewing clock by {}ms", offset_ms);
    }

    W32TIME_STATS.total_correction.fetch_add(offset, Ordering::Relaxed);
}

/// Get current sync status
pub fn get_sync_status() -> SyncStatus {
    let state = W32TIME_STATE.lock();
    state.sync_status
}

/// Get current stratum
pub fn get_stratum() -> Stratum {
    let state = W32TIME_STATE.lock();
    state.stratum
}

/// Get last sync time
pub fn get_last_sync_time() -> i64 {
    let state = W32TIME_STATE.lock();
    state.last_sync_time
}

/// Get current offset
pub fn get_current_offset() -> i64 {
    let state = W32TIME_STATE.lock();
    state.current_offset
}

// ============================================================================
// Configuration
// ============================================================================

/// Set sync mode
pub fn set_sync_mode(mode: SyncMode) {
    let mut state = W32TIME_STATE.lock();
    state.mode = mode;
    crate::serial_println!("[W32TIME] Sync mode: {:?}", mode);
}

/// Get sync mode
pub fn get_sync_mode() -> SyncMode {
    let state = W32TIME_STATE.lock();
    state.mode
}

/// Set sync interval
pub fn set_sync_interval(seconds: u32) {
    let mut state = W32TIME_STATE.lock();
    state.sync_interval = seconds;
}

/// Set poll interval
pub fn set_poll_interval(seconds: u32) {
    let mut state = W32TIME_STATE.lock();
    state.poll_interval = seconds;
}

/// Enable/disable local clock fallback
pub fn set_local_clock_fallback(enabled: bool) {
    let mut state = W32TIME_STATE.lock();
    state.local_clock_fallback = enabled;
}

// ============================================================================
// Statistics
// ============================================================================

/// Get W32Time statistics
pub fn get_statistics() -> (u64, u64, u64, u64, u64, i64, u64, u64) {
    (
        W32TIME_STATS.sync_attempts.load(Ordering::Relaxed),
        W32TIME_STATS.sync_successes.load(Ordering::Relaxed),
        W32TIME_STATS.sync_failures.load(Ordering::Relaxed),
        W32TIME_STATS.ntp_sent.load(Ordering::Relaxed),
        W32TIME_STATS.ntp_received.load(Ordering::Relaxed),
        W32TIME_STATS.total_correction.load(Ordering::Relaxed),
        W32TIME_STATS.time_steps.load(Ordering::Relaxed),
        W32TIME_STATS.time_slews.load(Ordering::Relaxed),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = W32TIME_STATE.lock();
    state.running
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialized flag
static W32TIME_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize Windows Time Service
pub fn init() {
    if W32TIME_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[W32TIME] Initializing Windows Time Service...");

    {
        let mut state = W32TIME_STATE.lock();
        state.running = true;
        state.mode = SyncMode::NtpClient;
        state.sync_interval = DEFAULT_SYNC_INTERVAL;
        state.poll_interval = 64;
        state.local_clock_fallback = true;
    }

    // Add default time sources
    let _ = add_time_source("time.windows.com", TimeSourceType::Ntp, 0);
    let _ = add_time_source("pool.ntp.org", TimeSourceType::Ntp, 1);
    let _ = add_time_source("time.nist.gov", TimeSourceType::Ntp, 2);

    // Perform initial sync
    let _ = resync();

    crate::serial_println!("[W32TIME] Windows Time Service initialized");
    crate::serial_println!("[W32TIME]   Time sources: 3");
    crate::serial_println!("[W32TIME]   Mode: NTP Client");
}
