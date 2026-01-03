//! Performance Monitoring Subsystem (PERF)
//!
//! Windows NT Performance Monitoring and Instrumentation.
//! Provides kernel-mode performance data collection, profiling,
//! and performance counter support.
//!
//! Reference: Windows Server 2003 base/ntos/perf/

extern crate alloc;

pub mod counters;
pub mod hooks;
pub mod profile;

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use crate::ke::SpinLock;

/// Performance group mask flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PerfGroup {
    /// Process/Thread events
    ProcThread = 0x0001,
    /// Loader events (DLL load/unload)
    Loader = 0x0002,
    /// Profile samples
    Profile = 0x0004,
    /// Context switches
    ContextSwitch = 0x0008,
    /// Memory manager events
    Memory = 0x0010,
    /// File I/O events
    FileIo = 0x0020,
    /// Disk I/O events
    DiskIo = 0x0040,
    /// Network I/O events
    NetworkIo = 0x0080,
    /// Registry events
    Registry = 0x0100,
    /// Driver events
    Drivers = 0x0200,
    /// Pool allocation events
    Pool = 0x0400,
    /// Hard faults
    HardFault = 0x0800,
    /// File name events
    FileName = 0x1000,
    /// Split I/O events
    SplitIo = 0x2000,
    /// System calls
    Syscall = 0x4000,
    /// DPC events
    Dpc = 0x8000,
    /// Interrupt events
    Interrupt = 0x10000,
    /// Power events
    Power = 0x20000,
}

/// Performance group mask
#[derive(Debug, Clone, Copy, Default)]
pub struct PerfGroupMask {
    pub masks: [u32; 8],
}

impl PerfGroupMask {
    pub const fn new() -> Self {
        Self { masks: [0; 8] }
    }

    pub fn is_group_on(&self, group: PerfGroup) -> bool {
        let group_val = group as u32;
        let index = (group_val >> 5) as usize;
        let bit = group_val & 0x1F;
        if index < 8 {
            (self.masks[index] & (1 << bit)) != 0
        } else {
            false
        }
    }

    pub fn set_group(&mut self, group: PerfGroup, enabled: bool) {
        let group_val = group as u32;
        let index = (group_val >> 5) as usize;
        let bit = group_val & 0x1F;
        if index < 8 {
            if enabled {
                self.masks[index] |= 1 << bit;
            } else {
                self.masks[index] &= !(1 << bit);
            }
        }
    }

    pub fn clear(&mut self) {
        self.masks = [0; 8];
    }

    pub fn is_any_on(&self) -> bool {
        self.masks.iter().any(|&m| m != 0)
    }
}

/// Performance hook handle
#[derive(Debug, Clone, Copy)]
pub struct PerfHookHandle {
    pub buffer: *mut u8,
    pub size: usize,
    pub valid: bool,
}

impl Default for PerfHookHandle {
    fn default() -> Self {
        Self {
            buffer: core::ptr::null_mut(),
            size: 0,
            valid: false,
        }
    }
}

/// Performance log location
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PerfStartLogLocation {
    /// Started at boot time
    AtBoot = 0,
    /// Started after boot
    PostBoot = 1,
    /// Started from global logger
    FromGlobalLogger = 2,
}

/// Performance statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct PerfStats {
    /// Total events logged
    pub total_events: u64,
    /// Events per category
    pub context_switches: u64,
    pub hard_faults: u64,
    pub disk_reads: u64,
    pub disk_writes: u64,
    pub network_sends: u64,
    pub network_receives: u64,
    pub registry_reads: u64,
    pub registry_writes: u64,
    pub pool_allocations: u64,
    pub pool_frees: u64,
    /// Profile samples
    pub profile_samples: u64,
    /// DPC count
    pub dpc_count: u64,
    /// Interrupt count
    pub interrupt_count: u64,
    /// System calls
    pub syscall_count: u64,
}

/// Global performance state
static PERF_ENABLED: AtomicBool = AtomicBool::new(false);
static PERF_LOGGING: AtomicBool = AtomicBool::new(false);
static mut PERF_GLOBAL_MASK: PerfGroupMask = PerfGroupMask::new();
static PERF_LOCK: SpinLock<()> = SpinLock::new(());

/// Performance counters
static TOTAL_EVENTS: AtomicU64 = AtomicU64::new(0);
static CONTEXT_SWITCHES: AtomicU64 = AtomicU64::new(0);
static HARD_FAULTS: AtomicU64 = AtomicU64::new(0);
static DISK_READS: AtomicU64 = AtomicU64::new(0);
static DISK_WRITES: AtomicU64 = AtomicU64::new(0);
static NETWORK_SENDS: AtomicU64 = AtomicU64::new(0);
static NETWORK_RECEIVES: AtomicU64 = AtomicU64::new(0);
static REGISTRY_READS: AtomicU64 = AtomicU64::new(0);
static REGISTRY_WRITES: AtomicU64 = AtomicU64::new(0);
static POOL_ALLOCS: AtomicU64 = AtomicU64::new(0);
static POOL_FREES: AtomicU64 = AtomicU64::new(0);
static PROFILE_SAMPLES: AtomicU64 = AtomicU64::new(0);
static DPC_COUNT: AtomicU64 = AtomicU64::new(0);
static INTERRUPT_COUNT: AtomicU64 = AtomicU64::new(0);
static SYSCALL_COUNT: AtomicU64 = AtomicU64::new(0);

/// Initialize the performance subsystem
pub fn init() {
    crate::serial_println!("[PERF] Initializing performance monitoring subsystem");

    // Initialize profiling
    profile::init();

    // Initialize performance counters
    counters::init();

    // Initialize hooks
    hooks::init();

    PERF_ENABLED.store(true, Ordering::SeqCst);

    crate::serial_println!("[PERF] Performance monitoring initialized");
}

/// Check if performance monitoring is enabled
pub fn is_enabled() -> bool {
    PERF_ENABLED.load(Ordering::Relaxed)
}

/// Check if logging is active
pub fn is_logging() -> bool {
    PERF_LOGGING.load(Ordering::Relaxed)
}

/// Check if a specific group is enabled
pub fn is_group_on(group: PerfGroup) -> bool {
    if !is_logging() {
        return false;
    }
    let _guard = PERF_LOCK.lock();
    unsafe { PERF_GLOBAL_MASK.is_group_on(group) }
}

/// Start performance logging
pub fn start_log(mask: &PerfGroupMask, location: PerfStartLogLocation) -> i32 {
    let _guard = PERF_LOCK.lock();

    crate::serial_println!("[PERF] Starting performance log (location: {:?})", location);

    unsafe {
        PERF_GLOBAL_MASK = *mask;
    }

    PERF_LOGGING.store(true, Ordering::SeqCst);

    // Initialize profiling if profile group is enabled
    if mask.is_group_on(PerfGroup::Profile) {
        profile::start();
    }

    // Log start event
    crate::ex::eventlog::log_info(
        crate::ex::eventlog::EventSource::System,
        100,
        "Performance logging started",
    );

    0 // STATUS_SUCCESS
}

/// Stop performance logging
pub fn stop_log() -> i32 {
    let _guard = PERF_LOCK.lock();

    crate::serial_println!("[PERF] Stopping performance log");

    // Stop profiling
    profile::stop();

    PERF_LOGGING.store(false, Ordering::SeqCst);

    unsafe {
        PERF_GLOBAL_MASK.clear();
    }

    // Log stop event
    crate::ex::eventlog::log_info(
        crate::ex::eventlog::EventSource::System,
        101,
        "Performance logging stopped",
    );

    0 // STATUS_SUCCESS
}

/// Get current performance statistics
pub fn get_stats() -> PerfStats {
    PerfStats {
        total_events: TOTAL_EVENTS.load(Ordering::Relaxed),
        context_switches: CONTEXT_SWITCHES.load(Ordering::Relaxed),
        hard_faults: HARD_FAULTS.load(Ordering::Relaxed),
        disk_reads: DISK_READS.load(Ordering::Relaxed),
        disk_writes: DISK_WRITES.load(Ordering::Relaxed),
        network_sends: NETWORK_SENDS.load(Ordering::Relaxed),
        network_receives: NETWORK_RECEIVES.load(Ordering::Relaxed),
        registry_reads: REGISTRY_READS.load(Ordering::Relaxed),
        registry_writes: REGISTRY_WRITES.load(Ordering::Relaxed),
        pool_allocations: POOL_ALLOCS.load(Ordering::Relaxed),
        pool_frees: POOL_FREES.load(Ordering::Relaxed),
        profile_samples: PROFILE_SAMPLES.load(Ordering::Relaxed),
        dpc_count: DPC_COUNT.load(Ordering::Relaxed),
        interrupt_count: INTERRUPT_COUNT.load(Ordering::Relaxed),
        syscall_count: SYSCALL_COUNT.load(Ordering::Relaxed),
    }
}

/// Reset all performance counters
pub fn reset_stats() {
    TOTAL_EVENTS.store(0, Ordering::Relaxed);
    CONTEXT_SWITCHES.store(0, Ordering::Relaxed);
    HARD_FAULTS.store(0, Ordering::Relaxed);
    DISK_READS.store(0, Ordering::Relaxed);
    DISK_WRITES.store(0, Ordering::Relaxed);
    NETWORK_SENDS.store(0, Ordering::Relaxed);
    NETWORK_RECEIVES.store(0, Ordering::Relaxed);
    REGISTRY_READS.store(0, Ordering::Relaxed);
    REGISTRY_WRITES.store(0, Ordering::Relaxed);
    POOL_ALLOCS.store(0, Ordering::Relaxed);
    POOL_FREES.store(0, Ordering::Relaxed);
    PROFILE_SAMPLES.store(0, Ordering::Relaxed);
    DPC_COUNT.store(0, Ordering::Relaxed);
    INTERRUPT_COUNT.store(0, Ordering::Relaxed);
    SYSCALL_COUNT.store(0, Ordering::Relaxed);
}

// ============================================================================
// Event logging functions - called by other subsystems
// ============================================================================

/// Log a context switch event
#[inline]
pub fn log_context_switch() {
    if is_group_on(PerfGroup::ContextSwitch) {
        CONTEXT_SWITCHES.fetch_add(1, Ordering::Relaxed);
        TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Log a hard fault event
#[inline]
pub fn log_hard_fault() {
    if is_group_on(PerfGroup::HardFault) {
        HARD_FAULTS.fetch_add(1, Ordering::Relaxed);
        TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Log a disk read event
#[inline]
pub fn log_disk_read(_bytes: u64) {
    if is_group_on(PerfGroup::DiskIo) {
        DISK_READS.fetch_add(1, Ordering::Relaxed);
        TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Log a disk write event
#[inline]
pub fn log_disk_write(_bytes: u64) {
    if is_group_on(PerfGroup::DiskIo) {
        DISK_WRITES.fetch_add(1, Ordering::Relaxed);
        TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Log a network send event
#[inline]
pub fn log_network_send(_bytes: u64) {
    if is_group_on(PerfGroup::NetworkIo) {
        NETWORK_SENDS.fetch_add(1, Ordering::Relaxed);
        TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Log a network receive event
#[inline]
pub fn log_network_receive(_bytes: u64) {
    if is_group_on(PerfGroup::NetworkIo) {
        NETWORK_RECEIVES.fetch_add(1, Ordering::Relaxed);
        TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Log a registry read event
#[inline]
pub fn log_registry_read() {
    if is_group_on(PerfGroup::Registry) {
        REGISTRY_READS.fetch_add(1, Ordering::Relaxed);
        TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Log a registry write event
#[inline]
pub fn log_registry_write() {
    if is_group_on(PerfGroup::Registry) {
        REGISTRY_WRITES.fetch_add(1, Ordering::Relaxed);
        TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Log a pool allocation event
#[inline]
pub fn log_pool_alloc(_size: usize) {
    if is_group_on(PerfGroup::Pool) {
        POOL_ALLOCS.fetch_add(1, Ordering::Relaxed);
        TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Log a pool free event
#[inline]
pub fn log_pool_free() {
    if is_group_on(PerfGroup::Pool) {
        POOL_FREES.fetch_add(1, Ordering::Relaxed);
        TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Log a profile sample
#[inline]
pub fn log_profile_sample(_ip: u64) {
    if is_group_on(PerfGroup::Profile) {
        PROFILE_SAMPLES.fetch_add(1, Ordering::Relaxed);
        TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Log a DPC event
#[inline]
pub fn log_dpc() {
    if is_group_on(PerfGroup::Dpc) {
        DPC_COUNT.fetch_add(1, Ordering::Relaxed);
        TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Log an interrupt event
#[inline]
pub fn log_interrupt(_vector: u8) {
    if is_group_on(PerfGroup::Interrupt) {
        INTERRUPT_COUNT.fetch_add(1, Ordering::Relaxed);
        TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Log a system call event
#[inline]
pub fn log_syscall(_syscall_num: u32) {
    if is_group_on(PerfGroup::Syscall) {
        SYSCALL_COUNT.fetch_add(1, Ordering::Relaxed);
        TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}
