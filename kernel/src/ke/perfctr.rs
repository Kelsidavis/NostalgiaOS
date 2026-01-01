//! Kernel Performance Counters
//!
//! Provides system-wide performance monitoring counters for:
//! - CPU utilization
//! - Context switches
//! - System calls
//! - Interrupts
//! - DPC/APC delivery
//! - Memory operations
//!
//! # NT Functions
//!
//! - `KeQueryPerformanceCounter` - Query high-resolution counter
//! - `NtQuerySystemInformation` - Query performance info class
//!
//! # Usage
//!
//! ```ignore
//! use crate::ke::perfctr;
//!
//! // Get current performance counters
//! let counters = perfctr::get_performance_counters();
//! println!("Context switches: {}", counters.context_switches);
//! ```

use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};

// ============================================================================
// Performance Counter Values
// ============================================================================

// Context switch counter
static CONTEXT_SWITCH_COUNT: AtomicU64 = AtomicU64::new(0);

// System call counters
static SYSTEM_CALL_COUNT: AtomicU64 = AtomicU64::new(0);
static SYSTEM_CALL_FAILED: AtomicU64 = AtomicU64::new(0);

// Interrupt counters
static INTERRUPT_COUNT: AtomicU64 = AtomicU64::new(0);
static INTERRUPT_TIME: AtomicU64 = AtomicU64::new(0); // In 100ns units

// DPC counters
static DPC_COUNT: AtomicU64 = AtomicU64::new(0);
static DPC_TIME: AtomicU64 = AtomicU64::new(0);
static DPC_QUEUE_DEPTH: AtomicU32 = AtomicU32::new(0);

// APC counters
static APC_COUNT: AtomicU64 = AtomicU64::new(0);
static APC_TIME: AtomicU64 = AtomicU64::new(0);

// Exception counters
static EXCEPTION_COUNT: AtomicU64 = AtomicU64::new(0);
static PAGE_FAULT_COUNT: AtomicU64 = AtomicU64::new(0);
static PAGE_FAULT_READ: AtomicU64 = AtomicU64::new(0);
static PAGE_FAULT_WRITE: AtomicU64 = AtomicU64::new(0);

// Memory counters
static POOL_ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static POOL_FREE_COUNT: AtomicU64 = AtomicU64::new(0);
static POOL_BYTES_ALLOCATED: AtomicU64 = AtomicU64::new(0);

// I/O counters
static IO_READ_COUNT: AtomicU64 = AtomicU64::new(0);
static IO_WRITE_COUNT: AtomicU64 = AtomicU64::new(0);
static IO_OTHER_COUNT: AtomicU64 = AtomicU64::new(0);
static IO_READ_BYTES: AtomicU64 = AtomicU64::new(0);
static IO_WRITE_BYTES: AtomicU64 = AtomicU64::new(0);

// Spinlock counters
static SPINLOCK_ACQUIRE_COUNT: AtomicU64 = AtomicU64::new(0);
static SPINLOCK_CONTENTION_COUNT: AtomicU64 = AtomicU64::new(0);
static SPINLOCK_SPIN_COUNT: AtomicU64 = AtomicU64::new(0);

// CPU time (in 100ns units)
static IDLE_TIME: AtomicU64 = AtomicU64::new(0);
static KERNEL_TIME: AtomicU64 = AtomicU64::new(0);
static USER_TIME: AtomicU64 = AtomicU64::new(0);

// Boot time
static BOOT_TIME: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Counter Increment Functions
// ============================================================================

/// Increment context switch counter
#[inline]
pub fn inc_context_switches() {
    CONTEXT_SWITCH_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Increment system call counter
#[inline]
pub fn inc_system_calls() {
    SYSTEM_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Increment failed system call counter
#[inline]
pub fn inc_system_call_failed() {
    SYSTEM_CALL_FAILED.fetch_add(1, Ordering::Relaxed);
}

/// Increment interrupt counter
#[inline]
pub fn inc_interrupts() {
    INTERRUPT_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Add interrupt time
#[inline]
pub fn add_interrupt_time(time_100ns: u64) {
    INTERRUPT_TIME.fetch_add(time_100ns, Ordering::Relaxed);
}

/// Increment DPC counter
#[inline]
pub fn inc_dpcs() {
    DPC_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Add DPC time
#[inline]
pub fn add_dpc_time(time_100ns: u64) {
    DPC_TIME.fetch_add(time_100ns, Ordering::Relaxed);
}

/// Set DPC queue depth
#[inline]
pub fn set_dpc_queue_depth(depth: u32) {
    DPC_QUEUE_DEPTH.store(depth, Ordering::Relaxed);
}

/// Increment APC counter
#[inline]
pub fn inc_apcs() {
    APC_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Add APC time
#[inline]
pub fn add_apc_time(time_100ns: u64) {
    APC_TIME.fetch_add(time_100ns, Ordering::Relaxed);
}

/// Increment exception counter
#[inline]
pub fn inc_exceptions() {
    EXCEPTION_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Increment page fault counter
#[inline]
pub fn inc_page_faults() {
    PAGE_FAULT_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Increment page fault read counter
#[inline]
pub fn inc_page_fault_reads() {
    PAGE_FAULT_READ.fetch_add(1, Ordering::Relaxed);
}

/// Increment page fault write counter
#[inline]
pub fn inc_page_fault_writes() {
    PAGE_FAULT_WRITE.fetch_add(1, Ordering::Relaxed);
}

/// Record pool allocation
#[inline]
pub fn record_pool_alloc(bytes: u64) {
    POOL_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
    POOL_BYTES_ALLOCATED.fetch_add(bytes, Ordering::Relaxed);
}

/// Record pool free
#[inline]
pub fn record_pool_free(bytes: u64) {
    POOL_FREE_COUNT.fetch_add(1, Ordering::Relaxed);
    POOL_BYTES_ALLOCATED.fetch_sub(bytes, Ordering::Relaxed);
}

/// Record I/O read
#[inline]
pub fn record_io_read(bytes: u64) {
    IO_READ_COUNT.fetch_add(1, Ordering::Relaxed);
    IO_READ_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

/// Record I/O write
#[inline]
pub fn record_io_write(bytes: u64) {
    IO_WRITE_COUNT.fetch_add(1, Ordering::Relaxed);
    IO_WRITE_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

/// Record other I/O
#[inline]
pub fn record_io_other() {
    IO_OTHER_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Record spinlock acquire
#[inline]
pub fn record_spinlock_acquire() {
    SPINLOCK_ACQUIRE_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Record spinlock contention
#[inline]
pub fn record_spinlock_contention() {
    SPINLOCK_CONTENTION_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Record spinlock spins
#[inline]
pub fn record_spinlock_spins(spins: u64) {
    SPINLOCK_SPIN_COUNT.fetch_add(spins, Ordering::Relaxed);
}

/// Add idle time
#[inline]
pub fn add_idle_time(time_100ns: u64) {
    IDLE_TIME.fetch_add(time_100ns, Ordering::Relaxed);
}

/// Add kernel time
#[inline]
pub fn add_kernel_time(time_100ns: u64) {
    KERNEL_TIME.fetch_add(time_100ns, Ordering::Relaxed);
}

/// Add user time
#[inline]
pub fn add_user_time(time_100ns: u64) {
    USER_TIME.fetch_add(time_100ns, Ordering::Relaxed);
}

// ============================================================================
// Performance Counter Structure
// ============================================================================

/// System performance counters
#[derive(Debug, Clone, Copy, Default)]
pub struct PerformanceCounters {
    /// Context switches
    pub context_switches: u64,
    /// System calls
    pub system_calls: u64,
    /// Failed system calls
    pub system_calls_failed: u64,
    /// Interrupts
    pub interrupts: u64,
    /// Interrupt time (100ns units)
    pub interrupt_time: u64,
    /// DPCs processed
    pub dpcs: u64,
    /// DPC time (100ns units)
    pub dpc_time: u64,
    /// Current DPC queue depth
    pub dpc_queue_depth: u32,
    /// APCs processed
    pub apcs: u64,
    /// APC time (100ns units)
    pub apc_time: u64,
    /// Exceptions
    pub exceptions: u64,
    /// Page faults
    pub page_faults: u64,
    /// Page fault reads
    pub page_fault_reads: u64,
    /// Page fault writes
    pub page_fault_writes: u64,
    /// Pool allocations
    pub pool_allocs: u64,
    /// Pool frees
    pub pool_frees: u64,
    /// Pool bytes currently allocated
    pub pool_bytes: u64,
    /// I/O reads
    pub io_reads: u64,
    /// I/O writes
    pub io_writes: u64,
    /// Other I/O operations
    pub io_other: u64,
    /// I/O read bytes
    pub io_read_bytes: u64,
    /// I/O write bytes
    pub io_write_bytes: u64,
    /// Spinlock acquires
    pub spinlock_acquires: u64,
    /// Spinlock contentions
    pub spinlock_contentions: u64,
    /// Spinlock spins
    pub spinlock_spins: u64,
    /// Idle time (100ns units)
    pub idle_time: u64,
    /// Kernel time (100ns units)
    pub kernel_time: u64,
    /// User time (100ns units)
    pub user_time: u64,
    /// Boot time (100ns since 1601)
    pub boot_time: u64,
    /// Uptime (100ns units)
    pub uptime: u64,
}

/// Get all performance counters
pub fn get_performance_counters() -> PerformanceCounters {
    let boot = BOOT_TIME.load(Ordering::Relaxed);
    let now = crate::rtl::rtl_get_system_time() as u64;

    PerformanceCounters {
        context_switches: CONTEXT_SWITCH_COUNT.load(Ordering::Relaxed),
        system_calls: SYSTEM_CALL_COUNT.load(Ordering::Relaxed),
        system_calls_failed: SYSTEM_CALL_FAILED.load(Ordering::Relaxed),
        interrupts: INTERRUPT_COUNT.load(Ordering::Relaxed),
        interrupt_time: INTERRUPT_TIME.load(Ordering::Relaxed),
        dpcs: DPC_COUNT.load(Ordering::Relaxed),
        dpc_time: DPC_TIME.load(Ordering::Relaxed),
        dpc_queue_depth: DPC_QUEUE_DEPTH.load(Ordering::Relaxed),
        apcs: APC_COUNT.load(Ordering::Relaxed),
        apc_time: APC_TIME.load(Ordering::Relaxed),
        exceptions: EXCEPTION_COUNT.load(Ordering::Relaxed),
        page_faults: PAGE_FAULT_COUNT.load(Ordering::Relaxed),
        page_fault_reads: PAGE_FAULT_READ.load(Ordering::Relaxed),
        page_fault_writes: PAGE_FAULT_WRITE.load(Ordering::Relaxed),
        pool_allocs: POOL_ALLOC_COUNT.load(Ordering::Relaxed),
        pool_frees: POOL_FREE_COUNT.load(Ordering::Relaxed),
        pool_bytes: POOL_BYTES_ALLOCATED.load(Ordering::Relaxed),
        io_reads: IO_READ_COUNT.load(Ordering::Relaxed),
        io_writes: IO_WRITE_COUNT.load(Ordering::Relaxed),
        io_other: IO_OTHER_COUNT.load(Ordering::Relaxed),
        io_read_bytes: IO_READ_BYTES.load(Ordering::Relaxed),
        io_write_bytes: IO_WRITE_BYTES.load(Ordering::Relaxed),
        spinlock_acquires: SPINLOCK_ACQUIRE_COUNT.load(Ordering::Relaxed),
        spinlock_contentions: SPINLOCK_CONTENTION_COUNT.load(Ordering::Relaxed),
        spinlock_spins: SPINLOCK_SPIN_COUNT.load(Ordering::Relaxed),
        idle_time: IDLE_TIME.load(Ordering::Relaxed),
        kernel_time: KERNEL_TIME.load(Ordering::Relaxed),
        user_time: USER_TIME.load(Ordering::Relaxed),
        boot_time: boot,
        uptime: now.saturating_sub(boot),
    }
}

// ============================================================================
// Individual Counter Queries
// ============================================================================

/// Get context switch count
#[inline]
pub fn get_context_switches() -> u64 {
    CONTEXT_SWITCH_COUNT.load(Ordering::Relaxed)
}

/// Get system call count
#[inline]
pub fn get_system_calls() -> u64 {
    SYSTEM_CALL_COUNT.load(Ordering::Relaxed)
}

/// Get interrupt count
#[inline]
pub fn get_interrupts() -> u64 {
    INTERRUPT_COUNT.load(Ordering::Relaxed)
}

/// Get DPC count
#[inline]
pub fn get_dpcs() -> u64 {
    DPC_COUNT.load(Ordering::Relaxed)
}

/// Get APC count
#[inline]
pub fn get_apcs() -> u64 {
    APC_COUNT.load(Ordering::Relaxed)
}

/// Get page fault count
#[inline]
pub fn get_page_faults() -> u64 {
    PAGE_FAULT_COUNT.load(Ordering::Relaxed)
}

/// Get system uptime in 100ns units
pub fn get_uptime() -> u64 {
    let boot = BOOT_TIME.load(Ordering::Relaxed);
    let now = crate::rtl::rtl_get_system_time() as u64;
    now.saturating_sub(boot)
}

/// Get system uptime in seconds
pub fn get_uptime_seconds() -> u64 {
    get_uptime() / 10_000_000
}

/// Get boot time
pub fn get_boot_time() -> u64 {
    BOOT_TIME.load(Ordering::Relaxed)
}

// ============================================================================
// High-Resolution Performance Counter
// ============================================================================

/// Performance counter frequency (ticks per second)
static PERF_COUNTER_FREQUENCY: AtomicU64 = AtomicU64::new(0);

/// Get high-resolution performance counter
///
/// Returns the current value of the performance counter.
/// Use `ke_query_performance_frequency` to convert to time.
pub fn ke_query_performance_counter() -> u64 {
    // Use TSC for high-resolution timing
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { core::arch::x86_64::_rdtsc() }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Fallback to system time
        crate::rtl::rtl_get_system_time() as u64
    }
}

/// Get performance counter frequency
///
/// Returns the frequency of the performance counter in Hz.
pub fn ke_query_performance_frequency() -> u64 {
    let freq = PERF_COUNTER_FREQUENCY.load(Ordering::Relaxed);
    if freq == 0 {
        // Estimate TSC frequency (rough approximation)
        // In real system, this would be calibrated during boot
        3_000_000_000 // Assume 3 GHz
    } else {
        freq
    }
}

/// Set performance counter frequency (called during calibration)
pub fn set_performance_frequency(freq: u64) {
    PERF_COUNTER_FREQUENCY.store(freq, Ordering::Release);
}

// ============================================================================
// CPU Utilization
// ============================================================================

/// CPU utilization snapshot
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuUtilization {
    /// Idle percentage (0-100)
    pub idle_percent: u8,
    /// Kernel percentage (0-100)
    pub kernel_percent: u8,
    /// User percentage (0-100)
    pub user_percent: u8,
    /// Interrupt percentage (0-100)
    pub interrupt_percent: u8,
    /// DPC percentage (0-100)
    pub dpc_percent: u8,
}

/// Calculate CPU utilization from counters
///
/// Note: This is a point-in-time calculation and should be called
/// periodically to get accurate utilization over time.
pub fn get_cpu_utilization() -> CpuUtilization {
    let idle = IDLE_TIME.load(Ordering::Relaxed);
    let kernel = KERNEL_TIME.load(Ordering::Relaxed);
    let user = USER_TIME.load(Ordering::Relaxed);
    let interrupt = INTERRUPT_TIME.load(Ordering::Relaxed);
    let dpc = DPC_TIME.load(Ordering::Relaxed);

    let total = idle + kernel + user;
    if total == 0 {
        return CpuUtilization::default();
    }

    CpuUtilization {
        idle_percent: ((idle * 100) / total) as u8,
        kernel_percent: ((kernel * 100) / total) as u8,
        user_percent: ((user * 100) / total) as u8,
        interrupt_percent: if total > 0 { ((interrupt * 100) / total) as u8 } else { 0 },
        dpc_percent: if total > 0 { ((dpc * 100) / total) as u8 } else { 0 },
    }
}

// ============================================================================
// Rate Calculations
// ============================================================================

/// Per-second rates
#[derive(Debug, Clone, Copy, Default)]
pub struct PerformanceRates {
    /// Context switches per second
    pub context_switches_per_sec: u64,
    /// System calls per second
    pub system_calls_per_sec: u64,
    /// Interrupts per second
    pub interrupts_per_sec: u64,
    /// DPCs per second
    pub dpcs_per_sec: u64,
    /// Page faults per second
    pub page_faults_per_sec: u64,
    /// I/O reads per second
    pub io_reads_per_sec: u64,
    /// I/O writes per second
    pub io_writes_per_sec: u64,
    /// I/O read bytes per second
    pub io_read_bytes_per_sec: u64,
    /// I/O write bytes per second
    pub io_write_bytes_per_sec: u64,
}

// Store last sample for rate calculation
static mut LAST_SAMPLE_TIME: u64 = 0;
static mut LAST_CONTEXT_SWITCHES: u64 = 0;
static mut LAST_SYSTEM_CALLS: u64 = 0;
static mut LAST_INTERRUPTS: u64 = 0;
static mut LAST_DPCS: u64 = 0;
static mut LAST_PAGE_FAULTS: u64 = 0;
static mut LAST_IO_READS: u64 = 0;
static mut LAST_IO_WRITES: u64 = 0;
static mut LAST_IO_READ_BYTES: u64 = 0;
static mut LAST_IO_WRITE_BYTES: u64 = 0;

/// Calculate performance rates (call periodically)
pub fn calculate_performance_rates() -> PerformanceRates {
    let now = crate::rtl::rtl_get_system_time() as u64;

    let ctx = CONTEXT_SWITCH_COUNT.load(Ordering::Relaxed);
    let sys = SYSTEM_CALL_COUNT.load(Ordering::Relaxed);
    let int = INTERRUPT_COUNT.load(Ordering::Relaxed);
    let dpc = DPC_COUNT.load(Ordering::Relaxed);
    let pf = PAGE_FAULT_COUNT.load(Ordering::Relaxed);
    let ior = IO_READ_COUNT.load(Ordering::Relaxed);
    let iow = IO_WRITE_COUNT.load(Ordering::Relaxed);
    let iorb = IO_READ_BYTES.load(Ordering::Relaxed);
    let iowb = IO_WRITE_BYTES.load(Ordering::Relaxed);

    unsafe {
        let elapsed = now.saturating_sub(LAST_SAMPLE_TIME);
        let elapsed_sec = elapsed / 10_000_000; // Convert 100ns to seconds

        let rates = if elapsed_sec > 0 {
            PerformanceRates {
                context_switches_per_sec: ctx.saturating_sub(LAST_CONTEXT_SWITCHES) / elapsed_sec,
                system_calls_per_sec: sys.saturating_sub(LAST_SYSTEM_CALLS) / elapsed_sec,
                interrupts_per_sec: int.saturating_sub(LAST_INTERRUPTS) / elapsed_sec,
                dpcs_per_sec: dpc.saturating_sub(LAST_DPCS) / elapsed_sec,
                page_faults_per_sec: pf.saturating_sub(LAST_PAGE_FAULTS) / elapsed_sec,
                io_reads_per_sec: ior.saturating_sub(LAST_IO_READS) / elapsed_sec,
                io_writes_per_sec: iow.saturating_sub(LAST_IO_WRITES) / elapsed_sec,
                io_read_bytes_per_sec: iorb.saturating_sub(LAST_IO_READ_BYTES) / elapsed_sec,
                io_write_bytes_per_sec: iowb.saturating_sub(LAST_IO_WRITE_BYTES) / elapsed_sec,
            }
        } else {
            PerformanceRates::default()
        };

        // Update last sample
        LAST_SAMPLE_TIME = now;
        LAST_CONTEXT_SWITCHES = ctx;
        LAST_SYSTEM_CALLS = sys;
        LAST_INTERRUPTS = int;
        LAST_DPCS = dpc;
        LAST_PAGE_FAULTS = pf;
        LAST_IO_READS = ior;
        LAST_IO_WRITES = iow;
        LAST_IO_READ_BYTES = iorb;
        LAST_IO_WRITE_BYTES = iowb;

        rates
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize performance counters
pub fn init() {
    // Record boot time
    let now = crate::rtl::rtl_get_system_time() as u64;
    BOOT_TIME.store(now, Ordering::Release);

    // Reset all counters
    CONTEXT_SWITCH_COUNT.store(0, Ordering::Relaxed);
    SYSTEM_CALL_COUNT.store(0, Ordering::Relaxed);
    SYSTEM_CALL_FAILED.store(0, Ordering::Relaxed);
    INTERRUPT_COUNT.store(0, Ordering::Relaxed);
    INTERRUPT_TIME.store(0, Ordering::Relaxed);
    DPC_COUNT.store(0, Ordering::Relaxed);
    DPC_TIME.store(0, Ordering::Relaxed);
    APC_COUNT.store(0, Ordering::Relaxed);
    APC_TIME.store(0, Ordering::Relaxed);
    EXCEPTION_COUNT.store(0, Ordering::Relaxed);
    PAGE_FAULT_COUNT.store(0, Ordering::Relaxed);

    // Initialize last sample for rate calculation
    unsafe {
        LAST_SAMPLE_TIME = now;
    }

    crate::serial_println!("[KE] Performance counters initialized");
}

/// Reset all performance counters
pub fn reset_counters() {
    CONTEXT_SWITCH_COUNT.store(0, Ordering::Relaxed);
    SYSTEM_CALL_COUNT.store(0, Ordering::Relaxed);
    SYSTEM_CALL_FAILED.store(0, Ordering::Relaxed);
    INTERRUPT_COUNT.store(0, Ordering::Relaxed);
    INTERRUPT_TIME.store(0, Ordering::Relaxed);
    DPC_COUNT.store(0, Ordering::Relaxed);
    DPC_TIME.store(0, Ordering::Relaxed);
    APC_COUNT.store(0, Ordering::Relaxed);
    APC_TIME.store(0, Ordering::Relaxed);
    EXCEPTION_COUNT.store(0, Ordering::Relaxed);
    PAGE_FAULT_COUNT.store(0, Ordering::Relaxed);
    PAGE_FAULT_READ.store(0, Ordering::Relaxed);
    PAGE_FAULT_WRITE.store(0, Ordering::Relaxed);
    POOL_ALLOC_COUNT.store(0, Ordering::Relaxed);
    POOL_FREE_COUNT.store(0, Ordering::Relaxed);
    IO_READ_COUNT.store(0, Ordering::Relaxed);
    IO_WRITE_COUNT.store(0, Ordering::Relaxed);
    IO_OTHER_COUNT.store(0, Ordering::Relaxed);
    IO_READ_BYTES.store(0, Ordering::Relaxed);
    IO_WRITE_BYTES.store(0, Ordering::Relaxed);
    SPINLOCK_ACQUIRE_COUNT.store(0, Ordering::Relaxed);
    SPINLOCK_CONTENTION_COUNT.store(0, Ordering::Relaxed);
    SPINLOCK_SPIN_COUNT.store(0, Ordering::Relaxed);
    IDLE_TIME.store(0, Ordering::Relaxed);
    KERNEL_TIME.store(0, Ordering::Relaxed);
    USER_TIME.store(0, Ordering::Relaxed);
}
