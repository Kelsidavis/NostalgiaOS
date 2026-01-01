//! Performance Profiling Support
//!
//! Provides hardware-based profiling and sampling:
//!
//! - **PMC**: Performance Monitoring Counters
//! - **NMI Profiling**: Timer-based sampling
//! - **Call Stack**: Capture on profile interrupt
//! - **Event Counters**: CPU events (cache, branch, etc.)
//!
//! # PMC Architecture
//!
//! x86_64 provides programmable performance counters:
//! - Fixed counters: Instructions, cycles, reference cycles
//! - Programmable counters: User-configurable events
//!
//! # Profile Modes
//!
//! - **Timer**: Sample at fixed intervals
//! - **Event**: Sample on counter overflow
//! - **Stack**: Capture call stack on sample
//!
//! # NT Functions
//!
//! - `HalStartProfileInterrupt` - Start profiling
//! - `HalStopProfileInterrupt` - Stop profiling
//! - `HalSetProfileInterval` - Set sample rate
//!
//! # Usage
//!
//! ```ignore
//! // Start CPU cycle profiling
//! profile_start(ProfileSource::CpuCycles, 1000);
//!
//! // Get samples
//! let samples = profile_get_samples(100);
//!
//! // Stop profiling
//! profile_stop();
//! ```

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;

// ============================================================================
// Constants
// ============================================================================

/// Maximum profile sources
pub const MAX_PROFILE_SOURCES: usize = 8;

/// Maximum samples in buffer
pub const MAX_PROFILE_SAMPLES: usize = 4096;

/// Maximum stack depth for call stack capture
pub const MAX_STACK_DEPTH: usize = 16;

/// Profile interrupt vector
pub const PROFILE_VECTOR: u8 = 0xFE;

/// Default profile interval (microseconds)
pub const DEFAULT_PROFILE_INTERVAL: u32 = 1000;

// ============================================================================
// MSR Constants
// ============================================================================

pub mod msr {
    /// IA32_PERF_GLOBAL_CTRL
    pub const PERF_GLOBAL_CTRL: u32 = 0x38F;
    /// IA32_PERF_GLOBAL_STATUS
    pub const PERF_GLOBAL_STATUS: u32 = 0x38E;
    /// IA32_PERF_GLOBAL_OVF_CTRL
    pub const PERF_GLOBAL_OVF_CTRL: u32 = 0x390;

    /// IA32_FIXED_CTR_CTRL
    pub const FIXED_CTR_CTRL: u32 = 0x38D;

    /// IA32_FIXED_CTR0 - Instructions retired
    pub const FIXED_CTR0: u32 = 0x309;
    /// IA32_FIXED_CTR1 - Unhalted core cycles
    pub const FIXED_CTR1: u32 = 0x30A;
    /// IA32_FIXED_CTR2 - Unhalted reference cycles
    pub const FIXED_CTR2: u32 = 0x30B;

    /// IA32_PERFEVTSEL0 base
    pub const PERFEVTSEL_BASE: u32 = 0x186;
    /// IA32_PMC0 base
    pub const PMC_BASE: u32 = 0x0C1;

    /// IA32_DEBUGCTL
    pub const DEBUGCTL: u32 = 0x1D9;
}

// ============================================================================
// Event Selection
// ============================================================================

pub mod events {
    /// CPU cycles
    pub const CPU_CYCLES: u16 = 0x003C;
    /// Instructions retired
    pub const INSTRUCTIONS_RETIRED: u16 = 0x00C0;
    /// Branch instructions retired
    pub const BRANCH_RETIRED: u16 = 0x00C4;
    /// Branch misses retired
    pub const BRANCH_MISSES: u16 = 0x00C5;
    /// LLC references
    pub const LLC_REFERENCES: u16 = 0x4F2E;
    /// LLC misses
    pub const LLC_MISSES: u16 = 0x412E;
    /// L1D cache loads
    pub const L1D_LOADS: u16 = 0x0143;
    /// L1D cache stores
    pub const L1D_STORES: u16 = 0x0243;
}

// ============================================================================
// Types
// ============================================================================

/// Profile source
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProfileSource {
    #[default]
    Timer = 0,
    CpuCycles = 1,
    Instructions = 2,
    CacheMisses = 3,
    BranchMisses = 4,
    TlbMisses = 5,
    MemoryLoads = 6,
    MemoryStores = 7,
}

/// Profile sample
#[derive(Debug, Clone, Copy, Default)]
pub struct ProfileSample {
    /// Sample is valid
    pub valid: bool,
    /// CPU that took the sample
    pub cpu: u32,
    /// Instruction pointer
    pub ip: u64,
    /// Stack pointer
    pub sp: u64,
    /// Timestamp (TSC)
    pub timestamp: u64,
    /// Profile source
    pub source: ProfileSource,
    /// Event count at sample time
    pub count: u64,
}

/// Call stack sample
#[derive(Debug, Clone, Copy, Default)]
pub struct StackSample {
    /// Number of valid frames
    pub depth: u8,
    /// Frame addresses
    pub frames: [u64; MAX_STACK_DEPTH],
}

/// Profile source state
#[derive(Debug)]
struct ProfileSourceState {
    active: AtomicBool,
    source: ProfileSource,
    interval: AtomicU32,
    samples: AtomicU64,
    overflows: AtomicU64,
}

impl Default for ProfileSourceState {
    fn default() -> Self {
        Self {
            active: AtomicBool::new(false),
            source: ProfileSource::Timer,
            interval: AtomicU32::new(DEFAULT_PROFILE_INTERVAL),
            samples: AtomicU64::new(0),
            overflows: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static PROFILE_LOCK: SpinLock<()> = SpinLock::new(());
static PROFILE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static PROFILE_ACTIVE: AtomicBool = AtomicBool::new(false);

static SAMPLE_BUFFER_INDEX: AtomicU32 = AtomicU32::new(0);
static TOTAL_SAMPLES: AtomicU64 = AtomicU64::new(0);
static DROPPED_SAMPLES: AtomicU64 = AtomicU64::new(0);

static mut SAMPLE_BUFFER: [ProfileSample; MAX_PROFILE_SAMPLES] = [ProfileSample {
    valid: false,
    cpu: 0,
    ip: 0,
    sp: 0,
    timestamp: 0,
    source: ProfileSource::Timer,
    count: 0,
}; MAX_PROFILE_SAMPLES];

static CAPTURE_STACK: AtomicBool = AtomicBool::new(false);
static PMC_SUPPORTED: AtomicBool = AtomicBool::new(false);
static PMC_VERSION: AtomicU32 = AtomicU32::new(0);
static PMC_COUNTERS: AtomicU32 = AtomicU32::new(0);
static FIXED_COUNTERS: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// MSR Access
// ============================================================================

#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let (low, high): (u32, u32);
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
        ((high as u64) << 32) | (low as u64)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

#[inline]
unsafe fn wrmsr(msr: u32, value: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        let low = value as u32;
        let high = (value >> 32) as u32;
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nostack, preserves_flags)
        );
    }
}

#[inline]
fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

// ============================================================================
// PMC Detection
// ============================================================================

/// Check if PMC is supported
pub fn profile_is_pmc_supported() -> bool {
    PMC_SUPPORTED.load(Ordering::Relaxed)
}

/// Detect PMC capabilities
fn detect_pmc() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // CPUID.0AH - Architectural Performance Monitoring
        let eax: u32;
        let ebx: u32;
        let edx: u32;

        core::arch::asm!(
            "push rbx",
            "mov eax, 0x0A",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) ebx,
            out("eax") eax,
            out("edx") edx,
            out("ecx") _,
            options(preserves_flags)
        );

        let version = eax & 0xFF;
        if version == 0 {
            return;
        }

        let counters = (eax >> 8) & 0xFF;
        let fixed_counters = edx & 0x1F;

        PMC_VERSION.store(version, Ordering::Relaxed);
        PMC_COUNTERS.store(counters, Ordering::Relaxed);
        FIXED_COUNTERS.store(fixed_counters, Ordering::Relaxed);
        PMC_SUPPORTED.store(true, Ordering::Release);

        crate::serial_println!(
            "[Profile] PMC v{} detected: {} counters, {} fixed",
            version, counters, fixed_counters
        );
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize profiling subsystem
pub fn init() {
    detect_pmc();

    // Clear sample buffer
    unsafe {
        for sample in SAMPLE_BUFFER.iter_mut() {
            *sample = ProfileSample::default();
        }
    }

    SAMPLE_BUFFER_INDEX.store(0, Ordering::Relaxed);
    TOTAL_SAMPLES.store(0, Ordering::Relaxed);
    DROPPED_SAMPLES.store(0, Ordering::Relaxed);

    PROFILE_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[Profile] Initialized");
}

/// Initialize profiling on AP
pub fn init_cpu(_cpu: u32) {
    // Nothing specific needed per-CPU for now
}

// ============================================================================
// Profile Control
// ============================================================================

/// Start profiling
pub fn profile_start(source: ProfileSource, interval_us: u32) -> bool {
    let _guard = PROFILE_LOCK.lock();

    if !PROFILE_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    if PROFILE_ACTIVE.load(Ordering::Relaxed) {
        return false;
    }

    // Clear sample buffer
    SAMPLE_BUFFER_INDEX.store(0, Ordering::Relaxed);
    unsafe {
        for sample in SAMPLE_BUFFER.iter_mut() {
            sample.valid = false;
        }
    }

    // Configure based on source
    match source {
        ProfileSource::Timer => {
            // Timer-based profiling - uses APIC timer or external mechanism
            // The interval is handled externally
        }
        ProfileSource::CpuCycles
        | ProfileSource::Instructions
        | ProfileSource::CacheMisses
        | ProfileSource::BranchMisses => {
            if !PMC_SUPPORTED.load(Ordering::Relaxed) {
                return false;
            }
            // Configure PMC for event-based sampling
            unsafe {
                configure_pmc(source, interval_us as u64);
            }
        }
        _ => {
            // Other sources not yet implemented
        }
    }

    PROFILE_ACTIVE.store(true, Ordering::Release);
    crate::serial_println!("[Profile] Started {:?} profiling, interval {}us", source, interval_us);
    true
}

/// Stop profiling
pub fn profile_stop() {
    let _guard = PROFILE_LOCK.lock();

    if !PROFILE_ACTIVE.load(Ordering::Relaxed) {
        return;
    }

    // Disable PMC if active
    if PMC_SUPPORTED.load(Ordering::Relaxed) {
        unsafe {
            // Disable all counters
            wrmsr(msr::PERF_GLOBAL_CTRL, 0);
        }
    }

    PROFILE_ACTIVE.store(false, Ordering::Release);
    crate::serial_println!("[Profile] Stopped");
}

/// Check if profiling is active
pub fn profile_is_active() -> bool {
    PROFILE_ACTIVE.load(Ordering::Relaxed)
}

/// Configure PMC for sampling
unsafe fn configure_pmc(source: ProfileSource, sample_interval: u64) {
    let event = match source {
        ProfileSource::CpuCycles => events::CPU_CYCLES,
        ProfileSource::Instructions => events::INSTRUCTIONS_RETIRED,
        ProfileSource::CacheMisses => events::LLC_MISSES,
        ProfileSource::BranchMisses => events::BRANCH_MISSES,
        _ => return,
    };

    // Configure PERFEVTSEL0
    // Bits: USR (16), OS (17), INT (20), EN (22), Event (0-7), UMask (8-15)
    let evtsel = ((event & 0xFF) as u64)
        | (((event >> 8) & 0xFF) as u64) << 8
        | (1 << 16)  // USR - count in user mode
        | (1 << 17)  // OS - count in kernel mode
        | (1 << 20)  // INT - enable interrupt on overflow
        | (1 << 22); // EN - enable counter

    wrmsr(msr::PERFEVTSEL_BASE, evtsel);

    // Set counter to overflow after sample_interval events
    let counter_value = 0u64.wrapping_sub(sample_interval);
    wrmsr(msr::PMC_BASE, counter_value);

    // Enable counter 0
    wrmsr(msr::PERF_GLOBAL_CTRL, 1);
}

// ============================================================================
// Sample Recording
// ============================================================================

/// Record a profile sample (called from interrupt handler)
pub fn profile_record_sample(cpu: u32, ip: u64, sp: u64, source: ProfileSource) {
    if !PROFILE_ACTIVE.load(Ordering::Acquire) {
        return;
    }

    let idx = SAMPLE_BUFFER_INDEX.fetch_add(1, Ordering::Relaxed) as usize % MAX_PROFILE_SAMPLES;

    unsafe {
        SAMPLE_BUFFER[idx] = ProfileSample {
            valid: true,
            cpu,
            ip,
            sp,
            timestamp: read_tsc(),
            source,
            count: TOTAL_SAMPLES.load(Ordering::Relaxed),
        };
    }

    TOTAL_SAMPLES.fetch_add(1, Ordering::Relaxed);
}

/// Record sample with stack capture
pub fn profile_record_sample_with_stack(
    cpu: u32,
    ip: u64,
    sp: u64,
    _bp: u64,
    source: ProfileSource,
) {
    profile_record_sample(cpu, ip, sp, source);

    // Stack capture would walk frame pointers here
    // For now, just record the sample
}

// ============================================================================
// Sample Access
// ============================================================================

/// Get profile samples
pub fn profile_get_samples(max_samples: usize) -> ([ProfileSample; 64], usize) {
    let mut samples = [ProfileSample::default(); 64];
    let mut count = 0;

    let limit = max_samples.min(64);

    unsafe {
        for sample in SAMPLE_BUFFER.iter() {
            if count >= limit {
                break;
            }
            if sample.valid {
                samples[count] = *sample;
                count += 1;
            }
        }
    }

    (samples, count)
}

/// Clear sample buffer
pub fn profile_clear_samples() {
    let _guard = PROFILE_LOCK.lock();

    unsafe {
        for sample in SAMPLE_BUFFER.iter_mut() {
            sample.valid = false;
        }
    }

    SAMPLE_BUFFER_INDEX.store(0, Ordering::Relaxed);
}

// ============================================================================
// Stack Capture
// ============================================================================

/// Enable/disable stack capture
pub fn profile_set_stack_capture(enable: bool) {
    CAPTURE_STACK.store(enable, Ordering::Relaxed);
}

/// Check if stack capture is enabled
pub fn profile_is_stack_capture_enabled() -> bool {
    CAPTURE_STACK.load(Ordering::Relaxed)
}

/// Capture call stack from frame pointer
pub fn profile_capture_stack(bp: u64) -> StackSample {
    let mut stack = StackSample::default();

    #[cfg(target_arch = "x86_64")]
    {
        let mut frame_ptr = bp;

        for i in 0..MAX_STACK_DEPTH {
            if frame_ptr == 0 || frame_ptr < 0x1000 {
                break;
            }

            // Validate frame pointer is accessible
            // In a real implementation, we'd check page tables

            unsafe {
                // Return address is at frame_ptr + 8
                let return_addr = *((frame_ptr + 8) as *const u64);

                if return_addr == 0 {
                    break;
                }

                stack.frames[i] = return_addr;
                stack.depth = (i + 1) as u8;

                // Previous frame pointer is at frame_ptr
                frame_ptr = *(frame_ptr as *const u64);
            }
        }
    }

    stack
}

// ============================================================================
// PMC Access
// ============================================================================

/// Read PMC counter
pub fn profile_read_pmc(counter: u32) -> u64 {
    if !PMC_SUPPORTED.load(Ordering::Relaxed) {
        return 0;
    }

    if counter >= PMC_COUNTERS.load(Ordering::Relaxed) {
        return 0;
    }

    unsafe { rdmsr(msr::PMC_BASE + counter) }
}

/// Read fixed counter
pub fn profile_read_fixed_counter(counter: u32) -> u64 {
    if !PMC_SUPPORTED.load(Ordering::Relaxed) {
        return 0;
    }

    if counter >= FIXED_COUNTERS.load(Ordering::Relaxed) {
        return 0;
    }

    unsafe { rdmsr(msr::FIXED_CTR0 + counter) }
}

/// Get instruction count (fixed counter 0)
pub fn profile_get_instructions() -> u64 {
    profile_read_fixed_counter(0)
}

/// Get CPU cycles (fixed counter 1)
pub fn profile_get_cycles() -> u64 {
    profile_read_fixed_counter(1)
}

/// Get reference cycles (fixed counter 2)
pub fn profile_get_ref_cycles() -> u64 {
    profile_read_fixed_counter(2)
}

// ============================================================================
// Statistics
// ============================================================================

/// Profile statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ProfileStats {
    pub initialized: bool,
    pub active: bool,
    pub pmc_supported: bool,
    pub pmc_version: u32,
    pub pmc_counters: u32,
    pub fixed_counters: u32,
    pub total_samples: u64,
    pub dropped_samples: u64,
    pub buffer_size: u32,
    pub stack_capture: bool,
}

/// Get profile statistics
pub fn profile_get_stats() -> ProfileStats {
    ProfileStats {
        initialized: PROFILE_INITIALIZED.load(Ordering::Relaxed),
        active: PROFILE_ACTIVE.load(Ordering::Relaxed),
        pmc_supported: PMC_SUPPORTED.load(Ordering::Relaxed),
        pmc_version: PMC_VERSION.load(Ordering::Relaxed),
        pmc_counters: PMC_COUNTERS.load(Ordering::Relaxed),
        fixed_counters: FIXED_COUNTERS.load(Ordering::Relaxed),
        total_samples: TOTAL_SAMPLES.load(Ordering::Relaxed),
        dropped_samples: DROPPED_SAMPLES.load(Ordering::Relaxed),
        buffer_size: MAX_PROFILE_SAMPLES as u32,
        stack_capture: CAPTURE_STACK.load(Ordering::Relaxed),
    }
}

/// Check if profiling is initialized
pub fn profile_is_initialized() -> bool {
    PROFILE_INITIALIZED.load(Ordering::Acquire)
}

// ============================================================================
// NT Compatibility
// ============================================================================

/// HalStartProfileInterrupt equivalent
pub fn hal_start_profile_interrupt(source: u32, interval: u32) -> bool {
    let src = match source {
        0 => ProfileSource::Timer,
        1 => ProfileSource::CpuCycles,
        2 => ProfileSource::Instructions,
        _ => ProfileSource::Timer,
    };

    profile_start(src, interval)
}

/// HalStopProfileInterrupt equivalent
pub fn hal_stop_profile_interrupt() {
    profile_stop()
}

/// HalSetProfileInterval equivalent
pub fn hal_set_profile_interval(interval: u32) {
    // Would restart profiling with new interval
    // For now, just record the desired interval
    let _ = interval;
}

/// KeQueryPerformanceCounter equivalent (returns PMC/TSC)
pub fn ke_query_performance_counter() -> u64 {
    if PMC_SUPPORTED.load(Ordering::Relaxed) {
        profile_get_cycles()
    } else {
        read_tsc()
    }
}
