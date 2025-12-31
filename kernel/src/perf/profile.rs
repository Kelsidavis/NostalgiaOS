//! CPU Profiling Support
//!
//! Implements CPU sampling profiler for performance analysis.
//! Uses timer interrupts to collect instruction pointer samples.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU32, Ordering};
use crate::ke::SpinLock;

/// Maximum profile samples to cache
pub const MAX_PROFILE_SAMPLES: usize = 4096;

/// Profile source types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ProfileSource {
    /// Time-based profiling
    Time = 0,
    /// Alignment fixups
    AlignmentFixup = 1,
    /// Total issues
    TotalIssues = 2,
    /// Branch instructions
    BranchInstructions = 3,
    /// Branch mispredictions
    BranchMispredictions = 4,
    /// Cache misses
    CacheMisses = 5,
    /// L1 data cache misses
    L1DataCacheMiss = 6,
    /// L1 instruction cache misses
    L1InstructionCacheMiss = 7,
    /// L2 cache misses
    L2CacheMiss = 8,
    /// TLB misses
    TlbMiss = 9,
    /// Maximum value marker
    Maximum = 10,
}

/// Profile sample
#[derive(Debug, Clone, Copy)]
pub struct ProfileSample {
    /// Instruction pointer
    pub ip: u64,
    /// Timestamp (tick count)
    pub timestamp: u64,
    /// Process ID
    pub pid: u32,
    /// Thread ID
    pub tid: u32,
    /// CPU number
    pub cpu: u32,
    /// Profile source
    pub source: ProfileSource,
}

impl ProfileSample {
    pub const fn empty() -> Self {
        Self {
            ip: 0,
            timestamp: 0,
            pid: 0,
            tid: 0,
            cpu: 0,
            source: ProfileSource::Time,
        }
    }
}

/// Profile sample cache for collecting samples
pub struct ProfileCache {
    pub samples: [ProfileSample; MAX_PROFILE_SAMPLES],
    pub count: usize,
    pub head: usize,
    pub tail: usize,
}

impl ProfileCache {
    pub const fn new() -> Self {
        const EMPTY: ProfileSample = ProfileSample::empty();
        Self {
            samples: [EMPTY; MAX_PROFILE_SAMPLES],
            count: 0,
            head: 0,
            tail: 0,
        }
    }

    pub fn add(&mut self, sample: ProfileSample) {
        if self.count < MAX_PROFILE_SAMPLES {
            self.samples[self.tail] = sample;
            self.tail = (self.tail + 1) % MAX_PROFILE_SAMPLES;
            self.count += 1;
        }
    }

    pub fn drain(&mut self) -> Vec<ProfileSample> {
        let mut result = Vec::with_capacity(self.count);
        while self.count > 0 {
            result.push(self.samples[self.head]);
            self.head = (self.head + 1) % MAX_PROFILE_SAMPLES;
            self.count -= 1;
        }
        result
    }

    pub fn clear(&mut self) {
        self.count = 0;
        self.head = 0;
        self.tail = 0;
    }
}

/// Profiler state
static PROFILING_ACTIVE: AtomicBool = AtomicBool::new(false);
static PROFILE_INTERVAL: AtomicU32 = AtomicU32::new(10000); // 10ms default
static mut PROFILE_CACHE: ProfileCache = ProfileCache::new();
static PROFILE_LOCK: SpinLock<()> = SpinLock::new(());

/// Current profile source
static mut PROFILE_SOURCE: ProfileSource = ProfileSource::Time;
static mut PROFILE_SOURCE_REQUESTED: ProfileSource = ProfileSource::Time;

/// Statistics
static SAMPLES_COLLECTED: AtomicU64 = AtomicU64::new(0);
static SAMPLES_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Initialize profiling subsystem
pub fn init() {
    crate::serial_println!("[PERF] Initializing CPU profiler");

    // Reset cache
    let _guard = PROFILE_LOCK.lock();
    unsafe {
        PROFILE_CACHE.clear();
    }

    crate::serial_println!("[PERF] CPU profiler initialized (interval: {} us)",
        PROFILE_INTERVAL.load(Ordering::Relaxed));
}

/// Start profiling
pub fn start() {
    if PROFILING_ACTIVE.load(Ordering::Relaxed) {
        return;
    }

    crate::serial_println!("[PERF] Starting CPU profiler");

    let _guard = PROFILE_LOCK.lock();

    unsafe {
        PROFILE_SOURCE = PROFILE_SOURCE_REQUESTED;
        PROFILE_CACHE.clear();
    }

    PROFILING_ACTIVE.store(true, Ordering::SeqCst);
}

/// Stop profiling
pub fn stop() {
    if !PROFILING_ACTIVE.load(Ordering::Relaxed) {
        return;
    }

    crate::serial_println!("[PERF] Stopping CPU profiler");

    PROFILING_ACTIVE.store(false, Ordering::SeqCst);

    // Flush remaining samples
    flush();
}

/// Check if profiling is active
pub fn is_active() -> bool {
    PROFILING_ACTIVE.load(Ordering::Relaxed)
}

/// Set profile interval (microseconds)
pub fn set_interval(interval_us: u32) {
    let interval = interval_us.max(100).min(1_000_000); // 100us to 1s
    PROFILE_INTERVAL.store(interval, Ordering::Relaxed);
}

/// Get profile interval
pub fn get_interval() -> u32 {
    PROFILE_INTERVAL.load(Ordering::Relaxed)
}

/// Set profile source
pub fn set_source(source: ProfileSource) {
    unsafe {
        PROFILE_SOURCE_REQUESTED = source;
        if !PROFILING_ACTIVE.load(Ordering::Relaxed) {
            PROFILE_SOURCE = source;
        }
    }
}

/// Get current profile source
pub fn get_source() -> ProfileSource {
    unsafe { PROFILE_SOURCE }
}

/// Record a profile sample (called from timer interrupt)
pub fn record_sample(ip: u64, cpu: u32) {
    if !PROFILING_ACTIVE.load(Ordering::Relaxed) {
        return;
    }

    let sample = ProfileSample {
        ip,
        timestamp: crate::hal::apic::get_tick_count(),
        pid: crate::ke::ke_get_current_process_id(),
        tid: crate::ke::ke_get_current_thread_id(),
        cpu,
        source: unsafe { PROFILE_SOURCE },
    };

    let _guard = PROFILE_LOCK.lock();

    unsafe {
        if PROFILE_CACHE.count < MAX_PROFILE_SAMPLES {
            PROFILE_CACHE.add(sample);
            SAMPLES_COLLECTED.fetch_add(1, Ordering::Relaxed);
        } else {
            SAMPLES_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Update perf counter
    super::log_profile_sample(ip);
}

/// Flush profile cache
pub fn flush() {
    let _guard = PROFILE_LOCK.lock();

    unsafe {
        let samples = PROFILE_CACHE.drain();
        let count = samples.len();
        if count > 0 {
            crate::serial_println!("[PERF] Flushed {} profile samples", count);
        }
    }
}

/// Get profiling statistics
#[derive(Debug, Clone, Copy)]
pub struct ProfileStats {
    pub samples_collected: u64,
    pub samples_dropped: u64,
    pub cache_size: usize,
    pub interval_us: u32,
    pub source: ProfileSource,
    pub active: bool,
}

pub fn get_stats() -> ProfileStats {
    let _guard = PROFILE_LOCK.lock();

    ProfileStats {
        samples_collected: SAMPLES_COLLECTED.load(Ordering::Relaxed),
        samples_dropped: SAMPLES_DROPPED.load(Ordering::Relaxed),
        cache_size: unsafe { PROFILE_CACHE.count },
        interval_us: PROFILE_INTERVAL.load(Ordering::Relaxed),
        source: unsafe { PROFILE_SOURCE },
        active: PROFILING_ACTIVE.load(Ordering::Relaxed),
    }
}

/// Get cached samples (for analysis)
pub fn get_samples(max_count: usize) -> Vec<ProfileSample> {
    let _guard = PROFILE_LOCK.lock();

    unsafe {
        let mut result = Vec::new();
        let take = max_count.min(PROFILE_CACHE.count);

        for i in 0..take {
            let idx = (PROFILE_CACHE.head + i) % MAX_PROFILE_SAMPLES;
            result.push(PROFILE_CACHE.samples[idx]);
        }

        result
    }
}

/// Hot spot analysis - find most sampled addresses
pub fn find_hot_spots(max_count: usize) -> Vec<(u64, u32)> {
    use alloc::collections::BTreeMap;

    let _guard = PROFILE_LOCK.lock();

    let mut ip_counts: BTreeMap<u64, u32> = BTreeMap::new();

    unsafe {
        for i in 0..PROFILE_CACHE.count {
            let idx = (PROFILE_CACHE.head + i) % MAX_PROFILE_SAMPLES;
            let ip = PROFILE_CACHE.samples[idx].ip;
            *ip_counts.entry(ip).or_insert(0) += 1;
        }
    }

    // Sort by count and take top N
    let mut sorted: Vec<(u64, u32)> = ip_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(max_count);

    sorted
}
