//! Executive Profile Objects
//!
//! Provides CPU profiling support for performance analysis:
//! - Profile object creation and management
//! - Range-based sampling (code/data profiling)
//! - Bucket-based hit counting
//! - Multi-processor support with CPU affinity
//! - Multiple profile sources (timer, cache, branch, etc.)
//!
//! Based on Windows Server 2003 base/ntos/ex/profile.c

use crate::ke::SpinLock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

extern crate alloc;

/// Maximum active profiles
pub const ACTIVE_PROFILE_LIMIT: usize = 8;

/// Minimum bucket size (log2) - 4 bytes
pub const PROFILE_MIN_BUCKET_SIZE: u32 = 2;

/// Maximum bucket size (log2)
pub const PROFILE_MAX_BUCKET_SIZE: u32 = 31;

/// Profile access rights
pub mod profile_access {
    pub const PROFILE_CONTROL: u32 = 0x0001;
    pub const PROFILE_ALL_ACCESS: u32 = 0x001F0001;
}

/// Profile sources (what triggers profile samples)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ProfileSource {
    /// Time-based sampling (default)
    Time = 0,
    /// Processor cycle counter
    TotalCycles = 1,
    /// Retired instructions
    InstructionRetired = 2,
    /// Cache misses
    CacheMisses = 3,
    /// Branch mispredictions
    BranchMispredictions = 4,
    /// Pipeline stalls
    PipelineStalls = 5,
    /// TLB misses
    TlbMisses = 6,
    /// Floating point operations
    FloatingPointInstructions = 7,
    /// Branch instructions
    BranchInstructions = 8,
    /// Memory references
    MemoryBarrierCycles = 9,
    /// Maximum profile source
    Maximum = 10,
}

impl From<u32> for ProfileSource {
    fn from(value: u32) -> Self {
        match value {
            0 => ProfileSource::Time,
            1 => ProfileSource::TotalCycles,
            2 => ProfileSource::InstructionRetired,
            3 => ProfileSource::CacheMisses,
            4 => ProfileSource::BranchMispredictions,
            5 => ProfileSource::PipelineStalls,
            6 => ProfileSource::TlbMisses,
            7 => ProfileSource::FloatingPointInstructions,
            8 => ProfileSource::BranchInstructions,
            9 => ProfileSource::MemoryBarrierCycles,
            _ => ProfileSource::Time,
        }
    }
}

/// Profile source name
pub fn profile_source_name(source: ProfileSource) -> &'static str {
    match source {
        ProfileSource::Time => "Time",
        ProfileSource::TotalCycles => "Cycles",
        ProfileSource::InstructionRetired => "Instructions",
        ProfileSource::CacheMisses => "CacheMisses",
        ProfileSource::BranchMispredictions => "BranchMispredict",
        ProfileSource::PipelineStalls => "PipelineStalls",
        ProfileSource::TlbMisses => "TlbMisses",
        ProfileSource::FloatingPointInstructions => "FloatingPoint",
        ProfileSource::BranchInstructions => "Branches",
        ProfileSource::MemoryBarrierCycles => "MemoryBarrier",
        ProfileSource::Maximum => "Unknown",
    }
}

/// Profile state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ProfileState {
    /// Profile not started
    Stopped = 0,
    /// Profile running
    Running = 1,
    /// Profile paused
    Paused = 2,
}

/// Profile bucket data
#[derive(Debug)]
pub struct ProfileBucket {
    /// Hit count for this bucket
    pub hit_count: AtomicU32,
}

impl ProfileBucket {
    pub fn new() -> Self {
        Self {
            hit_count: AtomicU32::new(0),
        }
    }

    pub fn increment(&self) {
        self.hit_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> u32 {
        self.hit_count.load(Ordering::Relaxed)
    }

    pub fn reset(&self) {
        self.hit_count.store(0, Ordering::Relaxed);
    }
}

/// Profile object
#[derive(Debug)]
pub struct Profile {
    /// Profile ID
    pub id: u32,
    /// Profile name
    pub name: String,
    /// Process ID (0 for system-wide)
    pub process_id: u64,
    /// Range base address
    pub range_base: usize,
    /// Range size
    pub range_size: usize,
    /// Bucket size (log2)
    pub bucket_shift: u32,
    /// Profile source
    pub source: ProfileSource,
    /// Processor affinity mask
    pub affinity: u64,
    /// Current state
    pub state: ProfileState,
    /// Hit buckets
    pub buckets: Vec<ProfileBucket>,
    /// Total hits
    pub total_hits: AtomicU64,
    /// Start timestamp
    pub start_time: u64,
    /// Total run time
    pub run_time: AtomicU64,
}

impl Profile {
    pub fn new(
        id: u32,
        name: &str,
        process_id: u64,
        range_base: usize,
        range_size: usize,
        bucket_shift: u32,
        source: ProfileSource,
        affinity: u64,
    ) -> Self {
        // Calculate bucket count
        let bucket_size = 1usize << bucket_shift;
        let bucket_count = (range_size + bucket_size - 1) / bucket_size;

        let mut buckets = Vec::with_capacity(bucket_count);
        for _ in 0..bucket_count {
            buckets.push(ProfileBucket::new());
        }

        Self {
            id,
            name: String::from(name),
            process_id,
            range_base,
            range_size,
            bucket_shift,
            source,
            affinity,
            state: ProfileState::Stopped,
            buckets,
            total_hits: AtomicU64::new(0),
            start_time: 0,
            run_time: AtomicU64::new(0),
        }
    }

    /// Record a hit at the given address
    pub fn record_hit(&self, address: usize) -> bool {
        if self.state != ProfileState::Running {
            return false;
        }

        if address < self.range_base || address >= self.range_base + self.range_size {
            return false;
        }

        let offset = address - self.range_base;
        let bucket_index = offset >> self.bucket_shift;

        if bucket_index < self.buckets.len() {
            self.buckets[bucket_index].increment();
            self.total_hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        false
    }

    /// Get bucket hit count
    pub fn get_bucket(&self, index: usize) -> Option<u32> {
        self.buckets.get(index).map(|b| b.get())
    }

    /// Get all non-zero bucket hits
    pub fn get_hits(&self) -> Vec<(usize, u32)> {
        let mut hits = Vec::new();
        for (i, bucket) in self.buckets.iter().enumerate() {
            let count = bucket.get();
            if count > 0 {
                hits.push((i, count));
            }
        }
        hits
    }

    /// Reset all buckets
    pub fn reset(&mut self) {
        for bucket in &self.buckets {
            bucket.reset();
        }
        self.total_hits.store(0, Ordering::Relaxed);
    }

    /// Get bucket address range
    pub fn get_bucket_range(&self, index: usize) -> Option<(usize, usize)> {
        if index >= self.buckets.len() {
            return None;
        }

        let bucket_size = 1usize << self.bucket_shift;
        let start = self.range_base + (index * bucket_size);
        let end = (start + bucket_size).min(self.range_base + self.range_size);
        Some((start, end))
    }
}

/// Profile interval settings
#[derive(Debug, Clone, Copy)]
pub struct ProfileInterval {
    /// Source
    pub source: ProfileSource,
    /// Interval in 100ns units
    pub interval: u32,
}

impl Default for ProfileInterval {
    fn default() -> Self {
        Self {
            source: ProfileSource::Time,
            interval: 10000, // 1ms default
        }
    }
}

/// Profile manager state
#[derive(Debug)]
pub struct ProfileState_ {
    /// Active profiles
    profiles: BTreeMap<u32, Profile>,
    /// Next profile ID
    next_id: u32,
    /// Profile intervals by source
    intervals: [ProfileInterval; 10],
    /// Global profiling enabled
    enabled: bool,
}

impl ProfileState_ {
    pub const fn new() -> Self {
        const DEFAULT_INTERVAL: ProfileInterval = ProfileInterval {
            source: ProfileSource::Time,
            interval: 10000,
        };

        Self {
            profiles: BTreeMap::new(),
            next_id: 1,
            intervals: [DEFAULT_INTERVAL; 10],
            enabled: false,
        }
    }
}

/// Global profile state
static mut PROFILE_STATE: Option<SpinLock<ProfileState_>> = None;

/// Statistics
static PROFILES_CREATED: AtomicU64 = AtomicU64::new(0);
static PROFILES_STARTED: AtomicU64 = AtomicU64::new(0);
static PROFILES_STOPPED: AtomicU64 = AtomicU64::new(0);
static TOTAL_HITS: AtomicU64 = AtomicU64::new(0);
static PROFILE_INITIALIZED: AtomicBool = AtomicBool::new(false);

fn get_profile_state() -> &'static SpinLock<ProfileState_> {
    unsafe {
        PROFILE_STATE
            .as_ref()
            .expect("Profile subsystem not initialized")
    }
}

/// Initialize profile subsystem
pub fn exp_profile_init() {
    unsafe {
        PROFILE_STATE = Some(SpinLock::new(ProfileState_::new()));
    }

    PROFILE_INITIALIZED.store(true, Ordering::SeqCst);
    crate::serial_println!("[EX] Profile subsystem initialized");
}

/// Create a profile object
pub fn exp_create_profile(
    name: &str,
    process_id: u64,
    range_base: usize,
    range_size: usize,
    bucket_shift: u32,
    source: ProfileSource,
    affinity: u64,
) -> Result<u32, &'static str> {
    // Validate parameters
    if bucket_shift < PROFILE_MIN_BUCKET_SIZE || bucket_shift > PROFILE_MAX_BUCKET_SIZE {
        return Err("Invalid bucket size");
    }

    if range_size == 0 {
        return Err("Invalid range size");
    }

    let state = get_profile_state();
    let mut guard = state.lock();

    // Check active profile limit
    let active_count = guard.profiles.values().filter(|p| p.state == ProfileState::Running).count();
    if active_count >= ACTIVE_PROFILE_LIMIT {
        return Err("Too many active profiles");
    }

    let id = guard.next_id;
    guard.next_id += 1;

    let profile = Profile::new(
        id,
        name,
        process_id,
        range_base,
        range_size,
        bucket_shift,
        source,
        affinity,
    );

    guard.profiles.insert(id, profile);
    PROFILES_CREATED.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!(
        "[EX] Profile {} created: {} ({:#x}-{:#x}, bucket={})",
        id,
        name,
        range_base,
        range_base + range_size,
        1 << bucket_shift
    );

    Ok(id)
}

/// Start profiling
pub fn exp_start_profile(profile_id: u32) -> Result<(), &'static str> {
    let state = get_profile_state();
    let mut guard = state.lock();

    let profile = guard.profiles.get_mut(&profile_id).ok_or("Profile not found")?;

    if profile.state == ProfileState::Running {
        return Err("Profile already running");
    }

    profile.state = ProfileState::Running;
    profile.start_time = unsafe { core::arch::x86_64::_rdtsc() };

    guard.enabled = true;
    PROFILES_STARTED.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[EX] Profile {} started", profile_id);

    Ok(())
}

/// Stop profiling
pub fn exp_stop_profile(profile_id: u32) -> Result<(), &'static str> {
    let state = get_profile_state();
    let mut guard = state.lock();

    // First check if profile exists and is running
    {
        let profile = guard.profiles.get(&profile_id).ok_or("Profile not found")?;
        if profile.state != ProfileState::Running {
            return Err("Profile not running");
        }
    }

    // Now update the profile
    let total_hits = {
        let profile = guard.profiles.get_mut(&profile_id).unwrap();
        let now = unsafe { core::arch::x86_64::_rdtsc() };
        let elapsed = now.saturating_sub(profile.start_time);
        profile.run_time.fetch_add(elapsed, Ordering::Relaxed);
        profile.state = ProfileState::Stopped;
        profile.total_hits.load(Ordering::Relaxed)
    };

    PROFILES_STOPPED.fetch_add(1, Ordering::Relaxed);

    // Check if any profiles are still running
    let any_running = guard.profiles.values().any(|p| p.state == ProfileState::Running);
    if !any_running {
        guard.enabled = false;
    }

    crate::serial_println!("[EX] Profile {} stopped (hits={})", profile_id, total_hits);

    Ok(())
}

/// Record a profile hit (called from interrupt handler)
pub fn exp_record_profile_hit(address: usize, process_id: u64) {
    if !PROFILE_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    let state = get_profile_state();
    let guard = state.lock();

    if !guard.enabled {
        return;
    }

    for profile in guard.profiles.values() {
        if profile.state != ProfileState::Running {
            continue;
        }

        // Check process filter
        if profile.process_id != 0 && profile.process_id != process_id {
            continue;
        }

        if profile.record_hit(address) {
            TOTAL_HITS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Delete a profile
pub fn exp_delete_profile(profile_id: u32) -> Result<(), &'static str> {
    let state = get_profile_state();
    let mut guard = state.lock();

    let profile = guard.profiles.get(&profile_id).ok_or("Profile not found")?;

    if profile.state == ProfileState::Running {
        return Err("Cannot delete running profile");
    }

    guard.profiles.remove(&profile_id);

    crate::serial_println!("[EX] Profile {} deleted", profile_id);

    Ok(())
}

/// Get profile information
pub fn exp_get_profile(profile_id: u32) -> Option<ProfileInfo> {
    let state = get_profile_state();
    let guard = state.lock();

    guard.profiles.get(&profile_id).map(|p| ProfileInfo {
        id: p.id,
        name: p.name.clone(),
        process_id: p.process_id,
        range_base: p.range_base,
        range_size: p.range_size,
        bucket_shift: p.bucket_shift,
        bucket_count: p.buckets.len(),
        source: p.source,
        affinity: p.affinity,
        state: p.state,
        total_hits: p.total_hits.load(Ordering::Relaxed),
        run_time: p.run_time.load(Ordering::Relaxed),
    })
}

/// Profile info (copy for external use)
#[derive(Debug, Clone)]
pub struct ProfileInfo {
    pub id: u32,
    pub name: String,
    pub process_id: u64,
    pub range_base: usize,
    pub range_size: usize,
    pub bucket_shift: u32,
    pub bucket_count: usize,
    pub source: ProfileSource,
    pub affinity: u64,
    pub state: ProfileState,
    pub total_hits: u64,
    pub run_time: u64,
}

/// Get profile hits
pub fn exp_get_profile_hits(profile_id: u32) -> Option<Vec<(usize, u32)>> {
    let state = get_profile_state();
    let guard = state.lock();

    guard.profiles.get(&profile_id).map(|p| p.get_hits())
}

/// Get top N profile hits
pub fn exp_get_top_hits(profile_id: u32, count: usize) -> Option<Vec<(usize, usize, u32)>> {
    let state = get_profile_state();
    let guard = state.lock();

    guard.profiles.get(&profile_id).map(|p| {
        let mut hits = p.get_hits();
        hits.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by hit count descending
        hits.truncate(count);

        hits.iter().filter_map(|(bucket_idx, count)| {
            p.get_bucket_range(*bucket_idx).map(|(start, _end)| (start, *bucket_idx, *count))
        }).collect()
    })
}

/// Reset profile buckets
pub fn exp_reset_profile(profile_id: u32) -> Result<(), &'static str> {
    let state = get_profile_state();
    let mut guard = state.lock();

    let profile = guard.profiles.get_mut(&profile_id).ok_or("Profile not found")?;
    profile.reset();

    crate::serial_println!("[EX] Profile {} reset", profile_id);

    Ok(())
}

/// List all profiles
pub fn exp_list_profiles() -> Vec<ProfileInfo> {
    let state = get_profile_state();
    let guard = state.lock();

    guard.profiles.values().map(|p| ProfileInfo {
        id: p.id,
        name: p.name.clone(),
        process_id: p.process_id,
        range_base: p.range_base,
        range_size: p.range_size,
        bucket_shift: p.bucket_shift,
        bucket_count: p.buckets.len(),
        source: p.source,
        affinity: p.affinity,
        state: p.state,
        total_hits: p.total_hits.load(Ordering::Relaxed),
        run_time: p.run_time.load(Ordering::Relaxed),
    }).collect()
}

/// Set profile interval
pub fn exp_set_profile_interval(source: ProfileSource, interval: u32) {
    let state = get_profile_state();
    let mut guard = state.lock();

    let idx = source as usize;
    if idx < guard.intervals.len() {
        guard.intervals[idx].interval = interval;
        crate::serial_println!(
            "[EX] Profile interval for {:?} set to {}",
            source,
            interval
        );
    }
}

/// Get profile interval
pub fn exp_get_profile_interval(source: ProfileSource) -> u32 {
    let state = get_profile_state();
    let guard = state.lock();

    let idx = source as usize;
    if idx < guard.intervals.len() {
        guard.intervals[idx].interval
    } else {
        10000 // Default
    }
}

/// Get profile statistics
pub fn exp_profile_get_stats() -> (u64, u64, u64, u64, usize) {
    let state = get_profile_state();
    let guard = state.lock();

    let active = guard.profiles.values().filter(|p| p.state == ProfileState::Running).count();

    (
        PROFILES_CREATED.load(Ordering::Relaxed),
        PROFILES_STARTED.load(Ordering::Relaxed),
        PROFILES_STOPPED.load(Ordering::Relaxed),
        TOTAL_HITS.load(Ordering::Relaxed),
        active,
    )
}

/// Check if profiling is enabled globally
pub fn exp_profile_enabled() -> bool {
    if !PROFILE_INITIALIZED.load(Ordering::Relaxed) {
        return false;
    }

    let state = get_profile_state();
    let guard = state.lock();
    guard.enabled
}

/// Query performance counter (high-resolution timer)
pub fn nt_query_performance_counter() -> (u64, u64) {
    // Return TSC value and frequency estimate
    let counter = unsafe { core::arch::x86_64::_rdtsc() };
    // Assume ~2GHz as a placeholder (real implementation would calibrate)
    let frequency = 2_000_000_000u64;

    (counter, frequency)
}
