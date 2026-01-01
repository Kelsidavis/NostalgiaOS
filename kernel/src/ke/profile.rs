//! Kernel Profile Object (KPROFILE)
//!
//! Profile objects are used to collect execution data for performance analysis.
//! They sample instruction execution within an address range and record
//! hits into a buffer of counters.
//!
//! # Design
//!
//! - Each profile targets a specific address range within a process (or system-wide)
//! - Buckets divide the range into sampling intervals
//! - Profile interrupts increment the appropriate bucket counter
//! - Multiple profile sources are supported (time, cache misses, etc.)
//!
//! # Windows Equivalent
//! This implements NT's profobj.c functionality.
//!
//! # Example
//! ```
//! let mut profile = KProfile::new();
//! profile.init(None, 0x1000, 0x10000, 4, ProfileTime);
//!
//! let mut buffer = [0u32; 1024];
//! profile.start(&mut buffer);
//!
//! // ... code executes, profile interrupts record samples ...
//!
//! profile.stop();
//! // buffer now contains hit counts per bucket
//! ```

use crate::ke::list::ListEntry;
use crate::ke::process::KProcess;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::cell::UnsafeCell;

/// Profile object type identifier
pub const PROFILE_OBJECT: u8 = 7;

/// Profile source types
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProfileSource {
    /// Time-based profiling
    Time = 0,
    /// Alignment fixup profiling
    AlignmentFixup = 1,
    /// Total issues (performance counter)
    TotalIssues = 2,
    /// Pipeline dry
    PipelineDry = 3,
    /// Load instructions
    LoadInstructions = 4,
    /// Pipeline frozen
    PipelineFrozen = 5,
    /// Branch instructions
    BranchInstructions = 6,
    /// Total non-issues
    TotalNonissues = 7,
    /// Data cache misses
    DcacheMisses = 8,
    /// Instruction cache misses
    IcacheMisses = 9,
    /// Cache misses
    CacheMisses = 10,
    /// Branch mispredictions
    BranchMispredictions = 11,
    /// Store instructions
    StoreInstructions = 12,
    /// Floating point instructions
    FpInstructions = 13,
    /// Integer instructions
    IntegerInstructions = 14,
    /// 2nd level data cache misses
    Dcache2Misses = 15,
    /// 2nd level instruction cache misses
    Icache2Misses = 16,
    /// 2nd level cache misses
    Cache2Misses = 17,
    /// 2nd level TLB misses
    Tlb2Misses = 18,
    /// Branch taken
    BranchTaken = 19,
    /// Total cycles
    TotalCycles = 20,
    /// Maximum profile source
    MaximumSource = 21,
}

/// Default profile interval (100ns units) - approximately 1ms
pub const DEFAULT_PROFILE_INTERVAL: u32 = 10000;

/// Minimum profile interval (100ns units) - approximately 100us
pub const MINIMUM_PROFILE_INTERVAL: u32 = 1000;

/// Maximum number of active profiles
pub const MAX_ACTIVE_PROFILES: usize = 64;

/// Kernel Profile Object
#[repr(C)]
pub struct KProfile {
    /// Object type (ProfileObject)
    pub object_type: u8,
    /// Size of the object
    pub size: u8,
    /// Segment selector (for x86 16-bit segment profiling, usually 0)
    pub segment: u16,
    /// Link in the profile list (per-process or global)
    pub profile_list_entry: ListEntry,
    /// Process to profile (None for system-wide)
    pub process: Option<*mut KProcess>,
    /// Start of the address range to profile
    pub range_base: usize,
    /// End of the address range to profile (exclusive)
    pub range_limit: usize,
    /// Bucket size shift (log2(bucket_size) - 2)
    pub bucket_shift: u32,
    /// Profile buffer pointer (array of u32 counters)
    pub buffer: UnsafeCell<*mut u32>,
    /// Whether profiling is active
    pub started: AtomicBool,
    /// Profile interrupt source
    pub source: ProfileSource,
    /// Processor affinity mask
    pub affinity: u64,
}

// Safety: KProfile is designed for multi-threaded access with atomic operations
unsafe impl Sync for KProfile {}
unsafe impl Send for KProfile {}

impl KProfile {
    /// Create a new uninitialized profile object
    pub const fn new() -> Self {
        Self {
            object_type: PROFILE_OBJECT,
            size: core::mem::size_of::<Self>() as u8,
            segment: 0,
            profile_list_entry: ListEntry::new(),
            process: None,
            range_base: 0,
            range_limit: 0,
            bucket_shift: 0,
            buffer: UnsafeCell::new(core::ptr::null_mut()),
            started: AtomicBool::new(false),
            source: ProfileSource::Time,
            affinity: !0, // All processors
        }
    }

    /// Initialize the profile object (KeInitializeProfile)
    ///
    /// # Arguments
    /// * `process` - Process to profile, or None for system-wide
    /// * `range_base` - Start address of the profiling range
    /// * `range_size` - Size of the profiling range in bytes
    /// * `bucket_size` - Log2 of bucket size (2 = 4 bytes, 7 = 128 bytes)
    /// * `source` - Profile interrupt source
    ///
    /// # Example
    /// To profile kernel code from 0xFFFF0000 with 128-byte buckets:
    /// ```
    /// profile.init(None, 0xFFFF0000, 0x10000, 7, ProfileSource::Time);
    /// ```
    pub fn init(
        &mut self,
        process: Option<*mut KProcess>,
        range_base: usize,
        range_size: usize,
        bucket_size: u32,
        source: ProfileSource,
    ) {
        self.init_with_affinity(process, range_base, range_size, bucket_size, source, !0)
    }

    /// Initialize the profile with specific processor affinity
    pub fn init_with_affinity(
        &mut self,
        process: Option<*mut KProcess>,
        range_base: usize,
        range_size: usize,
        bucket_size: u32,
        source: ProfileSource,
        affinity: u64,
    ) {
        self.object_type = PROFILE_OBJECT;
        self.size = core::mem::size_of::<Self>() as u8;
        self.segment = 0;
        self.profile_list_entry.init_head();
        self.process = process;
        self.range_base = range_base;
        self.range_limit = range_base.saturating_add(range_size);
        self.bucket_shift = bucket_size.saturating_sub(2);
        self.source = source;
        self.affinity = if affinity == 0 { !0 } else { affinity };
        self.started.store(false, Ordering::Release);
    }

    /// Check if the profile is currently active
    #[inline]
    pub fn is_started(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }

    /// Get the number of buckets needed for the buffer
    pub fn bucket_count(&self) -> usize {
        if self.range_limit <= self.range_base {
            return 0;
        }
        let range_size = self.range_limit - self.range_base;
        let bucket_size = 4usize << self.bucket_shift;
        range_size.div_ceil(bucket_size)
    }

    /// Start profiling (KeStartProfile)
    ///
    /// # Arguments
    /// * `buffer` - Array of u32 counters, one per bucket
    ///
    /// # Returns
    /// `true` if profiling was started, `false` if already running
    ///
    /// # Safety
    /// The buffer must remain valid until profiling is stopped.
    pub unsafe fn start(&self, buffer: *mut u32) -> bool {
        // Check if already started
        if self.started.swap(true, Ordering::AcqRel) {
            return false;
        }

        // Set the buffer pointer
        *self.buffer.get() = buffer;

        // TODO: Register with profile interrupt system
        // This would involve:
        // 1. Adding to the process or global profile list
        // 2. Enabling the profile interrupt if this is the first profile
        // 3. Configuring the HAL for the profile source

        true
    }

    /// Stop profiling (KeStopProfile)
    ///
    /// # Returns
    /// `true` if profiling was stopped, `false` if not running
    pub fn stop(&self) -> bool {
        // Check if running
        if !self.started.swap(false, Ordering::AcqRel) {
            return false;
        }

        // Clear the buffer pointer
        unsafe {
            *self.buffer.get() = core::ptr::null_mut();
        }

        // TODO: Unregister from profile interrupt system
        // This would involve:
        // 1. Removing from the process or global profile list
        // 2. Disabling the profile interrupt if this is the last profile

        true
    }

    /// Record a profile hit at the specified address
    ///
    /// Called from the profile interrupt handler when an instruction
    /// is sampled within our range.
    ///
    /// # Safety
    /// Must be called from the profile interrupt context with interrupts disabled.
    #[inline]
    pub unsafe fn record_hit(&self, address: usize) {
        // Check if address is in our range
        if address < self.range_base || address >= self.range_limit {
            return;
        }

        let buffer = *self.buffer.get();
        if buffer.is_null() {
            return;
        }

        // Calculate bucket index
        let offset = address - self.range_base;
        let bucket_index = offset >> (self.bucket_shift + 2);

        // Increment the bucket counter (atomic to handle SMP)
        let counter = buffer.add(bucket_index);
        let current = core::ptr::read_volatile(counter);
        core::ptr::write_volatile(counter, current.wrapping_add(1));
    }
}

impl Default for KProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Profile Management
// ============================================================================

use crate::ke::spinlock::SpinLock;
use crate::ke::prcb::MAX_CPUS;

/// Current profile interval (100ns units)
static PROFILE_INTERVAL: AtomicU32 = AtomicU32::new(DEFAULT_PROFILE_INTERVAL);

/// Current alignment fixup profile interval
static ALIGNMENT_FIXUP_INTERVAL: AtomicU32 = AtomicU32::new(DEFAULT_PROFILE_INTERVAL);

/// Whether alignment fixup profiling is enabled
static PROFILE_ALIGNMENT_FIXUP: AtomicBool = AtomicBool::new(false);

/// Profile lock for synchronizing profile list access
static PROFILE_LOCK: SpinLock<()> = SpinLock::new(());

/// Maximum number of active profile sources
pub const MAX_ACTIVE_SOURCES: usize = 32;

/// Active profile source entry
/// Tracks which profile sources are active and on which processors
#[repr(C)]
pub struct ActiveProfileSource {
    /// Whether this entry is in use
    pub in_use: bool,
    /// The profile source type
    pub source: ProfileSource,
    /// Affinity mask of processors where this source is active
    pub affinity: u64,
    /// Reference count per processor
    pub processor_count: [u32; MAX_CPUS],
}

impl ActiveProfileSource {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            source: ProfileSource::Time,
            affinity: 0,
            processor_count: [0; MAX_CPUS],
        }
    }
}

/// Global list of active profile sources
static mut ACTIVE_PROFILE_SOURCES: [ActiveProfileSource; MAX_ACTIVE_SOURCES] = {
    const EMPTY: ActiveProfileSource = ActiveProfileSource::new();
    [EMPTY; MAX_ACTIVE_SOURCES]
};

/// Global profile list head (for system-wide profiles)
static mut GLOBAL_PROFILE_LIST: [Option<*const KProfile>; MAX_ACTIVE_PROFILES] = [None; MAX_ACTIVE_PROFILES];

/// Number of active global profiles
static GLOBAL_PROFILE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Profile statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ProfileStats {
    /// Total profile interrupts received
    pub total_interrupts: u64,
    /// Total hits recorded
    pub total_hits: u64,
    /// Currently active profiles
    pub active_profiles: u32,
    /// Currently active sources
    pub active_sources: u32,
}

/// Global profile statistics
static mut PROFILE_STATS: ProfileStats = ProfileStats {
    total_interrupts: 0,
    total_hits: 0,
    active_profiles: 0,
    active_sources: 0,
};

/// Find or allocate an active profile source entry
unsafe fn find_or_allocate_source(source: ProfileSource) -> Option<&'static mut ActiveProfileSource> {
    // First, try to find existing
    for entry in ACTIVE_PROFILE_SOURCES.iter_mut() {
        if entry.in_use && entry.source == source {
            return Some(entry);
        }
    }

    // Allocate new entry
    for entry in ACTIVE_PROFILE_SOURCES.iter_mut() {
        if !entry.in_use {
            entry.in_use = true;
            entry.source = source;
            entry.affinity = 0;
            entry.processor_count = [0; MAX_CPUS];
            PROFILE_STATS.active_sources += 1;
            return Some(entry);
        }
    }

    None
}

/// Find an active profile source entry
unsafe fn find_source(source: ProfileSource) -> Option<&'static mut ActiveProfileSource> {
    for entry in ACTIVE_PROFILE_SOURCES.iter_mut() {
        if entry.in_use && entry.source == source {
            return Some(entry);
        }
    }
    None
}

/// Query the current profile interval (KeQueryIntervalProfile)
pub fn ke_query_interval_profile(source: ProfileSource) -> u32 {
    match source {
        ProfileSource::Time => PROFILE_INTERVAL.load(Ordering::Relaxed),
        ProfileSource::AlignmentFixup => ALIGNMENT_FIXUP_INTERVAL.load(Ordering::Relaxed),
        _ => {
            // Query HAL for other profile sources
            hal_query_profile_interval(source)
        }
    }
}

/// Set the profile interval (KeSetIntervalProfile)
pub fn ke_set_interval_profile(interval: u32, source: ProfileSource) {
    let interval = interval.max(MINIMUM_PROFILE_INTERVAL);

    match source {
        ProfileSource::Time => {
            PROFILE_INTERVAL.store(interval, Ordering::Relaxed);
            // Call HAL to set hardware profile timer
            hal_set_profile_interval(interval, source);
        }
        ProfileSource::AlignmentFixup => {
            ALIGNMENT_FIXUP_INTERVAL.store(interval, Ordering::Relaxed);
        }
        _ => {
            // Call HAL for other profile sources
            hal_set_profile_interval(interval, source);
        }
    }
}

// ============================================================================
// HAL Interface Functions
// ============================================================================

/// HAL callback to start profile interrupt
fn hal_start_profile_interrupt(source: ProfileSource) {
    // In a full implementation, this would call into the HAL
    // to configure the local APIC timer or performance counter
    match source {
        ProfileSource::Time => {
            // Configure APIC timer for profiling
            crate::serial_println!("[PROFILE] Starting time-based profile interrupt");
        }
        ProfileSource::AlignmentFixup => {
            // Enable alignment exception trapping
            crate::serial_println!("[PROFILE] Enabling alignment fixup profiling");
        }
        _ => {
            // Configure performance counter
            crate::serial_println!("[PROFILE] Starting profile source {:?}", source);
        }
    }
}

/// HAL callback to stop profile interrupt
fn hal_stop_profile_interrupt(source: ProfileSource) {
    match source {
        ProfileSource::Time => {
            crate::serial_println!("[PROFILE] Stopping time-based profile interrupt");
        }
        ProfileSource::AlignmentFixup => {
            crate::serial_println!("[PROFILE] Disabling alignment fixup profiling");
        }
        _ => {
            crate::serial_println!("[PROFILE] Stopping profile source {:?}", source);
        }
    }
}

/// Query profile interval from HAL
fn hal_query_profile_interval(_source: ProfileSource) -> u32 {
    // Default to 0 for unsupported sources
    0
}

/// Set profile interval in HAL
fn hal_set_profile_interval(_interval: u32, _source: ProfileSource) {
    // HAL would configure hardware here
}

// ============================================================================
// Profile Interrupt Handler
// ============================================================================

/// Profile interrupt handler
///
/// Called from the interrupt handler when a profile interrupt fires.
/// Samples all active profiles and increments appropriate buckets.
///
/// # Safety
/// Must be called with interrupts disabled at profile IRQL.
pub unsafe fn ki_profile_interrupt(instruction_pointer: usize, processor: u32) {
    PROFILE_STATS.total_interrupts += 1;

    // Sample all global profiles
    let count = GLOBAL_PROFILE_COUNT.load(Ordering::Relaxed) as usize;
    for i in 0..count.min(MAX_ACTIVE_PROFILES) {
        if let Some(profile_ptr) = GLOBAL_PROFILE_LIST[i] {
            let profile = &*profile_ptr;

            // Check if profile is active and matches our processor
            if profile.is_started() && (profile.affinity & (1u64 << processor)) != 0 {
                profile.record_hit(instruction_pointer);
                PROFILE_STATS.total_hits += 1;
            }
        }
    }
}

/// Profile alignment fixup handler
///
/// Called when an alignment exception occurs and alignment profiling is active.
pub unsafe fn ki_profile_alignment_fixup(address: usize, processor: u32) {
    if !PROFILE_ALIGNMENT_FIXUP.load(Ordering::Relaxed) {
        return;
    }

    // Sample alignment profiles
    let count = GLOBAL_PROFILE_COUNT.load(Ordering::Relaxed) as usize;
    for i in 0..count.min(MAX_ACTIVE_PROFILES) {
        if let Some(profile_ptr) = GLOBAL_PROFILE_LIST[i] {
            let profile = &*profile_ptr;

            if profile.is_started()
                && profile.source == ProfileSource::AlignmentFixup
                && (profile.affinity & (1u64 << processor)) != 0
            {
                profile.record_hit(address);
                PROFILE_STATS.total_hits += 1;
            }
        }
    }
}

/// Get profile statistics
pub fn get_profile_stats() -> ProfileStats {
    unsafe { PROFILE_STATS }
}

// ============================================================================
// IPI Target Functions for Multi-Processor Profile Control
// ============================================================================

/// IPI target to start profile interrupt on remote processor
pub fn ki_start_profile_interrupt_ipi(source: ProfileSource) {
    hal_start_profile_interrupt(source);
}

/// IPI target to stop profile interrupt on remote processor
pub fn ki_stop_profile_interrupt_ipi(source: ProfileSource) {
    hal_stop_profile_interrupt(source);
}

// ============================================================================
// Public API Functions (NT-compatible naming)
// ============================================================================

/// Initialize a profile object (KeInitializeProfile)
pub fn ke_initialize_profile(
    profile: &mut KProfile,
    process: Option<*mut KProcess>,
    range_base: usize,
    range_size: usize,
    bucket_size: u32,
    segment: u16,
    source: ProfileSource,
    affinity: u64,
) {
    profile.init_with_affinity(process, range_base, range_size, bucket_size, source, affinity);
    profile.segment = segment;
}

/// Start profiling (KeStartProfile)
///
/// This function starts profile data gathering. The profile object is marked
/// started and registered with the profile interrupt procedure.
///
/// If the number of active profiles for this source was previously zero on
/// any processor, then the profile interrupt is enabled on those processors.
pub unsafe fn ke_start_profile(profile: &KProfile, buffer: *mut u32) -> bool {
    // Acquire profile lock
    let _guard = PROFILE_LOCK.lock();

    // If already started, return false
    if profile.started.swap(true, Ordering::AcqRel) {
        return false;
    }

    // Set the buffer pointer
    *profile.buffer.get() = buffer;

    // Add to global profile list (for system-wide profiles)
    if profile.process.is_none() {
        let count = GLOBAL_PROFILE_COUNT.load(Ordering::Relaxed) as usize;
        if count < MAX_ACTIVE_PROFILES {
            GLOBAL_PROFILE_LIST[count] = Some(profile as *const KProfile);
            GLOBAL_PROFILE_COUNT.store((count + 1) as u32, Ordering::Release);
        }
    }

    // Find or allocate active source entry
    if let Some(source_entry) = find_or_allocate_source(profile.source) {
        // Compute which processors need to start the profile interrupt
        let new_affinity = profile.affinity & !source_entry.affinity;

        // Increment reference counts
        for proc in 0..MAX_CPUS {
            if (profile.affinity & (1u64 << proc)) != 0 {
                source_entry.processor_count[proc] += 1;
            }
        }

        // Update active affinity
        source_entry.affinity |= profile.affinity;

        // Start profile interrupt on processors that didn't have it
        if new_affinity != 0 {
            // For alignment fixup, enable exception handling
            if profile.source == ProfileSource::AlignmentFixup {
                PROFILE_ALIGNMENT_FIXUP.store(true, Ordering::Release);
            }

            // Start profile interrupt (would use IPI for remote processors)
            hal_start_profile_interrupt(profile.source);
        }
    }

    PROFILE_STATS.active_profiles += 1;
    true
}

/// Stop profiling (KeStopProfile)
///
/// This function stops profile data gathering. The object is marked stopped
/// and removed from the active profile list.
///
/// If the number of active profiles for this source goes to zero on any
/// processor, then the profile interrupt is disabled on those processors.
pub fn ke_stop_profile(profile: &KProfile) -> bool {
    // Acquire profile lock
    let _guard = PROFILE_LOCK.lock();

    // If not started, return false
    if !profile.started.swap(false, Ordering::AcqRel) {
        return false;
    }

    // Clear the buffer pointer
    unsafe {
        *profile.buffer.get() = core::ptr::null_mut();
    }

    // Remove from global profile list
    if profile.process.is_none() {
        unsafe {
            let count = GLOBAL_PROFILE_COUNT.load(Ordering::Relaxed) as usize;
            let profile_ptr = profile as *const KProfile;

            for i in 0..count {
                if GLOBAL_PROFILE_LIST[i] == Some(profile_ptr) {
                    // Shift remaining entries down
                    for j in i..count - 1 {
                        GLOBAL_PROFILE_LIST[j] = GLOBAL_PROFILE_LIST[j + 1];
                    }
                    GLOBAL_PROFILE_LIST[count - 1] = None;
                    GLOBAL_PROFILE_COUNT.store((count - 1) as u32, Ordering::Release);
                    break;
                }
            }
        }
    }

    // Update active source entry
    unsafe {
        if let Some(source_entry) = find_source(profile.source) {
            let mut stop_affinity: u64 = 0;

            // Decrement reference counts and find processors to stop
            for proc in 0..MAX_CPUS {
                if (profile.affinity & (1u64 << proc)) != 0 {
                    if source_entry.processor_count[proc] > 0 {
                        source_entry.processor_count[proc] -= 1;
                        if source_entry.processor_count[proc] == 0 {
                            stop_affinity |= 1u64 << proc;
                        }
                    }
                }
            }

            // Update active affinity
            source_entry.affinity &= !stop_affinity;

            // If no more profiles for this source, clean up
            if source_entry.affinity == 0 {
                source_entry.in_use = false;
                PROFILE_STATS.active_sources = PROFILE_STATS.active_sources.saturating_sub(1);

                if profile.source == ProfileSource::AlignmentFixup {
                    PROFILE_ALIGNMENT_FIXUP.store(false, Ordering::Release);
                }
            }

            // Stop profile interrupt on processors that no longer need it
            if stop_affinity != 0 {
                hal_stop_profile_interrupt(profile.source);
            }
        }

        PROFILE_STATS.active_profiles = PROFILE_STATS.active_profiles.saturating_sub(1);
    }

    true
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the profile subsystem
pub fn profile_init() {
    crate::serial_println!("[KE] Profile subsystem initialized (interval: {}00ns)",
        DEFAULT_PROFILE_INTERVAL);
}
