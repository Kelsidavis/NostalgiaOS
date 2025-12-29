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

/// Current profile interval (100ns units)
static PROFILE_INTERVAL: AtomicU32 = AtomicU32::new(DEFAULT_PROFILE_INTERVAL);

/// Current alignment fixup profile interval
static ALIGNMENT_FIXUP_INTERVAL: AtomicU32 = AtomicU32::new(DEFAULT_PROFILE_INTERVAL);

/// Query the current profile interval (KeQueryIntervalProfile)
pub fn ke_query_interval_profile(source: ProfileSource) -> u32 {
    match source {
        ProfileSource::Time => PROFILE_INTERVAL.load(Ordering::Relaxed),
        ProfileSource::AlignmentFixup => ALIGNMENT_FIXUP_INTERVAL.load(Ordering::Relaxed),
        _ => {
            // TODO: Query HAL for other profile sources
            0
        }
    }
}

/// Set the profile interval (KeSetIntervalProfile)
pub fn ke_set_interval_profile(interval: u32, source: ProfileSource) {
    let interval = interval.max(MINIMUM_PROFILE_INTERVAL);

    match source {
        ProfileSource::Time => {
            PROFILE_INTERVAL.store(interval, Ordering::Relaxed);
            // TODO: Call HAL to set hardware profile timer
        }
        ProfileSource::AlignmentFixup => {
            ALIGNMENT_FIXUP_INTERVAL.store(interval, Ordering::Relaxed);
        }
        _ => {
            // TODO: Call HAL for other profile sources
        }
    }
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
pub unsafe fn ke_start_profile(profile: &KProfile, buffer: *mut u32) -> bool {
    profile.start(buffer)
}

/// Stop profiling (KeStopProfile)
pub fn ke_stop_profile(profile: &KProfile) -> bool {
    profile.stop()
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the profile subsystem
pub fn profile_init() {
    crate::serial_println!("[KE] Profile subsystem initialized (interval: {}00ns)",
        DEFAULT_PROFILE_INTERVAL);
}
