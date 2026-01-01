//! UUID/GUID Generation (Executive)
//!
//! Provides UUID (Universally Unique Identifier) generation services for
//! kernel-mode components. UUIDs are 128-bit identifiers that are unique
//! across time and space.
//!
//! # UUID Structure
//!
//! A UUID is a 128-bit value structured as:
//! - TimeLow (32 bits): Low field of timestamp
//! - TimeMid (16 bits): Middle field of timestamp
//! - TimeHiAndVersion (16 bits): High field of timestamp + version
//! - ClockSeqHiAndReserved (8 bits): High field of clock sequence + variant
//! - ClockSeqLow (8 bits): Low field of clock sequence
//! - NodeId (48 bits): Node identifier (typically MAC address)
//!
//! # Time-Based UUIDs (Version 1)
//!
//! Time is measured in 100-nanosecond intervals since October 15, 1582.
//! The clock sequence changes when the clock goes backwards or the node
//! ID changes, preventing UUID collisions.
//!
//! # NT Functions
//!
//! - `ExUuidCreate` - Create a kernel-mode UUID
//! - `NtAllocateUuids` - Allocate a range of UUIDs (user mode)
//! - `NtSetUuidSeed` - Set the UUID node ID

use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};
use crate::ex::fast_mutex::FastMutex;

/// UUID structure (128-bit)
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Uuid {
    /// Low 32 bits of time
    pub data1: u32,
    /// Next 16 bits of time
    pub data2: u16,
    /// Next 16 bits of time and version
    pub data3: u16,
    /// Clock sequence and node ID
    pub data4: [u8; 8],
}

impl Uuid {
    pub const fn nil() -> Self {
        Self {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        }
    }
}

impl core::fmt::Debug for Uuid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
            self.data1, self.data2, self.data3,
            self.data4[0], self.data4[1],
            self.data4[2], self.data4[3], self.data4[4],
            self.data4[5], self.data4[6], self.data4[7])
    }
}

impl core::fmt::Display for Uuid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1, self.data2, self.data3,
            self.data4[0], self.data4[1],
            self.data4[2], self.data4[3], self.data4[4],
            self.data4[5], self.data4[6], self.data4[7])
    }
}

/// Alternative representation for UUID generation
#[repr(C)]
struct UuidGenerate {
    time_low: u32,
    time_mid: u16,
    time_hi_and_version: u16,
    clock_seq_hi_and_reserved: u8,
    clock_seq_low: u8,
    node_id: [u8; 6],
}

/// Cached UUID values for fast allocation
#[repr(C)]
struct UuidCachedValues {
    /// End time of allocation
    time: u64,
    /// Number of UUIDs allocated (can go negative)
    allocated_count: i32,
    /// Clock sequence high and reserved
    clock_seq_hi_and_reserved: u8,
    /// Clock sequence low
    clock_seq_low: u8,
    /// Node ID (MAC address or random)
    node_id: [u8; 6],
}

impl Default for UuidCachedValues {
    fn default() -> Self {
        Self {
            time: 0,
            allocated_count: -1, // Force allocation on first use
            clock_seq_hi_and_reserved: 0,
            clock_seq_low: 0,
            // Default node ID with multicast bit set (random)
            node_id: [0x80, b'n', b'o', b'n', b'i', b'c'],
        }
    }
}

// UUID bit masks and constants
const UUID_TIME_HIGH_MASK: u16 = 0x0FFF;
const UUID_VERSION: u16 = 0x1000; // Version 1 (time-based)
const UUID_RESERVED: u8 = 0x80;   // Variant bits
const UUID_CLOCK_SEQ_HI_MASK: u8 = 0x3F;

// Time offset from SYSTEMTIME (Jan 1, 1601) to UUID epoch (Oct 15, 1582)
// 17 days in Oct + 30 (Nov) + 31 (Dec) + 18 years and 5 leap days
const UUID_TIME_OFFSET: u64 = {
    const DAYS: u64 = 17 + 30 + 31 + 365 * 18 + 5;
    const SECS_PER_DAY: u64 = 60 * 60 * 24;
    const INTERVALS_PER_SEC: u64 = 10_000_000;
    DAYS * SECS_PER_DAY * INTERVALS_PER_SEC
};

/// Global UUID state
static mut UUID_CACHED_VALUES: UuidCachedValues = UuidCachedValues {
    time: 0,
    allocated_count: -1,
    clock_seq_hi_and_reserved: 0,
    clock_seq_low: 0,
    node_id: [0x80, b'n', b'o', b'n', b'i', b'c'],
};

/// Last time allocated
static UUID_LAST_TIME_ALLOCATED: AtomicU64 = AtomicU64::new(0);

/// Sequence number
static UUID_SEQUENCE_NUMBER: AtomicU32 = AtomicU32::new(0);

/// Sequence number valid flag
static UUID_SEQUENCE_VALID: AtomicBool = AtomicBool::new(false);

/// UUID generation count for statistics
static UUID_GENERATED_COUNT: AtomicU64 = AtomicU64::new(0);

/// UUID cache refill count
static UUID_CACHE_REFILLS: AtomicU64 = AtomicU64::new(0);

/// UUID lock (using spinlock-style for no_std)
static mut UUID_LOCK_STATE: bool = false;

fn acquire_uuid_lock() {
    // Simple spinlock for UUID operations
    unsafe {
        while UUID_LOCK_STATE {
            core::hint::spin_loop();
        }
        UUID_LOCK_STATE = true;
    }
}

fn release_uuid_lock() {
    unsafe {
        UUID_LOCK_STATE = false;
    }
}

/// Allocate a range of UUIDs (ExpAllocateUuids equivalent)
///
/// Returns (time, range, sequence) or None if retry needed
fn exp_allocate_uuids() -> Option<(u64, u32, u32)> {
    // Make sure we have a valid sequence number
    if !UUID_SEQUENCE_VALID.load(Ordering::Acquire) {
        // Generate initial sequence number based on system state
        let perf_counter = crate::rtl::rtl_get_system_time() as u64;
        let stack_addr = &perf_counter as *const _ as u64;

        let seq = (perf_counter ^ stack_addr) as u32;
        UUID_SEQUENCE_NUMBER.store(seq, Ordering::Release);
        UUID_SEQUENCE_VALID.store(true, Ordering::Release);
    }

    // Get current time
    let current_time = crate::rtl::rtl_get_system_time() as u64;
    let last_allocated = UUID_LAST_TIME_ALLOCATED.load(Ordering::Acquire);

    let available_time = if current_time > last_allocated {
        current_time - last_allocated
    } else if current_time < last_allocated {
        // Time went backwards - increment sequence number
        UUID_SEQUENCE_NUMBER.fetch_add(1, Ordering::AcqRel);
        // Set last allocated to slightly before current time
        UUID_LAST_TIME_ALLOCATED.store(current_time.saturating_sub(20000), Ordering::Release);
        20000u64
    } else {
        // Time hasn't advanced - caller should retry
        return None;
    };

    // Limit to 1 second max
    let available_time = available_time.min(10_000_000);

    // Calculate range to give out
    let (range, remaining) = if available_time > 10_000 {
        // Give out 1ms, keep the rest
        (10_000u32, available_time - 10_000)
    } else {
        // Give out everything
        (available_time as u32, 0)
    };

    let time = current_time - (range as u64 + remaining);
    UUID_LAST_TIME_ALLOCATED.store(time + range as u64, Ordering::Release);

    let sequence = UUID_SEQUENCE_NUMBER.load(Ordering::Acquire);

    Some((time, range, sequence))
}

/// Get values for UUID cache (ExpUuidGetValues equivalent)
fn exp_uuid_get_values() -> Option<()> {
    let (time, range, sequence) = exp_allocate_uuids()?;

    // Convert from SYSTEMTIME to UUID time (Oct 15, 1582)
    let uuid_time = time + UUID_TIME_OFFSET;

    unsafe {
        UUID_CACHED_VALUES.clock_seq_hi_and_reserved =
            UUID_RESERVED | ((sequence >> 8) as u8 & UUID_CLOCK_SEQ_HI_MASK);
        UUID_CACHED_VALUES.clock_seq_low = sequence as u8;

        // Time indicates end of range
        UUID_CACHED_VALUES.time = uuid_time + (range as u64 - 1);
        UUID_CACHED_VALUES.allocated_count = range as i32;
    }

    UUID_CACHE_REFILLS.fetch_add(1, Ordering::Relaxed);
    Some(())
}

/// Create a UUID (ExUuidCreate)
///
/// Creates a time-based UUID (version 1).
///
/// # Returns
/// * `Ok(uuid)` - Successfully created UUID
/// * `Err(status)` - Failed to create UUID (-1073741823 = STATUS_RETRY)
pub fn ex_uuid_create() -> Result<Uuid, i32> {
    let mut uuid = Uuid::nil();
    let uuid_gen = unsafe {
        &mut *(&mut uuid as *mut Uuid as *mut UuidGenerate)
    };

    loop {
        // Get cached time value
        let time = unsafe { UUID_CACHED_VALUES.time };

        // Copy static info (clock sequence and node ID)
        unsafe {
            uuid_gen.clock_seq_hi_and_reserved = UUID_CACHED_VALUES.clock_seq_hi_and_reserved;
            uuid_gen.clock_seq_low = UUID_CACHED_VALUES.clock_seq_low;
            uuid_gen.node_id = UUID_CACHED_VALUES.node_id;
        }

        // Decrement allocated count atomically
        let delta = unsafe {
            let old = UUID_CACHED_VALUES.allocated_count;
            UUID_CACHED_VALUES.allocated_count = old - 1;
            old - 1
        };

        // Check if cache time changed (another thread updated)
        if time != unsafe { UUID_CACHED_VALUES.time } {
            continue;
        }

        // If cache not exhausted, we're done
        if delta >= 0 {
            // Adjust time for this UUID
            let adjusted_time = time - delta as u64;

            uuid_gen.time_low = adjusted_time as u32;
            uuid_gen.time_mid = (adjusted_time >> 32) as u16;
            uuid_gen.time_hi_and_version =
                ((adjusted_time >> 48) as u16 & UUID_TIME_HIGH_MASK) | UUID_VERSION;

            UUID_GENERATED_COUNT.fetch_add(1, Ordering::Relaxed);
            return Ok(uuid);
        }

        // Cache exhausted - refill it
        acquire_uuid_lock();

        // Check again if another thread already refilled
        if time != unsafe { UUID_CACHED_VALUES.time } {
            release_uuid_lock();
            continue;
        }

        // Refill the cache
        if exp_uuid_get_values().is_none() {
            release_uuid_lock();
            return Err(-1073741823); // STATUS_RETRY
        }

        release_uuid_lock();
        // Loop to retry with refreshed cache
    }
}

/// Create a UUID, retrying on temporary failures
///
/// Automatically retries if STATUS_RETRY is returned.
/// This version yields the CPU between retries.
pub fn ex_uuid_create_reliable() -> Uuid {
    loop {
        match ex_uuid_create() {
            Ok(uuid) => return uuid,
            Err(_) => {
                // Yield and retry
                crate::ex::ex_yield();
            }
        }
    }
}

/// Set the UUID seed (node ID)
///
/// The seed is typically the MAC address of a network adapter.
/// If no hardware address is available, a random value with the
/// multicast bit set is used.
pub fn ex_set_uuid_seed(seed: &[u8; 6]) {
    acquire_uuid_lock();

    unsafe {
        UUID_CACHED_VALUES.node_id = *seed;
        // Invalidate cache to pick up new node ID
        UUID_CACHED_VALUES.allocated_count = -1;
    }

    // Increment sequence number when node ID changes
    UUID_SEQUENCE_NUMBER.fetch_add(1, Ordering::AcqRel);

    release_uuid_lock();
}

/// Allocate a range of UUIDs (NtAllocateUuids equivalent)
///
/// Returns information that can be used to generate multiple UUIDs.
///
/// # Arguments
/// * `time` - Receives the start time
/// * `range` - Receives the number of 100ns ticks reserved
/// * `sequence` - Receives the clock sequence
/// * `seed` - Receives the current node ID
///
/// # Returns
/// STATUS_SUCCESS (0) or error code
pub fn nt_allocate_uuids(
    time: &mut u64,
    range: &mut u32,
    sequence: &mut u32,
    seed: &mut [u8; 6],
) -> i32 {
    acquire_uuid_lock();

    let result = exp_allocate_uuids();

    match result {
        Some((t, r, s)) => {
            *time = t;
            *range = r;
            *sequence = s;
            unsafe {
                *seed = UUID_CACHED_VALUES.node_id;
            }
            release_uuid_lock();
            0 // STATUS_SUCCESS
        }
        None => {
            release_uuid_lock();
            -1073741823 // STATUS_RETRY
        }
    }
}

/// UUID generation statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct UuidStats {
    /// Total UUIDs generated
    pub generated: u64,
    /// Cache refill count
    pub cache_refills: u64,
    /// Current sequence number
    pub sequence: u32,
}

/// Get UUID generation statistics
pub fn get_uuid_stats() -> UuidStats {
    UuidStats {
        generated: UUID_GENERATED_COUNT.load(Ordering::Relaxed),
        cache_refills: UUID_CACHE_REFILLS.load(Ordering::Relaxed),
        sequence: UUID_SEQUENCE_NUMBER.load(Ordering::Relaxed),
    }
}

/// Initialize UUID generation
pub fn init() {
    // Generate random-ish initial sequence number
    let time = crate::rtl::rtl_get_system_time() as u64;
    let initial_seq = (time ^ (time >> 17) ^ (time << 7)) as u32;

    UUID_SEQUENCE_NUMBER.store(initial_seq, Ordering::Release);
    UUID_SEQUENCE_VALID.store(true, Ordering::Release);
    UUID_LAST_TIME_ALLOCATED.store(0, Ordering::Release);
    UUID_GENERATED_COUNT.store(0, Ordering::Release);
    UUID_CACHE_REFILLS.store(0, Ordering::Release);

    unsafe {
        UUID_CACHED_VALUES = UuidCachedValues::default();
        UUID_LOCK_STATE = false;
    }

    crate::serial_println!("[EX] UUID generation initialized (seq=0x{:08x})", initial_seq);
}

// ============================================================================
// Well-known UUIDs
// ============================================================================

/// Nil UUID (all zeros)
pub const UUID_NIL: Uuid = Uuid::nil();

/// Create a UUID from raw bytes
pub const fn uuid_from_bytes(bytes: [u8; 16]) -> Uuid {
    Uuid {
        data1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        data2: u16::from_le_bytes([bytes[4], bytes[5]]),
        data3: u16::from_le_bytes([bytes[6], bytes[7]]),
        data4: [bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15]],
    }
}

/// Create a UUID from components
pub const fn uuid_from_parts(
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
) -> Uuid {
    Uuid { data1, data2, data3, data4 }
}

// ============================================================================
// GUID type alias (Windows uses GUID, RPC uses UUID)
// ============================================================================

/// GUID is the Windows name for UUID
pub type Guid = Uuid;

/// Create a GUID (same as UUID)
pub fn co_create_guid() -> Result<Guid, i32> {
    ex_uuid_create()
}
