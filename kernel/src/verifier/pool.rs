//! Pool Allocation Verification
//!
//! Tracks pool allocations to detect leaks, corruptions, and use-after-free.

use super::{vf_increment_stat, vf_is_option_enabled, vf_report_violation, VerifierBugcheck, VerifierOptions, VerifierStat};
use crate::ke::SpinLock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

extern crate alloc;

/// Pool allocation tracking entry
#[derive(Debug, Clone)]
pub struct TrackedAllocation {
    /// Allocation address
    pub address: usize,
    /// Allocation size (requested)
    pub size: usize,
    /// Actual allocated size (may be larger for alignment)
    pub actual_size: usize,
    /// Pool type (0 = NonPaged, 1 = Paged)
    pub pool_type: u8,
    /// Pool tag (4 bytes)
    pub tag: u32,
    /// Allocator return address
    pub allocator: usize,
    /// Allocation timestamp (TSC)
    pub alloc_time: u64,
    /// Allocation state
    pub state: AllocationState,
    /// Call stack at allocation
    pub alloc_stack: [usize; 8],
    /// Free timestamp (if freed)
    pub free_time: u64,
    /// Freer return address (if freed)
    pub freer: usize,
}

impl TrackedAllocation {
    pub fn new(address: usize, size: usize, pool_type: u8, tag: u32, allocator: usize) -> Self {
        Self {
            address,
            size,
            actual_size: size,
            pool_type,
            tag,
            allocator,
            alloc_time: unsafe { core::arch::x86_64::_rdtsc() },
            state: AllocationState::Allocated,
            alloc_stack: [0; 8],
            free_time: 0,
            freer: 0,
        }
    }

    /// Get tag as string
    pub fn tag_string(&self) -> String {
        let bytes = self.tag.to_le_bytes();
        let mut s = String::with_capacity(4);
        for b in bytes.iter() {
            if b.is_ascii_graphic() || *b == b' ' {
                s.push(*b as char);
            } else {
                s.push('.');
            }
        }
        s
    }
}

/// Allocation state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationState {
    /// Currently allocated
    Allocated,
    /// Freed
    Freed,
    /// Corrupted (detected by guard pattern)
    Corrupted,
}

/// Pool verifier state
#[derive(Debug)]
pub struct PoolVerifierState {
    /// Tracked allocations by address
    allocations: BTreeMap<usize, TrackedAllocation>,
    /// Recently freed allocations (for use-after-free detection)
    recent_frees: Vec<TrackedAllocation>,
    /// Maximum recent frees to keep
    max_recent_frees: usize,
    /// Total allocation count
    total_allocs: u64,
    /// Total free count
    total_frees: u64,
    /// Total bytes allocated
    total_bytes_allocated: u64,
    /// Total bytes freed
    total_bytes_freed: u64,
    /// Peak allocation count
    peak_alloc_count: usize,
    /// Peak bytes allocated
    peak_bytes_allocated: u64,
}

impl PoolVerifierState {
    pub const fn new() -> Self {
        Self {
            allocations: BTreeMap::new(),
            recent_frees: Vec::new(),
            max_recent_frees: 1024,
            total_allocs: 0,
            total_frees: 0,
            total_bytes_allocated: 0,
            total_bytes_freed: 0,
            peak_alloc_count: 0,
            peak_bytes_allocated: 0,
        }
    }
}

/// Guard pattern for detecting overruns
const POOL_GUARD_PATTERN: u64 = 0xDEAD_BEEF_DEAD_BEEF;

/// Fill pattern for freed memory
const POOL_FREE_PATTERN: u8 = 0xDD;

/// Fill pattern for allocated memory
const POOL_ALLOC_PATTERN: u8 = 0xCD;

/// Global pool verifier state
static mut POOL_VERIFIER_STATE: Option<SpinLock<PoolVerifierState>> = None;

fn get_pool_state() -> &'static SpinLock<PoolVerifierState> {
    unsafe {
        POOL_VERIFIER_STATE
            .as_ref()
            .expect("Pool verifier not initialized")
    }
}

/// Initialize pool verification
pub fn vf_pool_init() {
    unsafe {
        POOL_VERIFIER_STATE = Some(SpinLock::new(PoolVerifierState::new()));
    }
    crate::serial_println!("[VERIFIER] Pool verification initialized");
}

/// Track a pool allocation
pub fn vf_pool_allocate(
    address: usize,
    size: usize,
    pool_type: u8,
    tag: u32,
    allocator: usize,
) {
    if !vf_is_option_enabled(VerifierOptions::TRACK_POOL) {
        return;
    }

    let state = get_pool_state();
    let mut guard = state.lock();

    // Check for double allocation (same address already tracked)
    if guard.allocations.contains_key(&address) {
        vf_report_violation(
            VerifierBugcheck::DriverVerifierDetectedViolation,
            "unknown",
            address,
            size,
            pool_type as usize,
            0x2001, // Double allocation
        );
    }

    let tracked = TrackedAllocation::new(address, size, pool_type, tag, allocator);
    guard.allocations.insert(address, tracked);

    guard.total_allocs += 1;
    guard.total_bytes_allocated += size as u64;

    // Update peaks
    if guard.allocations.len() > guard.peak_alloc_count {
        guard.peak_alloc_count = guard.allocations.len();
    }

    let current_bytes: u64 = guard.allocations.values().map(|a| a.size as u64).sum();
    if current_bytes > guard.peak_bytes_allocated {
        guard.peak_bytes_allocated = current_bytes;
    }

    vf_increment_stat(VerifierStat::PoolAllocations);
}

/// Track a pool free
pub fn vf_pool_free(address: usize, freer: usize) {
    if !vf_is_option_enabled(VerifierOptions::TRACK_POOL) {
        return;
    }

    let state = get_pool_state();
    let mut guard = state.lock();

    // Check if this was a recently freed allocation (double free)
    for recent in &guard.recent_frees {
        if recent.address == address {
            vf_report_violation(
                VerifierBugcheck::DriverVerifierDetectedViolation,
                "unknown",
                address,
                recent.size,
                recent.freer,
                0x2002, // Double free
            );
            return;
        }
    }

    if let Some(mut tracked) = guard.allocations.remove(&address) {
        tracked.state = AllocationState::Freed;
        tracked.free_time = unsafe { core::arch::x86_64::_rdtsc() };
        tracked.freer = freer;

        guard.total_frees += 1;
        guard.total_bytes_freed += tracked.size as u64;

        // Keep in recent frees for use-after-free detection
        if guard.recent_frees.len() >= guard.max_recent_frees {
            guard.recent_frees.remove(0);
        }
        guard.recent_frees.push(tracked);

        vf_increment_stat(VerifierStat::PoolFrees);
    } else {
        // Freeing untracked memory - could be from before verifier started
        // or could be corruption
        crate::serial_println!(
            "[VERIFIER] Warning: Free of untracked address {:#x}",
            address
        );
    }
}

/// Check for pool corruptions (called periodically or on demand)
pub fn vf_pool_check_corruption(address: usize, expected_size: usize) -> bool {
    if !vf_is_option_enabled(VerifierOptions::DETECT_POOL_CORRUPTION) {
        return false;
    }

    // In a real implementation, this would check guard patterns
    // around the allocation
    false
}

/// Get pool allocation leaks (allocations without corresponding frees)
pub fn vf_pool_get_leaks() -> Vec<TrackedAllocation> {
    let state = get_pool_state();
    let guard = state.lock();

    guard.allocations.values().cloned().collect()
}

/// Get pool statistics
#[derive(Debug, Clone, Default)]
pub struct PoolVerifierStats {
    /// Current allocation count
    pub current_allocs: usize,
    /// Total allocations
    pub total_allocs: u64,
    /// Total frees
    pub total_frees: u64,
    /// Total bytes allocated
    pub total_bytes_allocated: u64,
    /// Total bytes freed
    pub total_bytes_freed: u64,
    /// Current bytes outstanding
    pub current_bytes: u64,
    /// Peak allocation count
    pub peak_alloc_count: usize,
    /// Peak bytes allocated
    pub peak_bytes_allocated: u64,
}

pub fn vf_pool_get_stats() -> PoolVerifierStats {
    let state = get_pool_state();
    let guard = state.lock();

    let current_bytes: u64 = guard.allocations.values().map(|a| a.size as u64).sum();

    PoolVerifierStats {
        current_allocs: guard.allocations.len(),
        total_allocs: guard.total_allocs,
        total_frees: guard.total_frees,
        total_bytes_allocated: guard.total_bytes_allocated,
        total_bytes_freed: guard.total_bytes_freed,
        current_bytes,
        peak_alloc_count: guard.peak_alloc_count,
        peak_bytes_allocated: guard.peak_bytes_allocated,
    }
}

/// Get allocations by tag
pub fn vf_pool_get_by_tag(tag: u32) -> Vec<TrackedAllocation> {
    let state = get_pool_state();
    let guard = state.lock();

    guard
        .allocations
        .values()
        .filter(|a| a.tag == tag)
        .cloned()
        .collect()
}

/// Get pool summary by tag
#[derive(Debug, Clone)]
pub struct PoolTagSummary {
    pub tag: u32,
    pub tag_string: String,
    pub count: usize,
    pub total_bytes: u64,
}

pub fn vf_pool_get_tag_summary() -> Vec<PoolTagSummary> {
    let state = get_pool_state();
    let guard = state.lock();

    let mut tag_map: BTreeMap<u32, (usize, u64)> = BTreeMap::new();

    for alloc in guard.allocations.values() {
        let entry = tag_map.entry(alloc.tag).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += alloc.size as u64;
    }

    tag_map
        .into_iter()
        .map(|(tag, (count, total_bytes))| {
            let bytes = tag.to_le_bytes();
            let mut tag_string = String::with_capacity(4);
            for b in bytes.iter() {
                if b.is_ascii_graphic() || *b == b' ' {
                    tag_string.push(*b as char);
                } else {
                    tag_string.push('.');
                }
            }
            PoolTagSummary {
                tag,
                tag_string,
                count,
                total_bytes,
            }
        })
        .collect()
}

/// Special pool allocation wrapper
/// Allocates with guard pages to catch buffer overruns
pub struct SpecialPoolAllocation {
    /// User visible address
    pub user_address: usize,
    /// Actual allocation address (before guard page)
    pub real_address: usize,
    /// Allocation size
    pub size: usize,
    /// Guard page address
    pub guard_address: usize,
}

/// Pool types
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolType {
    NonPagedPool = 0,
    PagedPool = 1,
    NonPagedPoolMustSucceed = 2,
    NonPagedPoolCacheAligned = 4,
    PagedPoolCacheAligned = 5,
    NonPagedPoolCacheAlignedMustSucceed = 6,
    MaxPoolType = 7,
    NonPagedPoolSession = 32,
    PagedPoolSession = 33,
    NonPagedPoolNx = 512,
}

impl PoolType {
    pub fn name(self) -> &'static str {
        match self {
            PoolType::NonPagedPool => "NonPagedPool",
            PoolType::PagedPool => "PagedPool",
            PoolType::NonPagedPoolMustSucceed => "NonPagedPoolMustSucceed",
            PoolType::NonPagedPoolCacheAligned => "NonPagedPoolCacheAligned",
            PoolType::PagedPoolCacheAligned => "PagedPoolCacheAligned",
            PoolType::NonPagedPoolCacheAlignedMustSucceed => "NonPagedPoolCacheAlignedMustS",
            PoolType::MaxPoolType => "MaxPoolType",
            PoolType::NonPagedPoolSession => "NonPagedPoolSession",
            PoolType::PagedPoolSession => "PagedPoolSession",
            PoolType::NonPagedPoolNx => "NonPagedPoolNx",
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(PoolType::NonPagedPool),
            1 => Some(PoolType::PagedPool),
            2 => Some(PoolType::NonPagedPoolMustSucceed),
            4 => Some(PoolType::NonPagedPoolCacheAligned),
            5 => Some(PoolType::PagedPoolCacheAligned),
            6 => Some(PoolType::NonPagedPoolCacheAlignedMustSucceed),
            7 => Some(PoolType::MaxPoolType),
            32 => Some(PoolType::NonPagedPoolSession),
            33 => Some(PoolType::PagedPoolSession),
            _ => None,
        }
    }
}
