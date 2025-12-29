//! Mapping Control Block (MCB) Implementation
//!
//! MCBs track the mapping between Virtual Block Numbers (VBN) and
//! Logical Block Numbers (LBN) for file extents. This is essential
//! for file systems to manage file storage on disk.
//!
//! Key concepts:
//! - VBN: Virtual offset within a file (in blocks)
//! - LBN: Physical location on disk (in blocks)
//! - Run: A contiguous sequence of blocks with consecutive LBNs
//!
//! Example: A file with two runs:
//! - VBN 0-99 maps to LBN 500-599 (100 blocks)
//! - VBN 100-149 maps to LBN 1000-1049 (50 blocks)
//!
//! This implementation is NT 5.2 (Windows Server 2003) compatible.

use core::ptr;
use crate::ex::fast_mutex::FastMutex;
use crate::mm::pool::PoolType;

/// Maximum runs in initial MCB allocation
const MCB_INITIAL_PAIRS: usize = 16;

/// Growth factor for MCB reallocation
const MCB_GROWTH_FACTOR: usize = 2;

/// Represents a hole (unallocated extent) in the file
pub const LBN_HOLE: i64 = -1;

/// A single mapping pair in the MCB
///
/// Each pair represents a run end: (LBN of run start, VBN after run end)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct McbPair {
    /// Starting LBN of this run (or LBN_HOLE for unallocated)
    pub lbn: i64,
    /// VBN immediately after this run ends
    pub next_vbn: i64,
}

impl McbPair {
    pub const fn new() -> Self {
        Self { lbn: 0, next_vbn: 0 }
    }
}

/// Base MCB structure (unsynchronized)
///
/// This is the core mapping storage without synchronization.
/// Use LargeMcb for thread-safe operations.
#[repr(C)]
pub struct BaseMcb {
    /// Maximum number of pairs that can be stored
    pub max_pair_count: u32,
    /// Current number of pairs in use
    pub pair_count: u32,
    /// Pool type for allocations
    pub pool_type: PoolType,
    /// Pointer to pair array (null if using inline storage)
    pub mapping: *mut McbPair,
    /// Inline storage for small MCBs
    inline_pairs: [McbPair; MCB_INITIAL_PAIRS],
}

impl BaseMcb {
    /// Create a new empty base MCB
    pub const fn new() -> Self {
        Self {
            max_pair_count: MCB_INITIAL_PAIRS as u32,
            pair_count: 0,
            pool_type: PoolType::NonPagedPool,
            mapping: ptr::null_mut(),
            inline_pairs: [McbPair::new(); MCB_INITIAL_PAIRS],
        }
    }

    /// Initialize the base MCB
    pub fn init(&mut self, pool_type: PoolType) {
        self.max_pair_count = MCB_INITIAL_PAIRS as u32;
        self.pair_count = 0;
        self.pool_type = pool_type;
        self.mapping = ptr::null_mut();
    }

    /// Get the pair array
    fn pairs(&self) -> &[McbPair] {
        let ptr = if self.mapping.is_null() {
            self.inline_pairs.as_ptr()
        } else {
            self.mapping
        };
        unsafe { core::slice::from_raw_parts(ptr, self.pair_count as usize) }
    }

    /// Get mutable pair array
    fn pairs_mut(&mut self) -> &mut [McbPair] {
        let ptr = if self.mapping.is_null() {
            self.inline_pairs.as_mut_ptr()
        } else {
            self.mapping
        };
        unsafe { core::slice::from_raw_parts_mut(ptr, self.pair_count as usize) }
    }

    /// Ensure capacity for at least `count` pairs
    fn ensure_capacity(&mut self, count: u32) -> bool {
        if count <= self.max_pair_count {
            return true;
        }

        // Calculate new size
        let new_max = (self.max_pair_count as usize * MCB_GROWTH_FACTOR).max(count as usize);

        // TODO: Allocate from pool when pool allocator is available
        // For now, we're limited to inline storage
        if new_max > MCB_INITIAL_PAIRS {
            return false;
        }

        self.max_pair_count = new_max as u32;
        true
    }

    /// Find the run containing a VBN
    ///
    /// Returns the index of the run, or None if VBN is beyond all runs
    fn find_run(&self, vbn: i64) -> Option<usize> {
        let pairs = self.pairs();
        for (i, pair) in pairs.iter().enumerate() {
            if vbn < pair.next_vbn {
                return Some(i);
            }
        }
        None
    }

    /// Get the starting VBN of a run at index
    fn run_start_vbn(&self, index: usize) -> i64 {
        if index == 0 {
            0
        } else {
            self.pairs()[index - 1].next_vbn
        }
    }
}

impl Default for BaseMcb {
    fn default() -> Self {
        Self::new()
    }
}

/// Large MCB structure (synchronized)
///
/// Provides thread-safe access to the mapping using a fast mutex.
#[repr(C)]
pub struct LargeMcb {
    /// Fast mutex for synchronization
    pub fast_mutex: FastMutex,
    /// The underlying base MCB
    pub base_mcb: BaseMcb,
}

impl LargeMcb {
    /// Create a new empty large MCB
    pub const fn new() -> Self {
        Self {
            fast_mutex: FastMutex::new(),
            base_mcb: BaseMcb::new(),
        }
    }
}

impl Default for LargeMcb {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Initialize a large MCB
///
/// # Arguments
/// * `mcb` - The MCB to initialize
/// * `pool_type` - Pool type for allocations (Paged or NonPaged)
pub fn fsrtl_initialize_large_mcb(mcb: &mut LargeMcb, pool_type: PoolType) {
    mcb.fast_mutex.init();
    mcb.base_mcb.init(pool_type);
}

/// Uninitialize a large MCB and free resources
pub fn fsrtl_uninitialize_large_mcb(mcb: &mut LargeMcb) {
    // Free any dynamically allocated mapping
    if !mcb.base_mcb.mapping.is_null() {
        // TODO: Free to pool when allocator available
        mcb.base_mcb.mapping = ptr::null_mut();
    }
    mcb.base_mcb.pair_count = 0;
    mcb.base_mcb.max_pair_count = 0;
}

/// Add a mapping entry to the MCB
///
/// # Arguments
/// * `mcb` - The MCB to modify
/// * `vbn` - Starting virtual block number
/// * `lbn` - Starting logical block number
/// * `sector_count` - Number of sectors in this run
///
/// # Returns
/// true if successful, false if allocation failed
pub fn fsrtl_add_large_mcb_entry(
    mcb: &mut LargeMcb,
    vbn: i64,
    lbn: i64,
    sector_count: i64,
) -> bool {
    if sector_count <= 0 {
        return false;
    }

    mcb.fast_mutex.acquire();

    let result = add_mcb_entry_internal(&mut mcb.base_mcb, vbn, lbn, sector_count);

    mcb.fast_mutex.release();

    result
}

/// Internal function to add MCB entry without locking
fn add_mcb_entry_internal(mcb: &mut BaseMcb, vbn: i64, lbn: i64, sector_count: i64) -> bool {
    let end_vbn = vbn + sector_count;

    // Find where this run should be inserted
    let insert_pos = mcb.find_run(vbn).unwrap_or(mcb.pair_count as usize);

    // Check if we can merge with existing runs
    if insert_pos > 0 {
        let prev = &mcb.pairs()[insert_pos - 1];
        let prev_end_vbn = prev.next_vbn;
        let prev_end_lbn = prev.lbn + (prev_end_vbn - mcb.run_start_vbn(insert_pos - 1));

        // Check for overlap
        if prev_end_vbn > vbn {
            return false; // Overlapping runs not allowed
        }

        // Check if we can extend the previous run
        if prev_end_vbn == vbn && prev.lbn != LBN_HOLE && prev_end_lbn == lbn {
            // Extend the previous run
            let pairs = mcb.pairs_mut();
            pairs[insert_pos - 1].next_vbn = end_vbn;
            return true;
        }
    }

    // Need to insert a new run
    if !mcb.ensure_capacity(mcb.pair_count + 1) {
        return false;
    }

    // Shift existing entries if needed
    if insert_pos < mcb.pair_count as usize {
        let pairs_ptr = if mcb.mapping.is_null() {
            mcb.inline_pairs.as_mut_ptr()
        } else {
            mcb.mapping
        };
        unsafe {
            ptr::copy(
                pairs_ptr.add(insert_pos),
                pairs_ptr.add(insert_pos + 1),
                mcb.pair_count as usize - insert_pos,
            );
        }
    }

    // Insert the new run
    let pairs_ptr = if mcb.mapping.is_null() {
        mcb.inline_pairs.as_mut_ptr()
    } else {
        mcb.mapping
    };
    unsafe {
        (*pairs_ptr.add(insert_pos)).lbn = lbn;
        (*pairs_ptr.add(insert_pos)).next_vbn = end_vbn;
    }
    mcb.pair_count += 1;

    true
}

/// Remove a range from the MCB
///
/// # Arguments
/// * `mcb` - The MCB to modify
/// * `vbn` - Starting VBN of range to remove
/// * `sector_count` - Number of sectors to remove
pub fn fsrtl_remove_large_mcb_entry(mcb: &mut LargeMcb, vbn: i64, sector_count: i64) {
    if sector_count <= 0 {
        return;
    }

    mcb.fast_mutex.acquire();

    remove_mcb_entry_internal(&mut mcb.base_mcb, vbn, sector_count);

    mcb.fast_mutex.release();
}

/// Internal function to remove MCB entry without locking
fn remove_mcb_entry_internal(mcb: &mut BaseMcb, vbn: i64, sector_count: i64) {
    let end_vbn = vbn + sector_count;

    // Find runs that overlap with the removal range
    let mut i = 0;
    while i < mcb.pair_count as usize {
        let run_start = mcb.run_start_vbn(i);
        let pairs = mcb.pairs();
        let run_end = pairs[i].next_vbn;
        let run_lbn = pairs[i].lbn;

        if run_start >= end_vbn {
            // Past the removal range
            break;
        }

        if run_end <= vbn {
            // Before the removal range
            i += 1;
            continue;
        }

        // This run overlaps with the removal range
        if run_start >= vbn && run_end <= end_vbn {
            // Entire run is within removal range - remove it
            let pairs_ptr = if mcb.mapping.is_null() {
                mcb.inline_pairs.as_mut_ptr()
            } else {
                mcb.mapping
            };
            unsafe {
                ptr::copy(
                    pairs_ptr.add(i + 1),
                    pairs_ptr.add(i),
                    mcb.pair_count as usize - i - 1,
                );
            }
            mcb.pair_count -= 1;
            // Don't increment i, check the new run at this position
        } else if run_start < vbn && run_end > end_vbn {
            // Removal range is in the middle of this run - need to split
            // For now, just truncate (simplified)
            let pairs = mcb.pairs_mut();
            pairs[i].next_vbn = vbn;
            i += 1;
        } else if run_start < vbn {
            // Removal starts in the middle of this run
            let pairs = mcb.pairs_mut();
            pairs[i].next_vbn = vbn;
            i += 1;
        } else {
            // Removal ends in the middle of this run
            let new_start_vbn = end_vbn;
            let offset = new_start_vbn - run_start;
            let pairs = mcb.pairs_mut();
            if run_lbn != LBN_HOLE {
                pairs[i].lbn = run_lbn + offset;
            }
            i += 1;
        }
    }
}

/// Lookup an MCB entry
///
/// # Arguments
/// * `mcb` - The MCB to query
/// * `vbn` - Virtual block number to lookup
/// * `lbn` - Output: logical block number
/// * `sector_count_from_lbn` - Output: remaining sectors in run from LBN
/// * `starting_lbn` - Output: starting LBN of the run
/// * `sector_count_from_starting_lbn` - Output: total sectors in run
/// * `index` - Output: index of this run
///
/// # Returns
/// true if VBN is mapped, false if it's a hole or beyond file
pub fn fsrtl_lookup_large_mcb_entry(
    mcb: &LargeMcb,
    vbn: i64,
    lbn: &mut i64,
    sector_count_from_lbn: &mut i64,
    starting_lbn: &mut i64,
    sector_count_from_starting_lbn: &mut i64,
    index: &mut usize,
) -> bool {
    unsafe { (*(mcb as *const LargeMcb as *mut LargeMcb)).fast_mutex.acquire() };

    let result = lookup_mcb_entry_internal(
        &mcb.base_mcb,
        vbn,
        lbn,
        sector_count_from_lbn,
        starting_lbn,
        sector_count_from_starting_lbn,
        index,
    );

    unsafe { (*(mcb as *const LargeMcb as *mut LargeMcb)).fast_mutex.release() };

    result
}

/// Internal lookup without locking
fn lookup_mcb_entry_internal(
    mcb: &BaseMcb,
    vbn: i64,
    lbn: &mut i64,
    sector_count_from_lbn: &mut i64,
    starting_lbn: &mut i64,
    sector_count_from_starting_lbn: &mut i64,
    index: &mut usize,
) -> bool {
    if let Some(i) = mcb.find_run(vbn) {
        let pairs = mcb.pairs();
        let run_start_vbn = mcb.run_start_vbn(i);
        let run_end_vbn = pairs[i].next_vbn;
        let run_lbn = pairs[i].lbn;

        *index = i;
        *starting_lbn = run_lbn;
        *sector_count_from_starting_lbn = run_end_vbn - run_start_vbn;

        if run_lbn == LBN_HOLE {
            *lbn = LBN_HOLE;
            *sector_count_from_lbn = run_end_vbn - vbn;
            return false;
        }

        let offset = vbn - run_start_vbn;
        *lbn = run_lbn + offset;
        *sector_count_from_lbn = run_end_vbn - vbn;
        return true;
    }

    // VBN is beyond all runs
    *lbn = LBN_HOLE;
    *sector_count_from_lbn = 0;
    *starting_lbn = LBN_HOLE;
    *sector_count_from_starting_lbn = 0;
    *index = mcb.pair_count as usize;
    false
}

/// Lookup the last entry in the MCB
///
/// # Returns
/// (last_vbn, last_lbn) or None if MCB is empty
pub fn fsrtl_lookup_last_large_mcb_entry(mcb: &LargeMcb) -> Option<(i64, i64)> {
    unsafe { (*(mcb as *const LargeMcb as *mut LargeMcb)).fast_mutex.acquire() };

    let result = if mcb.base_mcb.pair_count == 0 {
        None
    } else {
        let pairs = mcb.base_mcb.pairs();
        let last = &pairs[mcb.base_mcb.pair_count as usize - 1];
        let last_vbn = last.next_vbn - 1;
        let run_start = mcb.base_mcb.run_start_vbn(mcb.base_mcb.pair_count as usize - 1);
        let last_lbn = if last.lbn == LBN_HOLE {
            LBN_HOLE
        } else {
            last.lbn + (last_vbn - run_start)
        };
        Some((last_vbn, last_lbn))
    };

    unsafe { (*(mcb as *const LargeMcb as *mut LargeMcb)).fast_mutex.release() };

    result
}

/// Get a run by index
///
/// # Arguments
/// * `mcb` - The MCB to query
/// * `index` - Run index (0-based)
/// * `vbn` - Output: starting VBN of run
/// * `lbn` - Output: starting LBN of run
/// * `sector_count` - Output: number of sectors in run
///
/// # Returns
/// true if index is valid, false otherwise
pub fn fsrtl_get_next_large_mcb_entry(
    mcb: &LargeMcb,
    index: usize,
    vbn: &mut i64,
    lbn: &mut i64,
    sector_count: &mut i64,
) -> bool {
    unsafe { (*(mcb as *const LargeMcb as *mut LargeMcb)).fast_mutex.acquire() };

    let result = if index >= mcb.base_mcb.pair_count as usize {
        false
    } else {
        let pairs = mcb.base_mcb.pairs();
        *vbn = mcb.base_mcb.run_start_vbn(index);
        *lbn = pairs[index].lbn;
        *sector_count = pairs[index].next_vbn - *vbn;
        true
    };

    unsafe { (*(mcb as *const LargeMcb as *mut LargeMcb)).fast_mutex.release() };

    result
}

/// Truncate the MCB at a VBN
///
/// Removes all mappings at or after the specified VBN.
pub fn fsrtl_truncate_large_mcb(mcb: &mut LargeMcb, vbn: i64) {
    mcb.fast_mutex.acquire();

    // Find the first run that extends beyond vbn
    if let Some(i) = mcb.base_mcb.find_run(vbn) {
        let run_start = mcb.base_mcb.run_start_vbn(i);
        if run_start < vbn {
            // Truncate this run
            mcb.base_mcb.pairs_mut()[i].next_vbn = vbn;
            mcb.base_mcb.pair_count = (i + 1) as u32;
        } else {
            // Remove this run and all following
            mcb.base_mcb.pair_count = i as u32;
        }
    }
    // If vbn is beyond all runs, nothing to do

    mcb.fast_mutex.release();
}

/// Get the number of runs in the MCB
pub fn fsrtl_number_of_runs_in_large_mcb(mcb: &LargeMcb) -> u32 {
    mcb.base_mcb.pair_count
}

/// Split a run at a specified VBN
///
/// Used when inserting a hole in the middle of a run.
pub fn fsrtl_split_large_mcb(mcb: &mut LargeMcb, vbn: i64, amount: i64) -> bool {
    if amount <= 0 {
        return true;
    }

    mcb.fast_mutex.acquire();

    // Find the run containing vbn
    let result = if let Some(i) = mcb.base_mcb.find_run(vbn) {
        let run_start = mcb.base_mcb.run_start_vbn(i);
        let pairs = mcb.base_mcb.pairs();
        let run_end = pairs[i].next_vbn;
        let run_lbn = pairs[i].lbn;

        if run_start == vbn {
            // Splitting at run start - just shift all following runs
            for j in i..mcb.base_mcb.pair_count as usize {
                mcb.base_mcb.pairs_mut()[j].next_vbn += amount;
            }
            true
        } else if vbn < run_end {
            // Splitting in the middle - need to create a new run
            if !mcb.base_mcb.ensure_capacity(mcb.base_mcb.pair_count + 1) {
                false
            } else {
                // Insert a new run for the second half
                let second_half_lbn = if run_lbn == LBN_HOLE {
                    LBN_HOLE
                } else {
                    run_lbn + (vbn - run_start)
                };

                // Shift runs after split point
                let pairs_ptr = if mcb.base_mcb.mapping.is_null() {
                    mcb.base_mcb.inline_pairs.as_mut_ptr()
                } else {
                    mcb.base_mcb.mapping
                };
                unsafe {
                    ptr::copy(
                        pairs_ptr.add(i + 1),
                        pairs_ptr.add(i + 2),
                        mcb.base_mcb.pair_count as usize - i - 1,
                    );
                }

                // Truncate first half
                mcb.base_mcb.pairs_mut()[i].next_vbn = vbn;

                // Create second half (shifted by amount)
                let _pairs = mcb.base_mcb.pairs_mut();
                unsafe {
                    let new_pair = pairs_ptr.add(i + 1);
                    (*new_pair).lbn = second_half_lbn;
                    (*new_pair).next_vbn = run_end + amount;
                }

                mcb.base_mcb.pair_count += 1;

                // Shift all following runs
                for j in (i + 2)..mcb.base_mcb.pair_count as usize {
                    mcb.base_mcb.pairs_mut()[j].next_vbn += amount;
                }

                true
            }
        } else {
            true
        }
    } else {
        true
    };

    mcb.fast_mutex.release();

    result
}
