//! Working Set Management (ws)
//!
//! The working set is the set of pages currently resident in memory for a process.
//! This module manages:
//! - Working set list entries (WSLE)
//! - Working set limits (min, max)
//! - Working set trimming when under memory pressure
//! - Working set growth/shrinking
//!
//! Based on Windows Server 2003 base/ntos/mm/wslist.c

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::Mutex;
use crate::ke::list::ListEntry;

/// Maximum working set entries per process (for static allocation)
pub const MAX_WSLE_PER_PROCESS: usize = 4096;

/// Default minimum working set size (pages)
pub const DEFAULT_MINIMUM_WORKING_SET_SIZE: u32 = 50;

/// Default maximum working set size (pages)
pub const DEFAULT_MAXIMUM_WORKING_SET_SIZE: u32 = 345;

/// Maximum allowed working set size
pub const MM_MAXIMUM_WORKING_SET: u32 = 0x0FFFFFFF;

/// Fluid working set gap (min + fluid must be < max for hard limits)
pub const MM_FLUID_WORKING_SET: u32 = 8;

/// Working set support flags
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MmSupportFlags {
    /// Protected by expansion lock
    pub expansion_bits: u8,
    /// Memory priority (0-7)
    pub memory_priority: u8,
    /// Protected by working set mutex
    pub ws_bits: u16,
}

impl MmSupportFlags {
    /// Session space flag
    pub const SESSION_SPACE: u8 = 0x01;
    /// Currently being trimmed
    pub const BEING_TRIMMED: u8 = 0x02;
    /// Session leader
    pub const SESSION_LEADER: u8 = 0x04;
    /// Hard trim in progress
    pub const TRIM_HARD: u8 = 0x08;
    /// Maximum working set is hard limit
    pub const MAXIMUM_WORKING_SET_HARD: u8 = 0x10;
    /// Force trim on next fault
    pub const FORCE_TRIM: u8 = 0x20;
    /// Minimum working set is hard limit
    pub const MINIMUM_WORKING_SET_HARD: u8 = 0x40;

    /// Check if being trimmed
    pub fn is_being_trimmed(&self) -> bool {
        (self.expansion_bits & Self::BEING_TRIMMED) != 0
    }

    /// Check if maximum is hard
    pub fn is_max_hard(&self) -> bool {
        (self.expansion_bits & Self::MAXIMUM_WORKING_SET_HARD) != 0
    }

    /// Check if minimum is hard
    pub fn is_min_hard(&self) -> bool {
        (self.expansion_bits & Self::MINIMUM_WORKING_SET_HARD) != 0
    }

    /// Set being trimmed
    pub fn set_being_trimmed(&mut self, value: bool) {
        if value {
            self.expansion_bits |= Self::BEING_TRIMMED;
        } else {
            self.expansion_bits &= !Self::BEING_TRIMMED;
        }
    }

    /// Set force trim
    pub fn set_force_trim(&mut self, value: bool) {
        if value {
            self.expansion_bits |= Self::FORCE_TRIM;
        } else {
            self.expansion_bits &= !Self::FORCE_TRIM;
        }
    }
}

/// Working Set List Entry (WSLE)
///
/// Each entry describes a page in the working set.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MmWsle {
    /// Virtual address of the page (page-aligned)
    pub virtual_address: u64,
    /// Entry is valid
    pub valid: bool,
    /// Entry is locked in memory
    pub locked: bool,
    /// Age counter for LRU-like replacement
    pub age: u8,
    /// Reference count for sharing
    pub share_count: u8,
    /// Protection flags
    pub protection: u8,
}

impl MmWsle {
    /// Create an empty WSLE
    pub const fn empty() -> Self {
        Self {
            virtual_address: 0,
            valid: false,
            locked: false,
            age: 0,
            share_count: 0,
            protection: 0,
        }
    }

    /// Create a new valid WSLE for a virtual address
    pub fn new(va: u64) -> Self {
        Self {
            virtual_address: va & !0xFFF, // Page-align
            valid: true,
            locked: false,
            age: 0,
            share_count: 1,
            protection: 0,
        }
    }

    /// Increment the age counter
    pub fn increment_age(&mut self) {
        if self.age < 7 {
            self.age += 1;
        }
    }

    /// Reset the age counter (referenced)
    pub fn reset_age(&mut self) {
        self.age = 0;
    }
}

/// Working Set List (MMWSL)
///
/// Contains the working set entries and tracking information.
#[repr(C)]
pub struct MmWsl {
    /// Working set list entries
    pub wsle: [MmWsle; MAX_WSLE_PER_PROCESS],
    /// First free entry index
    pub first_free: u32,
    /// First dynamic entry (after minimum)
    pub first_dynamic: u32,
    /// Last entry index in use
    pub last_entry: u32,
    /// Next slot to check for aging
    pub next_slot: u32,
    /// Last initialized entry
    pub last_initialized_wsle: u32,
    /// Non-direct count
    pub non_direct_count: u32,
    /// Hash table (simplified - index into wsle array)
    pub hash_table_start: u32,
    pub hash_table_size: u32,
}

impl MmWsl {
    /// Create a new empty working set list
    pub const fn new() -> Self {
        Self {
            wsle: [MmWsle::empty(); MAX_WSLE_PER_PROCESS],
            first_free: 0,
            first_dynamic: 0,
            last_entry: 0,
            next_slot: 0,
            last_initialized_wsle: 0,
            non_direct_count: 0,
            hash_table_start: 0,
            hash_table_size: 0,
        }
    }
}

/// Working Set Support Structure (MMSUPPORT)
///
/// Per-process working set information.
#[repr(C)]
pub struct MmSupport {
    /// Links for working set expansion list
    pub expansion_links: ListEntry,
    /// Last time this working set was trimmed
    pub last_trim_time: i64,
    /// Flags
    pub flags: MmSupportFlags,
    /// Page fault count
    pub page_fault_count: u32,
    /// Peak working set size (pages)
    pub peak_working_set_size: u32,
    /// Growth since last estimate
    pub growth_since_last_estimate: u32,
    /// Minimum working set size (pages)
    pub minimum_working_set_size: u32,
    /// Maximum working set size (pages)
    pub maximum_working_set_size: u32,
    /// Pointer to working set list
    pub vm_working_set_list: *mut MmWsl,
    /// Claim - pages that can be reclaimed
    pub claim: u32,
    /// Next slot for estimation
    pub next_estimation_slot: u32,
    /// Next slot for aging
    pub next_aging_slot: u32,
    /// Estimated available pages
    pub estimated_available: u32,
    /// Current working set size (pages)
    pub working_set_size: u32,
}

impl Default for MmSupport {
    fn default() -> Self {
        Self::new()
    }
}

impl MmSupport {
    /// Create a new MMSUPPORT with default values
    pub const fn new() -> Self {
        Self {
            expansion_links: ListEntry::new(),
            last_trim_time: 0,
            flags: MmSupportFlags {
                expansion_bits: 0,
                memory_priority: 0,
                ws_bits: 0,
            },
            page_fault_count: 0,
            peak_working_set_size: 0,
            growth_since_last_estimate: 0,
            minimum_working_set_size: DEFAULT_MINIMUM_WORKING_SET_SIZE,
            maximum_working_set_size: DEFAULT_MAXIMUM_WORKING_SET_SIZE,
            vm_working_set_list: core::ptr::null_mut(),
            claim: 0,
            next_estimation_slot: 0,
            next_aging_slot: 0,
            estimated_available: 0,
            working_set_size: 0,
        }
    }

    /// Initialize working set support
    pub fn init(&mut self, wsl: *mut MmWsl) {
        self.vm_working_set_list = wsl;
        self.minimum_working_set_size = DEFAULT_MINIMUM_WORKING_SET_SIZE;
        self.maximum_working_set_size = DEFAULT_MAXIMUM_WORKING_SET_SIZE;
        self.working_set_size = 0;
        self.peak_working_set_size = 0;
    }

    /// Set working set limits
    pub fn set_limits(&mut self, min: u32, max: u32) -> bool {
        // Validate limits
        if min > max {
            return false;
        }
        if max > MM_MAXIMUM_WORKING_SET {
            return false;
        }
        // If both hard, ensure min + fluid < max
        if self.flags.is_min_hard() && self.flags.is_max_hard() {
            if min + MM_FLUID_WORKING_SET >= max {
                return false;
            }
        }

        self.minimum_working_set_size = min;
        self.maximum_working_set_size = max;
        true
    }

    /// Update peak if current size exceeds it
    pub fn update_peak(&mut self) {
        if self.working_set_size > self.peak_working_set_size {
            self.peak_working_set_size = self.working_set_size;
        }
    }
}

// Global working set trimming statistics
static WS_STATS: Mutex<WorkingSetStats> = Mutex::new(WorkingSetStats::new());

/// Global working set statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkingSetStats {
    /// Total pages trimmed
    pub total_pages_trimmed: u64,
    /// Total trim operations
    pub trim_count: u64,
    /// Total pages faulted in
    pub pages_faulted_in: u64,
    /// Total working set insertions
    pub insertions: u64,
    /// Total working set removals
    pub removals: u64,
    /// Current total working set pages (all processes)
    pub total_working_set_pages: u64,
    /// Peak total working set pages
    pub peak_total_working_set_pages: u64,
}

impl WorkingSetStats {
    pub const fn new() -> Self {
        Self {
            total_pages_trimmed: 0,
            trim_count: 0,
            pages_faulted_in: 0,
            insertions: 0,
            removals: 0,
            total_working_set_pages: 0,
            peak_total_working_set_pages: 0,
        }
    }
}

/// Get global working set statistics
pub fn mm_get_ws_stats() -> WorkingSetStats {
    *WS_STATS.lock()
}

/// Allocate a WSLE in the working set
///
/// Returns the index of the allocated entry, or None if full.
pub unsafe fn mi_allocate_wsle(
    ws_info: *mut MmSupport,
    virtual_address: u64,
) -> Option<u32> {
    let ws = &mut *ws_info;
    let wsl = &mut *ws.vm_working_set_list;

    // Check if we're at the maximum
    if ws.working_set_size >= ws.maximum_working_set_size {
        if ws.flags.is_max_hard() {
            // Hard limit - must replace
            return None;
        }
        // Soft limit - can grow but should trigger trimming
    }

    // Find a free slot
    let mut index = wsl.first_free;
    while (index as usize) < MAX_WSLE_PER_PROCESS {
        if !wsl.wsle[index as usize].valid {
            // Found a free slot
            wsl.wsle[index as usize] = MmWsle::new(virtual_address);
            ws.working_set_size += 1;
            ws.update_peak();
            ws.growth_since_last_estimate += 1;

            // Update first_free to next slot
            if index >= wsl.last_entry {
                wsl.last_entry = index + 1;
            }

            // Update global stats
            {
                let mut stats = WS_STATS.lock();
                stats.insertions += 1;
                stats.total_working_set_pages += 1;
                if stats.total_working_set_pages > stats.peak_total_working_set_pages {
                    stats.peak_total_working_set_pages = stats.total_working_set_pages;
                }
            }

            return Some(index);
        }
        index += 1;
    }

    None
}

/// Remove a page from the working set
pub unsafe fn mi_remove_wsle(
    ws_info: *mut MmSupport,
    index: u32,
) {
    let ws = &mut *ws_info;
    let wsl = &mut *ws.vm_working_set_list;

    if (index as usize) >= MAX_WSLE_PER_PROCESS {
        return;
    }

    let wsle = &mut wsl.wsle[index as usize];
    if !wsle.valid {
        return;
    }

    wsle.valid = false;
    wsle.virtual_address = 0;
    ws.working_set_size = ws.working_set_size.saturating_sub(1);

    // Update first_free if this is earlier
    if index < wsl.first_free {
        wsl.first_free = index;
    }

    // Update global stats
    {
        let mut stats = WS_STATS.lock();
        stats.removals += 1;
        stats.total_working_set_pages = stats.total_working_set_pages.saturating_sub(1);
    }
}

/// Trim the working set to a target size
///
/// Returns the number of pages trimmed.
pub unsafe fn mi_trim_working_set(
    ws_info: *mut MmSupport,
    pages_to_trim: u32,
    trim_age: u8,
) -> u32 {
    let ws = &mut *ws_info;
    let wsl = &mut *ws.vm_working_set_list;

    // Mark as being trimmed
    ws.flags.set_being_trimmed(true);

    let mut trimmed = 0u32;
    let mut index = wsl.next_slot;
    let start_index = index;

    // Scan through the working set looking for old pages to trim
    loop {
        if trimmed >= pages_to_trim {
            break;
        }

        if (index as usize) >= MAX_WSLE_PER_PROCESS {
            index = 0;
        }

        let wsle = &mut wsl.wsle[index as usize];

        if wsle.valid && !wsle.locked && wsle.age >= trim_age {
            // This page is old enough to trim
            // In a real implementation, we would:
            // 1. Write the page to swap if dirty
            // 2. Update the PTE to mark page as not present
            // 3. Put the PFN on the appropriate list

            wsle.valid = false;
            wsle.virtual_address = 0;
            ws.working_set_size = ws.working_set_size.saturating_sub(1);
            trimmed += 1;

            if index < wsl.first_free {
                wsl.first_free = index;
            }
        }

        index += 1;
        if index == start_index {
            break; // Wrapped around
        }
    }

    wsl.next_slot = index;

    // Clear being trimmed flag
    ws.flags.set_being_trimmed(false);

    // Update global stats
    {
        let mut stats = WS_STATS.lock();
        stats.total_pages_trimmed += trimmed as u64;
        stats.trim_count += 1;
        stats.total_working_set_pages = stats.total_working_set_pages.saturating_sub(trimmed as u64);
    }

    trimmed
}

/// Age working set entries
///
/// Increments the age of entries that haven't been recently accessed.
pub unsafe fn mi_age_working_set(ws_info: *mut MmSupport) {
    let ws = &mut *ws_info;
    let wsl = &mut *ws.vm_working_set_list;

    let mut index = ws.next_aging_slot;
    let entries_to_age = 64u32.min(ws.working_set_size);
    let mut aged = 0u32;

    while aged < entries_to_age {
        if (index as usize) >= MAX_WSLE_PER_PROCESS {
            index = 0;
        }

        let wsle = &mut wsl.wsle[index as usize];
        if wsle.valid {
            // In a real implementation, we would check the PTE's accessed bit
            // and only age if not accessed. For now, just increment age.
            wsle.increment_age();
            aged += 1;
        }

        index += 1;
    }

    ws.next_aging_slot = index;
}

/// Estimate available pages that can be reclaimed
pub unsafe fn mi_estimate_available(ws_info: *mut MmSupport) -> u32 {
    let ws = &mut *ws_info;
    let wsl = &mut *ws.vm_working_set_list;

    let mut available = 0u32;

    for i in 0..MAX_WSLE_PER_PROCESS {
        let wsle = &wsl.wsle[i];
        if wsle.valid && !wsle.locked {
            // Pages with high age are considered available
            if wsle.age >= 3 {
                available += 1;
            }
        }
    }

    ws.estimated_available = available;
    ws.claim = available;

    available
}

/// Initialize a working set list
pub unsafe fn mi_initialize_working_set_list(wsl: *mut MmWsl) {
    let wsl = &mut *wsl;

    // Clear all entries
    for i in 0..MAX_WSLE_PER_PROCESS {
        wsl.wsle[i] = MmWsle::empty();
    }

    wsl.first_free = 0;
    wsl.first_dynamic = 0;
    wsl.last_entry = 0;
    wsl.next_slot = 0;
    wsl.last_initialized_wsle = 0;
}

/// Lock a page in the working set
pub unsafe fn mi_lock_wsle(ws_info: *mut MmSupport, index: u32) -> bool {
    let wsl = &mut *(*ws_info).vm_working_set_list;

    if (index as usize) >= MAX_WSLE_PER_PROCESS {
        return false;
    }

    let wsle = &mut wsl.wsle[index as usize];
    if !wsle.valid {
        return false;
    }

    wsle.locked = true;
    true
}

/// Unlock a page in the working set
pub unsafe fn mi_unlock_wsle(ws_info: *mut MmSupport, index: u32) -> bool {
    let wsl = &mut *(*ws_info).vm_working_set_list;

    if (index as usize) >= MAX_WSLE_PER_PROCESS {
        return false;
    }

    let wsle = &mut wsl.wsle[index as usize];
    if !wsle.valid {
        return false;
    }

    wsle.locked = false;
    true
}

/// Find a WSLE by virtual address
pub unsafe fn mi_find_wsle(
    ws_info: *mut MmSupport,
    virtual_address: u64,
) -> Option<u32> {
    let wsl = &*(*ws_info).vm_working_set_list;
    let va = virtual_address & !0xFFF; // Page-align

    for i in 0..MAX_WSLE_PER_PROCESS {
        let wsle = &wsl.wsle[i];
        if wsle.valid && wsle.virtual_address == va {
            return Some(i as u32);
        }
    }

    None
}

/// Record a page fault for statistics
pub fn mi_record_page_fault(ws_info: *mut MmSupport) {
    unsafe {
        (*ws_info).page_fault_count += 1;
    }

    let mut stats = WS_STATS.lock();
    stats.pages_faulted_in += 1;
}
