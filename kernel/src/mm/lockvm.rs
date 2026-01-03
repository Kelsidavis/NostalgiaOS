//! Virtual Memory Lock/Unlock Support
//!
//! This module implements NtLockVirtualMemory and NtUnlockVirtualMemory
//! which allow processes to lock pages in memory, preventing them from
//! being paged out.
//!
//! # Use Cases
//!
//! - Real-time applications that cannot tolerate page faults
//! - Security-sensitive memory (cryptographic keys)
//! - DMA buffers that must remain at fixed physical addresses
//! - I/O buffers for high-performance operations
//!
//! # Lock Types
//!
//! - MAP_PROCESS: Lock pages in the process working set
//! - MAP_SYSTEM: Lock pages in system memory (stronger guarantee)
//!
//! # Requirements
//!
//! - Caller must have PROCESS_VM_OPERATION access
//! - Caller typically needs SeLockMemoryPrivilege
//! - Locked pages count against process/system quotas
//!
//! # NT API
//!
//! - NtLockVirtualMemory: Lock a region of pages
//! - NtUnlockVirtualMemory: Unlock a previously locked region

use crate::ke::SpinLock;
use crate::mm::{PAGE_SIZE, PAGE_SHIFT};

/// Lock type: Lock in process working set
pub const MAP_PROCESS: u32 = 1;

/// Lock type: Lock in system address space (stronger)
pub const MAP_SYSTEM: u32 = 2;

/// Maximum number of locked regions per process
pub const MAX_LOCKED_REGIONS: usize = 64;

/// Maximum pages that can be locked per process
pub const MAX_LOCKED_PAGES_PER_PROCESS: usize = 16384; // 64MB

/// Maximum total locked pages system-wide
pub const MAX_LOCKED_PAGES_TOTAL: usize = 262144; // 1GB

/// Locked region descriptor
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LockedRegion {
    /// Process ID
    pub process_id: u32,
    /// Starting virtual address
    pub start_address: u64,
    /// Region size in bytes
    pub region_size: u64,
    /// Lock type (MAP_PROCESS or MAP_SYSTEM)
    pub lock_type: u32,
    /// Number of pages locked
    pub page_count: u32,
    /// Is this region active?
    pub active: bool,
    /// Reference count (multiple locks on same region)
    pub ref_count: u32,
}

impl LockedRegion {
    pub const fn new() -> Self {
        Self {
            process_id: 0,
            start_address: 0,
            region_size: 0,
            lock_type: 0,
            page_count: 0,
            active: false,
            ref_count: 0,
        }
    }

    /// Check if an address is within this region
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start_address && addr < self.start_address + self.region_size
    }

    /// Check if regions overlap
    pub fn overlaps(&self, start: u64, size: u64) -> bool {
        let end = self.start_address + self.region_size;
        let other_end = start + size;
        !(other_end <= self.start_address || start >= end)
    }

    /// Check if this region exactly matches
    pub fn matches(&self, start: u64, size: u64, lock_type: u32) -> bool {
        self.start_address == start &&
        self.region_size == size &&
        self.lock_type == lock_type
    }
}

impl Default for LockedRegion {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-process lock information
#[repr(C)]
pub struct ProcessLockInfo {
    /// Process ID
    pub process_id: u32,
    /// Total pages locked by this process
    pub total_locked_pages: u32,
    /// Number of active locked regions
    pub active_regions: u32,
    /// Is this info structure in use?
    pub active: bool,
}

impl ProcessLockInfo {
    pub const fn new() -> Self {
        Self {
            process_id: 0,
            total_locked_pages: 0,
            active_regions: 0,
            active: false,
        }
    }
}

impl Default for ProcessLockInfo {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Locked region pool
static mut LOCKED_REGIONS: [LockedRegion; MAX_LOCKED_REGIONS * 4] = {
    const INIT: LockedRegion = LockedRegion::new();
    [INIT; MAX_LOCKED_REGIONS * 4]
};

/// Per-process lock info
const MAX_PROCESSES: usize = 64;
static mut PROCESS_LOCK_INFO: [ProcessLockInfo; MAX_PROCESSES] = {
    const INIT: ProcessLockInfo = ProcessLockInfo::new();
    [INIT; MAX_PROCESSES]
};

/// Global lock for locked region operations
static LOCK_VM_LOCK: SpinLock<()> = SpinLock::new(());

/// Lock statistics
static mut LOCK_STATS: LockVmStats = LockVmStats::new();

/// Lock/unlock statistics
#[derive(Debug, Clone, Copy)]
pub struct LockVmStats {
    pub total_locked_pages: u64,
    pub total_locked_regions: u32,
    pub process_locks: u64,
    pub system_locks: u64,
    pub lock_failures: u64,
    pub unlock_count: u64,
}

impl LockVmStats {
    pub const fn new() -> Self {
        Self {
            total_locked_pages: 0,
            total_locked_regions: 0,
            process_locks: 0,
            system_locks: 0,
            lock_failures: 0,
            unlock_count: 0,
        }
    }
}

impl Default for LockVmStats {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Internal Functions
// ============================================================================

/// Get or create process lock info
unsafe fn get_or_create_process_info(process_id: u32) -> Option<&'static mut ProcessLockInfo> {
    // First look for existing
    for info in PROCESS_LOCK_INFO.iter_mut() {
        if info.active && info.process_id == process_id {
            return Some(info);
        }
    }

    // Create new
    for info in PROCESS_LOCK_INFO.iter_mut() {
        if !info.active {
            info.active = true;
            info.process_id = process_id;
            info.total_locked_pages = 0;
            info.active_regions = 0;
            return Some(info);
        }
    }

    None
}

/// Find process lock info
unsafe fn find_process_info(process_id: u32) -> Option<&'static mut ProcessLockInfo> {
    for info in PROCESS_LOCK_INFO.iter_mut() {
        if info.active && info.process_id == process_id {
            return Some(info);
        }
    }
    None
}

/// Find a locked region
unsafe fn find_locked_region(
    process_id: u32,
    start_addr: u64,
    size: u64,
    lock_type: u32,
) -> Option<usize> {
    for (idx, region) in LOCKED_REGIONS.iter().enumerate() {
        if region.active &&
           region.process_id == process_id &&
           region.matches(start_addr, size, lock_type)
        {
            return Some(idx);
        }
    }
    None
}

/// Find overlapping locked region
unsafe fn find_overlapping_region(process_id: u32, start_addr: u64, size: u64) -> Option<usize> {
    for (idx, region) in LOCKED_REGIONS.iter().enumerate() {
        if region.active &&
           region.process_id == process_id &&
           region.overlaps(start_addr, size)
        {
            return Some(idx);
        }
    }
    None
}

// ============================================================================
// Lock Virtual Memory API
// ============================================================================

/// Lock a region of virtual memory
///
/// Implementation of NtLockVirtualMemory.
pub unsafe fn nt_lock_virtual_memory(
    process_id: u32,
    base_address: *mut u64,
    region_size: *mut u64,
    map_type: u32,
) -> i32 {
    const STATUS_SUCCESS: i32 = 0;
    const STATUS_INVALID_PARAMETER: i32 = -1073741811_i32;
    const STATUS_WORKING_SET_QUOTA: i32 = -1073741663_i32;
    const STATUS_PRIVILEGE_NOT_HELD: i32 = -1073741727_i32;

    // Validate parameters
    if base_address.is_null() || region_size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate map type
    if (map_type & !(MAP_PROCESS | MAP_SYSTEM)) != 0 {
        return STATUS_INVALID_PARAMETER;
    }

    if (map_type & (MAP_PROCESS | MAP_SYSTEM)) == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Capture parameters
    let captured_base = *base_address;
    let captured_size = *region_size;

    if captured_size == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Page-align the region
    let start_addr = captured_base & !(PAGE_SIZE as u64 - 1);
    let end_addr = (captured_base + captured_size + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
    let actual_size = end_addr - start_addr;
    let page_count = (actual_size >> PAGE_SHIFT) as u32;

    let _guard = LOCK_VM_LOCK.lock();

    // Get or create process info
    let proc_info = match get_or_create_process_info(process_id) {
        Some(info) => info,
        None => {
            LOCK_STATS.lock_failures += 1;
            return STATUS_WORKING_SET_QUOTA;
        }
    };

    // Check per-process limit
    if proc_info.total_locked_pages as usize + page_count as usize > MAX_LOCKED_PAGES_PER_PROCESS {
        LOCK_STATS.lock_failures += 1;
        return STATUS_WORKING_SET_QUOTA;
    }

    // Check system-wide limit
    if LOCK_STATS.total_locked_pages + page_count as u64 > MAX_LOCKED_PAGES_TOTAL as u64 {
        LOCK_STATS.lock_failures += 1;
        return STATUS_WORKING_SET_QUOTA;
    }

    // Check if this exact region is already locked
    if let Some(region_idx) = find_locked_region(process_id, start_addr, actual_size, map_type) {
        // Increment reference count
        LOCKED_REGIONS[region_idx].ref_count += 1;

        // Return actual values
        *base_address = start_addr;
        *region_size = actual_size;

        return STATUS_SUCCESS;
    }

    // Find a free region slot
    let region_idx = match LOCKED_REGIONS.iter().position(|r| !r.active) {
        Some(idx) => idx,
        None => {
            LOCK_STATS.lock_failures += 1;
            return STATUS_WORKING_SET_QUOTA;
        }
    };

    // Create the locked region
    let region = &mut LOCKED_REGIONS[region_idx];
    region.process_id = process_id;
    region.start_address = start_addr;
    region.region_size = actual_size;
    region.lock_type = map_type;
    region.page_count = page_count;
    region.active = true;
    region.ref_count = 1;

    // Update process info
    proc_info.total_locked_pages += page_count;
    proc_info.active_regions += 1;

    // Update statistics
    LOCK_STATS.total_locked_pages += page_count as u64;
    LOCK_STATS.total_locked_regions += 1;

    if (map_type & MAP_PROCESS) != 0 {
        LOCK_STATS.process_locks += 1;
    }
    if (map_type & MAP_SYSTEM) != 0 {
        LOCK_STATS.system_locks += 1;
    }

    // Return actual values
    *base_address = start_addr;
    *region_size = actual_size;

    // In a full implementation, we would:
    // 1. Fault in all pages in the region
    // 2. Mark them as locked in the working set
    // 3. Mark the VAD as having locked pages

    STATUS_SUCCESS
}

/// Unlock a region of virtual memory
///
/// Implementation of NtUnlockVirtualMemory.
pub unsafe fn nt_unlock_virtual_memory(
    process_id: u32,
    base_address: *mut u64,
    region_size: *mut u64,
    map_type: u32,
) -> i32 {
    const STATUS_SUCCESS: i32 = 0;
    const STATUS_INVALID_PARAMETER: i32 = -1073741811_i32;
    const STATUS_NOT_LOCKED: i32 = -1073741782_i32;

    // Validate parameters
    if base_address.is_null() || region_size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate map type
    if (map_type & !(MAP_PROCESS | MAP_SYSTEM)) != 0 {
        return STATUS_INVALID_PARAMETER;
    }

    if (map_type & (MAP_PROCESS | MAP_SYSTEM)) == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Capture parameters
    let captured_base = *base_address;
    let captured_size = *region_size;

    if captured_size == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Page-align the region
    let start_addr = captured_base & !(PAGE_SIZE as u64 - 1);
    let end_addr = (captured_base + captured_size + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
    let actual_size = end_addr - start_addr;

    let _guard = LOCK_VM_LOCK.lock();

    // Find the locked region
    let region_idx = match find_locked_region(process_id, start_addr, actual_size, map_type) {
        Some(idx) => idx,
        None => return STATUS_NOT_LOCKED,
    };

    let region = &mut LOCKED_REGIONS[region_idx];

    // Decrement reference count
    region.ref_count = region.ref_count.saturating_sub(1);

    if region.ref_count == 0 {
        // Actually unlock the region
        let page_count = region.page_count;

        // Update process info
        if let Some(proc_info) = find_process_info(process_id) {
            proc_info.total_locked_pages = proc_info.total_locked_pages.saturating_sub(page_count);
            proc_info.active_regions = proc_info.active_regions.saturating_sub(1);

            // Clean up process info if no more locks
            if proc_info.active_regions == 0 {
                proc_info.active = false;
            }
        }

        // Update statistics
        LOCK_STATS.total_locked_pages = LOCK_STATS.total_locked_pages.saturating_sub(page_count as u64);
        LOCK_STATS.total_locked_regions = LOCK_STATS.total_locked_regions.saturating_sub(1);
        LOCK_STATS.unlock_count += 1;

        // Free the region
        region.active = false;
    }

    // Return actual values
    *base_address = start_addr;
    *region_size = actual_size;

    STATUS_SUCCESS
}

/// Check if a page is locked
pub unsafe fn mi_is_page_locked(process_id: u32, virt_addr: u64) -> bool {
    let _guard = LOCK_VM_LOCK.lock();

    for region in LOCKED_REGIONS.iter() {
        if region.active &&
           region.process_id == process_id &&
           region.contains(virt_addr)
        {
            return true;
        }
    }

    false
}

/// Check if any part of a range is locked
pub unsafe fn mi_is_range_locked(process_id: u32, start_addr: u64, size: u64) -> bool {
    let _guard = LOCK_VM_LOCK.lock();
    find_overlapping_region(process_id, start_addr, size).is_some()
}

/// Get lock type for a page
pub unsafe fn mi_get_page_lock_type(process_id: u32, virt_addr: u64) -> Option<u32> {
    let _guard = LOCK_VM_LOCK.lock();

    for region in LOCKED_REGIONS.iter() {
        if region.active &&
           region.process_id == process_id &&
           region.contains(virt_addr)
        {
            return Some(region.lock_type);
        }
    }

    None
}

/// Clean up all locks for a process (on process exit)
pub unsafe fn mi_cleanup_process_locks(process_id: u32) {
    let _guard = LOCK_VM_LOCK.lock();

    for region in LOCKED_REGIONS.iter_mut() {
        if region.active && region.process_id == process_id {
            LOCK_STATS.total_locked_pages =
                LOCK_STATS.total_locked_pages.saturating_sub(region.page_count as u64);
            LOCK_STATS.total_locked_regions =
                LOCK_STATS.total_locked_regions.saturating_sub(1);
            region.active = false;
        }
    }

    // Clean up process info
    for info in PROCESS_LOCK_INFO.iter_mut() {
        if info.active && info.process_id == process_id {
            info.active = false;
            break;
        }
    }
}

/// Get lock statistics
pub fn mi_get_lock_stats() -> LockVmStats {
    unsafe { LOCK_STATS }
}

/// Get snapshot of locked regions
pub fn mi_get_locked_region_snapshots() -> ([LockedRegionSnapshot; 32], usize) {
    let mut snapshots = [LockedRegionSnapshot::empty(); 32];
    let mut count = 0;

    unsafe {
        let _guard = LOCK_VM_LOCK.lock();

        for (idx, region) in LOCKED_REGIONS.iter().enumerate() {
            if count >= 32 {
                break;
            }
            if region.active {
                snapshots[count] = LockedRegionSnapshot {
                    index: idx,
                    process_id: region.process_id,
                    start_address: region.start_address,
                    region_size: region.region_size,
                    lock_type: region.lock_type,
                    page_count: region.page_count,
                    ref_count: region.ref_count,
                };
                count += 1;
            }
        }
    }

    (snapshots, count)
}

/// Locked region snapshot for diagnostics
#[derive(Debug, Clone, Copy)]
pub struct LockedRegionSnapshot {
    pub index: usize,
    pub process_id: u32,
    pub start_address: u64,
    pub region_size: u64,
    pub lock_type: u32,
    pub page_count: u32,
    pub ref_count: u32,
}

impl LockedRegionSnapshot {
    pub const fn empty() -> Self {
        Self {
            index: 0,
            process_id: 0,
            start_address: 0,
            region_size: 0,
            lock_type: 0,
            page_count: 0,
            ref_count: 0,
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize lock VM subsystem
pub fn init() {
    unsafe {
        for region in LOCKED_REGIONS.iter_mut() {
            region.active = false;
        }

        for info in PROCESS_LOCK_INFO.iter_mut() {
            info.active = false;
        }

        LOCK_STATS = LockVmStats::new();
    }

    crate::serial_println!("[MM] Lock Virtual Memory subsystem initialized");
}
