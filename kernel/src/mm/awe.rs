//! Address Windowing Extensions (AWE) Support
//!
//! AWE allows applications to directly allocate and manage physical memory,
//! bypassing the normal virtual memory system. This is used by applications
//! that need to:
//! - Access more physical memory than virtual address space allows
//! - Have direct control over physical page allocation
//! - Implement custom memory management (e.g., database buffer pools)
//!
//! # Architecture
//!
//! AWE works by:
//! 1. Application reserves a "window" of virtual addresses (VirtualAlloc with MEM_PHYSICAL)
//! 2. Application allocates physical pages (NtAllocateUserPhysicalPages)
//! 3. Application maps physical pages into the window (NtMapUserPhysicalPages)
//! 4. Application can remap different pages into the same window
//!
//! # Restrictions
//!
//! - AWE memory is always nonpaged
//! - Cannot be shared between processes
//! - Same physical page cannot be mapped at two virtual addresses
//! - Requires LOCK_VM privilege
//! - Only read-write protection is allowed
//!
//! # NT API
//!
//! - NtAllocateUserPhysicalPages: Allocate physical pages
//! - NtFreeUserPhysicalPages: Free physical pages
//! - NtMapUserPhysicalPages: Map pages into virtual window

use crate::ke::SpinLock;
use crate::mm::PAGE_SHIFT;

/// Maximum number of AWE regions per process
pub const MAX_AWE_REGIONS: usize = 16;

/// Maximum physical pages that can be allocated per process
pub const MAX_AWE_PAGES_PER_PROCESS: usize = 256 * 1024; // 1GB with 4KB pages

/// Maximum total AWE pages system-wide
pub const MAX_AWE_PAGES_TOTAL: usize = 1024 * 1024; // 4GB total

/// AWE allocation state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AwePageState {
    /// Page is free and available
    Free = 0,
    /// Page is allocated to a process
    Allocated = 1,
    /// Page is mapped into virtual address space
    Mapped = 2,
}

impl Default for AwePageState {
    fn default() -> Self {
        Self::Free
    }
}

/// Information about a physical page allocated for AWE
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AwePageInfo {
    /// Physical frame number
    pub pfn: u64,
    /// Current state
    pub state: AwePageState,
    /// Owning process ID
    pub process_id: u32,
    /// Virtual address if mapped (0 if not mapped)
    pub mapped_va: u64,
}

impl AwePageInfo {
    pub const fn new() -> Self {
        Self {
            pfn: 0,
            state: AwePageState::Free,
            process_id: 0,
            mapped_va: 0,
        }
    }
}

impl Default for AwePageInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// AWE region - represents a virtual address window for AWE
#[repr(C)]
pub struct AweRegion {
    /// Process ID
    pub process_id: u32,
    /// VAD index
    pub vad_index: u32,
    /// Starting virtual address of the window
    pub virtual_base: u64,
    /// Size of the window in bytes
    pub window_size: u64,
    /// Number of pages in the window
    pub window_pages: u64,
    /// Page frame numbers mapped in this window
    /// (index corresponds to page offset in window)
    pub mapped_pfns: [u64; 256], // Support windows up to 1MB
    /// Is this region active?
    pub active: bool,
    /// Statistics: total maps
    pub total_maps: u64,
    /// Statistics: total unmaps
    pub total_unmaps: u64,
}

impl AweRegion {
    pub const fn new() -> Self {
        Self {
            process_id: 0,
            vad_index: u32::MAX,
            virtual_base: 0,
            window_size: 0,
            window_pages: 0,
            mapped_pfns: [0; 256],
            active: false,
            total_maps: 0,
            total_unmaps: 0,
        }
    }

    /// Check if a virtual address is within this window
    pub fn contains_va(&self, va: u64) -> bool {
        va >= self.virtual_base && va < self.virtual_base + self.window_size
    }

    /// Get the page index for a virtual address
    pub fn va_to_page_index(&self, va: u64) -> Option<usize> {
        if self.contains_va(va) {
            Some(((va - self.virtual_base) >> PAGE_SHIFT) as usize)
        } else {
            None
        }
    }
}

impl Default for AweRegion {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-process AWE information
#[repr(C)]
pub struct AweInfo {
    /// Process ID
    pub process_id: u32,
    /// Number of physical pages allocated
    pub allocated_pages: u32,
    /// Number of physical pages currently mapped
    pub mapped_pages: u32,
    /// Physical page frame numbers owned by this process
    pub page_pfns: [u64; 1024], // Up to 4MB per process in this simple impl
    /// Is this info structure in use?
    pub active: bool,
}

impl AweInfo {
    pub const fn new() -> Self {
        Self {
            process_id: 0,
            allocated_pages: 0,
            mapped_pages: 0,
            page_pfns: [0; 1024],
            active: false,
        }
    }

    /// Find a slot for a new PFN
    fn find_free_slot(&self) -> Option<usize> {
        self.page_pfns.iter().position(|&pfn| pfn == 0)
    }

    /// Find a PFN in our list
    fn find_pfn(&self, pfn: u64) -> Option<usize> {
        self.page_pfns.iter().position(|&p| p == pfn)
    }
}

impl Default for AweInfo {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Per-process AWE info
const MAX_AWE_PROCESSES: usize = 32;
static mut AWE_PROCESS_INFO: [AweInfo; MAX_AWE_PROCESSES] = {
    const INIT: AweInfo = AweInfo::new();
    [INIT; MAX_AWE_PROCESSES]
};

/// AWE regions
static mut AWE_REGIONS: [AweRegion; MAX_AWE_REGIONS * 4] = {
    const INIT: AweRegion = AweRegion::new();
    [INIT; MAX_AWE_REGIONS * 4]
};

/// Global AWE lock
static AWE_LOCK: SpinLock<()> = SpinLock::new(());

/// AWE statistics
static mut AWE_STATS: AweStats = AweStats::new();

/// AWE system statistics
#[derive(Debug, Clone, Copy)]
pub struct AweStats {
    pub active_processes: u32,
    pub active_regions: u32,
    pub total_pages_allocated: u64,
    pub total_pages_mapped: u64,
    pub total_allocations: u64,
    pub total_frees: u64,
    pub total_maps: u64,
    pub total_unmaps: u64,
}

impl AweStats {
    pub const fn new() -> Self {
        Self {
            active_processes: 0,
            active_regions: 0,
            total_pages_allocated: 0,
            total_pages_mapped: 0,
            total_allocations: 0,
            total_frees: 0,
            total_maps: 0,
            total_unmaps: 0,
        }
    }
}

impl Default for AweStats {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// AWE API
// ============================================================================

/// Get or create AWE info for a process
unsafe fn get_or_create_awe_info(process_id: u32) -> Option<&'static mut AweInfo> {
    // First look for existing
    for info in AWE_PROCESS_INFO.iter_mut() {
        if info.active && info.process_id == process_id {
            return Some(info);
        }
    }

    // Create new
    for info in AWE_PROCESS_INFO.iter_mut() {
        if !info.active {
            info.active = true;
            info.process_id = process_id;
            info.allocated_pages = 0;
            info.mapped_pages = 0;
            for pfn in info.page_pfns.iter_mut() {
                *pfn = 0;
            }
            AWE_STATS.active_processes += 1;
            return Some(info);
        }
    }

    None
}

/// Find AWE info for a process
unsafe fn find_awe_info(process_id: u32) -> Option<&'static mut AweInfo> {
    for info in AWE_PROCESS_INFO.iter_mut() {
        if info.active && info.process_id == process_id {
            return Some(info);
        }
    }
    None
}

/// Allocate physical pages for user-mode access
///
/// This is the implementation of NtAllocateUserPhysicalPages.
pub unsafe fn nt_allocate_user_physical_pages(
    process_id: u32,
    number_of_pages: *mut u64,
    page_array: *mut u64,
) -> i32 {
    const STATUS_SUCCESS: i32 = 0;
    const STATUS_INSUFFICIENT_RESOURCES: i32 = -1073741670_i32;
    const STATUS_INVALID_PARAMETER: i32 = -1073741811_i32;

    if number_of_pages.is_null() || page_array.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let requested = *number_of_pages as usize;
    if requested == 0 {
        return STATUS_SUCCESS;
    }

    let _guard = AWE_LOCK.lock();

    // Get or create AWE info for this process
    let awe_info = match get_or_create_awe_info(process_id) {
        Some(info) => info,
        None => return STATUS_INSUFFICIENT_RESOURCES,
    };

    // Check limits
    if awe_info.allocated_pages as usize + requested > 1024 {
        *number_of_pages = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    let mut allocated = 0usize;

    // Allocate physical pages
    for i in 0..requested {
        // Find a free slot in our tracking
        let slot = match awe_info.find_free_slot() {
            Some(s) => s,
            None => break,
        };

        // Allocate a physical page from the system
        // In a real implementation, this would call mm_allocate_page()
        // For now, we'll simulate with sequential PFNs starting at a high address
        let pfn = 0x100000 + AWE_STATS.total_pages_allocated + allocated as u64;

        awe_info.page_pfns[slot] = pfn;
        awe_info.allocated_pages += 1;

        // Return the PFN to the caller
        *page_array.add(i) = pfn;
        allocated += 1;
    }

    *number_of_pages = allocated as u64;
    AWE_STATS.total_pages_allocated += allocated as u64;
    AWE_STATS.total_allocations += 1;

    STATUS_SUCCESS
}

/// Free physical pages previously allocated with NtAllocateUserPhysicalPages
pub unsafe fn nt_free_user_physical_pages(
    process_id: u32,
    number_of_pages: *mut u64,
    page_array: *const u64,
) -> i32 {
    const STATUS_SUCCESS: i32 = 0;
    const STATUS_INVALID_PARAMETER: i32 = -1073741811_i32;
    const STATUS_INVALID_PAGE_PROTECTION: i32 = -1073741800_i32;

    if number_of_pages.is_null() || page_array.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let requested = *number_of_pages as usize;
    if requested == 0 {
        return STATUS_SUCCESS;
    }

    let _guard = AWE_LOCK.lock();

    let awe_info = match find_awe_info(process_id) {
        Some(info) => info,
        None => return STATUS_INVALID_PARAMETER,
    };

    let mut freed = 0usize;

    for i in 0..requested {
        let pfn = *page_array.add(i);

        // Find this PFN in our list
        if let Some(slot) = awe_info.find_pfn(pfn) {
            // Check if it's currently mapped
            // In a full implementation, we'd need to unmap it first

            // Free the slot
            awe_info.page_pfns[slot] = 0;
            awe_info.allocated_pages = awe_info.allocated_pages.saturating_sub(1);
            freed += 1;
        }
    }

    *number_of_pages = freed as u64;
    AWE_STATS.total_frees += 1;

    // Clean up process info if no more pages
    if awe_info.allocated_pages == 0 {
        awe_info.active = false;
        AWE_STATS.active_processes = AWE_STATS.active_processes.saturating_sub(1);
    }

    STATUS_SUCCESS
}

/// Create an AWE region (virtual window) for mapping physical pages
pub unsafe fn mi_create_awe_region(
    process_id: u32,
    vad_index: u32,
    virtual_base: u64,
    window_size: u64,
) -> Option<usize> {
    let _guard = AWE_LOCK.lock();

    // Find a free region slot
    let region_idx = AWE_REGIONS.iter().position(|r| !r.active)?;

    let region = &mut AWE_REGIONS[region_idx];
    region.process_id = process_id;
    region.vad_index = vad_index;
    region.virtual_base = virtual_base;
    region.window_size = window_size;
    region.window_pages = window_size >> PAGE_SHIFT;
    region.active = true;
    region.total_maps = 0;
    region.total_unmaps = 0;

    // Clear mapped PFNs
    for pfn in region.mapped_pfns.iter_mut() {
        *pfn = 0;
    }

    AWE_STATS.active_regions += 1;

    Some(region_idx)
}

/// Destroy an AWE region
pub unsafe fn mi_destroy_awe_region(region_idx: usize) {
    let _guard = AWE_LOCK.lock();

    if region_idx >= AWE_REGIONS.len() {
        return;
    }

    let region = &mut AWE_REGIONS[region_idx];
    if !region.active {
        return;
    }

    // Unmap all pages first
    for pfn in region.mapped_pfns.iter_mut() {
        *pfn = 0;
    }

    region.active = false;
    AWE_STATS.active_regions = AWE_STATS.active_regions.saturating_sub(1);
}

/// Find AWE region by virtual address
pub unsafe fn mi_find_awe_region(process_id: u32, virtual_addr: u64) -> Option<usize> {
    for (idx, region) in AWE_REGIONS.iter().enumerate() {
        if region.active &&
           region.process_id == process_id &&
           region.contains_va(virtual_addr)
        {
            return Some(idx);
        }
    }
    None
}

/// Map physical pages into a virtual window
///
/// This is the implementation of NtMapUserPhysicalPages.
pub unsafe fn nt_map_user_physical_pages(
    process_id: u32,
    virtual_address: u64,
    number_of_pages: u64,
    page_array: *const u64, // NULL to unmap
) -> i32 {
    const STATUS_SUCCESS: i32 = 0;
    const STATUS_INVALID_PARAMETER_1: i32 = -1073741811_i32;
    const STATUS_INVALID_PARAMETER_2: i32 = -1073741810_i32;
    const STATUS_CONFLICTING_ADDRESSES: i32 = -1073741766_i32;

    if number_of_pages == 0 {
        return STATUS_SUCCESS;
    }

    let _guard = AWE_LOCK.lock();

    // Find the AWE region containing this address
    let region_idx = match mi_find_awe_region_unlocked(process_id, virtual_address) {
        Some(idx) => idx,
        None => return STATUS_INVALID_PARAMETER_1,
    };

    let region = &mut AWE_REGIONS[region_idx];

    // Calculate page offset within the window
    let start_page = ((virtual_address - region.virtual_base) >> PAGE_SHIFT) as usize;
    let end_page = start_page + number_of_pages as usize;

    if end_page > region.window_pages as usize || end_page > 256 {
        return STATUS_INVALID_PARAMETER_2;
    }

    // Get process AWE info
    let awe_info = match find_awe_info(process_id) {
        Some(info) => info,
        None => return STATUS_INVALID_PARAMETER_1,
    };

    if page_array.is_null() {
        // Unmap the pages
        for page_idx in start_page..end_page {
            if region.mapped_pfns[page_idx] != 0 {
                region.mapped_pfns[page_idx] = 0;
                region.total_unmaps += 1;
                AWE_STATS.total_unmaps += 1;
                AWE_STATS.total_pages_mapped = AWE_STATS.total_pages_mapped.saturating_sub(1);
            }
        }
    } else {
        // Map the pages
        for (i, page_idx) in (start_page..end_page).enumerate() {
            let pfn = *page_array.add(i);

            // Verify this PFN belongs to this process
            if pfn != 0 && awe_info.find_pfn(pfn).is_none() {
                return STATUS_CONFLICTING_ADDRESSES;
            }

            // Check if PFN is already mapped elsewhere
            // (In a full implementation, we'd check all regions)

            region.mapped_pfns[page_idx] = pfn;
            if pfn != 0 {
                region.total_maps += 1;
                AWE_STATS.total_maps += 1;
                AWE_STATS.total_pages_mapped += 1;
            }
        }
    }

    STATUS_SUCCESS
}

/// Internal: Find AWE region without taking lock
unsafe fn mi_find_awe_region_unlocked(process_id: u32, virtual_addr: u64) -> Option<usize> {
    for (idx, region) in AWE_REGIONS.iter().enumerate() {
        if region.active &&
           region.process_id == process_id &&
           region.contains_va(virtual_addr)
        {
            return Some(idx);
        }
    }
    None
}

/// Get the PFN mapped at a virtual address in an AWE region
pub unsafe fn mi_get_awe_pfn(process_id: u32, virtual_addr: u64) -> Option<u64> {
    let _guard = AWE_LOCK.lock();

    let region_idx = mi_find_awe_region_unlocked(process_id, virtual_addr)?;
    let region = &AWE_REGIONS[region_idx];

    let page_idx = region.va_to_page_index(virtual_addr)?;
    if page_idx < 256 {
        let pfn = region.mapped_pfns[page_idx];
        if pfn != 0 {
            return Some(pfn);
        }
    }

    None
}

/// Get AWE statistics
pub fn mi_get_awe_stats() -> AweStats {
    unsafe { AWE_STATS }
}

/// Get snapshot of active AWE regions
pub fn mi_get_awe_snapshots() -> ([AweSnapshot; 16], usize) {
    let mut snapshots = [AweSnapshot::empty(); 16];
    let mut count = 0;

    unsafe {
        let _guard = AWE_LOCK.lock();

        for (idx, region) in AWE_REGIONS.iter().enumerate() {
            if count >= 16 {
                break;
            }
            if region.active {
                let mapped_count = region.mapped_pfns.iter()
                    .take(region.window_pages as usize)
                    .filter(|&&pfn| pfn != 0)
                    .count();

                snapshots[count] = AweSnapshot {
                    index: idx,
                    process_id: region.process_id,
                    virtual_base: region.virtual_base,
                    window_size: region.window_size,
                    window_pages: region.window_pages,
                    mapped_pages: mapped_count as u64,
                    total_maps: region.total_maps,
                    total_unmaps: region.total_unmaps,
                };
                count += 1;
            }
        }
    }

    (snapshots, count)
}

/// AWE region snapshot for diagnostics
#[derive(Debug, Clone, Copy)]
pub struct AweSnapshot {
    pub index: usize,
    pub process_id: u32,
    pub virtual_base: u64,
    pub window_size: u64,
    pub window_pages: u64,
    pub mapped_pages: u64,
    pub total_maps: u64,
    pub total_unmaps: u64,
}

impl AweSnapshot {
    pub const fn empty() -> Self {
        Self {
            index: 0,
            process_id: 0,
            virtual_base: 0,
            window_size: 0,
            window_pages: 0,
            mapped_pages: 0,
            total_maps: 0,
            total_unmaps: 0,
        }
    }
}

// ============================================================================
// Scatter/Gather Support
// ============================================================================

/// Map pages using scatter/gather (non-contiguous virtual to non-contiguous physical)
///
/// This is the implementation of NtMapUserPhysicalPagesScatter.
pub unsafe fn nt_map_user_physical_pages_scatter(
    process_id: u32,
    virtual_addresses: *const u64,
    number_of_pages: u64,
    page_array: *const u64,
) -> i32 {
    const STATUS_SUCCESS: i32 = 0;
    const STATUS_INVALID_PARAMETER: i32 = -1073741811_i32;

    if virtual_addresses.is_null() || number_of_pages == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let _guard = AWE_LOCK.lock();

    let awe_info = match find_awe_info(process_id) {
        Some(info) => info,
        None => return STATUS_INVALID_PARAMETER,
    };

    for i in 0..number_of_pages as usize {
        let va = *virtual_addresses.add(i);
        let pfn = if page_array.is_null() { 0 } else { *page_array.add(i) };

        // Find the region for this VA
        let region_idx = match mi_find_awe_region_unlocked(process_id, va) {
            Some(idx) => idx,
            None => continue, // Skip invalid addresses
        };

        let region = &mut AWE_REGIONS[region_idx];

        if let Some(page_idx) = region.va_to_page_index(va) {
            if page_idx < 256 {
                // Verify PFN ownership if mapping
                if pfn != 0 && awe_info.find_pfn(pfn).is_none() {
                    continue;
                }

                region.mapped_pfns[page_idx] = pfn;
                if pfn != 0 {
                    region.total_maps += 1;
                } else {
                    region.total_unmaps += 1;
                }
            }
        }
    }

    AWE_STATS.total_maps += number_of_pages;
    STATUS_SUCCESS
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize AWE subsystem
pub fn init() {
    unsafe {
        for info in AWE_PROCESS_INFO.iter_mut() {
            info.active = false;
        }

        for region in AWE_REGIONS.iter_mut() {
            region.active = false;
        }

        AWE_STATS = AweStats::new();
    }

    crate::serial_println!("[MM] AWE (Address Windowing Extensions) initialized");
}
