//! Page Frame Number (PFN) Database
//!
//! The PFN database tracks the state of every physical page in the system.
//! Each entry (MMPFN) contains:
//! - Page state (free, active, standby, modified, etc.)
//! - Reference count
//! - Pointer to owning process/prototype PTE
//! - Links for free/standby/modified lists
//!
//! # Page States
//! - Free: Available for allocation
//! - Zeroed: Free and zero-filled
//! - Standby: Was in working set, can be reclaimed
//! - Modified: Was in working set, needs writeback
//! - Active: Currently in a working set
//! - Transition: Being read from/written to disk
//! - Bad: Hardware error, unusable

use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// Page size (4KB)
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;

/// Large page size (2MB)
pub const LARGE_PAGE_SIZE: usize = 2 * 1024 * 1024;
pub const LARGE_PAGE_SHIFT: usize = 21;

/// Page states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum MmPageState {
    /// Page is on the free list
    #[default]
    Free = 0,
    /// Page is free and zero-filled
    Zeroed = 1,
    /// Page was in working set, can be quickly reclaimed
    Standby = 2,
    /// Page was in working set, needs to be written to disk
    Modified = 3,
    /// Page has modified data, waiting for write
    ModifiedNoWrite = 4,
    /// Page is in a process's working set
    Active = 5,
    /// Page is being read from or written to disk
    Transition = 6,
    /// Page has hardware errors
    Bad = 7,
}


/// Page Frame Number database entry
///
/// One entry exists for each physical page in the system.
#[repr(C)]
pub struct MmPfn {
    /// Forward link (for free/standby/modified lists)
    pub flink: u32,
    /// Back link
    pub blink: u32,

    /// PTE address that maps this page (or prototype PTE)
    pub pte_address: AtomicU64,

    /// Reference count
    pub reference_count: AtomicU32,

    /// Share count (number of PTEs referencing this page)
    pub share_count: AtomicU32,

    /// Page state and flags
    pub state: MmPageState,

    /// Page color (NUMA node / cache coloring)
    pub color: u8,

    /// Flags
    pub flags: u16,

    /// Original PTE contents (for transition pages)
    pub original_pte: u64,

    /// Owning process (for active pages)
    pub owning_process: *mut u8,
}

impl MmPfn {
    pub const fn new() -> Self {
        Self {
            flink: 0,
            blink: 0,
            pte_address: AtomicU64::new(0),
            reference_count: AtomicU32::new(0),
            share_count: AtomicU32::new(0),
            state: MmPageState::Free,
            color: 0,
            flags: 0,
            original_pte: 0,
            owning_process: ptr::null_mut(),
        }
    }

    /// Check if page is free
    pub fn is_free(&self) -> bool {
        matches!(self.state, MmPageState::Free | MmPageState::Zeroed)
    }

    /// Check if page is in use
    pub fn is_active(&self) -> bool {
        matches!(self.state, MmPageState::Active)
    }

    /// Get reference count
    pub fn ref_count(&self) -> u32 {
        self.reference_count.load(Ordering::SeqCst)
    }

    /// Increment reference count
    pub fn add_ref(&self) -> u32 {
        self.reference_count.fetch_add(1, Ordering::SeqCst)
    }

    /// Decrement reference count
    pub fn release(&self) -> u32 {
        self.reference_count.fetch_sub(1, Ordering::SeqCst)
    }
}

impl Default for MmPfn {
    fn default() -> Self {
        Self::new()
    }
}

// Safety: MmPfn uses atomics for thread-safe access
unsafe impl Sync for MmPfn {}
unsafe impl Send for MmPfn {}

/// PFN flags
pub mod pfn_flags {
    /// Page is part of kernel address space
    pub const PFN_KERNEL: u16 = 0x0001;
    /// Page is locked in memory
    pub const PFN_LOCKED: u16 = 0x0002;
    /// Page is part of a prototype PTE chain
    pub const PFN_PROTOTYPE: u16 = 0x0004;
    /// Page is a large page
    pub const PFN_LARGE_PAGE: u16 = 0x0008;
    /// Page is ROM (read-only memory)
    pub const PFN_ROM: u16 = 0x0010;
    /// Page has been written to
    pub const PFN_DIRTY: u16 = 0x0020;
}

// ============================================================================
// PFN Database
// ============================================================================

/// Maximum physical memory we support (1GB for now)
pub const MAX_PHYSICAL_MEMORY: usize = 1024 * 1024 * 1024;

/// Maximum number of physical pages
pub const MAX_PHYSICAL_PAGES: usize = MAX_PHYSICAL_MEMORY / PAGE_SIZE;

/// PFN database (static allocation for simplicity)
/// In a real OS, this would be dynamically sized based on detected memory.
static mut PFN_DATABASE: [MmPfn; 4096] = {
    const INIT: MmPfn = MmPfn::new();
    [INIT; 4096]
};

/// PFN database lock
static PFN_LOCK: SpinLock<()> = SpinLock::new(());

/// Total number of physical pages in the system
static mut TOTAL_PAGES: usize = 0;

/// Number of free pages
static FREE_PAGES: AtomicU32 = AtomicU32::new(0);

/// Number of zeroed pages
static ZEROED_PAGES: AtomicU32 = AtomicU32::new(0);

/// Number of active pages
static ACTIVE_PAGES: AtomicU32 = AtomicU32::new(0);

/// Free page list head (index into PFN database)
static mut FREE_LIST_HEAD: u32 = u32::MAX;

/// Zeroed page list head
static mut ZEROED_LIST_HEAD: u32 = u32::MAX;

// ============================================================================
// Page List Operations
// ============================================================================

/// Insert a page at the head of the free list
unsafe fn insert_free_page(pfn_index: u32) {
    let pfn = &mut PFN_DATABASE[pfn_index as usize];
    pfn.state = MmPageState::Free;
    pfn.flink = FREE_LIST_HEAD;
    pfn.blink = u32::MAX;

    if FREE_LIST_HEAD != u32::MAX {
        PFN_DATABASE[FREE_LIST_HEAD as usize].blink = pfn_index;
    }
    FREE_LIST_HEAD = pfn_index;
    FREE_PAGES.fetch_add(1, Ordering::SeqCst);
}

/// Remove a page from the free list
unsafe fn remove_free_page(pfn_index: u32) {
    let pfn = &mut PFN_DATABASE[pfn_index as usize];

    if pfn.blink != u32::MAX {
        PFN_DATABASE[pfn.blink as usize].flink = pfn.flink;
    } else {
        FREE_LIST_HEAD = pfn.flink;
    }

    if pfn.flink != u32::MAX {
        PFN_DATABASE[pfn.flink as usize].blink = pfn.blink;
    }

    pfn.flink = u32::MAX;
    pfn.blink = u32::MAX;
    FREE_PAGES.fetch_sub(1, Ordering::SeqCst);
}

/// Insert a page at the head of the zeroed list
unsafe fn insert_zeroed_page(pfn_index: u32) {
    let pfn = &mut PFN_DATABASE[pfn_index as usize];
    pfn.state = MmPageState::Zeroed;
    pfn.flink = ZEROED_LIST_HEAD;
    pfn.blink = u32::MAX;

    if ZEROED_LIST_HEAD != u32::MAX {
        PFN_DATABASE[ZEROED_LIST_HEAD as usize].blink = pfn_index;
    }
    ZEROED_LIST_HEAD = pfn_index;
    ZEROED_PAGES.fetch_add(1, Ordering::SeqCst);
}

/// Remove a page from the zeroed list
unsafe fn remove_zeroed_page(pfn_index: u32) {
    let pfn = &mut PFN_DATABASE[pfn_index as usize];

    if pfn.blink != u32::MAX {
        PFN_DATABASE[pfn.blink as usize].flink = pfn.flink;
    } else {
        ZEROED_LIST_HEAD = pfn.flink;
    }

    if pfn.flink != u32::MAX {
        PFN_DATABASE[pfn.flink as usize].blink = pfn.blink;
    }

    pfn.flink = u32::MAX;
    pfn.blink = u32::MAX;
    ZEROED_PAGES.fetch_sub(1, Ordering::SeqCst);
}

// ============================================================================
// Public Interface
// ============================================================================

/// Get a PFN entry by physical page number
pub unsafe fn mm_pfn_entry(pfn_index: usize) -> Option<&'static mut MmPfn> {
    if pfn_index < PFN_DATABASE.len() {
        Some(&mut PFN_DATABASE[pfn_index])
    } else {
        None
    }
}

/// Allocate a physical page
///
/// Returns the physical page number, or None if no pages available.
pub unsafe fn mm_allocate_page() -> Option<usize> {
    let _guard = PFN_LOCK.lock();

    // Try zeroed list first
    if ZEROED_LIST_HEAD != u32::MAX {
        let pfn_index = ZEROED_LIST_HEAD as usize;
        remove_zeroed_page(pfn_index as u32);
        let pfn = &mut PFN_DATABASE[pfn_index];
        pfn.state = MmPageState::Active;
        pfn.reference_count.store(1, Ordering::SeqCst);
        ACTIVE_PAGES.fetch_add(1, Ordering::SeqCst);
        return Some(pfn_index);
    }

    // Try free list
    if FREE_LIST_HEAD != u32::MAX {
        let pfn_index = FREE_LIST_HEAD as usize;
        remove_free_page(pfn_index as u32);
        let pfn = &mut PFN_DATABASE[pfn_index];
        pfn.state = MmPageState::Active;
        pfn.reference_count.store(1, Ordering::SeqCst);
        ACTIVE_PAGES.fetch_add(1, Ordering::SeqCst);

        // Zero the page
        let page_addr = pfn_index * PAGE_SIZE;
        let page_ptr = page_addr as *mut u8;
        core::ptr::write_bytes(page_ptr, 0, PAGE_SIZE);

        return Some(pfn_index);
    }

    None
}

/// Allocate a zeroed physical page
pub unsafe fn mm_allocate_zeroed_page() -> Option<usize> {
    mm_allocate_page() // Our allocate_page already zeros
}

/// Free a physical page
pub unsafe fn mm_free_page(pfn_index: usize) {
    if pfn_index >= PFN_DATABASE.len() {
        return;
    }

    let _guard = PFN_LOCK.lock();

    let pfn = &mut PFN_DATABASE[pfn_index];

    // Decrement reference count
    let old_ref = pfn.release();
    if old_ref > 1 {
        return; // Still has references
    }

    if pfn.state == MmPageState::Active {
        ACTIVE_PAGES.fetch_sub(1, Ordering::SeqCst);
    }

    // Add to free list
    pfn.pte_address.store(0, Ordering::SeqCst);
    pfn.share_count.store(0, Ordering::SeqCst);
    pfn.owning_process = ptr::null_mut();
    insert_free_page(pfn_index as u32);
}

/// Get a PFN entry by index
///
/// Returns a mutable reference to the PFN entry, or None if invalid.
pub unsafe fn mm_get_pfn(pfn_index: usize) -> Option<&'static mut MmPfn> {
    if pfn_index < PFN_DATABASE.len() {
        Some(&mut PFN_DATABASE[pfn_index])
    } else {
        None
    }
}

/// Get memory statistics
pub fn mm_get_stats() -> MmStats {
    MmStats {
        total_pages: unsafe { TOTAL_PAGES } as u32,
        free_pages: FREE_PAGES.load(Ordering::SeqCst),
        zeroed_pages: ZEROED_PAGES.load(Ordering::SeqCst),
        active_pages: ACTIVE_PAGES.load(Ordering::SeqCst),
    }
}

/// Memory statistics
#[derive(Debug, Clone, Copy)]
pub struct MmStats {
    pub total_pages: u32,
    pub free_pages: u32,
    pub zeroed_pages: u32,
    pub active_pages: u32,
}

impl MmStats {
    pub fn total_bytes(&self) -> u64 {
        self.total_pages as u64 * PAGE_SIZE as u64
    }

    pub fn free_bytes(&self) -> u64 {
        (self.free_pages + self.zeroed_pages) as u64 * PAGE_SIZE as u64
    }

    pub fn used_bytes(&self) -> u64 {
        self.active_pages as u64 * PAGE_SIZE as u64
    }
}

/// Initialize the PFN database from memory map
///
/// This should be called during early boot with the memory map
/// provided by the bootloader.
pub unsafe fn mm_init_pfn_database(
    memory_map_addr: u64,
    memory_map_entries: u64,
    memory_map_entry_size: u64,
) {
    // Memory map entry types (UEFI)
    const EFI_CONVENTIONAL_MEMORY: u32 = 7;
    const EFI_BOOT_SERVICES_CODE: u32 = 3;
    const EFI_BOOT_SERVICES_DATA: u32 = 4;

    // Minimum memory region structure
    #[repr(C)]
    struct MemoryDescriptor {
        memory_type: u32,
        _padding: u32,
        physical_start: u64,
        virtual_start: u64,
        number_of_pages: u64,
        attribute: u64,
    }

    let mut pages_added = 0usize;

    // Process memory map
    for i in 0..memory_map_entries {
        let entry_addr = memory_map_addr + (i * memory_map_entry_size);
        let entry = &*(entry_addr as *const MemoryDescriptor);

        // Check if this is usable memory
        let usable = entry.memory_type == EFI_CONVENTIONAL_MEMORY ||
                     entry.memory_type == EFI_BOOT_SERVICES_CODE ||
                     entry.memory_type == EFI_BOOT_SERVICES_DATA;

        if usable {
            let start_page = (entry.physical_start as usize) / PAGE_SIZE;
            let num_pages = entry.number_of_pages as usize;

            // Add pages to PFN database (skip first 1MB for safety)
            for page in start_page..(start_page + num_pages) {
                if page < 256 {
                    continue; // Skip first 1MB
                }
                if page >= PFN_DATABASE.len() {
                    break;
                }

                insert_free_page(page as u32);
                pages_added += 1;
            }
        }
    }

    TOTAL_PAGES = pages_added;

    crate::serial_println!("[MM] PFN database initialized");
    crate::serial_println!("[MM]   {} pages ({} MB) available",
        pages_added, (pages_added * PAGE_SIZE) / (1024 * 1024));
}

/// Simple initialization for testing (marks some pages as free)
pub unsafe fn mm_init_pfn_simple(start_page: usize, num_pages: usize) {
    let end_page = (start_page + num_pages).min(PFN_DATABASE.len());

    for page in start_page..end_page {
        insert_free_page(page as u32);
    }

    TOTAL_PAGES = end_page - start_page;

    crate::serial_println!("[MM] PFN database initialized (simple)");
    crate::serial_println!("[MM]   {} pages ({} KB) available",
        TOTAL_PAGES, (TOTAL_PAGES * PAGE_SIZE) / 1024);
}

/// Initialize PFN subsystem
pub fn init() {
    // For now, just mark some pages as available
    // In a real implementation, we'd parse the memory map
    unsafe {
        // Mark pages 256-1024 as free (1MB - 4MB region)
        // This avoids the first 1MB which has BIOS/boot stuff
        mm_init_pfn_simple(256, 768);
    }
}

/// Detailed PFN database statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct PfnDetailedStats {
    pub total_pages: u32,
    pub free_pages: u32,
    pub zeroed_pages: u32,
    pub standby_pages: u32,
    pub modified_pages: u32,
    pub active_pages: u32,
    pub transition_pages: u32,
    pub bad_pages: u32,
    pub kernel_pages: u32,
    pub locked_pages: u32,
}

/// Get detailed PFN statistics by scanning the database
pub fn mm_get_detailed_pfn_stats() -> PfnDetailedStats {
    let _guard = PFN_LOCK.lock();

    let mut stats = PfnDetailedStats::default();

    unsafe {
        stats.total_pages = TOTAL_PAGES as u32;

        for i in 0..PFN_DATABASE.len() {
            let pfn = &PFN_DATABASE[i];

            match pfn.state {
                MmPageState::Free => stats.free_pages += 1,
                MmPageState::Zeroed => stats.zeroed_pages += 1,
                MmPageState::Standby => stats.standby_pages += 1,
                MmPageState::Modified | MmPageState::ModifiedNoWrite => stats.modified_pages += 1,
                MmPageState::Active => stats.active_pages += 1,
                MmPageState::Transition => stats.transition_pages += 1,
                MmPageState::Bad => stats.bad_pages += 1,
            }

            if (pfn.flags & pfn_flags::PFN_KERNEL) != 0 {
                stats.kernel_pages += 1;
            }
            if (pfn.flags & pfn_flags::PFN_LOCKED) != 0 {
                stats.locked_pages += 1;
            }
        }
    }

    stats
}

/// Get a snapshot of a specific PFN entry for display
#[derive(Debug, Clone, Copy)]
pub struct PfnSnapshot {
    pub index: usize,
    pub state: MmPageState,
    pub ref_count: u32,
    pub share_count: u32,
    pub flags: u16,
    pub pte_address: u64,
    pub flink: u32,
    pub blink: u32,
}

/// Get a snapshot of a PFN entry
pub fn mm_get_pfn_snapshot(pfn_index: usize) -> Option<PfnSnapshot> {
    if pfn_index >= unsafe { PFN_DATABASE.len() } {
        return None;
    }

    let _guard = PFN_LOCK.lock();

    unsafe {
        let pfn = &PFN_DATABASE[pfn_index];
        Some(PfnSnapshot {
            index: pfn_index,
            state: pfn.state,
            ref_count: pfn.reference_count.load(Ordering::Relaxed),
            share_count: pfn.share_count.load(Ordering::Relaxed),
            flags: pfn.flags,
            pte_address: pfn.pte_address.load(Ordering::Relaxed),
            flink: pfn.flink,
            blink: pfn.blink,
        })
    }
}

/// Get database size
pub fn mm_get_pfn_database_size() -> usize {
    unsafe { PFN_DATABASE.len() }
}

/// Get state name
pub fn mm_page_state_name(state: MmPageState) -> &'static str {
    match state {
        MmPageState::Free => "Free",
        MmPageState::Zeroed => "Zeroed",
        MmPageState::Standby => "Standby",
        MmPageState::Modified => "Modified",
        MmPageState::ModifiedNoWrite => "ModNoWrite",
        MmPageState::Active => "Active",
        MmPageState::Transition => "Transition",
        MmPageState::Bad => "Bad",
    }
}
