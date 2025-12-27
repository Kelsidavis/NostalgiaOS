//! Physical Memory Management
//!
//! Higher-level interface for physical memory operations.
//! Builds on top of the PFN database.
//!
//! # Features
//! - Physical page allocation (zeroed, non-zeroed)
//! - Contiguous allocation for DMA
//! - Memory region tracking
//! - Large page support

use core::sync::atomic::{AtomicU64, Ordering};
use super::pfn::{
    MmPfn, MmPageState, MmStats,
    mm_allocate_page, mm_allocate_zeroed_page, mm_free_page,
    mm_pfn_entry, mm_get_stats,
    PAGE_SIZE, LARGE_PAGE_SIZE,
};

/// Physical memory region types (from UEFI memory map)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MmMemoryType {
    /// Reserved by firmware
    Reserved = 0,
    /// Loader code (can be reclaimed)
    LoaderCode = 1,
    /// Loader data (can be reclaimed)
    LoaderData = 2,
    /// Boot services code (can be reclaimed after ExitBootServices)
    BootServicesCode = 3,
    /// Boot services data (can be reclaimed after ExitBootServices)
    BootServicesData = 4,
    /// Runtime services code (must be preserved)
    RuntimeServicesCode = 5,
    /// Runtime services data (must be preserved)
    RuntimeServicesData = 6,
    /// Conventional (usable) memory
    Conventional = 7,
    /// Unusable memory
    Unusable = 8,
    /// ACPI reclaimable memory
    AcpiReclaim = 9,
    /// ACPI NVS memory
    AcpiNvs = 10,
    /// Memory-mapped I/O
    Mmio = 11,
    /// Memory-mapped I/O port space
    MmioPortSpace = 12,
    /// Processor reserved memory
    PalCode = 13,
    /// Persistent memory
    Persistent = 14,
}

impl MmMemoryType {
    /// Check if this memory type is usable for allocation
    pub fn is_usable(&self) -> bool {
        matches!(self,
            MmMemoryType::LoaderCode |
            MmMemoryType::LoaderData |
            MmMemoryType::BootServicesCode |
            MmMemoryType::BootServicesData |
            MmMemoryType::Conventional
        )
    }

    /// Check if this memory must be preserved
    pub fn must_preserve(&self) -> bool {
        matches!(self,
            MmMemoryType::RuntimeServicesCode |
            MmMemoryType::RuntimeServicesData |
            MmMemoryType::AcpiNvs |
            MmMemoryType::PalCode
        )
    }
}

/// Memory region descriptor
#[derive(Debug, Clone, Copy)]
pub struct MmMemoryRegion {
    /// Physical start address
    pub physical_start: u64,
    /// Number of pages
    pub page_count: u64,
    /// Memory type
    pub memory_type: MmMemoryType,
    /// Attributes
    pub attributes: u64,
}

impl MmMemoryRegion {
    /// Get the physical end address
    pub fn physical_end(&self) -> u64 {
        self.physical_start + self.page_count * PAGE_SIZE as u64
    }

    /// Get size in bytes
    pub fn size(&self) -> u64 {
        self.page_count * PAGE_SIZE as u64
    }
}

/// Maximum number of memory regions
const MAX_MEMORY_REGIONS: usize = 64;

/// Memory regions
static mut MEMORY_REGIONS: [MmMemoryRegion; MAX_MEMORY_REGIONS] = [MmMemoryRegion {
    physical_start: 0,
    page_count: 0,
    memory_type: MmMemoryType::Reserved,
    attributes: 0,
}; MAX_MEMORY_REGIONS];

/// Number of valid memory regions
static mut MEMORY_REGION_COUNT: usize = 0;

/// Total physical memory
static TOTAL_PHYSICAL_MEMORY: AtomicU64 = AtomicU64::new(0);

/// Usable physical memory
static USABLE_PHYSICAL_MEMORY: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Physical Page Allocation
// ============================================================================

/// Allocate a physical page
///
/// Returns the physical address of the allocated page.
pub unsafe fn mm_alloc_physical_page() -> Option<u64> {
    let pfn = mm_allocate_page()?;
    Some(pfn as u64 * PAGE_SIZE as u64)
}

/// Allocate a zeroed physical page
pub unsafe fn mm_alloc_physical_page_zeroed() -> Option<u64> {
    let pfn = mm_allocate_zeroed_page()?;
    Some(pfn as u64 * PAGE_SIZE as u64)
}

/// Free a physical page
pub unsafe fn mm_free_physical_page(physical_address: u64) {
    let pfn = (physical_address / PAGE_SIZE as u64) as usize;
    mm_free_page(pfn);
}

/// Allocate multiple contiguous physical pages
///
/// This is needed for DMA operations that require contiguous memory.
/// Returns None if contiguous allocation is not possible.
pub unsafe fn mm_alloc_contiguous_pages(page_count: usize) -> Option<u64> {
    // Simple implementation: try to find contiguous free pages
    // In a real implementation, this would use a more sophisticated allocator

    if page_count == 0 {
        return None;
    }

    if page_count == 1 {
        return mm_alloc_physical_page();
    }

    // For now, we don't support multi-page contiguous allocation
    // This would require a buddy allocator or similar
    None
}

/// Free contiguous physical pages
pub unsafe fn mm_free_contiguous_pages(physical_address: u64, page_count: usize) {
    for i in 0..page_count {
        let addr = physical_address + (i * PAGE_SIZE) as u64;
        mm_free_physical_page(addr);
    }
}

// ============================================================================
// Physical Memory Information
// ============================================================================

/// Get physical memory statistics
pub fn mm_get_physical_stats() -> PhysicalMemoryStats {
    let pfn_stats = mm_get_stats();

    PhysicalMemoryStats {
        total_pages: pfn_stats.total_pages,
        free_pages: pfn_stats.free_pages,
        zeroed_pages: pfn_stats.zeroed_pages,
        active_pages: pfn_stats.active_pages,
        total_bytes: TOTAL_PHYSICAL_MEMORY.load(Ordering::SeqCst),
        usable_bytes: USABLE_PHYSICAL_MEMORY.load(Ordering::SeqCst),
    }
}

/// Physical memory statistics
#[derive(Debug, Clone, Copy)]
pub struct PhysicalMemoryStats {
    pub total_pages: u32,
    pub free_pages: u32,
    pub zeroed_pages: u32,
    pub active_pages: u32,
    pub total_bytes: u64,
    pub usable_bytes: u64,
}

impl PhysicalMemoryStats {
    /// Get percentage of memory in use
    pub fn usage_percent(&self) -> u32 {
        if self.total_pages == 0 {
            return 0;
        }
        ((self.active_pages as u64 * 100) / self.total_pages as u64) as u32
    }

    /// Get free memory in bytes
    pub fn free_bytes(&self) -> u64 {
        (self.free_pages + self.zeroed_pages) as u64 * PAGE_SIZE as u64
    }
}

/// Get the number of memory regions
pub fn mm_get_region_count() -> usize {
    unsafe { MEMORY_REGION_COUNT }
}

/// Get a memory region by index
pub fn mm_get_region(index: usize) -> Option<MmMemoryRegion> {
    unsafe {
        if index < MEMORY_REGION_COUNT {
            Some(MEMORY_REGIONS[index])
        } else {
            None
        }
    }
}

// ============================================================================
// Physical Address Validation
// ============================================================================

/// Check if a physical address is valid (mapped to RAM)
pub fn mm_is_valid_physical_address(physical_address: u64) -> bool {
    unsafe {
        for i in 0..MEMORY_REGION_COUNT {
            let region = &MEMORY_REGIONS[i];
            if region.memory_type.is_usable() {
                if physical_address >= region.physical_start
                    && physical_address < region.physical_end()
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Get the memory type for a physical address
pub fn mm_get_physical_memory_type(physical_address: u64) -> Option<MmMemoryType> {
    unsafe {
        for i in 0..MEMORY_REGION_COUNT {
            let region = &MEMORY_REGIONS[i];
            if physical_address >= region.physical_start
                && physical_address < region.physical_end()
            {
                return Some(region.memory_type);
            }
        }
    }
    None
}

// ============================================================================
// Large Pages
// ============================================================================

/// Allocate a large page (2MB)
///
/// Large pages can improve TLB efficiency for large allocations.
pub unsafe fn mm_alloc_large_page() -> Option<u64> {
    // Large pages need 512 contiguous 4KB pages aligned to 2MB
    // This is expensive - would need a buddy allocator

    // For now, not supported
    None
}

/// Free a large page
pub unsafe fn mm_free_large_page(physical_address: u64) {
    // Free 512 contiguous pages
    let pages = LARGE_PAGE_SIZE / PAGE_SIZE;
    for i in 0..pages {
        let addr = physical_address + (i * PAGE_SIZE) as u64;
        mm_free_physical_page(addr);
    }
}

// ============================================================================
// Memory Map Parsing
// ============================================================================

/// Parse memory map from bootloader
///
/// This converts the UEFI memory map format to our internal format.
pub unsafe fn mm_parse_memory_map(
    memory_map_addr: u64,
    memory_map_entries: u64,
    memory_map_entry_size: u64,
) {
    #[repr(C)]
    struct EfiMemoryDescriptor {
        memory_type: u32,
        _padding: u32,
        physical_start: u64,
        virtual_start: u64,
        number_of_pages: u64,
        attribute: u64,
    }

    let mut total = 0u64;
    let mut usable = 0u64;
    let mut region_idx = 0usize;

    for i in 0..memory_map_entries {
        if region_idx >= MAX_MEMORY_REGIONS {
            break;
        }

        let entry_addr = memory_map_addr + (i * memory_map_entry_size);
        let entry = &*(entry_addr as *const EfiMemoryDescriptor);

        let memory_type = match entry.memory_type {
            0 => MmMemoryType::Reserved,
            1 => MmMemoryType::LoaderCode,
            2 => MmMemoryType::LoaderData,
            3 => MmMemoryType::BootServicesCode,
            4 => MmMemoryType::BootServicesData,
            5 => MmMemoryType::RuntimeServicesCode,
            6 => MmMemoryType::RuntimeServicesData,
            7 => MmMemoryType::Conventional,
            8 => MmMemoryType::Unusable,
            9 => MmMemoryType::AcpiReclaim,
            10 => MmMemoryType::AcpiNvs,
            11 => MmMemoryType::Mmio,
            12 => MmMemoryType::MmioPortSpace,
            13 => MmMemoryType::PalCode,
            14 => MmMemoryType::Persistent,
            _ => MmMemoryType::Reserved,
        };

        let size = entry.number_of_pages * PAGE_SIZE as u64;
        total += size;

        if memory_type.is_usable() {
            usable += size;
        }

        MEMORY_REGIONS[region_idx] = MmMemoryRegion {
            physical_start: entry.physical_start,
            page_count: entry.number_of_pages,
            memory_type,
            attributes: entry.attribute,
        };

        region_idx += 1;
    }

    MEMORY_REGION_COUNT = region_idx;
    TOTAL_PHYSICAL_MEMORY.store(total, Ordering::SeqCst);
    USABLE_PHYSICAL_MEMORY.store(usable, Ordering::SeqCst);
}

// ============================================================================
// Page Locking
// ============================================================================

/// Lock physical pages in memory (prevent paging)
pub unsafe fn mm_lock_pages(physical_address: u64, page_count: usize) -> bool {
    for i in 0..page_count {
        let pfn = ((physical_address / PAGE_SIZE as u64) + i as u64) as usize;
        if let Some(entry) = mm_pfn_entry(pfn) {
            entry.flags |= super::pfn::pfn_flags::PFN_LOCKED;
        } else {
            return false;
        }
    }
    true
}

/// Unlock physical pages
pub unsafe fn mm_unlock_pages(physical_address: u64, page_count: usize) {
    for i in 0..page_count {
        let pfn = ((physical_address / PAGE_SIZE as u64) + i as u64) as usize;
        if let Some(entry) = mm_pfn_entry(pfn) {
            entry.flags &= !super::pfn::pfn_flags::PFN_LOCKED;
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize physical memory management
pub unsafe fn init(boot_info: &crate::BootInfo) {
    // Parse memory map from bootloader
    if boot_info.memory_map_entries > 0 {
        mm_parse_memory_map(
            boot_info.memory_map_addr,
            boot_info.memory_map_entries,
            boot_info.memory_map_entry_size,
        );
    }

    let total = TOTAL_PHYSICAL_MEMORY.load(Ordering::SeqCst);
    let usable = USABLE_PHYSICAL_MEMORY.load(Ordering::SeqCst);

    crate::serial_println!("[MM] Physical memory initialized");
    crate::serial_println!("[MM]   Total: {} MB", total / (1024 * 1024));
    crate::serial_println!("[MM]   Usable: {} MB", usable / (1024 * 1024));
    crate::serial_println!("[MM]   {} memory regions", unsafe { MEMORY_REGION_COUNT });
}
