//! Memory Manager (mm)
//!
//! The memory manager handles all virtual and physical memory:
//!
//! - **Virtual Memory**: 4-level page tables, address space management
//! - **PFN Database**: Tracks state of every physical page
//! - **VAD Tree**: AVL tree of virtual address descriptors
//! - **Working Sets**: Pages currently in memory per process
//! - **Section Objects**: Shared memory and file mapping
//! - **Pool Allocator**: Paged and NonPaged pools
//!
//! # Address Space Layout (x86_64)
//!
//! - User space: 0x0000_0000_0000_0000 - 0x0000_7FFF_FFFF_FFFF
//! - Kernel space: 0xFFFF_8000_0000_0000 - 0xFFFF_FFFF_FFFF_FFFF
//!
//! # Key Structures
//!
//! - `MMPFN`: Page Frame Number database entry
//! - `MMVAD`: Virtual Address Descriptor
//! - `MMWSL`: Working Set List
//! - `MMPTE`: Page Table Entry

pub mod pfn;
pub mod pte;
pub mod vad;
pub mod pool;
pub mod address;
pub mod physical;
pub mod user;
pub mod section;
pub mod tlb;

// Re-export PFN types
pub use pfn::{
    MmPfn,
    MmPageState,
    MmStats,
    PAGE_SIZE,
    PAGE_SHIFT,
    LARGE_PAGE_SIZE,
    LARGE_PAGE_SHIFT,
    pfn_flags,
    mm_allocate_page,
    mm_allocate_zeroed_page,
    mm_free_page,
    mm_pfn_entry,
    mm_get_stats,
    mm_init_pfn_database,
    mm_init_pfn_simple,
};

// Re-export PTE types
pub use pte::{
    HardwarePte,
    MmPte,
    SoftwarePte,
    PageTable,
    pte_flags,
    ENTRIES_PER_TABLE,
    // Virtual address manipulation
    pml4_index,
    pdpt_index,
    pd_index,
    pt_index,
    page_offset,
    is_canonical,
    is_kernel_address,
    is_user_address,
    // Page table operations
    mm_get_pte,
    mm_virtual_to_physical,
    mm_invalidate_page,
    mm_invalidate_page_local,
    mm_flush_tlb,
    mm_flush_tlb_local,
    mm_get_cr3,
    mm_set_cr3,
};

// Re-export VAD types
pub use vad::{
    MmVad,
    MmVadType,
    MmVadRoot,
    MmVadStats,
    MmVadSnapshot,
    MAX_VADS,
    protection,
    allocation_type,
    vad_flags,
    mm_allocate_vad,
    mm_free_vad,
    mm_get_vad,
    mm_find_vad,
    mm_insert_vad,
    mm_remove_vad,
    mm_find_free_region,
    mm_allocate_virtual_range,
    mm_free_virtual_range,
    mm_get_vad_stats,
    mm_get_vad_snapshots,
    vad_type_name,
    protection_name,
};

// Re-export pool types
pub use pool::{
    PoolType,
    PoolTag,
    PoolStats,
    make_tag,
    pool_tags,
    ex_allocate_pool_with_tag,
    ex_allocate_pool_zero,
    ex_free_pool_with_tag,
    ex_free_pool,
    mm_get_pool_stats,
    mm_get_pool_free_count,
};

// Re-export address space types
pub use address::{
    MmAddressSpace,
    MmWorkingSet,
    WsleEntry,
    MmMemoryInfo,
    MmAddressSpaceStats,
    MAX_ADDRESS_SPACES,
    USER_SPACE_START,
    USER_SPACE_END,
    KERNEL_SPACE_START,
    KERNEL_SPACE_END,
    DEFAULT_STACK_SIZE,
    DEFAULT_HEAP_SIZE,
    address_space_flags,
    wsle_flags,
    mm_create_address_space,
    mm_delete_address_space,
    mm_get_system_address_space,
    mm_attach_address_space,
    mm_detach_address_space,
    mm_allocate_virtual_memory,
    mm_free_virtual_memory,
    mm_protect_virtual_memory,
    mm_query_virtual_memory,
    mm_access_fault,
    mm_get_address_space_stats,
};

// Re-export physical memory types
pub use physical::{
    MmMemoryType,
    MmMemoryRegion,
    PhysicalMemoryStats,
    mm_alloc_physical_page,
    mm_alloc_physical_page_zeroed,
    mm_free_physical_page,
    mm_alloc_contiguous_pages,
    mm_free_contiguous_pages,
    mm_get_physical_stats,
    mm_get_region_count,
    mm_get_region,
    mm_is_valid_physical_address,
    mm_get_physical_memory_type,
    mm_alloc_large_page,
    mm_free_large_page,
    mm_parse_memory_map,
    mm_lock_pages,
    mm_unlock_pages,
};

// Re-export user mode types
pub use user::{
    init_user_page_tables,
    get_user_cr3,
    get_kernel_cr3,
    switch_to_user_pages,
    switch_to_kernel_pages,
    get_user_code_base,
    get_user_stack_top,
    get_user_code_phys,
    get_user_stack_phys,
    copy_code_to_user,
    run_user_mode_test,
    is_initialized as user_pages_initialized,
    USER_TEST_BASE,
    USER_STACK_TOP,
    USER_TEST_CODE,
};

// Re-export section types
pub use section::{
    Section,
    SectionView,
    SectionType,
    SectionInfo,
    SectionStats,
    ControlArea,
    section_access,
    section_type,
    page_protection,
    mm_create_section,
    mm_create_file_section,
    mm_create_image_section,
    mm_close_section,
    mm_map_view_of_section,
    mm_unmap_view_of_section,
    mm_find_section_by_view_address,
    mm_extend_section,
    mm_query_section,
    mm_get_section_stats,
    MAX_SECTIONS,
    SECTION_ALLOCATION_GRANULARITY,
};

// Re-export TLB shootdown types
pub use tlb::{
    TlbInvalidationType,
    TlbShootdownRequest,
    TLB_SHOOTDOWN_VECTOR,
    tlb_shootdown_single_page,
    tlb_shootdown_range,
    tlb_shootdown_all,
    tlb_shootdown_handler,
    get_shootdown_stats,
};

/// Initialize the Memory Manager
///
/// This initializes all memory management subsystems:
/// 1. PFN database
/// 2. PTE subsystem
/// 3. VAD subsystem
/// 4. Pool allocator
/// 5. Address space management
/// 6. Physical memory management
pub unsafe fn init(boot_info: &crate::BootInfo) {
    crate::serial_println!("[MM] Initializing Memory Manager...");

    // Initialize PFN database
    pfn::init();

    // Initialize PTE subsystem
    pte::init();

    // Initialize VAD subsystem
    vad::init();

    // Initialize pool allocator
    pool::init();

    // Initialize address space management
    address::init();

    // Initialize physical memory management (parses memory map)
    physical::init(boot_info);

    // Initialize section subsystem
    section::init();

    // Initialize TLB shootdown subsystem
    tlb::init();

    crate::serial_println!("[MM] Memory Manager initialized");
}
