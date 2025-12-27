//! User Mode Page Table Setup
//!
//! This module provides functions to set up user-accessible page mappings
//! for running code in ring 3.
//!
//! # Overview
//! User mode execution requires:
//! 1. Page tables with the USER bit set on all levels (PML4 -> PT)
//! 2. User-accessible code pages
//! 3. User-accessible stack pages
//!
//! # Approach
//! We use a static user address space with pre-allocated pages for testing.
//! The pages are identity-mapped for simplicity.

use core::ptr;
use super::pte::{
    PageTable, HardwarePte, pte_flags, ENTRIES_PER_TABLE,
    pml4_index, pdpt_index, pd_index, pt_index,
    mm_get_cr3, mm_set_cr3, mm_flush_tlb, mm_invalidate_page,
};
use super::pfn::PAGE_SIZE;

/// User space test address (low in user space)
/// We'll map a few pages starting here
pub const USER_TEST_BASE: u64 = 0x0000_0000_0040_0000; // 4MB

/// User stack top address
pub const USER_STACK_TOP: u64 = 0x0000_0000_0080_0000; // 8MB

/// Number of user code pages to allocate
const USER_CODE_PAGES: usize = 4; // 16KB

/// Number of user stack pages to allocate
const USER_STACK_PAGES: usize = 4; // 16KB

// ============================================================================
// Static Page Tables for User Space
// ============================================================================

/// PML4 table for user address space
#[repr(C, align(4096))]
struct AlignedPageTable {
    entries: [u64; ENTRIES_PER_TABLE],
}

impl AlignedPageTable {
    const fn new() -> Self {
        Self { entries: [0; ENTRIES_PER_TABLE] }
    }
}

/// User mode page tables (static allocation)
static mut USER_PML4: AlignedPageTable = AlignedPageTable::new();
static mut USER_PDPT: AlignedPageTable = AlignedPageTable::new();
static mut USER_PD: AlignedPageTable = AlignedPageTable::new();
static mut USER_PT_CODE: AlignedPageTable = AlignedPageTable::new();
static mut USER_PT_STACK: AlignedPageTable = AlignedPageTable::new();

/// User code pages (actual memory for user code)
#[repr(C, align(4096))]
struct UserCodePages {
    data: [[u8; PAGE_SIZE]; USER_CODE_PAGES],
}

static mut USER_CODE_AREA: UserCodePages = UserCodePages {
    data: [[0; PAGE_SIZE]; USER_CODE_PAGES],
};

/// User stack pages
#[repr(C, align(4096))]
struct UserStackPages {
    data: [[u8; PAGE_SIZE]; USER_STACK_PAGES],
}

static mut USER_STACK_AREA: UserStackPages = UserStackPages {
    data: [[0; PAGE_SIZE]; USER_STACK_PAGES],
};

/// Kernel PML4 backup (to copy kernel mappings)
static mut KERNEL_PML4_BACKUP: u64 = 0;

/// Whether user page tables are initialized
static mut USER_PAGES_INITIALIZED: bool = false;

// ============================================================================
// User Page Table Setup
// ============================================================================

/// Convert a kernel virtual address to physical address
/// Handles both 4KB pages and 2MB huge pages
unsafe fn virt_to_phys(virt: u64) -> u64 {
    let kernel_cr3 = KERNEL_PML4_BACKUP;

    // Walk the page tables manually to handle huge pages correctly
    let pml4 = kernel_cr3 as *const [u64; 512];
    let pml4_idx = ((virt >> 39) & 0x1FF) as usize;
    let pml4e = (*pml4)[pml4_idx];

    if (pml4e & 1) == 0 {
        panic!("PML4 entry not present for {:#x}", virt);
    }

    let pdpt = (pml4e & 0x000F_FFFF_FFFF_F000) as *const [u64; 512];
    let pdpt_idx = ((virt >> 30) & 0x1FF) as usize;
    let pdpte = (*pdpt)[pdpt_idx];

    if (pdpte & 1) == 0 {
        panic!("PDPT entry not present for {:#x}", virt);
    }

    // Check for 1GB huge page
    if (pdpte & 0x80) != 0 {
        let base = pdpte & 0x000F_FFFF_C000_0000; // 1GB aligned
        let offset = virt & 0x3FFF_FFFF; // 30-bit offset
        return base + offset;
    }

    let pd = (pdpte & 0x000F_FFFF_FFFF_F000) as *const [u64; 512];
    let pd_idx = ((virt >> 21) & 0x1FF) as usize;
    let pde = (*pd)[pd_idx];

    if (pde & 1) == 0 {
        panic!("PD entry not present for {:#x}", virt);
    }

    // Check for 2MB huge page
    if (pde & 0x80) != 0 {
        let base = pde & 0x000F_FFFF_FFE0_0000; // 2MB aligned
        let offset = virt & 0x1F_FFFF; // 21-bit offset
        return base + offset;
    }

    let pt = (pde & 0x000F_FFFF_FFFF_F000) as *const [u64; 512];
    let pt_idx = ((virt >> 12) & 0x1FF) as usize;
    let pte = (*pt)[pt_idx];

    if (pte & 1) == 0 {
        panic!("PT entry not present for {:#x}", virt);
    }

    let base = pte & 0x000F_FFFF_FFFF_F000; // 4KB aligned
    let offset = virt & 0xFFF; // 12-bit offset
    base + offset
}

/// Initialize user mode page tables
///
/// This sets up page tables that:
/// 1. Map the upper half (kernel space) identically to the current tables
/// 2. Map user code area at USER_TEST_BASE
/// 3. Map user stack area below USER_STACK_TOP
///
/// # Safety
/// Must be called once during kernel initialization
pub unsafe fn init_user_page_tables() {
    if USER_PAGES_INITIALIZED {
        return;
    }

    crate::serial_println!("[MM-USER] Initializing user mode page tables...");

    // Get current (kernel) CR3
    let kernel_cr3 = mm_get_cr3();
    KERNEL_PML4_BACKUP = kernel_cr3;

    // Clear our page tables
    for entry in USER_PML4.entries.iter_mut() {
        *entry = 0;
    }
    for entry in USER_PDPT.entries.iter_mut() {
        *entry = 0;
    }
    for entry in USER_PD.entries.iter_mut() {
        *entry = 0;
    }
    for entry in USER_PT_CODE.entries.iter_mut() {
        *entry = 0;
    }
    for entry in USER_PT_STACK.entries.iter_mut() {
        *entry = 0;
    }

    // Copy kernel space mappings from the current PML4
    // Kernel space is entries 256-511 (0xFFFF_8000... to 0xFFFF_FFFF...)
    // NOTE: kernel_cr3 is a physical address - low memory is identity mapped
    let kernel_pml4 = kernel_cr3 as *const AlignedPageTable;
    for i in 256..512 {
        USER_PML4.entries[i] = (*kernel_pml4).entries[i];
    }

    // Convert virtual addresses to physical addresses for page table entries
    let user_pml4_phys = virt_to_phys(USER_PML4.entries.as_ptr() as u64);
    let user_pdpt_phys = virt_to_phys(USER_PDPT.entries.as_ptr() as u64);
    let user_pd_phys = virt_to_phys(USER_PD.entries.as_ptr() as u64);
    let user_pt_code_phys = virt_to_phys(USER_PT_CODE.entries.as_ptr() as u64);
    let user_pt_stack_phys = virt_to_phys(USER_PT_STACK.entries.as_ptr() as u64);

    // Set PML4[0] to point to OUR USER_PDPT with USER bit
    // This allows user-mode access to low virtual addresses (0-512GB)
    // The kernel runs from high addresses (PML4[511]) during the transition
    USER_PML4.entries[0] = user_pdpt_phys | pte_flags::PRESENT | pte_flags::WRITABLE | pte_flags::USER;

    // Set up USER_PDPT[0] to point to USER_PD (for user code/stack at 0x0-0x40000000)
    USER_PDPT.entries[0] = user_pd_phys | pte_flags::PRESENT | pte_flags::WRITABLE | pte_flags::USER;

    // Also need to identity-map the entire first 4GB for kernel access
    // PDPT[1], [2], [3] cover 1GB-4GB range (0x40000000-0xFFFFFFFF)
    // Use 1GB huge pages for simplicity (PDPE with PS bit set)
    // Note: PDPT entries with huge page bit = 0x80 map 1GB directly
    USER_PDPT.entries[1] = (1u64 << 30) | pte_flags::PRESENT | pte_flags::WRITABLE | pte_flags::HUGE_PAGE;
    USER_PDPT.entries[2] = (2u64 << 30) | pte_flags::PRESENT | pte_flags::WRITABLE | pte_flags::HUGE_PAGE;
    USER_PDPT.entries[3] = (3u64 << 30) | pte_flags::PRESENT | pte_flags::WRITABLE | pte_flags::HUGE_PAGE;

    // Calculate indices for code and stack
    // USER_TEST_BASE = 0x400000 = 4MB
    // pd_index(0x400000) = (0x400000 >> 21) & 0x1FF = 2
    // pt_index(0x400000) = (0x400000 >> 12) & 0x1FF = 0

    let code_pd_idx = pd_index(USER_TEST_BASE);
    let code_pt_idx = pt_index(USER_TEST_BASE);

    // USER_STACK_TOP - 16KB = 0x7FC000
    // pd_index(0x7FC000) = (0x7FC000 >> 21) & 0x1FF = 3
    // pt_index(0x7FC000) = (0x7FC000 >> 12) & 0x1FF = 508
    let stack_base = USER_STACK_TOP - (USER_STACK_PAGES * PAGE_SIZE) as u64;
    let stack_pd_idx = pd_index(stack_base);
    let stack_pt_idx = pt_index(stack_base);

    // PD[code_pd_idx] -> PT_CODE
    USER_PD.entries[code_pd_idx] = user_pt_code_phys | pte_flags::PRESENT | pte_flags::WRITABLE | pte_flags::USER;

    // PD[stack_pd_idx] -> PT_STACK
    USER_PD.entries[stack_pd_idx] = user_pt_stack_phys | pte_flags::PRESENT | pte_flags::WRITABLE | pte_flags::USER;

    // CRITICAL: Also identity-map the kernel's physical address range!
    // The kernel is running from the identity-mapped low address (e.g., 0xda00000),
    // not from the high virtual address (0xffffffff80000000).
    // After CR3 switch, we need to continue executing from the low address.
    // Add 2MB huge pages for the kernel's physical area.
    //
    // We need to identity-map:
    // 1. PD[0..1] - Low kernel statics (stack at 0x7c7d8, etc.)
    //    Note: PD[2] = user code at 0x400000, PD[3] = user stack at 0x7FC000
    //    These are already set up as page tables, don't overwrite!
    // 2. PD[104..120] - Kernel code/data at ~0xda00000
    //
    // Map PD[0..1] as 2MB identity pages (kernel statics area)
    for pd_idx in 0..2 {
        let phys_addr = (pd_idx as u64) << 21; // 2MB aligned physical address
        USER_PD.entries[pd_idx] = phys_addr | pte_flags::PRESENT | pte_flags::WRITABLE | pte_flags::HUGE_PAGE;
    }

    // Map PD[4..127] as 2MB identity pages (skip user code/stack at 2,3)
    // This covers 0x800000 to 0xFFFFFFF (8MB to 256MB)
    for pd_idx in 4..128 {
        let phys_addr = (pd_idx as u64) << 21; // 2MB aligned physical address
        USER_PD.entries[pd_idx] = phys_addr | pte_flags::PRESENT | pte_flags::WRITABLE | pte_flags::HUGE_PAGE;
    }

    // Map code pages (USER_RWX - executable, readable, writable, user accessible)
    for i in 0..USER_CODE_PAGES {
        let virt_addr = USER_CODE_AREA.data[i].as_ptr() as u64;
        let phys_addr = virt_to_phys(virt_addr);
        USER_PT_CODE.entries[code_pt_idx + i] = phys_addr | pte_flags::USER_RWX;
    }

    // Map stack pages (USER_RW - writable, readable, user accessible)
    for i in 0..USER_STACK_PAGES {
        let virt_addr = USER_STACK_AREA.data[i].as_ptr() as u64;
        let phys_addr = virt_to_phys(virt_addr);
        USER_PT_STACK.entries[stack_pt_idx + i] = phys_addr | pte_flags::USER_RW;
    }

    // Store the physical address of our PML4 for CR3
    USER_PML4_PHYS = user_pml4_phys;

    USER_PAGES_INITIALIZED = true;

    crate::serial_println!("[MM-USER] User page tables initialized (CR3={:#x})", user_pml4_phys);
}

/// Physical address of user PML4 (cached after init)
static mut USER_PML4_PHYS: u64 = 0;

/// Get the user mode CR3 value (physical address)
pub fn get_user_cr3() -> u64 {
    unsafe { USER_PML4_PHYS }
}

/// Get the kernel mode CR3 value
pub fn get_kernel_cr3() -> u64 {
    unsafe { KERNEL_PML4_BACKUP }
}

/// Switch to user page tables
///
/// # Safety
/// Must have initialized user page tables first.
/// Interrupts are disabled during the switch.
pub unsafe fn switch_to_user_pages() {
    if !USER_PAGES_INITIALIZED {
        panic!("User page tables not initialized");
    }

    let user_cr3 = get_user_cr3();

    // Disable interrupts during CR3 switch
    core::arch::asm!("cli", options(nostack, preserves_flags));

    // Switch to user page tables
    core::arch::asm!(
        "mov cr3, {}",
        in(reg) user_cr3,
        options(nostack, preserves_flags)
    );

    // Re-enable interrupts
    core::arch::asm!("sti", options(nostack, preserves_flags));
}

/// Switch back to kernel page tables
///
/// # Safety
/// Interrupts are disabled during the switch.
pub unsafe fn switch_to_kernel_pages() {
    let kernel_cr3 = get_kernel_cr3();
    if kernel_cr3 != 0 {
        // Disable interrupts during CR3 switch
        core::arch::asm!("cli", options(nostack, preserves_flags));

        // Switch back to kernel page tables
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) kernel_cr3,
            options(nostack, preserves_flags)
        );

        // Re-enable interrupts
        core::arch::asm!("sti", options(nostack, preserves_flags));
    }
}

/// Get the user code area base address (virtual)
pub fn get_user_code_base() -> u64 {
    USER_TEST_BASE
}

/// Get the user stack top address
pub fn get_user_stack_top() -> u64 {
    USER_STACK_TOP
}

/// Copy code to user accessible memory
///
/// # Arguments
/// * `code` - Slice of bytes to copy
///
/// # Returns
/// The user-space virtual address where code was copied
///
/// # Safety
/// Code must fit within USER_CODE_PAGES * PAGE_SIZE
pub unsafe fn copy_code_to_user(code: &[u8]) -> Option<u64> {
    let max_size = USER_CODE_PAGES * PAGE_SIZE;
    if code.len() > max_size {
        crate::serial_println!("[MM-USER] Error: code too large ({} > {})", code.len(), max_size);
        return None;
    }

    // Copy to user code area
    let dest = USER_CODE_AREA.data[0].as_mut_ptr();
    ptr::copy_nonoverlapping(code.as_ptr(), dest, code.len());

    // Zero the rest
    if code.len() < max_size {
        ptr::write_bytes(dest.add(code.len()), 0, max_size - code.len());
    }

    crate::serial_println!("[MM-USER] Copied {} bytes to user code area at {:#x}",
        code.len(), USER_TEST_BASE);

    Some(USER_TEST_BASE)
}

/// Get the physical address of user code area
/// This is the address that can be used with identity mapping
pub fn get_user_code_phys() -> u64 {
    unsafe {
        let virt = USER_CODE_AREA.data[0].as_ptr() as u64;
        virt_to_phys(virt)
    }
}

/// Get the physical address of user stack top
/// This is the address that can be used with identity mapping
pub fn get_user_stack_phys() -> u64 {
    unsafe {
        // Stack grows down, so top is at the end of the last page
        let virt = USER_STACK_AREA.data[USER_STACK_PAGES - 1].as_ptr().add(PAGE_SIZE) as u64;
        virt_to_phys(virt)
    }
}

/// Check if user pages are initialized
pub fn is_initialized() -> bool {
    unsafe { USER_PAGES_INITIALIZED }
}

// ============================================================================
// User Mode Test
// ============================================================================

/// Simple user mode code that executes syscall and returns
/// This will be copied to user-accessible memory
#[rustfmt::skip]
pub static USER_TEST_CODE: [u8; 32] = [
    // mov rax, 4          ; NtGetCurrentThreadId (7 bytes)
    0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00,
    // syscall (2 bytes)
    0x0F, 0x05,
    // mov rdi, rax        ; exit code = thread id (3 bytes)
    0x48, 0x89, 0xC7,
    // mov rax, 1          ; NtTerminateThread (7 bytes)
    0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
    // syscall (2 bytes)
    0x0F, 0x05,
    // jmp $               ; loop forever if we get here (2 bytes)
    0xEB, 0xFE,
    // padding (9 bytes to reach 32)
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
];

/// Run the user mode test
///
/// # Safety
/// Requires proper syscall setup
pub unsafe fn run_user_mode_test() {
    // Initialize user page tables if not done
    if !USER_PAGES_INITIALIZED {
        init_user_page_tables();
    }

    // Copy test code to user memory
    if copy_code_to_user(&USER_TEST_CODE).is_none() {
        crate::serial_println!("[MM-USER] Failed to copy code to user memory");
        return;
    }

    // Use the run_user_code wrapper which handles context save/restore
    // Note: run_user_code uses VIRTUAL addresses from user page tables
    let code_virt = USER_TEST_BASE;
    let stack_virt = USER_STACK_TOP;

    let result = crate::arch::x86_64::syscall::run_user_code(code_virt, stack_virt);

    crate::serial_println!("[MM-USER] User mode returned with exit code: {}", result);
}
