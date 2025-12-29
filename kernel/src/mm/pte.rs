//! Page Table Entry (PTE) Implementation
//!
//! x86_64 uses 4-level paging:
//! - PML4 (Page Map Level 4) - 512 entries, each covers 512GB
//! - PDPT (Page Directory Pointer Table) - 512 entries, each covers 1GB
//! - PD (Page Directory) - 512 entries, each covers 2MB
//! - PT (Page Table) - 512 entries, each covers 4KB
//!
//! # Virtual Address Layout (48-bit)
//! ```text
//! 63-48: Sign extension (all 0s or 1s)
//! 47-39: PML4 index (9 bits)
//! 38-30: PDPT index (9 bits)
//! 29-21: PD index (9 bits)
//! 20-12: PT index (9 bits)
//! 11-0:  Page offset (12 bits)
//! ```
//!
//! # Page Table Entry Format
//! ```text
//! Bit 0:     Present
//! Bit 1:     Read/Write
//! Bit 2:     User/Supervisor
//! Bit 3:     Write-Through
//! Bit 4:     Cache Disable
//! Bit 5:     Accessed
//! Bit 6:     Dirty
//! Bit 7:     Page Size (1=Large page)
//! Bit 8:     Global
//! Bits 9-11: Available
//! Bits 12-51: Physical address (40 bits, 4KB aligned)
//! Bits 52-62: Available
//! Bit 63:    No Execute
//! ```


/// Number of entries per page table (all levels)
pub const ENTRIES_PER_TABLE: usize = 512;

/// Page table entry flags
pub mod pte_flags {
    /// Page is present in memory
    pub const PRESENT: u64 = 1 << 0;
    /// Page is writable
    pub const WRITABLE: u64 = 1 << 1;
    /// Page is accessible from user mode
    pub const USER: u64 = 1 << 2;
    /// Write-through caching
    pub const WRITE_THROUGH: u64 = 1 << 3;
    /// Disable caching
    pub const CACHE_DISABLE: u64 = 1 << 4;
    /// Page has been accessed
    pub const ACCESSED: u64 = 1 << 5;
    /// Page has been written to
    pub const DIRTY: u64 = 1 << 6;
    /// Large page (2MB or 1GB)
    pub const HUGE_PAGE: u64 = 1 << 7;
    /// Global (not flushed on CR3 switch)
    pub const GLOBAL: u64 = 1 << 8;

    // Software-defined bits (available for OS use)
    /// Copy-on-write
    pub const COPY_ON_WRITE: u64 = 1 << 9;
    /// Prototype PTE
    pub const PROTOTYPE: u64 = 1 << 10;
    /// Transition (page being paged in/out)
    pub const TRANSITION: u64 = 1 << 11;

    /// No execute
    pub const NO_EXECUTE: u64 = 1 << 63;

    /// Mask for physical address (bits 12-51)
    pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    /// Common combinations
    pub const KERNEL_RW: u64 = PRESENT | WRITABLE | GLOBAL;
    pub const KERNEL_RO: u64 = PRESENT | GLOBAL;
    pub const KERNEL_RWX: u64 = PRESENT | WRITABLE | GLOBAL;
    pub const KERNEL_RX: u64 = PRESENT | GLOBAL;
    pub const USER_RW: u64 = PRESENT | WRITABLE | USER;
    pub const USER_RO: u64 = PRESENT | USER;
    pub const USER_RWX: u64 = PRESENT | WRITABLE | USER;
    pub const USER_RX: u64 = PRESENT | USER;
}

/// Hardware Page Table Entry
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct HardwarePte(u64);

impl HardwarePte {
    /// Create an empty (not present) PTE
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create a PTE with the given physical address and flags
    pub const fn new(phys_addr: u64, flags: u64) -> Self {
        Self((phys_addr & pte_flags::ADDR_MASK) | flags)
    }

    /// Get the raw value
    pub fn raw(&self) -> u64 {
        self.0
    }

    /// Set the raw value
    pub fn set_raw(&mut self, value: u64) {
        self.0 = value;
    }

    /// Check if present
    pub fn is_present(&self) -> bool {
        (self.0 & pte_flags::PRESENT) != 0
    }

    /// Check if writable
    pub fn is_writable(&self) -> bool {
        (self.0 & pte_flags::WRITABLE) != 0
    }

    /// Check if user accessible
    pub fn is_user(&self) -> bool {
        (self.0 & pte_flags::USER) != 0
    }

    /// Check if huge page
    pub fn is_huge(&self) -> bool {
        (self.0 & pte_flags::HUGE_PAGE) != 0
    }

    /// Check if accessed
    pub fn is_accessed(&self) -> bool {
        (self.0 & pte_flags::ACCESSED) != 0
    }

    /// Check if dirty
    pub fn is_dirty(&self) -> bool {
        (self.0 & pte_flags::DIRTY) != 0
    }

    /// Check if no-execute
    pub fn is_no_execute(&self) -> bool {
        (self.0 & pte_flags::NO_EXECUTE) != 0
    }

    /// Get the physical address
    pub fn phys_addr(&self) -> u64 {
        self.0 & pte_flags::ADDR_MASK
    }

    /// Set the physical address
    pub fn set_phys_addr(&mut self, addr: u64) {
        self.0 = (self.0 & !pte_flags::ADDR_MASK) | (addr & pte_flags::ADDR_MASK);
    }

    /// Set a flag
    pub fn set_flag(&mut self, flag: u64) {
        self.0 |= flag;
    }

    /// Clear a flag
    pub fn clear_flag(&mut self, flag: u64) {
        self.0 &= !flag;
    }

    /// Clear the PTE
    pub fn clear(&mut self) {
        self.0 = 0;
    }

    /// Set present and physical address
    pub fn set_present(&mut self, phys_addr: u64, flags: u64) {
        self.0 = (phys_addr & pte_flags::ADDR_MASK) | flags | pte_flags::PRESENT;
    }
}

impl Default for HardwarePte {
    fn default() -> Self {
        Self::empty()
    }
}

/// Software PTE (MMPTE) - NT's extended PTE format
///
/// This can represent various states:
/// - Valid: maps a physical page
/// - Transition: page is being paged in/out
/// - Prototype: points to a prototype PTE
/// - Demand Zero: allocate zero page on access
/// - Page File: page is in the page file
#[derive(Clone, Copy)]
#[repr(C)]
pub union MmPte {
    /// Hardware format (when valid)
    pub hard: HardwarePte,
    /// Raw u64 value
    pub raw: u64,
    /// Software fields
    pub soft: SoftwarePte,
}

impl MmPte {
    pub const fn empty() -> Self {
        Self { raw: 0 }
    }

    pub const fn from_raw(raw: u64) -> Self {
        Self { raw }
    }

    /// Check if this is a valid (present) PTE
    pub fn is_valid(&self) -> bool {
        unsafe { self.hard.is_present() }
    }

    /// Get the physical address (only valid if present)
    pub fn phys_addr(&self) -> u64 {
        unsafe { self.hard.phys_addr() }
    }
}

impl Default for MmPte {
    fn default() -> Self {
        Self::empty()
    }
}

/// Software PTE fields (for non-present pages)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SoftwarePte {
    /// Bit 0: Always 0 (not present)
    /// Bits 1-4: Page file index (if paged out)
    /// Bit 5: Prototype
    /// Bit 6: Transition
    /// Bit 7: Demand zero
    /// Bits 8-11: Protection
    /// Bits 12-51: Page file offset or prototype PTE address
    pub value: u64,
}

impl SoftwarePte {
    /// Check if this is a prototype PTE
    pub fn is_prototype(&self) -> bool {
        (self.value & (1 << 5)) != 0
    }

    /// Check if this is a transition PTE
    pub fn is_transition(&self) -> bool {
        (self.value & (1 << 6)) != 0
    }

    /// Check if this is a demand-zero PTE
    pub fn is_demand_zero(&self) -> bool {
        (self.value & (1 << 7)) != 0
    }

    /// Get the page file index
    pub fn page_file_index(&self) -> u8 {
        ((self.value >> 1) & 0xF) as u8
    }

    /// Get the protection
    pub fn protection(&self) -> u8 {
        ((self.value >> 8) & 0xF) as u8
    }
}

/// Page Table (array of 512 PTEs)
#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [HardwarePte; ENTRIES_PER_TABLE],
}

impl PageTable {
    pub const fn new() -> Self {
        Self {
            entries: [HardwarePte::empty(); ENTRIES_PER_TABLE],
        }
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.clear();
        }
    }

    /// Get an entry
    pub fn get(&self, index: usize) -> Option<&HardwarePte> {
        self.entries.get(index)
    }

    /// Get a mutable entry
    pub fn get_mut(&mut self, index: usize) -> Option<&mut HardwarePte> {
        self.entries.get_mut(index)
    }

    /// Get the physical address of this table
    pub fn phys_addr(&self) -> u64 {
        self as *const _ as u64
    }
}

impl Default for PageTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Virtual Address Manipulation
// ============================================================================

/// Extract PML4 index from virtual address
pub fn pml4_index(virt_addr: u64) -> usize {
    ((virt_addr >> 39) & 0x1FF) as usize
}

/// Extract PDPT index from virtual address
pub fn pdpt_index(virt_addr: u64) -> usize {
    ((virt_addr >> 30) & 0x1FF) as usize
}

/// Extract PD index from virtual address
pub fn pd_index(virt_addr: u64) -> usize {
    ((virt_addr >> 21) & 0x1FF) as usize
}

/// Extract PT index from virtual address
pub fn pt_index(virt_addr: u64) -> usize {
    ((virt_addr >> 12) & 0x1FF) as usize
}

/// Extract page offset from virtual address
pub fn page_offset(virt_addr: u64) -> usize {
    (virt_addr & 0xFFF) as usize
}

/// Check if address is canonical (valid 48-bit address)
pub fn is_canonical(virt_addr: u64) -> bool {
    let top_bits = virt_addr >> 47;
    top_bits == 0 || top_bits == 0x1FFFF
}

/// Check if address is in kernel space
pub fn is_kernel_address(virt_addr: u64) -> bool {
    virt_addr >= 0xFFFF_8000_0000_0000
}

/// Check if address is in user space
pub fn is_user_address(virt_addr: u64) -> bool {
    virt_addr < 0x0000_8000_0000_0000
}

// ============================================================================
// Page Table Walking
// ============================================================================

/// Walk the page tables and return the PTE for a virtual address
///
/// # Safety
/// The PML4 physical address must be valid.
pub unsafe fn mm_get_pte(pml4_phys: u64, virt_addr: u64) -> Option<*mut HardwarePte> {
    if !is_canonical(virt_addr) {
        return None;
    }

    // PML4
    let pml4 = pml4_phys as *mut PageTable;
    let pml4e = &mut (*pml4).entries[pml4_index(virt_addr)];
    if !pml4e.is_present() {
        return None;
    }

    // PDPT
    let pdpt = pml4e.phys_addr() as *mut PageTable;
    let pdpte = &mut (*pdpt).entries[pdpt_index(virt_addr)];
    if !pdpte.is_present() {
        return None;
    }
    if pdpte.is_huge() {
        // 1GB page
        return Some(pdpte as *mut HardwarePte);
    }

    // PD
    let pd = pdpte.phys_addr() as *mut PageTable;
    let pde = &mut (*pd).entries[pd_index(virt_addr)];
    if !pde.is_present() {
        return None;
    }
    if pde.is_huge() {
        // 2MB page
        return Some(pde as *mut HardwarePte);
    }

    // PT
    let pt = pde.phys_addr() as *mut PageTable;
    let pte = &mut (*pt).entries[pt_index(virt_addr)];
    Some(pte as *mut HardwarePte)
}

/// Translate a virtual address to physical address
pub unsafe fn mm_virtual_to_physical(pml4_phys: u64, virt_addr: u64) -> Option<u64> {
    let pte = mm_get_pte(pml4_phys, virt_addr)?;
    if !(*pte).is_present() {
        return None;
    }

    let page_phys = (*pte).phys_addr();
    let offset = page_offset(virt_addr) as u64;
    Some(page_phys + offset)
}

/// Invalidate TLB entry for a virtual address (local CPU only)
///
/// This only invalidates the TLB on the current CPU. For SMP systems,
/// use mm_invalidate_page() which performs TLB shootdown across all CPUs.
#[inline]
pub fn mm_invalidate_page_local(virt_addr: u64) {
    unsafe {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) virt_addr,
            options(nostack, preserves_flags)
        );
    }
}

/// Flush the entire TLB (reload CR3) on local CPU only
///
/// This only flushes the TLB on the current CPU. For SMP systems,
/// use mm_flush_tlb() which performs TLB shootdown across all CPUs.
#[inline]
pub fn mm_flush_tlb_local() {
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

/// Invalidate TLB entry for a virtual address (all CPUs)
///
/// In SMP systems, this performs TLB shootdown across all CPUs.
/// In single-CPU systems, this is equivalent to mm_invalidate_page_local().
#[inline]
pub fn mm_invalidate_page(virt_addr: u64) {
    // Forward to TLB shootdown module which handles both single and multi-CPU cases
    super::tlb::tlb_shootdown_single_page(virt_addr);
}

/// Flush the entire TLB (all CPUs)
///
/// In SMP systems, this performs TLB shootdown across all CPUs.
/// In single-CPU systems, this is equivalent to mm_flush_tlb_local().
#[inline]
pub fn mm_flush_tlb() {
    // Forward to TLB shootdown module which handles both single and multi-CPU cases
    super::tlb::tlb_shootdown_all();
}

/// Get current CR3 value
#[inline]
pub fn mm_get_cr3() -> u64 {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
    }
    cr3
}

/// Set CR3 value
#[inline]
pub unsafe fn mm_set_cr3(cr3: u64) {
    core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
}

/// Initialize PTE subsystem
pub fn init() {
    crate::serial_println!("[MM] PTE subsystem initialized");
}
