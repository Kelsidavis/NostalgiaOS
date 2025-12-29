//! Address Space Management
//!
//! Each process has its own address space consisting of:
//! - Page tables (PML4, PDPT, PD, PT)
//! - VAD tree tracking virtual allocations
//! - Working set (resident pages)
//!
//! # Address Space Layout (x86_64)
//!
//! ```text
//! 0x0000_0000_0000_0000 - 0x0000_7FFF_FFFF_FFFF: User space (128TB)
//! 0x0000_8000_0000_0000 - 0xFFFF_7FFF_FFFF_FFFF: Non-canonical hole
//! 0xFFFF_8000_0000_0000 - 0xFFFF_FFFF_FFFF_FFFF: Kernel space (128TB)
//! ```
//!
//! # Key Structures
//! - `MmAddressSpace`: Per-process address space
//! - `MmWorkingSet`: Resident page tracking

use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;
use super::vad::MmVadRoot;
use super::pte::PageTable;

/// Maximum address spaces (processes)
pub const MAX_ADDRESS_SPACES: usize = 64;

/// User space start address
pub const USER_SPACE_START: u64 = 0x0000_0000_0001_0000; // 64KB
/// User space end address
pub const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_FFFF;   // 128TB - 1
/// Kernel space start address
pub const KERNEL_SPACE_START: u64 = 0xFFFF_8000_0000_0000;
/// Kernel space end address
pub const KERNEL_SPACE_END: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// Default user stack size (1MB)
pub const DEFAULT_STACK_SIZE: u64 = 1024 * 1024;
/// Default user heap size (16MB)
pub const DEFAULT_HEAP_SIZE: u64 = 16 * 1024 * 1024;

/// Address space flags
pub mod address_space_flags {
    /// Address space is active
    pub const AS_ACTIVE: u32 = 0x0001;
    /// Address space is being deleted
    pub const AS_DELETING: u32 = 0x0002;
    /// Address space owns its page tables
    pub const AS_OWNS_PAGE_TABLES: u32 = 0x0004;
    /// System (kernel) address space
    pub const AS_SYSTEM: u32 = 0x0008;
}

/// Working set entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WsleEntry {
    /// Virtual address of the page
    pub virtual_address: u64,
    /// Age (for page replacement)
    pub age: u8,
    /// Flags
    pub flags: u8,
    /// Reserved
    _reserved: u16,
}

impl WsleEntry {
    pub const fn empty() -> Self {
        Self {
            virtual_address: 0,
            age: 0,
            flags: 0,
            _reserved: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.virtual_address != 0
    }
}

/// Working set entry flags
pub mod wsle_flags {
    /// Entry is valid
    pub const VALID: u8 = 0x01;
    /// Entry is locked (cannot be trimmed)
    pub const LOCKED: u8 = 0x02;
    /// Entry was recently accessed
    pub const ACCESSED: u8 = 0x04;
}

/// Maximum working set list entries per address space
const MAX_WSLE: usize = 256;

/// Working set
#[repr(C)]
pub struct MmWorkingSet {
    /// Working set list entries
    pub entries: [WsleEntry; MAX_WSLE],
    /// Current size (pages)
    pub current_size: u32,
    /// Peak size
    pub peak_size: u32,
    /// Minimum size
    pub minimum_size: u32,
    /// Maximum size
    pub maximum_size: u32,
    /// Hard fault count
    pub hard_fault_count: AtomicU32,
    /// Soft fault count
    pub soft_fault_count: AtomicU32,
}

impl MmWorkingSet {
    pub const fn new() -> Self {
        Self {
            entries: [WsleEntry::empty(); MAX_WSLE],
            current_size: 0,
            peak_size: 0,
            minimum_size: 10,   // Minimum 10 pages
            maximum_size: MAX_WSLE as u32,
            hard_fault_count: AtomicU32::new(0),
            soft_fault_count: AtomicU32::new(0),
        }
    }

    /// Add a page to the working set
    pub fn add_page(&mut self, virtual_address: u64) -> bool {
        if self.current_size >= self.maximum_size {
            return false;
        }

        // Find a free slot
        for entry in self.entries.iter_mut() {
            if !entry.is_valid() {
                entry.virtual_address = virtual_address & !0xFFF; // Page-align
                entry.age = 0;
                entry.flags = wsle_flags::VALID | wsle_flags::ACCESSED;
                self.current_size += 1;
                if self.current_size > self.peak_size {
                    self.peak_size = self.current_size;
                }
                return true;
            }
        }

        false
    }

    /// Remove a page from the working set
    pub fn remove_page(&mut self, virtual_address: u64) -> bool {
        let page_addr = virtual_address & !0xFFF;

        for entry in self.entries.iter_mut() {
            if entry.is_valid() && entry.virtual_address == page_addr {
                *entry = WsleEntry::empty();
                self.current_size = self.current_size.saturating_sub(1);
                return true;
            }
        }

        false
    }

    /// Find a page in the working set
    pub fn find_page(&self, virtual_address: u64) -> Option<&WsleEntry> {
        let page_addr = virtual_address & !0xFFF;

        self.entries.iter().find(|&entry| entry.is_valid() && entry.virtual_address == page_addr).map(|v| v as _)
    }

    /// Age all entries (for page replacement)
    pub fn age_entries(&mut self) {
        for entry in self.entries.iter_mut() {
            if entry.is_valid() && (entry.flags & wsle_flags::LOCKED) == 0 {
                entry.age = entry.age.saturating_add(1);
                entry.flags &= !wsle_flags::ACCESSED;
            }
        }
    }

    /// Find the oldest unlocked page (for trimming)
    pub fn find_oldest(&self) -> Option<u64> {
        let mut oldest_age = 0u8;
        let mut oldest_addr = None;

        for entry in self.entries.iter() {
            if entry.is_valid() && (entry.flags & wsle_flags::LOCKED) == 0
                && entry.age > oldest_age {
                    oldest_age = entry.age;
                    oldest_addr = Some(entry.virtual_address);
                }
        }

        oldest_addr
    }
}

impl Default for MmWorkingSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory Manager Address Space
///
/// Represents a process's virtual address space.
#[repr(C)]
pub struct MmAddressSpace {
    /// Physical address of PML4 table
    pub pml4_physical: u64,
    /// Virtual address of PML4 table
    pub pml4_virtual: *mut PageTable,

    /// VAD tree root
    pub vad_root: MmVadRoot,

    /// Working set
    pub working_set: MmWorkingSet,

    /// Address space flags
    pub flags: AtomicU32,

    /// Address space lock
    pub lock: SpinLock<()>,

    /// Virtual memory counters
    pub virtual_size: AtomicU64,
    pub peak_virtual_size: AtomicU64,
    pub private_usage: AtomicU64,

    /// Owning process (if any)
    pub process: *mut u8,

    /// Reference count
    pub ref_count: AtomicU32,
}

impl MmAddressSpace {
    pub const fn new() -> Self {
        Self {
            pml4_physical: 0,
            pml4_virtual: ptr::null_mut(),
            vad_root: MmVadRoot::new(),
            working_set: MmWorkingSet::new(),
            flags: AtomicU32::new(0),
            lock: SpinLock::new(()),
            virtual_size: AtomicU64::new(0),
            peak_virtual_size: AtomicU64::new(0),
            private_usage: AtomicU64::new(0),
            process: ptr::null_mut(),
            ref_count: AtomicU32::new(0),
        }
    }

    /// Check if address space is active
    pub fn is_active(&self) -> bool {
        (self.flags.load(Ordering::SeqCst) & address_space_flags::AS_ACTIVE) != 0
    }

    /// Check if this is the system address space
    pub fn is_system(&self) -> bool {
        (self.flags.load(Ordering::SeqCst) & address_space_flags::AS_SYSTEM) != 0
    }

    /// Add a reference
    pub fn add_ref(&self) -> u32 {
        self.ref_count.fetch_add(1, Ordering::SeqCst)
    }

    /// Release a reference
    pub fn release(&self) -> u32 {
        self.ref_count.fetch_sub(1, Ordering::SeqCst)
    }

    /// Get current virtual memory size
    pub fn virtual_size(&self) -> u64 {
        self.virtual_size.load(Ordering::SeqCst)
    }

    /// Update virtual memory size
    pub fn add_virtual_size(&self, size: u64) {
        let old = self.virtual_size.fetch_add(size, Ordering::SeqCst);
        let new = old + size;
        // Update peak if needed
        let mut peak = self.peak_virtual_size.load(Ordering::SeqCst);
        while new > peak {
            match self.peak_virtual_size.compare_exchange_weak(
                peak, new, Ordering::SeqCst, Ordering::SeqCst
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }
    }
}

impl Default for MmAddressSpace {
    fn default() -> Self {
        Self::new()
    }
}

// Safety: Address space uses atomics and spinlocks for synchronization
unsafe impl Sync for MmAddressSpace {}
unsafe impl Send for MmAddressSpace {}

// ============================================================================
// Address Space Pool
// ============================================================================

/// Address space pool
static mut ADDRESS_SPACE_POOL: [MmAddressSpace; MAX_ADDRESS_SPACES] = {
    const INIT: MmAddressSpace = MmAddressSpace::new();
    [INIT; MAX_ADDRESS_SPACES]
};

/// Address space bitmap
static mut ADDRESS_SPACE_BITMAP: u64 = 0;

/// Address space pool lock
static ADDRESS_SPACE_LOCK: SpinLock<()> = SpinLock::new(());

/// Free address space count
static FREE_ADDRESS_SPACES: AtomicU32 = AtomicU32::new(MAX_ADDRESS_SPACES as u32);

/// System address space (always index 0)
static mut SYSTEM_ADDRESS_SPACE_INDEX: usize = 0;

// ============================================================================
// Address Space Operations
// ============================================================================

/// Create a new address space
pub unsafe fn mm_create_address_space() -> Option<*mut MmAddressSpace> {
    let _guard = ADDRESS_SPACE_LOCK.lock();

    // Find a free slot
    if ADDRESS_SPACE_BITMAP == u64::MAX || FREE_ADDRESS_SPACES.load(Ordering::SeqCst) == 0 {
        return None;
    }

    let idx = (!ADDRESS_SPACE_BITMAP).trailing_zeros() as usize;
    if idx >= MAX_ADDRESS_SPACES {
        return None;
    }

    // Mark as allocated
    ADDRESS_SPACE_BITMAP |= 1u64 << idx;
    FREE_ADDRESS_SPACES.fetch_sub(1, Ordering::SeqCst);

    let aspace = &mut ADDRESS_SPACE_POOL[idx];

    // Initialize
    *aspace = MmAddressSpace::new();
    aspace.flags.store(address_space_flags::AS_ACTIVE, Ordering::SeqCst);
    aspace.ref_count.store(1, Ordering::SeqCst);

    // TODO: Allocate page tables
    // For now, we don't have physical page allocation working
    // aspace.pml4_physical = mm_allocate_page()? * PAGE_SIZE;

    Some(aspace as *mut MmAddressSpace)
}

/// Delete an address space
pub unsafe fn mm_delete_address_space(aspace: *mut MmAddressSpace) {
    if aspace.is_null() {
        return;
    }

    let _guard = ADDRESS_SPACE_LOCK.lock();

    // Find the index
    let base = ADDRESS_SPACE_POOL.as_ptr() as usize;
    let addr = aspace as usize;
    let idx = (addr - base) / core::mem::size_of::<MmAddressSpace>();

    if idx >= MAX_ADDRESS_SPACES {
        return;
    }

    let aspace_ref = &mut *aspace;

    // Don't delete if still referenced
    if aspace_ref.ref_count.load(Ordering::SeqCst) > 0 {
        return;
    }

    // Mark as deleting
    aspace_ref.flags.fetch_or(address_space_flags::AS_DELETING, Ordering::SeqCst);

    // TODO: Free all VADs and pages
    // TODO: Free page tables

    // Clear the address space
    *aspace_ref = MmAddressSpace::new();

    // Mark as free
    ADDRESS_SPACE_BITMAP &= !(1u64 << idx);
    FREE_ADDRESS_SPACES.fetch_add(1, Ordering::SeqCst);
}

/// Get the system address space
pub unsafe fn mm_get_system_address_space() -> *mut MmAddressSpace {
    &mut ADDRESS_SPACE_POOL[SYSTEM_ADDRESS_SPACE_INDEX] as *mut MmAddressSpace
}

/// Attach to an address space (set CR3)
pub unsafe fn mm_attach_address_space(aspace: *mut MmAddressSpace) {
    if aspace.is_null() {
        return;
    }

    let aspace_ref = &*aspace;

    if aspace_ref.pml4_physical != 0 {
        super::pte::mm_set_cr3(aspace_ref.pml4_physical);
    }
}

/// Detach from an address space (restore to system)
pub unsafe fn mm_detach_address_space() {
    let system = mm_get_system_address_space();
    mm_attach_address_space(system);
}

// ============================================================================
// Virtual Memory Operations
// ============================================================================

/// Allocate virtual memory in an address space
///
/// This is the core of NtAllocateVirtualMemory.
pub unsafe fn mm_allocate_virtual_memory(
    aspace: *mut MmAddressSpace,
    base_address: Option<u64>,
    size: u64,
    allocation_type: u32,
    protection: u32,
) -> Option<u64> {
    if aspace.is_null() {
        return None;
    }

    let aspace_ref = &mut *aspace;
    let _guard = aspace_ref.lock.lock();

    // Use VAD allocation
    let result = super::vad::mm_allocate_virtual_range(
        &mut aspace_ref.vad_root,
        base_address,
        size,
        allocation_type,
        protection,
        aspace_ref.process,
    );

    if result.is_some() {
        aspace_ref.add_virtual_size(size);
    }

    result
}

/// Free virtual memory in an address space
///
/// This is the core of NtFreeVirtualMemory.
pub unsafe fn mm_free_virtual_memory(
    aspace: *mut MmAddressSpace,
    base_address: u64,
    size: u64,
    free_type: u32,
) -> bool {
    if aspace.is_null() {
        return false;
    }

    let aspace_ref = &mut *aspace;
    let _guard = aspace_ref.lock.lock();

    let result = super::vad::mm_free_virtual_range(
        &mut aspace_ref.vad_root,
        base_address,
        size,
        free_type,
    );

    if result {
        aspace_ref.virtual_size.fetch_sub(size, Ordering::SeqCst);
    }

    result
}

/// Query virtual memory
pub unsafe fn mm_query_virtual_memory(
    aspace: *mut MmAddressSpace,
    base_address: u64,
) -> Option<MmMemoryInfo> {
    if aspace.is_null() {
        return None;
    }

    let aspace_ref = &*aspace;

    // Find the VAD
    let vad = super::vad::mm_find_vad(&aspace_ref.vad_root, base_address)?;
    let vad_ref = &*vad;

    Some(MmMemoryInfo {
        base_address: vad_ref.start_address(),
        allocation_base: vad_ref.start_address(),
        allocation_protect: vad_ref.protection,
        region_size: vad_ref.size(),
        state: if vad_ref.is_committed() {
            super::vad::allocation_type::MEM_COMMIT
        } else {
            super::vad::allocation_type::MEM_RESERVE
        },
        protect: vad_ref.protection,
        vad_type: vad_ref.vad_type as u32,
    })
}

/// Memory information structure
#[derive(Debug, Clone, Copy)]
pub struct MmMemoryInfo {
    pub base_address: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
    pub vad_type: u32,
}

// ============================================================================
// Page Fault Handling
// ============================================================================

/// Handle a page fault
///
/// Returns true if the fault was handled, false if it's a real fault.
pub unsafe fn mm_access_fault(
    aspace: *mut MmAddressSpace,
    fault_address: u64,
    is_write: bool,
    is_user: bool,
) -> bool {
    if aspace.is_null() {
        return false;
    }

    let aspace_ref = &mut *aspace;

    // Check if address is in user space
    let is_user_address = fault_address < KERNEL_SPACE_START;

    // User mode can't access kernel space
    if is_user && !is_user_address {
        return false;
    }

    // Find the VAD for this address
    let vad = match super::vad::mm_find_vad(&aspace_ref.vad_root, fault_address) {
        Some(v) => v,
        None => return false, // No VAD = invalid access
    };

    let vad_ref = &*vad;

    // Check protection
    if is_write {
        let can_write = (vad_ref.protection & super::vad::protection::PAGE_READWRITE) != 0
            || (vad_ref.protection & super::vad::protection::PAGE_EXECUTE_READWRITE) != 0;

        if !can_write && !vad_ref.is_copy_on_write() {
            return false;
        }
    }

    // For committed memory, we need to actually allocate the page
    if !vad_ref.is_committed() {
        return false; // Access to reserved memory is a fault
    }

    // Page-align the fault address
    let page_addr = fault_address & !0xFFF;

    // Check if page is already mapped (soft fault - just need TLB update)
    if aspace_ref.pml4_physical != 0 {
        if let Some(pte) = super::pte::mm_get_pte(aspace_ref.pml4_physical, page_addr) {
            if (*pte).is_present() {
                // Page is already mapped - this was a TLB miss (soft fault)
                aspace_ref.working_set.soft_fault_count.fetch_add(1, Ordering::Relaxed);
                super::pte::mm_invalidate_page(page_addr);
                return true;
            }
        }
    }

    // Hard fault - need to allocate a physical page
    aspace_ref.working_set.hard_fault_count.fetch_add(1, Ordering::Relaxed);

    // Allocate a physical page
    let pfn = match super::pfn::mm_allocate_zeroed_page() {
        Some(p) => p,
        None => {
            // Try to trim working set to free pages
            if let Some(victim_addr) = aspace_ref.working_set.find_oldest() {
                // Unmap the victim page
                if aspace_ref.pml4_physical != 0 {
                    if let Some(victim_phys) = super::pte::mm_unmap_page(
                        aspace_ref.pml4_physical,
                        victim_addr,
                    ) {
                        // Free the physical page
                        let victim_pfn = (victim_phys / super::pfn::PAGE_SIZE as u64) as usize;
                        super::pfn::mm_free_page(victim_pfn);
                        aspace_ref.working_set.remove_page(victim_addr);

                        // Try allocation again
                        match super::pfn::mm_allocate_zeroed_page() {
                            Some(p) => p,
                            None => return false, // Still no memory
                        }
                    } else {
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                return false; // No pages to trim and no memory
            }
        }
    };

    let phys_addr = (pfn * super::pfn::PAGE_SIZE) as u64;

    // Determine PTE flags from VAD protection
    let pte_flags = super::pte::protection_to_pte_flags(vad_ref.protection, is_user_address);

    // Map the page
    if aspace_ref.pml4_physical == 0 {
        // No page tables yet - use system address space
        let system_cr3 = super::pte::mm_get_cr3();
        if super::pte::mm_map_page(system_cr3, page_addr, phys_addr, pte_flags).is_err() {
            // Failed to map - free the page we allocated
            super::pfn::mm_free_page(pfn);
            return false;
        }
    } else {
        if super::pte::mm_map_page(aspace_ref.pml4_physical, page_addr, phys_addr, pte_flags).is_err() {
            // Failed to map - free the page we allocated
            super::pfn::mm_free_page(pfn);
            return false;
        }
    }

    // Add to working set
    if !aspace_ref.working_set.add_page(page_addr) {
        // Working set full - this shouldn't happen since we trimmed above
        // but handle gracefully
        crate::serial_println!("[MM] Warning: Working set full after page allocation");
    }

    // Update PFN entry with owning process
    let pfn_entry = super::pfn::mm_get_pfn(pfn);
    if let Some(pfn_ref) = pfn_entry {
        pfn_ref.owning_process = aspace_ref.process;
        pfn_ref.pte_address.store(page_addr, Ordering::SeqCst);
    }

    // Update private usage counter
    aspace_ref.private_usage.fetch_add(super::pfn::PAGE_SIZE as u64, Ordering::Relaxed);

    true
}

// ============================================================================
// Statistics
// ============================================================================

/// Get address space statistics
pub fn mm_get_address_space_stats() -> MmAddressSpaceStats {
    let free = FREE_ADDRESS_SPACES.load(Ordering::SeqCst);
    MmAddressSpaceStats {
        total: MAX_ADDRESS_SPACES as u32,
        free,
        allocated: MAX_ADDRESS_SPACES as u32 - free,
    }
}

/// Address space statistics
#[derive(Debug, Clone, Copy)]
pub struct MmAddressSpaceStats {
    pub total: u32,
    pub free: u32,
    pub allocated: u32,
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize address space management
pub unsafe fn init() {
    // Initialize system address space
    let system = &mut ADDRESS_SPACE_POOL[SYSTEM_ADDRESS_SPACE_INDEX];
    system.flags.store(
        address_space_flags::AS_ACTIVE | address_space_flags::AS_SYSTEM,
        Ordering::SeqCst
    );
    system.ref_count.store(1, Ordering::SeqCst);

    // Get current CR3 as system page table
    system.pml4_physical = super::pte::mm_get_cr3();

    // Mark system address space as allocated
    ADDRESS_SPACE_BITMAP |= 1;
    FREE_ADDRESS_SPACES.store(MAX_ADDRESS_SPACES as u32 - 1, Ordering::SeqCst);

    crate::serial_println!("[MM] Address space subsystem initialized");
    crate::serial_println!("[MM]   System PML4: {:#x}", system.pml4_physical);
    crate::serial_println!("[MM]   {} address spaces available", MAX_ADDRESS_SPACES - 1);
}

// ============================================================================
// Virtual Memory Protection
// ============================================================================

/// Change protection on a region of virtual memory
///
/// # Arguments
/// * `base_address` - Starting address of the region
/// * `size` - Size of the region in bytes
/// * `new_protect` - New protection flags
///
/// # Returns
/// Ok(old_protect) on success, Err on failure
pub unsafe fn mm_protect_virtual_memory(
    base_address: usize,
    size: usize,
    new_protect: u32,
) -> Result<u32, ()> {
    // Get current address space
    let aspace = mm_get_system_address_space();
    if aspace.is_null() {
        return Err(());
    }

    let aspace_ref = &mut *aspace;

    // Find the VAD for this address
    let vad = match super::vad::mm_find_vad(&aspace_ref.vad_root, base_address as u64) {
        Some(v) => v,
        None => return Err(()),
    };

    let vad_ref = &mut *vad;

    // Check that the requested region is within the VAD
    let vad_end = vad_ref.start_address() + vad_ref.size();
    if base_address as u64 + size as u64 > vad_end {
        return Err(());
    }

    // Save old protection
    let old_protect = vad_ref.protection;

    // Update protection
    vad_ref.protection = new_protect;

    // TODO: Update page table entries to reflect new protection

    Ok(old_protect)
}

/// Check if an address is in user space
#[inline]
pub fn is_user_address(addr: u64) -> bool {
    (USER_SPACE_START..=USER_SPACE_END).contains(&addr)
}

/// Check if an address range is valid user space
pub fn is_valid_user_range(addr: u64, size: usize) -> bool {
    if size == 0 {
        return true;
    }

    // Check for overflow
    let end = match addr.checked_add(size as u64) {
        Some(e) => e,
        None => return false,
    };

    // Check bounds
    addr >= USER_SPACE_START && end <= USER_SPACE_END + 1
}

/// Probe user memory for read access
/// Returns true if the memory range is accessible for reading
pub fn probe_for_read(addr: u64, size: usize) -> bool {
    if !is_valid_user_range(addr, size) {
        return false;
    }

    // In a full implementation, this would:
    // 1. Check if the pages are mapped
    // 2. Check if the pages have read permission
    // 3. Handle page faults if needed

    // For now, basic validation passes
    true
}

/// Probe user memory for write access
/// Returns true if the memory range is accessible for writing
pub fn probe_for_write(addr: u64, size: usize) -> bool {
    if !is_valid_user_range(addr, size) {
        return false;
    }

    // In a full implementation, this would:
    // 1. Check if the pages are mapped
    // 2. Check if the pages have write permission
    // 3. Handle copy-on-write if needed

    // For now, basic validation passes
    true
}

/// Copy data from user space to kernel space
/// Returns the number of bytes copied, or None if the address is invalid
pub fn copy_from_user(dest: &mut [u8], src_addr: u64) -> Option<usize> {
    let size = dest.len();

    if !probe_for_read(src_addr, size) {
        return None;
    }

    // Perform the copy
    unsafe {
        let src = src_addr as *const u8;
        core::ptr::copy_nonoverlapping(src, dest.as_mut_ptr(), size);
    }

    Some(size)
}

/// Copy data from kernel space to user space
/// Returns the number of bytes copied, or None if the address is invalid
pub fn copy_to_user(dest_addr: u64, src: &[u8]) -> Option<usize> {
    let size = src.len();

    if !probe_for_write(dest_addr, size) {
        return None;
    }

    // Perform the copy
    unsafe {
        let dest = dest_addr as *mut u8;
        core::ptr::copy_nonoverlapping(src.as_ptr(), dest, size);
    }

    Some(size)
}
