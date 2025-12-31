//! Memory Descriptor List (MDL) Support
//!
//! MDLs describe a set of physical pages that back a virtual memory buffer.
//! They are used for:
//!
//! - **Direct I/O**: DMA transfers to/from user buffers
//! - **Locked Pages**: Preventing page-out during I/O
//! - **Scatter/Gather**: Non-contiguous physical pages
//!
//! # Architecture
//!
//! An MDL contains a fixed header followed by an array of PFNs (page frame numbers).
//! The PFN array immediately follows the MDL structure in memory.
//!
//! ```text
//! ┌──────────────────────┐
//! │ MDL Header           │
//! │  - Next              │
//! │  - Size              │
//! │  - MdlFlags          │
//! │  - Process           │
//! │  - MappedSystemVa    │
//! │  - StartVa           │
//! │  - ByteCount         │
//! │  - ByteOffset        │
//! ├──────────────────────┤
//! │ PFN[0]               │
//! │ PFN[1]               │
//! │ ...                  │
//! │ PFN[n]               │
//! └──────────────────────┘
//! ```
//!
//! # Key Functions
//!
//! - `IoAllocateMdl`: Allocate an MDL for a buffer
//! - `IoBuildPartialMdl`: Build partial MDL from existing
//! - `MmProbeAndLockPages`: Lock pages and fill PFN array
//! - `MmUnlockPages`: Unlock pages
//! - `MmMapLockedPages`: Map into system address space
//! - `MmUnmapLockedPages`: Unmap from system space
//!
//! Based on Windows Server 2003 base/ntos/mm/ and base/ntos/inc/ntosdef.h

extern crate alloc;

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use alloc::boxed::Box;
use alloc::vec::Vec;
use spin::Mutex;

use crate::mm::{PAGE_SIZE, PAGE_SHIFT};

// ============================================================================
// MDL Flags
// ============================================================================

/// MDL has been mapped to system virtual address space
pub const MDL_MAPPED_TO_SYSTEM_VA: u16 = 0x0001;
/// Pages are locked in memory
pub const MDL_PAGES_LOCKED: u16 = 0x0002;
/// Source buffer is in nonpaged pool
pub const MDL_SOURCE_IS_NONPAGED_POOL: u16 = 0x0004;
/// MDL was allocated with fixed size
pub const MDL_ALLOCATED_FIXED_SIZE: u16 = 0x0008;
/// This is a partial MDL
pub const MDL_PARTIAL: u16 = 0x0010;
/// Partial MDL has been mapped
pub const MDL_PARTIAL_HAS_BEEN_MAPPED: u16 = 0x0020;
/// Pages read for I/O
pub const MDL_IO_PAGE_READ: u16 = 0x0040;
/// This is a write operation
pub const MDL_WRITE_OPERATION: u16 = 0x0080;
/// Parent MDL's system VA used
pub const MDL_PARENT_MAPPED_SYSTEM_VA: u16 = 0x0100;
/// Free extra PTEs on unmap
pub const MDL_FREE_EXTRA_PTES: u16 = 0x0200;
/// Describes AWE pages
pub const MDL_DESCRIBES_AWE: u16 = 0x0400;
/// Pages are in I/O space
pub const MDL_IO_SPACE: u16 = 0x0800;
/// Contains network header
pub const MDL_NETWORK_HEADER: u16 = 0x1000;
/// Mapping can fail (returns NULL)
pub const MDL_MAPPING_CAN_FAIL: u16 = 0x2000;
/// Allocation must succeed
pub const MDL_ALLOCATED_MUST_SUCCEED: u16 = 0x4000;
/// MDL is from a pool allocation
pub const MDL_INTERNAL: u16 = 0x8000;

/// Flags that affect mapping behavior
pub const MDL_MAPPING_FLAGS: u16 = MDL_MAPPED_TO_SYSTEM_VA
    | MDL_PAGES_LOCKED
    | MDL_SOURCE_IS_NONPAGED_POOL
    | MDL_PARTIAL_HAS_BEEN_MAPPED
    | MDL_PARENT_MAPPED_SYSTEM_VA
    | MDL_IO_SPACE;

// ============================================================================
// Lock Operation
// ============================================================================

/// Lock operation type for MmProbeAndLockPages
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockOperation {
    /// For read access
    IoReadAccess = 0,
    /// For write access
    IoWriteAccess = 1,
    /// For modify access (read + write)
    IoModifyAccess = 2,
}

/// Memory caching type for mapping
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryCachingType {
    /// Use default caching
    MmNonCached = 0,
    /// Cache enabled
    MmCached = 1,
    /// Write-combined
    MmWriteCombined = 2,
    /// Hardware coherent
    MmHardwareCoherentCached = 3,
    /// Non-cached, no write-combine
    MmNonCachedUnordered = 4,
    /// Use PTE caching attributes
    MmFrameBufferCached = 5,
}

// ============================================================================
// MDL Structure
// ============================================================================

/// Memory Descriptor List
///
/// Describes a buffer in terms of its physical pages.
/// The PFN array follows immediately after this structure.
#[repr(C)]
#[derive(Debug)]
pub struct Mdl {
    /// Next MDL in chain (for MDL chains)
    pub next: *mut Mdl,
    /// Total size of MDL including PFN array
    pub size: i16,
    /// MDL flags
    pub mdl_flags: i16,
    /// Owning process (NULL for kernel)
    pub process: usize,
    /// Mapped system virtual address
    pub mapped_system_va: usize,
    /// Start virtual address (page-aligned)
    pub start_va: usize,
    /// Number of bytes described
    pub byte_count: u32,
    /// Byte offset within first page
    pub byte_offset: u32,
}

impl Mdl {
    /// Create a new MDL (header only, caller must allocate PFN space)
    pub const fn new() -> Self {
        Self {
            next: ptr::null_mut(),
            size: core::mem::size_of::<Mdl>() as i16,
            mdl_flags: 0,
            process: 0,
            mapped_system_va: 0,
            start_va: 0,
            byte_count: 0,
            byte_offset: 0,
        }
    }

    /// Get pointer to PFN array (immediately after MDL header)
    ///
    /// # Safety
    /// The MDL must have been properly allocated with space for PFNs.
    pub unsafe fn get_pfn_array(&self) -> *mut usize {
        let mdl_ptr = self as *const Mdl as *mut u8;
        mdl_ptr.add(core::mem::size_of::<Mdl>()) as *mut usize
    }

    /// Get number of pages this MDL describes
    pub fn page_count(&self) -> usize {
        if self.byte_count == 0 {
            return 0;
        }
        let start_offset = self.byte_offset as usize;
        let total_bytes = start_offset + self.byte_count as usize;
        (total_bytes + PAGE_SIZE - 1) / PAGE_SIZE
    }

    /// Check if pages are locked
    pub fn is_pages_locked(&self) -> bool {
        (self.mdl_flags & MDL_PAGES_LOCKED as i16) != 0
    }

    /// Check if MDL is mapped to system VA
    pub fn is_mapped(&self) -> bool {
        (self.mdl_flags & MDL_MAPPED_TO_SYSTEM_VA as i16) != 0
    }

    /// Check if this is a partial MDL
    pub fn is_partial(&self) -> bool {
        (self.mdl_flags & MDL_PARTIAL as i16) != 0
    }

    /// Get the virtual address of the buffer
    pub fn get_virtual_address(&self) -> usize {
        self.start_va + self.byte_offset as usize
    }

    /// Get the mapped system virtual address (if mapped)
    pub fn get_system_address(&self) -> Option<usize> {
        if self.is_mapped() && self.mapped_system_va != 0 {
            Some(self.mapped_system_va + self.byte_offset as usize)
        } else {
            None
        }
    }
}

// ============================================================================
// MDL Pool / Allocation
// ============================================================================

/// Maximum number of MDLs we can track
const MAX_MDLS: usize = 256;

/// MDL pool entry
struct MdlPoolEntry {
    /// The MDL data (header + PFN array space)
    data: [u8; 256], // Enough for header + ~28 pages
    /// Is this entry in use?
    in_use: bool,
}

impl MdlPoolEntry {
    const fn new() -> Self {
        Self {
            data: [0; 256],
            in_use: false,
        }
    }
}

/// Global MDL pool
static MDL_POOL: Mutex<[MdlPoolEntry; MAX_MDLS]> = {
    const INIT: MdlPoolEntry = MdlPoolEntry::new();
    Mutex::new([INIT; MAX_MDLS])
};

/// MDL statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct MdlStats {
    /// Total MDLs allocated
    pub allocated: u32,
    /// Total MDLs freed
    pub freed: u32,
    /// Current MDLs in use
    pub in_use: u32,
    /// Peak MDL usage
    pub peak_usage: u32,
    /// Pages locked via MDLs
    pub pages_locked: u64,
    /// Pages unlocked
    pub pages_unlocked: u64,
    /// System mappings created
    pub system_mappings: u32,
    /// System mappings removed
    pub system_unmappings: u32,
}

static MDL_STATS: Mutex<MdlStats> = Mutex::new(MdlStats {
    allocated: 0,
    freed: 0,
    in_use: 0,
    peak_usage: 0,
    pages_locked: 0,
    pages_unlocked: 0,
    system_mappings: 0,
    system_unmappings: 0,
});

/// Get MDL statistics
pub fn get_mdl_stats() -> MdlStats {
    *MDL_STATS.lock()
}

// ============================================================================
// MDL Functions (IoAllocateMdl, etc.)
// ============================================================================

/// Calculate the size needed for an MDL describing the given buffer
///
/// # Arguments
/// * `virtual_address` - Starting virtual address
/// * `length` - Length in bytes
///
/// # Returns
/// Size in bytes needed for MDL header + PFN array
pub fn mm_size_of_mdl(virtual_address: usize, length: u32) -> usize {
    if length == 0 {
        return core::mem::size_of::<Mdl>();
    }

    let byte_offset = virtual_address & (PAGE_SIZE - 1);
    let total_bytes = byte_offset + length as usize;
    let page_count = (total_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    core::mem::size_of::<Mdl>() + page_count * core::mem::size_of::<usize>()
}

/// Allocate an MDL for the specified buffer
///
/// # Arguments
/// * `virtual_address` - Starting virtual address
/// * `length` - Length in bytes
/// * `secondary_buffer` - If true, allocate for secondary buffer
/// * `charge_quota` - If true, charge quota for allocation
/// * `irp` - Optional IRP to attach MDL to
///
/// # Returns
/// Pointer to allocated MDL, or null on failure
pub fn io_allocate_mdl(
    virtual_address: usize,
    length: u32,
    _secondary_buffer: bool,
    _charge_quota: bool,
    _irp: usize,
) -> *mut Mdl {
    let size_needed = mm_size_of_mdl(virtual_address, length);

    // Find a free entry in the pool
    let mut pool = MDL_POOL.lock();
    for entry in pool.iter_mut() {
        if !entry.in_use && entry.data.len() >= size_needed {
            // Zero the entry
            entry.data.iter_mut().for_each(|b| *b = 0);
            entry.in_use = true;

            // Initialize the MDL
            let mdl = entry.data.as_mut_ptr() as *mut Mdl;
            unsafe {
                (*mdl).next = ptr::null_mut();
                (*mdl).size = size_needed as i16;
                (*mdl).mdl_flags = 0;
                (*mdl).process = 0;
                (*mdl).mapped_system_va = 0;
                (*mdl).start_va = virtual_address & !(PAGE_SIZE - 1);
                (*mdl).byte_count = length;
                (*mdl).byte_offset = (virtual_address & (PAGE_SIZE - 1)) as u32;
            }

            // Update stats
            let mut stats = MDL_STATS.lock();
            stats.allocated += 1;
            stats.in_use += 1;
            if stats.in_use > stats.peak_usage {
                stats.peak_usage = stats.in_use;
            }

            return mdl;
        }
    }

    ptr::null_mut()
}

/// Free an MDL
///
/// # Arguments
/// * `mdl` - MDL to free
///
/// # Safety
/// The MDL must have been allocated by io_allocate_mdl and not already freed.
/// Pages must be unlocked and unmapped before freeing.
pub unsafe fn io_free_mdl(mdl: *mut Mdl) {
    if mdl.is_null() {
        return;
    }

    // Verify MDL is not still locked or mapped
    if (*mdl).is_pages_locked() || (*mdl).is_mapped() {
        crate::serial_println!("[MDL] Warning: Freeing MDL with locked/mapped pages");
    }

    // Find in pool and mark as free
    let mut pool = MDL_POOL.lock();
    for entry in pool.iter_mut() {
        let entry_mdl = entry.data.as_ptr() as *const Mdl;
        if entry_mdl == mdl && entry.in_use {
            entry.in_use = false;

            let mut stats = MDL_STATS.lock();
            stats.freed += 1;
            stats.in_use = stats.in_use.saturating_sub(1);

            return;
        }
    }

    crate::serial_println!("[MDL] Warning: Tried to free unknown MDL {:p}", mdl);
}

/// Initialize an MDL (MmInitializeMdl equivalent)
///
/// # Arguments
/// * `mdl` - Pointer to MDL to initialize
/// * `base_va` - Base virtual address of buffer
/// * `length` - Length in bytes
///
/// # Safety
/// The MDL pointer must be valid and have enough space for the PFN array.
pub unsafe fn mm_initialize_mdl(mdl: *mut Mdl, base_va: usize, length: usize) {
    if mdl.is_null() {
        return;
    }

    let page_count = if length == 0 {
        0
    } else {
        let byte_offset = base_va & (PAGE_SIZE - 1);
        (byte_offset + length + PAGE_SIZE - 1) / PAGE_SIZE
    };

    let size = core::mem::size_of::<Mdl>() + page_count * core::mem::size_of::<usize>();

    (*mdl).next = ptr::null_mut();
    (*mdl).size = size as i16;
    (*mdl).mdl_flags = 0;
    (*mdl).process = 0;
    (*mdl).mapped_system_va = 0;
    (*mdl).start_va = base_va & !(PAGE_SIZE - 1);
    (*mdl).byte_count = length as u32;
    (*mdl).byte_offset = (base_va & (PAGE_SIZE - 1)) as u32;
}

/// Probe and lock pages described by an MDL
///
/// # Arguments
/// * `mdl` - MDL describing the buffer
/// * `access_mode` - Kernel or user mode
/// * `operation` - Read, write, or modify
///
/// # Safety
/// MDL must be properly initialized.
///
/// # Note
/// In this implementation, we simulate locking by filling the PFN array
/// with the physical addresses of the pages.
pub unsafe fn mm_probe_and_lock_pages(
    mdl: *mut Mdl,
    _access_mode: u32, // KernelMode = 0, UserMode = 1
    operation: LockOperation,
) -> i32 {
    if mdl.is_null() {
        return -1; // STATUS_INVALID_PARAMETER
    }

    // Already locked?
    if (*mdl).is_pages_locked() {
        return 0; // Already done
    }

    let page_count = (*mdl).page_count();
    if page_count == 0 {
        (*mdl).mdl_flags |= MDL_PAGES_LOCKED as i16;
        return 0;
    }

    // Get the PFN array
    let pfn_array = (*mdl).get_pfn_array();

    // For each page, get its physical address
    // In a real implementation, this would:
    // 1. Probe the virtual address for access
    // 2. Lock the page in memory (increment reference count)
    // 3. Get the physical page frame number

    let start_va = (*mdl).start_va;

    for i in 0..page_count {
        let va = start_va + i * PAGE_SIZE;
        // Simulate getting PFN - in reality would use page tables
        let pfn = va >> PAGE_SHIFT; // Simplified - assumes identity mapping
        *pfn_array.add(i) = pfn;
    }

    // Mark as locked
    (*mdl).mdl_flags |= MDL_PAGES_LOCKED as i16;

    if operation == LockOperation::IoWriteAccess || operation == LockOperation::IoModifyAccess {
        (*mdl).mdl_flags |= MDL_WRITE_OPERATION as i16;
    }

    // Update stats
    let mut stats = MDL_STATS.lock();
    stats.pages_locked += page_count as u64;

    0 // STATUS_SUCCESS
}

/// Unlock pages described by an MDL
///
/// # Arguments
/// * `mdl` - MDL with locked pages
///
/// # Safety
/// MDL must have been locked with mm_probe_and_lock_pages.
pub unsafe fn mm_unlock_pages(mdl: *mut Mdl) {
    if mdl.is_null() {
        return;
    }

    if !(*mdl).is_pages_locked() {
        return; // Not locked
    }

    let page_count = (*mdl).page_count();

    // In a real implementation, this would decrement reference counts
    // and potentially allow pages to be paged out

    // Clear flags
    (*mdl).mdl_flags &= !(MDL_PAGES_LOCKED as i16);
    (*mdl).mdl_flags &= !(MDL_WRITE_OPERATION as i16);

    // Update stats
    let mut stats = MDL_STATS.lock();
    stats.pages_unlocked += page_count as u64;
}

/// Map locked pages into system address space
///
/// # Arguments
/// * `mdl` - MDL with locked pages
/// * `access_mode` - Kernel or user mode
/// * `cache_type` - Memory caching type
///
/// # Returns
/// System virtual address, or 0 on failure
///
/// # Safety
/// MDL must have locked pages.
pub unsafe fn mm_map_locked_pages(
    mdl: *mut Mdl,
    _access_mode: u32,
    _cache_type: MemoryCachingType,
) -> usize {
    if mdl.is_null() {
        return 0;
    }

    if !(*mdl).is_pages_locked() {
        crate::serial_println!("[MDL] Cannot map: pages not locked");
        return 0;
    }

    if (*mdl).is_mapped() {
        // Already mapped, return existing address
        return (*mdl).mapped_system_va + (*mdl).byte_offset as usize;
    }

    // In a real implementation, this would:
    // 1. Allocate system PTEs
    // 2. Map the physical pages
    // 3. Return the system virtual address

    // For now, we simulate by using the original virtual address
    // (works if we have identity mapping or the address is already kernel)
    let system_va = (*mdl).start_va;

    (*mdl).mapped_system_va = system_va;
    (*mdl).mdl_flags |= MDL_MAPPED_TO_SYSTEM_VA as i16;

    // Update stats
    let mut stats = MDL_STATS.lock();
    stats.system_mappings += 1;

    system_va + (*mdl).byte_offset as usize
}

/// Unmap locked pages from system address space
///
/// # Arguments
/// * `mdl` - MDL to unmap
/// * `base_address` - System VA that was returned from MmMapLockedPages
///
/// # Safety
/// Must be called with the same address returned from mm_map_locked_pages.
pub unsafe fn mm_unmap_locked_pages(mdl: *mut Mdl, _base_address: usize) {
    if mdl.is_null() {
        return;
    }

    if !(*mdl).is_mapped() {
        return; // Not mapped
    }

    // In a real implementation, this would free the system PTEs

    (*mdl).mapped_system_va = 0;
    (*mdl).mdl_flags &= !(MDL_MAPPED_TO_SYSTEM_VA as i16);

    // Update stats
    let mut stats = MDL_STATS.lock();
    stats.system_unmappings += 1;
}

/// Build a partial MDL from an existing MDL
///
/// # Arguments
/// * `source_mdl` - Source MDL
/// * `target_mdl` - Target MDL (must be pre-allocated)
/// * `virtual_address` - Starting VA within source buffer
/// * `length` - Length in bytes
///
/// # Safety
/// Both MDLs must be valid. Source must be locked.
pub unsafe fn io_build_partial_mdl(
    source_mdl: *mut Mdl,
    target_mdl: *mut Mdl,
    virtual_address: usize,
    length: u32,
) {
    if source_mdl.is_null() || target_mdl.is_null() {
        return;
    }

    // Initialize target MDL
    (*target_mdl).next = ptr::null_mut();
    (*target_mdl).mdl_flags = MDL_PARTIAL as i16;
    (*target_mdl).process = (*source_mdl).process;
    (*target_mdl).mapped_system_va = 0;
    (*target_mdl).start_va = virtual_address & !(PAGE_SIZE - 1);
    (*target_mdl).byte_count = length;
    (*target_mdl).byte_offset = (virtual_address & (PAGE_SIZE - 1)) as u32;

    // Copy PFNs from source
    let source_pfn = (*source_mdl).get_pfn_array();
    let target_pfn = (*target_mdl).get_pfn_array();

    // Calculate which PFNs to copy
    let source_start_va = (*source_mdl).start_va;
    let offset_pages = (virtual_address - source_start_va) / PAGE_SIZE;
    let page_count = (*target_mdl).page_count();

    for i in 0..page_count {
        *target_pfn.add(i) = *source_pfn.add(offset_pages + i);
    }

    // Inherit lock status
    if (*source_mdl).is_pages_locked() {
        (*target_mdl).mdl_flags |= MDL_PAGES_LOCKED as i16;
    }
}

/// Get the byte count from an MDL
pub fn mm_get_mdl_byte_count(mdl: *const Mdl) -> u32 {
    if mdl.is_null() {
        return 0;
    }
    unsafe { (*mdl).byte_count }
}

/// Get the byte offset from an MDL
pub fn mm_get_mdl_byte_offset(mdl: *const Mdl) -> u32 {
    if mdl.is_null() {
        return 0;
    }
    unsafe { (*mdl).byte_offset }
}

/// Get the virtual address from an MDL
pub fn mm_get_mdl_virtual_address(mdl: *const Mdl) -> usize {
    if mdl.is_null() {
        return 0;
    }
    unsafe { (*mdl).start_va + (*mdl).byte_offset as usize }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize MDL subsystem
pub fn init() {
    crate::serial_println!("[MM] MDL subsystem initialized");
    crate::serial_println!("[MM]   MDL pool size: {} entries", MAX_MDLS);
    crate::serial_println!("[MM]   MDL header size: {} bytes", core::mem::size_of::<Mdl>());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdl_size_calculation() {
        // Single page
        assert!(mm_size_of_mdl(0x1000, 0x1000) >= core::mem::size_of::<Mdl>() + 8);

        // Two pages (crossing boundary)
        assert!(mm_size_of_mdl(0x800, 0x1000) >= core::mem::size_of::<Mdl>() + 16);

        // Zero length
        assert_eq!(mm_size_of_mdl(0, 0), core::mem::size_of::<Mdl>());
    }
}
