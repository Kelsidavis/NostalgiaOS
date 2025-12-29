//! Virtual Address Descriptor (VAD) Implementation
//!
//! VADs track virtual memory allocations within a process's address space.
//! In NT, VADs form an AVL tree for efficient O(log n) lookup.
//!
//! # VAD Types
//! - Private: Process-private memory (heap, stack)
//! - Mapped: Memory-mapped files
//! - Physical: Mapped physical memory
//!
//! # Memory Protection
//! - PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE
//! - PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE
//! - PAGE_GUARD, PAGE_NOCACHE, PAGE_WRITECOMBINE

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::ke::SpinLock;

/// Maximum number of VADs in the system (static allocation)
pub const MAX_VADS: usize = 256;

/// Page protection constants
pub mod protection {
    pub const PAGE_NOACCESS: u32 = 0x01;
    pub const PAGE_READONLY: u32 = 0x02;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_WRITECOPY: u32 = 0x08;
    pub const PAGE_EXECUTE: u32 = 0x10;
    pub const PAGE_EXECUTE_READ: u32 = 0x20;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
    pub const PAGE_GUARD: u32 = 0x100;
    pub const PAGE_NOCACHE: u32 = 0x200;
    pub const PAGE_WRITECOMBINE: u32 = 0x400;
}

/// Memory allocation type
pub mod allocation_type {
    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_DECOMMIT: u32 = 0x4000;
    pub const MEM_RELEASE: u32 = 0x8000;
    pub const MEM_FREE: u32 = 0x10000;
    pub const MEM_PRIVATE: u32 = 0x20000;
    pub const MEM_MAPPED: u32 = 0x40000;
    pub const MEM_RESET: u32 = 0x80000;
    pub const MEM_TOP_DOWN: u32 = 0x100000;
    pub const MEM_PHYSICAL: u32 = 0x400000;
    pub const MEM_LARGE_PAGES: u32 = 0x20000000;
}

/// VAD type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum MmVadType {
    /// Process-private memory (heap, stack)
    #[default]
    Private = 0,
    /// Memory-mapped file
    Mapped = 1,
    /// Mapped physical memory
    Physical = 2,
    /// Image (executable) mapping
    Image = 3,
    /// Large page allocation
    LargePage = 4,
    /// Rotate (AWE) memory
    Rotate = 5,
}


/// VAD flags
pub mod vad_flags {
    /// VAD is currently in use
    pub const VAD_IN_USE: u16 = 0x0001;
    /// Memory is committed (not just reserved)
    pub const VAD_COMMITTED: u16 = 0x0002;
    /// Copy-on-write
    pub const VAD_COPY_ON_WRITE: u16 = 0x0004;
    /// No cache
    pub const VAD_NO_CACHE: u16 = 0x0008;
    /// Write combine
    pub const VAD_WRITE_COMBINE: u16 = 0x0010;
    /// Memory is locked (cannot be paged)
    pub const VAD_LOCKED: u16 = 0x0020;
    /// Guard page
    pub const VAD_GUARD: u16 = 0x0040;
    /// Prototype PTEs
    pub const VAD_PROTOTYPE: u16 = 0x0080;
    /// Long VAD (has extended info)
    pub const VAD_LONG: u16 = 0x0100;
    /// Memory-mapped file
    pub const VAD_MAPPED_FILE: u16 = 0x0200;
}

/// Virtual Address Descriptor
///
/// Describes a contiguous range of virtual addresses within a process.
#[repr(C)]
pub struct MmVad {
    /// Starting virtual page number (VPN)
    pub starting_vpn: u64,
    /// Ending virtual page number (inclusive)
    pub ending_vpn: u64,

    /// Left child in AVL tree (index into VAD pool, or u32::MAX if none)
    pub left_child: u32,
    /// Right child in AVL tree
    pub right_child: u32,
    /// Parent node
    pub parent: u32,

    /// VAD type
    pub vad_type: MmVadType,
    /// Tree balance factor (-1, 0, +1)
    pub balance: i8,
    /// VAD flags
    pub flags: u16,

    /// Protection (PAGE_* constants)
    pub protection: u32,
    /// Allocation type (MEM_* constants)
    pub allocation_type: u32,

    /// Committed page count
    pub committed_pages: u32,
    /// Locked page count
    pub locked_pages: u32,

    /// For mapped files: file object pointer
    pub file_object: *mut u8,
    /// For mapped files: section offset
    pub section_offset: u64,

    /// Owning process
    pub process: *mut u8,

    /// Reserved for future use
    _reserved: [u64; 2],
}

impl MmVad {
    pub const fn new() -> Self {
        Self {
            starting_vpn: 0,
            ending_vpn: 0,
            left_child: u32::MAX,
            right_child: u32::MAX,
            parent: u32::MAX,
            vad_type: MmVadType::Private,
            balance: 0,
            flags: 0,
            protection: 0,
            allocation_type: 0,
            committed_pages: 0,
            locked_pages: 0,
            file_object: ptr::null_mut(),
            section_offset: 0,
            process: ptr::null_mut(),
            _reserved: [0; 2],
        }
    }

    /// Check if VAD is in use
    pub fn is_in_use(&self) -> bool {
        (self.flags & vad_flags::VAD_IN_USE) != 0
    }

    /// Get starting virtual address
    pub fn start_address(&self) -> u64 {
        self.starting_vpn << 12
    }

    /// Get ending virtual address (inclusive)
    pub fn end_address(&self) -> u64 {
        ((self.ending_vpn + 1) << 12) - 1
    }

    /// Get size in bytes
    pub fn size(&self) -> u64 {
        (self.ending_vpn - self.starting_vpn + 1) << 12
    }

    /// Get page count
    pub fn page_count(&self) -> u64 {
        self.ending_vpn - self.starting_vpn + 1
    }

    /// Check if address is within this VAD
    pub fn contains_address(&self, virt_addr: u64) -> bool {
        let vpn = virt_addr >> 12;
        vpn >= self.starting_vpn && vpn <= self.ending_vpn
    }

    /// Check if a range overlaps with this VAD
    pub fn overlaps(&self, start_vpn: u64, end_vpn: u64) -> bool {
        !(end_vpn < self.starting_vpn || start_vpn > self.ending_vpn)
    }

    /// Check if memory is committed
    pub fn is_committed(&self) -> bool {
        (self.flags & vad_flags::VAD_COMMITTED) != 0
    }

    /// Check if copy-on-write
    pub fn is_copy_on_write(&self) -> bool {
        (self.flags & vad_flags::VAD_COPY_ON_WRITE) != 0
    }

    /// Check if no-cache
    pub fn is_no_cache(&self) -> bool {
        (self.flags & vad_flags::VAD_NO_CACHE) != 0
    }

    /// Check if locked in memory
    pub fn is_locked(&self) -> bool {
        (self.flags & vad_flags::VAD_LOCKED) != 0
    }

    /// Clear the VAD
    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

impl Default for MmVad {
    fn default() -> Self {
        Self::new()
    }
}

// Safety: VAD only accessed with proper locking
unsafe impl Sync for MmVad {}
unsafe impl Send for MmVad {}

// ============================================================================
// VAD Pool
// ============================================================================

/// VAD pool (static allocation)
static mut VAD_POOL: [MmVad; MAX_VADS] = {
    const INIT: MmVad = MmVad::new();
    [INIT; MAX_VADS]
};

/// VAD allocation bitmap
static mut VAD_BITMAP: [u64; MAX_VADS.div_ceil(64)] = [0; MAX_VADS.div_ceil(64)];

/// VAD pool lock
static VAD_POOL_LOCK: SpinLock<()> = SpinLock::new(());

/// Free VAD count
static FREE_VAD_COUNT: AtomicU32 = AtomicU32::new(MAX_VADS as u32);

/// Allocate a VAD from the pool
pub unsafe fn mm_allocate_vad() -> Option<*mut MmVad> {
    let _guard = VAD_POOL_LOCK.lock();

    // Find a free slot
    for (word_idx, word) in VAD_BITMAP.iter_mut().enumerate() {
        if *word != u64::MAX {
            // Find first zero bit
            let bit_idx = (!*word).trailing_zeros() as usize;
            let vad_idx = word_idx * 64 + bit_idx;

            if vad_idx >= MAX_VADS {
                break;
            }

            // Mark as allocated
            *word |= 1u64 << bit_idx;
            FREE_VAD_COUNT.fetch_sub(1, Ordering::SeqCst);

            let vad = &mut VAD_POOL[vad_idx];
            vad.flags = vad_flags::VAD_IN_USE;
            return Some(vad as *mut MmVad);
        }
    }

    None
}

/// Free a VAD back to the pool
pub unsafe fn mm_free_vad(vad: *mut MmVad) {
    if vad.is_null() {
        return;
    }

    let _guard = VAD_POOL_LOCK.lock();

    // Find the index
    let base = VAD_POOL.as_ptr() as usize;
    let addr = vad as usize;
    let vad_idx = (addr - base) / core::mem::size_of::<MmVad>();

    if vad_idx >= MAX_VADS {
        return;
    }

    // Clear the VAD
    (*vad).clear();

    // Mark as free in bitmap
    let word_idx = vad_idx / 64;
    let bit_idx = vad_idx % 64;
    VAD_BITMAP[word_idx] &= !(1u64 << bit_idx);
    FREE_VAD_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Get VAD by index
pub unsafe fn mm_get_vad(index: usize) -> Option<*mut MmVad> {
    if index < MAX_VADS {
        Some(&mut VAD_POOL[index] as *mut MmVad)
    } else {
        None
    }
}

// ============================================================================
// VAD Tree Operations
// ============================================================================

/// VAD tree root for a process
#[repr(C)]
pub struct MmVadRoot {
    /// Root VAD index (u32::MAX if empty)
    pub root: u32,
    /// Total number of VADs in tree
    pub count: u32,
    /// Tree balance hint
    pub balance_hint: i32,
}

impl MmVadRoot {
    pub const fn new() -> Self {
        Self {
            root: u32::MAX,
            count: 0,
            balance_hint: 0,
        }
    }

    /// Check if tree is empty
    pub fn is_empty(&self) -> bool {
        self.root == u32::MAX
    }
}

impl Default for MmVadRoot {
    fn default() -> Self {
        Self::new()
    }
}

/// Find a VAD containing the given address
pub unsafe fn mm_find_vad(root: &MmVadRoot, virt_addr: u64) -> Option<*mut MmVad> {
    if root.is_empty() {
        return None;
    }

    let vpn = virt_addr >> 12;
    let mut current = root.root;

    while current != u32::MAX {
        let vad = &VAD_POOL[current as usize];

        if vpn < vad.starting_vpn {
            current = vad.left_child;
        } else if vpn > vad.ending_vpn {
            current = vad.right_child;
        } else {
            // Found it
            return Some(&mut VAD_POOL[current as usize] as *mut MmVad);
        }
    }

    None
}

/// Find the VAD that would precede the given address
pub unsafe fn mm_find_vad_predecessor(root: &MmVadRoot, vpn: u64) -> Option<*mut MmVad> {
    if root.is_empty() {
        return None;
    }

    let mut current = root.root;
    let mut predecessor: Option<u32> = None;

    while current != u32::MAX {
        let vad = &VAD_POOL[current as usize];

        if vpn > vad.ending_vpn {
            predecessor = Some(current);
            current = vad.right_child;
        } else {
            current = vad.left_child;
        }
    }

    predecessor.map(|idx| &mut VAD_POOL[idx as usize] as *mut MmVad)
}

/// Insert a VAD into the tree
///
/// Returns false if the range overlaps with an existing VAD.
pub unsafe fn mm_insert_vad(root: &mut MmVadRoot, vad: *mut MmVad) -> bool {
    let vad_ref = &mut *vad;
    let vad_idx = get_vad_index(vad);

    if root.is_empty() {
        // First node
        root.root = vad_idx;
        root.count = 1;
        return true;
    }

    // Find insertion point
    let mut current = root.root;
    let mut parent = u32::MAX;
    let mut go_left = false;

    while current != u32::MAX {
        let node = &VAD_POOL[current as usize];

        // Check for overlap
        if vad_ref.overlaps(node.starting_vpn, node.ending_vpn) {
            return false;
        }

        parent = current;
        if vad_ref.starting_vpn < node.starting_vpn {
            go_left = true;
            current = node.left_child;
        } else {
            go_left = false;
            current = node.right_child;
        }
    }

    // Insert the node
    vad_ref.parent = parent;
    vad_ref.left_child = u32::MAX;
    vad_ref.right_child = u32::MAX;

    if go_left {
        VAD_POOL[parent as usize].left_child = vad_idx;
    } else {
        VAD_POOL[parent as usize].right_child = vad_idx;
    }

    root.count += 1;

    // Note: Full AVL rebalancing not implemented for simplicity
    // In production, would need rotation operations here

    true
}

/// Remove a VAD from the tree
pub unsafe fn mm_remove_vad(root: &mut MmVadRoot, vad: *mut MmVad) -> bool {
    if root.is_empty() || vad.is_null() {
        return false;
    }

    let vad_ref = &mut *vad;
    let vad_idx = get_vad_index(vad);

    // Simple removal - replace with in-order successor if two children
    let replacement = if vad_ref.left_child != u32::MAX && vad_ref.right_child != u32::MAX {
        // Find in-order successor (leftmost node in right subtree)
        let mut successor = vad_ref.right_child;
        while VAD_POOL[successor as usize].left_child != u32::MAX {
            successor = VAD_POOL[successor as usize].left_child;
        }
        Some(successor)
    } else {
        None
    };

    if let Some(succ_idx) = replacement {
        // Copy successor data (except tree links)
        let succ = &VAD_POOL[succ_idx as usize];
        vad_ref.starting_vpn = succ.starting_vpn;
        vad_ref.ending_vpn = succ.ending_vpn;
        vad_ref.vad_type = succ.vad_type;
        vad_ref.flags = succ.flags;
        vad_ref.protection = succ.protection;
        vad_ref.allocation_type = succ.allocation_type;
        vad_ref.committed_pages = succ.committed_pages;
        vad_ref.file_object = succ.file_object;
        vad_ref.section_offset = succ.section_offset;

        // Now remove the successor (which has at most one child)
        remove_node_with_at_most_one_child(root, succ_idx);
    } else {
        // Node has at most one child
        remove_node_with_at_most_one_child(root, vad_idx);
    }

    true
}

/// Helper: Remove a node that has at most one child
unsafe fn remove_node_with_at_most_one_child(root: &mut MmVadRoot, node_idx: u32) {
    let node = &VAD_POOL[node_idx as usize];

    // Get the single child (if any)
    let child = if node.left_child != u32::MAX {
        node.left_child
    } else {
        node.right_child
    };

    let parent = node.parent;

    // Update parent's child pointer
    if parent == u32::MAX {
        // Removing root
        root.root = child;
    } else {
        let parent_node = &mut VAD_POOL[parent as usize];
        if parent_node.left_child == node_idx {
            parent_node.left_child = child;
        } else {
            parent_node.right_child = child;
        }
    }

    // Update child's parent pointer
    if child != u32::MAX {
        VAD_POOL[child as usize].parent = parent;
    }

    root.count -= 1;
}

/// Get the index of a VAD in the pool
unsafe fn get_vad_index(vad: *mut MmVad) -> u32 {
    let base = VAD_POOL.as_ptr() as usize;
    let addr = vad as usize;
    ((addr - base) / core::mem::size_of::<MmVad>()) as u32
}

// ============================================================================
// Memory Region Allocation
// ============================================================================

/// Find a free region in the address space
///
/// Returns the starting VPN of a free region of the requested size,
/// or None if no suitable region exists.
pub unsafe fn mm_find_free_region(
    root: &MmVadRoot,
    page_count: u64,
    start_vpn: u64,
    end_vpn: u64,
) -> Option<u64> {
    if root.is_empty() {
        // Entire range is free
        if end_vpn - start_vpn + 1 >= page_count {
            return Some(start_vpn);
        }
        return None;
    }

    // Collect all VADs in sorted order and find gaps
    let mut current_vpn = start_vpn;

    // Simple linear scan for gaps (not optimal but correct)
    // In production, would walk the tree in-order
    for i in 0..MAX_VADS {
        let vad = &VAD_POOL[i];
        if !vad.is_in_use() {
            continue;
        }

        // Check gap before this VAD
        if vad.starting_vpn > current_vpn {
            let gap_size = vad.starting_vpn - current_vpn;
            if gap_size >= page_count && current_vpn + page_count - 1 <= end_vpn {
                return Some(current_vpn);
            }
        }

        // Move past this VAD
        if vad.ending_vpn >= current_vpn {
            current_vpn = vad.ending_vpn + 1;
        }
    }

    // Check gap after last VAD
    if current_vpn + page_count - 1 <= end_vpn {
        return Some(current_vpn);
    }

    None
}

/// Allocate a virtual address range
///
/// Creates a VAD for the specified range or finds a free region.
pub unsafe fn mm_allocate_virtual_range(
    root: &mut MmVadRoot,
    base_address: Option<u64>,
    size: u64,
    allocation_type: u32,
    protection: u32,
    process: *mut u8,
) -> Option<u64> {
    let page_count = (size + 0xFFF) >> 12;

    // User space range (for now)
    let user_start_vpn: u64 = 0x10000 >> 12; // 64KB
    let user_end_vpn: u64 = 0x7FFF_FFFF_FFFF >> 12; // 128TB - 1

    // Find or verify the region
    let start_vpn = if let Some(addr) = base_address {
        let vpn = addr >> 12;
        // Verify the range is free
        let end_vpn = vpn + page_count - 1;
        for i in 0..MAX_VADS {
            let vad = &VAD_POOL[i];
            if vad.is_in_use() && vad.overlaps(vpn, end_vpn) {
                return None; // Range is occupied
            }
        }
        vpn
    } else {
        // Find a free region
        mm_find_free_region(root, page_count, user_start_vpn, user_end_vpn)?
    };

    // Allocate a VAD
    let vad = mm_allocate_vad()?;
    let vad_ref = &mut *vad;

    vad_ref.starting_vpn = start_vpn;
    vad_ref.ending_vpn = start_vpn + page_count - 1;
    vad_ref.vad_type = MmVadType::Private;
    vad_ref.protection = protection;
    vad_ref.allocation_type = allocation_type;
    vad_ref.process = process;

    if (allocation_type & allocation_type::MEM_COMMIT) != 0 {
        vad_ref.flags |= vad_flags::VAD_COMMITTED;
        vad_ref.committed_pages = page_count as u32;
    }

    // Insert into tree
    if !mm_insert_vad(root, vad) {
        mm_free_vad(vad);
        return None;
    }

    Some(start_vpn << 12)
}

/// Free a virtual address range
pub unsafe fn mm_free_virtual_range(
    root: &mut MmVadRoot,
    base_address: u64,
    _size: u64,
    free_type: u32,
) -> bool {
    let vad = mm_find_vad(root, base_address);
    if vad.is_none() {
        return false;
    }

    let vad = vad.unwrap();
    let vad_ref = &mut *vad;

    if (free_type & allocation_type::MEM_RELEASE) != 0 {
        // Full release - remove VAD
        mm_remove_vad(root, vad);
        mm_free_vad(vad);
    } else if (free_type & allocation_type::MEM_DECOMMIT) != 0 {
        // Just decommit - mark as reserved
        vad_ref.flags &= !vad_flags::VAD_COMMITTED;
        vad_ref.committed_pages = 0;
    }

    true
}

// ============================================================================
// Statistics
// ============================================================================

/// Get VAD statistics
pub fn mm_get_vad_stats() -> MmVadStats {
    let free = FREE_VAD_COUNT.load(Ordering::SeqCst);
    MmVadStats {
        total_vads: MAX_VADS as u32,
        free_vads: free,
        allocated_vads: MAX_VADS as u32 - free,
    }
}

/// VAD statistics
#[derive(Debug, Clone, Copy)]
pub struct MmVadStats {
    pub total_vads: u32,
    pub free_vads: u32,
    pub allocated_vads: u32,
}

/// Initialize VAD subsystem
pub fn init() {
    crate::serial_println!("[MM] VAD subsystem initialized ({} VADs available)", MAX_VADS);
}

// ============================================================================
// Inspection Functions
// ============================================================================

/// VAD snapshot for inspection
#[derive(Clone, Copy)]
pub struct MmVadSnapshot {
    /// VAD index
    pub index: u32,
    /// Starting virtual address
    pub start_address: u64,
    /// Ending virtual address
    pub end_address: u64,
    /// Size in bytes
    pub size: u64,
    /// VAD type
    pub vad_type: MmVadType,
    /// Protection flags
    pub protection: u32,
    /// Is committed
    pub committed: bool,
    /// Committed page count
    pub committed_pages: u32,
    /// Is locked
    pub locked: bool,
}

impl MmVadSnapshot {
    pub const fn empty() -> Self {
        Self {
            index: 0,
            start_address: 0,
            end_address: 0,
            size: 0,
            vad_type: MmVadType::Private,
            protection: 0,
            committed: false,
            committed_pages: 0,
            locked: false,
        }
    }
}

/// Get snapshots of all allocated VADs
pub fn mm_get_vad_snapshots(max_count: usize) -> ([MmVadSnapshot; 64], usize) {
    let mut snapshots = [MmVadSnapshot::empty(); 64];
    let mut count = 0;

    let limit = max_count.min(64).min(MAX_VADS);

    unsafe {
        let _guard = VAD_POOL_LOCK.lock();

        for i in 0..MAX_VADS {
            if count >= limit {
                break;
            }

            let vad = &VAD_POOL[i];
            if vad.is_in_use() {
                let snap = &mut snapshots[count];
                snap.index = i as u32;
                snap.start_address = vad.start_address();
                snap.end_address = vad.end_address();
                snap.size = vad.size();
                snap.vad_type = vad.vad_type;
                snap.protection = vad.protection;
                snap.committed = vad.is_committed();
                snap.committed_pages = vad.committed_pages;
                snap.locked = vad.is_locked();
                count += 1;
            }
        }
    }

    (snapshots, count)
}

/// Get VAD type name
pub fn vad_type_name(vad_type: MmVadType) -> &'static str {
    match vad_type {
        MmVadType::Private => "Private",
        MmVadType::Mapped => "Mapped",
        MmVadType::Physical => "Physical",
        MmVadType::Image => "Image",
        MmVadType::LargePage => "LargePage",
        MmVadType::Rotate => "Rotate",
    }
}

/// Get protection name
pub fn protection_name(protection: u32) -> &'static str {
    match protection {
        protection::PAGE_NOACCESS => "NoAccess",
        protection::PAGE_READONLY => "R-",
        protection::PAGE_READWRITE => "RW",
        protection::PAGE_EXECUTE => "X-",
        protection::PAGE_EXECUTE_READ => "RX",
        protection::PAGE_EXECUTE_READWRITE => "RWX",
        protection::PAGE_WRITECOPY => "WC",
        protection::PAGE_EXECUTE_WRITECOPY => "XWC",
        _ => "???",
    }
}
