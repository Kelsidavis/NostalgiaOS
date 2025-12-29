//! Kernel Pool Allocator
//!
//! NT uses pool allocators for dynamic kernel memory:
//!
//! - **NonPagedPool**: Cannot be paged out, for DPCs/ISRs
//! - **PagedPool**: Can be paged to disk
//! - **NonPagedPoolNx**: Non-executable nonpaged pool
//!
//! # Pool Tags
//! Each allocation has a 4-character tag for debugging and leak detection.
//!
//! # Implementation
//! Uses a simple block allocator with size classes for efficiency.
//! Each block has a header with size and pool tag.

use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::ke::SpinLock;

/// Pool types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum PoolType {
    /// Non-paged pool (always resident)
    #[default]
    NonPagedPool = 0,
    /// Paged pool (can be paged out)
    PagedPool = 1,
    /// Non-paged pool, non-executable
    NonPagedPoolNx = 2,
    /// Paged pool, non-executable
    PagedPoolNx = 3,
    /// Session paged pool
    SessionPagedPool = 4,
    /// Must succeed (system crash on failure)
    NonPagedPoolMustSucceed = 5,
}


/// Pool tag (4 characters)
pub type PoolTag = u32;

/// Create a pool tag from 4 ASCII characters
pub const fn make_tag(a: u8, b: u8, c: u8, d: u8) -> PoolTag {
    ((d as u32) << 24) | ((c as u32) << 16) | ((b as u32) << 8) | (a as u32)
}

/// Common pool tags
pub mod pool_tags {
    use super::make_tag;

    pub const TAG_GENERIC: u32 = make_tag(b'G', b'e', b'n', b' ');
    pub const TAG_PROCESS: u32 = make_tag(b'P', b'r', b'o', b'c');
    pub const TAG_THREAD: u32 = make_tag(b'T', b'h', b'r', b'd');
    pub const TAG_FILE: u32 = make_tag(b'F', b'i', b'l', b'e');
    pub const TAG_DRIVER: u32 = make_tag(b'D', b'r', b'v', b'r');
    pub const TAG_IRP: u32 = make_tag(b'I', b'r', b'p', b' ');
    pub const TAG_MDL: u32 = make_tag(b'M', b'd', b'l', b' ');
    pub const TAG_SECURITY: u32 = make_tag(b'S', b'e', b'c', b' ');
    pub const TAG_OBJECT: u32 = make_tag(b'O', b'b', b'j', b' ');
    pub const TAG_EVENT: u32 = make_tag(b'E', b'v', b'n', b't');
    pub const TAG_MUTEX: u32 = make_tag(b'M', b'u', b't', b'x');
    pub const TAG_SEMAPHORE: u32 = make_tag(b'S', b'e', b'm', b'a');
    pub const TAG_TIMER: u32 = make_tag(b'T', b'i', b'm', b'r');
    pub const TAG_REGISTRY: u32 = make_tag(b'R', b'e', b'g', b' ');
    pub const TAG_MM: u32 = make_tag(b'M', b'm', b' ', b' ');
}

/// Pool block header
#[repr(C)]
struct PoolHeader {
    /// Size of this block (including header)
    size: u32,
    /// Pool tag
    tag: PoolTag,
    /// Pool type
    pool_type: PoolType,
    /// Flags
    flags: u8,
    /// Reserved
    _reserved: u16,
}

impl PoolHeader {
    const SIZE: usize = 16; // Must be 16-byte aligned

    fn new(size: u32, tag: PoolTag, pool_type: PoolType) -> Self {
        Self {
            size,
            tag,
            pool_type,
            flags: 0,
            _reserved: 0,
        }
    }
}

/// Pool block flags
mod pool_flags {
    /// Block is allocated
    pub const ALLOCATED: u8 = 0x01;
    /// Block is from large allocation
    pub const LARGE_ALLOCATION: u8 = 0x02;
}

// ============================================================================
// Simple Block Allocator
// ============================================================================

/// Size classes for small allocations
const SIZE_CLASSES: [usize; 8] = [32, 64, 128, 256, 512, 1024, 2048, 4096];

/// Get size class index for a given size
fn get_size_class(size: usize) -> Option<usize> {
    for (i, &class_size) in SIZE_CLASSES.iter().enumerate() {
        if size <= class_size {
            return Some(i);
        }
    }
    None
}

/// Blocks per size class
const BLOCKS_PER_CLASS: usize = 64;

/// Pool arena for a size class
struct PoolArena {
    /// Block size for this arena
    block_size: usize,
    /// Free list head (index, or usize::MAX if empty)
    free_head: usize,
    /// Number of free blocks
    free_count: usize,
    /// Allocation bitmap
    bitmap: u64,
}

impl PoolArena {
    const fn new(block_size: usize) -> Self {
        Self {
            block_size,
            free_head: 0,
            free_count: BLOCKS_PER_CLASS,
            bitmap: 0, // All zeros = all free
        }
    }

    /// Allocate a block from this arena
    fn allocate(&mut self) -> Option<usize> {
        if self.bitmap == u64::MAX {
            return None;
        }

        // Find first zero bit
        let bit_idx = (!self.bitmap).trailing_zeros() as usize;
        if bit_idx >= BLOCKS_PER_CLASS {
            return None;
        }

        // Mark as allocated
        self.bitmap |= 1u64 << bit_idx;
        self.free_count -= 1;

        Some(bit_idx)
    }

    /// Free a block back to this arena
    fn free(&mut self, block_idx: usize) -> bool {
        if block_idx >= BLOCKS_PER_CLASS {
            return false;
        }

        let mask = 1u64 << block_idx;
        if (self.bitmap & mask) == 0 {
            return false; // Already free (double-free)
        }

        self.bitmap &= !mask;
        self.free_count += 1;
        true
    }

    /// Check if a block is allocated
    fn is_allocated(&self, block_idx: usize) -> bool {
        if block_idx >= BLOCKS_PER_CLASS {
            return false;
        }
        (self.bitmap & (1u64 << block_idx)) != 0
    }
}

// ============================================================================
// Pool Storage
// ============================================================================

/// Pool heap size (256KB for now)
const POOL_HEAP_SIZE: usize = 256 * 1024;

/// Pool heap storage
static mut POOL_HEAP: [u8; POOL_HEAP_SIZE] = [0; POOL_HEAP_SIZE];

/// Pool arenas for each size class
static mut POOL_ARENAS: [PoolArena; 8] = [
    PoolArena::new(32),
    PoolArena::new(64),
    PoolArena::new(128),
    PoolArena::new(256),
    PoolArena::new(512),
    PoolArena::new(1024),
    PoolArena::new(2048),
    PoolArena::new(4096),
];

/// Pool lock
static POOL_LOCK: SpinLock<()> = SpinLock::new(());

/// Statistics
static POOL_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static POOL_FREES: AtomicUsize = AtomicUsize::new(0);
static POOL_BYTES_ALLOCATED: AtomicUsize = AtomicUsize::new(0);

// ============================================================================
// Pool API
// ============================================================================

/// Allocate memory from the pool
///
/// # Arguments
/// * `pool_type` - Type of pool to allocate from
/// * `size` - Number of bytes to allocate
/// * `tag` - Pool tag for debugging
///
/// # Returns
/// Pointer to allocated memory, or null if allocation failed
pub unsafe fn ex_allocate_pool_with_tag(
    pool_type: PoolType,
    size: usize,
    tag: PoolTag,
) -> *mut u8 {
    // Add header size
    let total_size = size + PoolHeader::SIZE;

    // Get size class
    let class_idx = match get_size_class(total_size) {
        Some(idx) => idx,
        None => {
            // TODO: Large allocation support
            return ptr::null_mut();
        }
    };

    let _guard = POOL_LOCK.lock();

    // Allocate from arena
    let arena = &mut POOL_ARENAS[class_idx];
    let block_idx = match arena.allocate() {
        Some(idx) => idx,
        None => return ptr::null_mut(),
    };

    // Calculate block address
    let arena_offset = get_arena_offset(class_idx);
    let block_offset = arena_offset + block_idx * arena.block_size;

    if block_offset + arena.block_size > POOL_HEAP_SIZE {
        arena.free(block_idx);
        return ptr::null_mut();
    }

    let block_ptr = POOL_HEAP.as_mut_ptr().add(block_offset);

    // Write header
    let header = block_ptr as *mut PoolHeader;
    *header = PoolHeader::new(arena.block_size as u32, tag, pool_type);
    (*header).flags = pool_flags::ALLOCATED;

    // Update stats
    POOL_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    POOL_BYTES_ALLOCATED.fetch_add(arena.block_size, Ordering::Relaxed);

    // Return pointer after header
    block_ptr.add(PoolHeader::SIZE)
}

/// Allocate zeroed memory from the pool
pub unsafe fn ex_allocate_pool_zero(
    pool_type: PoolType,
    size: usize,
    tag: PoolTag,
) -> *mut u8 {
    let ptr = ex_allocate_pool_with_tag(pool_type, size, tag);
    if !ptr.is_null() {
        ptr::write_bytes(ptr, 0, size);
    }
    ptr
}

/// Free memory back to the pool
pub unsafe fn ex_free_pool_with_tag(ptr: *mut u8, tag: PoolTag) {
    if ptr.is_null() {
        return;
    }

    let _guard = POOL_LOCK.lock();

    // Get header
    let header_ptr = ptr.sub(PoolHeader::SIZE) as *mut PoolHeader;
    let header = &*header_ptr;

    // Verify tag (optional, for debugging)
    if header.tag != tag && tag != 0 {
        // Tag mismatch - potential corruption
        crate::serial_println!(
            "[MM] Pool tag mismatch: expected {:08x}, got {:08x}",
            tag, header.tag
        );
    }

    if (header.flags & pool_flags::ALLOCATED) == 0 {
        // Double free
        crate::serial_println!("[MM] Pool double-free detected!");
        return;
    }

    // Find which arena this belongs to
    let block_size = header.size as usize;
    let class_idx = match SIZE_CLASSES.iter().position(|&s| s == block_size) {
        Some(idx) => idx,
        None => {
            crate::serial_println!("[MM] Pool corruption: invalid block size {}", block_size);
            return;
        }
    };

    // Calculate block index
    let arena_offset = get_arena_offset(class_idx);
    let heap_base = POOL_HEAP.as_ptr() as usize;
    let block_addr = header_ptr as usize;
    let block_offset = block_addr - heap_base;

    if block_offset < arena_offset {
        return;
    }

    let block_idx = (block_offset - arena_offset) / block_size;

    // Free the block
    let arena = &mut POOL_ARENAS[class_idx];
    if arena.free(block_idx) {
        // Update stats
        POOL_FREES.fetch_add(1, Ordering::Relaxed);
        POOL_BYTES_ALLOCATED.fetch_sub(block_size, Ordering::Relaxed);

        // Clear header
        (*header_ptr).flags = 0;
    }
}

/// Free memory (without tag verification)
pub unsafe fn ex_free_pool(ptr: *mut u8) {
    ex_free_pool_with_tag(ptr, 0);
}

/// Get the offset of an arena in the heap
fn get_arena_offset(class_idx: usize) -> usize {
    let mut offset = 0;
    for i in 0..class_idx {
        offset += SIZE_CLASSES[i] * BLOCKS_PER_CLASS;
    }
    offset
}

// ============================================================================
// Pool Statistics
// ============================================================================

/// Pool statistics
#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    pub total_size: usize,
    pub bytes_allocated: usize,
    pub bytes_free: usize,
    pub allocation_count: usize,
    pub free_count: usize,
}

/// Get pool statistics
pub fn mm_get_pool_stats() -> PoolStats {
    let bytes_allocated = POOL_BYTES_ALLOCATED.load(Ordering::Relaxed);
    PoolStats {
        total_size: POOL_HEAP_SIZE,
        bytes_allocated,
        bytes_free: POOL_HEAP_SIZE.saturating_sub(bytes_allocated),
        allocation_count: POOL_ALLOCATIONS.load(Ordering::Relaxed),
        free_count: POOL_FREES.load(Ordering::Relaxed),
    }
}

/// Get free block count for a size class
pub fn mm_get_pool_free_count(class_idx: usize) -> usize {
    if class_idx >= SIZE_CLASSES.len() {
        return 0;
    }
    unsafe {
        let _guard = POOL_LOCK.lock();
        POOL_ARENAS[class_idx].free_count
    }
}

/// Per-class pool statistics
#[derive(Debug, Clone, Copy)]
pub struct PoolClassStats {
    pub block_size: usize,
    pub total_blocks: usize,
    pub free_blocks: usize,
    pub used_blocks: usize,
    pub total_bytes: usize,
    pub used_bytes: usize,
}

/// Get statistics for a specific size class
pub fn mm_get_pool_class_stats(class_idx: usize) -> Option<PoolClassStats> {
    if class_idx >= SIZE_CLASSES.len() {
        return None;
    }
    unsafe {
        let _guard = POOL_LOCK.lock();
        let arena = &POOL_ARENAS[class_idx];
        let block_size = SIZE_CLASSES[class_idx];
        let total_blocks = BLOCKS_PER_CLASS;
        let free_blocks = arena.free_count;
        let used_blocks = total_blocks - free_blocks;

        Some(PoolClassStats {
            block_size,
            total_blocks,
            free_blocks,
            used_blocks,
            total_bytes: block_size * total_blocks,
            used_bytes: block_size * used_blocks,
        })
    }
}

/// Get number of size classes
pub fn mm_get_pool_class_count() -> usize {
    SIZE_CLASSES.len()
}

/// Get all size classes
pub fn mm_get_size_classes() -> &'static [usize] {
    &SIZE_CLASSES
}

// ============================================================================
// Global Allocator (optional)
// ============================================================================

// Global allocator - disabled unless "alloc" feature is enabled
// The feature doesn't exist yet but code is ready for future use
#[cfg(any())]  // Effectively disabled - use #[cfg(feature = "alloc")] when ready
mod global_allocator {
    use super::*;
    use core::alloc::{GlobalAlloc, Layout};

    struct PoolAllocator;

    unsafe impl GlobalAlloc for PoolAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            ex_allocate_pool_with_tag(
                PoolType::NonPagedPool,
                layout.size(),
                pool_tags::TAG_GENERIC,
            )
        }

        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            ex_free_pool(ptr);
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let new_ptr = self.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
            if !new_ptr.is_null() {
                ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
            new_ptr
        }
    }

    #[global_allocator]
    static ALLOCATOR: PoolAllocator = PoolAllocator;
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the pool allocator
pub fn init() {
    // Calculate total usable space
    let mut total_blocks = 0;
    for (i, &size) in SIZE_CLASSES.iter().enumerate() {
        total_blocks += BLOCKS_PER_CLASS;
        crate::serial_println!(
            "[MM]   Size class {}: {}B x {} = {}KB",
            i, size, BLOCKS_PER_CLASS,
            (size * BLOCKS_PER_CLASS) / 1024
        );
    }

    crate::serial_println!(
        "[MM] Pool allocator initialized ({} KB heap, {} blocks)",
        POOL_HEAP_SIZE / 1024,
        total_blocks
    );
}
