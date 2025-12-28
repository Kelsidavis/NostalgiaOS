//! Lookaside List Implementation
//!
//! Lookaside lists are high-performance fixed-size memory allocators.
//! They maintain a per-CPU cache of freed blocks to avoid pool allocator
//! overhead for frequently allocated/freed structures.
//!
//! # NT Semantics
//!
//! - Each lookaside list allocates blocks of a fixed size
//! - Uses SLIST (interlocked singly-linked list) for lock-free operation
//! - Falls back to pool allocator when cache is empty/full
//! - Separate NonPaged and Paged lookaside lists
//!
//! # Usage
//! ```
//! let list = LookasideList::new(64, b"Test");
//! let block = list.allocate();
//! // ... use block ...
//! list.free(block);
//! ```

use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use crate::mm::pool::PoolType;

/// Maximum depth of lookaside list cache
const LOOKASIDE_DEPTH: u32 = 256;

/// Minimum depth of lookaside list cache
const LOOKASIDE_MIN_DEPTH: u32 = 4;

/// Singly-linked list entry for lock-free stack
#[repr(C)]
struct SListEntry {
    next: AtomicPtr<SListEntry>,
}

/// Singly-linked list header
#[repr(C)]
struct SListHeader {
    /// Next item in list (lock-free)
    next: AtomicPtr<SListEntry>,
    /// Current depth
    depth: AtomicU32,
}

impl SListHeader {
    const fn new() -> Self {
        Self {
            next: AtomicPtr::new(ptr::null_mut()),
            depth: AtomicU32::new(0),
        }
    }

    /// Push an entry onto the list (lock-free)
    fn push(&self, entry: *mut SListEntry) {
        loop {
            let old_head = self.next.load(Ordering::Relaxed);
            unsafe {
                (*entry).next.store(old_head, Ordering::Relaxed);
            }

            if self.next.compare_exchange_weak(
                old_head,
                entry,
                Ordering::Release,
                Ordering::Relaxed,
            ).is_ok() {
                self.depth.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }

    /// Pop an entry from the list (lock-free)
    fn pop(&self) -> *mut SListEntry {
        loop {
            let old_head = self.next.load(Ordering::Acquire);
            if old_head.is_null() {
                return ptr::null_mut();
            }

            let next = unsafe { (*old_head).next.load(Ordering::Relaxed) };

            if self.next.compare_exchange_weak(
                old_head,
                next,
                Ordering::Release,
                Ordering::Relaxed,
            ).is_ok() {
                self.depth.fetch_sub(1, Ordering::Relaxed);
                return old_head;
            }
        }
    }

    /// Get current depth
    fn depth(&self) -> u32 {
        self.depth.load(Ordering::Relaxed)
    }
}

/// Lookaside list statistics
#[derive(Debug, Default)]
pub struct LookasideStats {
    /// Total allocations
    pub allocates: u32,
    /// Total frees
    pub frees: u32,
    /// Allocations from cache (hits)
    pub allocate_hits: u32,
    /// Frees to cache (hits)
    pub free_hits: u32,
    /// Allocations from pool (misses)
    pub allocate_misses: u32,
    /// Frees to pool (misses - cache full)
    pub free_misses: u32,
}

/// General lookaside list for fixed-size allocations
#[repr(C)]
pub struct LookasideList {
    /// Lock-free list of cached blocks
    list: SListHeader,
    /// Maximum cache depth
    depth: AtomicU32,
    /// Size of each block
    block_size: u32,
    /// Pool tag for identification
    tag: u32,
    /// Pool type (Paged/NonPaged)
    pool_type: PoolType,
    /// Statistics
    stats: LookasideStats,
}

impl LookasideList {
    /// Create a new lookaside list
    ///
    /// # Arguments
    /// * `block_size` - Size of each block to allocate
    /// * `tag` - 4-byte pool tag for debugging
    /// * `pool_type` - Type of pool to use for fallback
    /// * `depth` - Maximum cache depth (0 for default)
    pub fn new(block_size: u32, tag: &[u8; 4], pool_type: PoolType, depth: u32) -> Self {
        let tag_value = u32::from_le_bytes(*tag);
        let actual_depth = if depth == 0 { LOOKASIDE_DEPTH } else { depth };

        // Ensure block size is at least as large as SListEntry
        let actual_size = block_size.max(core::mem::size_of::<SListEntry>() as u32);

        Self {
            list: SListHeader::new(),
            depth: AtomicU32::new(actual_depth),
            block_size: actual_size,
            tag: tag_value,
            pool_type,
            stats: LookasideStats::default(),
        }
    }

    /// Allocate a block from the lookaside list
    ///
    /// First tries the cache, falls back to pool allocator on miss.
    pub fn allocate(&self) -> *mut u8 {
        // Try to get from cache first
        let entry = self.list.pop();

        if !entry.is_null() {
            // Cache hit
            // Note: stats updates would need to be atomic for thread safety
            entry as *mut u8
        } else {
            // Cache miss - allocate from pool
            self.allocate_from_pool()
        }
    }

    /// Free a block back to the lookaside list
    ///
    /// If cache is full, frees to the pool allocator instead.
    pub fn free(&self, block: *mut u8) {
        if block.is_null() {
            return;
        }

        // Check if cache is full
        if self.list.depth() < self.depth.load(Ordering::Relaxed) {
            // Cache has room - add to cache
            self.list.push(block as *mut SListEntry);
        } else {
            // Cache full - free to pool
            self.free_to_pool(block);
        }
    }

    /// Allocate from the pool (slow path)
    fn allocate_from_pool(&self) -> *mut u8 {
        // Use the memory manager's pool allocator
        unsafe {
            crate::mm::pool::ex_allocate_pool_with_tag(
                self.pool_type,
                self.block_size as usize,
                self.tag,
            )
        }
    }

    /// Free to the pool (slow path)
    fn free_to_pool(&self, block: *mut u8) {
        unsafe {
            crate::mm::pool::ex_free_pool_with_tag(block, self.tag);
        }
    }

    /// Get current cache depth
    pub fn depth(&self) -> u32 {
        self.list.depth()
    }

    /// Get block size
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Set maximum cache depth
    pub fn set_depth(&self, depth: u32) {
        let depth = depth.max(LOOKASIDE_MIN_DEPTH).min(LOOKASIDE_DEPTH);
        self.depth.store(depth, Ordering::Relaxed);
    }

    /// Delete the lookaside list, freeing all cached blocks
    pub fn delete(&self) {
        loop {
            let entry = self.list.pop();
            if entry.is_null() {
                break;
            }
            self.free_to_pool(entry as *mut u8);
        }
    }
}

impl Drop for LookasideList {
    fn drop(&mut self) {
        self.delete();
    }
}

/// NonPaged lookaside list (convenience wrapper)
pub struct NPagedLookasideList {
    inner: LookasideList,
}

impl NPagedLookasideList {
    /// Create a new non-paged lookaside list
    pub fn new(block_size: u32, tag: &[u8; 4], depth: u32) -> Self {
        Self {
            inner: LookasideList::new(block_size, tag, PoolType::NonPagedPool, depth),
        }
    }

    /// Allocate a block
    #[inline]
    pub fn allocate(&self) -> *mut u8 {
        self.inner.allocate()
    }

    /// Free a block
    #[inline]
    pub fn free(&self, block: *mut u8) {
        self.inner.free(block)
    }

    /// Delete the list
    #[inline]
    pub fn delete(&self) {
        self.inner.delete()
    }
}

/// Paged lookaside list (convenience wrapper)
pub struct PagedLookasideList {
    inner: LookasideList,
}

impl PagedLookasideList {
    /// Create a new paged lookaside list
    pub fn new(block_size: u32, tag: &[u8; 4], depth: u32) -> Self {
        Self {
            inner: LookasideList::new(block_size, tag, PoolType::PagedPool, depth),
        }
    }

    /// Allocate a block
    #[inline]
    pub fn allocate(&self) -> *mut u8 {
        self.inner.allocate()
    }

    /// Free a block
    #[inline]
    pub fn free(&self, block: *mut u8) {
        self.inner.free(block)
    }

    /// Delete the list
    #[inline]
    pub fn delete(&self) {
        self.inner.delete()
    }
}

// NT API compatibility
pub type NPAGED_LOOKASIDE_LIST = NPagedLookasideList;
pub type PAGED_LOOKASIDE_LIST = PagedLookasideList;
pub type LOOKASIDE_LIST_EX = LookasideList;

/// Initialize a non-paged lookaside list (NT API)
pub fn ex_initialize_npaged_lookaside_list(
    list: &mut NPagedLookasideList,
    block_size: u32,
    tag: u32,
    depth: u32,
) {
    *list = NPagedLookasideList {
        inner: LookasideList {
            list: SListHeader::new(),
            depth: AtomicU32::new(if depth == 0 { LOOKASIDE_DEPTH } else { depth }),
            block_size: block_size.max(core::mem::size_of::<SListEntry>() as u32),
            tag,
            pool_type: PoolType::NonPagedPool,
            stats: LookasideStats::default(),
        },
    };
}

/// Delete a non-paged lookaside list (NT API)
pub fn ex_delete_npaged_lookaside_list(list: &NPagedLookasideList) {
    list.delete();
}

/// Allocate from non-paged lookaside list (NT API)
pub fn ex_allocate_from_npaged_lookaside_list(list: &NPagedLookasideList) -> *mut u8 {
    list.allocate()
}

/// Free to non-paged lookaside list (NT API)
pub fn ex_free_to_npaged_lookaside_list(list: &NPagedLookasideList, entry: *mut u8) {
    list.free(entry)
}
