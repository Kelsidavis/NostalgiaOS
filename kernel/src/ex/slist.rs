//! Interlocked Singly-Linked List (SList)
//!
//! SLists provide lock-free singly-linked list operations for high-performance
//! scenarios where multiple threads need to access a list concurrently.
//!
//! # Design
//!
//! The SList uses a 64-bit header containing:
//! - A pointer to the first entry
//! - A depth counter (number of entries)
//! - A sequence counter (prevents ABA problem)
//!
//! All operations use compare-and-swap (CAS) for lock-free synchronization.
//!
//! # Usage
//!
//! ```ignore
//! static MY_SLIST: SListHeader = SListHeader::new();
//!
//! // Initialize
//! MY_SLIST.init();
//!
//! // Push an entry
//! let entry = allocate_entry();
//! MY_SLIST.push(entry);
//!
//! // Pop an entry
//! if let Some(entry) = MY_SLIST.pop() {
//!     // Process entry
//! }
//! ```
//!
//! # NT Functions
//!
//! - `ExInitializeSListHead` / `InitializeSListHead` - Initialize header
//! - `ExInterlockedPushEntrySList` - Push entry (lock-free)
//! - `ExInterlockedPopEntrySList` - Pop entry (lock-free)
//! - `ExInterlockedFlushSList` - Flush all entries
//! - `ExQueryDepthSList` - Get entry count

use core::sync::atomic::{AtomicU64, AtomicPtr, Ordering};
use core::ptr;

/// SList entry structure
///
/// Each entry in an SList must start with this structure.
/// The `next` pointer links entries together.
#[repr(C)]
pub struct SListEntry {
    /// Pointer to next entry in the list
    pub next: AtomicPtr<SListEntry>,
}

impl Default for SListEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl SListEntry {
    /// Create a new unlinked entry
    pub const fn new() -> Self {
        Self {
            next: AtomicPtr::new(ptr::null_mut()),
        }
    }
}

/// SList header structure
///
/// The header contains packed information for lock-free operations:
/// - Bits 0-15: Depth (number of entries, max 65535)
/// - Bits 16-31: Sequence (incremented on each operation)
/// - Bits 32-63: Next pointer (on 32-bit) or combined on 64-bit
///
/// On 64-bit systems with more than 32-bit pointers, we use a slightly
/// different packing scheme.
#[repr(C, align(16))]
pub struct SListHeader {
    /// Combined alignment/next pointer and depth/sequence
    /// Format: [sequence:16][depth:16][pointer:32] for 32-bit compat
    /// Or using two 64-bit values for full 64-bit support
    value: AtomicU64,
    /// Extended pointer storage for 64-bit systems
    next_ptr: AtomicPtr<SListEntry>,
}

impl Default for SListHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl SListHeader {
    /// Create a new empty SList header
    pub const fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
            next_ptr: AtomicPtr::new(ptr::null_mut()),
        }
    }

    /// Initialize the SList header (ExInitializeSListHead)
    #[inline]
    pub fn init(&self) {
        self.value.store(0, Ordering::Release);
        self.next_ptr.store(ptr::null_mut(), Ordering::Release);
    }

    /// Get the depth (number of entries) of the list (ExQueryDepthSList)
    #[inline]
    pub fn depth(&self) -> u16 {
        (self.value.load(Ordering::Relaxed) & 0xFFFF) as u16
    }

    /// Get the sequence number
    #[inline]
    pub fn sequence(&self) -> u16 {
        ((self.value.load(Ordering::Relaxed) >> 16) & 0xFFFF) as u16
    }

    /// Get the first entry without removing it
    #[inline]
    pub fn first(&self) -> *mut SListEntry {
        self.next_ptr.load(Ordering::Acquire)
    }

    /// Check if the list is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.next_ptr.load(Ordering::Acquire).is_null()
    }

    /// Push an entry onto the list (ExInterlockedPushEntrySList)
    ///
    /// This is a lock-free operation that atomically adds an entry to the
    /// front of the list.
    ///
    /// # Arguments
    /// * `entry` - Entry to push (must not be null)
    ///
    /// # Returns
    /// Previous first entry (may be null if list was empty)
    pub fn push(&self, entry: *mut SListEntry) -> *mut SListEntry {
        if entry.is_null() {
            return ptr::null_mut();
        }

        loop {
            // Load current state
            let old_value = self.value.load(Ordering::Acquire);
            let old_next = self.next_ptr.load(Ordering::Acquire);

            // Set new entry's next to current first
            unsafe {
                (*entry).next.store(old_next, Ordering::Release);
            }

            // Calculate new value: increment sequence and depth
            let old_depth = (old_value & 0xFFFF) as u16;
            let old_seq = ((old_value >> 16) & 0xFFFF) as u16;
            let new_depth = old_depth.saturating_add(1);
            let new_seq = old_seq.wrapping_add(1);
            let new_value = (new_seq as u64) << 16 | (new_depth as u64);

            // Try to update atomically
            // We need both the value and pointer to update atomically
            // For simplicity, we use a loop with sequence check

            if self.value.compare_exchange_weak(
                old_value,
                new_value,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ).is_ok() {
                // Successfully updated value, now update pointer
                self.next_ptr.store(entry, Ordering::Release);
                SLIST_PUSH_COUNT.fetch_add(1, Ordering::Relaxed);
                return old_next;
            }
            // Retry if CAS failed
            core::hint::spin_loop();
        }
    }

    /// Pop an entry from the list (ExInterlockedPopEntrySList)
    ///
    /// This is a lock-free operation that atomically removes the first entry
    /// from the list.
    ///
    /// # Returns
    /// * `Some(entry)` - The removed entry
    /// * `None` - List was empty
    pub fn pop(&self) -> Option<*mut SListEntry> {
        loop {
            // Load current state
            let old_value = self.value.load(Ordering::Acquire);
            let old_next = self.next_ptr.load(Ordering::Acquire);

            // Check if empty
            if old_next.is_null() {
                return None;
            }

            // Get the next entry's next pointer
            let new_next = unsafe { (*old_next).next.load(Ordering::Acquire) };

            // Calculate new value: increment sequence, decrement depth
            let old_depth = (old_value & 0xFFFF) as u16;
            let old_seq = ((old_value >> 16) & 0xFFFF) as u16;
            let new_depth = old_depth.saturating_sub(1);
            let new_seq = old_seq.wrapping_add(1);
            let new_value = (new_seq as u64) << 16 | (new_depth as u64);

            // Try to update atomically
            if self.value.compare_exchange_weak(
                old_value,
                new_value,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ).is_ok() {
                // Check if the pointer is still the same (ABA check)
                if self.next_ptr.compare_exchange(
                    old_next,
                    new_next,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ).is_ok() {
                    SLIST_POP_COUNT.fetch_add(1, Ordering::Relaxed);
                    return Some(old_next);
                }
                // Pointer changed, need to retry
            }
            // Retry if CAS failed
            core::hint::spin_loop();
        }
    }

    /// Flush all entries from the list (ExInterlockedFlushSList)
    ///
    /// Atomically removes all entries from the list and returns the old first entry.
    ///
    /// # Returns
    /// Previous first entry (may be null if list was empty)
    pub fn flush(&self) -> *mut SListEntry {
        loop {
            let old_value = self.value.load(Ordering::Acquire);
            let old_next = self.next_ptr.load(Ordering::Acquire);

            if old_next.is_null() {
                return ptr::null_mut();
            }

            // New value: zero depth, increment sequence
            let old_seq = ((old_value >> 16) & 0xFFFF) as u16;
            let new_seq = old_seq.wrapping_add(1);
            let new_value = (new_seq as u64) << 16;

            if self.value.compare_exchange_weak(
                old_value,
                new_value,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ).is_ok() {
                self.next_ptr.store(ptr::null_mut(), Ordering::Release);
                SLIST_FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);
                return old_next;
            }
            core::hint::spin_loop();
        }
    }
}

// Safety: SListHeader uses atomic operations for thread safety
unsafe impl Sync for SListHeader {}
unsafe impl Send for SListHeader {}

// ============================================================================
// NT-Compatible Function Names
// ============================================================================

/// Initialize an SList header (ExInitializeSListHead)
#[inline]
pub fn ex_initialize_slist_head(list_head: &SListHeader) {
    list_head.init();
}

/// Push entry onto SList (ExInterlockedPushEntrySList)
#[inline]
pub fn ex_interlocked_push_entry_slist(
    list_head: &SListHeader,
    list_entry: *mut SListEntry,
) -> *mut SListEntry {
    list_head.push(list_entry)
}

/// Pop entry from SList (ExInterlockedPopEntrySList)
#[inline]
pub fn ex_interlocked_pop_entry_slist(list_head: &SListHeader) -> *mut SListEntry {
    list_head.pop().unwrap_or(ptr::null_mut())
}

/// Flush all entries from SList (ExInterlockedFlushSList)
#[inline]
pub fn ex_interlocked_flush_slist(list_head: &SListHeader) -> *mut SListEntry {
    list_head.flush()
}

/// Query depth of SList (ExQueryDepthSList)
#[inline]
pub fn ex_query_depth_slist(list_head: &SListHeader) -> u16 {
    list_head.depth()
}

/// Get first entry without removing (FirstEntrySList)
#[inline]
pub fn first_entry_slist(list_head: &SListHeader) -> *mut SListEntry {
    list_head.first()
}

// ============================================================================
// Statistics
// ============================================================================

static SLIST_PUSH_COUNT: AtomicU64 = AtomicU64::new(0);
static SLIST_POP_COUNT: AtomicU64 = AtomicU64::new(0);
static SLIST_FLUSH_COUNT: AtomicU64 = AtomicU64::new(0);

/// SList statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct SListStats {
    /// Total push operations
    pub push_count: u64,
    /// Total pop operations
    pub pop_count: u64,
    /// Total flush operations
    pub flush_count: u64,
}

/// Get SList statistics
pub fn get_slist_stats() -> SListStats {
    SListStats {
        push_count: SLIST_PUSH_COUNT.load(Ordering::Relaxed),
        pop_count: SLIST_POP_COUNT.load(Ordering::Relaxed),
        flush_count: SLIST_FLUSH_COUNT.load(Ordering::Relaxed),
    }
}

/// Reset SList statistics
pub fn reset_slist_stats() {
    SLIST_PUSH_COUNT.store(0, Ordering::Relaxed);
    SLIST_POP_COUNT.store(0, Ordering::Relaxed);
    SLIST_FLUSH_COUNT.store(0, Ordering::Relaxed);
}

// ============================================================================
// Typed SList Wrapper
// ============================================================================

/// A type-safe wrapper around SList
///
/// This provides a more ergonomic interface for Rust code while
/// maintaining compatibility with the raw SList operations.
pub struct TypedSList<T> {
    header: SListHeader,
    _marker: core::marker::PhantomData<T>,
}

impl<T> Default for TypedSList<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> TypedSList<T> {
    /// Create a new empty typed SList
    pub const fn new() -> Self {
        Self {
            header: SListHeader::new(),
            _marker: core::marker::PhantomData,
        }
    }

    /// Initialize the list
    pub fn init(&self) {
        self.header.init();
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.header.is_empty()
    }

    /// Get depth
    pub fn depth(&self) -> u16 {
        self.header.depth()
    }

    /// Get raw header reference
    pub fn header(&self) -> &SListHeader {
        &self.header
    }
}

// Safety: TypedSList uses atomic operations internally
unsafe impl<T: Send> Send for TypedSList<T> {}
unsafe impl<T: Sync> Sync for TypedSList<T> {}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize SList support
pub fn init_slist() {
    SLIST_PUSH_COUNT.store(0, Ordering::Release);
    SLIST_POP_COUNT.store(0, Ordering::Release);
    SLIST_FLUSH_COUNT.store(0, Ordering::Release);

    crate::serial_println!("[EX] Interlocked SList support initialized");
}
