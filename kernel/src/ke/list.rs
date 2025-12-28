//! Doubly-linked list implementation (NT LIST_ENTRY style)
//!
//! This provides an intrusive doubly-linked list similar to Windows NT's
//! LIST_ENTRY structure. The list entry is embedded within the containing
//! structure, allowing O(1) insertion and removal.
//!
//! # Safety
//!
//! This is an intrusive data structure. The caller must ensure:
//! - List entries are only in one list at a time
//! - The containing structure outlives its list membership
//! - Proper synchronization when accessed from multiple contexts

use core::ptr;

/// Doubly-linked list entry (embedded in containing structure)
///
/// Equivalent to NT's LIST_ENTRY:
/// ```c
/// typedef struct _LIST_ENTRY {
///     struct _LIST_ENTRY *Flink;  // Forward link
///     struct _LIST_ENTRY *Blink;  // Backward link
/// } LIST_ENTRY;
/// ```
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ListEntry {
    /// Forward link (next entry)
    pub flink: *mut ListEntry,
    /// Backward link (previous entry)
    pub blink: *mut ListEntry,
}

impl ListEntry {
    /// Create a new uninitialized list entry
    pub const fn new() -> Self {
        Self {
            flink: ptr::null_mut(),
            blink: ptr::null_mut(),
        }
    }

    /// Initialize a list head (empty list points to itself)
    ///
    /// Equivalent to InitializeListHead()
    #[inline]
    pub fn init_head(&mut self) {
        self.flink = self as *mut ListEntry;
        self.blink = self as *mut ListEntry;
    }

    /// Check if the list is empty
    ///
    /// Equivalent to IsListEmpty()
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.flink == self as *const ListEntry as *mut ListEntry
    }

    /// Insert entry at the head of the list (after the list head)
    ///
    /// Equivalent to InsertHeadList()
    ///
    /// # Safety
    /// The entry must not already be in a list
    #[inline]
    pub unsafe fn insert_head(&mut self, entry: *mut ListEntry) {
        let old_flink = self.flink;
        (*entry).flink = old_flink;
        (*entry).blink = self as *mut ListEntry;
        (*old_flink).blink = entry;
        self.flink = entry;
    }

    /// Insert entry at the tail of the list (before the list head)
    ///
    /// Equivalent to InsertTailList()
    ///
    /// # Safety
    /// The entry must not already be in a list
    #[inline]
    pub unsafe fn insert_tail(&mut self, entry: *mut ListEntry) {
        let old_blink = self.blink;
        (*entry).flink = self as *mut ListEntry;
        (*entry).blink = old_blink;
        (*old_blink).flink = entry;
        self.blink = entry;
    }

    /// Remove and return the first entry from the list
    ///
    /// Equivalent to RemoveHeadList()
    ///
    /// # Safety
    /// The list must not be empty
    #[inline]
    pub unsafe fn remove_head(&mut self) -> *mut ListEntry {
        let entry = self.flink;
        let new_flink = (*entry).flink;
        self.flink = new_flink;
        (*new_flink).blink = self as *mut ListEntry;
        entry
    }

    /// Remove and return the last entry from the list
    ///
    /// Equivalent to RemoveTailList()
    ///
    /// # Safety
    /// The list must not be empty
    #[inline]
    pub unsafe fn remove_tail(&mut self) -> *mut ListEntry {
        let entry = self.blink;
        let new_blink = (*entry).blink;
        self.blink = new_blink;
        (*new_blink).flink = self as *mut ListEntry;
        entry
    }

    /// Remove this entry from its current list
    ///
    /// Equivalent to RemoveEntryList()
    ///
    /// # Safety
    /// The entry must be in a list
    #[inline]
    pub unsafe fn remove_entry(&mut self) {
        let flink = self.flink;
        let blink = self.blink;
        (*blink).flink = flink;
        (*flink).blink = blink;
        // Clear pointers to help catch bugs
        self.flink = ptr::null_mut();
        self.blink = ptr::null_mut();
    }
}

impl Default for ListEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate the offset of a field within a struct
#[macro_export]
macro_rules! offset_of {
    ($type:ty, $field:ident) => {{
        let dummy = core::mem::MaybeUninit::<$type>::uninit();
        let base = dummy.as_ptr();
        // SAFETY: We're computing an offset from a valid MaybeUninit pointer,
        // not actually dereferencing it. addr_of! on raw pointers is safe.
        #[allow(unused_unsafe)]
        let field = unsafe { core::ptr::addr_of!((*base).$field) };
        (field as usize) - (base as usize)
    }};
}

/// Get a pointer to the containing structure from a list entry pointer
///
/// Equivalent to CONTAINING_RECORD() macro in Windows:
/// ```c
/// #define CONTAINING_RECORD(address, type, field) \
///     ((type *)((char *)(address) - offsetof(type, field)))
/// ```
#[macro_export]
macro_rules! containing_record {
    ($ptr:expr, $type:ty, $field:ident) => {{
        let offset = $crate::offset_of!($type, $field);
        ($ptr as *mut u8).sub(offset) as *mut $type
    }};
}
