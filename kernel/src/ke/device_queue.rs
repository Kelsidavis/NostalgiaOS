//! Device Queue Object (KDEVICE_QUEUE)
//!
//! Device queues are used to serialize I/O requests for devices that can
//! only process one request at a time. When a device is busy, new requests
//! are queued and processed in order when the device becomes available.
//!
//! # Key Concepts
//!
//! - **Busy state**: If the device is not busy, requests are processed immediately.
//!   If busy, requests are queued.
//! - **Key-based ordering**: Requests can be inserted by key for priority ordering.
//! - **Thread-safe**: Uses spinlock for synchronization.
//!
//! # Windows Equivalent
//! This implements NT's devquobj.c functionality.
//!
//! # Example
//! ```
//! let mut queue = KDeviceQueue::new();
//! queue.init();
//!
//! let mut entry = KDeviceQueueEntry::new();
//!
//! // If InsertDeviceQueue returns false, process immediately
//! // If true, the request was queued
//! if !queue.insert(&mut entry) {
//!     // Process the request now
//!     process_request(&entry);
//!     // When done, get next entry
//!     if let Some(next) = queue.remove() {
//!         process_request(&next);
//!     }
//! }
//! ```

use crate::ke::list::ListEntry;
use crate::ke::spinlock::RawSpinLock;
use crate::containing_record;
use core::cell::UnsafeCell;

/// Object type identifier for device queues
pub const DEVICE_QUEUE_OBJECT: u8 = 4;

/// Device queue object
///
/// Serializes I/O requests for devices that can only handle one at a time.
#[repr(C)]
pub struct KDeviceQueue {
    /// Object type (DeviceQueueObject)
    pub object_type: u8,
    /// Size of the object
    pub size: u8,
    /// Reserved/padding
    reserved: [u8; 2],
    /// Spinlock for synchronization
    lock: RawSpinLock,
    /// List of queued device requests
    device_list_head: UnsafeCell<ListEntry>,
    /// Whether the device is currently busy
    busy: UnsafeCell<bool>,
}

// Safety: Protected by spinlock
unsafe impl Sync for KDeviceQueue {}
unsafe impl Send for KDeviceQueue {}

impl KDeviceQueue {
    /// Create a new uninitialized device queue
    pub const fn new() -> Self {
        Self {
            object_type: DEVICE_QUEUE_OBJECT,
            size: core::mem::size_of::<Self>() as u8,
            reserved: [0; 2],
            lock: RawSpinLock::new(),
            device_list_head: UnsafeCell::new(ListEntry::new()),
            busy: UnsafeCell::new(false),
        }
    }

    /// Initialize the device queue (KeInitializeDeviceQueue)
    pub fn init(&mut self) {
        self.object_type = DEVICE_QUEUE_OBJECT;
        self.size = core::mem::size_of::<Self>() as u8;
        unsafe {
            (*self.device_list_head.get()).init_head();
            *self.busy.get() = false;
        }
    }

    /// Check if the device queue is busy
    #[inline]
    pub fn is_busy(&self) -> bool {
        unsafe { *self.busy.get() }
    }

    /// Insert an entry at the tail of the queue (KeInsertDeviceQueue)
    ///
    /// If the device is not busy, it is marked busy and the entry is NOT
    /// inserted (caller should process immediately).
    ///
    /// If the device is busy, the entry is inserted at the tail and will
    /// be processed when the current operation completes.
    ///
    /// # Returns
    /// - `true` if the entry was inserted (device was busy)
    /// - `false` if the entry was NOT inserted (device was not busy, now marked busy)
    ///
    /// # Safety
    /// The entry must remain valid until removed from the queue.
    pub unsafe fn insert(&self, entry: *mut KDeviceQueueEntry) -> bool {
        let irq = self.lock.acquire();

        let was_busy = *self.busy.get();
        *self.busy.get() = true;

        let inserted = if was_busy {
            // Device is busy - queue the entry
            let list = &mut *self.device_list_head.get();
            list.insert_tail(&mut (*entry).device_list_entry);
            (*entry).inserted = true;
            true
        } else {
            // Device was not busy - caller should process immediately
            (*entry).inserted = false;
            false
        };

        self.lock.release(irq);
        inserted
    }

    /// Insert an entry by sort key (KeInsertByKeyDeviceQueue)
    ///
    /// Entries are ordered by their sort key in ascending order.
    /// Lower keys are processed first.
    ///
    /// # Returns
    /// - `true` if the entry was inserted
    /// - `false` if the device was not busy (caller should process immediately)
    pub unsafe fn insert_by_key(&self, entry: *mut KDeviceQueueEntry, sort_key: u32) -> bool {
        (*entry).sort_key = sort_key;

        let irq = self.lock.acquire();

        let was_busy = *self.busy.get();
        *self.busy.get() = true;

        let inserted = if was_busy {
            // Find insertion point based on sort key
            let list = &mut *self.device_list_head.get();

            if list.is_empty() {
                list.insert_tail(&mut (*entry).device_list_entry);
            } else {
                let mut current = list.flink;
                let mut found_position = false;

                while !core::ptr::eq(current, list as *mut ListEntry) {
                    let current_entry = containing_record!(current, KDeviceQueueEntry, device_list_entry);
                    if (*current_entry).sort_key > sort_key {
                        // Insert before current
                        (*entry).device_list_entry.flink = current;
                        (*entry).device_list_entry.blink = (*current).blink;
                        (*(*current).blink).flink = &mut (*entry).device_list_entry;
                        (*current).blink = &mut (*entry).device_list_entry;
                        found_position = true;
                        break;
                    }
                    current = (*current).flink;
                }

                if !found_position {
                    // Insert at tail (highest key)
                    list.insert_tail(&mut (*entry).device_list_entry);
                }
            }

            (*entry).inserted = true;
            true
        } else {
            (*entry).inserted = false;
            false
        };

        self.lock.release(irq);
        inserted
    }

    /// Remove the first entry from the queue (KeRemoveDeviceQueue)
    ///
    /// Removes and returns the first entry. If the queue is empty,
    /// the device is marked as not busy.
    ///
    /// # Returns
    /// The removed entry, or None if the queue was empty.
    pub unsafe fn remove(&self) -> Option<*mut KDeviceQueueEntry> {
        let irq = self.lock.acquire();

        let list = &mut *self.device_list_head.get();
        let result = if list.is_empty() {
            *self.busy.get() = false;
            None
        } else {
            let entry_link = list.remove_head();
            let entry = containing_record!(entry_link, KDeviceQueueEntry, device_list_entry);
            (*entry).inserted = false;
            Some(entry)
        };

        self.lock.release(irq);
        result
    }

    /// Remove the first entry by key (KeRemoveByKeyDeviceQueue)
    ///
    /// Removes the first entry with a sort key less than or equal to
    /// the specified limit. Used for priority-based processing.
    ///
    /// # Returns
    /// The removed entry, or None if no entry matches or queue is empty.
    pub unsafe fn remove_by_key(&self, sort_key_limit: u32) -> Option<*mut KDeviceQueueEntry> {
        let irq = self.lock.acquire();

        let list = &mut *self.device_list_head.get();
        let mut result = None;

        if !list.is_empty() {
            let mut current = list.flink;

            while !core::ptr::eq(current, list as *mut ListEntry) {
                let entry = containing_record!(current, KDeviceQueueEntry, device_list_entry);
                if (*entry).sort_key <= sort_key_limit {
                    // Found a matching entry - remove it
                    (*current).remove_entry();
                    (*entry).inserted = false;
                    result = Some(entry);
                    break;
                }
                current = (*current).flink;
            }
        }

        if result.is_none() && list.is_empty() {
            *self.busy.get() = false;
        }

        self.lock.release(irq);
        result
    }

    /// Remove a specific entry from the queue (KeRemoveEntryDeviceQueue)
    ///
    /// # Returns
    /// - `true` if the entry was removed
    /// - `false` if the entry was not in the queue
    pub unsafe fn remove_entry(&self, entry: *mut KDeviceQueueEntry) -> bool {
        let irq = self.lock.acquire();

        let removed = if (*entry).inserted {
            (*entry).device_list_entry.remove_entry();
            (*entry).inserted = false;
            true
        } else {
            false
        };

        self.lock.release(irq);
        removed
    }
}

impl Default for KDeviceQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Device queue entry
///
/// Represents a single I/O request in the device queue.
#[repr(C)]
pub struct KDeviceQueueEntry {
    /// Link in the device queue list
    pub device_list_entry: ListEntry,
    /// Sort key for priority ordering
    pub sort_key: u32,
    /// Whether this entry is currently in a queue
    pub inserted: bool,
    /// Reserved/padding
    reserved: [u8; 3],
}

impl KDeviceQueueEntry {
    /// Create a new device queue entry
    pub const fn new() -> Self {
        Self {
            device_list_entry: ListEntry::new(),
            sort_key: 0,
            inserted: false,
            reserved: [0; 3],
        }
    }

    /// Initialize the entry
    pub fn init(&mut self) {
        self.device_list_entry.init_head();
        self.sort_key = 0;
        self.inserted = false;
    }

    /// Check if this entry is in a queue
    #[inline]
    pub fn is_inserted(&self) -> bool {
        self.inserted
    }
}

impl Default for KDeviceQueueEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Public API Functions (NT-compatible naming)
// ============================================================================

/// Initialize a device queue (KeInitializeDeviceQueue)
pub fn ke_initialize_device_queue(queue: &mut KDeviceQueue) {
    queue.init();
}

/// Insert an entry at the tail (KeInsertDeviceQueue)
///
/// # Returns
/// - `true` if inserted (device was busy)
/// - `false` if not inserted (device was not busy, now busy)
pub unsafe fn ke_insert_device_queue(
    queue: &KDeviceQueue,
    entry: *mut KDeviceQueueEntry,
) -> bool {
    queue.insert(entry)
}

/// Insert an entry by sort key (KeInsertByKeyDeviceQueue)
pub unsafe fn ke_insert_by_key_device_queue(
    queue: &KDeviceQueue,
    entry: *mut KDeviceQueueEntry,
    sort_key: u32,
) -> bool {
    queue.insert_by_key(entry, sort_key)
}

/// Remove the first entry (KeRemoveDeviceQueue)
pub unsafe fn ke_remove_device_queue(
    queue: &KDeviceQueue,
) -> Option<*mut KDeviceQueueEntry> {
    queue.remove()
}

/// Remove an entry by key limit (KeRemoveByKeyDeviceQueue)
pub unsafe fn ke_remove_by_key_device_queue(
    queue: &KDeviceQueue,
    sort_key_limit: u32,
) -> Option<*mut KDeviceQueueEntry> {
    queue.remove_by_key(sort_key_limit)
}

/// Remove a specific entry (KeRemoveEntryDeviceQueue)
pub unsafe fn ke_remove_entry_device_queue(
    queue: &KDeviceQueue,
    entry: *mut KDeviceQueueEntry,
) -> bool {
    queue.remove_entry(entry)
}
