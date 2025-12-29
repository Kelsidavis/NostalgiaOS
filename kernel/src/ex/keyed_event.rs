//! Keyed Events (KEYED_EVENT_OBJECT)
//!
//! Keyed events are an advanced synchronization primitive used by the
//! critical section implementation when memory is low. They allow threads
//! to wait and release each other based on a key value, enabling efficient
//! synchronization without allocating additional memory.
//!
//! # Design
//!
//! - Waiters and releasers are matched by key value within the same process
//! - If a releaser arrives before a waiter, it waits for the waiter
//! - The key's low bit indicates whether it's a release thread waiting
//! - A global keyed event (CritSecOutOfMemoryEvent) is used as fallback
//!
//! # Windows Equivalent
//! This implements NT's keyedevent.c functionality.
//!
//! # Usage
//! ```
//! // Thread 1 (waiter):
//! NtWaitForKeyedEvent(handle, key, FALSE, NULL);
//!
//! // Thread 2 (releaser):
//! NtReleaseKeyedEvent(handle, key, FALSE, NULL);
//! ```

use crate::ke::list::ListEntry;
use crate::ke::spinlock::RawSpinLock;
use crate::ke::semaphore::KSemaphore;
use crate::containing_record;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

/// Access rights for keyed events
pub mod access_rights {
    /// Wait for keyed event
    pub const KEYEDEVENT_WAIT: u32 = 0x0001;
    /// Wake a keyed event waiter
    pub const KEYEDEVENT_WAKE: u32 = 0x0002;
    /// All access
    pub const KEYEDEVENT_ALL_ACCESS: u32 = 0x000F0003;
}

/// The low bit of the key value indicates a release thread waiting
const KEYVALUE_RELEASE: usize = 1;

/// Maximum number of keyed event objects
pub const MAX_KEYED_EVENT_OBJECTS: usize = 64;

/// Keyed event object signature
const KEYED_EVENT_SIGNATURE: u32 = 0x4B455945; // 'KEYE'

/// Keyed event object
#[repr(C)]
pub struct KeyedEventObject {
    /// Signature for validation
    signature: u32,
    /// Spinlock for synchronization
    lock: RawSpinLock,
    /// List of waiting threads
    wait_queue: UnsafeCell<ListEntry>,
    /// Reference count
    ref_count: AtomicU32,
    /// Whether this object is in use
    in_use: AtomicBool,
    /// Object index in the global pool
    index: u32,
}

// Safety: Protected by spinlock
unsafe impl Sync for KeyedEventObject {}
unsafe impl Send for KeyedEventObject {}

impl KeyedEventObject {
    /// Create a new keyed event object
    pub const fn new() -> Self {
        Self {
            signature: 0,
            lock: RawSpinLock::new(),
            wait_queue: UnsafeCell::new(ListEntry::new()),
            ref_count: AtomicU32::new(0),
            in_use: AtomicBool::new(false),
            index: 0,
        }
    }

    /// Initialize the keyed event object
    pub fn init(&mut self, index: u32) {
        self.signature = KEYED_EVENT_SIGNATURE;
        self.index = index;
        unsafe {
            (*self.wait_queue.get()).init_head();
        }
        self.ref_count.store(1, Ordering::Release);
        self.in_use.store(true, Ordering::Release);
    }

    /// Check if this is a valid keyed event object
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.signature == KEYED_EVENT_SIGNATURE && self.in_use.load(Ordering::Acquire)
    }

    /// Add a reference
    pub fn add_ref(&self) -> u32 {
        self.ref_count.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Release a reference
    pub fn release(&self) -> u32 {
        let old = self.ref_count.fetch_sub(1, Ordering::AcqRel);
        if old == 1 {
            // Last reference - mark as not in use
            self.in_use.store(false, Ordering::Release);
        }
        old - 1
    }
}

impl Default for KeyedEventObject {
    fn default() -> Self {
        Self::new()
    }
}

/// Keyed wait entry (embedded in thread structure)
#[repr(C)]
pub struct KeyedWaitEntry {
    /// Link in the wait queue
    pub wait_chain: ListEntry,
    /// The key value being waited on
    pub key_value: UnsafeCell<usize>,
    /// Semaphore for wakeup
    pub wait_semaphore: UnsafeCell<KSemaphore>,
    /// Whether this entry is in use
    pub in_use: AtomicBool,
}

// Safety: Protected by the keyed event lock
unsafe impl Sync for KeyedWaitEntry {}
unsafe impl Send for KeyedWaitEntry {}

impl KeyedWaitEntry {
    /// Create a new keyed wait entry
    pub const fn new() -> Self {
        Self {
            wait_chain: ListEntry::new(),
            key_value: UnsafeCell::new(0),
            wait_semaphore: UnsafeCell::new(KSemaphore::new()),
            in_use: AtomicBool::new(false),
        }
    }

    /// Initialize the entry
    pub fn init(&mut self) {
        self.wait_chain.init_head();
        unsafe {
            *self.key_value.get() = 0;
            (*self.wait_semaphore.get()).init(0, 1);
        }
        self.in_use.store(false, Ordering::Release);
    }
}

impl Default for KeyedWaitEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global keyed event pool
// ============================================================================

/// Static pool of keyed event objects
static KEYED_EVENT_POOL: [KeyedEventObject; MAX_KEYED_EVENT_OBJECTS] = {
    const INIT: KeyedEventObject = KeyedEventObject::new();
    [INIT; MAX_KEYED_EVENT_OBJECTS]
};

/// Bitmap for allocated keyed events
static KEYED_EVENT_BITMAP: AtomicU64 = AtomicU64::new(0);

use core::sync::atomic::AtomicU64;

/// The global fallback keyed event for critical sections
static mut CRIT_SEC_KEYED_EVENT_INDEX: Option<u32> = None;

/// Allocate a keyed event object from the pool
fn allocate_keyed_event() -> Option<&'static KeyedEventObject> {
    loop {
        let bitmap = KEYED_EVENT_BITMAP.load(Ordering::Acquire);

        // Find first zero bit
        let idx = (!bitmap).trailing_zeros() as usize;
        if idx >= MAX_KEYED_EVENT_OBJECTS {
            return None; // All slots used
        }

        let new_bitmap = bitmap | (1u64 << idx);
        if KEYED_EVENT_BITMAP.compare_exchange_weak(
            bitmap, new_bitmap, Ordering::AcqRel, Ordering::Relaxed
        ).is_ok() {
            // Got a slot - initialize it
            let obj = unsafe {
                let ptr = &KEYED_EVENT_POOL[idx] as *const KeyedEventObject as *mut KeyedEventObject;
                (*ptr).init(idx as u32);
                &*ptr
            };
            return Some(obj);
        }
        // CAS failed, retry
    }
}

/// Free a keyed event object back to the pool
fn free_keyed_event(obj: &KeyedEventObject) {
    let idx = obj.index as usize;
    if idx < MAX_KEYED_EVENT_OBJECTS {
        loop {
            let bitmap = KEYED_EVENT_BITMAP.load(Ordering::Acquire);
            let new_bitmap = bitmap & !(1u64 << idx);
            if KEYED_EVENT_BITMAP.compare_exchange_weak(
                bitmap, new_bitmap, Ordering::AcqRel, Ordering::Relaxed
            ).is_ok() {
                break;
            }
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Create a new keyed event object (NtCreateKeyedEvent equivalent)
pub fn exp_create_keyed_event() -> Option<&'static KeyedEventObject> {
    allocate_keyed_event()
}

/// Reference a keyed event object by index
pub fn exp_reference_keyed_event(index: u32) -> Option<&'static KeyedEventObject> {
    if (index as usize) < MAX_KEYED_EVENT_OBJECTS {
        let obj = &KEYED_EVENT_POOL[index as usize];
        if obj.is_valid() {
            obj.add_ref();
            return Some(obj);
        }
    }
    None
}

/// Dereference a keyed event object
pub fn exp_dereference_keyed_event(obj: &KeyedEventObject) {
    if obj.release() == 0 {
        free_keyed_event(obj);
    }
}

/// Release a keyed event waiter with matching key (NtReleaseKeyedEvent equivalent)
///
/// # Arguments
/// * `obj` - The keyed event object
/// * `key_value` - The key to match against
/// * `wait_entry` - The current thread's wait entry (for if we need to wait)
///
/// # Returns
/// * `Ok(())` - Successfully released a waiter or was released ourselves
/// * `Err(())` - No matching waiter found and timeout expired
pub unsafe fn exp_release_keyed_event(
    obj: &KeyedEventObject,
    key_value: usize,
    wait_entry: &KeyedWaitEntry,
) -> Result<(), ()> {
    if (key_value & KEYVALUE_RELEASE) != 0 {
        return Err(()); // Invalid key value
    }

    let irq = obj.lock.acquire();
    let list = &mut *obj.wait_queue.get();

    // Search for a matching waiter
    let mut current = list.flink;
    let mut found = false;

    while !core::ptr::eq(current, list as *const ListEntry as *mut ListEntry) {
        let entry = containing_record!(current, KeyedWaitEntry, wait_chain);
        let entry_key = *(*entry).key_value.get();

        // Only match waiters (not release waiters) with matching key
        if (entry_key & KEYVALUE_RELEASE) == 0 && entry_key == key_value {
            // Found a matching waiter - remove it and wake it up
            (*current).remove_entry();
            (*entry).wait_chain.init_head();

            // Release the waiter's semaphore
            let sem = &mut *(*entry).wait_semaphore.get();
            sem.release(1);

            found = true;
            break;
        }
        current = (*current).flink;
    }

    if !found {
        // No matching waiter - we need to wait ourselves
        // Mark ourselves as a release waiter (set low bit)
        *wait_entry.key_value.get() = key_value | KEYVALUE_RELEASE;

        // Insert at head (release waiters go first for efficient searching)
        let wait_entry_ptr = wait_entry as *const KeyedWaitEntry as *mut KeyedWaitEntry;
        list.insert_head(&mut (*wait_entry_ptr).wait_chain);

        obj.lock.release(irq);

        // Wait on our semaphore for a matching waiter to arrive
        let sem = &*wait_entry.wait_semaphore.get();
        sem.wait();

        return Ok(());
    }

    obj.lock.release(irq);
    Ok(())
}

/// Wait for a keyed event release (NtWaitForKeyedEvent equivalent)
///
/// # Arguments
/// * `obj` - The keyed event object
/// * `key_value` - The key to match against
/// * `wait_entry` - The current thread's wait entry
///
/// # Returns
/// * `Ok(())` - Successfully matched with a releaser
/// * `Err(())` - Timeout or error
pub unsafe fn exp_wait_for_keyed_event(
    obj: &KeyedEventObject,
    key_value: usize,
    wait_entry: &KeyedWaitEntry,
) -> Result<(), ()> {
    if (key_value & KEYVALUE_RELEASE) != 0 {
        return Err(()); // Invalid key value
    }

    let irq = obj.lock.acquire();
    let list = &mut *obj.wait_queue.get();

    // Search for a matching release waiter
    let mut current = list.flink;
    let release_key = key_value | KEYVALUE_RELEASE;
    let mut found = false;

    while !core::ptr::eq(current, list as *const ListEntry as *mut ListEntry) {
        let entry = containing_record!(current, KeyedWaitEntry, wait_chain);
        let entry_key = *(*entry).key_value.get();

        // Only match release waiters (low bit set) with matching key
        if entry_key == release_key {
            // Found a matching release waiter - remove it and wake it up
            (*current).remove_entry();
            (*entry).wait_chain.init_head();

            // Release the waiter's semaphore
            let sem = &mut *(*entry).wait_semaphore.get();
            sem.release(1);

            found = true;
            break;
        }

        // Stop searching if we hit non-release waiters
        if (entry_key & KEYVALUE_RELEASE) == 0 {
            break;
        }

        current = (*current).flink;
    }

    if !found {
        // No matching release waiter - we need to wait
        *wait_entry.key_value.get() = key_value;

        // Insert at tail (waiters go at the end)
        let wait_entry_ptr = wait_entry as *const KeyedWaitEntry as *mut KeyedWaitEntry;
        list.insert_tail(&mut (*wait_entry_ptr).wait_chain);

        obj.lock.release(irq);

        // Wait on our semaphore for a matching releaser to arrive
        let sem = &*wait_entry.wait_semaphore.get();
        sem.wait();

        return Ok(());
    }

    obj.lock.release(irq);
    Ok(())
}

/// Get the global critical section keyed event
pub fn exp_get_crit_sec_keyed_event() -> Option<&'static KeyedEventObject> {
    unsafe {
        if let Some(idx) = CRIT_SEC_KEYED_EVENT_INDEX {
            exp_reference_keyed_event(idx)
        } else {
            None
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the keyed event subsystem
pub fn keyed_event_init() {
    // Create the global critical section keyed event
    if let Some(obj) = exp_create_keyed_event() {
        unsafe {
            CRIT_SEC_KEYED_EVENT_INDEX = Some(obj.index);
        }
        crate::serial_println!("[EX] Keyed events initialized (CritSecOutOfMemoryEvent: {})", obj.index);
    } else {
        panic!("Failed to create global keyed event");
    }
}

// ============================================================================
// Inspection Functions
// ============================================================================

/// Keyed event statistics
#[derive(Debug, Clone, Copy)]
pub struct KeyedEventStats {
    /// Maximum keyed events
    pub max_keyed_events: usize,
    /// Allocated keyed events
    pub allocated_count: usize,
    /// Free keyed events
    pub free_count: usize,
    /// Global CritSec keyed event index
    pub critsec_event_index: Option<u32>,
}

/// Get keyed event statistics
pub fn get_keyed_event_stats() -> KeyedEventStats {
    let bitmap = KEYED_EVENT_BITMAP.load(Ordering::Acquire);
    let allocated = bitmap.count_ones() as usize;

    KeyedEventStats {
        max_keyed_events: MAX_KEYED_EVENT_OBJECTS,
        allocated_count: allocated,
        free_count: MAX_KEYED_EVENT_OBJECTS - allocated,
        critsec_event_index: unsafe { CRIT_SEC_KEYED_EVENT_INDEX },
    }
}

/// Keyed event snapshot for inspection
#[derive(Clone, Copy)]
pub struct KeyedEventSnapshot {
    /// Index in pool
    pub index: u32,
    /// Reference count
    pub ref_count: u32,
    /// Is valid/active
    pub active: bool,
}

impl KeyedEventSnapshot {
    pub const fn empty() -> Self {
        Self {
            index: 0,
            ref_count: 0,
            active: false,
        }
    }
}

/// Get snapshots of allocated keyed events
pub fn get_keyed_event_snapshots(max_count: usize) -> ([KeyedEventSnapshot; 16], usize) {
    let mut snapshots = [KeyedEventSnapshot::empty(); 16];
    let mut count = 0;

    let limit = max_count.min(16).min(MAX_KEYED_EVENT_OBJECTS);
    let bitmap = KEYED_EVENT_BITMAP.load(Ordering::Acquire);

    for i in 0..MAX_KEYED_EVENT_OBJECTS {
        if count >= limit {
            break;
        }

        if (bitmap & (1u64 << i)) != 0 {
            let obj = &KEYED_EVENT_POOL[i];
            snapshots[count] = KeyedEventSnapshot {
                index: i as u32,
                ref_count: obj.ref_count.load(Ordering::Relaxed),
                active: obj.is_valid(),
            };
            count += 1;
        }
    }

    (snapshots, count)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyed_event_creation() {
        // This test would need proper initialization
    }
}
