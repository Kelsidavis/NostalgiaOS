//! RTL Remove Lock
//!
//! Implements remove lock synchronization for driver I/O operations:
//! - Prevents device removal during outstanding I/O requests
//! - Reference counting with wait-for-zero semantics
//! - Used by PnP and I/O subsystems
//!
//! Based on Windows Server 2003 base/ntos/rtl/remlock.c

use core::sync::atomic::{AtomicI32, AtomicBool, Ordering};
use spin::Mutex;

/// Remove lock signature
pub const RTL_REMOVE_LOCK_SIG: u32 = 0x4C4D5452; // 'RTML'

/// Status codes
pub const STATUS_SUCCESS: i32 = 0;
pub const STATUS_DELETE_PENDING: i32 = -1073741738; // 0xC0000056

/// Remove lock tracking block (for debugging)
#[cfg(debug_assertions)]
#[derive(Debug)]
pub struct RtlRemoveLockTrackingBlock {
    /// Tag for this acquisition
    pub tag: usize,
    /// File where lock was acquired
    pub file: &'static str,
    /// Line number where lock was acquired
    pub line: u32,
    /// Time when lock was acquired (ticks)
    pub time_locked: u64,
    /// Next block in tracking list
    pub link: Option<*mut RtlRemoveLockTrackingBlock>,
}

/// Remove lock structure
#[repr(C)]
pub struct RtlRemoveLock {
    /// Signature for validation
    pub signature: u32,
    /// Whether device is being removed
    pub removed: AtomicBool,
    /// I/O operation count (reference count)
    pub io_count: AtomicI32,
    /// Event for signaling when count reaches zero
    pub remove_event: RemoveEvent,
    /// Debug tracking
    #[cfg(debug_assertions)]
    pub high_watermark: u32,
    #[cfg(debug_assertions)]
    pub max_locked_minutes: u32,
    #[cfg(debug_assertions)]
    pub allocate_tag: u32,
    #[cfg(debug_assertions)]
    pub spin: Mutex<()>,
    #[cfg(debug_assertions)]
    pub blocks: Mutex<Option<*mut RtlRemoveLockTrackingBlock>>,
}

/// Simple event for remove lock wait
pub struct RemoveEvent {
    signaled: AtomicBool,
}

impl RemoveEvent {
    pub const fn new() -> Self {
        Self {
            signaled: AtomicBool::new(false),
        }
    }

    pub fn set(&self) {
        self.signaled.store(true, Ordering::Release);
    }

    pub fn wait(&self) {
        // Busy-wait implementation (in a real kernel, this would be a proper wait)
        while !self.signaled.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }

    pub fn reset(&self) {
        self.signaled.store(false, Ordering::Release);
    }
}

impl RtlRemoveLock {
    /// Create a new remove lock
    pub const fn new() -> Self {
        Self {
            signature: RTL_REMOVE_LOCK_SIG,
            removed: AtomicBool::new(false),
            io_count: AtomicI32::new(1), // Start with 1 for the initial reference
            remove_event: RemoveEvent::new(),
            #[cfg(debug_assertions)]
            high_watermark: 0,
            #[cfg(debug_assertions)]
            max_locked_minutes: 0,
            #[cfg(debug_assertions)]
            allocate_tag: 0,
            #[cfg(debug_assertions)]
            spin: Mutex::new(()),
            #[cfg(debug_assertions)]
            blocks: Mutex::new(None),
        }
    }
}

/// Initialize a remove lock
pub fn rtl_init_remove_lock(
    lock: &mut RtlRemoveLock,
    _allocate_tag: u32,
    _max_locked_minutes: u32,
    _high_watermark: u32,
) {
    lock.signature = RTL_REMOVE_LOCK_SIG;
    lock.removed.store(false, Ordering::Release);
    lock.io_count.store(1, Ordering::Release);
    lock.remove_event.reset();

    #[cfg(debug_assertions)]
    {
        lock.high_watermark = _high_watermark;
        lock.max_locked_minutes = _max_locked_minutes;
        lock.allocate_tag = _allocate_tag;
    }
}

/// Acquire the remove lock
///
/// Returns STATUS_SUCCESS if the lock was acquired, STATUS_DELETE_PENDING
/// if the device is being removed.
pub fn rtl_acquire_remove_lock(
    lock: &RtlRemoveLock,
    _tag: usize,
) -> i32 {
    rtl_acquire_remove_lock_ex(lock, _tag, "", 0)
}

/// Acquire the remove lock with extended debugging info
pub fn rtl_acquire_remove_lock_ex(
    lock: &RtlRemoveLock,
    _tag: usize,
    _file: &str,
    _line: u32,
) -> i32 {
    debug_assert!(lock.signature == RTL_REMOVE_LOCK_SIG);

    // Increment the I/O count
    let lock_value = lock.io_count.fetch_add(1, Ordering::AcqRel) + 1;
    debug_assert!(lock_value > 0, "Remove lock count went negative");

    #[cfg(debug_assertions)]
    {
        if lock.high_watermark != 0 && lock_value > lock.high_watermark as i32 {
            crate::serial_println!(
                "[REMLOCK] Warning: Lock count {} exceeds high watermark {}",
                lock_value,
                lock.high_watermark
            );
        }
    }

    if !lock.removed.load(Ordering::Acquire) {
        // Lock acquired successfully
        STATUS_SUCCESS
    } else {
        // Device is being removed, release our reference
        let new_count = lock.io_count.fetch_sub(1, Ordering::AcqRel) - 1;
        if new_count == 0 {
            lock.remove_event.set();
        }
        STATUS_DELETE_PENDING
    }
}

/// Release the remove lock
pub fn rtl_release_remove_lock(
    lock: &RtlRemoveLock,
    _tag: usize,
) {
    debug_assert!(lock.signature == RTL_REMOVE_LOCK_SIG);

    let lock_value = lock.io_count.fetch_sub(1, Ordering::AcqRel) - 1;
    debug_assert!(lock_value >= 0, "Remove lock count went negative on release");

    if lock_value == 0 {
        // All references released, signal the remove event
        debug_assert!(
            lock.removed.load(Ordering::Acquire),
            "IO count zero but device not being removed"
        );
        lock.remove_event.set();
    }
}

/// Release the remove lock and wait for all outstanding I/O to complete
///
/// This should be called when the device is being removed. After this returns,
/// it is safe to delete the device.
pub fn rtl_release_remove_lock_and_wait(
    lock: &RtlRemoveLock,
    _tag: usize,
) {
    debug_assert!(lock.signature == RTL_REMOVE_LOCK_SIG);

    // Mark device as being removed
    lock.removed.store(true, Ordering::Release);

    // Release the caller's reference (from the acquire that preceded this call)
    let io_count = lock.io_count.fetch_sub(1, Ordering::AcqRel) - 1;
    debug_assert!(io_count >= 0);

    // Release the initial reference (from initialization)
    let io_count = lock.io_count.fetch_sub(1, Ordering::AcqRel) - 1;

    if io_count > 0 {
        // Wait for all outstanding I/O to complete
        lock.remove_event.wait();
    }
}

/// Check if the remove lock has been marked for removal
#[inline]
pub fn rtl_is_remove_pending(lock: &RtlRemoveLock) -> bool {
    lock.removed.load(Ordering::Acquire)
}

/// Get the current I/O count
#[inline]
pub fn rtl_get_remove_lock_count(lock: &RtlRemoveLock) -> i32 {
    lock.io_count.load(Ordering::Acquire)
}

/// Initialize remove lock subsystem
pub fn rtl_remlock_init() {
    crate::serial_println!("[RTL] Remove lock subsystem initialized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_acquire_release() {
        let mut lock = RtlRemoveLock::new();
        rtl_init_remove_lock(&mut lock, 0, 0, 0);

        // Acquire should succeed
        assert_eq!(rtl_acquire_remove_lock(&lock, 1), STATUS_SUCCESS);
        assert_eq!(rtl_get_remove_lock_count(&lock), 2); // Initial + our acquire

        // Release
        rtl_release_remove_lock(&lock, 1);
        assert_eq!(rtl_get_remove_lock_count(&lock), 1); // Just initial
    }

    #[test]
    fn test_acquire_after_removal() {
        let mut lock = RtlRemoveLock::new();
        rtl_init_remove_lock(&mut lock, 0, 0, 0);

        // Acquire once
        assert_eq!(rtl_acquire_remove_lock(&lock, 1), STATUS_SUCCESS);

        // Start removal
        lock.removed.store(true, Ordering::Release);

        // New acquire should fail
        assert_eq!(rtl_acquire_remove_lock(&lock, 2), STATUS_DELETE_PENDING);
    }
}
