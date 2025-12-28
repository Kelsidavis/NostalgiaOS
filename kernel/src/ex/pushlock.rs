//! Push Lock Implementation (EX_PUSH_LOCK)
//!
//! Push locks are lightweight reader-writer locks optimized for
//! read-heavy workloads. They have lower overhead than ERESOURCEs.
//!
//! # NT Semantics
//!
//! - Single pointer-sized structure (very compact)
//! - Supports exclusive (write) and shared (read) acquisition
//! - Waiters "push" onto a wait list embedded in the lock
//! - Uses a single atomic operation for uncontended cases
//! - Cache-line friendly design
//!
//! # States
//!
//! The push lock uses a single usize with the following layout:
//! - Bit 0: Locked (1 = exclusive holder or waiting to acquire exclusive)
//! - Bit 1: Waiting (1 = there are waiters)
//! - Bit 2: Waking (1 = in the process of waking a waiter)
//! - Bit 3: Multiple shared (1 = multiple readers)
//! - Bits 4+: Share count (number of concurrent readers)
//!
//! # Usage
//! ```
//! let lock = ExPushLock::new();
//!
//! // Exclusive access
//! lock.acquire_exclusive();
//! // ... write critical section ...
//! lock.release_exclusive();
//!
//! // Shared access
//! lock.acquire_shared();
//! // ... read critical section ...
//! lock.release_shared();
//! ```

use core::sync::atomic::{AtomicUsize, Ordering};

/// Push lock bit flags
const EX_PUSH_LOCK_LOCKED: usize = 0x1;
const EX_PUSH_LOCK_WAITING: usize = 0x2;
const EX_PUSH_LOCK_WAKING: usize = 0x4;
const EX_PUSH_LOCK_MULTIPLE_SHARED: usize = 0x8;
const EX_PUSH_LOCK_SHARE_INC: usize = 0x10;

/// Mask for the share count portion
const EX_PUSH_LOCK_SHARE_MASK: usize = !0xF;

/// Push Lock structure
///
/// Equivalent to NT's EX_PUSH_LOCK
#[repr(C)]
pub struct ExPushLock {
    /// Combined lock state and wait list pointer
    value: AtomicUsize,
}

impl ExPushLock {
    /// Create a new unlocked push lock
    pub const fn new() -> Self {
        Self {
            value: AtomicUsize::new(0),
        }
    }

    /// Acquire the lock exclusively (write lock)
    ///
    /// Blocks until the lock is available.
    pub fn acquire_exclusive(&self) {
        // Fast path: try to set LOCKED bit from 0
        if self.value.compare_exchange(
            0,
            EX_PUSH_LOCK_LOCKED,
            Ordering::Acquire,
            Ordering::Relaxed,
        ).is_ok() {
            return;
        }

        // Slow path: contention
        self.acquire_exclusive_contended();
    }

    /// Slow path for exclusive acquisition
    fn acquire_exclusive_contended(&self) {
        loop {
            let current = self.value.load(Ordering::Relaxed);

            // If lock is free (no readers, not locked), try to acquire
            if current == 0 {
                if self.value.compare_exchange_weak(
                    0,
                    EX_PUSH_LOCK_LOCKED,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                ).is_ok() {
                    return;
                }
                continue;
            }

            // Lock is held - spin wait
            // In a real implementation, this would add to a wait list
            // and block the thread
            core::hint::spin_loop();
        }
    }

    /// Try to acquire the lock exclusively without blocking
    ///
    /// Returns true if acquired, false otherwise.
    pub fn try_acquire_exclusive(&self) -> bool {
        self.value.compare_exchange(
            0,
            EX_PUSH_LOCK_LOCKED,
            Ordering::Acquire,
            Ordering::Relaxed,
        ).is_ok()
    }

    /// Release an exclusively held lock
    pub fn release_exclusive(&self) {
        // Fast path: no waiters
        if self.value.compare_exchange(
            EX_PUSH_LOCK_LOCKED,
            0,
            Ordering::Release,
            Ordering::Relaxed,
        ).is_ok() {
            return;
        }

        // Slow path: there are waiters
        self.release_exclusive_contended();
    }

    /// Slow path for exclusive release
    fn release_exclusive_contended(&self) {
        // Clear the locked bit
        let old = self.value.fetch_and(!EX_PUSH_LOCK_LOCKED, Ordering::Release);

        // If there were waiters, we need to wake them
        if old & EX_PUSH_LOCK_WAITING != 0 {
            self.wake_waiters();
        }
    }

    /// Wake waiting threads
    fn wake_waiters(&self) {
        // In a full implementation, this would:
        // 1. Set the WAKING bit
        // 2. Walk the wait list
        // 3. Wake appropriate waiters (one exclusive or all shared)
        // 4. Clear WAKING and possibly WAITING bits
        //
        // For now, we just clear the WAITING bit
        self.value.fetch_and(!EX_PUSH_LOCK_WAITING, Ordering::Release);
    }

    /// Acquire the lock in shared mode (read lock)
    ///
    /// Multiple threads can hold shared access simultaneously.
    pub fn acquire_shared(&self) {
        // Fast path: lock is free or has only readers
        loop {
            let current = self.value.load(Ordering::Relaxed);

            // Check if we can acquire shared
            if current & EX_PUSH_LOCK_LOCKED == 0 {
                // No exclusive holder - try to increment share count
                let new_value = if current & EX_PUSH_LOCK_SHARE_MASK != 0 {
                    // Already have readers
                    current + EX_PUSH_LOCK_SHARE_INC
                } else {
                    // First reader
                    EX_PUSH_LOCK_SHARE_INC | EX_PUSH_LOCK_MULTIPLE_SHARED
                };

                if self.value.compare_exchange_weak(
                    current,
                    new_value,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                ).is_ok() {
                    return;
                }
            } else {
                // Exclusive holder exists - spin
                core::hint::spin_loop();
            }
        }
    }

    /// Try to acquire the lock in shared mode without blocking
    pub fn try_acquire_shared(&self) -> bool {
        let current = self.value.load(Ordering::Relaxed);

        // Check if we can acquire shared
        if current & EX_PUSH_LOCK_LOCKED != 0 {
            return false; // Exclusive holder exists
        }

        let new_value = if current & EX_PUSH_LOCK_SHARE_MASK != 0 {
            current + EX_PUSH_LOCK_SHARE_INC
        } else {
            EX_PUSH_LOCK_SHARE_INC | EX_PUSH_LOCK_MULTIPLE_SHARED
        };

        self.value.compare_exchange(
            current,
            new_value,
            Ordering::Acquire,
            Ordering::Relaxed,
        ).is_ok()
    }

    /// Release a shared lock
    pub fn release_shared(&self) {
        loop {
            let current = self.value.load(Ordering::Relaxed);
            let share_count = current & EX_PUSH_LOCK_SHARE_MASK;

            let new_value = if share_count == EX_PUSH_LOCK_SHARE_INC {
                // Last reader - clear share bits and MULTIPLE_SHARED
                current & !(EX_PUSH_LOCK_SHARE_MASK | EX_PUSH_LOCK_MULTIPLE_SHARED)
            } else {
                // Decrement reader count
                current - EX_PUSH_LOCK_SHARE_INC
            };

            if self.value.compare_exchange_weak(
                current,
                new_value,
                Ordering::Release,
                Ordering::Relaxed,
            ).is_ok() {
                // If this was the last reader and there are waiters, wake them
                if share_count == EX_PUSH_LOCK_SHARE_INC
                    && current & EX_PUSH_LOCK_WAITING != 0
                {
                    self.wake_waiters();
                }
                return;
            }
        }
    }

    /// Check if the lock is held exclusively
    #[inline]
    pub fn is_locked_exclusive(&self) -> bool {
        self.value.load(Ordering::Relaxed) & EX_PUSH_LOCK_LOCKED != 0
    }

    /// Check if the lock is held in shared mode
    #[inline]
    pub fn is_locked_shared(&self) -> bool {
        self.value.load(Ordering::Relaxed) & EX_PUSH_LOCK_SHARE_MASK != 0
    }

    /// Check if the lock has any waiters
    #[inline]
    pub fn has_waiters(&self) -> bool {
        self.value.load(Ordering::Relaxed) & EX_PUSH_LOCK_WAITING != 0
    }

    /// Get the current share count
    #[inline]
    pub fn share_count(&self) -> usize {
        (self.value.load(Ordering::Relaxed) & EX_PUSH_LOCK_SHARE_MASK) >> 4
    }
}

impl Default for ExPushLock {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard for exclusive push lock access
pub struct ExPushLockExclusiveGuard<'a> {
    lock: &'a ExPushLock,
}

impl<'a> ExPushLockExclusiveGuard<'a> {
    /// Acquire exclusive access and return a guard
    pub fn new(lock: &'a ExPushLock) -> Self {
        lock.acquire_exclusive();
        Self { lock }
    }

    /// Try to acquire, returning None if contended
    pub fn try_new(lock: &'a ExPushLock) -> Option<Self> {
        if lock.try_acquire_exclusive() {
            Some(Self { lock })
        } else {
            None
        }
    }
}

impl<'a> Drop for ExPushLockExclusiveGuard<'a> {
    fn drop(&mut self) {
        self.lock.release_exclusive();
    }
}

/// RAII guard for shared push lock access
pub struct ExPushLockSharedGuard<'a> {
    lock: &'a ExPushLock,
}

impl<'a> ExPushLockSharedGuard<'a> {
    /// Acquire shared access and return a guard
    pub fn new(lock: &'a ExPushLock) -> Self {
        lock.acquire_shared();
        Self { lock }
    }

    /// Try to acquire, returning None if contended
    pub fn try_new(lock: &'a ExPushLock) -> Option<Self> {
        if lock.try_acquire_shared() {
            Some(Self { lock })
        } else {
            None
        }
    }
}

impl<'a> Drop for ExPushLockSharedGuard<'a> {
    fn drop(&mut self) {
        self.lock.release_shared();
    }
}

// NT API compatibility type alias
#[allow(non_camel_case_types)]
pub type EX_PUSH_LOCK = ExPushLock;

/// Initialize a push lock (NT API compatibility)
#[inline]
pub fn ex_initialize_push_lock(lock: &mut ExPushLock) {
    *lock = ExPushLock::new();
}

/// Acquire push lock exclusive (NT API compatibility)
#[inline]
pub fn ex_acquire_push_lock_exclusive(lock: &ExPushLock) {
    lock.acquire_exclusive();
}

/// Release push lock exclusive (NT API compatibility)
#[inline]
pub fn ex_release_push_lock_exclusive(lock: &ExPushLock) {
    lock.release_exclusive();
}

/// Acquire push lock shared (NT API compatibility)
#[inline]
pub fn ex_acquire_push_lock_shared(lock: &ExPushLock) {
    lock.acquire_shared();
}

/// Release push lock shared (NT API compatibility)
#[inline]
pub fn ex_release_push_lock_shared(lock: &ExPushLock) {
    lock.release_shared();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exclusive_lock() {
        let lock = ExPushLock::new();

        assert!(!lock.is_locked_exclusive());

        lock.acquire_exclusive();
        assert!(lock.is_locked_exclusive());

        lock.release_exclusive();
        assert!(!lock.is_locked_exclusive());
    }

    #[test]
    fn test_shared_lock() {
        let lock = ExPushLock::new();

        assert_eq!(lock.share_count(), 0);

        lock.acquire_shared();
        assert!(lock.share_count() >= 1);

        lock.acquire_shared();
        assert!(lock.share_count() >= 2);

        lock.release_shared();
        lock.release_shared();
        assert_eq!(lock.share_count(), 0);
    }

    #[test]
    fn test_try_acquire() {
        let lock = ExPushLock::new();

        assert!(lock.try_acquire_exclusive());
        assert!(!lock.try_acquire_exclusive());
        assert!(!lock.try_acquire_shared());

        lock.release_exclusive();

        assert!(lock.try_acquire_shared());
        assert!(lock.try_acquire_shared());
        assert!(!lock.try_acquire_exclusive());

        lock.release_shared();
        lock.release_shared();
    }
}
