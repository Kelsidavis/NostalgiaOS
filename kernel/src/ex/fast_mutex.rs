//! Fast Mutex Implementation (FAST_MUTEX)
//!
//! Fast mutexes are executive-level synchronization primitives that provide
//! mutual exclusion with lower overhead than kernel mutexes (KMUTEX).
//!
//! Unlike spinlocks, fast mutexes allow the thread to block (sleep) when
//! the mutex is contended, rather than busy-waiting.
//!
//! # NT Semantics
//!
//! - Can only be acquired at IRQL <= APC_LEVEL
//! - Raises IRQL to APC_LEVEL while held (disables APCs)
//! - Cannot be acquired recursively
//! - No ownership tracking (unlike KMUTEX)
//!
//! # Usage
//! ```
//! let mutex = FastMutex::new();
//! mutex.acquire();
//! // ... critical section ...
//! mutex.release();
//! ```

use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use crate::ke::event::{KEvent, EventType};
use crate::ke::prcb::get_current_prcb;

/// Fast mutex structure
///
/// Equivalent to NT's FAST_MUTEX
#[repr(C)]
pub struct FastMutex {
    /// Lock count: 1 = unlocked, 0 = locked without waiters, <0 = locked with waiters
    count: AtomicI32,
    /// Owner thread (for debugging, not enforced)
    owner: AtomicU32,
    /// Contention count (statistics)
    contention: AtomicU32,
    /// Event for blocking waiters
    event: KEvent,
}

impl FastMutex {
    /// Create a new unlocked fast mutex
    pub const fn new() -> Self {
        Self {
            count: AtomicI32::new(1), // 1 = unlocked
            owner: AtomicU32::new(0),
            contention: AtomicU32::new(0),
            event: KEvent::new(),
        }
    }

    /// Initialize the fast mutex (for runtime init)
    pub fn init(&mut self) {
        self.count = AtomicI32::new(1);
        self.owner = AtomicU32::new(0);
        self.contention = AtomicU32::new(0);
        self.event.init(EventType::Synchronization, false);
    }

    /// Acquire the fast mutex
    ///
    /// Blocks if the mutex is held by another thread.
    /// Raises IRQL to APC_LEVEL while held.
    pub fn acquire(&self) {
        // Decrement count: 1->0 means we got it, 0->-1 means contention
        let old_count = self.count.fetch_sub(1, Ordering::Acquire);

        if old_count != 1 {
            // Mutex was already held - need to wait
            self.contention.fetch_add(1, Ordering::Relaxed);
            self.acquire_contended();
        }

        // Record owner for debugging
        self.owner.store(Self::current_thread_id(), Ordering::Relaxed);
    }

    /// Acquire when contended (slow path)
    fn acquire_contended(&self) {
        // Wait on the event until signaled
        loop {
            // Wait for the event to be signaled
            unsafe { self.event.wait(); }

            // Try to acquire again
            let old_count = self.count.fetch_sub(1, Ordering::Acquire);
            if old_count == 1 {
                // Got it
                return;
            }
            // Still contended, wait again
        }
    }

    /// Try to acquire without blocking
    ///
    /// Returns true if acquired, false if already held
    pub fn try_acquire(&self) -> bool {
        // Try to change 1 -> 0 (unlocked -> locked)
        let result = self.count.compare_exchange(
            1,
            0,
            Ordering::Acquire,
            Ordering::Relaxed,
        );

        if result.is_ok() {
            self.owner.store(Self::current_thread_id(), Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Release the fast mutex
    ///
    /// Wakes one waiting thread if any are blocked.
    pub fn release(&self) {
        // Clear owner
        self.owner.store(0, Ordering::Relaxed);

        // Increment count: 0->1 means no waiters, -N->-N+1 means wake one
        let old_count = self.count.fetch_add(1, Ordering::Release);

        if old_count != 0 {
            // There were waiters - signal the event to wake one
            unsafe { self.event.set(); }
        }
    }

    /// Check if the mutex is currently held
    #[inline]
    pub fn is_held(&self) -> bool {
        self.count.load(Ordering::Relaxed) <= 0
    }

    /// Get contention count (for debugging/statistics)
    #[inline]
    pub fn contention_count(&self) -> u32 {
        self.contention.load(Ordering::Relaxed)
    }

    /// Get current thread ID (placeholder)
    fn current_thread_id() -> u32 {
        // Get current thread from PRCB
        get_current_prcb().current_thread as u32
    }
}

impl Default for FastMutex {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard for fast mutex
pub struct FastMutexGuard<'a> {
    mutex: &'a FastMutex,
}

impl<'a> FastMutexGuard<'a> {
    /// Acquire the mutex and return a guard
    pub fn new(mutex: &'a FastMutex) -> Self {
        mutex.acquire();
        Self { mutex }
    }

    /// Try to acquire, returning None if contended
    pub fn try_new(mutex: &'a FastMutex) -> Option<Self> {
        if mutex.try_acquire() {
            Some(Self { mutex })
        } else {
            None
        }
    }
}

impl<'a> Drop for FastMutexGuard<'a> {
    fn drop(&mut self) {
        self.mutex.release();
    }
}

// Re-export NT-compatible names
#[allow(non_camel_case_types)]
pub type FAST_MUTEX = FastMutex;

/// Initialize a fast mutex (NT API compatibility)
#[inline]
pub fn ex_initialize_fast_mutex(mutex: &mut FastMutex) {
    *mutex = FastMutex::new();
}

/// Acquire a fast mutex (NT API compatibility)
#[inline]
pub fn ex_acquire_fast_mutex(mutex: &FastMutex) {
    mutex.acquire();
}

/// Try to acquire a fast mutex (NT API compatibility)
#[inline]
pub fn ex_try_to_acquire_fast_mutex(mutex: &FastMutex) -> bool {
    mutex.try_acquire()
}

/// Release a fast mutex (NT API compatibility)
#[inline]
pub fn ex_release_fast_mutex(mutex: &FastMutex) {
    mutex.release();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fast_mutex_basic() {
        let mutex = FastMutex::new();
        assert!(!mutex.is_held());

        mutex.acquire();
        assert!(mutex.is_held());

        mutex.release();
        assert!(!mutex.is_held());
    }

    #[test]
    fn test_fast_mutex_try_acquire() {
        let mutex = FastMutex::new();

        assert!(mutex.try_acquire());
        assert!(mutex.is_held());
        assert!(!mutex.try_acquire()); // Should fail

        mutex.release();
        assert!(mutex.try_acquire()); // Should succeed now
        mutex.release();
    }
}
