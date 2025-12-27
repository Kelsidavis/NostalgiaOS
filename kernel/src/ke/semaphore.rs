//! Kernel Semaphore Implementation (KSEMAPHORE)
//!
//! A semaphore is a synchronization object that maintains a count.
//! Multiple threads can acquire the semaphore as long as the count
//! is greater than zero. When the count reaches zero, waiting threads
//! block until another thread releases the semaphore.
//!
//! # Usage
//! ```
//! // Create a semaphore with initial count 3 and max 5
//! static SEM: KSemaphore = KSemaphore::new();
//! SEM.init(3, 5);
//!
//! // Thread acquires (decrements count)
//! SEM.wait();  // count: 3 -> 2
//!
//! // Thread releases (increments count)
//! SEM.release(1);  // count: 2 -> 3
//! ```
//!
//! # NT Compatibility
//! Equivalent to NT's KSEMAPHORE / KeInitializeSemaphore / KeReleaseSemaphore

use super::dispatcher::{DispatcherHeader, DispatcherType, KWaitBlock, WaitType};
use super::thread::{KThread, ThreadState};
use super::prcb::get_current_prcb_mut;
use super::scheduler;
use crate::containing_record;

/// Kernel Semaphore
///
/// Equivalent to NT's KSEMAPHORE
#[repr(C)]
pub struct KSemaphore {
    /// Dispatcher header (must be first for casting)
    /// signal_state holds the current count
    pub header: DispatcherHeader,
    /// Maximum count limit
    limit: i32,
}

// Safety: KSemaphore is designed for multi-threaded access
unsafe impl Sync for KSemaphore {}
unsafe impl Send for KSemaphore {}

impl KSemaphore {
    /// Create a new uninitialized semaphore
    pub const fn new() -> Self {
        Self {
            header: DispatcherHeader::new(DispatcherType::Semaphore),
            limit: 0,
        }
    }

    /// Initialize the semaphore
    ///
    /// # Arguments
    /// * `initial_count` - Starting count (number of available resources)
    /// * `limit` - Maximum count the semaphore can reach
    ///
    /// # Panics
    /// Panics if initial_count > limit or if either is negative
    pub fn init(&mut self, initial_count: i32, limit: i32) {
        assert!(initial_count >= 0, "initial_count must be non-negative");
        assert!(limit > 0, "limit must be positive");
        assert!(initial_count <= limit, "initial_count must not exceed limit");

        self.header.init(DispatcherType::Semaphore, initial_count);
        self.limit = limit;
    }

    /// Get the current count
    #[inline]
    pub fn count(&self) -> i32 {
        self.header.signal_state()
    }

    /// Get the maximum limit
    #[inline]
    pub fn limit(&self) -> i32 {
        self.limit
    }

    /// Check if the semaphore is signaled (count > 0)
    #[inline]
    pub fn is_signaled(&self) -> bool {
        self.header.is_signaled()
    }

    /// Wait (acquire) the semaphore
    ///
    /// Decrements the count by 1. If count is 0, blocks until
    /// another thread releases the semaphore.
    ///
    /// # Safety
    /// Must be called from thread context (not interrupt)
    pub unsafe fn wait(&self) {
        let prcb = get_current_prcb_mut();
        let current = prcb.current_thread;

        // Check if we can acquire immediately
        let count = self.header.signal_state();
        if count > 0 {
            // Decrement count
            self.header.set_signal_state(count - 1);
            return;
        }

        // Count is 0 - must wait
        self.wait_for_semaphore(current);
    }

    /// Try to acquire the semaphore without blocking
    ///
    /// Returns true if acquired, false if count was 0
    pub unsafe fn try_wait(&self) -> bool {
        let count = self.header.signal_state();
        if count > 0 {
            self.header.set_signal_state(count - 1);
            true
        } else {
            false
        }
    }

    /// Release the semaphore
    ///
    /// Increments the count by the specified amount.
    /// Wakes waiting threads if any.
    ///
    /// # Arguments
    /// * `release_count` - Amount to increment (usually 1)
    ///
    /// # Returns
    /// The previous count before releasing
    ///
    /// # Panics
    /// Panics if releasing would exceed the limit
    pub unsafe fn release(&self, release_count: i32) -> i32 {
        assert!(release_count > 0, "release_count must be positive");

        let old_count = self.header.signal_state();
        let new_count = old_count + release_count;

        assert!(new_count <= self.limit, "release would exceed semaphore limit");

        // If there are waiters and we're releasing, wake them
        let mut remaining = release_count;
        while remaining > 0 && self.header.has_waiters() {
            self.wake_one_waiter();
            remaining -= 1;
        }

        // Set the new count (remaining releases that didn't wake anyone)
        self.header.set_signal_state(old_count + remaining);

        old_count
    }

    /// Release one unit of the semaphore
    ///
    /// Convenience method equivalent to release(1)
    pub unsafe fn release_one(&self) -> i32 {
        self.release(1)
    }

    /// Internal: wait for semaphore to become available
    unsafe fn wait_for_semaphore(&self, thread: *mut KThread) {
        // Create wait block on stack
        let mut wait_block = KWaitBlock::new();
        wait_block.init(
            thread,
            &self.header as *const _ as *mut DispatcherHeader,
            WaitType::WaitAny,
        );

        // Add to semaphore's wait list
        self.header.wait_list().insert_tail(&mut wait_block.wait_list_entry);

        // Set thread state to waiting
        (*thread).state = ThreadState::Waiting;

        // Yield to scheduler
        scheduler::ki_dispatch_interrupt();

        // When we return, we've been woken up and own one unit
    }

    /// Internal: wake one waiting thread
    unsafe fn wake_one_waiter(&self) {
        if !self.header.has_waiters() {
            return;
        }

        // Remove first waiter
        let entry = self.header.wait_list().remove_head();
        let wait_block = containing_record!(entry, KWaitBlock, wait_list_entry);
        let thread = (*wait_block).thread;

        // The woken thread implicitly consumes one count
        // (we don't increment signal_state for this release)

        // Make thread ready
        (*thread).state = ThreadState::Ready;
        scheduler::ki_ready_thread(thread);
    }
}

impl Default for KSemaphore {
    fn default() -> Self {
        Self::new()
    }
}
