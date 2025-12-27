//! Kernel Mutex Implementation (KMUTEX)
//!
//! A mutex provides mutual exclusion with the ability to block
//! waiting threads. Unlike spinlocks, mutexes allow the thread
//! to sleep while waiting, freeing the CPU for other work.
//!
//! Features:
//! - Recursive locking (same thread can acquire multiple times)
//! - Priority inheritance (not yet implemented)
//! - Ownership tracking
//!
//! # Usage
//! ```
//! static MUTEX: KMutex = KMutex::new();
//!
//! // Initialize once
//! MUTEX.init();
//!
//! // Acquire (blocks if held by another thread)
//! MUTEX.acquire();
//!
//! // ... critical section ...
//!
//! // Release
//! MUTEX.release();
//! ```

use core::cell::UnsafeCell;
use core::ptr;
use super::dispatcher::{DispatcherHeader, DispatcherType, KWaitBlock, WaitType};
use super::thread::{KThread, ThreadState};
use super::prcb::get_current_prcb_mut;
use super::scheduler;
use crate::containing_record;

/// Kernel Mutex
///
/// Equivalent to NT's KMUTEX/KMUTANT
#[repr(C)]
pub struct KMutex {
    /// Dispatcher header (must be first for casting)
    pub header: DispatcherHeader,
    /// Owning thread (null if not owned)
    owner_thread: UnsafeCell<*mut KThread>,
    /// Recursion count (how many times owner has acquired)
    recursion_count: UnsafeCell<u32>,
    /// Whether this mutex was abandoned (owner terminated)
    abandoned: UnsafeCell<bool>,
}

// Safety: KMutex is designed for multi-threaded access
unsafe impl Sync for KMutex {}
unsafe impl Send for KMutex {}

impl KMutex {
    /// Create a new uninitialized mutex
    pub const fn new() -> Self {
        Self {
            header: DispatcherHeader::new(DispatcherType::Mutex),
            owner_thread: UnsafeCell::new(ptr::null_mut()),
            recursion_count: UnsafeCell::new(0),
            abandoned: UnsafeCell::new(false),
        }
    }

    /// Initialize the mutex
    ///
    /// Must be called before first use.
    pub fn init(&mut self) {
        // Mutex starts signaled (available)
        self.header.init(DispatcherType::Mutex, 1);
        unsafe {
            *self.owner_thread.get() = ptr::null_mut();
            *self.recursion_count.get() = 0;
            *self.abandoned.get() = false;
        }
    }

    /// Get the owning thread
    #[inline]
    pub fn owner(&self) -> *mut KThread {
        unsafe { *self.owner_thread.get() }
    }

    /// Check if the mutex is owned
    #[inline]
    pub fn is_owned(&self) -> bool {
        !self.owner().is_null()
    }

    /// Check if owned by the current thread
    #[inline]
    pub fn is_owned_by_current(&self) -> bool {
        let prcb = unsafe { get_current_prcb_mut() };
        self.owner() == prcb.current_thread
    }

    /// Acquire the mutex
    ///
    /// Blocks the calling thread until the mutex is available.
    /// If the current thread already owns the mutex, increments
    /// the recursion count.
    ///
    /// # Safety
    /// Must be called from thread context (not interrupt)
    pub unsafe fn acquire(&self) {
        let prcb = get_current_prcb_mut();
        let current = prcb.current_thread;

        // Check for recursive acquisition
        if self.owner() == current {
            *self.recursion_count.get() += 1;
            return;
        }

        // Try to acquire without waiting
        if self.header.signal_state() > 0 {
            // Mutex is available - take it
            self.header.set_signal_state(0);
            *self.owner_thread.get() = current;
            *self.recursion_count.get() = 1;
            return;
        }

        // Must wait - set up wait block and block thread
        self.wait_for_mutex(current);
    }

    /// Try to acquire the mutex without blocking
    ///
    /// Returns true if acquired, false if mutex is held by another thread
    pub unsafe fn try_acquire(&self) -> bool {
        let prcb = get_current_prcb_mut();
        let current = prcb.current_thread;

        // Check for recursive acquisition
        if self.owner() == current {
            *self.recursion_count.get() += 1;
            return true;
        }

        // Try to acquire
        if self.header.signal_state() > 0 {
            self.header.set_signal_state(0);
            *self.owner_thread.get() = current;
            *self.recursion_count.get() = 1;
            true
        } else {
            false
        }
    }

    /// Release the mutex
    ///
    /// Decrements recursion count. When count reaches 0, the mutex
    /// becomes available and the highest priority waiter is woken.
    ///
    /// # Panics
    /// Panics if called by a thread that doesn't own the mutex
    pub unsafe fn release(&self) {
        let prcb = get_current_prcb_mut();
        let current = prcb.current_thread;

        // Verify ownership
        if self.owner() != current {
            panic!("KMutex::release called by non-owner");
        }

        // Decrement recursion count
        let count = self.recursion_count.get();
        *count -= 1;

        if *count > 0 {
            // Still recursively held
            return;
        }

        // Fully released - clear ownership
        *self.owner_thread.get() = ptr::null_mut();

        // Check for waiters
        if self.header.has_waiters() {
            // Wake the first waiter (FIFO for now)
            self.wake_one_waiter();
        } else {
            // No waiters - mark as signaled
            self.header.set_signal_state(1);
        }
    }

    /// Internal: wait for the mutex to become available
    unsafe fn wait_for_mutex(&self, thread: *mut KThread) {
        // Create wait block on stack (will be valid while we're waiting)
        let mut wait_block = KWaitBlock::new();
        wait_block.init(
            thread,
            &self.header as *const _ as *mut DispatcherHeader,
            WaitType::WaitAny,
        );

        // Add to mutex's wait list
        self.header.wait_list().insert_tail(&mut wait_block.wait_list_entry);

        // Set thread state to waiting
        (*thread).state = ThreadState::Waiting;

        // Yield to scheduler - we'll be woken when mutex is available
        // The scheduler will pick another thread to run
        scheduler::ki_dispatch_interrupt();

        // When we return here, we own the mutex
        // (wake_one_waiter transferred ownership to us)
    }

    /// Internal: wake one waiting thread and transfer ownership
    unsafe fn wake_one_waiter(&self) {
        if !self.header.has_waiters() {
            return;
        }

        // Remove first waiter
        let entry = self.header.wait_list().remove_head();
        let wait_block = containing_record!(entry, KWaitBlock, wait_list_entry);
        let thread = (*wait_block).thread;

        // Transfer ownership to the woken thread
        *self.owner_thread.get() = thread;
        *self.recursion_count.get() = 1;
        // signal_state stays 0 (owned)

        // Make thread ready
        (*thread).state = ThreadState::Ready;
        scheduler::ki_ready_thread(thread);
    }
}

impl Default for KMutex {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII mutex guard for scoped locking
pub struct MutexGuard<'a> {
    mutex: &'a KMutex,
}

impl<'a> MutexGuard<'a> {
    /// Create a new guard by acquiring the mutex
    ///
    /// # Safety
    /// Must be called from thread context
    pub unsafe fn new(mutex: &'a KMutex) -> Self {
        mutex.acquire();
        Self { mutex }
    }
}

impl<'a> Drop for MutexGuard<'a> {
    fn drop(&mut self) {
        unsafe {
            self.mutex.release();
        }
    }
}
