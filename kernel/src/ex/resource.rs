//! Executive Resource (ERESOURCE) Implementation
//!
//! ERESOURCEs are full-featured reader-writer locks with ownership tracking,
//! recursive acquisition support, and waiter management.
//!
//! # NT Semantics
//!
//! - Supports exclusive (write) and shared (read) access
//! - Allows recursive acquisition by the same thread
//! - Tracks owner thread for exclusive access
//! - Supports shared-to-exclusive upgrade (with care)
//! - Provides waiter counts and priority boosting
//!
//! # Usage
//! ```
//! let resource = EResource::new();
//! resource.init();
//!
//! // Exclusive access
//! resource.acquire_exclusive(true);
//! // ... write critical section ...
//! resource.release();
//!
//! // Shared access
//! resource.acquire_shared(true);
//! // ... read critical section ...
//! resource.release();
//! ```

use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicPtr, Ordering};
use crate::ke::thread::KThread;
use crate::ke::prcb::get_current_prcb;
use crate::ke::event::{KEvent, EventType};
use crate::ke::list::ListEntry;

/// Maximum number of shared waiters to track individually
const MAX_SHARED_WAITERS: usize = 4;

/// Resource flags
const RESOURCE_FLAG_EXCLUSIVE_WAITER: u32 = 0x1;
const RESOURCE_FLAG_SHARED_WAITER: u32 = 0x2;

/// Executive Resource structure
///
/// Equivalent to NT's ERESOURCE
#[repr(C)]
pub struct EResource {
    /// List of shared owners (for debugging)
    system_resource_list: ListEntry,

    /// Owner of exclusive access (NULL if not exclusively held)
    owner_thread: AtomicPtr<KThread>,

    /// Count of active locks:
    /// - Positive: number of shared owners
    /// - Negative: exclusively owned (absolute value is recursion count)
    /// - Zero: not locked
    active_count: AtomicI32,

    /// Flags (RESOURCE_FLAG_*)
    flags: AtomicU32,

    /// Number of threads waiting for shared access
    shared_waiters: AtomicU32,

    /// Number of threads waiting for exclusive access
    exclusive_waiters: AtomicU32,

    /// Event for exclusive waiters
    exclusive_wait_event: KEvent,

    /// Event for shared waiters
    shared_wait_event: KEvent,

    /// Number of times current owner acquired the resource
    owner_count: AtomicU32,

    /// Statistics: total acquisitions
    contention_count: AtomicU32,
}

// Safety: EResource is designed for multi-threaded access
unsafe impl Sync for EResource {}
unsafe impl Send for EResource {}

impl EResource {
    /// Create a new uninitialized resource
    pub const fn new() -> Self {
        Self {
            system_resource_list: ListEntry::new(),
            owner_thread: AtomicPtr::new(ptr::null_mut()),
            active_count: AtomicI32::new(0),
            flags: AtomicU32::new(0),
            shared_waiters: AtomicU32::new(0),
            exclusive_waiters: AtomicU32::new(0),
            exclusive_wait_event: KEvent::new(),
            shared_wait_event: KEvent::new(),
            owner_count: AtomicU32::new(0),
            contention_count: AtomicU32::new(0),
        }
    }

    /// Initialize the resource
    pub fn init(&mut self) {
        self.system_resource_list.init_head();
        self.owner_thread.store(ptr::null_mut(), Ordering::Relaxed);
        self.active_count.store(0, Ordering::Relaxed);
        self.flags.store(0, Ordering::Relaxed);
        self.shared_waiters.store(0, Ordering::Relaxed);
        self.exclusive_waiters.store(0, Ordering::Relaxed);
        self.exclusive_wait_event.init(EventType::Synchronization, false);
        self.shared_wait_event.init(EventType::Synchronization, false);
        self.owner_count.store(0, Ordering::Relaxed);
        self.contention_count.store(0, Ordering::Relaxed);
    }

    /// Get the current thread pointer
    fn current_thread() -> *mut KThread {
        get_current_prcb().current_thread
    }

    /// Acquire the resource exclusively (write lock)
    ///
    /// # Arguments
    /// * `wait` - If true, wait for the resource; if false, fail immediately
    ///
    /// Returns true if acquired, false if couldn't acquire (wait=false only)
    pub fn acquire_exclusive(&self, wait: bool) -> bool {
        let current = Self::current_thread();
        let owner = self.owner_thread.load(Ordering::Relaxed);

        // Check for recursive acquisition
        if owner == current {
            // Already own it exclusively - increment recursion count
            self.active_count.fetch_sub(1, Ordering::Relaxed);
            self.owner_count.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        // Try to acquire
        loop {
            let active = self.active_count.load(Ordering::Relaxed);

            if active == 0 {
                // Resource is free - try to acquire
                if self.active_count.compare_exchange_weak(
                    0,
                    -1,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                ).is_ok() {
                    // Got it
                    self.owner_thread.store(current, Ordering::Release);
                    self.owner_count.store(1, Ordering::Relaxed);
                    return true;
                }
                continue;
            }

            // Resource is held - need to wait or fail
            if !wait {
                return false;
            }

            // Increment waiter count and wait
            self.contention_count.fetch_add(1, Ordering::Relaxed);
            self.exclusive_waiters.fetch_add(1, Ordering::Relaxed);
            self.flags.fetch_or(RESOURCE_FLAG_EXCLUSIVE_WAITER, Ordering::Relaxed);

            // Wait for the event
            unsafe { self.exclusive_wait_event.wait(); }

            // Decrement waiter count
            let waiters = self.exclusive_waiters.fetch_sub(1, Ordering::Relaxed);
            if waiters == 1 {
                self.flags.fetch_and(!RESOURCE_FLAG_EXCLUSIVE_WAITER, Ordering::Relaxed);
            }

            // Try again
        }
    }

    /// Try to acquire exclusively without waiting
    pub fn try_acquire_exclusive(&self) -> bool {
        self.acquire_exclusive(false)
    }

    /// Acquire the resource in shared mode (read lock)
    ///
    /// # Arguments
    /// * `wait` - If true, wait for the resource; if false, fail immediately
    ///
    /// Returns true if acquired, false if couldn't acquire (wait=false only)
    pub fn acquire_shared(&self, wait: bool) -> bool {
        let current = Self::current_thread();

        loop {
            let active = self.active_count.load(Ordering::Relaxed);
            let owner = self.owner_thread.load(Ordering::Relaxed);

            // If we already own it exclusively, we can also read
            if owner == current {
                return true;
            }

            if active >= 0 {
                // Resource is free or has shared owners
                // Check if there are exclusive waiters
                if self.flags.load(Ordering::Relaxed) & RESOURCE_FLAG_EXCLUSIVE_WAITER != 0 {
                    // Let exclusive waiters go first (unless we're not waiting)
                    if !wait {
                        return false;
                    }
                    // Fall through to wait
                } else {
                    // Try to increment shared count
                    if self.active_count.compare_exchange_weak(
                        active,
                        active + 1,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    ).is_ok() {
                        return true;
                    }
                    continue;
                }
            }

            // Resource is exclusively held - need to wait or fail
            if !wait {
                return false;
            }

            // Increment waiter count and wait
            self.contention_count.fetch_add(1, Ordering::Relaxed);
            self.shared_waiters.fetch_add(1, Ordering::Relaxed);
            self.flags.fetch_or(RESOURCE_FLAG_SHARED_WAITER, Ordering::Relaxed);

            // Wait for the event
            unsafe { self.shared_wait_event.wait(); }

            // Decrement waiter count
            let waiters = self.shared_waiters.fetch_sub(1, Ordering::Relaxed);
            if waiters == 1 {
                self.flags.fetch_and(!RESOURCE_FLAG_SHARED_WAITER, Ordering::Relaxed);
            }

            // Try again
        }
    }

    /// Try to acquire shared without waiting
    pub fn try_acquire_shared(&self) -> bool {
        self.acquire_shared(false)
    }

    /// Release the resource
    ///
    /// Must be called once for each successful acquire.
    pub fn release(&self) {
        let current = Self::current_thread();
        let active = self.active_count.load(Ordering::Relaxed);

        if active < 0 {
            // Exclusive release
            let owner = self.owner_thread.load(Ordering::Relaxed);
            debug_assert!(owner == current, "Releasing exclusive lock not owned by current thread");

            let owner_count = self.owner_count.fetch_sub(1, Ordering::Relaxed);
            if owner_count > 1 {
                // Still recursively held
                self.active_count.fetch_add(1, Ordering::Relaxed);
                return;
            }

            // Final release
            self.owner_thread.store(ptr::null_mut(), Ordering::Release);
            self.active_count.store(0, Ordering::Release);

            // Wake waiters
            self.wake_waiters();
        } else if active > 0 {
            // Shared release
            let new_count = self.active_count.fetch_sub(1, Ordering::Release) - 1;

            if new_count == 0 {
                // Last shared owner - wake exclusive waiters
                self.wake_waiters();
            }
        }
    }

    /// Wake waiting threads
    fn wake_waiters(&self) {
        let flags = self.flags.load(Ordering::Relaxed);

        // Prefer exclusive waiters
        if flags & RESOURCE_FLAG_EXCLUSIVE_WAITER != 0 {
            unsafe { self.exclusive_wait_event.set(); }
        } else if flags & RESOURCE_FLAG_SHARED_WAITER != 0 {
            // Wake all shared waiters
            unsafe { self.shared_wait_event.set(); }
        }
    }

    /// Check if resource is held exclusively
    #[inline]
    pub fn is_acquired_exclusive(&self) -> bool {
        self.active_count.load(Ordering::Relaxed) < 0
    }

    /// Check if resource is held (exclusively or shared)
    #[inline]
    pub fn is_acquired(&self) -> bool {
        self.active_count.load(Ordering::Relaxed) != 0
    }

    /// Check if resource is held in shared mode
    #[inline]
    pub fn is_acquired_shared(&self) -> bool {
        self.active_count.load(Ordering::Relaxed) > 0
    }

    /// Get the exclusive owner thread (or null)
    #[inline]
    pub fn owner(&self) -> *mut KThread {
        self.owner_thread.load(Ordering::Relaxed)
    }

    /// Get the number of shared owners
    #[inline]
    pub fn shared_count(&self) -> u32 {
        let active = self.active_count.load(Ordering::Relaxed);
        if active > 0 { active as u32 } else { 0 }
    }

    /// Get the contention count (for statistics)
    #[inline]
    pub fn contention_count(&self) -> u32 {
        self.contention_count.load(Ordering::Relaxed)
    }

    /// Check if current thread owns the resource exclusively
    pub fn is_owned_exclusively(&self) -> bool {
        self.owner_thread.load(Ordering::Relaxed) == Self::current_thread()
    }

    /// Convert exclusive lock to shared lock
    ///
    /// Allows waiting shared readers to proceed while retaining a shared lock.
    pub fn convert_to_shared(&self) {
        let active = self.active_count.load(Ordering::Relaxed);
        if active >= 0 {
            return; // Not exclusively held
        }

        // Clear exclusive owner
        self.owner_thread.store(ptr::null_mut(), Ordering::Release);
        self.owner_count.store(0, Ordering::Relaxed);

        // Convert to single shared owner
        self.active_count.store(1, Ordering::Release);

        // Wake shared waiters
        if self.flags.load(Ordering::Relaxed) & RESOURCE_FLAG_SHARED_WAITER != 0 {
            unsafe { self.shared_wait_event.set(); }
        }
    }
}

impl Default for EResource {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard for exclusive resource access
pub struct EResourceExclusiveGuard<'a> {
    resource: &'a EResource,
}

impl<'a> EResourceExclusiveGuard<'a> {
    /// Acquire exclusive access and return a guard
    pub fn new(resource: &'a EResource) -> Self {
        resource.acquire_exclusive(true);
        Self { resource }
    }

    /// Try to acquire, returning None if contended
    pub fn try_new(resource: &'a EResource) -> Option<Self> {
        if resource.try_acquire_exclusive() {
            Some(Self { resource })
        } else {
            None
        }
    }
}

impl<'a> Drop for EResourceExclusiveGuard<'a> {
    fn drop(&mut self) {
        self.resource.release();
    }
}

/// RAII guard for shared resource access
pub struct EResourceSharedGuard<'a> {
    resource: &'a EResource,
}

impl<'a> EResourceSharedGuard<'a> {
    /// Acquire shared access and return a guard
    pub fn new(resource: &'a EResource) -> Self {
        resource.acquire_shared(true);
        Self { resource }
    }

    /// Try to acquire, returning None if contended
    pub fn try_new(resource: &'a EResource) -> Option<Self> {
        if resource.try_acquire_shared() {
            Some(Self { resource })
        } else {
            None
        }
    }
}

impl<'a> Drop for EResourceSharedGuard<'a> {
    fn drop(&mut self) {
        self.resource.release();
    }
}

// NT API compatibility type alias
#[allow(non_camel_case_types)]
pub type ERESOURCE = EResource;

/// Initialize an executive resource (NT API compatibility)
#[inline]
pub fn ex_initialize_resource(resource: &mut EResource) {
    resource.init();
}

/// Delete an executive resource (NT API compatibility)
#[inline]
pub fn ex_delete_resource(_resource: &mut EResource) {
    // Nothing to do - no dynamic allocations
}

/// Acquire resource exclusive (NT API compatibility)
#[inline]
pub fn ex_acquire_resource_exclusive(resource: &EResource, wait: bool) -> bool {
    resource.acquire_exclusive(wait)
}

/// Acquire resource shared (NT API compatibility)
#[inline]
pub fn ex_acquire_resource_shared(resource: &EResource, wait: bool) -> bool {
    resource.acquire_shared(wait)
}

/// Release resource (NT API compatibility)
#[inline]
pub fn ex_release_resource(resource: &EResource) {
    resource.release();
}

/// Check if resource is acquired exclusive (NT API compatibility)
#[inline]
pub fn ex_is_resource_acquired_exclusive(resource: &EResource) -> bool {
    resource.is_acquired_exclusive()
}

/// Check if resource is acquired shared (NT API compatibility)
#[inline]
pub fn ex_is_resource_acquired_shared(resource: &EResource) -> usize {
    resource.shared_count() as usize
}

/// Convert exclusive to shared (NT API compatibility)
#[inline]
pub fn ex_convert_exclusive_to_shared(resource: &EResource) {
    resource.convert_to_shared();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_exclusive() {
        let mut resource = EResource::new();
        resource.init();

        assert!(!resource.is_acquired());

        assert!(resource.acquire_exclusive(true));
        assert!(resource.is_acquired_exclusive());

        resource.release();
        assert!(!resource.is_acquired());
    }

    #[test]
    fn test_basic_shared() {
        let mut resource = EResource::new();
        resource.init();

        assert!(resource.acquire_shared(true));
        assert!(resource.is_acquired_shared());
        assert_eq!(resource.shared_count(), 1);

        assert!(resource.acquire_shared(true));
        assert_eq!(resource.shared_count(), 2);

        resource.release();
        resource.release();
        assert!(!resource.is_acquired());
    }

    #[test]
    fn test_try_acquire() {
        let mut resource = EResource::new();
        resource.init();

        assert!(resource.try_acquire_exclusive());
        assert!(!resource.try_acquire_exclusive()); // Would need same thread check
        assert!(!resource.try_acquire_shared());

        resource.release();
    }
}
