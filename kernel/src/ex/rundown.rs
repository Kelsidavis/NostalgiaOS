//! Rundown Protection Implementation (EX_RUNDOWN_REF)
//!
//! Rundown protection is a mechanism that allows safe resource cleanup.
//! It tracks references to a resource and allows waiting until all
//! references are released before the resource can be safely destroyed.
//!
//! # NT Semantics
//!
//! - Used to protect objects during cleanup/teardown
//! - Acquiring a reference prevents rundown from completing
//! - After initiating rundown, new references fail
//! - The waiter blocks until all existing references are released
//!
//! # Usage
//! ```
//! let rundown = ExRundownRef::new();
//!
//! // Worker threads acquire references
//! if rundown.acquire() {
//!     // ... use the resource ...
//!     rundown.release();
//! }
//!
//! // During cleanup, wait for all references
//! rundown.wait_for_rundown();
//! // Now safe to destroy the resource
//! ```
//!
//! # States
//!
//! - Bit 0: Rundown active (new acquires will fail)
//! - Bits 1+: Reference count (shifted by 1)

use core::sync::atomic::{AtomicUsize, Ordering};

/// Bit indicating rundown is active
const EX_RUNDOWN_ACTIVE: usize = 0x1;

/// Increment value for reference count (bit 1+)
const EX_RUNDOWN_COUNT_INC: usize = 0x2;

/// Mask for the count portion
const EX_RUNDOWN_COUNT_MASK: usize = !EX_RUNDOWN_ACTIVE;

/// Rundown Reference structure
///
/// Equivalent to NT's EX_RUNDOWN_REF
#[repr(C)]
pub struct ExRundownRef {
    /// Combined rundown flag and reference count
    count: AtomicUsize,
}

impl ExRundownRef {
    /// Create a new rundown reference (not in rundown state)
    pub const fn new() -> Self {
        Self {
            count: AtomicUsize::new(0),
        }
    }

    /// Acquire a rundown reference
    ///
    /// Returns true if acquired successfully, false if rundown is active.
    /// If this returns true, you MUST call release() when done.
    pub fn acquire(&self) -> bool {
        loop {
            let current = self.count.load(Ordering::Relaxed);

            // Check if rundown is active
            if current & EX_RUNDOWN_ACTIVE != 0 {
                return false;
            }

            // Try to increment the reference count
            let new_value = current + EX_RUNDOWN_COUNT_INC;

            if self.count.compare_exchange_weak(
                current,
                new_value,
                Ordering::Acquire,
                Ordering::Relaxed,
            ).is_ok() {
                return true;
            }
        }
    }

    /// Try to acquire a rundown reference (non-blocking)
    ///
    /// Same as acquire() but may fail spuriously.
    pub fn try_acquire(&self) -> bool {
        let current = self.count.load(Ordering::Relaxed);

        if current & EX_RUNDOWN_ACTIVE != 0 {
            return false;
        }

        self.count.compare_exchange(
            current,
            current + EX_RUNDOWN_COUNT_INC,
            Ordering::Acquire,
            Ordering::Relaxed,
        ).is_ok()
    }

    /// Release a rundown reference
    ///
    /// Must be called exactly once for each successful acquire().
    pub fn release(&self) {
        let old = self.count.fetch_sub(EX_RUNDOWN_COUNT_INC, Ordering::Release);
        let new_count = (old - EX_RUNDOWN_COUNT_INC) & EX_RUNDOWN_COUNT_MASK;

        // If rundown is active and we were the last reference,
        // the waiter needs to be woken (handled by spin in wait_for_rundown)
        if old & EX_RUNDOWN_ACTIVE != 0 && new_count == 0 {
            // In a full implementation, we would signal a wait event here
            // The spin loop in wait_for_rundown will detect this
        }
    }

    /// Initiate rundown and wait for all references to be released
    ///
    /// After this returns:
    /// - All new acquire() calls will fail
    /// - All existing references have been released
    /// - The resource can be safely destroyed
    pub fn wait_for_rundown(&self) {
        // Set the rundown active bit
        let old = self.count.fetch_or(EX_RUNDOWN_ACTIVE, Ordering::AcqRel);

        // If there were no references, we're done
        if old & EX_RUNDOWN_COUNT_MASK == 0 {
            return;
        }

        // Wait for all references to be released
        loop {
            let current = self.count.load(Ordering::Acquire);

            // Check if all references are gone
            if current & EX_RUNDOWN_COUNT_MASK == 0 {
                return;
            }

            // Spin wait
            core::hint::spin_loop();
        }
    }

    /// Try to initiate rundown without waiting
    ///
    /// Returns true if there are no references and rundown is complete.
    /// Returns false if there are still references (rundown is now active
    /// but not complete).
    pub fn try_rundown(&self) -> bool {
        let old = self.count.fetch_or(EX_RUNDOWN_ACTIVE, Ordering::AcqRel);
        old & EX_RUNDOWN_COUNT_MASK == 0
    }

    /// Check if rundown is active
    #[inline]
    pub fn is_rundown_active(&self) -> bool {
        self.count.load(Ordering::Relaxed) & EX_RUNDOWN_ACTIVE != 0
    }

    /// Get the current reference count
    #[inline]
    pub fn reference_count(&self) -> usize {
        (self.count.load(Ordering::Relaxed) & EX_RUNDOWN_COUNT_MASK) >> 1
    }

    /// Re-initialize for reuse after rundown completed
    ///
    /// # Safety
    /// Only call this after wait_for_rundown() has returned AND
    /// no one else can access this object.
    pub unsafe fn reinitialize(&self) {
        self.count.store(0, Ordering::Release);
    }
}

impl Default for ExRundownRef {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard for rundown reference
///
/// Automatically releases the reference when dropped.
pub struct RundownGuard<'a> {
    rundown: &'a ExRundownRef,
}

impl<'a> RundownGuard<'a> {
    /// Try to acquire a rundown reference
    ///
    /// Returns Some(guard) if acquired, None if rundown is active.
    pub fn try_new(rundown: &'a ExRundownRef) -> Option<Self> {
        if rundown.acquire() {
            Some(Self { rundown })
        } else {
            None
        }
    }
}

impl<'a> Drop for RundownGuard<'a> {
    fn drop(&mut self) {
        self.rundown.release();
    }
}

// NT API compatibility type alias
#[allow(non_camel_case_types)]
pub type EX_RUNDOWN_REF = ExRundownRef;

/// Initialize rundown protection (NT API compatibility)
#[inline]
pub fn ex_initialize_rundown_protection(rundown: &mut ExRundownRef) {
    *rundown = ExRundownRef::new();
}

/// Acquire rundown protection (NT API compatibility)
#[inline]
pub fn ex_acquire_rundown_protection(rundown: &ExRundownRef) -> bool {
    rundown.acquire()
}

/// Release rundown protection (NT API compatibility)
#[inline]
pub fn ex_release_rundown_protection(rundown: &ExRundownRef) {
    rundown.release();
}

/// Wait for rundown protection (NT API compatibility)
#[inline]
pub fn ex_wait_for_rundown_protection_release(rundown: &ExRundownRef) {
    rundown.wait_for_rundown();
}

/// Re-initialize rundown protection (NT API compatibility)
///
/// # Safety
/// See ExRundownRef::reinitialize()
#[inline]
pub unsafe fn ex_reinitialize_rundown_protection(rundown: &ExRundownRef) {
    rundown.reinitialize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_rundown() {
        let rundown = ExRundownRef::new();

        // Acquire and release
        assert!(rundown.acquire());
        assert_eq!(rundown.reference_count(), 1);
        rundown.release();
        assert_eq!(rundown.reference_count(), 0);

        // Rundown with no references
        rundown.wait_for_rundown();
        assert!(rundown.is_rundown_active());

        // New acquires should fail
        assert!(!rundown.acquire());
    }

    #[test]
    fn test_multiple_references() {
        let rundown = ExRundownRef::new();

        assert!(rundown.acquire());
        assert!(rundown.acquire());
        assert!(rundown.acquire());
        assert_eq!(rundown.reference_count(), 3);

        rundown.release();
        assert_eq!(rundown.reference_count(), 2);

        rundown.release();
        rundown.release();
        assert_eq!(rundown.reference_count(), 0);
    }

    #[test]
    fn test_rundown_guard() {
        let rundown = ExRundownRef::new();

        {
            let _guard = RundownGuard::try_new(&rundown).unwrap();
            assert_eq!(rundown.reference_count(), 1);
        }

        assert_eq!(rundown.reference_count(), 0);
    }

    #[test]
    fn test_try_rundown() {
        let rundown = ExRundownRef::new();

        // Should succeed with no references
        assert!(rundown.try_rundown());
        assert!(rundown.is_rundown_active());
    }
}
