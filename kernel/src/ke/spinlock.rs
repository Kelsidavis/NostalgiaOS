//! Kernel Spinlock Implementation (KSPIN_LOCK)
//!
//! Spinlocks provide mutual exclusion for short critical sections.
//! They busy-wait (spin) until the lock becomes available.
//!
//! In NT, spinlocks raise IRQL to DISPATCH_LEVEL to prevent
//! preemption while holding the lock. For now, we disable
//! interrupts instead.
//!
//! # Usage
//! ```
//! let mut lock = SpinLock::new();
//! let guard = lock.acquire();
//! // ... critical section ...
//! // guard dropped, lock released
//! ```

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// A spinlock for mutual exclusion
///
/// Equivalent to NT's KSPIN_LOCK
#[repr(C)]
pub struct SpinLock<T> {
    /// Lock state (true = locked)
    locked: AtomicBool,
    /// Protected data
    data: UnsafeCell<T>,
}

// SpinLock is Sync if T is Send (data can be sent between threads)
unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Create a new unlocked spinlock
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    /// Acquire the spinlock, returning a guard that releases on drop
    ///
    /// This disables interrupts while the lock is held to prevent
    /// deadlock from interrupt handlers trying to acquire the same lock.
    #[inline]
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        // Disable interrupts and save previous state
        let interrupts_enabled = Self::disable_interrupts();

        // Spin until we acquire the lock
        while self.locked.compare_exchange_weak(
            false,
            true,
            Ordering::Acquire,
            Ordering::Relaxed,
        ).is_err() {
            // Spin with a hint to reduce power consumption
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }

        SpinLockGuard {
            lock: self,
            interrupts_enabled,
        }
    }

    /// Try to acquire the lock without blocking
    ///
    /// Returns Some(guard) if successful, None if lock is held
    #[inline]
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let interrupts_enabled = Self::disable_interrupts();

        if self.locked.compare_exchange(
            false,
            true,
            Ordering::Acquire,
            Ordering::Relaxed,
        ).is_ok() {
            Some(SpinLockGuard {
                lock: self,
                interrupts_enabled,
            })
        } else {
            // Failed to acquire - restore interrupts
            if interrupts_enabled {
                Self::enable_interrupts();
            }
            None
        }
    }

    /// Check if the lock is currently held
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }

    /// Disable interrupts and return whether they were enabled
    #[inline]
    fn disable_interrupts() -> bool {
        let flags: u64;
        unsafe {
            core::arch::asm!(
                "pushfq",
                "pop {0}",
                "cli",
                out(reg) flags,
                options(nomem, preserves_flags)
            );
        }
        // Check IF flag (bit 9)
        (flags & (1 << 9)) != 0
    }

    /// Enable interrupts
    #[inline]
    fn enable_interrupts() {
        unsafe {
            core::arch::asm!("sti", options(nomem, nostack));
        }
    }
}

/// RAII guard for spinlock
///
/// Releases the lock and restores interrupt state when dropped
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    interrupts_enabled: bool,
}

impl<'a, T> Deref for SpinLockGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        // Release the lock
        self.lock.locked.store(false, Ordering::Release);

        // Restore interrupt state
        if self.interrupts_enabled {
            SpinLock::<T>::enable_interrupts();
        }
    }
}

/// A raw spinlock without data protection
///
/// Use when you need to protect external data or need
/// more control over the critical section.
#[repr(C)]
pub struct RawSpinLock {
    locked: AtomicBool,
}

impl RawSpinLock {
    /// Create a new unlocked spinlock
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
        }
    }

    /// Acquire the lock
    ///
    /// Returns whether interrupts were enabled before acquiring
    #[inline]
    pub fn acquire(&self) -> bool {
        let interrupts_enabled = Self::disable_interrupts();

        while self.locked.compare_exchange_weak(
            false,
            true,
            Ordering::Acquire,
            Ordering::Relaxed,
        ).is_err() {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }

        interrupts_enabled
    }

    /// Release the lock
    ///
    /// # Arguments
    /// * `restore_interrupts` - Whether to restore interrupts (value from acquire)
    #[inline]
    pub fn release(&self, restore_interrupts: bool) {
        self.locked.store(false, Ordering::Release);

        if restore_interrupts {
            Self::enable_interrupts();
        }
    }

    /// Try to acquire without blocking
    #[inline]
    pub fn try_acquire(&self) -> Option<bool> {
        let interrupts_enabled = Self::disable_interrupts();

        if self.locked.compare_exchange(
            false,
            true,
            Ordering::Acquire,
            Ordering::Relaxed,
        ).is_ok() {
            Some(interrupts_enabled)
        } else {
            if interrupts_enabled {
                Self::enable_interrupts();
            }
            None
        }
    }

    #[inline]
    fn disable_interrupts() -> bool {
        let flags: u64;
        unsafe {
            core::arch::asm!(
                "pushfq",
                "pop {0}",
                "cli",
                out(reg) flags,
                options(nomem, preserves_flags)
            );
        }
        (flags & (1 << 9)) != 0
    }

    #[inline]
    fn enable_interrupts() {
        unsafe {
            core::arch::asm!("sti", options(nomem, nostack));
        }
    }
}

impl Default for RawSpinLock {
    fn default() -> Self {
        Self::new()
    }
}
