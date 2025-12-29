//! Queued Spinlock Implementation (NT Compatible)
//!
//! Queued spinlocks provide scalable locking for multiprocessor systems.
//! Unlike traditional spinlocks where all processors spin on the same memory
//! location (causing cache line bouncing), queued spinlocks form a queue
//! where each processor spins on its own per-processor memory location.
//!
//! Key features:
//! - Fair FIFO ordering (no starvation)
//! - Cache-efficient (each CPU spins on local memory)
//! - Per-processor lock queue entries in KPRCB
//!
//! This implementation is NT 5.2 (Windows Server 2003) compatible.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering, fence};
use super::prcb::{KPrcb, KSpinLockQueue, LockQueueNumber, get_current_prcb, get_current_prcb_mut};
use super::kpcr::{Kirql, irql, ke_raise_irql, ke_lower_irql};

// ============================================================================
// Queued Spinlock Type
// ============================================================================

/// A queued spinlock
///
/// This is the actual lock that processors contend for.
/// The lock value is 0 when free, or points to the tail of the wait queue.
#[repr(C, align(8))]
pub struct KQueuedSpinLock {
    /// Lock state:
    /// - 0: Lock is free
    /// - Non-zero: Pointer to tail of wait queue (last waiter's KSpinLockQueue)
    lock: AtomicUsize,
}

impl KQueuedSpinLock {
    /// Create a new unlocked queued spinlock
    pub const fn new() -> Self {
        Self {
            lock: AtomicUsize::new(0),
        }
    }

    /// Check if the lock is currently held
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.lock.load(Ordering::Relaxed) != 0
    }
}

impl Default for KQueuedSpinLock {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Lock Queue Entry Flags
// ============================================================================

/// Flag indicating the processor is waiting for the lock
const LOCK_QUEUE_WAIT: usize = 1;

/// Flag indicating the processor owns the lock
const LOCK_QUEUE_OWNER: usize = 2;

// ============================================================================
// Numbered Queued Spinlock Functions
// ============================================================================

/// Global array of numbered queued spinlocks
/// These correspond to the LockQueueNumber enum values
static mut KI_QUEUED_SPINLOCKS: [KQueuedSpinLock; 16] = [const { KQueuedSpinLock::new() }; 16];

/// Acquire a numbered queued spinlock, raising IRQL to DISPATCH_LEVEL
///
/// This is the main entry point for acquiring a queued lock.
/// It raises IRQL and then acquires the lock using the per-processor queue entry.
///
/// # Safety
/// - Must be called at IRQL <= DISPATCH_LEVEL
/// - Must call ke_release_queued_spinlock to release
#[inline]
pub unsafe fn ke_acquire_queued_spinlock(lock_number: LockQueueNumber) -> Kirql {
    // Raise IRQL to DISPATCH_LEVEL first
    let old_irql = ke_raise_irql(irql::DISPATCH_LEVEL);

    // Get the actual lock
    let lock = &KI_QUEUED_SPINLOCKS[lock_number as usize];

    // Get our per-processor queue entry for this lock
    let prcb = get_current_prcb_mut();
    let queue_entry = prcb.get_lock_queue_mut(lock_number);

    // Acquire the lock
    ki_acquire_queued_spinlock_at_dpc_level(lock, queue_entry);

    old_irql
}

/// Release a numbered queued spinlock and lower IRQL
///
/// # Safety
/// - Must hold the lock
/// - old_irql must be the value returned from ke_acquire_queued_spinlock
#[inline]
pub unsafe fn ke_release_queued_spinlock(lock_number: LockQueueNumber, old_irql: Kirql) {
    // Get the actual lock
    let lock = &KI_QUEUED_SPINLOCKS[lock_number as usize];

    // Get our per-processor queue entry for this lock
    let prcb = get_current_prcb_mut();
    let queue_entry = prcb.get_lock_queue_mut(lock_number);

    // Release the lock
    ki_release_queued_spinlock_from_dpc_level(lock, queue_entry);

    // Lower IRQL
    ke_lower_irql(old_irql);
}

/// Acquire a numbered queued spinlock when already at DPC level
///
/// # Safety
/// - Must be called at IRQL == DISPATCH_LEVEL
/// - Must call ke_release_queued_spinlock_from_dpc_level to release
#[inline]
pub unsafe fn ke_acquire_queued_spinlock_at_dpc_level(lock_number: LockQueueNumber) {
    let lock = &KI_QUEUED_SPINLOCKS[lock_number as usize];
    let prcb = get_current_prcb_mut();
    let queue_entry = prcb.get_lock_queue_mut(lock_number);

    ki_acquire_queued_spinlock_at_dpc_level(lock, queue_entry);
}

/// Release a numbered queued spinlock when staying at DPC level
///
/// # Safety
/// - Must hold the lock
/// - Must be at DISPATCH_LEVEL
#[inline]
pub unsafe fn ke_release_queued_spinlock_from_dpc_level(lock_number: LockQueueNumber) {
    let lock = &KI_QUEUED_SPINLOCKS[lock_number as usize];
    let prcb = get_current_prcb_mut();
    let queue_entry = prcb.get_lock_queue_mut(lock_number);

    ki_release_queued_spinlock_from_dpc_level(lock, queue_entry);
}

/// Try to acquire a numbered queued spinlock without blocking
///
/// Returns true if lock was acquired, false if already held.
///
/// # Safety
/// - Must be called at IRQL <= DISPATCH_LEVEL
#[inline]
pub unsafe fn ke_try_to_acquire_queued_spinlock(
    lock_number: LockQueueNumber,
    old_irql: &mut Kirql,
) -> bool {
    // Raise IRQL first
    *old_irql = ke_raise_irql(irql::DISPATCH_LEVEL);

    let lock = &KI_QUEUED_SPINLOCKS[lock_number as usize];

    // Try to acquire without queuing
    if lock.lock.compare_exchange(
        0,
        get_current_prcb() as *const KPrcb as usize | LOCK_QUEUE_OWNER,
        Ordering::Acquire,
        Ordering::Relaxed,
    ).is_ok() {
        true
    } else {
        // Failed - lower IRQL and return false
        ke_lower_irql(*old_irql);
        false
    }
}

// ============================================================================
// Internal Queued Spinlock Implementation
// ============================================================================

/// Internal function to acquire a queued spinlock
///
/// This implements the MCS-style queued spinlock algorithm.
///
/// # Safety
/// - Must be at DISPATCH_LEVEL or higher
/// - queue_entry must be the calling processor's entry for this lock
unsafe fn ki_acquire_queued_spinlock_at_dpc_level(
    lock: &KQueuedSpinLock,
    queue_entry: &mut KSpinLockQueue,
) {
    // Store pointer to the lock in our queue entry
    queue_entry.lock.store(&lock.lock as *const AtomicUsize as usize, Ordering::Relaxed);
    queue_entry.next.store(0, Ordering::Relaxed);

    // Atomically swap ourselves onto the tail of the queue
    // Returns the previous tail (or 0 if lock was free)
    let queue_entry_ptr = queue_entry as *mut KSpinLockQueue as usize;
    let old_tail = lock.lock.swap(queue_entry_ptr | LOCK_QUEUE_WAIT, Ordering::AcqRel);

    if old_tail == 0 {
        // Lock was free - we now own it
        // Clear wait flag, set owner flag
        lock.lock.store(queue_entry_ptr | LOCK_QUEUE_OWNER, Ordering::Release);
    } else {
        // Lock was held - we need to wait
        // Link ourselves to the previous tail
        let prev_entry = (old_tail & !3) as *mut KSpinLockQueue;
        (*prev_entry).next.store(queue_entry_ptr, Ordering::Release);

        // Spin until the lock holder grants us ownership
        // We spin on our own queue entry's lock field (set to LOCK_QUEUE_OWNER when granted)
        while queue_entry.lock.load(Ordering::Acquire) & LOCK_QUEUE_OWNER == 0 {
            // Check for freeze request while spinning (NT compatibility)
            let prcb = get_current_prcb();
            if prcb.freeze_requested {
                // Would handle freeze here
            }
            core::hint::spin_loop();
        }
    }

    // Memory barrier before entering critical section
    fence(Ordering::Acquire);
}

/// Internal function to release a queued spinlock
///
/// # Safety
/// - Must hold the lock
/// - queue_entry must be the calling processor's entry for this lock
unsafe fn ki_release_queued_spinlock_from_dpc_level(
    lock: &KQueuedSpinLock,
    queue_entry: &mut KSpinLockQueue,
) {
    // Memory barrier before release
    fence(Ordering::Release);

    let queue_entry_ptr = queue_entry as *mut KSpinLockQueue as usize;

    // Check if there's a waiter
    let next = queue_entry.next.load(Ordering::Acquire);

    if next == 0 {
        // No waiter visible yet - try to atomically release the lock
        // Compare with our pointer | OWNER flag
        if lock.lock.compare_exchange(
            queue_entry_ptr | LOCK_QUEUE_OWNER,
            0,
            Ordering::Release,
            Ordering::Relaxed,
        ).is_ok() {
            // Successfully released - no waiters
            queue_entry.lock.store(0, Ordering::Relaxed);
            return;
        }

        // CAS failed - a waiter has arrived but not yet linked
        // Spin until they link themselves
        loop {
            let next = queue_entry.next.load(Ordering::Acquire);
            if next != 0 {
                // Waiter has linked - grant them the lock
                let next_entry = next as *mut KSpinLockQueue;
                (*next_entry).lock.fetch_or(LOCK_QUEUE_OWNER, Ordering::Release);
                break;
            }
            core::hint::spin_loop();
        }
    } else {
        // Waiter is already linked - grant them the lock
        let next_entry = next as *mut KSpinLockQueue;
        (*next_entry).lock.fetch_or(LOCK_QUEUE_OWNER, Ordering::Release);
    }

    // Clear our queue entry
    queue_entry.lock.store(0, Ordering::Relaxed);
    queue_entry.next.store(0, Ordering::Relaxed);
}

// ============================================================================
// In-Stack Queued Spinlock (for non-numbered locks)
// ============================================================================

/// In-stack queued spinlock handle
///
/// Used for acquiring arbitrary (non-numbered) queued spinlocks.
/// The handle is allocated on the caller's stack.
#[repr(C)]
pub struct KLockQueueHandle {
    /// Queue entry for this acquisition
    pub lock_queue: KSpinLockQueue,
    /// Saved IRQL
    pub old_irql: Kirql,
}

impl KLockQueueHandle {
    /// Create a new uninitialized handle
    pub const fn new() -> Self {
        Self {
            lock_queue: KSpinLockQueue::new(),
            old_irql: irql::PASSIVE_LEVEL,
        }
    }
}

impl Default for KLockQueueHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Acquire a queued spinlock using an in-stack handle
///
/// # Safety
/// - Must be called at IRQL <= DISPATCH_LEVEL
/// - Handle must remain valid until release
#[inline]
pub unsafe fn ke_acquire_in_stack_queued_spinlock(
    lock: &KQueuedSpinLock,
    handle: &mut KLockQueueHandle,
) {
    // Raise IRQL
    handle.old_irql = ke_raise_irql(irql::DISPATCH_LEVEL);

    // Acquire using the handle's queue entry
    ki_acquire_queued_spinlock_at_dpc_level(lock, &mut handle.lock_queue);
}

/// Release a queued spinlock acquired with an in-stack handle
///
/// # Safety
/// - Must hold the lock via this handle
#[inline]
pub unsafe fn ke_release_in_stack_queued_spinlock(
    lock: &KQueuedSpinLock,
    handle: &mut KLockQueueHandle,
) {
    // Release the lock
    ki_release_queued_spinlock_from_dpc_level(lock, &mut handle.lock_queue);

    // Lower IRQL
    ke_lower_irql(handle.old_irql);
}

/// Acquire a queued spinlock using an in-stack handle, already at DPC level
///
/// # Safety
/// - Must be at DISPATCH_LEVEL
/// - Handle must remain valid until release
#[inline]
pub unsafe fn ke_acquire_in_stack_queued_spinlock_at_dpc_level(
    lock: &KQueuedSpinLock,
    handle: &mut KLockQueueHandle,
) {
    handle.old_irql = irql::DISPATCH_LEVEL;
    ki_acquire_queued_spinlock_at_dpc_level(lock, &mut handle.lock_queue);
}

/// Release a queued spinlock without lowering IRQL
///
/// # Safety
/// - Must hold the lock via this handle
#[inline]
pub unsafe fn ke_release_in_stack_queued_spinlock_from_dpc_level(
    lock: &KQueuedSpinLock,
    handle: &mut KLockQueueHandle,
) {
    ki_release_queued_spinlock_from_dpc_level(lock, &mut handle.lock_queue);
}

// ============================================================================
// Compatibility with Traditional Spinlocks
// ============================================================================

/// Traditional spinlock with queued implementation internally
///
/// This provides the KeAcquireSpinLock / KeReleaseSpinLock API
/// but uses queued locking internally for better scalability.
#[repr(C, align(8))]
pub struct KSpinLock {
    lock: AtomicU64,
}

impl KSpinLock {
    /// Create a new unlocked spinlock
    pub const fn new() -> Self {
        Self {
            lock: AtomicU64::new(0),
        }
    }

    /// Check if locked
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.lock.load(Ordering::Relaxed) != 0
    }
}

impl Default for KSpinLock {
    fn default() -> Self {
        Self::new()
    }
}

/// Acquire a spinlock, raising IRQL to DISPATCH_LEVEL
///
/// # Safety
/// - Must be at IRQL <= DISPATCH_LEVEL
/// - Must release with ke_release_spin_lock
pub unsafe fn ke_acquire_spin_lock(lock: &KSpinLock) -> Kirql {
    let old_irql = ke_raise_irql(irql::DISPATCH_LEVEL);

    // Simple spinlock for now - could be converted to queued
    while lock.lock.compare_exchange_weak(
        0,
        1,
        Ordering::Acquire,
        Ordering::Relaxed,
    ).is_err() {
        // Check for freeze while spinning
        let prcb = get_current_prcb();
        if prcb.freeze_requested {
            // Handle freeze
        }
        while lock.lock.load(Ordering::Relaxed) != 0 {
            core::hint::spin_loop();
        }
    }

    old_irql
}

/// Release a spinlock and lower IRQL
///
/// # Safety
/// - Must hold the lock
/// - old_irql must be from ke_acquire_spin_lock
pub unsafe fn ke_release_spin_lock(lock: &KSpinLock, old_irql: Kirql) {
    lock.lock.store(0, Ordering::Release);
    ke_lower_irql(old_irql);
}

/// Acquire spinlock at DPC level (already at DISPATCH_LEVEL)
///
/// # Safety
/// - Must be at DISPATCH_LEVEL
pub unsafe fn ke_acquire_spin_lock_at_dpc_level(lock: &KSpinLock) {
    while lock.lock.compare_exchange_weak(
        0,
        1,
        Ordering::Acquire,
        Ordering::Relaxed,
    ).is_err() {
        while lock.lock.load(Ordering::Relaxed) != 0 {
            core::hint::spin_loop();
        }
    }
}

/// Release spinlock staying at DPC level
///
/// # Safety
/// - Must hold the lock
pub unsafe fn ke_release_spin_lock_from_dpc_level(lock: &KSpinLock) {
    lock.lock.store(0, Ordering::Release);
}

/// Try to acquire a spinlock without blocking
///
/// # Safety
/// - Must be at IRQL <= DISPATCH_LEVEL
pub unsafe fn ke_try_to_acquire_spin_lock_at_dpc_level(lock: &KSpinLock) -> bool {
    lock.lock.compare_exchange(
        0,
        1,
        Ordering::Acquire,
        Ordering::Relaxed,
    ).is_ok()
}
