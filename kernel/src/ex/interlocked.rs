//! Interlocked Operations
//!
//! Provides NT-compatible atomic operation wrappers. These functions provide
//! thread-safe access to shared variables without requiring explicit locks.
//!
//! # Operations
//!
//! - **Increment/Decrement**: Atomic add/subtract 1
//! - **Exchange**: Atomic swap
//! - **CompareExchange**: Atomic compare-and-swap (CAS)
//! - **Add/And/Or/Xor**: Atomic arithmetic/bitwise operations
//! - **BitTest**: Atomic bit manipulation
//!
//! # Memory Ordering
//!
//! All operations use SeqCst ordering by default for maximum safety,
//! matching NT's full memory barrier semantics.
//!
//! # Usage
//!
//! ```ignore
//! use crate::ex::interlocked::*;
//!
//! static mut COUNTER: i32 = 0;
//!
//! // Atomic increment
//! let new_value = unsafe { interlocked_increment(&mut COUNTER) };
//!
//! // Compare and exchange
//! let old = unsafe { interlocked_compare_exchange(&mut COUNTER, 10, 5) };
//! ```

use core::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::ptr;

// ============================================================================
// 32-bit Interlocked Operations
// ============================================================================

/// Atomically increment a 32-bit value and return the new value (InterlockedIncrement)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_increment(target: *mut i32) -> i32 {
    let atomic = &*(target as *const AtomicI32);
    atomic.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
}

/// Atomically decrement a 32-bit value and return the new value (InterlockedDecrement)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_decrement(target: *mut i32) -> i32 {
    let atomic = &*(target as *const AtomicI32);
    atomic.fetch_sub(1, Ordering::SeqCst).wrapping_sub(1)
}

/// Atomically exchange a 32-bit value, returning the old value (InterlockedExchange)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_exchange(target: *mut i32, value: i32) -> i32 {
    let atomic = &*(target as *const AtomicI32);
    atomic.swap(value, Ordering::SeqCst)
}

/// Atomically compare and exchange a 32-bit value (InterlockedCompareExchange)
///
/// If *target == comparand, sets *target = exchange and returns comparand.
/// Otherwise, returns the current value of *target.
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_compare_exchange(
    target: *mut i32,
    exchange: i32,
    comparand: i32,
) -> i32 {
    let atomic = &*(target as *const AtomicI32);
    match atomic.compare_exchange(comparand, exchange, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(v) => v,
        Err(v) => v,
    }
}

/// Atomically add to a 32-bit value, returning the old value (InterlockedExchangeAdd)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_exchange_add(target: *mut i32, value: i32) -> i32 {
    let atomic = &*(target as *const AtomicI32);
    atomic.fetch_add(value, Ordering::SeqCst)
}

/// Atomically AND a 32-bit value, returning the old value (InterlockedAnd)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_and(target: *mut i32, value: i32) -> i32 {
    let atomic = &*(target as *const AtomicI32);
    atomic.fetch_and(value, Ordering::SeqCst)
}

/// Atomically OR a 32-bit value, returning the old value (InterlockedOr)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_or(target: *mut i32, value: i32) -> i32 {
    let atomic = &*(target as *const AtomicI32);
    atomic.fetch_or(value, Ordering::SeqCst)
}

/// Atomically XOR a 32-bit value, returning the old value (InterlockedXor)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_xor(target: *mut i32, value: i32) -> i32 {
    let atomic = &*(target as *const AtomicI32);
    atomic.fetch_xor(value, Ordering::SeqCst)
}

// ============================================================================
// 64-bit Interlocked Operations
// ============================================================================

/// Atomically increment a 64-bit value and return the new value (InterlockedIncrement64)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_increment64(target: *mut i64) -> i64 {
    let atomic = &*(target as *const AtomicI64);
    atomic.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
}

/// Atomically decrement a 64-bit value and return the new value (InterlockedDecrement64)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_decrement64(target: *mut i64) -> i64 {
    let atomic = &*(target as *const AtomicI64);
    atomic.fetch_sub(1, Ordering::SeqCst).wrapping_sub(1)
}

/// Atomically exchange a 64-bit value, returning the old value (InterlockedExchange64)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_exchange64(target: *mut i64, value: i64) -> i64 {
    let atomic = &*(target as *const AtomicI64);
    atomic.swap(value, Ordering::SeqCst)
}

/// Atomically compare and exchange a 64-bit value (InterlockedCompareExchange64)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_compare_exchange64(
    target: *mut i64,
    exchange: i64,
    comparand: i64,
) -> i64 {
    let atomic = &*(target as *const AtomicI64);
    match atomic.compare_exchange(comparand, exchange, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(v) => v,
        Err(v) => v,
    }
}

/// Atomically add to a 64-bit value, returning the old value (InterlockedExchangeAdd64)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_exchange_add64(target: *mut i64, value: i64) -> i64 {
    let atomic = &*(target as *const AtomicI64);
    atomic.fetch_add(value, Ordering::SeqCst)
}

/// Atomically AND a 64-bit value, returning the old value (InterlockedAnd64)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_and64(target: *mut i64, value: i64) -> i64 {
    let atomic = &*(target as *const AtomicI64);
    atomic.fetch_and(value, Ordering::SeqCst)
}

/// Atomically OR a 64-bit value, returning the old value (InterlockedOr64)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_or64(target: *mut i64, value: i64) -> i64 {
    let atomic = &*(target as *const AtomicI64);
    atomic.fetch_or(value, Ordering::SeqCst)
}

/// Atomically XOR a 64-bit value, returning the old value (InterlockedXor64)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_xor64(target: *mut i64, value: i64) -> i64 {
    let atomic = &*(target as *const AtomicI64);
    atomic.fetch_xor(value, Ordering::SeqCst)
}

// ============================================================================
// Pointer Interlocked Operations
// ============================================================================

/// Atomically exchange a pointer value, returning the old value (InterlockedExchangePointer)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_exchange_pointer<T>(target: *mut *mut T, value: *mut T) -> *mut T {
    let atomic = &*(target as *const AtomicUsize);
    atomic.swap(value as usize, Ordering::SeqCst) as *mut T
}

/// Atomically compare and exchange a pointer (InterlockedCompareExchangePointer)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_compare_exchange_pointer<T>(
    target: *mut *mut T,
    exchange: *mut T,
    comparand: *mut T,
) -> *mut T {
    let atomic = &*(target as *const AtomicUsize);
    match atomic.compare_exchange(
        comparand as usize,
        exchange as usize,
        Ordering::SeqCst,
        Ordering::SeqCst,
    ) {
        Ok(v) => v as *mut T,
        Err(v) => v as *mut T,
    }
}

// ============================================================================
// Bit Test Operations
// ============================================================================

/// Atomically test and set a bit (InterlockedBitTestAndSet)
///
/// Sets the bit at position `bit` and returns the previous value.
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_bit_test_and_set(target: *mut i32, bit: i32) -> bool {
    let atomic = &*(target as *const AtomicI32);
    let mask = 1i32 << bit;
    (atomic.fetch_or(mask, Ordering::SeqCst) & mask) != 0
}

/// Atomically test and reset a bit (InterlockedBitTestAndReset)
///
/// Clears the bit at position `bit` and returns the previous value.
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_bit_test_and_reset(target: *mut i32, bit: i32) -> bool {
    let atomic = &*(target as *const AtomicI32);
    let mask = 1i32 << bit;
    (atomic.fetch_and(!mask, Ordering::SeqCst) & mask) != 0
}

/// Atomically test and complement a bit (InterlockedBitTestAndComplement)
///
/// Flips the bit at position `bit` and returns the previous value.
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_bit_test_and_complement(target: *mut i32, bit: i32) -> bool {
    let atomic = &*(target as *const AtomicI32);
    let mask = 1i32 << bit;
    (atomic.fetch_xor(mask, Ordering::SeqCst) & mask) != 0
}

/// 64-bit test and set (InterlockedBitTestAndSet64)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_bit_test_and_set64(target: *mut i64, bit: i32) -> bool {
    let atomic = &*(target as *const AtomicI64);
    let mask = 1i64 << bit;
    (atomic.fetch_or(mask, Ordering::SeqCst) & mask) != 0
}

/// 64-bit test and reset (InterlockedBitTestAndReset64)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_bit_test_and_reset64(target: *mut i64, bit: i32) -> bool {
    let atomic = &*(target as *const AtomicI64);
    let mask = 1i64 << bit;
    (atomic.fetch_and(!mask, Ordering::SeqCst) & mask) != 0
}

// ============================================================================
// Unsigned Variants
// ============================================================================

/// Atomically increment an unsigned 32-bit value (InterlockedIncrementU)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_increment_u32(target: *mut u32) -> u32 {
    let atomic = &*(target as *const AtomicU32);
    atomic.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
}

/// Atomically decrement an unsigned 32-bit value (InterlockedDecrementU)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_decrement_u32(target: *mut u32) -> u32 {
    let atomic = &*(target as *const AtomicU32);
    atomic.fetch_sub(1, Ordering::SeqCst).wrapping_sub(1)
}

/// Atomically exchange an unsigned 32-bit value (InterlockedExchangeU)
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_exchange_u32(target: *mut u32, value: u32) -> u32 {
    let atomic = &*(target as *const AtomicU32);
    atomic.swap(value, Ordering::SeqCst)
}

/// Atomically compare and exchange an unsigned 32-bit value
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_compare_exchange_u32(
    target: *mut u32,
    exchange: u32,
    comparand: u32,
) -> u32 {
    let atomic = &*(target as *const AtomicU32);
    match atomic.compare_exchange(comparand, exchange, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(v) => v,
        Err(v) => v,
    }
}

/// Atomically increment an unsigned 64-bit value
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_increment_u64(target: *mut u64) -> u64 {
    let atomic = &*(target as *const AtomicU64);
    atomic.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
}

/// Atomically decrement an unsigned 64-bit value
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_decrement_u64(target: *mut u64) -> u64 {
    let atomic = &*(target as *const AtomicU64);
    atomic.fetch_sub(1, Ordering::SeqCst).wrapping_sub(1)
}

/// Atomically exchange an unsigned 64-bit value
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_exchange_u64(target: *mut u64, value: u64) -> u64 {
    let atomic = &*(target as *const AtomicU64);
    atomic.swap(value, Ordering::SeqCst)
}

/// Atomically compare and exchange an unsigned 64-bit value
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_compare_exchange_u64(
    target: *mut u64,
    exchange: u64,
    comparand: u64,
) -> u64 {
    let atomic = &*(target as *const AtomicU64);
    match atomic.compare_exchange(comparand, exchange, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(v) => v,
        Err(v) => v,
    }
}

// ============================================================================
// Acquire/Release Variants (for performance-sensitive code)
// ============================================================================

/// Interlocked increment with acquire semantics
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_increment_acquire(target: *mut i32) -> i32 {
    let atomic = &*(target as *const AtomicI32);
    atomic.fetch_add(1, Ordering::Acquire).wrapping_add(1)
}

/// Interlocked decrement with release semantics
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_decrement_release(target: *mut i32) -> i32 {
    let atomic = &*(target as *const AtomicI32);
    atomic.fetch_sub(1, Ordering::Release).wrapping_sub(1)
}

/// Interlocked compare-exchange with acquire semantics
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_compare_exchange_acquire(
    target: *mut i32,
    exchange: i32,
    comparand: i32,
) -> i32 {
    let atomic = &*(target as *const AtomicI32);
    match atomic.compare_exchange(comparand, exchange, Ordering::Acquire, Ordering::Relaxed) {
        Ok(v) => v,
        Err(v) => v,
    }
}

/// Interlocked compare-exchange with release semantics
///
/// # Safety
/// The target pointer must be valid and properly aligned.
#[inline]
pub unsafe fn interlocked_compare_exchange_release(
    target: *mut i32,
    exchange: i32,
    comparand: i32,
) -> i32 {
    let atomic = &*(target as *const AtomicI32);
    match atomic.compare_exchange(comparand, exchange, Ordering::Release, Ordering::Relaxed) {
        Ok(v) => v,
        Err(v) => v,
    }
}

// ============================================================================
// Interlocked List Operations (Single Entry)
// ============================================================================

/// Singly linked list entry for interlocked operations
#[repr(C)]
pub struct SingleListEntry {
    pub next: *mut SingleListEntry,
}

impl SingleListEntry {
    pub const fn new() -> Self {
        Self {
            next: ptr::null_mut(),
        }
    }
}

impl Default for SingleListEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Push entry onto a singly linked list (InterlockedPushEntrySList simplified)
///
/// # Safety
/// Pointers must be valid.
#[inline]
pub unsafe fn interlocked_push_entry_list(
    list_head: *mut *mut SingleListEntry,
    entry: *mut SingleListEntry,
) -> *mut SingleListEntry {
    loop {
        let old_head = *list_head;
        (*entry).next = old_head;

        let result = interlocked_compare_exchange_pointer(
            list_head,
            entry,
            old_head,
        );

        if result == old_head {
            return old_head;
        }
        core::hint::spin_loop();
    }
}

/// Pop entry from a singly linked list (InterlockedPopEntrySList simplified)
///
/// # Safety
/// Pointers must be valid.
#[inline]
pub unsafe fn interlocked_pop_entry_list(
    list_head: *mut *mut SingleListEntry,
) -> *mut SingleListEntry {
    loop {
        let old_head = *list_head;
        if old_head.is_null() {
            return ptr::null_mut();
        }

        let new_head = (*old_head).next;

        let result = interlocked_compare_exchange_pointer(
            list_head,
            new_head,
            old_head,
        );

        if result == old_head {
            return old_head;
        }
        core::hint::spin_loop();
    }
}

// ============================================================================
// Memory Barrier Operations
// ============================================================================

/// Full memory barrier (MemoryBarrier)
#[inline]
pub fn memory_barrier() {
    core::sync::atomic::fence(Ordering::SeqCst);
}

/// Read memory barrier (ReadBarrier)
#[inline]
pub fn read_barrier() {
    core::sync::atomic::fence(Ordering::Acquire);
}

/// Write memory barrier (WriteBarrier)
#[inline]
pub fn write_barrier() {
    core::sync::atomic::fence(Ordering::Release);
}

/// Compiler barrier only (no CPU barrier)
#[inline]
pub fn compiler_barrier() {
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

// ============================================================================
// Statistics
// ============================================================================

use core::sync::atomic::AtomicU64 as StatsAtomicU64;

static INTERLOCKED_OPS_COUNT: StatsAtomicU64 = StatsAtomicU64::new(0);

/// Get total interlocked operations count (approximate)
pub fn get_interlocked_ops_count() -> u64 {
    INTERLOCKED_OPS_COUNT.load(Ordering::Relaxed)
}

/// Reset interlocked operations counter
pub fn reset_interlocked_stats() {
    INTERLOCKED_OPS_COUNT.store(0, Ordering::Relaxed);
}

// ============================================================================
// NT API Compatibility Names (PascalCase)
// ============================================================================

// These are provided as aliases for code that uses NT naming conventions

pub use interlocked_increment as InterlockedIncrement;
pub use interlocked_decrement as InterlockedDecrement;
pub use interlocked_exchange as InterlockedExchange;
pub use interlocked_compare_exchange as InterlockedCompareExchange;
pub use interlocked_exchange_add as InterlockedExchangeAdd;
pub use interlocked_and as InterlockedAnd;
pub use interlocked_or as InterlockedOr;
pub use interlocked_xor as InterlockedXor;

pub use interlocked_increment64 as InterlockedIncrement64;
pub use interlocked_decrement64 as InterlockedDecrement64;
pub use interlocked_exchange64 as InterlockedExchange64;
pub use interlocked_compare_exchange64 as InterlockedCompareExchange64;
pub use interlocked_exchange_add64 as InterlockedExchangeAdd64;
pub use interlocked_and64 as InterlockedAnd64;
pub use interlocked_or64 as InterlockedOr64;
pub use interlocked_xor64 as InterlockedXor64;

pub use interlocked_exchange_pointer as InterlockedExchangePointer;
pub use interlocked_compare_exchange_pointer as InterlockedCompareExchangePointer;

pub use interlocked_bit_test_and_set as InterlockedBitTestAndSet;
pub use interlocked_bit_test_and_reset as InterlockedBitTestAndReset;
pub use interlocked_bit_test_and_complement as InterlockedBitTestAndComplement;
pub use interlocked_bit_test_and_set64 as InterlockedBitTestAndSet64;
pub use interlocked_bit_test_and_reset64 as InterlockedBitTestAndReset64;

pub use memory_barrier as MemoryBarrier;
pub use read_barrier as ReadBarrier;
pub use write_barrier as WriteBarrier;
