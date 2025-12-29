//! RTL Memory Functions
//!
//! Memory manipulation functions following NT conventions.
//!
//! These are the RTL equivalents of standard C library functions:
//! - RtlCopyMemory (memcpy)
//! - RtlMoveMemory (memmove)
//! - RtlZeroMemory (memset with 0)
//! - RtlFillMemory (memset)
//! - RtlCompareMemory (memcmp)
//! - RtlEqualMemory (memcmp == 0)

use core::ptr;

/// Copy memory from source to destination (non-overlapping)
///
/// This is equivalent to memcpy. The source and destination
/// must not overlap.
///
/// # Arguments
/// * `dest` - Destination buffer
/// * `src` - Source buffer
/// * `length` - Number of bytes to copy
///
/// # Safety
/// - Both pointers must be valid for the specified length
/// - Buffers must not overlap (use rtl_move_memory for overlapping)
#[inline]
pub unsafe fn rtl_copy_memory(dest: *mut u8, src: *const u8, length: usize) {
    if dest.is_null() || src.is_null() || length == 0 {
        return;
    }
    ptr::copy_nonoverlapping(src, dest, length);
}

/// Copy memory from source to destination (may overlap)
///
/// This is equivalent to memmove. Handles overlapping buffers correctly.
///
/// # Arguments
/// * `dest` - Destination buffer
/// * `src` - Source buffer
/// * `length` - Number of bytes to copy
///
/// # Safety
/// Both pointers must be valid for the specified length
#[inline]
pub unsafe fn rtl_move_memory(dest: *mut u8, src: *const u8, length: usize) {
    if dest.is_null() || src.is_null() || length == 0 {
        return;
    }
    ptr::copy(src, dest, length);
}

/// Zero out a memory region
///
/// This is equivalent to memset(dest, 0, length).
///
/// # Arguments
/// * `dest` - Destination buffer
/// * `length` - Number of bytes to zero
///
/// # Safety
/// Pointer must be valid for the specified length
#[inline]
pub unsafe fn rtl_zero_memory(dest: *mut u8, length: usize) {
    if dest.is_null() || length == 0 {
        return;
    }
    ptr::write_bytes(dest, 0, length);
}

/// Fill a memory region with a specified byte value
///
/// This is equivalent to memset.
///
/// # Arguments
/// * `dest` - Destination buffer
/// * `length` - Number of bytes to fill
/// * `fill` - Byte value to fill with
///
/// # Safety
/// Pointer must be valid for the specified length
#[inline]
pub unsafe fn rtl_fill_memory(dest: *mut u8, length: usize, fill: u8) {
    if dest.is_null() || length == 0 {
        return;
    }
    ptr::write_bytes(dest, fill, length);
}

/// Compare two memory regions
///
/// Returns the number of bytes that match before the first difference.
///
/// # Arguments
/// * `source1` - First buffer
/// * `source2` - Second buffer
/// * `length` - Number of bytes to compare
///
/// # Returns
/// Number of bytes that match (0 to length)
///
/// # Safety
/// Both pointers must be valid for the specified length
pub unsafe fn rtl_compare_memory(source1: *const u8, source2: *const u8, length: usize) -> usize {
    if source1.is_null() || source2.is_null() || length == 0 {
        return 0;
    }

    for i in 0..length {
        if *source1.add(i) != *source2.add(i) {
            return i;
        }
    }

    length
}

/// Check if two memory regions are equal
///
/// # Arguments
/// * `source1` - First buffer
/// * `source2` - Second buffer
/// * `length` - Number of bytes to compare
///
/// # Returns
/// true if all bytes match, false otherwise
///
/// # Safety
/// Both pointers must be valid for the specified length
#[inline]
pub unsafe fn rtl_equal_memory(source1: *const u8, source2: *const u8, length: usize) -> bool {
    rtl_compare_memory(source1, source2, length) == length
}

/// Secure zero memory (attempts to prevent optimization)
///
/// This is a more secure version of rtl_zero_memory that attempts
/// to ensure the zeroing is not optimized away by the compiler.
///
/// # Arguments
/// * `dest` - Destination buffer
/// * `length` - Number of bytes to zero
///
/// # Safety
/// Pointer must be valid for the specified length
#[inline(never)]
pub unsafe fn rtl_secure_zero_memory(dest: *mut u8, length: usize) {
    if dest.is_null() || length == 0 {
        return;
    }

    // Use volatile writes to prevent optimization
    for i in 0..length {
        ptr::write_volatile(dest.add(i), 0);
    }

    // Memory barrier to ensure writes complete
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Find a byte in a memory region
///
/// # Arguments
/// * `buffer` - Buffer to search
/// * `length` - Length of buffer
/// * `target` - Byte to find
///
/// # Returns
/// Pointer to first occurrence, or null if not found
///
/// # Safety
/// Buffer must be valid for the specified length
pub unsafe fn rtl_find_byte(buffer: *const u8, length: usize, target: u8) -> *const u8 {
    if buffer.is_null() || length == 0 {
        return ptr::null();
    }

    for i in 0..length {
        if *buffer.add(i) == target {
            return buffer.add(i);
        }
    }

    ptr::null()
}

/// Calculate a simple checksum of a memory region
///
/// # Arguments
/// * `buffer` - Buffer to checksum
/// * `length` - Length of buffer
///
/// # Returns
/// Simple additive checksum (sum of all bytes)
///
/// # Safety
/// Buffer must be valid for the specified length
pub unsafe fn rtl_compute_checksum(buffer: *const u8, length: usize) -> u32 {
    if buffer.is_null() || length == 0 {
        return 0;
    }

    let mut sum: u32 = 0;
    for i in 0..length {
        sum = sum.wrapping_add(*buffer.add(i) as u32);
    }

    sum
}

/// Prefix sum (running sum) of bytes in a buffer
///
/// # Arguments
/// * `buffer` - Buffer to process
/// * `length` - Length of buffer
/// * `initial` - Initial sum value
///
/// # Returns
/// Final sum value
///
/// # Safety
/// Buffer must be valid for the specified length
pub unsafe fn rtl_prefix_sum(buffer: *const u8, length: usize, initial: u64) -> u64 {
    if buffer.is_null() || length == 0 {
        return initial;
    }

    let mut sum = initial;
    for i in 0..length {
        sum = sum.wrapping_add(*buffer.add(i) as u64);
    }

    sum
}

// ============================================================================
// NT-style aliases (PascalCase)
// ============================================================================

/// Alias for rtl_copy_memory (NT naming)
#[inline]
pub unsafe fn RtlCopyMemory(dest: *mut u8, src: *const u8, length: usize) {
    rtl_copy_memory(dest, src, length)
}

/// Alias for rtl_move_memory (NT naming)
#[inline]
pub unsafe fn RtlMoveMemory(dest: *mut u8, src: *const u8, length: usize) {
    rtl_move_memory(dest, src, length)
}

/// Alias for rtl_zero_memory (NT naming)
#[inline]
pub unsafe fn RtlZeroMemory(dest: *mut u8, length: usize) {
    rtl_zero_memory(dest, length)
}

/// Alias for rtl_fill_memory (NT naming)
#[inline]
pub unsafe fn RtlFillMemory(dest: *mut u8, length: usize, fill: u8) {
    rtl_fill_memory(dest, length, fill)
}

/// Alias for rtl_compare_memory (NT naming)
#[inline]
pub unsafe fn RtlCompareMemory(source1: *const u8, source2: *const u8, length: usize) -> usize {
    rtl_compare_memory(source1, source2, length)
}

/// Alias for rtl_equal_memory (NT naming)
#[inline]
pub unsafe fn RtlEqualMemory(source1: *const u8, source2: *const u8, length: usize) -> bool {
    rtl_equal_memory(source1, source2, length)
}

/// Alias for rtl_secure_zero_memory (NT naming)
#[inline(never)]
pub unsafe fn RtlSecureZeroMemory(dest: *mut u8, length: usize) {
    rtl_secure_zero_memory(dest, length)
}

// ============================================================================
// Memory Pool Helpers
// ============================================================================

/// Simple memory block header for tracking allocations
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PoolHeader {
    /// Size of the allocation (including header)
    pub size: u32,
    /// Pool type tag (4 characters)
    pub tag: u32,
    /// Flags
    pub flags: u16,
    /// Previous size (for coalescing)
    pub previous_size: u16,
}

impl PoolHeader {
    /// Create a new pool header
    pub const fn new(size: u32, tag: u32) -> Self {
        Self {
            size,
            tag,
            flags: 0,
            previous_size: 0,
        }
    }

    /// Get the tag as a 4-character string
    pub fn tag_str(&self) -> [u8; 4] {
        self.tag.to_le_bytes()
    }
}

/// Create a pool tag from 4 characters
///
/// Example: `pool_tag(b"Test")` creates tag 0x74736554
#[inline]
pub const fn pool_tag(chars: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*chars)
}

// ============================================================================
// Memory alignment helpers
// ============================================================================

/// Align a value up to the nearest alignment boundary
#[inline]
pub const fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

/// Align a value down to the nearest alignment boundary
#[inline]
pub const fn align_down(value: usize, alignment: usize) -> usize {
    value & !(alignment - 1)
}

/// Check if a value is aligned to a given boundary
#[inline]
pub const fn is_aligned(value: usize, alignment: usize) -> bool {
    (value & (alignment - 1)) == 0
}

/// Round up to the next power of 2
pub const fn next_power_of_two(mut n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    n -= 1;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n |= n >> 32;
    n + 1
}
