//! RTL Bitmap Implementation
//!
//! Bitmaps are used throughout NT for efficient tracking of resources:
//! - PFN database (free physical pages)
//! - Handle table allocation
//! - Pool allocator free blocks
//! - Disk block allocation
//!
//! # Usage
//! ```
//! let mut buffer = [0u32; 4]; // 128 bits
//! let mut bitmap = RtlBitmap::new(&mut buffer);
//!
//! bitmap.set_bit(42);
//! assert!(bitmap.test_bit(42));
//!
//! let free = bitmap.find_clear_bits(8);
//! bitmap.set_bits(free, 8);
//! ```

use core::ptr;

/// RTL Bitmap structure
///
/// Equivalent to NT's RTL_BITMAP
#[repr(C)]
pub struct RtlBitmap {
    /// Number of bits in the bitmap
    pub size_of_bit_map: u32,
    /// Pointer to the bit buffer (array of u32)
    pub buffer: *mut u32,
}

impl RtlBitmap {
    /// Create a new bitmap from a buffer
    ///
    /// The buffer size determines the number of bits (size * 32)
    pub fn new(buffer: &mut [u32]) -> Self {
        // Clear the buffer
        for word in buffer.iter_mut() {
            *word = 0;
        }

        Self {
            size_of_bit_map: (buffer.len() * 32) as u32,
            buffer: buffer.as_mut_ptr(),
        }
    }

    /// Create a bitmap from raw parts
    ///
    /// # Safety
    /// The buffer must be valid for `num_bits / 32` u32 words
    pub unsafe fn from_raw_parts(buffer: *mut u32, num_bits: u32) -> Self {
        Self {
            size_of_bit_map: num_bits,
            buffer,
        }
    }

    /// Get the number of bits
    #[inline]
    pub fn size(&self) -> u32 {
        self.size_of_bit_map
    }

    /// Get the number of u32 words needed
    #[inline]
    pub fn word_count(&self) -> usize {
        ((self.size_of_bit_map + 31) / 32) as usize
    }

    /// Test if a bit is set
    #[inline]
    pub fn test_bit(&self, bit_index: u32) -> bool {
        if bit_index >= self.size_of_bit_map || self.buffer.is_null() {
            return false;
        }

        let word_index = (bit_index / 32) as usize;
        let bit_offset = bit_index % 32;

        unsafe {
            (*self.buffer.add(word_index) & (1 << bit_offset)) != 0
        }
    }

    /// Set a bit
    #[inline]
    pub fn set_bit(&mut self, bit_index: u32) {
        if bit_index >= self.size_of_bit_map || self.buffer.is_null() {
            return;
        }

        let word_index = (bit_index / 32) as usize;
        let bit_offset = bit_index % 32;

        unsafe {
            *self.buffer.add(word_index) |= 1 << bit_offset;
        }
    }

    /// Clear a bit
    #[inline]
    pub fn clear_bit(&mut self, bit_index: u32) {
        if bit_index >= self.size_of_bit_map || self.buffer.is_null() {
            return;
        }

        let word_index = (bit_index / 32) as usize;
        let bit_offset = bit_index % 32;

        unsafe {
            *self.buffer.add(word_index) &= !(1 << bit_offset);
        }
    }

    /// Set a range of bits
    pub fn set_bits(&mut self, start: u32, count: u32) {
        if self.buffer.is_null() {
            return;
        }

        for i in 0..count {
            let bit = start + i;
            if bit >= self.size_of_bit_map {
                break;
            }
            self.set_bit(bit);
        }
    }

    /// Clear a range of bits
    pub fn clear_bits(&mut self, start: u32, count: u32) {
        if self.buffer.is_null() {
            return;
        }

        for i in 0..count {
            let bit = start + i;
            if bit >= self.size_of_bit_map {
                break;
            }
            self.clear_bit(bit);
        }
    }

    /// Set all bits
    pub fn set_all_bits(&mut self) {
        if self.buffer.is_null() {
            return;
        }

        let word_count = self.word_count();
        for i in 0..word_count {
            unsafe {
                *self.buffer.add(i) = !0u32;
            }
        }

        // Clear any bits beyond size_of_bit_map in the last word
        let remainder = self.size_of_bit_map % 32;
        if remainder != 0 {
            let mask = (1u32 << remainder) - 1;
            unsafe {
                *self.buffer.add(word_count - 1) &= mask;
            }
        }
    }

    /// Clear all bits
    pub fn clear_all_bits(&mut self) {
        if self.buffer.is_null() {
            return;
        }

        let word_count = self.word_count();
        for i in 0..word_count {
            unsafe {
                *self.buffer.add(i) = 0;
            }
        }
    }

    /// Count the number of set bits
    pub fn number_of_set_bits(&self) -> u32 {
        if self.buffer.is_null() {
            return 0;
        }

        let mut count = 0u32;
        let word_count = self.word_count();

        for i in 0..word_count {
            let word = unsafe { *self.buffer.add(i) };
            count += word.count_ones();
        }

        // Adjust for bits beyond size_of_bit_map
        let remainder = self.size_of_bit_map % 32;
        if remainder != 0 {
            let last_word = unsafe { *self.buffer.add(word_count - 1) };
            let mask = !((1u32 << remainder) - 1);
            count -= (last_word & mask).count_ones();
        }

        count
    }

    /// Count the number of clear bits
    #[inline]
    pub fn number_of_clear_bits(&self) -> u32 {
        self.size_of_bit_map - self.number_of_set_bits()
    }

    /// Find first set bit
    pub fn find_set_bit(&self) -> Option<u32> {
        if self.buffer.is_null() {
            return None;
        }

        let word_count = self.word_count();
        for i in 0..word_count {
            let word = unsafe { *self.buffer.add(i) };
            if word != 0 {
                let bit_in_word = word.trailing_zeros();
                let bit_index = (i as u32) * 32 + bit_in_word;
                if bit_index < self.size_of_bit_map {
                    return Some(bit_index);
                }
            }
        }
        None
    }

    /// Find first clear bit
    pub fn find_clear_bit(&self) -> Option<u32> {
        if self.buffer.is_null() {
            return None;
        }

        let word_count = self.word_count();
        for i in 0..word_count {
            let word = unsafe { *self.buffer.add(i) };
            if word != !0u32 {
                let bit_in_word = (!word).trailing_zeros();
                let bit_index = (i as u32) * 32 + bit_in_word;
                if bit_index < self.size_of_bit_map {
                    return Some(bit_index);
                }
            }
        }
        None
    }

    /// Find a contiguous run of clear bits
    ///
    /// Returns the starting index of the run, or None if not found
    pub fn find_clear_bits(&self, count: u32) -> Option<u32> {
        if count == 0 || count > self.size_of_bit_map || self.buffer.is_null() {
            return None;
        }

        let mut run_start: Option<u32> = None;
        let mut run_length = 0u32;

        for bit in 0..self.size_of_bit_map {
            if !self.test_bit(bit) {
                // Clear bit
                if run_start.is_none() {
                    run_start = Some(bit);
                    run_length = 1;
                } else {
                    run_length += 1;
                }

                if run_length >= count {
                    return run_start;
                }
            } else {
                // Set bit - reset run
                run_start = None;
                run_length = 0;
            }
        }

        None
    }

    /// Find a contiguous run of set bits
    pub fn find_set_bits(&self, count: u32) -> Option<u32> {
        if count == 0 || count > self.size_of_bit_map || self.buffer.is_null() {
            return None;
        }

        let mut run_start: Option<u32> = None;
        let mut run_length = 0u32;

        for bit in 0..self.size_of_bit_map {
            if self.test_bit(bit) {
                // Set bit
                if run_start.is_none() {
                    run_start = Some(bit);
                    run_length = 1;
                } else {
                    run_length += 1;
                }

                if run_length >= count {
                    return run_start;
                }
            } else {
                // Clear bit - reset run
                run_start = None;
                run_length = 0;
            }
        }

        None
    }

    /// Find clear bits and set them atomically
    ///
    /// Returns the starting index, or None if not enough contiguous bits
    pub fn find_clear_bits_and_set(&mut self, count: u32) -> Option<u32> {
        let start = self.find_clear_bits(count)?;
        self.set_bits(start, count);
        Some(start)
    }

    /// Find set bits and clear them atomically
    pub fn find_set_bits_and_clear(&mut self, count: u32) -> Option<u32> {
        let start = self.find_set_bits(count)?;
        self.clear_bits(start, count);
        Some(start)
    }

    /// Check if a range of bits are all clear
    pub fn are_bits_clear(&self, start: u32, count: u32) -> bool {
        if self.buffer.is_null() {
            return false;
        }

        for i in 0..count {
            let bit = start + i;
            if bit >= self.size_of_bit_map {
                return false;
            }
            if self.test_bit(bit) {
                return false;
            }
        }
        true
    }

    /// Check if a range of bits are all set
    pub fn are_bits_set(&self, start: u32, count: u32) -> bool {
        if self.buffer.is_null() {
            return false;
        }

        for i in 0..count {
            let bit = start + i;
            if bit >= self.size_of_bit_map {
                return false;
            }
            if !self.test_bit(bit) {
                return false;
            }
        }
        true
    }

    /// Find the longest run of clear bits
    pub fn find_longest_run_of_clear(&self) -> (u32, u32) {
        if self.buffer.is_null() {
            return (0, 0);
        }

        let mut best_start = 0u32;
        let mut best_length = 0u32;
        let mut current_start = 0u32;
        let mut current_length = 0u32;
        let mut in_run = false;

        for bit in 0..self.size_of_bit_map {
            if !self.test_bit(bit) {
                if !in_run {
                    in_run = true;
                    current_start = bit;
                    current_length = 1;
                } else {
                    current_length += 1;
                }
            } else {
                if in_run && current_length > best_length {
                    best_start = current_start;
                    best_length = current_length;
                }
                in_run = false;
            }
        }

        // Check final run
        if in_run && current_length > best_length {
            best_start = current_start;
            best_length = current_length;
        }

        (best_start, best_length)
    }
}

impl Default for RtlBitmap {
    fn default() -> Self {
        Self {
            size_of_bit_map: 0,
            buffer: ptr::null_mut(),
        }
    }
}

// NT API compatibility type alias
#[allow(non_camel_case_types)]
pub type RTL_BITMAP = RtlBitmap;
#[allow(non_camel_case_types)]
pub type PRTL_BITMAP = *mut RtlBitmap;

/// Initialize a bitmap (NT API)
#[inline]
pub fn rtl_initialize_bitmap(bitmap: &mut RtlBitmap, buffer: *mut u32, size_bits: u32) {
    bitmap.size_of_bit_map = size_bits;
    bitmap.buffer = buffer;
}

/// Clear all bits (NT API)
#[inline]
pub fn rtl_clear_all_bits(bitmap: &mut RtlBitmap) {
    bitmap.clear_all_bits();
}

/// Set all bits (NT API)
#[inline]
pub fn rtl_set_all_bits(bitmap: &mut RtlBitmap) {
    bitmap.set_all_bits();
}

/// Set a single bit (NT API)
#[inline]
pub fn rtl_set_bit(bitmap: &mut RtlBitmap, bit: u32) {
    bitmap.set_bit(bit);
}

/// Clear a single bit (NT API)
#[inline]
pub fn rtl_clear_bit(bitmap: &mut RtlBitmap, bit: u32) {
    bitmap.clear_bit(bit);
}

/// Test a single bit (NT API)
#[inline]
pub fn rtl_test_bit(bitmap: &RtlBitmap, bit: u32) -> bool {
    bitmap.test_bit(bit)
}

/// Set a range of bits (NT API)
#[inline]
pub fn rtl_set_bits(bitmap: &mut RtlBitmap, start: u32, count: u32) {
    bitmap.set_bits(start, count);
}

/// Clear a range of bits (NT API)
#[inline]
pub fn rtl_clear_bits(bitmap: &mut RtlBitmap, start: u32, count: u32) {
    bitmap.clear_bits(start, count);
}

/// Find first set bit (NT API)
#[inline]
pub fn rtl_find_set_bits(bitmap: &RtlBitmap, count: u32, _hint: u32) -> u32 {
    bitmap.find_set_bits(count).unwrap_or(!0u32)
}

/// Find first clear bit (NT API)
#[inline]
pub fn rtl_find_clear_bits(bitmap: &RtlBitmap, count: u32, _hint: u32) -> u32 {
    bitmap.find_clear_bits(count).unwrap_or(!0u32)
}

/// Find and set clear bits (NT API)
#[inline]
pub fn rtl_find_clear_bits_and_set(bitmap: &mut RtlBitmap, count: u32, _hint: u32) -> u32 {
    bitmap.find_clear_bits_and_set(count).unwrap_or(!0u32)
}

/// Find and clear set bits (NT API)
#[inline]
pub fn rtl_find_set_bits_and_clear(bitmap: &mut RtlBitmap, count: u32, _hint: u32) -> u32 {
    bitmap.find_set_bits_and_clear(count).unwrap_or(!0u32)
}

/// Count set bits (NT API)
#[inline]
pub fn rtl_number_of_set_bits(bitmap: &RtlBitmap) -> u32 {
    bitmap.number_of_set_bits()
}

/// Count clear bits (NT API)
#[inline]
pub fn rtl_number_of_clear_bits(bitmap: &RtlBitmap) -> u32 {
    bitmap.number_of_clear_bits()
}

/// Check if all bits in range are set (NT API)
#[inline]
pub fn rtl_are_bits_set(bitmap: &RtlBitmap, start: u32, count: u32) -> bool {
    bitmap.are_bits_set(start, count)
}

/// Check if all bits in range are clear (NT API)
#[inline]
pub fn rtl_are_bits_clear(bitmap: &RtlBitmap, start: u32, count: u32) -> bool {
    bitmap.are_bits_clear(start, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_operations() {
        let mut buffer = [0u32; 4];
        let mut bitmap = RtlBitmap::new(&mut buffer);

        assert_eq!(bitmap.size(), 128);
        assert!(!bitmap.test_bit(0));

        bitmap.set_bit(42);
        assert!(bitmap.test_bit(42));
        assert!(!bitmap.test_bit(41));
        assert!(!bitmap.test_bit(43));

        bitmap.clear_bit(42);
        assert!(!bitmap.test_bit(42));
    }

    #[test]
    fn test_find_clear_bits() {
        let mut buffer = [0u32; 4];
        let mut bitmap = RtlBitmap::new(&mut buffer);

        // Set some bits
        bitmap.set_bits(0, 10);
        bitmap.set_bits(20, 5);

        // Find 8 clear bits - should find at position 10
        let result = bitmap.find_clear_bits(8);
        assert_eq!(result, Some(10));

        // Find 10 clear bits - should find at position 25
        let result = bitmap.find_clear_bits(10);
        assert_eq!(result, Some(25));
    }

    #[test]
    fn test_count_bits() {
        let mut buffer = [0u32; 4];
        let mut bitmap = RtlBitmap::new(&mut buffer);

        assert_eq!(bitmap.number_of_set_bits(), 0);
        assert_eq!(bitmap.number_of_clear_bits(), 128);

        bitmap.set_bits(0, 32);
        assert_eq!(bitmap.number_of_set_bits(), 32);
        assert_eq!(bitmap.number_of_clear_bits(), 96);
    }

    #[test]
    fn test_set_all_clear_all() {
        let mut buffer = [0u32; 2];
        let mut bitmap = RtlBitmap::new(&mut buffer);

        bitmap.set_all_bits();
        assert_eq!(bitmap.number_of_set_bits(), 64);

        bitmap.clear_all_bits();
        assert_eq!(bitmap.number_of_set_bits(), 0);
    }
}
