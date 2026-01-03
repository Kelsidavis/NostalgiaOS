//! Range List Management
//!
//! RTL-compatible range list implementation for tracking resource allocations.

extern crate alloc;


/// Maximum ranges per list
pub const MAX_RANGES: usize = 128;

/// Range entry
#[derive(Debug, Clone, Copy)]
pub struct RangeEntry {
    /// Start of range
    pub start: u64,
    /// End of range (inclusive)
    pub end: u64,
    /// Range attributes
    pub attributes: u8,
    /// Owner (device handle or 0)
    pub owner: u32,
    /// Flags for this entry
    pub flags: u8,
}

impl RangeEntry {
    pub const fn new() -> Self {
        Self {
            start: 0,
            end: 0,
            attributes: 0,
            owner: 0,
            flags: 0,
        }
    }

    /// Calculate length of range
    pub fn length(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Check if this range intersects with another
    pub fn intersects(&self, start: u64, end: u64) -> bool {
        !((self.start > end) || (self.end < start))
    }

    /// Check if this range contains another
    pub fn contains(&self, start: u64, end: u64) -> bool {
        self.start <= start && self.end >= end
    }
}

/// Range list for tracking allocations
#[derive(Clone)]
pub struct RangeList {
    /// Entries in the list
    pub entries: [RangeEntry; MAX_RANGES],
    /// Number of valid entries
    pub count: usize,
    /// Flags for the list
    pub flags: u32,
}

impl RangeList {
    pub const fn new() -> Self {
        const EMPTY: RangeEntry = RangeEntry::new();
        Self {
            entries: [EMPTY; MAX_RANGES],
            count: 0,
            flags: 0,
        }
    }

    /// Add a range to the list
    pub fn add_range(&mut self, start: u64, end: u64, attributes: u8, owner: u32) -> bool {
        if self.count >= MAX_RANGES {
            return false;
        }

        // Check for overlaps and merge if possible
        for i in 0..self.count {
            if self.entries[i].intersects(start, end) {
                // Merge ranges
                self.entries[i].start = self.entries[i].start.min(start);
                self.entries[i].end = self.entries[i].end.max(end);
                self.entries[i].attributes |= attributes;
                return true;
            }
        }

        // Add new entry
        self.entries[self.count] = RangeEntry {
            start,
            end,
            attributes,
            owner,
            flags: 0,
        };
        self.count += 1;

        // Sort by start address
        self.sort();

        true
    }

    /// Delete a range from the list
    pub fn delete_range(&mut self, start: u64, end: u64) -> bool {
        for i in 0..self.count {
            if self.entries[i].start == start && self.entries[i].end == end {
                // Remove by shifting
                for j in i..self.count - 1 {
                    self.entries[j] = self.entries[j + 1];
                }
                self.count -= 1;
                return true;
            }
        }
        false
    }

    /// Check if a range is available (no conflicts)
    pub fn is_range_available(&self, start: u64, end: u64, flags: u8) -> bool {
        for i in 0..self.count {
            if self.entries[i].intersects(start, end) {
                // Check if both are shareable
                let shared = (flags & super::range_flags::SHARED != 0) &&
                            (self.entries[i].attributes & super::range_flags::SHARED != 0);
                if !shared {
                    return false;
                }
            }
        }
        true
    }

    /// Find a conflict with a range
    pub fn find_conflict(&self, start: u64, end: u64) -> Option<RangeEntry> {
        for i in 0..self.count {
            if self.entries[i].intersects(start, end) {
                return Some(self.entries[i]);
            }
        }
        None
    }

    /// Find an available range within constraints
    pub fn find_available_range(
        &self,
        minimum: u64,
        maximum: u64,
        length: u64,
        alignment: u64,
        flags: u8,
    ) -> Option<u64> {
        let alignment = if alignment == 0 { 1 } else { alignment };

        // Align minimum up
        let mut current = (minimum + alignment - 1) & !(alignment - 1);

        while current + length - 1 <= maximum {
            let end = current + length - 1;

            if self.is_range_available(current, end, flags) {
                return Some(current);
            }

            // Find next position after any conflict
            let mut next = current + alignment;
            for i in 0..self.count {
                if self.entries[i].intersects(current, end) {
                    // Move past this conflict
                    let after = self.entries[i].end + 1;
                    let aligned = (after + alignment - 1) & !(alignment - 1);
                    if aligned > next {
                        next = aligned;
                    }
                }
            }

            current = next;
        }

        None
    }

    /// Clear the list
    pub fn clear(&mut self) {
        self.count = 0;
    }

    /// Sort entries by start address
    fn sort(&mut self) {
        // Simple bubble sort for small arrays
        for i in 0..self.count {
            for j in 0..self.count - 1 - i {
                if self.entries[j].start > self.entries[j + 1].start {
                    self.entries.swap(j, j + 1);
                }
            }
        }
    }

    /// Get range at index
    pub fn get(&self, index: usize) -> Option<&RangeEntry> {
        if index < self.count {
            Some(&self.entries[index])
        } else {
            None
        }
    }
}

/// Initialize range management
pub fn init() {
    crate::serial_println!("[ARB] Range list management initialized");
}

// ============================================================================
// RTL-compatible range functions
// ============================================================================

/// Add a range to a range list (RTL-compatible)
pub fn rtl_add_range(
    list: &mut RangeList,
    start: u64,
    end: u64,
    attributes: u8,
    _flags: u32,
    owner: u32,
) -> i32 {
    if list.add_range(start, end, attributes, owner) {
        0 // STATUS_SUCCESS
    } else {
        -1 // STATUS_INSUFFICIENT_RESOURCES
    }
}

/// Delete a range from a range list
pub fn rtl_delete_range(
    list: &mut RangeList,
    start: u64,
    end: u64,
    _owner: u32,
) -> i32 {
    if list.delete_range(start, end) {
        0
    } else {
        -2 // STATUS_RANGE_NOT_FOUND
    }
}

/// Find a range in a list
pub fn rtl_find_range(
    list: &RangeList,
    minimum: u64,
    maximum: u64,
    length: u32,
    alignment: u32,
    _flags: u32,
    available_attributes: u8,
) -> Option<u64> {
    list.find_available_range(minimum, maximum, length as u64, alignment as u64, available_attributes)
}

/// Check if a range is available
pub fn rtl_is_range_available(
    list: &RangeList,
    start: u64,
    end: u64,
    _flags: u32,
    available_attributes: u8,
) -> bool {
    list.is_range_available(start, end, available_attributes)
}

/// Copy a range list
pub fn rtl_copy_range_list(dest: &mut RangeList, src: &RangeList) {
    dest.entries = src.entries;
    dest.count = src.count;
    dest.flags = src.flags;
}

/// Merge two range lists
pub fn rtl_merge_range_lists(
    dest: &mut RangeList,
    src1: &RangeList,
    src2: &RangeList,
    _flags: u32,
) {
    dest.clear();

    for i in 0..src1.count {
        let entry = &src1.entries[i];
        dest.add_range(entry.start, entry.end, entry.attributes, entry.owner);
    }

    for i in 0..src2.count {
        let entry = &src2.entries[i];
        dest.add_range(entry.start, entry.end, entry.attributes, entry.owner);
    }
}

/// Invert a range list (available becomes used and vice versa)
pub fn rtl_invert_range_list(dest: &mut RangeList, src: &RangeList, total_start: u64, total_end: u64) {
    dest.clear();

    let mut current = total_start;

    for i in 0..src.count {
        let entry = &src.entries[i];
        if entry.start > current {
            // Gap before this range
            dest.add_range(current, entry.start - 1, 0, 0);
        }
        current = entry.end + 1;
    }

    // Gap after last range
    if current <= total_end {
        dest.add_range(current, total_end, 0, 0);
    }
}
