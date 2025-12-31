//! Ordering List Management
//!
//! Manages priority orderings for resource allocation.

extern crate alloc;

use alloc::vec::Vec;

/// Maximum orderings per list
pub const MAX_ORDERINGS: usize = 64;

/// Ordering entry
#[derive(Debug, Clone, Copy)]
pub struct Ordering {
    /// Start of range
    pub start: u64,
    /// End of range
    pub end: u64,
}

impl Ordering {
    pub const fn new() -> Self {
        Self { start: 0, end: 0 }
    }

    /// Calculate length of ordering
    pub fn length(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Check if this ordering intersects with a range
    pub fn intersects(&self, start: u64, end: u64) -> bool {
        !((self.start > end) || (self.end < start))
    }
}

/// Ordering list for allocation priority
#[derive(Clone)]
pub struct OrderingList {
    /// Entries in the list
    pub entries: [Ordering; MAX_ORDERINGS],
    /// Number of valid entries
    pub count: usize,
    /// Maximum entries allowed
    pub maximum: usize,
}

impl OrderingList {
    pub const fn new() -> Self {
        const EMPTY: Ordering = Ordering::new();
        Self {
            entries: [EMPTY; MAX_ORDERINGS],
            count: 0,
            maximum: MAX_ORDERINGS,
        }
    }

    /// Add an ordering to the list
    pub fn add(&mut self, start: u64, end: u64) -> bool {
        if self.count >= self.maximum {
            return false;
        }

        self.entries[self.count] = Ordering { start, end };
        self.count += 1;

        // Sort by start address
        self.sort();

        true
    }

    /// Remove an ordering from the list
    pub fn remove(&mut self, start: u64, end: u64) -> bool {
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

    /// Prune orderings to a specific range
    pub fn prune(&mut self, start: u64, end: u64) {
        let mut i = 0;
        while i < self.count {
            let ordering = &mut self.entries[i];

            if ordering.end < start || ordering.start > end {
                // Completely outside - remove
                for j in i..self.count - 1 {
                    self.entries[j] = self.entries[j + 1];
                }
                self.count -= 1;
            } else {
                // Clip to range
                if ordering.start < start {
                    ordering.start = start;
                }
                if ordering.end > end {
                    ordering.end = end;
                }
                i += 1;
            }
        }
    }

    /// Clear the list
    pub fn clear(&mut self) {
        self.count = 0;
    }

    /// Sort entries by start address
    fn sort(&mut self) {
        for i in 0..self.count {
            for j in 0..self.count - 1 - i {
                if self.entries[j].start > self.entries[j + 1].start {
                    self.entries.swap(j, j + 1);
                }
            }
        }
    }

    /// Get ordering at index
    pub fn get(&self, index: usize) -> Option<&Ordering> {
        if index < self.count {
            Some(&self.entries[index])
        } else {
            None
        }
    }

    /// Find which ordering a value falls into
    pub fn find_ordering(&self, value: u64) -> Option<usize> {
        for i in 0..self.count {
            if value >= self.entries[i].start && value <= self.entries[i].end {
                return Some(i);
            }
        }
        None
    }

    /// Calculate priority for a range (lower = higher priority)
    pub fn calculate_priority(&self, start: u64, end: u64, length: u64) -> i32 {
        // Priority is based on which ordering list entry we match
        // Earlier entries have lower (better) priority

        for i in 0..self.count {
            if self.entries[i].intersects(start, end) {
                // Check if the ordering has enough space
                let intersect_start = start.max(self.entries[i].start);
                let intersect_end = end.min(self.entries[i].end);
                let intersect_len = intersect_end - intersect_start + 1;

                if intersect_len >= length {
                    return (i + 1) as i32;
                }
            }
        }

        // No matching ordering - worst priority
        i32::MAX
    }
}

/// Initialize ordering management
pub fn init() {
    crate::serial_println!("[ARB] Ordering list management initialized");
}

// ============================================================================
// Arbiter ordering functions
// ============================================================================

/// Initialize an ordering list
pub fn arb_init_ordering_list(list: &mut OrderingList) {
    list.clear();
}

/// Free an ordering list
pub fn arb_free_ordering_list(list: &mut OrderingList) {
    list.clear();
}

/// Copy an ordering list
pub fn arb_copy_ordering_list(dest: &mut OrderingList, src: &OrderingList) {
    dest.entries = src.entries;
    dest.count = src.count;
    dest.maximum = src.maximum;
}

/// Add an ordering to a list
pub fn arb_add_ordering(list: &mut OrderingList, start: u64, end: u64) -> i32 {
    if list.add(start, end) {
        0 // STATUS_SUCCESS
    } else {
        -1 // STATUS_INSUFFICIENT_RESOURCES
    }
}

/// Prune an ordering list to a range
pub fn arb_prune_ordering(list: &mut OrderingList, start: u64, end: u64) -> i32 {
    list.prune(start, end);
    0 // STATUS_SUCCESS
}

/// Build default assignment ordering for a resource type
pub fn build_default_ordering(list: &mut OrderingList, resource_type: super::ResourceType) {
    list.clear();

    match resource_type {
        super::ResourceType::Port => {
            // I/O port allocation order
            // Prefer higher addresses first (less chance of conflicts)
            list.add(0x1000, 0xFFFF); // High ports
            list.add(0x0400, 0x0FFF); // Mid ports
            list.add(0x0100, 0x03FF); // Low ports
        }
        super::ResourceType::Memory => {
            // Memory allocation order
            // Prefer addresses above 1MB
            list.add(0x100000, 0xFFFFFFFF); // Above 1MB
            list.add(0x100000, 0xFFFFFFFFFFFF); // 64-bit addressable
        }
        super::ResourceType::Interrupt => {
            // IRQ allocation order
            // Prefer higher IRQs (less likely to conflict with system)
            list.add(9, 15);  // High IRQs
            list.add(3, 7);   // Mid IRQs
        }
        super::ResourceType::Dma => {
            // DMA channel allocation order
            list.add(5, 7);   // High DMA channels
            list.add(1, 3);   // Low DMA channels
            list.add(0, 0);   // Channel 0
        }
        super::ResourceType::BusNumber => {
            // Bus number allocation order
            list.add(1, 255); // All bus numbers
        }
        _ => {}
    }
}
