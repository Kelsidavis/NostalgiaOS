//! Dynamic Pointer Array (DPA) and Dynamic Structure Array (DSA) Implementation
//!
//! Windows COM helper arrays for managing collections of pointers and structures.
//! Based on Windows Server 2003 shlwapi.h.
//!
//! # Features
//!
//! - Dynamic pointer arrays (DPA)
//! - Dynamic structure arrays (DSA)
//! - Sorting and searching
//! - Stream serialization
//!
//! # References
//!
//! - `public/sdk/inc/shlwapi.h` - DPA/DSA functions

use crate::ke::spinlock::SpinLock;

// ============================================================================
// Constants
// ============================================================================

/// Maximum DPA handles
pub const MAX_DPA_HANDLES: usize = 64;

/// Maximum DSA handles
pub const MAX_DSA_HANDLES: usize = 64;

/// Default growth amount
pub const DEFAULT_GROWTH: usize = 8;

/// Maximum items per array
pub const MAX_ARRAY_ITEMS: usize = 256;

/// DPA/DSA handle types
pub type HDPA = usize;
pub type HDSA = usize;

/// Null handles
pub const NULL_HDPA: HDPA = 0;
pub const NULL_HDSA: HDSA = 0;

// ============================================================================
// Compare Function Types
// ============================================================================

/// DPA compare function type
pub type DpaCompareFunc = fn(p1: usize, p2: usize, lparam: isize) -> i32;

/// DSA compare function type
pub type DsaCompareFunc = fn(p1: &[u8], p2: &[u8], lparam: isize) -> i32;

/// DPA enumeration callback
pub type DpaEnumCallback = fn(p: usize, data: usize) -> bool;

/// DSA enumeration callback
pub type DsaEnumCallback = fn(p: &[u8], data: usize) -> bool;

// ============================================================================
// DPA Merge Flags
// ============================================================================

/// Merge unique
pub const DPAM_SORTED: u32 = 0x0001;

/// Merge normal
pub const DPAM_NORMAL: u32 = 0x0002;

/// Merge union
pub const DPAM_UNION: u32 = 0x0004;

/// Merge intersect
pub const DPAM_INTERSECT: u32 = 0x0008;

// ============================================================================
// Search Flags
// ============================================================================

/// Search from start
pub const DPAS_SORTED: u32 = 0x0001;

/// Insert if not found
pub const DPAS_INSERTBEFORE: u32 = 0x0002;

/// Insert after if not found
pub const DPAS_INSERTAFTER: u32 = 0x0004;

// ============================================================================
// Dynamic Pointer Array (DPA)
// ============================================================================

/// Dynamic pointer array
#[derive(Clone)]
pub struct Dpa {
    /// Is this slot in use
    pub in_use: bool,
    /// Pointer array
    pub items: [usize; MAX_ARRAY_ITEMS],
    /// Current item count
    pub count: usize,
    /// Allocated capacity
    pub capacity: usize,
    /// Growth amount
    pub growth: usize,
}

impl Dpa {
    /// Create empty DPA
    pub const fn new() -> Self {
        Self {
            in_use: false,
            items: [0; MAX_ARRAY_ITEMS],
            count: 0,
            capacity: MAX_ARRAY_ITEMS,
            growth: DEFAULT_GROWTH,
        }
    }

    /// Reset state
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Get item at index
    pub fn get(&self, index: usize) -> Option<usize> {
        if index < self.count {
            Some(self.items[index])
        } else {
            None
        }
    }

    /// Set item at index
    pub fn set(&mut self, index: usize, ptr: usize) -> bool {
        if index < self.count {
            self.items[index] = ptr;
            true
        } else {
            false
        }
    }

    /// Get pointer to item (returns index for pointer arithmetic)
    pub fn get_ptr(&self, index: usize) -> Option<usize> {
        if index < self.count {
            Some(index)
        } else {
            None
        }
    }

    /// Insert at index
    pub fn insert(&mut self, index: usize, ptr: usize) -> bool {
        if self.count >= MAX_ARRAY_ITEMS {
            return false;
        }

        let insert_at = if index > self.count { self.count } else { index };

        // Shift items up
        for i in (insert_at..self.count).rev() {
            self.items[i + 1] = self.items[i];
        }

        self.items[insert_at] = ptr;
        self.count += 1;
        true
    }

    /// Append item
    pub fn append(&mut self, ptr: usize) -> bool {
        self.insert(self.count, ptr)
    }

    /// Delete item at index
    pub fn delete(&mut self, index: usize) -> Option<usize> {
        if index >= self.count {
            return None;
        }

        let ptr = self.items[index];

        // Shift items down
        for i in index..self.count - 1 {
            self.items[i] = self.items[i + 1];
        }

        self.count -= 1;
        Some(ptr)
    }

    /// Delete all items
    pub fn delete_all(&mut self) {
        self.count = 0;
    }

    /// Search for item
    pub fn search(&self, ptr: usize, start: usize, compare: DpaCompareFunc, lparam: isize, flags: u32) -> Option<usize> {
        if flags & DPAS_SORTED != 0 {
            // Binary search
            self.binary_search(ptr, compare, lparam)
        } else {
            // Linear search
            for i in start..self.count {
                if compare(self.items[i], ptr, lparam) == 0 {
                    return Some(i);
                }
            }
            None
        }
    }

    /// Binary search
    fn binary_search(&self, ptr: usize, compare: DpaCompareFunc, lparam: isize) -> Option<usize> {
        if self.count == 0 {
            return None;
        }

        let mut low = 0;
        let mut high = self.count;

        while low < high {
            let mid = low + (high - low) / 2;
            let cmp = compare(self.items[mid], ptr, lparam);

            if cmp == 0 {
                return Some(mid);
            } else if cmp < 0 {
                low = mid + 1;
            } else {
                high = mid;
            }
        }

        None
    }

    /// Sort the array
    pub fn sort(&mut self, compare: DpaCompareFunc, lparam: isize) {
        // Simple insertion sort (stable)
        for i in 1..self.count {
            let key = self.items[i];
            let mut j = i;
            while j > 0 && compare(self.items[j - 1], key, lparam) > 0 {
                self.items[j] = self.items[j - 1];
                j -= 1;
            }
            self.items[j] = key;
        }
    }

    /// Clone array
    pub fn clone_array(&self) -> Self {
        self.clone()
    }
}

// ============================================================================
// Dynamic Structure Array (DSA)
// ============================================================================

/// Maximum structure size for DSA
pub const MAX_DSA_STRUCT_SIZE: usize = 64;

/// Dynamic structure array
#[derive(Clone)]
pub struct Dsa {
    /// Is this slot in use
    pub in_use: bool,
    /// Structure size
    pub struct_size: usize,
    /// Item storage (flattened)
    pub data: [u8; MAX_ARRAY_ITEMS * MAX_DSA_STRUCT_SIZE],
    /// Current item count
    pub count: usize,
    /// Growth amount
    pub growth: usize,
}

impl Dsa {
    /// Create empty DSA
    pub const fn new() -> Self {
        Self {
            in_use: false,
            struct_size: 0,
            data: [0; MAX_ARRAY_ITEMS * MAX_DSA_STRUCT_SIZE],
            count: 0,
            growth: DEFAULT_GROWTH,
        }
    }

    /// Create with struct size
    pub fn with_size(struct_size: usize, growth: usize) -> Self {
        Self {
            in_use: true,
            struct_size: struct_size.min(MAX_DSA_STRUCT_SIZE),
            data: [0; MAX_ARRAY_ITEMS * MAX_DSA_STRUCT_SIZE],
            count: 0,
            growth,
        }
    }

    /// Reset state
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Get item at index
    pub fn get(&self, index: usize) -> Option<&[u8]> {
        if index < self.count && self.struct_size > 0 {
            let offset = index * self.struct_size;
            Some(&self.data[offset..offset + self.struct_size])
        } else {
            None
        }
    }

    /// Get mutable item at index
    pub fn get_mut(&mut self, index: usize) -> Option<&mut [u8]> {
        if index < self.count && self.struct_size > 0 {
            let offset = index * self.struct_size;
            Some(&mut self.data[offset..offset + self.struct_size])
        } else {
            None
        }
    }

    /// Set item at index
    pub fn set(&mut self, index: usize, item: &[u8]) -> bool {
        if index < self.count && self.struct_size > 0 {
            let offset = index * self.struct_size;
            let len = item.len().min(self.struct_size);
            self.data[offset..offset + len].copy_from_slice(&item[..len]);
            true
        } else {
            false
        }
    }

    /// Insert at index
    pub fn insert(&mut self, index: usize, item: &[u8]) -> bool {
        if self.struct_size == 0 {
            return false;
        }

        let max_items = MAX_ARRAY_ITEMS * MAX_DSA_STRUCT_SIZE / self.struct_size;
        if self.count >= max_items {
            return false;
        }

        let insert_at = if index > self.count { self.count } else { index };

        // Shift items up
        if insert_at < self.count {
            let src_start = insert_at * self.struct_size;
            let dst_start = (insert_at + 1) * self.struct_size;
            let move_len = (self.count - insert_at) * self.struct_size;

            // Copy backwards to avoid overlap issues
            for i in (0..move_len).rev() {
                self.data[dst_start + i] = self.data[src_start + i];
            }
        }

        // Insert new item
        let offset = insert_at * self.struct_size;
        let len = item.len().min(self.struct_size);
        self.data[offset..offset + len].copy_from_slice(&item[..len]);
        // Zero remaining bytes
        for i in len..self.struct_size {
            self.data[offset + i] = 0;
        }

        self.count += 1;
        true
    }

    /// Append item
    pub fn append(&mut self, item: &[u8]) -> bool {
        self.insert(self.count, item)
    }

    /// Delete item at index
    pub fn delete(&mut self, index: usize) -> bool {
        if index >= self.count || self.struct_size == 0 {
            return false;
        }

        // Shift items down
        let src_start = (index + 1) * self.struct_size;
        let dst_start = index * self.struct_size;
        let move_len = (self.count - index - 1) * self.struct_size;

        for i in 0..move_len {
            self.data[dst_start + i] = self.data[src_start + i];
        }

        self.count -= 1;
        true
    }

    /// Delete all items
    pub fn delete_all(&mut self) {
        self.count = 0;
    }

    /// Sort the array
    pub fn sort(&mut self, compare: DsaCompareFunc, lparam: isize) {
        if self.struct_size == 0 || self.count <= 1 {
            return;
        }

        // Simple insertion sort (stable)
        let mut temp = [0u8; MAX_DSA_STRUCT_SIZE];
        let mut temp2 = [0u8; MAX_DSA_STRUCT_SIZE];

        for i in 1..self.count {
            let offset_i = i * self.struct_size;
            temp[..self.struct_size].copy_from_slice(&self.data[offset_i..offset_i + self.struct_size]);

            let mut j = i;
            while j > 0 {
                let offset_j_minus_1 = (j - 1) * self.struct_size;
                // Copy to temp2 to avoid borrow conflict
                temp2[..self.struct_size].copy_from_slice(&self.data[offset_j_minus_1..offset_j_minus_1 + self.struct_size]);

                if compare(&temp2[..self.struct_size], &temp[..self.struct_size], lparam) <= 0 {
                    break;
                }

                let offset_j = j * self.struct_size;
                self.data[offset_j..offset_j + self.struct_size]
                    .copy_from_slice(&temp2[..self.struct_size]);
                j -= 1;
            }

            let offset_j = j * self.struct_size;
            self.data[offset_j..offset_j + self.struct_size]
                .copy_from_slice(&temp[..self.struct_size]);
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global DPA storage
static DPA_HANDLES: SpinLock<[Dpa; MAX_DPA_HANDLES]> =
    SpinLock::new([const { Dpa::new() }; MAX_DPA_HANDLES]);

/// Global DSA storage
static DSA_HANDLES: SpinLock<[Dsa; MAX_DSA_HANDLES]> =
    SpinLock::new([const { Dsa::new() }; MAX_DSA_HANDLES]);

// ============================================================================
// DPA Public API
// ============================================================================

/// Initialize DPA/DSA subsystem
pub fn init() {
    crate::serial_println!("[USER] DPA/DSA arrays initialized");
}

/// Create a DPA
pub fn dpa_create(growth: usize) -> HDPA {
    let mut dpas = DPA_HANDLES.lock();

    for (i, dpa) in dpas.iter_mut().enumerate() {
        if !dpa.in_use {
            dpa.reset();
            dpa.in_use = true;
            dpa.growth = if growth > 0 { growth } else { DEFAULT_GROWTH };
            return i + 1;
        }
    }

    NULL_HDPA
}

/// Destroy a DPA
pub fn dpa_destroy(hdpa: HDPA) -> bool {
    if hdpa == NULL_HDPA {
        return false;
    }

    let mut dpas = DPA_HANDLES.lock();
    let idx = hdpa - 1;

    if idx >= MAX_DPA_HANDLES || !dpas[idx].in_use {
        return false;
    }

    dpas[idx].reset();
    true
}

/// Clone a DPA
pub fn dpa_clone(hdpa: HDPA) -> HDPA {
    if hdpa == NULL_HDPA {
        return NULL_HDPA;
    }

    let dpas = DPA_HANDLES.lock();
    let idx = hdpa - 1;

    if idx >= MAX_DPA_HANDLES || !dpas[idx].in_use {
        return NULL_HDPA;
    }

    let cloned = dpas[idx].clone_array();
    drop(dpas);

    // Create new handle
    let mut dpas = DPA_HANDLES.lock();
    for (i, dpa) in dpas.iter_mut().enumerate() {
        if !dpa.in_use {
            *dpa = cloned;
            dpa.in_use = true;
            return i + 1;
        }
    }

    NULL_HDPA
}

/// Get DPA item count
pub fn dpa_get_count(hdpa: HDPA) -> usize {
    if hdpa == NULL_HDPA {
        return 0;
    }

    let dpas = DPA_HANDLES.lock();
    let idx = hdpa - 1;

    if idx >= MAX_DPA_HANDLES || !dpas[idx].in_use {
        return 0;
    }

    dpas[idx].count
}

/// Get DPA item
pub fn dpa_get_ptr(hdpa: HDPA, index: usize) -> usize {
    if hdpa == NULL_HDPA {
        return 0;
    }

    let dpas = DPA_HANDLES.lock();
    let idx = hdpa - 1;

    if idx >= MAX_DPA_HANDLES || !dpas[idx].in_use {
        return 0;
    }

    dpas[idx].get(index).unwrap_or(0)
}

/// Set DPA item
pub fn dpa_set_ptr(hdpa: HDPA, index: usize, ptr: usize) -> bool {
    if hdpa == NULL_HDPA {
        return false;
    }

    let mut dpas = DPA_HANDLES.lock();
    let idx = hdpa - 1;

    if idx >= MAX_DPA_HANDLES || !dpas[idx].in_use {
        return false;
    }

    dpas[idx].set(index, ptr)
}

/// Insert DPA item
pub fn dpa_insert_ptr(hdpa: HDPA, index: usize, ptr: usize) -> bool {
    if hdpa == NULL_HDPA {
        return false;
    }

    let mut dpas = DPA_HANDLES.lock();
    let idx = hdpa - 1;

    if idx >= MAX_DPA_HANDLES || !dpas[idx].in_use {
        return false;
    }

    dpas[idx].insert(index, ptr)
}

/// Append DPA item
pub fn dpa_append_ptr(hdpa: HDPA, ptr: usize) -> bool {
    if hdpa == NULL_HDPA {
        return false;
    }

    let mut dpas = DPA_HANDLES.lock();
    let idx = hdpa - 1;

    if idx >= MAX_DPA_HANDLES || !dpas[idx].in_use {
        return false;
    }

    dpas[idx].append(ptr)
}

/// Delete DPA item
pub fn dpa_delete_ptr(hdpa: HDPA, index: usize) -> usize {
    if hdpa == NULL_HDPA {
        return 0;
    }

    let mut dpas = DPA_HANDLES.lock();
    let idx = hdpa - 1;

    if idx >= MAX_DPA_HANDLES || !dpas[idx].in_use {
        return 0;
    }

    dpas[idx].delete(index).unwrap_or(0)
}

/// Delete all DPA items
pub fn dpa_delete_all_ptrs(hdpa: HDPA) -> bool {
    if hdpa == NULL_HDPA {
        return false;
    }

    let mut dpas = DPA_HANDLES.lock();
    let idx = hdpa - 1;

    if idx >= MAX_DPA_HANDLES || !dpas[idx].in_use {
        return false;
    }

    dpas[idx].delete_all();
    true
}

/// Sort DPA
pub fn dpa_sort(hdpa: HDPA, compare: DpaCompareFunc, lparam: isize) -> bool {
    if hdpa == NULL_HDPA {
        return false;
    }

    let mut dpas = DPA_HANDLES.lock();
    let idx = hdpa - 1;

    if idx >= MAX_DPA_HANDLES || !dpas[idx].in_use {
        return false;
    }

    dpas[idx].sort(compare, lparam);
    true
}

/// Search DPA
pub fn dpa_search(hdpa: HDPA, ptr: usize, start: usize, compare: DpaCompareFunc, lparam: isize, flags: u32) -> Option<usize> {
    if hdpa == NULL_HDPA {
        return None;
    }

    let dpas = DPA_HANDLES.lock();
    let idx = hdpa - 1;

    if idx >= MAX_DPA_HANDLES || !dpas[idx].in_use {
        return None;
    }

    dpas[idx].search(ptr, start, compare, lparam, flags)
}

// ============================================================================
// DSA Public API
// ============================================================================

/// Create a DSA
pub fn dsa_create(struct_size: usize, growth: usize) -> HDSA {
    if struct_size == 0 || struct_size > MAX_DSA_STRUCT_SIZE {
        return NULL_HDSA;
    }

    let mut dsas = DSA_HANDLES.lock();

    for (i, dsa) in dsas.iter_mut().enumerate() {
        if !dsa.in_use {
            *dsa = Dsa::with_size(struct_size, if growth > 0 { growth } else { DEFAULT_GROWTH });
            return i + 1;
        }
    }

    NULL_HDSA
}

/// Destroy a DSA
pub fn dsa_destroy(hdsa: HDSA) -> bool {
    if hdsa == NULL_HDSA {
        return false;
    }

    let mut dsas = DSA_HANDLES.lock();
    let idx = hdsa - 1;

    if idx >= MAX_DSA_HANDLES || !dsas[idx].in_use {
        return false;
    }

    dsas[idx].reset();
    true
}

/// Clone a DSA
pub fn dsa_clone(hdsa: HDSA) -> HDSA {
    if hdsa == NULL_HDSA {
        return NULL_HDSA;
    }

    let dsas = DSA_HANDLES.lock();
    let idx = hdsa - 1;

    if idx >= MAX_DSA_HANDLES || !dsas[idx].in_use {
        return NULL_HDSA;
    }

    let cloned = dsas[idx].clone();
    drop(dsas);

    // Create new handle
    let mut dsas = DSA_HANDLES.lock();
    for (i, dsa) in dsas.iter_mut().enumerate() {
        if !dsa.in_use {
            *dsa = cloned;
            dsa.in_use = true;
            return i + 1;
        }
    }

    NULL_HDSA
}

/// Get DSA item count
pub fn dsa_get_item_count(hdsa: HDSA) -> usize {
    if hdsa == NULL_HDSA {
        return 0;
    }

    let dsas = DSA_HANDLES.lock();
    let idx = hdsa - 1;

    if idx >= MAX_DSA_HANDLES || !dsas[idx].in_use {
        return 0;
    }

    dsas[idx].count
}

/// Get DSA item pointer
pub fn dsa_get_item_ptr(hdsa: HDSA, index: usize, buffer: &mut [u8]) -> bool {
    if hdsa == NULL_HDSA {
        return false;
    }

    let dsas = DSA_HANDLES.lock();
    let idx = hdsa - 1;

    if idx >= MAX_DSA_HANDLES || !dsas[idx].in_use {
        return false;
    }

    if let Some(item) = dsas[idx].get(index) {
        let len = item.len().min(buffer.len());
        buffer[..len].copy_from_slice(&item[..len]);
        true
    } else {
        false
    }
}

/// Set DSA item
pub fn dsa_set_item(hdsa: HDSA, index: usize, item: &[u8]) -> bool {
    if hdsa == NULL_HDSA {
        return false;
    }

    let mut dsas = DSA_HANDLES.lock();
    let idx = hdsa - 1;

    if idx >= MAX_DSA_HANDLES || !dsas[idx].in_use {
        return false;
    }

    dsas[idx].set(index, item)
}

/// Insert DSA item
pub fn dsa_insert_item(hdsa: HDSA, index: usize, item: &[u8]) -> bool {
    if hdsa == NULL_HDSA {
        return false;
    }

    let mut dsas = DSA_HANDLES.lock();
    let idx = hdsa - 1;

    if idx >= MAX_DSA_HANDLES || !dsas[idx].in_use {
        return false;
    }

    dsas[idx].insert(index, item)
}

/// Append DSA item
pub fn dsa_append_item(hdsa: HDSA, item: &[u8]) -> bool {
    if hdsa == NULL_HDSA {
        return false;
    }

    let mut dsas = DSA_HANDLES.lock();
    let idx = hdsa - 1;

    if idx >= MAX_DSA_HANDLES || !dsas[idx].in_use {
        return false;
    }

    dsas[idx].append(item)
}

/// Delete DSA item
pub fn dsa_delete_item(hdsa: HDSA, index: usize) -> bool {
    if hdsa == NULL_HDSA {
        return false;
    }

    let mut dsas = DSA_HANDLES.lock();
    let idx = hdsa - 1;

    if idx >= MAX_DSA_HANDLES || !dsas[idx].in_use {
        return false;
    }

    dsas[idx].delete(index)
}

/// Delete all DSA items
pub fn dsa_delete_all_items(hdsa: HDSA) -> bool {
    if hdsa == NULL_HDSA {
        return false;
    }

    let mut dsas = DSA_HANDLES.lock();
    let idx = hdsa - 1;

    if idx >= MAX_DSA_HANDLES || !dsas[idx].in_use {
        return false;
    }

    dsas[idx].delete_all();
    true
}

/// Sort DSA
pub fn dsa_sort(hdsa: HDSA, compare: DsaCompareFunc, lparam: isize) -> bool {
    if hdsa == NULL_HDSA {
        return false;
    }

    let mut dsas = DSA_HANDLES.lock();
    let idx = hdsa - 1;

    if idx >= MAX_DSA_HANDLES || !dsas[idx].in_use {
        return false;
    }

    dsas[idx].sort(compare, lparam);
    true
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> DpaStats {
    let dpas = DPA_HANDLES.lock();
    let dsas = DSA_HANDLES.lock();

    let mut dpa_count = 0;
    let mut dpa_total_items = 0;
    let mut dsa_count = 0;
    let mut dsa_total_items = 0;

    for dpa in dpas.iter() {
        if dpa.in_use {
            dpa_count += 1;
            dpa_total_items += dpa.count;
        }
    }

    for dsa in dsas.iter() {
        if dsa.in_use {
            dsa_count += 1;
            dsa_total_items += dsa.count;
        }
    }

    DpaStats {
        max_dpa_handles: MAX_DPA_HANDLES,
        active_dpa_handles: dpa_count,
        total_dpa_items: dpa_total_items,
        max_dsa_handles: MAX_DSA_HANDLES,
        active_dsa_handles: dsa_count,
        total_dsa_items: dsa_total_items,
    }
}

/// DPA/DSA statistics
#[derive(Debug, Clone, Copy)]
pub struct DpaStats {
    pub max_dpa_handles: usize,
    pub active_dpa_handles: usize,
    pub total_dpa_items: usize,
    pub max_dsa_handles: usize,
    pub active_dsa_handles: usize,
    pub total_dsa_items: usize,
}
