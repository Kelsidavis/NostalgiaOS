//! Registry Cell Storage
//!
//! In NT's registry, cells are the fundamental storage units within a hive.
//! A cell can contain:
//! - Key nodes (directories)
//! - Value nodes (data)
//! - Security descriptors
//! - Subkey lists
//!
//! # Cell Organization
//! Cells are stored in bins (pages), and referenced by cell indices.
//! A cell index encodes both the bin and offset within the bin.
//!
//! For our simplified implementation, we use a flat cell table.

use core::sync::atomic::{AtomicU32, Ordering};

/// Cell index type
pub type CellIndex = u32;

/// Invalid cell index
pub const HCELL_NIL: CellIndex = u32::MAX;

/// Maximum cells per hive
pub const MAX_CELLS_PER_HIVE: usize = 512;

/// Cell types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum CmCellType {
    /// Free cell
    #[default]
    Free = 0,
    /// Key node cell
    KeyNode = 1,
    /// Key value cell
    KeyValue = 2,
    /// Key security cell
    KeySecurity = 3,
    /// Subkey list cell
    SubkeyList = 4,
    /// Value list cell
    ValueList = 5,
}


/// Cell header
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CmCellHeader {
    /// Cell size (including header)
    /// Negative size indicates free cell (NT convention)
    pub size: i32,
    /// Cell type
    pub cell_type: CmCellType,
    /// Flags
    pub flags: u8,
    /// Reference count
    pub ref_count: u16,
}

impl CmCellHeader {
    pub const fn new(size: i32, cell_type: CmCellType) -> Self {
        Self {
            size,
            cell_type,
            flags: 0,
            ref_count: 0,
        }
    }

    pub const fn empty() -> Self {
        Self::new(0, CmCellType::Free)
    }

    /// Check if cell is free
    pub fn is_free(&self) -> bool {
        self.size < 0 || self.cell_type == CmCellType::Free
    }

    /// Check if cell is allocated
    pub fn is_allocated(&self) -> bool {
        self.size > 0 && self.cell_type != CmCellType::Free
    }

    /// Get actual size (absolute value)
    pub fn actual_size(&self) -> u32 {
        self.size.unsigned_abs()
    }

    /// Mark as free
    pub fn mark_free(&mut self) {
        self.size = -(self.size.abs());
        self.cell_type = CmCellType::Free;
        self.ref_count = 0;
    }

    /// Mark as allocated
    pub fn mark_allocated(&mut self, cell_type: CmCellType) {
        self.size = self.size.abs();
        self.cell_type = cell_type;
        self.ref_count = 1;
    }
}

impl Default for CmCellHeader {
    fn default() -> Self {
        Self::empty()
    }
}

/// Cell data storage
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CmCell {
    /// Cell header
    pub header: CmCellHeader,
    /// Payload - stores a key index, value index, or other data
    pub key_index: u32,
    /// Additional data depending on cell type
    pub data: [u32; 6],
}

impl CmCell {
    pub const fn empty() -> Self {
        Self {
            header: CmCellHeader::empty(),
            key_index: u32::MAX,
            data: [0; 6],
        }
    }

    /// Create a key cell
    pub fn new_key_cell(key_index: u32) -> Self {
        let mut cell = Self::empty();
        cell.header.size = 32; // Fixed size for simplicity
        cell.header.cell_type = CmCellType::KeyNode;
        cell.header.ref_count = 1;
        cell.key_index = key_index;
        cell
    }

    /// Create a value cell
    pub fn new_value_cell(value_offset: u32) -> Self {
        let mut cell = Self::empty();
        cell.header.size = 32;
        cell.header.cell_type = CmCellType::KeyValue;
        cell.header.ref_count = 1;
        cell.key_index = value_offset;
        cell
    }

    /// Check if cell is free
    pub fn is_free(&self) -> bool {
        self.header.is_free()
    }

    /// Check if cell is allocated
    pub fn is_allocated(&self) -> bool {
        self.header.is_allocated()
    }

    /// Clear the cell
    pub fn clear(&mut self) {
        *self = Self::empty();
    }
}

impl Default for CmCell {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Cell Table per Hive
// ============================================================================

/// Cell table for a hive
#[repr(C)]
pub struct CmCellTable {
    /// Cells
    pub cells: [CmCell; MAX_CELLS_PER_HIVE],
    /// Free cell bitmap
    pub free_bitmap: [u64; MAX_CELLS_PER_HIVE.div_ceil(64)],
    /// Free cell count
    pub free_count: AtomicU32,
    /// Allocated cell count
    pub allocated_count: AtomicU32,
}

impl CmCellTable {
    /// Create a new empty cell table
    pub const fn new() -> Self {
        Self {
            cells: [CmCell::empty(); MAX_CELLS_PER_HIVE],
            free_bitmap: [0; MAX_CELLS_PER_HIVE.div_ceil(64)],
            free_count: AtomicU32::new(MAX_CELLS_PER_HIVE as u32),
            allocated_count: AtomicU32::new(0),
        }
    }

    /// Allocate a cell
    pub fn allocate(&mut self, cell_type: CmCellType) -> Option<CellIndex> {
        // Find a free cell
        for (word_idx, word) in self.free_bitmap.iter_mut().enumerate() {
            if *word != u64::MAX {
                let bit_idx = (!*word).trailing_zeros() as usize;
                let cell_idx = word_idx * 64 + bit_idx;

                if cell_idx >= MAX_CELLS_PER_HIVE {
                    break;
                }

                // Mark as allocated
                *word |= 1u64 << bit_idx;
                self.free_count.fetch_sub(1, Ordering::SeqCst);
                self.allocated_count.fetch_add(1, Ordering::SeqCst);

                // Initialize cell
                self.cells[cell_idx].header.mark_allocated(cell_type);

                return Some(cell_idx as CellIndex);
            }
        }

        None
    }

    /// Free a cell
    pub fn free(&mut self, cell_index: CellIndex) {
        let idx = cell_index as usize;
        if idx >= MAX_CELLS_PER_HIVE {
            return;
        }

        // Check if already free
        let word_idx = idx / 64;
        let bit_idx = idx % 64;
        if (self.free_bitmap[word_idx] & (1u64 << bit_idx)) == 0 {
            return; // Already free
        }

        // Mark as free
        self.cells[idx].clear();
        self.free_bitmap[word_idx] &= !(1u64 << bit_idx);
        self.free_count.fetch_add(1, Ordering::SeqCst);
        self.allocated_count.fetch_sub(1, Ordering::SeqCst);
    }

    /// Get a cell by index
    pub fn get(&self, cell_index: CellIndex) -> Option<&CmCell> {
        let idx = cell_index as usize;
        if idx < MAX_CELLS_PER_HIVE && self.cells[idx].is_allocated() {
            Some(&self.cells[idx])
        } else {
            None
        }
    }

    /// Get a mutable cell by index
    pub fn get_mut(&mut self, cell_index: CellIndex) -> Option<&mut CmCell> {
        let idx = cell_index as usize;
        if idx < MAX_CELLS_PER_HIVE && self.cells[idx].is_allocated() {
            Some(&mut self.cells[idx])
        } else {
            None
        }
    }

    /// Get statistics
    pub fn stats(&self) -> CellTableStats {
        CellTableStats {
            total: MAX_CELLS_PER_HIVE as u32,
            free: self.free_count.load(Ordering::SeqCst),
            allocated: self.allocated_count.load(Ordering::SeqCst),
        }
    }
}

impl Default for CmCellTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Cell table statistics
#[derive(Debug, Clone, Copy)]
pub struct CellTableStats {
    pub total: u32,
    pub free: u32,
    pub allocated: u32,
}

/// Cell flags
pub mod cell_flags {
    /// Cell is dirty (needs flush)
    pub const CELL_DIRTY: u8 = 0x01;
    /// Cell is volatile
    pub const CELL_VOLATILE: u8 = 0x02;
    /// Cell is locked
    pub const CELL_LOCKED: u8 = 0x04;
}

/// Initialize cell subsystem
pub fn init() {
    crate::serial_println!("[CM] Cell subsystem initialized");
}
