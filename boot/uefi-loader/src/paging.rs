//! Page table setup for kernel loading
//!
//! Sets up 4-level paging for x86_64:
//! - Identity maps first 4GB (so bootloader continues working after CR3 switch)
//! - Maps kernel to higher half at KERNEL_VIRTUAL_BASE
//!
//! Page table structure:
//! - PML4 (Page Map Level 4) - 512 entries, each covers 512GB
//! - PDPT (Page Directory Pointer Table) - 512 entries, each covers 1GB
//! - PD (Page Directory) - 512 entries, each covers 2MB
//! - PT (Page Table) - 512 entries, each covers 4KB
//!
//! We use 2MB huge pages where possible for efficiency.

#![allow(dead_code)] // Utility functions and constants for future use

use core::ptr;
use uefi::boot;
use uefi::mem::memory_map::MemoryType;

/// Page size (4 KB)
pub const PAGE_SIZE: u64 = 4096;

/// Large page size (2 MB)
pub const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// Number of entries in each page table level
const ENTRIES_PER_TABLE: usize = 512;

/// Page table entry flags
mod flags {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const USER: u64 = 1 << 2;
    pub const WRITE_THROUGH: u64 = 1 << 3;
    pub const CACHE_DISABLE: u64 = 1 << 4;
    pub const ACCESSED: u64 = 1 << 5;
    pub const DIRTY: u64 = 1 << 6;
    pub const HUGE_PAGE: u64 = 1 << 7; // For 2MB/1GB pages
    pub const GLOBAL: u64 = 1 << 8;
    pub const NO_EXECUTE: u64 = 1 << 63;
}

/// A page table (used for all levels: PML4, PDPT, PD, PT)
#[repr(C, align(4096))]
pub struct PageTable {
    entries: [u64; ENTRIES_PER_TABLE],
}

impl PageTable {
    /// Create a new empty page table
    pub const fn new() -> Self {
        Self {
            entries: [0; ENTRIES_PER_TABLE],
        }
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            *entry = 0;
        }
    }

    /// Set an entry to point to another table
    pub fn set_table_entry(&mut self, index: usize, table_phys_addr: u64) {
        self.entries[index] = table_phys_addr | flags::PRESENT | flags::WRITABLE;
    }

    /// Set an entry as a 2MB huge page
    pub fn set_huge_page(&mut self, index: usize, phys_addr: u64, writable: bool) {
        let mut entry = phys_addr | flags::PRESENT | flags::HUGE_PAGE;
        if writable {
            entry |= flags::WRITABLE;
        }
        self.entries[index] = entry;
    }

    /// Set an entry as a 4KB page
    pub fn set_page(&mut self, index: usize, phys_addr: u64, writable: bool) {
        let mut entry = phys_addr | flags::PRESENT;
        if writable {
            entry |= flags::WRITABLE;
        }
        self.entries[index] = entry;
    }

    /// Get physical address of this table
    pub fn phys_addr(&self) -> u64 {
        self as *const _ as u64
    }
}

/// Page table hierarchy for kernel mapping
pub struct PageTables {
    /// PML4 - top level
    pub pml4: *mut PageTable,
    /// Allocated tables for cleanup
    allocated_tables: [*mut PageTable; 32],
    allocated_count: usize,
}

impl PageTables {
    /// Allocate page tables using UEFI boot services
    pub fn new() -> Result<Self, &'static str> {
        let pml4 = Self::allocate_table()?;

        Ok(Self {
            pml4,
            allocated_tables: [core::ptr::null_mut(); 32],
            allocated_count: 0,
        })
    }

    /// Allocate a single page table
    fn allocate_table() -> Result<*mut PageTable, &'static str> {
        // Allocate a page for the table
        let ptr = boot::allocate_pages(
            boot::AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            1,
        ).map_err(|_| "Failed to allocate page table")?;

        let table = ptr.as_ptr() as *mut PageTable;

        // Zero out the table
        unsafe {
            ptr::write_bytes(table, 0, 1);
        }

        Ok(table)
    }

    /// Track an allocated table for potential cleanup
    fn track_table(&mut self, table: *mut PageTable) {
        if self.allocated_count < self.allocated_tables.len() {
            self.allocated_tables[self.allocated_count] = table;
            self.allocated_count += 1;
        }
    }

    /// Set up identity mapping for first 4GB using 2MB pages
    pub fn identity_map_first_4gb(&mut self) -> Result<(), &'static str> {
        let pml4 = unsafe { &mut *self.pml4 };

        // We need PDPT for first 512GB (entry 0 in PML4)
        let pdpt = Self::allocate_table()?;
        self.track_table(pdpt);
        pml4.set_table_entry(0, pdpt as u64);

        let pdpt = unsafe { &mut *pdpt };

        // Map first 4 entries of PDPT (4 * 1GB = 4GB)
        // Each PDPT entry points to a PD with 512 * 2MB pages
        for i in 0..4 {
            let pd = Self::allocate_table()?;
            self.track_table(pd);
            pdpt.set_table_entry(i, pd as u64);

            let pd = unsafe { &mut *pd };

            // Each PD entry is a 2MB huge page
            for j in 0..512 {
                let phys_addr = (i as u64 * 512 + j as u64) * LARGE_PAGE_SIZE;
                pd.set_huge_page(j, phys_addr, true);
            }
        }

        Ok(())
    }

    /// Map kernel to higher half
    ///
    /// Maps physical address range [kernel_phys, kernel_phys + size)
    /// to virtual address range [kernel_virt, kernel_virt + size)
    pub fn map_kernel(
        &mut self,
        kernel_phys: u64,
        kernel_virt: u64,
        size: u64,
    ) -> Result<(), &'static str> {
        // Calculate PML4 index for kernel virtual address
        // PML4 index is bits 39-47 of virtual address
        let pml4_index = ((kernel_virt >> 39) & 0x1FF) as usize;

        let pml4 = unsafe { &mut *self.pml4 };

        // Allocate PDPT for kernel space if not present
        let pdpt = if pml4.entries[pml4_index] == 0 {
            let pdpt = Self::allocate_table()?;
            self.track_table(pdpt);
            pml4.set_table_entry(pml4_index, pdpt as u64);
            pdpt
        } else {
            (pml4.entries[pml4_index] & !0xFFF) as *mut PageTable
        };

        let pdpt = unsafe { &mut *pdpt };

        // Map using 2MB pages for simplicity
        let mut offset = 0u64;
        while offset < size {
            let virt = kernel_virt + offset;
            let phys = kernel_phys + offset;

            // PDPT index is bits 30-38
            let pdpt_index = ((virt >> 30) & 0x1FF) as usize;

            // Get or allocate PD
            let pd = if pdpt.entries[pdpt_index] == 0 {
                let pd = Self::allocate_table()?;
                self.track_table(pd);
                pdpt.set_table_entry(pdpt_index, pd as u64);
                pd
            } else {
                (pdpt.entries[pdpt_index] & !0xFFF) as *mut PageTable
            };

            let pd = unsafe { &mut *pd };

            // PD index is bits 21-29
            let pd_index = ((virt >> 21) & 0x1FF) as usize;

            // Map as 2MB page
            pd.set_huge_page(pd_index, phys & !(LARGE_PAGE_SIZE - 1), true);

            offset += LARGE_PAGE_SIZE;
        }

        Ok(())
    }

    /// Get physical address of PML4 (for loading into CR3)
    pub fn pml4_phys_addr(&self) -> u64 {
        self.pml4 as u64
    }
}

/// Extract PML4 index from virtual address
#[inline]
pub fn pml4_index(virt: u64) -> usize {
    ((virt >> 39) & 0x1FF) as usize
}

/// Extract PDPT index from virtual address
#[inline]
pub fn pdpt_index(virt: u64) -> usize {
    ((virt >> 30) & 0x1FF) as usize
}

/// Extract PD index from virtual address
#[inline]
pub fn pd_index(virt: u64) -> usize {
    ((virt >> 21) & 0x1FF) as usize
}

/// Extract PT index from virtual address
#[inline]
pub fn pt_index(virt: u64) -> usize {
    ((virt >> 12) & 0x1FF) as usize
}
