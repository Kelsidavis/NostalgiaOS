//! Section Objects (Memory Mapped Files and Shared Memory)
//!
//! Section objects are the NT mechanism for:
//! - Memory-mapped files (file-backed sections)
//! - Shared memory between processes (page-file backed sections)
//! - Image sections (executables and DLLs)
//!
//! # Key Concepts
//!
//! - **Section**: A region of memory that can be mapped into one or more processes
//! - **View**: A mapping of part or all of a section into a process's address space
//! - **Control Area**: Kernel structure tracking the section's pages
//!
//! # NT API
//!
//! - `NtCreateSection` - Create a section object
//! - `NtOpenSection` - Open an existing section
//! - `NtMapViewOfSection` - Map a view into a process
//! - `NtUnmapViewOfSection` - Unmap a view
//! - `NtExtendSection` - Extend a section's size

use core::ptr;
use crate::ke::spinlock::SpinLock;

/// Maximum number of sections in the system
pub const MAX_SECTIONS: usize = 128;

/// Maximum views per section
pub const MAX_VIEWS_PER_SECTION: usize = 16;

/// Section allocation granularity (64KB, same as Windows)
pub const SECTION_ALLOCATION_GRANULARITY: u64 = 64 * 1024;

/// Section access rights
pub mod section_access {
    /// Query section attributes
    pub const SECTION_QUERY: u32 = 0x0001;
    /// Map section for read
    pub const SECTION_MAP_WRITE: u32 = 0x0002;
    /// Map section for write
    pub const SECTION_MAP_READ: u32 = 0x0004;
    /// Map section for execute
    pub const SECTION_MAP_EXECUTE: u32 = 0x0008;
    /// Extend section size
    pub const SECTION_EXTEND_SIZE: u32 = 0x0010;
    /// Map section for execute (explicit)
    pub const SECTION_MAP_EXECUTE_EXPLICIT: u32 = 0x0020;
    /// All access rights
    pub const SECTION_ALL_ACCESS: u32 = 0x001F;
}

/// Section allocation type
pub mod section_type {
    /// Section backed by page file
    pub const SEC_COMMIT: u32 = 0x8000000;
    /// Section is an image (executable)
    pub const SEC_IMAGE: u32 = 0x1000000;
    /// Section backed by a file
    pub const SEC_FILE: u32 = 0x800000;
    /// Reserve address space only
    pub const SEC_RESERVE: u32 = 0x4000000;
    /// No cache
    pub const SEC_NOCACHE: u32 = 0x10000000;
    /// Write-combine
    pub const SEC_WRITECOMBINE: u32 = 0x40000000;
    /// Large pages
    pub const SEC_LARGE_PAGES: u32 = 0x80000000;
}

/// Page protection flags
pub mod page_protection {
    pub const PAGE_NOACCESS: u32 = 0x01;
    pub const PAGE_READONLY: u32 = 0x02;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_WRITECOPY: u32 = 0x08;
    pub const PAGE_EXECUTE: u32 = 0x10;
    pub const PAGE_EXECUTE_READ: u32 = 0x20;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
    pub const PAGE_GUARD: u32 = 0x100;
    pub const PAGE_NOCACHE: u32 = 0x200;
    pub const PAGE_WRITECOMBINE: u32 = 0x400;
}

/// Section object type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SectionType {
    /// Page-file backed (shared memory)
    PageFile = 0,
    /// File-backed (memory mapped file)
    FileBacked = 1,
    /// Image section (executable)
    Image = 2,
    /// Physical memory section
    PhysicalMemory = 3,
}

/// A view of a section mapped into an address space
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SectionView {
    /// Base address of the view in the process
    pub base_address: u64,
    /// Size of the view in bytes
    pub view_size: u64,
    /// Offset into the section
    pub section_offset: u64,
    /// View protection
    pub protection: u32,
    /// View is active
    pub active: bool,
    /// Process that owns this view
    pub process: *mut u8,
}

impl Default for SectionView {
    fn default() -> Self {
        Self::new()
    }
}

impl SectionView {
    pub const fn new() -> Self {
        Self {
            base_address: 0,
            view_size: 0,
            section_offset: 0,
            protection: 0,
            active: false,
            process: ptr::null_mut(),
        }
    }

    /// Check if address falls within this view
    pub fn contains(&self, address: u64) -> bool {
        self.active && address >= self.base_address && address < self.base_address + self.view_size
    }
}

/// Control area - tracks pages for a section
#[repr(C)]
pub struct ControlArea {
    /// Section that owns this control area
    pub section: *mut Section,
    /// Number of mapped views
    pub view_count: u32,
    /// Number of page faults served
    pub page_faults: u64,
    /// Modified page count
    pub modified_pages: u32,
    /// For file-backed: file object
    pub file_object: *mut u8,
    /// For file-backed: file offset
    pub file_offset: u64,
}

impl Default for ControlArea {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlArea {
    pub const fn new() -> Self {
        Self {
            section: ptr::null_mut(),
            view_count: 0,
            page_faults: 0,
            modified_pages: 0,
            file_object: ptr::null_mut(),
            file_offset: 0,
        }
    }
}

/// Section object
#[repr(C)]
pub struct Section {
    /// Section type
    pub section_type: SectionType,
    /// Total size of section in bytes
    pub size: u64,
    /// Section attributes
    pub attributes: u32,
    /// Initial page protection
    pub initial_protection: u32,
    /// Reference count
    pub ref_count: u32,
    /// Section is active
    pub active: bool,
    /// Control area for this section
    pub control_area: ControlArea,
    /// Views mapped from this section
    pub views: [SectionView; MAX_VIEWS_PER_SECTION],
    /// Lock for synchronization
    lock: SpinLock<()>,
    /// For named sections: name hash
    pub name_hash: u32,
}

impl Default for Section {
    fn default() -> Self {
        Self::new()
    }
}

impl Section {
    pub const fn new() -> Self {
        Self {
            section_type: SectionType::PageFile,
            size: 0,
            attributes: 0,
            initial_protection: 0,
            ref_count: 0,
            active: false,
            control_area: ControlArea::new(),
            views: [SectionView::new(); MAX_VIEWS_PER_SECTION],
            lock: SpinLock::new(()),
            name_hash: 0,
        }
    }

    /// Initialize a page-file backed section (shared memory)
    pub fn init_pagefile(&mut self, size: u64, protection: u32) {
        self.section_type = SectionType::PageFile;
        self.size = align_up(size, super::PAGE_SIZE as u64);
        self.attributes = section_type::SEC_COMMIT;
        self.initial_protection = protection;
        self.ref_count = 1;
        self.active = true;
        self.control_area.section = self as *mut Section;
    }

    /// Initialize a file-backed section
    pub fn init_file(&mut self, file: *mut u8, size: u64, protection: u32) {
        self.section_type = SectionType::FileBacked;
        self.size = align_up(size, super::PAGE_SIZE as u64);
        self.attributes = section_type::SEC_FILE;
        self.initial_protection = protection;
        self.ref_count = 1;
        self.active = true;
        self.control_area.section = self as *mut Section;
        self.control_area.file_object = file;
    }

    /// Initialize an image section
    pub fn init_image(&mut self, file: *mut u8, size: u64) {
        self.section_type = SectionType::Image;
        self.size = align_up(size, super::PAGE_SIZE as u64);
        self.attributes = section_type::SEC_IMAGE;
        self.initial_protection = page_protection::PAGE_EXECUTE_READ;
        self.ref_count = 1;
        self.active = true;
        self.control_area.section = self as *mut Section;
        self.control_area.file_object = file;
    }

    /// Add a reference
    pub fn reference(&mut self) {
        self.ref_count += 1;
    }

    /// Remove a reference, returns true if section should be freed
    pub fn dereference(&mut self) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        self.ref_count == 0
    }

    /// Find a free view slot
    fn find_free_view(&mut self) -> Option<usize> {
        for (i, view) in self.views.iter().enumerate() {
            if !view.active {
                return Some(i);
            }
        }
        None
    }

    /// Map a view of this section
    pub unsafe fn map_view(
        &mut self,
        process: *mut u8,
        base_address: Option<u64>,
        section_offset: u64,
        view_size: u64,
        protection: u32,
    ) -> Option<u64> {
        // Validate parameters
        if section_offset + view_size > self.size {
            return None;
        }

        // Find a free view slot (inline to avoid borrow issues)
        let mut view_idx = None;
        for (i, view) in self.views.iter().enumerate() {
            if !view.active {
                view_idx = Some(i);
                break;
            }
        }
        let view_idx = view_idx?;

        // Determine actual view size (round up to page size)
        let actual_size = align_up(view_size, super::PAGE_SIZE as u64);

        // Find or use the specified base address
        let actual_base = if let Some(addr) = base_address {
            // Use specified address (must be aligned to allocation granularity)
            if addr % SECTION_ALLOCATION_GRANULARITY != 0 {
                return None;
            }
            addr
        } else {
            // Find a free region in the address space
            // For now, return a pseudo-address based on section and view index
            // In full implementation, this would use the VAD tree
            0x7FFE_0000_0000_u64 + (view_idx as u64 * SECTION_ALLOCATION_GRANULARITY * 16)
        };

        // Set up the view
        let view = &mut self.views[view_idx];
        view.base_address = actual_base;
        view.view_size = actual_size;
        view.section_offset = section_offset;
        view.protection = protection;
        view.process = process;
        view.active = true;

        // Update control area
        self.control_area.view_count += 1;

        Some(actual_base)
    }

    /// Unmap a view
    pub unsafe fn unmap_view(&mut self, base_address: u64) -> bool {
        for view in self.views.iter_mut() {
            if view.active && view.base_address == base_address {
                view.active = false;
                view.base_address = 0;
                view.view_size = 0;

                if self.control_area.view_count > 0 {
                    self.control_area.view_count -= 1;
                }

                return true;
            }
        }

        false
    }

    /// Find view containing an address
    pub fn find_view(&self, address: u64) -> Option<&SectionView> {
        self.views.iter().find(|&view| view.contains(address)).map(|v| v as _)
    }

    /// Extend section size
    pub fn extend(&mut self, new_size: u64) -> bool {
        if new_size <= self.size {
            return false;
        }

        // Only page-file backed sections can be extended
        if self.section_type != SectionType::PageFile {
            return false;
        }

        self.size = align_up(new_size, super::PAGE_SIZE as u64);
        true
    }

    /// Get active view count
    pub fn view_count(&self) -> u32 {
        self.control_area.view_count
    }

    /// Check if this is a file-backed section
    pub fn is_file_backed(&self) -> bool {
        self.section_type == SectionType::FileBacked || self.section_type == SectionType::Image
    }
}

// ============================================================================
// Global Section Pool
// ============================================================================

/// Pool of section objects
static mut SECTION_POOL: [Section; MAX_SECTIONS] = {
    const INIT: Section = Section::new();
    [INIT; MAX_SECTIONS]
};

/// Bitmap tracking allocated sections (2 u64s for 128 sections)
static mut SECTION_BITMAP: [u64; 2] = [0; 2];

/// Lock for section allocation
static SECTION_LOCK: SpinLock<()> = SpinLock::new(());

/// Create a page-file backed section (shared memory)
///
/// # Arguments
/// * `size` - Size of the section in bytes
/// * `protection` - Initial page protection
///
/// # Returns
/// Pointer to the section, or null if allocation failed
pub unsafe fn mm_create_section(
    size: u64,
    protection: u32,
) -> *mut Section {
    let _guard = SECTION_LOCK.lock();

    // Find a free slot
    for i in 0..MAX_SECTIONS {
        let word = i / 64;
        let bit = i % 64;

        if SECTION_BITMAP[word] & (1 << bit) == 0 {
            // Allocate this slot
            SECTION_BITMAP[word] |= 1 << bit;

            let section = &mut SECTION_POOL[i];
            section.init_pagefile(size, protection);

            return section as *mut Section;
        }
    }

    ptr::null_mut()
}

/// Create a file-backed section
///
/// # Arguments
/// * `file` - File object to back the section
/// * `size` - Size of the section (0 = file size)
/// * `protection` - Initial page protection
///
/// # Returns
/// Pointer to the section, or null if allocation failed
pub unsafe fn mm_create_file_section(
    file: *mut u8,
    size: u64,
    protection: u32,
) -> *mut Section {
    let _guard = SECTION_LOCK.lock();

    // Find a free slot
    for i in 0..MAX_SECTIONS {
        let word = i / 64;
        let bit = i % 64;

        if SECTION_BITMAP[word] & (1 << bit) == 0 {
            // Allocate this slot
            SECTION_BITMAP[word] |= 1 << bit;

            let section = &mut SECTION_POOL[i];
            section.init_file(file, size, protection);

            return section as *mut Section;
        }
    }

    ptr::null_mut()
}

/// Create an image section (for executables)
///
/// # Arguments
/// * `file` - Executable file object
/// * `size` - Size of the image
///
/// # Returns
/// Pointer to the section, or null if allocation failed
pub unsafe fn mm_create_image_section(
    file: *mut u8,
    size: u64,
) -> *mut Section {
    let _guard = SECTION_LOCK.lock();

    // Find a free slot
    for i in 0..MAX_SECTIONS {
        let word = i / 64;
        let bit = i % 64;

        if SECTION_BITMAP[word] & (1 << bit) == 0 {
            // Allocate this slot
            SECTION_BITMAP[word] |= 1 << bit;

            let section = &mut SECTION_POOL[i];
            section.init_image(file, size);

            return section as *mut Section;
        }
    }

    ptr::null_mut()
}

/// Close/dereference a section
pub unsafe fn mm_close_section(section: *mut Section) {
    if section.is_null() {
        return;
    }

    let _guard = SECTION_LOCK.lock();

    if (*section).dereference() {
        // Find and free the slot
        let base = SECTION_POOL.as_ptr() as usize;
        let section_addr = section as usize;
        let section_size = core::mem::size_of::<Section>();

        if section_addr >= base && section_addr < base + MAX_SECTIONS * section_size {
            let index = (section_addr - base) / section_size;
            let word = index / 64;
            let bit = index % 64;

            // Clear the section
            (*section).active = false;

            // Free the slot
            SECTION_BITMAP[word] &= !(1 << bit);
        }
    }
}

/// Map a view of a section into an address space
///
/// # Arguments
/// * `section` - Section to map
/// * `process` - Process to map into (null = current)
/// * `base_address` - Desired base address (None = let system choose)
/// * `section_offset` - Offset into section
/// * `view_size` - Size of view (0 = rest of section)
/// * `protection` - Page protection
///
/// # Returns
/// Base address of the mapped view, or None on failure
pub unsafe fn mm_map_view_of_section(
    section: *mut Section,
    process: *mut u8,
    base_address: Option<u64>,
    section_offset: u64,
    view_size: u64,
    protection: u32,
) -> Option<u64> {
    if section.is_null() {
        return None;
    }

    let actual_size = if view_size == 0 {
        (*section).size - section_offset
    } else {
        view_size
    };

    (*section).map_view(process, base_address, section_offset, actual_size, protection)
}

/// Unmap a view of a section
pub unsafe fn mm_unmap_view_of_section(
    section: *mut Section,
    base_address: u64,
) -> bool {
    if section.is_null() {
        return false;
    }

    (*section).unmap_view(base_address)
}

/// Extend a section
pub unsafe fn mm_extend_section(
    section: *mut Section,
    new_size: u64,
) -> bool {
    if section.is_null() {
        return false;
    }

    (*section).extend(new_size)
}

/// Query section information
#[repr(C)]
pub struct SectionInfo {
    pub size: u64,
    pub section_type: SectionType,
    pub attributes: u32,
    pub protection: u32,
    pub view_count: u32,
}

pub unsafe fn mm_query_section(section: *mut Section) -> Option<SectionInfo> {
    if section.is_null() {
        return None;
    }

    let s = &*section;
    Some(SectionInfo {
        size: s.size,
        section_type: s.section_type,
        attributes: s.attributes,
        protection: s.initial_protection,
        view_count: s.view_count(),
    })
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Align value up to alignment
fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

/// Initialize the section subsystem
pub fn init() {
    unsafe {
        SECTION_BITMAP = [0; 2];

        for section in SECTION_POOL.iter_mut() {
            section.active = false;
        }
    }

    crate::serial_println!("[MM] Section subsystem initialized");
}

/// Get section statistics
#[repr(C)]
pub struct SectionStats {
    pub total_sections: usize,
    pub active_sections: usize,
    pub total_views: usize,
}

pub fn mm_get_section_stats() -> SectionStats {
    let mut stats = SectionStats {
        total_sections: MAX_SECTIONS,
        active_sections: 0,
        total_views: 0,
    };

    unsafe {
        for section in SECTION_POOL.iter() {
            if section.active {
                stats.active_sections += 1;
                stats.total_views += section.view_count() as usize;
            }
        }
    }

    stats
}
