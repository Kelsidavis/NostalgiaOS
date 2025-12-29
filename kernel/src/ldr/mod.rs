//! Loader (ldr)
//!
//! The loader is responsible for:
//! - Parsing PE (Portable Executable) files
//! - Loading executables and DLLs into memory
//! - Processing relocations
//! - Resolving imports
//!
//! # Architecture
//!
//! ```text
//! PE File on Disk          Loaded Image in Memory
//! ┌─────────────────┐      ┌─────────────────┐
//! │ DOS Header      │ ──►  │ Headers         │
//! │ PE Headers      │      │ (read-only)     │
//! │ Section Table   │      ├─────────────────┤
//! ├─────────────────┤      │ .text           │
//! │ .text (code)    │ ──►  │ (RX)            │
//! ├─────────────────┤      ├─────────────────┤
//! │ .data (init)    │ ──►  │ .data           │
//! ├─────────────────┤      │ (RW)            │
//! │ .rdata (const)  │ ──►  ├─────────────────┤
//! └─────────────────┘      │ .rdata          │
//!                          │ (R)             │
//!                          ├─────────────────┤
//!                          │ .bss            │
//!                          │ (RW, zeroed)    │
//!                          └─────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use kernel::ldr;
//!
//! // Parse a PE file
//! let pe_info = ldr::parse_pe(image_base)?;
//!
//! // Load and relocate
//! let loaded = ldr::load_image(image_base, target_base)?;
//! ```

pub mod pe;

// Re-export PE types
pub use pe::*;

use core::ptr;

/// PE parsing result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeError {
    /// Invalid DOS header
    InvalidDosHeader,
    /// Invalid PE signature
    InvalidPeSignature,
    /// Invalid optional header magic
    InvalidOptionalHeader,
    /// Unsupported machine type
    UnsupportedMachine,
    /// Image too large
    ImageTooLarge,
    /// Invalid section
    InvalidSection,
    /// Relocation error
    RelocationError,
    /// Import error
    ImportError,
    /// Out of memory
    OutOfMemory,
    /// Image not relocatable
    NotRelocatable,
}

/// Parsed PE information
#[derive(Debug, Clone, Copy)]
pub struct PeInfo {
    /// Is this a 64-bit PE
    pub is_64bit: bool,
    /// Is this a DLL
    pub is_dll: bool,
    /// Machine type
    pub machine: u16,
    /// Preferred image base
    pub image_base: u64,
    /// Size of image in memory
    pub size_of_image: u32,
    /// Size of headers
    pub size_of_headers: u32,
    /// Entry point RVA
    pub entry_point_rva: u32,
    /// Number of sections
    pub number_of_sections: u16,
    /// Section alignment
    pub section_alignment: u32,
    /// File alignment
    pub file_alignment: u32,
    /// Subsystem
    pub subsystem: u16,
    /// DLL characteristics
    pub dll_characteristics: u16,
    /// Has relocations
    pub has_relocations: bool,
    /// Stack reserve size
    pub stack_reserve: u64,
    /// Stack commit size
    pub stack_commit: u64,
    /// Heap reserve size
    pub heap_reserve: u64,
    /// Heap commit size
    pub heap_commit: u64,
}

impl PeInfo {
    /// Create empty PE info
    pub const fn new() -> Self {
        Self {
            is_64bit: false,
            is_dll: false,
            machine: 0,
            image_base: 0,
            size_of_image: 0,
            size_of_headers: 0,
            entry_point_rva: 0,
            number_of_sections: 0,
            section_alignment: 0,
            file_alignment: 0,
            subsystem: 0,
            dll_characteristics: 0,
            has_relocations: false,
            stack_reserve: 0,
            stack_commit: 0,
            heap_reserve: 0,
            heap_commit: 0,
        }
    }

    /// Check if this is a kernel-mode driver
    pub fn is_driver(&self) -> bool {
        self.subsystem == subsystem::IMAGE_SUBSYSTEM_NATIVE
    }

    /// Check if this is a console application
    pub fn is_console(&self) -> bool {
        self.subsystem == subsystem::IMAGE_SUBSYSTEM_WINDOWS_CUI
    }

    /// Check if this is a GUI application
    pub fn is_gui(&self) -> bool {
        self.subsystem == subsystem::IMAGE_SUBSYSTEM_WINDOWS_GUI
    }
}

impl Default for PeInfo {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PE Parsing
// ============================================================================

/// Parse PE file at the given base address
///
/// # Safety
/// The caller must ensure `base` points to a valid, mapped PE image.
pub unsafe fn parse_pe(base: *const u8) -> Result<PeInfo, PeError> {
    if base.is_null() {
        return Err(PeError::InvalidDosHeader);
    }

    // Read DOS header
    let dos_header = &*(base as *const ImageDosHeader);
    if !dos_header.is_valid() {
        return Err(PeError::InvalidDosHeader);
    }

    // Get PE header offset
    let pe_offset = dos_header.pe_offset();
    let pe_base = base.add(pe_offset);

    // Read PE signature
    let signature = *(pe_base as *const u32);
    if signature != IMAGE_NT_SIGNATURE {
        return Err(PeError::InvalidPeSignature);
    }

    // Read file header
    let file_header = &*((pe_base.add(4)) as *const ImageFileHeader);

    // Check optional header magic to determine 32/64 bit
    let optional_header_base = pe_base.add(4 + core::mem::size_of::<ImageFileHeader>());
    let magic = *(optional_header_base as *const u16);

    let mut info = PeInfo::new();
    info.machine = file_header.machine;
    info.number_of_sections = file_header.number_of_sections;
    info.is_dll = file_header.is_dll();
    info.has_relocations = !file_header.relocs_stripped();

    // Validate machine type
    match info.machine {
        machine_type::IMAGE_FILE_MACHINE_AMD64 => info.is_64bit = true,
        machine_type::IMAGE_FILE_MACHINE_I386 => info.is_64bit = false,
        _ => return Err(PeError::UnsupportedMachine),
    }

    // Parse optional header based on PE type
    if magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        let opt_header = &*(optional_header_base as *const ImageOptionalHeader64);
        info.image_base = opt_header.image_base;
        info.size_of_image = opt_header.size_of_image;
        info.size_of_headers = opt_header.size_of_headers;
        info.entry_point_rva = opt_header.address_of_entry_point;
        info.section_alignment = opt_header.section_alignment;
        info.file_alignment = opt_header.file_alignment;
        info.subsystem = opt_header.subsystem;
        info.dll_characteristics = opt_header.dll_characteristics;
        info.stack_reserve = opt_header.size_of_stack_reserve;
        info.stack_commit = opt_header.size_of_stack_commit;
        info.heap_reserve = opt_header.size_of_heap_reserve;
        info.heap_commit = opt_header.size_of_heap_commit;
    } else if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC {
        let opt_header = &*(optional_header_base as *const ImageOptionalHeader32);
        info.image_base = opt_header.image_base as u64;
        info.size_of_image = opt_header.size_of_image;
        info.size_of_headers = opt_header.size_of_headers;
        info.entry_point_rva = opt_header.address_of_entry_point;
        info.section_alignment = opt_header.section_alignment;
        info.file_alignment = opt_header.file_alignment;
        info.subsystem = opt_header.subsystem;
        info.dll_characteristics = opt_header.dll_characteristics;
        info.stack_reserve = opt_header.size_of_stack_reserve as u64;
        info.stack_commit = opt_header.size_of_stack_commit as u64;
        info.heap_reserve = opt_header.size_of_heap_reserve as u64;
        info.heap_commit = opt_header.size_of_heap_commit as u64;
    } else {
        return Err(PeError::InvalidOptionalHeader);
    }

    Ok(info)
}

/// Get the section headers from a PE image
///
/// # Safety
/// The caller must ensure `base` points to a valid, mapped PE image.
pub unsafe fn get_section_headers(base: *const u8) -> Option<&'static [ImageSectionHeader]> {
    let dos_header = &*(base as *const ImageDosHeader);
    if !dos_header.is_valid() {
        return None;
    }

    let pe_base = base.add(dos_header.pe_offset());
    let signature = *(pe_base as *const u32);
    if signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    let file_header = &*((pe_base.add(4)) as *const ImageFileHeader);
    let num_sections = file_header.number_of_sections as usize;
    let optional_header_size = file_header.size_of_optional_header as usize;

    // Section headers follow optional header
    let section_base = pe_base.add(4 + core::mem::size_of::<ImageFileHeader>() + optional_header_size);
    let sections = core::slice::from_raw_parts(
        section_base as *const ImageSectionHeader,
        num_sections,
    );

    Some(sections)
}

/// Get a data directory entry from a PE image
///
/// # Safety
/// The caller must ensure `base` points to a valid, mapped PE image.
pub unsafe fn get_data_directory(base: *const u8, index: usize) -> Option<ImageDataDirectory> {
    if index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
        return None;
    }

    let dos_header = &*(base as *const ImageDosHeader);
    if !dos_header.is_valid() {
        return None;
    }

    let pe_base = base.add(dos_header.pe_offset());
    let optional_header_base = pe_base.add(4 + core::mem::size_of::<ImageFileHeader>());
    let magic = *(optional_header_base as *const u16);

    if magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        let opt_header = &*(optional_header_base as *const ImageOptionalHeader64);
        if index < opt_header.number_of_rva_and_sizes as usize {
            return Some(opt_header.data_directory[index]);
        }
    } else if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC {
        let opt_header = &*(optional_header_base as *const ImageOptionalHeader32);
        if index < opt_header.number_of_rva_and_sizes as usize {
            return Some(opt_header.data_directory[index]);
        }
    }

    None
}

/// Convert RVA to file offset
///
/// # Safety
/// The caller must ensure `base` points to a valid, mapped PE image.
pub unsafe fn rva_to_offset(base: *const u8, rva: u32) -> Option<u32> {
    let sections = get_section_headers(base)?;

    for section in sections {
        let section_start = section.virtual_address;
        let section_end = section_start + section.virtual_size.max(section.size_of_raw_data);

        if rva >= section_start && rva < section_end {
            let offset_in_section = rva - section_start;
            return Some(section.pointer_to_raw_data + offset_in_section);
        }
    }

    // RVA is in headers
    let info = parse_pe(base).ok()?;
    if rva < info.size_of_headers {
        return Some(rva);
    }

    None
}

/// Convert RVA to virtual address (when image is loaded at base)
pub fn rva_to_va(base: u64, rva: u32) -> u64 {
    base + rva as u64
}

// ============================================================================
// Relocation Processing
// ============================================================================

/// Process base relocations for an image
///
/// # Arguments
/// * `image_base` - Current base address of the loaded image
/// * `preferred_base` - Preferred base address from PE header
/// * `new_base` - New base address where image will be loaded
///
/// # Safety
/// The caller must ensure `image_base` points to a valid, mapped PE image
/// with writable relocation targets.
pub unsafe fn process_relocations(
    image_base: *mut u8,
    preferred_base: u64,
    new_base: u64,
) -> Result<(), PeError> {
    let delta = new_base as i64 - preferred_base as i64;
    if delta == 0 {
        return Ok(()); // No relocation needed
    }

    // Get relocation directory
    let reloc_dir = match get_data_directory(image_base, directory_entry::IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        Some(dir) if dir.is_present() => dir,
        _ => return Ok(()), // No relocations
    };

    let info = parse_pe(image_base)?;
    if !info.has_relocations {
        if delta != 0 {
            return Err(PeError::NotRelocatable);
        }
        return Ok(());
    }

    // Process each relocation block
    let mut block_offset = 0u32;
    let reloc_base = image_base.add(reloc_dir.virtual_address as usize);

    while block_offset < reloc_dir.size {
        let block = &*(reloc_base.add(block_offset as usize) as *const ImageBaseRelocation);

        if block.virtual_address == 0 && block.size_of_block == 0 {
            break; // End of relocations
        }

        if block.size_of_block < 8 {
            return Err(PeError::RelocationError);
        }

        let entry_count = block.entry_count();
        let entries_base = reloc_base.add(block_offset as usize + 8);

        for i in 0..entry_count {
            let entry = *((entries_base.add(i * 2)) as *const u16);
            let reloc_type = reloc_type(entry);
            let offset = reloc_offset(entry) as u32;

            let target_rva = block.virtual_address + offset;
            let target_ptr = image_base.add(target_rva as usize);

            match reloc_type {
                relocation_type::IMAGE_REL_BASED_ABSOLUTE => {
                    // Padding, ignore
                }
                relocation_type::IMAGE_REL_BASED_HIGHLOW => {
                    // 32-bit relocation
                    let target = target_ptr as *mut u32;
                    let value = (*target) as i64 + delta;
                    *target = value as u32;
                }
                relocation_type::IMAGE_REL_BASED_DIR64 => {
                    // 64-bit relocation
                    let target = target_ptr as *mut u64;
                    let value = (*target) as i64 + delta;
                    *target = value as u64;
                }
                relocation_type::IMAGE_REL_BASED_HIGH => {
                    // High 16 bits
                    let target = target_ptr as *mut u16;
                    let value = (*target as i64 + (delta >> 16)) as u16;
                    *target = value;
                }
                relocation_type::IMAGE_REL_BASED_LOW => {
                    // Low 16 bits
                    let target = target_ptr as *mut u16;
                    let value = (*target as i64 + (delta & 0xFFFF)) as u16;
                    *target = value;
                }
                _ => {
                    // Unknown relocation type
                    crate::serial_println!("[LDR] Unknown relocation type: {}", reloc_type);
                }
            }
        }

        block_offset += block.size_of_block;
    }

    Ok(())
}

// ============================================================================
// Import Resolution
// ============================================================================

/// Import resolution callback type
///
/// Called for each import to resolve.
/// Returns the address of the imported function, or None if not found.
pub type ImportResolver = fn(dll_name: &str, func_name: &str, ordinal: u16) -> Option<u64>;

/// Process imports for an image
///
/// # Arguments
/// * `image_base` - Base address of the loaded image
/// * `resolver` - Callback to resolve imports
///
/// # Safety
/// The caller must ensure `image_base` points to a valid, mapped PE image
/// with writable IAT.
pub unsafe fn process_imports(
    image_base: *mut u8,
    resolver: ImportResolver,
) -> Result<(), PeError> {
    // Get import directory
    let import_dir = match get_data_directory(image_base, directory_entry::IMAGE_DIRECTORY_ENTRY_IMPORT) {
        Some(dir) if dir.is_present() => dir,
        _ => return Ok(()), // No imports
    };

    let info = parse_pe(image_base)?;
    let is_64bit = info.is_64bit;

    // Process each import descriptor
    let import_base = image_base.add(import_dir.virtual_address as usize);
    let mut descriptor_offset = 0usize;

    loop {
        let descriptor = &*(import_base.add(descriptor_offset) as *const ImageImportDescriptor);

        if descriptor.is_null() {
            break; // End of import descriptors
        }

        // Get DLL name
        let dll_name_ptr = image_base.add(descriptor.name as usize);
        let dll_name = cstr_to_str(dll_name_ptr);

        // Get thunks
        let original_thunk_rva = if descriptor.original_first_thunk != 0 {
            descriptor.original_first_thunk
        } else {
            descriptor.first_thunk
        };
        let iat_rva = descriptor.first_thunk;

        let mut thunk_offset = 0usize;

        loop {
            let thunk_va = image_base.add(original_thunk_rva as usize + thunk_offset);
            let iat_va = image_base.add(iat_rva as usize + thunk_offset) as *mut u64;

            if is_64bit {
                let thunk_data = *(thunk_va as *const u64);
                if thunk_data == 0 {
                    break; // End of thunks
                }

                let address = if (thunk_data & IMAGE_ORDINAL_FLAG64) != 0 {
                    // Import by ordinal
                    let ordinal = (thunk_data & 0xFFFF) as u16;
                    resolver(dll_name, "", ordinal)
                } else {
                    // Import by name
                    let hint_name_ptr = image_base.add(thunk_data as usize);
                    let hint = *(hint_name_ptr as *const u16);
                    let name_ptr = hint_name_ptr.add(2);
                    let func_name = cstr_to_str(name_ptr);
                    resolver(dll_name, func_name, hint)
                };

                match address {
                    Some(addr) => *iat_va = addr,
                    None => return Err(PeError::ImportError),
                }

                thunk_offset += 8;
            } else {
                let thunk_data = *(thunk_va as *const u32);
                if thunk_data == 0 {
                    break; // End of thunks
                }

                let address = if (thunk_data & IMAGE_ORDINAL_FLAG32) != 0 {
                    // Import by ordinal
                    let ordinal = (thunk_data & 0xFFFF) as u16;
                    resolver(dll_name, "", ordinal)
                } else {
                    // Import by name
                    let hint_name_ptr = image_base.add(thunk_data as usize);
                    let hint = *(hint_name_ptr as *const u16);
                    let name_ptr = hint_name_ptr.add(2);
                    let func_name = cstr_to_str(name_ptr);
                    resolver(dll_name, func_name, hint)
                };

                match address {
                    Some(addr) => *(iat_va as *mut u32) = addr as u32,
                    None => return Err(PeError::ImportError),
                }

                thunk_offset += 4;
            }
        }

        descriptor_offset += core::mem::size_of::<ImageImportDescriptor>();
    }

    Ok(())
}

/// Convert C string to Rust str
unsafe fn cstr_to_str<'a>(ptr: *const u8) -> &'a str {
    if ptr.is_null() {
        return "";
    }

    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
        if len > 256 {
            break; // Safety limit
        }
    }

    core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr, len))
}

// ============================================================================
// Export Resolution
// ============================================================================

/// Find an exported function by name
///
/// # Arguments
/// * `image_base` - Base address of the loaded DLL
/// * `func_name` - Name of the function to find
///
/// # Safety
/// The caller must ensure `image_base` points to a valid, mapped PE image.
pub unsafe fn find_export_by_name(image_base: *const u8, func_name: &str) -> Option<u64> {
    let export_dir = get_data_directory(image_base, directory_entry::IMAGE_DIRECTORY_ENTRY_EXPORT)?;
    if !export_dir.is_present() {
        return None;
    }

    let exports = &*(image_base.add(export_dir.virtual_address as usize) as *const ImageExportDirectory);

    let name_table = image_base.add(exports.address_of_names as usize) as *const u32;
    let ordinal_table = image_base.add(exports.address_of_name_ordinals as usize) as *const u16;
    let function_table = image_base.add(exports.address_of_functions as usize) as *const u32;

    // Binary search through name table
    for i in 0..exports.number_of_names as usize {
        let name_rva = *name_table.add(i);
        let name_ptr = image_base.add(name_rva as usize);
        let export_name = cstr_to_str(name_ptr);

        if export_name == func_name {
            let ordinal = *ordinal_table.add(i);
            let function_rva = *function_table.add(ordinal as usize);

            // Check for forwarder
            let function_va = image_base.add(function_rva as usize);
            let export_start = export_dir.virtual_address;
            let export_end = export_start + export_dir.size;

            if function_rva >= export_start && function_rva < export_end {
                // This is a forwarder - would need to resolve recursively
                // For now, return None
                return None;
            }

            return Some(function_va as u64);
        }
    }

    None
}

/// Find an exported function by ordinal
///
/// # Arguments
/// * `image_base` - Base address of the loaded DLL
/// * `ordinal` - Ordinal of the function to find
///
/// # Safety
/// The caller must ensure `image_base` points to a valid, mapped PE image.
pub unsafe fn find_export_by_ordinal(image_base: *const u8, ordinal: u16) -> Option<u64> {
    let export_dir = get_data_directory(image_base, directory_entry::IMAGE_DIRECTORY_ENTRY_EXPORT)?;
    if !export_dir.is_present() {
        return None;
    }

    let exports = &*(image_base.add(export_dir.virtual_address as usize) as *const ImageExportDirectory);

    // Convert ordinal to function table index
    let index = ordinal as u32 - exports.base;
    if index >= exports.number_of_functions {
        return None;
    }

    let function_table = image_base.add(exports.address_of_functions as usize) as *const u32;
    let function_rva = *function_table.add(index as usize);

    if function_rva == 0 {
        return None;
    }

    // Check for forwarder
    let export_start = export_dir.virtual_address;
    let export_end = export_start + export_dir.size;

    if function_rva >= export_start && function_rva < export_end {
        // This is a forwarder
        return None;
    }

    Some(image_base.add(function_rva as usize) as u64)
}

// ============================================================================
// Image Loading
// ============================================================================

/// Loaded image information
#[derive(Debug, Clone, Copy)]
pub struct LoadedImage {
    /// Base address where image is loaded
    pub base: u64,
    /// Size of the image
    pub size: u32,
    /// Entry point address
    pub entry_point: u64,
    /// PE information
    pub pe_info: PeInfo,
}

/// Copy sections from file image to memory image
///
/// # Safety
/// The caller must ensure both pointers are valid and the destination
/// has enough space for the image.
pub unsafe fn copy_sections(
    file_base: *const u8,
    memory_base: *mut u8,
    info: &PeInfo,
) -> Result<(), PeError> {
    // Copy headers
    ptr::copy_nonoverlapping(file_base, memory_base, info.size_of_headers as usize);

    // Copy each section
    let sections = get_section_headers(file_base).ok_or(PeError::InvalidSection)?;

    for section in sections {
        if section.size_of_raw_data == 0 {
            continue; // BSS or similar
        }

        let src = file_base.add(section.pointer_to_raw_data as usize);
        let dst = memory_base.add(section.virtual_address as usize);
        let size = section.size_of_raw_data.min(section.virtual_size) as usize;

        ptr::copy_nonoverlapping(src, dst, size);

        // Zero-fill remainder of section if virtual_size > raw_size
        if section.virtual_size > section.size_of_raw_data {
            let zero_start = dst.add(section.size_of_raw_data as usize);
            let zero_size = (section.virtual_size - section.size_of_raw_data) as usize;
            ptr::write_bytes(zero_start, 0, zero_size);
        }
    }

    Ok(())
}

// ============================================================================
// Process Image Loading
// ============================================================================

/// Load result containing process and thread handles
#[derive(Debug)]
pub struct LoadResult {
    /// Pointer to created EPROCESS
    pub process: *mut crate::ps::EProcess,
    /// Pointer to initial ETHREAD
    pub thread: *mut crate::ps::EThread,
    /// Loaded image information
    pub image: LoadedImage,
}

/// Load a PE executable and create a user-mode process
///
/// This is the main entry point for loading executables. It:
/// 1. Parses the PE headers
/// 2. Allocates memory for the image
/// 3. Copies sections and processes relocations
/// 4. Creates the process and initial thread
///
/// Note: In a full implementation, this would also:
/// - Set up user-mode page tables
/// - Initialize PEB/TEB
/// - Load required DLLs
///
/// # Arguments
/// * `file_base` - Pointer to PE file in memory (e.g., loaded from disk)
/// * `file_size` - Size of the PE file
/// * `name` - Process name
///
/// # Safety
/// - file_base must point to a valid PE file
/// - The caller must ensure the file is safe to execute
pub unsafe fn load_executable(
    file_base: *const u8,
    _file_size: usize,
    name: &[u8],
) -> Result<LoadResult, PeError> {
    // Parse PE headers
    let pe_info = parse_pe(file_base)?;

    // Validate it's an executable (not a DLL)
    if pe_info.is_dll {
        crate::serial_println!("[LDR] Error: Cannot load DLL as executable");
        return Err(PeError::InvalidOptionalHeader);
    }

    // For now, we need the image to be loadable at its preferred base
    // or be relocatable
    let image_size = pe_info.size_of_image as usize;
    let preferred_base = pe_info.image_base;

    crate::serial_println!("[LDR] Loading executable:");
    crate::serial_println!("[LDR]   Preferred base: {:#x}", preferred_base);
    crate::serial_println!("[LDR]   Image size:     {:#x}", image_size);
    crate::serial_println!("[LDR]   Entry point:    {:#x}", pe_info.entry_point_rva);

    // In a full implementation, we would:
    // 1. Create user-mode page tables
    // 2. Allocate pages at the preferred base (or find alternative)
    // 3. Map the pages with appropriate permissions

    // For now, we'll use a static buffer for demonstration
    // This should be replaced with proper memory allocation
    static mut IMAGE_BUFFER: [u8; 0x100000] = [0; 0x100000]; // 1MB
    let load_base = IMAGE_BUFFER.as_mut_ptr();

    if image_size > IMAGE_BUFFER.len() {
        crate::serial_println!("[LDR] Error: Image too large ({} > {})", image_size, IMAGE_BUFFER.len());
        return Err(PeError::ImageTooLarge);
    }

    // Copy sections to the load buffer
    copy_sections(file_base, load_base, &pe_info)?;

    // Process relocations if loaded at different address
    let actual_base = load_base as u64;
    if actual_base != preferred_base {
        if !pe_info.has_relocations {
            crate::serial_println!("[LDR] Error: Image requires relocation but has none");
            return Err(PeError::NotRelocatable);
        }
        crate::serial_println!("[LDR] Relocating from {:#x} to {:#x}", preferred_base, actual_base);
        process_relocations(load_base, preferred_base, actual_base)?;
    }

    // Calculate entry point
    let entry_point = actual_base + pe_info.entry_point_rva as u64;

    // For now, create a kernel-mode representation of the process
    // In a full implementation, we'd create user-mode page tables
    let system_process = crate::ps::get_system_process();
    let process = crate::ps::ps_create_process(system_process, name, 8);
    if process.is_null() {
        return Err(PeError::OutOfMemory);
    }

    // Set up process image information
    // Note: This uses kernel addresses for now
    (*process).section_object = file_base as *mut u8;

    // Calculate user stack address (would be in user space in full implementation)
    let stack_size = pe_info.stack_commit.max(0x10000) as usize; // At least 64KB
    static mut STACK_BUFFER: [u8; 0x20000] = [0; 0x20000]; // 128KB stack
    let user_stack = STACK_BUFFER.as_ptr().add(STACK_BUFFER.len()) as u64;

    crate::serial_println!("[LDR] Creating initial thread:");
    crate::serial_println!("[LDR]   Entry point: {:#x}", entry_point);
    crate::serial_println!("[LDR]   Stack:       {:#x}", user_stack);

    // Create user-mode thread
    let thread = crate::ps::ps_create_user_thread(
        process,
        entry_point,
        user_stack,
        8, // Normal priority
    );

    if thread.is_null() {
        // TODO: Clean up process
        return Err(PeError::OutOfMemory);
    }

    let loaded = LoadedImage {
        base: actual_base,
        size: pe_info.size_of_image,
        entry_point,
        pe_info,
    };

    crate::serial_println!("[LDR] Executable loaded successfully");

    Ok(LoadResult {
        process,
        thread,
        image: loaded,
    })
}

/// Load a DLL into an existing process
///
/// # Arguments
/// * `process` - Target process
/// * `file_base` - Pointer to DLL file in memory
/// * `file_size` - Size of the DLL file
///
/// # Safety
/// - file_base must point to a valid PE DLL
/// - process must be a valid process pointer
pub unsafe fn load_dll(
    _process: *mut crate::ps::EProcess,
    file_base: *const u8,
    _file_size: usize,
) -> Result<LoadedImage, PeError> {
    // Parse PE headers
    let pe_info = parse_pe(file_base)?;

    // Validate it's a DLL
    if !pe_info.is_dll {
        crate::serial_println!("[LDR] Error: Not a DLL");
        return Err(PeError::InvalidOptionalHeader);
    }

    let image_size = pe_info.size_of_image as usize;
    let preferred_base = pe_info.image_base;

    crate::serial_println!("[LDR] Loading DLL:");
    crate::serial_println!("[LDR]   Preferred base: {:#x}", preferred_base);
    crate::serial_println!("[LDR]   Image size:     {:#x}", image_size);

    // In a full implementation:
    // 1. Find available address space in process
    // 2. Allocate and map pages
    // 3. Copy sections
    // 4. Process relocations
    // 5. Process imports
    // 6. Call DllMain with DLL_PROCESS_ATTACH

    // For now, return error as full DLL loading isn't implemented
    Err(PeError::OutOfMemory)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the loader subsystem
pub fn init() {
    crate::serial_println!("[LDR] Loader subsystem initialized");
}
