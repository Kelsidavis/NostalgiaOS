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
use crate::ke::SpinLock;

// ============================================================================
// DLL Buffer Pool
// ============================================================================

/// Maximum number of DLLs that can be loaded
pub const MAX_DLLS: usize = 16;

/// Maximum size of a single DLL (256KB)
pub const MAX_DLL_SIZE: usize = 0x40000;

/// DLL buffer pool
static mut DLL_BUFFER_POOL: [[u8; MAX_DLL_SIZE]; MAX_DLLS] = [[0; MAX_DLL_SIZE]; MAX_DLLS];

/// DLL buffer allocation bitmap
static mut DLL_BUFFER_BITMAP: u16 = 0;

/// DLL buffer pool lock
static DLL_BUFFER_LOCK: SpinLock<()> = SpinLock::new(());

/// Allocate a DLL buffer
///
/// Returns (buffer_ptr, buffer_index) or None if no buffers available
unsafe fn allocate_dll_buffer(size: usize) -> Option<(*mut u8, usize)> {
    if size > MAX_DLL_SIZE {
        crate::serial_println!("[LDR] DLL too large: {} > {}", size, MAX_DLL_SIZE);
        return None;
    }

    let _guard = DLL_BUFFER_LOCK.lock();

    for i in 0..MAX_DLLS {
        if DLL_BUFFER_BITMAP & (1 << i) == 0 {
            DLL_BUFFER_BITMAP |= 1 << i;
            let ptr = DLL_BUFFER_POOL[i].as_mut_ptr();
            // Zero the buffer
            ptr::write_bytes(ptr, 0, MAX_DLL_SIZE);
            return Some((ptr, i));
        }
    }

    None
}

/// Free a DLL buffer by index
unsafe fn free_dll_buffer(index: usize) {
    if index < MAX_DLLS {
        let _guard = DLL_BUFFER_LOCK.lock();
        DLL_BUFFER_BITMAP &= !(1 << index);
    }
}

/// Find DLL buffer index from address
unsafe fn find_dll_buffer_index(addr: *const u8) -> Option<usize> {
    for i in 0..MAX_DLLS {
        let start = DLL_BUFFER_POOL[i].as_ptr();
        let end = start.add(MAX_DLL_SIZE);
        if addr >= start && addr < end {
            return Some(i);
        }
    }
    None
}

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

/// Module resolver callback for forwarder resolution
/// Takes (module_name, function_name or ordinal) and returns the function address
pub type ModuleResolver = unsafe fn(&str, ForwarderTarget<'_>) -> Option<u64>;

/// Maximum length for forwarder function names
pub const MAX_FORWARDER_NAME_LEN: usize = 128;

/// Forwarder target - either a name or ordinal
#[derive(Debug, Clone)]
pub enum ForwarderTarget<'a> {
    Name(&'a str),
    Ordinal(u16),
}

/// Parse a forwarder string (e.g., "NTDLL.RtlGetVersion" or "NTDLL.#42")
fn parse_forwarder(forwarder: &str) -> Option<(&str, ForwarderTarget<'_>)> {
    let dot_pos = forwarder.find('.')?;
    let module_name = &forwarder[..dot_pos];
    let target_str = &forwarder[dot_pos + 1..];

    if target_str.starts_with('#') {
        // Ordinal forwarder
        let ordinal = target_str[1..].parse::<u16>().ok()?;
        Some((module_name, ForwarderTarget::Ordinal(ordinal)))
    } else {
        // Name forwarder
        Some((module_name, ForwarderTarget::Name(target_str)))
    }
}

/// Find an exported function by name with forwarder resolution
///
/// # Arguments
/// * `image_base` - Base address of the loaded DLL
/// * `func_name` - Name of the function to find
/// * `resolver` - Optional callback to resolve forwarders to other modules
///
/// # Safety
/// The caller must ensure `image_base` points to a valid, mapped PE image.
pub unsafe fn find_export_with_forwarder(
    image_base: *const u8,
    func_name: &str,
    resolver: Option<ModuleResolver>,
) -> Option<u64> {
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
                // This is a forwarder string
                let forwarder_str = cstr_to_str(function_va);

                if let Some(resolver_fn) = resolver {
                    if let Some((module_name, target)) = parse_forwarder(forwarder_str) {
                        return resolver_fn(module_name, target);
                    }
                }
                // No resolver or couldn't parse
                return None;
            }

            return Some(function_va as u64);
        }
    }

    None
}

// ============================================================================
// TLS (Thread Local Storage) Support
// ============================================================================

/// TLS callback function signature
pub type TlsCallback = unsafe extern "C" fn(dll_handle: *mut u8, reason: u32, reserved: *mut u8);

/// TLS callback reasons
pub mod tls_reason {
    pub const DLL_PROCESS_ATTACH: u32 = 1;
    pub const DLL_THREAD_ATTACH: u32 = 2;
    pub const DLL_THREAD_DETACH: u32 = 3;
    pub const DLL_PROCESS_DETACH: u32 = 0;
}

/// TLS Directory (32-bit)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageTlsDirectory32 {
    /// Starting address of TLS data template
    pub start_address_of_raw_data: u32,
    /// Ending address of TLS data template
    pub end_address_of_raw_data: u32,
    /// Address of TLS index
    pub address_of_index: u32,
    /// Address of TLS callbacks array (null-terminated)
    pub address_of_callbacks: u32,
    /// Size of zero-fill
    pub size_of_zero_fill: u32,
    /// Characteristics (reserved)
    pub characteristics: u32,
}

/// TLS Directory (64-bit)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageTlsDirectory64 {
    /// Starting address of TLS data template
    pub start_address_of_raw_data: u64,
    /// Ending address of TLS data template
    pub end_address_of_raw_data: u64,
    /// Address of TLS index
    pub address_of_index: u64,
    /// Address of TLS callbacks array (null-terminated)
    pub address_of_callbacks: u64,
    /// Size of zero-fill
    pub size_of_zero_fill: u32,
    /// Characteristics (reserved)
    pub characteristics: u32,
}

/// Process TLS initialization for a loaded image
///
/// # Arguments
/// * `image_base` - Base address of the loaded image
/// * `is_64bit` - Whether this is a 64-bit PE
/// * `reason` - TLS callback reason (DLL_PROCESS_ATTACH, etc.)
///
/// # Safety
/// The caller must ensure `image_base` points to a valid, mapped PE image.
pub unsafe fn process_tls_callbacks(image_base: *mut u8, is_64bit: bool, reason: u32) -> bool {
    let tls_dir = match get_data_directory(
        image_base as *const u8,
        directory_entry::IMAGE_DIRECTORY_ENTRY_TLS,
    ) {
        Some(dir) if dir.is_present() => dir,
        _ => return true, // No TLS directory is OK
    };

    if is_64bit {
        let tls = &*(image_base.add(tls_dir.virtual_address as usize) as *const ImageTlsDirectory64);

        // Initialize TLS index if present
        if tls.address_of_index != 0 {
            // For now, just set to 0 - would need proper TLS slot allocation
            let index_ptr = tls.address_of_index as *mut u32;
            *index_ptr = 0;
        }

        // Call TLS callbacks
        if tls.address_of_callbacks != 0 {
            let callbacks = tls.address_of_callbacks as *const u64;
            let mut i = 0;
            while *callbacks.add(i) != 0 {
                let callback_addr = *callbacks.add(i) as usize;
                let callback: TlsCallback = core::mem::transmute(callback_addr);
                callback(image_base, reason, core::ptr::null_mut());
                i += 1;
            }
        }
    } else {
        let tls = &*(image_base.add(tls_dir.virtual_address as usize) as *const ImageTlsDirectory32);

        // Initialize TLS index
        if tls.address_of_index != 0 {
            let index_ptr = tls.address_of_index as *mut u32;
            *index_ptr = 0;
        }

        // Call TLS callbacks
        if tls.address_of_callbacks != 0 {
            let callbacks = tls.address_of_callbacks as *const u32;
            let mut i = 0;
            while *callbacks.add(i) != 0 {
                let callback_addr = *callbacks.add(i) as usize;
                let callback: TlsCallback = core::mem::transmute(callback_addr);
                callback(image_base, reason, core::ptr::null_mut());
                i += 1;
            }
        }
    }

    true
}

/// Copy TLS data template to thread-specific storage
///
/// # Safety
/// Caller must ensure valid pointers.
pub unsafe fn copy_tls_data(image_base: *const u8, tls_data_ptr: *mut u8, is_64bit: bool) -> bool {
    let tls_dir = match get_data_directory(image_base, directory_entry::IMAGE_DIRECTORY_ENTRY_TLS) {
        Some(dir) if dir.is_present() => dir,
        _ => return true,
    };

    if is_64bit {
        let tls = &*(image_base.add(tls_dir.virtual_address as usize) as *const ImageTlsDirectory64);
        let start = tls.start_address_of_raw_data;
        let end = tls.end_address_of_raw_data;
        let size = (end - start) as usize;
        let zero_fill = tls.size_of_zero_fill as usize;

        if size > 0 {
            ptr::copy_nonoverlapping(start as *const u8, tls_data_ptr, size);
        }
        if zero_fill > 0 {
            ptr::write_bytes(tls_data_ptr.add(size), 0, zero_fill);
        }
    } else {
        let tls = &*(image_base.add(tls_dir.virtual_address as usize) as *const ImageTlsDirectory32);
        let start = tls.start_address_of_raw_data;
        let end = tls.end_address_of_raw_data;
        let size = (end - start) as usize;
        let zero_fill = tls.size_of_zero_fill as usize;

        if size > 0 {
            ptr::copy_nonoverlapping(start as *const u8, tls_data_ptr, size);
        }
        if zero_fill > 0 {
            ptr::write_bytes(tls_data_ptr.add(size), 0, zero_fill);
        }
    }

    true
}

// ============================================================================
// Delay-Load Import Support
// ============================================================================

/// Delay-load descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageDelayloadDescriptor {
    /// Must be zero
    pub attributes: u32,
    /// RVA of DLL name
    pub dll_name_rva: u32,
    /// RVA of module handle
    pub module_handle_rva: u32,
    /// RVA of delay IAT
    pub import_address_table_rva: u32,
    /// RVA of delay INT
    pub import_name_table_rva: u32,
    /// RVA of bound delay IAT
    pub bound_import_address_table_rva: u32,
    /// RVA of unload delay IAT
    pub unload_import_address_table_rva: u32,
    /// Timestamp of binding
    pub time_date_stamp: u32,
}

impl ImageDelayloadDescriptor {
    /// Check if this is the terminating null entry
    pub fn is_null(&self) -> bool {
        self.dll_name_rva == 0 && self.import_address_table_rva == 0
    }
}

/// Get delay-load descriptors from a PE image
///
/// # Safety
/// The caller must ensure `image_base` points to a valid PE image.
pub unsafe fn get_delay_load_descriptors(image_base: *const u8) -> Option<&'static [ImageDelayloadDescriptor]> {
    let delay_dir = get_data_directory(image_base, directory_entry::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)?;
    if !delay_dir.is_present() {
        return None;
    }

    let desc_ptr = image_base.add(delay_dir.virtual_address as usize) as *const ImageDelayloadDescriptor;

    // Count entries
    let mut count = 0;
    while !(*desc_ptr.add(count)).is_null() {
        count += 1;
    }

    if count == 0 {
        return None;
    }

    Some(core::slice::from_raw_parts(desc_ptr, count))
}

/// Process delay-load imports for a module
///
/// This snapshots the delay-load IAT entries so they can be resolved on first call
///
/// # Safety
/// Caller must ensure valid image base.
pub unsafe fn snapshot_delay_load_iat(image_base: *mut u8, is_64bit: bool) -> bool {
    let descriptors = match get_delay_load_descriptors(image_base as *const u8) {
        Some(d) => d,
        None => return true, // No delay loads is OK
    };

    for desc in descriptors {
        // The delay IAT initially contains thunks to the delay-load helper
        // For proper implementation, we'd need to set up the helper routine
        // For now, just log that delay loads are present
        let dll_name = cstr_to_str(image_base.add(desc.dll_name_rva as usize) as *const u8);
        crate::serial_println!("[LDR] Delay-load DLL: {}", dll_name);
    }

    true
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

    // Calculate user stack address (would be in user space in full implementation)
    static mut STACK_BUFFER: [u8; 0x20000] = [0; 0x20000]; // 128KB stack
    let user_stack = STACK_BUFFER.as_ptr().add(STACK_BUFFER.len()) as u64;

    crate::serial_println!("[LDR] Creating process and initial thread:");
    crate::serial_println!("[LDR]   Image base:   {:#x}", actual_base);
    crate::serial_println!("[LDR]   Image size:   {:#x}", pe_info.size_of_image);
    crate::serial_println!("[LDR]   Entry point:  {:#x}", entry_point);
    crate::serial_println!("[LDR]   Stack:        {:#x}", user_stack);
    crate::serial_println!("[LDR]   Subsystem:    {}", pe_info.subsystem);

    // Create user-mode process with PEB/TEB initialization
    let system_process = crate::ps::get_system_process();
    let (process, thread) = crate::ps::ps_create_user_process_ex(
        system_process,
        name,
        entry_point,
        user_stack,
        0, // CR3 - using kernel page tables for now
        actual_base,
        pe_info.size_of_image,
        pe_info.subsystem,
    );

    if process.is_null() {
        return Err(PeError::OutOfMemory);
    }

    if thread.is_null() {
        // TODO: Clean up process
        return Err(PeError::OutOfMemory);
    }

    // Set up process image information
    // Note: This uses kernel addresses for now
    (*process).section_object = file_base as *mut u8;

    // Create LDR entry for the main executable and add to module list
    let peb = (*process).peb;
    if !peb.is_null() && !(*peb).ldr.is_null() {
        let ldr_entry = crate::ps::create_ldr_entry_for_module(
            (*peb).ldr,
            actual_base,
            entry_point,
            pe_info.size_of_image,
            name,
            true, // is_exe = true for main executable
        );
        if ldr_entry.is_null() {
            crate::serial_println!("[LDR] Warning: Failed to create LDR entry");
        }
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

/// Load an executable into a process's address space
///
/// This function loads a PE executable into the process's own page tables,
/// providing true process isolation. Each process gets its own copy of
/// the executable mapped at the preferred base address (or a relocated address).
///
/// # Arguments
/// * `process` - Target process with initialized address space
/// * `file_base` - Pointer to PE file in memory
/// * `file_size` - Size of the PE file
///
/// # Returns
/// Ok((entry_point, image_base, image_size)) on success
///
/// # Safety
/// - file_base must point to a valid PE file
/// - process must have a valid address space
pub unsafe fn load_executable_to_address_space(
    process: *mut crate::ps::EProcess,
    file_base: *const u8,
    _file_size: usize,
) -> Result<(u64, u64, u32), PeError> {
    use crate::mm::{MmAddressSpace, pte_flags, mm_map_user_page, PAGE_SIZE};

    if process.is_null() {
        crate::serial_println!("[LDR] Error: Null process");
        return Err(PeError::OutOfMemory);
    }

    // Get the process's address space
    let aspace = (*process).address_space as *mut MmAddressSpace;
    if aspace.is_null() {
        crate::serial_println!("[LDR] Error: Process has no address space");
        return Err(PeError::OutOfMemory);
    }

    // Parse PE headers
    let pe_info = parse_pe(file_base)?;

    // Validate it's an executable
    if pe_info.is_dll {
        crate::serial_println!("[LDR] Error: Cannot load DLL as executable");
        return Err(PeError::InvalidOptionalHeader);
    }

    let image_size = pe_info.size_of_image as usize;
    let preferred_base = pe_info.image_base;
    let page_count = (image_size + PAGE_SIZE - 1) / PAGE_SIZE;

    crate::serial_println!("[LDR] Loading executable to address space:");
    crate::serial_println!("[LDR]   PML4:         {:#x}", (*aspace).pml4_physical);
    crate::serial_println!("[LDR]   Preferred:    {:#x}", preferred_base);
    crate::serial_println!("[LDR]   Image size:   {:#x} ({} pages)", image_size, page_count);

    // Allocate user pages at the preferred base address
    // Each section will be mapped with appropriate permissions
    let mut loaded_base = preferred_base;

    // Map pages for the entire image at the preferred base
    // For simplicity, map with RWX first, then we can adjust per-section later
    let mut mapped_pages = 0usize;
    for i in 0..page_count {
        let virt_addr = preferred_base + (i * PAGE_SIZE) as u64;
        let flags = pte_flags::USER_RWX; // User-accessible, read-write-execute

        if mm_map_user_page(aspace, virt_addr, flags).is_none() {
            crate::serial_println!("[LDR] Failed to map page {} at {:#x}", i, virt_addr);

            // If we fail at the preferred base, try an alternative
            if i == 0 {
                // Try loading at 0x10000 (64KB) instead
                loaded_base = 0x10000;
                crate::serial_println!("[LDR] Trying alternate base {:#x}", loaded_base);

                // Map at alternate location
                for j in 0..page_count {
                    let alt_addr = loaded_base + (j * PAGE_SIZE) as u64;
                    if mm_map_user_page(aspace, alt_addr, flags).is_none() {
                        crate::serial_println!("[LDR] Failed to map at alternate base");
                        return Err(PeError::OutOfMemory);
                    }
                    mapped_pages += 1;
                }
                break;
            } else {
                // Partial mapping failure - this is bad
                return Err(PeError::OutOfMemory);
            }
        }
        mapped_pages += 1;
    }

    crate::serial_println!("[LDR]   Mapped {} pages at {:#x}", mapped_pages, loaded_base);

    // Now copy the PE sections to the mapped pages
    // We need to access the user pages through the process's page tables
    // Since we're in kernel mode, we can access via identity mapping

    // Get the physical addresses for the mapped pages and copy data
    let section_headers = get_section_headers(file_base).ok_or(PeError::InvalidSection)?;

    // First, copy the PE headers (up to size_of_headers)
    let headers_size = pe_info.size_of_headers as usize;
    copy_to_user_pages(aspace, loaded_base, file_base, headers_size)?;

    // Copy each section
    for section in section_headers.iter() {
        // Read packed struct fields to local variables (avoid unaligned access)
        let virtual_size = { section.virtual_size };
        let size_of_raw_data = { section.size_of_raw_data };
        let virtual_address = { section.virtual_address };
        let pointer_to_raw_data = { section.pointer_to_raw_data };
        let name = { section.name };

        if virtual_size == 0 || size_of_raw_data == 0 {
            continue;
        }

        let section_rva = virtual_address as u64;
        let section_dest = loaded_base + section_rva;
        let section_src = file_base.add(pointer_to_raw_data as usize);
        let copy_size = core::cmp::min(virtual_size, size_of_raw_data) as usize;

        crate::serial_println!("[LDR]   Section '{}': {:#x} -> {:#x} ({} bytes)",
            core::str::from_utf8_unchecked(&name),
            pointer_to_raw_data,
            section_dest,
            copy_size
        );

        copy_to_user_pages(aspace, section_dest, section_src, copy_size)?;

        // Zero-fill any extra space if virtual_size > raw_size
        if virtual_size > size_of_raw_data {
            let zero_start = section_dest + size_of_raw_data as u64;
            let zero_size = (virtual_size - size_of_raw_data) as usize;
            zero_user_pages(aspace, zero_start, zero_size)?;
        }
    }

    // Process relocations if needed
    if loaded_base != preferred_base {
        if !pe_info.has_relocations {
            crate::serial_println!("[LDR] Error: Image requires relocation but has none");
            return Err(PeError::NotRelocatable);
        }
        crate::serial_println!("[LDR] Relocating from {:#x} to {:#x}", preferred_base, loaded_base);

        // We need to process relocations in the user pages
        // This is more complex since we're working with user page tables
        // For now, we'll do it through identity mapping since low memory is identity-mapped
        process_relocations_in_place(aspace, loaded_base, preferred_base, &pe_info)?;
    }

    let entry_point = loaded_base + pe_info.entry_point_rva as u64;

    crate::serial_println!("[LDR] Executable loaded to address space:");
    crate::serial_println!("[LDR]   Image base:  {:#x}", loaded_base);
    crate::serial_println!("[LDR]   Entry point: {:#x}", entry_point);

    Ok((entry_point, loaded_base, pe_info.size_of_image))
}

/// Copy data to user pages in a process's address space
unsafe fn copy_to_user_pages(
    aspace: *mut crate::mm::MmAddressSpace,
    dest_virt: u64,
    src: *const u8,
    len: usize,
) -> Result<(), PeError> {
    use crate::mm::{PAGE_SIZE, pte::mm_virtual_to_physical};

    let pml4 = (*aspace).pml4_physical;
    let mut remaining = len;
    let mut src_ptr = src;
    let mut dest_addr = dest_virt;

    while remaining > 0 {
        // Get the physical address for this page
        let dest_phys = match mm_virtual_to_physical(pml4, dest_addr) {
            Some(p) => p,
            None => {
                crate::serial_println!("[LDR] Failed to get physical for {:#x}", dest_addr);
                return Err(PeError::OutOfMemory);
            }
        };

        // Calculate offset within page and how much to copy
        let page_offset = (dest_addr & 0xFFF) as usize;
        let copy_size = core::cmp::min(remaining, PAGE_SIZE - page_offset);

        // Copy through identity-mapped physical address
        let dest_ptr = dest_phys as *mut u8;
        core::ptr::copy_nonoverlapping(src_ptr, dest_ptr, copy_size);

        remaining -= copy_size;
        src_ptr = src_ptr.add(copy_size);
        dest_addr += copy_size as u64;
    }

    Ok(())
}

/// Zero user pages in a process's address space
unsafe fn zero_user_pages(
    aspace: *mut crate::mm::MmAddressSpace,
    dest_virt: u64,
    len: usize,
) -> Result<(), PeError> {
    use crate::mm::{PAGE_SIZE, pte::mm_virtual_to_physical};

    let pml4 = (*aspace).pml4_physical;
    let mut remaining = len;
    let mut dest_addr = dest_virt;

    while remaining > 0 {
        let dest_phys = match mm_virtual_to_physical(pml4, dest_addr) {
            Some(p) => p,
            None => return Err(PeError::OutOfMemory),
        };

        let page_offset = (dest_addr & 0xFFF) as usize;
        let zero_size = core::cmp::min(remaining, crate::mm::PAGE_SIZE - page_offset);

        let dest_ptr = dest_phys as *mut u8;
        core::ptr::write_bytes(dest_ptr, 0, zero_size);

        remaining -= zero_size;
        dest_addr += zero_size as u64;
    }

    Ok(())
}

/// Process relocations in user pages
unsafe fn process_relocations_in_place(
    aspace: *mut crate::mm::MmAddressSpace,
    image_base: u64,
    original_base: u64,
    _pe_info: &PeInfo,
) -> Result<(), PeError> {
    use crate::mm::pte::mm_virtual_to_physical;

    let pml4 = (*aspace).pml4_physical;
    let delta = image_base.wrapping_sub(original_base) as i64;

    if delta == 0 {
        return Ok(());
    }

    // Get the relocation directory from the loaded image
    // We need to read from physical memory through identity mapping
    let header_phys = mm_virtual_to_physical(pml4, image_base).ok_or(PeError::RelocationError)?;
    let header_base = header_phys as *const u8;

    // Get relocation directory using the copied headers
    let reloc_dir = match get_data_directory(header_base, directory_entry::IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        Some(dir) if dir.is_present() => dir,
        _ => return Ok(()), // No relocations
    };

    let reloc_dir_rva = reloc_dir.virtual_address;
    if reloc_dir_rva == 0 {
        return Ok(());
    }

    // Read relocation data through physical mapping
    let reloc_virt = image_base + reloc_dir_rva as u64;
    let reloc_phys = mm_virtual_to_physical(pml4, reloc_virt).ok_or(PeError::RelocationError)?;

    let mut block_ptr = reloc_phys as *const ImageBaseRelocation;

    loop {
        let block = &*block_ptr;

        if block.virtual_address == 0 || block.size_of_block == 0 {
            break;
        }

        let entry_count = (block.size_of_block as usize - 8) / 2;
        let entries = core::slice::from_raw_parts(
            (block_ptr as *const u8).add(8) as *const u16,
            entry_count,
        );

        for &entry in entries {
            let reloc_type = (entry >> 12) as u8;
            let offset = (entry & 0x0FFF) as u32;

            if reloc_type == 0 {
                continue; // Padding
            }

            let target_rva = block.virtual_address + offset;
            let target_virt = image_base + target_rva as u64;
            let target_phys = match mm_virtual_to_physical(pml4, target_virt) {
                Some(p) => p,
                None => continue, // Skip if not mapped
            };

            match reloc_type {
                IMAGE_REL_BASED_HIGHLOW => {
                    // 32-bit relocation
                    let ptr = target_phys as *mut u32;
                    let old_val = *ptr;
                    *ptr = old_val.wrapping_add(delta as u32);
                }
                IMAGE_REL_BASED_DIR64 => {
                    // 64-bit relocation
                    let ptr = target_phys as *mut u64;
                    let old_val = *ptr;
                    *ptr = (old_val as i64).wrapping_add(delta) as u64;
                }
                _ => {} // Ignore other types
            }
        }

        // Move to next block
        block_ptr = (block_ptr as *const u8).add(block.size_of_block as usize) as *const ImageBaseRelocation;
    }

    crate::serial_println!("[LDR] Relocations applied (delta={:#x})", delta);
    Ok(())
}

/// Load a DLL into an existing process
///
/// # Arguments
/// * `process` - Target process
/// * `file_base` - Pointer to DLL file in memory
/// * `file_size` - Size of the DLL file
/// * `name` - DLL name for LDR entry
///
/// # Safety
/// - file_base must point to a valid PE DLL
/// - process must be a valid process pointer
pub unsafe fn load_dll(
    process: *mut crate::ps::EProcess,
    file_base: *const u8,
    _file_size: usize,
    name: &[u8],
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

    crate::serial_println!("[LDR] Loading DLL '{}':", core::str::from_utf8_unchecked(name));
    crate::serial_println!("[LDR]   Preferred base: {:#x}", preferred_base);
    crate::serial_println!("[LDR]   Image size:     {:#x}", image_size);

    // Allocate buffer from DLL pool
    let (load_base, _buffer_idx) = match allocate_dll_buffer(image_size) {
        Some((ptr, idx)) => (ptr, idx),
        None => {
            crate::serial_println!("[LDR] Error: No DLL buffers available");
            return Err(PeError::OutOfMemory);
        }
    };

    // Copy sections to the load buffer
    copy_sections(file_base, load_base, &pe_info)?;

    // Process relocations if loaded at different address
    let actual_base = load_base as u64;
    if actual_base != preferred_base {
        if !pe_info.has_relocations {
            crate::serial_println!("[LDR] Error: DLL requires relocation but has none");
            free_dll_buffer(_buffer_idx);
            return Err(PeError::NotRelocatable);
        }
        crate::serial_println!("[LDR] Relocating DLL from {:#x} to {:#x}", preferred_base, actual_base);
        if let Err(e) = process_relocations(load_base, preferred_base, actual_base) {
            free_dll_buffer(_buffer_idx);
            return Err(e);
        }
    }

    // Calculate entry point (DllMain)
    let entry_point = if pe_info.entry_point_rva != 0 {
        actual_base + pe_info.entry_point_rva as u64
    } else {
        0
    };

    // Create LDR entry for this DLL if process has a PEB
    if !process.is_null() {
        let peb = (*process).peb;
        if !peb.is_null() && !(*peb).ldr.is_null() {
            let ldr_entry = crate::ps::create_ldr_entry_for_module(
                (*peb).ldr,
                actual_base,
                entry_point,
                pe_info.size_of_image,
                name,
                false, // is_exe = false for DLLs
            );
            if ldr_entry.is_null() {
                crate::serial_println!("[LDR] Warning: Failed to create LDR entry for DLL");
            }
        }
    }

    let loaded = LoadedImage {
        base: actual_base,
        size: pe_info.size_of_image,
        entry_point,
        pe_info,
    };

    crate::serial_println!("[LDR] DLL loaded at {:#x} (entry={:#x})", actual_base, entry_point);

    Ok(loaded)
}

/// Unload a DLL from a process
///
/// # Safety
/// - image must have been loaded with load_dll
pub unsafe fn unload_dll(image: &LoadedImage) -> Result<(), PeError> {
    let base_ptr = image.base as *const u8;

    // Find and free the DLL buffer
    if let Some(idx) = find_dll_buffer_index(base_ptr) {
        free_dll_buffer(idx);
        crate::serial_println!("[LDR] DLL unloaded from {:#x}", image.base);
        Ok(())
    } else {
        crate::serial_println!("[LDR] Error: DLL not found in buffer pool");
        Err(PeError::InvalidSection)
    }
}

/// Load a DLL and resolve its imports
///
/// Extended version that also processes imports using a resolver callback.
pub unsafe fn load_dll_with_imports(
    process: *mut crate::ps::EProcess,
    file_base: *const u8,
    file_size: usize,
    name: &[u8],
    resolver: ImportResolver,
) -> Result<LoadedImage, PeError> {
    // First load the DLL
    let loaded = load_dll(process, file_base, file_size, name)?;

    // Process imports
    let load_base = loaded.base as *mut u8;
    if let Err(e) = process_imports(load_base, resolver) {
        crate::serial_println!("[LDR] Error processing imports for DLL");
        unload_dll(&loaded)?;
        return Err(e);
    }

    Ok(loaded)
}

// ============================================================================
// Module Lookup
// ============================================================================

/// Find a loaded module by name in a process's module list
///
/// # Safety
/// - process must be a valid process pointer
pub unsafe fn find_module_by_name(
    process: *mut crate::ps::EProcess,
    name: &str,
) -> Option<u64> {
    if process.is_null() {
        return None;
    }

    let peb = (*process).peb;
    if peb.is_null() {
        return None;
    }

    let ldr = (*peb).ldr;
    if ldr.is_null() {
        return None;
    }

    // Walk the InLoadOrderModuleList
    let list_head = &(*ldr).in_load_order_module_list as *const crate::ps::ListEntry64;
    let mut current = (*list_head).flink as *const crate::ps::ListEntry64;

    while current != list_head {
        // The ListEntry64 is the first field of LdrDataTableEntry
        let entry = current as *const crate::ps::LdrDataTableEntry;

        // Get the BaseDllName from the entry
        let base_name = &(*entry).base_dll_name;
        if base_name.length > 0 && !base_name.buffer.is_null() {
            // Convert wide string to compare (simplified - assumes ASCII)
            let name_buf = base_name.buffer as *const u16;
            let name_len = (base_name.length / 2) as usize;

            let mut matches = name_len == name.len();
            if matches {
                for i in 0..name_len {
                    let c = (*name_buf.add(i)) as u8;
                    let target = name.as_bytes()[i];
                    // Case-insensitive comparison
                    if c.to_ascii_lowercase() != target.to_ascii_lowercase() {
                        matches = false;
                        break;
                    }
                }
            }

            if matches {
                return Some((*entry).dll_base as u64);
            }
        }

        current = (*current).flink as *const crate::ps::ListEntry64;
    }

    None
}

/// Create an import resolver for a process
///
/// Returns a resolver function that looks up imports from loaded modules.
pub fn create_process_import_resolver(
    process: *mut crate::ps::EProcess,
) -> impl Fn(&str, &str, u16) -> Option<u64> {
    move |dll_name: &str, func_name: &str, ordinal: u16| -> Option<u64> {
        unsafe {
            // Find the DLL in the process's module list
            let dll_base = find_module_by_name(process, dll_name)?;

            if !func_name.is_empty() {
                // Resolve by name
                find_export_by_name(dll_base as *const u8, func_name)
            } else {
                // Resolve by ordinal
                find_export_by_ordinal(dll_base as *const u8, ordinal)
            }
        }
    }
}

/// Get the number of loaded DLLs from the buffer pool
pub fn get_loaded_dll_count() -> usize {
    unsafe {
        let _guard = DLL_BUFFER_LOCK.lock();
        DLL_BUFFER_BITMAP.count_ones() as usize
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the loader subsystem
pub fn init() {
    crate::serial_println!("[LDR] Loader subsystem initialized");
    crate::serial_println!("[LDR]   Max DLLs: {}", MAX_DLLS);
    crate::serial_println!("[LDR]   Max DLL size: {} KB", MAX_DLL_SIZE / 1024);
    crate::serial_println!("[LDR]   Kernel exports: {}", get_kernel_export_count());
}

// ============================================================================
// Kernel Export Resolution
// ============================================================================

/// Resolve a kernel export by name using match-based lookup
///
/// Checks ntoskrnl.exe and hal.dll exports
pub fn resolve_kernel_export(dll_name: &str, func_name: &str) -> Option<u64> {
    // Normalize DLL name (case-insensitive)
    let dll_lower = dll_name.to_ascii_lowercase();
    let is_ntoskrnl = dll_lower.starts_with("ntoskrnl") || dll_lower.starts_with("ntkrnl");
    let is_hal = dll_lower.starts_with("hal");

    if is_ntoskrnl {
        resolve_ntoskrnl_export(func_name)
    } else if is_hal {
        resolve_hal_export(func_name)
    } else {
        None
    }
}

/// Resolve ntoskrnl.exe exports
fn resolve_ntoskrnl_export(func_name: &str) -> Option<u64> {
    // Use match for efficient lookup (case-insensitive comparison)
    let addr: Option<unsafe extern "C" fn() -> ()> = match func_name {
        // Memory Manager
        "MmGetPhysicalAddress" => Some(unsafe { core::mem::transmute(mm_get_physical_address as usize) }),
        "MmMapIoSpace" => Some(unsafe { core::mem::transmute(mm_map_io_space as usize) }),
        "MmUnmapIoSpace" => Some(unsafe { core::mem::transmute(mm_unmap_io_space as usize) }),
        "MmAllocateContiguousMemory" => Some(unsafe { core::mem::transmute(mm_allocate_contiguous as usize) }),
        "MmFreeContiguousMemory" => Some(unsafe { core::mem::transmute(mm_free_contiguous as usize) }),

        // Executive Pool
        "ExAllocatePool" => Some(unsafe { core::mem::transmute(ex_allocate_pool as usize) }),
        "ExAllocatePoolWithTag" => Some(unsafe { core::mem::transmute(ex_allocate_pool_with_tag as usize) }),
        "ExFreePool" => Some(unsafe { core::mem::transmute(ex_free_pool as usize) }),
        "ExFreePoolWithTag" => Some(unsafe { core::mem::transmute(ex_free_pool_with_tag as usize) }),

        // Kernel Services
        "KeInitializeSpinLock" => Some(unsafe { core::mem::transmute(ke_initialize_spinlock as usize) }),
        "KeAcquireSpinLockAtDpcLevel" => Some(unsafe { core::mem::transmute(ke_acquire_spinlock_dpc as usize) }),
        "KeReleaseSpinLockFromDpcLevel" => Some(unsafe { core::mem::transmute(ke_release_spinlock_dpc as usize) }),
        "KeInitializeEvent" => Some(unsafe { core::mem::transmute(ke_initialize_event as usize) }),
        "KeSetEvent" => Some(unsafe { core::mem::transmute(ke_set_event as usize) }),
        "KeResetEvent" => Some(unsafe { core::mem::transmute(ke_reset_event as usize) }),
        "KeWaitForSingleObject" => Some(unsafe { core::mem::transmute(ke_wait_for_single_object as usize) }),
        "KeGetCurrentIrql" => Some(unsafe { core::mem::transmute(ke_get_current_irql as usize) }),
        "KeRaiseIrql" => Some(unsafe { core::mem::transmute(ke_raise_irql as usize) }),
        "KeLowerIrql" => Some(unsafe { core::mem::transmute(ke_lower_irql as usize) }),
        "KeQuerySystemTime" => Some(unsafe { core::mem::transmute(ke_query_system_time as usize) }),
        "KeDelayExecutionThread" => Some(unsafe { core::mem::transmute(ke_delay_execution as usize) }),

        // I/O Manager
        "IoCreateDevice" => Some(unsafe { core::mem::transmute(io_create_device as usize) }),
        "IoDeleteDevice" => Some(unsafe { core::mem::transmute(io_delete_device as usize) }),
        "IoAttachDevice" => Some(unsafe { core::mem::transmute(io_attach_device as usize) }),
        "IoDetachDevice" => Some(unsafe { core::mem::transmute(io_detach_device as usize) }),
        "IoGetCurrentIrpStackLocation" => Some(unsafe { core::mem::transmute(io_get_current_irp_stack as usize) }),
        "IoCompleteRequest" => Some(unsafe { core::mem::transmute(io_complete_request as usize) }),
        "IoCallDriver" => Some(unsafe { core::mem::transmute(io_call_driver as usize) }),
        "IofCompleteRequest" => Some(unsafe { core::mem::transmute(iof_complete_request as usize) }),
        "IofCallDriver" => Some(unsafe { core::mem::transmute(iof_call_driver as usize) }),

        // Runtime Library
        "RtlCopyMemory" => Some(unsafe { core::mem::transmute(rtl_copy_memory as usize) }),
        "RtlZeroMemory" => Some(unsafe { core::mem::transmute(rtl_zero_memory as usize) }),
        "RtlFillMemory" => Some(unsafe { core::mem::transmute(rtl_fill_memory as usize) }),
        "RtlCompareMemory" => Some(unsafe { core::mem::transmute(rtl_compare_memory as usize) }),
        "RtlInitUnicodeString" => Some(unsafe { core::mem::transmute(rtl_init_unicode_string as usize) }),
        "RtlCopyUnicodeString" => Some(unsafe { core::mem::transmute(rtl_copy_unicode_string as usize) }),
        "RtlCompareUnicodeString" => Some(unsafe { core::mem::transmute(rtl_compare_unicode_string as usize) }),

        // Debug Services
        "DbgPrint" => Some(unsafe { core::mem::transmute(dbg_print as usize) }),
        "DbgBreakPoint" => Some(unsafe { core::mem::transmute(dbg_break_point as usize) }),

        // Object Manager
        "ObReferenceObject" => Some(unsafe { core::mem::transmute(ob_reference_object as usize) }),
        "ObDereferenceObject" => Some(unsafe { core::mem::transmute(ob_dereference_object as usize) }),
        "ObReferenceObjectByHandle" => Some(unsafe { core::mem::transmute(ob_reference_by_handle as usize) }),

        // Process/Thread
        "PsGetCurrentProcess" => Some(unsafe { core::mem::transmute(ps_get_current_process as usize) }),
        "PsGetCurrentThread" => Some(unsafe { core::mem::transmute(ps_get_current_thread as usize) }),
        "PsGetCurrentProcessId" => Some(unsafe { core::mem::transmute(ps_get_current_process_id as usize) }),
        "PsGetCurrentThreadId" => Some(unsafe { core::mem::transmute(ps_get_current_thread_id as usize) }),

        _ => None,
    };

    if addr.is_some() {
        return addr.map(|f| f as usize as u64);
    }

    crate::serial_println!("[LDR] Unresolved ntoskrnl export: {}", func_name);
    None
}

/// Resolve hal.dll exports
fn resolve_hal_export(func_name: &str) -> Option<u64> {
    let addr: Option<unsafe extern "C" fn() -> ()> = match func_name {
        "HalGetInterruptVector" => Some(unsafe { core::mem::transmute(hal_get_interrupt_vector as usize) }),
        "HalTranslateBusAddress" => Some(unsafe { core::mem::transmute(hal_translate_bus_address as usize) }),
        "READ_PORT_UCHAR" => Some(unsafe { core::mem::transmute(hal_read_port_uchar as usize) }),
        "READ_PORT_USHORT" => Some(unsafe { core::mem::transmute(hal_read_port_ushort as usize) }),
        "READ_PORT_ULONG" => Some(unsafe { core::mem::transmute(hal_read_port_ulong as usize) }),
        "WRITE_PORT_UCHAR" => Some(unsafe { core::mem::transmute(hal_write_port_uchar as usize) }),
        "WRITE_PORT_USHORT" => Some(unsafe { core::mem::transmute(hal_write_port_ushort as usize) }),
        "WRITE_PORT_ULONG" => Some(unsafe { core::mem::transmute(hal_write_port_ulong as usize) }),
        _ => None,
    };

    if addr.is_some() {
        return addr.map(|f| f as usize as u64);
    }

    crate::serial_println!("[LDR] Unresolved hal export: {}", func_name);
    None
}

/// Get the count of available kernel exports
pub fn get_kernel_export_count() -> usize {
    // Count of entries in resolve_ntoskrnl_export match + resolve_hal_export
    52 + 8
}

/// Create a kernel-mode import resolver
///
/// Returns a resolver function that looks up imports from kernel exports
/// (ntoskrnl.exe, hal.dll) first, then falls back to loaded modules.
pub fn create_kernel_import_resolver() -> impl Fn(&str, &str, u16) -> Option<u64> {
    |dll_name: &str, func_name: &str, _ordinal: u16| -> Option<u64> {
        // First try kernel exports
        if let Some(addr) = resolve_kernel_export(dll_name, func_name) {
            return Some(addr);
        }

        // TODO: Fall back to loaded drivers/DLLs
        None
    }
}

// ============================================================================
// Kernel Export Stub Functions
// ============================================================================
//
// These stubs forward to the actual kernel implementations.
// They provide a stable ABI for driver compatibility.

// Memory Manager stubs
unsafe extern "C" fn mm_get_physical_address(virtual_addr: u64) -> u64 {
    // Walk page tables to get physical address using current CR3
    let cr3: u64;
    core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    crate::mm::pte::mm_virtual_to_physical(cr3, virtual_addr).unwrap_or(0)
}

unsafe extern "C" fn mm_map_io_space(phys_addr: u64, _size: usize, _cache_type: u32) -> u64 {
    // For now, assume physical memory is already identity mapped
    phys_addr
}

unsafe extern "C" fn mm_unmap_io_space(_virtual_addr: u64, _size: usize) {
    // No-op for now
}

unsafe extern "C" fn mm_allocate_contiguous(size: usize) -> u64 {
    // Allocate from nonpaged pool (contiguous is just pool allocation for now)
    crate::mm::pool::ex_allocate_pool_with_tag(
        crate::mm::pool::PoolType::NonPagedPool,
        size,
        u32::from_le_bytes(*b"Cont"),
    ) as u64
}

unsafe extern "C" fn mm_free_contiguous(base: u64, _size: usize) {
    crate::mm::pool::ex_free_pool_with_tag(base as *mut u8, u32::from_le_bytes(*b"Cont"));
}

// Executive Pool stubs
unsafe extern "C" fn ex_allocate_pool(pool_type: u32, size: usize) -> u64 {
    let pt = if pool_type == 0 {
        crate::mm::pool::PoolType::NonPagedPool
    } else {
        crate::mm::pool::PoolType::PagedPool
    };
    crate::mm::pool::ex_allocate_pool_with_tag(pt, size, u32::from_le_bytes(*b"Krnl")) as u64
}

unsafe extern "C" fn ex_allocate_pool_with_tag(pool_type: u32, size: usize, tag: u32) -> u64 {
    let pt = if pool_type == 0 {
        crate::mm::pool::PoolType::NonPagedPool
    } else {
        crate::mm::pool::PoolType::PagedPool
    };
    crate::mm::pool::ex_allocate_pool_with_tag(pt, size, tag) as u64
}

unsafe extern "C" fn ex_free_pool(ptr: u64) {
    crate::mm::pool::ex_free_pool_with_tag(ptr as *mut u8, 0);
}

unsafe extern "C" fn ex_free_pool_with_tag(ptr: u64, tag: u32) {
    crate::mm::pool::ex_free_pool_with_tag(ptr as *mut u8, tag);
}

// Kernel Services stubs
unsafe extern "C" fn ke_initialize_spinlock(lock: *mut u64) {
    *lock = 0;
}

unsafe extern "C" fn ke_acquire_spinlock_dpc(lock: *mut u64) {
    // Simple spinlock
    while core::sync::atomic::AtomicU64::from_ptr(lock)
        .compare_exchange(0, 1, core::sync::atomic::Ordering::Acquire, core::sync::atomic::Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

unsafe extern "C" fn ke_release_spinlock_dpc(lock: *mut u64) {
    core::sync::atomic::AtomicU64::from_ptr(lock).store(0, core::sync::atomic::Ordering::Release);
}

unsafe extern "C" fn ke_initialize_event(event: *mut u64, event_type: u32, state: bool) {
    let _ = (event, event_type, state);
    // TODO: Initialize dispatcher object
}

unsafe extern "C" fn ke_set_event(event: *mut u64, increment: i32, wait: bool) -> i32 {
    let _ = (event, increment, wait);
    0 // Previous state
}

unsafe extern "C" fn ke_reset_event(event: *mut u64) -> i32 {
    let _ = event;
    0 // Previous state
}

unsafe extern "C" fn ke_wait_for_single_object(
    object: *mut u64, wait_reason: u32, wait_mode: u32, alertable: bool, timeout: *const i64
) -> i32 {
    let _ = (object, wait_reason, wait_mode, alertable, timeout);
    0 // STATUS_SUCCESS
}

unsafe extern "C" fn ke_get_current_irql() -> u8 {
    crate::ke::kpcr::ke_get_current_irql()
}

unsafe extern "C" fn ke_raise_irql(new_irql: u8, old_irql: *mut u8) {
    *old_irql = crate::ke::kpcr::ke_raise_irql(new_irql);
}

unsafe extern "C" fn ke_lower_irql(new_irql: u8) {
    crate::ke::kpcr::ke_lower_irql(new_irql);
}

unsafe extern "C" fn ke_query_system_time(time: *mut i64) {
    *time = crate::rtl::rtl_get_system_time();
}

unsafe extern "C" fn ke_delay_execution(_alertable: bool, interval: *const i64) -> i32 {
    let _ = interval;
    // TODO: Actual delay
    0
}

// I/O Manager stubs
unsafe extern "C" fn io_create_device(
    _driver: u64, _ext_size: u32, _name: u64, _type: u32, _chars: u32, _exclusive: bool, _device: *mut u64
) -> i32 {
    // TODO: Create device object
    0
}

unsafe extern "C" fn io_delete_device(_device: u64) {
    // TODO: Delete device
}

unsafe extern "C" fn io_attach_device(_source: u64, _target_name: u64, _target: *mut u64) -> i32 {
    0
}

unsafe extern "C" fn io_detach_device(_target: u64) {
    // TODO: Detach
}

unsafe extern "C" fn io_get_current_irp_stack(irp: u64) -> u64 {
    // Return current stack location from IRP
    if irp == 0 { return 0; }
    let irp_ptr = irp as *const crate::io::Irp;
    match (*irp_ptr).get_current_stack_location() {
        Some(stack) => stack as *const _ as u64,
        None => 0,
    }
}

unsafe extern "C" fn io_complete_request(irp: u64, priority_boost: i8) {
    let _ = (irp, priority_boost);
    // TODO: Complete IRP
}

unsafe extern "C" fn io_call_driver(device: u64, irp: u64) -> i32 {
    let _ = (device, irp);
    // TODO: Call driver
    0
}

unsafe extern "C" fn iof_complete_request(irp: u64, priority_boost: i8) {
    io_complete_request(irp, priority_boost);
}

unsafe extern "C" fn iof_call_driver(device: u64, irp: u64) -> i32 {
    io_call_driver(device, irp)
}

// RTL stubs
unsafe extern "C" fn rtl_copy_memory(dest: *mut u8, src: *const u8, len: usize) {
    ptr::copy_nonoverlapping(src, dest, len);
}

unsafe extern "C" fn rtl_zero_memory(dest: *mut u8, len: usize) {
    ptr::write_bytes(dest, 0, len);
}

unsafe extern "C" fn rtl_fill_memory(dest: *mut u8, len: usize, fill: u8) {
    ptr::write_bytes(dest, fill, len);
}

unsafe extern "C" fn rtl_compare_memory(s1: *const u8, s2: *const u8, len: usize) -> usize {
    for i in 0..len {
        if *s1.add(i) != *s2.add(i) {
            return i;
        }
    }
    len
}

unsafe extern "C" fn rtl_init_unicode_string(dest: *mut crate::rtl::UnicodeString, source: *const u16) {
    if source.is_null() {
        (*dest).length = 0;
        (*dest).maximum_length = 0;
        (*dest).buffer = ptr::null_mut();
    } else {
        let mut len = 0u16;
        while *source.add(len as usize) != 0 {
            len += 1;
        }
        (*dest).length = len * 2;
        (*dest).maximum_length = (len + 1) * 2;
        (*dest).buffer = source as *mut u16;
    }
}

unsafe extern "C" fn rtl_copy_unicode_string(dest: *mut crate::rtl::UnicodeString, src: *const crate::rtl::UnicodeString) {
    if src.is_null() || (*src).buffer.is_null() {
        (*dest).length = 0;
        return;
    }
    let copy_len = core::cmp::min((*src).length, (*dest).maximum_length);
    ptr::copy_nonoverlapping((*src).buffer, (*dest).buffer, (copy_len / 2) as usize);
    (*dest).length = copy_len;
}

unsafe extern "C" fn rtl_compare_unicode_string(s1: *const crate::rtl::UnicodeString, s2: *const crate::rtl::UnicodeString, case_insensitive: bool) -> i32 {
    let len1 = (*s1).length / 2;
    let len2 = (*s2).length / 2;
    let min_len = core::cmp::min(len1, len2);

    for i in 0..min_len as usize {
        let mut c1 = *(*s1).buffer.add(i);
        let mut c2 = *(*s2).buffer.add(i);
        if case_insensitive {
            if c1 >= 'A' as u16 && c1 <= 'Z' as u16 { c1 += 32; }
            if c2 >= 'A' as u16 && c2 <= 'Z' as u16 { c2 += 32; }
        }
        if c1 != c2 {
            return if c1 < c2 { -1 } else { 1 };
        }
    }

    if len1 < len2 { -1 } else if len1 > len2 { 1 } else { 0 }
}

// Debug stubs
unsafe extern "C" fn dbg_print(format: *const u8) -> i32 {
    // Simple implementation - just print the format string
    // Note: Full variadic support would require c_variadic feature
    let s = cstr_to_str(format);
    crate::serial_println!("[DBG] {}", s);
    0
}

unsafe extern "C" fn dbg_break_point() {
    core::arch::asm!("int3", options(nomem, nostack));
}

// Object Manager stubs
unsafe extern "C" fn ob_reference_object(object: u64) {
    let _ = object;
    // TODO: Increment reference count
}

unsafe extern "C" fn ob_dereference_object(object: u64) {
    let _ = object;
    // TODO: Decrement reference count
}

unsafe extern "C" fn ob_reference_by_handle(handle: u64, _type: u64, _mode: u32, object: *mut u64, _handle_info: u64) -> i32 {
    let _ = handle;
    *object = 0;
    0
}

// Process/Thread stubs
unsafe extern "C" fn ps_get_current_process() -> u64 {
    // Get current thread and then its process
    let thread = crate::ke::prcb::get_current_thread();
    if thread.is_null() {
        return 0;
    }
    (*thread).process as u64
}

unsafe extern "C" fn ps_get_current_thread() -> u64 {
    crate::ke::prcb::get_current_thread() as u64
}

unsafe extern "C" fn ps_get_current_process_id() -> u32 {
    let process = ps_get_current_process();
    if process == 0 {
        return 0;
    }
    // Get PID from EPROCESS
    let eprocess = process as *const crate::ps::EProcess;
    (*eprocess).unique_process_id as u32
}

unsafe extern "C" fn ps_get_current_thread_id() -> u32 {
    let thread = crate::ke::prcb::get_current_thread();
    if thread.is_null() {
        return 0;
    }
    // Get TID from ETHREAD - need to get ETHREAD first
    // For now, use a simple thread ID from the thread structure
    (*thread).thread_id
}

// HAL stubs
unsafe extern "C" fn hal_get_interrupt_vector(
    _interface: u32, _bus: u32, _level: u32, _vector: u32, irql: *mut u8, affinity: *mut u64
) -> u32 {
    *irql = crate::ke::kpcr::irql::DEVICE_LEVEL_BASE;
    *affinity = 1;
    0x30 // Default vector
}

unsafe extern "C" fn hal_translate_bus_address(
    _interface: u32, _bus: u32, bus_addr: u64, _space: *mut u32, translated: *mut u64
) -> bool {
    // Identity translation for now
    *translated = bus_addr;
    true
}

unsafe extern "C" fn hal_read_port_uchar(port: u16) -> u8 {
    crate::arch::io::inb(port)
}

unsafe extern "C" fn hal_read_port_ushort(port: u16) -> u16 {
    crate::arch::io::inw(port)
}

unsafe extern "C" fn hal_read_port_ulong(port: u16) -> u32 {
    crate::arch::io::inl(port)
}

unsafe extern "C" fn hal_write_port_uchar(port: u16, value: u8) {
    crate::arch::io::outb(port, value);
}

unsafe extern "C" fn hal_write_port_ushort(port: u16, value: u16) {
    crate::arch::io::outw(port, value);
}

unsafe extern "C" fn hal_write_port_ulong(port: u16, value: u32) {
    crate::arch::io::outl(port, value);
}
