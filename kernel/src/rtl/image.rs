//! RTL Image Helper Functions
//!
//! These functions provide convenient access to PE image structures,
//! following the Windows NT RtlImage* API.
//!
//! # Functions
//! - `RtlImageNtHeader`: Get NT headers from image base
//! - `RtlImageDirectoryEntryToData`: Get data directory entry
//! - `RtlImageRvaToVa`: Convert RVA to virtual address
//! - `RtlImageRvaToSection`: Find section containing RVA

use crate::ldr::pe::*;
use core::ptr;

/// Get the NT headers from a PE image base
///
/// # Arguments
/// * `base` - Base address of the loaded PE image
///
/// # Returns
/// Pointer to IMAGE_NT_HEADERS, or null if invalid
///
/// # Safety
/// Caller must ensure `base` points to a valid PE image
#[inline]
pub unsafe fn rtl_image_nt_header(base: *const u8) -> *const u8 {
    if base.is_null() {
        return ptr::null();
    }

    // Check DOS header
    let dos_header = base as *const ImageDosHeader;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return ptr::null();
    }

    // Get PE header offset
    let pe_offset = (*dos_header).e_lfanew as usize;
    if pe_offset == 0 || pe_offset > 0x10000000 {
        return ptr::null();
    }

    let nt_header = base.add(pe_offset);

    // Verify PE signature
    let signature = *(nt_header as *const u32);
    if signature != IMAGE_NT_SIGNATURE {
        return ptr::null();
    }

    nt_header
}

/// Get a data directory entry from a PE image
///
/// # Arguments
/// * `base` - Base address of the loaded PE image
/// * `directory_index` - Index of the directory entry (0-15)
/// * `size` - Output: size of the directory data
///
/// # Returns
/// Pointer to the directory data, or null if not present
///
/// # Safety
/// Caller must ensure `base` points to a valid PE image
pub unsafe fn rtl_image_directory_entry_to_data(
    base: *const u8,
    directory_index: usize,
    size: *mut u32,
) -> *const u8 {
    if !size.is_null() {
        *size = 0;
    }

    if directory_index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
        return ptr::null();
    }

    let nt_header = rtl_image_nt_header(base);
    if nt_header.is_null() {
        return ptr::null();
    }

    // Get file header to determine PE type
    let file_header = nt_header.add(4) as *const ImageFileHeader;
    let optional_header_base = nt_header.add(4 + core::mem::size_of::<ImageFileHeader>());
    let magic = *(optional_header_base as *const u16);

    let data_dir = if magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        let opt_header = optional_header_base as *const ImageOptionalHeader64;
        if directory_index >= (*opt_header).number_of_rva_and_sizes as usize {
            return ptr::null();
        }
        (*opt_header).data_directory[directory_index]
    } else if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC {
        let opt_header = optional_header_base as *const ImageOptionalHeader32;
        if directory_index >= (*opt_header).number_of_rva_and_sizes as usize {
            return ptr::null();
        }
        (*opt_header).data_directory[directory_index]
    } else {
        return ptr::null();
    };

    if data_dir.virtual_address == 0 || data_dir.size == 0 {
        return ptr::null();
    }

    if !size.is_null() {
        *size = data_dir.size;
    }

    base.add(data_dir.virtual_address as usize)
}

/// Convert an RVA to a virtual address
///
/// # Arguments
/// * `base` - Base address of the loaded PE image
/// * `rva` - Relative Virtual Address to convert
///
/// # Returns
/// Virtual address, or null if RVA is invalid
#[inline]
pub unsafe fn rtl_image_rva_to_va(base: *const u8, rva: u32) -> *const u8 {
    if base.is_null() || rva == 0 {
        return ptr::null();
    }
    base.add(rva as usize)
}

/// Find the section header containing a given RVA
///
/// # Arguments
/// * `nt_header` - Pointer to NT headers
/// * `rva` - Relative Virtual Address to find
///
/// # Returns
/// Pointer to the section header, or null if not found
pub unsafe fn rtl_image_rva_to_section(
    nt_header: *const u8,
    rva: u32,
) -> *const ImageSectionHeader {
    if nt_header.is_null() {
        return ptr::null();
    }

    let file_header = nt_header.add(4) as *const ImageFileHeader;
    let num_sections = (*file_header).number_of_sections as usize;
    let optional_header_size = (*file_header).size_of_optional_header as usize;

    // Section headers follow optional header
    let section_base = nt_header.add(4 + core::mem::size_of::<ImageFileHeader>() + optional_header_size);

    for i in 0..num_sections {
        let section = section_base.add(i * core::mem::size_of::<ImageSectionHeader>())
            as *const ImageSectionHeader;

        let section_start = (*section).virtual_address;
        let section_end = section_start + (*section).virtual_size.max((*section).size_of_raw_data);

        if rva >= section_start && rva < section_end {
            return section;
        }
    }

    ptr::null()
}

/// Get the entry point address from a PE image
///
/// # Arguments
/// * `base` - Base address of the loaded PE image
///
/// # Returns
/// Entry point virtual address, or 0 if invalid
pub unsafe fn rtl_image_entry_point(base: *const u8) -> u64 {
    let nt_header = rtl_image_nt_header(base);
    if nt_header.is_null() {
        return 0;
    }

    let optional_header_base = nt_header.add(4 + core::mem::size_of::<ImageFileHeader>());
    let magic = *(optional_header_base as *const u16);

    let entry_rva = if magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        let opt_header = optional_header_base as *const ImageOptionalHeader64;
        (*opt_header).address_of_entry_point
    } else if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC {
        let opt_header = optional_header_base as *const ImageOptionalHeader32;
        (*opt_header).address_of_entry_point
    } else {
        return 0;
    };

    if entry_rva == 0 {
        return 0;
    }

    base as u64 + entry_rva as u64
}

/// Get the size of a PE image
///
/// # Arguments
/// * `base` - Base address of the loaded PE image
///
/// # Returns
/// Size of the image in memory, or 0 if invalid
pub unsafe fn rtl_image_size(base: *const u8) -> u32 {
    let nt_header = rtl_image_nt_header(base);
    if nt_header.is_null() {
        return 0;
    }

    let optional_header_base = nt_header.add(4 + core::mem::size_of::<ImageFileHeader>());
    let magic = *(optional_header_base as *const u16);

    if magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        let opt_header = optional_header_base as *const ImageOptionalHeader64;
        (*opt_header).size_of_image
    } else if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC {
        let opt_header = optional_header_base as *const ImageOptionalHeader32;
        (*opt_header).size_of_image
    } else {
        0
    }
}

/// Check if a PE image is a DLL
///
/// # Arguments
/// * `base` - Base address of the loaded PE image
///
/// # Returns
/// true if the image is a DLL, false otherwise
pub unsafe fn rtl_image_is_dll(base: *const u8) -> bool {
    let nt_header = rtl_image_nt_header(base);
    if nt_header.is_null() {
        return false;
    }

    let file_header = nt_header.add(4) as *const ImageFileHeader;
    ((*file_header).characteristics & file_characteristics::IMAGE_FILE_DLL) != 0
}

/// Get the subsystem from a PE image
///
/// # Arguments
/// * `base` - Base address of the loaded PE image
///
/// # Returns
/// Subsystem value, or 0 if invalid
pub unsafe fn rtl_image_subsystem(base: *const u8) -> u16 {
    let nt_header = rtl_image_nt_header(base);
    if nt_header.is_null() {
        return 0;
    }

    let optional_header_base = nt_header.add(4 + core::mem::size_of::<ImageFileHeader>());
    let magic = *(optional_header_base as *const u16);

    if magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        let opt_header = optional_header_base as *const ImageOptionalHeader64;
        (*opt_header).subsystem
    } else if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC {
        let opt_header = optional_header_base as *const ImageOptionalHeader32;
        (*opt_header).subsystem
    } else {
        0
    }
}

// ============================================================================
// Export Directory Helpers
// ============================================================================

/// Get the export directory from a PE image
///
/// # Arguments
/// * `base` - Base address of the loaded PE image
/// * `size` - Output: size of the export directory
///
/// # Returns
/// Pointer to IMAGE_EXPORT_DIRECTORY, or null if not present
pub unsafe fn rtl_image_export_directory(
    base: *const u8,
    size: *mut u32,
) -> *const ImageExportDirectory {
    rtl_image_directory_entry_to_data(
        base,
        directory_entry::IMAGE_DIRECTORY_ENTRY_EXPORT,
        size,
    ) as *const ImageExportDirectory
}

/// Get the import directory from a PE image
///
/// # Arguments
/// * `base` - Base address of the loaded PE image
/// * `size` - Output: size of the import directory
///
/// # Returns
/// Pointer to first IMAGE_IMPORT_DESCRIPTOR, or null if not present
pub unsafe fn rtl_image_import_directory(
    base: *const u8,
    size: *mut u32,
) -> *const ImageImportDescriptor {
    rtl_image_directory_entry_to_data(
        base,
        directory_entry::IMAGE_DIRECTORY_ENTRY_IMPORT,
        size,
    ) as *const ImageImportDescriptor
}

/// Get the relocation directory from a PE image
///
/// # Arguments
/// * `base` - Base address of the loaded PE image
/// * `size` - Output: size of the relocation directory
///
/// # Returns
/// Pointer to first IMAGE_BASE_RELOCATION, or null if not present
pub unsafe fn rtl_image_relocation_directory(
    base: *const u8,
    size: *mut u32,
) -> *const ImageBaseRelocation {
    rtl_image_directory_entry_to_data(
        base,
        directory_entry::IMAGE_DIRECTORY_ENTRY_BASERELOC,
        size,
    ) as *const ImageBaseRelocation
}

// ============================================================================
// Convenience Macros (NT-style naming)
// ============================================================================

/// Alias for rtl_image_nt_header (NT naming convention)
#[inline]
pub unsafe fn RtlImageNtHeader(base: *const u8) -> *const u8 {
    rtl_image_nt_header(base)
}

/// Alias for rtl_image_directory_entry_to_data (NT naming convention)
#[inline]
pub unsafe fn RtlImageDirectoryEntryToData(
    base: *const u8,
    directory_index: usize,
    size: *mut u32,
) -> *const u8 {
    rtl_image_directory_entry_to_data(base, directory_index, size)
}

/// Alias for rtl_image_rva_to_va (NT naming convention)
#[inline]
pub unsafe fn RtlImageRvaToVa(base: *const u8, rva: u32) -> *const u8 {
    rtl_image_rva_to_va(base, rva)
}

/// Alias for rtl_image_rva_to_section (NT naming convention)
#[inline]
pub unsafe fn RtlImageRvaToSection(
    nt_header: *const u8,
    rva: u32,
) -> *const ImageSectionHeader {
    rtl_image_rva_to_section(nt_header, rva)
}
