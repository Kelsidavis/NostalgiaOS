//! PE (Portable Executable) Format Definitions
//!
//! Defines structures and constants for parsing Windows PE files.
//! PE is the executable format used for Windows executables, DLLs, and drivers.
//!
//! # PE File Structure
//! ```text
//! +------------------+
//! | DOS Header (MZ)  |  64 bytes
//! +------------------+
//! | DOS Stub         |  Variable
//! +------------------+
//! | PE Signature     |  4 bytes ("PE\0\0")
//! +------------------+
//! | COFF Header      |  20 bytes
//! +------------------+
//! | Optional Header  |  Variable (PE32: 96, PE32+: 112)
//! +------------------+
//! | Data Directories |  Variable (up to 16 entries)
//! +------------------+
//! | Section Headers  |  40 bytes each
//! +------------------+
//! | Sections         |  Variable
//! +------------------+
//! ```

/// DOS Header signature ("MZ")
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;

/// PE Signature ("PE\0\0")
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550;

/// PE32 Optional Header Magic
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10B;

/// PE32+ (64-bit) Optional Header Magic
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;

/// Number of data directories
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

/// Size of section name
pub const IMAGE_SIZEOF_SHORT_NAME: usize = 8;

// ============================================================================
// Machine Types
// ============================================================================

/// Machine type constants
pub mod machine_type {
    /// Unknown machine type
    pub const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0x0000;
    /// Intel 386 or later
    pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
    /// AMD64 (x64)
    pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
    /// ARM
    pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x01C0;
    /// ARM64
    pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;
    /// Intel Itanium
    pub const IMAGE_FILE_MACHINE_IA64: u16 = 0x0200;
}

// ============================================================================
// File Characteristics
// ============================================================================

/// File characteristics flags
pub mod file_characteristics {
    /// Relocation info stripped from file
    pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
    /// File is executable
    pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
    /// Line numbers stripped from file
    pub const IMAGE_FILE_LINE_NUMS_STRIPPED: u16 = 0x0004;
    /// Local symbols stripped from file
    pub const IMAGE_FILE_LOCAL_SYMS_STRIPPED: u16 = 0x0008;
    /// Aggressively trim working set
    pub const IMAGE_FILE_AGGRESIVE_WS_TRIM: u16 = 0x0010;
    /// App can handle >2gb addresses
    pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
    /// Bytes of machine word are reversed (little endian)
    pub const IMAGE_FILE_BYTES_REVERSED_LO: u16 = 0x0080;
    /// 32 bit word machine
    pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
    /// Debugging info stripped from file
    pub const IMAGE_FILE_DEBUG_STRIPPED: u16 = 0x0200;
    /// If image is on removable media, copy to swap
    pub const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
    /// If image is on net, copy to swap
    pub const IMAGE_FILE_NET_RUN_FROM_SWAP: u16 = 0x0800;
    /// System file
    pub const IMAGE_FILE_SYSTEM: u16 = 0x1000;
    /// File is a DLL
    pub const IMAGE_FILE_DLL: u16 = 0x2000;
    /// Only run on uniprocessor machine
    pub const IMAGE_FILE_UP_SYSTEM_ONLY: u16 = 0x4000;
    /// Bytes of machine word are reversed (big endian)
    pub const IMAGE_FILE_BYTES_REVERSED_HI: u16 = 0x8000;
}

// ============================================================================
// Subsystem Types
// ============================================================================

/// Subsystem constants
pub mod subsystem {
    /// Unknown subsystem
    pub const IMAGE_SUBSYSTEM_UNKNOWN: u16 = 0;
    /// Image doesn't require a subsystem
    pub const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
    /// Windows GUI subsystem
    pub const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
    /// Windows CUI (console) subsystem
    pub const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
    /// OS/2 CUI subsystem
    pub const IMAGE_SUBSYSTEM_OS2_CUI: u16 = 5;
    /// Posix CUI subsystem
    pub const IMAGE_SUBSYSTEM_POSIX_CUI: u16 = 7;
    /// Native Win9x driver
    pub const IMAGE_SUBSYSTEM_NATIVE_WINDOWS: u16 = 8;
    /// Windows CE subsystem
    pub const IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: u16 = 9;
    /// EFI Application
    pub const IMAGE_SUBSYSTEM_EFI_APPLICATION: u16 = 10;
    /// EFI Boot Service Driver
    pub const IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: u16 = 11;
    /// EFI Runtime Driver
    pub const IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: u16 = 12;
    /// EFI ROM
    pub const IMAGE_SUBSYSTEM_EFI_ROM: u16 = 13;
    /// Xbox
    pub const IMAGE_SUBSYSTEM_XBOX: u16 = 14;
    /// Windows boot application
    pub const IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: u16 = 16;
}

// ============================================================================
// DLL Characteristics
// ============================================================================

/// DLL characteristics flags
pub mod dll_characteristics {
    /// Image can handle a high entropy 64-bit virtual address space
    pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
    /// DLL can be relocated at load time
    pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
    /// Code Integrity checks are enforced
    pub const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
    /// Image is NX compatible
    pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
    /// Isolation aware, but do not isolate the image
    pub const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: u16 = 0x0200;
    /// Image does not use structured exception handling
    pub const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
    /// Do not bind this image
    pub const IMAGE_DLLCHARACTERISTICS_NO_BIND: u16 = 0x0800;
    /// Image must execute in an AppContainer
    pub const IMAGE_DLLCHARACTERISTICS_APPCONTAINER: u16 = 0x1000;
    /// A WDM driver
    pub const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: u16 = 0x2000;
    /// Image supports Control Flow Guard
    pub const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;
    /// Terminal Server aware
    pub const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;
}

// ============================================================================
// Data Directory Indices
// ============================================================================

/// Data directory entry indices
pub mod directory_entry {
    /// Export Directory
    pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
    /// Import Directory
    pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
    /// Resource Directory
    pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
    /// Exception Directory
    pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
    /// Security Directory
    pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
    /// Base Relocation Table
    pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
    /// Debug Directory
    pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
    /// Architecture Specific Data
    pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
    /// Global Pointer
    pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
    /// TLS Directory
    pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
    /// Load Configuration Directory
    pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
    /// Bound Import Directory
    pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
    /// Import Address Table
    pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
    /// Delay Load Import Descriptors
    pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
    /// CLR Runtime Header
    pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;
    /// Reserved
    pub const IMAGE_DIRECTORY_ENTRY_RESERVED: usize = 15;
}

// ============================================================================
// Section Characteristics
// ============================================================================

/// Section characteristics flags
pub mod section_characteristics {
    /// Section contains code
    pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
    /// Section contains initialized data
    pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
    /// Section contains uninitialized data
    pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
    /// Section cannot be cached
    pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x04000000;
    /// Section is not pageable
    pub const IMAGE_SCN_MEM_NOT_PAGED: u32 = 0x08000000;
    /// Section is shareable
    pub const IMAGE_SCN_MEM_SHARED: u32 = 0x10000000;
    /// Section is executable
    pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
    /// Section is readable
    pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
    /// Section is writable
    pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
    /// Section contains extended relocations
    pub const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x01000000;
    /// Section can be discarded
    pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x02000000;
}

// ============================================================================
// Relocation Types
// ============================================================================

/// Relocation types
pub mod relocation_type {
    /// Relocation is ignored
    pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
    /// Add the high 16 bits of the delta
    pub const IMAGE_REL_BASED_HIGH: u16 = 1;
    /// Add the low 16 bits of the delta
    pub const IMAGE_REL_BASED_LOW: u16 = 2;
    /// Add the high and low 16 bits of the delta
    pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
    /// Add the high 16 bits of the delta (adjusted)
    pub const IMAGE_REL_BASED_HIGHADJ: u16 = 4;
    /// MIPS jump address
    pub const IMAGE_REL_BASED_MIPS_JMPADDR: u16 = 5;
    /// ARM MOV32 (T)
    pub const IMAGE_REL_BASED_ARM_MOV32: u16 = 5;
    /// RISC-V High 20 bits
    pub const IMAGE_REL_BASED_RISCV_HIGH20: u16 = 5;
    /// Reserved
    pub const IMAGE_REL_BASED_RESERVED: u16 = 6;
    /// Thumb MOV32
    pub const IMAGE_REL_BASED_THUMB_MOV32: u16 = 7;
    /// RISC-V Low 12 bits
    pub const IMAGE_REL_BASED_RISCV_LOW12I: u16 = 7;
    /// RISC-V Low 12 bits (S-type)
    pub const IMAGE_REL_BASED_RISCV_LOW12S: u16 = 8;
    /// MIPS16 jump address
    pub const IMAGE_REL_BASED_MIPS_JMPADDR16: u16 = 9;
    /// 64-bit delta (PE32+)
    pub const IMAGE_REL_BASED_DIR64: u16 = 10;
}

// ============================================================================
// DOS Header
// ============================================================================

/// DOS Header (IMAGE_DOS_HEADER)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageDosHeader {
    /// Magic number (MZ = 0x5A4D)
    pub e_magic: u16,
    /// Bytes on last page of file
    pub e_cblp: u16,
    /// Pages in file
    pub e_cp: u16,
    /// Relocations
    pub e_crlc: u16,
    /// Size of header in paragraphs
    pub e_cparhdr: u16,
    /// Minimum extra paragraphs needed
    pub e_minalloc: u16,
    /// Maximum extra paragraphs needed
    pub e_maxalloc: u16,
    /// Initial (relative) SS value
    pub e_ss: u16,
    /// Initial SP value
    pub e_sp: u16,
    /// Checksum
    pub e_csum: u16,
    /// Initial IP value
    pub e_ip: u16,
    /// Initial (relative) CS value
    pub e_cs: u16,
    /// File address of relocation table
    pub e_lfarlc: u16,
    /// Overlay number
    pub e_ovno: u16,
    /// Reserved words
    pub e_res: [u16; 4],
    /// OEM identifier
    pub e_oemid: u16,
    /// OEM information
    pub e_oeminfo: u16,
    /// Reserved words
    pub e_res2: [u16; 10],
    /// File address of new exe header (PE header offset)
    pub e_lfanew: i32,
}

impl ImageDosHeader {
    /// Check if this is a valid DOS header
    pub fn is_valid(&self) -> bool {
        self.e_magic == IMAGE_DOS_SIGNATURE
    }

    /// Get the PE header offset
    pub fn pe_offset(&self) -> usize {
        self.e_lfanew as usize
    }
}

// ============================================================================
// COFF File Header
// ============================================================================

/// COFF File Header (IMAGE_FILE_HEADER)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageFileHeader {
    /// Machine type
    pub machine: u16,
    /// Number of sections
    pub number_of_sections: u16,
    /// Time date stamp
    pub time_date_stamp: u32,
    /// Pointer to symbol table
    pub pointer_to_symbol_table: u32,
    /// Number of symbols
    pub number_of_symbols: u32,
    /// Size of optional header
    pub size_of_optional_header: u16,
    /// File characteristics
    pub characteristics: u16,
}

impl ImageFileHeader {
    /// Check if this is a 64-bit binary
    pub fn is_64bit(&self) -> bool {
        self.machine == machine_type::IMAGE_FILE_MACHINE_AMD64
    }

    /// Check if this is executable
    pub fn is_executable(&self) -> bool {
        (self.characteristics & file_characteristics::IMAGE_FILE_EXECUTABLE_IMAGE) != 0
    }

    /// Check if this is a DLL
    pub fn is_dll(&self) -> bool {
        (self.characteristics & file_characteristics::IMAGE_FILE_DLL) != 0
    }

    /// Check if relocations are stripped
    pub fn relocs_stripped(&self) -> bool {
        (self.characteristics & file_characteristics::IMAGE_FILE_RELOCS_STRIPPED) != 0
    }
}

// ============================================================================
// Data Directory Entry
// ============================================================================

/// Data Directory Entry (IMAGE_DATA_DIRECTORY)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ImageDataDirectory {
    /// RVA of the data
    pub virtual_address: u32,
    /// Size of the data
    pub size: u32,
}

impl ImageDataDirectory {
    /// Check if this directory entry is present
    pub fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

// ============================================================================
// Optional Header (PE32 - 32-bit)
// ============================================================================

/// Optional Header PE32 (32-bit)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageOptionalHeader32 {
    /// Magic number (0x10B for PE32)
    pub magic: u16,
    /// Major linker version
    pub major_linker_version: u8,
    /// Minor linker version
    pub minor_linker_version: u8,
    /// Size of code
    pub size_of_code: u32,
    /// Size of initialized data
    pub size_of_initialized_data: u32,
    /// Size of uninitialized data
    pub size_of_uninitialized_data: u32,
    /// Address of entry point
    pub address_of_entry_point: u32,
    /// Base of code
    pub base_of_code: u32,
    /// Base of data (PE32 only)
    pub base_of_data: u32,
    /// Preferred image base
    pub image_base: u32,
    /// Section alignment
    pub section_alignment: u32,
    /// File alignment
    pub file_alignment: u32,
    /// Major OS version
    pub major_operating_system_version: u16,
    /// Minor OS version
    pub minor_operating_system_version: u16,
    /// Major image version
    pub major_image_version: u16,
    /// Minor image version
    pub minor_image_version: u16,
    /// Major subsystem version
    pub major_subsystem_version: u16,
    /// Minor subsystem version
    pub minor_subsystem_version: u16,
    /// Win32 version value (reserved)
    pub win32_version_value: u32,
    /// Size of image
    pub size_of_image: u32,
    /// Size of headers
    pub size_of_headers: u32,
    /// Checksum
    pub check_sum: u32,
    /// Subsystem
    pub subsystem: u16,
    /// DLL characteristics
    pub dll_characteristics: u16,
    /// Size of stack reserve
    pub size_of_stack_reserve: u32,
    /// Size of stack commit
    pub size_of_stack_commit: u32,
    /// Size of heap reserve
    pub size_of_heap_reserve: u32,
    /// Size of heap commit
    pub size_of_heap_commit: u32,
    /// Loader flags (reserved)
    pub loader_flags: u32,
    /// Number of RVA and sizes
    pub number_of_rva_and_sizes: u32,
    /// Data directories
    pub data_directory: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

// ============================================================================
// Optional Header (PE32+ - 64-bit)
// ============================================================================

/// Optional Header PE32+ (64-bit)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageOptionalHeader64 {
    /// Magic number (0x20B for PE32+)
    pub magic: u16,
    /// Major linker version
    pub major_linker_version: u8,
    /// Minor linker version
    pub minor_linker_version: u8,
    /// Size of code
    pub size_of_code: u32,
    /// Size of initialized data
    pub size_of_initialized_data: u32,
    /// Size of uninitialized data
    pub size_of_uninitialized_data: u32,
    /// Address of entry point
    pub address_of_entry_point: u32,
    /// Base of code
    pub base_of_code: u32,
    /// Preferred image base (64-bit)
    pub image_base: u64,
    /// Section alignment
    pub section_alignment: u32,
    /// File alignment
    pub file_alignment: u32,
    /// Major OS version
    pub major_operating_system_version: u16,
    /// Minor OS version
    pub minor_operating_system_version: u16,
    /// Major image version
    pub major_image_version: u16,
    /// Minor image version
    pub minor_image_version: u16,
    /// Major subsystem version
    pub major_subsystem_version: u16,
    /// Minor subsystem version
    pub minor_subsystem_version: u16,
    /// Win32 version value (reserved)
    pub win32_version_value: u32,
    /// Size of image
    pub size_of_image: u32,
    /// Size of headers
    pub size_of_headers: u32,
    /// Checksum
    pub check_sum: u32,
    /// Subsystem
    pub subsystem: u16,
    /// DLL characteristics
    pub dll_characteristics: u16,
    /// Size of stack reserve (64-bit)
    pub size_of_stack_reserve: u64,
    /// Size of stack commit (64-bit)
    pub size_of_stack_commit: u64,
    /// Size of heap reserve (64-bit)
    pub size_of_heap_reserve: u64,
    /// Size of heap commit (64-bit)
    pub size_of_heap_commit: u64,
    /// Loader flags (reserved)
    pub loader_flags: u32,
    /// Number of RVA and sizes
    pub number_of_rva_and_sizes: u32,
    /// Data directories
    pub data_directory: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

// ============================================================================
// NT Headers
// ============================================================================

/// NT Headers PE32 (32-bit)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageNtHeaders32 {
    /// PE Signature
    pub signature: u32,
    /// File header
    pub file_header: ImageFileHeader,
    /// Optional header
    pub optional_header: ImageOptionalHeader32,
}

impl ImageNtHeaders32 {
    /// Check if this is a valid PE header
    pub fn is_valid(&self) -> bool {
        self.signature == IMAGE_NT_SIGNATURE &&
        self.optional_header.magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC
    }
}

/// NT Headers PE32+ (64-bit)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageNtHeaders64 {
    /// PE Signature
    pub signature: u32,
    /// File header
    pub file_header: ImageFileHeader,
    /// Optional header
    pub optional_header: ImageOptionalHeader64,
}

impl ImageNtHeaders64 {
    /// Check if this is a valid PE header
    pub fn is_valid(&self) -> bool {
        self.signature == IMAGE_NT_SIGNATURE &&
        self.optional_header.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
    }
}

// ============================================================================
// Section Header
// ============================================================================

/// Section Header (IMAGE_SECTION_HEADER)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageSectionHeader {
    /// Section name (8 bytes, null-padded)
    pub name: [u8; IMAGE_SIZEOF_SHORT_NAME],
    /// Virtual size (actual size in memory)
    pub virtual_size: u32,
    /// Virtual address (RVA)
    pub virtual_address: u32,
    /// Size of raw data (file size)
    pub size_of_raw_data: u32,
    /// Pointer to raw data (file offset)
    pub pointer_to_raw_data: u32,
    /// Pointer to relocations
    pub pointer_to_relocations: u32,
    /// Pointer to line numbers
    pub pointer_to_linenumbers: u32,
    /// Number of relocations
    pub number_of_relocations: u16,
    /// Number of line numbers
    pub number_of_linenumbers: u16,
    /// Section characteristics
    pub characteristics: u32,
}

impl ImageSectionHeader {
    /// Get section name as string
    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&c| c == 0).unwrap_or(IMAGE_SIZEOF_SHORT_NAME);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    /// Check if section contains code
    pub fn is_code(&self) -> bool {
        (self.characteristics & section_characteristics::IMAGE_SCN_CNT_CODE) != 0
    }

    /// Check if section is executable
    pub fn is_executable(&self) -> bool {
        (self.characteristics & section_characteristics::IMAGE_SCN_MEM_EXECUTE) != 0
    }

    /// Check if section is writable
    pub fn is_writable(&self) -> bool {
        (self.characteristics & section_characteristics::IMAGE_SCN_MEM_WRITE) != 0
    }

    /// Check if section is readable
    pub fn is_readable(&self) -> bool {
        (self.characteristics & section_characteristics::IMAGE_SCN_MEM_READ) != 0
    }

    /// Check if section is discardable
    pub fn is_discardable(&self) -> bool {
        (self.characteristics & section_characteristics::IMAGE_SCN_MEM_DISCARDABLE) != 0
    }
}

// ============================================================================
// Import Directory
// ============================================================================

/// Import Descriptor (IMAGE_IMPORT_DESCRIPTOR)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageImportDescriptor {
    /// RVA to original first thunk (import lookup table)
    pub original_first_thunk: u32,
    /// Time/date stamp (0 if not bound)
    pub time_date_stamp: u32,
    /// Forwarder chain (-1 if no forwarders)
    pub forwarder_chain: u32,
    /// RVA to module name string
    pub name: u32,
    /// RVA to first thunk (import address table)
    pub first_thunk: u32,
}

impl ImageImportDescriptor {
    /// Check if this is the null terminator
    pub fn is_null(&self) -> bool {
        self.original_first_thunk == 0 && self.name == 0 && self.first_thunk == 0
    }
}

/// Thunk data (64-bit)
#[repr(C)]
#[derive(Clone, Copy)]
pub union ImageThunkData64 {
    /// Forwarder string RVA
    pub forwarder_string: u64,
    /// Function address
    pub function: u64,
    /// Ordinal
    pub ordinal: u64,
    /// Address of data
    pub address_of_data: u64,
}

/// Thunk data (32-bit)
#[repr(C)]
#[derive(Clone, Copy)]
pub union ImageThunkData32 {
    /// Forwarder string RVA
    pub forwarder_string: u32,
    /// Function address
    pub function: u32,
    /// Ordinal
    pub ordinal: u32,
    /// Address of data
    pub address_of_data: u32,
}

/// Import by name
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageImportByName {
    /// Hint (index into export name table)
    pub hint: u16,
    /// Name (variable length, null-terminated)
    pub name: [u8; 1],
}

/// Ordinal flag for 64-bit
pub const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000;

/// Ordinal flag for 32-bit
pub const IMAGE_ORDINAL_FLAG32: u32 = 0x80000000;

// ============================================================================
// Export Directory
// ============================================================================

/// Export Directory (IMAGE_EXPORT_DIRECTORY)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageExportDirectory {
    /// Export flags (reserved)
    pub characteristics: u32,
    /// Time/date stamp
    pub time_date_stamp: u32,
    /// Major version
    pub major_version: u16,
    /// Minor version
    pub minor_version: u16,
    /// RVA to DLL name
    pub name: u32,
    /// Ordinal base
    pub base: u32,
    /// Number of functions
    pub number_of_functions: u32,
    /// Number of names
    pub number_of_names: u32,
    /// RVA to address table
    pub address_of_functions: u32,
    /// RVA to name pointer table
    pub address_of_names: u32,
    /// RVA to ordinal table
    pub address_of_name_ordinals: u32,
}

// ============================================================================
// Base Relocation
// ============================================================================

/// Base Relocation Block (IMAGE_BASE_RELOCATION)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageBaseRelocation {
    /// RVA of the page to apply relocations to
    pub virtual_address: u32,
    /// Total size of this relocation block
    pub size_of_block: u32,
    // Followed by variable number of u16 entries
}

impl ImageBaseRelocation {
    /// Get the number of relocation entries in this block
    pub fn entry_count(&self) -> usize {
        if self.size_of_block < 8 {
            0
        } else {
            ((self.size_of_block - 8) / 2) as usize
        }
    }
}

/// Get relocation type from entry
pub fn reloc_type(entry: u16) -> u16 {
    entry >> 12
}

/// Get relocation offset from entry
pub fn reloc_offset(entry: u16) -> u16 {
    entry & 0x0FFF
}

// ============================================================================
// TLS Directory
// ============================================================================

/// TLS Directory (64-bit)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageTlsDirectory64 {
    /// Start address of TLS data
    pub start_address_of_raw_data: u64,
    /// End address of TLS data
    pub end_address_of_raw_data: u64,
    /// Address of TLS index
    pub address_of_index: u64,
    /// Address of TLS callbacks
    pub address_of_callbacks: u64,
    /// Size of zero fill
    pub size_of_zero_fill: u32,
    /// TLS characteristics
    pub characteristics: u32,
}

/// TLS Directory (32-bit)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageTlsDirectory32 {
    /// Start address of TLS data
    pub start_address_of_raw_data: u32,
    /// End address of TLS data
    pub end_address_of_raw_data: u32,
    /// Address of TLS index
    pub address_of_index: u32,
    /// Address of TLS callbacks
    pub address_of_callbacks: u32,
    /// Size of zero fill
    pub size_of_zero_fill: u32,
    /// TLS characteristics
    pub characteristics: u32,
}

// ============================================================================
// Debug Directory
// ============================================================================

/// Debug Directory Entry (IMAGE_DEBUG_DIRECTORY)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageDebugDirectory {
    /// Characteristics (reserved)
    pub characteristics: u32,
    /// Time/date stamp
    pub time_date_stamp: u32,
    /// Major version
    pub major_version: u16,
    /// Minor version
    pub minor_version: u16,
    /// Debug type
    pub debug_type: u32,
    /// Size of debug data
    pub size_of_data: u32,
    /// RVA of debug data
    pub address_of_raw_data: u32,
    /// File offset of debug data
    pub pointer_to_raw_data: u32,
}

/// Debug types
pub mod debug_type {
    /// Unknown debug info
    pub const IMAGE_DEBUG_TYPE_UNKNOWN: u32 = 0;
    /// COFF debug info
    pub const IMAGE_DEBUG_TYPE_COFF: u32 = 1;
    /// CodeView debug info
    pub const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
    /// Frame Pointer Omission
    pub const IMAGE_DEBUG_TYPE_FPO: u32 = 3;
    /// Debug misc info
    pub const IMAGE_DEBUG_TYPE_MISC: u32 = 4;
    /// Exception info
    pub const IMAGE_DEBUG_TYPE_EXCEPTION: u32 = 5;
    /// Fixup info
    pub const IMAGE_DEBUG_TYPE_FIXUP: u32 = 6;
    /// OMAP to src
    pub const IMAGE_DEBUG_TYPE_OMAP_TO_SRC: u32 = 7;
    /// OMAP from src
    pub const IMAGE_DEBUG_TYPE_OMAP_FROM_SRC: u32 = 8;
    /// Borland debug info
    pub const IMAGE_DEBUG_TYPE_BORLAND: u32 = 9;
    /// Reserved
    pub const IMAGE_DEBUG_TYPE_RESERVED10: u32 = 10;
    /// CLSID
    pub const IMAGE_DEBUG_TYPE_CLSID: u32 = 11;
    /// Reproducible build
    pub const IMAGE_DEBUG_TYPE_REPRO: u32 = 16;
    /// Extended DLL characteristics
    pub const IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS: u32 = 20;
}

// ============================================================================
// Load Config Directory
// ============================================================================

/// Load Configuration Directory (64-bit, minimal)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageLoadConfigDirectory64 {
    /// Size of this structure
    pub size: u32,
    /// Time/date stamp
    pub time_date_stamp: u32,
    /// Major version
    pub major_version: u16,
    /// Minor version
    pub minor_version: u16,
    /// Global flags to clear
    pub global_flags_clear: u32,
    /// Global flags to set
    pub global_flags_set: u32,
    /// Critical section default timeout
    pub critical_section_default_timeout: u32,
    /// De-commit free block threshold
    pub de_commit_free_block_threshold: u64,
    /// De-commit total free threshold
    pub de_commit_total_free_threshold: u64,
    /// Lock prefix table VA
    pub lock_prefix_table: u64,
    /// Maximum allocation size
    pub maximum_allocation_size: u64,
    /// Virtual memory threshold
    pub virtual_memory_threshold: u64,
    /// Process affinity mask
    pub process_affinity_mask: u64,
    /// Process heap flags
    pub process_heap_flags: u32,
    /// CSD version
    pub csd_version: u16,
    /// Dependent load flags
    pub dependent_load_flags: u16,
    /// Edit list VA
    pub edit_list: u64,
    /// Security cookie VA
    pub security_cookie: u64,
    /// SE handler table VA
    pub se_handler_table: u64,
    /// SE handler count
    pub se_handler_count: u64,
    // Additional fields for CFG, etc. omitted for brevity
}
