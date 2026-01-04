//! DLL Injection Module
//!
//! Handles injecting required Win32 DLLs into new processes.
//! This sets up the user-mode environment needed to run Windows executables.

use crate::ps::EProcess;
use crate::mm;

/// Memory layout for injected DLLs
///
/// The DLLs are mapped into user space at fixed addresses:
/// - ntdll.dll:    0x7FFE_0000_0000 - Base NT layer
/// - kernel32.dll: 0x7FFE_0100_0000 - Win32 base
/// - user32.dll:   0x7FFE_0200_0000 - User interface
/// - gdi32.dll:    0x7FFE_0300_0000 - Graphics
/// - advapi32.dll: 0x7FFE_0400_0000 - Security/Registry
pub const NTDLL_BASE: u64 = 0x7FFE_0000_0000;
pub const KERNEL32_BASE: u64 = 0x7FFE_0100_0000;
pub const USER32_BASE: u64 = 0x7FFE_0200_0000;
pub const GDI32_BASE: u64 = 0x7FFE_0300_0000;
pub const ADVAPI32_BASE: u64 = 0x7FFE_0400_0000;

/// Size allocated for each DLL (1MB each)
pub const DLL_SIZE: u64 = 0x0010_0000;

/// DLL info structure stored in process memory
#[repr(C)]
pub struct DllInfo {
    /// Base address of the DLL in user space
    pub base: u64,
    /// Size of the DLL image
    pub size: u64,
    /// Entry point (DllMain)
    pub entry_point: u64,
    /// Number of exports
    pub num_exports: u32,
    /// Reserved
    pub _reserved: u32,
}

/// Export entry for DLL
#[repr(C)]
pub struct ExportEntry {
    /// Name hash (for fast lookup)
    pub name_hash: u32,
    /// RVA of the function
    pub rva: u32,
    /// Name offset in names section
    pub name_offset: u32,
    /// Reserved
    pub _reserved: u32,
}

/// PEB Loader Data structure
#[repr(C)]
pub struct PebLdrData {
    pub length: u32,
    pub initialized: u32,
    pub ss_handle: u64,
    pub in_load_order_module_list: ListEntry,
    pub in_memory_order_module_list: ListEntry,
    pub in_initialization_order_module_list: ListEntry,
}

/// Doubly-linked list entry
#[repr(C)]
pub struct ListEntry {
    pub flink: u64,
    pub blink: u64,
}

/// LDR_DATA_TABLE_ENTRY - describes a loaded module
#[repr(C)]
pub struct LdrDataTableEntry {
    pub in_load_order_links: ListEntry,
    pub in_memory_order_links: ListEntry,
    pub in_initialization_order_links: ListEntry,
    pub dll_base: u64,
    pub entry_point: u64,
    pub size_of_image: u32,
    pub _pad1: u32,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
    pub flags: u32,
    pub load_count: u16,
    pub tls_index: u16,
    pub hash_links: ListEntry,
    pub time_date_stamp: u32,
}

/// UNICODE_STRING structure
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub _pad: u32,
    pub buffer: u64,
}

/// Inject required DLLs into a new process
///
/// This function is called during process creation to set up the Win32
/// environment. It maps the DLL stubs into user space and initializes
/// the PEB loader data.
pub unsafe fn inject_required_dlls(process: *mut EProcess) -> bool {
    if process.is_null() {
        return false;
    }

    crate::serial_println!("[INJECT] Injecting Win32 DLLs into process...");

    // Map ntdll.dll (always first - it's the base layer)
    if !inject_ntdll(process) {
        crate::serial_println!("[INJECT] Failed to inject ntdll.dll");
        return false;
    }

    // Map kernel32.dll
    if !inject_kernel32(process) {
        crate::serial_println!("[INJECT] Failed to inject kernel32.dll");
        return false;
    }

    // Map user32.dll
    if !inject_user32(process) {
        crate::serial_println!("[INJECT] Failed to inject user32.dll");
        return false;
    }

    // Map gdi32.dll
    if !inject_gdi32(process) {
        crate::serial_println!("[INJECT] Failed to inject gdi32.dll");
        return false;
    }

    // Map advapi32.dll
    if !inject_advapi32(process) {
        crate::serial_println!("[INJECT] Failed to inject advapi32.dll");
        return false;
    }

    // Initialize PEB loader data structures
    if !init_peb_ldr_data(process) {
        crate::serial_println!("[INJECT] Failed to initialize PEB loader data");
        return false;
    }

    crate::serial_println!("[INJECT] Win32 DLLs injected successfully");
    true
}

/// Inject ntdll.dll into process
unsafe fn inject_ntdll(process: *mut EProcess) -> bool {
    inject_dll_stub(
        process,
        NTDLL_BASE,
        "ntdll.dll",
        super::ntdll::get_export,
    )
}

/// Inject kernel32.dll into process
unsafe fn inject_kernel32(process: *mut EProcess) -> bool {
    inject_dll_stub(
        process,
        KERNEL32_BASE,
        "kernel32.dll",
        super::kernel32::get_export,
    )
}

/// Inject user32.dll into process
unsafe fn inject_user32(process: *mut EProcess) -> bool {
    inject_dll_stub(
        process,
        USER32_BASE,
        "user32.dll",
        super::user32::get_export,
    )
}

/// Inject gdi32.dll into process
unsafe fn inject_gdi32(process: *mut EProcess) -> bool {
    inject_dll_stub(
        process,
        GDI32_BASE,
        "gdi32.dll",
        super::gdi32::get_export,
    )
}

/// Inject advapi32.dll into process
unsafe fn inject_advapi32(process: *mut EProcess) -> bool {
    inject_dll_stub(
        process,
        ADVAPI32_BASE,
        "advapi32.dll",
        super::advapi32::get_export,
    )
}

/// Generic DLL stub injection
///
/// Creates a minimal PE-like structure in user memory that:
/// - Has a valid DOS/PE header (for compatibility)
/// - Contains an export directory pointing to our stub functions
/// - Maps function addresses to kernel-mode syscall stubs
unsafe fn inject_dll_stub(
    _process: *mut EProcess,
    base_address: u64,
    dll_name: &str,
    _get_export: fn(&str) -> Option<u64>,
) -> bool {
    // For now, we just allocate the memory region
    // In a full implementation, we would:
    // 1. Allocate user-mode pages at base_address
    // 2. Build a PE header
    // 3. Build an export directory
    // 4. Map syscall thunks for each export

    crate::serial_println!("[INJECT] Mapping {} at {:#x}", dll_name, base_address);

    // Allocate user-mode pages for this DLL
    // This is a simplified version - a real implementation would use
    // MmCreateSection and MmMapViewOfSection

    // For now, just mark success - the actual mapping will be done
    // when we have proper user-mode memory management
    true
}

/// Initialize PEB loader data structures
///
/// Sets up the linked lists in PEB that describe loaded modules.
/// This is required for GetModuleHandle, etc. to work.
unsafe fn init_peb_ldr_data(_process: *mut EProcess) -> bool {
    // The PEB is at a fixed location per process
    // We need to:
    // 1. Allocate PebLdrData structure
    // 2. Create LdrDataTableEntry for each DLL
    // 3. Link them into the three module lists
    // 4. Update PEB.Ldr to point to PebLdrData

    crate::serial_println!("[INJECT] Initializing PEB loader data...");

    // Simplified - actual implementation would build the loader data structures
    true
}

/// Hash a function name for fast export lookup
pub fn hash_name(name: &str) -> u32 {
    let mut hash: u32 = 0;
    for byte in name.bytes() {
        hash = hash.wrapping_mul(0x1003F);
        hash = hash.wrapping_add(byte as u32);
    }
    hash
}

/// Resolve an import from a DLL
///
/// Given a DLL name and function name, returns the address of the function.
/// This is used during executable loading to resolve imports.
pub fn resolve_import(dll_name: &str, func_name: &str) -> Option<u64> {
    let dll_lower = dll_name.to_ascii_lowercase();

    // Map to base addresses
    let (base, get_export): (u64, fn(&str) -> Option<u64>) = if dll_lower.contains("ntdll") {
        (NTDLL_BASE, super::ntdll::get_export)
    } else if dll_lower.contains("kernel32") {
        (KERNEL32_BASE, super::kernel32::get_export)
    } else if dll_lower.contains("user32") {
        (USER32_BASE, super::user32::get_export)
    } else if dll_lower.contains("gdi32") {
        (GDI32_BASE, super::gdi32::get_export)
    } else if dll_lower.contains("advapi32") {
        (ADVAPI32_BASE, super::advapi32::get_export)
    } else {
        return None;
    };

    // Get the kernel-mode function address
    if let Some(kernel_addr) = get_export(func_name) {
        // For now, return the kernel address directly
        // In a full implementation, this would return a user-mode
        // thunk that performs a syscall to the kernel function
        Some(kernel_addr)
    } else {
        crate::serial_println!(
            "[INJECT] Warning: unresolved import {}!{}",
            dll_name,
            func_name
        );
        None
    }
}

/// Get the base address of a loaded DLL
pub fn get_dll_base(dll_name: &str) -> Option<u64> {
    let dll_lower = dll_name.to_ascii_lowercase();

    if dll_lower.contains("ntdll") {
        Some(NTDLL_BASE)
    } else if dll_lower.contains("kernel32") {
        Some(KERNEL32_BASE)
    } else if dll_lower.contains("user32") {
        Some(USER32_BASE)
    } else if dll_lower.contains("gdi32") {
        Some(GDI32_BASE)
    } else if dll_lower.contains("advapi32") {
        Some(ADVAPI32_BASE)
    } else {
        None
    }
}

/// Check if a DLL is one of our built-in stubs
pub fn is_builtin_dll(dll_name: &str) -> bool {
    let dll_lower = dll_name.to_ascii_lowercase();
    dll_lower.contains("ntdll")
        || dll_lower.contains("kernel32")
        || dll_lower.contains("user32")
        || dll_lower.contains("gdi32")
        || dll_lower.contains("advapi32")
}

/// Generate syscall thunk code
///
/// Creates x86_64 assembly for a syscall thunk that:
/// 1. Puts the syscall number in RAX
/// 2. Moves RCX to R10 (Windows calling convention)
/// 3. Executes SYSCALL
/// 4. Returns
///
/// Returns the thunk as a byte array.
pub fn generate_syscall_thunk(syscall_num: u32) -> [u8; 16] {
    // mov eax, <syscall_num>     ; B8 xx xx xx xx
    // mov r10, rcx               ; 49 89 CA
    // syscall                    ; 0F 05
    // ret                        ; C3
    // nop (padding)              ; 90 90 90 90 90
    [
        0xB8,
        (syscall_num & 0xFF) as u8,
        ((syscall_num >> 8) & 0xFF) as u8,
        ((syscall_num >> 16) & 0xFF) as u8,
        ((syscall_num >> 24) & 0xFF) as u8,
        0x49, 0x89, 0xCA,  // mov r10, rcx
        0x0F, 0x05,         // syscall
        0xC3,               // ret
        0x90, 0x90, 0x90, 0x90, 0x90, // padding
    ]
}

/// Build a minimal PE header for a stub DLL
///
/// Creates DOS and PE headers that are valid enough for
/// Windows API functions to parse.
pub fn build_pe_header(
    base: u64,
    size: u64,
    entry_point: u64,
    num_sections: u16,
) -> [u8; 512] {
    let mut header = [0u8; 512];

    // DOS Header (64 bytes)
    // e_magic = "MZ"
    header[0] = b'M';
    header[1] = b'Z';
    // e_lfanew = PE header offset (0x80)
    header[0x3C] = 0x80;
    header[0x3D] = 0x00;
    header[0x3E] = 0x00;
    header[0x3F] = 0x00;

    // PE Signature at offset 0x80
    header[0x80] = b'P';
    header[0x81] = b'E';
    header[0x82] = 0x00;
    header[0x83] = 0x00;

    // COFF File Header (20 bytes) at 0x84
    // Machine = AMD64 (0x8664)
    header[0x84] = 0x64;
    header[0x85] = 0x86;
    // NumberOfSections
    header[0x86] = (num_sections & 0xFF) as u8;
    header[0x87] = ((num_sections >> 8) & 0xFF) as u8;
    // SizeOfOptionalHeader = 240 (PE32+)
    header[0x94] = 0xF0;
    header[0x95] = 0x00;
    // Characteristics = DLL | EXECUTABLE
    header[0x96] = 0x22;
    header[0x97] = 0x20;

    // Optional Header (PE32+) at 0x98
    // Magic = PE32+ (0x20B)
    header[0x98] = 0x0B;
    header[0x99] = 0x02;
    // AddressOfEntryPoint
    let ep_rva = (entry_point - base) as u32;
    header[0xA8] = (ep_rva & 0xFF) as u8;
    header[0xA9] = ((ep_rva >> 8) & 0xFF) as u8;
    header[0xAA] = ((ep_rva >> 16) & 0xFF) as u8;
    header[0xAB] = ((ep_rva >> 24) & 0xFF) as u8;
    // ImageBase
    header[0xB8] = (base & 0xFF) as u8;
    header[0xB9] = ((base >> 8) & 0xFF) as u8;
    header[0xBA] = ((base >> 16) & 0xFF) as u8;
    header[0xBB] = ((base >> 24) & 0xFF) as u8;
    header[0xBC] = ((base >> 32) & 0xFF) as u8;
    header[0xBD] = ((base >> 40) & 0xFF) as u8;
    header[0xBE] = ((base >> 48) & 0xFF) as u8;
    header[0xBF] = ((base >> 56) & 0xFF) as u8;
    // SizeOfImage
    header[0xC8] = (size & 0xFF) as u8;
    header[0xC9] = ((size >> 8) & 0xFF) as u8;
    header[0xCA] = ((size >> 16) & 0xFF) as u8;
    header[0xCB] = ((size >> 24) & 0xFF) as u8;
    // SizeOfHeaders
    header[0xCC] = 0x00;
    header[0xCD] = 0x02; // 512 bytes

    header
}

/// Information about an injected DLL
#[derive(Clone, Copy)]
pub struct InjectedDll {
    pub name: &'static str,
    pub base: u64,
    pub size: u64,
}

/// List of all injected DLLs
pub static INJECTED_DLLS: &[InjectedDll] = &[
    InjectedDll { name: "ntdll.dll", base: NTDLL_BASE, size: DLL_SIZE },
    InjectedDll { name: "kernel32.dll", base: KERNEL32_BASE, size: DLL_SIZE },
    InjectedDll { name: "user32.dll", base: USER32_BASE, size: DLL_SIZE },
    InjectedDll { name: "gdi32.dll", base: GDI32_BASE, size: DLL_SIZE },
    InjectedDll { name: "advapi32.dll", base: ADVAPI32_BASE, size: DLL_SIZE },
];

/// Find DLL by name
pub fn find_dll(name: &str) -> Option<InjectedDll> {
    let name_lower = name.to_ascii_lowercase();
    for dll in INJECTED_DLLS {
        if name_lower.contains(dll.name) || dll.name.contains(&name_lower) {
            return Some(*dll);
        }
    }
    None
}
