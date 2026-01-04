//! Win32 Subsystem DLL Stubs
//!
//! This module provides in-kernel implementations of Win32 DLLs that can be
//! loaded into user-mode processes. These stub DLLs forward calls to kernel
//! syscalls, implementing the Windows API.
//!
//! # Architecture
//!
//! ```text
//! User Mode                     Kernel Mode
//! ┌─────────────┐              ┌───────────────┐
//! │ Application │              │               │
//! │             │              │  Win32k.sys   │
//! │   ↓ call    │              │  (GDI/USER)   │
//! │             │              │               │
//! │ kernel32    │───syscall───>│  Syscall      │
//! │   ↓         │              │  Handlers     │
//! │ ntdll       │              │               │
//! └─────────────┘              └───────────────┘
//! ```
//!
//! # DLLs Implemented
//!
//! - **ntdll.dll**: NT layer - syscall wrappers
//! - **kernel32.dll**: Win32 base - file, memory, process, thread APIs
//! - **user32.dll**: User interface - window, message, input APIs
//! - **gdi32.dll**: Graphics - drawing, fonts, bitmaps
//! - **advapi32.dll**: Security, registry, services

pub mod ntdll;
pub mod kernel32;
pub mod user32;
pub mod gdi32;
pub mod advapi32;
pub mod inject;

use crate::ps::EProcess;

/// Initialize the subsystem DLL stubs
pub fn init() {
    crate::serial_println!("[SUBSYS] Initializing Win32 subsystem stubs...");

    // Initialize each DLL module
    ntdll::init();
    kernel32::init();
    user32::init();
    gdi32::init();
    advapi32::init();

    crate::serial_println!("[SUBSYS] Win32 subsystem initialized");
}

/// Inject required DLLs into a new process
///
/// This is called during process creation to set up the Win32 environment.
/// It injects ntdll.dll (always first), then kernel32.dll, user32.dll, etc.
pub unsafe fn inject_dlls(process: *mut EProcess) -> bool {
    inject::inject_required_dlls(process)
}

/// Get the address of a Win32 API function
///
/// Used for import resolution during executable loading.
pub fn resolve_win32_import(dll_name: &str, func_name: &str) -> Option<u64> {
    let dll_lower = dll_name.to_ascii_lowercase();

    if dll_lower.contains("ntdll") {
        ntdll::get_export(func_name)
    } else if dll_lower.contains("kernel32") {
        kernel32::get_export(func_name)
    } else if dll_lower.contains("user32") {
        user32::get_export(func_name)
    } else if dll_lower.contains("gdi32") {
        gdi32::get_export(func_name)
    } else if dll_lower.contains("advapi32") {
        advapi32::get_export(func_name)
    } else {
        None
    }
}
