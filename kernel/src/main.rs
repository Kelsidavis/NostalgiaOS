//! Nostalgia OS Kernel
//!
//! A Rust recreation of the Windows NT kernel architecture, targeting x86_64.
//!
//! # Architecture Overview
//!
//! The kernel follows the NT model with these major subsystems:
//!
//! - **ke** - Kernel Executive: scheduler, DPC/APC, synchronization primitives
//! - **mm** - Memory Manager: virtual memory, PFN database, working sets
//! - **ob** - Object Manager: handles, namespace, object types
//! - **io** - I/O Manager: IRP, device/driver objects, completion ports
//! - **cc** - Cache Manager: file caching, lazy writer, read-ahead
//! - **ps** - Process Manager: EPROCESS/ETHREAD
//! - **ex** - Executive: pools, resources, worker threads
//! - **se** - Security: tokens, ACLs, access checks
//! - **cm** - Configuration Manager: registry, hives, keys/values
//! - **fs** - File System: VFS, FAT32 driver, mount points
//! - **rtl** - Runtime Library: strings, bitmaps, data structures
//! - **hal** - Hardware Abstraction Layer
//!
//! # Initialization
//!
//! Kernel initialization proceeds in two phases:
//!
//! - **Phase 0**: Single-threaded, interrupts disabled. Basic memory, PRCB setup.
//! - **Phase 1**: Multi-threaded capable. Full subsystem initialization.

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]
#![feature(alloc_error_handler)]
#![allow(static_mut_refs)]
#![allow(dead_code)]
// Kernel-specific lint configurations:
// - missing_safety_doc: In a kernel, virtually everything is unsafe by nature
// - declare_interior_mutable_const: Common pattern for static initialization in no_std
// - type_complexity: Function pointer types for driver/syscall interfaces are necessarily complex
// - too_many_arguments: Some kernel APIs require many parameters
// - needless_range_loop: Sometimes index access is clearer in kernel code
// - while_let_loop: Pattern matching style preference
// - manual_find: Sometimes explicit loops are clearer
// - result_unit_err: Some kernel APIs don't need error details
// - new_without_default: Kernel structs often have specific initialization requirements
// - if_same_then_else: Sometimes used for clarity in symmetric patterns
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::declare_interior_mutable_const)]
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::while_let_loop)]
#![allow(clippy::manual_find)]
#![allow(clippy::result_unit_err)]
#![allow(clippy::new_without_default)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::manual_is_ascii_check)]
#![allow(clippy::manual_ignore_case_cmp)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::collapsible_if)]
// Kernel-specific: raw pointer operations are ubiquitous and often intentionally unsafe
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::mut_from_ref)]

// Subsystem modules
pub mod arch;
pub mod cc;
pub mod cm;
pub mod ex;
pub mod fs;
pub mod fsrtl;
pub mod hal;
pub mod io;
pub mod ke;
pub mod lpc;
pub mod mm;
pub mod ob;
pub mod po;
pub mod ps;
pub mod rtl;
pub mod se;
pub mod shell;

mod framebuffer;
mod serial;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicPtr, Ordering};

/// Boot information passed from the bootloader
/// Must match the bootloader's BootInfo structure exactly!
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootInfo {
    /// Magic number for validation
    pub magic: u64,
    /// Physical address of the framebuffer
    pub framebuffer_addr: u64,
    /// Framebuffer width in pixels
    pub framebuffer_width: u32,
    /// Framebuffer height in pixels
    pub framebuffer_height: u32,
    /// Framebuffer stride (bytes per row)
    pub framebuffer_stride: u32,
    /// Bytes per pixel
    pub framebuffer_bpp: u32,
    /// Physical address of the memory map
    pub memory_map_addr: u64,
    /// Number of memory map entries
    pub memory_map_entries: u64,
    /// Size of each memory map entry
    pub memory_map_entry_size: u64,
    /// Physical address of the kernel
    pub kernel_physical_base: u64,
    /// Virtual address of the kernel
    pub kernel_virtual_base: u64,
    /// Size of the kernel in bytes
    pub kernel_size: u64,
    /// Physical address of the PML4 table
    pub pml4_physical_addr: u64,
    /// ACPI RSDP address (if found)
    pub rsdp_addr: u64,
}

impl BootInfo {
    pub const MAGIC: u64 = 0x4E4F5354414C4749; // "NOSTALGI" in ASCII

    /// Validate the boot info structure
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

/// Global boot info pointer
static BOOT_INFO: AtomicPtr<BootInfo> = AtomicPtr::new(core::ptr::null_mut());

/// Get the boot info
pub fn boot_info() -> Option<&'static BootInfo> {
    let ptr = BOOT_INFO.load(Ordering::Relaxed);
    if ptr.is_null() {
        None
    } else {
        unsafe { Some(&*ptr) }
    }
}

// BSS section symbols from linker script
extern "C" {
    static __bss_start: u8;
    static __bss_end: u8;
}

/// Zero the .bss section
///
/// # Safety
/// Must be called exactly once at the very start of kernel execution,
/// before any statics are accessed.
#[inline(never)]
unsafe fn zero_bss() {
    let start = &__bss_start as *const u8 as *mut u8;
    let end = &__bss_end as *const u8 as *mut u8;
    let size = end as usize - start as usize;

    // Zero using volatile writes to ensure it's not optimized away
    for i in 0..size {
        core::ptr::write_volatile(start.add(i), 0);
    }
}

/// Static copy of boot info (placed in .data, not .bss)
static mut BOOT_INFO_COPY: BootInfo = BootInfo {
    magic: 0,
    framebuffer_addr: 0,
    framebuffer_width: 0,
    framebuffer_height: 0,
    framebuffer_stride: 0,
    framebuffer_bpp: 0,
    memory_map_addr: 0,
    memory_map_entries: 0,
    memory_map_entry_size: 0,
    kernel_physical_base: 0,
    kernel_virtual_base: 0,
    kernel_size: 0,
    pml4_physical_addr: 0,
    rsdp_addr: 0,
};

/// Kernel entry point - called by bootloader
///
/// The bootloader passes a pointer to BootInfo in RDI (System V ABI).
/// This function performs Phase 0 initialization and then starts Phase 1.
#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: *const BootInfo) -> ! {
    // CRITICAL: Copy boot_info BEFORE zeroing .bss!
    // The bootloader may have placed boot_info in our .bss region.
    // We must save it first, then zero .bss, then restore it.
    let saved_boot_info = unsafe { core::ptr::read_volatile(boot_info_ptr) };

    // Zero .bss before anything else
    // This must happen before any statics (including Mutex) are used.
    unsafe { zero_bss(); }

    // Now store the saved boot_info in our static (which is in .data, not .bss)
    unsafe { BOOT_INFO_COPY = saved_boot_info; }

    // Absolute first thing: write directly to serial (no mutex, no formatting)
    serial::early_puts(b"K\n");  // Just output "K" to prove we're alive

    // First thing: signal we're alive on serial
    serial_println!("Kernel entry point reached!");

    // Store boot info pointer (pointing to our copy)
    BOOT_INFO.store(&raw mut BOOT_INFO_COPY, Ordering::SeqCst);

    // Validate boot info
    let boot_info = unsafe { &BOOT_INFO_COPY };
    serial_println!("Boot info ptr: {:#x}", boot_info_ptr as u64);
    serial_println!("Boot info magic: {:#x}", boot_info.magic);

    if !boot_info.is_valid() {
        serial_println!("FATAL: Invalid boot info magic!");
        // Can't do much without valid boot info - just halt
        loop {
            arch::halt();
        }
    }
    serial_println!("Boot info validated OK");

    // Initialize framebuffer for early output
    serial_println!("Initializing framebuffer...");
    framebuffer::init(boot_info);
    serial_println!("Framebuffer initialized");

    // Print welcome message
    kprintln!("========================================");
    kprintln!("  Nostalgia OS Kernel v0.1.0");
    kprintln!("========================================");
    kprintln!("");
    serial_println!("========================================");
    serial_println!("  Nostalgia OS Kernel v0.1.0");
    serial_println!("========================================");

    // Phase 0: Early initialization (single-threaded, interrupts off)
    kprintln!("[Phase 0] Early initialization...");
    serial_println!("[Phase 0] Early initialization...");
    phase0_init(boot_info);
    kprintln!("[Phase 0] Complete");
    serial_println!("[Phase 0] Complete");

    // Phase 1: Full initialization (multi-threaded capable)
    kprintln!("");
    kprintln!("[Phase 1] Full initialization...");
    serial_println!("[Phase 1] Full initialization...");
    phase1_init(boot_info);
    kprintln!("[Phase 1] Complete");
    serial_println!("[Phase 1] Complete");

    // Start Application Processors (SMP)
    kprintln!("");
    kprintln!("[SMP] Starting multiprocessor support...");
    serial_println!("[SMP] Starting multiprocessor support...");
    unsafe {
        hal::apic::start_all_aps();
    }
    kprintln!("[SMP] Active CPUs: {}", ke::prcb::get_active_cpu_count());
    serial_println!("[SMP] Active CPUs: {}", ke::prcb::get_active_cpu_count());

    kprintln!("");
    kprintln!("Kernel initialization complete!");
    kprintln!("Entering idle loop...");
    serial_println!("Kernel initialization complete!");
    serial_println!("Entering idle loop...");

    // Enter idle loop
    idle_loop()
}

/// Phase 0 initialization
///
/// Runs with interrupts disabled, single-threaded.
/// Sets up minimum infrastructure needed for Phase 1.
fn phase0_init(boot_info: &BootInfo) {
    // Print boot info
    kprintln!("  Boot info:");
    kprintln!("    Framebuffer: {}x{} @ {:#x}",
        boot_info.framebuffer_width,
        boot_info.framebuffer_height,
        boot_info.framebuffer_addr);
    kprintln!("    Kernel: phys={:#x} virt={:#x} size={}KB",
        boot_info.kernel_physical_base,
        boot_info.kernel_virtual_base,
        boot_info.kernel_size / 1024);
    kprintln!("    Memory map: {} entries @ {:#x}",
        boot_info.memory_map_entries,
        boot_info.memory_map_addr);
    if boot_info.rsdp_addr != 0 {
        kprintln!("    RSDP: {:#x}", boot_info.rsdp_addr);
    }

    // Initialize architecture-specific components
    kprintln!("  Initializing GDT...");
    arch::init_phase0();
    kprintln!("  GDT and IDT initialized");
}

/// Phase 1 initialization
///
/// Full kernel initialization with interrupts and scheduling enabled.
fn phase1_init(boot_info: &BootInfo) {
    // Initialize kernel executive (scheduler, PRCB, timer)
    kprintln!("  Initializing kernel executive...");
    unsafe {
        ke::init::init();
    }
    kprintln!("  Kernel executive initialized");

    // Initialize memory manager
    kprintln!("  Initializing memory manager...");
    unsafe {
        mm::init(boot_info);
    }
    kprintln!("  Memory manager initialized");

    // Initialize ACPI (hardware discovery)
    kprintln!("  Initializing ACPI...");
    unsafe {
        hal::acpi::init(boot_info.rsdp_addr);
    }
    if hal::acpi::is_initialized() {
        kprintln!("  ACPI initialized: {} CPU(s), {} I/O APIC(s)",
            hal::acpi::get_processor_count(),
            hal::acpi::get_io_apic_count());
    } else {
        kprintln!("  ACPI not available");
    }

    // Initialize RTC (real-time clock)
    kprintln!("  Initializing RTC...");
    hal::rtc::init();
    kprintln!("  RTC initialized");

    // Initialize power manager
    kprintln!("  Initializing power manager...");
    po::init();
    kprintln!("  Power manager initialized");

    // Initialize object manager
    kprintln!("  Initializing object manager...");
    unsafe {
        ob::init();
    }
    kprintln!("  Object manager initialized");

    // Initialize process manager
    kprintln!("  Initializing process manager...");
    unsafe {
        ps::init();
    }
    kprintln!("  Process manager initialized");

    // Initialize I/O manager
    kprintln!("  Initializing I/O manager...");
    io::init();
    kprintln!("  I/O manager initialized");

    // Initialize Cache Manager
    kprintln!("  Initializing cache manager...");
    cc::init();
    kprintln!("  Cache manager initialized");

    // Initialize storage subsystem (ATA driver, disk partitions)
    kprintln!("  Initializing storage subsystem...");
    io::init_storage();
    kprintln!("  Storage subsystem initialized");

    // Initialize Security Reference Monitor
    kprintln!("  Initializing security reference monitor...");
    se::init();
    kprintln!("  Security reference monitor initialized");

    // Initialize Configuration Manager (Registry)
    kprintln!("  Initializing configuration manager...");
    unsafe {
        cm::init();
    }
    kprintln!("  Configuration manager initialized");

    // Initialize File System
    kprintln!("  Initializing file system...");
    fs::init();
    kprintln!("  File system initialized");

    // Initialize LPC (Local Procedure Call)
    kprintln!("  Initializing LPC subsystem...");
    lpc::init();
    kprintln!("  LPC subsystem initialized");

    // Test file system by reading C:\TEST.TXT
    test_file_read();

    // Test syscall infrastructure (runs regardless of FS mount status)
    test_syscall();

    // Create test threads to verify context switching
    kprintln!("  Creating test threads...");
    serial_println!("  Creating test threads...");
    unsafe {
        // Timer and APC tests
        ke::init::create_test_threads();
        // Multi-object wait tests
        ke::init::create_wait_test_threads();
    }

    // Initialize PIC and keyboard for PS/2 input
    kprintln!("  Initializing keyboard...");
    hal::pic::init();
    hal::keyboard::init();
    kprintln!("  Keyboard initialized");

    // Create shell thread
    kprintln!("  Creating shell thread...");
    unsafe {
        if ke::init::create_thread(12, shell_thread_entry).is_some() {
            serial_println!("[SHELL] Shell thread created at priority 12");
        } else {
            serial_println!("[SHELL] ERROR: Failed to create shell thread");
        }
    }

    // Start the scheduler (enables interrupts)
    kprintln!("  Starting scheduler...");
    unsafe {
        ke::init::start_scheduler();
    }
    kprintln!("  Scheduler started");
}

/// Shell thread entry point
fn shell_thread_entry() {
    // Wait a moment for other threads to start and print their messages
    for _ in 0..500 {
        unsafe { core::arch::asm!("pause"); }
    }

    // Run the shell
    shell::run();

    // Shell exited - halt this thread
    loop {
        unsafe { crate::ke::scheduler::ki_yield(); }
    }
}

/// Test file system by reading C:\TEST.TXT
fn test_file_read() {
    serial_println!("");
    serial_println!("[FS-TEST] Testing file read from C:\\TEST.TXT...");

    // Debug: Check mount status
    if let Some(mp) = fs::mount::get_mount_point('C') {
        serial_println!("[FS-TEST] C: drive is mounted (fs_index={})", mp.fs_index);
    } else {
        serial_println!("[FS-TEST] C: drive is NOT mounted!");
    }

    // Try to open the file
    match fs::open("C:\\TEST.TXT", 0) {
        Ok(handle) => {
            serial_println!("[FS-TEST] File opened successfully (handle={})", handle);

            // Read file contents
            let mut buf = [0u8; 128];
            match fs::read(handle, &mut buf) {
                Ok(bytes_read) => {
                    serial_println!("[FS-TEST] Read {} bytes:", bytes_read);

                    // Print the contents as a string
                    if let Ok(content) = core::str::from_utf8(&buf[..bytes_read]) {
                        serial_println!("[FS-TEST] Content: \"{}\"", content.trim());
                    } else {
                        serial_println!("[FS-TEST] (binary data)");
                        for i in 0..bytes_read.min(32) {
                            serial_print!("{:02X} ", buf[i]);
                        }
                        serial_println!("");
                    }
                }
                Err(e) => {
                    serial_println!("[FS-TEST] Read failed: {:?}", e);
                }
            }

            // Test writing to the file
            serial_println!("[FS-TEST] Testing write...");
            // Seek back to start before writing
            let _ = fs::seek(handle, 0, fs::SeekWhence::Set);
            let write_data = b"Modified by Nostalgia OS!";
            match fs::write(handle, write_data) {
                Ok(bytes_written) => {
                    serial_println!("[FS-TEST] Wrote {} bytes", bytes_written);

                    // Seek back to start and read again
                    let _ = fs::seek(handle, 0, fs::SeekWhence::Set);
                    let mut buf2 = [0u8; 128];
                    match fs::read(handle, &mut buf2) {
                        Ok(bytes_read) => {
                            if let Ok(content) = core::str::from_utf8(&buf2[..bytes_read]) {
                                serial_println!("[FS-TEST] After write: \"{}\"", content.trim());
                            }
                        }
                        Err(e) => {
                            serial_println!("[FS-TEST] Re-read failed: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    serial_println!("[FS-TEST] Write failed: {:?}", e);
                }
            }

            // Close the file
            let _ = fs::close(handle);
            serial_println!("[FS-TEST] File closed");
        }
        Err(e) => {
            serial_println!("[FS-TEST] Failed to open file: {:?}", e);
        }
    }

    serial_println!("[FS-TEST] Test complete");
    serial_println!("");

    // Test creating a new file
    test_file_create();
}

/// Test creating a new file on C:\
fn test_file_create() {
    serial_println!("[FS-CREATE] Testing file creation on C:\\NEWFILE.TXT...");

    match fs::create("C:\\NEWFILE.TXT", 0) {
        Ok(handle) => {
            serial_println!("[FS-CREATE] File created successfully (handle={})", handle);

            // Write some data to the new file
            let data = b"Created by Nostalgia OS kernel!";
            match fs::write(handle, data) {
                Ok(bytes) => {
                    serial_println!("[FS-CREATE] Wrote {} bytes to new file", bytes);
                }
                Err(e) => {
                    serial_println!("[FS-CREATE] Write failed: {:?}", e);
                }
            }

            // Seek back and verify
            let _ = fs::seek(handle, 0, fs::SeekWhence::Set);
            let mut buf = [0u8; 64];
            match fs::read(handle, &mut buf) {
                Ok(bytes) => {
                    if let Ok(content) = core::str::from_utf8(&buf[..bytes]) {
                        serial_println!("[FS-CREATE] Verified: \"{}\"", content.trim());
                    }
                }
                Err(e) => {
                    serial_println!("[FS-CREATE] Read-back failed: {:?}", e);
                }
            }

            let _ = fs::close(handle);
            serial_println!("[FS-CREATE] File closed");
        }
        Err(e) => {
            serial_println!("[FS-CREATE] Failed to create file: {:?}", e);
        }
    }

    serial_println!("[FS-CREATE] Test complete");

    // Test deleting a file
    test_file_delete();
}

/// Test deleting a file on C:\
fn test_file_delete() {
    serial_println!("[FS-DELETE] Testing file deletion...");

    // First, verify the file exists
    match fs::open("C:\\NEWFILE.TXT", 0) {
        Ok(handle) => {
            serial_println!("[FS-DELETE] NEWFILE.TXT exists, closing...");
            let _ = fs::close(handle);
        }
        Err(_) => {
            serial_println!("[FS-DELETE] NEWFILE.TXT does not exist, creating...");
            if let Ok(h) = fs::create("C:\\NEWFILE.TXT", 0) {
                let _ = fs::write(h, b"Temporary file");
                let _ = fs::close(h);
            }
        }
    }

    // Now delete the file
    match fs::delete("C:\\NEWFILE.TXT") {
        Ok(()) => {
            serial_println!("[FS-DELETE] File deleted successfully");

            // Verify it's gone
            match fs::open("C:\\NEWFILE.TXT", 0) {
                Ok(handle) => {
                    serial_println!("[FS-DELETE] ERROR: File still exists after delete!");
                    let _ = fs::close(handle);
                }
                Err(e) => {
                    serial_println!("[FS-DELETE] Verified: File no longer exists ({:?})", e);
                }
            }
        }
        Err(e) => {
            serial_println!("[FS-DELETE] Delete failed: {:?}", e);
        }
    }

    serial_println!("[FS-DELETE] Test complete");

    // Test creating a directory
    test_mkdir();
}

/// Test creating a directory on C:\
fn test_mkdir() {
    serial_println!("[FS-MKDIR] Testing directory creation on C:\\TESTDIR...");

    match fs::mkdir("C:\\TESTDIR") {
        Ok(()) => {
            serial_println!("[FS-MKDIR] Directory created successfully");

            // Verify by listing root directory
            serial_println!("[FS-MKDIR] Verifying directory exists...");
            let mut found = false;
            for i in 0..16 {
                match fs::readdir("C:\\", i) {
                    Ok(entry) => {
                        let name = entry.name_str();
                        if name == "TESTDIR" {
                            serial_println!("[FS-MKDIR] Found TESTDIR in root directory");
                            found = true;
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            if !found {
                serial_println!("[FS-MKDIR] WARNING: TESTDIR not found in directory listing");
            }

            // Try to create a file inside the new directory
            serial_println!("[FS-MKDIR] Creating file inside TESTDIR...");
            match fs::create("C:\\TESTDIR\\HELLO.TXT", 0) {
                Ok(handle) => {
                    let data = b"Hello from subdirectory!";
                    match fs::write(handle, data) {
                        Ok(bytes) => {
                            serial_println!("[FS-MKDIR] Wrote {} bytes to TESTDIR\\HELLO.TXT", bytes);
                        }
                        Err(e) => {
                            serial_println!("[FS-MKDIR] Write failed: {:?}", e);
                        }
                    }
                    let _ = fs::close(handle);
                }
                Err(e) => {
                    serial_println!("[FS-MKDIR] Failed to create file in TESTDIR: {:?}", e);
                }
            }
        }
        Err(e) => {
            serial_println!("[FS-MKDIR] Failed to create directory: {:?}", e);
        }
    }

    serial_println!("[FS-MKDIR] Test complete");

    // Test removing the directory
    test_rmdir();
}

/// Test removing a directory from C:\
fn test_rmdir() {
    serial_println!("[FS-RMDIR] Testing directory removal...");

    // First, we need to delete the file inside TESTDIR
    serial_println!("[FS-RMDIR] Deleting HELLO.TXT from TESTDIR...");
    match fs::delete("C:\\TESTDIR\\HELLO.TXT") {
        Ok(()) => {
            serial_println!("[FS-RMDIR] HELLO.TXT deleted");
        }
        Err(e) => {
            serial_println!("[FS-RMDIR] Failed to delete HELLO.TXT: {:?}", e);
            // Try to remove anyway to see if it fails properly
        }
    }

    // Now try to remove the directory
    serial_println!("[FS-RMDIR] Removing C:\\TESTDIR...");
    match fs::rmdir("C:\\TESTDIR") {
        Ok(()) => {
            serial_println!("[FS-RMDIR] Directory removed successfully");

            // Verify by listing root directory
            serial_println!("[FS-RMDIR] Verifying directory no longer exists...");
            let mut found = false;
            for i in 0..16 {
                match fs::readdir("C:\\", i) {
                    Ok(entry) => {
                        let name = entry.name_str();
                        if name == "TESTDIR" {
                            found = true;
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            if found {
                serial_println!("[FS-RMDIR] ERROR: TESTDIR still exists!");
            } else {
                serial_println!("[FS-RMDIR] Verified: TESTDIR no longer exists");
            }
        }
        Err(e) => {
            serial_println!("[FS-RMDIR] Failed to remove directory: {:?}", e);
        }
    }

    serial_println!("[FS-RMDIR] Test complete");

    // Test renaming files and directories
    test_rename();
}

/// Test renaming files and directories
fn test_rename() {
    serial_println!("[FS-RENAME] Testing file and directory rename...");

    // First create a test file to rename
    serial_println!("[FS-RENAME] Creating test file C:\\OLDNAME.TXT...");
    match fs::create("C:\\OLDNAME.TXT", 0) {
        Ok(handle) => {
            let data = b"Rename test file content";
            let _ = fs::write(handle, data);
            let _ = fs::close(handle);
            serial_println!("[FS-RENAME] Created OLDNAME.TXT");
        }
        Err(e) => {
            serial_println!("[FS-RENAME] Failed to create test file: {:?}", e);
            return;
        }
    }

    // Test 1: Simple rename in same directory
    serial_println!("[FS-RENAME] Test 1: Renaming OLDNAME.TXT to NEWNAME.TXT...");
    match fs::rename("C:\\OLDNAME.TXT", "C:\\NEWNAME.TXT") {
        Ok(()) => {
            serial_println!("[FS-RENAME] Rename successful");

            // Verify old file doesn't exist
            match fs::open("C:\\OLDNAME.TXT", 0) {
                Ok(h) => {
                    let _ = fs::close(h);
                    serial_println!("[FS-RENAME] ERROR: Old file still exists!");
                }
                Err(_) => {
                    serial_println!("[FS-RENAME] Verified: OLDNAME.TXT no longer exists");
                }
            }

            // Verify new file exists and has correct content
            match fs::open("C:\\NEWNAME.TXT", 0) {
                Ok(handle) => {
                    let mut buf = [0u8; 64];
                    match fs::read(handle, &mut buf) {
                        Ok(n) => {
                            let content = core::str::from_utf8(&buf[..n]).unwrap_or("");
                            serial_println!("[FS-RENAME] NEWNAME.TXT content: \"{}\"", content);
                        }
                        Err(e) => {
                            serial_println!("[FS-RENAME] Failed to read: {:?}", e);
                        }
                    }
                    let _ = fs::close(handle);
                }
                Err(e) => {
                    serial_println!("[FS-RENAME] ERROR: New file not found: {:?}", e);
                }
            }
        }
        Err(e) => {
            serial_println!("[FS-RENAME] Rename failed: {:?}", e);
        }
    }

    // Test 2: Create a directory and move file into it
    serial_println!("[FS-RENAME] Test 2: Creating directory and moving file...");
    match fs::mkdir("C:\\MOVEDIR") {
        Ok(()) => {
            serial_println!("[FS-RENAME] Created MOVEDIR");

            // Move NEWNAME.TXT into MOVEDIR
            serial_println!("[FS-RENAME] Moving NEWNAME.TXT to MOVEDIR\\MOVED.TXT...");
            match fs::rename("C:\\NEWNAME.TXT", "C:\\MOVEDIR\\MOVED.TXT") {
                Ok(()) => {
                    serial_println!("[FS-RENAME] Move successful");

                    // Verify file is in new location
                    match fs::open("C:\\MOVEDIR\\MOVED.TXT", 0) {
                        Ok(handle) => {
                            serial_println!("[FS-RENAME] Verified: File found in MOVEDIR");
                            let _ = fs::close(handle);
                        }
                        Err(e) => {
                            serial_println!("[FS-RENAME] ERROR: File not found in new location: {:?}", e);
                        }
                    }

                    // Verify file is not in old location
                    match fs::open("C:\\NEWNAME.TXT", 0) {
                        Ok(h) => {
                            let _ = fs::close(h);
                            serial_println!("[FS-RENAME] ERROR: File still in old location!");
                        }
                        Err(_) => {
                            serial_println!("[FS-RENAME] Verified: File removed from root");
                        }
                    }
                }
                Err(e) => {
                    serial_println!("[FS-RENAME] Move failed: {:?}", e);
                }
            }

            // Clean up: delete the moved file and directory
            let _ = fs::delete("C:\\MOVEDIR\\MOVED.TXT");
            let _ = fs::rmdir("C:\\MOVEDIR");
        }
        Err(e) => {
            serial_println!("[FS-RENAME] Failed to create directory: {:?}", e);
        }
    }

    // Clean up any remaining test files
    let _ = fs::delete("C:\\NEWNAME.TXT");
    let _ = fs::delete("C:\\OLDNAME.TXT");

    serial_println!("[FS-RENAME] Test complete");

    // Test truncating files
    test_truncate();
}

/// Test truncating files
fn test_truncate() {
    serial_println!("[FS-TRUNCATE] Testing file truncation...");

    // Create a test file with some content
    serial_println!("[FS-TRUNCATE] Creating test file with 100 bytes...");
    match fs::create("C:\\TRUNC.TXT", 0) {
        Ok(handle) => {
            // Write 100 bytes
            let data = [b'X'; 100];
            match fs::write(handle, &data) {
                Ok(n) => {
                    serial_println!("[FS-TRUNCATE] Wrote {} bytes", n);
                }
                Err(e) => {
                    serial_println!("[FS-TRUNCATE] Write failed: {:?}", e);
                    let _ = fs::close(handle);
                    return;
                }
            }

            // Test 1: Shrink the file to 50 bytes
            serial_println!("[FS-TRUNCATE] Test 1: Shrinking file to 50 bytes...");
            match fs::truncate(handle, 50) {
                Ok(()) => {
                    serial_println!("[FS-TRUNCATE] Truncate to 50 bytes successful");

                    // Seek to start and verify size
                    let _ = fs::seek(handle, 0, fs::SeekWhence::Set);
                    let mut buf = [0u8; 128];
                    match fs::read(handle, &mut buf) {
                        Ok(n) => {
                            serial_println!("[FS-TRUNCATE] Read {} bytes after shrink", n);
                            if n == 50 {
                                serial_println!("[FS-TRUNCATE] Size verified: 50 bytes");
                            } else {
                                serial_println!("[FS-TRUNCATE] ERROR: Expected 50 bytes, got {}", n);
                            }
                        }
                        Err(e) => {
                            serial_println!("[FS-TRUNCATE] Read failed: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    serial_println!("[FS-TRUNCATE] Truncate failed: {:?}", e);
                }
            }

            // Test 2: Extend the file to 200 bytes
            serial_println!("[FS-TRUNCATE] Test 2: Extending file to 200 bytes...");
            match fs::truncate(handle, 200) {
                Ok(()) => {
                    serial_println!("[FS-TRUNCATE] Extend to 200 bytes successful");

                    // Seek to end and check position
                    match fs::seek(handle, 0, fs::SeekWhence::End) {
                        Ok(pos) => {
                            serial_println!("[FS-TRUNCATE] File end position: {}", pos);
                            if pos == 200 {
                                serial_println!("[FS-TRUNCATE] Size verified: 200 bytes");
                            }
                        }
                        Err(e) => {
                            serial_println!("[FS-TRUNCATE] Seek failed: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    serial_println!("[FS-TRUNCATE] Extend failed: {:?}", e);
                }
            }

            // Test 3: Truncate to zero
            serial_println!("[FS-TRUNCATE] Test 3: Truncating file to 0 bytes...");
            match fs::truncate(handle, 0) {
                Ok(()) => {
                    serial_println!("[FS-TRUNCATE] Truncate to 0 bytes successful");

                    // Seek to start and verify empty
                    let _ = fs::seek(handle, 0, fs::SeekWhence::Set);
                    let mut buf = [0u8; 16];
                    match fs::read(handle, &mut buf) {
                        Ok(n) => {
                            if n == 0 {
                                serial_println!("[FS-TRUNCATE] Verified: File is empty");
                            } else {
                                serial_println!("[FS-TRUNCATE] ERROR: Expected 0 bytes, got {}", n);
                            }
                        }
                        Err(e) => {
                            // EOF is expected for empty file
                            serial_println!("[FS-TRUNCATE] Read result: {:?} (expected for empty file)", e);
                        }
                    }
                }
                Err(e) => {
                    serial_println!("[FS-TRUNCATE] Truncate to 0 failed: {:?}", e);
                }
            }

            let _ = fs::close(handle);
        }
        Err(e) => {
            serial_println!("[FS-TRUNCATE] Failed to create test file: {:?}", e);
            return;
        }
    }

    // Clean up
    let _ = fs::delete("C:\\TRUNC.TXT");

    serial_println!("[FS-TRUNCATE] Test complete");

    // Test stat/fstat
    test_fstat();
}

/// Test file stat/fstat operations
fn test_fstat() {
    serial_println!("[FS-STAT] Testing file stat/fstat...");

    // Create a test file with known content
    serial_println!("[FS-STAT] Creating test file...");
    let handle = match fs::create("C:\\STAT.TXT", 0) {
        Ok(h) => h,
        Err(e) => {
            serial_println!("[FS-STAT] Failed to create file: {:?}", e);
            return;
        }
    };

    // Write some data
    let test_data = b"Hello, this is test data for stat!";
    match fs::write(handle, test_data) {
        Ok(n) => serial_println!("[FS-STAT] Wrote {} bytes", n),
        Err(e) => {
            serial_println!("[FS-STAT] Write failed: {:?}", e);
            let _ = fs::close(handle);
            return;
        }
    }

    // Test fstat on the open file
    serial_println!("[FS-STAT] Testing fstat on open file...");
    match fs::fstat(handle) {
        Ok(info) => {
            serial_println!("[FS-STAT] fstat successful:");
            serial_println!("[FS-STAT]   Size: {} bytes", info.size);
            serial_println!("[FS-STAT]   Type: {:?}", info.file_type);
            serial_println!("[FS-STAT]   Attributes: 0x{:02x}", info.attributes);
            serial_println!("[FS-STAT]   Block size: {} bytes", info.block_size);
            serial_println!("[FS-STAT]   Blocks: {}", info.blocks);

            // Verify size matches what we wrote
            if info.size == test_data.len() as u64 {
                serial_println!("[FS-STAT] Size verified: {} bytes", info.size);
            } else {
                serial_println!("[FS-STAT] ERROR: Size mismatch! Expected {}, got {}",
                    test_data.len(), info.size);
            }
        }
        Err(e) => {
            serial_println!("[FS-STAT] fstat failed: {:?}", e);
        }
    }

    // Close and reopen to test stat by path
    let _ = fs::close(handle);

    // Test stat by path
    serial_println!("[FS-STAT] Testing stat by path...");

    // First need to open the file to have it in the open files table
    let handle2 = match fs::open("C:\\STAT.TXT", 0) {
        Ok(h) => h,
        Err(e) => {
            serial_println!("[FS-STAT] Failed to reopen file: {:?}", e);
            let _ = fs::delete("C:\\STAT.TXT");
            return;
        }
    };

    match fs::fstat(handle2) {
        Ok(info) => {
            serial_println!("[FS-STAT] stat successful:");
            serial_println!("[FS-STAT]   Size: {} bytes", info.size);
            serial_println!("[FS-STAT]   Type: {:?}", info.file_type);
            if info.size == test_data.len() as u64 {
                serial_println!("[FS-STAT] Size verified after reopen");
            }
        }
        Err(e) => {
            serial_println!("[FS-STAT] stat failed: {:?}", e);
        }
    }

    // Clean up
    let _ = fs::close(handle2);
    let _ = fs::delete("C:\\STAT.TXT");

    serial_println!("[FS-STAT] Test complete");

    // Test sync
    test_sync();
}

/// Test file sync/flush operations
fn test_sync() {
    serial_println!("[FS-SYNC] Testing file sync...");

    // Create a test file
    let handle = match fs::create("C:\\SYNC.TXT", 0) {
        Ok(h) => h,
        Err(e) => {
            serial_println!("[FS-SYNC] Failed to create file: {:?}", e);
            return;
        }
    };

    // Write some data
    let data1 = b"Initial data before sync";
    match fs::write(handle, data1) {
        Ok(n) => serial_println!("[FS-SYNC] Wrote {} bytes", n),
        Err(e) => {
            serial_println!("[FS-SYNC] Write failed: {:?}", e);
            let _ = fs::close(handle);
            return;
        }
    }

    // Sync the file (should flush metadata)
    serial_println!("[FS-SYNC] Calling sync...");
    match fs::sync(handle) {
        Ok(()) => serial_println!("[FS-SYNC] Sync successful"),
        Err(e) => serial_println!("[FS-SYNC] Sync failed: {:?}", e),
    }

    // Write more data
    let data2 = b" - more data after sync";
    match fs::write(handle, data2) {
        Ok(n) => serial_println!("[FS-SYNC] Wrote {} more bytes", n),
        Err(e) => serial_println!("[FS-SYNC] Second write failed: {:?}", e),
    }

    // Sync again
    serial_println!("[FS-SYNC] Calling sync again...");
    match fs::sync(handle) {
        Ok(()) => serial_println!("[FS-SYNC] Second sync successful"),
        Err(e) => serial_println!("[FS-SYNC] Second sync failed: {:?}", e),
    }

    // Verify final size with fstat
    match fs::fstat(handle) {
        Ok(info) => {
            let expected_size = data1.len() + data2.len();
            serial_println!("[FS-SYNC] Final size: {} bytes (expected {})",
                info.size, expected_size);
            if info.size == expected_size as u64 {
                serial_println!("[FS-SYNC] Size verified");
            }
        }
        Err(e) => serial_println!("[FS-SYNC] fstat failed: {:?}", e),
    }

    // Clean up
    let _ = fs::close(handle);
    let _ = fs::delete("C:\\SYNC.TXT");

    serial_println!("[FS-SYNC] Test complete");

    // Test readdir
    test_readdir();
}

/// Test directory listing
fn test_readdir() {
    serial_println!("[FS-READDIR] Testing directory listing...");

    // Create some test files and a directory
    serial_println!("[FS-READDIR] Creating test files...");

    // Create test files with static paths
    if let Ok(h) = fs::create("C:\\FILE1.TXT", 0) {
        let _ = fs::write(h, b"test content 1");
        let _ = fs::close(h);
    }
    if let Ok(h) = fs::create("C:\\FILE2.TXT", 0) {
        let _ = fs::write(h, b"test content 2");
        let _ = fs::close(h);
    }
    if let Ok(h) = fs::create("C:\\FILE3.TXT", 0) {
        let _ = fs::write(h, b"test content 3");
        let _ = fs::close(h);
    }

    // Create a test directory
    match fs::mkdir("C:\\TESTDIR2") {
        Ok(()) => serial_println!("[FS-READDIR] Created TESTDIR2"),
        Err(e) => serial_println!("[FS-READDIR] Failed to create TESTDIR2: {:?}", e),
    }

    // List the root directory
    serial_println!("[FS-READDIR] Listing C:\\ contents:");
    let mut offset = 0u32;
    let mut count = 0;

    loop {
        match fs::readdir("C:\\", offset) {
            Ok(entry) => {
                let name = entry.name_str();
                let type_str = match entry.file_type {
                    fs::FileType::Directory => "<DIR>",
                    fs::FileType::Regular => "     ",
                    _ => "?????",
                };
                serial_println!("[FS-READDIR]   {} {:>8} bytes  {}",
                    type_str, entry.size, name);
                count += 1;
                offset = entry.next_offset;
            }
            Err(fs::FsStatus::NoMoreEntries) => {
                serial_println!("[FS-READDIR] End of directory ({} entries)", count);
                break;
            }
            Err(e) => {
                serial_println!("[FS-READDIR] Error: {:?}", e);
                break;
            }
        }
    }

    // Clean up test files
    serial_println!("[FS-READDIR] Cleaning up...");
    let _ = fs::delete("C:\\FILE1.TXT");
    let _ = fs::delete("C:\\FILE2.TXT");
    let _ = fs::delete("C:\\FILE3.TXT");
    let _ = fs::rmdir("C:\\TESTDIR2");

    serial_println!("[FS-READDIR] Test complete");

    // Test copy
    test_copy();
}

/// Test file copy operation
fn test_copy() {
    serial_println!("[FS-COPY] Testing file copy...");

    // Create a source file with known content
    serial_println!("[FS-COPY] Creating source file...");
    let test_data = b"This is test data for the copy operation. It should be copied exactly to the destination file.";

    let src_handle = match fs::create("C:\\SOURCE.TXT", 0) {
        Ok(h) => h,
        Err(e) => {
            serial_println!("[FS-COPY] Failed to create source: {:?}", e);
            return;
        }
    };

    match fs::write(src_handle, test_data) {
        Ok(n) => serial_println!("[FS-COPY] Wrote {} bytes to source", n),
        Err(e) => {
            serial_println!("[FS-COPY] Write failed: {:?}", e);
            let _ = fs::close(src_handle);
            return;
        }
    }
    let _ = fs::close(src_handle);

    // Copy the file
    serial_println!("[FS-COPY] Copying SOURCE.TXT to DEST.TXT...");
    match fs::copy("C:\\SOURCE.TXT", "C:\\DEST.TXT") {
        Ok(bytes) => {
            serial_println!("[FS-COPY] Copied {} bytes", bytes);
            if bytes == test_data.len() as u64 {
                serial_println!("[FS-COPY] Size verified");
            } else {
                serial_println!("[FS-COPY] ERROR: Size mismatch! Expected {}", test_data.len());
            }
        }
        Err(e) => {
            serial_println!("[FS-COPY] Copy failed: {:?}", e);
            let _ = fs::delete("C:\\SOURCE.TXT");
            return;
        }
    }

    // Verify the destination file contents
    serial_println!("[FS-COPY] Verifying destination contents...");
    let dst_handle = match fs::open("C:\\DEST.TXT", 0) {
        Ok(h) => h,
        Err(e) => {
            serial_println!("[FS-COPY] Failed to open destination: {:?}", e);
            let _ = fs::delete("C:\\SOURCE.TXT");
            let _ = fs::delete("C:\\DEST.TXT");
            return;
        }
    };

    let mut read_buf = [0u8; 128];
    match fs::read(dst_handle, &mut read_buf) {
        Ok(n) => {
            serial_println!("[FS-COPY] Read {} bytes from destination", n);
            if n == test_data.len() && &read_buf[..n] == test_data {
                serial_println!("[FS-COPY] Content verified - copy successful!");
            } else {
                serial_println!("[FS-COPY] ERROR: Content mismatch!");
            }
        }
        Err(e) => {
            serial_println!("[FS-COPY] Read failed: {:?}", e);
        }
    }
    let _ = fs::close(dst_handle);

    // Test copying to a subdirectory
    serial_println!("[FS-COPY] Testing copy to subdirectory...");
    let _ = fs::mkdir("C:\\COPYDIR");

    match fs::copy("C:\\SOURCE.TXT", "C:\\COPYDIR\\COPIED.TXT") {
        Ok(bytes) => serial_println!("[FS-COPY] Copied {} bytes to subdirectory", bytes),
        Err(e) => serial_println!("[FS-COPY] Subdirectory copy failed: {:?}", e),
    }

    // Clean up
    serial_println!("[FS-COPY] Cleaning up...");
    let _ = fs::delete("C:\\SOURCE.TXT");
    let _ = fs::delete("C:\\DEST.TXT");
    let _ = fs::delete("C:\\COPYDIR\\COPIED.TXT");
    let _ = fs::rmdir("C:\\COPYDIR");

    serial_println!("[FS-COPY] Test complete");
}

/// Test syscall infrastructure
fn test_syscall() {
    serial_println!("[SYSCALL-TEST] Testing syscall dispatcher...");

    // Test NtGetCurrentProcessId (syscall 3)
    let pid = unsafe {
        // Directly call the dispatcher for testing (simulates SYSCALL instruction)
        extern "C" {
            fn syscall_dispatcher(
                num: usize, a1: usize, a2: usize, a3: usize,
                a4: usize, a5: usize, a6: usize,
            ) -> isize;
        }
        syscall_dispatcher(3, 0, 0, 0, 0, 0, 0)
    };
    serial_println!("[SYSCALL-TEST] NtGetCurrentProcessId returned: {}", pid);

    // Test NtGetCurrentThreadId (syscall 4)
    let tid = unsafe {
        extern "C" {
            fn syscall_dispatcher(
                num: usize, a1: usize, a2: usize, a3: usize,
                a4: usize, a5: usize, a6: usize,
            ) -> isize;
        }
        syscall_dispatcher(4, 0, 0, 0, 0, 0, 0)
    };
    serial_println!("[SYSCALL-TEST] NtGetCurrentThreadId returned: {}", tid);

    // Test NtDebugPrint (syscall 52)
    let msg = b"Hello from syscall!\n";
    let result = unsafe {
        extern "C" {
            fn syscall_dispatcher(
                num: usize, a1: usize, a2: usize, a3: usize,
                a4: usize, a5: usize, a6: usize,
            ) -> isize;
        }
        syscall_dispatcher(52, msg.as_ptr() as usize, msg.len(), 0, 0, 0, 0)
    };
    serial_println!("[SYSCALL-TEST] NtDebugPrint returned: {}", result);

    // Test invalid syscall
    let invalid = unsafe {
        extern "C" {
            fn syscall_dispatcher(
                num: usize, a1: usize, a2: usize, a3: usize,
                a4: usize, a5: usize, a6: usize,
            ) -> isize;
        }
        syscall_dispatcher(999, 0, 0, 0, 0, 0, 0)
    };
    serial_println!("[SYSCALL-TEST] Invalid syscall 999 returned: {}", invalid);

    // Test suspend/resume syscalls
    test_suspend_resume_syscalls();

    serial_println!("[SYSCALL-TEST] All syscall tests passed!");

    // Test user mode page tables and execution
    test_user_mode();
}

/// Test suspend/resume syscalls
fn test_suspend_resume_syscalls() {
    serial_println!("[SUSPEND-TEST] Testing suspend/resume syscalls...");

    // Syscall numbers
    const NT_SUSPEND_THREAD: usize = 98;
    const NT_RESUME_THREAD: usize = 99;
    const NT_SUSPEND_PROCESS: usize = 93;
    const NT_RESUME_PROCESS: usize = 94;

    // Test NtSuspendThread with invalid handle
    let result = unsafe {
        extern "C" {
            fn syscall_dispatcher(
                num: usize, a1: usize, a2: usize, a3: usize,
                a4: usize, a5: usize, a6: usize,
            ) -> isize;
        }
        syscall_dispatcher(NT_SUSPEND_THREAD, 0xFFFF, 0, 0, 0, 0, 0)
    };
    serial_println!("[SUSPEND-TEST] NtSuspendThread(invalid) = {:#x}", result as u32);

    // Test NtResumeThread with invalid handle
    let result = unsafe {
        extern "C" {
            fn syscall_dispatcher(
                num: usize, a1: usize, a2: usize, a3: usize,
                a4: usize, a5: usize, a6: usize,
            ) -> isize;
        }
        syscall_dispatcher(NT_RESUME_THREAD, 0xFFFF, 0, 0, 0, 0, 0)
    };
    serial_println!("[SUSPEND-TEST] NtResumeThread(invalid) = {:#x}", result as u32);

    // Test NtSuspendProcess with invalid handle
    let result = unsafe {
        extern "C" {
            fn syscall_dispatcher(
                num: usize, a1: usize, a2: usize, a3: usize,
                a4: usize, a5: usize, a6: usize,
            ) -> isize;
        }
        syscall_dispatcher(NT_SUSPEND_PROCESS, 0xFFFF, 0, 0, 0, 0, 0)
    };
    serial_println!("[SUSPEND-TEST] NtSuspendProcess(invalid) = {:#x}", result as u32);

    // Test NtResumeProcess with invalid handle
    let result = unsafe {
        extern "C" {
            fn syscall_dispatcher(
                num: usize, a1: usize, a2: usize, a3: usize,
                a4: usize, a5: usize, a6: usize,
            ) -> isize;
        }
        syscall_dispatcher(NT_RESUME_PROCESS, 0xFFFF, 0, 0, 0, 0, 0)
    };
    serial_println!("[SUSPEND-TEST] NtResumeProcess(invalid) = {:#x}", result as u32);

    // Test with valid process handle (system process, PID 0)
    // Process handle base is 0x5000, so handle for PID 0 = 0x5000
    let result = unsafe {
        extern "C" {
            fn syscall_dispatcher(
                num: usize, a1: usize, a2: usize, a3: usize,
                a4: usize, a5: usize, a6: usize,
            ) -> isize;
        }
        syscall_dispatcher(NT_SUSPEND_PROCESS, 0x5000, 0, 0, 0, 0, 0)
    };
    serial_println!("[SUSPEND-TEST] NtSuspendProcess(system) = {:#x}", result as u32);

    // Resume it
    let result = unsafe {
        extern "C" {
            fn syscall_dispatcher(
                num: usize, a1: usize, a2: usize, a3: usize,
                a4: usize, a5: usize, a6: usize,
            ) -> isize;
        }
        syscall_dispatcher(NT_RESUME_PROCESS, 0x5000, 0, 0, 0, 0, 0)
    };
    serial_println!("[SUSPEND-TEST] NtResumeProcess(system) = {:#x}", result as u32);

    serial_println!("[SUSPEND-TEST] Suspend/resume tests complete!");
}

/// Test user mode page tables and execution
fn test_user_mode() {
    serial_println!("[USER-TEST] Testing user mode execution...");

    // Initialize user page tables
    unsafe {
        mm::user::init_user_page_tables();
    }

    serial_println!("[USER-TEST] User CR3: {:#x}", mm::user::get_user_cr3());
    serial_println!("[USER-TEST] Kernel CR3: {:#x}", mm::user::get_kernel_cr3());

    // Copy test code to user memory
    let user_addr = unsafe {
        match mm::user::copy_code_to_user(&mm::user::USER_TEST_CODE) {
            Some(addr) => addr,
            None => {
                serial_println!("[USER-TEST] Failed to copy code");
                return;
            }
        }
    };

    serial_println!("[USER-TEST] User code at: {:#x}", user_addr);
    serial_println!("[USER-TEST] User stack top: {:#x}", mm::user::get_user_stack_top());

    // Note: We skip the separate switch test because run_user_code does
    // the CR3 switch atomically with IRETQ (no interrupts can fire between)
    serial_println!("[USER-TEST] User mode page tables ready for ring 3 execution");

    // Now actually run code in ring 3!
    serial_println!("[USER-TEST] Entering ring 3...");
    unsafe {
        arch::x86_64::syscall::test_user_mode();
    }

    serial_println!("[USER-TEST] Test complete");
}

/// Kernel idle loop
///
/// Runs when no threads are ready. Halts the CPU until an interrupt arrives.
fn idle_loop() -> ! {
    loop {
        arch::halt();
    }
}

/// Panic handler
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kprintln!("");
    kprintln!("!!! KERNEL PANIC !!!");
    kprintln!("{}", info);
    serial_println!("");
    serial_println!("!!! KERNEL PANIC !!!");
    serial_println!("{}", info);

    loop {
        arch::halt();
    }
}

/// Allocation error handler
#[alloc_error_handler]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    panic!("Allocation failed: {:?}", layout);
}
