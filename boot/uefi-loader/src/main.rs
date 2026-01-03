//! Nostalgia OS UEFI Bootloader
//!
//! This bootloader:
//! 1. Loads the kernel from \EFI\nostalgia\kernel.bin
//! 2. Sets up 4-level page tables (identity + higher-half mapping)
//! 3. Acquires the UEFI memory map
//! 4. Exits UEFI boot services
//! 5. Jumps to the kernel entry point

#![no_std]
#![no_main]

mod kernel;
mod paging;
mod serial;

use core::arch::asm;
use log::info;
use uefi::prelude::*;
use uefi::boot;
use uefi::mem::memory_map::{MemoryMap, MemoryMapOwned, MemoryType};

use paging::PageTables;

/// Boot information passed to the kernel
/// This structure is passed to kernel_main
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
}

/// Static boot info that persists after UEFI exit
static mut BOOT_INFO: BootInfo = BootInfo {
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

#[entry]
fn main() -> Status {
    // Initialize serial port first for early debugging
    serial::init();
    serial_println!("========================================");
    serial_println!("  Nostalgia OS UEFI Bootloader v0.1.0");
    serial_println!("========================================");

    // Initialize UEFI logging
    uefi::helpers::init().unwrap();

    info!("========================================");
    info!("  Nostalgia OS UEFI Bootloader v0.1.0");
    info!("========================================");
    info!("");
    info!("Firmware: {} v{}",
        uefi::system::firmware_vendor(),
        uefi::system::firmware_revision());
    serial_println!("Firmware initialized");

    // Step 1: Get framebuffer info
    info!("");
    info!("[1/5] Getting framebuffer info...");
    serial_println!("[1/5] Getting framebuffer info...");
    let (fb_addr, fb_width, fb_height, fb_stride, fb_bpp) = get_framebuffer_info();
    if fb_addr != 0 {
        info!("  Framebuffer: {}x{} @ {:#x}", fb_width, fb_height, fb_addr);
        serial_println!("  Framebuffer: {}x{} @ {:#x}", fb_width, fb_height, fb_addr);
    } else {
        info!("  No framebuffer available (headless mode)");
        serial_println!("  No framebuffer available (headless mode)");
    }

    // Step 2: Load kernel
    info!("");
    info!("[2/5] Loading kernel...");
    serial_println!("[2/5] Loading kernel...");
    let loaded_kernel = match kernel::load_kernel_or_stub() {
        Ok(k) => k,
        Err(e) => {
            info!("FATAL: {}", e);
            serial_println!("FATAL: {}", e);
            loop { unsafe { asm!("hlt") }; }
        }
    };
    info!("  Kernel loaded at phys={:#x}, size={} bytes",
        loaded_kernel.phys_addr, loaded_kernel.size);
    serial_println!("  Kernel loaded at phys={:#x}, size={} bytes",
        loaded_kernel.phys_addr, loaded_kernel.size);

    // Step 3: Set up page tables
    info!("");
    info!("[3/5] Setting up page tables...");
    serial_println!("[3/5] Setting up page tables...");
    let mut page_tables = match PageTables::new() {
        Ok(pt) => pt,
        Err(e) => {
            info!("FATAL: {}", e);
            serial_println!("FATAL: {}", e);
            loop { unsafe { asm!("hlt") }; }
        }
    };

    // Identity map first 4GB
    if let Err(e) = page_tables.identity_map_first_4gb() {
        info!("FATAL: {}", e);
        serial_println!("FATAL: {}", e);
        loop { unsafe { asm!("hlt") }; }
    }
    info!("  Identity mapped first 4GB");
    serial_println!("  Identity mapped first 4GB");

    // Map kernel to higher half
    // Note: BSS section is ~10MB (uninitialized static data for pools/tables)
    // We need to map: text + data + bss + stack/heap headroom
    // Add 16MB extra to cover BSS and leave room for early heap
    if let Err(e) = page_tables.map_kernel(
        loaded_kernel.phys_addr,
        loaded_kernel.virt_addr,
        loaded_kernel.size + 0x100_0000, // Add extra 16MB for BSS/stack/heap
    ) {
        info!("FATAL: {}", e);
        serial_println!("FATAL: {}", e);
        loop { unsafe { asm!("hlt") }; }
    }
    info!("  Mapped kernel: phys={:#x} -> virt={:#x}",
        loaded_kernel.phys_addr, loaded_kernel.virt_addr);
    serial_println!("  Mapped kernel: phys={:#x} -> virt={:#x}",
        loaded_kernel.phys_addr, loaded_kernel.virt_addr);

    let pml4_addr = page_tables.pml4_phys_addr();
    info!("  PML4 at {:#x}", pml4_addr);
    serial_println!("  PML4 at {:#x}", pml4_addr);

    // Step 4: Prepare boot info
    info!("");
    info!("[4/5] Preparing boot info...");
    serial_println!("[4/5] Preparing boot info...");

    // Find ACPI RSDP
    let rsdp_addr = find_rsdp();
    if rsdp_addr != 0 {
        info!("  RSDP found at {:#x}", rsdp_addr);
        serial_println!("  RSDP found at {:#x}", rsdp_addr);
    }

    // Fill in boot info (before we exit boot services)
    unsafe {
        BOOT_INFO.magic = BootInfo::MAGIC;
        BOOT_INFO.framebuffer_addr = fb_addr;
        BOOT_INFO.framebuffer_width = fb_width;
        BOOT_INFO.framebuffer_height = fb_height;
        BOOT_INFO.framebuffer_stride = fb_stride;
        BOOT_INFO.framebuffer_bpp = fb_bpp;
        BOOT_INFO.kernel_physical_base = loaded_kernel.phys_addr;
        BOOT_INFO.kernel_virtual_base = loaded_kernel.virt_addr;
        BOOT_INFO.kernel_size = loaded_kernel.size;
        BOOT_INFO.pml4_physical_addr = pml4_addr;
        BOOT_INFO.rsdp_addr = rsdp_addr;
    }

    // Step 5: Exit boot services and jump to kernel
    info!("");
    info!("[5/5] Exiting UEFI boot services...");
    serial_println!("[5/5] Exiting UEFI boot services...");
    info!("");
    info!("Jumping to kernel at {:#x} (virt: {:#x})",
        loaded_kernel.entry_phys(),
        loaded_kernel.entry_virt());
    serial_println!("Jumping to kernel at {:#x} (virt: {:#x})",
        loaded_kernel.entry_phys(),
        loaded_kernel.entry_virt());
    info!("========================================");
    serial_println!("========================================");

    // Exit boot services - this is the point of no return!
    let memory_map = unsafe { boot::exit_boot_services(MemoryType::LOADER_DATA) };

    // Store memory map info
    let (mmap_addr, mmap_entries, mmap_entry_size) = get_memory_map_info(&memory_map);
    unsafe {
        BOOT_INFO.memory_map_addr = mmap_addr;
        BOOT_INFO.memory_map_entries = mmap_entries;
        BOOT_INFO.memory_map_entry_size = mmap_entry_size;
    }

    // Now we're on our own - no more UEFI services!
    // Switch to our page tables and jump to kernel
    unsafe {
        jump_to_kernel(
            pml4_addr,
            loaded_kernel.entry_phys(),
            &raw const BOOT_INFO as u64,
        );
    }
}

/// Get framebuffer information from GOP
fn get_framebuffer_info() -> (u64, u32, u32, u32, u32) {
    use uefi::proto::console::gop::GraphicsOutput;

    let gop_handle = match boot::get_handle_for_protocol::<GraphicsOutput>() {
        Ok(h) => h,
        Err(_) => return (0, 0, 0, 0, 0),
    };

    let mut gop = match boot::open_protocol_exclusive::<GraphicsOutput>(gop_handle) {
        Ok(g) => g,
        Err(_) => return (0, 0, 0, 0, 0),
    };

    let mode_info = gop.current_mode_info();
    let (width, height) = mode_info.resolution();
    let stride = mode_info.stride() as u32;
    let fb_addr = gop.frame_buffer().as_mut_ptr() as u64;

    // Assume 32-bit color (BGRA)
    let bpp = 32;

    (fb_addr, width as u32, height as u32, stride * 4, bpp)
}

/// Find ACPI RSDP from UEFI configuration tables
fn find_rsdp() -> u64 {
    use uefi::table::cfg::{ACPI2_GUID, ACPI_GUID};

    

    uefi::system::with_config_table(|tables| {
        // Try ACPI 2.0 first
        for entry in tables {
            if entry.guid == ACPI2_GUID {
                return entry.address as u64;
            }
        }

        // Fall back to ACPI 1.0
        for entry in tables {
            if entry.guid == ACPI_GUID {
                return entry.address as u64;
            }
        }

        0
    })
}

/// Get memory map information
fn get_memory_map_info(memory_map: &MemoryMapOwned) -> (u64, u64, u64) {
    // Get the raw buffer from the memory map
    let buf = memory_map.buffer();
    let ptr = buf.as_ptr() as u64;
    let count = memory_map.len() as u64;
    let entry_size = memory_map.meta().desc_size as u64;

    (ptr, count, entry_size)
}

/// Jump to the kernel
///
/// This function:
/// 1. Loads our page tables into CR3
/// 2. Sets up a minimal stack
/// 3. Jumps to the kernel entry point with boot_info pointer in RDI
///
/// # Safety
/// This is extremely unsafe - we're switching page tables and jumping to arbitrary code
#[inline(never)]
unsafe fn jump_to_kernel(pml4_addr: u64, entry_point: u64, boot_info_ptr: u64) -> ! {
    // Set up a stack (use some memory after the kernel)
    // We'll use physical addresses since we identity-mapped the first 4GB
    let stack_top = 0x80000u64; // 512KB mark - should be safe

    // Use explicit register assignments to avoid conflicts
    // We put entry and boot_info in preserved registers first, then clear others
    asm!(
        // Disable interrupts
        "cli",

        // Load new page tables
        "mov cr3, rax",

        // Set up stack
        "mov rsp, rdx",
        "mov rbp, rdx",

        // Save entry point and boot_info before clearing registers
        // rcx = entry point, rsi = boot_info (from input operands)

        // Clear unused registers
        "xor rax, rax",
        "xor rbx, rbx",
        "xor rdx, rdx",
        "xor r8, r8",
        "xor r9, r9",
        "xor r10, r10",
        "xor r11, r11",
        "xor r12, r12",
        "xor r13, r13",
        "xor r14, r14",
        "xor r15, r15",
        "xor rbp, rbp",

        // Set boot_info pointer as first argument (System V ABI: RDI)
        "mov rdi, rsi",

        // Jump to kernel entry point (in rcx)
        "jmp rcx",

        in("rax") pml4_addr,
        in("rdx") stack_top,
        in("rsi") boot_info_ptr,
        in("rcx") entry_point,
        options(noreturn)
    );
}
