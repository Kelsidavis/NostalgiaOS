//! Kernel loading from EFI System Partition
//!
//! Loads the kernel binary from \EFI\nostalgia\kernel.bin on the ESP.
//! The kernel is a flat binary that will be loaded at KERNEL_PHYSICAL_BASE.

use log::info;
use uefi::boot;
use uefi::cstr16;
use uefi::fs::FileSystem;
use uefi::mem::memory_map::MemoryType;
use uefi::proto::media::fs::SimpleFileSystem;

/// Kernel physical load address (16 MB)
pub const KERNEL_PHYSICAL_BASE: u64 = 0x100_0000;

/// Kernel virtual address (higher half)
/// Using -2GB from top of address space
pub const KERNEL_VIRTUAL_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Maximum kernel size (16 MB)
pub const MAX_KERNEL_SIZE: usize = 16 * 1024 * 1024;

/// Loaded kernel information
pub struct LoadedKernel {
    /// Physical address where kernel is loaded
    pub phys_addr: u64,
    /// Virtual address where kernel will be mapped
    pub virt_addr: u64,
    /// Size of loaded kernel in bytes
    pub size: u64,
    /// Entry point offset from base
    pub entry_offset: u64,
}

impl LoadedKernel {
    /// Get the physical entry point address
    pub fn entry_phys(&self) -> u64 {
        self.phys_addr + self.entry_offset
    }

    /// Get the virtual entry point address
    pub fn entry_virt(&self) -> u64 {
        self.virt_addr + self.entry_offset
    }
}

/// Load kernel from the EFI System Partition
pub fn load_kernel() -> Result<LoadedKernel, &'static str> {
    info!("Loading kernel from ESP...");

    // Get the filesystem protocol
    let fs_handle = boot::get_handle_for_protocol::<SimpleFileSystem>()
        .map_err(|_| "Failed to get filesystem handle")?;

    let fs = boot::open_protocol_exclusive::<SimpleFileSystem>(fs_handle)
        .map_err(|_| "Failed to open filesystem protocol")?;

    let mut fs = FileSystem::new(fs);

    // Try to read kernel from \EFI\nostalgia\kernel.bin
    let kernel_path = cstr16!("\\EFI\\nostalgia\\kernel.bin");

    let kernel_data = fs.read(kernel_path)
        .map_err(|_| "Failed to read kernel file - ensure \\EFI\\nostalgia\\kernel.bin exists")?;

    let kernel_size = kernel_data.len();
    info!("Kernel file size: {} bytes", kernel_size);

    if kernel_size > MAX_KERNEL_SIZE {
        return Err("Kernel too large");
    }

    if kernel_size == 0 {
        return Err("Kernel file is empty");
    }

    // Allocate memory at the desired physical address for the kernel
    // We need 2MB alignment for huge page mapping!
    // Allocate extra pages to ensure we can find a 2MB-aligned region
    const PAGE_SIZE: usize = 4096;
    const LARGE_PAGE_SIZE: usize = 2 * 1024 * 1024; // 2MB

    let pages_needed = kernel_size.div_ceil(PAGE_SIZE);
    // Allocate extra for 2MB alignment (512 pages = 2MB)
    let pages_for_alignment = LARGE_PAGE_SIZE / PAGE_SIZE;
    let total_pages = pages_needed + pages_for_alignment;

    // Try to allocate at specific address (already 2MB aligned)
    let (kernel_phys, kernel_phys_addr) = boot::allocate_pages(
        boot::AllocateType::Address(KERNEL_PHYSICAL_BASE),
        MemoryType::LOADER_DATA,
        pages_needed,
    ).map(|ptr| (ptr, ptr.as_ptr() as u64))
    .or_else(|_| {
        // Fall back to any address, but align to 2MB
        info!("Could not allocate at preferred address, using any available");
        let ptr = boot::allocate_pages(
            boot::AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            total_pages,
        ).map_err(|_| "Failed to allocate memory for kernel")?;

        let raw_addr = ptr.as_ptr() as u64;
        // Align up to 2MB boundary
        let aligned_addr = (raw_addr + LARGE_PAGE_SIZE as u64 - 1) & !(LARGE_PAGE_SIZE as u64 - 1);
        info!("Aligned kernel from {:#x} to {:#x}", raw_addr, aligned_addr);
        Ok((ptr, aligned_addr))
    })?;

    let _ = kernel_phys; // Keep allocation alive
    info!("Kernel loaded at physical address: {:#x}", kernel_phys_addr);

    // Copy kernel to allocated memory
    unsafe {
        let dest = kernel_phys_addr as *mut u8;
        core::ptr::copy_nonoverlapping(kernel_data.as_ptr(), dest, kernel_size);
    }

    // For a flat binary, entry point is at the start
    // For ELF, we would parse the header here
    let entry_offset = 0;

    Ok(LoadedKernel {
        phys_addr: kernel_phys_addr,
        virt_addr: KERNEL_VIRTUAL_BASE,
        size: kernel_size as u64,
        entry_offset,
    })
}

/// Load kernel or create a minimal stub if file not found
pub fn load_kernel_or_stub() -> Result<LoadedKernel, &'static str> {
    match load_kernel() {
        Ok(kernel) => Ok(kernel),
        Err(e) => {
            info!("Could not load kernel: {}", e);
            info!("Creating minimal kernel stub for testing...");
            create_kernel_stub()
        }
    }
}

/// Create a minimal kernel stub for testing when no kernel file exists
fn create_kernel_stub() -> Result<LoadedKernel, &'static str> {
    // Minimal kernel stub that just halts
    // This is x86_64 machine code:
    // cli      ; disable interrupts (0xFA)
    // hlt      ; halt (0xF4)
    // jmp $-2  ; infinite loop (0xEB 0xFC)
    let stub_code: [u8; 4] = [0xFA, 0xF4, 0xEB, 0xFC];

    let kernel_phys = boot::allocate_pages(
        boot::AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        1,
    ).map_err(|_| "Failed to allocate memory for kernel stub")?;

    let kernel_phys_addr = kernel_phys.as_ptr() as u64;

    // Copy stub code
    unsafe {
        let dest = kernel_phys_addr as *mut u8;
        core::ptr::copy_nonoverlapping(stub_code.as_ptr(), dest, stub_code.len());
    }

    info!("Kernel stub created at {:#x}", kernel_phys_addr);

    Ok(LoadedKernel {
        phys_addr: kernel_phys_addr,
        virt_addr: KERNEL_VIRTUAL_BASE,
        size: 4096, // One page
        entry_offset: 0,
    })
}
