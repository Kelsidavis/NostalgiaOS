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

/// Maximum kernel size (64 MB)
pub const MAX_KERNEL_SIZE: usize = 128 * 1024 * 1024;

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

    // Parse ELF header to get entry point and load segments properly
    let elf_magic = &kernel_data[0..4];
    if elf_magic != [0x7f, b'E', b'L', b'F'] {
        return Err("Not a valid ELF file");
    }

    // Check it's ELF64
    if kernel_data[4] != 2 {
        return Err("Not a 64-bit ELF file");
    }

    // Get entry point (e_entry at offset 24, 8 bytes, little-endian)
    let e_entry = u64::from_le_bytes(kernel_data[24..32].try_into().unwrap());
    info!("ELF entry point: {:#x}", e_entry);

    // Get program header info
    let e_phoff = u64::from_le_bytes(kernel_data[32..40].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes(kernel_data[54..56].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(kernel_data[56..58].try_into().unwrap()) as usize;

    // Find the lowest physical address from LOAD segments
    let mut load_base_virt: u64 = u64::MAX;
    let mut load_base_phys: u64 = u64::MAX;

    for i in 0..e_phnum {
        let ph_start = e_phoff + i * e_phentsize;
        let p_type = u32::from_le_bytes(kernel_data[ph_start..ph_start+4].try_into().unwrap());

        // PT_LOAD = 1
        if p_type == 1 {
            let p_offset = u64::from_le_bytes(kernel_data[ph_start+8..ph_start+16].try_into().unwrap());
            let p_vaddr = u64::from_le_bytes(kernel_data[ph_start+16..ph_start+24].try_into().unwrap());
            let p_paddr = u64::from_le_bytes(kernel_data[ph_start+24..ph_start+32].try_into().unwrap());
            let p_filesz = u64::from_le_bytes(kernel_data[ph_start+32..ph_start+40].try_into().unwrap());
            let p_memsz = u64::from_le_bytes(kernel_data[ph_start+40..ph_start+48].try_into().unwrap());

            info!("LOAD segment: virt={:#x} phys={:#x} offset={:#x} filesz={:#x} memsz={:#x}",
                p_vaddr, p_paddr, p_offset, p_filesz, p_memsz);

            if p_vaddr < load_base_virt {
                load_base_virt = p_vaddr;
            }
            if p_paddr < load_base_phys && p_paddr > 0 {
                load_base_phys = p_paddr;
            }
        }
    }

    // Load each ELF segment to its proper physical address
    let mut max_phys_end: u64 = 0;
    let mut min_phys_start: u64 = u64::MAX;

    for i in 0..e_phnum {
        let ph_start = e_phoff + i * e_phentsize;
        let p_type = u32::from_le_bytes(kernel_data[ph_start..ph_start+4].try_into().unwrap());

        // PT_LOAD = 1
        if p_type == 1 {
            let p_offset = u64::from_le_bytes(kernel_data[ph_start+8..ph_start+16].try_into().unwrap()) as usize;
            let _p_vaddr = u64::from_le_bytes(kernel_data[ph_start+16..ph_start+24].try_into().unwrap());
            let p_paddr = u64::from_le_bytes(kernel_data[ph_start+24..ph_start+32].try_into().unwrap());
            let p_filesz = u64::from_le_bytes(kernel_data[ph_start+32..ph_start+40].try_into().unwrap()) as usize;
            let p_memsz = u64::from_le_bytes(kernel_data[ph_start+40..ph_start+48].try_into().unwrap());

            // Track physical memory range
            if p_paddr < min_phys_start && p_paddr > 0 {
                min_phys_start = p_paddr;
            }
            let phys_end = p_paddr + p_memsz;
            if phys_end > max_phys_end {
                max_phys_end = phys_end;
            }

            // Copy segment data from file to physical memory
            if p_filesz > 0 {
                info!("Loading segment to phys {:#x}, {} bytes from offset {:#x}",
                    p_paddr, p_filesz, p_offset);
                unsafe {
                    let dest = p_paddr as *mut u8;
                    let src = &kernel_data[p_offset..p_offset + p_filesz];
                    core::ptr::copy_nonoverlapping(src.as_ptr(), dest, p_filesz);
                }
            }

            // Zero out any extra memory (BSS)
            if p_memsz as usize > p_filesz {
                let bss_start = p_paddr + p_filesz as u64;
                let bss_size = p_memsz as usize - p_filesz;
                info!("Zeroing BSS at phys {:#x}, {} bytes", bss_start, bss_size);
                unsafe {
                    let dest = bss_start as *mut u8;
                    core::ptr::write_bytes(dest, 0, bss_size);
                }
            }
        }
    }

    // The entry point is the virtual address from the ELF
    // We need to calculate the physical entry point
    let entry_phys = e_entry - KERNEL_VIRTUAL_BASE + min_phys_start;
    info!("Kernel loaded from phys {:#x} to {:#x}", min_phys_start, max_phys_end);
    info!("Entry point: virt={:#x} phys={:#x}", e_entry, entry_phys);

    Ok(LoadedKernel {
        phys_addr: min_phys_start,
        virt_addr: KERNEL_VIRTUAL_BASE,
        size: max_phys_end - min_phys_start,
        entry_offset: entry_phys - min_phys_start,
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
