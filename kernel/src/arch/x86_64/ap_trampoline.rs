//! Application Processor (AP) Startup Trampoline
//!
//! This module provides the low-level bootstrap code for starting Application Processors
//! in a multiprocessor system. APs start in 16-bit real mode and must transition through
//! protected mode to reach 64-bit long mode.
//!
//! ## Startup Sequence:
//! 1. BSP copies trampoline code to low memory (< 1MB, typically 0x8000)
//! 2. BSP sends INIT-SIPI-SIPI sequence via APIC
//! 3. AP wakes up at trampoline address in real mode
//! 4. AP enables protected mode
//! 5. AP enables PAE and long mode
//! 6. AP jumps to 64-bit entry point (ap_main)
//!
//! ## Memory Layout:
//! ```text
//! 0x8000: Trampoline code start (16-bit real mode entry)
//! 0x8100: GDT for AP
//! 0x8150: GDT descriptor
//! 0x8158: AP entry point address (64-bit)
//! 0x8160: PML4 physical address
//! 0x9000: AP boot stack (grows down)
//! ```

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};
use core::ptr;

/// Trampoline code location in low memory
pub const TRAMPOLINE_ADDR: u64 = 0x8000;

/// GDT location in low memory
const TRAMPOLINE_GDT: u64 = 0x8100;

/// GDT descriptor location
const TRAMPOLINE_GDT_DESC: u64 = 0x8150;

/// AP entry point address location
const TRAMPOLINE_ENTRY_ADDR: u64 = 0x8158;

/// PML4 address location
const TRAMPOLINE_PML4_ADDR: u64 = 0x8160;

/// Stack location for AP startup (grows down from here)
const AP_BOOT_STACK: u64 = 0x9000;

/// Number of APs that have successfully started
pub static AP_STARTED_COUNT: AtomicU32 = AtomicU32::new(0);

/// AP startup trampoline - compiled machine code
/// This code starts at 0x8000 in 16-bit real mode
///
/// The trampoline:
/// 1. Disables interrupts
/// 2. Sets up real mode segments
/// 3. Loads GDT (at 0x8150)
/// 4. Enables protected mode (CR0.PE)
/// 5. Far jump to 32-bit code
/// 6. Enables PAE (CR4.PAE)
/// 7. Loads PML4 (from 0x8160)
/// 8. Enables long mode (EFER.LME)
/// 9. Enables paging (CR0.PG)
/// 10. Far jump to 64-bit code
/// 11. Sets up 64-bit segments and stack
/// 12. Jumps to ap_main (address at 0x8158)
#[rustfmt::skip]
static TRAMPOLINE_CODE: [u8; 135] = [
    // 0x8000: 16-bit real mode entry
    0xFA,                               // cli
    0x31, 0xC0,                         // xor ax, ax
    0x8E, 0xD8,                         // mov ds, ax
    0x8E, 0xC0,                         // mov es, ax
    0x8E, 0xD0,                         // mov ss, ax

    // Load GDT (descriptor at 0x8150)
    0x0F, 0x01, 0x16, 0x50, 0x81,       // lgdt [0x8150]

    // Enable protected mode (CR0.PE = 1)
    0x0F, 0x20, 0xC0,                   // mov eax, cr0
    0x0C, 0x01,                         // or al, 1
    0x0F, 0x22, 0xC0,                   // mov cr0, eax

    // Far jump to protected mode (selector 0x08, offset 0x8020)
    0x66, 0xEA, 0x20, 0x80, 0x00, 0x00, 0x08, 0x00,  // ljmp $0x08, $0x8020

    // 0x8020: 32-bit protected mode
    0xB8, 0x10, 0x00, 0x00, 0x00,       // mov eax, 0x10 (data selector)
    0x8E, 0xD8,                         // mov ds, ax
    0x8E, 0xC0,                         // mov es, ax
    0x8E, 0xE0,                         // mov fs, ax
    0x8E, 0xE8,                         // mov gs, ax
    0x8E, 0xD0,                         // mov ss, ax

    // Enable PAE (CR4.PAE = 1)
    0x0F, 0x20, 0xE0,                   // mov eax, cr4
    0x0D, 0x20, 0x00, 0x00, 0x00,       // or eax, 0x20
    0x0F, 0x22, 0xE0,                   // mov cr4, eax

    // Load PML4 from 0x8160
    0x8B, 0x05, 0x60, 0x81, 0x00, 0x00, // mov eax, [0x8160]
    0x0F, 0x22, 0xD8,                   // mov cr3, eax

    // Enable long mode (EFER.LME = 1)
    0xB9, 0x80, 0x00, 0x00, 0xC0,       // mov ecx, 0xC0000080
    0x0F, 0x32,                         // rdmsr
    0x0D, 0x00, 0x01, 0x00, 0x00,       // or eax, 0x100
    0x0F, 0x30,                         // wrmsr

    // Enable paging (CR0.PG = 1)
    0x0F, 0x20, 0xC0,                   // mov eax, cr0
    0x0D, 0x00, 0x00, 0x00, 0x80,       // or eax, 0x80000000
    0x0F, 0x22, 0xC0,                   // mov cr0, eax

    // Far jump to long mode (selector 0x18, offset 0x8060)
    0xEA, 0x60, 0x80, 0x00, 0x00, 0x18, 0x00,  // ljmp $0x18, $0x8060

    // 0x8060: 64-bit long mode
    0xB8, 0x20, 0x00, 0x00, 0x00,       // mov eax, 0x20 (64-bit data)
    0x8E, 0xD8,                         // mov ds, ax
    0x8E, 0xC0,                         // mov es, ax
    0x8E, 0xE0,                         // mov fs, ax
    0x8E, 0xE8,                         // mov gs, ax
    0x8E, 0xD0,                         // mov ss, ax

    // Set up stack (rsp = 0x9000)
    0x48, 0xBC, 0x00, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rsp, 0x9000

    // Call ap_main (address at 0x8158)
    0x48, 0x8B, 0x04, 0x25, 0x58, 0x81, 0x00, 0x00,  // mov rax, [0x8158]
    0xFF, 0xD0,                         // call rax

    // Halt loop (should never reach)
    0xF4,                               // hlt
    0xEB, 0xFD,                         // jmp -3
];

/// GDT entries for AP trampoline
/// 5 entries: null, 32-bit code, 32-bit data, 64-bit code, 64-bit data
#[rustfmt::skip]
static TRAMPOLINE_GDT_ENTRIES: [u64; 5] = [
    // Entry 0: Null descriptor
    0x0000000000000000,

    // Entry 1 (0x08): 32-bit code segment
    // Base=0, Limit=0xFFFFF, Access=0x9A (P=1, DPL=0, Code, Exec, Read), Flags=0xCF (G=1, D=1)
    0x00CF9A000000FFFF,

    // Entry 2 (0x10): 32-bit data segment
    // Base=0, Limit=0xFFFFF, Access=0x92 (P=1, DPL=0, Data, Write), Flags=0xCF
    0x00CF92000000FFFF,

    // Entry 3 (0x18): 64-bit code segment
    // Access=0x9A (P=1, DPL=0, Code, Exec, Read), Flags=0xAF (L=1, D=0)
    0x00AF9A000000FFFF,

    // Entry 4 (0x20): 64-bit data segment
    // Access=0x92 (P=1, DPL=0, Data, Write)
    0x0000920000000000,
];

/// Copy trampoline code to low memory and set up GDT
///
/// # Safety
/// Must be called before starting APs. Writes to low memory at 0x8000-0x9000.
/// Requires that low memory is identity-mapped.
pub unsafe fn setup_trampoline() {
    crate::serial_println!("[AP] Setting up AP trampoline at {:#x}", TRAMPOLINE_ADDR);

    // Copy trampoline code to 0x8000
    let trampoline_ptr = TRAMPOLINE_ADDR as *mut u8;
    ptr::copy_nonoverlapping(
        TRAMPOLINE_CODE.as_ptr(),
        trampoline_ptr,
        TRAMPOLINE_CODE.len(),
    );

    // Copy GDT to 0x8100
    let gdt_ptr = TRAMPOLINE_GDT as *mut u64;
    for (i, entry) in TRAMPOLINE_GDT_ENTRIES.iter().enumerate() {
        ptr::write_volatile(gdt_ptr.add(i), *entry);
    }

    // Set up GDT descriptor at 0x8150
    // Format: 2-byte limit, 4-byte base (for 16/32-bit mode)
    // Note: The base is at offset +2, which is NOT 4-byte aligned,
    // so we must use write_unaligned for the 32-bit base write
    let gdt_desc_ptr = TRAMPOLINE_GDT_DESC as *mut u8;
    let gdt_limit: u16 = (TRAMPOLINE_GDT_ENTRIES.len() * 8 - 1) as u16;
    let gdt_base: u32 = TRAMPOLINE_GDT as u32;

    ptr::write_volatile(gdt_desc_ptr as *mut u16, gdt_limit);
    ptr::write_unaligned((gdt_desc_ptr.add(2)) as *mut u32, gdt_base);

    // Store AP entry point address at 0x8158
    let entry_ptr = TRAMPOLINE_ENTRY_ADDR as *mut u64;
    ptr::write_volatile(entry_ptr, ap_main as *const () as u64);

    // Store PML4 physical address at 0x8160
    // Read CR3 to get the current page table
    let pml4: u64;
    asm!("mov {}, cr3", out(reg) pml4, options(nomem, nostack, preserves_flags));
    let pml4_ptr = TRAMPOLINE_PML4_ADDR as *mut u32;
    ptr::write_volatile(pml4_ptr, pml4 as u32);

    crate::serial_println!("[AP] Trampoline code: {} bytes at {:#x}", TRAMPOLINE_CODE.len(), TRAMPOLINE_ADDR);
    crate::serial_println!("[AP] GDT at {:#x}, {} entries", TRAMPOLINE_GDT, TRAMPOLINE_GDT_ENTRIES.len());
    crate::serial_println!("[AP] Entry point: {:#x}", ap_main as *const () as u64);
    crate::serial_println!("[AP] PML4 at: {:#x}", pml4);
}

/// Get the physical address of the ap_main function
///
/// This is stored at a known location for the trampoline to jump to
pub fn get_ap_entry_point() -> u64 {
    ap_main as *const () as u64
}

/// Application Processor entry point (64-bit long mode)
///
/// This function is called by each AP after it completes the trampoline
/// and enters 64-bit mode. It initializes per-CPU structures and enters
/// the idle loop.
///
/// # Safety
/// Called from assembly trampoline code
pub unsafe extern "C" fn ap_main() -> ! {
    // Get the current CPU ID from APIC
    let cpu_id = crate::arch::x86_64::percpu::get_cpu_id();

    crate::serial_println!("[AP{}] Starting...", cpu_id);

    // Initialize this CPU's PRCB and set GS base
    crate::ke::prcb::init_prcb(cpu_id);

    // Initialize this CPU's KPCR (Processor Control Region)
    let prcb = crate::ke::prcb::ki_get_processor_block(cpu_id);
    crate::ke::kpcr::init_kpcr(cpu_id, prcb);

    // Lower IRQL to PASSIVE_LEVEL
    crate::ke::kpcr::ke_lower_irql(crate::ke::kpcr::irql::PASSIVE_LEVEL);

    // Initialize this CPU's idle thread
    crate::ke::idle::init_idle_thread(cpu_id);

    // Initialize Local APIC for this CPU
    crate::hal::apic::init();

    // Start APIC timer for this CPU
    crate::hal::apic::start_timer(
        crate::arch::x86_64::idt::vector::TIMER,
        1000, // 1kHz
    );

    // Increment active CPU count
    crate::ke::prcb::increment_active_cpu_count();

    // Signal that this AP has started
    AP_STARTED_COUNT.fetch_add(1, Ordering::SeqCst);

    crate::serial_println!("[AP{}] KPRCB and KPCR initialized", cpu_id);
    crate::serial_println!("[AP{}] Initialization complete, entering idle loop", cpu_id);

    // Enter the idle loop - this never returns
    loop {
        asm!(
            "sti",  // Enable interrupts
            "hlt",  // Halt until interrupt
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Wait for a specific number of APs to start
///
/// # Arguments
/// * `expected_count` - Number of APs to wait for
/// * `timeout_ms` - Timeout in milliseconds (0 = infinite)
///
/// Returns true if all APs started, false if timeout
pub fn wait_for_aps(expected_count: u32, timeout_ms: u32) -> bool {
    // SAFETY: TICK_COUNT is an atomic, safe to read
    let start_ticks = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed);

    loop {
        let started = AP_STARTED_COUNT.load(Ordering::Acquire);
        if started >= expected_count {
            return true;
        }

        if timeout_ms > 0 {
            // SAFETY: TICK_COUNT is an atomic, safe to read
            let elapsed_ticks = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed) - start_ticks;
            if elapsed_ticks > timeout_ms as u64 {
                return false;
            }
        }

        // Spin-wait with hint
        core::hint::spin_loop();
    }
}

/// Reset the AP started counter (for testing)
pub fn reset_ap_count() {
    AP_STARTED_COUNT.store(0, Ordering::SeqCst);
}
