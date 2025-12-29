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
//! ```
//! 0x8000: Trampoline code start (16-bit)
//! 0x8200: GDT
//! 0x8300: Page tables (PML4, PDPT, PD)
//! 0x9000: Stack (grows down)
//! ```

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

/// Trampoline code location in low memory
pub const TRAMPOLINE_ADDR: u64 = 0x8000;

/// Stack location for AP startup (grows down from here)
const AP_BOOT_STACK: u64 = 0x9000;

/// Number of APs that have successfully started
pub static AP_STARTED_COUNT: AtomicU32 = AtomicU32::new(0);

/// Trampoline code (will be copied to low memory)
///
/// This is the actual 16-bit code that executes when an AP starts.
/// It's defined in assembly and linked into the kernel.
///
/// TODO: Implement build.rs to properly compile ap_trampoline.S
/// For now, this is a placeholder.
// extern "C" {
//     static ap_trampoline_start: u8;
//     static ap_trampoline_end: u8;
// }

/// Copy trampoline code to low memory
///
/// # Safety
/// Must be called before starting APs. Writes to low memory.
pub unsafe fn setup_trampoline() {
    // TODO: Implement proper trampoline code copying
    // This requires building ap_trampoline.S via build.rs
    crate::serial_println!("[AP] Trampoline setup (TODO: implement assembly build)");
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
