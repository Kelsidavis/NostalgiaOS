//! x86_64 architecture support
//!
//! This module provides low-level CPU and hardware support for x86_64:
//!
//! - GDT (Global Descriptor Table) setup
//! - IDT (Interrupt Descriptor Table) and interrupt handlers
//! - Paging (4-level page tables)
//! - APIC (Advanced Programmable Interrupt Controller)
//! - Context switching
//! - System call handling (SYSCALL/SYSRET)

pub mod gdt;
pub mod idt;
pub mod context;
pub mod io;
pub mod syscall;
pub mod percpu;
pub mod ap_trampoline;

// Re-export key context types for user-mode support
pub use context::{KTrapFrame, UserContext, ProcessorMode};
pub use context::{setup_user_thread_context, ki_return_to_user};

use x86_64::instructions::{hlt, interrupts};

/// Phase 0 architecture initialization
///
/// Called early in boot with interrupts disabled.
/// Sets up GDT, IDT, and basic CPU state.
pub fn init_phase0() {
    // Initialize GDT with kernel code/data segments and TSS
    gdt::init();

    // Initialize IDT with interrupt handlers
    idt::init();

    // Initialize SYSCALL/SYSRET support
    unsafe {
        syscall::init();
    }

    // TODO: Initialize paging structures
    // TODO: Initialize LAPIC
}

/// Enable interrupts
#[inline]
pub fn enable_interrupts() {
    interrupts::enable();
}

/// Disable interrupts
#[inline]
pub fn disable_interrupts() {
    interrupts::disable();
}

/// Check if interrupts are enabled
#[inline]
pub fn interrupts_enabled() -> bool {
    interrupts::are_enabled()
}

/// Halt the CPU until the next interrupt
#[inline]
pub fn halt() {
    hlt();
}

/// Execute a function with interrupts disabled
#[inline]
pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    interrupts::without_interrupts(f)
}
