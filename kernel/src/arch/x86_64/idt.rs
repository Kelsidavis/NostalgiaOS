//! Interrupt Descriptor Table (IDT)
//!
//! The IDT defines handlers for:
//! - CPU exceptions (divide error, page fault, etc.)
//! - Hardware interrupts (timer, keyboard, etc.)
//! - Software interrupts (system calls)
//!
//! NT IRQL (Interrupt Request Level) concept is implemented on top of this:
//! - PASSIVE_LEVEL (0): Normal thread execution
//! - APC_LEVEL (1): APC delivery
//! - DISPATCH_LEVEL (2): DPC execution, scheduler
//! - Device IRQLs (3-26): Hardware interrupts
//! - HIGH_LEVEL (31): Clock, IPI, power fail

use core::sync::atomic::Ordering;
use spin::Lazy;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use super::gdt;
use crate::hal::apic;

/// Interrupt vector numbers
pub mod vector {
    pub const TIMER: u8 = 32;
    pub const KEYBOARD: u8 = 33;
    pub const TLB_SHOOTDOWN: u8 = 0xFE;
    pub const SPURIOUS: u8 = 0xFF;
}

/// IDT with all handlers registered
static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();

    // CPU Exceptions
    idt.divide_error.set_handler_fn(divide_error_handler);
    idt.debug.set_handler_fn(debug_handler);
    idt.non_maskable_interrupt.set_handler_fn(nmi_handler);
    idt.breakpoint.set_handler_fn(breakpoint_handler);
    idt.overflow.set_handler_fn(overflow_handler);
    idt.bound_range_exceeded.set_handler_fn(bound_range_handler);
    idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
    idt.device_not_available.set_handler_fn(device_not_available_handler);

    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
    }

    idt.invalid_tss.set_handler_fn(invalid_tss_handler);
    idt.segment_not_present.set_handler_fn(segment_not_present_handler);
    idt.stack_segment_fault.set_handler_fn(stack_segment_fault_handler);

    unsafe {
        idt.general_protection_fault
            .set_handler_fn(general_protection_fault_handler)
            .set_stack_index(gdt::GPF_IST_INDEX);
    }

    unsafe {
        idt.page_fault
            .set_handler_fn(page_fault_handler)
            .set_stack_index(gdt::PAGE_FAULT_IST_INDEX);
    }

    idt.x87_floating_point.set_handler_fn(x87_floating_point_handler);
    idt.alignment_check.set_handler_fn(alignment_check_handler);
    idt.machine_check.set_handler_fn(machine_check_handler);
    idt.simd_floating_point.set_handler_fn(simd_floating_point_handler);
    idt.virtualization.set_handler_fn(virtualization_handler);

    // Hardware interrupt handlers (vectors 32-255)
    // Timer interrupt (vector 32) - connected to APIC timer
    idt[vector::TIMER].set_handler_fn(timer_interrupt_handler);

    // Keyboard interrupt (vector 33) - PS/2 keyboard
    idt[vector::KEYBOARD].set_handler_fn(keyboard_interrupt_handler);

    // TLB shootdown IPI handler (vector 0xFE)
    idt[vector::TLB_SHOOTDOWN].set_handler_fn(tlb_shootdown_ipi_handler);

    // Spurious interrupt handler
    idt[vector::SPURIOUS].set_handler_fn(spurious_interrupt_handler);

    idt
});

/// Initialize the IDT
pub fn init() {
    IDT.load();
}

// Exception Handlers

extern "x86-interrupt" fn divide_error_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: DIVIDE ERROR\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn debug_handler(stack_frame: InterruptStackFrame) {
    // Debug exceptions can be continued
    let _ = stack_frame;
}

extern "x86-interrupt" fn nmi_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: NMI\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    // Breakpoint - typically used for debugging
    let _ = stack_frame;
}

extern "x86-interrupt" fn overflow_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: OVERFLOW\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn bound_range_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: BOUND RANGE EXCEEDED\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: INVALID OPCODE\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn device_not_available_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: DEVICE NOT AVAILABLE\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    panic!(
        "EXCEPTION: DOUBLE FAULT (error code: {})\n{:#?}",
        error_code, stack_frame
    );
}

extern "x86-interrupt" fn invalid_tss_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    panic!(
        "EXCEPTION: INVALID TSS (error code: {})\n{:#?}",
        error_code, stack_frame
    );
}

extern "x86-interrupt" fn segment_not_present_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    panic!(
        "EXCEPTION: SEGMENT NOT PRESENT (error code: {})\n{:#?}",
        error_code, stack_frame
    );
}

extern "x86-interrupt" fn stack_segment_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    panic!(
        "EXCEPTION: STACK SEGMENT FAULT (error code: {})\n{:#?}",
        error_code, stack_frame
    );
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    panic!(
        "EXCEPTION: GENERAL PROTECTION FAULT (error code: {})\n{:#?}",
        error_code, stack_frame
    );
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;

    let faulting_address = Cr2::read();

    panic!(
        "EXCEPTION: PAGE FAULT\n\
        Accessed Address: {:?}\n\
        Error Code: {:?}\n\
        {:#?}",
        faulting_address, error_code, stack_frame
    );
}

extern "x86-interrupt" fn x87_floating_point_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: X87 FLOATING POINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn alignment_check_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    panic!(
        "EXCEPTION: ALIGNMENT CHECK (error code: {})\n{:#?}",
        error_code, stack_frame
    );
}

extern "x86-interrupt" fn machine_check_handler(stack_frame: InterruptStackFrame) -> ! {
    panic!("EXCEPTION: MACHINE CHECK\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn simd_floating_point_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: SIMD FLOATING POINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn virtualization_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: VIRTUALIZATION\n{:#?}", stack_frame);
}

// Hardware Interrupt Handlers

/// Timer interrupt handler (vector 32)
/// Called by APIC timer at configured frequency (typically 1000Hz)
extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    // Increment system tick counter
    let ticks = apic::TICK_COUNT.fetch_add(1, Ordering::Relaxed);

    // Debug: print tick count every second (first few seconds)
    if ticks < 5 && ticks > 0 {
        // Can't print inside interrupt easily, but this helps debug
    }

    // Send End of Interrupt to APIC
    apic::eoi();

    // Process expired timers
    unsafe {
        crate::ke::timer::ki_expire_timers();
    }

    // Call scheduler to handle quantum expiration
    unsafe {
        crate::ke::scheduler::ki_quantum_end();

        // Retire any pending DPCs (including timer DPCs)
        // This runs at DISPATCH_LEVEL equivalent
        crate::ke::dpc::ki_retire_dpc_list();
    }
}

/// Keyboard interrupt handler (vector 33)
/// Called when a key is pressed or released
extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    // Handle the keyboard interrupt
    crate::hal::keyboard::handle_interrupt();

    // Send End of Interrupt to PIC (keyboard uses legacy PIC on IRQ1)
    // For PIC, we need to send EOI to the master PIC at port 0x20
    unsafe {
        crate::arch::io::outb(0x20, 0x20);
    }
}

/// TLB shootdown IPI handler (vector 0xFE)
/// Called when this CPU receives a TLB shootdown request from another CPU
extern "x86-interrupt" fn tlb_shootdown_ipi_handler(_stack_frame: InterruptStackFrame) {
    // Call the TLB shootdown handler in mm::tlb
    unsafe {
        crate::mm::tlb_shootdown_handler();
    }
    // EOI is sent by the handler
}

/// Spurious interrupt handler (vector 0xFF)
/// These occur when an interrupt is no longer pending when the CPU
/// tries to handle it. Just ignore them.
extern "x86-interrupt" fn spurious_interrupt_handler(_stack_frame: InterruptStackFrame) {
    // Spurious interrupts should NOT send EOI
    // Just return - no action needed
}
