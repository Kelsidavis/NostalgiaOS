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
    // SMP IPIs (high vectors)
    pub const IPI_STOP: u8 = 0xFC;
    pub const IPI_RESCHEDULE: u8 = 0xFD;
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

    // SMP IPI handlers
    idt[vector::IPI_STOP].set_handler_fn(ipi_stop_handler);
    idt[vector::IPI_RESCHEDULE].set_handler_fn(ipi_reschedule_handler);
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

    let faulting_address = Cr2::read().unwrap_or(x86_64::VirtAddr::zero());
    let fault_addr_u64 = faulting_address.as_u64();

    // Parse error code to determine access type
    let is_write = error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE);
    let is_user = error_code.contains(PageFaultErrorCode::USER_MODE);
    let is_protection_violation = error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION);
    let is_instruction_fetch = error_code.contains(PageFaultErrorCode::INSTRUCTION_FETCH);

    // Try to handle the fault through the memory manager
    unsafe {
        // Get the current address space
        let aspace = crate::mm::mm_get_system_address_space();

        // Attempt to resolve the page fault
        if crate::mm::mm_access_fault(aspace, fault_addr_u64, is_write, is_user) {
            // Fault was successfully handled - return to continue execution
            return;
        }
    }

    // Fault could not be handled - this is a real fault
    // Generate appropriate error based on context
    let fault_type = if is_protection_violation {
        if is_write {
            "WRITE ACCESS VIOLATION"
        } else if is_instruction_fetch {
            "INSTRUCTION FETCH VIOLATION"
        } else {
            "READ ACCESS VIOLATION"
        }
    } else {
        "PAGE NOT PRESENT"
    };

    let mode = if is_user { "USER MODE" } else { "KERNEL MODE" };

    panic!(
        "EXCEPTION: PAGE FAULT ({})\n\
        Fault Type:      {}\n\
        Access Mode:     {}\n\
        Faulting Address: 0x{:016x}\n\
        Error Code:      {:?}\n\
        Instruction Ptr: 0x{:016x}\n\
        Stack Pointer:   0x{:016x}\n\
        Code Segment:    0x{:04x}\n\
        Stack Segment:   0x{:04x}\n\
        CPU Flags:       0x{:016x}",
        if is_user { "USER" } else { "KERNEL" },
        fault_type,
        mode,
        fault_addr_u64,
        error_code,
        stack_frame.instruction_pointer.as_u64(),
        stack_frame.stack_pointer.as_u64(),
        stack_frame.code_segment.0,
        stack_frame.stack_segment.0,
        stack_frame.cpu_flags
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
    // Increment statistics counter
    INTERRUPT_STATS.timer.fetch_add(1, Ordering::Relaxed);

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
    // Increment statistics counter
    INTERRUPT_STATS.keyboard.fetch_add(1, Ordering::Relaxed);

    // Handle the keyboard interrupt
    crate::hal::keyboard::handle_interrupt();

    // Send End of Interrupt to PIC (keyboard uses legacy PIC on IRQ1)
    // For PIC, we need to send EOI to the master PIC at port 0x20
    unsafe {
        crate::arch::io::outb(0x20, 0x20);
    }
}

/// IPI STOP handler (vector 0xFC)
/// Halts this CPU immediately (for shutdown or panic)
extern "x86-interrupt" fn ipi_stop_handler(_stack_frame: InterruptStackFrame) {
    // Increment statistics counter
    INTERRUPT_STATS.ipi_stop.fetch_add(1, Ordering::Relaxed);

    // Log that we're stopping
    crate::serial_println!("[IPI] CPU {} received STOP IPI - halting", unsafe {
        crate::arch::x86_64::percpu::get_cpu_id()
    });

    // Send EOI before halting
    apic::eoi();

    // Halt this CPU forever
    loop {
        unsafe {
            core::arch::asm!("cli", "hlt");
        }
    }
}

/// IPI RESCHEDULE handler (vector 0xFD)
/// Forces this CPU to run the scheduler immediately
extern "x86-interrupt" fn ipi_reschedule_handler(_stack_frame: InterruptStackFrame) {
    // Increment statistics counter
    INTERRUPT_STATS.ipi_reschedule.fetch_add(1, Ordering::Relaxed);

    // Send EOI first
    apic::eoi();

    // Force a reschedule by calling the dispatcher
    // This will select the highest priority ready thread
    unsafe {
        crate::ke::scheduler::ki_dispatch_interrupt();
    }
}

/// TLB shootdown IPI handler (vector 0xFE)
/// Called when this CPU receives a TLB shootdown request from another CPU
extern "x86-interrupt" fn tlb_shootdown_ipi_handler(_stack_frame: InterruptStackFrame) {
    // Increment statistics counter
    INTERRUPT_STATS.tlb_shootdown.fetch_add(1, Ordering::Relaxed);

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
    // But track the count
    INTERRUPT_STATS.spurious.fetch_add(1, Ordering::Relaxed);
}

// =============================================================================
// Interrupt Statistics Tracking
// =============================================================================

use core::sync::atomic::AtomicU64;

/// Statistics counters for interrupts and exceptions
pub struct InterruptStats {
    // CPU Exceptions (vectors 0-31)
    pub divide_error: AtomicU64,
    pub debug: AtomicU64,
    pub nmi: AtomicU64,
    pub breakpoint: AtomicU64,
    pub overflow: AtomicU64,
    pub bound_range: AtomicU64,
    pub invalid_opcode: AtomicU64,
    pub device_not_available: AtomicU64,
    pub double_fault: AtomicU64,
    pub invalid_tss: AtomicU64,
    pub segment_not_present: AtomicU64,
    pub stack_segment_fault: AtomicU64,
    pub general_protection: AtomicU64,
    pub page_fault: AtomicU64,
    pub x87_fp: AtomicU64,
    pub alignment_check: AtomicU64,
    pub machine_check: AtomicU64,
    pub simd_fp: AtomicU64,
    pub virtualization: AtomicU64,

    // Hardware Interrupts
    pub timer: AtomicU64,
    pub keyboard: AtomicU64,

    // IPIs
    pub ipi_stop: AtomicU64,
    pub ipi_reschedule: AtomicU64,
    pub tlb_shootdown: AtomicU64,
    pub spurious: AtomicU64,

    // Generic counters for other vectors
    pub other_exceptions: AtomicU64,
    pub other_interrupts: AtomicU64,
}

impl InterruptStats {
    pub const fn new() -> Self {
        Self {
            divide_error: AtomicU64::new(0),
            debug: AtomicU64::new(0),
            nmi: AtomicU64::new(0),
            breakpoint: AtomicU64::new(0),
            overflow: AtomicU64::new(0),
            bound_range: AtomicU64::new(0),
            invalid_opcode: AtomicU64::new(0),
            device_not_available: AtomicU64::new(0),
            double_fault: AtomicU64::new(0),
            invalid_tss: AtomicU64::new(0),
            segment_not_present: AtomicU64::new(0),
            stack_segment_fault: AtomicU64::new(0),
            general_protection: AtomicU64::new(0),
            page_fault: AtomicU64::new(0),
            x87_fp: AtomicU64::new(0),
            alignment_check: AtomicU64::new(0),
            machine_check: AtomicU64::new(0),
            simd_fp: AtomicU64::new(0),
            virtualization: AtomicU64::new(0),
            timer: AtomicU64::new(0),
            keyboard: AtomicU64::new(0),
            ipi_stop: AtomicU64::new(0),
            ipi_reschedule: AtomicU64::new(0),
            tlb_shootdown: AtomicU64::new(0),
            spurious: AtomicU64::new(0),
            other_exceptions: AtomicU64::new(0),
            other_interrupts: AtomicU64::new(0),
        }
    }

    /// Get total exception count
    pub fn total_exceptions(&self) -> u64 {
        self.divide_error.load(Ordering::Relaxed)
            + self.debug.load(Ordering::Relaxed)
            + self.nmi.load(Ordering::Relaxed)
            + self.breakpoint.load(Ordering::Relaxed)
            + self.overflow.load(Ordering::Relaxed)
            + self.bound_range.load(Ordering::Relaxed)
            + self.invalid_opcode.load(Ordering::Relaxed)
            + self.device_not_available.load(Ordering::Relaxed)
            + self.double_fault.load(Ordering::Relaxed)
            + self.invalid_tss.load(Ordering::Relaxed)
            + self.segment_not_present.load(Ordering::Relaxed)
            + self.stack_segment_fault.load(Ordering::Relaxed)
            + self.general_protection.load(Ordering::Relaxed)
            + self.page_fault.load(Ordering::Relaxed)
            + self.x87_fp.load(Ordering::Relaxed)
            + self.alignment_check.load(Ordering::Relaxed)
            + self.machine_check.load(Ordering::Relaxed)
            + self.simd_fp.load(Ordering::Relaxed)
            + self.virtualization.load(Ordering::Relaxed)
            + self.other_exceptions.load(Ordering::Relaxed)
    }

    /// Get total interrupt count
    pub fn total_interrupts(&self) -> u64 {
        self.timer.load(Ordering::Relaxed)
            + self.keyboard.load(Ordering::Relaxed)
            + self.ipi_stop.load(Ordering::Relaxed)
            + self.ipi_reschedule.load(Ordering::Relaxed)
            + self.tlb_shootdown.load(Ordering::Relaxed)
            + self.spurious.load(Ordering::Relaxed)
            + self.other_interrupts.load(Ordering::Relaxed)
    }

    /// Clear all statistics
    pub fn clear(&self) {
        self.divide_error.store(0, Ordering::Relaxed);
        self.debug.store(0, Ordering::Relaxed);
        self.nmi.store(0, Ordering::Relaxed);
        self.breakpoint.store(0, Ordering::Relaxed);
        self.overflow.store(0, Ordering::Relaxed);
        self.bound_range.store(0, Ordering::Relaxed);
        self.invalid_opcode.store(0, Ordering::Relaxed);
        self.device_not_available.store(0, Ordering::Relaxed);
        self.double_fault.store(0, Ordering::Relaxed);
        self.invalid_tss.store(0, Ordering::Relaxed);
        self.segment_not_present.store(0, Ordering::Relaxed);
        self.stack_segment_fault.store(0, Ordering::Relaxed);
        self.general_protection.store(0, Ordering::Relaxed);
        self.page_fault.store(0, Ordering::Relaxed);
        self.x87_fp.store(0, Ordering::Relaxed);
        self.alignment_check.store(0, Ordering::Relaxed);
        self.machine_check.store(0, Ordering::Relaxed);
        self.simd_fp.store(0, Ordering::Relaxed);
        self.virtualization.store(0, Ordering::Relaxed);
        self.timer.store(0, Ordering::Relaxed);
        self.keyboard.store(0, Ordering::Relaxed);
        self.ipi_stop.store(0, Ordering::Relaxed);
        self.ipi_reschedule.store(0, Ordering::Relaxed);
        self.tlb_shootdown.store(0, Ordering::Relaxed);
        self.spurious.store(0, Ordering::Relaxed);
        self.other_exceptions.store(0, Ordering::Relaxed);
        self.other_interrupts.store(0, Ordering::Relaxed);
    }
}

/// Global interrupt statistics
pub static INTERRUPT_STATS: InterruptStats = InterruptStats::new();

/// Get a reference to the interrupt statistics
pub fn get_interrupt_stats() -> &'static InterruptStats {
    &INTERRUPT_STATS
}
