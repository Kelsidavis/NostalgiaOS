//! 8259 Programmable Interrupt Controller (PIC) Driver
//!
//! The legacy PIC is used for keyboard and other legacy interrupts.
//! Modern systems use the APIC, but the PIC is still needed for
//! PS/2 keyboard support.

use crate::arch::io::{inb, outb};

/// PIC ports
pub mod ports {
    pub const PIC1_COMMAND: u16 = 0x20;
    pub const PIC1_DATA: u16 = 0x21;
    pub const PIC2_COMMAND: u16 = 0xA0;
    pub const PIC2_DATA: u16 = 0xA1;
}

/// PIC commands
pub mod commands {
    pub const EOI: u8 = 0x20;
    pub const ICW1_INIT: u8 = 0x11;
    pub const ICW4_8086: u8 = 0x01;
}

/// IRQ numbers
pub mod irq {
    pub const TIMER: u8 = 0;
    pub const KEYBOARD: u8 = 1;
    pub const CASCADE: u8 = 2;
    pub const COM2: u8 = 3;
    pub const COM1: u8 = 4;
    pub const LPT2: u8 = 5;
    pub const FLOPPY: u8 = 6;
    pub const LPT1: u8 = 7;
    pub const RTC: u8 = 8;
    pub const FREE1: u8 = 9;
    pub const FREE2: u8 = 10;
    pub const FREE3: u8 = 11;
    pub const MOUSE: u8 = 12;
    pub const FPU: u8 = 13;
    pub const PRIMARY_ATA: u8 = 14;
    pub const SECONDARY_ATA: u8 = 15;
}

/// Remap the PIC to use vectors 32-47
/// By default, PIC uses vectors 0-15 which conflict with CPU exceptions
pub unsafe fn remap(offset1: u8, offset2: u8) {
    // Save masks
    let mask1 = inb(ports::PIC1_DATA);
    let mask2 = inb(ports::PIC2_DATA);

    // Start initialization sequence (cascade mode)
    outb(ports::PIC1_COMMAND, commands::ICW1_INIT);
    io_wait();
    outb(ports::PIC2_COMMAND, commands::ICW1_INIT);
    io_wait();

    // Set vector offsets
    outb(ports::PIC1_DATA, offset1); // Master PIC vector offset (32)
    io_wait();
    outb(ports::PIC2_DATA, offset2); // Slave PIC vector offset (40)
    io_wait();

    // Tell Master PIC that Slave PIC is at IRQ2
    outb(ports::PIC1_DATA, 4);
    io_wait();
    // Tell Slave PIC its cascade identity
    outb(ports::PIC2_DATA, 2);
    io_wait();

    // Set 8086 mode
    outb(ports::PIC1_DATA, commands::ICW4_8086);
    io_wait();
    outb(ports::PIC2_DATA, commands::ICW4_8086);
    io_wait();

    // Restore saved masks
    outb(ports::PIC1_DATA, mask1);
    outb(ports::PIC2_DATA, mask2);
}

/// Short delay for PIC operations
fn io_wait() {
    // Write to an unused port for a small delay
    unsafe {
        outb(0x80, 0);
    }
}

/// Send End of Interrupt to the PIC
pub unsafe fn send_eoi(irq: u8) {
    if irq >= 8 {
        // Send EOI to slave PIC
        outb(ports::PIC2_COMMAND, commands::EOI);
    }
    // Always send EOI to master PIC
    outb(ports::PIC1_COMMAND, commands::EOI);
}

/// Set the IRQ mask (1 = disabled, 0 = enabled)
pub unsafe fn set_mask(irq: u8) {
    let port = if irq < 8 {
        ports::PIC1_DATA
    } else {
        ports::PIC2_DATA
    };
    let irq_bit = irq & 7;
    let value = inb(port) | (1 << irq_bit);
    outb(port, value);
}

/// Clear the IRQ mask (enable the interrupt)
pub unsafe fn clear_mask(irq: u8) {
    let port = if irq < 8 {
        ports::PIC1_DATA
    } else {
        ports::PIC2_DATA
    };
    let irq_bit = irq & 7;
    let value = inb(port) & !(1 << irq_bit);
    outb(port, value);
}

/// Disable the PIC (mask all interrupts)
/// Used when switching to APIC
pub unsafe fn disable() {
    outb(ports::PIC1_DATA, 0xFF);
    outb(ports::PIC2_DATA, 0xFF);
}

/// Initialize the PIC for keyboard support
pub fn init() {
    unsafe {
        // Remap PIC to vectors 32-47
        remap(32, 40);

        // Mask all interrupts except keyboard (IRQ1)
        // We use APIC for timer, so mask IRQ0
        outb(ports::PIC1_DATA, 0xFD); // 11111101 - only keyboard enabled
        outb(ports::PIC2_DATA, 0xFF); // All slave interrupts masked
    }

    crate::serial_println!("[PIC] 8259 PIC initialized (keyboard IRQ enabled)");
}

/// Enable mouse IRQ (IRQ12 on slave PIC)
/// Must be called after mouse controller is initialized
pub fn enable_mouse_irq() {
    unsafe {
        // Enable IRQ2 (cascade) on master PIC and IRQ1 (keyboard)
        // 0xF9 = 11111001 - bits 1 (keyboard) and 2 (cascade) enabled
        outb(ports::PIC1_DATA, 0xF9);

        // Enable IRQ12 (mouse) on slave PIC
        // IRQ12 is bit 4 on the slave PIC (IRQ 8-15)
        // 0xEF = 11101111 - bit 4 (IRQ12) enabled
        outb(ports::PIC2_DATA, 0xEF);
    }

    crate::serial_println!("[PIC] Mouse IRQ12 enabled");
}
