//! Serial port output for debugging
//!
//! Outputs to COM1 (0x3F8) for QEMU serial console.

use core::fmt::{self, Write};

/// COM1 port address
const COM1: u16 = 0x3F8;

/// Serial port writer
pub struct SerialWriter;

impl SerialWriter {
    /// Write a byte to COM1
    fn write_byte(&mut self, byte: u8) {
        unsafe {
            // Wait for transmit buffer to be empty
            while (port_read(COM1 + 5) & 0x20) == 0 {}
            // Write the byte
            port_write(COM1, byte);
        }
    }
}

impl Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
        Ok(())
    }
}

/// Initialize the serial port
pub fn init() {
    unsafe {
        // Disable interrupts
        port_write(COM1 + 1, 0x00);
        // Enable DLAB (set baud rate divisor)
        port_write(COM1 + 3, 0x80);
        // Set divisor to 1 (115200 baud)
        port_write(COM1 + 0, 0x01);
        port_write(COM1 + 1, 0x00);
        // 8 bits, no parity, one stop bit
        port_write(COM1 + 3, 0x03);
        // Enable FIFO, clear them, with 14-byte threshold
        port_write(COM1 + 2, 0xC7);
        // IRQs enabled, RTS/DSR set
        port_write(COM1 + 4, 0x0B);
    }
}

/// Print to serial port
pub fn serial_print(args: fmt::Arguments) {
    let mut writer = SerialWriter;
    writer.write_fmt(args).unwrap();
}

/// Print macro for serial output
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => ($crate::serial::serial_print(format_args!($($arg)*)));
}

/// Print with newline macro for serial output
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)));
}

/// Read from I/O port
#[inline]
unsafe fn port_read(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!(
        "in al, dx",
        out("al") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
    value
}

/// Write to I/O port
#[inline]
unsafe fn port_write(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}
