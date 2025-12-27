//! Serial port output for debugging
//!
//! Outputs to COM1 (0x3F8) for QEMU serial console.

use core::fmt::{self, Write};
use spin::Mutex;

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

/// Global serial writer (already initialized by bootloader)
static WRITER: Mutex<SerialWriter> = Mutex::new(SerialWriter);

/// Print to serial port
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    WRITER.lock().write_fmt(args).unwrap();
}

/// Print macro for serial output
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => ($crate::serial::_print(format_args!($($arg)*)));
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

/// Write a single character directly to serial (for early debugging)
/// Bypasses mutex and formatting - minimal code path
#[inline(never)]
pub fn early_putc(c: u8) {
    unsafe {
        // Wait for transmit buffer to be empty
        while (port_read(COM1 + 5) & 0x20) == 0 {}
        // Write the byte
        port_write(COM1, c);
    }
}

/// Write a string directly to serial (for early debugging)
#[inline(never)]
pub fn early_puts(s: &[u8]) {
    for &c in s {
        if c == b'\n' {
            early_putc(b'\r');
        }
        early_putc(c);
    }
}
