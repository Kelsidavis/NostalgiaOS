//! x86_64 Port I/O Operations
//!
//! Provides low-level port I/O for hardware access.
//! Used by device drivers (ATA, PIC, etc.) for register access.

use x86_64::instructions::port::{PortReadOnly, PortWriteOnly};

/// Read a byte from an I/O port
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let mut port = PortReadOnly::new(port);
    port.read()
}

/// Read a word (16-bit) from an I/O port
#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    let mut port: PortReadOnly<u16> = PortReadOnly::new(port);
    port.read()
}

/// Read a dword (32-bit) from an I/O port
#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    let mut port: PortReadOnly<u32> = PortReadOnly::new(port);
    port.read()
}

/// Write a byte to an I/O port
#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    let mut port = PortWriteOnly::new(port);
    port.write(value);
}

/// Write a word (16-bit) to an I/O port
#[inline]
pub unsafe fn outw(port: u16, value: u16) {
    let mut port: PortWriteOnly<u16> = PortWriteOnly::new(port);
    port.write(value);
}

/// Write a dword (32-bit) to an I/O port
#[inline]
pub unsafe fn outl(port: u16, value: u32) {
    let mut port: PortWriteOnly<u32> = PortWriteOnly::new(port);
    port.write(value);
}

/// Read multiple words from an I/O port (REP INSW)
///
/// Used for bulk data transfer from ATA devices
#[inline]
pub unsafe fn insw(port: u16, buf: &mut [u16]) {
    let mut port: PortReadOnly<u16> = PortReadOnly::new(port);
    for word in buf.iter_mut() {
        *word = port.read();
    }
}

/// Write multiple words to an I/O port (REP OUTSW)
///
/// Used for bulk data transfer to ATA devices
#[inline]
pub unsafe fn outsw(port: u16, buf: &[u16]) {
    let mut port: PortWriteOnly<u16> = PortWriteOnly::new(port);
    for &word in buf.iter() {
        port.write(word);
    }
}

/// I/O delay - short delay for slow devices
///
/// Some legacy devices need a small delay between I/O operations.
/// Writing to port 0x80 (POST code port) provides ~1μs delay.
#[inline]
pub unsafe fn io_delay() {
    outb(0x80, 0);
}
