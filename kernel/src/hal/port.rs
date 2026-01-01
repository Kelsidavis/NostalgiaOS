//! I/O Port Access
//!
//! Provides abstraction for x86 I/O port access:
//!
//! - **Input**: Read from I/O ports (INB, INW, INL)
//! - **Output**: Write to I/O ports (OUTB, OUTW, OUTL)
//! - **String I/O**: Block I/O operations (INSB, OUTSB, etc.)
//! - **Delayed I/O**: For slow devices requiring timing gaps
//!
//! # Port Ranges
//!
//! Standard I/O port ranges:
//! - 0x000-0x01F: DMA Controller 1
//! - 0x020-0x03F: PIC 1
//! - 0x040-0x05F: PIT (Timer)
//! - 0x060-0x06F: Keyboard Controller
//! - 0x070-0x07F: CMOS/RTC
//! - 0x080-0x09F: DMA Page Registers
//! - 0x0A0-0x0BF: PIC 2
//! - 0x0C0-0x0DF: DMA Controller 2
//! - 0x0CF8-0x0CFF: PCI Configuration
//! - 0x1F0-0x1F7: Primary IDE
//! - 0x2F8-0x2FF: COM2
//! - 0x3F0-0x3F7: Floppy Controller
//! - 0x3F8-0x3FF: COM1
//!
//! # NT Functions
//!
//! - `READ_PORT_UCHAR` - Read byte from port
//! - `READ_PORT_USHORT` - Read word from port
//! - `READ_PORT_ULONG` - Read dword from port
//! - `WRITE_PORT_UCHAR` - Write byte to port
//! - `WRITE_PORT_USHORT` - Write word to port
//! - `WRITE_PORT_ULONG` - Write dword to port
//!
//! # Usage
//!
//! ```ignore
//! // Read from keyboard controller
//! let status = read_port_u8(0x64);
//!
//! // Write to PIC
//! write_port_u8(0x20, 0x20); // EOI
//!
//! // Block read from IDE
//! let mut buffer = [0u16; 256];
//! read_port_buffer_u16(0x1F0, &mut buffer);
//! ```

use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Statistics
// ============================================================================

static PORT_READS: AtomicU64 = AtomicU64::new(0);
static PORT_WRITES: AtomicU64 = AtomicU64::new(0);
static PORT_READ_BYTES: AtomicU64 = AtomicU64::new(0);
static PORT_WRITE_BYTES: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Single-Value Port I/O
// ============================================================================

/// Read a byte from an I/O port
#[inline]
pub fn read_port_u8(port: u16) -> u8 {
    PORT_READS.fetch_add(1, Ordering::Relaxed);
    PORT_READ_BYTES.fetch_add(1, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        let value: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nostack, preserves_flags)
        );
        value
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Read a word (16-bit) from an I/O port
#[inline]
pub fn read_port_u16(port: u16) -> u16 {
    PORT_READS.fetch_add(1, Ordering::Relaxed);
    PORT_READ_BYTES.fetch_add(2, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        let value: u16;
        core::arch::asm!(
            "in ax, dx",
            out("ax") value,
            in("dx") port,
            options(nostack, preserves_flags)
        );
        value
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Read a dword (32-bit) from an I/O port
#[inline]
pub fn read_port_u32(port: u16) -> u32 {
    PORT_READS.fetch_add(1, Ordering::Relaxed);
    PORT_READ_BYTES.fetch_add(4, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        let value: u32;
        core::arch::asm!(
            "in eax, dx",
            out("eax") value,
            in("dx") port,
            options(nostack, preserves_flags)
        );
        value
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Write a byte to an I/O port
#[inline]
pub fn write_port_u8(port: u16, value: u8) {
    PORT_WRITES.fetch_add(1, Ordering::Relaxed);
    PORT_WRITE_BYTES.fetch_add(1, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nostack, preserves_flags)
        );
    }
}

/// Write a word (16-bit) to an I/O port
#[inline]
pub fn write_port_u16(port: u16, value: u16) {
    PORT_WRITES.fetch_add(1, Ordering::Relaxed);
    PORT_WRITE_BYTES.fetch_add(2, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") value,
            options(nostack, preserves_flags)
        );
    }
}

/// Write a dword (32-bit) to an I/O port
#[inline]
pub fn write_port_u32(port: u16, value: u32) {
    PORT_WRITES.fetch_add(1, Ordering::Relaxed);
    PORT_WRITE_BYTES.fetch_add(4, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") value,
            options(nostack, preserves_flags)
        );
    }
}

// ============================================================================
// Buffer Port I/O (String I/O)
// ============================================================================

/// Read multiple bytes from an I/O port
#[inline]
pub fn read_port_buffer_u8(port: u16, buffer: &mut [u8]) {
    PORT_READS.fetch_add(buffer.len() as u64, Ordering::Relaxed);
    PORT_READ_BYTES.fetch_add(buffer.len() as u64, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "rep insb",
            in("dx") port,
            inout("rdi") buffer.as_mut_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }
}

/// Read multiple words from an I/O port
#[inline]
pub fn read_port_buffer_u16(port: u16, buffer: &mut [u16]) {
    PORT_READS.fetch_add(buffer.len() as u64, Ordering::Relaxed);
    PORT_READ_BYTES.fetch_add((buffer.len() * 2) as u64, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "rep insw",
            in("dx") port,
            inout("rdi") buffer.as_mut_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }
}

/// Read multiple dwords from an I/O port
#[inline]
pub fn read_port_buffer_u32(port: u16, buffer: &mut [u32]) {
    PORT_READS.fetch_add(buffer.len() as u64, Ordering::Relaxed);
    PORT_READ_BYTES.fetch_add((buffer.len() * 4) as u64, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "rep insd",
            in("dx") port,
            inout("rdi") buffer.as_mut_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }
}

/// Write multiple bytes to an I/O port
#[inline]
pub fn write_port_buffer_u8(port: u16, buffer: &[u8]) {
    PORT_WRITES.fetch_add(buffer.len() as u64, Ordering::Relaxed);
    PORT_WRITE_BYTES.fetch_add(buffer.len() as u64, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "rep outsb",
            in("dx") port,
            inout("rsi") buffer.as_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }
}

/// Write multiple words to an I/O port
#[inline]
pub fn write_port_buffer_u16(port: u16, buffer: &[u16]) {
    PORT_WRITES.fetch_add(buffer.len() as u64, Ordering::Relaxed);
    PORT_WRITE_BYTES.fetch_add((buffer.len() * 2) as u64, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "rep outsw",
            in("dx") port,
            inout("rsi") buffer.as_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }
}

/// Write multiple dwords to an I/O port
#[inline]
pub fn write_port_buffer_u32(port: u16, buffer: &[u32]) {
    PORT_WRITES.fetch_add(buffer.len() as u64, Ordering::Relaxed);
    PORT_WRITE_BYTES.fetch_add((buffer.len() * 4) as u64, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "rep outsd",
            in("dx") port,
            inout("rsi") buffer.as_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }
}

// ============================================================================
// Delayed I/O (for slow devices)
// ============================================================================

/// Delay port - writes to port 0x80 cause ~1μs delay
const DELAY_PORT: u16 = 0x80;

/// Small I/O delay (approximately 1-4 μs)
#[inline]
pub fn io_delay() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Write to port 0x80 - traditionally unused diagnostic port
        // Takes approximately 1 microsecond on most systems
        core::arch::asm!(
            "out 0x80, al",
            in("al") 0u8,
            options(nostack, preserves_flags)
        );
    }
}

/// Read byte with delay
#[inline]
pub fn read_port_u8_delayed(port: u16) -> u8 {
    let value = read_port_u8(port);
    io_delay();
    value
}

/// Write byte with delay
#[inline]
pub fn write_port_u8_delayed(port: u16, value: u8) {
    write_port_u8(port, value);
    io_delay();
}

/// Multiple I/O delays
#[inline]
pub fn io_delay_multiple(count: u32) {
    for _ in 0..count {
        io_delay();
    }
}

// ============================================================================
// NT Compatibility Aliases
// ============================================================================

/// READ_PORT_UCHAR equivalent
#[inline]
pub fn hal_read_port_uchar(port: u16) -> u8 {
    read_port_u8(port)
}

/// READ_PORT_USHORT equivalent
#[inline]
pub fn hal_read_port_ushort(port: u16) -> u16 {
    read_port_u16(port)
}

/// READ_PORT_ULONG equivalent
#[inline]
pub fn hal_read_port_ulong(port: u16) -> u32 {
    read_port_u32(port)
}

/// WRITE_PORT_UCHAR equivalent
#[inline]
pub fn hal_write_port_uchar(port: u16, value: u8) {
    write_port_u8(port, value)
}

/// WRITE_PORT_USHORT equivalent
#[inline]
pub fn hal_write_port_ushort(port: u16, value: u16) {
    write_port_u16(port, value)
}

/// WRITE_PORT_ULONG equivalent
#[inline]
pub fn hal_write_port_ulong(port: u16, value: u32) {
    write_port_u32(port, value)
}

/// READ_PORT_BUFFER_UCHAR equivalent
#[inline]
pub fn hal_read_port_buffer_uchar(port: u16, buffer: &mut [u8]) {
    read_port_buffer_u8(port, buffer)
}

/// READ_PORT_BUFFER_USHORT equivalent
#[inline]
pub fn hal_read_port_buffer_ushort(port: u16, buffer: &mut [u16]) {
    read_port_buffer_u16(port, buffer)
}

/// READ_PORT_BUFFER_ULONG equivalent
#[inline]
pub fn hal_read_port_buffer_ulong(port: u16, buffer: &mut [u32]) {
    read_port_buffer_u32(port, buffer)
}

/// WRITE_PORT_BUFFER_UCHAR equivalent
#[inline]
pub fn hal_write_port_buffer_uchar(port: u16, buffer: &[u8]) {
    write_port_buffer_u8(port, buffer)
}

/// WRITE_PORT_BUFFER_USHORT equivalent
#[inline]
pub fn hal_write_port_buffer_ushort(port: u16, buffer: &[u16]) {
    write_port_buffer_u16(port, buffer)
}

/// WRITE_PORT_BUFFER_ULONG equivalent
#[inline]
pub fn hal_write_port_buffer_ulong(port: u16, buffer: &[u32]) {
    write_port_buffer_u32(port, buffer)
}

// ============================================================================
// Port Range Operations
// ============================================================================

/// Well-known port ranges
pub mod ports {
    /// DMA Controller 1
    pub const DMA1_BASE: u16 = 0x00;
    pub const DMA1_END: u16 = 0x1F;

    /// PIC 1 (Master)
    pub const PIC1_COMMAND: u16 = 0x20;
    pub const PIC1_DATA: u16 = 0x21;

    /// PIT (Programmable Interval Timer)
    pub const PIT_CHANNEL0: u16 = 0x40;
    pub const PIT_CHANNEL1: u16 = 0x41;
    pub const PIT_CHANNEL2: u16 = 0x42;
    pub const PIT_COMMAND: u16 = 0x43;

    /// Keyboard/PS2 Controller
    pub const PS2_DATA: u16 = 0x60;
    pub const PS2_STATUS: u16 = 0x64;
    pub const PS2_COMMAND: u16 = 0x64;

    /// CMOS/RTC
    pub const CMOS_ADDRESS: u16 = 0x70;
    pub const CMOS_DATA: u16 = 0x71;

    /// DMA Page Registers
    pub const DMA_PAGE_BASE: u16 = 0x80;

    /// PIC 2 (Slave)
    pub const PIC2_COMMAND: u16 = 0xA0;
    pub const PIC2_DATA: u16 = 0xA1;

    /// DMA Controller 2
    pub const DMA2_BASE: u16 = 0xC0;
    pub const DMA2_END: u16 = 0xDF;

    /// PCI Configuration
    pub const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
    pub const PCI_CONFIG_DATA: u16 = 0xCFC;

    /// Primary IDE Controller
    pub const IDE_PRIMARY_DATA: u16 = 0x1F0;
    pub const IDE_PRIMARY_ERROR: u16 = 0x1F1;
    pub const IDE_PRIMARY_SECTOR_COUNT: u16 = 0x1F2;
    pub const IDE_PRIMARY_LBA_LOW: u16 = 0x1F3;
    pub const IDE_PRIMARY_LBA_MID: u16 = 0x1F4;
    pub const IDE_PRIMARY_LBA_HIGH: u16 = 0x1F5;
    pub const IDE_PRIMARY_DEVICE: u16 = 0x1F6;
    pub const IDE_PRIMARY_COMMAND: u16 = 0x1F7;
    pub const IDE_PRIMARY_STATUS: u16 = 0x1F7;
    pub const IDE_PRIMARY_CONTROL: u16 = 0x3F6;

    /// Secondary IDE Controller
    pub const IDE_SECONDARY_DATA: u16 = 0x170;
    pub const IDE_SECONDARY_COMMAND: u16 = 0x177;
    pub const IDE_SECONDARY_STATUS: u16 = 0x177;
    pub const IDE_SECONDARY_CONTROL: u16 = 0x376;

    /// COM Ports
    pub const COM1_BASE: u16 = 0x3F8;
    pub const COM2_BASE: u16 = 0x2F8;
    pub const COM3_BASE: u16 = 0x3E8;
    pub const COM4_BASE: u16 = 0x2E8;

    /// LPT Ports
    pub const LPT1_BASE: u16 = 0x378;
    pub const LPT2_BASE: u16 = 0x278;

    /// Floppy Controller
    pub const FDC_STATUS_A: u16 = 0x3F0;
    pub const FDC_STATUS_B: u16 = 0x3F1;
    pub const FDC_DOR: u16 = 0x3F2;  // Digital Output Register
    pub const FDC_MSR: u16 = 0x3F4;  // Main Status Register
    pub const FDC_FIFO: u16 = 0x3F5;
    pub const FDC_DIR: u16 = 0x3F7;  // Digital Input Register

    /// VGA Ports
    pub const VGA_MISC_OUTPUT: u16 = 0x3C2;
    pub const VGA_SEQ_INDEX: u16 = 0x3C4;
    pub const VGA_SEQ_DATA: u16 = 0x3C5;
    pub const VGA_GC_INDEX: u16 = 0x3CE;
    pub const VGA_GC_DATA: u16 = 0x3CF;
    pub const VGA_CRTC_INDEX: u16 = 0x3D4;
    pub const VGA_CRTC_DATA: u16 = 0x3D5;
    pub const VGA_STATUS: u16 = 0x3DA;
}

// ============================================================================
// Port Wrapper Type
// ============================================================================

/// Type-safe I/O port handle
#[derive(Debug, Clone, Copy)]
pub struct Port<T> {
    port: u16,
    _marker: core::marker::PhantomData<T>,
}

impl Port<u8> {
    /// Create new byte port
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _marker: core::marker::PhantomData,
        }
    }

    /// Read from port
    #[inline]
    pub fn read(&self) -> u8 {
        read_port_u8(self.port)
    }

    /// Write to port
    #[inline]
    pub fn write(&self, value: u8) {
        write_port_u8(self.port, value)
    }

    /// Read with delay
    #[inline]
    pub fn read_delayed(&self) -> u8 {
        read_port_u8_delayed(self.port)
    }

    /// Write with delay
    #[inline]
    pub fn write_delayed(&self, value: u8) {
        write_port_u8_delayed(self.port, value)
    }
}

impl Port<u16> {
    /// Create new word port
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _marker: core::marker::PhantomData,
        }
    }

    /// Read from port
    #[inline]
    pub fn read(&self) -> u16 {
        read_port_u16(self.port)
    }

    /// Write to port
    #[inline]
    pub fn write(&self, value: u16) {
        write_port_u16(self.port, value)
    }
}

impl Port<u32> {
    /// Create new dword port
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _marker: core::marker::PhantomData,
        }
    }

    /// Read from port
    #[inline]
    pub fn read(&self) -> u32 {
        read_port_u32(self.port)
    }

    /// Write to port
    #[inline]
    pub fn write(&self, value: u32) {
        write_port_u32(self.port, value)
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Port I/O statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct PortStats {
    pub reads: u64,
    pub writes: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

/// Get I/O port statistics
pub fn hal_get_port_stats() -> PortStats {
    PortStats {
        reads: PORT_READS.load(Ordering::Relaxed),
        writes: PORT_WRITES.load(Ordering::Relaxed),
        bytes_read: PORT_READ_BYTES.load(Ordering::Relaxed),
        bytes_written: PORT_WRITE_BYTES.load(Ordering::Relaxed),
    }
}

/// Reset I/O port statistics
pub fn hal_reset_port_stats() {
    PORT_READS.store(0, Ordering::Relaxed);
    PORT_WRITES.store(0, Ordering::Relaxed);
    PORT_READ_BYTES.store(0, Ordering::Relaxed);
    PORT_WRITE_BYTES.store(0, Ordering::Relaxed);
}
