//! Serial Port (COM/UART) Driver
//!
//! 16550 UART compatible serial port driver.
//! Supports COM1-COM4 with configurable baud rates.

extern crate alloc;

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, Ordering};
use crate::ke::SpinLock;

/// COM1 base port (IRQ 4)
pub const COM1_PORT: u16 = 0x3F8;
/// COM2 base port (IRQ 3)
pub const COM2_PORT: u16 = 0x2F8;
/// COM3 base port (IRQ 4)
pub const COM3_PORT: u16 = 0x3E8;
/// COM4 base port (IRQ 3)
pub const COM4_PORT: u16 = 0x2E8;

/// Maximum receive buffer size
pub const RX_BUFFER_SIZE: usize = 4096;

/// Maximum transmit buffer size
pub const TX_BUFFER_SIZE: usize = 4096;

/// UART register offsets
pub mod regs {
    /// Data register (read/write)
    pub const DATA: u16 = 0;
    /// Interrupt Enable Register
    pub const IER: u16 = 1;
    /// Interrupt Identification Register (read)
    pub const IIR: u16 = 2;
    /// FIFO Control Register (write)
    pub const FCR: u16 = 2;
    /// Line Control Register
    pub const LCR: u16 = 3;
    /// Modem Control Register
    pub const MCR: u16 = 4;
    /// Line Status Register
    pub const LSR: u16 = 5;
    /// Modem Status Register
    pub const MSR: u16 = 6;
    /// Scratch Register
    pub const SCR: u16 = 7;

    /// Divisor Latch Low (when DLAB=1)
    pub const DLL: u16 = 0;
    /// Divisor Latch High (when DLAB=1)
    pub const DLH: u16 = 1;
}

/// Line Status Register bits
pub mod lsr {
    /// Data Ready - data available to read
    pub const DR: u8 = 0x01;
    /// Overrun Error
    pub const OE: u8 = 0x02;
    /// Parity Error
    pub const PE: u8 = 0x04;
    /// Framing Error
    pub const FE: u8 = 0x08;
    /// Break Interrupt
    pub const BI: u8 = 0x10;
    /// Transmitter Holding Register Empty
    pub const THRE: u8 = 0x20;
    /// Transmitter Empty
    pub const TEMT: u8 = 0x40;
    /// Error in FIFO
    pub const FIFOE: u8 = 0x80;
}

/// Line Control Register bits
pub mod lcr {
    /// 5 data bits
    pub const BITS_5: u8 = 0x00;
    /// 6 data bits
    pub const BITS_6: u8 = 0x01;
    /// 7 data bits
    pub const BITS_7: u8 = 0x02;
    /// 8 data bits
    pub const BITS_8: u8 = 0x03;
    /// 1 stop bit
    pub const STOP_1: u8 = 0x00;
    /// 2 stop bits
    pub const STOP_2: u8 = 0x04;
    /// No parity
    pub const PARITY_NONE: u8 = 0x00;
    /// Odd parity
    pub const PARITY_ODD: u8 = 0x08;
    /// Even parity
    pub const PARITY_EVEN: u8 = 0x18;
    /// Mark parity
    pub const PARITY_MARK: u8 = 0x28;
    /// Space parity
    pub const PARITY_SPACE: u8 = 0x38;
    /// Divisor Latch Access Bit
    pub const DLAB: u8 = 0x80;
}

/// FIFO Control Register bits
pub mod fcr {
    /// Enable FIFOs
    pub const ENABLE: u8 = 0x01;
    /// Clear receive FIFO
    pub const CLEAR_RX: u8 = 0x02;
    /// Clear transmit FIFO
    pub const CLEAR_TX: u8 = 0x04;
    /// DMA mode select
    pub const DMA: u8 = 0x08;
    /// 1-byte trigger level
    pub const TRIGGER_1: u8 = 0x00;
    /// 4-byte trigger level
    pub const TRIGGER_4: u8 = 0x40;
    /// 8-byte trigger level
    pub const TRIGGER_8: u8 = 0x80;
    /// 14-byte trigger level
    pub const TRIGGER_14: u8 = 0xC0;
}

/// Modem Control Register bits
pub mod mcr {
    /// Data Terminal Ready
    pub const DTR: u8 = 0x01;
    /// Request To Send
    pub const RTS: u8 = 0x02;
    /// Output 1 (auxiliary)
    pub const OUT1: u8 = 0x04;
    /// Output 2 (enables interrupts)
    pub const OUT2: u8 = 0x08;
    /// Loopback mode
    pub const LOOP: u8 = 0x10;
}

/// Interrupt Enable Register bits
pub mod ier {
    /// Received Data Available
    pub const RDA: u8 = 0x01;
    /// Transmitter Holding Register Empty
    pub const THRE: u8 = 0x02;
    /// Receiver Line Status
    pub const RLS: u8 = 0x04;
    /// Modem Status
    pub const MS: u8 = 0x08;
}

/// Standard baud rates
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BaudRate {
    Baud300 = 300,
    Baud1200 = 1200,
    Baud2400 = 2400,
    Baud4800 = 4800,
    Baud9600 = 9600,
    Baud19200 = 19200,
    Baud38400 = 38400,
    Baud57600 = 57600,
    Baud115200 = 115200,
}

impl BaudRate {
    /// Calculate divisor from baud rate (base clock is 115200 * 16 = 1843200 Hz)
    pub fn divisor(&self) -> u16 {
        (115200 / (*self as u32)) as u16
    }
}

/// Serial port state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    /// Port not initialized
    Uninitialized,
    /// Port is ready
    Ready,
    /// Port not present
    NotPresent,
    /// Port has error
    Error,
}

/// Serial port statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct PortStats {
    pub bytes_received: u64,
    pub bytes_transmitted: u64,
    pub rx_overruns: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

/// Serial port instance
pub struct SerialPort {
    /// Base I/O port address
    pub base_port: u16,
    /// Port number (1-4)
    pub port_num: u8,
    /// IRQ number
    pub irq: u8,
    /// Current state
    pub state: PortState,
    /// Current baud rate
    pub baud_rate: BaudRate,
    /// Receive buffer
    rx_buffer: VecDeque<u8>,
    /// Transmit buffer
    tx_buffer: VecDeque<u8>,
    /// Statistics
    pub stats: PortStats,
    /// Interrupts enabled
    pub interrupts_enabled: bool,
}

impl SerialPort {
    /// Create a new uninitialized serial port
    pub fn new(port_num: u8) -> Self {
        let (base_port, irq) = match port_num {
            1 => (COM1_PORT, 4),
            2 => (COM2_PORT, 3),
            3 => (COM3_PORT, 4),
            4 => (COM4_PORT, 3),
            _ => (0, 0),
        };

        Self {
            base_port,
            port_num,
            irq,
            state: PortState::Uninitialized,
            baud_rate: BaudRate::Baud115200,
            rx_buffer: VecDeque::with_capacity(RX_BUFFER_SIZE),
            tx_buffer: VecDeque::with_capacity(TX_BUFFER_SIZE),
            stats: PortStats::default(),
            interrupts_enabled: false,
        }
    }

    /// Initialize the serial port
    pub fn init(&mut self, baud_rate: BaudRate) -> Result<(), &'static str> {
        if self.base_port == 0 {
            self.state = PortState::NotPresent;
            return Err("Invalid port number");
        }

        // Check if UART is present by writing to scratch register
        unsafe {
            port_write(self.base_port + regs::SCR, 0x42);
            if port_read(self.base_port + regs::SCR) != 0x42 {
                self.state = PortState::NotPresent;
                return Err("UART not present");
            }
        }

        // Disable interrupts
        unsafe {
            port_write(self.base_port + regs::IER, 0x00);
        }

        // Set baud rate
        self.set_baud_rate(baud_rate)?;

        // Configure: 8 data bits, 1 stop bit, no parity
        unsafe {
            port_write(self.base_port + regs::LCR, lcr::BITS_8 | lcr::STOP_1 | lcr::PARITY_NONE);
        }

        // Enable and clear FIFOs with 14-byte trigger level
        unsafe {
            port_write(self.base_port + regs::FCR, fcr::ENABLE | fcr::CLEAR_RX | fcr::CLEAR_TX | fcr::TRIGGER_14);
        }

        // Enable DTR, RTS, and OUT2 (enables interrupts)
        unsafe {
            port_write(self.base_port + regs::MCR, mcr::DTR | mcr::RTS | mcr::OUT2);
        }

        // Test in loopback mode
        unsafe {
            port_write(self.base_port + regs::MCR, mcr::LOOP | mcr::DTR | mcr::RTS | mcr::OUT2);
            port_write(self.base_port + regs::DATA, 0xAE);

            // Wait a bit for loopback
            for _ in 0..1000 {
                core::hint::spin_loop();
            }

            if port_read(self.base_port + regs::DATA) != 0xAE {
                self.state = PortState::Error;
                return Err("Loopback test failed");
            }

            // Restore normal mode
            port_write(self.base_port + regs::MCR, mcr::DTR | mcr::RTS | mcr::OUT2);
        }

        self.state = PortState::Ready;
        self.baud_rate = baud_rate;

        crate::serial_println!("[SERIAL] COM{} initialized at {} baud", self.port_num, baud_rate as u32);

        Ok(())
    }

    /// Set baud rate
    pub fn set_baud_rate(&mut self, baud_rate: BaudRate) -> Result<(), &'static str> {
        let divisor = baud_rate.divisor();

        unsafe {
            // Enable DLAB
            let lcr = port_read(self.base_port + regs::LCR);
            port_write(self.base_port + regs::LCR, lcr | lcr::DLAB);

            // Set divisor
            port_write(self.base_port + regs::DLL, (divisor & 0xFF) as u8);
            port_write(self.base_port + regs::DLH, ((divisor >> 8) & 0xFF) as u8);

            // Disable DLAB
            port_write(self.base_port + regs::LCR, lcr & !lcr::DLAB);
        }

        self.baud_rate = baud_rate;
        Ok(())
    }

    /// Enable receive interrupts
    pub fn enable_interrupts(&mut self) {
        unsafe {
            port_write(self.base_port + regs::IER, ier::RDA | ier::RLS);
        }
        self.interrupts_enabled = true;
    }

    /// Disable interrupts
    pub fn disable_interrupts(&mut self) {
        unsafe {
            port_write(self.base_port + regs::IER, 0x00);
        }
        self.interrupts_enabled = false;
    }

    /// Check if data is available to read
    pub fn data_available(&self) -> bool {
        if self.state != PortState::Ready {
            return false;
        }
        unsafe { (port_read(self.base_port + regs::LSR) & lsr::DR) != 0 }
    }

    /// Check if transmitter is ready
    pub fn transmit_ready(&self) -> bool {
        if self.state != PortState::Ready {
            return false;
        }
        unsafe { (port_read(self.base_port + regs::LSR) & lsr::THRE) != 0 }
    }

    /// Read a single byte (blocking)
    pub fn read_byte(&mut self) -> Option<u8> {
        if self.state != PortState::Ready {
            return None;
        }

        // First check internal buffer
        if let Some(byte) = self.rx_buffer.pop_front() {
            return Some(byte);
        }

        // Then check hardware
        if self.data_available() {
            let byte = unsafe { port_read(self.base_port + regs::DATA) };
            self.stats.bytes_received += 1;
            Some(byte)
        } else {
            None
        }
    }

    /// Read a single byte (non-blocking)
    pub fn try_read_byte(&mut self) -> Option<u8> {
        if self.state != PortState::Ready {
            return None;
        }

        if let Some(byte) = self.rx_buffer.pop_front() {
            return Some(byte);
        }

        if self.data_available() {
            let byte = unsafe { port_read(self.base_port + regs::DATA) };
            self.stats.bytes_received += 1;
            Some(byte)
        } else {
            None
        }
    }

    /// Write a single byte (blocking)
    pub fn write_byte(&mut self, byte: u8) -> Result<(), &'static str> {
        if self.state != PortState::Ready {
            return Err("Port not ready");
        }

        // Wait for transmitter to be ready
        let mut timeout = 100000;
        while !self.transmit_ready() {
            timeout -= 1;
            if timeout == 0 {
                self.stats.tx_errors += 1;
                return Err("Transmit timeout");
            }
            core::hint::spin_loop();
        }

        unsafe {
            port_write(self.base_port + regs::DATA, byte);
        }
        self.stats.bytes_transmitted += 1;
        Ok(())
    }

    /// Write multiple bytes
    pub fn write(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        for &byte in data {
            self.write_byte(byte)?;
        }
        Ok(data.len())
    }

    /// Read into buffer (non-blocking)
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut count = 0;
        for byte in buf.iter_mut() {
            if let Some(b) = self.try_read_byte() {
                *byte = b;
                count += 1;
            } else {
                break;
            }
        }
        count
    }

    /// Poll for received data (call from interrupt or polling loop)
    pub fn poll_rx(&mut self) {
        while self.data_available() {
            if self.rx_buffer.len() >= RX_BUFFER_SIZE {
                self.stats.rx_overruns += 1;
                // Read and discard to clear interrupt
                let _ = unsafe { port_read(self.base_port + regs::DATA) };
                break;
            }
            let byte = unsafe { port_read(self.base_port + regs::DATA) };
            self.rx_buffer.push_back(byte);
            self.stats.bytes_received += 1;
        }
    }

    /// Get number of bytes available in receive buffer
    pub fn rx_available(&self) -> usize {
        self.rx_buffer.len()
    }

    /// Get line status
    pub fn line_status(&self) -> u8 {
        if self.state != PortState::Ready {
            return 0;
        }
        unsafe { port_read(self.base_port + regs::LSR) }
    }

    /// Get modem status
    pub fn modem_status(&self) -> u8 {
        if self.state != PortState::Ready {
            return 0;
        }
        unsafe { port_read(self.base_port + regs::MSR) }
    }

    /// Set DTR (Data Terminal Ready)
    pub fn set_dtr(&mut self, state: bool) {
        if self.state != PortState::Ready {
            return;
        }
        unsafe {
            let mut mcr_val = port_read(self.base_port + regs::MCR);
            if state {
                mcr_val |= mcr::DTR;
            } else {
                mcr_val &= !mcr::DTR;
            }
            port_write(self.base_port + regs::MCR, mcr_val);
        }
    }

    /// Set RTS (Request To Send)
    pub fn set_rts(&mut self, state: bool) {
        if self.state != PortState::Ready {
            return;
        }
        unsafe {
            let mut mcr_val = port_read(self.base_port + regs::MCR);
            if state {
                mcr_val |= mcr::RTS;
            } else {
                mcr_val &= !mcr::RTS;
            }
            port_write(self.base_port + regs::MCR, mcr_val);
        }
    }
}

/// Global serial ports
static mut SERIAL_PORTS: [Option<SerialPort>; 4] = [None, None, None, None];
static SERIAL_LOCK: SpinLock<()> = SpinLock::new(());
static SERIAL_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the serial port driver
pub fn init() -> Result<(), &'static str> {
    let _guard = SERIAL_LOCK.lock();

    crate::serial_println!("[SERIAL] Initializing serial port driver...");

    unsafe {
        // Initialize COM1 (primary debug port)
        let mut com1 = SerialPort::new(1);
        match com1.init(BaudRate::Baud115200) {
            Ok(()) => {
                SERIAL_PORTS[0] = Some(com1);
            }
            Err(e) => {
                crate::serial_println!("[SERIAL] COM1 init failed: {}", e);
            }
        }

        // Try to detect other COM ports
        for port_num in 2..=4 {
            let mut port = SerialPort::new(port_num);
            match port.init(BaudRate::Baud115200) {
                Ok(()) => {
                    SERIAL_PORTS[(port_num - 1) as usize] = Some(port);
                }
                Err(_) => {
                    // Port not present, that's OK
                }
            }
        }
    }

    SERIAL_INITIALIZED.store(true, Ordering::SeqCst);
    crate::serial_println!("[SERIAL] Serial port driver initialized");

    Ok(())
}

/// Get a serial port by number (1-4)
pub fn get_port(port_num: u8) -> Option<&'static mut SerialPort> {
    if port_num < 1 || port_num > 4 {
        return None;
    }
    let _guard = SERIAL_LOCK.lock();
    unsafe { SERIAL_PORTS[(port_num - 1) as usize].as_mut() }
}

/// Write to a serial port
pub fn write(port_num: u8, data: &[u8]) -> Result<usize, &'static str> {
    let _guard = SERIAL_LOCK.lock();
    unsafe {
        if let Some(port) = SERIAL_PORTS.get_mut((port_num - 1) as usize).and_then(|p| p.as_mut()) {
            port.write(data)
        } else {
            Err("Port not found")
        }
    }
}

/// Read from a serial port (non-blocking)
pub fn read(port_num: u8, buf: &mut [u8]) -> usize {
    let _guard = SERIAL_LOCK.lock();
    unsafe {
        if let Some(port) = SERIAL_PORTS.get_mut((port_num - 1) as usize).and_then(|p| p.as_mut()) {
            port.read(buf)
        } else {
            0
        }
    }
}

/// Poll all serial ports for received data
pub fn poll_all() {
    let _guard = SERIAL_LOCK.lock();
    unsafe {
        for port_opt in SERIAL_PORTS.iter_mut() {
            if let Some(port) = port_opt {
                port.poll_rx();
            }
        }
    }
}

/// Get serial port statistics
pub fn get_stats(port_num: u8) -> Option<PortStats> {
    let _guard = SERIAL_LOCK.lock();
    unsafe {
        SERIAL_PORTS.get((port_num - 1) as usize)
            .and_then(|p| p.as_ref())
            .map(|p| p.stats)
    }
}

/// Get number of initialized ports
pub fn port_count() -> usize {
    let _guard = SERIAL_LOCK.lock();
    unsafe {
        SERIAL_PORTS.iter().filter(|p| p.is_some()).count()
    }
}

/// I/O port read
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

/// I/O port write
#[inline]
unsafe fn port_write(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}
