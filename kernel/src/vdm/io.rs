//! VDM I/O Port Emulation
//!
//! Provides I/O port virtualization for DOS applications.
//! Handles port reads/writes and routes them appropriately.

extern crate alloc;

use super::VDM_TABLE;
use crate::ke::spinlock::SpinLock;
use alloc::collections::BTreeMap;

// ============================================================================
// I/O Port Constants
// ============================================================================

/// Standard PC I/O ports
pub mod ports {
    // DMA Controller
    pub const DMA1_ADDR_CH0: u16 = 0x00;
    pub const DMA1_COUNT_CH0: u16 = 0x01;
    pub const DMA1_STATUS: u16 = 0x08;
    pub const DMA1_COMMAND: u16 = 0x08;
    pub const DMA_PAGE_CH2: u16 = 0x81;

    // PIC (Programmable Interrupt Controller)
    pub const PIC1_COMMAND: u16 = 0x20;
    pub const PIC1_DATA: u16 = 0x21;
    pub const PIC2_COMMAND: u16 = 0xA0;
    pub const PIC2_DATA: u16 = 0xA1;

    // PIT (Programmable Interval Timer)
    pub const PIT_CH0: u16 = 0x40;
    pub const PIT_CH1: u16 = 0x41;
    pub const PIT_CH2: u16 = 0x42;
    pub const PIT_COMMAND: u16 = 0x43;

    // Keyboard Controller
    pub const KBD_DATA: u16 = 0x60;
    pub const KBD_STATUS: u16 = 0x64;
    pub const KBD_COMMAND: u16 = 0x64;

    // RTC/CMOS
    pub const CMOS_ADDR: u16 = 0x70;
    pub const CMOS_DATA: u16 = 0x71;

    // COM Ports
    pub const COM1_BASE: u16 = 0x3F8;
    pub const COM2_BASE: u16 = 0x2F8;
    pub const COM3_BASE: u16 = 0x3E8;
    pub const COM4_BASE: u16 = 0x2E8;

    // LPT Ports
    pub const LPT1_DATA: u16 = 0x378;
    pub const LPT1_STATUS: u16 = 0x379;
    pub const LPT1_CONTROL: u16 = 0x37A;

    // VGA
    pub const VGA_CRT_INDEX: u16 = 0x3D4;
    pub const VGA_CRT_DATA: u16 = 0x3D5;
    pub const VGA_INPUT_STATUS: u16 = 0x3DA;

    // Floppy Disk Controller
    pub const FDC_STATUS: u16 = 0x3F4;
    pub const FDC_DATA: u16 = 0x3F5;
    pub const FDC_DOR: u16 = 0x3F2;
}

/// I/O port handler function type
pub type IoPortHandler = fn(port: u16, is_write: bool, value: u32, size: u8) -> u32;

/// I/O port emulation state
struct IoPortState {
    /// PIC1 mask register
    pic1_mask: u8,
    /// PIC2 mask register
    pic2_mask: u8,
    /// PIT channel 0 count
    pit_count: [u16; 3],
    /// PIT command/mode
    pit_mode: [u8; 3],
    /// Keyboard buffer
    kbd_buffer: [u8; 16],
    kbd_read_index: usize,
    kbd_write_index: usize,
    /// CMOS address register
    cmos_address: u8,
    /// CMOS data
    cmos_data: [u8; 128],
    /// VGA CRT register index
    vga_crt_index: u8,
    /// VGA CRT registers
    vga_crt_regs: [u8; 256],
}

impl IoPortState {
    const fn new() -> Self {
        Self {
            pic1_mask: 0xFF,
            pic2_mask: 0xFF,
            pit_count: [0; 3],
            pit_mode: [0; 3],
            kbd_buffer: [0; 16],
            kbd_read_index: 0,
            kbd_write_index: 0,
            cmos_address: 0,
            cmos_data: [0; 128],
            vga_crt_index: 0,
            vga_crt_regs: [0; 256],
        }
    }
}

static IO_STATE: SpinLock<IoPortState> = SpinLock::new(IoPortState::new());

// ============================================================================
// I/O Port Functions
// ============================================================================

/// Initialize I/O port emulation
pub fn init() {
    let mut state = IO_STATE.lock();

    // Initialize CMOS with default values
    init_cmos(&mut state.cmos_data);

    crate::serial_println!("[VDM] I/O port emulation initialized");
}

/// Initialize CMOS data with sensible defaults
fn init_cmos(cmos: &mut [u8; 128]) {
    // RTC time (12:00:00)
    cmos[0x00] = 0x00; // Seconds
    cmos[0x02] = 0x00; // Minutes
    cmos[0x04] = 0x12; // Hours (BCD)

    // RTC date (01-01-2003)
    cmos[0x06] = 0x04; // Day of week (Wednesday)
    cmos[0x07] = 0x01; // Day
    cmos[0x08] = 0x01; // Month
    cmos[0x09] = 0x03; // Year (2003)
    cmos[0x32] = 0x20; // Century

    // Status registers
    cmos[0x0A] = 0x26; // Status A
    cmos[0x0B] = 0x02; // Status B
    cmos[0x0C] = 0x00; // Status C
    cmos[0x0D] = 0x80; // Status D (battery OK)

    // Equipment byte
    cmos[0x14] = 0x27; // 80x25 color, 2 floppies, math coprocessor

    // Base memory (640 KB)
    cmos[0x15] = 0x80;
    cmos[0x16] = 0x02;

    // Extended memory (15 MB)
    cmos[0x17] = 0x00;
    cmos[0x18] = 0x3C;
}

/// Read from I/O port
pub fn vdm_port_read(vdm_id: u32, port: u16, size: u8) -> u32 {
    // Check if VDM has permission
    let table = VDM_TABLE.lock();
    if let Some(state) = table.get(&vdm_id) {
        if !state.is_port_allowed(port) {
            return 0xFFFF_FFFF; // Return all 1s for denied ports
        }
    } else {
        return 0xFFFF_FFFF;
    }
    drop(table);

    // Handle the port read
    port_read_internal(port, size)
}

/// Write to I/O port
pub fn vdm_port_write(vdm_id: u32, port: u16, value: u32, size: u8) {
    // Check if VDM has permission
    let table = VDM_TABLE.lock();
    if let Some(state) = table.get(&vdm_id) {
        if !state.is_port_allowed(port) {
            return; // Silently ignore writes to denied ports
        }
    } else {
        return;
    }
    drop(table);

    // Handle the port write
    port_write_internal(port, value, size);
}

/// Internal port read handler
fn port_read_internal(port: u16, size: u8) -> u32 {
    let mut state = IO_STATE.lock();

    match port {
        // PIC
        ports::PIC1_DATA => state.pic1_mask as u32,
        ports::PIC2_DATA => state.pic2_mask as u32,
        ports::PIC1_COMMAND => 0, // No pending interrupt
        ports::PIC2_COMMAND => 0,

        // PIT - return count
        ports::PIT_CH0 => state.pit_count[0] as u32,
        ports::PIT_CH1 => state.pit_count[1] as u32,
        ports::PIT_CH2 => state.pit_count[2] as u32,

        // Keyboard
        ports::KBD_DATA => {
            if state.kbd_read_index != state.kbd_write_index {
                let data = state.kbd_buffer[state.kbd_read_index];
                state.kbd_read_index = (state.kbd_read_index + 1) % state.kbd_buffer.len();
                data as u32
            } else {
                0
            }
        }
        ports::KBD_STATUS => {
            let mut status = 0u8;
            // Bit 0: Output buffer full
            if state.kbd_read_index != state.kbd_write_index {
                status |= 0x01;
            }
            // Bit 1: Input buffer empty (ready for command)
            status |= 0x00;
            status as u32
        }

        // CMOS
        ports::CMOS_DATA => {
            let addr = state.cmos_address & 0x7F;
            state.cmos_data[addr as usize] as u32
        }

        // VGA
        ports::VGA_INPUT_STATUS => {
            // Bit 0: Display enable (toggles)
            // Bit 3: Vertical retrace
            static mut VGA_TOGGLE: u8 = 0;
            unsafe {
                VGA_TOGGLE ^= 0x09;
                VGA_TOGGLE as u32
            }
        }
        ports::VGA_CRT_DATA => {
            state.vga_crt_regs[state.vga_crt_index as usize] as u32
        }

        // Default: return 0xFF for unknown ports
        _ => {
            if size == 1 { 0xFF }
            else if size == 2 { 0xFFFF }
            else { 0xFFFFFFFF }
        }
    }
}

/// Internal port write handler
fn port_write_internal(port: u16, value: u32, _size: u8) {
    let mut state = IO_STATE.lock();

    match port {
        // PIC
        ports::PIC1_DATA => state.pic1_mask = value as u8,
        ports::PIC2_DATA => state.pic2_mask = value as u8,
        ports::PIC1_COMMAND => {
            // Handle PIC commands (EOI, etc.)
            if (value & 0x20) != 0 {
                // EOI command
            }
        }
        ports::PIC2_COMMAND => {
            if (value & 0x20) != 0 {
                // EOI command
            }
        }

        // PIT
        ports::PIT_COMMAND => {
            let channel = ((value >> 6) & 0x03) as usize;
            if channel < 3 {
                state.pit_mode[channel] = value as u8;
            }
        }
        ports::PIT_CH0 => state.pit_count[0] = value as u16,
        ports::PIT_CH1 => state.pit_count[1] = value as u16,
        ports::PIT_CH2 => state.pit_count[2] = value as u16,

        // Keyboard
        ports::KBD_COMMAND => {
            // Handle keyboard controller commands
            match value as u8 {
                0xAD => {} // Disable keyboard
                0xAE => {} // Enable keyboard
                0xD1 => {} // Write output port
                _ => {}
            }
        }

        // CMOS
        ports::CMOS_ADDR => state.cmos_address = value as u8,
        ports::CMOS_DATA => {
            let addr = state.cmos_address & 0x7F;
            state.cmos_data[addr as usize] = value as u8;
        }

        // VGA
        ports::VGA_CRT_INDEX => state.vga_crt_index = value as u8,
        ports::VGA_CRT_DATA => {
            let index = state.vga_crt_index as usize;
            state.vga_crt_regs[index] = value as u8;
        }

        _ => {
            // Unknown port, ignore
        }
    }
}

/// Queue a keyboard scancode for VDM
pub fn queue_keyboard_scancode(scancode: u8) {
    let mut state = IO_STATE.lock();
    let next_write = (state.kbd_write_index + 1) % state.kbd_buffer.len();
    if next_write != state.kbd_read_index {
        let write_index = state.kbd_write_index;
        state.kbd_buffer[write_index] = scancode;
        state.kbd_write_index = next_write;
    }
}

/// Get current PIT counter value
pub fn get_pit_count(channel: usize) -> u16 {
    if channel < 3 {
        let state = IO_STATE.lock();
        state.pit_count[channel]
    } else {
        0
    }
}
