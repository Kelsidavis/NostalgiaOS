//! PS/2 Keyboard Driver
//!
//! Handles keyboard input via the PS/2 controller.
//! Uses IRQ1 (vector 33) for interrupt-driven input.

use crate::arch::io::{inb, outb};
use crate::ke::SpinLock;
use core::sync::atomic::{AtomicBool, Ordering};

/// PS/2 controller ports
pub mod ps2_ports {
    pub const DATA: u16 = 0x60;
    pub const STATUS: u16 = 0x64;
    pub const COMMAND: u16 = 0x64;
}

/// PS/2 status register bits
pub mod ps2_status {
    pub const OUTPUT_FULL: u8 = 0x01;
    pub const INPUT_FULL: u8 = 0x02;
}

/// Keyboard buffer size
const KEYBOARD_BUFFER_SIZE: usize = 256;

/// Keyboard input buffer
struct KeyboardBuffer {
    buffer: [u8; KEYBOARD_BUFFER_SIZE],
    read_pos: usize,
    write_pos: usize,
    count: usize,
}

impl KeyboardBuffer {
    const fn new() -> Self {
        Self {
            buffer: [0; KEYBOARD_BUFFER_SIZE],
            read_pos: 0,
            write_pos: 0,
            count: 0,
        }
    }

    fn push(&mut self, byte: u8) -> bool {
        if self.count >= KEYBOARD_BUFFER_SIZE {
            return false;
        }
        self.buffer[self.write_pos] = byte;
        self.write_pos = (self.write_pos + 1) % KEYBOARD_BUFFER_SIZE;
        self.count += 1;
        true
    }

    fn pop(&mut self) -> Option<u8> {
        if self.count == 0 {
            return None;
        }
        let byte = self.buffer[self.read_pos];
        self.read_pos = (self.read_pos + 1) % KEYBOARD_BUFFER_SIZE;
        self.count -= 1;
        Some(byte)
    }

    fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn len(&self) -> usize {
        self.count
    }
}

/// Global keyboard buffer
static KEYBOARD_BUFFER: SpinLock<KeyboardBuffer> = SpinLock::new(KeyboardBuffer::new());

/// Keyboard state
static mut SHIFT_PRESSED: bool = false;
static mut CTRL_PRESSED: bool = false;
static mut ALT_PRESSED: bool = false;
static mut CAPS_LOCK: bool = false;

/// Keyboard initialized flag
static KEYBOARD_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// US keyboard layout - scancode set 1
/// Lowercase mappings
const SCANCODE_TO_ASCII: [u8; 128] = [
    0,   27,  b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', 8,   // 0x00-0x0E (backspace = 8)
    b'\t', b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'[', b']', b'\n', // 0x0F-0x1C (enter)
    0,   b'a', b's', b'd', b'f', b'g', b'h', b'j', b'k', b'l', b';', b'\'', b'`',         // 0x1D-0x29 (left ctrl at 0x1D)
    0,   b'\\', b'z', b'x', b'c', b'v', b'b', b'n', b'm', b',', b'.', b'/',               // 0x2A-0x35 (left shift at 0x2A)
    0,   b'*', 0,   b' ', 0,   0,   0,   0,   0,   0,                                     // 0x36-0x3F (right shift, alt, space, caps, F1-F4)
    0,   0,   0,   0,   0,   0,   0,                                                      // 0x40-0x46 (F5-F10, numlock, scrolllock)
    b'7', b'8', b'9', b'-', b'4', b'5', b'6', b'+', b'1', b'2', b'3', b'0', b'.',         // 0x47-0x53 (numpad)
    0,   0,   0,   0,   0,                                                                // 0x54-0x58 (F11, F12)
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,         // 0x59-0x68
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,              // 0x69-0x77
    0,   0,   0,   0,   0,   0,   0,   0,                                                  // 0x78-0x7F
];

/// Shifted mappings
const SCANCODE_TO_ASCII_SHIFT: [u8; 128] = [
    0,   27,  b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', b'_', b'+', 8,
    b'\t', b'Q', b'W', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', b'{', b'}', b'\n',
    0,   b'A', b'S', b'D', b'F', b'G', b'H', b'J', b'K', b'L', b':', b'"', b'~',
    0,   b'|', b'Z', b'X', b'C', b'V', b'B', b'N', b'M', b'<', b'>', b'?',
    0,   b'*', 0,   b' ', 0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,
    b'7', b'8', b'9', b'-', b'4', b'5', b'6', b'+', b'1', b'2', b'3', b'0', b'.',
    0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,
];

/// Special scancodes
pub mod scancode {
    pub const LEFT_SHIFT: u8 = 0x2A;
    pub const RIGHT_SHIFT: u8 = 0x36;
    pub const LEFT_CTRL: u8 = 0x1D;
    pub const LEFT_ALT: u8 = 0x38;
    pub const CAPS_LOCK: u8 = 0x3A;
    pub const ESCAPE: u8 = 0x01;
    pub const BACKSPACE: u8 = 0x0E;
    pub const ENTER: u8 = 0x1C;
    pub const TAB: u8 = 0x0F;

    // Arrow keys (extended - prefixed by 0xE0)
    pub const UP: u8 = 0x48;
    pub const DOWN: u8 = 0x50;
    pub const LEFT: u8 = 0x4B;
    pub const RIGHT: u8 = 0x4D;

    // Function keys
    pub const F1: u8 = 0x3B;
    pub const F2: u8 = 0x3C;
    pub const F3: u8 = 0x3D;
    pub const F4: u8 = 0x3E;
    pub const F5: u8 = 0x3F;
    pub const F6: u8 = 0x40;
    pub const F7: u8 = 0x41;
    pub const F8: u8 = 0x42;
    pub const F9: u8 = 0x43;
    pub const F10: u8 = 0x44;
    pub const F11: u8 = 0x57;
    pub const F12: u8 = 0x58;
}

/// Key event types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEvent {
    /// Key pressed with ASCII character
    Char(u8),
    /// Special key pressed
    Special(SpecialKey),
    /// No event
    None,
}

/// Special keys (non-ASCII)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialKey {
    Escape,
    Backspace,
    Tab,
    Enter,
    Up,
    Down,
    Left,
    Right,
    F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12,
    Delete,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
}

/// Extended scancode state
static mut EXTENDED_SCANCODE: bool = false;

/// Handle a keyboard interrupt
pub fn handle_interrupt() {
    // Read scancode from the PS/2 data port
    let scancode = unsafe { inb(ps2_ports::DATA) };

    // Handle the scancode
    process_scancode(scancode);
}

/// Process a scancode
fn process_scancode(scancode: u8) {
    unsafe {
        // Check for extended scancode prefix
        if scancode == 0xE0 {
            EXTENDED_SCANCODE = true;
            return;
        }

        let is_extended = EXTENDED_SCANCODE;
        EXTENDED_SCANCODE = false;

        // Check if key release (high bit set)
        let is_release = (scancode & 0x80) != 0;
        let scancode = scancode & 0x7F;

        // Handle modifier keys
        match scancode {
            scancode::LEFT_SHIFT | scancode::RIGHT_SHIFT => {
                SHIFT_PRESSED = !is_release;
                return;
            }
            scancode::LEFT_CTRL => {
                CTRL_PRESSED = !is_release;
                return;
            }
            scancode::LEFT_ALT => {
                ALT_PRESSED = !is_release;
                return;
            }
            scancode::CAPS_LOCK if !is_release => {
                CAPS_LOCK = !CAPS_LOCK;
                return;
            }
            _ => {}
        }

        // Only process key presses, not releases
        if is_release {
            return;
        }

        // Handle extended keys (arrow keys, etc.)
        if is_extended {
            let special = match scancode {
                scancode::UP => Some(SpecialKey::Up),
                scancode::DOWN => Some(SpecialKey::Down),
                scancode::LEFT => Some(SpecialKey::Left),
                scancode::RIGHT => Some(SpecialKey::Right),
                0x47 => Some(SpecialKey::Home),
                0x4F => Some(SpecialKey::End),
                0x49 => Some(SpecialKey::PageUp),
                0x51 => Some(SpecialKey::PageDown),
                0x52 => Some(SpecialKey::Insert),
                0x53 => Some(SpecialKey::Delete),
                _ => None,
            };

            if let Some(key) = special {
                // Encode special key as escape sequence
                let mut buf = KEYBOARD_BUFFER.lock();
                buf.push(0x1B); // ESC
                buf.push(b'[');
                match key {
                    SpecialKey::Up => { buf.push(b'A'); }
                    SpecialKey::Down => { buf.push(b'B'); }
                    SpecialKey::Right => { buf.push(b'C'); }
                    SpecialKey::Left => { buf.push(b'D'); }
                    SpecialKey::Home => { buf.push(b'H'); }
                    SpecialKey::End => { buf.push(b'F'); }
                    _ => {}
                }
            }
            return;
        }

        // Handle special keys
        match scancode {
            scancode::ESCAPE => {
                let mut buf = KEYBOARD_BUFFER.lock();
                buf.push(0x1B); // ESC
                return;
            }
            scancode::BACKSPACE => {
                let mut buf = KEYBOARD_BUFFER.lock();
                buf.push(0x7F); // DEL (or use 0x08 for backspace)
                return;
            }
            scancode::F1..=scancode::F10 | scancode::F11 | scancode::F12 => {
                // Encode function keys as escape sequences
                let mut buf = KEYBOARD_BUFFER.lock();
                buf.push(0x1B);
                buf.push(b'O');
                let key = match scancode {
                    scancode::F1 => b'P',
                    scancode::F2 => b'Q',
                    scancode::F3 => b'R',
                    scancode::F4 => b'S',
                    _ => return,
                };
                buf.push(key);
                return;
            }
            _ => {}
        }

        // Convert to ASCII
        let use_shift = SHIFT_PRESSED ^ CAPS_LOCK;
        let ascii = if use_shift {
            SCANCODE_TO_ASCII_SHIFT[scancode as usize]
        } else {
            SCANCODE_TO_ASCII[scancode as usize]
        };

        if ascii != 0 {
            // Handle Ctrl+key combinations
            if CTRL_PRESSED && ascii.is_ascii_lowercase() {
                let ctrl_char = ascii - b'a' + 1; // Ctrl+A = 1, Ctrl+B = 2, etc.
                let mut buf = KEYBOARD_BUFFER.lock();
                buf.push(ctrl_char);
            } else if CTRL_PRESSED && ascii.is_ascii_uppercase() {
                let ctrl_char = ascii - b'A' + 1;
                let mut buf = KEYBOARD_BUFFER.lock();
                buf.push(ctrl_char);
            } else {
                let mut buf = KEYBOARD_BUFFER.lock();
                buf.push(ascii);
            }
        }
    }
}

/// Read a character from the keyboard buffer (blocking)
/// Waits for interrupt-driven input to fill the buffer
pub fn read_char() -> u8 {
    loop {
        // Check buffer (filled by interrupt handler)
        {
            let mut buf = KEYBOARD_BUFFER.lock();
            if let Some(c) = buf.pop() {
                return c;
            }
        }

        // Yield to other threads while waiting for keyboard input
        unsafe { crate::ke::scheduler::ki_yield(); }
    }
}

/// Try to read a character from the keyboard buffer (non-blocking)
pub fn try_read_char() -> Option<u8> {
    let mut buf = KEYBOARD_BUFFER.lock();
    buf.pop()
}

/// Check if there are characters available
pub fn has_input() -> bool {
    let buf = KEYBOARD_BUFFER.lock();
    !buf.is_empty()
}

/// Get the number of characters in the buffer
pub fn buffer_len() -> usize {
    let buf = KEYBOARD_BUFFER.lock();
    buf.len()
}

/// Read a line from the keyboard (blocking, with echo)
pub fn read_line(buffer: &mut [u8]) -> usize {
    let mut pos = 0;

    while pos < buffer.len() - 1 {
        let c = read_char();

        match c {
            b'\n' | b'\r' => {
                crate::serial_println!();
                buffer[pos] = 0;
                return pos;
            }
            0x7F | 0x08 => {
                // Backspace/Delete
                if pos > 0 {
                    pos -= 1;
                    crate::serial_print!("\x08 \x08"); // Erase character
                }
            }
            0x03 => {
                // Ctrl+C
                crate::serial_println!("^C");
                buffer[0] = 0;
                return 0;
            }
            c if (0x20..0x7F).contains(&c) => {
                // Printable character
                buffer[pos] = c;
                pos += 1;
                crate::serial_print!("{}", c as char);
            }
            _ => {
                // Ignore other characters
            }
        }
    }

    buffer[pos] = 0;
    pos
}

/// Initialize the keyboard driver
pub fn init() {
    if KEYBOARD_INITIALIZED.swap(true, Ordering::SeqCst) {
        return; // Already initialized
    }

    // Wait for keyboard controller to be ready
    unsafe {
        // Disable devices temporarily
        wait_write_ready();
        outb(ps2_ports::COMMAND, 0xAD); // Disable keyboard
        wait_write_ready();
        outb(ps2_ports::COMMAND, 0xA7); // Disable mouse

        // Flush output buffer
        while (inb(ps2_ports::STATUS) & ps2_status::OUTPUT_FULL) != 0 {
            let _ = inb(ps2_ports::DATA);
        }

        // Read controller configuration
        wait_write_ready();
        outb(ps2_ports::COMMAND, 0x20);
        wait_read_ready();
        let mut config = inb(ps2_ports::DATA);

        // Configure the controller:
        // Bit 0: Enable keyboard interrupt (IRQ1)
        // Bit 1: Disable mouse interrupt
        // Bit 4: Enable keyboard clock
        // Bit 6: Keep translation enabled (QEMU default) - translates set 2 to set 1
        config |= 0x01;  // Enable keyboard IRQ
        config &= !0x02; // Disable mouse IRQ
        config &= !0x10; // Enable keyboard clock (clear disable bit)
        config |= 0x40;  // Ensure translation is enabled

        // Write configuration
        wait_write_ready();
        outb(ps2_ports::COMMAND, 0x60);
        wait_write_ready();
        outb(ps2_ports::DATA, config);

        // Enable keyboard
        wait_write_ready();
        outb(ps2_ports::COMMAND, 0xAE);

        // Flush any pending data
        for _ in 0..10 {
            if (inb(ps2_ports::STATUS) & ps2_status::OUTPUT_FULL) != 0 {
                let _ = inb(ps2_ports::DATA);
            }
        }

        // Enable scanning (in case it was disabled)
        wait_write_ready();
        outb(ps2_ports::DATA, 0xF4);
        // Wait for ACK
        wait_read_ready();
        let _ = inb(ps2_ports::DATA);
    }

    crate::serial_println!("[KB] PS/2 keyboard initialized");
}

/// Wait for write ready
fn wait_write_ready() {
    unsafe {
        for _ in 0..10000 {
            if (inb(ps2_ports::STATUS) & ps2_status::INPUT_FULL) == 0 {
                return;
            }
        }
    }
}

/// Wait for read ready
fn wait_read_ready() {
    unsafe {
        for _ in 0..10000 {
            if (inb(ps2_ports::STATUS) & ps2_status::OUTPUT_FULL) != 0 {
                return;
            }
        }
    }
}
