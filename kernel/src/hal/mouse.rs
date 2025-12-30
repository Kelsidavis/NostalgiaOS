//! PS/2 Mouse Driver
//!
//! Handles mouse input via the PS/2 controller.
//! Uses IRQ12 (vector 44) for interrupt-driven input.

use crate::arch::io::{inb, outb};
use crate::ke::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

/// PS/2 controller ports (shared with keyboard)
pub mod ps2_ports {
    pub const DATA: u16 = 0x60;
    pub const STATUS: u16 = 0x64;
    pub const COMMAND: u16 = 0x64;
}

/// PS/2 controller commands
pub mod ps2_cmd {
    /// Read controller config byte
    pub const READ_CONFIG: u8 = 0x20;
    /// Write controller config byte
    pub const WRITE_CONFIG: u8 = 0x60;
    /// Disable mouse port
    pub const DISABLE_MOUSE: u8 = 0xA7;
    /// Enable mouse port
    pub const ENABLE_MOUSE: u8 = 0xA8;
    /// Test mouse port
    pub const TEST_MOUSE: u8 = 0xA9;
    /// Send command to mouse
    pub const WRITE_MOUSE: u8 = 0xD4;
}

/// PS/2 mouse commands
pub mod mouse_cmd {
    /// Reset mouse
    pub const RESET: u8 = 0xFF;
    /// Enable data reporting
    pub const ENABLE_REPORTING: u8 = 0xF4;
    /// Disable data reporting
    pub const DISABLE_REPORTING: u8 = 0xF5;
    /// Set defaults
    pub const SET_DEFAULTS: u8 = 0xF6;
    /// Set sample rate
    pub const SET_SAMPLE_RATE: u8 = 0xF3;
    /// Get device ID
    pub const GET_DEVICE_ID: u8 = 0xF2;
    /// Set resolution
    pub const SET_RESOLUTION: u8 = 0xE8;
    /// Set scaling 1:1
    pub const SET_SCALING_1_1: u8 = 0xE6;
    /// Set scaling 2:1
    pub const SET_SCALING_2_1: u8 = 0xE7;
}

/// PS/2 mouse responses
pub mod mouse_ack {
    pub const ACK: u8 = 0xFA;
    pub const RESEND: u8 = 0xFE;
    pub const ERROR: u8 = 0xFC;
    pub const SELF_TEST_OK: u8 = 0xAA;
}

/// Mouse button state
#[derive(Debug, Clone, Copy, Default)]
pub struct MouseButtons {
    pub left: bool,
    pub right: bool,
    pub middle: bool,
    pub button4: bool,
    pub button5: bool,
}

/// Mouse event
#[derive(Debug, Clone, Copy)]
pub struct MouseEvent {
    /// X movement (relative)
    pub dx: i16,
    /// Y movement (relative)
    pub dy: i16,
    /// Scroll wheel movement
    pub dz: i8,
    /// Button state
    pub buttons: MouseButtons,
}

/// Mouse packet buffer (3 or 4 bytes depending on mouse type)
struct PacketBuffer {
    data: [u8; 4],
    pos: usize,
    packet_size: usize,
}

impl PacketBuffer {
    const fn new() -> Self {
        Self {
            data: [0; 4],
            pos: 0,
            packet_size: 3, // Standard PS/2 mouse
        }
    }

    fn push(&mut self, byte: u8) -> bool {
        if self.pos < self.packet_size {
            self.data[self.pos] = byte;
            self.pos += 1;
        }
        self.pos >= self.packet_size
    }

    fn reset(&mut self) {
        self.pos = 0;
    }

    fn is_complete(&self) -> bool {
        self.pos >= self.packet_size
    }
}

/// Event queue entry
struct EventQueueEntry {
    event: Option<MouseEvent>,
}

impl EventQueueEntry {
    const fn empty() -> Self {
        Self { event: None }
    }
}

/// Event queue
const EVENT_QUEUE_SIZE: usize = 64;
struct EventQueue {
    events: [EventQueueEntry; EVENT_QUEUE_SIZE],
    read_pos: usize,
    write_pos: usize,
    count: usize,
}

impl EventQueue {
    const fn new() -> Self {
        const EMPTY: EventQueueEntry = EventQueueEntry::empty();
        Self {
            events: [EMPTY; EVENT_QUEUE_SIZE],
            read_pos: 0,
            write_pos: 0,
            count: 0,
        }
    }

    fn push(&mut self, event: MouseEvent) -> bool {
        if self.count >= EVENT_QUEUE_SIZE {
            return false;
        }
        self.events[self.write_pos].event = Some(event);
        self.write_pos = (self.write_pos + 1) % EVENT_QUEUE_SIZE;
        self.count += 1;
        true
    }

    fn pop(&mut self) -> Option<MouseEvent> {
        if self.count == 0 {
            return None;
        }
        let event = self.events[self.read_pos].event.take();
        self.read_pos = (self.read_pos + 1) % EVENT_QUEUE_SIZE;
        self.count -= 1;
        event
    }

    fn len(&self) -> usize {
        self.count
    }
}

/// Global mouse state
static MOUSE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static MOUSE_ENABLED: AtomicBool = AtomicBool::new(false);
static PACKET_BUFFER: SpinLock<PacketBuffer> = SpinLock::new(PacketBuffer::new());
static EVENT_QUEUE: SpinLock<EventQueue> = SpinLock::new(EventQueue::new());

/// Mouse position (for absolute tracking)
static MOUSE_X: AtomicI32 = AtomicI32::new(0);
static MOUSE_Y: AtomicI32 = AtomicI32::new(0);
static SCREEN_WIDTH: AtomicU32 = AtomicU32::new(1024);
static SCREEN_HEIGHT: AtomicU32 = AtomicU32::new(768);

/// Button state
static mut BUTTON_STATE: MouseButtons = MouseButtons {
    left: false,
    right: false,
    middle: false,
    button4: false,
    button5: false,
};

/// Mouse type (3-byte or 4-byte packets)
static MOUSE_TYPE: AtomicU32 = AtomicU32::new(0);

/// Statistics
static PACKETS_RECEIVED: AtomicU32 = AtomicU32::new(0);
static EVENTS_GENERATED: AtomicU32 = AtomicU32::new(0);

/// Wait for PS/2 controller input buffer to be empty
fn wait_write() -> bool {
    for _ in 0..100000 {
        let status = unsafe { inb(ps2_ports::STATUS) };
        if (status & 0x02) == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Wait for PS/2 controller output buffer to be full
fn wait_read() -> bool {
    for _ in 0..100000 {
        let status = unsafe { inb(ps2_ports::STATUS) };
        if (status & 0x01) != 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Send command to PS/2 controller
fn ps2_command(cmd: u8) -> bool {
    if !wait_write() {
        return false;
    }
    unsafe { outb(ps2_ports::COMMAND, cmd) };
    true
}

/// Send command to mouse via PS/2 controller
fn mouse_command(cmd: u8) -> bool {
    if !ps2_command(ps2_cmd::WRITE_MOUSE) {
        return false;
    }
    if !wait_write() {
        return false;
    }
    unsafe { outb(ps2_ports::DATA, cmd) };
    true
}

/// Read response from mouse
fn mouse_read() -> Option<u8> {
    if !wait_read() {
        return None;
    }
    Some(unsafe { inb(ps2_ports::DATA) })
}

/// Send command and wait for ACK
fn mouse_command_ack(cmd: u8) -> bool {
    if !mouse_command(cmd) {
        return false;
    }
    match mouse_read() {
        Some(mouse_ack::ACK) => true,
        _ => false,
    }
}

/// Initialize mouse
pub fn init() -> Result<(), &'static str> {
    crate::serial_println!("[MOUSE] Initializing PS/2 mouse...");

    // Enable mouse port
    if !ps2_command(ps2_cmd::ENABLE_MOUSE) {
        return Err("Failed to enable mouse port");
    }

    // Get and modify controller configuration
    if !ps2_command(ps2_cmd::READ_CONFIG) {
        return Err("Failed to read config");
    }
    let config = mouse_read().ok_or("Failed to read config byte")?;

    // Enable mouse interrupt (bit 1) and mouse clock (bit 5 = 0)
    let new_config = (config | 0x02) & !0x20;

    if !ps2_command(ps2_cmd::WRITE_CONFIG) {
        return Err("Failed to write config command");
    }
    if !wait_write() {
        return Err("Timeout writing config");
    }
    unsafe { outb(ps2_ports::DATA, new_config) };

    // Reset mouse
    if !mouse_command(mouse_cmd::RESET) {
        return Err("Failed to send reset");
    }

    // Wait for ACK and self-test result
    let _ = mouse_read(); // ACK
    let _ = mouse_read(); // Self-test result (0xAA)
    let _ = mouse_read(); // Device ID (0x00)

    // Set defaults
    if !mouse_command_ack(mouse_cmd::SET_DEFAULTS) {
        crate::serial_println!("[MOUSE] Warning: SET_DEFAULTS failed");
    }

    // Try to enable scroll wheel (IntelliMouse)
    // Magic sequence: set sample rate 200, 100, 80
    let _ = mouse_command_ack(mouse_cmd::SET_SAMPLE_RATE);
    let _ = mouse_command_ack(200);
    let _ = mouse_command_ack(mouse_cmd::SET_SAMPLE_RATE);
    let _ = mouse_command_ack(100);
    let _ = mouse_command_ack(mouse_cmd::SET_SAMPLE_RATE);
    let _ = mouse_command_ack(80);

    // Check device ID
    if mouse_command_ack(mouse_cmd::GET_DEVICE_ID) {
        if let Some(id) = mouse_read() {
            MOUSE_TYPE.store(id as u32, Ordering::SeqCst);
            if id == 3 {
                // IntelliMouse - 4 byte packets
                let mut buf = PACKET_BUFFER.lock();
                buf.packet_size = 4;
                crate::serial_println!("[MOUSE] IntelliMouse detected (scroll wheel)");
            } else if id == 4 {
                // IntelliMouse Explorer - 4 byte packets with extra buttons
                let mut buf = PACKET_BUFFER.lock();
                buf.packet_size = 4;
                crate::serial_println!("[MOUSE] IntelliMouse Explorer detected");
            } else {
                crate::serial_println!("[MOUSE] Standard mouse (ID: {})", id);
            }
        }
    }

    // Set sample rate to 100 samples/sec
    let _ = mouse_command_ack(mouse_cmd::SET_SAMPLE_RATE);
    let _ = mouse_command_ack(100);

    // Set resolution to 4 counts/mm
    let _ = mouse_command_ack(mouse_cmd::SET_RESOLUTION);
    let _ = mouse_command_ack(2); // 0=1, 1=2, 2=4, 3=8 counts/mm

    // Enable data reporting
    if !mouse_command_ack(mouse_cmd::ENABLE_REPORTING) {
        return Err("Failed to enable reporting");
    }

    MOUSE_INITIALIZED.store(true, Ordering::SeqCst);
    MOUSE_ENABLED.store(true, Ordering::SeqCst);

    crate::serial_println!("[MOUSE] PS/2 mouse initialized");
    Ok(())
}

/// Handle mouse interrupt (IRQ12)
pub fn handle_interrupt() {
    if !MOUSE_INITIALIZED.load(Ordering::SeqCst) {
        // Drain the byte to clear interrupt
        let _ = unsafe { inb(ps2_ports::DATA) };
        return;
    }

    let byte = unsafe { inb(ps2_ports::DATA) };

    let mut buf = PACKET_BUFFER.lock();

    // First byte must have bit 3 set (always 1)
    if buf.pos == 0 && (byte & 0x08) == 0 {
        // Out of sync, skip
        return;
    }

    if buf.push(byte) {
        // Packet complete
        PACKETS_RECEIVED.fetch_add(1, Ordering::Relaxed);

        // Parse packet
        let packet = buf.data;
        let packet_size = buf.packet_size;
        buf.reset();
        drop(buf);

        // Decode packet
        let buttons = MouseButtons {
            left: (packet[0] & 0x01) != 0,
            right: (packet[0] & 0x02) != 0,
            middle: (packet[0] & 0x04) != 0,
            button4: if packet_size == 4 { (packet[3] & 0x10) != 0 } else { false },
            button5: if packet_size == 4 { (packet[3] & 0x20) != 0 } else { false },
        };

        // X/Y movement (9-bit signed)
        let dx_raw = packet[1] as i16;
        let dy_raw = packet[2] as i16;

        // Sign extend using overflow bits
        let dx = if (packet[0] & 0x10) != 0 {
            dx_raw - 256
        } else {
            dx_raw
        };
        let dy = if (packet[0] & 0x20) != 0 {
            dy_raw - 256
        } else {
            dy_raw
        };

        // Scroll wheel (4th byte for IntelliMouse)
        let dz = if packet_size == 4 {
            (packet[3] & 0x0F) as i8
        } else {
            0
        };

        // Create event
        let event = MouseEvent { dx, dy: -dy, dz, buttons };

        // Update position
        let w = SCREEN_WIDTH.load(Ordering::Relaxed) as i32;
        let h = SCREEN_HEIGHT.load(Ordering::Relaxed) as i32;

        let mut x = MOUSE_X.load(Ordering::Relaxed);
        let mut y = MOUSE_Y.load(Ordering::Relaxed);
        x = (x + dx as i32).max(0).min(w - 1);
        y = (y + (-dy) as i32).max(0).min(h - 1);
        MOUSE_X.store(x, Ordering::Relaxed);
        MOUSE_Y.store(y, Ordering::Relaxed);

        // Update button state
        unsafe { BUTTON_STATE = buttons; }

        // Queue event
        let mut queue = EVENT_QUEUE.lock();
        if queue.push(event) {
            EVENTS_GENERATED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Get next mouse event
pub fn poll_event() -> Option<MouseEvent> {
    let mut queue = EVENT_QUEUE.lock();
    queue.pop()
}

/// Check if events are pending
pub fn events_pending() -> bool {
    let queue = EVENT_QUEUE.lock();
    queue.len() > 0
}

/// Get current mouse position
pub fn get_position() -> (i32, i32) {
    (
        MOUSE_X.load(Ordering::Relaxed),
        MOUSE_Y.load(Ordering::Relaxed),
    )
}

/// Set mouse position
pub fn set_position(x: i32, y: i32) {
    let w = SCREEN_WIDTH.load(Ordering::Relaxed) as i32;
    let h = SCREEN_HEIGHT.load(Ordering::Relaxed) as i32;
    MOUSE_X.store(x.max(0).min(w - 1), Ordering::Relaxed);
    MOUSE_Y.store(y.max(0).min(h - 1), Ordering::Relaxed);
}

/// Set screen dimensions (for position clamping)
pub fn set_screen_size(width: u32, height: u32) {
    SCREEN_WIDTH.store(width, Ordering::Relaxed);
    SCREEN_HEIGHT.store(height, Ordering::Relaxed);
}

/// Get current button state
pub fn get_buttons() -> MouseButtons {
    unsafe { BUTTON_STATE }
}

/// Get mouse statistics
pub fn get_stats() -> (u32, u32, u32) {
    (
        MOUSE_TYPE.load(Ordering::Relaxed),
        PACKETS_RECEIVED.load(Ordering::Relaxed),
        EVENTS_GENERATED.load(Ordering::Relaxed),
    )
}

/// Check if mouse is initialized
pub fn is_initialized() -> bool {
    MOUSE_INITIALIZED.load(Ordering::SeqCst)
}

/// Enable/disable mouse
pub fn set_enabled(enabled: bool) {
    if MOUSE_INITIALIZED.load(Ordering::SeqCst) {
        if enabled {
            let _ = mouse_command_ack(mouse_cmd::ENABLE_REPORTING);
        } else {
            let _ = mouse_command_ack(mouse_cmd::DISABLE_REPORTING);
        }
        MOUSE_ENABLED.store(enabled, Ordering::SeqCst);
    }
}
