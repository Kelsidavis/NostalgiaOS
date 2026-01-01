//! HAL Display Support
//!
//! Provides low-level display output for bugchecks:
//!
//! - **Bugcheck Display**: Blue screen text output
//! - **VGA Text Mode**: Direct framebuffer access
//! - **Serial Fallback**: Output to serial port
//! - **Video Reset**: Reset display to known state
//!
//! # Display Modes
//!
//! - VGA text mode (80x25 or 80x50)
//! - VGA graphics mode (for modern displays)
//! - UEFI GOP framebuffer
//! - Serial console fallback
//!
//! # Colors
//!
//! VGA text mode uses 4-bit colors:
//! - Background: 0-7 (no bright)
//! - Foreground: 0-15 (with bright)
//!
//! # NT Functions
//!
//! - `HalDisplayString` - Write string to screen
//! - `HalQueryDisplayParameters` - Get display info
//! - `HalSetDisplayParameters` - Set display mode
//!
//! # Usage
//!
//! ```ignore
//! // Initialize display
//! display_init();
//!
//! // Show bugcheck screen
//! display_bugcheck_screen(KERNEL_MODE_EXCEPTION, 0, 0, 0, 0);
//!
//! // Write text
//! display_write_string("STOP: 0x0000001E\n");
//! ```

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;

// ============================================================================
// Constants
// ============================================================================

/// VGA text mode framebuffer address
pub const VGA_BUFFER_ADDR: u64 = 0xB8000;

/// VGA text mode width
pub const VGA_WIDTH: usize = 80;

/// VGA text mode height (standard)
pub const VGA_HEIGHT: usize = 25;

/// VGA text mode height (extended)
pub const VGA_HEIGHT_50: usize = 50;

/// Default bugcheck background color (blue)
pub const BSOD_BACKGROUND: u8 = 0x10;

/// Default bugcheck foreground color (white)
pub const BSOD_FOREGROUND: u8 = 0x0F;

/// Default text attribute for bugcheck
pub const BSOD_ATTRIBUTE: u8 = BSOD_BACKGROUND | BSOD_FOREGROUND;

// ============================================================================
// VGA Colors
// ============================================================================

/// VGA color palette
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VgaColor {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    LightMagenta = 13,
    Yellow = 14,
    White = 15,
}

impl VgaColor {
    /// Create attribute byte from foreground and background
    pub const fn make_attr(fg: VgaColor, bg: VgaColor) -> u8 {
        ((bg as u8) << 4) | (fg as u8)
    }
}

// ============================================================================
// Types
// ============================================================================

/// Display mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisplayMode {
    #[default]
    None = 0,
    VgaText = 1,
    VgaGraphics = 2,
    GopFramebuffer = 3,
    Serial = 4,
}

/// Display information
#[derive(Debug, Clone, Copy, Default)]
pub struct DisplayInfo {
    pub mode: DisplayMode,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub bpp: u8,
    pub framebuffer: u64,
    pub framebuffer_size: u64,
}

/// Cursor position
#[derive(Debug, Clone, Copy, Default)]
pub struct CursorPos {
    pub x: u16,
    pub y: u16,
}

// ============================================================================
// Global State
// ============================================================================

static DISPLAY_LOCK: SpinLock<()> = SpinLock::new(());
static DISPLAY_INITIALIZED: AtomicBool = AtomicBool::new(false);
static DISPLAY_MODE: AtomicU32 = AtomicU32::new(DisplayMode::None as u32);

static CURSOR_X: AtomicU16 = AtomicU16::new(0);
static CURSOR_Y: AtomicU16 = AtomicU16::new(0);
static SCREEN_WIDTH: AtomicU16 = AtomicU16::new(VGA_WIDTH as u16);
static SCREEN_HEIGHT: AtomicU16 = AtomicU16::new(VGA_HEIGHT as u16);

static CURRENT_ATTR: AtomicU16 = AtomicU16::new(0x07);  // Light gray on black
static BUGCHECK_ACTIVE: AtomicBool = AtomicBool::new(false);

static CHARS_WRITTEN: AtomicU64 = AtomicU64::new(0);
static LINES_SCROLLED: AtomicU64 = AtomicU64::new(0);

/// GOP framebuffer info (set by bootloader)
static GOP_FRAMEBUFFER: AtomicU64 = AtomicU64::new(0);
static GOP_WIDTH: AtomicU32 = AtomicU32::new(0);
static GOP_HEIGHT: AtomicU32 = AtomicU32::new(0);
static GOP_STRIDE: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// VGA Port Access
// ============================================================================

mod vga_ports {
    pub const MISC_OUTPUT_READ: u16 = 0x3CC;
    pub const MISC_OUTPUT_WRITE: u16 = 0x3C2;
    pub const SEQ_INDEX: u16 = 0x3C4;
    pub const SEQ_DATA: u16 = 0x3C5;
    pub const CRTC_INDEX: u16 = 0x3D4;
    pub const CRTC_DATA: u16 = 0x3D5;
    pub const GC_INDEX: u16 = 0x3CE;
    pub const GC_DATA: u16 = 0x3CF;
    pub const AC_INDEX: u16 = 0x3C0;
    pub const AC_READ: u16 = 0x3C1;
    pub const INPUT_STATUS: u16 = 0x3DA;
}

// ============================================================================
// VGA Text Mode
// ============================================================================

/// Get VGA buffer pointer
fn vga_buffer() -> *mut u16 {
    VGA_BUFFER_ADDR as *mut u16
}

/// Write character at position
fn vga_write_char(x: u16, y: u16, ch: u8, attr: u8) {
    if x as usize >= VGA_WIDTH || y as usize >= VGA_HEIGHT {
        return;
    }

    let offset = (y as usize * VGA_WIDTH + x as usize) as isize;
    let entry = (attr as u16) << 8 | (ch as u16);

    unsafe {
        *vga_buffer().offset(offset) = entry;
    }
}

/// Read character at position
fn vga_read_char(x: u16, y: u16) -> (u8, u8) {
    if x as usize >= VGA_WIDTH || y as usize >= VGA_HEIGHT {
        return (0, 0);
    }

    let offset = (y as usize * VGA_WIDTH + x as usize) as isize;
    let entry = unsafe { *vga_buffer().offset(offset) };

    ((entry & 0xFF) as u8, (entry >> 8) as u8)
}

/// Clear screen with attribute
fn vga_clear_screen(attr: u8) {
    let entry = (attr as u16) << 8 | (' ' as u16);
    let height = SCREEN_HEIGHT.load(Ordering::Relaxed) as usize;

    for i in 0..(VGA_WIDTH * height) {
        unsafe {
            *vga_buffer().add(i) = entry;
        }
    }

    CURSOR_X.store(0, Ordering::Relaxed);
    CURSOR_Y.store(0, Ordering::Relaxed);
}

/// Scroll screen up by one line
fn vga_scroll_up() {
    let width = SCREEN_WIDTH.load(Ordering::Relaxed) as usize;
    let height = SCREEN_HEIGHT.load(Ordering::Relaxed) as usize;
    let attr = CURRENT_ATTR.load(Ordering::Relaxed) as u8;

    // Move lines up
    for row in 1..height {
        for col in 0..width {
            let (ch, a) = vga_read_char(col as u16, row as u16);
            vga_write_char(col as u16, (row - 1) as u16, ch, a);
        }
    }

    // Clear last line
    let blank = (attr as u16) << 8 | (' ' as u16);
    for col in 0..width {
        unsafe {
            *vga_buffer().add((height - 1) * width + col) = blank;
        }
    }

    LINES_SCROLLED.fetch_add(1, Ordering::Relaxed);
}

/// Update hardware cursor position
fn vga_update_cursor(x: u16, y: u16) {
    let pos = y as u16 * VGA_WIDTH as u16 + x as u16;

    #[cfg(target_arch = "x86_64")]
    unsafe {
        super::port::write_port_u8(vga_ports::CRTC_INDEX, 0x0F);
        super::port::write_port_u8(vga_ports::CRTC_DATA, (pos & 0xFF) as u8);
        super::port::write_port_u8(vga_ports::CRTC_INDEX, 0x0E);
        super::port::write_port_u8(vga_ports::CRTC_DATA, ((pos >> 8) & 0xFF) as u8);
    }
}

/// Enable/disable cursor
fn vga_set_cursor_visible(visible: bool) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        super::port::write_port_u8(vga_ports::CRTC_INDEX, 0x0A);
        if visible {
            super::port::write_port_u8(vga_ports::CRTC_DATA, 0x0E);
        } else {
            super::port::write_port_u8(vga_ports::CRTC_DATA, 0x20);
        }
    }
}

// ============================================================================
// Text Output
// ============================================================================

/// Write a character to the display
pub fn display_write_char(ch: char) {
    let mode = DisplayMode::try_from(DISPLAY_MODE.load(Ordering::Relaxed) as u8).unwrap_or(DisplayMode::None);

    match mode {
        DisplayMode::VgaText => {
            let mut x = CURSOR_X.load(Ordering::Relaxed);
            let mut y = CURSOR_Y.load(Ordering::Relaxed);
            let width = SCREEN_WIDTH.load(Ordering::Relaxed);
            let height = SCREEN_HEIGHT.load(Ordering::Relaxed);
            let attr = CURRENT_ATTR.load(Ordering::Relaxed) as u8;

            match ch {
                '\n' => {
                    x = 0;
                    y += 1;
                }
                '\r' => {
                    x = 0;
                }
                '\t' => {
                    x = (x + 8) & !7;
                    if x >= width {
                        x = 0;
                        y += 1;
                    }
                }
                _ => {
                    if ch.is_ascii() {
                        vga_write_char(x, y, ch as u8, attr);
                        x += 1;
                        if x >= width {
                            x = 0;
                            y += 1;
                        }
                    }
                }
            }

            // Scroll if needed
            while y >= height {
                vga_scroll_up();
                y -= 1;
            }

            CURSOR_X.store(x, Ordering::Relaxed);
            CURSOR_Y.store(y, Ordering::Relaxed);
            vga_update_cursor(x, y);
        }
        DisplayMode::Serial | DisplayMode::None => {
            // Output to serial
            crate::serial_print!("{}", ch);
        }
        _ => {}
    }

    CHARS_WRITTEN.fetch_add(1, Ordering::Relaxed);
}

/// Write a string to the display
pub fn display_write_string(s: &str) {
    for ch in s.chars() {
        display_write_char(ch);
    }
}

/// Write a byte as hexadecimal
pub fn display_write_hex(value: u64, width: usize) {
    const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";

    for i in (0..width).rev() {
        let nibble = ((value >> (i * 4)) & 0xF) as usize;
        display_write_char(HEX_CHARS[nibble] as char);
    }
}

// ============================================================================
// Display Control
// ============================================================================

/// Set text attribute
pub fn display_set_attribute(fg: VgaColor, bg: VgaColor) {
    let attr = VgaColor::make_attr(fg, bg);
    CURRENT_ATTR.store(attr as u16, Ordering::Relaxed);
}

/// Get current cursor position
pub fn display_get_cursor() -> CursorPos {
    CursorPos {
        x: CURSOR_X.load(Ordering::Relaxed),
        y: CURSOR_Y.load(Ordering::Relaxed),
    }
}

/// Set cursor position
pub fn display_set_cursor(x: u16, y: u16) {
    let width = SCREEN_WIDTH.load(Ordering::Relaxed);
    let height = SCREEN_HEIGHT.load(Ordering::Relaxed);

    let x = x.min(width - 1);
    let y = y.min(height - 1);

    CURSOR_X.store(x, Ordering::Relaxed);
    CURSOR_Y.store(y, Ordering::Relaxed);
    vga_update_cursor(x, y);
}

/// Clear the screen
pub fn display_clear() {
    let attr = CURRENT_ATTR.load(Ordering::Relaxed) as u8;
    vga_clear_screen(attr);
}

// ============================================================================
// Bugcheck Display
// ============================================================================

/// Show bugcheck (blue screen) display
pub fn display_bugcheck_screen(
    code: u32,
    param1: u64,
    param2: u64,
    param3: u64,
    param4: u64,
) {
    let _guard = DISPLAY_LOCK.lock();

    BUGCHECK_ACTIVE.store(true, Ordering::Release);

    // Set BSOD colors
    CURRENT_ATTR.store(BSOD_ATTRIBUTE as u16, Ordering::Relaxed);

    // Clear screen with blue background
    vga_clear_screen(BSOD_ATTRIBUTE);

    // Hide cursor
    vga_set_cursor_visible(false);

    // Display header
    display_set_cursor(0, 0);
    display_write_string("\n\n");
    display_write_string("   A problem has been detected and Windows has been shut down to prevent damage\n");
    display_write_string("   to your computer.\n\n");

    // Display stop code
    display_write_string("   ");
    display_write_string(bugcheck_name(code));
    display_write_string("\n\n");

    // Display parameters
    display_write_string("   STOP: 0x");
    display_write_hex(code as u64, 8);
    display_write_string(" (0x");
    display_write_hex(param1, 16);
    display_write_string(", 0x");
    display_write_hex(param2, 16);
    display_write_string(",\n         0x");
    display_write_hex(param3, 16);
    display_write_string(", 0x");
    display_write_hex(param4, 16);
    display_write_string(")\n\n");

    // Technical information
    display_write_string("   Technical information:\n\n");
    display_write_string("   *** STOP: 0x");
    display_write_hex(code as u64, 8);
    display_write_string("\n\n");

    // Instructions
    display_write_string("   If this is the first time you've seen this Stop error screen,\n");
    display_write_string("   restart your computer. If this screen appears again, follow\n");
    display_write_string("   these steps:\n\n");

    display_write_string("   Check to make sure any new hardware or software is properly installed.\n");
    display_write_string("   If this is a new installation, ask your hardware or software manufacturer\n");
    display_write_string("   for any Windows updates you might need.\n\n");

    display_write_string("   If problems continue, disable or remove any newly installed hardware\n");
    display_write_string("   or software. Disable BIOS memory options such as caching or shadowing.\n");
}

/// Get bugcheck name from code
fn bugcheck_name(code: u32) -> &'static str {
    match code {
        0x0000001E => "KMODE_EXCEPTION_NOT_HANDLED",
        0x0000003B => "SYSTEM_SERVICE_EXCEPTION",
        0x00000050 => "PAGE_FAULT_IN_NONPAGED_AREA",
        0x0000007E => "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        0x0000007F => "UNEXPECTED_KERNEL_MODE_TRAP",
        0x0000009C => "MACHINE_CHECK_EXCEPTION",
        0x000000D1 => "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        0x000000FC => "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
        0x00000101 => "CLOCK_WATCHDOG_TIMEOUT",
        0x00000124 => "WHEA_UNCORRECTABLE_ERROR",
        _ => "UNKNOWN_BUGCHECK",
    }
}

/// Check if bugcheck is active
pub fn display_is_bugcheck_active() -> bool {
    BUGCHECK_ACTIVE.load(Ordering::Relaxed)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize display subsystem
pub fn init() {
    let _guard = DISPLAY_LOCK.lock();

    // Default to VGA text mode
    DISPLAY_MODE.store(DisplayMode::VgaText as u32, Ordering::Relaxed);
    SCREEN_WIDTH.store(VGA_WIDTH as u16, Ordering::Relaxed);
    SCREEN_HEIGHT.store(VGA_HEIGHT as u16, Ordering::Relaxed);
    CURRENT_ATTR.store(0x07, Ordering::Relaxed);

    // Clear screen
    vga_clear_screen(0x07);
    vga_set_cursor_visible(true);

    DISPLAY_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[Display] Initialized (VGA text mode)");
}

/// Set GOP framebuffer parameters (called by bootloader)
pub fn display_set_gop(framebuffer: u64, width: u32, height: u32, stride: u32) {
    GOP_FRAMEBUFFER.store(framebuffer, Ordering::Relaxed);
    GOP_WIDTH.store(width, Ordering::Relaxed);
    GOP_HEIGHT.store(height, Ordering::Relaxed);
    GOP_STRIDE.store(stride, Ordering::Relaxed);

    if framebuffer != 0 {
        DISPLAY_MODE.store(DisplayMode::GopFramebuffer as u32, Ordering::Relaxed);
    }
}

// ============================================================================
// Query Functions
// ============================================================================

/// Get display information
pub fn display_get_info() -> DisplayInfo {
    let mode = DisplayMode::try_from(DISPLAY_MODE.load(Ordering::Relaxed) as u8)
        .unwrap_or(DisplayMode::None);

    match mode {
        DisplayMode::VgaText => DisplayInfo {
            mode,
            width: SCREEN_WIDTH.load(Ordering::Relaxed) as u32,
            height: SCREEN_HEIGHT.load(Ordering::Relaxed) as u32,
            stride: VGA_WIDTH as u32 * 2,
            bpp: 16,
            framebuffer: VGA_BUFFER_ADDR,
            framebuffer_size: (VGA_WIDTH * VGA_HEIGHT * 2) as u64,
        },
        DisplayMode::GopFramebuffer => DisplayInfo {
            mode,
            width: GOP_WIDTH.load(Ordering::Relaxed),
            height: GOP_HEIGHT.load(Ordering::Relaxed),
            stride: GOP_STRIDE.load(Ordering::Relaxed),
            bpp: 32,
            framebuffer: GOP_FRAMEBUFFER.load(Ordering::Relaxed),
            framebuffer_size: (GOP_STRIDE.load(Ordering::Relaxed)
                * GOP_HEIGHT.load(Ordering::Relaxed)) as u64,
        },
        _ => DisplayInfo::default(),
    }
}

/// Get display mode
pub fn display_get_mode() -> DisplayMode {
    DisplayMode::try_from(DISPLAY_MODE.load(Ordering::Relaxed) as u8)
        .unwrap_or(DisplayMode::None)
}

/// Check if display is initialized
pub fn display_is_initialized() -> bool {
    DISPLAY_INITIALIZED.load(Ordering::Acquire)
}

// ============================================================================
// DisplayMode conversion
// ============================================================================

impl TryFrom<u8> for DisplayMode {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DisplayMode::None),
            1 => Ok(DisplayMode::VgaText),
            2 => Ok(DisplayMode::VgaGraphics),
            3 => Ok(DisplayMode::GopFramebuffer),
            4 => Ok(DisplayMode::Serial),
            _ => Err(()),
        }
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Display statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct DisplayStats {
    pub initialized: bool,
    pub mode: DisplayMode,
    pub width: u32,
    pub height: u32,
    pub cursor_x: u16,
    pub cursor_y: u16,
    pub chars_written: u64,
    pub lines_scrolled: u64,
    pub bugcheck_active: bool,
}

/// Get display statistics
pub fn display_get_stats() -> DisplayStats {
    DisplayStats {
        initialized: DISPLAY_INITIALIZED.load(Ordering::Relaxed),
        mode: display_get_mode(),
        width: SCREEN_WIDTH.load(Ordering::Relaxed) as u32,
        height: SCREEN_HEIGHT.load(Ordering::Relaxed) as u32,
        cursor_x: CURSOR_X.load(Ordering::Relaxed),
        cursor_y: CURSOR_Y.load(Ordering::Relaxed),
        chars_written: CHARS_WRITTEN.load(Ordering::Relaxed),
        lines_scrolled: LINES_SCROLLED.load(Ordering::Relaxed),
        bugcheck_active: BUGCHECK_ACTIVE.load(Ordering::Relaxed),
    }
}

// ============================================================================
// NT Compatibility
// ============================================================================

/// HalDisplayString equivalent
pub fn hal_display_string(s: &str) {
    display_write_string(s);
}

/// HalQueryDisplayParameters equivalent
pub fn hal_query_display_parameters() -> (u32, u32, u32, u32) {
    let info = display_get_info();
    (info.width, info.height, info.stride, info.bpp as u32)
}

/// InbvDisplayString equivalent (used during boot)
pub fn inbv_display_string(s: &str) {
    display_write_string(s);
}

/// InbvSetTextColor equivalent
pub fn inbv_set_text_color(color: u32) {
    let fg = VgaColor::try_from((color & 0x0F) as u8).unwrap_or(VgaColor::White);
    let bg = VgaColor::try_from(((color >> 4) & 0x07) as u8).unwrap_or(VgaColor::Black);
    display_set_attribute(fg, bg);
}

impl TryFrom<u8> for VgaColor {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(VgaColor::Black),
            1 => Ok(VgaColor::Blue),
            2 => Ok(VgaColor::Green),
            3 => Ok(VgaColor::Cyan),
            4 => Ok(VgaColor::Red),
            5 => Ok(VgaColor::Magenta),
            6 => Ok(VgaColor::Brown),
            7 => Ok(VgaColor::LightGray),
            8 => Ok(VgaColor::DarkGray),
            9 => Ok(VgaColor::LightBlue),
            10 => Ok(VgaColor::LightGreen),
            11 => Ok(VgaColor::LightCyan),
            12 => Ok(VgaColor::LightRed),
            13 => Ok(VgaColor::LightMagenta),
            14 => Ok(VgaColor::Yellow),
            15 => Ok(VgaColor::White),
            _ => Err(()),
        }
    }
}
