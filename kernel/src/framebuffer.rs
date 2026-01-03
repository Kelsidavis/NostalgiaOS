//! Framebuffer output for early kernel messages
//!
//! Provides basic text output to the UEFI framebuffer before proper
//! display drivers are loaded.

use core::fmt::{self, Write};
use core::ptr;
use spin::Mutex;

use crate::BootInfo;

/// Font width in pixels
const FONT_WIDTH: u32 = 8;

/// Font height in pixels
const FONT_HEIGHT: u32 = 16;

/// Basic 8x16 font (CP437-style)
/// Each character is 16 bytes, one byte per row
static FONT: &[u8] = include_bytes!("font8x16.bin");

/// Framebuffer writer state
struct FramebufferWriter {
    /// Framebuffer base address
    buffer: *mut u32,
    /// Width in pixels
    width: u32,
    /// Height in pixels
    height: u32,
    /// Stride in pixels
    stride: u32,
    /// Current cursor X position (in characters)
    cursor_x: u32,
    /// Current cursor Y position (in characters)
    cursor_y: u32,
    /// Foreground color
    fg_color: u32,
    /// Background color
    bg_color: u32,
}

unsafe impl Send for FramebufferWriter {}

impl FramebufferWriter {
    /// Create a new uninitialized framebuffer writer
    const fn new() -> Self {
        Self {
            buffer: ptr::null_mut(),
            width: 0,
            height: 0,
            stride: 0,
            cursor_x: 0,
            cursor_y: 0,
            fg_color: 0x00FFFFFF, // White
            bg_color: 0x00000080, // Dark blue
        }
    }

    /// Initialize from boot info
    fn init(&mut self, boot_info: &BootInfo) {
        self.buffer = boot_info.framebuffer_addr as *mut u32;
        self.width = boot_info.framebuffer_width;
        self.height = boot_info.framebuffer_height;
        // stride is in bytes, we need pixels
        self.stride = boot_info.framebuffer_stride / 4;
        self.cursor_x = 0;
        self.cursor_y = 0;

        // Clear screen with background color
        self.clear();
    }

    /// Check if initialized
    fn is_initialized(&self) -> bool {
        !self.buffer.is_null() && self.width > 0 && self.height > 0
    }

    /// Clear the screen
    fn clear(&mut self) {
        if !self.is_initialized() {
            return;
        }

        for y in 0..self.height {
            for x in 0..self.width {
                unsafe {
                    let offset = (y * self.stride + x) as isize;
                    ptr::write_volatile(self.buffer.offset(offset), self.bg_color);
                }
            }
        }
        self.cursor_x = 0;
        self.cursor_y = 0;
    }

    /// Get maximum columns
    fn max_cols(&self) -> u32 {
        self.width / FONT_WIDTH
    }

    /// Get maximum rows
    fn max_rows(&self) -> u32 {
        self.height / FONT_HEIGHT
    }

    /// Scroll up one line
    fn scroll_up(&mut self) {
        if !self.is_initialized() {
            return;
        }

        // Copy each line up
        let line_height = FONT_HEIGHT;
        let bytes_per_line = self.stride;

        for y in 0..(self.height - line_height) {
            for x in 0..self.width {
                unsafe {
                    let src_offset = ((y + line_height) * bytes_per_line + x) as isize;
                    let dst_offset = (y * bytes_per_line + x) as isize;
                    let pixel = ptr::read_volatile(self.buffer.offset(src_offset));
                    ptr::write_volatile(self.buffer.offset(dst_offset), pixel);
                }
            }
        }

        // Clear the last line
        for y in (self.height - line_height)..self.height {
            for x in 0..self.width {
                unsafe {
                    let offset = (y * bytes_per_line + x) as isize;
                    ptr::write_volatile(self.buffer.offset(offset), self.bg_color);
                }
            }
        }
    }

    /// Put a character at the current cursor position
    fn put_char(&mut self, c: char) {
        if !self.is_initialized() {
            return;
        }

        match c {
            '\n' => {
                self.cursor_x = 0;
                self.cursor_y += 1;
                if self.cursor_y >= self.max_rows() {
                    self.scroll_up();
                    self.cursor_y = self.max_rows() - 1;
                }
            }
            '\r' => {
                self.cursor_x = 0;
            }
            '\t' => {
                // Tab to next 8-column boundary
                self.cursor_x = (self.cursor_x + 8) & !7;
                if self.cursor_x >= self.max_cols() {
                    self.cursor_x = 0;
                    self.cursor_y += 1;
                    if self.cursor_y >= self.max_rows() {
                        self.scroll_up();
                        self.cursor_y = self.max_rows() - 1;
                    }
                }
            }
            c => {
                self.draw_char(c);
                self.cursor_x += 1;
                if self.cursor_x >= self.max_cols() {
                    self.cursor_x = 0;
                    self.cursor_y += 1;
                    if self.cursor_y >= self.max_rows() {
                        self.scroll_up();
                        self.cursor_y = self.max_rows() - 1;
                    }
                }
            }
        }
    }

    /// Draw a character at the current cursor position
    fn draw_char(&mut self, c: char) {
        let char_index = if c.is_ascii() { c as usize } else { '?' as usize };

        // Get font data for this character (16 bytes)
        let font_offset = char_index * 16;
        if font_offset + 16 > FONT.len() {
            return;
        }

        let char_data = &FONT[font_offset..font_offset + 16];

        let screen_x = self.cursor_x * FONT_WIDTH;
        let screen_y = self.cursor_y * FONT_HEIGHT;

        for (row, &byte) in char_data.iter().enumerate() {
            for col in 0..8 {
                let pixel_x = screen_x + col;
                let pixel_y = screen_y + row as u32;

                if pixel_x >= self.width || pixel_y >= self.height {
                    continue;
                }

                let color = if (byte >> (7 - col)) & 1 != 0 {
                    self.fg_color
                } else {
                    self.bg_color
                };

                unsafe {
                    let offset = (pixel_y * self.stride + pixel_x) as isize;
                    ptr::write_volatile(self.buffer.offset(offset), color);
                }
            }
        }
    }
}

impl Write for FramebufferWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            self.put_char(c);
        }
        Ok(())
    }
}

/// Global framebuffer writer
static WRITER: Mutex<FramebufferWriter> = Mutex::new(FramebufferWriter::new());

/// Flag to disable text output (when graphical desktop is active)
static DISABLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Initialize the framebuffer
pub fn init(boot_info: &BootInfo) {
    WRITER.lock().init(boot_info);
}

/// Disable framebuffer text output (for graphical desktop)
pub fn disable() {
    DISABLED.store(true, core::sync::atomic::Ordering::Release);
}

/// Re-enable framebuffer text output
pub fn enable() {
    DISABLED.store(false, core::sync::atomic::Ordering::Release);
}

/// Check if framebuffer text is disabled
pub fn is_disabled() -> bool {
    DISABLED.load(core::sync::atomic::Ordering::Acquire)
}

/// Print to the framebuffer
#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    // Skip if disabled for graphical mode
    if DISABLED.load(core::sync::atomic::Ordering::Acquire) {
        return;
    }
    use core::fmt::Write;
    WRITER.lock().write_fmt(args).unwrap();
}

/// Print macro
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => ($crate::framebuffer::_print(format_args!($($arg)*)));
}

/// Print with newline macro
#[macro_export]
macro_rules! kprintln {
    () => ($crate::kprint!("\n"));
    ($($arg:tt)*) => ($crate::kprint!("{}\n", format_args!($($arg)*)));
}
