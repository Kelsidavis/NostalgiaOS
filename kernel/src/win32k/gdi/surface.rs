//! Surface/Bitmap Implementation
//!
//! Surfaces represent drawable areas - either the screen framebuffer
//! or in-memory bitmaps for off-screen rendering.
//!
//! # Surface Types
//!
//! - **Primary**: The main display framebuffer
//! - **DIB**: Device-Independent Bitmap (memory)
//! - **DDB**: Device-Dependent Bitmap
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntgdi/gre/surfobj.cxx`

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{GdiHandle, ColorRef, Rect};
use alloc::alloc::{alloc_zeroed, Layout};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of surfaces
pub const MAX_SURFACES: usize = 256;

// ============================================================================
// Types
// ============================================================================

/// Surface handle (internal)
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceHandle(u32);

impl SurfaceHandle {
    pub const NULL: SurfaceHandle = SurfaceHandle(0);
    pub const PRIMARY: SurfaceHandle = SurfaceHandle(1);

    pub const fn new(index: u16) -> Self {
        SurfaceHandle(index as u32)
    }

    pub const fn index(self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }

    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

/// Surface type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SurfaceType {
    #[default]
    None = 0,
    Primary = 1,      // Screen framebuffer
    DeviceBitmap = 2, // DDB
    DIBSection = 3,   // DIB
}

/// Pixel format
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PixelFormat {
    #[default]
    Unknown = 0,
    Indexed1 = 1,     // 1 bpp indexed
    Indexed4 = 2,     // 4 bpp indexed
    Indexed8 = 3,     // 8 bpp indexed
    Rgb555 = 4,       // 15 bpp (5-5-5)
    Rgb565 = 5,       // 16 bpp (5-6-5)
    Rgb24 = 6,        // 24 bpp (8-8-8)
    Rgb32 = 7,        // 32 bpp (8-8-8-8)
    Argb32 = 8,       // 32 bpp with alpha
}

impl PixelFormat {
    pub const fn bits_per_pixel(self) -> u8 {
        match self {
            PixelFormat::Unknown => 0,
            PixelFormat::Indexed1 => 1,
            PixelFormat::Indexed4 => 4,
            PixelFormat::Indexed8 => 8,
            PixelFormat::Rgb555 => 16,
            PixelFormat::Rgb565 => 16,
            PixelFormat::Rgb24 => 24,
            PixelFormat::Rgb32 | PixelFormat::Argb32 => 32,
        }
    }

    pub const fn bytes_per_pixel(self) -> u8 {
        (self.bits_per_pixel() + 7) / 8
    }
}

// ============================================================================
// Surface Structure
// ============================================================================

/// Surface object
#[derive(Debug, Clone)]
pub struct Surface {
    /// Surface type
    pub surf_type: SurfaceType,

    /// Pixel format
    pub format: PixelFormat,

    /// Width in pixels
    pub width: u32,

    /// Height in pixels
    pub height: u32,

    /// Bytes per scanline (stride)
    pub stride: u32,

    /// Bits per pixel
    pub bpp: u8,

    /// Framebuffer/bitmap data pointer
    pub bits: u64,

    /// Size of bits in bytes
    pub size: u64,

    /// Reference count
    pub ref_count: u32,

    /// Valid flag
    pub valid: bool,
}

impl Default for Surface {
    fn default() -> Self {
        Self {
            surf_type: SurfaceType::None,
            format: PixelFormat::Unknown,
            width: 0,
            height: 0,
            stride: 0,
            bpp: 0,
            bits: 0,
            size: 0,
            ref_count: 0,
            valid: false,
        }
    }
}

impl Surface {
    /// Get pixel offset in bits
    pub fn pixel_offset(&self, x: i32, y: i32) -> Option<usize> {
        if x < 0 || y < 0 || x >= self.width as i32 || y >= self.height as i32 {
            return None;
        }

        let x = x as u32;
        let y = y as u32;

        Some((y * self.stride + x * (self.bpp as u32 / 8)) as usize)
    }

    /// Read pixel at (x, y)
    pub fn get_pixel(&self, x: i32, y: i32) -> Option<ColorRef> {
        let offset = self.pixel_offset(x, y)?;

        unsafe {
            let ptr = self.bits as *const u8;

            match self.format {
                PixelFormat::Rgb32 | PixelFormat::Argb32 => {
                    let pixel = *(ptr.add(offset) as *const u32);
                    // BGRA to RGB
                    Some(ColorRef::rgb(
                        ((pixel >> 16) & 0xFF) as u8,
                        ((pixel >> 8) & 0xFF) as u8,
                        (pixel & 0xFF) as u8,
                    ))
                }
                PixelFormat::Rgb24 => {
                    let b = *ptr.add(offset);
                    let g = *ptr.add(offset + 1);
                    let r = *ptr.add(offset + 2);
                    Some(ColorRef::rgb(r, g, b))
                }
                _ => None, // TODO: implement other formats
            }
        }
    }

    /// Write pixel at (x, y)
    pub fn set_pixel(&self, x: i32, y: i32, color: ColorRef) -> bool {
        let offset = match self.pixel_offset(x, y) {
            Some(o) => o,
            None => return false,
        };

        unsafe {
            let ptr = self.bits as *mut u8;

            match self.format {
                PixelFormat::Rgb32 | PixelFormat::Argb32 => {
                    let pixel = color.to_bgra();
                    *(ptr.add(offset) as *mut u32) = pixel;
                    true
                }
                PixelFormat::Rgb24 => {
                    *ptr.add(offset) = color.blue();
                    *ptr.add(offset + 1) = color.green();
                    *ptr.add(offset + 2) = color.red();
                    true
                }
                _ => false,
            }
        }
    }

    /// Fill rectangle with color
    pub fn fill_rect(&self, rect: &Rect, color: ColorRef) -> bool {
        let clip = Rect::new(0, 0, self.width as i32, self.height as i32);
        let rect = match rect.intersect(&clip) {
            Some(r) => r,
            None => return true, // Nothing to draw
        };

        unsafe {
            let ptr = self.bits as *mut u8;

            match self.format {
                PixelFormat::Rgb32 | PixelFormat::Argb32 => {
                    let pixel = color.to_bgra();

                    for y in rect.top..rect.bottom {
                        let row_offset = (y as u32 * self.stride) as usize;

                        for x in rect.left..rect.right {
                            let offset = row_offset + (x as u32 * 4) as usize;
                            *(ptr.add(offset) as *mut u32) = pixel;
                        }
                    }
                    true
                }
                _ => false,
            }
        }
    }

    /// Draw horizontal line
    pub fn hline(&self, x1: i32, x2: i32, y: i32, color: ColorRef) {
        if y < 0 || y >= self.height as i32 {
            return;
        }

        let x_start = x1.max(0);
        let x_end = x2.min(self.width as i32);

        if x_start >= x_end {
            return;
        }

        unsafe {
            let ptr = self.bits as *mut u8;

            match self.format {
                PixelFormat::Rgb32 | PixelFormat::Argb32 => {
                    let pixel = color.to_bgra();
                    let row_offset = (y as u32 * self.stride) as usize;

                    for x in x_start..x_end {
                        let offset = row_offset + (x as u32 * 4) as usize;
                        *(ptr.add(offset) as *mut u32) = pixel;
                    }
                }
                _ => {}
            }
        }
    }

    /// Draw vertical line
    pub fn vline(&self, x: i32, y1: i32, y2: i32, color: ColorRef) {
        if x < 0 || x >= self.width as i32 {
            return;
        }

        let y_start = y1.max(0);
        let y_end = y2.min(self.height as i32);

        if y_start >= y_end {
            return;
        }

        unsafe {
            let ptr = self.bits as *mut u8;

            match self.format {
                PixelFormat::Rgb32 | PixelFormat::Argb32 => {
                    let pixel = color.to_bgra();

                    for y in y_start..y_end {
                        let offset = (y as u32 * self.stride + x as u32 * 4) as usize;
                        *(ptr.add(offset) as *mut u32) = pixel;
                    }
                }
                _ => {}
            }
        }
    }
}

// ============================================================================
// Surface Table
// ============================================================================

struct SurfaceEntry {
    surface: Option<Surface>,
}

impl Default for SurfaceEntry {
    fn default() -> Self {
        Self { surface: None }
    }
}

static SURFACE_TABLE: SpinLock<SurfaceTable> = SpinLock::new(SurfaceTable::new());

struct SurfaceTable {
    entries: [SurfaceEntry; MAX_SURFACES],
}

impl SurfaceTable {
    const fn new() -> Self {
        const EMPTY: SurfaceEntry = SurfaceEntry { surface: None };
        Self {
            entries: [EMPTY; MAX_SURFACES],
        }
    }
}

// Primary display surface info (set during initialization)
static PRIMARY_FRAMEBUFFER: AtomicU64 = AtomicU64::new(0);
static PRIMARY_WIDTH: AtomicU32 = AtomicU32::new(0);
static PRIMARY_HEIGHT: AtomicU32 = AtomicU32::new(0);
static PRIMARY_STRIDE: AtomicU32 = AtomicU32::new(0);
static PRIMARY_BPP: AtomicU32 = AtomicU32::new(0);
static SURFACE_INITIALIZED: AtomicBool = AtomicBool::new(false);

// Double buffering - back buffer address
static BACK_BUFFER: AtomicU64 = AtomicU64::new(0);
static BACK_BUFFER_HANDLE: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize surface subsystem
pub fn init() {
    // Get framebuffer info from boot info
    if let Some(boot_info) = crate::boot_info() {
        PRIMARY_FRAMEBUFFER.store(boot_info.framebuffer_addr, Ordering::Relaxed);
        PRIMARY_WIDTH.store(boot_info.framebuffer_width, Ordering::Relaxed);
        PRIMARY_HEIGHT.store(boot_info.framebuffer_height, Ordering::Relaxed);
        PRIMARY_STRIDE.store(boot_info.framebuffer_stride, Ordering::Relaxed);
        PRIMARY_BPP.store(boot_info.framebuffer_bpp, Ordering::Relaxed);

        // Create primary surface entry (front buffer - actual screen)
        let primary = Surface {
            surf_type: SurfaceType::Primary,
            format: PixelFormat::Rgb32, // Assume 32-bit from GOP
            width: boot_info.framebuffer_width,
            height: boot_info.framebuffer_height,
            stride: boot_info.framebuffer_stride,
            bpp: boot_info.framebuffer_bpp as u8,
            bits: boot_info.framebuffer_addr,
            size: (boot_info.framebuffer_stride * boot_info.framebuffer_height) as u64,
            ref_count: 1,
            valid: true,
        };

        let mut table = SURFACE_TABLE.lock();
        table.entries[1].surface = Some(primary);

        // Allocate back buffer for double buffering
        let buffer_size = (boot_info.framebuffer_stride * boot_info.framebuffer_height) as usize;
        let layout = Layout::from_size_align(buffer_size, 4096).unwrap_or(Layout::new::<u8>());
        let back_buf_ptr = unsafe { alloc_zeroed(layout) };

        if !back_buf_ptr.is_null() {
            let back_buf_addr = back_buf_ptr as u64;
            BACK_BUFFER.store(back_buf_addr, Ordering::Relaxed);

            // Create back buffer surface entry
            let back_buffer = Surface {
                surf_type: SurfaceType::DeviceBitmap,
                format: PixelFormat::Rgb32,
                width: boot_info.framebuffer_width,
                height: boot_info.framebuffer_height,
                stride: boot_info.framebuffer_stride,
                bpp: boot_info.framebuffer_bpp as u8,
                bits: back_buf_addr,
                size: buffer_size as u64,
                ref_count: 1,
                valid: true,
            };

            // Use index 2 for back buffer
            table.entries[2].surface = Some(back_buffer);
            BACK_BUFFER_HANDLE.store(2, Ordering::Relaxed);

            crate::serial_println!("[GDI/Surface] Back buffer: {}x{} @ {:#x} ({} bytes)",
                boot_info.framebuffer_width, boot_info.framebuffer_height,
                back_buf_addr, buffer_size);
        } else {
            crate::serial_println!("[GDI/Surface] WARNING: Failed to allocate back buffer, using direct rendering");
        }

        crate::serial_println!("[GDI/Surface] Primary surface: {}x{} @ {:#x}",
            boot_info.framebuffer_width, boot_info.framebuffer_height,
            boot_info.framebuffer_addr);
    }

    SURFACE_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[GDI/Surface] Surface manager initialized");
}

/// Get the display surface (returns back buffer if double buffering is enabled)
pub fn get_display_surface() -> SurfaceHandle {
    if SURFACE_INITIALIZED.load(Ordering::Acquire) {
        // Return back buffer if available, otherwise primary
        let back_handle = BACK_BUFFER_HANDLE.load(Ordering::Relaxed);
        if back_handle != 0 {
            SurfaceHandle::new(back_handle as u16)
        } else {
            SurfaceHandle::PRIMARY
        }
    } else {
        SurfaceHandle::NULL
    }
}

/// Get the primary (front) surface directly - used for cursor drawing
/// This bypasses the back buffer so cursor appears on top after swap
pub fn get_primary_surface() -> SurfaceHandle {
    if SURFACE_INITIALIZED.load(Ordering::Acquire) {
        SurfaceHandle::PRIMARY
    } else {
        SurfaceHandle::NULL
    }
}

/// Swap buffers - copy back buffer to front buffer (primary display)
/// This is the key function for double buffering to eliminate flicker
pub fn swap_buffers() {
    let back_addr = BACK_BUFFER.load(Ordering::Relaxed);
    if back_addr == 0 {
        return; // No back buffer, nothing to do
    }

    let front_addr = PRIMARY_FRAMEBUFFER.load(Ordering::Relaxed);
    let stride = PRIMARY_STRIDE.load(Ordering::Relaxed);
    let height = PRIMARY_HEIGHT.load(Ordering::Relaxed);
    let size = (stride * height) as usize;

    // Fast memory copy from back buffer to front buffer
    unsafe {
        core::ptr::copy_nonoverlapping(
            back_addr as *const u8,
            front_addr as *mut u8,
            size,
        );
    }
}

/// Get surface by handle
pub fn get_surface(handle: SurfaceHandle) -> Option<Surface> {
    if !handle.is_valid() {
        return None;
    }

    let index = handle.index() as usize;
    if index >= MAX_SURFACES {
        return None;
    }

    let table = SURFACE_TABLE.lock();
    table.entries[index].surface.clone()
}

/// Get surface with mutable access (via callback)
pub fn with_surface<F, R>(handle: SurfaceHandle, f: F) -> Option<R>
where
    F: FnOnce(&Surface) -> R,
{
    if !handle.is_valid() {
        return None;
    }

    let index = handle.index() as usize;
    if index >= MAX_SURFACES {
        return None;
    }

    let table = SURFACE_TABLE.lock();
    table.entries[index].surface.as_ref().map(f)
}

/// Create a compatible bitmap
pub fn create_compatible_bitmap(_width: u32, _height: u32) -> Result<GdiHandle, super::super::W32Status> {
    // For now, just return NULL (bitmap memory allocation not implemented)
    // TODO: implement bitmap memory allocation
    Err(super::super::W32Status::NotImplemented)
}

/// Get primary surface dimensions
pub fn get_primary_dimensions() -> (u32, u32) {
    (
        PRIMARY_WIDTH.load(Ordering::Relaxed),
        PRIMARY_HEIGHT.load(Ordering::Relaxed),
    )
}

/// Get primary surface stride
pub fn get_primary_stride() -> u32 {
    PRIMARY_STRIDE.load(Ordering::Relaxed)
}
