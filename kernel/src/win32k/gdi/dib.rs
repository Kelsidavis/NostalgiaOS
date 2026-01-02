//! Device Independent Bitmaps (DIB)
//!
//! GDI DIB support for device-independent bitmap operations.
//! Provides bitmap creation, manipulation, and blitting operations.
//!
//! # Operations
//!
//! - **CreateDIBSection**: Create a DIB with direct memory access
//! - **StretchBlt**: Stretch/shrink blit with scaling
//! - **StretchDIBits**: Stretch DIB to device
//! - **SetDIBits/GetDIBits**: Copy bits to/from DIB
//!
//! # DIB Formats
//!
//! - BI_RGB: Uncompressed RGB
//! - BI_BITFIELDS: RGB with custom bit masks
//! - BI_RLE8/BI_RLE4: Run-length encoded
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntgdi/gre/dibapi.cxx` - DIB API
//! - `windows/core/ntgdi/gre/stretchb.cxx` - StretchBlt

extern crate alloc;

use super::super::{GdiHandle, GdiObjectType, ColorRef};
use super::{dc, surface, Rop3};
use crate::ke::spinlock::SpinLock;
use alloc::vec;
use alloc::vec::Vec;

// ============================================================================
// DIB Constants
// ============================================================================

/// Compression types
pub const BI_RGB: u32 = 0;
pub const BI_RLE8: u32 = 1;
pub const BI_RLE4: u32 = 2;
pub const BI_BITFIELDS: u32 = 3;
pub const BI_JPEG: u32 = 4;
pub const BI_PNG: u32 = 5;

/// DIB color usage
pub const DIB_RGB_COLORS: u32 = 0;
pub const DIB_PAL_COLORS: u32 = 1;

/// Stretch modes
pub const BLACKONWHITE: u32 = 1;
pub const WHITEONBLACK: u32 = 2;
pub const COLORONCOLOR: u32 = 3;
pub const HALFTONE: u32 = 4;
pub const STRETCH_ANDSCANS: u32 = BLACKONWHITE;
pub const STRETCH_ORSCANS: u32 = WHITEONBLACK;
pub const STRETCH_DELETESCANS: u32 = COLORONCOLOR;
pub const STRETCH_HALFTONE: u32 = HALFTONE;

/// Maximum DIB sections
const MAX_DIB_SECTIONS: usize = 256;

// ============================================================================
// Bitmap Info Header
// ============================================================================

/// BITMAPINFOHEADER structure
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, packed)]
pub struct BitmapInfoHeader {
    /// Size of this structure (40 bytes)
    pub biSize: u32,
    /// Width in pixels
    pub biWidth: i32,
    /// Height in pixels (negative = top-down)
    pub biHeight: i32,
    /// Number of planes (must be 1)
    pub biPlanes: u16,
    /// Bits per pixel (1, 4, 8, 16, 24, 32)
    pub biBitCount: u16,
    /// Compression type (BI_RGB, etc.)
    pub biCompression: u32,
    /// Image size in bytes (can be 0 for BI_RGB)
    pub biSizeImage: u32,
    /// Horizontal resolution (pixels per meter)
    pub biXPelsPerMeter: i32,
    /// Vertical resolution (pixels per meter)
    pub biYPelsPerMeter: i32,
    /// Number of colors used
    pub biClrUsed: u32,
    /// Number of important colors
    pub biClrImportant: u32,
}

impl BitmapInfoHeader {
    /// Create a new bitmap info header
    pub fn new(width: i32, height: i32, bit_count: u16) -> Self {
        Self {
            biSize: 40,
            biWidth: width,
            biHeight: height,
            biPlanes: 1,
            biBitCount: bit_count,
            biCompression: BI_RGB,
            biSizeImage: 0,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        }
    }

    /// Calculate stride (bytes per row, aligned to 4 bytes)
    pub fn stride(&self) -> usize {
        let bits_per_row = self.biWidth.abs() as usize * self.biBitCount as usize;
        let bytes_per_row = (bits_per_row + 7) / 8;
        (bytes_per_row + 3) & !3
    }

    /// Calculate total image size in bytes
    pub fn image_size(&self) -> usize {
        self.stride() * self.biHeight.abs() as usize
    }

    /// Check if DIB is top-down (negative height)
    pub fn is_top_down(&self) -> bool {
        self.biHeight < 0
    }
}

/// RGB quad for color table
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RgbQuad {
    pub rgbBlue: u8,
    pub rgbGreen: u8,
    pub rgbRed: u8,
    pub rgbReserved: u8,
}

impl RgbQuad {
    pub fn new(r: u8, g: u8, b: u8) -> Self {
        Self {
            rgbRed: r,
            rgbGreen: g,
            rgbBlue: b,
            rgbReserved: 0,
        }
    }

    pub fn from_color_ref(color: ColorRef) -> Self {
        Self::new(color.red(), color.green(), color.blue())
    }

    pub fn to_color_ref(&self) -> ColorRef {
        ColorRef::rgb(self.rgbRed, self.rgbGreen, self.rgbBlue)
    }
}

// ============================================================================
// DIB Section
// ============================================================================

/// DIB Section - a DIB with direct memory access
#[derive(Debug)]
pub struct DibSection {
    /// Bitmap info header
    pub header: BitmapInfoHeader,
    /// Color table (for indexed formats)
    pub colors: Vec<RgbQuad>,
    /// Pixel data
    pub bits: Vec<u8>,
    /// GDI handle for this DIB
    pub handle: GdiHandle,
}

impl DibSection {
    /// Create a new DIB section
    pub fn new(header: BitmapInfoHeader) -> Self {
        let size = header.image_size();
        let color_count = if header.biBitCount <= 8 {
            1 << header.biBitCount
        } else {
            0
        };

        Self {
            header,
            colors: vec![RgbQuad::default(); color_count],
            bits: vec![0u8; size],
            handle: GdiHandle::NULL,
        }
    }

    /// Get pixel at (x, y) as ColorRef
    pub fn get_pixel(&self, x: i32, y: i32) -> Option<ColorRef> {
        let width = self.header.biWidth.abs();
        let height = self.header.biHeight.abs();

        if x < 0 || x >= width || y < 0 || y >= height {
            return None;
        }

        // Adjust y for bottom-up vs top-down
        let row = if self.header.is_top_down() {
            y as usize
        } else {
            (height - 1 - y) as usize
        };

        let stride = self.header.stride();
        let offset = row * stride;

        match self.header.biBitCount {
            32 => {
                let idx = offset + (x as usize) * 4;
                if idx + 3 < self.bits.len() {
                    let b = self.bits[idx];
                    let g = self.bits[idx + 1];
                    let r = self.bits[idx + 2];
                    Some(ColorRef::rgb(r, g, b))
                } else {
                    None
                }
            }
            24 => {
                let idx = offset + (x as usize) * 3;
                if idx + 2 < self.bits.len() {
                    let b = self.bits[idx];
                    let g = self.bits[idx + 1];
                    let r = self.bits[idx + 2];
                    Some(ColorRef::rgb(r, g, b))
                } else {
                    None
                }
            }
            16 => {
                let idx = offset + (x as usize) * 2;
                if idx + 1 < self.bits.len() {
                    let word = (self.bits[idx] as u16) | ((self.bits[idx + 1] as u16) << 8);
                    // Assume 5-5-5 format
                    let r = ((word >> 10) & 0x1F) as u8 * 8;
                    let g = ((word >> 5) & 0x1F) as u8 * 8;
                    let b = (word & 0x1F) as u8 * 8;
                    Some(ColorRef::rgb(r, g, b))
                } else {
                    None
                }
            }
            8 => {
                let idx = offset + x as usize;
                if idx < self.bits.len() && (self.bits[idx] as usize) < self.colors.len() {
                    Some(self.colors[self.bits[idx] as usize].to_color_ref())
                } else {
                    None
                }
            }
            4 => {
                let idx = offset + (x as usize) / 2;
                if idx < self.bits.len() {
                    let nibble = if x % 2 == 0 {
                        (self.bits[idx] >> 4) & 0x0F
                    } else {
                        self.bits[idx] & 0x0F
                    };
                    if (nibble as usize) < self.colors.len() {
                        Some(self.colors[nibble as usize].to_color_ref())
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            1 => {
                let idx = offset + (x as usize) / 8;
                if idx < self.bits.len() {
                    let bit = (self.bits[idx] >> (7 - (x % 8))) & 1;
                    if (bit as usize) < self.colors.len() {
                        Some(self.colors[bit as usize].to_color_ref())
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Set pixel at (x, y)
    pub fn set_pixel(&mut self, x: i32, y: i32, color: ColorRef) {
        let width = self.header.biWidth.abs();
        let height = self.header.biHeight.abs();

        if x < 0 || x >= width || y < 0 || y >= height {
            return;
        }

        let row = if self.header.is_top_down() {
            y as usize
        } else {
            (height - 1 - y) as usize
        };

        let stride = self.header.stride();
        let offset = row * stride;

        match self.header.biBitCount {
            32 => {
                let idx = offset + (x as usize) * 4;
                if idx + 3 < self.bits.len() {
                    self.bits[idx] = color.blue();
                    self.bits[idx + 1] = color.green();
                    self.bits[idx + 2] = color.red();
                    self.bits[idx + 3] = 0xFF; // Alpha
                }
            }
            24 => {
                let idx = offset + (x as usize) * 3;
                if idx + 2 < self.bits.len() {
                    self.bits[idx] = color.blue();
                    self.bits[idx + 1] = color.green();
                    self.bits[idx + 2] = color.red();
                }
            }
            _ => {
                // For indexed formats, would need to find nearest color
            }
        }
    }
}

// ============================================================================
// DIB Section Table
// ============================================================================

static DIB_TABLE: SpinLock<DibTable> = SpinLock::new(DibTable::new());

struct DibTable {
    sections: Vec<DibSection>,
    next_handle: u32,
}

impl DibTable {
    const fn new() -> Self {
        Self {
            sections: Vec::new(),
            next_handle: 0x1000,
        }
    }

    fn allocate(&mut self, section: DibSection) -> GdiHandle {
        let handle = GdiHandle::new(self.next_handle as u16, GdiObjectType::Bitmap);
        self.next_handle += 1;

        let mut sec = section;
        sec.handle = handle;
        self.sections.push(sec);

        handle
    }

    fn get(&self, handle: GdiHandle) -> Option<&DibSection> {
        self.sections.iter().find(|s| s.handle == handle)
    }

    fn get_mut(&mut self, handle: GdiHandle) -> Option<&mut DibSection> {
        self.sections.iter_mut().find(|s| s.handle == handle)
    }

    fn remove(&mut self, handle: GdiHandle) -> bool {
        if let Some(idx) = self.sections.iter().position(|s| s.handle == handle) {
            self.sections.remove(idx);
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Stretch Mode per DC
// ============================================================================

static DC_STRETCH_MODE: SpinLock<Vec<(GdiHandle, u32)>> = SpinLock::new(Vec::new());

// ============================================================================
// DIB API
// ============================================================================

/// Initialize DIB subsystem
pub fn init() {
    crate::serial_println!("[GDI] DIB subsystem initialized");
}

/// Create a DIB section
pub fn create_dib_section(
    hdc: GdiHandle,
    header: &BitmapInfoHeader,
    usage: u32,
) -> (GdiHandle, *mut u8) {
    let _ = hdc;
    let _ = usage;

    let section = DibSection::new(*header);
    let bits_ptr = section.bits.as_ptr() as *mut u8;

    let mut table = DIB_TABLE.lock();
    let handle = table.allocate(section);

    // Get pointer to bits after allocation
    if let Some(sec) = table.get(handle) {
        return (handle, sec.bits.as_ptr() as *mut u8);
    }

    (handle, bits_ptr)
}

/// Delete a DIB section
pub fn delete_dib_section(handle: GdiHandle) -> bool {
    let mut table = DIB_TABLE.lock();
    table.remove(handle)
}

/// Get DIB section pointer
pub fn get_dib_bits_ptr(handle: GdiHandle) -> Option<*mut u8> {
    let table = DIB_TABLE.lock();
    table.get(handle).map(|s| s.bits.as_ptr() as *mut u8)
}

/// Set stretch blt mode
pub fn set_stretch_blt_mode(hdc: GdiHandle, mode: u32) -> u32 {
    let mut modes = DC_STRETCH_MODE.lock();

    // Find existing entry
    for (h, m) in modes.iter_mut() {
        if *h == hdc {
            let old = *m;
            *m = mode;
            return old;
        }
    }

    // Add new entry
    modes.push((hdc, mode));
    COLORONCOLOR // Default previous mode
}

/// Get stretch blt mode
pub fn get_stretch_blt_mode(hdc: GdiHandle) -> u32 {
    let modes = DC_STRETCH_MODE.lock();
    modes.iter()
        .find(|(h, _)| *h == hdc)
        .map(|(_, m)| *m)
        .unwrap_or(COLORONCOLOR)
}

/// StretchBlt - stretch or compress a bitmap
pub fn stretch_blt(
    hdc_dest: GdiHandle,
    x_dest: i32,
    y_dest: i32,
    width_dest: i32,
    height_dest: i32,
    hdc_src: GdiHandle,
    x_src: i32,
    y_src: i32,
    width_src: i32,
    height_src: i32,
    rop: Rop3,
) -> bool {
    // Get source and destination surfaces
    let dc_dest = match dc::get_dc(hdc_dest) {
        Some(d) => d,
        None => return false,
    };
    let dc_src = match dc::get_dc(hdc_src) {
        Some(d) => d,
        None => return false,
    };

    let surf_dest = match surface::get_surface(dc_dest.surface) {
        Some(s) => s,
        None => return false,
    };
    let surf_src = match surface::get_surface(dc_src.surface) {
        Some(s) => s,
        None => return false,
    };

    // Handle negative dimensions (mirror)
    let (x_d_start, x_d_step, w_d) = if width_dest < 0 {
        (x_dest + width_dest + 1, -1i32, -width_dest)
    } else {
        (x_dest, 1i32, width_dest)
    };

    let (y_d_start, y_d_step, h_d) = if height_dest < 0 {
        (y_dest + height_dest + 1, -1i32, -height_dest)
    } else {
        (y_dest, 1i32, height_dest)
    };

    let (x_s_start, w_s) = if width_src < 0 {
        (x_src + width_src + 1, -width_src)
    } else {
        (x_src, width_src)
    };

    let (y_s_start, h_s) = if height_src < 0 {
        (y_src + height_src + 1, -height_src)
    } else {
        (y_src, height_src)
    };

    // Simple nearest-neighbor scaling
    let stretch_mode = get_stretch_blt_mode(hdc_dest);

    for dy in 0..h_d {
        let y_d = y_d_start + dy * y_d_step;
        let y_s = y_s_start + (dy * h_s / h_d);

        for dx in 0..w_d {
            let x_d = x_d_start + dx * x_d_step;
            let x_s = x_s_start + (dx * w_s / w_d);

            // Get source pixel
            let src_color = surf_src.get_pixel(x_s, y_s).unwrap_or(ColorRef::BLACK);

            // Apply ROP (simplified - only handle common cases)
            let final_color = match rop {
                Rop3::SrcCopy => src_color,
                Rop3::Blackness => ColorRef::BLACK,
                Rop3::Whiteness => ColorRef::WHITE,
                Rop3::DstInvert => {
                    let dst = surf_dest.get_pixel(x_d, y_d).unwrap_or(ColorRef::BLACK);
                    ColorRef::rgb(!dst.red(), !dst.green(), !dst.blue())
                }
                Rop3::SrcInvert => {
                    let dst = surf_dest.get_pixel(x_d, y_d).unwrap_or(ColorRef::BLACK);
                    ColorRef::rgb(
                        src_color.red() ^ dst.red(),
                        src_color.green() ^ dst.green(),
                        src_color.blue() ^ dst.blue()
                    )
                }
                Rop3::SrcAnd => {
                    let dst = surf_dest.get_pixel(x_d, y_d).unwrap_or(ColorRef::BLACK);
                    ColorRef::rgb(
                        src_color.red() & dst.red(),
                        src_color.green() & dst.green(),
                        src_color.blue() & dst.blue()
                    )
                }
                Rop3::SrcPaint => {
                    let dst = surf_dest.get_pixel(x_d, y_d).unwrap_or(ColorRef::BLACK);
                    ColorRef::rgb(
                        src_color.red() | dst.red(),
                        src_color.green() | dst.green(),
                        src_color.blue() | dst.blue()
                    )
                }
                _ => src_color,
            };

            // Apply stretch mode for color reduction (simplified)
            surf_dest.set_pixel(x_d, y_d, final_color);
        }
    }

    true
}

/// Set DIB bits to a device
pub fn set_di_bits(
    hdc: GdiHandle,
    hbitmap: GdiHandle,
    start_scan: u32,
    num_scans: u32,
    bits: &[u8],
    header: &BitmapInfoHeader,
    usage: u32,
) -> u32 {
    let _ = usage;

    // Get target surface
    let dc_data = match dc::get_dc(hdc) {
        Some(d) => d,
        None => return 0,
    };

    let surf = match surface::get_surface(dc_data.surface) {
        Some(s) => s,
        None => return 0,
    };

    let width = header.biWidth.abs();
    let height = header.biHeight.abs();
    let stride = header.stride();
    let top_down = header.is_top_down();

    let mut scans_copied = 0u32;

    for scan in start_scan..(start_scan + num_scans) {
        if scan >= height as u32 {
            break;
        }

        let row = if top_down {
            scan as usize
        } else {
            (height as u32 - 1 - scan) as usize
        };

        let row_offset = row * stride;

        for x in 0..width {
            let color = match header.biBitCount {
                32 => {
                    let idx = row_offset + (x as usize) * 4;
                    if idx + 3 < bits.len() {
                        ColorRef::rgb(bits[idx + 2], bits[idx + 1], bits[idx])
                    } else {
                        continue;
                    }
                }
                24 => {
                    let idx = row_offset + (x as usize) * 3;
                    if idx + 2 < bits.len() {
                        ColorRef::rgb(bits[idx + 2], bits[idx + 1], bits[idx])
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };

            surf.set_pixel(x, scan as i32, color);
        }

        scans_copied += 1;
    }

    scans_copied
}

/// Get DIB bits from a device
pub fn get_di_bits(
    hdc: GdiHandle,
    hbitmap: GdiHandle,
    start_scan: u32,
    num_scans: u32,
    bits: &mut [u8],
    header: &mut BitmapInfoHeader,
    usage: u32,
) -> u32 {
    let _ = usage;

    // Get source surface
    let dc_data = match dc::get_dc(hdc) {
        Some(d) => d,
        None => return 0,
    };

    let surf = match surface::get_surface(dc_data.surface) {
        Some(s) => s,
        None => return 0,
    };

    let width = header.biWidth.abs();
    let height = header.biHeight.abs();
    let stride = header.stride();
    let top_down = header.is_top_down();

    let mut scans_copied = 0u32;

    for scan in start_scan..(start_scan + num_scans) {
        if scan >= height as u32 {
            break;
        }

        let src_y = scan as i32;
        let row = if top_down {
            scan as usize
        } else {
            (height as u32 - 1 - scan) as usize
        };

        let row_offset = row * stride;

        for x in 0..width {
            let color = surf.get_pixel(x, src_y).unwrap_or(ColorRef::BLACK);

            match header.biBitCount {
                32 => {
                    let idx = row_offset + (x as usize) * 4;
                    if idx + 3 < bits.len() {
                        bits[idx] = color.blue();
                        bits[idx + 1] = color.green();
                        bits[idx + 2] = color.red();
                        bits[idx + 3] = 0xFF;
                    }
                }
                24 => {
                    let idx = row_offset + (x as usize) * 3;
                    if idx + 2 < bits.len() {
                        bits[idx] = color.blue();
                        bits[idx + 1] = color.green();
                        bits[idx + 2] = color.red();
                    }
                }
                _ => {}
            }
        }

        scans_copied += 1;
    }

    scans_copied
}

/// StretchDIBits - stretch DIB to device
pub fn stretch_di_bits(
    hdc: GdiHandle,
    x_dest: i32,
    y_dest: i32,
    width_dest: i32,
    height_dest: i32,
    x_src: i32,
    y_src: i32,
    width_src: i32,
    height_src: i32,
    bits: &[u8],
    header: &BitmapInfoHeader,
    usage: u32,
    rop: Rop3,
) -> i32 {
    let _ = usage;

    // Get destination surface
    let dc_data = match dc::get_dc(hdc) {
        Some(d) => d,
        None => return 0,
    };

    let surf = match surface::get_surface(dc_data.surface) {
        Some(s) => s,
        None => return 0,
    };

    let src_width = header.biWidth.abs();
    let src_height = header.biHeight.abs();
    let stride = header.stride();
    let top_down = header.is_top_down();

    // Handle negative dimensions
    let (x_d_start, w_d) = if width_dest < 0 {
        (x_dest + width_dest + 1, -width_dest)
    } else {
        (x_dest, width_dest)
    };

    let (y_d_start, h_d) = if height_dest < 0 {
        (y_dest + height_dest + 1, -height_dest)
    } else {
        (y_dest, height_dest)
    };

    let w_s = width_src.abs();
    let h_s = height_src.abs();

    for dy in 0..h_d {
        let y_d = y_d_start + dy;
        let y_s = y_src + (dy * h_s / h_d);

        if y_s < 0 || y_s >= src_height {
            continue;
        }

        let row = if top_down {
            y_s as usize
        } else {
            (src_height - 1 - y_s) as usize
        };

        let row_offset = row * stride;

        for dx in 0..w_d {
            let x_d = x_d_start + dx;
            let x_s = x_src + (dx * w_s / w_d);

            if x_s < 0 || x_s >= src_width {
                continue;
            }

            let color = match header.biBitCount {
                32 => {
                    let idx = row_offset + (x_s as usize) * 4;
                    if idx + 3 < bits.len() {
                        ColorRef::rgb(bits[idx + 2], bits[idx + 1], bits[idx])
                    } else {
                        continue;
                    }
                }
                24 => {
                    let idx = row_offset + (x_s as usize) * 3;
                    if idx + 2 < bits.len() {
                        ColorRef::rgb(bits[idx + 2], bits[idx + 1], bits[idx])
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };

            // Apply ROP (simplified)
            let final_color = match rop {
                Rop3::SrcCopy => color,
                Rop3::Blackness => ColorRef::BLACK,
                Rop3::Whiteness => ColorRef::WHITE,
                _ => color,
            };

            surf.set_pixel(x_d, y_d, final_color);
        }
    }

    h_d
}

/// Create a compatible bitmap
pub fn create_compatible_bitmap(hdc: GdiHandle, width: i32, height: i32) -> GdiHandle {
    let header = BitmapInfoHeader::new(width, height, 32);
    let (handle, _) = create_dib_section(hdc, &header, DIB_RGB_COLORS);
    handle
}

/// AlphaBlend - blend with alpha channel
pub fn alpha_blend(
    hdc_dest: GdiHandle,
    x_dest: i32,
    y_dest: i32,
    width_dest: i32,
    height_dest: i32,
    hdc_src: GdiHandle,
    x_src: i32,
    y_src: i32,
    width_src: i32,
    height_src: i32,
    blend_function: BlendFunction,
) -> bool {
    // Get surfaces
    let dc_dest = match dc::get_dc(hdc_dest) {
        Some(d) => d,
        None => return false,
    };
    let dc_src = match dc::get_dc(hdc_src) {
        Some(d) => d,
        None => return false,
    };

    let surf_dest = match surface::get_surface(dc_dest.surface) {
        Some(s) => s,
        None => return false,
    };
    let surf_src = match surface::get_surface(dc_src.surface) {
        Some(s) => s,
        None => return false,
    };

    let w_s = width_src.abs();
    let h_s = height_src.abs();
    let w_d = width_dest.abs();
    let h_d = height_dest.abs();

    for dy in 0..h_d {
        let y_d = y_dest + dy;
        let y_s = y_src + (dy * h_s / h_d);

        for dx in 0..w_d {
            let x_d = x_dest + dx;
            let x_s = x_src + (dx * w_s / w_d);

            let src = surf_src.get_pixel(x_s, y_s).unwrap_or(ColorRef::BLACK);
            let dst = surf_dest.get_pixel(x_d, y_d).unwrap_or(ColorRef::BLACK);

            // Calculate alpha
            let src_alpha = if blend_function.alpha_format & AC_SRC_ALPHA != 0 {
                // Per-pixel alpha (would need 32-bit source)
                blend_function.source_constant_alpha as u32
            } else {
                blend_function.source_constant_alpha as u32
            };

            // Blend: result = (src * alpha + dst * (255 - alpha)) / 255
            let inv_alpha = 255 - src_alpha;
            let r = ((src.red() as u32 * src_alpha + dst.red() as u32 * inv_alpha) / 255) as u8;
            let g = ((src.green() as u32 * src_alpha + dst.green() as u32 * inv_alpha) / 255) as u8;
            let b = ((src.blue() as u32 * src_alpha + dst.blue() as u32 * inv_alpha) / 255) as u8;

            surf_dest.set_pixel(x_d, y_d, ColorRef::rgb(r, g, b));
        }
    }

    true
}

/// Blend function for AlphaBlend
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct BlendFunction {
    pub blend_op: u8,
    pub blend_flags: u8,
    pub source_constant_alpha: u8,
    pub alpha_format: u8,
}

/// Alpha blend op
pub const AC_SRC_OVER: u8 = 0x00;
/// Use source alpha
pub const AC_SRC_ALPHA: u8 = 0x01;

/// TransparentBlt - blit with transparency
pub fn transparent_blt(
    hdc_dest: GdiHandle,
    x_dest: i32,
    y_dest: i32,
    width_dest: i32,
    height_dest: i32,
    hdc_src: GdiHandle,
    x_src: i32,
    y_src: i32,
    width_src: i32,
    height_src: i32,
    transparent_color: ColorRef,
) -> bool {
    // Get surfaces
    let dc_dest = match dc::get_dc(hdc_dest) {
        Some(d) => d,
        None => return false,
    };
    let dc_src = match dc::get_dc(hdc_src) {
        Some(d) => d,
        None => return false,
    };

    let surf_dest = match surface::get_surface(dc_dest.surface) {
        Some(s) => s,
        None => return false,
    };
    let surf_src = match surface::get_surface(dc_src.surface) {
        Some(s) => s,
        None => return false,
    };

    let w_s = width_src.abs();
    let h_s = height_src.abs();
    let w_d = width_dest.abs();
    let h_d = height_dest.abs();

    for dy in 0..h_d {
        let y_d = y_dest + dy;
        let y_s = y_src + (dy * h_s / h_d);

        for dx in 0..w_d {
            let x_d = x_dest + dx;
            let x_s = x_src + (dx * w_s / w_d);

            let src = surf_src.get_pixel(x_s, y_s).unwrap_or(ColorRef::BLACK);

            // Skip transparent pixels
            if src.red() == transparent_color.red() &&
               src.green() == transparent_color.green() &&
               src.blue() == transparent_color.blue() {
                continue;
            }

            surf_dest.set_pixel(x_d, y_d, src);
        }
    }

    true
}
