//! GDI - Graphics Device Interface
//!
//! Kernel-mode graphics rendering engine following the Windows NT GDI architecture.
//! Provides device contexts, drawing primitives, and graphics objects.
//!
//! # Components
//!
//! - **dc**: Device Context management (HDC)
//! - **surface**: Bitmap/surface objects
//! - **brush**: Brush objects (HBRUSH)
//! - **pen**: Pen objects (HPEN)
//! - **region**: Region objects (HRGN)
//! - **draw**: Drawing operations (BitBlt, LineTo, Rectangle)
//!
//! # Object Model
//!
//! GDI objects use a handle-based system:
//! - Objects are stored in tables indexed by handle
//! - Reference counting for object lifetime
//! - Per-process object ownership
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntgdi/gre/dcobj.cxx` - Device context
//! - `windows/core/ntgdi/gre/surfobj.cxx` - Surface objects
//! - `windows/core/ntgdi/gre/brushobj.cxx` - Brush objects

pub mod dc;
pub mod surface;
pub mod brush;
pub mod pen;
pub mod region;
pub mod draw;
pub mod font;
pub mod palette;
pub mod path;
pub mod transform;
pub mod dib;
pub mod icm;
pub mod emf;

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::{GdiHandle, ColorRef, Rect, Point};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of GDI objects
pub const MAX_GDI_OBJECTS: usize = 16384;

/// Stock object base index
pub const STOCK_OBJECT_BASE: u16 = 0x8000;

// ============================================================================
// Stock Objects
// ============================================================================

/// Stock object identifiers
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockObject {
    WhiteBrush = 0,
    LightGrayBrush = 1,
    GrayBrush = 2,
    DarkGrayBrush = 3,
    BlackBrush = 4,
    NullBrush = 5,
    WhitePen = 6,
    BlackPen = 7,
    NullPen = 8,
    SystemFont = 13,
    DeviceDefaultFont = 14,
    SystemFixedFont = 16,
    DefaultPalette = 15,
    DcBrush = 18,
    DcPen = 19,
}

// ============================================================================
// Raster Operations
// ============================================================================

/// Binary raster operations (ROP2)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Rop2 {
    Black = 1,          // 0
    NotMergePen = 2,    // ~(D | S)
    MaskNotPen = 3,     // D & ~S
    NotCopyPen = 4,     // ~S
    MaskPenNot = 5,     // S & ~D
    Not = 6,            // ~D
    XorPen = 7,         // D ^ S
    NotMaskPen = 8,     // ~(D & S)
    MaskPen = 9,        // D & S
    NotXorPen = 10,     // ~(D ^ S)
    Nop = 11,           // D
    MergeNotPen = 12,   // D | ~S
    #[default]
    CopyPen = 13,       // S
    MergePenNot = 14,   // S | ~D
    MergePen = 15,      // D | S
    White = 16,         // 1
}

/// Ternary raster operations (for BitBlt)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rop3 {
    SrcCopy = 0x00CC0020,      // S
    SrcPaint = 0x00EE0086,     // D | S
    SrcAnd = 0x008800C6,       // D & S
    SrcInvert = 0x00660046,    // D ^ S
    SrcErase = 0x00440328,     // S & ~D
    NotSrcCopy = 0x00330008,   // ~S
    NotSrcErase = 0x001100A6,  // ~(D | S)
    MergeCopy = 0x00C000CA,    // S & P
    MergePaint = 0x00BB0226,   // D | ~S
    PatCopy = 0x00F00021,      // P
    PatPaint = 0x00FB0A09,     // D | ~S | P
    PatInvert = 0x005A0049,    // D ^ P
    DstInvert = 0x00550009,    // ~D
    Blackness = 0x00000042,    // 0
    Whiteness = 0x00FF0062,    // 1
}

// ============================================================================
// GDI State
// ============================================================================

static GDI_INITIALIZED: AtomicBool = AtomicBool::new(false);
static GDI_LOCK: SpinLock<()> = SpinLock::new(());

// Statistics
static DC_COUNT: AtomicU32 = AtomicU32::new(0);
static BITMAP_COUNT: AtomicU32 = AtomicU32::new(0);
static BRUSH_COUNT: AtomicU32 = AtomicU32::new(0);
static PEN_COUNT: AtomicU32 = AtomicU32::new(0);
static REGION_COUNT: AtomicU32 = AtomicU32::new(0);
static FONT_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize GDI subsystem
pub fn init() {
    let _guard = GDI_LOCK.lock();

    if GDI_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[GDI] Initializing Graphics Device Interface...");

    // Initialize DC manager
    dc::init();

    // Initialize surface manager
    surface::init();

    // Initialize brush manager
    brush::init();

    // Initialize pen manager
    pen::init();

    // Initialize region manager
    region::init();

    // Initialize font manager
    font::init();

    // Initialize palette manager
    palette::init();

    // Initialize path subsystem
    path::init();

    // Initialize transform subsystem
    transform::init();

    // Initialize DIB subsystem
    dib::init();

    // Initialize ICM subsystem
    icm::init();

    // Initialize EMF subsystem
    emf::init();

    // Create stock objects
    create_stock_objects();

    GDI_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[GDI] Graphics Device Interface initialized");
}

/// Create stock GDI objects
fn create_stock_objects() {
    // Create stock brushes
    brush::create_stock_brushes();

    // Create stock pens
    pen::create_stock_pens();

    // Create stock fonts
    font::create_stock_fonts();

    crate::serial_println!("[GDI] Stock objects created");
}

/// Get stock object handle
pub fn get_stock_object(stock: StockObject) -> GdiHandle {
    match stock {
        StockObject::WhiteBrush => brush::get_stock_brush(0),
        StockObject::LightGrayBrush => brush::get_stock_brush(1),
        StockObject::GrayBrush => brush::get_stock_brush(2),
        StockObject::DarkGrayBrush => brush::get_stock_brush(3),
        StockObject::BlackBrush => brush::get_stock_brush(4),
        StockObject::NullBrush => brush::get_stock_brush(5),
        StockObject::WhitePen => pen::get_stock_pen(0),
        StockObject::BlackPen => pen::get_stock_pen(1),
        StockObject::NullPen => pen::get_stock_pen(2),
        StockObject::SystemFont => font::get_stock_font(0),
        StockObject::DeviceDefaultFont => font::get_stock_font(1),
        StockObject::SystemFixedFont => font::get_stock_font(2),
        StockObject::DefaultPalette => GdiHandle::NULL, // TODO: palette support
        StockObject::DcBrush => brush::get_stock_brush(6),
        StockObject::DcPen => pen::get_stock_pen(3),
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// GDI statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct GdiStats {
    pub initialized: bool,
    pub dc_count: u32,
    pub bitmap_count: u32,
    pub brush_count: u32,
    pub pen_count: u32,
    pub region_count: u32,
    pub font_count: u32,
}

/// Get GDI statistics
pub fn get_stats() -> GdiStats {
    GdiStats {
        initialized: GDI_INITIALIZED.load(Ordering::Relaxed),
        dc_count: DC_COUNT.load(Ordering::Relaxed),
        bitmap_count: BITMAP_COUNT.load(Ordering::Relaxed),
        brush_count: BRUSH_COUNT.load(Ordering::Relaxed),
        pen_count: PEN_COUNT.load(Ordering::Relaxed),
        region_count: REGION_COUNT.load(Ordering::Relaxed),
        font_count: FONT_COUNT.load(Ordering::Relaxed),
    }
}

pub fn inc_dc_count() { DC_COUNT.fetch_add(1, Ordering::Relaxed); }
pub fn dec_dc_count() { DC_COUNT.fetch_sub(1, Ordering::Relaxed); }
pub fn inc_bitmap_count() { BITMAP_COUNT.fetch_add(1, Ordering::Relaxed); }
pub fn dec_bitmap_count() { BITMAP_COUNT.fetch_sub(1, Ordering::Relaxed); }
pub fn inc_brush_count() { BRUSH_COUNT.fetch_add(1, Ordering::Relaxed); }
pub fn dec_brush_count() { BRUSH_COUNT.fetch_sub(1, Ordering::Relaxed); }
pub fn inc_pen_count() { PEN_COUNT.fetch_add(1, Ordering::Relaxed); }
pub fn dec_pen_count() { PEN_COUNT.fetch_sub(1, Ordering::Relaxed); }
pub fn inc_region_count() { REGION_COUNT.fetch_add(1, Ordering::Relaxed); }
pub fn dec_region_count() { REGION_COUNT.fetch_sub(1, Ordering::Relaxed); }
pub fn inc_font_count() { FONT_COUNT.fetch_add(1, Ordering::Relaxed); }
pub fn dec_font_count() { FONT_COUNT.fetch_sub(1, Ordering::Relaxed); }

// ============================================================================
// High-Level Drawing API
// ============================================================================

/// Set pixel color
pub fn set_pixel(hdc: GdiHandle, x: i32, y: i32, color: ColorRef) -> ColorRef {
    draw::gdi_set_pixel(hdc, x, y, color)
}

/// Get pixel color
pub fn get_pixel(hdc: GdiHandle, x: i32, y: i32) -> ColorRef {
    draw::gdi_get_pixel(hdc, x, y)
}

/// Draw a line from current position to (x, y)
pub fn line_to(hdc: GdiHandle, x: i32, y: i32) -> bool {
    draw::gdi_line_to(hdc, x, y)
}

/// Move current position to (x, y)
pub fn move_to(hdc: GdiHandle, x: i32, y: i32) -> bool {
    dc::dc_move_to(hdc, x, y)
}

/// Draw a rectangle
pub fn rectangle(hdc: GdiHandle, left: i32, top: i32, right: i32, bottom: i32) -> bool {
    draw::gdi_rectangle(hdc, left, top, right, bottom)
}

/// Fill a rectangle with a brush
pub fn fill_rect(hdc: GdiHandle, rect: &Rect, brush: GdiHandle) -> bool {
    draw::gdi_fill_rect(hdc, rect, brush)
}

/// Draw a rectangle frame
pub fn frame_rect(hdc: GdiHandle, rect: &Rect, brush: GdiHandle) -> bool {
    draw::gdi_frame_rect(hdc, rect, brush)
}

/// Bit block transfer
pub fn bit_blt(
    hdc_dest: GdiHandle,
    x_dest: i32,
    y_dest: i32,
    width: i32,
    height: i32,
    hdc_src: GdiHandle,
    x_src: i32,
    y_src: i32,
    rop: Rop3,
) -> bool {
    draw::gdi_bit_blt(hdc_dest, x_dest, y_dest, width, height, hdc_src, x_src, y_src, rop)
}

/// Pattern block transfer (fill with brush)
pub fn pat_blt(
    hdc: GdiHandle,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    rop: Rop3,
) -> bool {
    draw::gdi_pat_blt(hdc, x, y, width, height, rop)
}

/// Draw text
pub fn text_out(hdc: GdiHandle, x: i32, y: i32, text: &str) -> bool {
    draw::gdi_text_out(hdc, x, y, text)
}

/// Draw an ellipse
pub fn ellipse(hdc: GdiHandle, left: i32, top: i32, right: i32, bottom: i32) -> bool {
    draw::gdi_ellipse(hdc, left, top, right, bottom)
}

/// Draw a rounded rectangle
pub fn round_rect(
    hdc: GdiHandle,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    width: i32,
    height: i32,
) -> bool {
    draw::gdi_round_rect(hdc, left, top, right, bottom, width, height)
}

/// Draw a polygon
pub fn polygon(hdc: GdiHandle, points: &[Point]) -> bool {
    draw::gdi_polygon(hdc, points)
}

/// Draw a polyline
pub fn polyline(hdc: GdiHandle, points: &[Point]) -> bool {
    draw::gdi_polyline(hdc, points)
}

/// Draw an arc
pub fn arc(
    hdc: GdiHandle,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    x_start: i32,
    y_start: i32,
    x_end: i32,
    y_end: i32,
) -> bool {
    draw::gdi_arc(hdc, left, top, right, bottom, x_start, y_start, x_end, y_end)
}

/// Draw a pie (filled arc with lines to center)
pub fn pie(
    hdc: GdiHandle,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    x_start: i32,
    y_start: i32,
    x_end: i32,
    y_end: i32,
) -> bool {
    draw::gdi_pie(hdc, left, top, right, bottom, x_start, y_start, x_end, y_end)
}

/// Draw a chord (arc with line connecting endpoints)
pub fn chord(
    hdc: GdiHandle,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    x_start: i32,
    y_start: i32,
    x_end: i32,
    y_end: i32,
) -> bool {
    draw::gdi_chord(hdc, left, top, right, bottom, x_start, y_start, x_end, y_end)
}

/// Draw a 3D raised edge
pub fn draw_edge_raised(hdc: GdiHandle, rect: &Rect) -> bool {
    draw::draw_edge_raised(hdc, rect)
}

/// Draw a 3D sunken edge
pub fn draw_edge_sunken(hdc: GdiHandle, rect: &Rect) -> bool {
    draw::draw_edge_sunken(hdc, rect)
}

// ============================================================================
// Path API
// ============================================================================

/// Begin recording a path
pub fn begin_path(hdc: GdiHandle) -> bool {
    path::begin_path(hdc)
}

/// End recording a path
pub fn end_path(hdc: GdiHandle) -> bool {
    path::end_path(hdc)
}

/// Abort path recording
pub fn abort_path(hdc: GdiHandle) -> bool {
    path::abort_path(hdc)
}

/// Close the current figure in the path
pub fn close_figure(hdc: GdiHandle) -> bool {
    path::close_figure(hdc)
}

/// Stroke the path with the current pen
pub fn stroke_path(hdc: GdiHandle) -> bool {
    path::stroke_path(hdc)
}

/// Fill the path with the current brush
pub fn fill_path(hdc: GdiHandle) -> bool {
    path::fill_path(hdc)
}

/// Stroke and fill the path
pub fn stroke_and_fill_path(hdc: GdiHandle) -> bool {
    path::stroke_and_fill_path(hdc)
}

/// Widen the path to stroked outline
pub fn widen_path(hdc: GdiHandle) -> bool {
    path::widen_path(hdc)
}

/// Flatten curves in path to line segments
pub fn flatten_path(hdc: GdiHandle) -> bool {
    path::flatten_path(hdc)
}

/// Get path data
pub fn get_path(hdc: GdiHandle, points: &mut [Point], types: &mut [u8]) -> i32 {
    path::get_path(hdc, points, types)
}

/// Add cubic bezier curve to path
pub fn poly_bezier_to(hdc: GdiHandle, points: &[Point]) -> bool {
    path::path_bezier_to(hdc, points)
}

// ============================================================================
// Transform API
// ============================================================================

// Re-export transform types
pub use transform::{XForm, GM_COMPATIBLE, GM_ADVANCED, MWT_IDENTITY, MWT_LEFTMULTIPLY, MWT_RIGHTMULTIPLY};
pub use transform::{MM_TEXT, MM_LOMETRIC, MM_HIMETRIC, MM_LOENGLISH, MM_HIENGLISH, MM_TWIPS, MM_ISOTROPIC, MM_ANISOTROPIC};

/// Set the graphics mode
pub fn set_graphics_mode(hdc: GdiHandle, mode: u32) -> u32 {
    transform::set_graphics_mode(hdc, mode)
}

/// Get the graphics mode
pub fn get_graphics_mode(hdc: GdiHandle) -> u32 {
    transform::get_graphics_mode(hdc)
}

/// Set the world transform
pub fn set_world_transform(hdc: GdiHandle, xform: &transform::XForm) -> bool {
    transform::set_world_transform(hdc, xform)
}

/// Get the world transform
pub fn get_world_transform(hdc: GdiHandle, xform: &mut transform::XForm) -> bool {
    transform::get_world_transform(hdc, xform)
}

/// Modify the world transform
pub fn modify_world_transform(hdc: GdiHandle, xform: &transform::XForm, mode: u32) -> bool {
    transform::modify_world_transform(hdc, xform, mode)
}

/// Set the mapping mode
pub fn set_map_mode(hdc: GdiHandle, mode: u32) -> u32 {
    transform::set_map_mode(hdc, mode)
}

/// Get the mapping mode
pub fn get_map_mode(hdc: GdiHandle) -> u32 {
    transform::get_map_mode(hdc)
}

/// Set window origin
pub fn set_window_org_ex(hdc: GdiHandle, x: i32, y: i32) -> Point {
    transform::set_window_org(hdc, x, y)
}

/// Get window origin
pub fn get_window_org_ex(hdc: GdiHandle) -> Point {
    transform::get_window_org(hdc)
}

/// Set viewport origin
pub fn set_viewport_org_ex(hdc: GdiHandle, x: i32, y: i32) -> Point {
    transform::set_viewport_org(hdc, x, y)
}

/// Get viewport origin
pub fn get_viewport_org_ex(hdc: GdiHandle) -> Point {
    transform::get_viewport_org(hdc)
}

/// Set window extent
pub fn set_window_ext_ex(hdc: GdiHandle, x: i32, y: i32) -> Point {
    transform::set_window_ext(hdc, x, y)
}

/// Get window extent
pub fn get_window_ext_ex(hdc: GdiHandle) -> Point {
    transform::get_window_ext(hdc)
}

/// Set viewport extent
pub fn set_viewport_ext_ex(hdc: GdiHandle, x: i32, y: i32) -> Point {
    transform::set_viewport_ext(hdc, x, y)
}

/// Get viewport extent
pub fn get_viewport_ext_ex(hdc: GdiHandle) -> Point {
    transform::get_viewport_ext(hdc)
}

/// Transform logical points to device points
pub fn lp_to_dp_points(hdc: GdiHandle, points: &mut [Point]) -> bool {
    transform::lp_to_dp(hdc, points)
}

/// Transform device points to logical points
pub fn dp_to_lp_points(hdc: GdiHandle, points: &mut [Point]) -> bool {
    transform::dp_to_lp(hdc, points)
}

// ============================================================================
// DIB API
// ============================================================================

// Re-export DIB types
pub use dib::{BitmapInfoHeader, RgbQuad, BlendFunction};
pub use dib::{BI_RGB, BI_RLE8, BI_RLE4, BI_BITFIELDS, DIB_RGB_COLORS, DIB_PAL_COLORS};
pub use dib::{BLACKONWHITE, WHITEONBLACK, COLORONCOLOR, HALFTONE};
pub use dib::{AC_SRC_OVER, AC_SRC_ALPHA};

/// Create a DIB section
pub fn create_dib_section(hdc: GdiHandle, header: &dib::BitmapInfoHeader, usage: u32) -> (GdiHandle, *mut u8) {
    dib::create_dib_section(hdc, header, usage)
}

/// Delete a DIB section
pub fn delete_dib_section(handle: GdiHandle) -> bool {
    dib::delete_dib_section(handle)
}

/// Set stretch blt mode
pub fn set_stretch_blt_mode(hdc: GdiHandle, mode: u32) -> u32 {
    dib::set_stretch_blt_mode(hdc, mode)
}

/// Get stretch blt mode
pub fn get_stretch_blt_mode(hdc: GdiHandle) -> u32 {
    dib::get_stretch_blt_mode(hdc)
}

/// StretchBlt - stretch or compress a bitmap
pub fn stretch_blt(
    hdc_dest: GdiHandle, x_dest: i32, y_dest: i32, width_dest: i32, height_dest: i32,
    hdc_src: GdiHandle, x_src: i32, y_src: i32, width_src: i32, height_src: i32,
    rop: Rop3,
) -> bool {
    dib::stretch_blt(hdc_dest, x_dest, y_dest, width_dest, height_dest,
                     hdc_src, x_src, y_src, width_src, height_src, rop)
}

/// Set DIB bits to a device
pub fn set_di_bits(hdc: GdiHandle, hbitmap: GdiHandle, start: u32, count: u32, bits: &[u8], header: &dib::BitmapInfoHeader, usage: u32) -> u32 {
    dib::set_di_bits(hdc, hbitmap, start, count, bits, header, usage)
}

/// Get DIB bits from a device
pub fn get_di_bits(hdc: GdiHandle, hbitmap: GdiHandle, start: u32, count: u32, bits: &mut [u8], header: &mut dib::BitmapInfoHeader, usage: u32) -> u32 {
    dib::get_di_bits(hdc, hbitmap, start, count, bits, header, usage)
}

/// StretchDIBits - stretch DIB to device
pub fn stretch_di_bits(
    hdc: GdiHandle, x_dest: i32, y_dest: i32, width_dest: i32, height_dest: i32,
    x_src: i32, y_src: i32, width_src: i32, height_src: i32,
    bits: &[u8], header: &dib::BitmapInfoHeader, usage: u32, rop: Rop3,
) -> i32 {
    dib::stretch_di_bits(hdc, x_dest, y_dest, width_dest, height_dest,
                         x_src, y_src, width_src, height_src, bits, header, usage, rop)
}

/// Create a compatible bitmap
pub fn create_compatible_bitmap(hdc: GdiHandle, width: i32, height: i32) -> GdiHandle {
    dib::create_compatible_bitmap(hdc, width, height)
}

/// AlphaBlend - blend with alpha channel
pub fn alpha_blend(
    hdc_dest: GdiHandle, x_dest: i32, y_dest: i32, width_dest: i32, height_dest: i32,
    hdc_src: GdiHandle, x_src: i32, y_src: i32, width_src: i32, height_src: i32,
    blend_function: dib::BlendFunction,
) -> bool {
    dib::alpha_blend(hdc_dest, x_dest, y_dest, width_dest, height_dest,
                     hdc_src, x_src, y_src, width_src, height_src, blend_function)
}

/// TransparentBlt - blit with transparency
pub fn transparent_blt(
    hdc_dest: GdiHandle, x_dest: i32, y_dest: i32, width_dest: i32, height_dest: i32,
    hdc_src: GdiHandle, x_src: i32, y_src: i32, width_src: i32, height_src: i32,
    transparent_color: ColorRef,
) -> bool {
    dib::transparent_blt(hdc_dest, x_dest, y_dest, width_dest, height_dest,
                         hdc_src, x_src, y_src, width_src, height_src, transparent_color)
}

// ============================================================================
// ICM API
// ============================================================================

// Re-export ICM types
pub use icm::{HColorSpace, LogColorSpace, CieXyz, CieXyzTriple};
pub use icm::{ICM_OFF, ICM_ON, ICM_QUERY, ICM_DONE_OUTSIDEDC};
pub use icm::{LCS_CALIBRATED_RGB, LCS_sRGB, LCS_WINDOWS_COLOR_SPACE};
pub use icm::{LCS_GM_BUSINESS, LCS_GM_GRAPHICS, LCS_GM_IMAGES, LCS_GM_ABS_COLORIMETRIC};

/// Set ICM mode
pub fn set_icm_mode(hdc: GdiHandle, mode: u32) -> u32 {
    icm::set_icm_mode(hdc, mode)
}

/// Get ICM mode
pub fn get_icm_mode(hdc: GdiHandle) -> u32 {
    icm::get_icm_mode(hdc)
}

/// Create a color space
pub fn create_color_space(lcs: &icm::LogColorSpace) -> icm::HColorSpace {
    icm::create_color_space(lcs)
}

/// Delete a color space
pub fn delete_color_space(hcs: icm::HColorSpace) -> bool {
    icm::delete_color_space(hcs)
}

/// Set color space for DC
pub fn set_color_space(hdc: GdiHandle, hcs: icm::HColorSpace) -> icm::HColorSpace {
    icm::set_color_space(hdc, hcs)
}

/// Get color space for DC
pub fn get_color_space_handle(hdc: GdiHandle) -> icm::HColorSpace {
    icm::get_color_space(hdc)
}

/// Get the stock sRGB color space
pub fn get_stock_color_space() -> icm::HColorSpace {
    icm::get_stock_color_space()
}
