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
