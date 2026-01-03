//! Device Context (DC) Implementation
//!
//! A Device Context is the primary GDI object for drawing operations.
//! It encapsulates the drawing state (selected objects, colors, position)
//! and provides the target surface for rendering.
//!
//! # DC Types
//!
//! - **Display DC**: Connected to screen framebuffer
//! - **Memory DC**: Connected to an in-memory bitmap
//! - **Printer DC**: Connected to printer (future)
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntgdi/gre/dcobj.cxx`
//! - `windows/core/ntgdi/inc/dcobj.hxx`

use core::sync::atomic::AtomicU16;
use crate::ke::spinlock::SpinLock;
use super::super::{GdiHandle, GdiObjectType, ColorRef, Point, Rect, W32Status};
use super::{Rop2, surface::SurfaceHandle};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of device contexts
pub const MAX_DC_COUNT: usize = 1024;

// ============================================================================
// DC Types
// ============================================================================

/// Device context type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DcType {
    #[default]
    None = 0,
    Display = 1,    // Screen DC
    Memory = 2,     // Memory DC (compatible bitmap)
    Info = 3,       // Information DC (query only)
    Printer = 4,    // Printer DC
}

/// Background mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BkMode {
    #[default]
    Transparent = 1,
    Opaque = 2,
}

/// Mapping mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MapMode {
    #[default]
    Text = 1,       // Each unit = 1 pixel
    LoMetric = 2,   // Each unit = 0.1 mm
    HiMetric = 3,   // Each unit = 0.01 mm
    LoEnglish = 4,  // Each unit = 0.01 inch
    HiEnglish = 5,  // Each unit = 0.001 inch
    Twips = 6,      // Each unit = 1/1440 inch
    Isotropic = 7,  // Custom, X = Y scaling
    Anisotropic = 8,// Custom, X != Y scaling
}

// ============================================================================
// Device Context Structure
// ============================================================================

/// Device Context state
#[derive(Debug, Clone)]
pub struct DeviceContext {
    /// DC type
    pub dc_type: DcType,

    /// Reference count
    pub ref_count: u32,

    /// Owning process ID
    pub owner_pid: u32,

    /// Associated surface (framebuffer or bitmap)
    pub surface: SurfaceHandle,

    /// Currently selected brush
    pub brush: GdiHandle,

    /// Currently selected pen
    pub pen: GdiHandle,

    /// Currently selected font
    pub font: GdiHandle,

    /// Currently selected bitmap (for memory DC)
    pub bitmap: GdiHandle,

    /// Current text color
    pub text_color: ColorRef,

    /// Current background color
    pub bk_color: ColorRef,

    /// Background mode
    pub bk_mode: BkMode,

    /// Current pen position
    pub current_pos: Point,

    /// Drawing ROP2 mode
    pub rop2: Rop2,

    /// Mapping mode
    pub map_mode: MapMode,

    /// Viewport origin
    pub viewport_org: Point,

    /// Viewport extent
    pub viewport_ext: Point,

    /// Window origin
    pub window_org: Point,

    /// Window extent
    pub window_ext: Point,

    /// Clipping region
    pub clip_region: GdiHandle,

    /// DC bounds (dirty rectangle)
    pub bounds: Rect,

    /// Is bounds tracking enabled
    pub bounds_enabled: bool,

    /// DC is valid
    pub valid: bool,
}

impl Default for DeviceContext {
    fn default() -> Self {
        Self {
            dc_type: DcType::None,
            ref_count: 1,
            owner_pid: 0,
            surface: SurfaceHandle::NULL,
            brush: GdiHandle::NULL,
            pen: GdiHandle::NULL,
            font: GdiHandle::NULL,
            bitmap: GdiHandle::NULL,
            text_color: ColorRef::BLACK,
            bk_color: ColorRef::WHITE,
            bk_mode: BkMode::Opaque,
            current_pos: Point::new(0, 0),
            rop2: Rop2::CopyPen,
            map_mode: MapMode::Text,
            viewport_org: Point::new(0, 0),
            viewport_ext: Point::new(1, 1),
            window_org: Point::new(0, 0),
            window_ext: Point::new(1, 1),
            clip_region: GdiHandle::NULL,
            bounds: Rect::new(0, 0, 0, 0),
            bounds_enabled: false,
            valid: false,
        }
    }
}

// ============================================================================
// DC Table
// ============================================================================

/// DC table entry
struct DcEntry {
    dc: Option<DeviceContext>,
}

impl Default for DcEntry {
    fn default() -> Self {
        Self { dc: None }
    }
}

/// DC table
static DC_TABLE: SpinLock<DcTable> = SpinLock::new(DcTable::new());
static NEXT_DC_INDEX: AtomicU16 = AtomicU16::new(1);

struct DcTable {
    entries: [DcEntry; MAX_DC_COUNT],
}

impl DcTable {
    const fn new() -> Self {
        const EMPTY: DcEntry = DcEntry { dc: None };
        Self {
            entries: [EMPTY; MAX_DC_COUNT],
        }
    }
}

// ============================================================================
// DC Management
// ============================================================================

/// Initialize DC subsystem
pub fn init() {
    // DC table is already initialized via const
    crate::serial_println!("[GDI/DC] Device Context manager initialized");
}

/// Allocate a new DC slot
fn allocate_dc_slot() -> Option<u16> {
    let table = DC_TABLE.lock();

    // Find a free slot
    for i in 1..MAX_DC_COUNT {
        if table.entries[i].dc.is_none() {
            return Some(i as u16);
        }
    }

    None
}

/// Create a display DC
pub fn create_display_dc() -> Result<GdiHandle, W32Status> {
    let index = allocate_dc_slot().ok_or(W32Status::NoMemory)?;

    let mut dc = DeviceContext::default();
    dc.dc_type = DcType::Display;
    dc.valid = true;

    // Get display surface
    dc.surface = super::surface::get_display_surface();

    // Select default objects
    dc.brush = super::get_stock_object(super::StockObject::WhiteBrush);
    dc.pen = super::get_stock_object(super::StockObject::BlackPen);
    dc.font = super::get_stock_object(super::StockObject::SystemFont);

    let handle = GdiHandle::new(index, GdiObjectType::DC);

    {
        let mut table = DC_TABLE.lock();
        table.entries[index as usize].dc = Some(dc);
    }

    super::inc_dc_count();

    Ok(handle)
}

/// Create a memory DC compatible with another DC
pub fn create_compatible_dc(hdc: GdiHandle) -> Result<GdiHandle, W32Status> {
    let index = allocate_dc_slot().ok_or(W32Status::NoMemory)?;

    let mut dc = DeviceContext::default();
    dc.dc_type = DcType::Memory;
    dc.valid = true;

    // Copy properties from source DC if valid
    if hdc.is_valid() {
        if let Some(src_dc) = get_dc(hdc) {
            dc.text_color = src_dc.text_color;
            dc.bk_color = src_dc.bk_color;
            dc.bk_mode = src_dc.bk_mode;
        }
    }

    // Select default objects
    dc.brush = super::get_stock_object(super::StockObject::WhiteBrush);
    dc.pen = super::get_stock_object(super::StockObject::BlackPen);
    dc.font = super::get_stock_object(super::StockObject::SystemFont);

    let handle = GdiHandle::new(index, GdiObjectType::DC);

    {
        let mut table = DC_TABLE.lock();
        table.entries[index as usize].dc = Some(dc);
    }

    super::inc_dc_count();

    Ok(handle)
}

/// Delete a DC
pub fn delete_dc(hdc: GdiHandle) -> bool {
    if hdc.object_type() != GdiObjectType::DC {
        return false;
    }

    let index = hdc.index() as usize;
    if index >= MAX_DC_COUNT {
        return false;
    }

    let mut table = DC_TABLE.lock();
    if table.entries[index].dc.is_some() {
        table.entries[index].dc = None;
        super::dec_dc_count();
        true
    } else {
        false
    }
}

/// Get DC by handle
pub fn get_dc(hdc: GdiHandle) -> Option<DeviceContext> {
    if hdc.object_type() != GdiObjectType::DC {
        return None;
    }

    let index = hdc.index() as usize;
    if index >= MAX_DC_COUNT {
        return None;
    }

    let table = DC_TABLE.lock();
    table.entries[index].dc.clone()
}

/// Get mutable access to DC (via callback)
pub fn with_dc_mut<F, R>(hdc: GdiHandle, f: F) -> Option<R>
where
    F: FnOnce(&mut DeviceContext) -> R,
{
    if hdc.object_type() != GdiObjectType::DC {
        return None;
    }

    let index = hdc.index() as usize;
    if index >= MAX_DC_COUNT {
        return None;
    }

    let mut table = DC_TABLE.lock();
    if let Some(ref mut dc) = table.entries[index].dc {
        Some(f(dc))
    } else {
        None
    }
}

// ============================================================================
// DC Operations
// ============================================================================

/// Select object into DC, returns previous object
pub fn select_object(hdc: GdiHandle, obj: GdiHandle) -> GdiHandle {
    with_dc_mut(hdc, |dc| {
        match obj.object_type() {
            GdiObjectType::Brush => {
                let prev = dc.brush;
                dc.brush = obj;
                prev
            }
            GdiObjectType::Pen => {
                let prev = dc.pen;
                dc.pen = obj;
                prev
            }
            GdiObjectType::Font => {
                let prev = dc.font;
                dc.font = obj;
                prev
            }
            GdiObjectType::Bitmap => {
                let prev = dc.bitmap;
                dc.bitmap = obj;
                prev
            }
            GdiObjectType::Region => {
                let prev = dc.clip_region;
                dc.clip_region = obj;
                prev
            }
            _ => GdiHandle::NULL,
        }
    }).unwrap_or(GdiHandle::NULL)
}

/// Set text color
pub fn set_text_color(hdc: GdiHandle, color: ColorRef) -> ColorRef {
    with_dc_mut(hdc, |dc| {
        let prev = dc.text_color;
        dc.text_color = color;
        prev
    }).unwrap_or(ColorRef::BLACK)
}

/// Get text color
pub fn get_text_color(hdc: GdiHandle) -> ColorRef {
    get_dc(hdc).map(|dc| dc.text_color).unwrap_or(ColorRef::BLACK)
}

/// Set background color
pub fn set_bk_color(hdc: GdiHandle, color: ColorRef) -> ColorRef {
    with_dc_mut(hdc, |dc| {
        let prev = dc.bk_color;
        dc.bk_color = color;
        prev
    }).unwrap_or(ColorRef::WHITE)
}

/// Get background color
pub fn get_bk_color(hdc: GdiHandle) -> ColorRef {
    get_dc(hdc).map(|dc| dc.bk_color).unwrap_or(ColorRef::WHITE)
}

/// Set background mode
pub fn set_bk_mode(hdc: GdiHandle, mode: BkMode) -> BkMode {
    with_dc_mut(hdc, |dc| {
        let prev = dc.bk_mode;
        dc.bk_mode = mode;
        prev
    }).unwrap_or(BkMode::Opaque)
}

/// Get background mode
pub fn get_bk_mode(hdc: GdiHandle) -> BkMode {
    get_dc(hdc).map(|dc| dc.bk_mode).unwrap_or(BkMode::Opaque)
}

/// Move current position to (x, y)
pub fn dc_move_to(hdc: GdiHandle, x: i32, y: i32) -> bool {
    with_dc_mut(hdc, |dc| {
        dc.current_pos = Point::new(x, y);
        true
    }).unwrap_or(false)
}

/// Get current position
pub fn get_current_position(hdc: GdiHandle) -> Point {
    get_dc(hdc).map(|dc| dc.current_pos).unwrap_or(Point::new(0, 0))
}

/// Set ROP2 mode
pub fn set_rop2(hdc: GdiHandle, rop: Rop2) -> Rop2 {
    with_dc_mut(hdc, |dc| {
        let prev = dc.rop2;
        dc.rop2 = rop;
        prev
    }).unwrap_or(Rop2::CopyPen)
}

/// Get ROP2 mode
pub fn get_rop2(hdc: GdiHandle) -> Rop2 {
    get_dc(hdc).map(|dc| dc.rop2).unwrap_or(Rop2::CopyPen)
}

/// Get DC surface
pub fn get_dc_surface(hdc: GdiHandle) -> SurfaceHandle {
    get_dc(hdc).map(|dc| dc.surface).unwrap_or(SurfaceHandle::NULL)
}

/// Get selected brush
pub fn get_dc_brush(hdc: GdiHandle) -> GdiHandle {
    get_dc(hdc).map(|dc| dc.brush).unwrap_or(GdiHandle::NULL)
}

/// Get selected pen
pub fn get_dc_pen(hdc: GdiHandle) -> GdiHandle {
    get_dc(hdc).map(|dc| dc.pen).unwrap_or(GdiHandle::NULL)
}

/// Get selected font
pub fn get_dc_font(hdc: GdiHandle) -> GdiHandle {
    get_dc(hdc).map(|dc| dc.font).unwrap_or(GdiHandle::NULL)
}

// ============================================================================
// Coordinate Transformation
// ============================================================================

/// Convert logical coordinates to device coordinates
pub fn lp_to_dp(hdc: GdiHandle, pt: Point) -> Point {
    // In MM_TEXT mode (default), logical = device
    let dc = match get_dc(hdc) {
        Some(dc) => dc,
        None => return pt,
    };

    match dc.map_mode {
        MapMode::Text => {
            Point::new(
                pt.x + dc.viewport_org.x - dc.window_org.x,
                pt.y + dc.viewport_org.y - dc.window_org.y,
            )
        }
        _ => pt, // TODO: implement other mapping modes
    }
}

/// Convert device coordinates to logical coordinates
pub fn dp_to_lp(hdc: GdiHandle, pt: Point) -> Point {
    let dc = match get_dc(hdc) {
        Some(dc) => dc,
        None => return pt,
    };

    match dc.map_mode {
        MapMode::Text => {
            Point::new(
                pt.x - dc.viewport_org.x + dc.window_org.x,
                pt.y - dc.viewport_org.y + dc.window_org.y,
            )
        }
        _ => pt,
    }
}

/// Set viewport origin
pub fn set_viewport_org(hdc: GdiHandle, x: i32, y: i32) -> Point {
    with_dc_mut(hdc, |dc| {
        let prev = dc.viewport_org;
        dc.viewport_org = Point::new(x, y);
        prev
    }).unwrap_or(Point::new(0, 0))
}

/// Set window origin
pub fn set_window_org(hdc: GdiHandle, x: i32, y: i32) -> Point {
    with_dc_mut(hdc, |dc| {
        let prev = dc.window_org;
        dc.window_org = Point::new(x, y);
        prev
    }).unwrap_or(Point::new(0, 0))
}
