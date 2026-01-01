//! Pen Implementation
//!
//! Pens are used to draw lines and outline shapes.
//!
//! # Pen Types
//!
//! - **Cosmetic**: Thin lines (1 pixel wide in device units)
//! - **Geometric**: Lines with width, end caps, join styles
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntgdi/gre/penobj.cxx`

use crate::ke::spinlock::SpinLock;
use super::super::{GdiHandle, GdiObjectType, ColorRef};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of pens
pub const MAX_PENS: usize = 512;

/// Number of stock pens
pub const STOCK_PEN_COUNT: usize = 4;

// ============================================================================
// Types
// ============================================================================

/// Pen style
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PenStyle {
    #[default]
    Solid = 0,
    Dash = 1,
    Dot = 2,
    DashDot = 3,
    DashDotDot = 4,
    Null = 5,
    InsideFrame = 6,
}

/// End cap style
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EndCap {
    #[default]
    Round = 0,
    Square = 1,
    Flat = 2,
}

/// Line join style
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LineJoin {
    #[default]
    Round = 0,
    Bevel = 1,
    Miter = 2,
}

// ============================================================================
// Pen Structure
// ============================================================================

/// Pen object
#[derive(Debug, Clone, Copy)]
pub struct Pen {
    /// Pen style
    pub style: PenStyle,

    /// Pen width (in logical units)
    pub width: i32,

    /// Pen color
    pub color: ColorRef,

    /// End cap style (geometric pens)
    pub end_cap: EndCap,

    /// Line join style (geometric pens)
    pub join: LineJoin,

    /// Reference count
    pub ref_count: u32,

    /// Is stock object
    pub stock: bool,

    /// Valid flag
    pub valid: bool,
}

impl Default for Pen {
    fn default() -> Self {
        Self {
            style: PenStyle::Solid,
            width: 1,
            color: ColorRef::BLACK,
            end_cap: EndCap::Round,
            join: LineJoin::Round,
            ref_count: 1,
            stock: false,
            valid: false,
        }
    }
}

// ============================================================================
// Pen Table
// ============================================================================

struct PenEntry {
    pen: Option<Pen>,
}

impl Default for PenEntry {
    fn default() -> Self {
        Self { pen: None }
    }
}

static PEN_TABLE: SpinLock<PenTable> = SpinLock::new(PenTable::new());

struct PenTable {
    entries: [PenEntry; MAX_PENS],
}

impl PenTable {
    const fn new() -> Self {
        const EMPTY: PenEntry = PenEntry { pen: None };
        Self {
            entries: [EMPTY; MAX_PENS],
        }
    }
}

// Stock pen handles
static STOCK_PENS: SpinLock<[GdiHandle; STOCK_PEN_COUNT]> =
    SpinLock::new([GdiHandle::NULL; STOCK_PEN_COUNT]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize pen subsystem
pub fn init() {
    crate::serial_println!("[GDI/Pen] Pen manager initialized");
}

/// Create stock pens
pub fn create_stock_pens() {
    let pens = [
        (ColorRef::WHITE, PenStyle::Solid, 1),  // WHITE_PEN
        (ColorRef::BLACK, PenStyle::Solid, 1),  // BLACK_PEN
        (ColorRef::BLACK, PenStyle::Null, 0),   // NULL_PEN
        (ColorRef::BLACK, PenStyle::Solid, 1),  // DC_PEN (default)
    ];

    let mut stock = STOCK_PENS.lock();
    let mut table = PEN_TABLE.lock();

    for (i, (color, style, width)) in pens.iter().enumerate() {
        let pen = Pen {
            style: *style,
            width: *width,
            color: *color,
            end_cap: EndCap::Round,
            join: LineJoin::Round,
            ref_count: 1,
            stock: true,
            valid: true,
        };

        // Stock pens start at index 1
        let index = (i + 1) as u16;
        table.entries[index as usize].pen = Some(pen);

        let handle = GdiHandle::new(index, GdiObjectType::Pen);
        stock[i] = handle;

        super::inc_pen_count();
    }

    crate::serial_println!("[GDI/Pen] Created {} stock pens", STOCK_PEN_COUNT);
}

/// Get stock pen handle
pub fn get_stock_pen(index: usize) -> GdiHandle {
    if index >= STOCK_PEN_COUNT {
        return GdiHandle::NULL;
    }

    let stock = STOCK_PENS.lock();
    stock[index]
}

// ============================================================================
// Pen Operations
// ============================================================================

/// Allocate a pen slot
fn allocate_pen_slot() -> Option<u16> {
    let table = PEN_TABLE.lock();

    // Start after stock pens
    for i in (STOCK_PEN_COUNT + 1)..MAX_PENS {
        if table.entries[i].pen.is_none() {
            return Some(i as u16);
        }
    }

    None
}

/// Create a pen
pub fn create_pen(style: PenStyle, width: i32, color: ColorRef) -> GdiHandle {
    let index = match allocate_pen_slot() {
        Some(i) => i,
        None => return GdiHandle::NULL,
    };

    let pen = Pen {
        style,
        width: if style == PenStyle::Null { 0 } else { width.max(1) },
        color,
        end_cap: EndCap::Round,
        join: LineJoin::Round,
        ref_count: 1,
        stock: false,
        valid: true,
    };

    let handle = GdiHandle::new(index, GdiObjectType::Pen);

    {
        let mut table = PEN_TABLE.lock();
        table.entries[index as usize].pen = Some(pen);
    }

    super::inc_pen_count();

    handle
}

/// Create an extended pen (geometric)
pub fn create_pen_ex(
    style: PenStyle,
    width: i32,
    color: ColorRef,
    end_cap: EndCap,
    join: LineJoin,
) -> GdiHandle {
    let index = match allocate_pen_slot() {
        Some(i) => i,
        None => return GdiHandle::NULL,
    };

    let pen = Pen {
        style,
        width: if style == PenStyle::Null { 0 } else { width.max(1) },
        color,
        end_cap,
        join,
        ref_count: 1,
        stock: false,
        valid: true,
    };

    let handle = GdiHandle::new(index, GdiObjectType::Pen);

    {
        let mut table = PEN_TABLE.lock();
        table.entries[index as usize].pen = Some(pen);
    }

    super::inc_pen_count();

    handle
}

/// Delete a pen
pub fn delete_pen(handle: GdiHandle) -> bool {
    if handle.object_type() != GdiObjectType::Pen {
        return false;
    }

    let index = handle.index() as usize;
    if index >= MAX_PENS {
        return false;
    }

    let mut table = PEN_TABLE.lock();

    if let Some(ref pen) = table.entries[index].pen {
        // Can't delete stock objects
        if pen.stock {
            return false;
        }
    }

    if table.entries[index].pen.is_some() {
        table.entries[index].pen = None;
        super::dec_pen_count();
        true
    } else {
        false
    }
}

/// Get pen by handle
pub fn get_pen(handle: GdiHandle) -> Option<Pen> {
    if handle.object_type() != GdiObjectType::Pen {
        return None;
    }

    let index = handle.index() as usize;
    if index >= MAX_PENS {
        return None;
    }

    let table = PEN_TABLE.lock();
    table.entries[index].pen
}

/// Get pen color
pub fn get_pen_color(handle: GdiHandle) -> ColorRef {
    get_pen(handle).map(|p| p.color).unwrap_or(ColorRef::BLACK)
}

/// Get pen width
pub fn get_pen_width(handle: GdiHandle) -> i32 {
    get_pen(handle).map(|p| p.width).unwrap_or(1)
}

/// Get pen style
pub fn get_pen_style(handle: GdiHandle) -> PenStyle {
    get_pen(handle).map(|p| p.style).unwrap_or(PenStyle::Solid)
}
