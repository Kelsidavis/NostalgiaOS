//! Brush Implementation
//!
//! Brushes are used to fill areas with colors or patterns.
//!
//! # Brush Types
//!
//! - **Solid**: Single color fill
//! - **Hatched**: Pattern fill (horizontal, vertical, cross, etc.)
//! - **Pattern**: Bitmap pattern fill
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntgdi/gre/brushobj.cxx`

use crate::ke::spinlock::SpinLock;
use super::super::{GdiHandle, GdiObjectType, ColorRef};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of brushes
pub const MAX_BRUSHES: usize = 512;

/// Number of stock brushes
pub const STOCK_BRUSH_COUNT: usize = 8;

// ============================================================================
// Types
// ============================================================================

/// Brush style
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BrushStyle {
    #[default]
    Solid = 0,
    Null = 1,
    Hatched = 2,
    Pattern = 3,
    Indexed = 4,
    DibPattern = 5,
}

/// Hatch style
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HatchStyle {
    #[default]
    Horizontal = 0,     // -----
    Vertical = 1,       // |||||
    FDiagonal = 2,      // \\\\\
    BDiagonal = 3,      // /////
    Cross = 4,          // +++++
    DiagCross = 5,      // XXXXX
}

// ============================================================================
// Brush Structure
// ============================================================================

/// Brush object
#[derive(Debug, Clone, Copy)]
pub struct Brush {
    /// Brush style
    pub style: BrushStyle,

    /// Brush color (for solid/hatched)
    pub color: ColorRef,

    /// Hatch style (for hatched)
    pub hatch: HatchStyle,

    /// Pattern bitmap handle (for pattern)
    pub pattern: GdiHandle,

    /// Reference count
    pub ref_count: u32,

    /// Is stock object
    pub stock: bool,

    /// Valid flag
    pub valid: bool,
}

impl Default for Brush {
    fn default() -> Self {
        Self {
            style: BrushStyle::Solid,
            color: ColorRef::WHITE,
            hatch: HatchStyle::Horizontal,
            pattern: GdiHandle::NULL,
            ref_count: 1,
            stock: false,
            valid: false,
        }
    }
}

// ============================================================================
// Brush Table
// ============================================================================

struct BrushEntry {
    brush: Option<Brush>,
}

impl Default for BrushEntry {
    fn default() -> Self {
        Self { brush: None }
    }
}

static BRUSH_TABLE: SpinLock<BrushTable> = SpinLock::new(BrushTable::new());

struct BrushTable {
    entries: [BrushEntry; MAX_BRUSHES],
}

impl BrushTable {
    const fn new() -> Self {
        const EMPTY: BrushEntry = BrushEntry { brush: None };
        Self {
            entries: [EMPTY; MAX_BRUSHES],
        }
    }
}

// Stock brush handles
static STOCK_BRUSHES: SpinLock<[GdiHandle; STOCK_BRUSH_COUNT]> =
    SpinLock::new([GdiHandle::NULL; STOCK_BRUSH_COUNT]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize brush subsystem
pub fn init() {
    crate::serial_println!("[GDI/Brush] Brush manager initialized");
}

/// Create stock brushes
pub fn create_stock_brushes() {
    let brushes = [
        (ColorRef::WHITE, BrushStyle::Solid),      // WHITE_BRUSH
        (ColorRef::LIGHT_GRAY, BrushStyle::Solid), // LTGRAY_BRUSH
        (ColorRef::GRAY, BrushStyle::Solid),       // GRAY_BRUSH
        (ColorRef::DARK_GRAY, BrushStyle::Solid),  // DKGRAY_BRUSH
        (ColorRef::BLACK, BrushStyle::Solid),      // BLACK_BRUSH
        (ColorRef::BLACK, BrushStyle::Null),       // NULL_BRUSH
        (ColorRef::WHITE, BrushStyle::Solid),      // DC_BRUSH (default)
        (ColorRef::BUTTON_FACE, BrushStyle::Solid), // 3DFACE_BRUSH
    ];

    let mut stock = STOCK_BRUSHES.lock();
    let mut table = BRUSH_TABLE.lock();

    for (i, (color, style)) in brushes.iter().enumerate() {
        let brush = Brush {
            style: *style,
            color: *color,
            hatch: HatchStyle::Horizontal,
            pattern: GdiHandle::NULL,
            ref_count: 1,
            stock: true,
            valid: true,
        };

        // Stock brushes start at index 1
        let index = (i + 1) as u16;
        table.entries[index as usize].brush = Some(brush);

        let handle = GdiHandle::new(index, GdiObjectType::Brush);
        stock[i] = handle;

        super::inc_brush_count();
    }

    crate::serial_println!("[GDI/Brush] Created {} stock brushes", STOCK_BRUSH_COUNT);
}

/// Get stock brush handle
pub fn get_stock_brush(index: usize) -> GdiHandle {
    if index >= STOCK_BRUSH_COUNT {
        return GdiHandle::NULL;
    }

    let stock = STOCK_BRUSHES.lock();
    stock[index]
}

// ============================================================================
// Brush Operations
// ============================================================================

/// Allocate a brush slot
fn allocate_brush_slot() -> Option<u16> {
    let table = BRUSH_TABLE.lock();

    // Start after stock brushes
    for i in (STOCK_BRUSH_COUNT + 1)..MAX_BRUSHES {
        if table.entries[i].brush.is_none() {
            return Some(i as u16);
        }
    }

    None
}

/// Create a solid brush
pub fn create_solid_brush(color: ColorRef) -> GdiHandle {
    let index = match allocate_brush_slot() {
        Some(i) => i,
        None => return GdiHandle::NULL,
    };

    let brush = Brush {
        style: BrushStyle::Solid,
        color,
        hatch: HatchStyle::Horizontal,
        pattern: GdiHandle::NULL,
        ref_count: 1,
        stock: false,
        valid: true,
    };

    let handle = GdiHandle::new(index, GdiObjectType::Brush);

    {
        let mut table = BRUSH_TABLE.lock();
        table.entries[index as usize].brush = Some(brush);
    }

    super::inc_brush_count();

    handle
}

/// Create a hatched brush
pub fn create_hatch_brush(hatch: HatchStyle, color: ColorRef) -> GdiHandle {
    let index = match allocate_brush_slot() {
        Some(i) => i,
        None => return GdiHandle::NULL,
    };

    let brush = Brush {
        style: BrushStyle::Hatched,
        color,
        hatch,
        pattern: GdiHandle::NULL,
        ref_count: 1,
        stock: false,
        valid: true,
    };

    let handle = GdiHandle::new(index, GdiObjectType::Brush);

    {
        let mut table = BRUSH_TABLE.lock();
        table.entries[index as usize].brush = Some(brush);
    }

    super::inc_brush_count();

    handle
}

/// Delete a brush
pub fn delete_brush(handle: GdiHandle) -> bool {
    if handle.object_type() != GdiObjectType::Brush {
        return false;
    }

    let index = handle.index() as usize;
    if index >= MAX_BRUSHES {
        return false;
    }

    let mut table = BRUSH_TABLE.lock();

    if let Some(ref brush) = table.entries[index].brush {
        // Can't delete stock objects
        if brush.stock {
            return false;
        }
    }

    if table.entries[index].brush.is_some() {
        table.entries[index].brush = None;
        super::dec_brush_count();
        true
    } else {
        false
    }
}

/// Get brush by handle
pub fn get_brush(handle: GdiHandle) -> Option<Brush> {
    if handle.object_type() != GdiObjectType::Brush {
        return None;
    }

    let index = handle.index() as usize;
    if index >= MAX_BRUSHES {
        return None;
    }

    let table = BRUSH_TABLE.lock();
    table.entries[index].brush
}

/// Get brush color
pub fn get_brush_color(handle: GdiHandle) -> ColorRef {
    get_brush(handle).map(|b| b.color).unwrap_or(ColorRef::WHITE)
}

/// Get brush style
pub fn get_brush_style(handle: GdiHandle) -> BrushStyle {
    get_brush(handle).map(|b| b.style).unwrap_or(BrushStyle::Solid)
}
