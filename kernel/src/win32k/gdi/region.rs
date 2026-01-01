//! Region Implementation
//!
//! Regions define arbitrary areas for clipping and hit testing.
//!
//! # Region Types
//!
//! - **Rectangular**: Simple rectangle
//! - **Elliptical**: Ellipse
//! - **Polygonal**: Arbitrary polygon
//! - **Combined**: Union/intersection of regions
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntgdi/gre/rgnobj.cxx`

use crate::ke::spinlock::SpinLock;
use super::super::{GdiHandle, GdiObjectType, Rect, Point};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of regions
pub const MAX_REGIONS: usize = 256;

/// Maximum rectangles in a complex region
pub const MAX_REGION_RECTS: usize = 64;

// ============================================================================
// Types
// ============================================================================

/// Region type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegionType {
    #[default]
    Error = 0,
    Null = 1,
    Simple = 2,   // Single rectangle
    Complex = 3,  // Multiple rectangles
}

/// Region combine mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CombineMode {
    And = 1,    // Intersection
    Or = 2,     // Union
    Xor = 3,    // Exclusive or
    Diff = 4,   // Difference
    Copy = 5,   // Copy
}

// ============================================================================
// Region Structure
// ============================================================================

/// Region object
#[derive(Debug, Clone)]
pub struct Region {
    /// Region type
    pub rgn_type: RegionType,

    /// Bounding rectangle
    pub bounds: Rect,

    /// Rectangles (for complex regions)
    pub rects: [Rect; MAX_REGION_RECTS],

    /// Number of rectangles
    pub rect_count: usize,

    /// Reference count
    pub ref_count: u32,

    /// Valid flag
    pub valid: bool,
}

impl Default for Region {
    fn default() -> Self {
        Self {
            rgn_type: RegionType::Null,
            bounds: Rect::new(0, 0, 0, 0),
            rects: [Rect::new(0, 0, 0, 0); MAX_REGION_RECTS],
            rect_count: 0,
            ref_count: 1,
            valid: false,
        }
    }
}

impl Region {
    /// Check if point is in region
    pub fn contains_point(&self, pt: Point) -> bool {
        if !self.bounds.contains_point(pt) {
            return false;
        }

        match self.rgn_type {
            RegionType::Null | RegionType::Error => false,
            RegionType::Simple => self.bounds.contains_point(pt),
            RegionType::Complex => {
                for i in 0..self.rect_count {
                    if self.rects[i].contains_point(pt) {
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Check if rectangle intersects region
    pub fn intersects_rect(&self, rect: &Rect) -> bool {
        if !self.bounds.intersects(rect) {
            return false;
        }

        match self.rgn_type {
            RegionType::Null | RegionType::Error => false,
            RegionType::Simple => self.bounds.intersects(rect),
            RegionType::Complex => {
                for i in 0..self.rect_count {
                    if self.rects[i].intersects(rect) {
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Offset the region
    pub fn offset(&mut self, dx: i32, dy: i32) {
        self.bounds.offset(dx, dy);
        for i in 0..self.rect_count {
            self.rects[i].offset(dx, dy);
        }
    }
}

// ============================================================================
// Region Table
// ============================================================================

struct RegionEntry {
    region: Option<Region>,
}

impl Default for RegionEntry {
    fn default() -> Self {
        Self { region: None }
    }
}

static REGION_TABLE: SpinLock<RegionTable> = SpinLock::new(RegionTable::new());

struct RegionTable {
    entries: [RegionEntry; MAX_REGIONS],
}

impl RegionTable {
    const fn new() -> Self {
        const EMPTY: RegionEntry = RegionEntry { region: None };
        Self {
            entries: [EMPTY; MAX_REGIONS],
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize region subsystem
pub fn init() {
    crate::serial_println!("[GDI/Region] Region manager initialized");
}

// ============================================================================
// Region Operations
// ============================================================================

/// Allocate a region slot
fn allocate_region_slot() -> Option<u16> {
    let table = REGION_TABLE.lock();

    for i in 1..MAX_REGIONS {
        if table.entries[i].region.is_none() {
            return Some(i as u16);
        }
    }

    None
}

/// Create a rectangular region
pub fn create_rect_rgn(left: i32, top: i32, right: i32, bottom: i32) -> GdiHandle {
    let index = match allocate_region_slot() {
        Some(i) => i,
        None => return GdiHandle::NULL,
    };

    let rect = Rect::new(left, top, right, bottom);

    let mut region = Region::default();
    region.rgn_type = if rect.is_empty() { RegionType::Null } else { RegionType::Simple };
    region.bounds = rect;
    region.rects[0] = rect;
    region.rect_count = 1;
    region.valid = true;

    let handle = GdiHandle::new(index, GdiObjectType::Region);

    {
        let mut table = REGION_TABLE.lock();
        table.entries[index as usize].region = Some(region);
    }

    super::inc_region_count();

    handle
}

/// Create an elliptical region
pub fn create_elliptic_rgn(left: i32, top: i32, right: i32, bottom: i32) -> GdiHandle {
    // For simplicity, approximate with bounding rectangle
    // TODO: proper ellipse support
    create_rect_rgn(left, top, right, bottom)
}

/// Delete a region
pub fn delete_rgn(handle: GdiHandle) -> bool {
    if handle.object_type() != GdiObjectType::Region {
        return false;
    }

    let index = handle.index() as usize;
    if index >= MAX_REGIONS {
        return false;
    }

    let mut table = REGION_TABLE.lock();
    if table.entries[index].region.is_some() {
        table.entries[index].region = None;
        super::dec_region_count();
        true
    } else {
        false
    }
}

/// Get region by handle
pub fn get_region(handle: GdiHandle) -> Option<Region> {
    if handle.object_type() != GdiObjectType::Region {
        return None;
    }

    let index = handle.index() as usize;
    if index >= MAX_REGIONS {
        return None;
    }

    let table = REGION_TABLE.lock();
    table.entries[index].region.clone()
}

/// Get region bounding box
pub fn get_rgn_box(handle: GdiHandle) -> (RegionType, Rect) {
    match get_region(handle) {
        Some(rgn) => (rgn.rgn_type, rgn.bounds),
        None => (RegionType::Error, Rect::new(0, 0, 0, 0)),
    }
}

/// Combine two regions
pub fn combine_rgn(
    dest: GdiHandle,
    src1: GdiHandle,
    src2: GdiHandle,
    mode: CombineMode,
) -> RegionType {
    let rgn1 = match get_region(src1) {
        Some(r) => r,
        None => return RegionType::Error,
    };

    let rgn2 = match get_region(src2) {
        Some(r) => r,
        None => return RegionType::Error,
    };

    let result_bounds = match mode {
        CombineMode::And => {
            match rgn1.bounds.intersect(&rgn2.bounds) {
                Some(r) => r,
                None => return RegionType::Null,
            }
        }
        CombineMode::Or | CombineMode::Xor => rgn1.bounds.union(&rgn2.bounds),
        CombineMode::Diff => rgn1.bounds,
        CombineMode::Copy => rgn1.bounds,
    };

    // Update destination region
    if dest.object_type() == GdiObjectType::Region {
        let index = dest.index() as usize;
        if index < MAX_REGIONS {
            let mut table = REGION_TABLE.lock();
            if let Some(ref mut rgn) = table.entries[index].region {
                rgn.bounds = result_bounds;
                rgn.rects[0] = result_bounds;
                rgn.rect_count = 1;
                rgn.rgn_type = if result_bounds.is_empty() {
                    RegionType::Null
                } else {
                    RegionType::Simple
                };
                return rgn.rgn_type;
            }
        }
    }

    RegionType::Error
}

/// Offset a region
pub fn offset_rgn(handle: GdiHandle, dx: i32, dy: i32) -> RegionType {
    if handle.object_type() != GdiObjectType::Region {
        return RegionType::Error;
    }

    let index = handle.index() as usize;
    if index >= MAX_REGIONS {
        return RegionType::Error;
    }

    let mut table = REGION_TABLE.lock();
    if let Some(ref mut rgn) = table.entries[index].region {
        rgn.offset(dx, dy);
        rgn.rgn_type
    } else {
        RegionType::Error
    }
}

/// Check if point is in region
pub fn pt_in_region(handle: GdiHandle, x: i32, y: i32) -> bool {
    match get_region(handle) {
        Some(rgn) => rgn.contains_point(Point::new(x, y)),
        None => false,
    }
}

/// Check if rectangle intersects region
pub fn rect_in_region(handle: GdiHandle, rect: &Rect) -> bool {
    match get_region(handle) {
        Some(rgn) => rgn.intersects_rect(rect),
        None => false,
    }
}
