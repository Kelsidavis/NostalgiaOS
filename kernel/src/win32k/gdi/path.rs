//! Path Objects
//!
//! GDI path support for complex shapes built from lines, curves, and figures.
//! Paths can be stroked, filled, or used as clipping regions.
//!
//! # Path Operations
//!
//! - **BeginPath**: Start recording path commands
//! - **EndPath**: Finish recording and create path object
//! - **StrokePath**: Draw path outline with current pen
//! - **FillPath**: Fill path interior with current brush
//! - **CloseFigure**: Close current sub-path
//!
//! # Path Elements
//!
//! - **MoveTo**: Start new figure at point
//! - **LineTo**: Add line segment
//! - **PolyBezierTo**: Add cubic Bezier curve
//! - **ArcTo**: Add elliptical arc
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntgdi/gre/pathobj.cxx` - Path object management
//! - `windows/core/ntgdi/gre/pathgdi.cxx` - Path GDI entry points
//! - `windows/core/ntgdi/gre/pathflat.cxx` - Path flattening (curves to lines)
//! - `windows/core/ntgdi/gre/pathwide.cxx` - Path widening

extern crate alloc;

use super::super::{GdiHandle, ColorRef, Point};
use super::{dc, surface, brush, pen};
use crate::ke::spinlock::SpinLock;
use alloc::vec::Vec;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of path objects
const MAX_PATHS: usize = 1024;

/// Maximum points in a single path
const MAX_PATH_POINTS: usize = 65536;

/// Bezier curve flattening tolerance (in pixels)
const BEZIER_TOLERANCE: f32 = 0.25;

// ============================================================================
// Path Point Types
// ============================================================================

bitflags::bitflags! {
    /// Point type flags (PT_* constants from Windows)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct PointType: u8 {
        /// Close figure flag
        const CLOSEFIGURE = 0x01;
        /// Line to point
        const LINETO = 0x02;
        /// Bezier control point
        const BEZIERTO = 0x04;
        /// Move to point (start new figure)
        const MOVETO = 0x06;
    }
}

// ============================================================================
// Path State
// ============================================================================

/// Path recording state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// No path is being recorded
    Idle,
    /// Path is being recorded (between BeginPath/EndPath)
    Recording,
    /// Path has been recorded and is ready to use
    Ready,
}

impl Default for PathState {
    fn default() -> Self {
        PathState::Idle
    }
}

// ============================================================================
// Path Element
// ============================================================================

/// A single element in a path
#[derive(Debug, Clone, Copy)]
pub struct PathElement {
    /// Point coordinates
    pub point: Point,
    /// Point type (MoveTo, LineTo, BezierTo, etc.)
    pub point_type: PointType,
}

impl PathElement {
    /// Create a new path element
    pub fn new(point: Point, point_type: PointType) -> Self {
        Self { point, point_type }
    }

    /// Create a MoveTo element
    pub fn move_to(x: i32, y: i32) -> Self {
        Self::new(Point::new(x, y), PointType::MOVETO)
    }

    /// Create a LineTo element
    pub fn line_to(x: i32, y: i32) -> Self {
        Self::new(Point::new(x, y), PointType::LINETO)
    }

    /// Create a BezierTo element
    pub fn bezier_to(x: i32, y: i32) -> Self {
        Self::new(Point::new(x, y), PointType::BEZIERTO)
    }
}

// ============================================================================
// Path Object
// ============================================================================

/// Path object containing recorded path elements
#[derive(Debug, Clone)]
pub struct Path {
    /// Path elements (points and types)
    elements: Vec<PathElement>,
    /// Current figure start index (for CloseFigure)
    figure_start: usize,
    /// Whether current figure is closed
    figure_closed: bool,
    /// Fill mode (alternate or winding)
    fill_mode: FillMode,
}

impl Default for Path {
    fn default() -> Self {
        Self::new()
    }
}

impl Path {
    /// Create a new empty path
    pub fn new() -> Self {
        Self {
            elements: Vec::new(),
            figure_start: 0,
            figure_closed: true,
            fill_mode: FillMode::Alternate,
        }
    }

    /// Clear all path elements
    pub fn clear(&mut self) {
        self.elements.clear();
        self.figure_start = 0;
        self.figure_closed = true;
    }

    /// Get number of elements
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Check if path is empty
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Get path elements
    pub fn elements(&self) -> &[PathElement] {
        &self.elements
    }

    /// Add a MoveTo element (starts new figure)
    pub fn move_to(&mut self, x: i32, y: i32) -> bool {
        if self.elements.len() >= MAX_PATH_POINTS {
            return false;
        }

        // Close previous figure if not already closed
        if !self.figure_closed && !self.elements.is_empty() {
            self.figure_closed = true;
        }

        self.figure_start = self.elements.len();
        self.figure_closed = false;
        self.elements.push(PathElement::move_to(x, y));
        true
    }

    /// Add a LineTo element
    pub fn line_to(&mut self, x: i32, y: i32) -> bool {
        if self.elements.len() >= MAX_PATH_POINTS {
            return false;
        }

        // If no figure started, implicitly start at origin
        if self.figure_closed && self.elements.is_empty() {
            self.move_to(0, 0);
        }

        self.elements.push(PathElement::line_to(x, y));
        true
    }

    /// Add a cubic Bezier curve (3 control points)
    pub fn bezier_to(&mut self, x1: i32, y1: i32, x2: i32, y2: i32, x3: i32, y3: i32) -> bool {
        if self.elements.len() + 3 > MAX_PATH_POINTS {
            return false;
        }

        // Bezier requires 3 points: 2 control points + end point
        self.elements.push(PathElement::bezier_to(x1, y1));
        self.elements.push(PathElement::bezier_to(x2, y2));
        self.elements.push(PathElement::bezier_to(x3, y3));
        true
    }

    /// Close the current figure with a line back to figure start
    pub fn close_figure(&mut self) -> bool {
        if self.figure_closed || self.elements.is_empty() {
            return false;
        }

        // Mark the last element as closing the figure
        if let Some(last) = self.elements.last_mut() {
            last.point_type = last.point_type | PointType::CLOSEFIGURE;
        }

        self.figure_closed = true;
        true
    }

    /// Get the starting point of current figure
    pub fn figure_start_point(&self) -> Option<Point> {
        if self.figure_start < self.elements.len() {
            Some(self.elements[self.figure_start].point)
        } else {
            None
        }
    }

    /// Get the last point in the path
    pub fn current_point(&self) -> Option<Point> {
        self.elements.last().map(|e| e.point)
    }

    /// Set fill mode
    pub fn set_fill_mode(&mut self, mode: FillMode) {
        self.fill_mode = mode;
    }

    /// Get fill mode
    pub fn fill_mode(&self) -> FillMode {
        self.fill_mode
    }

    /// Flatten the path (convert curves to line segments)
    pub fn flatten(&self, tolerance: f32) -> Path {
        let mut result = Path::new();
        result.fill_mode = self.fill_mode;

        let mut i = 0;
        while i < self.elements.len() {
            let elem = &self.elements[i];

            match elem.point_type & !PointType::CLOSEFIGURE {
                PointType::MOVETO => {
                    result.move_to(elem.point.x, elem.point.y);
                    i += 1;
                }
                PointType::LINETO => {
                    result.line_to(elem.point.x, elem.point.y);
                    if elem.point_type.contains(PointType::CLOSEFIGURE) {
                        result.close_figure();
                    }
                    i += 1;
                }
                PointType::BEZIERTO => {
                    // Bezier curve: need 3 points
                    if i + 2 < self.elements.len() {
                        let p0 = result.current_point().unwrap_or(Point::new(0, 0));
                        let p1 = self.elements[i].point;
                        let p2 = self.elements[i + 1].point;
                        let p3 = self.elements[i + 2].point;

                        // Flatten cubic bezier to line segments
                        flatten_cubic_bezier(&mut result, p0, p1, p2, p3, tolerance);

                        // Check if last control point closes figure
                        if self.elements[i + 2].point_type.contains(PointType::CLOSEFIGURE) {
                            result.close_figure();
                        }

                        i += 3;
                    } else {
                        i += 1;
                    }
                }
                _ => {
                    i += 1;
                }
            }
        }

        result
    }
}

// ============================================================================
// Fill Mode
// ============================================================================

/// Polygon fill mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum FillMode {
    /// Alternate fill (odd-even rule)
    #[default]
    Alternate = 1,
    /// Winding fill (non-zero winding rule)
    Winding = 2,
}

// ============================================================================
// Bezier Flattening
// ============================================================================

/// Recursively flatten a cubic Bezier curve to line segments
fn flatten_cubic_bezier(path: &mut Path, p0: Point, p1: Point, p2: Point, p3: Point, tolerance: f32) {
    // Calculate flatness using the maximum deviation of control points from the line
    let dx = p3.x - p0.x;
    let dy = p3.y - p0.y;
    let len_sq = (dx * dx + dy * dy) as f32;

    if len_sq < 1.0 {
        // Very short curve, just draw a line
        path.line_to(p3.x, p3.y);
        return;
    }

    // Calculate perpendicular distance of control points from line p0-p3
    let d1 = ((p1.x - p0.x) * dy - (p1.y - p0.y) * dx).abs() as f32;
    let d2 = ((p2.x - p0.x) * dy - (p2.y - p0.y) * dx).abs() as f32;
    let max_dist = (d1.max(d2)) / sqrt_approx(len_sq);

    if max_dist <= tolerance {
        // Flat enough, draw a line to end point
        path.line_to(p3.x, p3.y);
    } else {
        // Subdivide using de Casteljau's algorithm
        let p01 = midpoint(p0, p1);
        let p12 = midpoint(p1, p2);
        let p23 = midpoint(p2, p3);
        let p012 = midpoint(p01, p12);
        let p123 = midpoint(p12, p23);
        let p0123 = midpoint(p012, p123);

        // Recursively flatten both halves
        flatten_cubic_bezier(path, p0, p01, p012, p0123, tolerance);
        flatten_cubic_bezier(path, p0123, p123, p23, p3, tolerance);
    }
}

/// Approximate square root using Newton-Raphson iteration
fn sqrt_approx(x: f32) -> f32 {
    if x <= 0.0 {
        return 0.0;
    }

    // Initial guess using bit manipulation (fast inverse sqrt trick)
    let mut i = x.to_bits();
    i = 0x5f3759df - (i >> 1);
    let inv_sqrt = f32::from_bits(i);
    let mut guess = 1.0 / inv_sqrt;

    // Two Newton-Raphson iterations for better accuracy
    guess = 0.5 * (guess + x / guess);
    guess = 0.5 * (guess + x / guess);

    guess
}

/// Calculate midpoint between two points
fn midpoint(p1: Point, p2: Point) -> Point {
    Point::new((p1.x + p2.x) / 2, (p1.y + p2.y) / 2)
}

// ============================================================================
// Path Table
// ============================================================================

/// Path table entry
struct PathEntry {
    path: Path,
    in_use: bool,
}

impl Default for PathEntry {
    fn default() -> Self {
        Self {
            path: Path::new(),
            in_use: false,
        }
    }
}

/// Global path table
static PATH_TABLE: SpinLock<PathTable> = SpinLock::new(PathTable::new());

struct PathTable {
    entries: [PathEntry; MAX_PATHS],
    count: usize,
}

impl PathTable {
    const fn new() -> Self {
        const DEFAULT_ENTRY: PathEntry = PathEntry {
            path: Path {
                elements: Vec::new(),
                figure_start: 0,
                figure_closed: true,
                fill_mode: FillMode::Alternate,
            },
            in_use: false,
        };
        Self {
            entries: [DEFAULT_ENTRY; MAX_PATHS],
            count: 0,
        }
    }
}

// ============================================================================
// DC Path State
// ============================================================================

/// Per-DC path recording state
static DC_PATH_STATE: SpinLock<DcPathTable> = SpinLock::new(DcPathTable::new());

struct DcPathEntry {
    dc: GdiHandle,
    state: PathState,
    path: Path,
}

struct DcPathTable {
    entries: Vec<DcPathEntry>,
}

impl DcPathTable {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn get_entry(&mut self, hdc: GdiHandle) -> Option<&mut DcPathEntry> {
        self.entries.iter_mut().find(|e| e.dc == hdc)
    }

    fn get_or_create(&mut self, hdc: GdiHandle) -> &mut DcPathEntry {
        if let Some(idx) = self.entries.iter().position(|e| e.dc == hdc) {
            return &mut self.entries[idx];
        }
        self.entries.push(DcPathEntry {
            dc: hdc,
            state: PathState::Idle,
            path: Path::new(),
        });
        self.entries.last_mut().unwrap()
    }
}

// ============================================================================
// Path API
// ============================================================================

/// Initialize path subsystem
pub fn init() {
    crate::serial_println!("[GDI] Path subsystem initialized");
}

/// Begin recording a path
pub fn begin_path(hdc: GdiHandle) -> bool {
    if hdc == GdiHandle::NULL {
        return false;
    }

    let mut table = DC_PATH_STATE.lock();
    let entry = table.get_or_create(hdc);

    // Clear any existing path and start recording
    entry.path.clear();
    entry.state = PathState::Recording;

    true
}

/// End recording a path
pub fn end_path(hdc: GdiHandle) -> bool {
    if hdc == GdiHandle::NULL {
        return false;
    }

    let mut table = DC_PATH_STATE.lock();
    if let Some(entry) = table.get_entry(hdc) {
        if entry.state == PathState::Recording {
            entry.state = PathState::Ready;
            return true;
        }
    }
    false
}

/// Abort path recording
pub fn abort_path(hdc: GdiHandle) -> bool {
    if hdc == GdiHandle::NULL {
        return false;
    }

    let mut table = DC_PATH_STATE.lock();
    if let Some(entry) = table.get_entry(hdc) {
        entry.path.clear();
        entry.state = PathState::Idle;
        return true;
    }
    false
}

/// Close the current figure in the path
pub fn close_figure(hdc: GdiHandle) -> bool {
    if hdc == GdiHandle::NULL {
        return false;
    }

    let mut table = DC_PATH_STATE.lock();
    if let Some(entry) = table.get_entry(hdc) {
        if entry.state == PathState::Recording {
            return entry.path.close_figure();
        }
    }
    false
}

/// Check if DC is recording a path
pub fn is_recording(hdc: GdiHandle) -> bool {
    let table = DC_PATH_STATE.lock();
    table.entries.iter().any(|e| e.dc == hdc && e.state == PathState::Recording)
}

/// Add a MoveTo to the path (if recording)
pub fn path_move_to(hdc: GdiHandle, x: i32, y: i32) -> bool {
    let mut table = DC_PATH_STATE.lock();
    if let Some(entry) = table.get_entry(hdc) {
        if entry.state == PathState::Recording {
            return entry.path.move_to(x, y);
        }
    }
    false
}

/// Add a LineTo to the path (if recording)
pub fn path_line_to(hdc: GdiHandle, x: i32, y: i32) -> bool {
    let mut table = DC_PATH_STATE.lock();
    if let Some(entry) = table.get_entry(hdc) {
        if entry.state == PathState::Recording {
            return entry.path.line_to(x, y);
        }
    }
    false
}

/// Add a PolyBezierTo to the path (if recording)
pub fn path_bezier_to(hdc: GdiHandle, points: &[Point]) -> bool {
    if points.len() < 3 || points.len() % 3 != 0 {
        return false;
    }

    let mut table = DC_PATH_STATE.lock();
    if let Some(entry) = table.get_entry(hdc) {
        if entry.state == PathState::Recording {
            for chunk in points.chunks(3) {
                if !entry.path.bezier_to(
                    chunk[0].x, chunk[0].y,
                    chunk[1].x, chunk[1].y,
                    chunk[2].x, chunk[2].y,
                ) {
                    return false;
                }
            }
            return true;
        }
    }
    false
}

/// Stroke the path with the current pen
pub fn stroke_path(hdc: GdiHandle) -> bool {
    if hdc == GdiHandle::NULL {
        return false;
    }

    let mut table = DC_PATH_STATE.lock();
    if let Some(entry) = table.get_entry(hdc) {
        if entry.state != PathState::Ready {
            return false;
        }

        // Flatten the path for rendering
        let flattened = entry.path.flatten(BEZIER_TOLERANCE);

        // Get DC data
        let dc_data = match dc::get_dc(hdc) {
            Some(d) => d,
            None => return false,
        };

        let surface_handle = dc_data.surface;
        let surf = match surface::get_surface(surface_handle) {
            Some(s) => s,
            None => return false,
        };

        // Get pen properties
        let pen_data = pen::get_pen(dc_data.pen);
        let color = pen_data.map(|p| p.color).unwrap_or(ColorRef::BLACK);
        let pen_width = pen_data.map(|p| p.width).unwrap_or(1);

        // Draw each segment
        let mut last_point: Option<Point> = None;
        let mut figure_start: Option<Point> = None;

        for elem in flattened.elements() {
            match elem.point_type & !PointType::CLOSEFIGURE {
                PointType::MOVETO => {
                    last_point = Some(elem.point);
                    figure_start = Some(elem.point);
                }
                PointType::LINETO => {
                    if let Some(from) = last_point {
                        super::draw::draw_line_internal(
                            &surf, from.x, from.y, elem.point.x, elem.point.y,
                            color, pen_width
                        );
                    }
                    last_point = Some(elem.point);

                    // Close figure if needed
                    if elem.point_type.contains(PointType::CLOSEFIGURE) {
                        if let (Some(from), Some(start)) = (last_point, figure_start) {
                            super::draw::draw_line_internal(
                                &surf, from.x, from.y, start.x, start.y,
                                color, pen_width
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        // Clear the path after stroking
        entry.path.clear();
        entry.state = PathState::Idle;

        return true;
    }
    false
}

/// Fill the path with the current brush
pub fn fill_path(hdc: GdiHandle) -> bool {
    if hdc == GdiHandle::NULL {
        return false;
    }

    let mut table = DC_PATH_STATE.lock();
    if let Some(entry) = table.get_entry(hdc) {
        if entry.state != PathState::Ready {
            return false;
        }

        // Flatten the path for rendering
        let flattened = entry.path.flatten(BEZIER_TOLERANCE);
        let fill_mode = entry.path.fill_mode();

        // Get DC data
        let dc_data = match dc::get_dc(hdc) {
            Some(d) => d,
            None => return false,
        };

        let surface_handle = dc_data.surface;
        let surf = match surface::get_surface(surface_handle) {
            Some(s) => s,
            None => return false,
        };

        // Get brush color
        let brush_data = brush::get_brush(dc_data.brush);
        let color = brush_data.map(|b| b.color).unwrap_or(ColorRef::WHITE);

        // Collect polygon points
        let points: Vec<Point> = flattened.elements().iter()
            .map(|e| e.point)
            .collect();

        if !points.is_empty() {
            // Fill polygon using scanline algorithm
            fill_polygon_scanline(&surf, &points, color, fill_mode);
        }

        // Clear the path after filling
        entry.path.clear();
        entry.state = PathState::Idle;

        return true;
    }
    false
}

/// Stroke and fill the path
pub fn stroke_and_fill_path(hdc: GdiHandle) -> bool {
    if hdc == GdiHandle::NULL {
        return false;
    }

    // We need to fill first, then stroke (so stroke appears on top)
    let mut table = DC_PATH_STATE.lock();
    if let Some(entry) = table.get_entry(hdc) {
        if entry.state != PathState::Ready {
            return false;
        }

        // Clone the path for both operations
        let path_clone = entry.path.clone();
        let flattened = path_clone.flatten(BEZIER_TOLERANCE);
        let fill_mode = path_clone.fill_mode();

        // Get DC data
        let dc_data = match dc::get_dc(hdc) {
            Some(d) => d,
            None => return false,
        };

        let surface_handle = dc_data.surface;
        let surf = match surface::get_surface(surface_handle) {
            Some(s) => s,
            None => return false,
        };

        // Get brush and pen data
        let brush_data = brush::get_brush(dc_data.brush);
        let brush_color = brush_data.map(|b| b.color).unwrap_or(ColorRef::WHITE);

        let pen_data = pen::get_pen(dc_data.pen);
        let pen_color = pen_data.map(|p| p.color).unwrap_or(ColorRef::BLACK);
        let pen_width = pen_data.map(|p| p.width).unwrap_or(1);

        // Fill first
        let points: Vec<Point> = flattened.elements().iter()
            .map(|e| e.point)
            .collect();

        if !points.is_empty() {
            fill_polygon_scanline(&surf, &points, brush_color, fill_mode);
        }

        // Then stroke
        let mut last_point: Option<Point> = None;
        let mut figure_start: Option<Point> = None;

        for elem in flattened.elements() {
            match elem.point_type & !PointType::CLOSEFIGURE {
                PointType::MOVETO => {
                    last_point = Some(elem.point);
                    figure_start = Some(elem.point);
                }
                PointType::LINETO => {
                    if let Some(from) = last_point {
                        super::draw::draw_line_internal(
                            &surf, from.x, from.y, elem.point.x, elem.point.y,
                            pen_color, pen_width
                        );
                    }
                    last_point = Some(elem.point);

                    if elem.point_type.contains(PointType::CLOSEFIGURE) {
                        if let (Some(from), Some(start)) = (last_point, figure_start) {
                            super::draw::draw_line_internal(
                                &surf, from.x, from.y, start.x, start.y,
                                pen_color, pen_width
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        // Clear the path
        entry.path.clear();
        entry.state = PathState::Idle;

        return true;
    }
    false
}

/// Widen the path (convert to outlined path)
pub fn widen_path(hdc: GdiHandle) -> bool {
    // TODO: Implement path widening (convert path to stroked outline)
    // This involves offsetting the path by pen width on both sides
    let _ = hdc;
    false
}

/// Flatten the path (convert curves to line segments)
pub fn flatten_path(hdc: GdiHandle) -> bool {
    let mut table = DC_PATH_STATE.lock();
    if let Some(entry) = table.get_entry(hdc) {
        if entry.state == PathState::Ready {
            entry.path = entry.path.flatten(BEZIER_TOLERANCE);
            return true;
        }
    }
    false
}

/// Get path data (points and types)
pub fn get_path(hdc: GdiHandle, points: &mut [Point], types: &mut [u8]) -> i32 {
    let table = DC_PATH_STATE.lock();
    if let Some(entry) = table.entries.iter().find(|e| e.dc == hdc) {
        if entry.state != PathState::Ready {
            return -1;
        }

        let count = entry.path.len();

        // If buffers are provided, fill them
        if !points.is_empty() && !types.is_empty() {
            let copy_count = count.min(points.len()).min(types.len());
            for (i, elem) in entry.path.elements().iter().take(copy_count).enumerate() {
                points[i] = elem.point;
                types[i] = elem.point_type.bits();
            }
        }

        return count as i32;
    }
    -1
}

/// Set the polygon fill mode for the DC
pub fn set_poly_fill_mode(hdc: GdiHandle, mode: FillMode) -> FillMode {
    let mut table = DC_PATH_STATE.lock();
    if let Some(entry) = table.get_entry(hdc) {
        let old_mode = entry.path.fill_mode();
        entry.path.set_fill_mode(mode);
        return old_mode;
    }
    FillMode::Alternate
}

// ============================================================================
// Scanline Fill Algorithm
// ============================================================================

/// Fill a polygon using scanline algorithm
fn fill_polygon_scanline(surf: &surface::Surface, points: &[Point], color: ColorRef, mode: FillMode) {
    if points.len() < 3 {
        return;
    }

    // Find bounding box
    let mut min_y = points[0].y;
    let mut max_y = points[0].y;

    for p in points.iter() {
        min_y = min_y.min(p.y);
        max_y = max_y.max(p.y);
    }

    // Scanline algorithm
    for y in min_y..=max_y {
        let mut intersections: Vec<i32> = Vec::new();

        // Find all edge intersections with this scanline
        let n = points.len();
        for i in 0..n {
            let p1 = points[i];
            let p2 = points[(i + 1) % n];

            // Skip horizontal edges
            if p1.y == p2.y {
                continue;
            }

            // Check if edge crosses this scanline
            let (y_min, y_max) = if p1.y < p2.y { (p1.y, p2.y) } else { (p2.y, p1.y) };

            if y >= y_min && y < y_max {
                // Calculate x intersection
                let x = p1.x + ((y - p1.y) as i64 * (p2.x - p1.x) as i64 / (p2.y - p1.y) as i64) as i32;
                intersections.push(x);
            }
        }

        // Sort intersections
        intersections.sort();

        // Fill between pairs of intersections
        match mode {
            FillMode::Alternate => {
                // Odd-even rule: fill between pairs
                for pair in intersections.chunks(2) {
                    if pair.len() == 2 {
                        for x in pair[0]..=pair[1] {
                            surf.set_pixel(x, y, color);
                        }
                    }
                }
            }
            FillMode::Winding => {
                // Non-zero winding: fill between pairs (simplified)
                // Full implementation would track winding direction
                for pair in intersections.chunks(2) {
                    if pair.len() == 2 {
                        for x in pair[0]..=pair[1] {
                            surf.set_pixel(x, y, color);
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// Extended Path Functions
// ============================================================================

/// Add a rectangle to the path
pub fn path_rectangle(hdc: GdiHandle, left: i32, top: i32, right: i32, bottom: i32) -> bool {
    let mut table = DC_PATH_STATE.lock();
    if let Some(entry) = table.get_entry(hdc) {
        if entry.state == PathState::Recording {
            entry.path.move_to(left, top);
            entry.path.line_to(right, top);
            entry.path.line_to(right, bottom);
            entry.path.line_to(left, bottom);
            entry.path.close_figure();
            return true;
        }
    }
    false
}

/// Add an ellipse to the path (approximated with bezier curves)
pub fn path_ellipse(hdc: GdiHandle, left: i32, top: i32, right: i32, bottom: i32) -> bool {
    let mut table = DC_PATH_STATE.lock();
    if let Some(entry) = table.get_entry(hdc) {
        if entry.state == PathState::Recording {
            // Approximate ellipse with 4 cubic bezier curves
            let cx = (left + right) / 2;
            let cy = (top + bottom) / 2;
            let rx = (right - left) / 2;
            let ry = (bottom - top) / 2;

            // Magic number for bezier approximation of quarter circle: (4/3) * tan(pi/8) ≈ 0.5523
            let kx = (rx as f32 * 0.5523) as i32;
            let ky = (ry as f32 * 0.5523) as i32;

            // Start at right-most point
            entry.path.move_to(cx + rx, cy);

            // Bottom-right quarter
            entry.path.bezier_to(
                cx + rx, cy + ky,
                cx + kx, cy + ry,
                cx, cy + ry
            );

            // Bottom-left quarter
            entry.path.bezier_to(
                cx - kx, cy + ry,
                cx - rx, cy + ky,
                cx - rx, cy
            );

            // Top-left quarter
            entry.path.bezier_to(
                cx - rx, cy - ky,
                cx - kx, cy - ry,
                cx, cy - ry
            );

            // Top-right quarter
            entry.path.bezier_to(
                cx + kx, cy - ry,
                cx + rx, cy - ky,
                cx + rx, cy
            );

            entry.path.close_figure();
            return true;
        }
    }
    false
}

/// Add a polygon to the path
pub fn path_polygon(hdc: GdiHandle, points: &[Point]) -> bool {
    if points.len() < 2 {
        return false;
    }

    let mut table = DC_PATH_STATE.lock();
    if let Some(entry) = table.get_entry(hdc) {
        if entry.state == PathState::Recording {
            entry.path.move_to(points[0].x, points[0].y);
            for p in points.iter().skip(1) {
                entry.path.line_to(p.x, p.y);
            }
            entry.path.close_figure();
            return true;
        }
    }
    false
}

/// Add a polyline to the path (no closing)
pub fn path_polyline(hdc: GdiHandle, points: &[Point]) -> bool {
    if points.len() < 2 {
        return false;
    }

    let mut table = DC_PATH_STATE.lock();
    if let Some(entry) = table.get_entry(hdc) {
        if entry.state == PathState::Recording {
            entry.path.move_to(points[0].x, points[0].y);
            for p in points.iter().skip(1) {
                entry.path.line_to(p.x, p.y);
            }
            return true;
        }
    }
    false
}
