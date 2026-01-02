//! Coordinate Transforms
//!
//! GDI coordinate transformation support including world, page, and device transforms.
//! Supports translation, scaling, rotation, and shearing.
//!
//! # Transform Chain
//!
//! Logical coords → World transform → Page transform → Device coords
//!
//! # Operations
//!
//! - **SetWorldTransform**: Set the world transformation matrix
//! - **ModifyWorldTransform**: Modify existing transform (multiply, prepend)
//! - **GetWorldTransform**: Retrieve current world transform
//! - **SetGraphicsMode**: Enable/disable advanced graphics mode
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntgdi/gre/xformobj.cxx` - Transform object
//! - `windows/core/ntgdi/gre/mapmode.cxx` - Mapping mode

extern crate alloc;

use super::super::{GdiHandle, Point};
use crate::ke::spinlock::SpinLock;
use alloc::vec::Vec;

// ============================================================================
// Constants
// ============================================================================

/// Graphics mode: Compatible (no world transform)
pub const GM_COMPATIBLE: u32 = 1;
/// Graphics mode: Advanced (world transform enabled)
pub const GM_ADVANCED: u32 = 2;

/// Modify world transform: Replace
pub const MWT_IDENTITY: u32 = 1;
/// Modify world transform: Left-multiply (prepend)
pub const MWT_LEFTMULTIPLY: u32 = 2;
/// Modify world transform: Right-multiply (append)
pub const MWT_RIGHTMULTIPLY: u32 = 3;

/// Mapping mode: 1 logical unit = 1 device pixel
pub const MM_TEXT: u32 = 1;
/// Mapping mode: 1 logical unit = 0.1mm
pub const MM_LOMETRIC: u32 = 2;
/// Mapping mode: 1 logical unit = 0.01mm
pub const MM_HIMETRIC: u32 = 3;
/// Mapping mode: 1 logical unit = 0.01 inch
pub const MM_LOENGLISH: u32 = 4;
/// Mapping mode: 1 logical unit = 0.001 inch
pub const MM_HIENGLISH: u32 = 5;
/// Mapping mode: 1 logical unit = 1/1440 inch (twip)
pub const MM_TWIPS: u32 = 6;
/// Mapping mode: Isotropic (user-defined, aspect preserved)
pub const MM_ISOTROPIC: u32 = 7;
/// Mapping mode: Anisotropic (user-defined)
pub const MM_ANISOTROPIC: u32 = 8;

// ============================================================================
// Transform Matrix
// ============================================================================

/// 2D affine transformation matrix
///
/// Represented as a 3x2 matrix:
/// ```text
/// | eM11  eM12  0 |
/// | eM21  eM22  0 |
/// | eDx   eDy   1 |
/// ```
///
/// Transform: x' = x*eM11 + y*eM21 + eDx
///           y' = x*eM12 + y*eM22 + eDy
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct XForm {
    /// Horizontal scaling component
    pub eM11: f32,
    /// Vertical shear component
    pub eM12: f32,
    /// Horizontal shear component
    pub eM21: f32,
    /// Vertical scaling component
    pub eM22: f32,
    /// Horizontal translation
    pub eDx: f32,
    /// Vertical translation
    pub eDy: f32,
}

impl Default for XForm {
    fn default() -> Self {
        Self::identity()
    }
}

impl XForm {
    /// Create identity transform
    pub const fn identity() -> Self {
        Self {
            eM11: 1.0,
            eM12: 0.0,
            eM21: 0.0,
            eM22: 1.0,
            eDx: 0.0,
            eDy: 0.0,
        }
    }

    /// Create translation transform
    pub fn translate(dx: f32, dy: f32) -> Self {
        Self {
            eM11: 1.0,
            eM12: 0.0,
            eM21: 0.0,
            eM22: 1.0,
            eDx: dx,
            eDy: dy,
        }
    }

    /// Create scaling transform
    pub fn scale(sx: f32, sy: f32) -> Self {
        Self {
            eM11: sx,
            eM12: 0.0,
            eM21: 0.0,
            eM22: sy,
            eDx: 0.0,
            eDy: 0.0,
        }
    }

    /// Create rotation transform (angle in radians)
    pub fn rotate(angle: f32) -> Self {
        // Simple Taylor series approximation for sin/cos
        let cos_a = cos_approx(angle);
        let sin_a = sin_approx(angle);
        Self {
            eM11: cos_a,
            eM12: sin_a,
            eM21: -sin_a,
            eM22: cos_a,
            eDx: 0.0,
            eDy: 0.0,
        }
    }

    /// Create rotation transform (angle in degrees)
    pub fn rotate_degrees(degrees: f32) -> Self {
        Self::rotate(degrees * core::f32::consts::PI / 180.0)
    }

    /// Create shear transform
    pub fn shear(shx: f32, shy: f32) -> Self {
        Self {
            eM11: 1.0,
            eM12: shy,
            eM21: shx,
            eM22: 1.0,
            eDx: 0.0,
            eDy: 0.0,
        }
    }

    /// Create mirror/reflection transform
    pub fn mirror(horizontal: bool, vertical: bool) -> Self {
        Self {
            eM11: if horizontal { -1.0 } else { 1.0 },
            eM12: 0.0,
            eM21: 0.0,
            eM22: if vertical { -1.0 } else { 1.0 },
            eDx: 0.0,
            eDy: 0.0,
        }
    }

    /// Multiply two transforms (self * other)
    pub fn multiply(&self, other: &XForm) -> XForm {
        XForm {
            eM11: self.eM11 * other.eM11 + self.eM12 * other.eM21,
            eM12: self.eM11 * other.eM12 + self.eM12 * other.eM22,
            eM21: self.eM21 * other.eM11 + self.eM22 * other.eM21,
            eM22: self.eM21 * other.eM12 + self.eM22 * other.eM22,
            eDx: self.eDx * other.eM11 + self.eDy * other.eM21 + other.eDx,
            eDy: self.eDx * other.eM12 + self.eDy * other.eM22 + other.eDy,
        }
    }

    /// Compute the inverse transform
    pub fn inverse(&self) -> Option<XForm> {
        let det = self.eM11 * self.eM22 - self.eM12 * self.eM21;

        // Check for singular matrix
        if det.abs() < 1e-10 {
            return None;
        }

        let inv_det = 1.0 / det;

        Some(XForm {
            eM11: self.eM22 * inv_det,
            eM12: -self.eM12 * inv_det,
            eM21: -self.eM21 * inv_det,
            eM22: self.eM11 * inv_det,
            eDx: (self.eM21 * self.eDy - self.eM22 * self.eDx) * inv_det,
            eDy: (self.eM12 * self.eDx - self.eM11 * self.eDy) * inv_det,
        })
    }

    /// Transform a point
    pub fn transform_point(&self, x: f32, y: f32) -> (f32, f32) {
        let new_x = x * self.eM11 + y * self.eM21 + self.eDx;
        let new_y = x * self.eM12 + y * self.eM22 + self.eDy;
        (new_x, new_y)
    }

    /// Transform a point (integer version)
    pub fn transform_point_i(&self, x: i32, y: i32) -> (i32, i32) {
        let (fx, fy) = self.transform_point(x as f32, y as f32);
        (round_f32(fx) as i32, round_f32(fy) as i32)
    }

    /// Transform a Point struct
    pub fn transform(&self, p: Point) -> Point {
        let (x, y) = self.transform_point_i(p.x, p.y);
        Point::new(x, y)
    }

    /// Check if this is an identity transform
    pub fn is_identity(&self) -> bool {
        (self.eM11 - 1.0).abs() < 1e-6 &&
        self.eM12.abs() < 1e-6 &&
        self.eM21.abs() < 1e-6 &&
        (self.eM22 - 1.0).abs() < 1e-6 &&
        self.eDx.abs() < 1e-6 &&
        self.eDy.abs() < 1e-6
    }

    /// Check if transform only involves translation and scaling (no rotation/shear)
    pub fn is_simple(&self) -> bool {
        self.eM12.abs() < 1e-6 && self.eM21.abs() < 1e-6
    }
}

// ============================================================================
// Per-DC Transform State
// ============================================================================

/// Transform state for a DC
#[derive(Debug, Clone)]
pub struct TransformState {
    /// Graphics mode (GM_COMPATIBLE or GM_ADVANCED)
    pub graphics_mode: u32,
    /// World transform (only used in GM_ADVANCED)
    pub world_transform: XForm,
    /// Mapping mode (MM_TEXT, MM_LOMETRIC, etc.)
    pub map_mode: u32,
    /// Window origin (logical coords)
    pub window_org: Point,
    /// Window extent (logical coords)
    pub window_ext: Point,
    /// Viewport origin (device coords)
    pub viewport_org: Point,
    /// Viewport extent (device coords)
    pub viewport_ext: Point,
}

impl Default for TransformState {
    fn default() -> Self {
        Self {
            graphics_mode: GM_COMPATIBLE,
            world_transform: XForm::identity(),
            map_mode: MM_TEXT,
            window_org: Point::new(0, 0),
            window_ext: Point::new(1, 1),
            viewport_org: Point::new(0, 0),
            viewport_ext: Point::new(1, 1),
        }
    }
}

impl TransformState {
    /// Get the combined page transform (window/viewport mapping)
    pub fn page_transform(&self) -> XForm {
        if self.map_mode == MM_TEXT {
            // Simple identity for MM_TEXT
            XForm::identity()
        } else {
            // Scale from window to viewport
            let scale_x = self.viewport_ext.x as f32 / self.window_ext.x as f32;
            let scale_y = self.viewport_ext.y as f32 / self.window_ext.y as f32;

            // Translate from window origin to viewport origin
            let dx = self.viewport_org.x as f32 - self.window_org.x as f32 * scale_x;
            let dy = self.viewport_org.y as f32 - self.window_org.y as f32 * scale_y;

            XForm {
                eM11: scale_x,
                eM12: 0.0,
                eM21: 0.0,
                eM22: scale_y,
                eDx: dx,
                eDy: dy,
            }
        }
    }

    /// Get the combined transform (world + page)
    pub fn combined_transform(&self) -> XForm {
        if self.graphics_mode == GM_ADVANCED {
            self.world_transform.multiply(&self.page_transform())
        } else {
            self.page_transform()
        }
    }

    /// Transform logical point to device point
    pub fn lp_to_dp(&self, p: Point) -> Point {
        self.combined_transform().transform(p)
    }

    /// Transform device point to logical point
    pub fn dp_to_lp(&self, p: Point) -> Option<Point> {
        self.combined_transform().inverse().map(|inv| inv.transform(p))
    }
}

// ============================================================================
// DC Transform Table
// ============================================================================

static DC_TRANSFORMS: SpinLock<DcTransformTable> = SpinLock::new(DcTransformTable::new());

struct DcTransformEntry {
    dc: GdiHandle,
    state: TransformState,
}

struct DcTransformTable {
    entries: Vec<DcTransformEntry>,
}

impl DcTransformTable {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn get_entry(&mut self, hdc: GdiHandle) -> Option<&mut DcTransformEntry> {
        self.entries.iter_mut().find(|e| e.dc == hdc)
    }

    fn get_or_create(&mut self, hdc: GdiHandle) -> &mut DcTransformEntry {
        if let Some(idx) = self.entries.iter().position(|e| e.dc == hdc) {
            return &mut self.entries[idx];
        }
        self.entries.push(DcTransformEntry {
            dc: hdc,
            state: TransformState::default(),
        });
        self.entries.last_mut().unwrap()
    }
}

// ============================================================================
// Transform API
// ============================================================================

/// Initialize transform subsystem
pub fn init() {
    crate::serial_println!("[GDI] Transform subsystem initialized");
}

/// Set the graphics mode
pub fn set_graphics_mode(hdc: GdiHandle, mode: u32) -> u32 {
    if mode != GM_COMPATIBLE && mode != GM_ADVANCED {
        return 0;
    }

    let mut table = DC_TRANSFORMS.lock();
    let entry = table.get_or_create(hdc);
    let old_mode = entry.state.graphics_mode;
    entry.state.graphics_mode = mode;

    // Reset world transform when switching modes
    if mode != old_mode {
        entry.state.world_transform = XForm::identity();
    }

    old_mode
}

/// Get the graphics mode
pub fn get_graphics_mode(hdc: GdiHandle) -> u32 {
    let mut table = DC_TRANSFORMS.lock();
    table.get_or_create(hdc).state.graphics_mode
}

/// Set the world transform
pub fn set_world_transform(hdc: GdiHandle, xform: &XForm) -> bool {
    let mut table = DC_TRANSFORMS.lock();
    let entry = table.get_or_create(hdc);

    // World transform only works in advanced mode
    if entry.state.graphics_mode != GM_ADVANCED {
        return false;
    }

    entry.state.world_transform = *xform;
    true
}

/// Get the world transform
pub fn get_world_transform(hdc: GdiHandle, xform: &mut XForm) -> bool {
    let mut table = DC_TRANSFORMS.lock();
    let entry = table.get_or_create(hdc);
    *xform = entry.state.world_transform;
    true
}

/// Modify the world transform
pub fn modify_world_transform(hdc: GdiHandle, xform: &XForm, mode: u32) -> bool {
    let mut table = DC_TRANSFORMS.lock();
    let entry = table.get_or_create(hdc);

    if entry.state.graphics_mode != GM_ADVANCED {
        return false;
    }

    match mode {
        MWT_IDENTITY => {
            entry.state.world_transform = XForm::identity();
        }
        MWT_LEFTMULTIPLY => {
            // New = xform * old
            entry.state.world_transform = xform.multiply(&entry.state.world_transform);
        }
        MWT_RIGHTMULTIPLY => {
            // New = old * xform
            entry.state.world_transform = entry.state.world_transform.multiply(xform);
        }
        _ => return false,
    }

    true
}

/// Set the mapping mode
pub fn set_map_mode(hdc: GdiHandle, mode: u32) -> u32 {
    if mode < MM_TEXT || mode > MM_ANISOTROPIC {
        return 0;
    }

    let mut table = DC_TRANSFORMS.lock();
    let entry = table.get_or_create(hdc);
    let old_mode = entry.state.map_mode;
    entry.state.map_mode = mode;

    // Set default extents based on mode
    match mode {
        MM_TEXT => {
            entry.state.window_ext = Point::new(1, 1);
            entry.state.viewport_ext = Point::new(1, 1);
        }
        MM_LOMETRIC => {
            // 0.1mm per unit, y-axis up
            entry.state.window_ext = Point::new(1, 1);
            entry.state.viewport_ext = Point::new(1, -1);
        }
        MM_HIMETRIC => {
            // 0.01mm per unit, y-axis up
            entry.state.window_ext = Point::new(1, 1);
            entry.state.viewport_ext = Point::new(1, -1);
        }
        MM_LOENGLISH => {
            // 0.01 inch per unit, y-axis up
            entry.state.window_ext = Point::new(1, 1);
            entry.state.viewport_ext = Point::new(1, -1);
        }
        MM_HIENGLISH => {
            // 0.001 inch per unit, y-axis up
            entry.state.window_ext = Point::new(1, 1);
            entry.state.viewport_ext = Point::new(1, -1);
        }
        MM_TWIPS => {
            // 1/1440 inch per unit, y-axis up
            entry.state.window_ext = Point::new(1, 1);
            entry.state.viewport_ext = Point::new(1, -1);
        }
        _ => {}
    }

    old_mode
}

/// Get the mapping mode
pub fn get_map_mode(hdc: GdiHandle) -> u32 {
    let mut table = DC_TRANSFORMS.lock();
    table.get_or_create(hdc).state.map_mode
}

/// Set the window origin
pub fn set_window_org(hdc: GdiHandle, x: i32, y: i32) -> Point {
    let mut table = DC_TRANSFORMS.lock();
    let entry = table.get_or_create(hdc);
    let old = entry.state.window_org;
    entry.state.window_org = Point::new(x, y);
    old
}

/// Get the window origin
pub fn get_window_org(hdc: GdiHandle) -> Point {
    let mut table = DC_TRANSFORMS.lock();
    table.get_or_create(hdc).state.window_org
}

/// Offset the window origin
pub fn offset_window_org(hdc: GdiHandle, dx: i32, dy: i32) -> Point {
    let mut table = DC_TRANSFORMS.lock();
    let entry = table.get_or_create(hdc);
    let old = entry.state.window_org;
    entry.state.window_org.x += dx;
    entry.state.window_org.y += dy;
    old
}

/// Set the window extent
pub fn set_window_ext(hdc: GdiHandle, x: i32, y: i32) -> Point {
    let mut table = DC_TRANSFORMS.lock();
    let entry = table.get_or_create(hdc);

    // Only allowed in MM_ISOTROPIC or MM_ANISOTROPIC
    if entry.state.map_mode != MM_ISOTROPIC && entry.state.map_mode != MM_ANISOTROPIC {
        return entry.state.window_ext;
    }

    let old = entry.state.window_ext;
    entry.state.window_ext = Point::new(x, y);

    // For isotropic mode, adjust viewport to maintain aspect ratio
    if entry.state.map_mode == MM_ISOTROPIC {
        adjust_viewport_for_isotropic(entry);
    }

    old
}

/// Get the window extent
pub fn get_window_ext(hdc: GdiHandle) -> Point {
    let mut table = DC_TRANSFORMS.lock();
    table.get_or_create(hdc).state.window_ext
}

/// Set the viewport origin
pub fn set_viewport_org(hdc: GdiHandle, x: i32, y: i32) -> Point {
    let mut table = DC_TRANSFORMS.lock();
    let entry = table.get_or_create(hdc);
    let old = entry.state.viewport_org;
    entry.state.viewport_org = Point::new(x, y);
    old
}

/// Get the viewport origin
pub fn get_viewport_org(hdc: GdiHandle) -> Point {
    let mut table = DC_TRANSFORMS.lock();
    table.get_or_create(hdc).state.viewport_org
}

/// Offset the viewport origin
pub fn offset_viewport_org(hdc: GdiHandle, dx: i32, dy: i32) -> Point {
    let mut table = DC_TRANSFORMS.lock();
    let entry = table.get_or_create(hdc);
    let old = entry.state.viewport_org;
    entry.state.viewport_org.x += dx;
    entry.state.viewport_org.y += dy;
    old
}

/// Set the viewport extent
pub fn set_viewport_ext(hdc: GdiHandle, x: i32, y: i32) -> Point {
    let mut table = DC_TRANSFORMS.lock();
    let entry = table.get_or_create(hdc);

    // Only allowed in MM_ISOTROPIC or MM_ANISOTROPIC
    if entry.state.map_mode != MM_ISOTROPIC && entry.state.map_mode != MM_ANISOTROPIC {
        return entry.state.viewport_ext;
    }

    let old = entry.state.viewport_ext;
    entry.state.viewport_ext = Point::new(x, y);

    // For isotropic mode, adjust to maintain aspect ratio
    if entry.state.map_mode == MM_ISOTROPIC {
        adjust_viewport_for_isotropic(entry);
    }

    old
}

/// Get the viewport extent
pub fn get_viewport_ext(hdc: GdiHandle) -> Point {
    let mut table = DC_TRANSFORMS.lock();
    table.get_or_create(hdc).state.viewport_ext
}

/// Adjust viewport extent to maintain aspect ratio (for MM_ISOTROPIC)
fn adjust_viewport_for_isotropic(entry: &mut DcTransformEntry) {
    let wx = entry.state.window_ext.x.abs() as f32;
    let wy = entry.state.window_ext.y.abs() as f32;
    let vx = entry.state.viewport_ext.x.abs() as f32;
    let vy = entry.state.viewport_ext.y.abs() as f32;

    if wx == 0.0 || wy == 0.0 {
        return;
    }

    let window_aspect = wx / wy;
    let viewport_aspect = vx / vy;

    if viewport_aspect > window_aspect {
        // Viewport is wider, adjust x
        let new_vx = (vy * window_aspect) as i32;
        let sign = if entry.state.viewport_ext.x < 0 { -1 } else { 1 };
        entry.state.viewport_ext.x = new_vx * sign;
    } else {
        // Viewport is taller, adjust y
        let new_vy = (vx / window_aspect) as i32;
        let sign = if entry.state.viewport_ext.y < 0 { -1 } else { 1 };
        entry.state.viewport_ext.y = new_vy * sign;
    }
}

/// Transform logical point to device point
pub fn lp_to_dp(hdc: GdiHandle, points: &mut [Point]) -> bool {
    let mut table = DC_TRANSFORMS.lock();
    let entry = table.get_or_create(hdc);
    let xform = entry.state.combined_transform();

    for p in points.iter_mut() {
        *p = xform.transform(*p);
    }

    true
}

/// Transform device point to logical point
pub fn dp_to_lp(hdc: GdiHandle, points: &mut [Point]) -> bool {
    let mut table = DC_TRANSFORMS.lock();
    let entry = table.get_or_create(hdc);

    if let Some(inv) = entry.state.combined_transform().inverse() {
        for p in points.iter_mut() {
            *p = inv.transform(*p);
        }
        true
    } else {
        false
    }
}

/// Get transform state for a DC
pub fn get_transform_state(hdc: GdiHandle) -> TransformState {
    let mut table = DC_TRANSFORMS.lock();
    table.get_or_create(hdc).state.clone()
}

/// Scale viewport to window ratio
pub fn scale_viewport_ext(hdc: GdiHandle, x_num: i32, x_denom: i32, y_num: i32, y_denom: i32) -> Point {
    let mut table = DC_TRANSFORMS.lock();
    let entry = table.get_or_create(hdc);

    if entry.state.map_mode != MM_ISOTROPIC && entry.state.map_mode != MM_ANISOTROPIC {
        return entry.state.viewport_ext;
    }

    let old = entry.state.viewport_ext;

    if x_denom != 0 {
        entry.state.viewport_ext.x = entry.state.viewport_ext.x * x_num / x_denom;
    }
    if y_denom != 0 {
        entry.state.viewport_ext.y = entry.state.viewport_ext.y * y_num / y_denom;
    }

    if entry.state.map_mode == MM_ISOTROPIC {
        adjust_viewport_for_isotropic(entry);
    }

    old
}

/// Scale window to viewport ratio
pub fn scale_window_ext(hdc: GdiHandle, x_num: i32, x_denom: i32, y_num: i32, y_denom: i32) -> Point {
    let mut table = DC_TRANSFORMS.lock();
    let entry = table.get_or_create(hdc);

    if entry.state.map_mode != MM_ISOTROPIC && entry.state.map_mode != MM_ANISOTROPIC {
        return entry.state.window_ext;
    }

    let old = entry.state.window_ext;

    if x_denom != 0 {
        entry.state.window_ext.x = entry.state.window_ext.x * x_num / x_denom;
    }
    if y_denom != 0 {
        entry.state.window_ext.y = entry.state.window_ext.y * y_num / y_denom;
    }

    if entry.state.map_mode == MM_ISOTROPIC {
        adjust_viewport_for_isotropic(entry);
    }

    old
}

// ============================================================================
// Math Helper Functions
// ============================================================================

/// Approximate sine using Taylor series
fn sin_approx(x: f32) -> f32 {
    // Normalize to [-PI, PI]
    let pi = core::f32::consts::PI;
    let mut x = x % (2.0 * pi);
    if x > pi {
        x -= 2.0 * pi;
    } else if x < -pi {
        x += 2.0 * pi;
    }

    // Taylor series: sin(x) ≈ x - x³/6 + x⁵/120 - x⁷/5040
    let x2 = x * x;
    let x3 = x2 * x;
    let x5 = x3 * x2;
    let x7 = x5 * x2;

    x - x3 / 6.0 + x5 / 120.0 - x7 / 5040.0
}

/// Approximate cosine using Taylor series
fn cos_approx(x: f32) -> f32 {
    // cos(x) = sin(x + PI/2)
    sin_approx(x + core::f32::consts::FRAC_PI_2)
}

/// Round a float to nearest integer
fn round_f32(x: f32) -> f32 {
    let truncated = x as i32 as f32;
    if x - truncated >= 0.5 {
        truncated + 1.0
    } else if x - truncated <= -0.5 {
        truncated - 1.0
    } else {
        truncated
    }
}
