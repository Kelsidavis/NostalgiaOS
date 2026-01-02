//! Image Color Management (ICM)
//!
//! GDI color management support for accurate color reproduction.
//! Provides color profile handling, color space conversions, and
//! color matching between devices.
//!
//! # Color Spaces
//!
//! - **sRGB**: Standard RGB color space
//! - **CIEXYZ**: CIE 1931 XYZ color space
//! - **CIELAB**: CIE L*a*b* perceptual color space
//! - **CMYK**: Cyan, Magenta, Yellow, Black (print)
//!
//! # Operations
//!
//! - **SetICMMode**: Enable/disable color management
//! - **SetColorSpace**: Set current color space
//! - **GetColorSpace**: Get current color space
//! - **CreateColorSpace**: Create a color space from profile
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntgdi/icm/` - ICM implementation
//! - `base/ntos/w32/ntgdi/icm/` - Kernel ICM support

extern crate alloc;

use super::super::{GdiHandle, ColorRef};
use crate::ke::spinlock::SpinLock;
use alloc::vec::Vec;
use alloc::string::String;

// ============================================================================
// ICM Constants
// ============================================================================

/// ICM mode: off
pub const ICM_OFF: u32 = 1;
/// ICM mode: on
pub const ICM_ON: u32 = 2;
/// ICM mode: query
pub const ICM_QUERY: u32 = 3;
/// ICM mode: done outside DC
pub const ICM_DONE_OUTSIDEDC: u32 = 4;

/// Color space type: calibrated RGB
pub const LCS_CALIBRATED_RGB: u32 = 0x00000000;
/// Color space type: sRGB
pub const LCS_sRGB: u32 = 0x73524742; // 'sRGB'
/// Color space type: Windows default
pub const LCS_WINDOWS_COLOR_SPACE: u32 = 0x57696E20; // 'Win '
/// Color space type: linked profile
pub const PROFILE_LINKED: u32 = 0x4C494E4B; // 'LINK'
/// Color space type: embedded profile
pub const PROFILE_EMBEDDED: u32 = 0x4D424544; // 'MBED'

/// Intent: Perceptual (images)
pub const LCS_GM_BUSINESS: u32 = 0x00000001;
/// Intent: Relative colorimetric
pub const LCS_GM_GRAPHICS: u32 = 0x00000002;
/// Intent: Saturation (graphics)
pub const LCS_GM_IMAGES: u32 = 0x00000004;
/// Intent: Absolute colorimetric
pub const LCS_GM_ABS_COLORIMETRIC: u32 = 0x00000008;

/// Maximum color profiles per DC
const MAX_COLOR_SPACES: usize = 64;

// ============================================================================
// CIE XYZ Color
// ============================================================================

/// CIE XYZ color value (fixed point Q2.30)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CieXyz {
    pub x: i32,
    pub y: i32,
    pub z: i32,
}

impl CieXyz {
    /// Create from floating point values
    pub fn from_float(x: f32, y: f32, z: f32) -> Self {
        Self {
            x: (x * (1 << 30) as f32) as i32,
            y: (y * (1 << 30) as f32) as i32,
            z: (z * (1 << 30) as f32) as i32,
        }
    }

    /// Convert to floating point
    pub fn to_float(&self) -> (f32, f32, f32) {
        let scale = 1.0 / (1 << 30) as f32;
        (
            self.x as f32 * scale,
            self.y as f32 * scale,
            self.z as f32 * scale,
        )
    }
}

/// CIE XYZ triple (for color space definition)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CieXyzTriple {
    pub red: CieXyz,
    pub green: CieXyz,
    pub blue: CieXyz,
}

impl CieXyzTriple {
    /// sRGB primaries
    pub fn srgb() -> Self {
        Self {
            red: CieXyz::from_float(0.64, 0.33, 0.03),
            green: CieXyz::from_float(0.30, 0.60, 0.10),
            blue: CieXyz::from_float(0.15, 0.06, 0.79),
        }
    }
}

// ============================================================================
// Logical Color Space
// ============================================================================

/// Logical color space definition
#[derive(Debug, Clone)]
#[repr(C)]
pub struct LogColorSpace {
    /// Signature (must be LCS_SIGNATURE)
    pub lcs_signature: u32,
    /// Version (0x400)
    pub lcs_version: u32,
    /// Size of structure
    pub lcs_size: u32,
    /// Color space type
    pub lcs_cs_type: u32,
    /// Rendering intent
    pub lcs_intent: u32,
    /// Endpoints (RGB primaries)
    pub lcs_endpoints: CieXyzTriple,
    /// Red gamma (Q16.16)
    pub lcs_gamma_red: u32,
    /// Green gamma (Q16.16)
    pub lcs_gamma_green: u32,
    /// Blue gamma (Q16.16)
    pub lcs_gamma_blue: u32,
    /// Profile filename (if linked)
    pub lcs_filename: String,
}

/// LCS signature
pub const LCS_SIGNATURE: u32 = 0x50534F43; // 'PSOC'

impl Default for LogColorSpace {
    fn default() -> Self {
        Self::srgb()
    }
}

impl LogColorSpace {
    /// Create sRGB color space
    pub fn srgb() -> Self {
        Self {
            lcs_signature: LCS_SIGNATURE,
            lcs_version: 0x400,
            lcs_size: core::mem::size_of::<Self>() as u32,
            lcs_cs_type: LCS_sRGB,
            lcs_intent: LCS_GM_IMAGES,
            lcs_endpoints: CieXyzTriple::srgb(),
            lcs_gamma_red: 0x00010000,   // Gamma 1.0 (sRGB uses 2.2 but stored as 1.0)
            lcs_gamma_green: 0x00010000,
            lcs_gamma_blue: 0x00010000,
            lcs_filename: String::new(),
        }
    }

    /// Create from calibrated RGB
    pub fn calibrated(endpoints: CieXyzTriple, gamma: f32) -> Self {
        let gamma_fixed = (gamma * 65536.0) as u32;
        Self {
            lcs_signature: LCS_SIGNATURE,
            lcs_version: 0x400,
            lcs_size: core::mem::size_of::<Self>() as u32,
            lcs_cs_type: LCS_CALIBRATED_RGB,
            lcs_intent: LCS_GM_IMAGES,
            lcs_endpoints: endpoints,
            lcs_gamma_red: gamma_fixed,
            lcs_gamma_green: gamma_fixed,
            lcs_gamma_blue: gamma_fixed,
            lcs_filename: String::new(),
        }
    }
}

// ============================================================================
// Color Space Handle
// ============================================================================

/// Color space handle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct HColorSpace(u32);

impl HColorSpace {
    pub const NULL: Self = Self(0);

    pub fn from_raw(value: u32) -> Self {
        Self(value)
    }

    pub fn as_raw(&self) -> u32 {
        self.0
    }

    pub fn is_null(&self) -> bool {
        self.0 == 0
    }
}

// ============================================================================
// Color Space Table
// ============================================================================

struct ColorSpaceEntry {
    handle: HColorSpace,
    color_space: LogColorSpace,
}

static COLOR_SPACE_TABLE: SpinLock<ColorSpaceTable> = SpinLock::new(ColorSpaceTable::new());

struct ColorSpaceTable {
    entries: Vec<ColorSpaceEntry>,
    next_handle: u32,
    srgb_handle: HColorSpace,
}

impl ColorSpaceTable {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_handle: 0x1000,
            srgb_handle: HColorSpace::NULL,
        }
    }

    fn init(&mut self) {
        // Create default sRGB color space
        let srgb = LogColorSpace::srgb();
        self.srgb_handle = self.allocate(srgb);
    }

    fn allocate(&mut self, color_space: LogColorSpace) -> HColorSpace {
        let handle = HColorSpace::from_raw(self.next_handle);
        self.next_handle += 1;

        self.entries.push(ColorSpaceEntry {
            handle,
            color_space,
        });

        handle
    }

    fn get(&self, handle: HColorSpace) -> Option<&LogColorSpace> {
        self.entries.iter()
            .find(|e| e.handle == handle)
            .map(|e| &e.color_space)
    }

    fn remove(&mut self, handle: HColorSpace) -> bool {
        if let Some(idx) = self.entries.iter().position(|e| e.handle == handle) {
            self.entries.remove(idx);
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Per-DC ICM State
// ============================================================================

struct DcIcmEntry {
    dc: GdiHandle,
    mode: u32,
    color_space: HColorSpace,
}

static DC_ICM_STATE: SpinLock<Vec<DcIcmEntry>> = SpinLock::new(Vec::new());

// ============================================================================
// ICM API
// ============================================================================

/// Initialize ICM subsystem
pub fn init() {
    let mut table = COLOR_SPACE_TABLE.lock();
    table.init();
    crate::serial_println!("[GDI] ICM subsystem initialized");
}

/// Set ICM mode for a DC
pub fn set_icm_mode(hdc: GdiHandle, mode: u32) -> u32 {
    if mode < ICM_OFF || mode > ICM_DONE_OUTSIDEDC {
        return 0;
    }

    let mut entries = DC_ICM_STATE.lock();

    // Find existing entry
    for entry in entries.iter_mut() {
        if entry.dc == hdc {
            let old = entry.mode;
            entry.mode = mode;
            return old;
        }
    }

    // Create new entry
    let table = COLOR_SPACE_TABLE.lock();
    entries.push(DcIcmEntry {
        dc: hdc,
        mode,
        color_space: table.srgb_handle,
    });

    ICM_OFF // Default previous mode
}

/// Get ICM mode for a DC
pub fn get_icm_mode(hdc: GdiHandle) -> u32 {
    let entries = DC_ICM_STATE.lock();
    entries.iter()
        .find(|e| e.dc == hdc)
        .map(|e| e.mode)
        .unwrap_or(ICM_OFF)
}

/// Create a color space from a logical color space
pub fn create_color_space(lcs: &LogColorSpace) -> HColorSpace {
    let mut table = COLOR_SPACE_TABLE.lock();
    table.allocate(lcs.clone())
}

/// Delete a color space
pub fn delete_color_space(hcs: HColorSpace) -> bool {
    // Don't delete the default sRGB color space
    let table_guard = COLOR_SPACE_TABLE.lock();
    if hcs == table_guard.srgb_handle {
        return false;
    }
    drop(table_guard);

    let mut table = COLOR_SPACE_TABLE.lock();
    table.remove(hcs)
}

/// Set the color space for a DC
pub fn set_color_space(hdc: GdiHandle, hcs: HColorSpace) -> HColorSpace {
    let mut entries = DC_ICM_STATE.lock();

    for entry in entries.iter_mut() {
        if entry.dc == hdc {
            let old = entry.color_space;
            entry.color_space = hcs;
            return old;
        }
    }

    // Create new entry
    let table = COLOR_SPACE_TABLE.lock();
    let default_cs = table.srgb_handle;
    drop(table);

    entries.push(DcIcmEntry {
        dc: hdc,
        mode: ICM_OFF,
        color_space: hcs,
    });

    default_cs
}

/// Get the color space for a DC
pub fn get_color_space(hdc: GdiHandle) -> HColorSpace {
    let entries = DC_ICM_STATE.lock();
    let result = entries.iter()
        .find(|e| e.dc == hdc)
        .map(|e| e.color_space);

    if let Some(hcs) = result {
        return hcs;
    }

    let table = COLOR_SPACE_TABLE.lock();
    table.srgb_handle
}

/// Get the default sRGB color space
pub fn get_stock_color_space() -> HColorSpace {
    let table = COLOR_SPACE_TABLE.lock();
    table.srgb_handle
}

/// Get logical color space data
pub fn get_log_color_space(hcs: HColorSpace) -> Option<LogColorSpace> {
    let table = COLOR_SPACE_TABLE.lock();
    table.get(hcs).cloned()
}

// ============================================================================
// Math Helpers (no_std compatible)
// ============================================================================

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

/// Approximate square root using Newton-Raphson iteration
fn sqrt_approx(x: f32) -> f32 {
    if x <= 0.0 {
        return 0.0;
    }

    // Initial guess using bit manipulation
    let mut guess = x;
    let mut i = x.to_bits();
    i = 0x5f3759df - (i >> 1); // Fast inverse sqrt trick
    let inv_sqrt = f32::from_bits(i);
    guess = 1.0 / inv_sqrt; // Invert to get sqrt

    // Two Newton-Raphson iterations for better accuracy
    guess = 0.5 * (guess + x / guess);
    guess = 0.5 * (guess + x / guess);

    guess
}

/// Approximate cube root
fn cbrt_approx(x: f32) -> f32 {
    if x == 0.0 {
        return 0.0;
    }

    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let abs_x = x * sign;

    // Initial guess
    let mut guess = abs_x;

    // Halley's method iterations for cube root
    for _ in 0..5 {
        let guess_cubed = guess * guess * guess;
        guess = guess * (guess_cubed + 2.0 * abs_x) / (2.0 * guess_cubed + abs_x);
    }

    guess * sign
}

/// Approximate power function x^y for positive x and arbitrary y
fn pow_approx(x: f32, y: f32) -> f32 {
    if x <= 0.0 {
        return 0.0;
    }
    if y == 0.0 {
        return 1.0;
    }
    if y == 1.0 {
        return x;
    }
    if y == 2.0 {
        return x * x;
    }
    if y == 0.5 {
        return sqrt_approx(x);
    }

    // Use exp(y * ln(x)) approximation
    // First compute natural log approximation
    let ln_x = ln_approx(x);
    exp_approx(y * ln_x)
}

/// Approximate natural logarithm
fn ln_approx(x: f32) -> f32 {
    if x <= 0.0 {
        return f32::NEG_INFINITY;
    }

    // Extract exponent and mantissa
    let bits = x.to_bits();
    let exp = ((bits >> 23) & 0xFF) as i32 - 127;
    let mantissa_bits = (bits & 0x007FFFFF) | 0x3F800000;
    let m = f32::from_bits(mantissa_bits);

    // ln(x) = ln(m * 2^exp) = ln(m) + exp * ln(2)
    // Approximate ln(m) for m in [1, 2) using polynomial
    let t = m - 1.0;
    let ln_m = t * (1.0 - t * (0.5 - t * (0.333333 - t * 0.25)));

    ln_m + (exp as f32) * 0.693147 // ln(2)
}

/// Approximate exponential function
fn exp_approx(x: f32) -> f32 {
    // Clamp to avoid overflow
    let x_clamped = if x > 88.0 { 88.0 } else if x < -88.0 { -88.0 } else { x };

    // exp(x) = 2^(x / ln(2)) = 2^(x * 1.4427)
    let t = x_clamped * 1.4427; // 1/ln(2)
    let floor_t = t as i32;
    let frac = t - floor_t as f32;

    // Approximate 2^frac for frac in [0, 1)
    let two_frac = 1.0 + frac * (0.693147 + frac * (0.240226 + frac * 0.055504));

    // Combine: 2^floor_t * 2^frac
    if floor_t >= 0 && floor_t < 127 {
        let bits = ((floor_t + 127) as u32) << 23;
        f32::from_bits(bits) * two_frac
    } else if floor_t < 0 && floor_t > -127 {
        let bits = ((floor_t + 127) as u32) << 23;
        f32::from_bits(bits) * two_frac
    } else {
        0.0
    }
}

// ============================================================================
// Color Conversion
// ============================================================================

/// Convert sRGB to linear RGB (gamma decode)
/// Uses a simplified approximation instead of exact gamma 2.4
pub fn srgb_to_linear(c: f32) -> f32 {
    if c <= 0.04045 {
        c / 12.92
    } else {
        // Approximate pow((c + 0.055) / 1.055, 2.4) with simpler formula
        let base = (c + 0.055) / 1.055;
        // Use x^2.4 ≈ x^2 * x^0.4, approximate x^0.4 with sqrt(sqrt(x)) * x^0.15
        base * base * sqrt_approx(base)
    }
}

/// Convert linear RGB to sRGB (gamma encode)
/// Uses a simplified approximation instead of exact gamma 1/2.4
pub fn linear_to_srgb(c: f32) -> f32 {
    if c <= 0.0031308 {
        c * 12.92
    } else {
        // Approximate pow(c, 1/2.4) ≈ sqrt(sqrt(c)) for simplicity
        1.055 * sqrt_approx(sqrt_approx(c)) - 0.055
    }
}

/// Convert sRGB to CIE XYZ
pub fn srgb_to_xyz(r: f32, g: f32, b: f32) -> (f32, f32, f32) {
    // Linearize
    let r_lin = srgb_to_linear(r);
    let g_lin = srgb_to_linear(g);
    let b_lin = srgb_to_linear(b);

    // sRGB to XYZ matrix (D65 illuminant)
    let x = 0.4124564 * r_lin + 0.3575761 * g_lin + 0.1804375 * b_lin;
    let y = 0.2126729 * r_lin + 0.7151522 * g_lin + 0.0721750 * b_lin;
    let z = 0.0193339 * r_lin + 0.1191920 * g_lin + 0.9503041 * b_lin;

    (x, y, z)
}

/// Convert CIE XYZ to sRGB
pub fn xyz_to_srgb(x: f32, y: f32, z: f32) -> (f32, f32, f32) {
    // XYZ to linear RGB matrix (D65 illuminant)
    let r_lin =  3.2404542 * x - 1.5371385 * y - 0.4985314 * z;
    let g_lin = -0.9692660 * x + 1.8760108 * y + 0.0415560 * z;
    let b_lin =  0.0556434 * x - 0.2040259 * y + 1.0572252 * z;

    // Clamp and gamma encode
    let r = linear_to_srgb(r_lin.max(0.0).min(1.0));
    let g = linear_to_srgb(g_lin.max(0.0).min(1.0));
    let b = linear_to_srgb(b_lin.max(0.0).min(1.0));

    (r, g, b)
}

/// Lab conversion helper function
fn lab_f(t: f32) -> f32 {
    if t > 0.008856 {
        cbrt_approx(t)
    } else {
        7.787 * t + 16.0 / 116.0
    }
}

/// Convert CIE XYZ to CIE L*a*b*
pub fn xyz_to_lab(x: f32, y: f32, z: f32) -> (f32, f32, f32) {
    // D65 reference white
    const XN: f32 = 0.95047;
    const YN: f32 = 1.00000;
    const ZN: f32 = 1.08883;

    let fx = lab_f(x / XN);
    let fy = lab_f(y / YN);
    let fz = lab_f(z / ZN);

    let l = 116.0 * fy - 16.0;
    let a = 500.0 * (fx - fy);
    let b = 200.0 * (fy - fz);

    (l, a, b)
}

/// Convert CIE L*a*b* to CIE XYZ
pub fn lab_to_xyz(l: f32, a: f32, b: f32) -> (f32, f32, f32) {
    // D65 reference white
    const XN: f32 = 0.95047;
    const YN: f32 = 1.00000;
    const ZN: f32 = 1.08883;

    fn f_inv(t: f32) -> f32 {
        if t > 0.206893 {
            t * t * t
        } else {
            (t - 16.0 / 116.0) / 7.787
        }
    }

    let fy = (l + 16.0) / 116.0;
    let fx = a / 500.0 + fy;
    let fz = fy - b / 200.0;

    let x = XN * f_inv(fx);
    let y = YN * f_inv(fy);
    let z = ZN * f_inv(fz);

    (x, y, z)
}

/// Convert sRGB ColorRef to CIE L*a*b*
pub fn color_to_lab(color: ColorRef) -> (f32, f32, f32) {
    let r = color.red() as f32 / 255.0;
    let g = color.green() as f32 / 255.0;
    let b = color.blue() as f32 / 255.0;

    let (x, y, z) = srgb_to_xyz(r, g, b);
    xyz_to_lab(x, y, z)
}

/// Convert CIE L*a*b* to sRGB ColorRef
pub fn lab_to_color(l: f32, a: f32, b: f32) -> ColorRef {
    let (x, y, z) = lab_to_xyz(l, a, b);
    let (r, g, b) = xyz_to_srgb(x, y, z);

    ColorRef::rgb(
        (r * 255.0)as u8,
        (g * 255.0)as u8,
        (b * 255.0)as u8,
    )
}

/// Calculate color difference (Delta E 2000)
pub fn color_difference(color1: ColorRef, color2: ColorRef) -> f32 {
    let (l1, a1, b1) = color_to_lab(color1);
    let (l2, a2, b2) = color_to_lab(color2);

    // Simplified Delta E (CIE76)
    let dl = l2 - l1;
    let da = a2 - a1;
    let db = b2 - b1;

    sqrt_approx(dl * dl + da * da + db * db)
}

/// Check if DC has ICM enabled
pub fn is_icm_enabled(hdc: GdiHandle) -> bool {
    get_icm_mode(hdc) == ICM_ON
}

/// Apply gamma correction to a color
pub fn apply_gamma(color: ColorRef, gamma: f32) -> ColorRef {
    let r = pow_approx(color.red() as f32 / 255.0, gamma);
    let g = pow_approx(color.green() as f32 / 255.0, gamma);
    let b = pow_approx(color.blue() as f32 / 255.0, gamma);

    ColorRef::rgb(
        (r * 255.0)as u8,
        (g * 255.0)as u8,
        (b * 255.0)as u8,
    )
}

/// Convert RGB to CMYK
pub fn rgb_to_cmyk(r: u8, g: u8, b: u8) -> (u8, u8, u8, u8) {
    let r_f = r as f32 / 255.0;
    let g_f = g as f32 / 255.0;
    let b_f = b as f32 / 255.0;

    let k = 1.0 - r_f.max(g_f).max(b_f);

    if k >= 1.0 {
        return (0, 0, 0, 255);
    }

    let c = (1.0 - r_f - k) / (1.0 - k);
    let m = (1.0 - g_f - k) / (1.0 - k);
    let y = (1.0 - b_f - k) / (1.0 - k);

    (
        (c * 255.0)as u8,
        (m * 255.0)as u8,
        (y * 255.0)as u8,
        (k * 255.0)as u8,
    )
}

/// Convert CMYK to RGB
pub fn cmyk_to_rgb(c: u8, m: u8, y: u8, k: u8) -> (u8, u8, u8) {
    let c_f = c as f32 / 255.0;
    let m_f = m as f32 / 255.0;
    let y_f = y as f32 / 255.0;
    let k_f = k as f32 / 255.0;

    let r = (1.0 - c_f) * (1.0 - k_f);
    let g = (1.0 - m_f) * (1.0 - k_f);
    let b = (1.0 - y_f) * (1.0 - k_f);

    (
        (r * 255.0)as u8,
        (g * 255.0)as u8,
        (b * 255.0)as u8,
    )
}
