//! GDI Drawing Helpers
//!
//! Helper functions for GDI drawing operations.
//! Based on Windows Server 2003 wingdi.h.
//!
//! # Features
//!
//! - Drawing primitives
//! - Brush/Pen helpers
//! - Text rendering helpers
//! - Bitmap helpers
//!
//! # References
//!
//! - `public/sdk/inc/wingdi.h` - GDI API

use super::super::{Rect, Point, ColorRef};

// ============================================================================
// Stock Object IDs (GetStockObject)
// ============================================================================

/// White brush
pub const WHITE_BRUSH: i32 = 0;

/// Light gray brush
pub const LTGRAY_BRUSH: i32 = 1;

/// Gray brush
pub const GRAY_BRUSH: i32 = 2;

/// Dark gray brush
pub const DKGRAY_BRUSH: i32 = 3;

/// Black brush
pub const BLACK_BRUSH: i32 = 4;

/// Null brush
pub const NULL_BRUSH: i32 = 5;

/// Hollow brush (same as null)
pub const HOLLOW_BRUSH: i32 = NULL_BRUSH;

/// White pen
pub const WHITE_PEN: i32 = 6;

/// Black pen
pub const BLACK_PEN: i32 = 7;

/// Null pen
pub const NULL_PEN: i32 = 8;

/// OEM fixed font
pub const OEM_FIXED_FONT: i32 = 10;

/// ANSI fixed font
pub const ANSI_FIXED_FONT: i32 = 11;

/// ANSI var font
pub const ANSI_VAR_FONT: i32 = 12;

/// System font
pub const SYSTEM_FONT: i32 = 13;

/// Device default font
pub const DEVICE_DEFAULT_FONT: i32 = 14;

/// Default palette
pub const DEFAULT_PALETTE: i32 = 15;

/// System fixed font
pub const SYSTEM_FIXED_FONT: i32 = 16;

/// Default GUI font
pub const DEFAULT_GUI_FONT: i32 = 17;

/// DC brush
pub const DC_BRUSH: i32 = 18;

/// DC pen
pub const DC_PEN: i32 = 19;

// ============================================================================
// Pen Styles (PS_*)
// ============================================================================

/// Solid pen
pub const PS_SOLID: i32 = 0;

/// Dash pen
pub const PS_DASH: i32 = 1;

/// Dot pen
pub const PS_DOT: i32 = 2;

/// Dash dot pen
pub const PS_DASHDOT: i32 = 3;

/// Dash dot dot pen
pub const PS_DASHDOTDOT: i32 = 4;

/// Null pen style
pub const PS_NULL: i32 = 5;

/// Inside frame pen
pub const PS_INSIDEFRAME: i32 = 6;

/// User style pen
pub const PS_USERSTYLE: i32 = 7;

/// Alternate pen
pub const PS_ALTERNATE: i32 = 8;

/// Style mask
pub const PS_STYLE_MASK: i32 = 0x0000000F;

/// End cap round
pub const PS_ENDCAP_ROUND: i32 = 0x00000000;

/// End cap square
pub const PS_ENDCAP_SQUARE: i32 = 0x00000100;

/// End cap flat
pub const PS_ENDCAP_FLAT: i32 = 0x00000200;

/// End cap mask
pub const PS_ENDCAP_MASK: i32 = 0x00000F00;

/// Join round
pub const PS_JOIN_ROUND: i32 = 0x00000000;

/// Join bevel
pub const PS_JOIN_BEVEL: i32 = 0x00001000;

/// Join miter
pub const PS_JOIN_MITER: i32 = 0x00002000;

/// Join mask
pub const PS_JOIN_MASK: i32 = 0x0000F000;

/// Cosmetic pen
pub const PS_COSMETIC: i32 = 0x00000000;

/// Geometric pen
pub const PS_GEOMETRIC: i32 = 0x00010000;

/// Type mask
pub const PS_TYPE_MASK: i32 = 0x000F0000;

// ============================================================================
// Brush Styles (BS_*)
// ============================================================================

/// Solid brush
pub const BS_SOLID: i32 = 0;

/// Null brush
pub const BS_NULL: i32 = 1;

/// Hollow brush
pub const BS_HOLLOW: i32 = BS_NULL;

/// Hatched brush
pub const BS_HATCHED: i32 = 2;

/// Pattern brush
pub const BS_PATTERN: i32 = 3;

/// Indexed brush
pub const BS_INDEXED: i32 = 4;

/// DIB pattern brush
pub const BS_DIBPATTERN: i32 = 5;

/// DIB pattern PT brush
pub const BS_DIBPATTERNPT: i32 = 6;

/// Pattern 8x8 brush
pub const BS_PATTERN8X8: i32 = 7;

/// DIB pattern 8x8 brush
pub const BS_DIBPATTERN8X8: i32 = 8;

/// Mono pattern brush
pub const BS_MONOPATTERN: i32 = 9;

// ============================================================================
// Hatch Styles (HS_*)
// ============================================================================

/// Horizontal hatch
pub const HS_HORIZONTAL: i32 = 0;

/// Vertical hatch
pub const HS_VERTICAL: i32 = 1;

/// Forward diagonal hatch
pub const HS_FDIAGONAL: i32 = 2;

/// Backward diagonal hatch
pub const HS_BDIAGONAL: i32 = 3;

/// Cross hatch
pub const HS_CROSS: i32 = 4;

/// Diagonal cross hatch
pub const HS_DIAGCROSS: i32 = 5;

// ============================================================================
// ROP2 Modes
// ============================================================================

/// R2 black
pub const R2_BLACK: i32 = 1;

/// R2 not merge pen
pub const R2_NOTMERGEPEN: i32 = 2;

/// R2 mask not pen
pub const R2_MASKNOTPEN: i32 = 3;

/// R2 not copy pen
pub const R2_NOTCOPYPEN: i32 = 4;

/// R2 mask pen not
pub const R2_MASKPENNOT: i32 = 5;

/// R2 not
pub const R2_NOT: i32 = 6;

/// R2 xor pen
pub const R2_XORPEN: i32 = 7;

/// R2 not mask pen
pub const R2_NOTMASKPEN: i32 = 8;

/// R2 mask pen
pub const R2_MASKPEN: i32 = 9;

/// R2 not xor pen
pub const R2_NOTXORPEN: i32 = 10;

/// R2 nop
pub const R2_NOP: i32 = 11;

/// R2 merge not pen
pub const R2_MERGENOTPEN: i32 = 12;

/// R2 copy pen
pub const R2_COPYPEN: i32 = 13;

/// R2 merge pen not
pub const R2_MERGEPENNOT: i32 = 14;

/// R2 merge pen
pub const R2_MERGEPEN: i32 = 15;

/// R2 white
pub const R2_WHITE: i32 = 16;

// ============================================================================
// Ternary Raster Operations
// ============================================================================

/// Source copy
pub const SRCCOPY: u32 = 0x00CC0020;

/// Source paint
pub const SRCPAINT: u32 = 0x00EE0086;

/// Source and
pub const SRCAND: u32 = 0x008800C6;

/// Source invert
pub const SRCINVERT: u32 = 0x00660046;

/// Source erase
pub const SRCERASE: u32 = 0x00440328;

/// Not source copy
pub const NOTSRCCOPY: u32 = 0x00330008;

/// Not source erase
pub const NOTSRCERASE: u32 = 0x001100A6;

/// Merge copy
pub const MERGECOPY: u32 = 0x00C000CA;

/// Merge paint
pub const MERGEPAINT: u32 = 0x00BB0226;

/// Pattern copy
pub const PATCOPY: u32 = 0x00F00021;

/// Pattern paint
pub const PATPAINT: u32 = 0x00FB0A09;

/// Pattern invert
pub const PATINVERT: u32 = 0x005A0049;

/// Dest invert
pub const DSTINVERT: u32 = 0x00550009;

/// Blackness
pub const BLACKNESS: u32 = 0x00000042;

/// Whiteness
pub const WHITENESS: u32 = 0x00FF0062;

// ============================================================================
// Mapping Modes (MM_*)
// ============================================================================

/// Text mapping mode
pub const MM_TEXT: i32 = 1;

/// Low metric
pub const MM_LOMETRIC: i32 = 2;

/// High metric
pub const MM_HIMETRIC: i32 = 3;

/// Low English
pub const MM_LOENGLISH: i32 = 4;

/// High English
pub const MM_HIENGLISH: i32 = 5;

/// Twips
pub const MM_TWIPS: i32 = 6;

/// Isotropic
pub const MM_ISOTROPIC: i32 = 7;

/// Anisotropic
pub const MM_ANISOTROPIC: i32 = 8;

// ============================================================================
// Background Modes
// ============================================================================

/// Transparent background
pub const TRANSPARENT: i32 = 1;

/// Opaque background
pub const OPAQUE: i32 = 2;

// ============================================================================
// Text Alignment (TA_*)
// ============================================================================

/// Left align
pub const TA_LEFT: u32 = 0;

/// Right align
pub const TA_RIGHT: u32 = 2;

/// Center align
pub const TA_CENTER: u32 = 6;

/// Top align
pub const TA_TOP: u32 = 0;

/// Bottom align
pub const TA_BOTTOM: u32 = 8;

/// Baseline align
pub const TA_BASELINE: u32 = 24;

/// Update CP
pub const TA_UPDATECP: u32 = 1;

/// No update CP
pub const TA_NOUPDATECP: u32 = 0;

// ============================================================================
// Stretch Modes
// ============================================================================

/// Blackonwhite
pub const BLACKONWHITE: i32 = 1;

/// Whiteonblack
pub const WHITEONBLACK: i32 = 2;

/// Coloroncolor
pub const COLORONCOLOR: i32 = 3;

/// Halftone
pub const HALFTONE: i32 = 4;

/// Stretch and scans
pub const STRETCH_ANDSCANS: i32 = BLACKONWHITE;

/// Stretch or scans
pub const STRETCH_ORSCANS: i32 = WHITEONBLACK;

/// Stretch delete scans
pub const STRETCH_DELETESCANS: i32 = COLORONCOLOR;

/// Stretch halftone
pub const STRETCH_HALFTONE: i32 = HALFTONE;

// ============================================================================
// Polygon Fill Modes
// ============================================================================

/// Alternate fill
pub const ALTERNATE: i32 = 1;

/// Winding fill
pub const WINDING: i32 = 2;

// ============================================================================
// Arc Direction
// ============================================================================

/// Counterclockwise
pub const AD_COUNTERCLOCKWISE: i32 = 1;

/// Clockwise
pub const AD_CLOCKWISE: i32 = 2;

// ============================================================================
// Region Types
// ============================================================================

/// Error region
pub const ERROR: i32 = 0;

/// Null region
pub const NULLREGION: i32 = 1;

/// Simple region
pub const SIMPLEREGION: i32 = 2;

/// Complex region
pub const COMPLEXREGION: i32 = 3;

// ============================================================================
// Region Combine Modes (RGN_*)
// ============================================================================

/// And regions
pub const RGN_AND: i32 = 1;

/// Or regions
pub const RGN_OR: i32 = 2;

/// Xor regions
pub const RGN_XOR: i32 = 3;

/// Diff regions
pub const RGN_DIFF: i32 = 4;

/// Copy region
pub const RGN_COPY: i32 = 5;

// ============================================================================
// Helper Functions
// ============================================================================

/// Create RGB color
pub const fn rgb(r: u8, g: u8, b: u8) -> ColorRef {
    ColorRef::rgb(r, g, b)
}

/// Get red component
pub const fn get_r_value(color: ColorRef) -> u8 {
    color.red()
}

/// Get green component
pub const fn get_g_value(color: ColorRef) -> u8 {
    color.green()
}

/// Get blue component
pub const fn get_b_value(color: ColorRef) -> u8 {
    color.blue()
}

/// Palette RGB
pub const fn palettergb(r: u8, g: u8, b: u8) -> ColorRef {
    ColorRef((r as u32) | ((g as u32) << 8) | ((b as u32) << 16) | 0x02000000)
}

/// Palette index
pub const fn paletteindex(i: u16) -> ColorRef {
    ColorRef((i as u32) | 0x01000000)
}

/// Calculate rectangle width
pub const fn rect_width(r: &Rect) -> i32 {
    r.right - r.left
}

/// Calculate rectangle height
pub const fn rect_height(r: &Rect) -> i32 {
    r.bottom - r.top
}

/// Set rectangle
pub fn set_rect(r: &mut Rect, left: i32, top: i32, right: i32, bottom: i32) {
    r.left = left;
    r.top = top;
    r.right = right;
    r.bottom = bottom;
}

/// Set rectangle empty
pub fn set_rect_empty(r: &mut Rect) {
    r.left = 0;
    r.top = 0;
    r.right = 0;
    r.bottom = 0;
}

/// Copy rectangle
pub fn copy_rect(dest: &mut Rect, src: &Rect) {
    *dest = *src;
}

/// Is rectangle empty
pub fn is_rect_empty(r: &Rect) -> bool {
    r.left >= r.right || r.top >= r.bottom
}

/// Point in rectangle
pub fn pt_in_rect(r: &Rect, pt: Point) -> bool {
    pt.x >= r.left && pt.x < r.right && pt.y >= r.top && pt.y < r.bottom
}

/// Offset rectangle
pub fn offset_rect(r: &mut Rect, dx: i32, dy: i32) {
    r.left += dx;
    r.top += dy;
    r.right += dx;
    r.bottom += dy;
}

/// Inflate rectangle
pub fn inflate_rect(r: &mut Rect, dx: i32, dy: i32) {
    r.left -= dx;
    r.top -= dy;
    r.right += dx;
    r.bottom += dy;
}

/// Intersect rectangles
pub fn intersect_rect(dest: &mut Rect, src1: &Rect, src2: &Rect) -> bool {
    dest.left = src1.left.max(src2.left);
    dest.top = src1.top.max(src2.top);
    dest.right = src1.right.min(src2.right);
    dest.bottom = src1.bottom.min(src2.bottom);

    if dest.left >= dest.right || dest.top >= dest.bottom {
        set_rect_empty(dest);
        false
    } else {
        true
    }
}

/// Union rectangles
pub fn union_rect(dest: &mut Rect, src1: &Rect, src2: &Rect) -> bool {
    if is_rect_empty(src1) {
        if is_rect_empty(src2) {
            set_rect_empty(dest);
            return false;
        }
        *dest = *src2;
        return true;
    }

    if is_rect_empty(src2) {
        *dest = *src1;
        return true;
    }

    dest.left = src1.left.min(src2.left);
    dest.top = src1.top.min(src2.top);
    dest.right = src1.right.max(src2.right);
    dest.bottom = src1.bottom.max(src2.bottom);

    true
}

/// Subtract rectangles
pub fn subtract_rect(dest: &mut Rect, src1: &Rect, src2: &Rect) -> bool {
    // Simple case: no intersection
    if src1.left >= src2.right || src1.right <= src2.left ||
       src1.top >= src2.bottom || src1.bottom <= src2.top {
        *dest = *src1;
        return !is_rect_empty(dest);
    }

    // If src2 completely contains src1
    if src2.left <= src1.left && src2.right >= src1.right &&
       src2.top <= src1.top && src2.bottom >= src1.bottom {
        set_rect_empty(dest);
        return false;
    }

    // Return src1 (simplified - real impl would handle partial overlap)
    *dest = *src1;
    !is_rect_empty(dest)
}

/// Equal rectangles
pub fn equal_rect(r1: &Rect, r2: &Rect) -> bool {
    r1.left == r2.left && r1.top == r2.top &&
    r1.right == r2.right && r1.bottom == r2.bottom
}

/// Normalize rectangle (ensure left < right, top < bottom)
pub fn normalize_rect(r: &mut Rect) {
    if r.left > r.right {
        core::mem::swap(&mut r.left, &mut r.right);
    }
    if r.top > r.bottom {
        core::mem::swap(&mut r.top, &mut r.bottom);
    }
}

/// Make POINTS from x, y
pub const fn make_points(x: i16, y: i16) -> u32 {
    ((y as u32) << 16) | (x as u16 as u32)
}

/// Get X from POINTS
pub const fn points_x(pts: u32) -> i16 {
    pts as i16
}

/// Get Y from POINTS
pub const fn points_y(pts: u32) -> i16 {
    (pts >> 16) as i16
}

/// Make POINT from lParam
pub fn point_from_lparam(lparam: usize) -> Point {
    Point {
        x: (lparam & 0xFFFF) as i16 as i32,
        y: ((lparam >> 16) & 0xFFFF) as i16 as i32,
    }
}

/// Make lParam from POINT
pub fn lparam_from_point(pt: Point) -> usize {
    ((pt.y as u16 as usize) << 16) | (pt.x as u16 as usize)
}

// ============================================================================
// Color Helpers
// ============================================================================

/// Blend two colors
pub fn blend_colors(c1: ColorRef, c2: ColorRef, weight: u8) -> ColorRef {
    let w1 = weight as u32;
    let w2 = 255 - w1;

    let r = ((c1.red() as u32 * w1 + c2.red() as u32 * w2) / 255) as u8;
    let g = ((c1.green() as u32 * w1 + c2.green() as u32 * w2) / 255) as u8;
    let b = ((c1.blue() as u32 * w1 + c2.blue() as u32 * w2) / 255) as u8;

    ColorRef::rgb(r, g, b)
}

/// Lighten color
pub fn lighten_color(color: ColorRef, amount: u8) -> ColorRef {
    blend_colors(ColorRef::rgb(255, 255, 255), color, amount)
}

/// Darken color
pub fn darken_color(color: ColorRef, amount: u8) -> ColorRef {
    blend_colors(ColorRef::rgb(0, 0, 0), color, amount)
}

/// Get system color value (simplified)
pub fn get_sys_color(index: i32) -> ColorRef {
    match index {
        0 => ColorRef::rgb(212, 208, 200),  // COLOR_SCROLLBAR
        1 => ColorRef::rgb(58, 110, 165),   // COLOR_BACKGROUND
        2 => ColorRef::rgb(10, 36, 106),    // COLOR_ACTIVECAPTION
        3 => ColorRef::rgb(128, 128, 128),  // COLOR_INACTIVECAPTION
        4 => ColorRef::rgb(212, 208, 200),  // COLOR_MENU
        5 => ColorRef::rgb(255, 255, 255),  // COLOR_WINDOW
        6 => ColorRef::rgb(0, 0, 0),        // COLOR_WINDOWFRAME
        7 => ColorRef::rgb(0, 0, 0),        // COLOR_MENUTEXT
        8 => ColorRef::rgb(0, 0, 0),        // COLOR_WINDOWTEXT
        9 => ColorRef::rgb(255, 255, 255),  // COLOR_CAPTIONTEXT
        10 => ColorRef::rgb(212, 208, 200), // COLOR_ACTIVEBORDER
        11 => ColorRef::rgb(212, 208, 200), // COLOR_INACTIVEBORDER
        12 => ColorRef::rgb(128, 128, 128), // COLOR_APPWORKSPACE
        13 => ColorRef::rgb(10, 36, 106),   // COLOR_HIGHLIGHT
        14 => ColorRef::rgb(255, 255, 255), // COLOR_HIGHLIGHTTEXT
        15 => ColorRef::rgb(212, 208, 200), // COLOR_BTNFACE/COLOR_3DFACE
        16 => ColorRef::rgb(128, 128, 128), // COLOR_BTNSHADOW/COLOR_3DSHADOW
        17 => ColorRef::rgb(128, 128, 128), // COLOR_GRAYTEXT
        18 => ColorRef::rgb(0, 0, 0),       // COLOR_BTNTEXT
        19 => ColorRef::rgb(212, 208, 200), // COLOR_INACTIVECAPTIONTEXT
        20 => ColorRef::rgb(255, 255, 255), // COLOR_BTNHIGHLIGHT/COLOR_3DHIGHLIGHT
        21 => ColorRef::rgb(64, 64, 64),    // COLOR_3DDKSHADOW
        22 => ColorRef::rgb(223, 223, 223), // COLOR_3DLIGHT
        23 => ColorRef::rgb(0, 0, 0),       // COLOR_INFOTEXT
        24 => ColorRef::rgb(255, 255, 225), // COLOR_INFOBK
        26 => ColorRef::rgb(181, 181, 181), // COLOR_HOTLIGHT
        27 => ColorRef::rgb(166, 202, 240), // COLOR_GRADIENTACTIVECAPTION
        28 => ColorRef::rgb(192, 192, 192), // COLOR_GRADIENTINACTIVECAPTION
        29 => ColorRef::rgb(49, 106, 197),  // COLOR_MENUHILIGHT
        30 => ColorRef::rgb(236, 233, 216), // COLOR_MENUBAR
        _ => ColorRef::rgb(0, 0, 0),
    }
}

/// Get system color brush (returns fake handle based on color index)
pub fn get_sys_color_brush(index: i32) -> usize {
    // Return a pseudo-handle that encodes the color index
    (index as usize) | 0x80000000
}

// ============================================================================
// Text Helpers
// ============================================================================

/// Calculate text width (simplified - assumes 8 pixels per char)
pub fn get_text_extent_simple(text: &[u8]) -> (i32, i32) {
    let len = super::strhelp::str_len(text) as i32;
    (len * 8, 16)
}

/// Calculate multiline text height
pub fn calculate_text_height(text: &[u8], width: i32, char_width: i32, line_height: i32) -> i32 {
    if width <= 0 || char_width <= 0 {
        return line_height;
    }

    let chars_per_line = (width / char_width).max(1);
    let text_len = super::strhelp::str_len(text) as i32;
    let lines = ((text_len + chars_per_line - 1) / chars_per_line).max(1);

    lines * line_height
}

// ============================================================================
// Initialize
// ============================================================================

/// Initialize GDI helpers
pub fn init() {
    crate::serial_println!("[USER] GDI helpers initialized");
}
