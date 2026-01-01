//! Drawing Operations
//!
//! Low-level drawing primitives that render to surfaces.
//!
//! # Operations
//!
//! - **BitBlt**: Bit block transfer
//! - **PatBlt**: Pattern block transfer
//! - **LineTo**: Draw line
//! - **Rectangle**: Draw rectangle
//! - **FillRect**: Fill rectangle
//! - **TextOut**: Draw text
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntgdi/gre/drawgdi.cxx`
//! - `windows/core/ntgdi/gre/trivblt.cxx`

use super::super::{GdiHandle, ColorRef, Rect, Point};
use super::{Rop3, dc, surface, brush, pen, font};

// ============================================================================
// Pixel Operations
// ============================================================================

/// Set a pixel
pub fn gdi_set_pixel(hdc: GdiHandle, x: i32, y: i32, color: ColorRef) -> ColorRef {
    let surface_handle = dc::get_dc_surface(hdc);

    if let Some(surf) = surface::get_surface(surface_handle) {
        // Transform coordinates
        let pt = dc::lp_to_dp(hdc, Point::new(x, y));

        let prev = surf.get_pixel(pt.x, pt.y).unwrap_or(ColorRef::BLACK);
        surf.set_pixel(pt.x, pt.y, color);
        prev
    } else {
        ColorRef::BLACK
    }
}

/// Get a pixel
pub fn gdi_get_pixel(hdc: GdiHandle, x: i32, y: i32) -> ColorRef {
    let surface_handle = dc::get_dc_surface(hdc);

    if let Some(surf) = surface::get_surface(surface_handle) {
        let pt = dc::lp_to_dp(hdc, Point::new(x, y));
        surf.get_pixel(pt.x, pt.y).unwrap_or(ColorRef::BLACK)
    } else {
        ColorRef::BLACK
    }
}

// ============================================================================
// Line Drawing
// ============================================================================

/// Draw a line from current position to (x, y)
pub fn gdi_line_to(hdc: GdiHandle, x: i32, y: i32) -> bool {
    let dc_data = match dc::get_dc(hdc) {
        Some(d) => d,
        None => return false,
    };

    let surface_handle = dc_data.surface;
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return false,
    };

    // Get pen color
    let pen_data = pen::get_pen(dc_data.pen);
    let color = pen_data.map(|p| p.color).unwrap_or(ColorRef::BLACK);
    let pen_width = pen_data.map(|p| p.width).unwrap_or(1);

    // Is it a null pen?
    if pen_data.map(|p| p.style == pen::PenStyle::Null).unwrap_or(false) {
        // Just update position, don't draw
        dc::dc_move_to(hdc, x, y);
        return true;
    }

    // Transform coordinates
    let p1 = dc::lp_to_dp(hdc, dc_data.current_pos);
    let p2 = dc::lp_to_dp(hdc, Point::new(x, y));

    // Draw line using Bresenham's algorithm
    draw_line(&surf, p1.x, p1.y, p2.x, p2.y, color, pen_width);

    // Update current position
    dc::dc_move_to(hdc, x, y);

    true
}

/// Bresenham's line algorithm
fn draw_line(surf: &surface::Surface, x0: i32, y0: i32, x1: i32, y1: i32, color: ColorRef, width: i32) {
    let dx = (x1 - x0).abs();
    let dy = (y1 - y0).abs();
    let sx: i32 = if x0 < x1 { 1 } else { -1 };
    let sy: i32 = if y0 < y1 { 1 } else { -1 };
    let mut err = dx - dy;

    let mut x = x0;
    let mut y = y0;

    loop {
        // Draw pixel (or thick line)
        if width <= 1 {
            surf.set_pixel(x, y, color);
        } else {
            // Draw a filled circle for thick lines
            let half = width / 2;
            for py in (y - half)..=(y + half) {
                for px in (x - half)..=(x + half) {
                    let dx = px - x;
                    let dy = py - y;
                    if dx * dx + dy * dy <= half * half {
                        surf.set_pixel(px, py, color);
                    }
                }
            }
        }

        if x == x1 && y == y1 {
            break;
        }

        let e2 = 2 * err;
        if e2 > -dy {
            err -= dy;
            x += sx;
        }
        if e2 < dx {
            err += dx;
            y += sy;
        }
    }
}

// ============================================================================
// Rectangle Drawing
// ============================================================================

/// Draw a rectangle outline and fill
pub fn gdi_rectangle(hdc: GdiHandle, left: i32, top: i32, right: i32, bottom: i32) -> bool {
    let dc_data = match dc::get_dc(hdc) {
        Some(d) => d,
        None => return false,
    };

    let surface_handle = dc_data.surface;
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return false,
    };

    // Transform coordinates
    let p1 = dc::lp_to_dp(hdc, Point::new(left, top));
    let p2 = dc::lp_to_dp(hdc, Point::new(right, bottom));

    let rect = Rect::new(p1.x, p1.y, p2.x, p2.y);

    // Fill with brush
    let brush_data = brush::get_brush(dc_data.brush);
    if let Some(b) = brush_data {
        if b.style != brush::BrushStyle::Null {
            // Fill interior (excluding border)
            let inner = Rect::new(rect.left + 1, rect.top + 1, rect.right - 1, rect.bottom - 1);
            surf.fill_rect(&inner, b.color);
        }
    }

    // Draw border with pen
    let pen_data = pen::get_pen(dc_data.pen);
    if let Some(p) = pen_data {
        if p.style != pen::PenStyle::Null {
            // Top
            surf.hline(rect.left, rect.right, rect.top, p.color);
            // Bottom
            surf.hline(rect.left, rect.right, rect.bottom - 1, p.color);
            // Left
            surf.vline(rect.left, rect.top, rect.bottom, p.color);
            // Right
            surf.vline(rect.right - 1, rect.top, rect.bottom, p.color);
        }
    }

    true
}

/// Fill a rectangle with a brush
pub fn gdi_fill_rect(hdc: GdiHandle, rect: &Rect, hbrush: GdiHandle) -> bool {
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return false,
    };

    // Get brush color
    let color = brush::get_brush_color(hbrush);

    // Transform coordinates
    let p1 = dc::lp_to_dp(hdc, Point::new(rect.left, rect.top));
    let p2 = dc::lp_to_dp(hdc, Point::new(rect.right, rect.bottom));

    let transformed = Rect::new(p1.x, p1.y, p2.x, p2.y);

    surf.fill_rect(&transformed, color)
}

/// Draw a rectangle frame
pub fn gdi_frame_rect(hdc: GdiHandle, rect: &Rect, hbrush: GdiHandle) -> bool {
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return false,
    };

    // Get brush color
    let color = brush::get_brush_color(hbrush);

    // Transform coordinates
    let p1 = dc::lp_to_dp(hdc, Point::new(rect.left, rect.top));
    let p2 = dc::lp_to_dp(hdc, Point::new(rect.right, rect.bottom));

    // Draw frame
    surf.hline(p1.x, p2.x, p1.y, color);     // Top
    surf.hline(p1.x, p2.x, p2.y - 1, color); // Bottom
    surf.vline(p1.x, p1.y, p2.y, color);     // Left
    surf.vline(p2.x - 1, p1.y, p2.y, color); // Right

    true
}

// ============================================================================
// Bit Block Transfer
// ============================================================================

/// Bit block transfer
pub fn gdi_bit_blt(
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
    let dest_surface = dc::get_dc_surface(hdc_dest);
    let src_surface = dc::get_dc_surface(hdc_src);

    let dest = match surface::get_surface(dest_surface) {
        Some(s) => s,
        None => return false,
    };

    // For SRCCOPY with valid source, copy pixels
    if rop as u32 == Rop3::SrcCopy as u32 {
        if let Some(src) = surface::get_surface(src_surface) {
            // Simple copy without clipping optimization
            for y in 0..height {
                for x in 0..width {
                    if let Some(pixel) = src.get_pixel(x_src + x, y_src + y) {
                        dest.set_pixel(x_dest + x, y_dest + y, pixel);
                    }
                }
            }
            return true;
        }
    }

    // For pattern operations, use the brush
    match rop {
        Rop3::PatCopy => {
            let brush_handle = dc::get_dc_brush(hdc_dest);
            let color = brush::get_brush_color(brush_handle);
            let rect = Rect::new(x_dest, y_dest, x_dest + width, y_dest + height);
            dest.fill_rect(&rect, color)
        }
        Rop3::Blackness => {
            let rect = Rect::new(x_dest, y_dest, x_dest + width, y_dest + height);
            dest.fill_rect(&rect, ColorRef::BLACK)
        }
        Rop3::Whiteness => {
            let rect = Rect::new(x_dest, y_dest, x_dest + width, y_dest + height);
            dest.fill_rect(&rect, ColorRef::WHITE)
        }
        Rop3::DstInvert => {
            // Invert destination pixels
            for y in y_dest..(y_dest + height) {
                for x in x_dest..(x_dest + width) {
                    if let Some(pixel) = dest.get_pixel(x, y) {
                        let inverted = ColorRef::rgb(
                            255 - pixel.red(),
                            255 - pixel.green(),
                            255 - pixel.blue(),
                        );
                        dest.set_pixel(x, y, inverted);
                    }
                }
            }
            true
        }
        _ => {
            // Other ROPs not implemented
            false
        }
    }
}

/// Pattern block transfer (fill with brush)
pub fn gdi_pat_blt(
    hdc: GdiHandle,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    rop: Rop3,
) -> bool {
    gdi_bit_blt(hdc, x, y, width, height, GdiHandle::NULL, 0, 0, rop)
}

// ============================================================================
// Text Drawing
// ============================================================================

/// Draw text at position
pub fn gdi_text_out(hdc: GdiHandle, x: i32, y: i32, text: &str) -> bool {
    let dc_data = match dc::get_dc(hdc) {
        Some(d) => d,
        None => return false,
    };

    let surface_handle = dc_data.surface;
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return false,
    };

    let text_color = dc_data.text_color;
    let bk_color = dc_data.bk_color;
    let bk_mode = dc_data.bk_mode;

    // Get font cell size
    let cell_size = font::get_font_cell_size(dc_data.font);
    let char_width = cell_size.cx;
    let char_height = cell_size.cy;

    // Transform starting position
    let start = dc::lp_to_dp(hdc, Point::new(x, y));

    let mut cx = start.x;
    let cy = start.y;

    for ch in text.bytes() {
        // Get character bitmap
        let bitmap = font::get_char_bitmap(ch);

        // Draw each row of the character
        for row in 0..16 {
            let bits = bitmap[row];
            for col in 0..8 {
                let px = cx + col;
                let py = cy + row as i32;

                if (bits >> (7 - col)) & 1 != 0 {
                    // Foreground pixel
                    surf.set_pixel(px, py, text_color);
                } else if bk_mode == dc::BkMode::Opaque {
                    // Background pixel (only in opaque mode)
                    surf.set_pixel(px, py, bk_color);
                }
            }
        }

        cx += char_width;
    }

    true
}

/// Draw text with extent
pub fn gdi_ext_text_out(
    hdc: GdiHandle,
    x: i32,
    y: i32,
    options: u32,
    rect: Option<&Rect>,
    text: &str,
) -> bool {
    const ETO_OPAQUE: u32 = 0x0002;
    const ETO_CLIPPED: u32 = 0x0004;

    // If ETO_OPAQUE, fill background rect first
    if options & ETO_OPAQUE != 0 {
        if let Some(r) = rect {
            let dc_data = match dc::get_dc(hdc) {
                Some(d) => d,
                None => return false,
            };

            let surface_handle = dc_data.surface;
            if let Some(surf) = surface::get_surface(surface_handle) {
                let p1 = dc::lp_to_dp(hdc, Point::new(r.left, r.top));
                let p2 = dc::lp_to_dp(hdc, Point::new(r.right, r.bottom));
                let transformed = Rect::new(p1.x, p1.y, p2.x, p2.y);
                surf.fill_rect(&transformed, dc_data.bk_color);
            }
        }
    }

    // TODO: implement clipping (ETO_CLIPPED)

    gdi_text_out(hdc, x, y, text)
}

// ============================================================================
// Ellipse/Circle Drawing
// ============================================================================

/// Draw an ellipse
pub fn gdi_ellipse(hdc: GdiHandle, left: i32, top: i32, right: i32, bottom: i32) -> bool {
    let dc_data = match dc::get_dc(hdc) {
        Some(d) => d,
        None => return false,
    };

    let surface_handle = dc_data.surface;
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return false,
    };

    // Transform coordinates
    let p1 = dc::lp_to_dp(hdc, Point::new(left, top));
    let p2 = dc::lp_to_dp(hdc, Point::new(right, bottom));

    let cx = (p1.x + p2.x) / 2;
    let cy = (p1.y + p2.y) / 2;
    let rx = (p2.x - p1.x) / 2;
    let ry = (p2.y - p1.y) / 2;

    // Get brush for fill
    let brush_data = brush::get_brush(dc_data.brush);
    let fill_color = brush_data.map(|b| b.color);
    let is_null_brush = brush_data.map(|b| b.style == brush::BrushStyle::Null).unwrap_or(true);

    // Get pen for outline
    let pen_data = pen::get_pen(dc_data.pen);
    let outline_color = pen_data.map(|p| p.color).unwrap_or(ColorRef::BLACK);
    let is_null_pen = pen_data.map(|p| p.style == pen::PenStyle::Null).unwrap_or(false);

    // Draw filled ellipse using midpoint algorithm
    if !is_null_brush {
        if let Some(color) = fill_color {
            draw_filled_ellipse(&surf, cx, cy, rx, ry, color);
        }
    }

    // Draw ellipse outline
    if !is_null_pen {
        draw_ellipse_outline(&surf, cx, cy, rx, ry, outline_color);
    }

    true
}

/// Draw filled ellipse
fn draw_filled_ellipse(surf: &surface::Surface, cx: i32, cy: i32, rx: i32, ry: i32, color: ColorRef) {
    if rx <= 0 || ry <= 0 {
        return;
    }

    let rx2 = (rx * rx) as i64;
    let ry2 = (ry * ry) as i64;

    for y in -ry..=ry {
        // Calculate x extent at this y
        let y2 = (y * y) as i64;
        let x_max_sq = rx2 - (y2 * rx2) / ry2;
        if x_max_sq < 0 {
            continue;
        }

        let x_max = isqrt(x_max_sq as u64) as i32;

        surf.hline(cx - x_max, cx + x_max + 1, cy + y, color);
    }
}

/// Integer square root (Newton's method)
fn isqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Draw ellipse outline using midpoint algorithm
fn draw_ellipse_outline(surf: &surface::Surface, cx: i32, cy: i32, rx: i32, ry: i32, color: ColorRef) {
    if rx <= 0 || ry <= 0 {
        surf.set_pixel(cx, cy, color);
        return;
    }

    let mut x = 0i32;
    let mut y = ry;

    let rx2 = (rx * rx) as i64;
    let ry2 = (ry * ry) as i64;

    let mut dx = 2 * ry2 * x as i64;
    let mut dy = 2 * rx2 * y as i64;

    let mut d1 = ry2 - rx2 * ry as i64 + rx2 / 4;

    while dx < dy {
        // Draw the 4 symmetric points
        surf.set_pixel(cx + x, cy + y, color);
        surf.set_pixel(cx - x, cy + y, color);
        surf.set_pixel(cx + x, cy - y, color);
        surf.set_pixel(cx - x, cy - y, color);

        if d1 < 0 {
            x += 1;
            dx += 2 * ry2;
            d1 += dx + ry2;
        } else {
            x += 1;
            y -= 1;
            dx += 2 * ry2;
            dy -= 2 * rx2;
            d1 += dx - dy + ry2;
        }
    }

    let mut d2 = ry2 * ((2 * x + 1) * (2 * x + 1)) as i64 / 4
        + rx2 * (y - 1) as i64 * (y - 1) as i64
        - rx2 * ry2;

    while y >= 0 {
        surf.set_pixel(cx + x, cy + y, color);
        surf.set_pixel(cx - x, cy + y, color);
        surf.set_pixel(cx + x, cy - y, color);
        surf.set_pixel(cx - x, cy - y, color);

        if d2 > 0 {
            y -= 1;
            dy -= 2 * rx2;
            d2 += rx2 - dy;
        } else {
            y -= 1;
            x += 1;
            dx += 2 * ry2;
            dy -= 2 * rx2;
            d2 += dx - dy + rx2;
        }
    }
}

// ============================================================================
// Rounded Rectangle Drawing
// ============================================================================

/// Draw a rounded rectangle
pub fn gdi_round_rect(
    hdc: GdiHandle,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    width: i32,
    height: i32,
) -> bool {
    let dc_data = match dc::get_dc(hdc) {
        Some(d) => d,
        None => return false,
    };

    let surface_handle = dc_data.surface;
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return false,
    };

    // Transform coordinates
    let p1 = dc::lp_to_dp(hdc, Point::new(left, top));
    let p2 = dc::lp_to_dp(hdc, Point::new(right, bottom));

    let rect_left = p1.x.min(p2.x);
    let rect_top = p1.y.min(p2.y);
    let rect_right = p1.x.max(p2.x);
    let rect_bottom = p1.y.max(p2.y);

    // Corner radii (half of ellipse width/height)
    let rx = (width / 2).min((rect_right - rect_left) / 2);
    let ry = (height / 2).min((rect_bottom - rect_top) / 2);

    // Get brush for fill
    let brush_data = brush::get_brush(dc_data.brush);
    let fill_color = brush_data.map(|b| b.color);
    let is_null_brush = brush_data.map(|b| b.style == brush::BrushStyle::Null).unwrap_or(true);

    // Get pen for outline
    let pen_data = pen::get_pen(dc_data.pen);
    let outline_color = pen_data.map(|p| p.color).unwrap_or(ColorRef::BLACK);
    let is_null_pen = pen_data.map(|p| p.style == pen::PenStyle::Null).unwrap_or(false);

    // Fill the rounded rectangle
    if !is_null_brush {
        if let Some(color) = fill_color {
            draw_filled_round_rect(&surf, rect_left, rect_top, rect_right, rect_bottom, rx, ry, color);
        }
    }

    // Draw the outline
    if !is_null_pen {
        draw_round_rect_outline(&surf, rect_left, rect_top, rect_right, rect_bottom, rx, ry, outline_color);
    }

    true
}

/// Draw filled rounded rectangle
fn draw_filled_round_rect(
    surf: &surface::Surface,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    rx: i32,
    ry: i32,
    color: ColorRef,
) {
    if rx <= 0 || ry <= 0 {
        // No rounding, just a regular rectangle
        surf.fill_rect(&Rect::new(left, top, right, bottom), color);
        return;
    }

    let rx2 = (rx * rx) as i64;
    let ry2 = (ry * ry) as i64;

    // Fill the center rectangle (full width)
    surf.fill_rect(&Rect::new(left, top + ry, right, bottom - ry), color);

    // Fill top and bottom with rounded corners
    for dy in 0..ry {
        let y2 = (dy * dy) as i64;
        let x_max_sq = rx2 - (y2 * rx2) / ry2;
        let x_offset = isqrt(x_max_sq as u64) as i32;

        // Top edge
        let y_top = top + ry - dy - 1;
        surf.hline(left + rx - x_offset, right - rx + x_offset, y_top, color);

        // Bottom edge
        let y_bottom = bottom - ry + dy;
        surf.hline(left + rx - x_offset, right - rx + x_offset, y_bottom, color);
    }
}

/// Draw rounded rectangle outline
fn draw_round_rect_outline(
    surf: &surface::Surface,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    rx: i32,
    ry: i32,
    color: ColorRef,
) {
    if rx <= 0 || ry <= 0 {
        // No rounding, just draw rectangle outline
        surf.hline(left, right, top, color);
        surf.hline(left, right, bottom - 1, color);
        surf.vline(left, top, bottom, color);
        surf.vline(right - 1, top, bottom, color);
        return;
    }

    // Draw the straight edges
    // Top edge
    surf.hline(left + rx, right - rx, top, color);
    // Bottom edge
    surf.hline(left + rx, right - rx, bottom - 1, color);
    // Left edge
    surf.vline(left, top + ry, bottom - ry, color);
    // Right edge
    surf.vline(right - 1, top + ry, bottom - ry, color);

    // Draw the corner arcs
    // Corner centers
    let tl_cx = left + rx;
    let tl_cy = top + ry;
    let tr_cx = right - rx - 1;
    let tr_cy = top + ry;
    let bl_cx = left + rx;
    let bl_cy = bottom - ry - 1;
    let br_cx = right - rx - 1;
    let br_cy = bottom - ry - 1;

    draw_corner_arc(surf, tl_cx, tl_cy, rx, ry, 2, color); // Top-left (quadrant 2)
    draw_corner_arc(surf, tr_cx, tr_cy, rx, ry, 1, color); // Top-right (quadrant 1)
    draw_corner_arc(surf, bl_cx, bl_cy, rx, ry, 3, color); // Bottom-left (quadrant 3)
    draw_corner_arc(surf, br_cx, br_cy, rx, ry, 4, color); // Bottom-right (quadrant 4)
}

/// Draw a quarter ellipse arc for a corner
/// quadrant: 1=top-right, 2=top-left, 3=bottom-left, 4=bottom-right
fn draw_corner_arc(
    surf: &surface::Surface,
    cx: i32,
    cy: i32,
    rx: i32,
    ry: i32,
    quadrant: u8,
    color: ColorRef,
) {
    if rx <= 0 || ry <= 0 {
        return;
    }

    let mut x = 0i32;
    let mut y = ry;

    let rx2 = (rx * rx) as i64;
    let ry2 = (ry * ry) as i64;

    let mut dx = 2 * ry2 * x as i64;
    let mut dy = 2 * rx2 * y as i64;

    let mut d1 = ry2 - rx2 * ry as i64 + rx2 / 4;

    while dx < dy {
        draw_quadrant_pixel(surf, cx, cy, x, y, quadrant, color);

        if d1 < 0 {
            x += 1;
            dx += 2 * ry2;
            d1 += dx + ry2;
        } else {
            x += 1;
            y -= 1;
            dx += 2 * ry2;
            dy -= 2 * rx2;
            d1 += dx - dy + ry2;
        }
    }

    let mut d2 = ry2 * ((2 * x + 1) * (2 * x + 1)) as i64 / 4
        + rx2 * (y - 1) as i64 * (y - 1) as i64
        - rx2 * ry2;

    while y >= 0 {
        draw_quadrant_pixel(surf, cx, cy, x, y, quadrant, color);

        if d2 > 0 {
            y -= 1;
            dy -= 2 * rx2;
            d2 += rx2 - dy;
        } else {
            y -= 1;
            x += 1;
            dx += 2 * ry2;
            dy -= 2 * rx2;
            d2 += dx - dy + rx2;
        }
    }
}

/// Draw pixel in specific quadrant relative to center
fn draw_quadrant_pixel(surf: &surface::Surface, cx: i32, cy: i32, x: i32, y: i32, quadrant: u8, color: ColorRef) {
    let (px, py) = match quadrant {
        1 => (cx + x, cy - y),      // Top-right
        2 => (cx - x, cy - y),      // Top-left
        3 => (cx - x, cy + y),      // Bottom-left
        4 => (cx + x, cy + y),      // Bottom-right
        _ => return,
    };
    surf.set_pixel(px, py, color);
}

// ============================================================================
// Polygon Drawing
// ============================================================================

/// Draw a polygon
pub fn gdi_polygon(hdc: GdiHandle, points: &[Point]) -> bool {
    if points.len() < 3 {
        return false;
    }

    let dc_data = match dc::get_dc(hdc) {
        Some(d) => d,
        None => return false,
    };

    let surface_handle = dc_data.surface;
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return false,
    };

    // Transform all points
    let transformed: [Point; 64] = {
        let mut arr = [Point::new(0, 0); 64];
        let count = points.len().min(64);
        for (i, pt) in points.iter().take(count).enumerate() {
            arr[i] = dc::lp_to_dp(hdc, *pt);
        }
        arr
    };
    let count = points.len().min(64);

    // Get brush for fill
    let brush_data = brush::get_brush(dc_data.brush);
    let fill_color = brush_data.map(|b| b.color);
    let is_null_brush = brush_data.map(|b| b.style == brush::BrushStyle::Null).unwrap_or(true);

    // Get pen for outline
    let pen_data = pen::get_pen(dc_data.pen);
    let outline_color = pen_data.map(|p| p.color).unwrap_or(ColorRef::BLACK);
    let pen_width = pen_data.map(|p| p.width).unwrap_or(1);
    let is_null_pen = pen_data.map(|p| p.style == pen::PenStyle::Null).unwrap_or(false);

    // Fill the polygon using scanline fill
    if !is_null_brush {
        if let Some(color) = fill_color {
            fill_polygon(&surf, &transformed[..count], color);
        }
    }

    // Draw the outline
    if !is_null_pen {
        for i in 0..count {
            let p1 = transformed[i];
            let p2 = transformed[(i + 1) % count];
            draw_line(&surf, p1.x, p1.y, p2.x, p2.y, outline_color, pen_width);
        }
    }

    true
}

/// Fill polygon using scanline algorithm
fn fill_polygon(surf: &surface::Surface, points: &[Point], color: ColorRef) {
    if points.len() < 3 {
        return;
    }

    // Find bounding box
    let mut min_y = points[0].y;
    let mut max_y = points[0].y;
    for pt in points {
        min_y = min_y.min(pt.y);
        max_y = max_y.max(pt.y);
    }

    // Scanline fill
    for y in min_y..=max_y {
        // Find intersections with edges
        let mut intersections: [i32; 64] = [0; 64];
        let mut num_intersections = 0;

        for i in 0..points.len() {
            let p1 = points[i];
            let p2 = points[(i + 1) % points.len()];

            // Check if edge crosses this scanline
            if (p1.y <= y && p2.y > y) || (p2.y <= y && p1.y > y) {
                // Calculate x intersection
                let dy = p2.y - p1.y;
                if dy != 0 {
                    let x = p1.x + ((y - p1.y) as i64 * (p2.x - p1.x) as i64 / dy as i64) as i32;
                    if num_intersections < 64 {
                        intersections[num_intersections] = x;
                        num_intersections += 1;
                    }
                }
            }
        }

        // Sort intersections
        for i in 0..num_intersections {
            for j in (i + 1)..num_intersections {
                if intersections[j] < intersections[i] {
                    intersections.swap(i, j);
                }
            }
        }

        // Fill between pairs of intersections
        let mut i = 0;
        while i + 1 < num_intersections {
            surf.hline(intersections[i], intersections[i + 1] + 1, y, color);
            i += 2;
        }
    }
}

/// Draw a polyline (unfilled)
pub fn gdi_polyline(hdc: GdiHandle, points: &[Point]) -> bool {
    if points.len() < 2 {
        return false;
    }

    let dc_data = match dc::get_dc(hdc) {
        Some(d) => d,
        None => return false,
    };

    let surface_handle = dc_data.surface;
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return false,
    };

    // Get pen
    let pen_data = pen::get_pen(dc_data.pen);
    let color = pen_data.map(|p| p.color).unwrap_or(ColorRef::BLACK);
    let width = pen_data.map(|p| p.width).unwrap_or(1);

    if pen_data.map(|p| p.style == pen::PenStyle::Null).unwrap_or(false) {
        return true;
    }

    // Draw connected lines
    for i in 0..(points.len() - 1) {
        let p1 = dc::lp_to_dp(hdc, points[i]);
        let p2 = dc::lp_to_dp(hdc, points[i + 1]);
        draw_line(&surf, p1.x, p1.y, p2.x, p2.y, color, width);
    }

    true
}

// ============================================================================
// Arc Drawing
// ============================================================================

/// Draw an arc (portion of ellipse outline)
pub fn gdi_arc(
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
    let dc_data = match dc::get_dc(hdc) {
        Some(d) => d,
        None => return false,
    };

    let surface_handle = dc_data.surface;
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return false,
    };

    // Transform coordinates
    let p1 = dc::lp_to_dp(hdc, Point::new(left, top));
    let p2 = dc::lp_to_dp(hdc, Point::new(right, bottom));
    let start = dc::lp_to_dp(hdc, Point::new(x_start, y_start));
    let end = dc::lp_to_dp(hdc, Point::new(x_end, y_end));

    let cx = (p1.x + p2.x) / 2;
    let cy = (p1.y + p2.y) / 2;
    let rx = (p2.x - p1.x).abs() / 2;
    let ry = (p2.y - p1.y).abs() / 2;

    // Get pen
    let pen_data = pen::get_pen(dc_data.pen);
    let color = pen_data.map(|p| p.color).unwrap_or(ColorRef::BLACK);

    if pen_data.map(|p| p.style == pen::PenStyle::Null).unwrap_or(false) {
        return true;
    }

    // Calculate start and end angles from points
    let start_angle = atan2_approx(start.y - cy, start.x - cx);
    let end_angle = atan2_approx(end.y - cy, end.x - cx);

    draw_arc_outline(&surf, cx, cy, rx, ry, start_angle, end_angle, color);

    true
}

/// Approximate atan2 returning angle in fixed point (0-1024 = 0-360 degrees)
fn atan2_approx(y: i32, x: i32) -> i32 {
    if x == 0 && y == 0 {
        return 0;
    }

    // Use octant-based approximation
    let ax = x.abs();
    let ay = y.abs();

    // Base angle in first octant (0-128 for 0-45 degrees)
    let angle = if ax >= ay {
        if ax == 0 { 0 } else { (ay * 128 / ax) }
    } else {
        256 - (ax * 128 / ay)
    };

    // Adjust for quadrant
    match (x >= 0, y >= 0) {
        (true, false) => angle,          // Quadrant 1 (0-256)
        (false, false) => 512 - angle,   // Quadrant 2 (256-512)
        (false, true) => 512 + angle,    // Quadrant 3 (512-768)
        (true, true) => 1024 - angle,    // Quadrant 4 (768-1024)
    }
}

/// Draw arc outline between two angles
fn draw_arc_outline(
    surf: &surface::Surface,
    cx: i32,
    cy: i32,
    rx: i32,
    ry: i32,
    start_angle: i32,
    end_angle: i32,
    color: ColorRef,
) {
    if rx <= 0 || ry <= 0 {
        return;
    }

    // Normalize angles to 0-1024 range
    let start = ((start_angle % 1024) + 1024) % 1024;
    let end = ((end_angle % 1024) + 1024) % 1024;

    // Use parametric ellipse, drawing points in angular range
    // Step through angles from start to end
    let steps = rx.max(ry) * 4; // More points for larger ellipses

    for i in 0..=steps {
        let angle = if start <= end {
            start + (end - start) * i / steps
        } else {
            // Wrap around
            let total = (1024 - start) + end;
            let a = start + total * i / steps;
            a % 1024
        };

        // Convert angle to approximate x, y on ellipse
        let (sin_a, cos_a) = sin_cos_approx(angle);
        let x = cx + (rx as i64 * cos_a as i64 / 1024) as i32;
        let y = cy - (ry as i64 * sin_a as i64 / 1024) as i32;

        surf.set_pixel(x, y, color);
    }
}

/// Approximate sin and cos for angle in 0-1024 range
/// Returns values scaled by 1024
fn sin_cos_approx(angle: i32) -> (i32, i32) {
    // Normalize to 0-1024
    let a = ((angle % 1024) + 1024) % 1024;

    // Use lookup or approximation for sin/cos
    // Simple quadrant-based approximation using linear interpolation

    let quadrant = a / 256;
    let offset = a % 256;

    // Simple parabolic approximation per quadrant
    let (sin_val, cos_val) = match quadrant {
        0 => {
            // 0-90 degrees: sin increases 0->1024, cos decreases 1024->0
            let sin = offset * 4;
            let cos = 1024 - offset * 4;
            (sin, cos)
        }
        1 => {
            // 90-180 degrees: sin decreases 1024->0, cos decreases 0->-1024
            let sin = 1024 - offset * 4;
            let cos = -(offset * 4);
            (sin, cos)
        }
        2 => {
            // 180-270 degrees: sin decreases 0->-1024, cos increases -1024->0
            let sin = -(offset * 4);
            let cos = -1024 + offset * 4;
            (sin, cos)
        }
        3 => {
            // 270-360 degrees: sin increases -1024->0, cos increases 0->1024
            let sin = -1024 + offset * 4;
            let cos = offset * 4;
            (sin, cos)
        }
        _ => (0, 1024),
    };

    (sin_val, cos_val)
}

/// Draw a pie (filled arc section with lines to center)
pub fn gdi_pie(
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
    let dc_data = match dc::get_dc(hdc) {
        Some(d) => d,
        None => return false,
    };

    let surface_handle = dc_data.surface;
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return false,
    };

    // Transform coordinates
    let p1 = dc::lp_to_dp(hdc, Point::new(left, top));
    let p2 = dc::lp_to_dp(hdc, Point::new(right, bottom));
    let start = dc::lp_to_dp(hdc, Point::new(x_start, y_start));
    let end = dc::lp_to_dp(hdc, Point::new(x_end, y_end));

    let cx = (p1.x + p2.x) / 2;
    let cy = (p1.y + p2.y) / 2;
    let rx = (p2.x - p1.x).abs() / 2;
    let ry = (p2.y - p1.y).abs() / 2;

    // Get brush for fill
    let brush_data = brush::get_brush(dc_data.brush);
    let fill_color = brush_data.map(|b| b.color);
    let is_null_brush = brush_data.map(|b| b.style == brush::BrushStyle::Null).unwrap_or(true);

    // Get pen for outline
    let pen_data = pen::get_pen(dc_data.pen);
    let outline_color = pen_data.map(|p| p.color).unwrap_or(ColorRef::BLACK);
    let pen_width = pen_data.map(|p| p.width).unwrap_or(1);
    let is_null_pen = pen_data.map(|p| p.style == pen::PenStyle::Null).unwrap_or(false);

    let start_angle = atan2_approx(start.y - cy, start.x - cx);
    let end_angle = atan2_approx(end.y - cy, end.x - cx);

    // Fill the pie
    if !is_null_brush {
        if let Some(color) = fill_color {
            fill_pie(&surf, cx, cy, rx, ry, start_angle, end_angle, color);
        }
    }

    // Draw outline
    if !is_null_pen {
        // Draw arc
        draw_arc_outline(&surf, cx, cy, rx, ry, start_angle, end_angle, outline_color);

        // Draw lines from center to arc endpoints
        let (sin_s, cos_s) = sin_cos_approx(start_angle);
        let x1 = cx + (rx as i64 * cos_s as i64 / 1024) as i32;
        let y1 = cy - (ry as i64 * sin_s as i64 / 1024) as i32;

        let (sin_e, cos_e) = sin_cos_approx(end_angle);
        let x2 = cx + (rx as i64 * cos_e as i64 / 1024) as i32;
        let y2 = cy - (ry as i64 * sin_e as i64 / 1024) as i32;

        draw_line(&surf, cx, cy, x1, y1, outline_color, pen_width);
        draw_line(&surf, cx, cy, x2, y2, outline_color, pen_width);
    }

    true
}

/// Fill a pie shape using scanline fill
fn fill_pie(
    surf: &surface::Surface,
    cx: i32,
    cy: i32,
    rx: i32,
    ry: i32,
    start_angle: i32,
    end_angle: i32,
    color: ColorRef,
) {
    if rx <= 0 || ry <= 0 {
        return;
    }

    // Simple approach: for each scanline in the bounding box,
    // check if points are both inside ellipse and within angle range

    for dy in -ry..=ry {
        let y = cy + dy;
        let y2 = (dy * dy) as i64;
        let rx2 = (rx * rx) as i64;
        let ry2 = (ry * ry) as i64;

        // Calculate x range on ellipse at this y
        let x_max_sq = rx2 - (y2 * rx2) / ry2;
        if x_max_sq < 0 {
            continue;
        }
        let x_max = isqrt(x_max_sq as u64) as i32;

        for dx in -x_max..=x_max {
            let x = cx + dx;

            // Check if this point is within the angle range
            let point_angle = atan2_approx(-(y - cy), x - cx);

            if angle_in_range(point_angle, start_angle, end_angle) {
                surf.set_pixel(x, y, color);
            }
        }
    }
}

/// Check if angle is in the range from start to end (counterclockwise)
fn angle_in_range(angle: i32, start: i32, end: i32) -> bool {
    let a = ((angle % 1024) + 1024) % 1024;
    let s = ((start % 1024) + 1024) % 1024;
    let e = ((end % 1024) + 1024) % 1024;

    if s <= e {
        a >= s && a <= e
    } else {
        // Wraps around
        a >= s || a <= e
    }
}

/// Draw a chord (arc with straight line connecting endpoints)
pub fn gdi_chord(
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
    let dc_data = match dc::get_dc(hdc) {
        Some(d) => d,
        None => return false,
    };

    let surface_handle = dc_data.surface;
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return false,
    };

    // Transform coordinates
    let p1 = dc::lp_to_dp(hdc, Point::new(left, top));
    let p2 = dc::lp_to_dp(hdc, Point::new(right, bottom));
    let start = dc::lp_to_dp(hdc, Point::new(x_start, y_start));
    let end = dc::lp_to_dp(hdc, Point::new(x_end, y_end));

    let cx = (p1.x + p2.x) / 2;
    let cy = (p1.y + p2.y) / 2;
    let rx = (p2.x - p1.x).abs() / 2;
    let ry = (p2.y - p1.y).abs() / 2;

    // Get pen for outline
    let pen_data = pen::get_pen(dc_data.pen);
    let outline_color = pen_data.map(|p| p.color).unwrap_or(ColorRef::BLACK);
    let pen_width = pen_data.map(|p| p.width).unwrap_or(1);
    let is_null_pen = pen_data.map(|p| p.style == pen::PenStyle::Null).unwrap_or(false);

    let start_angle = atan2_approx(start.y - cy, start.x - cx);
    let end_angle = atan2_approx(end.y - cy, end.x - cx);

    // Draw outline
    if !is_null_pen {
        // Draw arc
        draw_arc_outline(&surf, cx, cy, rx, ry, start_angle, end_angle, outline_color);

        // Draw chord line connecting endpoints
        let (sin_s, cos_s) = sin_cos_approx(start_angle);
        let x1 = cx + (rx as i64 * cos_s as i64 / 1024) as i32;
        let y1 = cy - (ry as i64 * sin_s as i64 / 1024) as i32;

        let (sin_e, cos_e) = sin_cos_approx(end_angle);
        let x2 = cx + (rx as i64 * cos_e as i64 / 1024) as i32;
        let y2 = cy - (ry as i64 * sin_e as i64 / 1024) as i32;

        draw_line(&surf, x1, y1, x2, y2, outline_color, pen_width);
    }

    true
}

// ============================================================================
// 3D Border Drawing (for controls)
// ============================================================================

/// Draw a 3D raised edge
pub fn draw_edge_raised(hdc: GdiHandle, rect: &Rect) -> bool {
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return false,
    };

    let p1 = dc::lp_to_dp(hdc, Point::new(rect.left, rect.top));
    let p2 = dc::lp_to_dp(hdc, Point::new(rect.right, rect.bottom));

    // Outer highlight (white)
    surf.hline(p1.x, p2.x, p1.y, ColorRef::WHITE);
    surf.vline(p1.x, p1.y, p2.y, ColorRef::WHITE);

    // Inner highlight (light gray)
    surf.hline(p1.x + 1, p2.x - 1, p1.y + 1, ColorRef::LIGHT_GRAY);
    surf.vline(p1.x + 1, p1.y + 1, p2.y - 1, ColorRef::LIGHT_GRAY);

    // Outer shadow (dark gray)
    surf.hline(p1.x, p2.x, p2.y - 1, ColorRef::DARK_GRAY);
    surf.vline(p2.x - 1, p1.y, p2.y, ColorRef::DARK_GRAY);

    // Inner shadow (gray)
    surf.hline(p1.x + 1, p2.x - 1, p2.y - 2, ColorRef::GRAY);
    surf.vline(p2.x - 2, p1.y + 1, p2.y - 1, ColorRef::GRAY);

    true
}

/// Draw a 3D sunken edge
pub fn draw_edge_sunken(hdc: GdiHandle, rect: &Rect) -> bool {
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return false,
    };

    let p1 = dc::lp_to_dp(hdc, Point::new(rect.left, rect.top));
    let p2 = dc::lp_to_dp(hdc, Point::new(rect.right, rect.bottom));

    // Outer shadow (dark gray)
    surf.hline(p1.x, p2.x, p1.y, ColorRef::DARK_GRAY);
    surf.vline(p1.x, p1.y, p2.y, ColorRef::DARK_GRAY);

    // Inner shadow (gray)
    surf.hline(p1.x + 1, p2.x - 1, p1.y + 1, ColorRef::GRAY);
    surf.vline(p1.x + 1, p1.y + 1, p2.y - 1, ColorRef::GRAY);

    // Outer highlight (white)
    surf.hline(p1.x, p2.x, p2.y - 1, ColorRef::WHITE);
    surf.vline(p2.x - 1, p1.y, p2.y, ColorRef::WHITE);

    // Inner highlight (light gray)
    surf.hline(p1.x + 1, p2.x - 1, p2.y - 2, ColorRef::LIGHT_GRAY);
    surf.vline(p2.x - 2, p1.y + 1, p2.y - 1, ColorRef::LIGHT_GRAY);

    true
}
