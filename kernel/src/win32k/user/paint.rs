//! Window Painting
//!
//! Handles WM_PAINT processing, window DC management, and
//! non-client area painting (title bars, borders, etc.)
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/paint.c`
//! - `windows/core/ntuser/kernel/drawfrm.c`

use super::super::{HDC, HWND, Rect, Point, ColorRef};
use super::super::gdi::{dc, surface};
use super::window::{self, FrameMetrics};
use super::message;

// ============================================================================
// Paint Structures
// ============================================================================

/// Paint structure (returned by BeginPaint)
#[derive(Debug, Clone, Copy, Default)]
pub struct PaintStruct {
    /// Device context handle
    pub hdc: HDC,

    /// Erase background flag
    pub erase: bool,

    /// Paint rectangle
    pub paint_rect: Rect,

    /// Reserved fields
    pub restore: bool,
    pub inc_update: bool,
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize paint system
pub fn init() {
    crate::serial_println!("[USER/Paint] Paint system initialized");
}

// ============================================================================
// Paint Operations
// ============================================================================

/// Begin painting a window
pub fn begin_paint(hwnd: HWND) -> Option<(dc::DeviceContext, PaintStruct)> {
    let wnd = window::get_window(hwnd)?;

    // Create DC for the window
    let hdc = match dc::create_display_dc() {
        Ok(h) => h,
        Err(_) => return None,
    };

    // Set up clipping to window client area
    let client_origin = window::client_to_screen(hwnd, Point::new(0, 0));

    // Get the DC
    let dc_obj = dc::get_dc(hdc)?;

    // Set viewport origin to client area
    dc::set_viewport_org(hdc, client_origin.x, client_origin.y);

    // Get paint rectangle (invalid region or whole client)
    let paint_rect = wnd.invalid_rect.unwrap_or(wnd.client_rect);

    let ps = PaintStruct {
        hdc,
        erase: true,
        paint_rect,
        restore: false,
        inc_update: false,
    };

    // Clear needs_paint flag
    window::with_window_mut(hwnd, |w| {
        w.needs_paint = false;
        w.invalid_rect = None;
    });

    Some((dc_obj, ps))
}

/// End painting a window
pub fn end_paint(_hwnd: HWND, ps: &PaintStruct) {
    // Delete the DC
    dc::delete_dc(ps.hdc);
}

/// Get window DC (not limited to client area)
pub fn get_window_dc(hwnd: HWND) -> HDC {
    match dc::create_display_dc() {
        Ok(hdc) => {
            // Set viewport to window origin
            if let Some(wnd) = window::get_window(hwnd) {
                dc::set_viewport_org(hdc, wnd.rect.left, wnd.rect.top);
            }
            hdc
        }
        Err(_) => HDC::NULL,
    }
}

/// Release window DC
pub fn release_dc(_hwnd: HWND, hdc: HDC) -> bool {
    dc::delete_dc(hdc)
}

/// Update window (process pending WM_PAINT)
pub fn update_window(hwnd: HWND) -> bool {
    if let Some(wnd) = window::get_window(hwnd) {
        if wnd.needs_paint && wnd.visible {
            // Send WM_PAINT directly
            message::send_message(hwnd, message::WM_PAINT, 0, 0);
            return true;
        }
    }
    false
}

/// Invalidate a rectangle of a window
pub fn invalidate_rect(hwnd: HWND, rect: Option<&Rect>, erase: bool) -> bool {
    window::with_window_mut(hwnd, |wnd| {
        wnd.needs_paint = true;

        // Merge invalid region
        if let Some(r) = rect {
            if let Some(ref mut existing) = wnd.invalid_rect {
                *existing = existing.union(r);
            } else {
                wnd.invalid_rect = Some(*r);
            }
        } else {
            // Invalidate entire client area
            wnd.invalid_rect = Some(wnd.client_rect);
        }

        if erase {
            // Post WM_ERASEBKGND
            message::post_message(hwnd, message::WM_ERASEBKGND, 0, 0);
        }

        // Post WM_PAINT
        message::post_message(hwnd, message::WM_PAINT, 0, 0);
    }).is_some()
}

/// Validate a rectangle (remove from invalid region)
pub fn validate_rect(hwnd: HWND, rect: Option<&Rect>) -> bool {
    window::with_window_mut(hwnd, |wnd| {
        if rect.is_none() {
            // Validate entire window
            wnd.invalid_rect = None;
            wnd.needs_paint = false;
        }
        // TODO: proper region subtraction for partial validation
    }).is_some()
}

// ============================================================================
// Non-Client Painting
// ============================================================================

/// Draw window non-client area (frame, title bar, etc.)
pub fn draw_window_frame(hwnd: HWND) {
    let wnd = match window::get_window(hwnd) {
        Some(w) => w,
        None => return,
    };

    // Get DC for entire window
    let hdc = match dc::create_display_dc() {
        Ok(h) => h,
        Err(_) => return,
    };

    // Set viewport to window origin
    dc::set_viewport_org(hdc, wnd.rect.left, wnd.rect.top);

    let metrics = wnd.get_frame_metrics();

    // Draw based on window style
    if wnd.has_border() {
        draw_border(hdc, &wnd.rect, &metrics);
    }

    if wnd.has_caption() {
        draw_caption(hdc, &wnd, &metrics);
    }

    // Fill client area with window background color
    draw_client_background(hdc, &wnd, &metrics);

    // Draw window content based on class
    draw_window_content(hdc, &wnd, &metrics);

    // Clean up
    dc::delete_dc(hdc);
}

/// Draw window client area background
fn draw_client_background(hdc: HDC, wnd: &window::Window, metrics: &FrameMetrics) {
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let offset = dc::get_dc(hdc)
        .map(|d| d.viewport_org)
        .unwrap_or(Point::new(0, 0));

    // Calculate client area (inside frame and caption)
    let border = metrics.border_width;
    let caption = if wnd.has_caption() { metrics.caption_height } else { 0 };

    let client_rect = Rect::new(
        offset.x + border,
        offset.y + border + caption,
        offset.x + wnd.rect.width() - border,
        offset.y + wnd.rect.height() - border,
    );

    // Fill with window background color (white for standard windows)
    surf.fill_rect(&client_rect, ColorRef::WHITE);
}

/// Draw window content based on window class
fn draw_window_content(hdc: HDC, wnd: &window::Window, metrics: &FrameMetrics) {
    let class_name = wnd.class_name_str();

    // Only draw content for explorer-style windows
    if class_name != "CabinetWClass" {
        return;
    }

    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let offset = dc::get_dc(hdc)
        .map(|d| d.viewport_org)
        .unwrap_or(Point::new(0, 0));

    let border = metrics.border_width;
    let caption = if wnd.has_caption() { metrics.caption_height } else { 0 };

    // Client area coordinates
    let client_x = offset.x + border;
    let client_y = offset.y + border + caption;
    let client_w = wnd.rect.width() - border * 2;
    let client_h = wnd.rect.height() - border * 2 - caption;

    // Draw toolbar area (gray bar at top of client area)
    let toolbar_height = 26;
    let toolbar_rect = Rect::new(
        client_x,
        client_y,
        client_x + client_w,
        client_y + toolbar_height,
    );
    surf.fill_rect(&toolbar_rect, ColorRef::BUTTON_FACE);
    // Toolbar bottom edge
    surf.hline(client_x, client_x + client_w, client_y + toolbar_height - 1, ColorRef::BUTTON_SHADOW);

    // Draw address bar area
    let addr_y = client_y + toolbar_height;
    let addr_height = 22;
    let addr_rect = Rect::new(
        client_x,
        addr_y,
        client_x + client_w,
        addr_y + addr_height,
    );
    surf.fill_rect(&addr_rect, ColorRef::BUTTON_FACE);

    // Address label
    dc::set_text_color(hdc, ColorRef::BLACK);
    dc::set_bk_mode(hdc, dc::BkMode::Transparent);
    super::super::gdi::text_out(hdc, client_x + 4, addr_y + 4, "Address:");

    // Address bar (white sunken box)
    let addr_box = Rect::new(
        client_x + 55,
        addr_y + 2,
        client_x + client_w - 4,
        addr_y + addr_height - 2,
    );
    surf.fill_rect(&addr_box, ColorRef::WHITE);
    // Sunken edge
    surf.hline(addr_box.left, addr_box.right, addr_box.top, ColorRef::BUTTON_SHADOW);
    surf.vline(addr_box.left, addr_box.top, addr_box.bottom, ColorRef::BUTTON_SHADOW);
    surf.hline(addr_box.left, addr_box.right, addr_box.bottom - 1, ColorRef::BUTTON_HIGHLIGHT);
    surf.vline(addr_box.right - 1, addr_box.top, addr_box.bottom, ColorRef::BUTTON_HIGHLIGHT);

    // Draw window title in address bar
    let title = wnd.title_str();
    super::super::gdi::text_out(hdc, addr_box.left + 4, addr_y + 4, title);

    // Address bar bottom edge
    surf.hline(client_x, client_x + client_w, addr_y + addr_height - 1, ColorRef::BUTTON_SHADOW);

    // Content area starts below address bar
    let content_y = addr_y + addr_height;
    let content_h = client_h - toolbar_height - addr_height;

    if content_h > 20 {
        // Draw some placeholder folder icons
        let icon_size = 32;
        let icon_spacing = 80;
        let start_x = client_x + 20;
        let start_y = content_y + 20;

        // Draw a few folder placeholders
        let folders = ["Documents", "Pictures", "Music", "Downloads"];
        for (i, folder_name) in folders.iter().enumerate() {
            let ix = start_x + (i as i32 % 4) * icon_spacing;
            let iy = start_y + (i as i32 / 4) * (icon_size + 40);

            if ix + icon_size < client_x + client_w && iy + icon_size + 16 < client_y + client_h {
                // Draw folder icon (simple yellow folder shape)
                draw_folder_icon(&surf, ix, iy);

                // Draw folder name below icon
                let text_x = ix - 5;
                let text_y = iy + icon_size + 2;
                super::super::gdi::text_out(hdc, text_x, text_y, folder_name);
            }
        }
    }
}

/// Draw a simple folder icon
fn draw_folder_icon(surf: &surface::Surface, x: i32, y: i32) {
    // Folder colors
    let folder_dark = ColorRef::rgb(180, 160, 80);
    let folder_light = ColorRef::rgb(255, 220, 100);
    let folder_tab = ColorRef::rgb(200, 180, 90);

    // Draw folder tab (top part)
    for dy in 0..4 {
        surf.hline(x + 2, x + 14, y + dy, folder_tab);
    }

    // Draw folder body
    for dy in 4..28 {
        surf.hline(x, x + 30, y + dy, folder_light);
    }

    // Draw folder edges (3D effect)
    surf.hline(x, x + 30, y + 4, folder_dark);
    surf.vline(x, y + 4, y + 28, folder_dark);
    surf.hline(x, x + 30, y + 27, folder_dark);
    surf.vline(x + 29, y + 4, y + 28, folder_dark);
}

/// Draw window border
fn draw_border(hdc: HDC, rect: &Rect, metrics: &FrameMetrics) {
    let width = rect.width();
    let height = rect.height();

    // Get surface for direct drawing
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    // Get DC viewport offset
    let offset = dc::get_dc(hdc)
        .map(|d| d.viewport_org)
        .unwrap_or(Point::new(0, 0));

    // Draw 3D border effect
    let border_width = metrics.border_width;

    // Outer highlight (white/light)
    for i in 0..border_width.min(2) {
        // Top
        surf.hline(offset.x + i, offset.x + width - i, offset.y + i, ColorRef::BUTTON_HIGHLIGHT);
        // Left
        surf.vline(offset.x + i, offset.y + i, offset.y + height - i, ColorRef::BUTTON_HIGHLIGHT);
    }

    // Outer shadow (dark gray)
    for i in 0..border_width.min(2) {
        // Bottom
        surf.hline(
            offset.x + i,
            offset.x + width - i,
            offset.y + height - 1 - i,
            ColorRef::BUTTON_SHADOW,
        );
        // Right
        surf.vline(
            offset.x + width - 1 - i,
            offset.y + i,
            offset.y + height - i,
            ColorRef::BUTTON_SHADOW,
        );
    }
}

/// Draw window caption (title bar)
fn draw_caption(hdc: HDC, wnd: &window::Window, metrics: &FrameMetrics) {
    let width = wnd.rect.width();
    let border = metrics.border_width;
    let caption_height = metrics.caption_height;

    // Get surface
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let offset = dc::get_dc(hdc)
        .map(|d| d.viewport_org)
        .unwrap_or(Point::new(0, 0));

    // Caption rectangle
    let caption_rect = Rect::new(
        offset.x + border,
        offset.y + border,
        offset.x + width - border,
        offset.y + border + caption_height,
    );

    // Check if this window is active
    let is_active = super::input::get_active_window() == wnd.hwnd;

    // Draw caption background - blue for active, gray for inactive
    let caption_color = if is_active {
        ColorRef::ACTIVE_CAPTION  // Blue (#0A246A for classic, or #0054E3)
    } else {
        ColorRef::INACTIVE_CAPTION  // Gray (#808080)
    };
    surf.fill_rect(&caption_rect, caption_color);

    // Draw caption text
    let text_x = caption_rect.left + 4;
    let text_y = caption_rect.top + 2;

    // Set text color - white for active, light gray for inactive
    let text_color = if is_active {
        ColorRef::WHITE
    } else {
        ColorRef::INACTIVE_CAPTION_TEXT
    };
    dc::set_text_color(hdc, text_color);
    dc::set_bk_mode(hdc, dc::BkMode::Transparent);

    // Draw the title
    super::super::gdi::draw::gdi_text_out(hdc, text_x, text_y, wnd.title_str());

    // Draw caption buttons
    if metrics.has_sys_menu || metrics.has_min_box || metrics.has_max_box {
        draw_caption_buttons(hdc, &caption_rect, metrics, wnd.maximized);
    }
}

/// Draw caption buttons (minimize, maximize, close)
fn draw_caption_buttons(hdc: HDC, caption_rect: &Rect, metrics: &FrameMetrics, is_maximized: bool) {
    let button_width = 16;
    let button_height = 14;
    let button_y = caption_rect.top + (caption_rect.height() - button_height) / 2;
    let mut button_x = caption_rect.right - button_width - 2;

    // Get surface for drawing
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    // Close button (always present with system menu)
    if metrics.has_sys_menu {
        let btn_rect = Rect::new(button_x, button_y, button_x + button_width, button_y + button_height);
        draw_caption_button(&surf, &btn_rect, CaptionButton::Close);
        button_x -= button_width + 2;
    }

    // Maximize/Restore button
    if metrics.has_max_box {
        let btn_rect = Rect::new(button_x, button_y, button_x + button_width, button_y + button_height);
        if is_maximized {
            draw_caption_button(&surf, &btn_rect, CaptionButton::Restore);
        } else {
            draw_caption_button(&surf, &btn_rect, CaptionButton::Maximize);
        }
        button_x -= button_width;
    }

    // Minimize button
    if metrics.has_min_box {
        let btn_rect = Rect::new(button_x, button_y, button_x + button_width, button_y + button_height);
        draw_caption_button(&surf, &btn_rect, CaptionButton::Minimize);
    }
}

/// Caption button type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptionButton {
    Close,
    Maximize,
    Restore,
    Minimize,
}

/// Draw a caption button with 3D effect and glyph
fn draw_caption_button(surf: &surface::Surface, rect: &Rect, button: CaptionButton) {
    // Draw button face (raised 3D)
    surf.fill_rect(rect, ColorRef::BUTTON_FACE);

    // Top and left highlight (light)
    surf.hline(rect.left, rect.right - 1, rect.top, ColorRef::BUTTON_HIGHLIGHT);
    surf.vline(rect.left, rect.top, rect.bottom - 1, ColorRef::BUTTON_HIGHLIGHT);

    // Bottom and right shadow (dark)
    surf.hline(rect.left, rect.right, rect.bottom - 1, ColorRef::BUTTON_SHADOW);
    surf.vline(rect.right - 1, rect.top, rect.bottom, ColorRef::BUTTON_SHADOW);

    // Draw glyph in center
    let cx = rect.left + rect.width() / 2;
    let cy = rect.top + rect.height() / 2;
    let glyph_color = ColorRef::BLACK;

    match button {
        CaptionButton::Close => {
            // Draw X glyph (5x5)
            for i in 0..5 {
                surf.set_pixel(cx - 2 + i, cy - 2 + i, glyph_color);
                surf.set_pixel(cx + 2 - i, cy - 2 + i, glyph_color);
            }
        }
        CaptionButton::Maximize => {
            // Draw maximize box (6x6 outline)
            let bx = cx - 3;
            let by = cy - 3;
            surf.hline(bx, bx + 6, by, glyph_color);
            surf.hline(bx, bx + 6, by + 1, glyph_color); // Thick top
            surf.hline(bx, bx + 6, by + 5, glyph_color);
            surf.vline(bx, by, by + 6, glyph_color);
            surf.vline(bx + 5, by, by + 6, glyph_color);
        }
        CaptionButton::Restore => {
            // Draw restore icon (two overlapping boxes)
            let bx = cx - 3;
            let by = cy - 3;
            // Back box (smaller, offset up-right)
            surf.hline(bx + 2, bx + 6, by, glyph_color);
            surf.hline(bx + 2, bx + 6, by + 1, glyph_color); // Thick top
            surf.vline(bx + 6, by, by + 4, glyph_color);
            // Front box (main, offset down-left)
            surf.hline(bx, bx + 5, by + 2, glyph_color);
            surf.hline(bx, bx + 5, by + 3, glyph_color); // Thick top
            surf.hline(bx, bx + 5, by + 6, glyph_color);
            surf.vline(bx, by + 2, by + 7, glyph_color);
            surf.vline(bx + 4, by + 2, by + 7, glyph_color);
        }
        CaptionButton::Minimize => {
            // Draw minimize line (underscore)
            surf.hline(cx - 3, cx + 3, cy + 2, glyph_color);
            surf.hline(cx - 3, cx + 3, cy + 3, glyph_color);
        }
    }
}

// ============================================================================
// Desktop Painting
// ============================================================================

/// Paint the desktop background
pub fn paint_desktop() {
    crate::serial_println!("[PAINT] paint_desktop called");

    // Get display surface
    let surface_handle = super::super::gdi::surface::get_display_surface();
    crate::serial_println!("[PAINT] Surface handle: {:?}", surface_handle.is_valid());

    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => {
            crate::serial_println!("[PAINT] ERROR: No surface found!");
            return;
        }
    };

    crate::serial_println!("[PAINT] Surface: {}x{} @ {:#x}", surf.width, surf.height, surf.bits);

    // Get desktop color
    let color = super::desktop::get_desktop_color();
    crate::serial_println!("[PAINT] Desktop color: {:#x}", color.0);

    // Get desktop dimensions
    let rect = super::desktop::get_desktop_rect();
    crate::serial_println!("[PAINT] Desktop rect: ({},{}) - ({},{})",
        rect.left, rect.top, rect.right, rect.bottom);

    // Fill with desktop color
    surf.fill_rect(&rect, color);
    crate::serial_println!("[PAINT] Desktop painted");
}

/// Repaint all visible windows
pub fn repaint_all() {
    // Paint desktop first
    paint_desktop();

    // Also paint desktop icons
    super::explorer::deskhost::paint_icons_only();

    // Collect all visible windows with their z-orders
    // Max 32 windows for now
    let mut windows: [(HWND, u32); 32] = [(HWND::NULL, 0); 32];
    let mut window_count = 0usize;

    let count = window::get_window_count() as usize;
    for i in 0..count {
        if let Some(hwnd) = window::get_window_at_index(i) {
            if let Some(wnd) = window::get_window(hwnd) {
                if wnd.visible && !wnd.minimized && window_count < 32 {
                    windows[window_count] = (hwnd, wnd.z_order);
                    window_count += 1;
                }
            }
        }
    }

    // Sort by z-order (lowest first, so topmost window is painted last)
    for i in 0..window_count {
        for j in (i + 1)..window_count {
            if windows[j].1 < windows[i].1 {
                windows.swap(i, j);
            }
        }
    }

    // Paint windows in z-order
    for i in 0..window_count {
        draw_window_frame(windows[i].0);
    }
}

/// Recursively repaint window and children
fn repaint_window_tree(hwnd: HWND) {
    if !hwnd.is_valid() {
        return;
    }

    if let Some(wnd) = window::get_window(hwnd) {
        // Skip minimized windows (they shouldn't be painted on screen)
        if wnd.visible && !wnd.minimized {
            // Paint this window's frame
            draw_window_frame(hwnd);

            // Send paint message for client area
            if wnd.needs_paint {
                message::send_message(hwnd, message::WM_PAINT, 0, 0);
            }

            // Paint children
            let mut child = wnd.child;
            while child.is_valid() {
                repaint_window_tree(child);

                // Move to next sibling
                if let Some(child_wnd) = window::get_window(child) {
                    child = child_wnd.sibling;
                } else {
                    break;
                }
            }
        }
    }
}
