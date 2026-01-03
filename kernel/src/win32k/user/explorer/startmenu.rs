//! Start Menu Implementation
//!
//! This module implements CStartMenuHost - the Windows Start menu popup.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/explorer/startmnu.cpp`
//! - `shell/explorer/startmnu.h`

use core::sync::atomic::{AtomicBool, Ordering};
use super::super::super::{HWND, HDC, Rect, ColorRef};
use super::super::super::gdi::{dc, brush};
use super::super::{message, window, winlogon, cursor};
use super::tray::TASKBAR_HEIGHT;

// ============================================================================
// Constants
// ============================================================================

/// Start menu item count (main items)
const START_MENU_ITEMS: usize = 8;

/// Start menu item height
const START_MENU_ITEM_HEIGHT: i32 = 24;

/// Start menu total width (sidebar + items)
const START_MENU_WIDTH: i32 = 220;

/// Start menu sidebar width (blue user panel)
const START_MENU_SIDEBAR_WIDTH: i32 = 54;

/// Start menu header height (user area)
const START_MENU_HEADER_HEIGHT: i32 = 36;

// ============================================================================
// State
// ============================================================================

/// Start menu visible
static START_MENU_VISIBLE: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Start Menu Item Structure
// ============================================================================

/// Start menu item structure
struct StartMenuItem {
    name: &'static str,
    has_submenu: bool,
    is_separator: bool,
}

/// Start menu items (Windows 2003 style)
const START_MENU_ITEM_LIST: [StartMenuItem; START_MENU_ITEMS] = [
    StartMenuItem { name: "Programs", has_submenu: true, is_separator: false },
    StartMenuItem { name: "Documents", has_submenu: true, is_separator: false },
    StartMenuItem { name: "Settings", has_submenu: true, is_separator: false },
    StartMenuItem { name: "Search", has_submenu: true, is_separator: false },
    StartMenuItem { name: "Help and Support", has_submenu: false, is_separator: false },
    StartMenuItem { name: "Run...", has_submenu: false, is_separator: false },
    StartMenuItem { name: "Shut Down...", has_submenu: false, is_separator: false },
    StartMenuItem { name: "Log Off", has_submenu: false, is_separator: false },
];

// ============================================================================
// Public API
// ============================================================================

/// Toggle Start menu visibility
pub fn toggle() {
    if is_visible() {
        hide();
    } else {
        show();
    }
}

/// Show the Start menu
pub fn show() {
    START_MENU_VISIBLE.store(true, Ordering::SeqCst);
    crate::serial_println!("[STARTMENU] Showing Start menu");
    paint();
}

/// Hide the Start menu
pub fn hide() {
    START_MENU_VISIBLE.store(false, Ordering::SeqCst);
    crate::serial_println!("[STARTMENU] Hiding Start menu");

    // Invalidate cursor background so it doesn't restore menu pixels
    cursor::invalidate_cursor_background();

    // Repaint desktop to clear the menu
    super::paint_desktop();
    super::paint_taskbar();

    // Redraw cursor with fresh background
    cursor::draw_cursor();
}

/// Check if Start menu is visible
pub fn is_visible() -> bool {
    START_MENU_VISIBLE.load(Ordering::SeqCst)
}

/// Get the menu rectangle
pub fn get_menu_rect() -> Rect {
    let (_, height) = super::super::super::gdi::surface::get_primary_dimensions();
    let taskbar_y = height as i32 - TASKBAR_HEIGHT;
    let menu_height = START_MENU_ITEMS as i32 * START_MENU_ITEM_HEIGHT + START_MENU_HEADER_HEIGHT + 4;
    let menu_x = 2;
    let menu_y = taskbar_y - menu_height;

    Rect::new(menu_x, menu_y, menu_x + START_MENU_WIDTH, taskbar_y)
}

// ============================================================================
// Click Handling
// ============================================================================

/// Handle click on Start menu
pub fn handle_click(x: i32, y: i32) -> bool {
    if !is_visible() {
        return false;
    }

    let (_, height) = super::super::super::gdi::surface::get_primary_dimensions();
    let taskbar_y = height as i32 - TASKBAR_HEIGHT;
    let menu_height = START_MENU_ITEMS as i32 * START_MENU_ITEM_HEIGHT + START_MENU_HEADER_HEIGHT + 4;
    let menu_y = taskbar_y - menu_height;
    let menu_x = 2;

    // Check if click is in menu area
    if x < menu_x || x > menu_x + START_MENU_WIDTH || y < menu_y || y >= taskbar_y {
        hide();
        return true;
    }

    // Check if click is in items area (not in header)
    let items_start_y = menu_y + START_MENU_HEADER_HEIGHT + 2;
    if y < items_start_y {
        // Click in header - do nothing
        return true;
    }

    // Determine which item was clicked
    let relative_y = y - items_start_y;
    let item_index = relative_y / START_MENU_ITEM_HEIGHT;

    if item_index >= 0 && (item_index as usize) < START_MENU_ITEMS {
        let item = item_index as usize;
        crate::serial_println!("[STARTMENU] Item clicked: {}", START_MENU_ITEM_LIST[item].name);

        match item {
            5 => {
                // Run... - disabled for now
                hide();
                crate::serial_println!("[STARTMENU] Run... item clicked (not implemented)");
            }
            6 => {
                // Shut Down...
                hide();
                crate::serial_println!("[STARTMENU] Initiating shutdown...");
                winlogon::shutdown(false);
                // Note: shutdown never returns
            }
            7 => {
                // Log Off
                hide();
                crate::serial_println!("[STARTMENU] Initiating logoff...");
                winlogon::logoff();
            }
            _ => {
                // Items with submenus - just hide for now
                hide();
                // TODO: Implement submenus for Programs, Documents, Settings, Search
            }
        }
    }

    true
}

// ============================================================================
// Painting
// ============================================================================

/// Paint the Start menu with Windows 2003 styling
pub fn paint() {
    if !is_visible() {
        return;
    }

    if let Ok(hdc) = dc::create_display_dc() {
        let (_, height) = super::super::super::gdi::surface::get_primary_dimensions();
        let taskbar_y = height as i32 - TASKBAR_HEIGHT;

        // Calculate menu dimensions
        let menu_height = START_MENU_ITEMS as i32 * START_MENU_ITEM_HEIGHT + START_MENU_HEADER_HEIGHT + 4;
        let menu_x = 2;
        let menu_y = taskbar_y - menu_height;

        let menu_rect = Rect::new(
            menu_x, menu_y,
            menu_x + START_MENU_WIDTH, taskbar_y
        );

        // Get surface for direct drawing
        let surface_handle = dc::get_dc_surface(hdc);
        if let Some(surf) = super::super::super::gdi::surface::get_surface(surface_handle) {
            // Draw menu background (gray)
            surf.fill_rect(&menu_rect, ColorRef::BUTTON_FACE);

            // Draw blue sidebar on the left (Windows 2003 style)
            let sidebar_rect = Rect::new(
                menu_x,
                menu_y,
                menu_x + START_MENU_SIDEBAR_WIDTH,
                taskbar_y,
            );
            // Gradient-like blue sidebar (simplified - use solid color)
            surf.fill_rect(&sidebar_rect, ColorRef::rgb(0, 51, 153)); // Dark blue

            // Draw user header area at top of sidebar
            let header_rect = Rect::new(
                menu_x,
                menu_y,
                menu_x + START_MENU_WIDTH,
                menu_y + START_MENU_HEADER_HEIGHT,
            );
            surf.fill_rect(&header_rect, ColorRef::rgb(0, 51, 153)); // Match sidebar

            // Draw user icon
            paint_user_icon(surf, menu_x + 6, menu_y + 6);

            // Draw username
            dc::set_text_color(hdc, ColorRef::WHITE);
            dc::set_bk_mode(hdc, dc::BkMode::Transparent);
            super::super::super::gdi::text_out(hdc, menu_x + 36, menu_y + 10, "Administrator");

            // Draw 3D border around menu
            // Top and left highlight
            surf.hline(menu_rect.left, menu_rect.right - 1, menu_rect.top, ColorRef::WHITE);
            surf.vline(menu_rect.left, menu_rect.top, menu_rect.bottom - 1, ColorRef::WHITE);
            // Bottom and right shadow
            surf.hline(menu_rect.left, menu_rect.right, menu_rect.bottom - 1, ColorRef::DARK_GRAY);
            surf.vline(menu_rect.right - 1, menu_rect.top, menu_rect.bottom, ColorRef::DARK_GRAY);

            // Draw separator between header and items
            let sep_y = menu_y + START_MENU_HEADER_HEIGHT;
            surf.hline(menu_x, menu_x + START_MENU_WIDTH, sep_y, ColorRef::BUTTON_SHADOW);
            surf.hline(menu_x, menu_x + START_MENU_WIDTH, sep_y + 1, ColorRef::WHITE);
        }

        // Draw menu items
        paint_menu_items(hdc, menu_x, menu_y);

        dc::delete_dc(hdc);
    }
}

/// Paint the user icon
fn paint_user_icon(surf: &super::super::super::gdi::surface::Surface, icon_x: i32, icon_y: i32) {
    // Draw simple user silhouette icon (24x24)
    for row in 0..24 {
        for col in 0..24 {
            let px = icon_x + col as i32;
            let py = icon_y + row as i32;

            // Simple person icon design
            let is_icon = if row >= 6 && row <= 10 {
                // Head (circle approximation)
                let dx = col as i32 - 12;
                let dy = row as i32 - 8;
                dx * dx + dy * dy <= 16
            } else if row >= 12 && row <= 22 {
                // Body (trapezoid)
                let top_width = 8;
                let bottom_width = 16;
                let body_height = 10;
                let row_offset = row - 12;
                let width_at_row = top_width + (bottom_width - top_width) * row_offset as i32 / body_height;
                let left_edge = 12 - width_at_row / 2;
                let right_edge = 12 + width_at_row / 2;
                col >= left_edge as usize && col <= right_edge as usize
            } else {
                false
            };

            if is_icon {
                // Light blue/cyan user icon
                surf.set_pixel(px, py, ColorRef::rgb(150, 200, 255));
            }
        }
    }
}

/// Paint the menu items
fn paint_menu_items(hdc: HDC, menu_x: i32, menu_y: i32) {
    let items_start_y = menu_y + START_MENU_HEADER_HEIGHT + 2;
    let items_x = menu_x + START_MENU_SIDEBAR_WIDTH + 4;

    for (i, item) in START_MENU_ITEM_LIST.iter().enumerate() {
        let item_y = items_start_y + (i as i32 * START_MENU_ITEM_HEIGHT);

        // Draw separator before Shut Down (after Help)
        if i == 6 {
            if let Some(surf) = super::super::super::gdi::surface::get_surface(dc::get_dc_surface(hdc)) {
                let sep_y2 = item_y - 2;
                surf.hline(items_x, menu_x + START_MENU_WIDTH - 4, sep_y2, ColorRef::BUTTON_SHADOW);
                surf.hline(items_x, menu_x + START_MENU_WIDTH - 4, sep_y2 + 1, ColorRef::WHITE);
            }
        }

        // Draw menu item icon
        paint_menu_item_icon(hdc, items_x + 2, item_y + 2, i);

        // Draw item text (shifted right to make room for icon)
        dc::set_text_color(hdc, ColorRef::BLACK);
        super::super::super::gdi::text_out(hdc, items_x + 20, item_y + 4, item.name);

        // Draw submenu arrow if has submenu
        if item.has_submenu {
            if let Some(surf) = super::super::super::gdi::surface::get_surface(dc::get_dc_surface(hdc)) {
                let arrow_x = menu_x + START_MENU_WIDTH - 12;
                let arrow_y = item_y + 8;
                // Draw simple right arrow
                surf.set_pixel(arrow_x, arrow_y, ColorRef::BLACK);
                surf.set_pixel(arrow_x + 1, arrow_y + 1, ColorRef::BLACK);
                surf.set_pixel(arrow_x + 2, arrow_y + 2, ColorRef::BLACK);
                surf.set_pixel(arrow_x + 1, arrow_y + 3, ColorRef::BLACK);
                surf.set_pixel(arrow_x, arrow_y + 4, ColorRef::BLACK);
            }
        }
    }
}

/// Paint a menu item icon
fn paint_menu_item_icon(hdc: HDC, icon_x: i32, icon_y: i32, item_index: usize) {
    if let Some(surf) = super::super::super::gdi::surface::get_surface(dc::get_dc_surface(hdc)) {
        use super::super::desktop_icons::*;

        // Select icon data based on menu item
        let (width, height, data) = match item_index {
            0 => (PROGRAMS_WIDTH, PROGRAMS_HEIGHT, &PROGRAMS_DATA[..]),  // Programs
            1 => (DOCUMENTS_WIDTH, DOCUMENTS_HEIGHT, &DOCUMENTS_DATA[..]),  // Documents
            2 => (SETTINGS_WIDTH, SETTINGS_HEIGHT, &SETTINGS_DATA[..]),  // Settings
            3 => (SEARCH_WIDTH, SEARCH_HEIGHT, &SEARCH_DATA[..]),  // Search
            4 => (HELP_WIDTH, HELP_HEIGHT, &HELP_DATA[..]),  // Help
            5 => (RUN_WIDTH, RUN_HEIGHT, &RUN_DATA[..]),  // Run
            6 => (SHUTDOWN_WIDTH, SHUTDOWN_HEIGHT, &SHUTDOWN_DATA[..]),  // Shut Down
            7 => (LOGOFF_WIDTH, LOGOFF_HEIGHT, &LOGOFF_DATA[..]),  // Log Off
            _ => return,  // Safety fallback
        };

        // Draw 16x16 icon (scaled down from 32x32)
        for row in 0..16 {
            for col in 0..16 {
                // Sample from 32x32 data (every other pixel)
                let src_row = row * 2;
                let src_col = col * 2;
                let offset = (src_row * width + src_col) * 4;

                if offset + 3 < data.len() {
                    let r = data[offset];
                    let g = data[offset + 1];
                    let b = data[offset + 2];
                    let a = data[offset + 3];

                    // Skip fully transparent pixels
                    if a == 0 {
                        continue;
                    }

                    let px = icon_x + col as i32;
                    let py = icon_y + row as i32;

                    if a == 255 {
                        surf.set_pixel(px, py, ColorRef::rgb(r, g, b));
                    } else {
                        // Blend with menu background (light gray)
                        let bg_r = 192u8;
                        let bg_g = 192u8;
                        let bg_b = 192u8;

                        let blended_r = ((r as u16 * a as u16 + bg_r as u16 * (255 - a) as u16) / 255) as u8;
                        let blended_g = ((g as u16 * a as u16 + bg_g as u16 * (255 - a) as u16) / 255) as u8;
                        let blended_b = ((b as u16 * a as u16 + bg_b as u16 * (255 - a) as u16) / 255) as u8;

                        surf.set_pixel(px, py, ColorRef::rgb(blended_r, blended_g, blended_b));
                    }
                }
            }
        }
    }
}
