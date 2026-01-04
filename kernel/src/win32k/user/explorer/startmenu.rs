//! Start Menu Implementation
//!
//! This module implements CStartMenuHost - the Windows Start menu popup.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/explorer/startmnu.cpp`
//! - `shell/explorer/startmnu.h`

use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use crate::ke::SpinLock;
use super::super::super::{HWND, HDC, Rect, ColorRef};
use super::super::super::gdi::{dc, brush};
use super::super::{message, window, winlogon, cursor};
use super::tray::TASKBAR_HEIGHT;
use crate::io::{vfs_read_directory, vfs_read_special_folder, VfsEntry, SpecialFolder};

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

/// Submenu width
const SUBMENU_WIDTH: i32 = 200;

/// Maximum submenu items
const MAX_SUBMENU_ITEMS: usize = 16;

// ============================================================================
// State
// ============================================================================

/// Start menu visible
static START_MENU_VISIBLE: AtomicBool = AtomicBool::new(false);

/// Active submenu index (-1 = none)
static ACTIVE_SUBMENU: AtomicI32 = AtomicI32::new(-1);

/// Submenu entries cache
struct SubmenuCache {
    entries: [VfsEntry; MAX_SUBMENU_ITEMS],
    count: usize,
    path: [u8; 128],
    path_len: usize,
}

impl SubmenuCache {
    const fn new() -> Self {
        Self {
            entries: [VfsEntry::empty(); MAX_SUBMENU_ITEMS],
            count: 0,
            path: [0; 128],
            path_len: 0,
        }
    }
}

static SUBMENU_CACHE: SpinLock<SubmenuCache> = SpinLock::new(SubmenuCache::new());

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
    ACTIVE_SUBMENU.store(-1, Ordering::SeqCst);
    crate::serial_println!("[STARTMENU] Hiding Start menu");

    // Invalidate cursor background so it doesn't restore menu pixels
    cursor::invalidate_cursor_background();

    // Repaint desktop to clear the menu
    super::paint_desktop();
    super::paint_taskbar();

    // Redraw cursor with fresh background
    cursor::draw_cursor();
}

/// Special entry marker for Command Prompt
const CMD_ENTRY_MARKER: &[u8] = b":CMD";

/// Show submenu for a menu item
fn show_submenu(item_index: i32) {
    ACTIVE_SUBMENU.store(item_index, Ordering::SeqCst);

    // Load content for this submenu
    let mut cache = SUBMENU_CACHE.lock();
    cache.count = 0;
    cache.path_len = 0;

    let path = match item_index {
        0 => "C:/Program Files",  // Programs
        1 => ":MyDocuments",       // Documents (special folder)
        2 => "C:/Windows",         // Settings (show Windows folder)
        3 => "C:/",                // Search (show root)
        _ => return,
    };

    // Store path
    let path_len = path.len().min(127);
    cache.path[..path_len].copy_from_slice(&path.as_bytes()[..path_len]);
    cache.path_len = path_len;

    // For Programs menu, add built-in entries first
    let mut offset = 0;
    if item_index == 0 {
        // Add Command Prompt as first entry
        let cmd_name = b"Command Prompt";
        cache.entries[0] = VfsEntry::empty();
        cache.entries[0].name[..CMD_ENTRY_MARKER.len()].copy_from_slice(CMD_ENTRY_MARKER);
        cache.entries[0].name_len = CMD_ENTRY_MARKER.len();
        cache.entries[0].is_directory = false;
        // Store display name in a way we can recognize
        // We'll handle this specially in painting
        offset = 1;
    }

    // Load entries from VFS
    let mut entries = [VfsEntry::empty(); MAX_SUBMENU_ITEMS];
    let count = if path.starts_with(':') {
        // Special folder
        let folder = match item_index {
            1 => SpecialFolder::MyDocuments,
            _ => return,
        };
        vfs_read_special_folder(folder, &mut entries)
    } else {
        vfs_read_directory(path, &mut entries)
    };

    // Copy entries to cache (limit to MAX_SUBMENU_ITEMS - offset)
    let count = count.min(MAX_SUBMENU_ITEMS - offset);
    for i in 0..count {
        cache.entries[offset + i] = entries[i];
    }
    cache.count = offset + count;

    crate::serial_println!("[STARTMENU] Loaded {} items for submenu {}", cache.count, item_index);
}

/// Hide submenu
fn hide_submenu() {
    ACTIVE_SUBMENU.store(-1, Ordering::SeqCst);
}

/// Get submenu rectangle
fn get_submenu_rect() -> Option<Rect> {
    let submenu_idx = ACTIVE_SUBMENU.load(Ordering::SeqCst);
    if submenu_idx < 0 {
        return None;
    }

    let (_, height) = super::super::super::gdi::surface::get_primary_dimensions();
    let taskbar_y = height as i32 - TASKBAR_HEIGHT;
    let menu_height = START_MENU_ITEMS as i32 * START_MENU_ITEM_HEIGHT + START_MENU_HEADER_HEIGHT + 4;
    let menu_y = taskbar_y - menu_height;
    let menu_x = 2;

    let items_start_y = menu_y + START_MENU_HEADER_HEIGHT + 2;
    let item_y = items_start_y + (submenu_idx as i32 * START_MENU_ITEM_HEIGHT);

    let cache = SUBMENU_CACHE.lock();
    let submenu_height = (cache.count as i32 * START_MENU_ITEM_HEIGHT).max(START_MENU_ITEM_HEIGHT);

    Some(Rect::new(
        menu_x + START_MENU_WIDTH,
        item_y,
        menu_x + START_MENU_WIDTH + SUBMENU_WIDTH,
        item_y + submenu_height + 4,
    ))
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

    // Check if click is in submenu area
    if let Some(submenu_rect) = get_submenu_rect() {
        if x >= submenu_rect.left && x < submenu_rect.right &&
           y >= submenu_rect.top && y < submenu_rect.bottom {
            // Click in submenu - determine which item
            let relative_y = y - submenu_rect.top - 2;
            let item_index = relative_y / START_MENU_ITEM_HEIGHT;

            let (full_path_buf, full_path_len, name_buf, name_len, is_directory) = {
                let cache = SUBMENU_CACHE.lock();
                if item_index >= 0 && (item_index as usize) < cache.count {
                    let entry = &cache.entries[item_index as usize];

                    // Copy name to local buffer
                    let mut name_buf = [0u8; 64];
                    let name_len = entry.name_len.min(63);
                    name_buf[..name_len].copy_from_slice(&entry.name[..name_len]);

                    // Build full path
                    let path = core::str::from_utf8(&cache.path[..cache.path_len]).unwrap_or("");
                    let mut full_path = [0u8; 256];
                    let mut pos = 0;

                    // Copy base path
                    for &b in path.as_bytes() {
                        if pos < 255 {
                            full_path[pos] = b;
                            pos += 1;
                        }
                    }
                    // Add separator if needed
                    if pos > 0 && pos < 255 && full_path[pos - 1] != b'/' && full_path[pos - 1] != b'\\' {
                        full_path[pos] = b'/';
                        pos += 1;
                    }
                    // Add entry name
                    for &b in entry.name[..entry.name_len].iter() {
                        if pos < 255 {
                            full_path[pos] = b;
                            pos += 1;
                        }
                    }

                    (full_path, pos, name_buf, name_len, entry.is_directory)
                } else {
                    return true;
                }
            };

            let name = core::str::from_utf8(&name_buf[..name_len]).unwrap_or("");
            let full_path_str = core::str::from_utf8(&full_path_buf[..full_path_len]).unwrap_or("");

            crate::serial_println!("[STARTMENU] Submenu item clicked: {} path={}", name, full_path_str);

            // Check if it's the Command Prompt entry
            if name == ":CMD" {
                hide();
                crate::serial_println!("[STARTMENU] Launching Command Prompt...");
                super::super::shell::create_shell();
                return true;
            }

            if is_directory {
                hide();
                open_folder_window(full_path_str, name);
            } else {
                hide();
            }
            return true;
        }
    }

    // Check if click is in main menu area
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
            0 | 1 | 2 | 3 => {
                // Items with submenus - show submenu
                if ACTIVE_SUBMENU.load(Ordering::SeqCst) == item_index {
                    // Already showing this submenu, open the folder directly
                    let path = match item {
                        0 => "C:/Program Files",
                        1 => "C:/Documents and Settings",
                        2 => "C:/Windows",
                        3 => "C:/",
                        _ => return true,
                    };
                    let title = START_MENU_ITEM_LIST[item].name;
                    hide();
                    open_folder_window(path, title);
                } else {
                    show_submenu(item_index);
                    paint();
                }
            }
            4 => {
                // Help and Support
                hide();
                crate::serial_println!("[STARTMENU] Help clicked (not implemented)");
            }
            5 => {
                // Run...
                hide();
                crate::serial_println!("[STARTMENU] Run... clicked (not implemented)");
            }
            6 => {
                // Shut Down...
                hide();
                crate::serial_println!("[STARTMENU] Initiating shutdown...");
                winlogon::shutdown(false);
            }
            7 => {
                // Log Off
                hide();
                crate::serial_println!("[STARTMENU] Initiating logoff...");
                winlogon::logoff();
            }
            _ => {
                hide();
            }
        }
    }

    true
}

/// Open a folder in an explorer window
fn open_folder_window(path: &str, title: &str) {
    use super::super::WindowStyle;

    let hwnd = window::create_window(
        "CabinetWClass",
        title,
        WindowStyle::OVERLAPPEDWINDOW | WindowStyle::VISIBLE,
        super::super::WindowStyleEx::empty(),
        200, 100, 400, 300,
        super::super::super::HWND::NULL,
        0,
    );

    if hwnd.is_valid() {
        window::set_window_user_data(hwnd, path);
        window::with_window_mut(hwnd, |w| {
            w.push_nav_history(path);
        });
        super::taskband::add_task(hwnd);
        window::set_foreground_window(hwnd);
        super::super::input::set_active_window(hwnd);
    }
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
            paint_user_icon(&surf, menu_x + 6, menu_y + 6);

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

        // Draw submenu if visible
        if ACTIVE_SUBMENU.load(Ordering::SeqCst) >= 0 {
            paint_submenu(hdc, menu_x, menu_y);
        }

        dc::delete_dc(hdc);
    }
}

/// Paint the submenu
fn paint_submenu(hdc: HDC, menu_x: i32, menu_y: i32) {
    let submenu_idx = ACTIVE_SUBMENU.load(Ordering::SeqCst);
    if submenu_idx < 0 {
        return;
    }

    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match super::super::super::gdi::surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let items_start_y = menu_y + START_MENU_HEADER_HEIGHT + 2;
    let item_y = items_start_y + (submenu_idx as i32 * START_MENU_ITEM_HEIGHT);

    let cache = SUBMENU_CACHE.lock();
    if cache.count == 0 {
        return;
    }

    let submenu_height = cache.count as i32 * START_MENU_ITEM_HEIGHT + 4;
    let submenu_x = menu_x + START_MENU_WIDTH;

    let submenu_rect = Rect::new(
        submenu_x,
        item_y,
        submenu_x + SUBMENU_WIDTH,
        item_y + submenu_height,
    );

    // Draw submenu background
    surf.fill_rect(&submenu_rect, ColorRef::BUTTON_FACE);

    // Draw 3D border
    surf.hline(submenu_rect.left, submenu_rect.right - 1, submenu_rect.top, ColorRef::WHITE);
    surf.vline(submenu_rect.left, submenu_rect.top, submenu_rect.bottom - 1, ColorRef::WHITE);
    surf.hline(submenu_rect.left, submenu_rect.right, submenu_rect.bottom - 1, ColorRef::DARK_GRAY);
    surf.vline(submenu_rect.right - 1, submenu_rect.top, submenu_rect.bottom, ColorRef::DARK_GRAY);

    // Draw submenu items
    dc::set_text_color(hdc, ColorRef::BLACK);
    dc::set_bk_mode(hdc, dc::BkMode::Transparent);

    for i in 0..cache.count {
        let entry = &cache.entries[i];
        let entry_y = item_y + 2 + (i as i32 * START_MENU_ITEM_HEIGHT);

        // Check if this is the CMD entry
        let is_cmd = entry.name_len == CMD_ENTRY_MARKER.len()
            && &entry.name[..entry.name_len] == CMD_ENTRY_MARKER;

        if is_cmd {
            // Draw console icon
            paint_console_icon(&surf, submenu_x + 4, entry_y + 2);
            // Draw "Command Prompt" text
            super::super::super::gdi::text_out(hdc, submenu_x + 24, entry_y + 4, "Command Prompt");
        } else {
            // Draw folder/file icon
            if entry.is_directory {
                paint_folder_icon(&surf, submenu_x + 4, entry_y + 2);
            } else {
                paint_file_icon(&surf, submenu_x + 4, entry_y + 2);
            }

            // Draw entry name
            let name = entry.name_str();
            super::super::super::gdi::text_out(hdc, submenu_x + 24, entry_y + 4, name);

            // Draw submenu arrow if directory
            if entry.is_directory {
                let arrow_x = submenu_x + SUBMENU_WIDTH - 12;
                let arrow_y = entry_y + 8;
                surf.set_pixel(arrow_x, arrow_y, ColorRef::BLACK);
                surf.set_pixel(arrow_x + 1, arrow_y + 1, ColorRef::BLACK);
                surf.set_pixel(arrow_x + 2, arrow_y + 2, ColorRef::BLACK);
                surf.set_pixel(arrow_x + 1, arrow_y + 3, ColorRef::BLACK);
                surf.set_pixel(arrow_x, arrow_y + 4, ColorRef::BLACK);
            }
        }
    }
}

/// Paint a small folder icon (16x16)
fn paint_folder_icon(surf: &super::super::super::gdi::surface::Surface, x: i32, y: i32) {
    // Simple folder icon - yellow folder
    let folder_color = ColorRef::rgb(255, 200, 0);
    let outline_color = ColorRef::rgb(180, 140, 0);

    // Tab at top
    surf.hline(x + 1, x + 6, y + 2, folder_color);
    surf.hline(x + 1, x + 6, y + 3, folder_color);

    // Main folder body
    for row in 4..14 {
        surf.hline(x + 1, x + 15, y + row, folder_color);
    }

    // Outline
    surf.hline(x + 1, x + 6, y + 2, outline_color);
    surf.hline(x, x + 16, y + 4, outline_color);
    surf.hline(x, x + 16, y + 14, outline_color);
    surf.vline(x, y + 4, y + 14, outline_color);
    surf.vline(x + 15, y + 4, y + 14, outline_color);
}

/// Paint a small file icon (16x16)
fn paint_file_icon(surf: &super::super::super::gdi::surface::Surface, x: i32, y: i32) {
    // Simple file icon - white with folded corner
    let paper_color = ColorRef::WHITE;
    let outline_color = ColorRef::rgb(128, 128, 128);

    // Main paper body
    for row in 2..14 {
        let width = if row < 5 { 10 } else { 13 };
        surf.hline(x + 2, x + 2 + width, y + row, paper_color);
    }

    // Folded corner (top right)
    for i in 0..3 {
        surf.hline(x + 12 - i, x + 12, y + 2 + i, ColorRef::rgb(200, 200, 200));
    }

    // Outline
    surf.vline(x + 2, y + 2, y + 14, outline_color);
    surf.vline(x + 14, y + 5, y + 14, outline_color);
    surf.hline(x + 2, x + 10, y + 2, outline_color);
    surf.hline(x + 2, x + 15, y + 14, outline_color);
    // Diagonal fold line
    surf.set_pixel(x + 10, y + 2, outline_color);
    surf.set_pixel(x + 11, y + 3, outline_color);
    surf.set_pixel(x + 12, y + 4, outline_color);
    surf.set_pixel(x + 13, y + 5, outline_color);
    surf.set_pixel(x + 14, y + 5, outline_color);
}

/// Paint a small console icon (16x16)
fn paint_console_icon(surf: &super::super::super::gdi::surface::Surface, x: i32, y: i32) {
    // Black background console window
    let bg_color = ColorRef::BLACK;
    let border_color = ColorRef::rgb(128, 128, 128);
    let title_color = ColorRef::rgb(0, 0, 128);  // Dark blue title bar
    let text_color = ColorRef::rgb(192, 192, 192);  // Light gray text

    // Title bar
    surf.hline(x + 1, x + 15, y + 2, title_color);
    surf.hline(x + 1, x + 15, y + 3, title_color);
    surf.hline(x + 1, x + 15, y + 4, title_color);

    // Console background
    for row in 5..14 {
        surf.hline(x + 1, x + 15, y + row, bg_color);
    }

    // Border
    surf.hline(x, x + 16, y + 1, border_color);
    surf.hline(x, x + 16, y + 14, border_color);
    surf.vline(x, y + 1, y + 14, border_color);
    surf.vline(x + 15, y + 1, y + 14, border_color);

    // Text prompt "C:>" in console
    surf.set_pixel(x + 2, y + 7, text_color);
    surf.set_pixel(x + 3, y + 7, text_color);
    surf.set_pixel(x + 5, y + 7, text_color);
    surf.set_pixel(x + 6, y + 7, text_color);
    surf.set_pixel(x + 7, y + 7, text_color);

    // Cursor blink underscore
    surf.hline(x + 9, x + 12, y + 11, text_color);
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
