//! File Properties Dialog
//!
//! Implements the Windows-style Properties dialog for files and folders.
//! Shows file attributes, size, location, and timestamps.
//!
//! # Features
//!
//! - General tab with file information
//! - File attributes (Read-only, Hidden)
//! - OK/Cancel/Apply buttons
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/shell32/ftprop.cpp` - File properties
//! - `shell/shell32/propsht.cpp` - Property sheets

use crate::ke::spinlock::SpinLock;
use crate::io::VfsIconType;
use super::super::super::{HWND, HDC, Rect, ColorRef};
use super::super::super::gdi::{self, dc, dc::BkMode, surface};
use super::filebrowser::{MAX_PATH, FileItem};

// ============================================================================
// Constants
// ============================================================================

/// Properties dialog width
pub const PROPERTIES_WIDTH: i32 = 380;

/// Properties dialog height
pub const PROPERTIES_HEIGHT: i32 = 420;

/// Label width
const LABEL_WIDTH: i32 = 80;

/// Value start X
const VALUE_X: i32 = 100;

/// Row height
const ROW_HEIGHT: i32 = 22;

/// Button width
const BUTTON_WIDTH: i32 = 75;

/// Button height
const BUTTON_HEIGHT: i32 = 23;

/// Maximum properties dialogs
const MAX_PROPERTIES_DIALOGS: usize = 8;

// ============================================================================
// Colors
// ============================================================================

const COLOR_DIALOG_BG: ColorRef = ColorRef::rgb(240, 240, 240);
const COLOR_LABEL: ColorRef = ColorRef::rgb(0, 0, 0);
const COLOR_VALUE: ColorRef = ColorRef::rgb(0, 0, 0);
const COLOR_SEPARATOR: ColorRef = ColorRef::rgb(180, 180, 180);
const COLOR_BUTTON_BG: ColorRef = ColorRef::rgb(236, 233, 216);
const COLOR_BUTTON_BORDER: ColorRef = ColorRef::rgb(0, 0, 0);
const COLOR_ICON_BG: ColorRef = ColorRef::rgb(255, 255, 255);
const COLOR_CHECKBOX_BG: ColorRef = ColorRef::rgb(255, 255, 255);
const COLOR_CHECK_MARK: ColorRef = ColorRef::rgb(0, 0, 0);

// ============================================================================
// Properties Dialog State
// ============================================================================

/// Properties dialog instance
#[derive(Clone, Copy)]
pub struct PropertiesDialog {
    /// Window handle
    pub hwnd: HWND,
    /// Source browser window
    pub source_hwnd: HWND,
    /// File/folder name
    pub name: [u8; 256],
    pub name_len: usize,
    /// Full path
    pub path: [u8; MAX_PATH],
    pub path_len: usize,
    /// Is directory
    pub is_directory: bool,
    /// File size
    pub size: u64,
    /// Icon type
    pub icon_type: VfsIconType,
    /// Read-only attribute
    pub readonly: bool,
    /// Hidden attribute
    pub hidden: bool,
    /// Dialog visible
    pub visible: bool,
    /// Active/in use
    pub active: bool,
    /// Dialog position
    pub x: i32,
    pub y: i32,
    /// Which button is hovered (0=none, 1=OK, 2=Cancel, 3=Apply)
    pub hover_button: u8,
}

impl PropertiesDialog {
    pub const fn empty() -> Self {
        Self {
            hwnd: HWND::NULL,
            source_hwnd: HWND::NULL,
            name: [0; 256],
            name_len: 0,
            path: [0; MAX_PATH],
            path_len: 0,
            is_directory: false,
            size: 0,
            icon_type: VfsIconType::File,
            readonly: false,
            hidden: false,
            visible: false,
            active: false,
            x: 100,
            y: 100,
            hover_button: 0,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }

    pub fn path_str(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }

    /// Get file type description
    pub fn get_type_name(&self) -> &'static str {
        if self.is_directory {
            return "File Folder";
        }
        match self.icon_type {
            VfsIconType::Executable => "Application",
            VfsIconType::Image => "Image File",
            VfsIconType::Audio => "Audio File",
            VfsIconType::Video => "Video File",
            VfsIconType::Document => "Document",
            _ => "File",
        }
    }

    /// Format file size for display
    pub fn format_size(&self, buf: &mut [u8]) -> usize {
        if self.is_directory {
            let text = b"(folder)";
            let len = text.len().min(buf.len());
            buf[..len].copy_from_slice(&text[..len]);
            return len;
        }

        let size = self.size;
        if size < 1024 {
            format_number_with_suffix(size, buf, " bytes")
        } else if size < 1024 * 1024 {
            format_number_with_suffix(size / 1024, buf, " KB")
        } else if size < 1024 * 1024 * 1024 {
            format_number_with_suffix(size / (1024 * 1024), buf, " MB")
        } else {
            format_number_with_suffix(size / (1024 * 1024 * 1024), buf, " GB")
        }
    }

    /// Get location (parent directory)
    pub fn get_location(&self) -> &str {
        let path = self.path_str();
        if let Some(pos) = path.rfind('\\') {
            if pos > 0 {
                return &path[..pos];
            }
        }
        path
    }
}

fn format_number_with_suffix(n: u64, buf: &mut [u8], suffix: &str) -> usize {
    let mut temp = [0u8; 32];
    let mut pos = 0;
    let mut num = n;

    if num == 0 {
        temp[pos] = b'0';
        pos += 1;
    } else {
        while num > 0 && pos < 20 {
            temp[pos] = b'0' + (num % 10) as u8;
            num /= 10;
            pos += 1;
        }
    }

    // Reverse digits
    let mut out_pos = 0;
    for i in (0..pos).rev() {
        if out_pos < buf.len() {
            buf[out_pos] = temp[i];
            out_pos += 1;
        }
    }

    // Add suffix
    for &b in suffix.as_bytes() {
        if out_pos < buf.len() {
            buf[out_pos] = b;
            out_pos += 1;
        }
    }

    out_pos
}

// ============================================================================
// Global State
// ============================================================================

static PROPERTIES_DIALOGS: SpinLock<[PropertiesDialog; MAX_PROPERTIES_DIALOGS]> =
    SpinLock::new([const { PropertiesDialog::empty() }; MAX_PROPERTIES_DIALOGS]);

// ============================================================================
// Public API
// ============================================================================

/// Show properties dialog for a file item
pub fn show_properties(source_hwnd: HWND, item: &FileItem, path: &str) {
    let mut dialogs = PROPERTIES_DIALOGS.lock();

    // Find free slot
    for dialog in dialogs.iter_mut() {
        if !dialog.active {
            dialog.active = true;
            dialog.visible = true;
            dialog.source_hwnd = source_hwnd;
            dialog.hwnd = HWND::NULL; // Properties dialogs are painted directly

            // Copy item info
            dialog.name_len = item.name_len;
            dialog.name[..item.name_len].copy_from_slice(&item.name[..item.name_len]);
            dialog.is_directory = item.is_directory;
            dialog.size = item.size;
            dialog.icon_type = item.icon_type;
            dialog.readonly = false; // TODO: Get from VFS
            dialog.hidden = false;   // TODO: Get from VFS

            // Build full path
            let path_bytes = path.as_bytes();
            let name = item.name_str();
            let name_bytes = name.as_bytes();

            if path.is_empty() {
                // Root level - just use name
                dialog.path_len = name_bytes.len().min(MAX_PATH);
                dialog.path[..dialog.path_len].copy_from_slice(&name_bytes[..dialog.path_len]);
            } else {
                // Combine path + backslash + name
                let path_len = path_bytes.len();
                let total_len = (path_len + 1 + name_bytes.len()).min(MAX_PATH);

                dialog.path[..path_len].copy_from_slice(path_bytes);
                if path_len < MAX_PATH {
                    dialog.path[path_len] = b'\\';
                }
                let remaining = MAX_PATH - path_len - 1;
                let name_copy_len = name_bytes.len().min(remaining);
                if path_len + 1 < MAX_PATH && name_copy_len > 0 {
                    dialog.path[path_len + 1..path_len + 1 + name_copy_len]
                        .copy_from_slice(&name_bytes[..name_copy_len]);
                }
                dialog.path_len = total_len;
            }

            // Position dialog (center of screen)
            let (screen_w, screen_h) = super::super::super::gdi::surface::get_primary_dimensions();
            dialog.x = (screen_w as i32 - PROPERTIES_WIDTH) / 2;
            dialog.y = (screen_h as i32 - PROPERTIES_HEIGHT) / 2;

            crate::serial_println!("[PROPERTIES] Showing properties for: {}", dialog.name_str());
            return;
        }
    }

    crate::serial_println!("[PROPERTIES] No free slot for properties dialog");
}

/// Close properties dialog for a source window
pub fn close_properties(source_hwnd: HWND) {
    let mut dialogs = PROPERTIES_DIALOGS.lock();
    for dialog in dialogs.iter_mut() {
        if dialog.active && dialog.source_hwnd == source_hwnd {
            dialog.active = false;
            dialog.visible = false;
            return;
        }
    }
}

/// Check if any properties dialog is visible
pub fn is_any_visible() -> bool {
    let dialogs = PROPERTIES_DIALOGS.lock();
    dialogs.iter().any(|d| d.active && d.visible)
}

/// Get visible properties dialog rect (for hit testing)
pub fn get_visible_dialog_rect() -> Option<(Rect, usize)> {
    let dialogs = PROPERTIES_DIALOGS.lock();
    for (i, dialog) in dialogs.iter().enumerate() {
        if dialog.active && dialog.visible {
            let rect = Rect::new(
                dialog.x,
                dialog.y,
                dialog.x + PROPERTIES_WIDTH,
                dialog.y + PROPERTIES_HEIGHT,
            );
            return Some((rect, i));
        }
    }
    None
}

/// Handle click on properties dialog
pub fn handle_click(x: i32, y: i32) -> bool {
    let mut dialogs = PROPERTIES_DIALOGS.lock();

    for dialog in dialogs.iter_mut() {
        if !dialog.active || !dialog.visible {
            continue;
        }

        // Check if click is within dialog bounds
        if x < dialog.x || x >= dialog.x + PROPERTIES_WIDTH ||
           y < dialog.y || y >= dialog.y + PROPERTIES_HEIGHT {
            continue;
        }

        let rel_x = x - dialog.x;
        let rel_y = y - dialog.y;

        // Check close button (top right corner)
        if rel_x >= PROPERTIES_WIDTH - 25 && rel_x < PROPERTIES_WIDTH - 5 &&
           rel_y >= 5 && rel_y < 25 {
            dialog.active = false;
            dialog.visible = false;
            crate::serial_println!("[PROPERTIES] Dialog closed via X button");
            return true;
        }

        // Check attribute checkboxes
        let checkbox_y = 280;
        let checkbox_x = 20;

        // Read-only checkbox
        if rel_x >= checkbox_x && rel_x < checkbox_x + 16 &&
           rel_y >= checkbox_y && rel_y < checkbox_y + 16 {
            dialog.readonly = !dialog.readonly;
            crate::serial_println!("[PROPERTIES] Read-only toggled: {}", dialog.readonly);
            return true;
        }

        // Hidden checkbox
        if rel_x >= checkbox_x && rel_x < checkbox_x + 16 &&
           rel_y >= checkbox_y + 24 && rel_y < checkbox_y + 40 {
            dialog.hidden = !dialog.hidden;
            crate::serial_println!("[PROPERTIES] Hidden toggled: {}", dialog.hidden);
            return true;
        }

        // Check buttons (OK, Cancel, Apply)
        let button_y = PROPERTIES_HEIGHT - 40;
        let button_spacing = BUTTON_WIDTH + 10;
        let buttons_start_x = PROPERTIES_WIDTH - 3 * button_spacing - 10;

        for (i, _label) in ["OK", "Cancel", "Apply"].iter().enumerate() {
            let btn_x = buttons_start_x + i as i32 * button_spacing;
            if rel_x >= btn_x && rel_x < btn_x + BUTTON_WIDTH &&
               rel_y >= button_y && rel_y < button_y + BUTTON_HEIGHT {
                match i {
                    0 => {
                        // OK - apply and close
                        crate::serial_println!("[PROPERTIES] OK clicked");
                        dialog.active = false;
                        dialog.visible = false;
                    }
                    1 => {
                        // Cancel - close without saving
                        crate::serial_println!("[PROPERTIES] Cancel clicked");
                        dialog.active = false;
                        dialog.visible = false;
                    }
                    2 => {
                        // Apply - apply without closing
                        crate::serial_println!("[PROPERTIES] Apply clicked");
                    }
                    _ => {}
                }
                return true;
            }
        }

        // Click was in dialog but not on any control
        return true;
    }

    false
}

/// Handle mouse move for button hover effects
pub fn handle_mouse_move(x: i32, y: i32) {
    let mut dialogs = PROPERTIES_DIALOGS.lock();

    for dialog in dialogs.iter_mut() {
        if !dialog.active || !dialog.visible {
            continue;
        }

        if x < dialog.x || x >= dialog.x + PROPERTIES_WIDTH ||
           y < dialog.y || y >= dialog.y + PROPERTIES_HEIGHT {
            dialog.hover_button = 0;
            continue;
        }

        let rel_x = x - dialog.x;
        let rel_y = y - dialog.y;

        let button_y = PROPERTIES_HEIGHT - 40;
        let button_spacing = BUTTON_WIDTH + 10;
        let buttons_start_x = PROPERTIES_WIDTH - 3 * button_spacing - 10;

        dialog.hover_button = 0;
        for i in 0..3 {
            let btn_x = buttons_start_x + i as i32 * button_spacing;
            if rel_x >= btn_x && rel_x < btn_x + BUTTON_WIDTH &&
               rel_y >= button_y && rel_y < button_y + BUTTON_HEIGHT {
                dialog.hover_button = (i + 1) as u8;
                break;
            }
        }
    }
}

// ============================================================================
// Painting
// ============================================================================

/// Paint all visible properties dialogs
pub fn paint_all() {
    let dialogs = PROPERTIES_DIALOGS.lock();

    for dialog in dialogs.iter() {
        if dialog.active && dialog.visible {
            paint_dialog(dialog);
        }
    }
}

fn paint_dialog(dialog: &PropertiesDialog) {
    let surface_handle = surface::get_display_surface();
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let hdc = match dc::create_display_dc() {
        Ok(h) => h,
        Err(_) => return,
    };
    let x = dialog.x;
    let y = dialog.y;

    // Dialog background
    let bg_rect = Rect::new(x, y, x + PROPERTIES_WIDTH, y + PROPERTIES_HEIGHT);
    surf.fill_rect(&bg_rect, COLOR_DIALOG_BG);

    // Dialog border (3D effect)
    draw_3d_border(&surf, x, y, PROPERTIES_WIDTH, PROPERTIES_HEIGHT);

    // Title bar
    let title_rect = Rect::new(x + 2, y + 2, x + PROPERTIES_WIDTH - 2, y + 26);
    surf.fill_rect(&title_rect, ColorRef::rgb(0, 84, 227)); // XP blue

    // Title text
    dc::set_text_color(hdc, ColorRef::WHITE);
    dc::set_bk_mode(hdc, BkMode::Transparent);
    let (title_buf, title_len) = format_title(dialog.name_str());
    let title_str = core::str::from_utf8(&title_buf[..title_len]).unwrap_or("Properties");
    gdi::text_out(hdc, x + 8, y + 6, title_str);

    // Close button (X)
    let close_x = x + PROPERTIES_WIDTH - 25;
    let close_y = y + 5;
    draw_close_button(&surf, close_x, close_y);

    // Tab area (just "General" for now)
    dc::set_text_color(hdc, COLOR_LABEL);
    let tab_rect = Rect::new(x + 10, y + 35, x + 80, y + 55);
    surf.fill_rect(&tab_rect, COLOR_DIALOG_BG);
    surf.hline(x + 10, x + 80, y + 55, COLOR_SEPARATOR);
    gdi::text_out(hdc, x + 20, y + 40, "General");

    // Content area
    let content_y = y + 65;

    // Large icon area
    let icon_rect = Rect::new(x + 20, content_y, x + 70, content_y + 50);
    surf.fill_rect(&icon_rect, COLOR_ICON_BG);
    draw_3d_border_inset(&surf, x + 20, content_y, 50, 50);
    draw_large_icon(&surf, x + 27, content_y + 7, dialog);

    // File name (editable field appearance)
    let name_rect = Rect::new(x + 85, content_y + 10, x + PROPERTIES_WIDTH - 20, content_y + 32);
    surf.fill_rect(&name_rect, ColorRef::WHITE);
    draw_3d_border_inset(&surf, x + 85, content_y + 10, PROPERTIES_WIDTH - 105, 22);
    dc::set_text_color(hdc, COLOR_VALUE);
    gdi::text_out(hdc, x + 90, content_y + 14, dialog.name_str());

    // Separator line
    let sep_y = content_y + 60;
    surf.hline(x + 15, x + PROPERTIES_WIDTH - 15, sep_y, COLOR_SEPARATOR);

    // Property rows
    let mut row_y = sep_y + 15;
    dc::set_text_color(hdc, COLOR_LABEL);

    // Type
    gdi::text_out(hdc, x + 20, row_y, "Type:");
    dc::set_text_color(hdc, COLOR_VALUE);
    gdi::text_out(hdc, x + VALUE_X, row_y, dialog.get_type_name());
    row_y += ROW_HEIGHT;

    // Location
    dc::set_text_color(hdc, COLOR_LABEL);
    gdi::text_out(hdc, x + 20, row_y, "Location:");
    dc::set_text_color(hdc, COLOR_VALUE);
    let location = dialog.get_location();
    let display_loc = if location.len() > 35 { &location[..35] } else { location };
    gdi::text_out(hdc, x + VALUE_X, row_y, display_loc);
    row_y += ROW_HEIGHT;

    // Size
    dc::set_text_color(hdc, COLOR_LABEL);
    gdi::text_out(hdc, x + 20, row_y, "Size:");
    dc::set_text_color(hdc, COLOR_VALUE);
    let mut size_buf = [0u8; 64];
    let size_len = dialog.format_size(&mut size_buf);
    let size_str = core::str::from_utf8(&size_buf[..size_len]).unwrap_or("");
    gdi::text_out(hdc, x + VALUE_X, row_y, size_str);
    row_y += ROW_HEIGHT;

    // Size on disk
    dc::set_text_color(hdc, COLOR_LABEL);
    gdi::text_out(hdc, x + 20, row_y, "Size on disk:");
    dc::set_text_color(hdc, COLOR_VALUE);
    gdi::text_out(hdc, x + VALUE_X, row_y, size_str); // Same as size for now
    row_y += ROW_HEIGHT + 10;

    // Another separator
    surf.hline(x + 15, x + PROPERTIES_WIDTH - 15, row_y, COLOR_SEPARATOR);
    row_y += 15;

    // Created
    dc::set_text_color(hdc, COLOR_LABEL);
    gdi::text_out(hdc, x + 20, row_y, "Created:");
    dc::set_text_color(hdc, COLOR_VALUE);
    gdi::text_out(hdc, x + VALUE_X, row_y, "January 1, 2003");
    row_y += ROW_HEIGHT;

    // Modified
    dc::set_text_color(hdc, COLOR_LABEL);
    gdi::text_out(hdc, x + 20, row_y, "Modified:");
    dc::set_text_color(hdc, COLOR_VALUE);
    gdi::text_out(hdc, x + VALUE_X, row_y, "January 1, 2003");
    row_y += ROW_HEIGHT;

    // Accessed
    dc::set_text_color(hdc, COLOR_LABEL);
    gdi::text_out(hdc, x + 20, row_y, "Accessed:");
    dc::set_text_color(hdc, COLOR_VALUE);
    gdi::text_out(hdc, x + VALUE_X, row_y, "January 1, 2003");
    row_y += ROW_HEIGHT + 10;

    // Separator before attributes
    surf.hline(x + 15, x + PROPERTIES_WIDTH - 15, row_y, COLOR_SEPARATOR);
    row_y += 15;

    // Attributes section
    dc::set_text_color(hdc, COLOR_LABEL);
    gdi::text_out(hdc, x + 20, row_y, "Attributes:");

    // Read-only checkbox
    let checkbox_y = row_y + ROW_HEIGHT;
    draw_checkbox(&surf, x + 20, checkbox_y, dialog.readonly);
    gdi::text_out(hdc, x + 42, checkbox_y, "Read-only");

    // Hidden checkbox
    draw_checkbox(&surf, x + 20, checkbox_y + 24, dialog.hidden);
    gdi::text_out(hdc, x + 42, checkbox_y + 24, "Hidden");

    // Advanced button (placeholder)
    let adv_x = x + 180;
    draw_button(&surf, hdc, adv_x, checkbox_y + 8, 90, BUTTON_HEIGHT, "Advanced...", false);

    // Bottom buttons (OK, Cancel, Apply)
    let button_y = y + PROPERTIES_HEIGHT - 40;
    let button_spacing = BUTTON_WIDTH + 10;
    let buttons_start_x = x + PROPERTIES_WIDTH - 3 * button_spacing - 10;

    for (i, label) in ["OK", "Cancel", "Apply"].iter().enumerate() {
        let btn_x = buttons_start_x + i as i32 * button_spacing;
        let hover = dialog.hover_button == (i + 1) as u8;
        draw_button(&surf, hdc, btn_x, button_y, BUTTON_WIDTH, BUTTON_HEIGHT, label, hover);
    }

    dc::delete_dc(hdc);
}

fn format_title(name: &str) -> ([u8; 64], usize) {
    let mut buf = [0u8; 64];
    let suffix = b" Properties";
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(64 - suffix.len());

    buf[..name_len].copy_from_slice(&name_bytes[..name_len]);
    let suffix_len = suffix.len().min(64 - name_len);
    buf[name_len..name_len + suffix_len].copy_from_slice(&suffix[..suffix_len]);

    (buf, name_len + suffix_len)
}

fn draw_3d_border(surf: &surface::Surface, x: i32, y: i32, w: i32, h: i32) {
    // Outer highlight (top, left)
    surf.hline(x, x + w, y, ColorRef::WHITE);
    surf.vline(x, y, y + h, ColorRef::WHITE);

    // Outer shadow (bottom, right)
    surf.hline(x, x + w, y + h - 1, ColorRef::rgb(64, 64, 64));
    surf.vline(x + w - 1, y, y + h, ColorRef::rgb(64, 64, 64));

    // Inner border
    surf.hline(x + 1, x + w - 1, y + 1, ColorRef::rgb(212, 208, 200));
    surf.vline(x + 1, y + 1, y + h - 1, ColorRef::rgb(212, 208, 200));
    surf.hline(x + 1, x + w - 1, y + h - 2, ColorRef::rgb(128, 128, 128));
    surf.vline(x + w - 2, y + 1, y + h - 1, ColorRef::rgb(128, 128, 128));
}

fn draw_3d_border_inset(surf: &surface::Surface, x: i32, y: i32, w: i32, h: i32) {
    // Shadow (top, left)
    surf.hline(x, x + w, y, ColorRef::rgb(128, 128, 128));
    surf.vline(x, y, y + h, ColorRef::rgb(128, 128, 128));

    // Highlight (bottom, right)
    surf.hline(x, x + w, y + h - 1, ColorRef::WHITE);
    surf.vline(x + w - 1, y, y + h, ColorRef::WHITE);
}

fn draw_close_button(surf: &surface::Surface, x: i32, y: i32) {
    let btn_rect = Rect::new(x, y, x + 20, y + 20);
    surf.fill_rect(&btn_rect, ColorRef::rgb(200, 80, 80));

    // X mark
    let cx = x + 10;
    let cy = y + 10;
    for i in -4..=4 {
        surf.set_pixel(cx + i, cy + i, ColorRef::WHITE);
        surf.set_pixel(cx + i + 1, cy + i, ColorRef::WHITE);
        surf.set_pixel(cx + i, cy - i, ColorRef::WHITE);
        surf.set_pixel(cx + i + 1, cy - i, ColorRef::WHITE);
    }
}

fn draw_checkbox(surf: &surface::Surface, x: i32, y: i32, checked: bool) {
    let box_rect = Rect::new(x, y, x + 16, y + 16);
    surf.fill_rect(&box_rect, COLOR_CHECKBOX_BG);
    draw_3d_border_inset(surf, x, y, 16, 16);

    if checked {
        // Draw check mark
        for i in 0..4 {
            surf.set_pixel(x + 4 + i, y + 8 + i, COLOR_CHECK_MARK);
            surf.set_pixel(x + 5 + i, y + 8 + i, COLOR_CHECK_MARK);
        }
        for i in 0..6 {
            surf.set_pixel(x + 7 + i, y + 11 - i, COLOR_CHECK_MARK);
            surf.set_pixel(x + 8 + i, y + 11 - i, COLOR_CHECK_MARK);
        }
    }
}

fn draw_button(surf: &surface::Surface, hdc: HDC, x: i32, y: i32, w: i32, h: i32, label: &str, hover: bool) {
    let bg = if hover {
        ColorRef::rgb(220, 220, 220)
    } else {
        COLOR_BUTTON_BG
    };

    let btn_rect = Rect::new(x, y, x + w, y + h);
    surf.fill_rect(&btn_rect, bg);

    // 3D border
    surf.hline(x, x + w, y, ColorRef::WHITE);
    surf.vline(x, y, y + h, ColorRef::WHITE);
    surf.hline(x, x + w, y + h - 1, ColorRef::rgb(64, 64, 64));
    surf.vline(x + w - 1, y, y + h, ColorRef::rgb(64, 64, 64));
    surf.hline(x + 1, x + w - 1, y + h - 2, ColorRef::rgb(128, 128, 128));
    surf.vline(x + w - 2, y + 1, y + h - 1, ColorRef::rgb(128, 128, 128));

    // Label (centered)
    dc::set_text_color(hdc, COLOR_LABEL);
    let text_x = x + (w - label.len() as i32 * 7) / 2;
    let text_y = y + (h - 14) / 2;
    gdi::text_out(hdc, text_x, text_y, label);
}

fn draw_large_icon(surf: &surface::Surface, x: i32, y: i32, dialog: &PropertiesDialog) {
    let size = 36;

    if dialog.is_directory {
        // Folder icon
        let folder_color = ColorRef::rgb(255, 210, 80);
        let folder_dark = ColorRef::rgb(200, 170, 60);

        let body_top = y + size / 5;
        let body = Rect::new(x + 2, body_top, x + size - 2, y + size - 2);
        surf.fill_rect(&body, folder_color);

        let tab_width = size / 2;
        let tab = Rect::new(x + 2, y + 2, x + 2 + tab_width, body_top + 2);
        surf.fill_rect(&tab, folder_color);

        surf.hline(x + 2, x + size - 2, body_top, ColorRef::rgb(255, 230, 150));
        surf.hline(x + 2, x + size - 2, y + size - 3, folder_dark);
        surf.vline(x + size - 3, body_top, y + size - 2, folder_dark);
    } else {
        // Document icon
        let body = Rect::new(x + 4, y + 2, x + size - 4, y + size - 2);
        surf.fill_rect(&body, ColorRef::WHITE);

        // Corner fold
        let fold = Rect::new(x + size - 12, y + 2, x + size - 4, y + 10);
        surf.fill_rect(&fold, ColorRef::rgb(200, 200, 200));

        // Border
        surf.hline(x + 4, x + size - 12, y + 2, ColorRef::rgb(128, 128, 128));
        surf.vline(x + 4, y + 2, y + size - 2, ColorRef::rgb(128, 128, 128));
        surf.hline(x + 4, x + size - 4, y + size - 3, ColorRef::rgb(128, 128, 128));
        surf.vline(x + size - 5, y + 10, y + size - 2, ColorRef::rgb(128, 128, 128));

        // Type indicator bar
        let color = match dialog.icon_type {
            VfsIconType::Executable => ColorRef::rgb(100, 200, 100),
            VfsIconType::Image => ColorRef::rgb(100, 150, 255),
            VfsIconType::Audio => ColorRef::rgb(150, 100, 200),
            VfsIconType::Video => ColorRef::rgb(200, 150, 100),
            VfsIconType::Document => ColorRef::rgb(200, 200, 200),
            _ => ColorRef::rgb(180, 180, 180),
        };
        let bar = Rect::new(x + 6, y + 14, x + size - 8, y + 18);
        surf.fill_rect(&bar, color);
    }
}
