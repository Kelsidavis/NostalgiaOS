//! Desktop Host (Desktop Window)
//!
//! This module implements CDesktopHost - the desktop window that hosts
//! the icon view and handles desktop interactions.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/explorer/desktop2/deskhost.cpp`
//! - `shell/explorer/desktop2/deskhost.h`
//! - `shell/shell32/unicpp/desktop.cpp`

use core::sync::atomic::{AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::super::{HWND, HDC, Rect, Point, ColorRef};
use super::super::super::gdi::{dc, brush};
use super::super::{window, controls, WindowStyle, WindowStyleEx};
use super::tray::TASKBAR_HEIGHT;

// ============================================================================
// Constants
// ============================================================================

/// Desktop icon size (32x32 pixels)
const ICON_SIZE: i32 = 32;

/// Grid cell spacing - matches Windows XP (SM_CXICONSPACING, SM_CYICONSPACING)
const ICON_GRID_X: i32 = 75;
const ICON_GRID_Y: i32 = 75;

/// Margin from desktop edges
const ICON_MARGIN_X: i32 = 10;
const ICON_MARGIN_Y: i32 = 10;

/// Maximum desktop icons
const MAX_DESKTOP_ICONS: usize = 64;

/// Menu dimensions
const MENU_ITEM_HEIGHT: i32 = 20;
const MENU_WIDTH: i32 = 150;

// ============================================================================
// Icon Types
// ============================================================================

/// Icon types for different desktop items
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IconType {
    MyComputer,
    RecycleBin,
    MyDocuments,
    NetworkPlaces,
}

// ============================================================================
// Desktop Icon Instance
// ============================================================================

/// Desktop icon with position
#[derive(Clone, Copy)]
struct DesktopIcon {
    valid: bool,
    name: &'static str,
    icon_type: IconType,
    grid_x: i32,
    grid_y: i32,
}

impl DesktopIcon {
    const fn empty() -> Self {
        Self {
            valid: false,
            name: "",
            icon_type: IconType::MyComputer,
            grid_x: 0,
            grid_y: 0,
        }
    }

    fn get_pixel_pos(&self) -> (i32, i32) {
        let px = ICON_MARGIN_X + self.grid_x * ICON_GRID_X + (ICON_GRID_X - ICON_SIZE) / 2;
        let py = ICON_MARGIN_Y + self.grid_y * ICON_GRID_Y;
        (px, py)
    }

    fn get_bounds(&self) -> Rect {
        let (px, py) = self.get_pixel_pos();
        Rect::new(px - 10, py - 2, px + ICON_SIZE + 10, py + ICON_SIZE + 20)
    }
}

// ============================================================================
// Desktop State (CDesktopHost equivalent)
// ============================================================================

struct CDesktopHost {
    hwnd: HWND,
    icons: [DesktopIcon; MAX_DESKTOP_ICONS],
    icon_count: usize,
    selected: Option<usize>,
    dragging: Option<usize>,
    drag_start_mouse: Point,
    drag_start_grid: (i32, i32),
}

impl CDesktopHost {
    const fn new() -> Self {
        Self {
            hwnd: HWND::NULL,
            icons: [const { DesktopIcon::empty() }; MAX_DESKTOP_ICONS],
            icon_count: 0,
            selected: None,
            dragging: None,
            drag_start_mouse: Point::new(0, 0),
            drag_start_grid: (0, 0),
        }
    }
}

static DESKTOP_HOST: SpinLock<CDesktopHost> = SpinLock::new(CDesktopHost::new());

// ============================================================================
// Context Menu State
// ============================================================================

/// Desktop background context menu items
const DESKTOP_MENU_ITEMS: [&str; 6] = [
    "Refresh",
    "─────────────",
    "Paste",
    "Paste Shortcut",
    "─────────────",
    "Properties",
];

/// Icon context menu items
const ICON_MENU_ITEMS: [&str; 7] = [
    "Open",
    "Explore",
    "─────────────",
    "Cut",
    "Copy",
    "─────────────",
    "Properties",
];

static DESKTOP_MENU_VISIBLE: AtomicBool = AtomicBool::new(false);
static DESKTOP_MENU_POS: SpinLock<Point> = SpinLock::new(Point::new(0, 0));

static ICON_MENU_VISIBLE: AtomicBool = AtomicBool::new(false);
static ICON_MENU_POS: SpinLock<Point> = SpinLock::new(Point::new(0, 0));
static ICON_MENU_TARGET: SpinLock<Option<usize>> = SpinLock::new(None);

// ============================================================================
// Initialization
// ============================================================================

/// Create the desktop window
pub fn create_desktop(rect: Rect) {
    let hwnd = window::create_window(
        "Progman",
        "Program Manager",
        WindowStyle::POPUP | WindowStyle::VISIBLE,
        WindowStyleEx::empty(),
        rect.left, rect.top,
        rect.right - rect.left, rect.bottom - rect.top,
        super::super::super::HWND::NULL,
        0, // menu
    );

    let mut host = DESKTOP_HOST.lock();
    host.hwnd = hwnd;

    // Initialize default icons
    let default_icons = [
        ("My Computer", IconType::MyComputer, 0, 0),
        ("My Documents", IconType::MyDocuments, 0, 1),
        ("Recycle Bin", IconType::RecycleBin, 0, 2),
        ("Network Places", IconType::NetworkPlaces, 0, 3),
    ];

    for (i, (name, icon_type, gx, gy)) in default_icons.iter().enumerate() {
        host.icons[i] = DesktopIcon {
            valid: true,
            name,
            icon_type: *icon_type,
            grid_x: *gx,
            grid_y: *gy,
        };
    }
    host.icon_count = default_icons.len();

    crate::serial_println!("[DESKTOP] Desktop created: hwnd={:#x}", hwnd.raw());
}

/// Get the desktop window handle
pub fn get_desktop_hwnd() -> HWND {
    DESKTOP_HOST.lock().hwnd
}

// ============================================================================
// Icon Management
// ============================================================================

/// Get icon at position
pub fn get_icon_at_position(x: i32, y: i32) -> Option<usize> {
    // Check if on desktop (not on another window)
    let hwnd = window::window_from_point(Point::new(x, y));
    let desktop_hwnd = DESKTOP_HOST.lock().hwnd;
    let system_desktop = window::get_desktop_window();

    if hwnd.is_valid() && hwnd != desktop_hwnd && hwnd != system_desktop {
        return None;
    }

    let host = DESKTOP_HOST.lock();
    for (idx, icon) in host.icons.iter().enumerate() {
        if !icon.valid {
            continue;
        }
        let bounds = icon.get_bounds();
        if x >= bounds.left && x < bounds.right && y >= bounds.top && y < bounds.bottom {
            return Some(idx);
        }
    }
    None
}

/// Select an icon
pub fn select_icon(idx: Option<usize>) {
    let current = DESKTOP_HOST.lock().selected;
    if current != idx {
        DESKTOP_HOST.lock().selected = idx;
        paint_desktop();
    }
}

/// Start dragging an icon
pub fn start_icon_drag(icon_idx: usize, mouse_x: i32, mouse_y: i32) {
    let mut host = DESKTOP_HOST.lock();
    if icon_idx < MAX_DESKTOP_ICONS && host.icons[icon_idx].valid {
        host.dragging = Some(icon_idx);
        host.selected = Some(icon_idx);
        host.drag_start_mouse = Point::new(mouse_x, mouse_y);
        host.drag_start_grid = (host.icons[icon_idx].grid_x, host.icons[icon_idx].grid_y);
    }
}

/// Update icon drag position
pub fn update_icon_drag(mouse_x: i32, mouse_y: i32) {
    let dragging = DESKTOP_HOST.lock().dragging;

    if let Some(idx) = dragging {
        let (new_gx, new_gy) = snap_to_grid(mouse_x - ICON_SIZE / 2, mouse_y - ICON_SIZE / 2);

        let mut host = DESKTOP_HOST.lock();
        if host.icons[idx].valid {
            let old_gx = host.icons[idx].grid_x;
            let old_gy = host.icons[idx].grid_y;

            if new_gx != old_gx || new_gy != old_gy {
                host.icons[idx].grid_x = new_gx;
                host.icons[idx].grid_y = new_gy;
                drop(host);
                paint_desktop();
            }
        }
    }
}

/// End icon drag
pub fn end_icon_drag() {
    let mut needs_repaint = false;

    {
        let mut host = DESKTOP_HOST.lock();
        if let Some(idx) = host.dragging {
            if host.icons[idx].valid {
                let gx = host.icons[idx].grid_x;
                let gy = host.icons[idx].grid_y;
                let (final_gx, final_gy) = find_free_grid_pos(&host, gx, gy, Some(idx));
                host.icons[idx].grid_x = final_gx;
                host.icons[idx].grid_y = final_gy;
            }
            host.dragging = None;
            needs_repaint = true;
        }
    }

    if needs_repaint {
        paint_desktop();
    }
}

/// Check if icon is being dragged
pub fn is_icon_dragging() -> bool {
    DESKTOP_HOST.lock().dragging.is_some()
}

/// Handle icon double-click
pub fn handle_icon_double_click(icon_idx: usize) {
    let icon_info = {
        let host = DESKTOP_HOST.lock();
        if icon_idx < MAX_DESKTOP_ICONS && host.icons[icon_idx].valid {
            Some((host.icons[icon_idx].name, host.icons[icon_idx].icon_type))
        } else {
            None
        }
    };

    if let Some((name, icon_type)) = icon_info {
        crate::serial_println!("[DESKTOP] Opening: {}", name);

        match icon_type {
            IconType::MyComputer => {
                create_explorer_window("My Computer", "C:\\ D:\\ E:\\");
            }
            IconType::RecycleBin => {
                create_explorer_window("Recycle Bin", "Empty");
            }
            IconType::MyDocuments => {
                create_explorer_window("My Documents", "Your documents");
            }
            IconType::NetworkPlaces => {
                create_explorer_window("Network Places", "Network resources");
            }
        }
    }
}

fn create_explorer_window(title: &str, _content: &str) {
    let hwnd = window::create_window(
        "CabinetWClass",
        title,
        WindowStyle::OVERLAPPEDWINDOW | WindowStyle::VISIBLE,
        WindowStyleEx::empty(),
        200, 100, 400, 300,
        super::super::super::HWND::NULL,
        0, // menu
    );
    window::show_window(hwnd, super::super::ShowCommand::Show);
}

// ============================================================================
// Grid Helpers
// ============================================================================

fn snap_to_grid(px: i32, py: i32) -> (i32, i32) {
    let gx = ((px - ICON_MARGIN_X + ICON_GRID_X / 2) / ICON_GRID_X).max(0);
    let gy = ((py - ICON_MARGIN_Y + ICON_GRID_Y / 2) / ICON_GRID_Y).max(0);

    let (width, height) = super::super::super::gdi::surface::get_primary_dimensions();
    let max_gx = ((width as i32 - ICON_MARGIN_X * 2) / ICON_GRID_X).max(0);
    let max_gy = ((height as i32 - TASKBAR_HEIGHT - ICON_MARGIN_Y * 2) / ICON_GRID_Y).max(0);

    (gx.min(max_gx), gy.min(max_gy))
}

fn find_free_grid_pos(host: &CDesktopHost, preferred_gx: i32, preferred_gy: i32, exclude_idx: Option<usize>) -> (i32, i32) {
    if !is_grid_occupied(host, preferred_gx, preferred_gy, exclude_idx) {
        return (preferred_gx, preferred_gy);
    }

    let (width, height) = super::super::super::gdi::surface::get_primary_dimensions();
    let max_gx = ((width as i32 - ICON_MARGIN_X * 2) / ICON_GRID_X).max(0);
    let max_gy = ((height as i32 - TASKBAR_HEIGHT - ICON_MARGIN_Y * 2) / ICON_GRID_Y).max(0);

    for radius in 1i32..20 {
        for dy in -radius..=radius {
            for dx in -radius..=radius {
                if dx.abs() != radius && dy.abs() != radius {
                    continue;
                }
                let gx = preferred_gx + dx;
                let gy = preferred_gy + dy;
                if gx >= 0 && gx <= max_gx && gy >= 0 && gy <= max_gy {
                    if !is_grid_occupied(host, gx, gy, exclude_idx) {
                        return (gx, gy);
                    }
                }
            }
        }
    }

    (preferred_gx, preferred_gy)
}

fn is_grid_occupied(host: &CDesktopHost, gx: i32, gy: i32, exclude_idx: Option<usize>) -> bool {
    for (i, icon) in host.icons.iter().enumerate() {
        if !icon.valid {
            continue;
        }
        if let Some(exclude) = exclude_idx {
            if i == exclude {
                continue;
            }
        }
        if icon.grid_x == gx && icon.grid_y == gy {
            return true;
        }
    }
    false
}

// ============================================================================
// Context Menus
// ============================================================================

pub fn is_context_menu_visible() -> bool {
    DESKTOP_MENU_VISIBLE.load(Ordering::SeqCst) || ICON_MENU_VISIBLE.load(Ordering::SeqCst)
}

pub fn is_desktop_menu_visible() -> bool {
    DESKTOP_MENU_VISIBLE.load(Ordering::SeqCst)
}

pub fn is_icon_menu_visible() -> bool {
    ICON_MENU_VISIBLE.load(Ordering::SeqCst)
}

pub fn show_desktop_context_menu(x: i32, y: i32) {
    hide_icon_context_menu();
    super::startmenu::hide();

    *DESKTOP_MENU_POS.lock() = Point::new(x, y);
    DESKTOP_MENU_VISIBLE.store(true, Ordering::SeqCst);
    paint_context_menu(x, y, &DESKTOP_MENU_ITEMS);
}

pub fn show_icon_context_menu(x: i32, y: i32, icon_idx: usize) {
    hide_desktop_context_menu();
    super::startmenu::hide();

    *ICON_MENU_POS.lock() = Point::new(x, y);
    *ICON_MENU_TARGET.lock() = Some(icon_idx);
    ICON_MENU_VISIBLE.store(true, Ordering::SeqCst);
    paint_context_menu(x, y, &ICON_MENU_ITEMS);
}

fn paint_context_menu(x: i32, y: i32, items: &[&str]) {
    if let Ok(hdc) = dc::create_display_dc() {
        let menu_height = (items.len() as i32) * MENU_ITEM_HEIGHT + 4;
        let menu_rect = Rect::new(x, y, x + MENU_WIDTH, y + menu_height);

        if let Some(surf) = super::super::super::gdi::surface::get_surface(dc::get_dc_surface(hdc)) {
            // Background
            surf.fill_rect(&menu_rect, ColorRef::WINDOW_BG);

            // 3D border
            surf.hline(menu_rect.left, menu_rect.right - 1, menu_rect.top, ColorRef::WHITE);
            surf.vline(menu_rect.left, menu_rect.top, menu_rect.bottom - 1, ColorRef::WHITE);
            surf.hline(menu_rect.left, menu_rect.right, menu_rect.bottom - 1, ColorRef::DARK_GRAY);
            surf.vline(menu_rect.right - 1, menu_rect.top, menu_rect.bottom, ColorRef::DARK_GRAY);

            // Items
            let mut item_y = y + 2;
            for (i, item) in items.iter().enumerate() {
                if item.starts_with('─') {
                    let sep_y = item_y + MENU_ITEM_HEIGHT / 2;
                    surf.hline(x + 2, x + MENU_WIDTH - 2, sep_y, ColorRef::GRAY);
                    surf.hline(x + 2, x + MENU_WIDTH - 2, sep_y + 1, ColorRef::WHITE);
                } else {
                    dc::set_text_color(hdc, ColorRef::BLACK);
                    if i == 0 && items.as_ptr() == ICON_MENU_ITEMS.as_ptr() {
                        // Bold first item for icon menu
                        super::super::super::gdi::draw::gdi_text_out(hdc, x + 20, item_y + 2, item);
                        super::super::super::gdi::draw::gdi_text_out(hdc, x + 21, item_y + 2, item);
                    } else {
                        super::super::super::gdi::draw::gdi_text_out(hdc, x + 20, item_y + 2, item);
                    }
                }
                item_y += MENU_ITEM_HEIGHT;
            }
        }
        dc::delete_dc(hdc);
    }
}

pub fn handle_desktop_menu_click(x: i32, y: i32) -> bool {
    if !DESKTOP_MENU_VISIBLE.load(Ordering::SeqCst) {
        return false;
    }

    let menu_pos = *DESKTOP_MENU_POS.lock();
    let menu_height = (DESKTOP_MENU_ITEMS.len() as i32) * MENU_ITEM_HEIGHT + 4;
    let menu_rect = Rect::new(menu_pos.x, menu_pos.y, menu_pos.x + MENU_WIDTH, menu_pos.y + menu_height);

    if x >= menu_rect.left && x < menu_rect.right && y >= menu_rect.top && y < menu_rect.bottom {
        let item_index = ((y - menu_rect.top - 2) / MENU_ITEM_HEIGHT) as usize;
        if item_index < DESKTOP_MENU_ITEMS.len() {
            let item = DESKTOP_MENU_ITEMS[item_index];
            if !item.starts_with('─') {
                match item {
                    "Refresh" => {
                        super::super::paint::repaint_all();
                        super::paint_taskbar();
                    }
                    _ => {}
                }
            }
        }
        hide_desktop_context_menu();
        return true;
    }

    hide_desktop_context_menu();
    false
}

pub fn handle_icon_menu_click(x: i32, y: i32) -> bool {
    if !ICON_MENU_VISIBLE.load(Ordering::SeqCst) {
        return false;
    }

    let menu_pos = *ICON_MENU_POS.lock();
    let target_icon = *ICON_MENU_TARGET.lock();
    let menu_height = (ICON_MENU_ITEMS.len() as i32) * MENU_ITEM_HEIGHT + 4;
    let menu_rect = Rect::new(menu_pos.x, menu_pos.y, menu_pos.x + MENU_WIDTH, menu_pos.y + menu_height);

    if x >= menu_rect.left && x < menu_rect.right && y >= menu_rect.top && y < menu_rect.bottom {
        let item_index = ((y - menu_rect.top - 2) / MENU_ITEM_HEIGHT) as usize;
        if item_index < ICON_MENU_ITEMS.len() {
            let item = ICON_MENU_ITEMS[item_index];
            if !item.starts_with('─') {
                match item {
                    "Open" | "Explore" => {
                        if let Some(idx) = target_icon {
                            handle_icon_double_click(idx);
                        }
                    }
                    _ => {}
                }
            }
        }
        hide_icon_context_menu();
        return true;
    }

    hide_icon_context_menu();
    false
}

fn hide_desktop_context_menu() {
    if DESKTOP_MENU_VISIBLE.load(Ordering::SeqCst) {
        DESKTOP_MENU_VISIBLE.store(false, Ordering::SeqCst);
        super::super::cursor::invalidate_cursor_background();
        super::super::paint::repaint_all();
        super::paint_taskbar();
        super::super::cursor::draw_cursor();
    }
}

fn hide_icon_context_menu() {
    if ICON_MENU_VISIBLE.load(Ordering::SeqCst) {
        ICON_MENU_VISIBLE.store(false, Ordering::SeqCst);
        *ICON_MENU_TARGET.lock() = None;
        super::super::cursor::invalidate_cursor_background();
        super::super::paint::repaint_all();
        super::paint_taskbar();
        super::super::cursor::draw_cursor();
    }
}

// ============================================================================
// Painting
// ============================================================================

/// Paint the desktop
pub fn paint_desktop() {
    if let Ok(hdc) = dc::create_display_dc() {
        paint_desktop_background(hdc);
        paint_desktop_icons(hdc);
        dc::delete_dc(hdc);
    }
}

/// Paint only the desktop icons (used by repaint_all)
pub fn paint_icons_only() {
    if let Ok(hdc) = dc::create_display_dc() {
        paint_desktop_icons(hdc);
        dc::delete_dc(hdc);
    }
}

fn paint_desktop_background(hdc: HDC) {
    let (width, height) = super::super::super::gdi::surface::get_primary_dimensions();
    let desktop_rect = Rect::new(0, 0, width as i32, height as i32 - super::tray::TASKBAR_HEIGHT);

    // Use system desktop color
    let color = super::super::desktop::get_desktop_color();
    let bg_brush = brush::create_solid_brush(color);
    super::super::super::gdi::fill_rect(hdc, &desktop_rect, bg_brush);
}

fn paint_desktop_icons(hdc: HDC) {
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match super::super::super::gdi::surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let host = DESKTOP_HOST.lock();
    let selected = host.selected;
    let dragging = host.dragging;

    for (idx, icon) in host.icons.iter().enumerate() {
        if !icon.valid {
            continue;
        }

        let (x, y) = icon.get_pixel_pos();
        let is_selected = selected == Some(idx);
        let is_dragging = dragging == Some(idx);

        // Selection highlight
        if is_selected {
            let highlight_rect = Rect::new(x - 4, y - 2, x + ICON_SIZE + 4, y + ICON_SIZE + 20);
            surf.fill_rect(&highlight_rect, ColorRef::rgb(0, 84, 227));
        }

        if is_dragging {
            continue;
        }

        // Draw icon
        draw_icon(&surf, x, y, icon.icon_type);

        // Draw label
        let label_x = x + ICON_SIZE / 2;
        let label_y = y + ICON_SIZE + 4;
        draw_icon_label(&surf, label_x, label_y, icon.name, is_selected);
    }
}

fn draw_icon(surf: &super::super::super::gdi::surface::Surface, x: i32, y: i32, icon_type: IconType) {
    use super::super::desktop_icons::*;

    let (width, height, data) = match icon_type {
        IconType::MyComputer => (MY_COMPUTER_WIDTH, MY_COMPUTER_HEIGHT, &MY_COMPUTER_DATA[..]),
        IconType::RecycleBin => (RECYCLE_BIN_WIDTH, RECYCLE_BIN_HEIGHT, &RECYCLE_BIN_DATA[..]),
        IconType::MyDocuments => (MY_DOCUMENTS_WIDTH, MY_DOCUMENTS_HEIGHT, &MY_DOCUMENTS_DATA[..]),
        IconType::NetworkPlaces => (NETWORK_PLACES_WIDTH, NETWORK_PLACES_HEIGHT, &NETWORK_PLACES_DATA[..]),
    };

    for row in 0..height {
        for col in 0..width {
            let offset = (row * width + col) * 4;
            let r = data[offset];
            let g = data[offset + 1];
            let b = data[offset + 2];
            let a = data[offset + 3];

            if a == 0 {
                continue;
            }

            let px = x + col as i32;
            let py = y + row as i32;

            if a == 255 {
                surf.set_pixel(px, py, ColorRef::rgb(r, g, b));
            } else {
                let bg_r = 0u8;
                let bg_g = 128u8;
                let bg_b = 128u8;
                let blended_r = ((r as u16 * a as u16 + bg_r as u16 * (255 - a) as u16) / 255) as u8;
                let blended_g = ((g as u16 * a as u16 + bg_g as u16 * (255 - a) as u16) / 255) as u8;
                let blended_b = ((b as u16 * a as u16 + bg_b as u16 * (255 - a) as u16) / 255) as u8;
                surf.set_pixel(px, py, ColorRef::rgb(blended_r, blended_g, blended_b));
            }
        }
    }
}

fn draw_icon_label(surf: &super::super::super::gdi::surface::Surface, center_x: i32, y: i32, text: &str, selected: bool) {
    let text_width = (text.len() as i32) * 6;
    let mut x = (center_x - text_width / 2).max(2);

    if selected {
        for (i, c) in text.chars().enumerate() {
            draw_char(surf, x + (i as i32) * 6, y, c, ColorRef::WHITE);
        }
    } else {
        // Shadow
        for (i, c) in text.chars().enumerate() {
            draw_char(surf, x + (i as i32) * 6 + 1, y + 1, c, ColorRef::BLACK);
        }
        // Text
        for (i, c) in text.chars().enumerate() {
            draw_char(surf, x + (i as i32) * 6, y, c, ColorRef::WHITE);
        }
    }
}

fn draw_char(surf: &super::super::super::gdi::surface::Surface, x: i32, y: i32, c: char, color: ColorRef) {
    let pattern = get_char_pattern(c);
    for (row, &bits) in pattern.iter().enumerate() {
        for col in 0..5 {
            if (bits >> (4 - col)) & 1 == 1 {
                surf.set_pixel(x + col, y + row as i32, color);
            }
        }
    }
}

fn get_char_pattern(c: char) -> [u8; 7] {
    match c.to_ascii_uppercase() {
        'A' => [0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
        'B' => [0b11110, 0b10001, 0b11110, 0b10001, 0b10001, 0b10001, 0b11110],
        'C' => [0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110],
        'D' => [0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110],
        'E' => [0b11111, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000, 0b11111],
        'F' => [0b11111, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000, 0b10000],
        'G' => [0b01110, 0b10001, 0b10000, 0b10111, 0b10001, 0b10001, 0b01110],
        'H' => [0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001, 0b10001],
        'I' => [0b01110, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110],
        'K' => [0b10001, 0b10010, 0b11100, 0b10010, 0b10001, 0b10001, 0b10001],
        'L' => [0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111],
        'M' => [0b10001, 0b11011, 0b10101, 0b10001, 0b10001, 0b10001, 0b10001],
        'N' => [0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001],
        'O' => [0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
        'P' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000],
        'R' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10010, 0b10001, 0b10001],
        'S' => [0b01110, 0b10001, 0b10000, 0b01110, 0b00001, 0b10001, 0b01110],
        'T' => [0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100],
        'U' => [0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
        'W' => [0b10001, 0b10001, 0b10001, 0b10101, 0b10101, 0b11011, 0b10001],
        'Y' => [0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100, 0b00100],
        ' ' => [0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000],
        _ => [0b00000, 0b00000, 0b00000, 0b00100, 0b00000, 0b00000, 0b00000],
    }
}
