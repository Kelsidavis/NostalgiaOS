//! Context Menu System
//!
//! Provides popup context menus for right-click actions.

use super::super::{HWND, Rect, ColorRef};
use super::super::gdi::surface;
use super::paint;

/// Maximum menu items
pub const MAX_MENU_ITEMS: usize = 16;

/// Menu item ID constants
pub mod menu_id {
    pub const NONE: u16 = 0;
    pub const NEW_FOLDER: u16 = 1;
    pub const NEW_TEXT_FILE: u16 = 2;
    pub const REFRESH: u16 = 3;
    pub const PASTE: u16 = 4;
    pub const PROPERTIES: u16 = 5;

    // File/folder context menu items
    pub const OPEN: u16 = 10;
    pub const OPEN_WITH: u16 = 11;
    pub const CUT: u16 = 12;
    pub const COPY: u16 = 13;
    pub const DELETE: u16 = 14;
    pub const RENAME: u16 = 15;
    pub const CREATE_SHORTCUT: u16 = 16;

    // View submenu
    pub const VIEW_LARGE_ICONS: u16 = 20;
    pub const VIEW_SMALL_ICONS: u16 = 21;
    pub const VIEW_LIST: u16 = 22;
    pub const VIEW_DETAILS: u16 = 23;

    // Arrange by
    pub const ARRANGE_NAME: u16 = 30;
    pub const ARRANGE_SIZE: u16 = 31;
    pub const ARRANGE_TYPE: u16 = 32;
    pub const ARRANGE_DATE: u16 = 33;

    pub const SELECT_ALL: u16 = 40;
    pub const INVERT_SELECTION: u16 = 41;
    pub const SELECT_BY_TYPE: u16 = 42;
    pub const TOGGLE_DETAILS_PANEL: u16 = 43;

    pub const SEPARATOR: u16 = 0xFFFE;
    pub const SUBMENU_NEW: u16 = 0xFFFF;
    pub const SUBMENU_VIEW: u16 = 0xFFFD;
    pub const SUBMENU_ARRANGE: u16 = 0xFFFC;
}

/// Menu item
#[derive(Clone, Copy)]
pub struct MenuItem {
    pub id: u16,
    pub text: [u8; 32],
    pub text_len: usize,
    pub is_separator: bool,
    pub is_submenu: bool,
    pub disabled: bool,
}

impl MenuItem {
    pub const fn empty() -> Self {
        Self {
            id: menu_id::NONE,
            text: [0; 32],
            text_len: 0,
            is_separator: false,
            is_submenu: false,
            disabled: false,
        }
    }

    pub fn new(id: u16, text: &str) -> Self {
        let mut item = Self::empty();
        item.id = id;
        let bytes = text.as_bytes();
        let len = bytes.len().min(31);
        item.text[..len].copy_from_slice(&bytes[..len]);
        item.text_len = len;
        item
    }

    pub fn separator() -> Self {
        let mut item = Self::empty();
        item.id = menu_id::SEPARATOR;
        item.is_separator = true;
        item
    }

    pub fn text_str(&self) -> &str {
        core::str::from_utf8(&self.text[..self.text_len]).unwrap_or("")
    }
}

/// Context menu state
pub struct ContextMenu {
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    pub items: [MenuItem; MAX_MENU_ITEMS],
    pub item_count: usize,
    pub highlight_index: i32,
    pub owner_hwnd: HWND,
    pub folder_path: [u8; 128],
    pub folder_path_len: usize,
    pub submenu_visible: bool,
    pub submenu_parent_index: i32,
}

impl ContextMenu {
    pub const fn empty() -> Self {
        Self {
            visible: false,
            x: 0,
            y: 0,
            items: [MenuItem::empty(); MAX_MENU_ITEMS],
            item_count: 0,
            highlight_index: -1,
            owner_hwnd: HWND::NULL,
            folder_path: [0; 128],
            folder_path_len: 0,
            submenu_visible: false,
            submenu_parent_index: -1,
        }
    }

    pub fn folder_path_str(&self) -> &str {
        core::str::from_utf8(&self.folder_path[..self.folder_path_len]).unwrap_or("")
    }
}

static mut CONTEXT_MENU: ContextMenu = ContextMenu::empty();

const ITEM_HEIGHT: i32 = 20;
const SEPARATOR_HEIGHT: i32 = 8;
const MENU_PADDING: i32 = 2;
const TEXT_MARGIN: i32 = 24;

/// Show context menu for explorer window background
pub fn show_explorer_context_menu(hwnd: HWND, x: i32, y: i32, folder_path: &str) {
    unsafe {
        CONTEXT_MENU.visible = true;
        CONTEXT_MENU.x = x;
        CONTEXT_MENU.y = y;
        CONTEXT_MENU.owner_hwnd = hwnd;
        CONTEXT_MENU.highlight_index = -1;
        CONTEXT_MENU.submenu_visible = false;
        CONTEXT_MENU.submenu_parent_index = -1;

        let path_bytes = folder_path.as_bytes();
        let path_len = path_bytes.len().min(127);
        CONTEXT_MENU.folder_path[..path_len].copy_from_slice(&path_bytes[..path_len]);
        CONTEXT_MENU.folder_path_len = path_len;

        CONTEXT_MENU.item_count = 0;

        // View submenu
        let mut view_item = MenuItem::new(menu_id::SUBMENU_VIEW, "View");
        view_item.is_submenu = true;
        add_menu_item(view_item);

        // Arrange submenu
        let mut arrange_item = MenuItem::new(menu_id::SUBMENU_ARRANGE, "Arrange Icons By");
        arrange_item.is_submenu = true;
        add_menu_item(arrange_item);

        add_menu_item(MenuItem::separator());
        add_menu_item(MenuItem::new(menu_id::REFRESH, "Refresh"));
        add_menu_item(MenuItem::separator());

        // New submenu
        let mut new_item = MenuItem::new(menu_id::SUBMENU_NEW, "New");
        new_item.is_submenu = true;
        add_menu_item(new_item);

        add_menu_item(MenuItem::separator());
        let mut paste_item = MenuItem::new(menu_id::PASTE, "Paste");
        paste_item.disabled = true;
        add_menu_item(paste_item);
        add_menu_item(MenuItem::separator());
        add_menu_item(MenuItem::new(menu_id::SELECT_ALL, "Select All"));
        add_menu_item(MenuItem::new(menu_id::TOGGLE_DETAILS_PANEL, "Details Panel"));
        add_menu_item(MenuItem::separator());
        add_menu_item(MenuItem::new(menu_id::PROPERTIES, "Properties"));
    }
    draw_context_menu();
}

/// Show context menu for selected file(s) or folder(s)
pub fn show_file_context_menu(hwnd: HWND, x: i32, y: i32, is_directory: bool, has_clipboard: bool) {
    unsafe {
        CONTEXT_MENU.visible = true;
        CONTEXT_MENU.x = x;
        CONTEXT_MENU.y = y;
        CONTEXT_MENU.owner_hwnd = hwnd;
        CONTEXT_MENU.highlight_index = -1;
        CONTEXT_MENU.submenu_visible = false;
        CONTEXT_MENU.submenu_parent_index = -1;
        CONTEXT_MENU.item_count = 0;

        if is_directory {
            add_menu_item(MenuItem::new(menu_id::OPEN, "Open"));
        } else {
            add_menu_item(MenuItem::new(menu_id::OPEN, "Open"));
            let mut open_with = MenuItem::new(menu_id::OPEN_WITH, "Open With...");
            open_with.is_submenu = true;
            add_menu_item(open_with);
        }

        add_menu_item(MenuItem::separator());
        add_menu_item(MenuItem::new(menu_id::CUT, "Cut"));
        add_menu_item(MenuItem::new(menu_id::COPY, "Copy"));
        add_menu_item(MenuItem::separator());
        add_menu_item(MenuItem::new(menu_id::DELETE, "Delete"));
        add_menu_item(MenuItem::new(menu_id::RENAME, "Rename"));
        add_menu_item(MenuItem::separator());
        add_menu_item(MenuItem::new(menu_id::SELECT_BY_TYPE, "Select Same Type"));
        add_menu_item(MenuItem::separator());
        add_menu_item(MenuItem::new(menu_id::PROPERTIES, "Properties"));
    }
    draw_context_menu();
}

fn add_menu_item(item: MenuItem) {
    unsafe {
        if CONTEXT_MENU.item_count < MAX_MENU_ITEMS {
            CONTEXT_MENU.items[CONTEXT_MENU.item_count] = item;
            CONTEXT_MENU.item_count += 1;
        }
    }
}

pub fn hide_context_menu() {
    unsafe {
        if CONTEXT_MENU.visible {
            CONTEXT_MENU.visible = false;
            CONTEXT_MENU.submenu_visible = false;
            paint::repaint_all();
        }
    }
}

pub fn is_menu_visible() -> bool {
    unsafe { CONTEXT_MENU.visible }
}

fn get_menu_rect() -> Rect {
    unsafe {
        let mut max_width = 120;
        let mut total_height = MENU_PADDING * 2;
        for i in 0..CONTEXT_MENU.item_count {
            let item = &CONTEXT_MENU.items[i];
            if item.is_separator {
                total_height += SEPARATOR_HEIGHT;
            } else {
                total_height += ITEM_HEIGHT;
                let text_width = item.text_len as i32 * 7 + TEXT_MARGIN * 2;
                if text_width > max_width { max_width = text_width; }
            }
        }
        Rect::new(CONTEXT_MENU.x, CONTEXT_MENU.y, CONTEXT_MENU.x + max_width, CONTEXT_MENU.y + total_height)
    }
}

pub fn draw_context_menu() {
    unsafe { if !CONTEXT_MENU.visible { return; } }
    let surface_handle = super::super::gdi::surface::get_display_surface();
    let surf = match surface::get_surface(surface_handle) { Some(s) => s, None => return };
    let menu_rect = get_menu_rect();
    surf.fill_rect(&menu_rect, ColorRef::MENU);
    surf.hline(menu_rect.left, menu_rect.right, menu_rect.top, ColorRef::BUTTON_HIGHLIGHT);
    surf.vline(menu_rect.left, menu_rect.top, menu_rect.bottom, ColorRef::BUTTON_HIGHLIGHT);
    surf.hline(menu_rect.left, menu_rect.right, menu_rect.bottom - 1, ColorRef::BUTTON_SHADOW);
    surf.vline(menu_rect.right - 1, menu_rect.top, menu_rect.bottom, ColorRef::BUTTON_SHADOW);

    let mut y = menu_rect.top + MENU_PADDING;
    unsafe {
        for i in 0..CONTEXT_MENU.item_count {
            let item = &CONTEXT_MENU.items[i];
            if item.is_separator {
                let sep_y = y + SEPARATOR_HEIGHT / 2;
                surf.hline(menu_rect.left + 2, menu_rect.right - 2, sep_y, ColorRef::BUTTON_SHADOW);
                surf.hline(menu_rect.left + 2, menu_rect.right - 2, sep_y + 1, ColorRef::BUTTON_HIGHLIGHT);
                y += SEPARATOR_HEIGHT;
            } else {
                if i as i32 == CONTEXT_MENU.highlight_index && !item.disabled {
                    let hr = Rect::new(menu_rect.left + 2, y, menu_rect.right - 2, y + ITEM_HEIGHT);
                    surf.fill_rect(&hr, ColorRef::HIGHLIGHT);
                }
                let text_color = if item.disabled { ColorRef::GRAY_TEXT }
                    else if i as i32 == CONTEXT_MENU.highlight_index { ColorRef::HIGHLIGHT_TEXT }
                    else { ColorRef::MENU_TEXT };
                draw_menu_text(&surf, menu_rect.left + TEXT_MARGIN, y + 3, item.text_str(), text_color);
                if item.is_submenu {
                    let ax = menu_rect.right - 12;
                    let ay = y + ITEM_HEIGHT / 2;
                    for dy in -3..=3i32 { surf.set_pixel(ax + 3 - dy.abs(), ay + dy, text_color); }
                }
                y += ITEM_HEIGHT;
            }
        }
    }
    draw_submenu(&surf);
}

fn draw_submenu(surf: &surface::Surface) {
    unsafe { if !CONTEXT_MENU.submenu_visible { return; } }
    let menu_rect = get_menu_rect();
    let mut parent_y = menu_rect.top + MENU_PADDING;
    unsafe {
        for i in 0..CONTEXT_MENU.submenu_parent_index {
            parent_y += if CONTEXT_MENU.items[i as usize].is_separator { SEPARATOR_HEIGHT } else { ITEM_HEIGHT };
        }
    }
    let submenu_x = menu_rect.right - 2;
    let submenu_y = parent_y;
    let items = [("Folder", menu_id::NEW_FOLDER), ("", menu_id::SEPARATOR), ("Text Document", menu_id::NEW_TEXT_FILE)];
    let submenu_width = 140;
    let mut submenu_height = MENU_PADDING * 2;
    for (_, id) in items.iter() { submenu_height += if *id == menu_id::SEPARATOR { SEPARATOR_HEIGHT } else { ITEM_HEIGHT }; }
    let sr = Rect::new(submenu_x, submenu_y, submenu_x + submenu_width, submenu_y + submenu_height);
    surf.fill_rect(&sr, ColorRef::MENU);
    surf.hline(sr.left, sr.right, sr.top, ColorRef::BUTTON_HIGHLIGHT);
    surf.vline(sr.left, sr.top, sr.bottom, ColorRef::BUTTON_HIGHLIGHT);
    surf.hline(sr.left, sr.right, sr.bottom - 1, ColorRef::BUTTON_SHADOW);
    surf.vline(sr.right - 1, sr.top, sr.bottom, ColorRef::BUTTON_SHADOW);
    let mut y = sr.top + MENU_PADDING;
    for (text, id) in items.iter() {
        if *id == menu_id::SEPARATOR {
            surf.hline(sr.left + 2, sr.right - 2, y + SEPARATOR_HEIGHT / 2, ColorRef::BUTTON_SHADOW);
            y += SEPARATOR_HEIGHT;
        } else {
            draw_menu_text(surf, sr.left + TEXT_MARGIN, y + 3, text, ColorRef::MENU_TEXT);
            y += ITEM_HEIGHT;
        }
    }
}

fn draw_menu_text(surf: &surface::Surface, x: i32, y: i32, text: &str, color: ColorRef) {
    let mut cx = x;
    for ch in text.chars() { draw_char(surf, cx, y, ch, color); cx += 7; }
}

fn draw_char(surf: &surface::Surface, x: i32, y: i32, ch: char, color: ColorRef) {
    let pattern: [u8; 7] = match ch {
        'A' => [0x1C,0x22,0x22,0x3E,0x22,0x22,0x22], 'B' => [0x3C,0x22,0x22,0x3C,0x22,0x22,0x3C],
        'C' => [0x1C,0x22,0x20,0x20,0x20,0x22,0x1C], 'D' => [0x3C,0x22,0x22,0x22,0x22,0x22,0x3C],
        'E' => [0x3E,0x20,0x20,0x3C,0x20,0x20,0x3E], 'F' => [0x3E,0x20,0x20,0x3C,0x20,0x20,0x20],
        'G' => [0x1C,0x22,0x20,0x2E,0x22,0x22,0x1C], 'H' => [0x22,0x22,0x22,0x3E,0x22,0x22,0x22],
        'I' => [0x1C,0x08,0x08,0x08,0x08,0x08,0x1C], 'J' => [0x0E,0x04,0x04,0x04,0x04,0x24,0x18],
        'K' => [0x22,0x24,0x28,0x30,0x28,0x24,0x22], 'L' => [0x20,0x20,0x20,0x20,0x20,0x20,0x3E],
        'M' => [0x22,0x36,0x2A,0x2A,0x22,0x22,0x22], 'N' => [0x22,0x32,0x2A,0x26,0x22,0x22,0x22],
        'O' => [0x1C,0x22,0x22,0x22,0x22,0x22,0x1C], 'P' => [0x3C,0x22,0x22,0x3C,0x20,0x20,0x20],
        'R' => [0x3C,0x22,0x22,0x3C,0x28,0x24,0x22], 'S' => [0x1C,0x22,0x20,0x1C,0x02,0x22,0x1C],
        'T' => [0x3E,0x08,0x08,0x08,0x08,0x08,0x08], 'U' => [0x22,0x22,0x22,0x22,0x22,0x22,0x1C],
        'V' => [0x22,0x22,0x22,0x22,0x22,0x14,0x08], 'W' => [0x22,0x22,0x22,0x2A,0x2A,0x36,0x22],
        'X' => [0x22,0x22,0x14,0x08,0x14,0x22,0x22], 'Y' => [0x22,0x22,0x14,0x08,0x08,0x08,0x08],
        'a' => [0x00,0x00,0x1C,0x02,0x1E,0x22,0x1E], 'e' => [0x00,0x00,0x1C,0x22,0x3E,0x20,0x1C],
        'f' => [0x0C,0x10,0x3C,0x10,0x10,0x10,0x10], 'h' => [0x20,0x20,0x3C,0x22,0x22,0x22,0x22],
        'i' => [0x08,0x00,0x18,0x08,0x08,0x08,0x1C], 'l' => [0x18,0x08,0x08,0x08,0x08,0x08,0x1C],
        'n' => [0x00,0x00,0x3C,0x22,0x22,0x22,0x22], 'o' => [0x00,0x00,0x1C,0x22,0x22,0x22,0x1C],
        'p' => [0x00,0x00,0x3C,0x22,0x3C,0x20,0x20], 'r' => [0x00,0x00,0x2C,0x30,0x20,0x20,0x20],
        's' => [0x00,0x00,0x1E,0x20,0x1C,0x02,0x3C], 't' => [0x10,0x10,0x3C,0x10,0x10,0x10,0x0C],
        'u' => [0x00,0x00,0x22,0x22,0x22,0x22,0x1E], 'w' => [0x00,0x00,0x22,0x22,0x2A,0x2A,0x14],
        'x' => [0x00,0x00,0x22,0x14,0x08,0x14,0x22], 'c' => [0x00,0x00,0x1E,0x20,0x20,0x20,0x1E],
        'd' => [0x02,0x02,0x1E,0x22,0x22,0x22,0x1E], 'm' => [0x00,0x00,0x34,0x2A,0x2A,0x2A,0x22],
        'g' => [0x00,0x00,0x1E,0x22,0x1E,0x02,0x1C], 'y' => [0x00,0x00,0x22,0x22,0x1E,0x02,0x1C],
        ' ' => [0;7], '.' => [0x00,0x00,0x00,0x00,0x00,0x18,0x18],
        _ => [0;7],
    };
    for (row, &bits) in pattern.iter().enumerate() {
        for col in 0..6 { if (bits >> (5 - col)) & 1 != 0 { surf.set_pixel(x + col, y + row as i32, color); } }
    }
}

pub fn on_mouse_move(screen_x: i32, screen_y: i32) {
    unsafe {
        if !CONTEXT_MENU.visible { return; }
        let menu_rect = get_menu_rect();

        // Check if mouse is in submenu area first
        if CONTEXT_MENU.submenu_visible {
            let mut py = menu_rect.top + MENU_PADDING;
            for i in 0..CONTEXT_MENU.submenu_parent_index {
                py += if CONTEXT_MENU.items[i as usize].is_separator { SEPARATOR_HEIGHT } else { ITEM_HEIGHT };
            }
            let sx = menu_rect.right - 2;
            let sy = py;
            let items = [("Folder", menu_id::NEW_FOLDER), ("", menu_id::SEPARATOR), ("Text Document", menu_id::NEW_TEXT_FILE)];
            let sw = 140;
            let mut sh = MENU_PADDING * 2;
            for (_, id) in items.iter() { sh += if *id == menu_id::SEPARATOR { SEPARATOR_HEIGHT } else { ITEM_HEIGHT }; }
            let sr = Rect::new(sx, sy, sx + sw, sy + sh);

            // If mouse is in submenu, keep it visible and don't process main menu
            if screen_x >= sr.left && screen_x < sr.right && screen_y >= sr.top && screen_y < sr.bottom {
                return;
            }
        }

        if screen_x >= menu_rect.left && screen_x < menu_rect.right && screen_y >= menu_rect.top && screen_y < menu_rect.bottom {
            let mut y = menu_rect.top + MENU_PADDING;
            let mut new_hi = -1i32;
            for i in 0..CONTEXT_MENU.item_count {
                let item = &CONTEXT_MENU.items[i];
                let ih = if item.is_separator { SEPARATOR_HEIGHT } else { ITEM_HEIGHT };
                if !item.is_separator && screen_y >= y && screen_y < y + ih {
                    new_hi = i as i32;
                    if item.is_submenu { CONTEXT_MENU.submenu_visible = true; CONTEXT_MENU.submenu_parent_index = i as i32; }
                    break;
                }
                y += ih;
            }
            if new_hi != CONTEXT_MENU.highlight_index {
                CONTEXT_MENU.highlight_index = new_hi;
                if new_hi >= 0 && !CONTEXT_MENU.items[new_hi as usize].is_submenu { CONTEXT_MENU.submenu_visible = false; }
                draw_context_menu();
            }
        }
    }
}

pub fn on_click(screen_x: i32, screen_y: i32) -> u16 {
    unsafe {
        if !CONTEXT_MENU.visible { return menu_id::NONE; }
        let menu_rect = get_menu_rect();
        crate::serial_println!("[MENU] on_click at ({}, {}), submenu_visible={}", screen_x, screen_y, CONTEXT_MENU.submenu_visible);
        if CONTEXT_MENU.submenu_visible {
            let mut py = menu_rect.top + MENU_PADDING;
            for i in 0..CONTEXT_MENU.submenu_parent_index {
                py += if CONTEXT_MENU.items[i as usize].is_separator { SEPARATOR_HEIGHT } else { ITEM_HEIGHT };
            }
            let sx = menu_rect.right - 2; let sy = py;
            let items = [("Folder", menu_id::NEW_FOLDER), ("", menu_id::SEPARATOR), ("Text Document", menu_id::NEW_TEXT_FILE)];
            let sw = 140;
            let mut sh = MENU_PADDING * 2;
            for (_, id) in items.iter() { sh += if *id == menu_id::SEPARATOR { SEPARATOR_HEIGHT } else { ITEM_HEIGHT }; }
            let sr = Rect::new(sx, sy, sx + sw, sy + sh);
            crate::serial_println!("[MENU] submenu rect: ({},{}) to ({},{})", sr.left, sr.top, sr.right, sr.bottom);
            if screen_x >= sr.left && screen_x < sr.right && screen_y >= sr.top && screen_y < sr.bottom {
                crate::serial_println!("[MENU] click is inside submenu");
                let mut y = sr.top + MENU_PADDING;
                for (name, id) in items.iter() {
                    let ih = if *id == menu_id::SEPARATOR { SEPARATOR_HEIGHT } else { ITEM_HEIGHT };
                    crate::serial_println!("[MENU] checking item '{}' id={} y={} ih={}", name, id, y, ih);
                    if *id != menu_id::SEPARATOR && screen_y >= y && screen_y < y + ih {
                        crate::serial_println!("[MENU] matched item id={}", id);
                        hide_context_menu();
                        return *id;
                    }
                    y += ih;
                }
            }
        }
        if screen_x >= menu_rect.left && screen_x < menu_rect.right && screen_y >= menu_rect.top && screen_y < menu_rect.bottom {
            let mut y = menu_rect.top + MENU_PADDING;
            for i in 0..CONTEXT_MENU.item_count {
                let item = &CONTEXT_MENU.items[i];
                let ih = if item.is_separator { SEPARATOR_HEIGHT } else { ITEM_HEIGHT };
                if !item.is_separator && !item.disabled && !item.is_submenu && screen_y >= y && screen_y < y + ih {
                    let id = item.id; hide_context_menu(); return id;
                }
                y += ih;
            }
        }
        hide_context_menu();
        menu_id::NONE
    }
}

pub fn get_menu_folder_path() -> &'static str { unsafe { CONTEXT_MENU.folder_path_str() } }

/// Get the window handle that owns the current context menu
pub fn get_menu_owner() -> HWND {
    unsafe { CONTEXT_MENU.owner_hwnd }
}

pub fn init() { crate::serial_println!("[USER/Menu] Context menu system initialized"); }
