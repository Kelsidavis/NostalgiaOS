//! Menu Subsystem
//!
//! Implementation of Windows NT-style menus following the USER architecture.
//! Provides menus, popup menus, and menu bars.
//!
//! # Components
//!
//! - **Menu objects**: HMENU handles and menu item management
//! - **Popup menus**: TrackPopupMenu for context menus
//! - **Menu bar**: Window menu bar integration
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/menu.c`
//! - `windows/core/ntuser/kernel/menudd.c`

use super::super::{HWND, HMENU, UserHandle, UserObjectType, ColorRef, Rect, Point};
use super::super::gdi::{dc, surface, brush};
use super::message::{self, WM_COMMAND, WM_INITMENU, WM_INITMENUPOPUP, WM_MENUSELECT};
use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of menus
const MAX_MENUS: usize = 256;

/// Maximum items per menu
const MAX_MENU_ITEMS: usize = 64;

/// Menu item height
const MENU_ITEM_HEIGHT: i32 = 20;

/// Menu item horizontal padding
const MENU_ITEM_HPADDING: i32 = 24;

/// Separator height
const MENU_SEPARATOR_HEIGHT: i32 = 8;

/// Menu border width
const MENU_BORDER: i32 = 3;

// ============================================================================
// Menu Item Types (MFT_*)
// ============================================================================

bitflags::bitflags! {
    /// Menu item type flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct MenuItemType: u32 {
        /// String item (default)
        const STRING = 0x00000000;
        /// Bitmap item
        const BITMAP = 0x00000004;
        /// Owner-drawn item
        const OWNERDRAW = 0x00000100;
        /// Separator line
        const SEPARATOR = 0x00000800;
        /// Menu bar break
        const MENUBARBREAK = 0x00000020;
        /// Menu break (new column)
        const MENUBREAK = 0x00000040;
        /// Radio check mark
        const RADIOCHECK = 0x00000200;
        /// Right-to-left order
        const RIGHTORDER = 0x00002000;
        /// Right-justified (menu bar)
        const RIGHTJUSTIFY = 0x00004000;
    }
}

// ============================================================================
// Menu Item State (MFS_*)
// ============================================================================

bitflags::bitflags! {
    /// Menu item state flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct MenuItemState: u32 {
        /// Enabled (default)
        const ENABLED = 0x00000000;
        /// Grayed/disabled
        const GRAYED = 0x00000003;
        /// Disabled (no gray)
        const DISABLED = 0x00000002;
        /// Checked
        const CHECKED = 0x00000008;
        /// Highlighted
        const HILITE = 0x00000080;
        /// Default item (bold)
        const DEFAULT = 0x00001000;
    }
}

// ============================================================================
// Menu Flags (MF_*)
// ============================================================================

bitflags::bitflags! {
    /// Combined menu flags for InsertMenu/AppendMenu
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct MenuFlags: u32 {
        /// By command ID (default)
        const BYCOMMAND = 0x00000000;
        /// By position
        const BYPOSITION = 0x00000400;
        /// Separator
        const SEPARATOR = 0x00000800;
        /// Enabled
        const ENABLED = 0x00000000;
        /// Grayed
        const GRAYED = 0x00000001;
        /// Disabled
        const DISABLED = 0x00000002;
        /// Unchecked
        const UNCHECKED = 0x00000000;
        /// Checked
        const CHECKED = 0x00000008;
        /// String item
        const STRING = 0x00000000;
        /// Bitmap item
        const BITMAP = 0x00000004;
        /// Owner-drawn
        const OWNERDRAW = 0x00000100;
        /// Popup submenu
        const POPUP = 0x00000010;
        /// Menu bar break
        const MENUBARBREAK = 0x00000020;
        /// Menu break
        const MENUBREAK = 0x00000040;
        /// Highlighted
        const HILITE = 0x00000080;
    }
}

// ============================================================================
// TrackPopupMenu Flags (TPM_*)
// ============================================================================

bitflags::bitflags! {
    /// TrackPopupMenu flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct TrackPopupFlags: u32 {
        /// Left button activates
        const LEFTBUTTON = 0x0000;
        /// Right button activates
        const RIGHTBUTTON = 0x0002;
        /// Align left edge at x
        const LEFTALIGN = 0x0000;
        /// Center at x
        const CENTERALIGN = 0x0004;
        /// Align right edge at x
        const RIGHTALIGN = 0x0008;
        /// Align top at y
        const TOPALIGN = 0x0000;
        /// Center at y
        const VCENTERALIGN = 0x0010;
        /// Align bottom at y
        const BOTTOMALIGN = 0x0020;
        /// Don't send notification
        const NONOTIFY = 0x0080;
        /// Return command ID
        const RETURNCMD = 0x0100;
        /// No animation
        const NOANIMATION = 0x4000;
    }
}

// ============================================================================
// Menu Item Structure
// ============================================================================

/// Menu item
#[derive(Clone, Copy)]
struct MenuItem {
    /// Item type flags
    item_type: MenuItemType,
    /// Item state flags
    state: MenuItemState,
    /// Command ID
    id: u32,
    /// Submenu handle (for popup items)
    submenu: HMENU,
    /// Item text (up to 64 chars)
    text: [u8; 64],
    text_len: usize,
    /// Item data (app-defined)
    item_data: usize,
    /// Item rectangle (calculated when displayed)
    rect: Rect,
    /// Is this slot in use?
    in_use: bool,
}

impl MenuItem {
    const fn empty() -> Self {
        Self {
            item_type: MenuItemType::STRING,
            state: MenuItemState::ENABLED,
            id: 0,
            submenu: UserHandle::NULL,
            text: [0; 64],
            text_len: 0,
            item_data: 0,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            in_use: false,
        }
    }

    fn get_text(&self) -> &str {
        core::str::from_utf8(&self.text[..self.text_len]).unwrap_or("")
    }
}

// ============================================================================
// Menu Structure
// ============================================================================

/// Menu object
#[derive(Clone, Copy)]
struct Menu {
    /// Menu handle
    handle: HMENU,
    /// Menu items
    items: [MenuItem; MAX_MENU_ITEMS],
    /// Number of items
    item_count: usize,
    /// Menu width (calculated)
    width: i32,
    /// Menu height (calculated)
    height: i32,
    /// Owner window
    owner: HWND,
    /// Is this a popup menu?
    is_popup: bool,
    /// Is this menu in use?
    in_use: bool,
    /// Currently selected item (-1 for none)
    selected_item: i32,
}

impl Menu {
    const fn empty() -> Self {
        Self {
            handle: UserHandle::NULL,
            items: [MenuItem::empty(); MAX_MENU_ITEMS],
            item_count: 0,
            width: 0,
            height: 0,
            owner: UserHandle::NULL,
            is_popup: false,
            in_use: false,
            selected_item: -1,
        }
    }
}

// ============================================================================
// Menu Table
// ============================================================================

struct MenuTable {
    menus: [Menu; MAX_MENUS],
    count: usize,
}

impl MenuTable {
    const fn new() -> Self {
        Self {
            menus: [Menu::empty(); MAX_MENUS],
            count: 0,
        }
    }
}

static MENU_TABLE: SpinLock<MenuTable> = SpinLock::new(MenuTable::new());
static MENU_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NEXT_MENU_INDEX: AtomicU32 = AtomicU32::new(1);

// Active popup state
static ACTIVE_POPUP: SpinLock<Option<HMENU>> = SpinLock::new(None);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize menu subsystem
pub fn init() {
    if MENU_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[USER/Menu] Menu subsystem initialized");
    MENU_INITIALIZED.store(true, Ordering::Release);
}

// ============================================================================
// Menu Creation/Destruction
// ============================================================================

/// Create a menu
pub fn create_menu() -> HMENU {
    let mut table = MENU_TABLE.lock();

    for menu in table.menus.iter_mut() {
        if !menu.in_use {
            let index = NEXT_MENU_INDEX.fetch_add(1, Ordering::Relaxed) as u16;
            let handle = UserHandle::new(index, UserObjectType::Menu);

            menu.handle = handle;
            menu.item_count = 0;
            menu.width = 0;
            menu.height = 0;
            menu.owner = UserHandle::NULL;
            menu.is_popup = false;
            menu.in_use = true;
            menu.selected_item = -1;
            table.count += 1;

            crate::serial_println!("[USER/Menu] Created menu {:x}", handle.raw());
            return handle;
        }
    }

    UserHandle::NULL
}

/// Create a popup menu
pub fn create_popup_menu() -> HMENU {
    let handle = create_menu();
    if handle.is_valid() {
        let mut table = MENU_TABLE.lock();
        if let Some(menu) = find_menu_mut(&mut table, handle) {
            menu.is_popup = true;
        }
    }
    handle
}

/// Destroy a menu
pub fn destroy_menu(hmenu: HMENU) -> bool {
    let mut table = MENU_TABLE.lock();

    for menu in table.menus.iter_mut() {
        if menu.in_use && menu.handle == hmenu {
            // Clear all items
            for item in menu.items.iter_mut() {
                item.in_use = false;
            }
            menu.in_use = false;
            table.count -= 1;

            crate::serial_println!("[USER/Menu] Destroyed menu {:x}", hmenu.raw());
            return true;
        }
    }

    false
}

// ============================================================================
// Menu Item Management
// ============================================================================

/// Append a menu item
pub fn append_menu(hmenu: HMENU, flags: MenuFlags, id: u32, text: &str) -> bool {
    let mut table = MENU_TABLE.lock();

    if let Some(menu) = find_menu_mut(&mut table, hmenu) {
        if menu.item_count >= MAX_MENU_ITEMS {
            return false;
        }

        let item = &mut menu.items[menu.item_count];
        item.in_use = true;
        item.id = id;

        // Parse flags
        if flags.contains(MenuFlags::SEPARATOR) {
            item.item_type = MenuItemType::SEPARATOR;
        } else if flags.contains(MenuFlags::POPUP) {
            item.item_type = MenuItemType::STRING;
            item.submenu = UserHandle::new(id as u16, UserObjectType::Menu);
        } else {
            item.item_type = MenuItemType::STRING;
        }

        if flags.contains(MenuFlags::GRAYED) {
            item.state = MenuItemState::GRAYED;
        } else if flags.contains(MenuFlags::DISABLED) {
            item.state = MenuItemState::DISABLED;
        } else {
            item.state = MenuItemState::ENABLED;
        }

        if flags.contains(MenuFlags::CHECKED) {
            item.state |= MenuItemState::CHECKED;
        }

        // Copy text
        let bytes = text.as_bytes();
        let len = bytes.len().min(63);
        item.text[..len].copy_from_slice(&bytes[..len]);
        item.text_len = len;

        menu.item_count += 1;
        return true;
    }

    false
}

/// Insert a menu item at position
pub fn insert_menu(hmenu: HMENU, position: u32, flags: MenuFlags, id: u32, text: &str) -> bool {
    let mut table = MENU_TABLE.lock();

    if let Some(menu) = find_menu_mut(&mut table, hmenu) {
        if menu.item_count >= MAX_MENU_ITEMS {
            return false;
        }

        let pos = if flags.contains(MenuFlags::BYPOSITION) {
            position as usize
        } else {
            // Find by command ID
            menu.items.iter().position(|i| i.in_use && i.id == position).unwrap_or(menu.item_count)
        };

        let pos = pos.min(menu.item_count);

        // Shift items down
        for i in (pos..menu.item_count).rev() {
            menu.items[i + 1] = menu.items[i].clone();
        }

        let item = &mut menu.items[pos];
        item.in_use = true;
        item.id = id;

        if flags.contains(MenuFlags::SEPARATOR) {
            item.item_type = MenuItemType::SEPARATOR;
        } else {
            item.item_type = MenuItemType::STRING;
        }

        item.state = if flags.contains(MenuFlags::GRAYED) {
            MenuItemState::GRAYED
        } else {
            MenuItemState::ENABLED
        };

        if flags.contains(MenuFlags::CHECKED) {
            item.state |= MenuItemState::CHECKED;
        }

        let bytes = text.as_bytes();
        let len = bytes.len().min(63);
        item.text[..len].copy_from_slice(&bytes[..len]);
        item.text_len = len;

        menu.item_count += 1;
        return true;
    }

    false
}

/// Remove a menu item
pub fn remove_menu(hmenu: HMENU, position: u32, flags: MenuFlags) -> bool {
    let mut table = MENU_TABLE.lock();

    if let Some(menu) = find_menu_mut(&mut table, hmenu) {
        let pos = if flags.contains(MenuFlags::BYPOSITION) {
            position as usize
        } else {
            match menu.items.iter().position(|i| i.in_use && i.id == position) {
                Some(p) => p,
                None => return false,
            }
        };

        if pos >= menu.item_count {
            return false;
        }

        // Shift items up
        for i in pos..(menu.item_count - 1) {
            menu.items[i] = menu.items[i + 1].clone();
        }
        menu.items[menu.item_count - 1].in_use = false;
        menu.item_count -= 1;

        return true;
    }

    false
}

/// Check or uncheck a menu item
pub fn check_menu_item(hmenu: HMENU, id: u32, check: bool) -> bool {
    let mut table = MENU_TABLE.lock();

    if let Some(menu) = find_menu_mut(&mut table, hmenu) {
        for item in menu.items.iter_mut() {
            if item.in_use && item.id == id {
                if check {
                    item.state |= MenuItemState::CHECKED;
                } else {
                    item.state &= !MenuItemState::CHECKED;
                }
                return true;
            }
        }
    }

    false
}

/// Enable or disable a menu item
pub fn enable_menu_item(hmenu: HMENU, id: u32, enable: bool) -> bool {
    let mut table = MENU_TABLE.lock();

    if let Some(menu) = find_menu_mut(&mut table, hmenu) {
        for item in menu.items.iter_mut() {
            if item.in_use && item.id == id {
                if enable {
                    item.state &= !(MenuItemState::GRAYED | MenuItemState::DISABLED);
                } else {
                    item.state |= MenuItemState::GRAYED;
                }
                return true;
            }
        }
    }

    false
}

/// Get menu item count
pub fn get_menu_item_count(hmenu: HMENU) -> i32 {
    let table = MENU_TABLE.lock();

    if let Some(menu) = find_menu(&table, hmenu) {
        return menu.item_count as i32;
    }

    -1
}

/// Get submenu at position
pub fn get_sub_menu(hmenu: HMENU, position: i32) -> HMENU {
    let table = MENU_TABLE.lock();

    if let Some(menu) = find_menu(&table, hmenu) {
        if position >= 0 && (position as usize) < menu.item_count {
            let item = &menu.items[position as usize];
            if item.in_use && item.submenu.is_valid() {
                return item.submenu;
            }
        }
    }

    UserHandle::NULL
}

// ============================================================================
// Menu Display
// ============================================================================

/// Track and display a popup menu
pub fn track_popup_menu(
    hmenu: HMENU,
    flags: TrackPopupFlags,
    x: i32,
    y: i32,
    hwnd: HWND,
) -> u32 {
    // Send WM_INITMENU
    if !flags.contains(TrackPopupFlags::NONOTIFY) {
        message::send_message(hwnd, WM_INITMENU, hmenu.raw() as usize, 0);
        message::send_message(hwnd, WM_INITMENUPOPUP, hmenu.raw() as usize, 0);
    }

    // Calculate menu dimensions
    let (width, height) = calculate_menu_size(hmenu);

    // Adjust position based on flags
    let menu_x = if flags.contains(TrackPopupFlags::RIGHTALIGN) {
        x - width
    } else if flags.contains(TrackPopupFlags::CENTERALIGN) {
        x - width / 2
    } else {
        x
    };

    let menu_y = if flags.contains(TrackPopupFlags::BOTTOMALIGN) {
        y - height
    } else if flags.contains(TrackPopupFlags::VCENTERALIGN) {
        y - height / 2
    } else {
        y
    };

    // Set active popup
    {
        let mut active = ACTIVE_POPUP.lock();
        *active = Some(hmenu);
    }

    // Draw the popup menu
    draw_popup_menu(hmenu, menu_x, menu_y, width, height);

    // Store menu position for hit testing
    {
        let mut table = MENU_TABLE.lock();
        if let Some(menu) = find_menu_mut(&mut table, hmenu) {
            menu.owner = hwnd;
        }
    }

    // In a real implementation, we would enter a modal message loop here
    // For now, we'll return 0 (no selection) or use RETURNCMD behavior
    if flags.contains(TrackPopupFlags::RETURNCMD) {
        // Return the selected command ID
        0
    } else {
        0
    }
}

/// Draw a popup menu at the specified position
fn draw_popup_menu(hmenu: HMENU, x: i32, y: i32, width: i32, height: i32) {
    if let Ok(hdc) = super::super::gdi::dc::create_display_dc() {
        // Draw menu background
        let menu_rect = Rect::new(x, y, x + width, y + height);

        // Fill background
        let bg_brush = brush::create_solid_brush(ColorRef::WINDOW_BG);
        super::super::gdi::fill_rect(hdc, &menu_rect, bg_brush);

        // Draw 3D border
        super::super::gdi::draw_edge_raised(hdc, &menu_rect);

        // Draw menu items
        let table = MENU_TABLE.lock();
        if let Some(menu) = find_menu(&table, hmenu) {
            let mut item_y = y + MENU_BORDER;

            for i in 0..menu.item_count {
                let item = &menu.items[i];
                if !item.in_use {
                    continue;
                }

                if item.item_type.contains(MenuItemType::SEPARATOR) {
                    // Draw separator
                    let sep_y = item_y + MENU_SEPARATOR_HEIGHT / 2;
                    let sep_rect = Rect::new(x + 2, sep_y - 1, x + width - 2, sep_y + 1);
                    super::super::gdi::draw_edge_sunken(hdc, &sep_rect);
                    item_y += MENU_SEPARATOR_HEIGHT;
                } else {
                    // Draw menu item
                    let item_rect = Rect::new(
                        x + MENU_BORDER,
                        item_y,
                        x + width - MENU_BORDER,
                        item_y + MENU_ITEM_HEIGHT,
                    );

                    // Highlight if selected
                    if menu.selected_item == i as i32 {
                        let hilite_brush = brush::create_solid_brush(ColorRef::ACTIVE_CAPTION);
                        super::super::gdi::fill_rect(hdc, &item_rect, hilite_brush);
                        dc::set_text_color(hdc, ColorRef::WHITE);
                    } else {
                        dc::set_text_color(hdc, if item.state.contains(MenuItemState::GRAYED) {
                            ColorRef::GRAY
                        } else {
                            ColorRef::BLACK
                        });
                    }

                    // Draw checkmark if checked
                    if item.state.contains(MenuItemState::CHECKED) {
                        // Simple checkmark
                        let check_x = x + MENU_BORDER + 4;
                        let check_y = item_y + MENU_ITEM_HEIGHT / 2;
                        draw_checkmark(hdc, check_x, check_y);
                    }

                    // Draw text
                    dc::set_bk_mode(hdc, dc::BkMode::Transparent);
                    let text_x = x + MENU_ITEM_HPADDING;
                    let text_y = item_y + (MENU_ITEM_HEIGHT - 16) / 2;
                    super::super::gdi::text_out(hdc, text_x, text_y, item.get_text());

                    // Draw submenu arrow if has submenu
                    if item.submenu.is_valid() {
                        let arrow_x = x + width - MENU_BORDER - 12;
                        let arrow_y = item_y + MENU_ITEM_HEIGHT / 2;
                        draw_submenu_arrow(hdc, arrow_x, arrow_y);
                    }

                    item_y += MENU_ITEM_HEIGHT;
                }
            }
        }

        super::super::gdi::dc::delete_dc(hdc);
    }
}

/// Draw a checkmark at position
fn draw_checkmark(hdc: super::super::HDC, x: i32, y: i32) {
    let surface_handle = dc::get_dc_surface(hdc);
    if let Some(surf) = surface::get_surface(surface_handle) {
        let color = dc::get_text_color(hdc);
        // Simple checkmark
        for i in 0..3 {
            surf.set_pixel(x + i, y + i - 1, color);
            surf.set_pixel(x + i, y + i, color);
        }
        for i in 0..5 {
            surf.set_pixel(x + 2 + i, y + 1 - i, color);
            surf.set_pixel(x + 2 + i, y + 2 - i, color);
        }
    }
}

/// Draw submenu arrow at position
fn draw_submenu_arrow(hdc: super::super::HDC, x: i32, y: i32) {
    let surface_handle = dc::get_dc_surface(hdc);
    if let Some(surf) = surface::get_surface(surface_handle) {
        let color = dc::get_text_color(hdc);
        // Right-pointing triangle
        for i in 0..4 {
            surf.vline(x + i, y - i, y + i + 1, color);
        }
    }
}

/// Calculate menu size
fn calculate_menu_size(hmenu: HMENU) -> (i32, i32) {
    let table = MENU_TABLE.lock();

    if let Some(menu) = find_menu(&table, hmenu) {
        let mut max_width = 100; // Minimum width
        let mut total_height = MENU_BORDER * 2;

        for i in 0..menu.item_count {
            let item = &menu.items[i];
            if !item.in_use {
                continue;
            }

            if item.item_type.contains(MenuItemType::SEPARATOR) {
                total_height += MENU_SEPARATOR_HEIGHT;
            } else {
                // Calculate text width
                let text_width = item.text_len as i32 * 8 + MENU_ITEM_HPADDING * 2;
                if item.submenu.is_valid() {
                    // Add space for submenu arrow
                    max_width = max_width.max(text_width + 20);
                } else {
                    max_width = max_width.max(text_width);
                }
                total_height += MENU_ITEM_HEIGHT;
            }
        }

        return (max_width + MENU_BORDER * 2, total_height);
    }

    (100, 50)
}

/// Close any active popup menu
pub fn close_popup_menu() {
    let mut active = ACTIVE_POPUP.lock();
    *active = None;
    // In a real implementation, we would redraw the area behind the menu
}

// ============================================================================
// Menu Bar Support
// ============================================================================

/// Draw a menu bar for a window
pub fn draw_menu_bar(hwnd: HWND, hmenu: HMENU, rect: &Rect) {
    if let Ok(hdc) = super::super::gdi::dc::create_display_dc() {
        // Fill menu bar background
        let bg_brush = brush::create_solid_brush(ColorRef::BUTTON_FACE);
        super::super::gdi::fill_rect(hdc, rect, bg_brush);

        // Draw menu bar items
        let table = MENU_TABLE.lock();
        if let Some(menu) = find_menu(&table, hmenu) {
            let mut item_x = rect.left + 4;
            let item_y = rect.top + 2;

            for i in 0..menu.item_count {
                let item = &menu.items[i];
                if !item.in_use || item.item_type.contains(MenuItemType::SEPARATOR) {
                    continue;
                }

                let text_width = item.text_len as i32 * 8 + 16;

                // Draw item text
                if menu.selected_item == i as i32 {
                    // Highlighted
                    let hilite_rect = Rect::new(item_x - 2, item_y, item_x + text_width, rect.bottom - 2);
                    let hilite_brush = brush::create_solid_brush(ColorRef::ACTIVE_CAPTION);
                    super::super::gdi::fill_rect(hdc, &hilite_rect, hilite_brush);
                    dc::set_text_color(hdc, ColorRef::WHITE);
                } else {
                    dc::set_text_color(hdc, if item.state.contains(MenuItemState::GRAYED) {
                        ColorRef::GRAY
                    } else {
                        ColorRef::BLACK
                    });
                }

                dc::set_bk_mode(hdc, dc::BkMode::Transparent);
                super::super::gdi::text_out(hdc, item_x + 4, item_y + 2, item.get_text());

                item_x += text_width;
            }
        }

        super::super::gdi::dc::delete_dc(hdc);
    }
}

/// Handle menu bar click
pub fn menu_bar_hit_test(hmenu: HMENU, rect: &Rect, x: i32, y: i32) -> i32 {
    if y < rect.top || y >= rect.bottom {
        return -1;
    }

    let table = MENU_TABLE.lock();
    if let Some(menu) = find_menu(&table, hmenu) {
        let mut item_x = rect.left + 4;

        for i in 0..menu.item_count {
            let item = &menu.items[i];
            if !item.in_use || item.item_type.contains(MenuItemType::SEPARATOR) {
                continue;
            }

            let text_width = item.text_len as i32 * 8 + 16;

            if x >= item_x && x < item_x + text_width {
                return i as i32;
            }

            item_x += text_width;
        }
    }

    -1
}

// ============================================================================
// Helper Functions
// ============================================================================

fn find_menu(table: &MenuTable, hmenu: HMENU) -> Option<&Menu> {
    table.menus.iter().find(|m| m.in_use && m.handle == hmenu)
}

fn find_menu_mut(table: &mut MenuTable, hmenu: HMENU) -> Option<&mut Menu> {
    table.menus.iter_mut().find(|m| m.in_use && m.handle == hmenu)
}

// ============================================================================
// Statistics
// ============================================================================

/// Menu statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct MenuStats {
    pub menu_count: usize,
}

/// Get menu statistics
pub fn get_stats() -> MenuStats {
    let table = MENU_TABLE.lock();
    MenuStats {
        menu_count: table.count,
    }
}
