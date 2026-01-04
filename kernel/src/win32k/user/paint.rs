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
use crate::io::vfs::{self, VfsEntry, VfsIconType, SpecialFolder};

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

    // Use black background for console windows, white for others
    let bg_color = if wnd.class_name_str() == "ConsoleWindowClass" {
        ColorRef::BLACK
    } else {
        ColorRef::WHITE
    };
    surf.fill_rect(&client_rect, bg_color);
}

/// Draw window content based on window class
fn draw_window_content(hdc: HDC, wnd: &window::Window, metrics: &FrameMetrics) {
    let class_name = wnd.class_name_str();

    // Handle console windows specially
    if class_name == "ConsoleWindowClass" {
        super::shell::paint_shell(wnd.hwnd);
        return;
    }

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

    // Client area coordinates (screen space, for surface operations)
    let client_x = offset.x + border;
    let client_y = offset.y + border + caption;
    let client_w = wnd.rect.width() - border * 2;
    let client_h = wnd.rect.height() - border * 2 - caption;

    // Logical coordinates (window-relative, for text_out which applies viewport transform)
    let log_client_x = border;
    let log_client_y = border + caption;

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

    // Navigation buttons
    let nav_btn_size = 22;
    let nav_btn_y = client_y + 2;

    // Back button
    let back_x = client_x + 4;
    let can_back = window::can_go_back(wnd.hwnd);
    draw_nav_button(&surf, back_x, nav_btn_y, nav_btn_size, true, can_back);

    // Forward button
    let forward_x = back_x + nav_btn_size + 2;
    let can_forward = window::can_go_forward(wnd.hwnd);
    draw_nav_button(&surf, forward_x, nav_btn_y, nav_btn_size, false, can_forward);

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

    // Logical address bar Y (for text_out)
    let log_addr_y = log_client_y + toolbar_height;

    // Address label
    dc::set_text_color(hdc, ColorRef::BLACK);
    dc::set_bk_mode(hdc, dc::BkMode::Transparent);
    super::super::gdi::text_out(hdc, log_client_x + 4, log_addr_y + 4, "Address:");

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

    // Draw window title in address bar (use logical coordinates for text)
    let title = wnd.title_str();
    super::super::gdi::text_out(hdc, log_client_x + 55 + 4, log_addr_y + 4, title);

    // Address bar bottom edge
    surf.hline(client_x, client_x + client_w, addr_y + addr_height - 1, ColorRef::BUTTON_SHADOW);

    // Content area starts below address bar
    let content_y = addr_y + addr_height;
    let content_h = client_h - toolbar_height - addr_height;

    // Logical content area (for text_out)
    let log_content_y = log_addr_y + addr_height;

    if content_h > 20 {
        // Get folder contents based on window's folder path (stored in user_data)
        let folder_path = wnd.user_data_str();

        // Read directory contents using VFS
        let mut entries = [VfsEntry::empty(); 64];
        let entry_count = get_vfs_folder_contents(folder_path, &mut entries);

        // Draw folder icons with proper alignment
        // Icon cell: 32x32 icon area + space for label below
        let icon_width = 32;
        let icon_height = 32;
        let cell_width = 90;   // Horizontal spacing between icon centers
        let cell_height = 70;  // Vertical spacing (icon + label + padding)
        let margin_x = 16;
        let margin_y = 12;

        // Calculate icons per row based on window width
        let icons_per_row = ((client_w - margin_x * 2) / cell_width).max(1);

        // Screen coords for surface operations
        let start_x = client_x + margin_x;
        let start_y = content_y + margin_y;
        // Logical coords for text_out
        let log_start_x = log_client_x + margin_x;
        let log_start_y = log_content_y + margin_y;
        let char_width = 6; // Approximate character width for system font

        // Draw folder icons
        for i in 0..entry_count {
            let entry = &entries[i];
            let col = i as i32 % icons_per_row;
            let row = i as i32 / icons_per_row;

            // Screen coordinates for icon drawing (center icon in cell)
            let cell_x = start_x + col * cell_width;
            let cell_y = start_y + row * cell_height;
            let ix = cell_x + (cell_width - icon_width) / 2;
            let iy = cell_y;

            // Logical coordinates for text drawing
            let log_cell_x = log_start_x + col * cell_width;
            let log_cell_y = log_start_y + row * cell_height;

            if cell_x + cell_width < client_x + client_w && cell_y + cell_height < client_y + client_h {
                // Draw appropriate icon based on type (surface uses screen coords)
                draw_vfs_icon(&surf, ix, iy, entry.icon_type);

                // Center text under icon (text_out uses logical coords)
                let name = entry.name_str();
                // Truncate long names with ellipsis
                let max_chars = (cell_width / char_width) as usize;
                let display_name = if name.len() > max_chars && max_chars > 3 {
                    // Can't easily create truncated string without alloc, just use original
                    name
                } else {
                    name
                };
                let text_width = display_name.len() as i32 * char_width;
                let text_x = log_cell_x + (cell_width - text_width) / 2;
                let text_y = log_cell_y + icon_height + 4;
                super::super::gdi::text_out(hdc, text_x, text_y, display_name);
            }
        }
    }
}

/// Get folder contents using VFS layer
fn get_vfs_folder_contents(folder_path: &str, entries: &mut [VfsEntry]) -> usize {
    // Check for special folders first
    match folder_path {
        "MyComputer" => {
            return vfs::read_special_folder(SpecialFolder::MyComputer, entries);
        }
        "MyDocuments" => {
            return vfs::read_special_folder(SpecialFolder::MyDocuments, entries);
        }
        "RecycleBin" => {
            return vfs::read_special_folder(SpecialFolder::RecycleBin, entries);
        }
        "NetworkPlaces" => {
            return vfs::read_special_folder(SpecialFolder::NetworkPlaces, entries);
        }
        "ControlPanel" => {
            return vfs::read_special_folder(SpecialFolder::ControlPanel, entries);
        }
        _ => {}
    }

    // Check if it's a drive path (e.g., "C:" or "C:\folder")
    if folder_path.len() >= 2 {
        let bytes = folder_path.as_bytes();
        if bytes[1] == b':' {
            // It's a drive path - use VFS
            let count = vfs::read_directory(folder_path, entries);
            if count > 0 {
                return count;
            }
        }
    }

    // Handle paths like "MyComputer/C:" by converting to "C:"
    if folder_path.starts_with("MyComputer/") {
        let drive_path = &folder_path[11..]; // Skip "MyComputer/"
        let count = vfs::read_directory(drive_path, entries);
        if count > 0 {
            return count;
        }
    }

    // Handle paths like "MyDocuments/Documents" as relative paths
    if folder_path.starts_with("MyDocuments/") {
        // Try to map to actual file system path
        let subpath = &folder_path[12..]; // Skip "MyDocuments/"
        // Construct full path (e.g., "C:\Documents and Settings\User\My Documents\Documents")
        let mut full_path = [0u8; 256];
        let base = b"C:\\Documents and Settings\\User\\My Documents\\";
        let copy_len = base.len().min(full_path.len());
        full_path[..copy_len].copy_from_slice(&base[..copy_len]);
        let subpath_bytes = subpath.as_bytes();
        let subpath_len = subpath_bytes.len().min(full_path.len() - copy_len);
        full_path[copy_len..copy_len + subpath_len].copy_from_slice(&subpath_bytes[..subpath_len]);

        if let Ok(path_str) = core::str::from_utf8(&full_path[..copy_len + subpath_len]) {
            let count = vfs::read_directory(path_str, entries);
            if count > 0 {
                return count;
            }
        }

        // Fallback demo content for MyDocuments subfolders
        return get_demo_folder_contents(folder_path, entries);
    }

    // Fallback: show demo content based on path
    get_demo_folder_contents(folder_path, entries)
}

/// Get demo folder contents when no real file system is available
fn get_demo_folder_contents(folder_path: &str, entries: &mut [VfsEntry]) -> usize {
    let demo_items: &[(&str, VfsIconType)] = match folder_path {
        // Drive contents
        "MyComputer/Local Disk (C:)" | "MyComputer/C:" | "C:" => &[
            ("Windows", VfsIconType::Folder),
            ("Program Files", VfsIconType::Folder),
            ("Documents and Settings", VfsIconType::Folder),
        ],
        "MyComputer/Data (D:)" | "MyComputer/D:" | "D:" => &[
            ("Games", VfsIconType::Folder),
            ("Media", VfsIconType::Folder),
            ("Backup", VfsIconType::Folder),
        ],
        // Windows folder
        "C:/Windows" | "C:\\Windows" | "MyComputer/Local Disk (C:)/Windows" => &[
            ("System32", VfsIconType::Folder),
            ("Fonts", VfsIconType::Folder),
            ("Help", VfsIconType::Folder),
            ("notepad.exe", VfsIconType::Executable),
            ("explorer.exe", VfsIconType::Executable),
        ],
        // Program Files
        "C:/Program Files" | "C:\\Program Files" | "MyComputer/Local Disk (C:)/Program Files" => &[
            ("Internet Explorer", VfsIconType::Folder),
            ("Windows Media Player", VfsIconType::Folder),
            ("Common Files", VfsIconType::Folder),
        ],
        // My Documents subfolders
        "MyDocuments/My Pictures" => &[
            ("Vacation", VfsIconType::Folder),
            ("Family", VfsIconType::Folder),
            ("photo1.jpg", VfsIconType::Image),
        ],
        "MyDocuments/My Music" => &[
            ("Albums", VfsIconType::Folder),
            ("Playlists", VfsIconType::Folder),
            ("song.mp3", VfsIconType::Audio),
        ],
        "MyDocuments/My Videos" => &[
            ("Movies", VfsIconType::Folder),
            ("video.avi", VfsIconType::Video),
        ],
        "MyDocuments/Downloads" => &[
            ("setup.exe", VfsIconType::Executable),
            ("document.pdf", VfsIconType::Document),
            ("readme.txt", VfsIconType::Document),
        ],
        _ => &[],
    };

    let mut count = 0;
    for (name, icon) in demo_items.iter() {
        if count >= entries.len() {
            break;
        }
        let entry = &mut entries[count];
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len().min(255);
        entry.name[..name_len].copy_from_slice(&name_bytes[..name_len]);
        entry.name_len = name_len;
        entry.is_directory = *icon == VfsIconType::Folder;
        entry.icon_type = *icon;
        count += 1;
    }

    count
}

/// Static buffer for clicked entry name (since we can't return dynamic lifetimes)
static mut CLICKED_ENTRY_NAME: [u8; 256] = [0u8; 256];
static mut CLICKED_ENTRY_LEN: usize = 0;

/// Get window content icon at position (returns folder name if clicked on an icon)
/// The returned string is valid until the next call to this function.
pub fn get_content_icon_at_position(hwnd: HWND, screen_x: i32, screen_y: i32) -> Option<&'static str> {
    let wnd = window::get_window(hwnd)?;

    // Only handle CabinetWClass windows
    if wnd.class_name_str() != "CabinetWClass" {
        return None;
    }

    let metrics = wnd.get_frame_metrics();
    let border = metrics.border_width;
    let caption = if wnd.has_caption() { metrics.caption_height } else { 0 };

    // Client area coordinates (screen coords)
    let client_x = wnd.rect.left + border;
    let client_y = wnd.rect.top + border + caption;
    let _client_w = wnd.rect.width() - border * 2;
    let client_h = wnd.rect.height() - border * 2 - caption;

    // Content area starts below toolbar and address bar
    let toolbar_height = 26;
    let addr_height = 22;
    let content_y = client_y + toolbar_height + addr_height;
    let content_h = client_h - toolbar_height - addr_height;

    if content_h <= 20 {
        return None;
    }

    // Get entries based on current path using VFS
    let folder_path = wnd.user_data_str();
    let mut entries = [VfsEntry::empty(); 64];
    let entry_count = get_vfs_folder_contents(folder_path, &mut entries);

    // Icon layout matches draw_window_content
    let client_w = wnd.rect.width() - border * 2;
    let cell_width = 90;
    let cell_height = 70;
    let margin_x = 16;
    let margin_y = 12;
    let icons_per_row = ((client_w - margin_x * 2) / cell_width).max(1);
    let start_x = client_x + margin_x;
    let start_y = content_y + margin_y;

    for i in 0..entry_count {
        let entry = &entries[i];
        let col = i as i32 % icons_per_row;
        let row = i as i32 / icons_per_row;
        let cell_x = start_x + col * cell_width;
        let cell_y = start_y + row * cell_height;

        // Check if click is within cell area
        if screen_x >= cell_x && screen_x < cell_x + cell_width &&
           screen_y >= cell_y && screen_y < cell_y + cell_height {
            // Store the name in static buffer
            unsafe {
                let name_len = entry.name_len.min(255);
                CLICKED_ENTRY_NAME[..name_len].copy_from_slice(&entry.name[..name_len]);
                CLICKED_ENTRY_NAME[name_len] = 0;
                CLICKED_ENTRY_LEN = name_len;
                return Some(core::str::from_utf8_unchecked(&CLICKED_ENTRY_NAME[..CLICKED_ENTRY_LEN]));
            }
        }
    }

    None
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

/// Draw icon based on VFS icon type
fn draw_vfs_icon(surf: &surface::Surface, x: i32, y: i32, icon_type: VfsIconType) {
    match icon_type {
        VfsIconType::Folder => draw_folder_icon(surf, x, y),
        VfsIconType::Drive => draw_drive_icon(surf, x, y),
        VfsIconType::MyComputer => draw_my_computer_icon(surf, x, y),
        VfsIconType::MyDocuments => draw_folder_icon(surf, x, y), // Use folder for now
        VfsIconType::RecycleBin => draw_recycle_bin_icon(surf, x, y),
        VfsIconType::NetworkPlaces => draw_network_icon(surf, x, y),
        VfsIconType::ControlPanel => draw_control_panel_icon(surf, x, y),
        VfsIconType::Executable => draw_exe_icon(surf, x, y),
        VfsIconType::Document => draw_document_icon(surf, x, y),
        VfsIconType::Image => draw_image_icon(surf, x, y),
        VfsIconType::Audio => draw_audio_icon(surf, x, y),
        VfsIconType::Video => draw_video_icon(surf, x, y),
        VfsIconType::File => draw_file_icon(surf, x, y),
    }
}

/// Draw drive icon (hard disk)
fn draw_drive_icon(surf: &surface::Surface, x: i32, y: i32) {
    let drive_body = ColorRef::rgb(180, 180, 180);
    let drive_dark = ColorRef::rgb(100, 100, 100);
    let drive_light = ColorRef::rgb(220, 220, 220);
    let led_green = ColorRef::rgb(0, 200, 0);

    // Draw drive body
    for dy in 8..24 {
        surf.hline(x + 2, x + 28, y + dy, drive_body);
    }

    // 3D edges
    surf.hline(x + 2, x + 28, y + 8, drive_light);
    surf.vline(x + 2, y + 8, y + 24, drive_light);
    surf.hline(x + 2, x + 28, y + 23, drive_dark);
    surf.vline(x + 27, y + 8, y + 24, drive_dark);

    // Activity LED
    for dx in 0..4 {
        for dy in 0..2 {
            surf.set_pixel(x + 22 + dx, y + 18 + dy, led_green);
        }
    }
}

/// Draw My Computer icon
fn draw_my_computer_icon(surf: &surface::Surface, x: i32, y: i32) {
    let monitor_body = ColorRef::rgb(180, 180, 180);
    let screen_color = ColorRef::rgb(0, 0, 128);
    let dark = ColorRef::rgb(80, 80, 80);

    // Monitor body
    for dy in 2..20 {
        surf.hline(x + 4, x + 26, y + dy, monitor_body);
    }

    // Screen (blue)
    for dy in 4..16 {
        surf.hline(x + 6, x + 24, y + dy, screen_color);
    }

    // Monitor stand
    for dy in 20..24 {
        surf.hline(x + 10, x + 20, y + dy, monitor_body);
    }
    for dy in 24..26 {
        surf.hline(x + 6, x + 24, y + dy, dark);
    }
}

/// Draw Recycle Bin icon
fn draw_recycle_bin_icon(surf: &surface::Surface, x: i32, y: i32) {
    let bin_color = ColorRef::rgb(100, 100, 100);
    let lid_color = ColorRef::rgb(120, 120, 120);

    // Lid
    for dy in 4..8 {
        surf.hline(x + 6, x + 24, y + dy, lid_color);
    }

    // Body (tapered)
    for dy in 8..26 {
        let taper = (dy - 8) / 6;
        surf.hline(x + 8 - taper, x + 22 + taper, y + dy, bin_color);
    }
}

/// Draw Network icon
fn draw_network_icon(surf: &surface::Surface, x: i32, y: i32) {
    let computer_color = ColorRef::rgb(180, 180, 180);
    let wire_color = ColorRef::rgb(0, 0, 200);

    // Left computer
    for dy in 6..16 {
        surf.hline(x + 2, x + 10, y + dy, computer_color);
    }

    // Right computer
    for dy in 6..16 {
        surf.hline(x + 20, x + 28, y + dy, computer_color);
    }

    // Network wire between them
    surf.hline(x + 10, x + 20, y + 11, wire_color);

    // Bottom computer
    for dy in 18..26 {
        surf.hline(x + 11, x + 19, y + dy, computer_color);
    }

    // Vertical wire
    surf.vline(x + 15, y + 11, y + 18, wire_color);
}

/// Draw Control Panel icon (gears/settings)
fn draw_control_panel_icon(surf: &surface::Surface, x: i32, y: i32) {
    let gear_color = ColorRef::rgb(128, 128, 128);
    let center_color = ColorRef::rgb(64, 64, 64);

    // Simple gear representation
    for dy in 8..20 {
        surf.hline(x + 8, x + 22, y + dy, gear_color);
    }
    for dy in 4..24 {
        surf.hline(x + 12, x + 18, y + dy, gear_color);
    }

    // Center hole
    for dy in 12..16 {
        surf.hline(x + 13, x + 17, y + dy, center_color);
    }
}

/// Draw executable icon
fn draw_exe_icon(surf: &surface::Surface, x: i32, y: i32) {
    let window_bg = ColorRef::rgb(200, 200, 200);
    let titlebar = ColorRef::rgb(0, 0, 128);

    // Window frame
    for dy in 4..24 {
        surf.hline(x + 4, x + 26, y + dy, window_bg);
    }

    // Title bar
    for dy in 4..8 {
        surf.hline(x + 4, x + 26, y + dy, titlebar);
    }
}

/// Draw document icon
fn draw_document_icon(surf: &surface::Surface, x: i32, y: i32) {
    let paper_color = ColorRef::WHITE;
    let border_color = ColorRef::rgb(128, 128, 128);
    let text_color = ColorRef::rgb(64, 64, 64);

    // Paper background
    for dy in 2..26 {
        surf.hline(x + 6, x + 24, y + dy, paper_color);
    }

    // Paper border
    surf.hline(x + 6, x + 24, y + 2, border_color);
    surf.hline(x + 6, x + 24, y + 25, border_color);
    surf.vline(x + 6, y + 2, y + 26, border_color);
    surf.vline(x + 23, y + 2, y + 26, border_color);

    // Text lines
    surf.hline(x + 8, x + 20, y + 6, text_color);
    surf.hline(x + 8, x + 18, y + 10, text_color);
    surf.hline(x + 8, x + 21, y + 14, text_color);
    surf.hline(x + 8, x + 16, y + 18, text_color);
}

/// Draw image icon
fn draw_image_icon(surf: &surface::Surface, x: i32, y: i32) {
    let frame_color = ColorRef::rgb(64, 64, 64);
    let sky_color = ColorRef::rgb(135, 206, 235);
    let grass_color = ColorRef::rgb(34, 139, 34);
    let sun_color = ColorRef::rgb(255, 255, 0);

    // Frame
    for dy in 4..24 {
        surf.hline(x + 4, x + 26, y + dy, frame_color);
    }

    // Sky
    for dy in 6..16 {
        surf.hline(x + 6, x + 24, y + dy, sky_color);
    }

    // Grass
    for dy in 16..22 {
        surf.hline(x + 6, x + 24, y + dy, grass_color);
    }

    // Sun
    for dx in 0..4 {
        for dy in 0..4 {
            surf.set_pixel(x + 18 + dx, y + 8 + dy, sun_color);
        }
    }
}

/// Draw audio icon
fn draw_audio_icon(surf: &surface::Surface, x: i32, y: i32) {
    let note_color = ColorRef::rgb(0, 0, 0);

    // Musical note
    // Note head 1
    for dx in 0..4 {
        for dy in 0..3 {
            surf.set_pixel(x + 10 + dx, y + 18 + dy, note_color);
        }
    }
    // Stem 1
    surf.vline(x + 13, y + 6, y + 19, note_color);

    // Note head 2
    for dx in 0..4 {
        for dy in 0..3 {
            surf.set_pixel(x + 18 + dx, y + 20 + dy, note_color);
        }
    }
    // Stem 2
    surf.vline(x + 21, y + 8, y + 21, note_color);

    // Beam connecting notes
    surf.hline(x + 13, x + 22, y + 6, note_color);
    surf.hline(x + 13, x + 22, y + 7, note_color);
}

/// Draw video icon
fn draw_video_icon(surf: &surface::Surface, x: i32, y: i32) {
    let film_color = ColorRef::rgb(64, 64, 64);
    let screen_color = ColorRef::rgb(0, 0, 128);
    let sprocket_color = ColorRef::WHITE;

    // Film strip
    for dy in 4..24 {
        surf.hline(x + 4, x + 26, y + dy, film_color);
    }

    // Screen area
    for dy in 8..20 {
        surf.hline(x + 10, x + 20, y + dy, screen_color);
    }

    // Sprocket holes (left)
    for i in 0..3 {
        let sy = y + 6 + i * 6;
        surf.set_pixel(x + 6, sy, sprocket_color);
        surf.set_pixel(x + 7, sy, sprocket_color);
    }

    // Sprocket holes (right)
    for i in 0..3 {
        let sy = y + 6 + i * 6;
        surf.set_pixel(x + 22, sy, sprocket_color);
        surf.set_pixel(x + 23, sy, sprocket_color);
    }
}

/// Draw generic file icon
fn draw_file_icon(surf: &surface::Surface, x: i32, y: i32) {
    let paper_color = ColorRef::WHITE;
    let border_color = ColorRef::rgb(128, 128, 128);
    let fold_color = ColorRef::rgb(192, 192, 192);

    // Paper with folded corner
    for dy in 2..26 {
        surf.hline(x + 6, x + 24, y + dy, paper_color);
    }

    // Folded corner
    for dy in 2..8 {
        for dx in 0..(8 - (dy - 2)) {
            surf.set_pixel(x + 18 + dx, y + dy, fold_color);
        }
    }

    // Border
    surf.hline(x + 6, x + 18, y + 2, border_color);
    surf.hline(x + 6, x + 24, y + 25, border_color);
    surf.vline(x + 6, y + 2, y + 26, border_color);
    surf.vline(x + 23, y + 8, y + 26, border_color);
    // Diagonal fold
    for i in 0..6 {
        surf.set_pixel(x + 18 + i, y + 2 + i, border_color);
    }
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
/// Navigation button size constant
pub const NAV_BUTTON_SIZE: i32 = 22;

/// Get the navigation button rects for a window (back_rect, forward_rect)
/// Returns None if the window doesn't have navigation buttons
pub fn get_nav_button_rects(hwnd: HWND) -> Option<(Rect, Rect)> {
    let wnd = window::get_window(hwnd)?;

    if wnd.class_name_str() != "CabinetWClass" {
        return None;
    }

    let metrics = wnd.get_frame_metrics();
    let border = metrics.border_width;
    let caption = if wnd.has_caption() { metrics.caption_height } else { 0 };

    // Client area start (in screen coordinates)
    let client_x = wnd.rect.left + border;
    let client_y = wnd.rect.top + border + caption;

    // Navigation buttons position
    let nav_btn_y = client_y + 2;
    let back_x = client_x + 4;
    let forward_x = back_x + NAV_BUTTON_SIZE + 2;

    let back_rect = Rect::new(back_x, nav_btn_y, back_x + NAV_BUTTON_SIZE, nav_btn_y + NAV_BUTTON_SIZE);
    let forward_rect = Rect::new(forward_x, nav_btn_y, forward_x + NAV_BUTTON_SIZE, nav_btn_y + NAV_BUTTON_SIZE);

    Some((back_rect, forward_rect))
}

/// Check if a point is inside the back button
pub fn hit_test_back_button(hwnd: HWND, x: i32, y: i32) -> bool {
    if let Some((back_rect, _)) = get_nav_button_rects(hwnd) {
        x >= back_rect.left && x < back_rect.right && y >= back_rect.top && y < back_rect.bottom
    } else {
        false
    }
}

/// Check if a point is inside the forward button
pub fn hit_test_forward_button(hwnd: HWND, x: i32, y: i32) -> bool {
    if let Some((_, forward_rect)) = get_nav_button_rects(hwnd) {
        x >= forward_rect.left && x < forward_rect.right && y >= forward_rect.top && y < forward_rect.bottom
    } else {
        false
    }
}

/// Draw a navigation button (back or forward arrow)
fn draw_nav_button(surf: &surface::Surface, x: i32, y: i32, size: i32, is_back: bool, enabled: bool) {
    let rect = Rect::new(x, y, x + size, y + size);

    // Draw button face
    surf.fill_rect(&rect, ColorRef::BUTTON_FACE);

    // 3D border effect
    surf.hline(rect.left, rect.right - 1, rect.top, ColorRef::BUTTON_HIGHLIGHT);
    surf.vline(rect.left, rect.top, rect.bottom - 1, ColorRef::BUTTON_HIGHLIGHT);
    surf.hline(rect.left, rect.right, rect.bottom - 1, ColorRef::BUTTON_SHADOW);
    surf.vline(rect.right - 1, rect.top, rect.bottom, ColorRef::BUTTON_SHADOW);

    // Arrow color - black if enabled, gray if disabled
    let arrow_color = if enabled { ColorRef::BLACK } else { ColorRef::GRAY };

    // Draw arrow in center
    let cx = x + size / 2;
    let cy = y + size / 2;

    if is_back {
        // Left-pointing arrow (back)
        // Draw arrow head pointing left
        for i in 0..5 {
            let px = cx - 3 + i;
            surf.set_pixel(px, cy - i, arrow_color);
            surf.set_pixel(px, cy + i, arrow_color);
        }
        // Arrow stem
        surf.hline(cx - 3, cx + 4, cy, arrow_color);
        surf.hline(cx - 3, cx + 4, cy - 1, arrow_color);
        surf.hline(cx - 3, cx + 4, cy + 1, arrow_color);
    } else {
        // Right-pointing arrow (forward)
        // Draw arrow head pointing right
        for i in 0..5 {
            let px = cx + 3 - i;
            surf.set_pixel(px, cy - i, arrow_color);
            surf.set_pixel(px, cy + i, arrow_color);
        }
        // Arrow stem
        surf.hline(cx - 4, cx + 3, cy, arrow_color);
        surf.hline(cx - 4, cx + 3, cy - 1, arrow_color);
        surf.hline(cx - 4, cx + 3, cy + 1, arrow_color);
    }
}

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

    // Draw caption text - use logical coordinates (without viewport offset)
    // since gdi_text_out applies the viewport transformation
    let text_x = border + 4;
    let text_y = border + 2;

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

    // Draw context menu on top of everything
    super::context_menu::draw_context_menu();

    // Swap buffers to display the composed frame (double buffering)
    super::super::gdi::surface::swap_buffers();
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
