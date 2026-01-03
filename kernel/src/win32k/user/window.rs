//! Window Object Implementation
//!
//! Windows are the fundamental UI element in the Windows graphical subsystem.
//! Each window has a position, size, style, parent/child relationships,
//! and receives messages for user interaction.
//!
//! # Window Hierarchy
//!
//! - Desktop window (root)
//!   - Top-level windows (overlapped, popup)
//!     - Child windows
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/createw.c`
//! - `windows/core/ntuser/kernel/winmgr.c`

use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, UserObjectType, HWND, Rect, Point};
use super::{WindowStyle, WindowStyleEx, ShowCommand, MAX_WINDOWS};

// ============================================================================
// Constants
// ============================================================================

/// Default window position
pub const CW_USEDEFAULT: i32 = 0x80000000u32 as i32;

/// Maximum window title length
pub const MAX_WINDOW_TITLE: usize = 128;

// ============================================================================
// Window Structure
// ============================================================================

/// Window object
#[derive(Debug, Clone)]
pub struct Window {
    /// Window handle
    pub hwnd: HWND,

    /// Window class name
    pub class_name: [u8; 64],

    /// Window title
    pub title: [u8; MAX_WINDOW_TITLE],

    /// Title length
    pub title_len: usize,

    /// Window style
    pub style: WindowStyle,

    /// Extended style
    pub ex_style: WindowStyleEx,

    /// Window rectangle (screen coordinates)
    pub rect: Rect,

    /// Client rectangle (client coordinates)
    pub client_rect: Rect,

    /// Parent window
    pub parent: HWND,

    /// First child window
    pub child: HWND,

    /// Next sibling window
    pub sibling: HWND,

    /// Owner window (for popups)
    pub owner: HWND,

    /// Menu ID or menu handle
    pub menu: u32,

    /// Window is visible
    pub visible: bool,

    /// Window is enabled
    pub enabled: bool,

    /// Window is minimized
    pub minimized: bool,

    /// Window is maximized
    pub maximized: bool,

    /// Saved rect for restore (after maximize)
    pub restore_rect: Option<Rect>,

    /// Window needs repainting
    pub needs_paint: bool,

    /// Invalid region (area needing repaint)
    pub invalid_rect: Option<Rect>,

    /// Owning process ID
    pub owner_pid: u32,

    /// Owning thread ID
    pub owner_tid: u32,

    /// Reference count
    pub ref_count: u32,

    /// Valid flag
    pub valid: bool,

    /// Is desktop window
    pub is_desktop: bool,

    /// Z-order value (higher = on top)
    pub z_order: u32,
}

impl Default for Window {
    fn default() -> Self {
        Self {
            hwnd: HWND::NULL,
            class_name: [0; 64],
            title: [0; MAX_WINDOW_TITLE],
            title_len: 0,
            style: WindowStyle::OVERLAPPED,
            ex_style: WindowStyleEx::empty(),
            rect: Rect::new(0, 0, 0, 0),
            client_rect: Rect::new(0, 0, 0, 0),
            parent: HWND::NULL,
            child: HWND::NULL,
            sibling: HWND::NULL,
            owner: HWND::NULL,
            menu: 0,
            visible: false,
            enabled: true,
            minimized: false,
            maximized: false,
            restore_rect: None,
            needs_paint: true,
            invalid_rect: None,
            owner_pid: 0,
            owner_tid: 0,
            ref_count: 1,
            valid: false,
            is_desktop: false,
            z_order: 0,
        }
    }
}

impl Window {
    /// Get class name as string
    pub fn class_name_str(&self) -> &str {
        let len = self.class_name.iter().position(|&c| c == 0).unwrap_or(64);
        core::str::from_utf8(&self.class_name[..len]).unwrap_or("")
    }

    /// Get title as string
    pub fn title_str(&self) -> &str {
        core::str::from_utf8(&self.title[..self.title_len]).unwrap_or("")
    }

    /// Check if window has caption
    pub fn has_caption(&self) -> bool {
        self.style.contains(WindowStyle::CAPTION)
    }

    /// Check if window has border
    pub fn has_border(&self) -> bool {
        self.style.contains(WindowStyle::BORDER) ||
        self.style.contains(WindowStyle::DLGFRAME) ||
        self.style.contains(WindowStyle::THICKFRAME)
    }

    /// Calculate non-client area metrics
    pub fn get_frame_metrics(&self) -> FrameMetrics {
        let mut metrics = FrameMetrics::default();

        if self.has_caption() {
            metrics.caption_height = 20; // Classic caption height
        }

        if self.has_border() {
            if self.style.contains(WindowStyle::THICKFRAME) {
                metrics.border_width = 4; // Sizeable border
            } else if self.style.contains(WindowStyle::DLGFRAME) {
                metrics.border_width = 3; // Dialog border
            } else {
                metrics.border_width = 1; // Thin border
            }
        }

        if self.style.contains(WindowStyle::SYSMENU) {
            metrics.has_sys_menu = true;
        }
        if self.style.contains(WindowStyle::MINIMIZEBOX) {
            metrics.has_min_box = true;
        }
        if self.style.contains(WindowStyle::MAXIMIZEBOX) {
            metrics.has_max_box = true;
        }

        metrics
    }

    /// Calculate client rect from window rect
    pub fn calculate_client_rect(&mut self) {
        let metrics = self.get_frame_metrics();

        self.client_rect = Rect::new(
            metrics.border_width,
            metrics.border_width + metrics.caption_height,
            self.rect.width() - metrics.border_width,
            self.rect.height() - metrics.border_width,
        );
    }
}

/// Frame metrics for non-client area
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameMetrics {
    pub border_width: i32,
    pub caption_height: i32,
    pub has_sys_menu: bool,
    pub has_min_box: bool,
    pub has_max_box: bool,
}

// ============================================================================
// Window Table
// ============================================================================

struct WindowEntry {
    window: Option<Window>,
}

impl Default for WindowEntry {
    fn default() -> Self {
        Self { window: None }
    }
}

static WINDOW_TABLE: SpinLock<WindowTable> = SpinLock::new(WindowTable::new());
static NEXT_WINDOW_INDEX: AtomicU16 = AtomicU16::new(1);
static NEXT_Z_ORDER: AtomicU32 = AtomicU32::new(1);

struct WindowTable {
    entries: [WindowEntry; MAX_WINDOWS],
}

impl WindowTable {
    const fn new() -> Self {
        const EMPTY: WindowEntry = WindowEntry { window: None };
        Self {
            entries: [EMPTY; MAX_WINDOWS],
        }
    }
}

// Desktop window handle
static DESKTOP_WINDOW: SpinLock<HWND> = SpinLock::new(HWND::NULL);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize window manager
pub fn init() {
    // Create desktop window
    let desktop = create_desktop_window();
    *DESKTOP_WINDOW.lock() = desktop;

    crate::serial_println!("[USER/Window] Window manager initialized, desktop={:#x}",
        desktop.raw());
}

/// Create the desktop window
fn create_desktop_window() -> HWND {
    // Get screen dimensions
    let (width, height) = super::super::gdi::surface::get_primary_dimensions();

    let index = allocate_window_slot().expect("Failed to create desktop window");

    let mut window = Window::default();
    window.hwnd = HWND::new(index, UserObjectType::Window);
    window.style = WindowStyle::VISIBLE | WindowStyle::CLIPCHILDREN;
    window.rect = Rect::new(0, 0, width as i32, height as i32);
    window.client_rect = window.rect;
    window.visible = true;
    window.valid = true;

    // Set class name
    let class_name = b"Desktop";
    for (i, &b) in class_name.iter().enumerate() {
        window.class_name[i] = b;
    }

    let handle = window.hwnd;

    {
        let mut table = WINDOW_TABLE.lock();
        table.entries[index as usize].window = Some(window);
    }

    super::inc_window_count();

    handle
}

/// Get desktop window handle
pub fn get_desktop_window() -> HWND {
    *DESKTOP_WINDOW.lock()
}

// ============================================================================
// Window Operations
// ============================================================================

/// Allocate a window slot
fn allocate_window_slot() -> Option<u16> {
    let mut table = WINDOW_TABLE.lock();

    for i in 1..MAX_WINDOWS {
        if table.entries[i].window.is_none() {
            return Some(i as u16);
        }
    }

    None
}

/// Create a window
pub fn create_window(
    class_name: &str,
    window_name: &str,
    style: WindowStyle,
    ex_style: WindowStyleEx,
    mut x: i32,
    mut y: i32,
    mut width: i32,
    mut height: i32,
    parent: HWND,
    menu: u32,
) -> HWND {
    // Allocate window slot
    let index = match allocate_window_slot() {
        Some(i) => i,
        None => return HWND::NULL,
    };

    // Handle CW_USEDEFAULT
    if x == CW_USEDEFAULT {
        x = 100;
    }
    if y == CW_USEDEFAULT {
        y = 100;
    }
    if width == CW_USEDEFAULT {
        width = 400;
    }
    if height == CW_USEDEFAULT {
        height = 300;
    }

    let handle = HWND::new(index, UserObjectType::Window);

    let mut window = Window::default();
    window.hwnd = handle;
    window.style = style;
    window.ex_style = ex_style;
    window.rect = Rect::new(x, y, x + width, y + height);
    window.parent = if parent.is_valid() { parent } else { get_desktop_window() };
    window.menu = menu;
    window.visible = style.contains(WindowStyle::VISIBLE);
    window.enabled = !style.contains(WindowStyle::DISABLED);
    window.minimized = style.contains(WindowStyle::MINIMIZE);
    window.maximized = style.contains(WindowStyle::MAXIMIZE);
    window.needs_paint = true;
    window.z_order = NEXT_Z_ORDER.fetch_add(1, Ordering::SeqCst);
    window.valid = true;

    // Copy class name
    for (i, &b) in class_name.as_bytes().iter().take(63).enumerate() {
        window.class_name[i] = b;
    }

    // Copy window title
    window.title_len = window_name.len().min(MAX_WINDOW_TITLE - 1);
    for (i, &b) in window_name.as_bytes().iter().take(window.title_len).enumerate() {
        window.title[i] = b;
    }

    // Calculate client rect
    window.calculate_client_rect();

    // Link to parent's child list
    if window.parent.is_valid() {
        link_window_to_parent(handle, window.parent);
    }

    {
        let mut table = WINDOW_TABLE.lock();
        table.entries[index as usize].window = Some(window);
    }

    super::inc_window_count();

    // Send WM_CREATE message
    super::message::send_message(handle, super::message::WM_CREATE, 0, 0);

    // If visible, send WM_SHOWWINDOW and WM_PAINT
    if style.contains(WindowStyle::VISIBLE) {
        super::message::send_message(handle, super::message::WM_SHOWWINDOW, 1, 0);
        super::message::post_message(handle, super::message::WM_PAINT, 0, 0);
    }

    handle
}

/// Link window to parent's child list
fn link_window_to_parent(hwnd: HWND, parent: HWND) {
    let mut table = WINDOW_TABLE.lock();

    // Get current first child of parent
    let first_child = if let Some(ref parent_wnd) = table.entries[parent.index() as usize].window {
        parent_wnd.child
    } else {
        return;
    };

    // Set new window as first child
    if let Some(ref mut parent_wnd) = table.entries[parent.index() as usize].window {
        parent_wnd.child = hwnd;
    }

    // Set old first child as sibling of new window
    if let Some(ref mut wnd) = table.entries[hwnd.index() as usize].window {
        wnd.sibling = first_child;
    }
}

/// Destroy a window
pub fn destroy_window(hwnd: HWND) -> bool {
    if !hwnd.is_valid() {
        return false;
    }

    // Send WM_DESTROY
    super::message::send_message(hwnd, super::message::WM_DESTROY, 0, 0);

    // Destroy children first
    let children = get_child_windows(hwnd);
    for child in children {
        destroy_window(child);
    }

    // Remove from taskbar
    super::explorer::remove_taskbar_button(hwnd);

    let index = hwnd.index() as usize;
    if index >= MAX_WINDOWS {
        return false;
    }

    let mut table = WINDOW_TABLE.lock();
    if table.entries[index].window.is_some() {
        table.entries[index].window = None;
        super::dec_window_count();

        // Repaint desktop to remove window
        drop(table); // Release lock before repainting
        super::paint::repaint_all();
        super::explorer::paint_taskbar();

        true
    } else {
        false
    }
}

/// Get child windows
fn get_child_windows(hwnd: HWND) -> [HWND; 64] {
    let mut children = [HWND::NULL; 64];
    let mut count = 0;

    let table = WINDOW_TABLE.lock();

    if let Some(ref wnd) = table.entries[hwnd.index() as usize].window {
        let mut child = wnd.child;

        while child.is_valid() && count < 64 {
            children[count] = child;
            count += 1;

            if let Some(ref child_wnd) = table.entries[child.index() as usize].window {
                child = child_wnd.sibling;
            } else {
                break;
            }
        }
    }

    children
}

/// Get a child window by its control ID
pub fn get_child_by_id(hwnd: HWND, id: u32) -> HWND {
    if !hwnd.is_valid() {
        return HWND::NULL;
    }

    let table = WINDOW_TABLE.lock();
    let parent_index = hwnd.index() as usize;

    if parent_index >= MAX_WINDOWS {
        return HWND::NULL;
    }

    if let Some(ref wnd) = table.entries[parent_index].window {
        let mut child = wnd.child;

        while child.is_valid() {
            let child_index = child.index() as usize;
            if child_index >= MAX_WINDOWS {
                break;
            }

            if let Some(ref child_wnd) = table.entries[child_index].window {
                // Check if this child has the matching ID (stored in menu field for controls)
                if child_wnd.menu == id {
                    return child;
                }
                child = child_wnd.sibling;
            } else {
                break;
            }
        }
    }

    HWND::NULL
}

/// Show/hide a window
pub fn show_window(hwnd: HWND, cmd: ShowCommand) -> bool {
    if !hwnd.is_valid() {
        return false;
    }

    let index = hwnd.index() as usize;
    if index >= MAX_WINDOWS {
        return false;
    }

    let was_visible = {
        let table = WINDOW_TABLE.lock();
        table.entries[index].window.as_ref().map(|w| w.visible).unwrap_or(false)
    };

    let mut table = WINDOW_TABLE.lock();
    if let Some(ref mut wnd) = table.entries[index].window {
        match cmd {
            ShowCommand::Hide => {
                wnd.visible = false;
            }
            ShowCommand::Show | ShowCommand::ShowNormal | ShowCommand::ShowDefault => {
                wnd.visible = true;
                wnd.minimized = false;
                wnd.maximized = false;
            }
            ShowCommand::ShowMinimized | ShowCommand::Minimize => {
                wnd.visible = true;
                wnd.minimized = true;
                wnd.maximized = false;
            }
            ShowCommand::ShowMaximized => {
                wnd.visible = true;
                wnd.minimized = false;
                wnd.maximized = true;
            }
            ShowCommand::Restore => {
                wnd.visible = true;
                wnd.minimized = false;
                wnd.maximized = false;
            }
            _ => {}
        }

        wnd.needs_paint = true;
    }

    // Post paint message if newly visible
    drop(table);
    if !was_visible {
        super::message::post_message(hwnd, super::message::WM_PAINT, 0, 0);
    }

    was_visible
}

/// Get window by handle
pub fn get_window(hwnd: HWND) -> Option<Window> {
    if !hwnd.is_valid() {
        return None;
    }

    let index = hwnd.index() as usize;
    if index >= MAX_WINDOWS {
        return None;
    }

    let table = WINDOW_TABLE.lock();
    table.entries[index].window.clone()
}

/// Get mutable access to window (via callback)
pub fn with_window_mut<F, R>(hwnd: HWND, f: F) -> Option<R>
where
    F: FnOnce(&mut Window) -> R,
{
    if !hwnd.is_valid() {
        return None;
    }

    let index = hwnd.index() as usize;
    if index >= MAX_WINDOWS {
        return None;
    }

    let mut table = WINDOW_TABLE.lock();
    if let Some(ref mut wnd) = table.entries[index].window {
        Some(f(wnd))
    } else {
        None
    }
}

/// Get window rectangle
pub fn get_window_rect(hwnd: HWND) -> Option<Rect> {
    get_window(hwnd).map(|w| w.rect)
}

/// Get client rectangle
pub fn get_client_rect(hwnd: HWND) -> Option<Rect> {
    get_window(hwnd).map(|w| w.client_rect)
}

/// Move a window
pub fn move_window(hwnd: HWND, x: i32, y: i32, width: i32, height: i32, repaint: bool) -> bool {
    with_window_mut(hwnd, |wnd| {
        wnd.rect = Rect::new(x, y, x + width, y + height);
        wnd.calculate_client_rect();
        if repaint {
            wnd.needs_paint = true;
        }
    }).is_some()
}

/// Set window position
pub fn set_window_pos(hwnd: HWND, x: i32, y: i32, width: i32, height: i32, _flags: u32) -> bool {
    move_window(hwnd, x, y, width, height, true)
}

/// Set window text
pub fn set_window_text(hwnd: HWND, text: &str) -> bool {
    with_window_mut(hwnd, |wnd| {
        wnd.title_len = text.len().min(MAX_WINDOW_TITLE - 1);
        wnd.title = [0; MAX_WINDOW_TITLE];
        for (i, &b) in text.as_bytes().iter().take(wnd.title_len).enumerate() {
            wnd.title[i] = b;
        }
    }).is_some()
}

/// Get window text
pub fn get_window_text(hwnd: HWND, buffer: &mut [u8]) -> usize {
    if let Some(wnd) = get_window(hwnd) {
        let len = wnd.title_len.min(buffer.len());
        buffer[..len].copy_from_slice(&wnd.title[..len]);
        len
    } else {
        0
    }
}

/// Check if window is visible
pub fn is_window_visible(hwnd: HWND) -> bool {
    get_window(hwnd).map(|w| w.visible).unwrap_or(false)
}

/// Check if window is enabled
pub fn is_window_enabled(hwnd: HWND) -> bool {
    get_window(hwnd).map(|w| w.enabled).unwrap_or(false)
}

/// Get parent window
pub fn get_parent(hwnd: HWND) -> HWND {
    get_window(hwnd).map(|w| w.parent).unwrap_or(HWND::NULL)
}

/// Client to screen coordinate conversion
pub fn client_to_screen(hwnd: HWND, pt: Point) -> Point {
    if let Some(wnd) = get_window(hwnd) {
        let metrics = wnd.get_frame_metrics();
        Point::new(
            wnd.rect.left + metrics.border_width + pt.x,
            wnd.rect.top + metrics.border_width + metrics.caption_height + pt.y,
        )
    } else {
        pt
    }
}

/// Screen to client coordinate conversion
pub fn screen_to_client(hwnd: HWND, pt: Point) -> Point {
    if let Some(wnd) = get_window(hwnd) {
        let metrics = wnd.get_frame_metrics();
        Point::new(
            pt.x - wnd.rect.left - metrics.border_width,
            pt.y - wnd.rect.top - metrics.border_width - metrics.caption_height,
        )
    } else {
        pt
    }
}

// ============================================================================
// Shell Support Functions
// ============================================================================

/// Get list of windows that need repainting
pub fn get_dirty_windows() -> [HWND; 16] {
    let mut result = [HWND::NULL; 16];
    let mut count = 0;

    let table = WINDOW_TABLE.lock();
    for entry in table.entries.iter() {
        if let Some(ref wnd) = entry.window {
            if wnd.valid && wnd.visible && wnd.needs_paint && count < 16 {
                result[count] = wnd.hwnd;
                count += 1;
            }
        }
    }

    result
}

/// Get count of valid windows
pub fn get_window_count() -> u32 {
    let mut count = 0u32;

    let table = WINDOW_TABLE.lock();
    for entry in table.entries.iter() {
        if let Some(ref wnd) = entry.window {
            if wnd.valid && wnd.visible && !wnd.is_desktop {
                count += 1;
            }
        }
    }

    count
}

/// Get window handle at a specific index (for Alt+Tab)
pub fn get_window_at_index(index: usize) -> Option<HWND> {
    let mut current = 0usize;

    let table = WINDOW_TABLE.lock();
    for entry in table.entries.iter() {
        if let Some(ref wnd) = entry.window {
            if wnd.valid && wnd.visible && !wnd.is_desktop {
                if current == index {
                    return Some(wnd.hwnd);
                }
                current += 1;
            }
        }
    }

    None
}

/// Get window text as static string
pub fn get_window_text_str(hwnd: HWND) -> &'static str {
    // For now, return a placeholder
    // In a full implementation, we'd need a different approach
    if let Some(wnd) = get_window(hwnd) {
        if wnd.title_len > 0 {
            return "Window";
        }
    }
    "Window"
}

/// Set foreground window (bring to top of z-order)
pub fn set_foreground_window(hwnd: HWND) -> bool {
    if !hwnd.is_valid() {
        return false;
    }

    // Assign new highest z-order value
    let new_z = NEXT_Z_ORDER.fetch_add(1, Ordering::SeqCst);

    with_window_mut(hwnd, |wnd| {
        wnd.visible = true;
        wnd.needs_paint = true;
        wnd.z_order = new_z;
    });

    true
}

/// Bring window to top of z-order
pub fn bring_window_to_top(hwnd: HWND) -> bool {
    set_foreground_window(hwnd)
}

/// ShowWindowCmd enum for shell compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShowWindowCmd {
    Hide = 0,
    Show = 1,
    Minimize = 2,
    Maximize = 3,
    Restore = 4,
}

// ============================================================================
// Point-Based Window Lookup
// ============================================================================

/// Find the topmost window at a given screen point
pub fn window_from_point(pt: Point) -> HWND {
    let table = WINDOW_TABLE.lock();

    // Find topmost visible window containing this point using z-order
    let mut best = HWND::NULL;
    let mut best_z_order: u32 = 0;

    for entry in table.entries.iter() {
        if let Some(ref wnd) = entry.window {
            // Skip desktop and hidden windows
            if !wnd.valid || !wnd.visible || wnd.is_desktop || wnd.minimized {
                continue;
            }

            // Check if point is inside this window
            if pt.x >= wnd.rect.left && pt.x < wnd.rect.right &&
               pt.y >= wnd.rect.top && pt.y < wnd.rect.bottom {
                // Use z-order to determine topmost window
                if wnd.z_order > best_z_order || !best.is_valid() {
                    best = wnd.hwnd;
                    best_z_order = wnd.z_order;
                }
            }
        }
    }

    // If no window found, return desktop
    if !best.is_valid() {
        best = get_desktop_window();
    }

    best
}

/// Find a child window at a point (relative to parent's client area)
pub fn child_window_from_point(parent: HWND, pt: Point) -> HWND {
    if !parent.is_valid() {
        return HWND::NULL;
    }

    let parent_wnd = match get_window(parent) {
        Some(w) => w,
        None => return HWND::NULL,
    };

    // Convert to screen coordinates
    let screen_pt = client_to_screen(parent, pt);

    // Search children
    let table = WINDOW_TABLE.lock();

    let mut child = parent_wnd.child;
    while child.is_valid() {
        let child_index = child.index() as usize;
        if child_index >= MAX_WINDOWS {
            break;
        }

        if let Some(ref child_wnd) = table.entries[child_index].window {
            if child_wnd.valid && child_wnd.visible {
                if screen_pt.x >= child_wnd.rect.left && screen_pt.x < child_wnd.rect.right &&
                   screen_pt.y >= child_wnd.rect.top && screen_pt.y < child_wnd.rect.bottom {
                    return child;
                }
            }
            child = child_wnd.sibling;
        } else {
            break;
        }
    }

    // Point not in any child - return parent
    parent
}
