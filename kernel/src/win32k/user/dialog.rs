//! Dialog Box Subsystem
//!
//! Implementation of Windows NT-style dialog boxes following the USER architecture.
//! Provides modal and modeless dialogs, dialog templates, and standard dialogs.
//!
//! # Components
//!
//! - **Dialog creation**: CreateDialog, DialogBox
//! - **Dialog procedures**: DLGPROC handling
//! - **Dialog controls**: Tab navigation, default buttons
//! - **Message boxes**: Standard message box dialogs
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/dlgmgr.c`
//! - `windows/core/ntuser/kernel/msgbox.c`

use super::super::{HWND, UserHandle, ColorRef, Rect};
use super::super::gdi::{dc, surface, brush};
use super::message::{self};
use super::window;
use super::{WindowStyle, WindowStyleEx, ShowCommand};
use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of active dialogs
const MAX_DIALOGS: usize = 32;

/// Maximum controls per dialog
const MAX_DIALOG_CONTROLS: usize = 32;

/// Dialog message: Initialize dialog
pub const WM_INITDIALOG: u32 = 0x0110;

/// Dialog return codes
pub const IDOK: i32 = 1;
pub const IDCANCEL: i32 = 2;
pub const IDABORT: i32 = 3;
pub const IDRETRY: i32 = 4;
pub const IDIGNORE: i32 = 5;
pub const IDYES: i32 = 6;
pub const IDNO: i32 = 7;
pub const IDCLOSE: i32 = 8;
pub const IDHELP: i32 = 9;

// ============================================================================
// Dialog Styles (DS_*)
// ============================================================================

bitflags::bitflags! {
    /// Dialog styles
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct DialogStyle: u32 {
        /// Absolute alignment
        const ABSALIGN = 0x0001;
        /// Use system font
        const SYSMODAL = 0x0002;
        /// 3D look (deprecated)
        const DS_3DLOOK = 0x0004;
        /// Fixed system font
        const FIXEDSYS = 0x0008;
        /// No fail on create
        const NOFAILCREATE = 0x0010;
        /// Local edit
        const LOCALEDIT = 0x0020;
        /// Set foreground
        const SETFOREGROUND = 0x0200;
        /// Control parent
        const CONTROL = 0x0400;
        /// Center on parent
        const CENTER = 0x0800;
        /// Center on screen
        const CENTERMOUSE = 0x1000;
        /// Context help
        const CONTEXTHELP = 0x2000;
        /// Use shell font
        const SHELLFONT = 0x0040 | 0x0008;
        /// Modal frame
        const MODALFRAME = 0x0080;
    }
}

// ============================================================================
// Message Box Types (MB_*)
// ============================================================================

bitflags::bitflags! {
    /// Message box types and flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct MessageBoxFlags: u32 {
        /// OK button only
        const OK = 0x00000000;
        /// OK and Cancel buttons
        const OKCANCEL = 0x00000001;
        /// Abort, Retry, Ignore buttons
        const ABORTRETRYIGNORE = 0x00000002;
        /// Yes, No, Cancel buttons
        const YESNOCANCEL = 0x00000003;
        /// Yes, No buttons
        const YESNO = 0x00000004;
        /// Retry, Cancel buttons
        const RETRYCANCEL = 0x00000005;
        /// Cancel, Try Again, Continue
        const CANCELTRYCONTINUE = 0x00000006;

        /// Icon: Hand/Error
        const ICONHAND = 0x00000010;
        const ICONERROR = 0x00000010;
        const ICONSTOP = 0x00000010;
        /// Icon: Question
        const ICONQUESTION = 0x00000020;
        /// Icon: Exclamation/Warning
        const ICONEXCLAMATION = 0x00000030;
        const ICONWARNING = 0x00000030;
        /// Icon: Information
        const ICONASTERISK = 0x00000040;
        const ICONINFORMATION = 0x00000040;

        /// Default button 1
        const DEFBUTTON1 = 0x00000000;
        /// Default button 2
        const DEFBUTTON2 = 0x00000100;
        /// Default button 3
        const DEFBUTTON3 = 0x00000200;
        /// Default button 4
        const DEFBUTTON4 = 0x00000300;

        /// Application modal
        const APPLMODAL = 0x00000000;
        /// System modal
        const SYSTEMMODAL = 0x00001000;
        /// Task modal
        const TASKMODAL = 0x00002000;

        /// Add help button
        const HELP = 0x00004000;
        /// No focus
        const NOFOCUS = 0x00008000;
        /// Set foreground
        const SETFOREGROUND = 0x00010000;
        /// Default desktop only
        const DEFAULT_DESKTOP_ONLY = 0x00020000;
        /// Topmost
        const TOPMOST = 0x00040000;
        /// Right aligned text
        const RIGHT = 0x00080000;
        /// RTL reading order
        const RTLREADING = 0x00100000;
    }
}

// ============================================================================
// Dialog Control Template
// ============================================================================

/// Dialog control item template
#[derive(Clone, Copy)]
pub struct DialogControlItem {
    /// Control style
    pub style: u32,
    /// Extended style
    pub ex_style: u32,
    /// X position (dialog units)
    pub x: i16,
    /// Y position (dialog units)
    pub y: i16,
    /// Width (dialog units)
    pub cx: i16,
    /// Height (dialog units)
    pub cy: i16,
    /// Control ID
    pub id: u16,
    /// Control class (predefined)
    pub class: DialogControlClass,
    /// Text buffer
    pub text: [u8; 32],
    pub text_len: usize,
}

impl DialogControlItem {
    pub const fn empty() -> Self {
        Self {
            style: 0,
            ex_style: 0,
            x: 0,
            y: 0,
            cx: 0,
            cy: 0,
            id: 0,
            class: DialogControlClass::Button,
            text: [0; 32],
            text_len: 0,
        }
    }

    pub fn get_text(&self) -> &str {
        core::str::from_utf8(&self.text[..self.text_len]).unwrap_or("")
    }
}

/// Predefined dialog control classes
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DialogControlClass {
    #[default]
    Button = 0x0080,
    Edit = 0x0081,
    Static = 0x0082,
    ListBox = 0x0083,
    ScrollBar = 0x0084,
    ComboBox = 0x0085,
}

// ============================================================================
// Dialog Template
// ============================================================================

/// Dialog template
#[derive(Clone, Copy)]
pub struct DialogTemplate {
    /// Dialog style
    pub style: DialogStyle,
    /// Window style
    pub window_style: WindowStyle,
    /// Extended style
    pub ex_style: WindowStyleEx,
    /// Number of controls
    pub control_count: u16,
    /// X position (dialog units)
    pub x: i16,
    /// Y position (dialog units)
    pub y: i16,
    /// Width (dialog units)
    pub cx: i16,
    /// Height (dialog units)
    pub cy: i16,
    /// Title buffer
    pub title: [u8; 64],
    pub title_len: usize,
    /// Controls
    pub controls: [DialogControlItem; MAX_DIALOG_CONTROLS],
}

impl DialogTemplate {
    pub const fn empty() -> Self {
        Self {
            style: DialogStyle::empty(),
            window_style: WindowStyle::empty(),
            ex_style: WindowStyleEx::empty(),
            control_count: 0,
            x: 0,
            y: 0,
            cx: 200,
            cy: 100,
            title: [0; 64],
            title_len: 0,
            controls: [DialogControlItem::empty(); MAX_DIALOG_CONTROLS],
        }
    }

    pub fn get_title(&self) -> &str {
        core::str::from_utf8(&self.title[..self.title_len]).unwrap_or("")
    }

    /// Set dialog title
    pub fn set_title(&mut self, title: &str) {
        let bytes = title.as_bytes();
        let len = bytes.len().min(63);
        self.title[..len].copy_from_slice(&bytes[..len]);
        self.title_len = len;
    }

    /// Add a control to the template
    pub fn add_control(
        &mut self,
        class: DialogControlClass,
        text: &str,
        id: u16,
        x: i16,
        y: i16,
        cx: i16,
        cy: i16,
        style: u32,
    ) -> bool {
        if self.control_count as usize >= MAX_DIALOG_CONTROLS {
            return false;
        }

        let item = &mut self.controls[self.control_count as usize];
        item.class = class;
        item.id = id;
        item.x = x;
        item.y = y;
        item.cx = cx;
        item.cy = cy;
        item.style = style;

        let bytes = text.as_bytes();
        let len = bytes.len().min(31);
        item.text[..len].copy_from_slice(&bytes[..len]);
        item.text_len = len;

        self.control_count += 1;
        true
    }
}

// ============================================================================
// Dialog Instance
// ============================================================================

/// Active dialog instance
#[derive(Clone, Copy)]
struct DialogInstance {
    /// Dialog window handle
    hwnd: HWND,
    /// Parent window
    parent: HWND,
    /// Is modal?
    is_modal: bool,
    /// Result code
    result: i32,
    /// Is dialog ended?
    ended: bool,
    /// In use?
    in_use: bool,
}

impl DialogInstance {
    const fn empty() -> Self {
        Self {
            hwnd: UserHandle::NULL,
            parent: UserHandle::NULL,
            is_modal: false,
            result: 0,
            ended: false,
            in_use: false,
        }
    }
}

struct DialogTable {
    dialogs: [DialogInstance; MAX_DIALOGS],
    count: usize,
}

impl DialogTable {
    const fn new() -> Self {
        Self {
            dialogs: [DialogInstance::empty(); MAX_DIALOGS],
            count: 0,
        }
    }
}

static DIALOG_TABLE: SpinLock<DialogTable> = SpinLock::new(DialogTable::new());
static DIALOG_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize dialog subsystem
pub fn init() {
    if DIALOG_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[USER/Dialog] Dialog subsystem initialized");
    DIALOG_INITIALIZED.store(true, Ordering::Release);
}

// ============================================================================
// Dialog Unit Conversion
// ============================================================================

/// Convert dialog units to pixels (horizontal)
pub fn du_to_pixels_x(du: i16) -> i32 {
    // Approximate: 1 dialog unit = 2 pixels horizontally
    // (In Windows, this is based on font metrics)
    (du as i32) * 2
}

/// Convert dialog units to pixels (vertical)
pub fn du_to_pixels_y(du: i16) -> i32 {
    // Approximate: 1 dialog unit = 2 pixels vertically
    (du as i32) * 2
}

// ============================================================================
// Dialog Creation
// ============================================================================

/// Create a modeless dialog
pub fn create_dialog(
    template: &DialogTemplate,
    parent: HWND,
) -> HWND {
    create_dialog_internal(template, parent, false)
}

/// Create and run a modal dialog
pub fn dialog_box(
    template: &DialogTemplate,
    parent: HWND,
) -> i32 {
    let hwnd = create_dialog_internal(template, parent, true);
    if !hwnd.is_valid() {
        return -1;
    }

    // Run modal message loop
    run_modal_loop(hwnd)
}

/// Internal dialog creation
fn create_dialog_internal(
    template: &DialogTemplate,
    parent: HWND,
    is_modal: bool,
) -> HWND {
    // Calculate pixel dimensions
    let x = du_to_pixels_x(template.x);
    let y = du_to_pixels_y(template.y);
    let cx = du_to_pixels_x(template.cx);
    let cy = du_to_pixels_y(template.cy);

    // Center dialog if requested
    let (final_x, final_y) = if template.style.contains(DialogStyle::CENTER) {
        // Center on screen (assume 800x600 for now)
        ((800 - cx) / 2, (600 - cy) / 2)
    } else {
        (x, y)
    };

    // Create dialog window with appropriate styles
    let style = WindowStyle::OVERLAPPED
        | WindowStyle::CAPTION
        | WindowStyle::SYSMENU
        | WindowStyle::VISIBLE;

    let hwnd = window::create_window(
        "Dialog",
        template.get_title(),
        style,
        WindowStyleEx::DLGMODALFRAME,
        final_x,
        final_y,
        cx,
        cy,
        parent,
        0,
    );

    if !hwnd.is_valid() {
        return UserHandle::NULL;
    }

    // Register dialog
    {
        let mut table = DIALOG_TABLE.lock();
        for dialog in table.dialogs.iter_mut() {
            if !dialog.in_use {
                dialog.hwnd = hwnd;
                dialog.parent = parent;
                dialog.is_modal = is_modal;
                dialog.result = 0;
                dialog.ended = false;
                dialog.in_use = true;
                table.count += 1;
                break;
            }
        }
    }

    // Create controls from template
    for i in 0..template.control_count as usize {
        let ctrl = &template.controls[i];
        create_dialog_control(hwnd, ctrl);
    }

    // Send WM_INITDIALOG
    message::send_message(hwnd, WM_INITDIALOG, parent.raw() as usize, 0);

    // Show window
    window::show_window(hwnd, ShowCommand::Show);

    hwnd
}

/// Create a dialog control
fn create_dialog_control(parent: HWND, ctrl: &DialogControlItem) {
    let x = du_to_pixels_x(ctrl.x);
    let y = du_to_pixels_y(ctrl.y);
    let cx = du_to_pixels_x(ctrl.cx);
    let cy = du_to_pixels_y(ctrl.cy);

    let class_name = match ctrl.class {
        DialogControlClass::Button => "Button",
        DialogControlClass::Edit => "Edit",
        DialogControlClass::Static => "Static",
        DialogControlClass::ListBox => "ListBox",
        DialogControlClass::ScrollBar => "ScrollBar",
        DialogControlClass::ComboBox => "ComboBox",
    };

    let style = WindowStyle::CHILD | WindowStyle::VISIBLE | WindowStyle::from_bits_truncate(ctrl.style);

    window::create_window(
        class_name,
        ctrl.get_text(),
        style,
        WindowStyleEx::from_bits_truncate(ctrl.ex_style),
        x,
        y,
        cx,
        cy,
        parent,
        ctrl.id as u32,
    );
}

/// Run modal message loop
fn run_modal_loop(hwnd: HWND) -> i32 {
    // In a real implementation, this would be a full message loop
    // that processes messages until the dialog is ended.
    // For now, return a default value.

    // Check if dialog has ended
    let table = DIALOG_TABLE.lock();
    for dialog in table.dialogs.iter() {
        if dialog.in_use && dialog.hwnd == hwnd {
            if dialog.ended {
                return dialog.result;
            }
        }
    }

    // Default: dialog was closed
    IDCANCEL
}

// ============================================================================
// Dialog Control
// ============================================================================

/// End a modal dialog
pub fn end_dialog(hwnd: HWND, result: i32) -> bool {
    let mut table = DIALOG_TABLE.lock();

    for dialog in table.dialogs.iter_mut() {
        if dialog.in_use && dialog.hwnd == hwnd {
            dialog.result = result;
            dialog.ended = true;

            // Destroy dialog window
            drop(table);
            window::destroy_window(hwnd);

            return true;
        }
    }

    false
}

/// Get dialog item (control) handle
pub fn get_dlg_item(hwnd: HWND, id: i32) -> HWND {
    // Search child windows for matching ID
    window::get_child_by_id(hwnd, id as u32)
}

/// Set dialog item text
pub fn set_dlg_item_text(hwnd: HWND, id: i32, text: &str) -> bool {
    let item = get_dlg_item(hwnd, id);
    if item.is_valid() {
        window::set_window_text(item, text);
        return true;
    }
    false
}

/// Get dialog item text
pub fn get_dlg_item_text(hwnd: HWND, id: i32, buffer: &mut [u8]) -> usize {
    let item = get_dlg_item(hwnd, id);
    if item.is_valid() {
        return window::get_window_text(item, buffer);
    }
    0
}

/// Check a dialog button
pub fn check_dlg_button(hwnd: HWND, id: i32, check: bool) -> bool {
    let item = get_dlg_item(hwnd, id);
    if item.is_valid() {
        // Send BM_SETCHECK message
        const BM_SETCHECK: u32 = 0x00F1;
        message::send_message(item, BM_SETCHECK, if check { 1 } else { 0 }, 0);
        return true;
    }
    false
}

/// Is dialog button checked?
pub fn is_dlg_button_checked(hwnd: HWND, id: i32) -> bool {
    let item = get_dlg_item(hwnd, id);
    if item.is_valid() {
        const BM_GETCHECK: u32 = 0x00F0;
        return message::send_message(item, BM_GETCHECK, 0, 0) != 0;
    }
    false
}

// ============================================================================
// Message Box
// ============================================================================

/// Display a message box
pub fn message_box(
    parent: HWND,
    text: &str,
    caption: &str,
    flags: MessageBoxFlags,
) -> i32 {
    // Calculate message box dimensions
    let text_width = text.len() as i32 * 8;
    let text_lines = text.lines().count() as i32;
    let text_height = text_lines.max(1) * 20;

    let button_count = get_button_count(flags);
    let buttons_width = button_count as i32 * 80 + (button_count as i32 - 1) * 10;

    let box_width = text_width.max(buttons_width).max(200) + 40;
    let box_height = text_height + 80 + 40; // text + buttons + margins

    // Create message box template
    let mut template = DialogTemplate::empty();
    template.style = DialogStyle::CENTER | DialogStyle::MODALFRAME;
    template.set_title(caption);
    template.cx = (box_width / 2) as i16;
    template.cy = (box_height / 2) as i16;

    // Add text static control
    template.add_control(
        DialogControlClass::Static,
        text,
        0xFFFF,
        20 / 2,
        20 / 2,
        (text_width / 2) as i16,
        (text_height / 2) as i16,
        0,
    );

    // Add buttons based on flags
    let button_y = ((box_height - 50) / 2) as i16;
    let button_width = 75 / 2;
    let button_height = 23 / 2;

    let buttons = get_button_ids(flags);
    let start_x = ((box_width - buttons_width) / 4) as i16;

    for (i, (id, label)) in buttons.iter().enumerate() {
        let x = start_x + (i as i16 * 45);
        template.add_control(
            DialogControlClass::Button,
            label,
            *id as u16,
            x,
            button_y,
            button_width,
            button_height,
            0,
        );
    }

    // Show modal dialog
    dialog_box(&template, parent)
}

/// Get button count for message box type
fn get_button_count(flags: MessageBoxFlags) -> usize {
    let button_type = flags.bits() & 0x0F;
    match button_type {
        0 => 1,  // OK
        1 => 2,  // OKCANCEL
        2 => 3,  // ABORTRETRYIGNORE
        3 => 3,  // YESNOCANCEL
        4 => 2,  // YESNO
        5 => 2,  // RETRYCANCEL
        6 => 3,  // CANCELTRYCONTINUE
        _ => 1,
    }
}

/// Get button IDs and labels for message box type
fn get_button_ids(flags: MessageBoxFlags) -> [(i32, &'static str); 3] {
    let button_type = flags.bits() & 0x0F;
    match button_type {
        0 => [(IDOK, "OK"), (0, ""), (0, "")],
        1 => [(IDOK, "OK"), (IDCANCEL, "Cancel"), (0, "")],
        2 => [(IDABORT, "Abort"), (IDRETRY, "Retry"), (IDIGNORE, "Ignore")],
        3 => [(IDYES, "Yes"), (IDNO, "No"), (IDCANCEL, "Cancel")],
        4 => [(IDYES, "Yes"), (IDNO, "No"), (0, "")],
        5 => [(IDRETRY, "Retry"), (IDCANCEL, "Cancel"), (0, "")],
        6 => [(IDCANCEL, "Cancel"), (IDRETRY, "Try Again"), (IDNO, "Continue")],
        _ => [(IDOK, "OK"), (0, ""), (0, "")],
    }
}

// ============================================================================
// Dialog Rendering
// ============================================================================

/// Draw a dialog background
pub fn draw_dialog_background(hdc: super::super::HDC, rect: &Rect) {
    let bg_brush = brush::create_solid_brush(ColorRef::BUTTON_FACE);
    super::super::gdi::fill_rect(hdc, rect, bg_brush);
}

/// Draw message box icon
pub fn draw_message_box_icon(hdc: super::super::HDC, x: i32, y: i32, flags: MessageBoxFlags) {
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let icon_type = flags.bits() & 0xF0;
    let size = 32;

    match icon_type {
        0x10 => {
            // Error icon (red circle with X)
            draw_error_icon(&surf, x, y, size);
        }
        0x20 => {
            // Question icon (blue circle with ?)
            draw_question_icon(&surf, x, y, size);
        }
        0x30 => {
            // Warning icon (yellow triangle with !)
            draw_warning_icon(&surf, x, y, size);
        }
        0x40 => {
            // Information icon (blue circle with i)
            draw_info_icon(&surf, x, y, size);
        }
        _ => {}
    }
}

/// Draw error icon
fn draw_error_icon(surf: &surface::Surface, x: i32, y: i32, size: i32) {
    let cx = x + size / 2;
    let cy = y + size / 2;
    let radius = size / 2 - 2;

    // Draw red circle
    for dy in -radius..=radius {
        for dx in -radius..=radius {
            if dx * dx + dy * dy <= radius * radius {
                surf.set_pixel(cx + dx, cy + dy, ColorRef::rgb(200, 0, 0));
            }
        }
    }

    // Draw white X
    let offset = radius / 2;
    for i in -offset..=offset {
        surf.set_pixel(cx + i, cy + i, ColorRef::WHITE);
        surf.set_pixel(cx + i + 1, cy + i, ColorRef::WHITE);
        surf.set_pixel(cx + i, cy - i, ColorRef::WHITE);
        surf.set_pixel(cx + i + 1, cy - i, ColorRef::WHITE);
    }
}

/// Draw question icon
fn draw_question_icon(surf: &surface::Surface, x: i32, y: i32, size: i32) {
    let cx = x + size / 2;
    let cy = y + size / 2;
    let radius = size / 2 - 2;

    // Draw blue circle
    for dy in -radius..=radius {
        for dx in -radius..=radius {
            if dx * dx + dy * dy <= radius * radius {
                surf.set_pixel(cx + dx, cy + dy, ColorRef::rgb(0, 0, 200));
            }
        }
    }

    // Draw white ?
    surf.vline(cx, cy - 6, cy + 2, ColorRef::WHITE);
    surf.vline(cx + 1, cy - 6, cy + 2, ColorRef::WHITE);
    surf.set_pixel(cx, cy + 5, ColorRef::WHITE);
    surf.set_pixel(cx + 1, cy + 5, ColorRef::WHITE);
}

/// Draw warning icon
fn draw_warning_icon(surf: &surface::Surface, x: i32, y: i32, size: i32) {
    let cx = x + size / 2;
    let top = y + 2;
    let bottom = y + size - 2;
    let half_width = (size - 4) / 2;

    // Draw yellow triangle
    for row in 0..(bottom - top) {
        let width = (row * half_width) / (bottom - top - 1);
        for dx in -width..=width {
            surf.set_pixel(cx + dx, top + row, ColorRef::rgb(255, 200, 0));
        }
    }

    // Draw black !
    let cy = y + size / 2;
    surf.vline(cx, cy - 6, cy + 2, ColorRef::BLACK);
    surf.set_pixel(cx, cy + 5, ColorRef::BLACK);
}

/// Draw info icon
fn draw_info_icon(surf: &surface::Surface, x: i32, y: i32, size: i32) {
    let cx = x + size / 2;
    let cy = y + size / 2;
    let radius = size / 2 - 2;

    // Draw blue circle
    for dy in -radius..=radius {
        for dx in -radius..=radius {
            if dx * dx + dy * dy <= radius * radius {
                surf.set_pixel(cx + dx, cy + dy, ColorRef::rgb(0, 0, 200));
            }
        }
    }

    // Draw white i
    surf.set_pixel(cx, cy - 6, ColorRef::WHITE);
    surf.set_pixel(cx + 1, cy - 6, ColorRef::WHITE);
    surf.vline(cx, cy - 2, cy + 6, ColorRef::WHITE);
    surf.vline(cx + 1, cy - 2, cy + 6, ColorRef::WHITE);
}

// ============================================================================
// Statistics
// ============================================================================

/// Dialog statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct DialogStats {
    pub active_dialogs: usize,
}

/// Get dialog statistics
pub fn get_stats() -> DialogStats {
    let table = DIALOG_TABLE.lock();
    DialogStats {
        active_dialogs: table.count,
    }
}
