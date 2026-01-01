//! Standard Window Controls
//!
//! Implementation of common window controls:
//! - Button (push button, checkbox, radio button)
//! - Static (text label, icon, rectangle)
//! - Edit (single-line and multi-line text input)
//! - ListBox (scrollable list of items)
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/client/btnctl.c`
//! - `windows/core/ntuser/client/statctl.c`
//! - `windows/core/ntuser/client/editctl.c`

use super::super::{ColorRef, Rect, Point, GdiHandle, HWND};
use super::super::gdi::{dc, surface, brush};
use super::{message, window};

// ============================================================================
// Button Styles
// ============================================================================

/// Button styles (BS_*)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ButtonStyle {
    #[default]
    PushButton = 0x00000000,
    DefPushButton = 0x00000001,
    CheckBox = 0x00000002,
    AutoCheckBox = 0x00000003,
    RadioButton = 0x00000004,
    ThreeState = 0x00000005,
    AutoThreeState = 0x00000006,
    GroupBox = 0x00000007,
    OwnerDraw = 0x0000000B,
    AutoRadioButton = 0x00000009,
}

/// Button states
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ButtonState {
    #[default]
    Normal = 0,
    Hover = 1,
    Pressed = 2,
    Disabled = 3,
    Focused = 4,
}

/// Check state for checkboxes and radio buttons
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CheckState {
    #[default]
    Unchecked = 0,
    Checked = 1,
    Indeterminate = 2,
}

// ============================================================================
// Static Styles
// ============================================================================

/// Static control styles (SS_*)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StaticStyle {
    #[default]
    Left = 0x00000000,
    Center = 0x00000001,
    Right = 0x00000002,
    Icon = 0x00000003,
    BlackRect = 0x00000004,
    GrayRect = 0x00000005,
    WhiteRect = 0x00000006,
    BlackFrame = 0x00000007,
    GrayFrame = 0x00000008,
    WhiteFrame = 0x00000009,
    Simple = 0x0000000B,
    LeftNoWordWrap = 0x0000000C,
    Sunken = 0x00001000,
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize controls subsystem
pub fn init() {
    crate::serial_println!("[USER/Controls] Controls subsystem initialized");
}

// ============================================================================
// Button Drawing
// ============================================================================

/// Draw a push button
pub fn draw_button(
    hdc: GdiHandle,
    rect: &Rect,
    text: &str,
    state: ButtonState,
    style: ButtonStyle,
) {
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    // Get DC viewport offset
    let offset = dc::get_dc(hdc)
        .map(|d| d.viewport_org)
        .unwrap_or(Point::new(0, 0));

    let left = rect.left + offset.x;
    let top = rect.top + offset.y;
    let right = rect.right + offset.x;
    let bottom = rect.bottom + offset.y;

    // Determine colors based on state
    let (face_color, highlight_color, shadow_color, text_color) = match state {
        ButtonState::Normal | ButtonState::Focused => (
            ColorRef::BUTTON_FACE,
            ColorRef::BUTTON_HIGHLIGHT,
            ColorRef::BUTTON_SHADOW,
            ColorRef::BLACK,
        ),
        ButtonState::Hover => (
            ColorRef::rgb(220, 216, 208), // Slightly lighter
            ColorRef::BUTTON_HIGHLIGHT,
            ColorRef::BUTTON_SHADOW,
            ColorRef::BLACK,
        ),
        ButtonState::Pressed => (
            ColorRef::rgb(200, 196, 188), // Darker when pressed
            ColorRef::BUTTON_SHADOW,
            ColorRef::BUTTON_HIGHLIGHT,
            ColorRef::BLACK,
        ),
        ButtonState::Disabled => (
            ColorRef::BUTTON_FACE,
            ColorRef::BUTTON_HIGHLIGHT,
            ColorRef::BUTTON_SHADOW,
            ColorRef::GRAY,
        ),
    };

    // Fill button face
    let face_rect = Rect::new(left + 2, top + 2, right - 2, bottom - 2);
    surf.fill_rect(&face_rect, face_color);

    // Draw 3D border
    if state == ButtonState::Pressed {
        // Pressed: invert border
        // Top-left shadow
        surf.hline(left, right, top, shadow_color);
        surf.hline(left + 1, right - 1, top + 1, shadow_color);
        surf.vline(left, top, bottom, shadow_color);
        surf.vline(left + 1, top + 1, bottom - 1, shadow_color);
    } else {
        // Normal: 3D raised border
        // Top-left highlight
        surf.hline(left, right, top, highlight_color);
        surf.hline(left + 1, right - 1, top + 1, highlight_color);
        surf.vline(left, top, bottom, highlight_color);
        surf.vline(left + 1, top + 1, bottom - 1, highlight_color);

        // Bottom-right shadow
        surf.hline(left + 1, right, bottom - 1, shadow_color);
        surf.hline(left, right, bottom - 2, ColorRef::DARK_GRAY);
        surf.vline(right - 1, top + 1, bottom, shadow_color);
        surf.vline(right - 2, top, bottom, ColorRef::DARK_GRAY);
    }

    // Draw text centered
    if !text.is_empty() {
        let text_width = text.len() as i32 * 8; // Assume 8 pixel wide chars
        let text_height = 16;

        let text_x = left + (right - left - text_width) / 2;
        let text_y = top + (bottom - top - text_height) / 2;

        // Offset text when pressed
        let (tx, ty) = if state == ButtonState::Pressed {
            (text_x + 1, text_y + 1)
        } else {
            (text_x, text_y)
        };

        dc::set_text_color(hdc, text_color);
        dc::set_bk_mode(hdc, dc::BkMode::Transparent);
        super::super::gdi::draw::gdi_text_out(hdc, tx - offset.x, ty - offset.y, text);
    }

    // Draw focus rectangle if focused
    if state == ButtonState::Focused {
        draw_focus_rect(&surf, left + 4, top + 4, right - 4, bottom - 4);
    }
}

/// Draw a checkbox
pub fn draw_checkbox(
    hdc: GdiHandle,
    rect: &Rect,
    text: &str,
    state: ButtonState,
    check_state: CheckState,
) {
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let offset = dc::get_dc(hdc)
        .map(|d| d.viewport_org)
        .unwrap_or(Point::new(0, 0));

    let left = rect.left + offset.x;
    let top = rect.top + offset.y;
    let bottom = rect.bottom + offset.y;

    // Checkbox is 13x13 pixels
    let box_size = 13;
    let box_top = top + (bottom - top - box_size) / 2;
    let box_left = left + 2;

    // Draw checkbox box
    let box_rect = Rect::new(box_left, box_top, box_left + box_size, box_top + box_size);

    // Fill with white
    surf.fill_rect(&box_rect, ColorRef::WHITE);

    // Draw sunken border
    surf.hline(box_left, box_left + box_size, box_top, ColorRef::BUTTON_SHADOW);
    surf.vline(box_left, box_top, box_top + box_size, ColorRef::BUTTON_SHADOW);
    surf.hline(box_left, box_left + box_size, box_top + box_size - 1, ColorRef::BUTTON_HIGHLIGHT);
    surf.vline(box_left + box_size - 1, box_top, box_top + box_size, ColorRef::BUTTON_HIGHLIGHT);

    // Draw check mark if checked
    match check_state {
        CheckState::Checked => {
            let cx = box_left + box_size / 2;
            let cy = box_top + box_size / 2;
            let color = ColorRef::BLACK;

            // Draw checkmark (simple version)
            for i in 0..3 {
                surf.set_pixel(cx - 3 + i, cy + i, color);
                surf.set_pixel(cx - 2 + i, cy + i, color);
            }
            for i in 0..5 {
                surf.set_pixel(cx + i, cy + 2 - i, color);
                surf.set_pixel(cx + 1 + i, cy + 2 - i, color);
            }
        }
        CheckState::Indeterminate => {
            // Draw filled gray square
            let inner = Rect::new(box_left + 3, box_top + 3, box_left + box_size - 3, box_top + box_size - 3);
            surf.fill_rect(&inner, ColorRef::GRAY);
        }
        CheckState::Unchecked => {}
    }

    // Draw text
    if !text.is_empty() {
        let text_x = box_left + box_size + 4;
        let text_y = top + (bottom - top - 16) / 2;

        let text_color = if state == ButtonState::Disabled {
            ColorRef::GRAY
        } else {
            ColorRef::BLACK
        };

        dc::set_text_color(hdc, text_color);
        dc::set_bk_mode(hdc, dc::BkMode::Transparent);
        super::super::gdi::draw::gdi_text_out(hdc, text_x - offset.x, text_y - offset.y, text);
    }
}

/// Draw a radio button
pub fn draw_radio_button(
    hdc: GdiHandle,
    rect: &Rect,
    text: &str,
    state: ButtonState,
    selected: bool,
) {
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let offset = dc::get_dc(hdc)
        .map(|d| d.viewport_org)
        .unwrap_or(Point::new(0, 0));

    let left = rect.left + offset.x;
    let top = rect.top + offset.y;
    let bottom = rect.bottom + offset.y;

    // Radio button is 12x12 pixels circle
    let radius = 6;
    let cy = top + (bottom - top) / 2;
    let cx = left + 2 + radius;

    // Draw outer circle (simple approximation with pixels)
    draw_circle(&surf, cx, cy, radius, ColorRef::BUTTON_SHADOW);

    // Fill inner circle
    for dy in -radius + 1..radius {
        for dx in -radius + 1..radius {
            if dx * dx + dy * dy < (radius - 1) * (radius - 1) {
                surf.set_pixel(cx + dx, cy + dy, ColorRef::WHITE);
            }
        }
    }

    // Draw selected indicator
    if selected {
        for dy in -3..=3 {
            for dx in -3..=3 {
                if dx * dx + dy * dy <= 9 {
                    surf.set_pixel(cx + dx, cy + dy, ColorRef::BLACK);
                }
            }
        }
    }

    // Draw text
    if !text.is_empty() {
        let text_x = left + 2 + radius * 2 + 4;
        let text_y = top + (bottom - top - 16) / 2;

        let text_color = if state == ButtonState::Disabled {
            ColorRef::GRAY
        } else {
            ColorRef::BLACK
        };

        dc::set_text_color(hdc, text_color);
        dc::set_bk_mode(hdc, dc::BkMode::Transparent);
        super::super::gdi::draw::gdi_text_out(hdc, text_x - offset.x, text_y - offset.y, text);
    }
}

// ============================================================================
// Static Control Drawing
// ============================================================================

/// Draw a static text control
pub fn draw_static_text(
    hdc: GdiHandle,
    rect: &Rect,
    text: &str,
    style: StaticStyle,
) {
    let offset = dc::get_dc(hdc)
        .map(|d| d.viewport_org)
        .unwrap_or(Point::new(0, 0));

    let left = rect.left + offset.x;
    let top = rect.top + offset.y;
    let right = rect.right + offset.x;
    let bottom = rect.bottom + offset.y;

    // Calculate text position based on alignment
    let text_width = text.len() as i32 * 8;
    let text_height = 16;

    let text_x = match style {
        StaticStyle::Center => left + (right - left - text_width) / 2,
        StaticStyle::Right => right - text_width,
        _ => left, // Left aligned
    };

    let text_y = top + (bottom - top - text_height) / 2;

    dc::set_text_color(hdc, ColorRef::BLACK);
    dc::set_bk_mode(hdc, dc::BkMode::Transparent);
    super::super::gdi::draw::gdi_text_out(hdc, text_x - offset.x, text_y - offset.y, text);
}

/// Draw a static frame/rectangle
pub fn draw_static_frame(
    hdc: GdiHandle,
    rect: &Rect,
    style: StaticStyle,
) {
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let offset = dc::get_dc(hdc)
        .map(|d| d.viewport_org)
        .unwrap_or(Point::new(0, 0));

    let left = rect.left + offset.x;
    let top = rect.top + offset.y;
    let right = rect.right + offset.x;
    let bottom = rect.bottom + offset.y;

    let color = match style {
        StaticStyle::BlackRect | StaticStyle::BlackFrame => ColorRef::BLACK,
        StaticStyle::GrayRect | StaticStyle::GrayFrame => ColorRef::GRAY,
        StaticStyle::WhiteRect | StaticStyle::WhiteFrame => ColorRef::WHITE,
        _ => ColorRef::BLACK,
    };

    match style {
        StaticStyle::BlackRect | StaticStyle::GrayRect | StaticStyle::WhiteRect => {
            // Filled rectangle
            let r = Rect::new(left, top, right, bottom);
            surf.fill_rect(&r, color);
        }
        StaticStyle::BlackFrame | StaticStyle::GrayFrame | StaticStyle::WhiteFrame => {
            // Frame only
            surf.hline(left, right, top, color);
            surf.hline(left, right, bottom - 1, color);
            surf.vline(left, top, bottom, color);
            surf.vline(right - 1, top, bottom, color);
        }
        _ => {}
    }
}

// ============================================================================
// Edit Control Drawing
// ============================================================================

/// Draw an edit control (text box)
pub fn draw_edit_control(
    hdc: GdiHandle,
    rect: &Rect,
    text: &str,
    cursor_pos: usize,
    has_focus: bool,
) {
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let offset = dc::get_dc(hdc)
        .map(|d| d.viewport_org)
        .unwrap_or(Point::new(0, 0));

    let left = rect.left + offset.x;
    let top = rect.top + offset.y;
    let right = rect.right + offset.x;
    let bottom = rect.bottom + offset.y;

    // Draw sunken border
    surf.hline(left, right, top, ColorRef::BUTTON_SHADOW);
    surf.hline(left + 1, right - 1, top + 1, ColorRef::DARK_GRAY);
    surf.vline(left, top, bottom, ColorRef::BUTTON_SHADOW);
    surf.vline(left + 1, top + 1, bottom - 1, ColorRef::DARK_GRAY);
    surf.hline(left + 1, right, bottom - 1, ColorRef::BUTTON_HIGHLIGHT);
    surf.vline(right - 1, top + 1, bottom, ColorRef::BUTTON_HIGHLIGHT);

    // Fill with white
    let inner = Rect::new(left + 2, top + 2, right - 2, bottom - 2);
    surf.fill_rect(&inner, ColorRef::WHITE);

    // Draw text
    let text_x = left + 4;
    let text_y = top + (bottom - top - 16) / 2;

    dc::set_text_color(hdc, ColorRef::BLACK);
    dc::set_bk_mode(hdc, dc::BkMode::Transparent);
    super::super::gdi::draw::gdi_text_out(hdc, text_x - offset.x, text_y - offset.y, text);

    // Draw cursor if focused
    if has_focus {
        let cursor_x = text_x + (cursor_pos as i32 * 8);
        surf.vline(cursor_x, text_y, text_y + 16, ColorRef::BLACK);
    }
}

// ============================================================================
// Progress Bar
// ============================================================================

/// Draw a progress bar
pub fn draw_progress_bar(
    hdc: GdiHandle,
    rect: &Rect,
    progress: u32, // 0-100
) {
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let offset = dc::get_dc(hdc)
        .map(|d| d.viewport_org)
        .unwrap_or(Point::new(0, 0));

    let left = rect.left + offset.x;
    let top = rect.top + offset.y;
    let right = rect.right + offset.x;
    let bottom = rect.bottom + offset.y;

    // Draw sunken border
    surf.hline(left, right, top, ColorRef::BUTTON_SHADOW);
    surf.vline(left, top, bottom, ColorRef::BUTTON_SHADOW);
    surf.hline(left + 1, right, bottom - 1, ColorRef::BUTTON_HIGHLIGHT);
    surf.vline(right - 1, top + 1, bottom, ColorRef::BUTTON_HIGHLIGHT);

    // Fill background
    let inner = Rect::new(left + 1, top + 1, right - 1, bottom - 1);
    surf.fill_rect(&inner, ColorRef::WHITE);

    // Draw progress
    let progress = progress.min(100);
    let progress_width = ((right - left - 2) as u32 * progress / 100) as i32;

    if progress_width > 0 {
        let progress_rect = Rect::new(left + 1, top + 1, left + 1 + progress_width, bottom - 1);
        // Classic Windows green progress bar
        surf.fill_rect(&progress_rect, ColorRef::rgb(0, 128, 0));
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Draw a focus rectangle (dotted)
fn draw_focus_rect(surf: &surface::Surface, left: i32, top: i32, right: i32, bottom: i32) {
    let color = ColorRef::BLACK;

    // Draw dotted rectangle
    for x in (left..right).step_by(2) {
        surf.set_pixel(x, top, color);
        surf.set_pixel(x, bottom - 1, color);
    }
    for y in (top..bottom).step_by(2) {
        surf.set_pixel(left, y, color);
        surf.set_pixel(right - 1, y, color);
    }
}

/// Draw a simple circle outline
fn draw_circle(surf: &surface::Surface, cx: i32, cy: i32, radius: i32, color: ColorRef) {
    let mut x = 0;
    let mut y = radius;
    let mut d = 3 - 2 * radius;

    while x <= y {
        // Draw 8 symmetric points
        surf.set_pixel(cx + x, cy + y, color);
        surf.set_pixel(cx - x, cy + y, color);
        surf.set_pixel(cx + x, cy - y, color);
        surf.set_pixel(cx - x, cy - y, color);
        surf.set_pixel(cx + y, cy + x, color);
        surf.set_pixel(cx - y, cy + x, color);
        surf.set_pixel(cx + y, cy - x, color);
        surf.set_pixel(cx - y, cy - x, color);

        if d < 0 {
            d += 4 * x + 6;
        } else {
            d += 4 * (x - y) + 10;
            y -= 1;
        }
        x += 1;
    }
}

// ============================================================================
// Group Box
// ============================================================================

/// Draw a group box
pub fn draw_group_box(
    hdc: GdiHandle,
    rect: &Rect,
    text: &str,
) {
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let offset = dc::get_dc(hdc)
        .map(|d| d.viewport_org)
        .unwrap_or(Point::new(0, 0));

    let left = rect.left + offset.x;
    let top = rect.top + offset.y;
    let right = rect.right + offset.x;
    let bottom = rect.bottom + offset.y;

    // Text position (8 pixels from left, centered in top edge)
    let text_x = left + 8;
    let text_y = top;
    let text_width = text.len() as i32 * 8;

    // Draw frame (leaving gap for text)
    let frame_top = top + 8;

    // Top line (with gap for text)
    surf.hline(left, text_x - 2, frame_top, ColorRef::BUTTON_SHADOW);
    surf.hline(text_x + text_width + 2, right, frame_top, ColorRef::BUTTON_SHADOW);

    // Left, bottom, right
    surf.vline(left, frame_top, bottom, ColorRef::BUTTON_SHADOW);
    surf.hline(left, right, bottom - 1, ColorRef::BUTTON_HIGHLIGHT);
    surf.vline(right - 1, frame_top, bottom, ColorRef::BUTTON_HIGHLIGHT);

    // Inner highlight
    surf.hline(left + 1, text_x - 2, frame_top + 1, ColorRef::BUTTON_HIGHLIGHT);
    surf.hline(text_x + text_width + 2, right - 1, frame_top + 1, ColorRef::BUTTON_HIGHLIGHT);
    surf.vline(left + 1, frame_top + 1, bottom - 1, ColorRef::BUTTON_HIGHLIGHT);

    // Draw text
    if !text.is_empty() {
        dc::set_text_color(hdc, ColorRef::BLACK);
        dc::set_bk_mode(hdc, dc::BkMode::Opaque);
        dc::set_bk_color(hdc, ColorRef::BUTTON_FACE);
        super::super::gdi::draw::gdi_text_out(hdc, text_x - offset.x, text_y - offset.y, text);
    }
}

// ============================================================================
// Scrollbar Control
// ============================================================================

/// Scrollbar type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScrollbarType {
    #[default]
    Horizontal = 0,
    Vertical = 1,
    Control = 2,  // Standalone scrollbar control
}

/// Scrollbar arrow types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollArrow {
    LineUp = 0,      // Up or left arrow
    LineDown = 1,    // Down or right arrow
    PageUp = 2,      // Page up or left (track above thumb)
    PageDown = 3,    // Page down or right (track below thumb)
    Thumb = 4,       // The thumb/slider
}

/// Scrollbar state
#[derive(Debug, Clone, Copy, Default)]
pub struct ScrollbarState {
    /// Minimum scroll position
    pub min: i32,
    /// Maximum scroll position
    pub max: i32,
    /// Current position
    pub pos: i32,
    /// Page size (visible portion)
    pub page: i32,
    /// Is up/left arrow pressed?
    pub arrow_up_pressed: bool,
    /// Is down/right arrow pressed?
    pub arrow_down_pressed: bool,
    /// Is thumb being dragged?
    pub thumb_dragging: bool,
    /// Is scrollbar disabled?
    pub disabled: bool,
}

impl ScrollbarState {
    /// Create a new scrollbar state
    pub fn new(min: i32, max: i32, pos: i32, page: i32) -> Self {
        Self {
            min,
            max,
            pos: pos.clamp(min, max),
            page,
            arrow_up_pressed: false,
            arrow_down_pressed: false,
            thumb_dragging: false,
            disabled: false,
        }
    }

    /// Calculate thumb position as a ratio (0.0 to 1.0)
    pub fn thumb_ratio(&self) -> f32 {
        let range = self.max - self.min;
        if range <= 0 {
            0.0
        } else {
            (self.pos - self.min) as f32 / range as f32
        }
    }

    /// Calculate thumb size as a ratio (0.0 to 1.0)
    pub fn thumb_size_ratio(&self) -> f32 {
        let total = self.max - self.min + self.page;
        if total <= 0 {
            1.0
        } else {
            (self.page as f32 / total as f32).clamp(0.1, 1.0)
        }
    }
}

/// Scrollbar metrics
const SCROLLBAR_ARROW_SIZE: i32 = 17;  // Arrow button size
const SCROLLBAR_MIN_THUMB: i32 = 8;    // Minimum thumb size

/// Draw a complete scrollbar
pub fn draw_scrollbar(
    hdc: GdiHandle,
    rect: &Rect,
    sb_type: ScrollbarType,
    state: &ScrollbarState,
) {
    let surface_handle = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(surface_handle) {
        Some(s) => s,
        None => return,
    };

    let offset = dc::get_dc(hdc)
        .map(|d| d.viewport_org)
        .unwrap_or(Point::new(0, 0));

    let left = rect.left + offset.x;
    let top = rect.top + offset.y;
    let right = rect.right + offset.x;
    let bottom = rect.bottom + offset.y;

    let is_vertical = sb_type == ScrollbarType::Vertical;

    // Calculate track area (between arrows)
    let (track_start, track_end, track_length) = if is_vertical {
        let ts = top + SCROLLBAR_ARROW_SIZE;
        let te = bottom - SCROLLBAR_ARROW_SIZE;
        (ts, te, te - ts)
    } else {
        let ts = left + SCROLLBAR_ARROW_SIZE;
        let te = right - SCROLLBAR_ARROW_SIZE;
        (ts, te, te - ts)
    };

    // Calculate thumb dimensions
    let thumb_size_ratio = state.thumb_size_ratio();
    let thumb_size = ((track_length as f32 * thumb_size_ratio) as i32).max(SCROLLBAR_MIN_THUMB);
    let usable_track = track_length - thumb_size;

    let thumb_offset = if usable_track > 0 {
        ((usable_track as f32 * state.thumb_ratio()) as i32).clamp(0, usable_track)
    } else {
        0
    };

    // Draw arrow buttons
    if is_vertical {
        // Up arrow
        let up_rect = Rect::new(left, top, right, top + SCROLLBAR_ARROW_SIZE);
        draw_scrollbar_arrow(&surf, &up_rect, true, true, state.arrow_up_pressed, state.disabled);

        // Down arrow
        let down_rect = Rect::new(left, bottom - SCROLLBAR_ARROW_SIZE, right, bottom);
        draw_scrollbar_arrow(&surf, &down_rect, true, false, state.arrow_down_pressed, state.disabled);

        // Draw track (shaded area)
        let track_rect = Rect::new(left, track_start, right, track_end);
        draw_scrollbar_track(&surf, &track_rect, true);

        // Draw thumb
        let thumb_top = track_start + thumb_offset;
        let thumb_rect = Rect::new(left, thumb_top, right, thumb_top + thumb_size);
        draw_scrollbar_thumb(&surf, &thumb_rect, true, state.thumb_dragging, state.disabled);
    } else {
        // Left arrow
        let left_rect = Rect::new(left, top, left + SCROLLBAR_ARROW_SIZE, bottom);
        draw_scrollbar_arrow(&surf, &left_rect, false, true, state.arrow_up_pressed, state.disabled);

        // Right arrow
        let right_rect = Rect::new(right - SCROLLBAR_ARROW_SIZE, top, right, bottom);
        draw_scrollbar_arrow(&surf, &right_rect, false, false, state.arrow_down_pressed, state.disabled);

        // Draw track
        let track_rect = Rect::new(track_start, top, track_end, bottom);
        draw_scrollbar_track(&surf, &track_rect, false);

        // Draw thumb
        let thumb_left = track_start + thumb_offset;
        let thumb_rect = Rect::new(thumb_left, top, thumb_left + thumb_size, bottom);
        draw_scrollbar_thumb(&surf, &thumb_rect, false, state.thumb_dragging, state.disabled);
    }
}

/// Draw a scrollbar arrow button
fn draw_scrollbar_arrow(
    surf: &surface::Surface,
    rect: &Rect,
    vertical: bool,
    is_up_left: bool,
    pressed: bool,
    disabled: bool,
) {
    let left = rect.left;
    let top = rect.top;
    let right = rect.right;
    let bottom = rect.bottom;

    // Fill background
    surf.fill_rect(rect, ColorRef::BUTTON_FACE);

    // Draw 3D border
    if pressed && !disabled {
        // Pressed: sunken
        surf.hline(left, right, top, ColorRef::BUTTON_SHADOW);
        surf.vline(left, top, bottom, ColorRef::BUTTON_SHADOW);
        surf.hline(left, right, bottom - 1, ColorRef::BUTTON_HIGHLIGHT);
        surf.vline(right - 1, top, bottom, ColorRef::BUTTON_HIGHLIGHT);
    } else {
        // Normal: raised
        surf.hline(left, right, top, ColorRef::BUTTON_HIGHLIGHT);
        surf.vline(left, top, bottom, ColorRef::BUTTON_HIGHLIGHT);
        surf.hline(left + 1, right, bottom - 1, ColorRef::BUTTON_SHADOW);
        surf.hline(left, right, bottom - 2, ColorRef::DARK_GRAY);
        surf.vline(right - 1, top + 1, bottom, ColorRef::BUTTON_SHADOW);
        surf.vline(right - 2, top, bottom, ColorRef::DARK_GRAY);
    }

    // Draw arrow
    let cx = left + (right - left) / 2;
    let cy = top + (bottom - top) / 2;
    let arrow_color = if disabled { ColorRef::GRAY } else { ColorRef::BLACK };
    let offset = if pressed && !disabled { 1 } else { 0 };

    if vertical {
        if is_up_left {
            // Up arrow
            draw_arrow_up(surf, cx + offset, cy + offset, arrow_color);
        } else {
            // Down arrow
            draw_arrow_down(surf, cx + offset, cy + offset, arrow_color);
        }
    } else {
        if is_up_left {
            // Left arrow
            draw_arrow_left(surf, cx + offset, cy + offset, arrow_color);
        } else {
            // Right arrow
            draw_arrow_right(surf, cx + offset, cy + offset, arrow_color);
        }
    }
}

/// Draw up arrow
fn draw_arrow_up(surf: &surface::Surface, cx: i32, cy: i32, color: ColorRef) {
    for i in 0..4 {
        surf.hline(cx - i, cx + i + 1, cy - 2 + i, color);
    }
}

/// Draw down arrow
fn draw_arrow_down(surf: &surface::Surface, cx: i32, cy: i32, color: ColorRef) {
    for i in 0..4 {
        surf.hline(cx - i, cx + i + 1, cy + 2 - i, color);
    }
}

/// Draw left arrow
fn draw_arrow_left(surf: &surface::Surface, cx: i32, cy: i32, color: ColorRef) {
    for i in 0..4 {
        surf.vline(cx - 2 + i, cy - i, cy + i + 1, color);
    }
}

/// Draw right arrow
fn draw_arrow_right(surf: &surface::Surface, cx: i32, cy: i32, color: ColorRef) {
    for i in 0..4 {
        surf.vline(cx + 2 - i, cy - i, cy + i + 1, color);
    }
}

/// Draw scrollbar track (shaft)
fn draw_scrollbar_track(surf: &surface::Surface, rect: &Rect, _vertical: bool) {
    // Classic Windows dithered pattern
    let pattern_color1 = ColorRef::BUTTON_FACE;
    let pattern_color2 = ColorRef::WHITE;

    for y in rect.top..rect.bottom {
        for x in rect.left..rect.right {
            let color = if (x + y) % 2 == 0 { pattern_color1 } else { pattern_color2 };
            surf.set_pixel(x, y, color);
        }
    }
}

/// Draw scrollbar thumb
fn draw_scrollbar_thumb(
    surf: &surface::Surface,
    rect: &Rect,
    _vertical: bool,
    dragging: bool,
    disabled: bool,
) {
    let left = rect.left;
    let top = rect.top;
    let right = rect.right;
    let bottom = rect.bottom;

    // Fill thumb
    let face_color = if disabled {
        ColorRef::BUTTON_FACE
    } else if dragging {
        ColorRef::rgb(200, 196, 188)
    } else {
        ColorRef::BUTTON_FACE
    };
    surf.fill_rect(rect, face_color);

    if !disabled {
        // Draw 3D border
        surf.hline(left, right, top, ColorRef::BUTTON_HIGHLIGHT);
        surf.vline(left, top, bottom, ColorRef::BUTTON_HIGHLIGHT);
        surf.hline(left + 1, right, bottom - 1, ColorRef::BUTTON_SHADOW);
        surf.hline(left, right, bottom - 2, ColorRef::DARK_GRAY);
        surf.vline(right - 1, top + 1, bottom, ColorRef::BUTTON_SHADOW);
        surf.vline(right - 2, top, bottom, ColorRef::DARK_GRAY);
    }
}

/// Scrollbar hit test
pub fn scrollbar_hit_test(
    rect: &Rect,
    sb_type: ScrollbarType,
    state: &ScrollbarState,
    x: i32,
    y: i32,
) -> Option<ScrollArrow> {
    let is_vertical = sb_type == ScrollbarType::Vertical;

    let left = rect.left;
    let top = rect.top;
    let right = rect.right;
    let bottom = rect.bottom;

    // Check if point is in scrollbar
    if x < left || x >= right || y < top || y >= bottom {
        return None;
    }

    if is_vertical {
        // Up arrow
        if y < top + SCROLLBAR_ARROW_SIZE {
            return Some(ScrollArrow::LineUp);
        }
        // Down arrow
        if y >= bottom - SCROLLBAR_ARROW_SIZE {
            return Some(ScrollArrow::LineDown);
        }

        // Calculate thumb position
        let track_start = top + SCROLLBAR_ARROW_SIZE;
        let track_end = bottom - SCROLLBAR_ARROW_SIZE;
        let track_length = track_end - track_start;
        let thumb_size_ratio = state.thumb_size_ratio();
        let thumb_size = ((track_length as f32 * thumb_size_ratio) as i32).max(SCROLLBAR_MIN_THUMB);
        let usable_track = track_length - thumb_size;
        let thumb_offset = if usable_track > 0 {
            ((usable_track as f32 * state.thumb_ratio()) as i32).clamp(0, usable_track)
        } else {
            0
        };
        let thumb_top = track_start + thumb_offset;
        let thumb_bottom = thumb_top + thumb_size;

        if y < thumb_top {
            Some(ScrollArrow::PageUp)
        } else if y >= thumb_bottom {
            Some(ScrollArrow::PageDown)
        } else {
            Some(ScrollArrow::Thumb)
        }
    } else {
        // Left arrow
        if x < left + SCROLLBAR_ARROW_SIZE {
            return Some(ScrollArrow::LineUp);
        }
        // Right arrow
        if x >= right - SCROLLBAR_ARROW_SIZE {
            return Some(ScrollArrow::LineDown);
        }

        // Calculate thumb position
        let track_start = left + SCROLLBAR_ARROW_SIZE;
        let track_end = right - SCROLLBAR_ARROW_SIZE;
        let track_length = track_end - track_start;
        let thumb_size_ratio = state.thumb_size_ratio();
        let thumb_size = ((track_length as f32 * thumb_size_ratio) as i32).max(SCROLLBAR_MIN_THUMB);
        let usable_track = track_length - thumb_size;
        let thumb_offset = if usable_track > 0 {
            ((usable_track as f32 * state.thumb_ratio()) as i32).clamp(0, usable_track)
        } else {
            0
        };
        let thumb_left = track_start + thumb_offset;
        let thumb_right = thumb_left + thumb_size;

        if x < thumb_left {
            Some(ScrollArrow::PageUp)
        } else if x >= thumb_right {
            Some(ScrollArrow::PageDown)
        } else {
            Some(ScrollArrow::Thumb)
        }
    }
}

/// Convert track position to scroll position
pub fn track_to_scroll_pos(
    rect: &Rect,
    sb_type: ScrollbarType,
    state: &ScrollbarState,
    track_pos: i32,
) -> i32 {
    let is_vertical = sb_type == ScrollbarType::Vertical;

    let (track_start, track_length) = if is_vertical {
        let ts = rect.top + SCROLLBAR_ARROW_SIZE;
        let te = rect.bottom - SCROLLBAR_ARROW_SIZE;
        (ts, te - ts)
    } else {
        let ts = rect.left + SCROLLBAR_ARROW_SIZE;
        let te = rect.right - SCROLLBAR_ARROW_SIZE;
        (ts, te - ts)
    };

    let thumb_size_ratio = state.thumb_size_ratio();
    let thumb_size = ((track_length as f32 * thumb_size_ratio) as i32).max(SCROLLBAR_MIN_THUMB);
    let usable_track = track_length - thumb_size;

    if usable_track <= 0 {
        return state.min;
    }

    let relative_pos = track_pos - track_start;
    let ratio = relative_pos as f32 / usable_track as f32;
    let range = state.max - state.min;

    (state.min + (range as f32 * ratio) as i32).clamp(state.min, state.max)
}
