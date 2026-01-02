//! Color Picker Dialog
//!
//! Provides the color selection dialog following the Windows comdlg32
//! ChooseColor pattern.
//!
//! # References
//!
//! - Windows Server 2003 comdlg32 color dialog
//! - CHOOSECOLOR structure

use core::sync::atomic::{AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle, ColorRef};

// ============================================================================
// Constants
// ============================================================================

/// Maximum custom colors
pub const MAX_CUSTOM_COLORS: usize = 16;

/// Choose color flags (CC_*)
pub mod cc_flags {
    /// Show RGB values
    pub const RGBINIT: u32 = 0x00000001;
    /// Full open dialog
    pub const FULLOPEN: u32 = 0x00000002;
    /// Prevent full open
    pub const PREVENTFULLOPEN: u32 = 0x00000004;
    /// Show help button
    pub const SHOWHELP: u32 = 0x00000008;
    /// Enable hook
    pub const ENABLEHOOK: u32 = 0x00000010;
    /// Enable template
    pub const ENABLETEMPLATE: u32 = 0x00000020;
    /// Enable template handle
    pub const ENABLETEMPLATEHANDLE: u32 = 0x00000040;
    /// Solid color only
    pub const SOLIDCOLOR: u32 = 0x00000080;
    /// Any color
    pub const ANYCOLOR: u32 = 0x00000100;
}

// ============================================================================
// Structures
// ============================================================================

/// Choose color structure (CHOOSECOLOR equivalent)
#[derive(Debug, Clone, Copy)]
pub struct ChooseColor {
    /// Structure size
    pub struct_size: u32,
    /// Owner window
    pub hwnd_owner: HWND,
    /// Instance handle
    pub instance: u32,
    /// Initial/result color
    pub rgb_result: ColorRef,
    /// Custom colors array offset
    pub cust_colors_idx: u8,
    /// Flags
    pub flags: u32,
    /// Custom data
    pub cust_data: usize,
    /// Hook function
    pub hook_fn: usize,
    /// Template name
    pub template_name: u32,
}

impl ChooseColor {
    pub const fn new() -> Self {
        Self {
            struct_size: 0,
            hwnd_owner: UserHandle::NULL,
            instance: 0,
            rgb_result: ColorRef(0),
            cust_colors_idx: 0,
            flags: 0,
            cust_data: 0,
            hook_fn: 0,
            template_name: 0,
        }
    }
}

/// Color dialog state
#[derive(Debug, Clone, Copy)]
pub struct ColorDialogState {
    /// Dialog is active
    pub active: bool,
    /// Dialog handle
    pub hwnd: HWND,
    /// Current hue (0-359)
    pub hue: u16,
    /// Current saturation (0-100)
    pub saturation: u8,
    /// Current luminance (0-100)
    pub luminance: u8,
    /// Current red (0-255)
    pub red: u8,
    /// Current green (0-255)
    pub green: u8,
    /// Current blue (0-255)
    pub blue: u8,
    /// Full open mode
    pub full_open: bool,
}

impl ColorDialogState {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            hue: 0,
            saturation: 100,
            luminance: 50,
            red: 255,
            green: 0,
            blue: 0,
            full_open: false,
        }
    }
}

/// HSL color values
#[derive(Debug, Clone, Copy)]
pub struct HslColor {
    /// Hue (0-359)
    pub hue: u16,
    /// Saturation (0-100)
    pub saturation: u8,
    /// Luminance (0-100)
    pub luminance: u8,
}

// ============================================================================
// State
// ============================================================================

static COLORDLG_INITIALIZED: AtomicBool = AtomicBool::new(false);
static COLORDLG_LOCK: SpinLock<()> = SpinLock::new(());

static CURRENT_STATE: SpinLock<ColorDialogState> = SpinLock::new(ColorDialogState::new());

// Custom colors storage
static CUSTOM_COLORS: SpinLock<[ColorRef; MAX_CUSTOM_COLORS]> =
    SpinLock::new([ColorRef(0xFFFFFF); MAX_CUSTOM_COLORS]);

// Basic colors (16 standard colors)
static BASIC_COLORS: [ColorRef; 48] = [
    // Row 1
    ColorRef(0xFF0000), ColorRef(0x00FF00), ColorRef(0x0000FF), ColorRef(0xFFFF00),
    ColorRef(0xFF00FF), ColorRef(0x00FFFF), ColorRef(0xFFFFFF), ColorRef(0x000000),
    // Row 2
    ColorRef(0x800000), ColorRef(0x008000), ColorRef(0x000080), ColorRef(0x808000),
    ColorRef(0x800080), ColorRef(0x008080), ColorRef(0xC0C0C0), ColorRef(0x808080),
    // Row 3
    ColorRef(0xFF8080), ColorRef(0x80FF80), ColorRef(0x8080FF), ColorRef(0xFFFF80),
    ColorRef(0xFF80FF), ColorRef(0x80FFFF), ColorRef(0xFFE0E0), ColorRef(0x404040),
    // Row 4
    ColorRef(0xC00000), ColorRef(0x00C000), ColorRef(0x0000C0), ColorRef(0xC0C000),
    ColorRef(0xC000C0), ColorRef(0x00C0C0), ColorRef(0xE0E0E0), ColorRef(0x202020),
    // Row 5
    ColorRef(0xFFA500), ColorRef(0xA52A2A), ColorRef(0x8B4513), ColorRef(0x2F4F4F),
    ColorRef(0x191970), ColorRef(0x483D8B), ColorRef(0xF5F5F5), ColorRef(0x101010),
    // Row 6
    ColorRef(0xFFC0CB), ColorRef(0xFFE4B5), ColorRef(0x98FB98), ColorRef(0xADD8E6),
    ColorRef(0xE6E6FA), ColorRef(0xFAFAD2), ColorRef(0xFFFAFA), ColorRef(0x080808),
];

// ============================================================================
// Initialization
// ============================================================================

/// Initialize color dialog subsystem
pub fn init() {
    let _guard = COLORDLG_LOCK.lock();

    if COLORDLG_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[COLORDLG] Initializing color dialog...");

    COLORDLG_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[COLORDLG] Color dialog initialized");
}

// ============================================================================
// Color Dialog API
// ============================================================================

/// Show color picker dialog
pub fn choose_color(cc: &mut ChooseColor) -> bool {
    if !COLORDLG_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = CURRENT_STATE.lock();

    if state.active {
        return false;
    }

    // Initialize state from input
    let (r, g, b) = (cc.rgb_result.red(), cc.rgb_result.green(), cc.rgb_result.blue());
    state.red = r;
    state.green = g;
    state.blue = b;

    let hsl = rgb_to_hsl(r, g, b);
    state.hue = hsl.hue;
    state.saturation = hsl.saturation;
    state.luminance = hsl.luminance;
    state.full_open = (cc.flags & cc_flags::FULLOPEN) != 0;

    // Create dialog
    let hwnd = create_color_dialog(cc);

    if hwnd == UserHandle::NULL {
        return false;
    }

    state.active = true;
    state.hwnd = hwnd;

    drop(state);

    // Run dialog (would be modal loop)
    let result = run_color_dialog(hwnd, cc);

    // Get result
    if result {
        let state = CURRENT_STATE.lock();
        cc.rgb_result = ColorRef::rgb(state.red, state.green, state.blue);
    }

    // Clean up
    let mut state = CURRENT_STATE.lock();
    state.active = false;
    state.hwnd = UserHandle::NULL;

    result
}

/// Quick color picker (simplified API)
pub fn pick_color(owner: HWND, initial_color: ColorRef) -> Option<ColorRef> {
    let mut cc = ChooseColor::new();
    cc.hwnd_owner = owner;
    cc.rgb_result = initial_color;
    cc.flags = cc_flags::RGBINIT | cc_flags::FULLOPEN;

    if choose_color(&mut cc) {
        Some(cc.rgb_result)
    } else {
        None
    }
}

/// Close color dialog
pub fn close_color_dialog() {
    let mut state = CURRENT_STATE.lock();

    if state.active {
        if state.hwnd != UserHandle::NULL {
            super::window::destroy_window(state.hwnd);
        }

        state.active = false;
        state.hwnd = UserHandle::NULL;
    }
}

/// Get dialog state
pub fn get_dialog_state() -> ColorDialogState {
    *CURRENT_STATE.lock()
}

// ============================================================================
// Custom Colors
// ============================================================================

/// Get custom colors
pub fn get_custom_colors() -> [ColorRef; MAX_CUSTOM_COLORS] {
    *CUSTOM_COLORS.lock()
}

/// Set custom colors
pub fn set_custom_colors(colors: &[ColorRef; MAX_CUSTOM_COLORS]) {
    let mut custom = CUSTOM_COLORS.lock();
    *custom = *colors;
}

/// Set a single custom color
pub fn set_custom_color(index: usize, color: ColorRef) {
    if index < MAX_CUSTOM_COLORS {
        let mut custom = CUSTOM_COLORS.lock();
        custom[index] = color;
    }
}

/// Get basic colors
pub fn get_basic_colors() -> &'static [ColorRef; 48] {
    &BASIC_COLORS
}

// ============================================================================
// Color Conversion
// ============================================================================

/// Convert RGB to HSL
pub fn rgb_to_hsl(r: u8, g: u8, b: u8) -> HslColor {
    let r = r as f32 / 255.0;
    let g = g as f32 / 255.0;
    let b = b as f32 / 255.0;

    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let l = (max + min) / 2.0;

    if max == min {
        // Achromatic
        return HslColor {
            hue: 0,
            saturation: 0,
            luminance: (l * 100.0) as u8,
        };
    }

    let d = max - min;
    let s = if l > 0.5 {
        d / (2.0 - max - min)
    } else {
        d / (max + min)
    };

    let h = if max == r {
        let mut h = (g - b) / d;
        if g < b {
            h += 6.0;
        }
        h
    } else if max == g {
        (b - r) / d + 2.0
    } else {
        (r - g) / d + 4.0
    };

    HslColor {
        hue: ((h * 60.0) as u16) % 360,
        saturation: (s * 100.0) as u8,
        luminance: (l * 100.0) as u8,
    }
}

/// Convert HSL to RGB
pub fn hsl_to_rgb(hsl: HslColor) -> (u8, u8, u8) {
    let h = hsl.hue as f32 / 360.0;
    let s = hsl.saturation as f32 / 100.0;
    let l = hsl.luminance as f32 / 100.0;

    if s == 0.0 {
        // Achromatic
        let v = (l * 255.0) as u8;
        return (v, v, v);
    }

    let q = if l < 0.5 {
        l * (1.0 + s)
    } else {
        l + s - l * s
    };
    let p = 2.0 * l - q;

    let r = hue_to_rgb(p, q, h + 1.0 / 3.0);
    let g = hue_to_rgb(p, q, h);
    let b = hue_to_rgb(p, q, h - 1.0 / 3.0);

    (
        (r * 255.0) as u8,
        (g * 255.0) as u8,
        (b * 255.0) as u8,
    )
}

fn hue_to_rgb(p: f32, q: f32, mut t: f32) -> f32 {
    if t < 0.0 {
        t += 1.0;
    }
    if t > 1.0 {
        t -= 1.0;
    }

    if t < 1.0 / 6.0 {
        return p + (q - p) * 6.0 * t;
    }
    if t < 1.0 / 2.0 {
        return q;
    }
    if t < 2.0 / 3.0 {
        return p + (q - p) * (2.0 / 3.0 - t) * 6.0;
    }
    p
}

// ============================================================================
// Dialog Creation
// ============================================================================

/// Create color dialog window
fn create_color_dialog(_cc: &ChooseColor) -> HWND {
    // Would create the actual dialog window
    UserHandle::NULL
}

/// Run color dialog modal loop
fn run_color_dialog(_hwnd: HWND, _cc: &mut ChooseColor) -> bool {
    // Would run modal dialog loop
    true
}

// ============================================================================
// Dialog Procedure
// ============================================================================

/// Color dialog window procedure
pub fn color_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    _lparam: isize,
) -> isize {
    match msg {
        super::message::WM_COMMAND => {
            handle_color_command(hwnd, wparam as u32)
        }
        super::message::WM_CLOSE => {
            close_color_dialog();
            0
        }
        _ => 0,
    }
}

/// Handle color dialog commands
fn handle_color_command(hwnd: HWND, command: u32) -> isize {
    let id = command as u16;

    match id {
        1 => {
            // OK button
            let state = CURRENT_STATE.lock();
            if state.active && state.hwnd == hwnd {
                // Result is already in state
                drop(state);
                close_color_dialog();
            }
            1
        }
        2 => {
            // Cancel button
            close_color_dialog();
            0
        }
        100..=147 => {
            // Basic color selection (48 colors)
            let color_idx = (id - 100) as usize;
            if color_idx < 48 {
                let color = BASIC_COLORS[color_idx];
                let (r, g, b) = (color.red(), color.green(), color.blue());
                let mut state = CURRENT_STATE.lock();
                state.red = r;
                state.green = g;
                state.blue = b;
                let hsl = rgb_to_hsl(r, g, b);
                state.hue = hsl.hue;
                state.saturation = hsl.saturation;
                state.luminance = hsl.luminance;
            }
            0
        }
        200..=215 => {
            // Custom color selection
            let color_idx = (id - 200) as usize;
            if color_idx < MAX_CUSTOM_COLORS {
                let custom = CUSTOM_COLORS.lock();
                let color = custom[color_idx];
                let (r, g, b) = (color.red(), color.green(), color.blue());
                let mut state = CURRENT_STATE.lock();
                state.red = r;
                state.green = g;
                state.blue = b;
                let hsl = rgb_to_hsl(r, g, b);
                state.hue = hsl.hue;
                state.saturation = hsl.saturation;
                state.luminance = hsl.luminance;
            }
            0
        }
        300 => {
            // Add to custom colors
            let state = CURRENT_STATE.lock();
            let color = ColorRef::rgb(state.red, state.green, state.blue);
            drop(state);

            // Find first white slot or use first slot
            let mut custom = CUSTOM_COLORS.lock();
            let mut target_idx = 0;
            for (i, c) in custom.iter().enumerate() {
                if c.0 == 0xFFFFFF {
                    target_idx = i;
                    break;
                }
            }
            custom[target_idx] = color;
            0
        }
        _ => 0,
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Create color from RGB components
pub fn make_rgb(r: u8, g: u8, b: u8) -> ColorRef {
    ColorRef::rgb(r, g, b)
}

/// Extract red component
pub fn get_r_value(color: ColorRef) -> u8 {
    (color.0 & 0xFF) as u8
}

/// Extract green component
pub fn get_g_value(color: ColorRef) -> u8 {
    ((color.0 >> 8) & 0xFF) as u8
}

/// Extract blue component
pub fn get_b_value(color: ColorRef) -> u8 {
    ((color.0 >> 16) & 0xFF) as u8
}

/// Blend two colors
pub fn blend_colors(c1: ColorRef, c2: ColorRef, factor: u8) -> ColorRef {
    let f = factor as u32;
    let inv_f = 255 - f;

    let (r1, g1, b1) = (c1.red(), c1.green(), c1.blue());
    let (r2, g2, b2) = (c2.red(), c2.green(), c2.blue());

    let r = ((r1 as u32 * inv_f + r2 as u32 * f) / 255) as u8;
    let g = ((g1 as u32 * inv_f + g2 as u32 * f) / 255) as u8;
    let b = ((b1 as u32 * inv_f + b2 as u32 * f) / 255) as u8;

    ColorRef::rgb(r, g, b)
}

/// Invert a color
pub fn invert_color(color: ColorRef) -> ColorRef {
    let (r, g, b) = (color.red(), color.green(), color.blue());
    ColorRef::rgb(255 - r, 255 - g, 255 - b)
}

/// Get contrasting text color (black or white)
pub fn get_contrast_color(background: ColorRef) -> ColorRef {
    let (r, g, b) = (background.red(), background.green(), background.blue());
    // Using luminance formula
    let luminance = (r as u32 * 299 + g as u32 * 587 + b as u32 * 114) / 1000;
    if luminance > 128 {
        ColorRef::rgb(0, 0, 0) // Black text
    } else {
        ColorRef::rgb(255, 255, 255) // White text
    }
}
