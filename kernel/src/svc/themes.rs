//! Themes Service (Themes)
//!
//! The Themes service provides visual styling support for Windows, including
//! the Luna theme introduced in Windows XP and the visual styles framework.
//!
//! # Features
//!
//! - **Visual Styles**: Apply visual themes to windows and controls
//! - **Theme Files**: Load and parse .msstyles theme files
//! - **Color Schemes**: Support multiple color schemes per theme
//! - **Classic Mode**: Fallback to Windows Classic look
//!
//! # Theme Structure
//!
//! A theme consists of:
//! - Visual style file (.msstyles)
//! - Color schemes
//! - Font sizes
//! - Wallpaper settings
//! - Sound schemes
//! - Mouse cursors
//!
//! # Default Themes
//!
//! Windows Server 2003 includes:
//! - Windows Classic (no visual style)
//! - Luna (Blue, Olive Green, Silver)
//! - Windows Standard

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum themes
const MAX_THEMES: usize = 16;

/// Maximum color schemes
const MAX_SCHEMES: usize = 8;

/// Maximum theme name length
const MAX_THEME_NAME: usize = 64;

/// Maximum path length
const MAX_PATH: usize = 260;

/// Maximum display name length
const MAX_DISPLAY_NAME: usize = 128;

/// Theme type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeType {
    /// Windows Classic (no visual style)
    Classic = 0,
    /// Visual style theme
    VisualStyle = 1,
    /// High contrast theme
    HighContrast = 2,
}

impl ThemeType {
    const fn empty() -> Self {
        ThemeType::Classic
    }
}

/// Color scheme
#[repr(C)]
#[derive(Clone)]
pub struct ColorScheme {
    /// Scheme name
    pub name: [u8; MAX_THEME_NAME],
    /// Display name
    pub display_name: [u8; MAX_DISPLAY_NAME],
    /// Is default scheme
    pub is_default: bool,
    /// Entry is valid
    pub valid: bool,
}

impl ColorScheme {
    const fn empty() -> Self {
        ColorScheme {
            name: [0; MAX_THEME_NAME],
            display_name: [0; MAX_DISPLAY_NAME],
            is_default: false,
            valid: false,
        }
    }
}

/// Font size option
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FontSize {
    /// Normal (96 DPI)
    Normal = 0,
    /// Large (120 DPI)
    Large = 1,
    /// Extra Large (144 DPI)
    ExtraLarge = 2,
}

impl FontSize {
    const fn empty() -> Self {
        FontSize::Normal
    }
}

/// Theme definition
#[repr(C)]
#[derive(Clone)]
pub struct ThemeDef {
    /// Theme name
    pub name: [u8; MAX_THEME_NAME],
    /// Display name
    pub display_name: [u8; MAX_DISPLAY_NAME],
    /// Theme file path
    pub file_path: [u8; MAX_PATH],
    /// Theme type
    pub theme_type: ThemeType,
    /// Color schemes
    pub schemes: [ColorScheme; MAX_SCHEMES],
    /// Scheme count
    pub scheme_count: usize,
    /// Current scheme index
    pub current_scheme: usize,
    /// Current font size
    pub font_size: FontSize,
    /// Wallpaper path
    pub wallpaper: [u8; MAX_PATH],
    /// Theme is active
    pub active: bool,
    /// Entry is valid
    pub valid: bool,
}

impl ThemeDef {
    const fn empty() -> Self {
        ThemeDef {
            name: [0; MAX_THEME_NAME],
            display_name: [0; MAX_DISPLAY_NAME],
            file_path: [0; MAX_PATH],
            theme_type: ThemeType::empty(),
            schemes: [const { ColorScheme::empty() }; MAX_SCHEMES],
            scheme_count: 0,
            current_scheme: 0,
            font_size: FontSize::empty(),
            wallpaper: [0; MAX_PATH],
            active: false,
            valid: false,
        }
    }
}

/// System colors
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SystemColors {
    /// Scrollbar
    pub scrollbar: u32,
    /// Desktop background
    pub background: u32,
    /// Active window caption
    pub active_caption: u32,
    /// Inactive window caption
    pub inactive_caption: u32,
    /// Menu
    pub menu: u32,
    /// Window background
    pub window: u32,
    /// Window frame
    pub window_frame: u32,
    /// Menu text
    pub menu_text: u32,
    /// Window text
    pub window_text: u32,
    /// Caption text
    pub caption_text: u32,
    /// Active border
    pub active_border: u32,
    /// Inactive border
    pub inactive_border: u32,
    /// Application workspace
    pub app_workspace: u32,
    /// Highlight
    pub highlight: u32,
    /// Highlight text
    pub highlight_text: u32,
    /// Button face
    pub btn_face: u32,
    /// Button shadow
    pub btn_shadow: u32,
    /// Gray text
    pub gray_text: u32,
    /// Button text
    pub btn_text: u32,
    /// Inactive caption text
    pub inactive_caption_text: u32,
    /// Button highlight
    pub btn_highlight: u32,
}

impl SystemColors {
    /// Classic Windows colors
    const fn classic() -> Self {
        SystemColors {
            scrollbar: 0x00C8C8C8, // Light gray
            background: 0x00004080, // Dark teal
            active_caption: 0x00800000, // Dark blue
            inactive_caption: 0x00808080, // Gray
            menu: 0x00C8C8C8,
            window: 0x00FFFFFF,
            window_frame: 0x00000000,
            menu_text: 0x00000000,
            window_text: 0x00000000,
            caption_text: 0x00FFFFFF,
            active_border: 0x00C8C8C8,
            inactive_border: 0x00C8C8C8,
            app_workspace: 0x00808080,
            highlight: 0x00800000,
            highlight_text: 0x00FFFFFF,
            btn_face: 0x00C8C8C8,
            btn_shadow: 0x00808080,
            gray_text: 0x00808080,
            btn_text: 0x00000000,
            inactive_caption_text: 0x00C8C8C8,
            btn_highlight: 0x00FFFFFF,
        }
    }

    /// Luna Blue colors (default XP/2003 theme)
    const fn luna_blue() -> Self {
        SystemColors {
            scrollbar: 0x00EBE8D8,
            background: 0x00AF8452,
            active_caption: 0x00D09256,
            inactive_caption: 0x00C6BAA2,
            menu: 0x00FFFFFF,
            window: 0x00FFFFFF,
            window_frame: 0x00000000,
            menu_text: 0x00000000,
            window_text: 0x00000000,
            caption_text: 0x00FFFFFF,
            active_border: 0x00D4D0C8,
            inactive_border: 0x00D4D0C8,
            app_workspace: 0x00808080,
            highlight: 0x00E36700,
            highlight_text: 0x00FFFFFF,
            btn_face: 0x00EBE8D8,
            btn_shadow: 0x00ADA990,
            gray_text: 0x00808080,
            btn_text: 0x00000000,
            inactive_caption_text: 0x00524742,
            btn_highlight: 0x00FFFFFF,
        }
    }
}

/// Themes service state
pub struct ThemesState {
    /// Service is running
    pub running: bool,
    /// Registered themes
    pub themes: [ThemeDef; MAX_THEMES],
    /// Theme count
    pub theme_count: usize,
    /// Active theme index
    pub active_theme: Option<usize>,
    /// Visual styles enabled
    pub visual_styles_enabled: bool,
    /// Current system colors
    pub colors: SystemColors,
    /// Flat menus enabled
    pub flat_menus: bool,
    /// Gradient captions enabled
    pub gradient_captions: bool,
    /// Service start time
    pub start_time: i64,
}

impl ThemesState {
    const fn new() -> Self {
        ThemesState {
            running: false,
            themes: [const { ThemeDef::empty() }; MAX_THEMES],
            theme_count: 0,
            active_theme: None,
            visual_styles_enabled: true,
            colors: SystemColors::classic(),
            flat_menus: true,
            gradient_captions: true,
            start_time: 0,
        }
    }
}

/// Global state
static THEMES_STATE: Mutex<ThemesState> = Mutex::new(ThemesState::new());

/// Statistics
static THEME_CHANGES: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize Themes service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = THEMES_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    // Register built-in themes
    register_builtin_themes(&mut state);

    // Apply default theme (Luna Blue if visual styles enabled)
    if state.visual_styles_enabled && state.theme_count > 1 {
        state.active_theme = Some(1); // Luna
        state.colors = SystemColors::luna_blue();
    } else {
        state.active_theme = Some(0); // Classic
    }

    crate::serial_println!("[THEMES] Themes service initialized");
}

/// Register built-in themes
fn register_builtin_themes(state: &mut ThemesState) {
    // Windows Classic
    let classic_idx = 0;
    let name = b"Classic";
    state.themes[classic_idx].name[..name.len()].copy_from_slice(name);
    let display = b"Windows Classic";
    state.themes[classic_idx].display_name[..display.len()].copy_from_slice(display);
    state.themes[classic_idx].theme_type = ThemeType::Classic;
    state.themes[classic_idx].valid = true;

    // Luna theme with color schemes
    let luna_idx = 1;
    let name = b"Luna";
    state.themes[luna_idx].name[..name.len()].copy_from_slice(name);
    let display = b"Windows XP";
    state.themes[luna_idx].display_name[..display.len()].copy_from_slice(display);
    let path = b"C:\\Windows\\Resources\\Themes\\luna\\luna.msstyles";
    state.themes[luna_idx].file_path[..path.len()].copy_from_slice(path);
    state.themes[luna_idx].theme_type = ThemeType::VisualStyle;

    // Blue scheme
    let scheme_name = b"NormalColor";
    state.themes[luna_idx].schemes[0].name[..scheme_name.len()].copy_from_slice(scheme_name);
    let scheme_display = b"Default (blue)";
    state.themes[luna_idx].schemes[0].display_name[..scheme_display.len()].copy_from_slice(scheme_display);
    state.themes[luna_idx].schemes[0].is_default = true;
    state.themes[luna_idx].schemes[0].valid = true;

    // Olive Green scheme
    let scheme_name = b"HomeStead";
    state.themes[luna_idx].schemes[1].name[..scheme_name.len()].copy_from_slice(scheme_name);
    let scheme_display = b"Olive Green";
    state.themes[luna_idx].schemes[1].display_name[..scheme_display.len()].copy_from_slice(scheme_display);
    state.themes[luna_idx].schemes[1].valid = true;

    // Silver scheme
    let scheme_name = b"Metallic";
    state.themes[luna_idx].schemes[2].name[..scheme_name.len()].copy_from_slice(scheme_name);
    let scheme_display = b"Silver";
    state.themes[luna_idx].schemes[2].display_name[..scheme_display.len()].copy_from_slice(scheme_display);
    state.themes[luna_idx].schemes[2].valid = true;

    state.themes[luna_idx].scheme_count = 3;
    state.themes[luna_idx].valid = true;

    // High Contrast Black
    let hc_idx = 2;
    let name = b"HighContrastBlack";
    state.themes[hc_idx].name[..name.len()].copy_from_slice(name);
    let display = b"High Contrast Black";
    state.themes[hc_idx].display_name[..display.len()].copy_from_slice(display);
    state.themes[hc_idx].theme_type = ThemeType::HighContrast;
    state.themes[hc_idx].valid = true;

    state.theme_count = 3;
}

/// Get current theme
pub fn get_current_theme() -> Option<ThemeDef> {
    let state = THEMES_STATE.lock();

    state.active_theme.and_then(|idx| {
        if idx < MAX_THEMES && state.themes[idx].valid {
            Some(state.themes[idx].clone())
        } else {
            None
        }
    })
}

/// Set active theme
pub fn set_theme(theme_idx: usize, scheme_idx: Option<usize>) -> Result<(), u32> {
    let mut state = THEMES_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    if theme_idx >= MAX_THEMES || !state.themes[theme_idx].valid {
        return Err(0x80070057);
    }

    // Deactivate current theme
    if let Some(current) = state.active_theme {
        if current < MAX_THEMES {
            state.themes[current].active = false;
        }
    }

    state.active_theme = Some(theme_idx);
    state.themes[theme_idx].active = true;

    // Set color scheme if specified
    if let Some(scheme) = scheme_idx {
        if scheme < state.themes[theme_idx].scheme_count {
            state.themes[theme_idx].current_scheme = scheme;
        }
    }

    // Update system colors based on theme type
    state.colors = match state.themes[theme_idx].theme_type {
        ThemeType::Classic => SystemColors::classic(),
        ThemeType::VisualStyle => SystemColors::luna_blue(),
        ThemeType::HighContrast => SystemColors::classic(), // Would be high contrast colors
    };

    THEME_CHANGES.fetch_add(1, Ordering::SeqCst);

    Ok(())
}

/// Enumerate themes
pub fn enum_themes() -> ([ThemeDef; MAX_THEMES], usize) {
    let state = THEMES_STATE.lock();
    let mut result = [const { ThemeDef::empty() }; MAX_THEMES];
    let mut count = 0;

    for theme in state.themes.iter() {
        if theme.valid && count < MAX_THEMES {
            result[count] = theme.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get system colors
pub fn get_system_colors() -> SystemColors {
    let state = THEMES_STATE.lock();
    state.colors
}

/// Set system color
pub fn set_system_color(color_idx: usize, value: u32) -> Result<(), u32> {
    let mut state = THEMES_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    match color_idx {
        0 => state.colors.scrollbar = value,
        1 => state.colors.background = value,
        2 => state.colors.active_caption = value,
        3 => state.colors.inactive_caption = value,
        4 => state.colors.menu = value,
        5 => state.colors.window = value,
        6 => state.colors.window_frame = value,
        7 => state.colors.menu_text = value,
        8 => state.colors.window_text = value,
        9 => state.colors.caption_text = value,
        10 => state.colors.active_border = value,
        11 => state.colors.inactive_border = value,
        12 => state.colors.app_workspace = value,
        13 => state.colors.highlight = value,
        14 => state.colors.highlight_text = value,
        15 => state.colors.btn_face = value,
        16 => state.colors.btn_shadow = value,
        17 => state.colors.gray_text = value,
        18 => state.colors.btn_text = value,
        19 => state.colors.inactive_caption_text = value,
        20 => state.colors.btn_highlight = value,
        _ => return Err(0x80070057),
    }

    Ok(())
}

/// Set visual styles enabled
pub fn set_visual_styles_enabled(enabled: bool) {
    let mut state = THEMES_STATE.lock();
    state.visual_styles_enabled = enabled;

    if !enabled {
        // Switch to classic theme
        if let Some(classic_idx) = state.themes.iter().position(|t| t.valid && t.theme_type == ThemeType::Classic) {
            if let Some(current) = state.active_theme {
                if current < MAX_THEMES {
                    state.themes[current].active = false;
                }
            }
            state.active_theme = Some(classic_idx);
            state.themes[classic_idx].active = true;
            state.colors = SystemColors::classic();
        }
    }
}

/// Is visual styles enabled
pub fn is_visual_styles_enabled() -> bool {
    let state = THEMES_STATE.lock();
    state.visual_styles_enabled
}

/// Set flat menus
pub fn set_flat_menus(enabled: bool) {
    let mut state = THEMES_STATE.lock();
    state.flat_menus = enabled;
}

/// Set gradient captions
pub fn set_gradient_captions(enabled: bool) {
    let mut state = THEMES_STATE.lock();
    state.gradient_captions = enabled;
}

/// Get theme by name
pub fn get_theme_by_name(name: &[u8]) -> Option<usize> {
    let state = THEMES_STATE.lock();
    let name_len = name.len().min(MAX_THEME_NAME);

    state.themes.iter().enumerate()
        .find(|(_, t)| t.valid && t.name[..name_len] == name[..name_len])
        .map(|(idx, _)| idx)
}

/// Set font size
pub fn set_font_size(theme_idx: usize, font_size: FontSize) -> Result<(), u32> {
    let mut state = THEMES_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    if theme_idx >= MAX_THEMES || !state.themes[theme_idx].valid {
        return Err(0x80070057);
    }

    state.themes[theme_idx].font_size = font_size;
    Ok(())
}

/// Set wallpaper
pub fn set_wallpaper(theme_idx: usize, wallpaper_path: &[u8]) -> Result<(), u32> {
    let mut state = THEMES_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    if theme_idx >= MAX_THEMES || !state.themes[theme_idx].valid {
        return Err(0x80070057);
    }

    let path_len = wallpaper_path.len().min(MAX_PATH);
    state.themes[theme_idx].wallpaper = [0; MAX_PATH];
    state.themes[theme_idx].wallpaper[..path_len].copy_from_slice(&wallpaper_path[..path_len]);

    Ok(())
}

/// Get statistics
pub fn get_statistics() -> u64 {
    THEME_CHANGES.load(Ordering::SeqCst)
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = THEMES_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = THEMES_STATE.lock();
    state.running = false;
    crate::serial_println!("[THEMES] Themes service stopped");
}
