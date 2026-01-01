//! System Metrics
//!
//! Implementation of Windows NT-style system metrics (GetSystemMetrics).
//! Provides system configuration values like screen dimensions, border sizes, etc.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/sysmet.c`
//! - `windows/published/winuser.w` (SM_* constants)

use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// System Metrics Constants (SM_*)
// ============================================================================

/// System metric indices
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemMetric {
    /// Screen width in pixels
    CxScreen = 0,
    /// Screen height in pixels
    CyScreen = 1,
    /// Vertical scroll bar width
    CxVScroll = 2,
    /// Horizontal scroll bar height
    CyHScroll = 3,
    /// Caption bar height
    CyCaption = 4,
    /// Window border width
    CxBorder = 5,
    /// Window border height
    CyBorder = 6,
    /// Dialog frame width
    CxDlgFrame = 7,
    /// Dialog frame height
    CyDlgFrame = 8,
    /// Vertical scroll thumb height
    CyVThumb = 9,
    /// Horizontal scroll thumb width
    CxHThumb = 10,
    /// Icon width
    CxIcon = 11,
    /// Icon height
    CyIcon = 12,
    /// Cursor width
    CxCursor = 13,
    /// Cursor height
    CyCursor = 14,
    /// Menu bar height
    CyMenu = 15,
    /// Full-screen client width
    CxFullScreen = 16,
    /// Full-screen client height
    CyFullScreen = 17,
    /// Kanji window height
    CyKanjiWindow = 18,
    /// Mouse present flag
    MousePresent = 19,
    /// Vertical scroll arrow height
    CyVScroll = 20,
    /// Horizontal scroll arrow width
    CxHScroll = 21,
    /// Debug flag
    Debug = 22,
    /// Swap mouse buttons flag
    SwapButton = 23,
    /// Reserved
    Reserved1 = 24,
    /// Reserved
    Reserved2 = 25,
    /// Reserved
    Reserved3 = 26,
    /// Reserved
    Reserved4 = 27,
    /// Minimum window width
    CxMin = 28,
    /// Minimum window height
    CyMin = 29,
    /// Caption button width
    CxSize = 30,
    /// Caption button height
    CySize = 31,
    /// Sizing border width
    CxFrame = 32,
    /// Sizing border height
    CyFrame = 33,
    /// Minimum tracking width
    CxMinTrack = 34,
    /// Minimum tracking height
    CyMinTrack = 35,
    /// Double-click width
    CxDoubleClk = 36,
    /// Double-click height
    CyDoubleClk = 37,
    /// Icon grid width
    CxIconSpacing = 38,
    /// Icon grid height
    CyIconSpacing = 39,
    /// Menu drop alignment
    MenuDropAlignment = 40,
    /// Pen Windows present
    PenWindows = 41,
    /// DBCS enabled
    DbcsEnabled = 42,
    /// Number of mouse buttons
    CMouseButtons = 43,
    /// Secure desktop flag
    Secure = 44,
    /// 3D edge width
    CxEdge = 45,
    /// 3D edge height
    CyEdge = 46,
    /// Minimized grid width
    CxMinSpacing = 47,
    /// Minimized grid height
    CyMinSpacing = 48,
    /// Small icon width
    CxSmIcon = 49,
    /// Small icon height
    CySmIcon = 50,
    /// Small caption height
    CySmCaption = 51,
    /// Small caption button width
    CxSmSize = 52,
    /// Small caption button height
    CySmSize = 53,
    /// Menu bar button width
    CxMenuSize = 54,
    /// Menu bar button height
    CyMenuSize = 55,
    /// Arrange direction flags
    Arrange = 56,
    /// Minimized window width
    CxMinimized = 57,
    /// Minimized window height
    CyMinimized = 58,
    /// Maximum tracking width
    CxMaxTrack = 59,
    /// Maximum tracking height
    CyMaxTrack = 60,
    /// Maximized window width
    CxMaximized = 61,
    /// Maximized window height
    CyMaximized = 62,
    /// Network present flag
    Network = 63,
    /// Clean boot type
    CleanBoot = 67,
    /// Drag width
    CxDrag = 68,
    /// Drag height
    CyDrag = 69,
    /// Show sounds flag
    ShowSounds = 70,
    /// Menu check width
    CxMenuCheck = 71,
    /// Menu check height
    CyMenuCheck = 72,
    /// Slow machine flag
    SlowMachine = 73,
    /// Mideast enabled flag
    MideastEnabled = 74,
    /// Mouse wheel present
    MouseWheelPresent = 75,
    /// Virtual screen x
    XVirtualScreen = 76,
    /// Virtual screen y
    YVirtualScreen = 77,
    /// Virtual screen width
    CxVirtualScreen = 78,
    /// Virtual screen height
    CyVirtualScreen = 79,
    /// Number of monitors
    CMonitors = 80,
    /// Same display format flag
    SameDisplayFormat = 81,
    /// IMM enabled
    ImmEnabled = 82,
    /// Focus border width
    CxFocusBorder = 83,
    /// Focus border height
    CyFocusBorder = 84,
    /// Tablet PC flag
    TabletPc = 86,
    /// Media center flag
    MediaCenter = 87,
    /// Starter flag
    Starter = 88,
    /// Server R2 flag
    ServerR2 = 89,
}

impl SystemMetric {
    /// Convert from raw index
    pub fn from_index(index: i32) -> Option<Self> {
        if index >= 0 && index <= 89 {
            // Safe because we're in valid range
            Some(unsafe { core::mem::transmute(index) })
        } else {
            None
        }
    }
}

// ============================================================================
// System Metrics Values
// ============================================================================

/// System metrics storage
struct SystemMetricsData {
    /// Screen width
    cx_screen: i32,
    /// Screen height
    cy_screen: i32,
    /// Mouse present
    mouse_present: bool,
    /// Number of mouse buttons
    mouse_buttons: i32,
    /// Mouse wheel present
    mouse_wheel_present: bool,
    /// Network present
    network_present: bool,
    /// DBCS enabled
    dbcs_enabled: bool,
    /// Debug mode
    debug_mode: bool,
    /// Swap mouse buttons
    swap_buttons: bool,
}

impl SystemMetricsData {
    const fn new() -> Self {
        Self {
            cx_screen: 800,
            cy_screen: 600,
            mouse_present: true,
            mouse_buttons: 3,
            mouse_wheel_present: true,
            network_present: false,
            dbcs_enabled: false,
            debug_mode: false,
            swap_buttons: false,
        }
    }
}

static METRICS: SpinLock<SystemMetricsData> = SpinLock::new(SystemMetricsData::new());
static METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize system metrics
pub fn init() {
    if METRICS_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[USER/Metrics] System metrics initialized");
    METRICS_INITIALIZED.store(true, Ordering::Release);
}

/// Set screen dimensions
pub fn set_screen_size(width: i32, height: i32) {
    let mut metrics = METRICS.lock();
    metrics.cx_screen = width;
    metrics.cy_screen = height;
    crate::serial_println!("[USER/Metrics] Screen size set to {}x{}", width, height);
}

// ============================================================================
// GetSystemMetrics
// ============================================================================

/// Get a system metric value
///
/// # Arguments
/// * `index` - System metric index (SM_* constant)
///
/// # Returns
/// The metric value, or 0 if the index is invalid
pub fn get_system_metrics(index: i32) -> i32 {
    let metrics = METRICS.lock();

    match index {
        // Screen dimensions
        0 => metrics.cx_screen,                    // SM_CXSCREEN
        1 => metrics.cy_screen,                    // SM_CYSCREEN

        // Scroll bar dimensions
        2 => 17,                                   // SM_CXVSCROLL - vertical scrollbar width
        3 => 17,                                   // SM_CYHSCROLL - horizontal scrollbar height
        20 => 17,                                  // SM_CYVSCROLL - vertical scroll arrow height
        21 => 17,                                  // SM_CXHSCROLL - horizontal scroll arrow width
        9 => 17,                                   // SM_CYVTHUMB - vertical thumb height
        10 => 17,                                  // SM_CXHTHUMB - horizontal thumb width

        // Caption and title bar
        4 => 23,                                   // SM_CYCAPTION - caption height
        51 => 17,                                  // SM_CYSMCAPTION - small caption height

        // Borders and frames
        5 => 1,                                    // SM_CXBORDER
        6 => 1,                                    // SM_CYBORDER
        7 => 3,                                    // SM_CXDLGFRAME / SM_CXFIXEDFRAME
        8 => 3,                                    // SM_CYDLGFRAME / SM_CYFIXEDFRAME
        32 => 4,                                   // SM_CXFRAME / SM_CXSIZEFRAME
        33 => 4,                                   // SM_CYFRAME / SM_CYSIZEFRAME
        45 => 2,                                   // SM_CXEDGE
        46 => 2,                                   // SM_CYEDGE

        // Icons
        11 => 32,                                  // SM_CXICON
        12 => 32,                                  // SM_CYICON
        49 => 16,                                  // SM_CXSMICON
        50 => 16,                                  // SM_CYSMICON
        38 => 75,                                  // SM_CXICONSPACING
        39 => 75,                                  // SM_CYICONSPACING

        // Cursor
        13 => 32,                                  // SM_CXCURSOR
        14 => 32,                                  // SM_CYCURSOR

        // Menu
        15 => 20,                                  // SM_CYMENU
        54 => 19,                                  // SM_CXMENUSIZE
        55 => 19,                                  // SM_CYMENUSIZE
        71 => 15,                                  // SM_CXMENUCHECK
        72 => 15,                                  // SM_CYMENUCHECK
        40 => 0,                                   // SM_MENUDROPALIGNMENT (0 = left)

        // Full screen
        16 => metrics.cx_screen,                   // SM_CXFULLSCREEN
        17 => metrics.cy_screen - 23,              // SM_CYFULLSCREEN (minus taskbar)

        // Caption buttons
        30 => 18,                                  // SM_CXSIZE
        31 => 18,                                  // SM_CYSIZE
        52 => 15,                                  // SM_CXSMSIZE
        53 => 15,                                  // SM_CYSMSIZE

        // Window minimums
        28 => 112,                                 // SM_CXMIN
        29 => 27,                                  // SM_CYMIN
        34 => 112,                                 // SM_CXMINTRACK
        35 => 27,                                  // SM_CYMINTRACK

        // Window maximums
        59 => metrics.cx_screen + 8,               // SM_CXMAXTRACK
        60 => metrics.cy_screen + 8,               // SM_CYMAXTRACK
        61 => metrics.cx_screen,                   // SM_CXMAXIMIZED
        62 => metrics.cy_screen - 4,               // SM_CYMAXIMIZED

        // Minimized windows
        57 => 160,                                 // SM_CXMINIMIZED
        58 => 24,                                  // SM_CYMINIMIZED
        47 => 160,                                 // SM_CXMINSPACING
        48 => 24,                                  // SM_CYMINSPACING
        56 => 8,                                   // SM_ARRANGE (ARW_HIDE)

        // Double click
        36 => 4,                                   // SM_CXDOUBLECLICK
        37 => 4,                                   // SM_CYDOUBLECLICK

        // Drag
        68 => 4,                                   // SM_CXDRAG
        69 => 4,                                   // SM_CYDRAG

        // Focus border
        83 => 1,                                   // SM_CXFOCUSBORDER
        84 => 1,                                   // SM_CYFOCUSBORDER

        // Mouse
        19 => if metrics.mouse_present { 1 } else { 0 },   // SM_MOUSEPRESENT
        23 => if metrics.swap_buttons { 1 } else { 0 },    // SM_SWAPBUTTON
        43 => metrics.mouse_buttons,               // SM_CMOUSEBUTTONS
        75 => if metrics.mouse_wheel_present { 1 } else { 0 }, // SM_MOUSEWHEELPRESENT

        // System flags
        22 => if metrics.debug_mode { 1 } else { 0 },      // SM_DEBUG
        42 => if metrics.dbcs_enabled { 1 } else { 0 },    // SM_DBCSENABLED
        63 => if metrics.network_present { 3 } else { 0 }, // SM_NETWORK
        67 => 0,                                   // SM_CLEANBOOT (normal boot)
        70 => 0,                                   // SM_SHOWSOUNDS
        73 => 0,                                   // SM_SLOWMACHINE
        74 => 0,                                   // SM_MIDEASTENABLED
        82 => 0,                                   // SM_IMMENABLED
        86 => 0,                                   // SM_TABLETPC
        87 => 0,                                   // SM_MEDIACENTER
        88 => 0,                                   // SM_STARTER
        89 => 0,                                   // SM_SERVERR2

        // Virtual screen (multi-monitor)
        76 => 0,                                   // SM_XVIRTUALSCREEN
        77 => 0,                                   // SM_YVIRTUALSCREEN
        78 => metrics.cx_screen,                   // SM_CXVIRTUALSCREEN
        79 => metrics.cy_screen,                   // SM_CYVIRTUALSCREEN
        80 => 1,                                   // SM_CMONITORS
        81 => 1,                                   // SM_SAMEDISPLAYFORMAT

        // Reserved / misc
        18 => 0,                                   // SM_CYKANJIWINDOW
        41 => 0,                                   // SM_PENWINDOWS
        44 => 0,                                   // SM_SECURE

        _ => 0,                                    // Unknown metric
    }
}

/// Get a system metric by enum value
pub fn get_metric(metric: SystemMetric) -> i32 {
    get_system_metrics(metric as i32)
}

// ============================================================================
// System Parameter Info (partial)
// ============================================================================

/// System parameter actions (SPI_*)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemParameterAction {
    /// Get beep setting
    GetBeep = 0x0001,
    /// Set beep setting
    SetBeep = 0x0002,
    /// Get mouse settings
    GetMouse = 0x0003,
    /// Set mouse settings
    SetMouse = 0x0004,
    /// Get border width
    GetBorder = 0x0005,
    /// Set border width
    SetBorder = 0x0006,
    /// Get keyboard speed
    GetKeyboardSpeed = 0x000A,
    /// Set keyboard speed
    SetKeyboardSpeed = 0x000B,
    /// Get icon title wrap
    GetIconTitleWrap = 0x0019,
    /// Set icon title wrap
    SetIconTitleWrap = 0x001A,
    /// Get screen saver timeout
    GetScreenSaveTimeout = 0x000E,
    /// Set screen saver timeout
    SetScreenSaveTimeout = 0x000F,
    /// Get screen saver active
    GetScreenSaveActive = 0x0010,
    /// Set screen saver active
    SetScreenSaveActive = 0x0011,
    /// Get work area
    GetWorkArea = 0x0030,
    /// Set work area
    SetWorkArea = 0x002F,
    /// Get non-client metrics
    GetNonClientMetrics = 0x0029,
    /// Set non-client metrics
    SetNonClientMetrics = 0x002A,
    /// Get minimize metrics
    GetMinimizedMetrics = 0x002B,
    /// Set minimize metrics
    SetMinimizedMetrics = 0x002C,
    /// Get icon metrics
    GetIconMetrics = 0x002D,
    /// Set icon metrics
    SetIconMetrics = 0x002E,
    /// Get drag full windows
    GetDragFullWindows = 0x0026,
    /// Set drag full windows
    SetDragFullWindows = 0x0025,
    /// Get font smoothing
    GetFontSmoothing = 0x004A,
    /// Set font smoothing
    SetFontSmoothing = 0x004B,
    /// Get gradient captions
    GetGradientCaptions = 0x1008,
    /// Set gradient captions
    SetGradientCaptions = 0x1009,
    /// Get hot tracking
    GetHotTracking = 0x100E,
    /// Set hot tracking
    SetHotTracking = 0x100F,
    /// Get flat menu
    GetFlatMenu = 0x1022,
    /// Set flat menu
    SetFlatMenu = 0x1023,
}

/// System parameters storage
struct SystemParameters {
    /// Beep enabled
    beep: bool,
    /// Border width
    border: i32,
    /// Keyboard speed (0-31)
    keyboard_speed: i32,
    /// Icon title wrap
    icon_title_wrap: bool,
    /// Screen saver timeout (seconds)
    screensaver_timeout: i32,
    /// Screen saver active
    screensaver_active: bool,
    /// Drag full windows
    drag_full_windows: bool,
    /// Font smoothing enabled
    font_smoothing: bool,
    /// Gradient captions
    gradient_captions: bool,
    /// Hot tracking
    hot_tracking: bool,
    /// Flat menu
    flat_menu: bool,
}

impl SystemParameters {
    const fn new() -> Self {
        Self {
            beep: true,
            border: 1,
            keyboard_speed: 31,
            icon_title_wrap: true,
            screensaver_timeout: 900, // 15 minutes
            screensaver_active: false,
            drag_full_windows: true,
            font_smoothing: true,
            gradient_captions: true,
            hot_tracking: true,
            flat_menu: false,
        }
    }
}

static SYSTEM_PARAMS: SpinLock<SystemParameters> = SpinLock::new(SystemParameters::new());

/// Get or set a system parameter
///
/// # Arguments
/// * `action` - Action to perform (SPI_GET* or SPI_SET*)
/// * `param` - Action-specific parameter
/// * `data` - Pointer to data buffer (for get/set operations)
/// * `win_ini` - Update flags (SPIF_*)
///
/// # Returns
/// true on success, false on failure
pub fn system_parameters_info(action: u32, param: u32, data: usize, _win_ini: u32) -> bool {
    let mut params = SYSTEM_PARAMS.lock();

    match action {
        // Beep
        0x0001 => { // SPI_GETBEEP
            if data != 0 {
                unsafe { *(data as *mut bool) = params.beep; }
            }
            true
        }
        0x0002 => { // SPI_SETBEEP
            params.beep = param != 0;
            true
        }

        // Border
        0x0005 => { // SPI_GETBORDER
            if data != 0 {
                unsafe { *(data as *mut i32) = params.border; }
            }
            true
        }
        0x0006 => { // SPI_SETBORDER
            params.border = param as i32;
            true
        }

        // Keyboard speed
        0x000A => { // SPI_GETKEYBOARDSPEED
            if data != 0 {
                unsafe { *(data as *mut i32) = params.keyboard_speed; }
            }
            true
        }
        0x000B => { // SPI_SETKEYBOARDSPEED
            params.keyboard_speed = (param as i32).clamp(0, 31);
            true
        }

        // Screen saver
        0x000E => { // SPI_GETSCREENSAVETIMEOUT
            if data != 0 {
                unsafe { *(data as *mut i32) = params.screensaver_timeout; }
            }
            true
        }
        0x000F => { // SPI_SETSCREENSAVETIMEOUT
            params.screensaver_timeout = param as i32;
            true
        }
        0x0010 => { // SPI_GETSCREENSAVEACTIVE
            if data != 0 {
                unsafe { *(data as *mut bool) = params.screensaver_active; }
            }
            true
        }
        0x0011 => { // SPI_SETSCREENSAVEACTIVE
            params.screensaver_active = param != 0;
            true
        }

        // Icon title wrap
        0x0019 => { // SPI_GETICONTITLEWRAP
            if data != 0 {
                unsafe { *(data as *mut bool) = params.icon_title_wrap; }
            }
            true
        }
        0x001A => { // SPI_SETICONTITLEWRAP
            params.icon_title_wrap = param != 0;
            true
        }

        // Visual effects
        0x0026 => { // SPI_GETDRAGFULLWINDOWS
            if data != 0 {
                unsafe { *(data as *mut bool) = params.drag_full_windows; }
            }
            true
        }
        0x0025 => { // SPI_SETDRAGFULLWINDOWS
            params.drag_full_windows = param != 0;
            true
        }

        0x004A => { // SPI_GETFONTSMOOTHING
            if data != 0 {
                unsafe { *(data as *mut bool) = params.font_smoothing; }
            }
            true
        }
        0x004B => { // SPI_SETFONTSMOOTHING
            params.font_smoothing = param != 0;
            true
        }

        0x1008 => { // SPI_GETGRADIENTCAPTIONS
            if data != 0 {
                unsafe { *(data as *mut bool) = params.gradient_captions; }
            }
            true
        }
        0x1009 => { // SPI_SETGRADIENTCAPTIONS
            params.gradient_captions = param != 0;
            true
        }

        0x100E => { // SPI_GETHOTTRACKING
            if data != 0 {
                unsafe { *(data as *mut bool) = params.hot_tracking; }
            }
            true
        }
        0x100F => { // SPI_SETHOTTRACKING
            params.hot_tracking = param != 0;
            true
        }

        0x1022 => { // SPI_GETFLATMENU
            if data != 0 {
                unsafe { *(data as *mut bool) = params.flat_menu; }
            }
            true
        }
        0x1023 => { // SPI_SETFLATMENU
            params.flat_menu = param != 0;
            true
        }

        // Work area (returns screen rect minus taskbar)
        0x0030 => { // SPI_GETWORKAREA
            if data != 0 {
                let metrics = METRICS.lock();
                let rect = super::super::Rect::new(0, 0, metrics.cx_screen, metrics.cy_screen - 30);
                unsafe { *(data as *mut super::super::Rect) = rect; }
            }
            true
        }

        _ => false,
    }
}

// ============================================================================
// Color Constants
// ============================================================================

/// System color indices
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemColor {
    /// Scroll bar
    ScrollBar = 0,
    /// Desktop background
    Background = 1,
    /// Active caption
    ActiveCaption = 2,
    /// Inactive caption
    InactiveCaption = 3,
    /// Menu background
    Menu = 4,
    /// Window background
    Window = 5,
    /// Window frame
    WindowFrame = 6,
    /// Menu text
    MenuText = 7,
    /// Window text
    WindowText = 8,
    /// Caption text
    CaptionText = 9,
    /// Active border
    ActiveBorder = 10,
    /// Inactive border
    InactiveBorder = 11,
    /// App workspace
    AppWorkspace = 12,
    /// Highlight
    Highlight = 13,
    /// Highlight text
    HighlightText = 14,
    /// Button face
    BtnFace = 15,
    /// Button shadow
    BtnShadow = 16,
    /// Gray text
    GrayText = 17,
    /// Button text
    BtnText = 18,
    /// Inactive caption text
    InactiveCaptionText = 19,
    /// Button highlight
    BtnHighlight = 20,
    /// 3D dark shadow
    DkShadow3D = 21,
    /// 3D light
    Light3D = 22,
    /// Info text
    InfoText = 23,
    /// Info background
    InfoBk = 24,
    /// Hot light
    HotLight = 26,
    /// Gradient active caption
    GradientActiveCaption = 27,
    /// Gradient inactive caption
    GradientInactiveCaption = 28,
    /// Menu highlight
    MenuHighlight = 29,
    /// Menu bar
    MenuBar = 30,
}

/// System colors storage
static SYSTEM_COLORS: SpinLock<[u32; 31]> = SpinLock::new([
    0x00C8C8C8, // COLOR_SCROLLBAR
    0x00A56E3A, // COLOR_BACKGROUND (desktop)
    0x00D1B499, // COLOR_ACTIVECAPTION
    0x00ACA899, // COLOR_INACTIVECAPTION
    0x00FFFFFF, // COLOR_MENU
    0x00FFFFFF, // COLOR_WINDOW
    0x00000000, // COLOR_WINDOWFRAME
    0x00000000, // COLOR_MENUTEXT
    0x00000000, // COLOR_WINDOWTEXT
    0x00FFFFFF, // COLOR_CAPTIONTEXT
    0x00D4D0C8, // COLOR_ACTIVEBORDER
    0x00D4D0C8, // COLOR_INACTIVEBORDER
    0x00808080, // COLOR_APPWORKSPACE
    0x00D1B499, // COLOR_HIGHLIGHT
    0x00FFFFFF, // COLOR_HIGHLIGHTTEXT
    0x00D4D0C8, // COLOR_BTNFACE
    0x00808080, // COLOR_BTNSHADOW
    0x00808080, // COLOR_GRAYTEXT
    0x00000000, // COLOR_BTNTEXT
    0x00D4D0C8, // COLOR_INACTIVECAPTIONTEXT
    0x00FFFFFF, // COLOR_BTNHIGHLIGHT
    0x00404040, // COLOR_3DDKSHADOW
    0x00E0E0E0, // COLOR_3DLIGHT
    0x00000000, // COLOR_INFOTEXT
    0x00E1FFFF, // COLOR_INFOBK
    0x00000000, // Reserved
    0x00FF8000, // COLOR_HOTLIGHT
    0x00EAD999, // COLOR_GRADIENTACTIVECAPTION
    0x00C8C8C8, // COLOR_GRADIENTINACTIVECAPTION
    0x00D1B499, // COLOR_MENUHILIGHT
    0x00D4D0C8, // COLOR_MENUBAR
]);

/// Get a system color
pub fn get_sys_color(index: i32) -> u32 {
    if index >= 0 && index < 31 {
        let colors = SYSTEM_COLORS.lock();
        colors[index as usize]
    } else {
        0
    }
}

/// Set a system color
pub fn set_sys_colors(indices: &[i32], colors: &[u32]) -> bool {
    if indices.len() != colors.len() {
        return false;
    }

    let mut sys_colors = SYSTEM_COLORS.lock();

    for (i, &index) in indices.iter().enumerate() {
        if index >= 0 && index < 31 {
            sys_colors[index as usize] = colors[i];
        }
    }

    true
}

/// Get system color brush
pub fn get_sys_color_brush(index: i32) -> super::super::GdiHandle {
    let color = get_sys_color(index);
    let r = ((color >> 16) & 0xFF) as u8;
    let g = ((color >> 8) & 0xFF) as u8;
    let b = (color & 0xFF) as u8;
    super::super::gdi::brush::create_solid_brush(super::super::ColorRef::rgb(r, g, b))
}
