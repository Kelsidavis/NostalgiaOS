//! Accessibility Support
//!
//! Windows accessibility features (SystemParametersInfo, screen reader support).
//! Based on Windows Server 2003 user32.h.
//!
//! # Features
//!
//! - High contrast mode
//! - Screen reader detection
//! - Keyboard accessibility
//! - Mouse accessibility
//! - Sound accessibility
//!
//! # References
//!
//! - `public/sdk/inc/winuser.h` - SPI_* constants

use crate::ke::spinlock::SpinLock;

// ============================================================================
// Accessibility Feature Flags
// ============================================================================

/// FilterKeys feature is on
pub const FKF_FILTERKEYSON: u32 = 0x00000001;

/// Available (shown in control panel)
pub const FKF_AVAILABLE: u32 = 0x00000002;

/// Hotkey active
pub const FKF_HOTKEYACTIVE: u32 = 0x00000004;

/// Confirmation dialog
pub const FKF_CONFIRMHOTKEY: u32 = 0x00000008;

/// Hotkey sound
pub const FKF_HOTKEYSOUND: u32 = 0x00000010;

/// Indicator
pub const FKF_INDICATOR: u32 = 0x00000020;

/// Click on
pub const FKF_CLICKON: u32 = 0x00000040;

/// StickyKeys feature is on
pub const SKF_STICKYKEYSON: u32 = 0x00000001;

/// StickyKeys available
pub const SKF_AVAILABLE: u32 = 0x00000002;

/// StickyKeys hotkey active
pub const SKF_HOTKEYACTIVE: u32 = 0x00000004;

/// StickyKeys confirmation
pub const SKF_CONFIRMHOTKEY: u32 = 0x00000008;

/// StickyKeys hotkey sound
pub const SKF_HOTKEYSOUND: u32 = 0x00000010;

/// StickyKeys indicator
pub const SKF_INDICATOR: u32 = 0x00000020;

/// StickyKeys audible feedback
pub const SKF_AUDIBLEFEEDBACK: u32 = 0x00000040;

/// StickyKeys tristate
pub const SKF_TRISTATE: u32 = 0x00000080;

/// StickyKeys two keys off
pub const SKF_TWOKEYSOFF: u32 = 0x00000100;

/// StickyKeys left alt latched
pub const SKF_LALTLATCHED: u32 = 0x10000000;

/// StickyKeys left ctrl latched
pub const SKF_LCTLLATCHED: u32 = 0x04000000;

/// StickyKeys left shift latched
pub const SKF_LSHIFTLATCHED: u32 = 0x01000000;

/// StickyKeys right alt latched
pub const SKF_RALTLATCHED: u32 = 0x20000000;

/// StickyKeys right ctrl latched
pub const SKF_RCTLLATCHED: u32 = 0x08000000;

/// StickyKeys right shift latched
pub const SKF_RSHIFTLATCHED: u32 = 0x02000000;

/// StickyKeys left windows latched
pub const SKF_LWINLATCHED: u32 = 0x40000000;

/// StickyKeys right windows latched
pub const SKF_RWINLATCHED: u32 = 0x80000000;

/// ToggleKeys feature is on
pub const TKF_TOGGLEKEYSON: u32 = 0x00000001;

/// ToggleKeys available
pub const TKF_AVAILABLE: u32 = 0x00000002;

/// ToggleKeys hotkey active
pub const TKF_HOTKEYACTIVE: u32 = 0x00000004;

/// ToggleKeys confirmation
pub const TKF_CONFIRMHOTKEY: u32 = 0x00000008;

/// ToggleKeys hotkey sound
pub const TKF_HOTKEYSOUND: u32 = 0x00000010;

/// ToggleKeys indicator
pub const TKF_INDICATOR: u32 = 0x00000020;

/// MouseKeys feature is on
pub const MKF_MOUSEKEYSON: u32 = 0x00000001;

/// MouseKeys available
pub const MKF_AVAILABLE: u32 = 0x00000002;

/// MouseKeys hotkey active
pub const MKF_HOTKEYACTIVE: u32 = 0x00000004;

/// MouseKeys confirmation
pub const MKF_CONFIRMHOTKEY: u32 = 0x00000008;

/// MouseKeys hotkey sound
pub const MKF_HOTKEYSOUND: u32 = 0x00000010;

/// MouseKeys indicator
pub const MKF_INDICATOR: u32 = 0x00000020;

/// MouseKeys modifiers
pub const MKF_MODIFIERS: u32 = 0x00000040;

/// MouseKeys replace numbers
pub const MKF_REPLACENUMBERS: u32 = 0x00000080;

/// MouseKeys left button selected
pub const MKF_LEFTBUTTONSEL: u32 = 0x10000000;

/// MouseKeys right button selected
pub const MKF_RIGHTBUTTONSEL: u32 = 0x20000000;

/// MouseKeys left button down
pub const MKF_LEFTBUTTONDOWN: u32 = 0x01000000;

/// MouseKeys right button down
pub const MKF_RIGHTBUTTONDOWN: u32 = 0x02000000;

/// HighContrast feature is on
pub const HCF_HIGHCONTRASTON: u32 = 0x00000001;

/// HighContrast available
pub const HCF_AVAILABLE: u32 = 0x00000002;

/// HighContrast hotkey active
pub const HCF_HOTKEYACTIVE: u32 = 0x00000004;

/// HighContrast confirmation
pub const HCF_CONFIRMHOTKEY: u32 = 0x00000008;

/// HighContrast hotkey sound
pub const HCF_HOTKEYSOUND: u32 = 0x00000010;

/// HighContrast indicator
pub const HCF_INDICATOR: u32 = 0x00000020;

/// HighContrast hotkey available
pub const HCF_HOTKEYAVAILABLE: u32 = 0x00000040;

/// SoundSentry feature is on
pub const SSF_SOUNDSENTRYON: u32 = 0x00000001;

/// SoundSentry available
pub const SSF_AVAILABLE: u32 = 0x00000002;

/// SoundSentry indicator
pub const SSF_INDICATOR: u32 = 0x00000004;

// ============================================================================
// SoundSentry Effects
// ============================================================================

/// No visual
pub const SSWF_NONE: u32 = 0;

/// Flash title
pub const SSWF_TITLE: u32 = 1;

/// Flash window
pub const SSWF_WINDOW: u32 = 2;

/// Flash display
pub const SSWF_DISPLAY: u32 = 3;

/// Custom
pub const SSWF_CUSTOM: u32 = 4;

// ============================================================================
// Accessibility Structures
// ============================================================================

/// FilterKeys settings
#[derive(Clone, Copy, Default)]
pub struct FilterKeys {
    /// Size of structure
    pub cb_size: u32,
    /// Flags
    pub flags: u32,
    /// Wait time (ms)
    pub wait_ms: u32,
    /// Delay time (ms)
    pub delay_ms: u32,
    /// Repeat time (ms)
    pub repeat_ms: u32,
    /// Bounce time (ms)
    pub bounce_ms: u32,
}

/// StickyKeys settings
#[derive(Clone, Copy, Default)]
pub struct StickyKeys {
    /// Size of structure
    pub cb_size: u32,
    /// Flags
    pub flags: u32,
}

/// ToggleKeys settings
#[derive(Clone, Copy, Default)]
pub struct ToggleKeys {
    /// Size of structure
    pub cb_size: u32,
    /// Flags
    pub flags: u32,
}

/// MouseKeys settings
#[derive(Clone, Copy, Default)]
pub struct MouseKeys {
    /// Size of structure
    pub cb_size: u32,
    /// Flags
    pub flags: u32,
    /// Maximum speed
    pub max_speed: u32,
    /// Time to max speed
    pub time_to_max_speed: u32,
    /// Control speed
    pub ctrl_speed: u32,
}

/// HighContrast settings
#[derive(Clone)]
pub struct HighContrast {
    /// Size of structure
    pub cb_size: u32,
    /// Flags
    pub flags: u32,
    /// Color scheme name
    pub color_scheme: [u8; 64],
}

impl Default for HighContrast {
    fn default() -> Self {
        Self {
            cb_size: 0,
            flags: 0,
            color_scheme: [0; 64],
        }
    }
}

/// SoundSentry settings
#[derive(Clone, Copy)]
pub struct SoundSentry {
    /// Size of structure
    pub cb_size: u32,
    /// Flags
    pub flags: u32,
    /// Windows effect
    pub windows_effect: u32,
    /// Windows effect MS
    pub windows_effect_ms: u32,
    /// Windows effect DLL
    pub windows_effect_dll: [u8; 64],
    /// FS text effect
    pub fs_text_effect: u32,
    /// FS text effect MS
    pub fs_text_effect_ms: u32,
    /// FS text effect color bits
    pub fs_text_effect_color_bits: u32,
    /// FS graphics effect
    pub fs_graphics_effect: u32,
    /// FS graphics effect MS
    pub fs_graphics_effect_ms: u32,
    /// FS graphics effect color bits
    pub fs_graphics_effect_color_bits: u32,
}

impl Default for SoundSentry {
    fn default() -> Self {
        Self {
            cb_size: 0,
            flags: 0,
            windows_effect: SSWF_NONE,
            windows_effect_ms: 0,
            windows_effect_dll: [0; 64],
            fs_text_effect: SSWF_NONE,
            fs_text_effect_ms: 0,
            fs_text_effect_color_bits: 0,
            fs_graphics_effect: SSWF_NONE,
            fs_graphics_effect_ms: 0,
            fs_graphics_effect_color_bits: 0,
        }
    }
}

/// AccessTimeout settings
#[derive(Clone, Copy, Default)]
pub struct AccessTimeout {
    /// Size of structure
    pub cb_size: u32,
    /// Flags
    pub flags: u32,
    /// Timeout (ms)
    pub timeout_ms: u32,
}

/// Access timeout flags
pub const ATF_TIMEOUTON: u32 = 0x00000001;
pub const ATF_ONOFFFEEDBACK: u32 = 0x00000002;

// ============================================================================
// Accessibility State
// ============================================================================

/// Global accessibility state
#[derive(Clone)]
struct AccessibilityState {
    /// Filter keys
    filter_keys: FilterKeys,
    /// Sticky keys
    sticky_keys: StickyKeys,
    /// Toggle keys
    toggle_keys: ToggleKeys,
    /// Mouse keys
    mouse_keys: MouseKeys,
    /// High contrast
    high_contrast: HighContrast,
    /// Sound sentry
    sound_sentry: SoundSentry,
    /// Access timeout
    access_timeout: AccessTimeout,
    /// Screen reader running
    screen_reader_running: bool,
    /// Screen magnifier running
    screen_magnifier_running: bool,
    /// On-screen keyboard running
    on_screen_keyboard_running: bool,
    /// Show sounds
    show_sounds: bool,
    /// Keyboard preference
    keyboard_pref: bool,
}

impl AccessibilityState {
    const fn new() -> Self {
        Self {
            filter_keys: FilterKeys {
                cb_size: 0,
                flags: FKF_AVAILABLE,
                wait_ms: 0,
                delay_ms: 0,
                repeat_ms: 0,
                bounce_ms: 0,
            },
            sticky_keys: StickyKeys {
                cb_size: 0,
                flags: SKF_AVAILABLE,
            },
            toggle_keys: ToggleKeys {
                cb_size: 0,
                flags: TKF_AVAILABLE,
            },
            mouse_keys: MouseKeys {
                cb_size: 0,
                flags: MKF_AVAILABLE,
                max_speed: 40,
                time_to_max_speed: 3000,
                ctrl_speed: 0,
            },
            high_contrast: HighContrast {
                cb_size: 0,
                flags: HCF_AVAILABLE | HCF_HOTKEYAVAILABLE,
                color_scheme: [0; 64],
            },
            sound_sentry: SoundSentry {
                cb_size: 0,
                flags: SSF_AVAILABLE,
                windows_effect: SSWF_NONE,
                windows_effect_ms: 0,
                windows_effect_dll: [0; 64],
                fs_text_effect: SSWF_NONE,
                fs_text_effect_ms: 0,
                fs_text_effect_color_bits: 0,
                fs_graphics_effect: SSWF_NONE,
                fs_graphics_effect_ms: 0,
                fs_graphics_effect_color_bits: 0,
            },
            access_timeout: AccessTimeout {
                cb_size: 0,
                flags: 0,
                timeout_ms: 300000, // 5 minutes
            },
            screen_reader_running: false,
            screen_magnifier_running: false,
            on_screen_keyboard_running: false,
            show_sounds: false,
            keyboard_pref: false,
        }
    }
}

static STATE: SpinLock<AccessibilityState> = SpinLock::new(AccessibilityState::new());

// ============================================================================
// Public API
// ============================================================================

/// Initialize accessibility
pub fn init() {
    crate::serial_println!("[USER] Accessibility support initialized");
}

/// Check if screen reader is running
pub fn is_screen_reader_running() -> bool {
    STATE.lock().screen_reader_running
}

/// Set screen reader running state
pub fn set_screen_reader_running(running: bool) {
    STATE.lock().screen_reader_running = running;
}

/// Check if high contrast is enabled
pub fn is_high_contrast() -> bool {
    let state = STATE.lock();
    (state.high_contrast.flags & HCF_HIGHCONTRASTON) != 0
}

/// Set high contrast state
pub fn set_high_contrast(enabled: bool) {
    let mut state = STATE.lock();
    if enabled {
        state.high_contrast.flags |= HCF_HIGHCONTRASTON;
    } else {
        state.high_contrast.flags &= !HCF_HIGHCONTRASTON;
    }
}

/// Get high contrast color scheme
pub fn get_high_contrast_scheme(buffer: &mut [u8]) -> usize {
    let state = STATE.lock();
    let len = super::strhelp::str_len(&state.high_contrast.color_scheme);
    let copy_len = len.min(buffer.len() - 1);
    buffer[..copy_len].copy_from_slice(&state.high_contrast.color_scheme[..copy_len]);
    if copy_len < buffer.len() {
        buffer[copy_len] = 0;
    }
    copy_len
}

/// Set high contrast color scheme
pub fn set_high_contrast_scheme(scheme: &[u8]) {
    let mut state = STATE.lock();
    let len = super::strhelp::str_len(scheme).min(63);
    state.high_contrast.color_scheme[..len].copy_from_slice(&scheme[..len]);
    state.high_contrast.color_scheme[len] = 0;
}

/// Check if filter keys is enabled
pub fn is_filter_keys() -> bool {
    let state = STATE.lock();
    (state.filter_keys.flags & FKF_FILTERKEYSON) != 0
}

/// Get filter keys settings
pub fn get_filter_keys() -> FilterKeys {
    STATE.lock().filter_keys
}

/// Set filter keys settings
pub fn set_filter_keys(settings: &FilterKeys) {
    STATE.lock().filter_keys = *settings;
}

/// Check if sticky keys is enabled
pub fn is_sticky_keys() -> bool {
    let state = STATE.lock();
    (state.sticky_keys.flags & SKF_STICKYKEYSON) != 0
}

/// Get sticky keys settings
pub fn get_sticky_keys() -> StickyKeys {
    STATE.lock().sticky_keys
}

/// Set sticky keys settings
pub fn set_sticky_keys(settings: &StickyKeys) {
    STATE.lock().sticky_keys = *settings;
}

/// Check if toggle keys is enabled
pub fn is_toggle_keys() -> bool {
    let state = STATE.lock();
    (state.toggle_keys.flags & TKF_TOGGLEKEYSON) != 0
}

/// Get toggle keys settings
pub fn get_toggle_keys() -> ToggleKeys {
    STATE.lock().toggle_keys
}

/// Set toggle keys settings
pub fn set_toggle_keys(settings: &ToggleKeys) {
    STATE.lock().toggle_keys = *settings;
}

/// Check if mouse keys is enabled
pub fn is_mouse_keys() -> bool {
    let state = STATE.lock();
    (state.mouse_keys.flags & MKF_MOUSEKEYSON) != 0
}

/// Get mouse keys settings
pub fn get_mouse_keys() -> MouseKeys {
    STATE.lock().mouse_keys
}

/// Set mouse keys settings
pub fn set_mouse_keys(settings: &MouseKeys) {
    STATE.lock().mouse_keys = *settings;
}

/// Check if show sounds is enabled
pub fn is_show_sounds() -> bool {
    STATE.lock().show_sounds
}

/// Set show sounds
pub fn set_show_sounds(enabled: bool) {
    STATE.lock().show_sounds = enabled;
}

/// Check keyboard preference
pub fn get_keyboard_pref() -> bool {
    STATE.lock().keyboard_pref
}

/// Set keyboard preference
pub fn set_keyboard_pref(pref: bool) {
    STATE.lock().keyboard_pref = pref;
}

/// Get sound sentry settings
pub fn get_sound_sentry() -> SoundSentry {
    STATE.lock().sound_sentry
}

/// Set sound sentry settings
pub fn set_sound_sentry(settings: &SoundSentry) {
    STATE.lock().sound_sentry = *settings;
}

/// Get access timeout settings
pub fn get_access_timeout() -> AccessTimeout {
    STATE.lock().access_timeout
}

/// Set access timeout settings
pub fn set_access_timeout(settings: &AccessTimeout) {
    STATE.lock().access_timeout = *settings;
}

/// Notify accessibility event
pub fn notify_win_event(event: u32, hwnd: super::super::HWND, id_object: i32, id_child: i32) {
    // In a real implementation, this would notify screen readers
    let _ = (event, hwnd, id_object, id_child);
}

/// Event constants
pub const EVENT_SYSTEM_SOUND: u32 = 0x0001;
pub const EVENT_SYSTEM_ALERT: u32 = 0x0002;
pub const EVENT_SYSTEM_FOREGROUND: u32 = 0x0003;
pub const EVENT_SYSTEM_MENUSTART: u32 = 0x0004;
pub const EVENT_SYSTEM_MENUEND: u32 = 0x0005;
pub const EVENT_SYSTEM_MENUPOPUPSTART: u32 = 0x0006;
pub const EVENT_SYSTEM_MENUPOPUPEND: u32 = 0x0007;
pub const EVENT_SYSTEM_CAPTURESTART: u32 = 0x0008;
pub const EVENT_SYSTEM_CAPTUREEND: u32 = 0x0009;
pub const EVENT_SYSTEM_MOVESIZESTART: u32 = 0x000A;
pub const EVENT_SYSTEM_MOVESIZEEND: u32 = 0x000B;
pub const EVENT_SYSTEM_CONTEXTHELPSTART: u32 = 0x000C;
pub const EVENT_SYSTEM_CONTEXTHELPEND: u32 = 0x000D;
pub const EVENT_SYSTEM_DRAGDROPSTART: u32 = 0x000E;
pub const EVENT_SYSTEM_DRAGDROPEND: u32 = 0x000F;
pub const EVENT_SYSTEM_DIALOGSTART: u32 = 0x0010;
pub const EVENT_SYSTEM_DIALOGEND: u32 = 0x0011;
pub const EVENT_SYSTEM_SCROLLINGSTART: u32 = 0x0012;
pub const EVENT_SYSTEM_SCROLLINGEND: u32 = 0x0013;
pub const EVENT_SYSTEM_SWITCHSTART: u32 = 0x0014;
pub const EVENT_SYSTEM_SWITCHEND: u32 = 0x0015;
pub const EVENT_SYSTEM_MINIMIZESTART: u32 = 0x0016;
pub const EVENT_SYSTEM_MINIMIZEEND: u32 = 0x0017;

pub const EVENT_OBJECT_CREATE: u32 = 0x8000;
pub const EVENT_OBJECT_DESTROY: u32 = 0x8001;
pub const EVENT_OBJECT_SHOW: u32 = 0x8002;
pub const EVENT_OBJECT_HIDE: u32 = 0x8003;
pub const EVENT_OBJECT_REORDER: u32 = 0x8004;
pub const EVENT_OBJECT_FOCUS: u32 = 0x8005;
pub const EVENT_OBJECT_SELECTION: u32 = 0x8006;
pub const EVENT_OBJECT_SELECTIONADD: u32 = 0x8007;
pub const EVENT_OBJECT_SELECTIONREMOVE: u32 = 0x8008;
pub const EVENT_OBJECT_SELECTIONWITHIN: u32 = 0x8009;
pub const EVENT_OBJECT_STATECHANGE: u32 = 0x800A;
pub const EVENT_OBJECT_LOCATIONCHANGE: u32 = 0x800B;
pub const EVENT_OBJECT_NAMECHANGE: u32 = 0x800C;
pub const EVENT_OBJECT_DESCRIPTIONCHANGE: u32 = 0x800D;
pub const EVENT_OBJECT_VALUECHANGE: u32 = 0x800E;
pub const EVENT_OBJECT_PARENTCHANGE: u32 = 0x800F;
pub const EVENT_OBJECT_HELPCHANGE: u32 = 0x8010;
pub const EVENT_OBJECT_DEFACTIONCHANGE: u32 = 0x8011;
pub const EVENT_OBJECT_ACCELERATORCHANGE: u32 = 0x8012;

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> AccessibilityStats {
    let state = STATE.lock();

    AccessibilityStats {
        filter_keys_enabled: (state.filter_keys.flags & FKF_FILTERKEYSON) != 0,
        sticky_keys_enabled: (state.sticky_keys.flags & SKF_STICKYKEYSON) != 0,
        toggle_keys_enabled: (state.toggle_keys.flags & TKF_TOGGLEKEYSON) != 0,
        mouse_keys_enabled: (state.mouse_keys.flags & MKF_MOUSEKEYSON) != 0,
        high_contrast_enabled: (state.high_contrast.flags & HCF_HIGHCONTRASTON) != 0,
        screen_reader_running: state.screen_reader_running,
    }
}

/// Accessibility statistics
#[derive(Debug, Clone, Copy)]
pub struct AccessibilityStats {
    pub filter_keys_enabled: bool,
    pub sticky_keys_enabled: bool,
    pub toggle_keys_enabled: bool,
    pub mouse_keys_enabled: bool,
    pub high_contrast_enabled: bool,
    pub screen_reader_running: bool,
}
