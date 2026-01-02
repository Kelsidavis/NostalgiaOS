//! Accessibility Settings
//!
//! Kernel-mode accessibility options control panel following Windows NT patterns.
//! Provides StickyKeys, FilterKeys, ToggleKeys, SoundSentry, MouseKeys, and
//! high contrast/visual settings.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/cpls/access/access.c` - Accessibility control panel

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// Constants
// ============================================================================

/// StickyKeys flags
pub mod sticky_keys_flags {
    /// StickyKeys available
    pub const AVAILABLE: u32 = 0x0002;
    /// StickyKeys confirmation dialog
    pub const CONFIRM_HOTKEY: u32 = 0x0008;
    /// Hotkey active
    pub const HOTKEY_ACTIVE: u32 = 0x0010;
    /// Hotkey sound
    pub const HOTKEY_SOUND: u32 = 0x0020;
    /// Indicator on
    pub const INDICATOR: u32 = 0x0040;
    /// Audible feedback
    pub const AUDIBLE_FEEDBACK: u32 = 0x0080;
    /// Three key trigger
    pub const TRISTATE: u32 = 0x0100;
    /// Two keys at once turns off
    pub const TWO_KEYS_OFF: u32 = 0x0200;
    /// StickyKeys on
    pub const ON: u32 = 0x0001;
}

/// FilterKeys flags
pub mod filter_keys_flags {
    /// FilterKeys available
    pub const AVAILABLE: u32 = 0x0002;
    /// Hotkey active
    pub const HOTKEY_ACTIVE: u32 = 0x0010;
    /// Confirmation dialog
    pub const CONFIRM_HOTKEY: u32 = 0x0008;
    /// Hotkey sound
    pub const HOTKEY_SOUND: u32 = 0x0020;
    /// Indicator
    pub const INDICATOR: u32 = 0x0040;
    /// Click on
    pub const CLICK_ON: u32 = 0x0100;
    /// FilterKeys on
    pub const ON: u32 = 0x0001;
}

/// ToggleKeys flags
pub mod toggle_keys_flags {
    /// ToggleKeys available
    pub const AVAILABLE: u32 = 0x0002;
    /// Hotkey active
    pub const HOTKEY_ACTIVE: u32 = 0x0010;
    /// Confirmation dialog
    pub const CONFIRM_HOTKEY: u32 = 0x0008;
    /// Hotkey sound
    pub const HOTKEY_SOUND: u32 = 0x0020;
    /// Indicator
    pub const INDICATOR: u32 = 0x0040;
    /// ToggleKeys on
    pub const ON: u32 = 0x0001;
}

/// MouseKeys flags
pub mod mouse_keys_flags {
    /// MouseKeys available
    pub const AVAILABLE: u32 = 0x0002;
    /// Hotkey active
    pub const HOTKEY_ACTIVE: u32 = 0x0010;
    /// Confirmation dialog
    pub const CONFIRM_HOTKEY: u32 = 0x0008;
    /// Hotkey sound
    pub const HOTKEY_SOUND: u32 = 0x0020;
    /// Indicator
    pub const INDICATOR: u32 = 0x0040;
    /// Modifiers enabled
    pub const MODIFIERS: u32 = 0x0100;
    /// Replace numbers
    pub const REPLACE_NUMBERS: u32 = 0x0200;
    /// Left button selected
    pub const LEFT_BUTTON_SEL: u32 = 0x1000;
    /// Right button selected
    pub const RIGHT_BUTTON_SEL: u32 = 0x2000;
    /// Left button down
    pub const LEFT_BUTTON_DOWN: u32 = 0x4000;
    /// Right button down
    pub const RIGHT_BUTTON_DOWN: u32 = 0x8000;
    /// MouseKeys on
    pub const ON: u32 = 0x0001;
}

/// SoundSentry flags
pub mod sound_sentry_flags {
    /// SoundSentry available
    pub const AVAILABLE: u32 = 0x0002;
    /// Indicator
    pub const INDICATOR: u32 = 0x0040;
    /// SoundSentry on
    pub const ON: u32 = 0x0001;
}

/// SoundSentry visual signal types
pub mod sound_sentry_signal {
    /// No visual signal
    pub const NONE: u32 = 0;
    /// Flash window title
    pub const TITLE: u32 = 1;
    /// Flash window
    pub const WINDOW: u32 = 2;
    /// Flash display
    pub const DISPLAY: u32 = 3;
}

/// High contrast flags
pub mod high_contrast_flags {
    /// High contrast available
    pub const AVAILABLE: u32 = 0x0002;
    /// Hotkey active
    pub const HOTKEY_ACTIVE: u32 = 0x0004;
    /// Confirmation
    pub const CONFIRM_HOTKEY: u32 = 0x0008;
    /// Hotkey sound
    pub const HOTKEY_SOUND: u32 = 0x0010;
    /// Indicator
    pub const INDICATOR: u32 = 0x0020;
    /// High contrast on
    pub const ON: u32 = 0x0001;
}

/// SerialKeys flags
pub mod serial_keys_flags {
    /// SerialKeys available
    pub const AVAILABLE: u32 = 0x0002;
    /// Indicator
    pub const INDICATOR: u32 = 0x0040;
    /// SerialKeys on
    pub const ON: u32 = 0x0001;
}

/// Maximum high contrast scheme name length
const MAX_SCHEME_NAME: usize = 256;

/// Maximum serial port name length
const MAX_PORT_NAME: usize = 32;

// ============================================================================
// Types
// ============================================================================

/// StickyKeys settings
#[derive(Clone, Copy)]
pub struct StickyKeysSettings {
    /// Size of structure
    pub size: u32,
    /// Flags (sticky_keys_flags)
    pub flags: u32,
}

impl StickyKeysSettings {
    pub const fn new() -> Self {
        Self {
            size: 8,
            flags: sticky_keys_flags::AVAILABLE | sticky_keys_flags::HOTKEY_ACTIVE |
                   sticky_keys_flags::AUDIBLE_FEEDBACK | sticky_keys_flags::TWO_KEYS_OFF,
        }
    }
}

/// FilterKeys settings
#[derive(Clone, Copy)]
pub struct FilterKeysSettings {
    /// Size of structure
    pub size: u32,
    /// Flags (filter_keys_flags)
    pub flags: u32,
    /// Wait milliseconds before key accepted
    pub wait_msec: u32,
    /// Delay milliseconds before repeat
    pub delay_msec: u32,
    /// Repeat rate milliseconds
    pub repeat_msec: u32,
    /// Bounce milliseconds (key debounce)
    pub bounce_msec: u32,
}

impl FilterKeysSettings {
    pub const fn new() -> Self {
        Self {
            size: 24,
            flags: filter_keys_flags::AVAILABLE | filter_keys_flags::HOTKEY_ACTIVE,
            wait_msec: 0,
            delay_msec: 1000,
            repeat_msec: 500,
            bounce_msec: 0,
        }
    }
}

/// ToggleKeys settings
#[derive(Clone, Copy)]
pub struct ToggleKeysSettings {
    /// Size of structure
    pub size: u32,
    /// Flags (toggle_keys_flags)
    pub flags: u32,
}

impl ToggleKeysSettings {
    pub const fn new() -> Self {
        Self {
            size: 8,
            flags: toggle_keys_flags::AVAILABLE | toggle_keys_flags::HOTKEY_ACTIVE,
        }
    }
}

/// MouseKeys settings
#[derive(Clone, Copy)]
pub struct MouseKeysSettings {
    /// Size of structure
    pub size: u32,
    /// Flags (mouse_keys_flags)
    pub flags: u32,
    /// Maximum speed (1-100)
    pub max_speed: u32,
    /// Time to reach max speed (1-10000 ms)
    pub time_to_max_speed: u32,
    /// Ctrl multiplier (1-1000%)
    pub ctrl_speed: u32,
}

impl MouseKeysSettings {
    pub const fn new() -> Self {
        Self {
            size: 20,
            flags: mouse_keys_flags::AVAILABLE | mouse_keys_flags::HOTKEY_ACTIVE,
            max_speed: 40,
            time_to_max_speed: 3000,
            ctrl_speed: 100,
        }
    }
}

/// SoundSentry settings
#[derive(Clone, Copy)]
pub struct SoundSentrySettings {
    /// Size of structure
    pub size: u32,
    /// Flags (sound_sentry_flags)
    pub flags: u32,
    /// Text effect when fullscreen text app is active
    pub text_effect: u32,
    /// Graphics effect (windowed mode)
    pub graphics_effect: u32,
    /// Windows effect
    pub windows_effect: u32,
}

impl SoundSentrySettings {
    pub const fn new() -> Self {
        Self {
            size: 20,
            flags: sound_sentry_flags::AVAILABLE,
            text_effect: sound_sentry_signal::NONE,
            graphics_effect: sound_sentry_signal::NONE,
            windows_effect: sound_sentry_signal::DISPLAY,
        }
    }
}

/// AccessTimeout settings (turn off accessibility after idle)
#[derive(Clone, Copy)]
pub struct AccessTimeoutSettings {
    /// Size of structure
    pub size: u32,
    /// Flags
    pub flags: u32,
    /// Timeout milliseconds
    pub timeout_msec: u32,
}

impl AccessTimeoutSettings {
    pub const fn new() -> Self {
        Self {
            size: 12,
            flags: 0x0002, // AVAILABLE
            timeout_msec: 5 * 60 * 1000, // 5 minutes
        }
    }
}

/// High contrast settings
#[derive(Clone, Copy)]
pub struct HighContrastSettings {
    /// Size of structure
    pub size: u32,
    /// Flags (high_contrast_flags)
    pub flags: u32,
    /// Scheme name
    pub scheme_name: [u8; MAX_SCHEME_NAME],
    /// Scheme name length
    pub scheme_name_len: u16,
}

impl HighContrastSettings {
    pub const fn new() -> Self {
        Self {
            size: 264,
            flags: high_contrast_flags::AVAILABLE | high_contrast_flags::HOTKEY_ACTIVE,
            scheme_name: [0; MAX_SCHEME_NAME],
            scheme_name_len: 0,
        }
    }
}

/// SerialKeys settings (accessibility serial input device)
#[derive(Clone, Copy)]
pub struct SerialKeysSettings {
    /// Size of structure
    pub size: u32,
    /// Flags (serial_keys_flags)
    pub flags: u32,
    /// Active port name (COM1, COM2, etc.)
    pub port_name: [u8; MAX_PORT_NAME],
    /// Port name length
    pub port_name_len: u8,
    /// Baud rate
    pub baud_rate: u32,
    /// Port state
    pub port_state: u32,
    /// Active port number (0 = none)
    pub active_port: u32,
}

impl SerialKeysSettings {
    pub const fn new() -> Self {
        Self {
            size: 52,
            flags: serial_keys_flags::AVAILABLE,
            port_name: [0; MAX_PORT_NAME],
            port_name_len: 0,
            baud_rate: 300,
            port_state: 0,
            active_port: 0,
        }
    }
}

/// Complete accessibility settings state
pub struct AccessibilitySettings {
    /// StickyKeys
    pub sticky_keys: StickyKeysSettings,
    /// FilterKeys
    pub filter_keys: FilterKeysSettings,
    /// ToggleKeys
    pub toggle_keys: ToggleKeysSettings,
    /// MouseKeys
    pub mouse_keys: MouseKeysSettings,
    /// SoundSentry
    pub sound_sentry: SoundSentrySettings,
    /// ShowSounds (visual caption for sounds)
    pub show_sounds: bool,
    /// AccessTimeout
    pub access_timeout: AccessTimeoutSettings,
    /// High contrast
    pub high_contrast: HighContrastSettings,
    /// SerialKeys
    pub serial_keys: SerialKeysSettings,
    /// Screen reader running
    pub screen_reader: bool,
    /// Keyboard preference (keyboard over mouse)
    pub keyboard_pref: bool,
    /// Cursor blink rate (0 = no blink)
    pub cursor_blink_rate: u32,
    /// Cursor width
    pub cursor_width: u32,
    /// Focus border width
    pub focus_border_width: u32,
    /// Focus border height
    pub focus_border_height: u32,
}

impl AccessibilitySettings {
    pub const fn new() -> Self {
        Self {
            sticky_keys: StickyKeysSettings::new(),
            filter_keys: FilterKeysSettings::new(),
            toggle_keys: ToggleKeysSettings::new(),
            mouse_keys: MouseKeysSettings::new(),
            sound_sentry: SoundSentrySettings::new(),
            show_sounds: false,
            access_timeout: AccessTimeoutSettings::new(),
            high_contrast: HighContrastSettings::new(),
            serial_keys: SerialKeysSettings::new(),
            screen_reader: false,
            keyboard_pref: false,
            cursor_blink_rate: 530,
            cursor_width: 1,
            focus_border_width: 1,
            focus_border_height: 1,
        }
    }
}

/// Accessibility dialog state
struct AccessibilityDialog {
    /// Parent window
    parent: HWND,
    /// Current page
    current_page: u32,
    /// Settings modified
    modified: bool,
}

impl AccessibilityDialog {
    const fn new() -> Self {
        Self {
            parent: UserHandle::NULL,
            current_page: 0,
            modified: false,
        }
    }
}

// ============================================================================
// Static State
// ============================================================================

/// Module initialized
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Global accessibility settings
static SETTINGS: SpinLock<AccessibilitySettings> =
    SpinLock::new(AccessibilitySettings::new());

/// Active dialog
static DIALOG: SpinLock<AccessibilityDialog> =
    SpinLock::new(AccessibilityDialog::new());

/// StickyKeys currently latched modifier
static STICKY_LATCHED: AtomicU32 = AtomicU32::new(0);

/// StickyKeys currently locked modifier
static STICKY_LOCKED: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize accessibility settings
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[ACCESS] Accessibility options initialized");
}

// ============================================================================
// StickyKeys
// ============================================================================

/// Get StickyKeys settings
pub fn get_sticky_keys(settings: &mut StickyKeysSettings) {
    *settings = SETTINGS.lock().sticky_keys;
}

/// Set StickyKeys settings
pub fn set_sticky_keys(settings: &StickyKeysSettings) {
    SETTINGS.lock().sticky_keys = *settings;
}

/// Check if StickyKeys is enabled
pub fn is_sticky_keys_on() -> bool {
    SETTINGS.lock().sticky_keys.flags & sticky_keys_flags::ON != 0
}

/// Process key for StickyKeys (returns true if key was consumed)
pub fn sticky_keys_process(vk: u32, key_down: bool) -> bool {
    let settings = SETTINGS.lock();

    if settings.sticky_keys.flags & sticky_keys_flags::ON == 0 {
        return false;
    }

    // Check if this is a modifier key
    let modifier_bit = match vk {
        0x10 => 0x01, // VK_SHIFT
        0x11 => 0x02, // VK_CONTROL
        0x12 => 0x04, // VK_MENU (Alt)
        0x5B | 0x5C => 0x08, // VK_LWIN/VK_RWIN
        _ => 0,
    };

    if modifier_bit == 0 {
        // Non-modifier key pressed - release all latched modifiers
        if !key_down {
            let latched = STICKY_LATCHED.swap(0, Ordering::SeqCst);
            if latched != 0 {
                // Clear latched state after use
            }
        }
        return false;
    }

    if key_down {
        let latched = STICKY_LATCHED.load(Ordering::Acquire);
        let locked = STICKY_LOCKED.load(Ordering::Acquire);

        if locked & modifier_bit != 0 {
            // Already locked - unlock
            STICKY_LOCKED.fetch_and(!modifier_bit, Ordering::SeqCst);
        } else if latched & modifier_bit != 0 {
            // Already latched - lock it
            STICKY_LATCHED.fetch_and(!modifier_bit, Ordering::SeqCst);
            STICKY_LOCKED.fetch_or(modifier_bit, Ordering::SeqCst);
        } else {
            // First press - latch
            STICKY_LATCHED.fetch_or(modifier_bit, Ordering::SeqCst);
        }

        // Play audio feedback if enabled
        if settings.sticky_keys.flags & sticky_keys_flags::AUDIBLE_FEEDBACK != 0 {
            // Would play feedback sound
        }
    }

    true
}

/// Get current StickyKeys modifier state
pub fn sticky_keys_get_modifiers() -> u32 {
    STICKY_LATCHED.load(Ordering::Acquire) | STICKY_LOCKED.load(Ordering::Acquire)
}

// ============================================================================
// FilterKeys
// ============================================================================

/// Get FilterKeys settings
pub fn get_filter_keys(settings: &mut FilterKeysSettings) {
    *settings = SETTINGS.lock().filter_keys;
}

/// Set FilterKeys settings
pub fn set_filter_keys(settings: &FilterKeysSettings) {
    SETTINGS.lock().filter_keys = *settings;
}

/// Check if FilterKeys is enabled
pub fn is_filter_keys_on() -> bool {
    SETTINGS.lock().filter_keys.flags & filter_keys_flags::ON != 0
}

// ============================================================================
// ToggleKeys
// ============================================================================

/// Get ToggleKeys settings
pub fn get_toggle_keys(settings: &mut ToggleKeysSettings) {
    *settings = SETTINGS.lock().toggle_keys;
}

/// Set ToggleKeys settings
pub fn set_toggle_keys(settings: &ToggleKeysSettings) {
    SETTINGS.lock().toggle_keys = *settings;
}

/// Check if ToggleKeys is enabled
pub fn is_toggle_keys_on() -> bool {
    SETTINGS.lock().toggle_keys.flags & toggle_keys_flags::ON != 0
}

/// Play toggle sound for CapsLock/NumLock/ScrollLock
pub fn toggle_keys_play(on: bool) {
    if !is_toggle_keys_on() {
        return;
    }

    // Would play high tone for on, low tone for off
    let _freq = if on { 1000 } else { 500 };
}

// ============================================================================
// MouseKeys
// ============================================================================

/// Get MouseKeys settings
pub fn get_mouse_keys(settings: &mut MouseKeysSettings) {
    *settings = SETTINGS.lock().mouse_keys;
}

/// Set MouseKeys settings
pub fn set_mouse_keys(settings: &MouseKeysSettings) {
    SETTINGS.lock().mouse_keys = *settings;
}

/// Check if MouseKeys is enabled
pub fn is_mouse_keys_on() -> bool {
    SETTINGS.lock().mouse_keys.flags & mouse_keys_flags::ON != 0
}

/// Process numpad key for MouseKeys (returns mouse movement)
pub fn mouse_keys_process(vk: u32, key_down: bool) -> Option<(i32, i32, u32)> {
    if !is_mouse_keys_on() || !key_down {
        return None;
    }

    let settings = SETTINGS.lock();
    let max_speed = settings.mouse_keys.max_speed as i32;
    drop(settings);

    // Return (dx, dy, button_action)
    // button_action: 0=none, 1=left_down, 2=left_up, 3=left_click, 4=right_down, etc.
    match vk {
        0x24 => Some((-max_speed, -max_speed, 0)), // VK_HOME - up-left
        0x26 => Some((0, -max_speed, 0)),          // VK_UP
        0x21 => Some((max_speed, -max_speed, 0)),  // VK_PRIOR - up-right
        0x25 => Some((-max_speed, 0, 0)),          // VK_LEFT
        0x0C => Some((0, 0, 0)),                   // VK_CLEAR (numpad 5) - no move
        0x27 => Some((max_speed, 0, 0)),           // VK_RIGHT
        0x23 => Some((-max_speed, max_speed, 0)),  // VK_END - down-left
        0x28 => Some((0, max_speed, 0)),           // VK_DOWN
        0x22 => Some((max_speed, max_speed, 0)),   // VK_NEXT - down-right
        0x2D => Some((0, 0, 3)),                   // VK_INSERT - click
        0x2E => Some((0, 0, 1)),                   // VK_DELETE - button down
        _ => None,
    }
}

// ============================================================================
// SoundSentry
// ============================================================================

/// Get SoundSentry settings
pub fn get_sound_sentry(settings: &mut SoundSentrySettings) {
    *settings = SETTINGS.lock().sound_sentry;
}

/// Set SoundSentry settings
pub fn set_sound_sentry(settings: &SoundSentrySettings) {
    SETTINGS.lock().sound_sentry = *settings;
}

/// Check if SoundSentry is enabled
pub fn is_sound_sentry_on() -> bool {
    SETTINGS.lock().sound_sentry.flags & sound_sentry_flags::ON != 0
}

/// Trigger SoundSentry visual signal
pub fn sound_sentry_trigger() {
    if !is_sound_sentry_on() {
        return;
    }

    let settings = SETTINGS.lock();
    let effect = settings.sound_sentry.windows_effect;
    drop(settings);

    match effect {
        sound_sentry_signal::TITLE => {
            // Flash active window title bar
        }
        sound_sentry_signal::WINDOW => {
            // Flash active window
        }
        sound_sentry_signal::DISPLAY => {
            // Flash entire screen
        }
        _ => {}
    }
}

// ============================================================================
// ShowSounds
// ============================================================================

/// Get ShowSounds setting
pub fn get_show_sounds() -> bool {
    SETTINGS.lock().show_sounds
}

/// Set ShowSounds setting
pub fn set_show_sounds(show: bool) {
    SETTINGS.lock().show_sounds = show;
}

// ============================================================================
// High Contrast
// ============================================================================

/// Get high contrast settings
pub fn get_high_contrast(settings: &mut HighContrastSettings) {
    *settings = SETTINGS.lock().high_contrast;
}

/// Set high contrast settings
pub fn set_high_contrast(settings: &HighContrastSettings) {
    let mut state = SETTINGS.lock();

    let was_on = state.high_contrast.flags & high_contrast_flags::ON != 0;
    let is_on = settings.flags & high_contrast_flags::ON != 0;

    state.high_contrast = *settings;

    if was_on != is_on {
        // Apply or remove high contrast theme
        if is_on {
            apply_high_contrast_theme(settings);
        } else {
            remove_high_contrast_theme();
        }
    }
}

/// Check if high contrast is on
pub fn is_high_contrast_on() -> bool {
    SETTINGS.lock().high_contrast.flags & high_contrast_flags::ON != 0
}

/// Apply high contrast theme
fn apply_high_contrast_theme(_settings: &HighContrastSettings) {
    // Would apply the high contrast color scheme
}

/// Remove high contrast theme
fn remove_high_contrast_theme() {
    // Would restore normal color scheme
}

// ============================================================================
// AccessTimeout
// ============================================================================

/// Get access timeout settings
pub fn get_access_timeout(settings: &mut AccessTimeoutSettings) {
    *settings = SETTINGS.lock().access_timeout;
}

/// Set access timeout settings
pub fn set_access_timeout(settings: &AccessTimeoutSettings) {
    SETTINGS.lock().access_timeout = *settings;
}

/// Check and handle accessibility timeout
pub fn check_timeout(_idle_ms: u32) {
    let settings = SETTINGS.lock();

    if settings.access_timeout.flags & 0x0001 == 0 {
        // Timeout not enabled
        return;
    }

    // Would check if idle time exceeds timeout and disable features
}

// ============================================================================
// SerialKeys
// ============================================================================

/// Get SerialKeys settings
pub fn get_serial_keys(settings: &mut SerialKeysSettings) {
    *settings = SETTINGS.lock().serial_keys;
}

/// Set SerialKeys settings
pub fn set_serial_keys(settings: &SerialKeysSettings) {
    SETTINGS.lock().serial_keys = *settings;
}

/// Check if SerialKeys is enabled
pub fn is_serial_keys_on() -> bool {
    SETTINGS.lock().serial_keys.flags & serial_keys_flags::ON != 0
}

// ============================================================================
// Screen Reader
// ============================================================================

/// Get screen reader active state
pub fn get_screen_reader() -> bool {
    SETTINGS.lock().screen_reader
}

/// Set screen reader active state
pub fn set_screen_reader(active: bool) {
    SETTINGS.lock().screen_reader = active;
}

// ============================================================================
// Keyboard Preference
// ============================================================================

/// Get keyboard preference (prefer keyboard over mouse)
pub fn get_keyboard_pref() -> bool {
    SETTINGS.lock().keyboard_pref
}

/// Set keyboard preference
pub fn set_keyboard_pref(pref: bool) {
    SETTINGS.lock().keyboard_pref = pref;
}

// ============================================================================
// Visual Settings
// ============================================================================

/// Get cursor blink rate (0 = no blink)
pub fn get_cursor_blink_rate() -> u32 {
    SETTINGS.lock().cursor_blink_rate
}

/// Set cursor blink rate
pub fn set_cursor_blink_rate(rate: u32) {
    SETTINGS.lock().cursor_blink_rate = rate;
}

/// Get cursor width
pub fn get_cursor_width() -> u32 {
    SETTINGS.lock().cursor_width
}

/// Set cursor width
pub fn set_cursor_width(width: u32) {
    let width = width.clamp(1, 20);
    SETTINGS.lock().cursor_width = width;
}

/// Get focus border dimensions
pub fn get_focus_border() -> (u32, u32) {
    let settings = SETTINGS.lock();
    (settings.focus_border_width, settings.focus_border_height)
}

/// Set focus border dimensions
pub fn set_focus_border(width: u32, height: u32) {
    let mut settings = SETTINGS.lock();
    settings.focus_border_width = width.clamp(1, 10);
    settings.focus_border_height = height.clamp(1, 10);
}

// ============================================================================
// Dialog API
// ============================================================================

/// Show accessibility options dialog
pub fn show_accessibility_options(parent: HWND) -> bool {
    let mut dialog = DIALOG.lock();

    dialog.parent = parent;
    dialog.current_page = 0;
    dialog.modified = false;

    // Would create property sheet with tabs for:
    // - Keyboard (StickyKeys, FilterKeys, ToggleKeys)
    // - Sound (SoundSentry, ShowSounds)
    // - Display (High Contrast, cursor settings)
    // - Mouse (MouseKeys)
    // - General (timeout, SerialKeys)

    true
}

// ============================================================================
// Hotkey Processing
// ============================================================================

/// Check for accessibility hotkeys
/// Returns true if a hotkey was processed
pub fn check_hotkeys(vk: u32, shift: bool, ctrl: bool, alt: bool) -> bool {
    // StickyKeys: Press Shift 5 times
    // FilterKeys: Hold Right Shift for 8 seconds
    // ToggleKeys: Hold NumLock for 5 seconds
    // MouseKeys: Left Alt + Left Shift + NumLock
    // High Contrast: Left Alt + Left Shift + PrtScn

    if alt && shift && !ctrl {
        // Left Alt + Left Shift + NumLock = MouseKeys
        if vk == 0x90 {
            toggle_mouse_keys();
            return true;
        }
        // Left Alt + Left Shift + PrtScn = High Contrast
        if vk == 0x2C {
            toggle_high_contrast();
            return true;
        }
    }

    false
}

/// Toggle MouseKeys on/off
fn toggle_mouse_keys() {
    let mut settings = SETTINGS.lock();
    settings.mouse_keys.flags ^= mouse_keys_flags::ON;
}

/// Toggle High Contrast on/off
fn toggle_high_contrast() {
    let mut settings = SETTINGS.lock();
    settings.high_contrast.flags ^= high_contrast_flags::ON;

    let is_on = settings.high_contrast.flags & high_contrast_flags::ON != 0;
    if is_on {
        apply_high_contrast_theme(&settings.high_contrast);
    } else {
        remove_high_contrast_theme();
    }
}
