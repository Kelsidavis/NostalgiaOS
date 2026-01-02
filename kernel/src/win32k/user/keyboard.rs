//! Keyboard Settings Dialog
//!
//! Provides keyboard properties and input settings following
//! Windows main.cpl keyboard patterns.
//!
//! # References
//!
//! - Windows Server 2003 Keyboard control panel
//! - SystemParametersInfo keyboard settings

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle};

// ============================================================================
// Constants
// ============================================================================

/// Maximum name length
pub const MAX_NAME: usize = 64;

/// Keyboard layout ID type
pub type HKL = u32;

/// Default keyboard layouts
pub mod keyboard_layout {
    /// US English
    pub const US: u32 = 0x04090409;
    /// UK English
    pub const UK: u32 = 0x08090809;
    /// German
    pub const DE: u32 = 0x04070407;
    /// French
    pub const FR: u32 = 0x040C040C;
    /// Spanish
    pub const ES: u32 = 0x040A040A;
    /// Italian
    pub const IT: u32 = 0x04100410;
    /// Portuguese (Brazil)
    pub const PT_BR: u32 = 0x04160416;
    /// Russian
    pub const RU: u32 = 0x04190419;
    /// Japanese
    pub const JP: u32 = 0x04110411;
    /// Chinese (Simplified)
    pub const ZH: u32 = 0x08040804;
    /// Korean
    pub const KO: u32 = 0x04120412;
}

/// Keyboard repeat delay (0-3, 0=long, 3=short)
pub const REPEAT_DELAY_MIN: u32 = 0;
pub const REPEAT_DELAY_MAX: u32 = 3;

/// Keyboard repeat rate (0-31, 0=slow, 31=fast)
pub const REPEAT_RATE_MIN: u32 = 0;
pub const REPEAT_RATE_MAX: u32 = 31;

// ============================================================================
// Structures
// ============================================================================

/// Keyboard settings
#[derive(Clone, Copy)]
pub struct KeyboardSettings {
    /// Repeat delay (0-3)
    pub repeat_delay: u8,
    /// Repeat rate (0-31)
    pub repeat_rate: u8,
    /// Cursor blink rate in ms
    pub cursor_blink_rate: u16,
}

impl KeyboardSettings {
    pub const fn new() -> Self {
        Self {
            repeat_delay: 1,
            repeat_rate: 15,
            cursor_blink_rate: 530,
        }
    }
}

/// Keyboard layout entry
#[derive(Clone, Copy)]
pub struct KeyboardLayoutEntry {
    /// Entry is valid
    pub valid: bool,
    /// Layout ID (HKL)
    pub hkl: HKL,
    /// Display name length
    pub name_len: u8,
    /// Display name
    pub name: [u8; MAX_NAME],
    /// Layout name length
    pub layout_name_len: u8,
    /// Layout name (e.g., "US", "QWERTZ")
    pub layout_name: [u8; 32],
    /// Is IME
    pub is_ime: bool,
}

impl KeyboardLayoutEntry {
    const fn new() -> Self {
        Self {
            valid: false,
            hkl: 0,
            name_len: 0,
            name: [0; MAX_NAME],
            layout_name_len: 0,
            layout_name: [0; 32],
            is_ime: false,
        }
    }
}

/// Installed input language
#[derive(Clone, Copy)]
pub struct InputLanguage {
    /// Entry is valid
    pub valid: bool,
    /// Language ID
    pub lang_id: u16,
    /// Name length
    pub name_len: u8,
    /// Language name
    pub name: [u8; MAX_NAME],
    /// Default layout
    pub default_layout: HKL,
    /// Number of layouts
    pub layout_count: u8,
}

impl InputLanguage {
    const fn new() -> Self {
        Self {
            valid: false,
            lang_id: 0,
            name_len: 0,
            name: [0; MAX_NAME],
            default_layout: 0,
            layout_count: 0,
        }
    }
}

/// Keyboard dialog state
#[derive(Clone, Copy)]
pub struct KeyboardDialogState {
    /// Dialog is active
    pub active: bool,
    /// Dialog handle
    pub hwnd: HWND,
    /// Current tab
    pub current_tab: u8,
    /// Pending settings
    pub pending_settings: KeyboardSettings,
    /// Changes pending
    pub changes_pending: bool,
}

impl KeyboardDialogState {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            current_tab: 0,
            pending_settings: KeyboardSettings::new(),
            changes_pending: false,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static KEYBOARD_INITIALIZED: AtomicBool = AtomicBool::new(false);
static KEYBOARD_LOCK: SpinLock<()> = SpinLock::new(());
static CURRENT_LAYOUT: AtomicU32 = AtomicU32::new(keyboard_layout::US);

static SETTINGS: SpinLock<KeyboardSettings> = SpinLock::new(KeyboardSettings::new());

// Keyboard layouts
const MAX_LAYOUTS: usize = 16;
static LAYOUTS: SpinLock<[KeyboardLayoutEntry; MAX_LAYOUTS]> =
    SpinLock::new([const { KeyboardLayoutEntry::new() }; MAX_LAYOUTS]);

// Input languages
const MAX_LANGUAGES: usize = 8;
static LANGUAGES: SpinLock<[InputLanguage; MAX_LANGUAGES]> =
    SpinLock::new([const { InputLanguage::new() }; MAX_LANGUAGES]);

// Dialog state
static DIALOG_STATE: SpinLock<KeyboardDialogState> = SpinLock::new(KeyboardDialogState::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize keyboard settings subsystem
pub fn init() {
    let _guard = KEYBOARD_LOCK.lock();

    if KEYBOARD_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[KEYBOARD] Initializing keyboard settings...");

    // Initialize keyboard layouts
    init_layouts();

    // Initialize input languages
    init_languages();

    KEYBOARD_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[KEYBOARD] Keyboard settings initialized");
}

/// Initialize keyboard layouts
fn init_layouts() {
    let layout_data: &[(HKL, &[u8], &[u8], bool)] = &[
        (keyboard_layout::US, b"US", b"United States", false),
        (keyboard_layout::UK, b"UK", b"United Kingdom", false),
        (keyboard_layout::DE, b"DE", b"German", false),
        (keyboard_layout::FR, b"FR", b"French", false),
        (keyboard_layout::ES, b"ES", b"Spanish", false),
        (keyboard_layout::IT, b"IT", b"Italian", false),
        (keyboard_layout::PT_BR, b"BR", b"Portuguese (Brazilian ABNT)", false),
        (keyboard_layout::RU, b"RU", b"Russian", false),
        (keyboard_layout::JP, b"JP", b"Japanese", true),
        (keyboard_layout::ZH, b"CH", b"Chinese (Simplified)", true),
        (keyboard_layout::KO, b"KO", b"Korean", true),
    ];

    let mut layouts = LAYOUTS.lock();

    for (i, (hkl, layout_name, name, is_ime)) in layout_data.iter().enumerate() {
        if i >= MAX_LAYOUTS {
            break;
        }

        let layout = &mut layouts[i];
        layout.valid = true;
        layout.hkl = *hkl;
        layout.is_ime = *is_ime;

        layout.layout_name_len = layout_name.len().min(32) as u8;
        layout.layout_name[..layout.layout_name_len as usize]
            .copy_from_slice(&layout_name[..layout.layout_name_len as usize]);

        layout.name_len = name.len().min(MAX_NAME) as u8;
        layout.name[..layout.name_len as usize]
            .copy_from_slice(&name[..layout.name_len as usize]);
    }
}

/// Initialize input languages
fn init_languages() {
    let lang_data: &[(u16, &[u8], HKL)] = &[
        (0x0409, b"English (United States)", keyboard_layout::US),
        (0x0809, b"English (United Kingdom)", keyboard_layout::UK),
        (0x0407, b"German (Germany)", keyboard_layout::DE),
        (0x040C, b"French (France)", keyboard_layout::FR),
    ];

    let mut languages = LANGUAGES.lock();

    for (i, (lang_id, name, default_layout)) in lang_data.iter().enumerate() {
        if i >= MAX_LANGUAGES {
            break;
        }

        let lang = &mut languages[i];
        lang.valid = true;
        lang.lang_id = *lang_id;
        lang.default_layout = *default_layout;
        lang.layout_count = 1;

        lang.name_len = name.len().min(MAX_NAME) as u8;
        lang.name[..lang.name_len as usize]
            .copy_from_slice(&name[..lang.name_len as usize]);
    }
}

// ============================================================================
// Keyboard Settings API
// ============================================================================

/// Get keyboard settings
pub fn get_keyboard_settings() -> KeyboardSettings {
    *SETTINGS.lock()
}

/// Set keyboard settings
pub fn set_keyboard_settings(settings: &KeyboardSettings) -> bool {
    if settings.repeat_delay > REPEAT_DELAY_MAX as u8 {
        return false;
    }
    if settings.repeat_rate > REPEAT_RATE_MAX as u8 {
        return false;
    }

    let mut s = SETTINGS.lock();
    *s = *settings;
    true
}

/// Get repeat delay
pub fn get_repeat_delay() -> u8 {
    SETTINGS.lock().repeat_delay
}

/// Set repeat delay (0-3)
pub fn set_repeat_delay(delay: u8) -> bool {
    if delay > REPEAT_DELAY_MAX as u8 {
        return false;
    }
    SETTINGS.lock().repeat_delay = delay;
    true
}

/// Get repeat rate
pub fn get_repeat_rate() -> u8 {
    SETTINGS.lock().repeat_rate
}

/// Set repeat rate (0-31)
pub fn set_repeat_rate(rate: u8) -> bool {
    if rate > REPEAT_RATE_MAX as u8 {
        return false;
    }
    SETTINGS.lock().repeat_rate = rate;
    true
}

/// Get cursor blink rate
pub fn get_cursor_blink_rate() -> u16 {
    SETTINGS.lock().cursor_blink_rate
}

/// Set cursor blink rate
pub fn set_cursor_blink_rate(rate: u16) -> bool {
    SETTINGS.lock().cursor_blink_rate = rate;
    true
}

// ============================================================================
// Keyboard Layout API
// ============================================================================

/// Get current keyboard layout
pub fn get_keyboard_layout() -> HKL {
    CURRENT_LAYOUT.load(Ordering::Acquire)
}

/// Set keyboard layout
pub fn set_keyboard_layout(hkl: HKL) -> bool {
    // Validate layout
    let layouts = LAYOUTS.lock();
    let valid = layouts.iter().any(|l| l.valid && l.hkl == hkl);
    drop(layouts);

    if !valid {
        return false;
    }

    CURRENT_LAYOUT.store(hkl, Ordering::Release);
    true
}

/// Get keyboard layout list
pub fn get_keyboard_layout_list() -> ([HKL; MAX_LAYOUTS], usize) {
    let layouts = LAYOUTS.lock();
    let mut list = [0u32; MAX_LAYOUTS];
    let mut count = 0;

    for layout in layouts.iter() {
        if layout.valid {
            list[count] = layout.hkl;
            count += 1;
        }
    }

    (list, count)
}

/// Get keyboard layout name
pub fn get_keyboard_layout_name(hkl: HKL, buffer: &mut [u8]) -> usize {
    let layouts = LAYOUTS.lock();

    for layout in layouts.iter() {
        if layout.valid && layout.hkl == hkl {
            let len = (layout.name_len as usize).min(buffer.len());
            buffer[..len].copy_from_slice(&layout.name[..len]);
            return len;
        }
    }

    0
}

/// Activate keyboard layout
pub fn activate_keyboard_layout(hkl: HKL) -> HKL {
    let prev = get_keyboard_layout();
    if set_keyboard_layout(hkl) {
        prev
    } else {
        0
    }
}

/// Get keyboard layout entry
pub fn get_layout_entry(hkl: HKL) -> Option<KeyboardLayoutEntry> {
    let layouts = LAYOUTS.lock();

    for layout in layouts.iter() {
        if layout.valid && layout.hkl == hkl {
            return Some(*layout);
        }
    }

    None
}

// ============================================================================
// Input Language API
// ============================================================================

/// Get input language count
pub fn get_input_language_count() -> usize {
    let languages = LANGUAGES.lock();
    languages.iter().filter(|l| l.valid).count()
}

/// Get input language by index
pub fn get_input_language(index: usize) -> Option<InputLanguage> {
    let languages = LANGUAGES.lock();

    if index < MAX_LANGUAGES && languages[index].valid {
        Some(languages[index])
    } else {
        None
    }
}

/// Add input language
pub fn add_input_language(lang_id: u16, layout: HKL) -> bool {
    let mut languages = LANGUAGES.lock();

    // Check if already exists
    for lang in languages.iter() {
        if lang.valid && lang.lang_id == lang_id {
            return true; // Already added
        }
    }

    // Find free slot
    for lang in languages.iter_mut() {
        if !lang.valid {
            lang.valid = true;
            lang.lang_id = lang_id;
            lang.default_layout = layout;
            lang.layout_count = 1;
            return true;
        }
    }

    false
}

/// Remove input language
pub fn remove_input_language(lang_id: u16) -> bool {
    let mut languages = LANGUAGES.lock();

    for lang in languages.iter_mut() {
        if lang.valid && lang.lang_id == lang_id {
            lang.valid = false;
            return true;
        }
    }

    false
}

// ============================================================================
// Keyboard Dialog
// ============================================================================

/// Show keyboard properties dialog
pub fn show_keyboard_dialog(hwnd_owner: HWND, tab: u8) -> bool {
    if !KEYBOARD_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = DIALOG_STATE.lock();

    if state.active {
        return false;
    }

    state.current_tab = tab;
    state.pending_settings = get_keyboard_settings();
    state.changes_pending = false;

    let hwnd = create_keyboard_dialog(hwnd_owner);

    if hwnd == UserHandle::NULL {
        return false;
    }

    state.active = true;
    state.hwnd = hwnd;

    drop(state);

    let result = run_keyboard_dialog(hwnd);

    if result {
        apply_keyboard_changes();
    }

    let mut state = DIALOG_STATE.lock();
    state.active = false;
    state.hwnd = UserHandle::NULL;

    result
}

/// Close keyboard dialog
pub fn close_keyboard_dialog() {
    let mut state = DIALOG_STATE.lock();

    if state.active {
        if state.hwnd != UserHandle::NULL {
            super::window::destroy_window(state.hwnd);
        }
        state.active = false;
        state.hwnd = UserHandle::NULL;
    }
}

/// Apply pending changes
fn apply_keyboard_changes() {
    let state = DIALOG_STATE.lock();

    if !state.changes_pending {
        return;
    }

    let settings = state.pending_settings;
    drop(state);

    set_keyboard_settings(&settings);
}

fn create_keyboard_dialog(_owner: HWND) -> HWND { UserHandle::NULL }
fn run_keyboard_dialog(_hwnd: HWND) -> bool { true }

/// Keyboard dialog procedure
pub fn keyboard_dialog_proc(hwnd: HWND, msg: u32, wparam: usize, _lparam: isize) -> isize {
    match msg {
        super::message::WM_COMMAND => handle_keyboard_command(hwnd, wparam as u32),
        super::message::WM_CLOSE => { close_keyboard_dialog(); 0 }
        _ => 0,
    }
}

fn handle_keyboard_command(hwnd: HWND, command: u32) -> isize {
    let id = command as u16;
    match id {
        1 => {
            let state = DIALOG_STATE.lock();
            if state.active && state.hwnd == hwnd {
                drop(state);
                apply_keyboard_changes();
                close_keyboard_dialog();
            }
            0
        }
        2 => { close_keyboard_dialog(); 0 }
        3 => { apply_keyboard_changes(); 0 }
        100 => { // Repeat delay slider
            let mut state = DIALOG_STATE.lock();
            state.pending_settings.repeat_delay = ((command >> 16) & 0x03) as u8;
            state.changes_pending = true;
            0
        }
        101 => { // Repeat rate slider
            let mut state = DIALOG_STATE.lock();
            state.pending_settings.repeat_rate = ((command >> 16) & 0x1F) as u8;
            state.changes_pending = true;
            0
        }
        102 => { // Cursor blink rate slider
            let mut state = DIALOG_STATE.lock();
            state.pending_settings.cursor_blink_rate = (command >> 16) as u16;
            state.changes_pending = true;
            0
        }
        _ => 0,
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Convert repeat delay to milliseconds
pub fn repeat_delay_to_ms(delay: u8) -> u32 {
    match delay {
        0 => 1000, // Long
        1 => 750,
        2 => 500,
        3 => 250,  // Short
        _ => 500,
    }
}

/// Convert repeat rate to characters per second
pub fn repeat_rate_to_cps(rate: u8) -> u32 {
    // 0 = ~2.5 cps, 31 = ~30 cps
    ((rate as u32) + 3) * 30 / 34
}
