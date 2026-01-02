//! Sound Schemes and Events
//!
//! Kernel-mode sound event management following Windows NT patterns.
//! Provides sound scheme management and event-to-sound mapping.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/cpls/main/sounds.c` - Sound control panel
//! - `base/ntos/mm/shutdown.c` - System sound events

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// Constants
// ============================================================================

/// Maximum sound schemes
const MAX_SOUND_SCHEMES: usize = 32;

/// Maximum sound events
const MAX_SOUND_EVENTS: usize = 64;

/// Maximum sound file path length
const MAX_SOUND_PATH: usize = 260;

/// Maximum scheme name length
const MAX_SCHEME_NAME: usize = 128;

/// Maximum event name length
const MAX_EVENT_NAME: usize = 64;

/// Maximum event description length
const MAX_EVENT_DESC: usize = 128;

/// System sound event IDs
pub mod sound_event {
    /// Default beep
    pub const DEFAULT: u32 = 0;
    /// System asterisk (information)
    pub const ASTERISK: u32 = 1;
    /// System exclamation (warning)
    pub const EXCLAMATION: u32 = 2;
    /// System hand (critical stop)
    pub const HAND: u32 = 3;
    /// System question
    pub const QUESTION: u32 = 4;
    /// Windows logon
    pub const LOGON: u32 = 5;
    /// Windows logoff
    pub const LOGOFF: u32 = 6;
    /// Windows startup
    pub const STARTUP: u32 = 7;
    /// Windows exit
    pub const EXIT: u32 = 8;
    /// Open program
    pub const OPEN: u32 = 9;
    /// Close program
    pub const CLOSE: u32 = 10;
    /// Minimize window
    pub const MINIMIZE: u32 = 11;
    /// Maximize window
    pub const MAXIMIZE: u32 = 12;
    /// Restore window
    pub const RESTORE_UP: u32 = 13;
    /// Restore down
    pub const RESTORE_DOWN: u32 = 14;
    /// Menu command
    pub const MENU_COMMAND: u32 = 15;
    /// Menu popup
    pub const MENU_POPUP: u32 = 16;
    /// New mail notification
    pub const NEW_MAIL: u32 = 17;
    /// Empty recycle bin
    pub const EMPTY_RECYCLE_BIN: u32 = 18;
    /// Device connect
    pub const DEVICE_CONNECT: u32 = 19;
    /// Device disconnect
    pub const DEVICE_DISCONNECT: u32 = 20;
    /// Device failed
    pub const DEVICE_FAIL: u32 = 21;
    /// Print complete
    pub const PRINT_COMPLETE: u32 = 22;
    /// Low battery alarm
    pub const LOW_BATTERY: u32 = 23;
    /// Critical battery alarm
    pub const CRITICAL_BATTERY: u32 = 24;
    /// Blocked popup
    pub const BLOCKED_POPUP: u32 = 25;
    /// Balloon tooltip show
    pub const BALLOON: u32 = 26;
    /// Information bar
    pub const INFO_BAR: u32 = 27;
    /// Navigate start
    pub const NAV_START: u32 = 28;
    /// Navigate end
    pub const NAV_END: u32 = 29;
    /// Feed discovered
    pub const FEED_DISCOVERED: u32 = 30;
    /// Click
    pub const CLICK: u32 = 31;
}

/// Sound event application IDs
pub mod sound_app {
    /// Windows system sounds
    pub const SYSTEM: u32 = 0;
    /// Windows Explorer
    pub const EXPLORER: u32 = 1;
    /// Speech recognition
    pub const SPEECH: u32 = 2;
    /// Windows Media Player
    pub const MEDIA_PLAYER: u32 = 3;
}

/// Sound flags
pub mod sound_flags {
    /// Play asynchronously
    pub const ASYNC: u32 = 0x0001;
    /// Don't stop current sound
    pub const NOSTOP: u32 = 0x0010;
    /// File name is a resource ID
    pub const RESOURCE: u32 = 0x00040000;
    /// Loop until next PlaySound
    pub const LOOP: u32 = 0x0008;
    /// Use system default if file not found
    pub const SYSTEM_DEFAULT: u32 = 0x0004;
    /// Purge current sound
    pub const PURGE: u32 = 0x0040;
    /// No default sound
    pub const NODEFAULT: u32 = 0x0002;
    /// Wait for sound to complete
    pub const SYNC: u32 = 0x0000;
}

// ============================================================================
// Types
// ============================================================================

/// Sound event definition
#[derive(Clone, Copy)]
pub struct SoundEvent {
    /// Event ID
    pub event_id: u32,
    /// Application ID
    pub app_id: u32,
    /// Event name (registry key)
    pub name: [u8; MAX_EVENT_NAME],
    /// Name length
    pub name_len: u8,
    /// Display description
    pub description: [u8; MAX_EVENT_DESC],
    /// Description length
    pub desc_len: u8,
    /// Event is active
    pub active: bool,
}

impl SoundEvent {
    pub const fn new() -> Self {
        Self {
            event_id: 0,
            app_id: 0,
            name: [0; MAX_EVENT_NAME],
            name_len: 0,
            description: [0; MAX_EVENT_DESC],
            desc_len: 0,
            active: true,
        }
    }
}

/// Sound file mapping for an event in a scheme
#[derive(Clone, Copy)]
pub struct SoundMapping {
    /// Event ID
    pub event_id: u32,
    /// Application ID
    pub app_id: u32,
    /// Sound file path
    pub file_path: [u8; MAX_SOUND_PATH],
    /// Path length
    pub path_len: u16,
}

impl SoundMapping {
    pub const fn new() -> Self {
        Self {
            event_id: 0,
            app_id: 0,
            file_path: [0; MAX_SOUND_PATH],
            path_len: 0,
        }
    }
}

/// Sound scheme
#[derive(Clone, Copy)]
pub struct SoundScheme {
    /// Scheme name
    pub name: [u8; MAX_SCHEME_NAME],
    /// Name length
    pub name_len: u8,
    /// Display name
    pub display_name: [u8; MAX_SCHEME_NAME],
    /// Display name length
    pub display_len: u8,
    /// Is system scheme
    pub is_system: bool,
    /// Is active scheme
    pub is_active: bool,
    /// Sound mappings
    pub mappings: [SoundMapping; MAX_SOUND_EVENTS],
    /// Mapping count
    pub mapping_count: u16,
}

impl SoundScheme {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_SCHEME_NAME],
            name_len: 0,
            display_name: [0; MAX_SCHEME_NAME],
            display_len: 0,
            is_system: false,
            is_active: false,
            mappings: [const { SoundMapping::new() }; MAX_SOUND_EVENTS],
            mapping_count: 0,
        }
    }
}

/// Sound settings
pub struct SoundSettings {
    /// System sounds enabled
    pub sounds_enabled: bool,
    /// Play Windows startup sound
    pub play_startup: bool,
    /// Current scheme index
    pub current_scheme: usize,
    /// Master volume (0-100)
    pub master_volume: u32,
    /// Wave volume (0-100)
    pub wave_volume: u32,
    /// System beep enabled
    pub beep_enabled: bool,
}

impl SoundSettings {
    pub const fn new() -> Self {
        Self {
            sounds_enabled: true,
            play_startup: true,
            current_scheme: 0,
            master_volume: 100,
            wave_volume: 100,
            beep_enabled: true,
        }
    }
}

/// Sounds dialog state
struct SoundsDialog {
    /// Parent window
    parent: HWND,
    /// Modified flag
    modified: bool,
    /// Currently selected event
    selected_event: u32,
    /// Preview playing
    preview_playing: bool,
}

impl SoundsDialog {
    const fn new() -> Self {
        Self {
            parent: UserHandle::NULL,
            modified: false,
            selected_event: 0,
            preview_playing: false,
        }
    }
}

// ============================================================================
// Static State
// ============================================================================

/// Module initialized
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Global settings
static SETTINGS: SpinLock<SoundSettings> = SpinLock::new(SoundSettings::new());

/// Sound events
static EVENTS: SpinLock<[SoundEvent; MAX_SOUND_EVENTS]> =
    SpinLock::new([const { SoundEvent::new() }; MAX_SOUND_EVENTS]);

/// Event count
static EVENT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Sound schemes
static SCHEMES: SpinLock<[SoundScheme; MAX_SOUND_SCHEMES]> =
    SpinLock::new([const { SoundScheme::new() }; MAX_SOUND_SCHEMES]);

/// Scheme count
static SCHEME_COUNT: AtomicU32 = AtomicU32::new(0);

/// Dialog state
static DIALOG: SpinLock<SoundsDialog> = SpinLock::new(SoundsDialog::new());

/// Currently playing sound
static PLAYING_SOUND: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize sound schemes
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Initialize system sound events
    init_system_events();

    // Initialize default sound schemes
    init_default_schemes();

    crate::serial_println!("[SOUNDS] Sound schemes initialized");
}

/// Initialize system sound events
fn init_system_events() {
    let mut events = EVENTS.lock();
    let mut count = 0;

    let event_defs: &[(&[u8], &[u8], u32)] = &[
        (b".Default", b"Default Beep", sound_event::DEFAULT),
        (b"SystemAsterisk", b"Asterisk", sound_event::ASTERISK),
        (b"SystemExclamation", b"Exclamation", sound_event::EXCLAMATION),
        (b"SystemHand", b"Critical Stop", sound_event::HAND),
        (b"SystemQuestion", b"Question", sound_event::QUESTION),
        (b"WindowsLogon", b"Windows Logon", sound_event::LOGON),
        (b"WindowsLogoff", b"Windows Logoff", sound_event::LOGOFF),
        (b"SystemStart", b"Start Windows", sound_event::STARTUP),
        (b"SystemExit", b"Exit Windows", sound_event::EXIT),
        (b"Open", b"Open Program", sound_event::OPEN),
        (b"Close", b"Close Program", sound_event::CLOSE),
        (b"Minimize", b"Minimize", sound_event::MINIMIZE),
        (b"Maximize", b"Maximize", sound_event::MAXIMIZE),
        (b"RestoreUp", b"Restore Up", sound_event::RESTORE_UP),
        (b"RestoreDown", b"Restore Down", sound_event::RESTORE_DOWN),
        (b"MenuCommand", b"Menu Command", sound_event::MENU_COMMAND),
        (b"MenuPopup", b"Menu Popup", sound_event::MENU_POPUP),
        (b"MailBeep", b"New Mail Notification", sound_event::NEW_MAIL),
        (b"EmptyRecycleBin", b"Empty Recycle Bin", sound_event::EMPTY_RECYCLE_BIN),
        (b"DeviceConnect", b"Device Connect", sound_event::DEVICE_CONNECT),
        (b"DeviceDisconnect", b"Device Disconnect", sound_event::DEVICE_DISCONNECT),
        (b"DeviceFail", b"Device Failed to Connect", sound_event::DEVICE_FAIL),
        (b"PrintComplete", b"Print Complete", sound_event::PRINT_COMPLETE),
        (b"LowBatteryAlarm", b"Low Battery Alarm", sound_event::LOW_BATTERY),
        (b"CriticalBatteryAlarm", b"Critical Battery Alarm", sound_event::CRITICAL_BATTERY),
    ];

    for (name, desc, event_id) in event_defs.iter() {
        if count >= MAX_SOUND_EVENTS {
            break;
        }

        let event = &mut events[count];
        event.event_id = *event_id;
        event.app_id = sound_app::SYSTEM;

        let name_len = name.len().min(MAX_EVENT_NAME);
        event.name[..name_len].copy_from_slice(&name[..name_len]);
        event.name_len = name_len as u8;

        let desc_len = desc.len().min(MAX_EVENT_DESC);
        event.description[..desc_len].copy_from_slice(&desc[..desc_len]);
        event.desc_len = desc_len as u8;

        event.active = true;
        count += 1;
    }

    EVENT_COUNT.store(count as u32, Ordering::Release);
}

/// Initialize default sound schemes
fn init_default_schemes() {
    let mut schemes = SCHEMES.lock();
    let mut count = 0;

    // Windows Default scheme
    {
        let scheme = &mut schemes[count];
        let name = b".Default";
        let len = name.len();
        scheme.name[..len].copy_from_slice(name);
        scheme.name_len = len as u8;

        let display = b"Windows Default";
        let dlen = display.len();
        scheme.display_name[..dlen].copy_from_slice(display);
        scheme.display_len = dlen as u8;

        scheme.is_system = true;
        scheme.is_active = true;

        init_default_mappings(&mut scheme.mappings, &mut scheme.mapping_count);
        count += 1;
    }

    // No Sounds scheme
    {
        let scheme = &mut schemes[count];
        let name = b".None";
        let len = name.len();
        scheme.name[..len].copy_from_slice(name);
        scheme.name_len = len as u8;

        let display = b"No Sounds";
        let dlen = display.len();
        scheme.display_name[..dlen].copy_from_slice(display);
        scheme.display_len = dlen as u8;

        scheme.is_system = true;
        scheme.is_active = false;
        scheme.mapping_count = 0;
        count += 1;
    }

    // Windows Classic scheme
    {
        let scheme = &mut schemes[count];
        let name = b"Windows Classic";
        let len = name.len();
        scheme.name[..len].copy_from_slice(name);
        scheme.name_len = len as u8;

        let display = b"Windows Classic";
        let dlen = display.len();
        scheme.display_name[..dlen].copy_from_slice(display);
        scheme.display_len = dlen as u8;

        scheme.is_system = true;
        scheme.is_active = false;

        init_classic_mappings(&mut scheme.mappings, &mut scheme.mapping_count);
        count += 1;
    }

    SCHEME_COUNT.store(count as u32, Ordering::Release);
}

/// Initialize default Windows sound mappings
fn init_default_mappings(mappings: &mut [SoundMapping; MAX_SOUND_EVENTS], count: &mut u16) {
    let defaults: &[(u32, &[u8])] = &[
        (sound_event::DEFAULT, b"C:\\Windows\\Media\\ding.wav"),
        (sound_event::ASTERISK, b"C:\\Windows\\Media\\Windows XP Information Bar.wav"),
        (sound_event::EXCLAMATION, b"C:\\Windows\\Media\\Windows XP Exclamation.wav"),
        (sound_event::HAND, b"C:\\Windows\\Media\\Windows XP Critical Stop.wav"),
        (sound_event::QUESTION, b"C:\\Windows\\Media\\Windows XP Question.wav"),
        (sound_event::LOGON, b"C:\\Windows\\Media\\Windows XP Logon Sound.wav"),
        (sound_event::LOGOFF, b"C:\\Windows\\Media\\Windows XP Logoff Sound.wav"),
        (sound_event::STARTUP, b"C:\\Windows\\Media\\Windows XP Startup.wav"),
        (sound_event::EXIT, b"C:\\Windows\\Media\\Windows XP Shutdown.wav"),
        (sound_event::MENU_COMMAND, b"C:\\Windows\\Media\\Windows XP Menu Command.wav"),
        (sound_event::MINIMIZE, b"C:\\Windows\\Media\\Windows XP Minimize.wav"),
        (sound_event::MAXIMIZE, b"C:\\Windows\\Media\\Windows XP Maximize.wav"),
        (sound_event::RESTORE_UP, b"C:\\Windows\\Media\\Windows XP Restore.wav"),
        (sound_event::RESTORE_DOWN, b"C:\\Windows\\Media\\Windows XP Restore.wav"),
        (sound_event::NEW_MAIL, b"C:\\Windows\\Media\\Windows XP Notify.wav"),
        (sound_event::EMPTY_RECYCLE_BIN, b"C:\\Windows\\Media\\Windows XP Recycle.wav"),
        (sound_event::DEVICE_CONNECT, b"C:\\Windows\\Media\\Windows XP Hardware Insert.wav"),
        (sound_event::DEVICE_DISCONNECT, b"C:\\Windows\\Media\\Windows XP Hardware Remove.wav"),
        (sound_event::DEVICE_FAIL, b"C:\\Windows\\Media\\Windows XP Hardware Fail.wav"),
        (sound_event::PRINT_COMPLETE, b"C:\\Windows\\Media\\Windows XP Print complete.wav"),
        (sound_event::LOW_BATTERY, b"C:\\Windows\\Media\\Windows XP Battery Low.wav"),
        (sound_event::CRITICAL_BATTERY, b"C:\\Windows\\Media\\Windows XP Battery Critical.wav"),
    ];

    for (i, (event_id, path)) in defaults.iter().enumerate() {
        if i >= MAX_SOUND_EVENTS {
            break;
        }

        let mapping = &mut mappings[i];
        mapping.event_id = *event_id;
        mapping.app_id = sound_app::SYSTEM;

        let path_len = path.len().min(MAX_SOUND_PATH);
        mapping.file_path[..path_len].copy_from_slice(&path[..path_len]);
        mapping.path_len = path_len as u16;
    }

    *count = defaults.len() as u16;
}

/// Initialize Windows Classic sound mappings
fn init_classic_mappings(mappings: &mut [SoundMapping; MAX_SOUND_EVENTS], count: &mut u16) {
    let classics: &[(u32, &[u8])] = &[
        (sound_event::DEFAULT, b"C:\\Windows\\Media\\chord.wav"),
        (sound_event::ASTERISK, b"C:\\Windows\\Media\\chord.wav"),
        (sound_event::EXCLAMATION, b"C:\\Windows\\Media\\chord.wav"),
        (sound_event::HAND, b"C:\\Windows\\Media\\chord.wav"),
        (sound_event::QUESTION, b"C:\\Windows\\Media\\chord.wav"),
        (sound_event::STARTUP, b"C:\\Windows\\Media\\The Microsoft Sound.wav"),
    ];

    for (i, (event_id, path)) in classics.iter().enumerate() {
        if i >= MAX_SOUND_EVENTS {
            break;
        }

        let mapping = &mut mappings[i];
        mapping.event_id = *event_id;
        mapping.app_id = sound_app::SYSTEM;

        let path_len = path.len().min(MAX_SOUND_PATH);
        mapping.file_path[..path_len].copy_from_slice(&path[..path_len]);
        mapping.path_len = path_len as u16;
    }

    *count = classics.len() as u16;
}

// ============================================================================
// Settings Access
// ============================================================================

/// Get sounds enabled state
pub fn get_sounds_enabled() -> bool {
    SETTINGS.lock().sounds_enabled
}

/// Set sounds enabled state
pub fn set_sounds_enabled(enabled: bool) {
    SETTINGS.lock().sounds_enabled = enabled;
}

/// Get startup sound enabled
pub fn get_play_startup() -> bool {
    SETTINGS.lock().play_startup
}

/// Set startup sound enabled
pub fn set_play_startup(enabled: bool) {
    SETTINGS.lock().play_startup = enabled;
}

/// Get system beep enabled
pub fn get_beep_enabled() -> bool {
    SETTINGS.lock().beep_enabled
}

/// Set system beep enabled
pub fn set_beep_enabled(enabled: bool) {
    SETTINGS.lock().beep_enabled = enabled;
}

// ============================================================================
// Sound Event Access
// ============================================================================

/// Get number of sound events
pub fn get_event_count() -> u32 {
    EVENT_COUNT.load(Ordering::Acquire)
}

/// Get sound event info by index
pub fn get_event_info(index: usize, name: &mut [u8], desc: &mut [u8]) -> bool {
    let events = EVENTS.lock();
    let count = EVENT_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    let event = &events[index];

    let name_len = (event.name_len as usize).min(name.len());
    name[..name_len].copy_from_slice(&event.name[..name_len]);

    let desc_len = (event.desc_len as usize).min(desc.len());
    desc[..desc_len].copy_from_slice(&event.description[..desc_len]);

    true
}

/// Get sound event ID by index
pub fn get_event_id(index: usize) -> Option<u32> {
    let events = EVENTS.lock();
    let count = EVENT_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return None;
    }

    Some(events[index].event_id)
}

// ============================================================================
// Sound Scheme Management
// ============================================================================

/// Get number of sound schemes
pub fn get_scheme_count() -> u32 {
    SCHEME_COUNT.load(Ordering::Acquire)
}

/// Get active scheme index
pub fn get_active_scheme() -> usize {
    let schemes = SCHEMES.lock();
    let count = SCHEME_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        if schemes[i].is_active {
            return i;
        }
    }
    0
}

/// Set active scheme
pub fn set_active_scheme(index: usize) -> bool {
    let mut schemes = SCHEMES.lock();
    let count = SCHEME_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    // Deactivate current
    for i in 0..count {
        schemes[i].is_active = false;
    }

    // Activate new
    schemes[index].is_active = true;
    SETTINGS.lock().current_scheme = index;

    true
}

/// Get scheme info by index
pub fn get_scheme_info(index: usize, name: &mut [u8], display: &mut [u8],
                       is_system: &mut bool) -> bool {
    let schemes = SCHEMES.lock();
    let count = SCHEME_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    let scheme = &schemes[index];

    let name_len = (scheme.name_len as usize).min(name.len());
    name[..name_len].copy_from_slice(&scheme.name[..name_len]);

    let display_len = (scheme.display_len as usize).min(display.len());
    display[..display_len].copy_from_slice(&scheme.display_name[..display_len]);

    *is_system = scheme.is_system;

    true
}

/// Get sound file for an event in a scheme
pub fn get_event_sound(scheme_index: usize, event_id: u32, path: &mut [u8]) -> usize {
    let schemes = SCHEMES.lock();
    let count = SCHEME_COUNT.load(Ordering::Acquire) as usize;

    if scheme_index >= count {
        return 0;
    }

    let scheme = &schemes[scheme_index];
    let mapping_count = scheme.mapping_count as usize;

    for i in 0..mapping_count {
        if scheme.mappings[i].event_id == event_id {
            let len = (scheme.mappings[i].path_len as usize).min(path.len());
            path[..len].copy_from_slice(&scheme.mappings[i].file_path[..len]);
            return len;
        }
    }

    0
}

/// Set sound file for an event in a scheme
pub fn set_event_sound(scheme_index: usize, event_id: u32, path: &[u8]) -> bool {
    let mut schemes = SCHEMES.lock();
    let count = SCHEME_COUNT.load(Ordering::Acquire) as usize;

    if scheme_index >= count {
        return false;
    }

    let scheme = &mut schemes[scheme_index];

    // Don't modify system schemes
    if scheme.is_system {
        return false;
    }

    // Find existing mapping
    let mapping_count = scheme.mapping_count as usize;
    for i in 0..mapping_count {
        if scheme.mappings[i].event_id == event_id {
            let len = path.len().min(MAX_SOUND_PATH);
            scheme.mappings[i].file_path[..len].copy_from_slice(&path[..len]);
            scheme.mappings[i].path_len = len as u16;
            return true;
        }
    }

    // Add new mapping
    if mapping_count < MAX_SOUND_EVENTS {
        let mapping = &mut scheme.mappings[mapping_count];
        mapping.event_id = event_id;
        mapping.app_id = sound_app::SYSTEM;
        let len = path.len().min(MAX_SOUND_PATH);
        mapping.file_path[..len].copy_from_slice(&path[..len]);
        mapping.path_len = len as u16;
        scheme.mapping_count += 1;
        return true;
    }

    false
}

/// Create a new user sound scheme
pub fn create_scheme(name: &[u8], display_name: &[u8]) -> Option<usize> {
    let mut schemes = SCHEMES.lock();
    let count = SCHEME_COUNT.load(Ordering::Acquire) as usize;

    if count >= MAX_SOUND_SCHEMES {
        return None;
    }

    let scheme = &mut schemes[count];

    let name_len = name.len().min(MAX_SCHEME_NAME);
    scheme.name[..name_len].copy_from_slice(&name[..name_len]);
    scheme.name_len = name_len as u8;

    let display_len = display_name.len().min(MAX_SCHEME_NAME);
    scheme.display_name[..display_len].copy_from_slice(&display_name[..display_len]);
    scheme.display_len = display_len as u8;

    scheme.is_system = false;
    scheme.is_active = false;
    scheme.mapping_count = 0;

    SCHEME_COUNT.store((count + 1) as u32, Ordering::Release);

    Some(count)
}

/// Delete a user sound scheme
pub fn delete_scheme(index: usize) -> bool {
    let mut schemes = SCHEMES.lock();
    let count = SCHEME_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    // Don't delete system schemes
    if schemes[index].is_system {
        return false;
    }

    // Don't delete active scheme
    if schemes[index].is_active {
        return false;
    }

    // Shift remaining schemes
    for i in index..(count - 1) {
        schemes[i] = schemes[i + 1];
    }

    schemes[count - 1] = SoundScheme::new();
    SCHEME_COUNT.store((count - 1) as u32, Ordering::Release);

    true
}

// ============================================================================
// Sound Playback
// ============================================================================

/// Play a sound event
pub fn play_sound_event(event_id: u32) -> bool {
    let settings = SETTINGS.lock();

    if !settings.sounds_enabled {
        return false;
    }

    let scheme_index = settings.current_scheme;
    drop(settings);

    let mut path = [0u8; MAX_SOUND_PATH];
    let len = get_event_sound(scheme_index, event_id, &mut path);

    if len == 0 {
        return false;
    }

    play_sound_file(&path[..len], 0)
}

/// Play a sound file
pub fn play_sound_file(path: &[u8], flags: u32) -> bool {
    // Mark as playing
    PLAYING_SOUND.store(true, Ordering::SeqCst);

    // In a real implementation, this would:
    // 1. Load the WAV file
    // 2. Parse the RIFF/WAVE format
    // 3. Send audio data to the sound driver
    // 4. Handle async/sync flags

    let _async = flags & sound_flags::ASYNC != 0;
    let _loop_sound = flags & sound_flags::LOOP != 0;

    // Simulate completion
    if flags & sound_flags::ASYNC == 0 {
        PLAYING_SOUND.store(false, Ordering::SeqCst);
    }

    let _ = path;
    true
}

/// Stop currently playing sound
pub fn stop_sound() {
    PLAYING_SOUND.store(false, Ordering::SeqCst);
}

/// Check if a sound is playing
pub fn is_sound_playing() -> bool {
    PLAYING_SOUND.load(Ordering::Acquire)
}

/// Play system beep
pub fn message_beep(beep_type: u32) -> bool {
    if !get_beep_enabled() {
        return false;
    }

    match beep_type {
        0xFFFFFFFF => {
            // Simple beep (speaker)
            // Would send to PC speaker
            true
        }
        _ => {
            // Map to sound event
            let event = match beep_type {
                0x00 => sound_event::DEFAULT,     // MB_OK
                0x10 => sound_event::HAND,        // MB_ICONHAND
                0x20 => sound_event::QUESTION,    // MB_ICONQUESTION
                0x30 => sound_event::EXCLAMATION, // MB_ICONEXCLAMATION
                0x40 => sound_event::ASTERISK,    // MB_ICONASTERISK
                _ => sound_event::DEFAULT,
            };
            play_sound_event(event)
        }
    }
}

// ============================================================================
// Dialog API
// ============================================================================

/// Show sounds control panel dialog
pub fn show_sounds_dialog(parent: HWND) -> bool {
    let mut dialog = DIALOG.lock();

    dialog.parent = parent;
    dialog.modified = false;
    dialog.selected_event = 0;
    dialog.preview_playing = false;

    // Would create dialog with:
    // - Sound scheme dropdown
    // - Event list with current sound
    // - Browse button for custom sound
    // - Preview/Stop buttons
    // - Play Windows Startup sound checkbox

    true
}

/// Preview sound for selected event
pub fn preview_sound(event_id: u32) -> bool {
    let mut dialog = DIALOG.lock();

    if dialog.preview_playing {
        stop_sound();
        dialog.preview_playing = false;
        return true;
    }

    dialog.preview_playing = true;
    drop(dialog);

    let result = play_sound_event(event_id);

    DIALOG.lock().preview_playing = false;

    result
}
