//! Volume Control UI
//!
//! Provides volume mixer and sound settings UI following Windows
//! sndvol32 patterns.
//!
//! # References
//!
//! - Windows Server 2003 sndvol32
//! - Volume mixer API

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle, Point};

// ============================================================================
// Constants
// ============================================================================

/// Maximum name length
pub const MAX_NAME: usize = 64;

/// Volume flags
pub mod vol_flags {
    /// Channel is muted
    pub const MUTED: u32 = 0x00000001;
    /// Has balance control
    pub const HAS_BALANCE: u32 = 0x00000002;
    /// Is master volume
    pub const MASTER: u32 = 0x00000004;
    /// Is playback device
    pub const PLAYBACK: u32 = 0x00000008;
    /// Is recording device
    pub const RECORDING: u32 = 0x00000010;
    /// Is application mixer
    pub const APPLICATION: u32 = 0x00000020;
}

/// Mixer line types
pub mod line_type {
    /// Speakers/wave out
    pub const SPEAKERS: u32 = 0;
    /// Wave
    pub const WAVE: u32 = 1;
    /// MIDI synthesizer
    pub const MIDI: u32 = 2;
    /// CD audio
    pub const CD: u32 = 3;
    /// Line in
    pub const LINE_IN: u32 = 4;
    /// Microphone
    pub const MICROPHONE: u32 = 5;
    /// Aux
    pub const AUX: u32 = 6;
}

// ============================================================================
// Structures
// ============================================================================

/// Volume channel
#[derive(Clone, Copy)]
pub struct VolumeChannel {
    /// Channel is valid
    pub valid: bool,
    /// Channel ID
    pub id: u32,
    /// Flags
    pub flags: u32,
    /// Line type
    pub line_type: u32,
    /// Volume level (0-65535)
    pub volume: u16,
    /// Left volume (0-65535)
    pub volume_left: u16,
    /// Right volume (0-65535)
    pub volume_right: u16,
    /// Balance (-100 to +100)
    pub balance: i8,
    /// Name length
    pub name_len: u8,
    /// Display name
    pub name: [u8; MAX_NAME],
    /// Icon index
    pub icon: u16,
}

impl VolumeChannel {
    const fn new() -> Self {
        Self {
            valid: false,
            id: 0,
            flags: 0,
            line_type: 0,
            volume: 65535,
            volume_left: 65535,
            volume_right: 65535,
            balance: 0,
            name_len: 0,
            name: [0; MAX_NAME],
            icon: 0,
        }
    }

    /// Set name
    pub fn set_name(&mut self, name: &[u8]) {
        self.name_len = name.len().min(MAX_NAME) as u8;
        let len = self.name_len as usize;
        self.name[..len].copy_from_slice(&name[..len]);
    }
}

/// Audio device
#[derive(Clone, Copy)]
pub struct AudioDevice {
    /// Device is valid
    pub valid: bool,
    /// Device ID
    pub id: u32,
    /// Is playback device
    pub playback: bool,
    /// Is default device
    pub is_default: bool,
    /// Name length
    pub name_len: u8,
    /// Display name
    pub name: [u8; MAX_NAME],
    /// Channel count
    pub channel_count: u8,
}

impl AudioDevice {
    const fn new() -> Self {
        Self {
            valid: false,
            id: 0,
            playback: true,
            is_default: false,
            name_len: 0,
            name: [0; MAX_NAME],
            channel_count: 0,
        }
    }
}

/// Volume popup state (tray icon popup)
#[derive(Clone, Copy)]
pub struct VolumePopupState {
    /// Popup is active
    pub active: bool,
    /// Window handle
    pub hwnd: HWND,
    /// Anchor point
    pub anchor: Point,
    /// Master volume
    pub volume: u16,
    /// Is muted
    pub muted: bool,
}

impl VolumePopupState {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            anchor: Point { x: 0, y: 0 },
            volume: 65535,
            muted: false,
        }
    }
}

/// Volume mixer dialog state
#[derive(Clone, Copy)]
pub struct VolumeMixerState {
    /// Dialog is active
    pub active: bool,
    /// Window handle
    pub hwnd: HWND,
    /// Recording mode (vs playback)
    pub recording_mode: bool,
    /// Selected device
    pub selected_device: u8,
}

impl VolumeMixerState {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            recording_mode: false,
            selected_device: 0,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static VOLUME_INITIALIZED: AtomicBool = AtomicBool::new(false);
static VOLUME_LOCK: SpinLock<()> = SpinLock::new(());

// Master volume state
static MASTER_VOLUME: AtomicU32 = AtomicU32::new(65535);
static MASTER_MUTED: AtomicBool = AtomicBool::new(false);

// Channels
const MAX_CHANNELS: usize = 16;
static CHANNELS: SpinLock<[VolumeChannel; MAX_CHANNELS]> =
    SpinLock::new([const { VolumeChannel::new() }; MAX_CHANNELS]);

// Devices
const MAX_DEVICES: usize = 8;
static DEVICES: SpinLock<[AudioDevice; MAX_DEVICES]> =
    SpinLock::new([const { AudioDevice::new() }; MAX_DEVICES]);

// UI state
static POPUP_STATE: SpinLock<VolumePopupState> = SpinLock::new(VolumePopupState::new());
static MIXER_STATE: SpinLock<VolumeMixerState> = SpinLock::new(VolumeMixerState::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize volume control subsystem
pub fn init() {
    let _guard = VOLUME_LOCK.lock();

    if VOLUME_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[VOLUME] Initializing volume control...");

    // Initialize default devices
    init_default_devices();

    // Initialize default channels
    init_default_channels();

    VOLUME_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[VOLUME] Volume control initialized");
}

/// Initialize default devices
fn init_default_devices() {
    let mut devices = DEVICES.lock();

    // Default playback device
    let playback = &mut devices[0];
    playback.valid = true;
    playback.id = 0;
    playback.playback = true;
    playback.is_default = true;
    let name = b"Speakers (High Definition Audio)";
    playback.name_len = name.len() as u8;
    playback.name[..name.len()].copy_from_slice(name);

    // Default recording device
    let recording = &mut devices[1];
    recording.valid = true;
    recording.id = 1;
    recording.playback = false;
    recording.is_default = true;
    let name = b"Microphone (High Definition Audio)";
    recording.name_len = name.len() as u8;
    recording.name[..name.len()].copy_from_slice(name);
}

/// Initialize default channels
fn init_default_channels() {
    let channels: &[(&[u8], u32, u32)] = &[
        (b"Master Volume", line_type::SPEAKERS, vol_flags::MASTER | vol_flags::HAS_BALANCE),
        (b"Wave", line_type::WAVE, vol_flags::HAS_BALANCE),
        (b"SW Synth", line_type::MIDI, vol_flags::HAS_BALANCE),
        (b"CD Audio", line_type::CD, vol_flags::HAS_BALANCE),
        (b"Line In", line_type::LINE_IN, vol_flags::RECORDING),
        (b"Microphone", line_type::MICROPHONE, vol_flags::RECORDING),
    ];

    let mut channel_list = CHANNELS.lock();

    for (i, (name, line_type, flags)) in channels.iter().enumerate() {
        if i >= MAX_CHANNELS {
            break;
        }

        let channel = &mut channel_list[i];
        channel.valid = true;
        channel.id = i as u32;
        channel.flags = *flags;
        channel.line_type = *line_type;
        channel.volume = 65535;
        channel.volume_left = 65535;
        channel.volume_right = 65535;
        channel.set_name(name);
    }
}

// ============================================================================
// Volume API
// ============================================================================

/// Get master volume (0-65535)
pub fn get_master_volume() -> u16 {
    MASTER_VOLUME.load(Ordering::Acquire) as u16
}

/// Set master volume (0-65535)
pub fn set_master_volume(volume: u16) -> bool {
    MASTER_VOLUME.store(volume as u32, Ordering::Release);

    // Update master channel
    let mut channels = CHANNELS.lock();
    for channel in channels.iter_mut() {
        if channel.valid && (channel.flags & vol_flags::MASTER) != 0 {
            channel.volume = volume;
            channel.volume_left = volume;
            channel.volume_right = volume;
            break;
        }
    }

    true
}

/// Get mute state
pub fn is_muted() -> bool {
    MASTER_MUTED.load(Ordering::Acquire)
}

/// Set mute state
pub fn set_muted(muted: bool) -> bool {
    MASTER_MUTED.store(muted, Ordering::Release);

    // Update master channel
    let mut channels = CHANNELS.lock();
    for channel in channels.iter_mut() {
        if channel.valid && (channel.flags & vol_flags::MASTER) != 0 {
            if muted {
                channel.flags |= vol_flags::MUTED;
            } else {
                channel.flags &= !vol_flags::MUTED;
            }
            break;
        }
    }

    true
}

/// Toggle mute
pub fn toggle_mute() -> bool {
    let muted = !is_muted();
    set_muted(muted);
    muted
}

/// Adjust volume by delta
pub fn adjust_volume(delta: i32) -> u16 {
    let current = get_master_volume() as i32;
    let new_vol = (current + delta).clamp(0, 65535) as u16;
    set_master_volume(new_vol);
    new_vol
}

// ============================================================================
// Channel API
// ============================================================================

/// Get channel count
pub fn get_channel_count() -> usize {
    let channels = CHANNELS.lock();
    channels.iter().filter(|c| c.valid).count()
}

/// Get channel by index
pub fn get_channel(index: usize) -> Option<VolumeChannel> {
    let channels = CHANNELS.lock();

    if index < MAX_CHANNELS && channels[index].valid {
        Some(channels[index])
    } else {
        None
    }
}

/// Set channel volume
pub fn set_channel_volume(id: u32, volume: u16) -> bool {
    let mut channels = CHANNELS.lock();

    for channel in channels.iter_mut() {
        if channel.valid && channel.id == id {
            channel.volume = volume;
            channel.volume_left = volume;
            channel.volume_right = volume;
            return true;
        }
    }

    false
}

/// Set channel balance
pub fn set_channel_balance(id: u32, balance: i8) -> bool {
    let mut channels = CHANNELS.lock();

    for channel in channels.iter_mut() {
        if channel.valid && channel.id == id {
            channel.balance = balance;

            // Calculate left/right from balance
            let vol = channel.volume as i32;
            if balance < 0 {
                // More left
                channel.volume_left = channel.volume;
                channel.volume_right = ((vol * (100 + balance as i32)) / 100) as u16;
            } else if balance > 0 {
                // More right
                channel.volume_left = ((vol * (100 - balance as i32)) / 100) as u16;
                channel.volume_right = channel.volume;
            } else {
                channel.volume_left = channel.volume;
                channel.volume_right = channel.volume;
            }

            return true;
        }
    }

    false
}

/// Mute/unmute channel
pub fn set_channel_muted(id: u32, muted: bool) -> bool {
    let mut channels = CHANNELS.lock();

    for channel in channels.iter_mut() {
        if channel.valid && channel.id == id {
            if muted {
                channel.flags |= vol_flags::MUTED;
            } else {
                channel.flags &= !vol_flags::MUTED;
            }
            return true;
        }
    }

    false
}

// ============================================================================
// Device API
// ============================================================================

/// Get device count
pub fn get_device_count(playback: bool) -> usize {
    let devices = DEVICES.lock();
    devices.iter().filter(|d| d.valid && d.playback == playback).count()
}

/// Get device by index
pub fn get_device(index: usize) -> Option<AudioDevice> {
    let devices = DEVICES.lock();

    if index < MAX_DEVICES && devices[index].valid {
        Some(devices[index])
    } else {
        None
    }
}

/// Get default device
pub fn get_default_device(playback: bool) -> Option<AudioDevice> {
    let devices = DEVICES.lock();

    for device in devices.iter() {
        if device.valid && device.playback == playback && device.is_default {
            return Some(*device);
        }
    }

    None
}

/// Set default device
pub fn set_default_device(id: u32, playback: bool) -> bool {
    let mut devices = DEVICES.lock();

    // Clear current default
    for device in devices.iter_mut() {
        if device.valid && device.playback == playback {
            device.is_default = false;
        }
    }

    // Set new default
    for device in devices.iter_mut() {
        if device.valid && device.id == id {
            device.is_default = true;
            return true;
        }
    }

    false
}

// ============================================================================
// Volume Popup (Tray Icon)
// ============================================================================

/// Show volume popup
pub fn show_volume_popup(anchor: Point) -> bool {
    if !VOLUME_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = POPUP_STATE.lock();

    if state.active {
        // Already open - close it
        hide_volume_popup();
        return true;
    }

    state.active = true;
    state.anchor = anchor;
    state.volume = get_master_volume();
    state.muted = is_muted();

    // Would create popup window
    state.hwnd = UserHandle::NULL;

    true
}

/// Hide volume popup
pub fn hide_volume_popup() {
    let mut state = POPUP_STATE.lock();

    if state.active {
        if state.hwnd != UserHandle::NULL {
            super::window::destroy_window(state.hwnd);
        }

        state.active = false;
        state.hwnd = UserHandle::NULL;
    }
}

/// Is volume popup visible
pub fn is_popup_visible() -> bool {
    POPUP_STATE.lock().active
}

// ============================================================================
// Volume Mixer Dialog
// ============================================================================

/// Show volume mixer
pub fn show_volume_mixer(hwnd_owner: HWND, recording: bool) -> bool {
    if !VOLUME_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = MIXER_STATE.lock();

    if state.active {
        return false;
    }

    state.recording_mode = recording;
    state.selected_device = 0;

    // Create dialog
    let hwnd = create_mixer_dialog(hwnd_owner);

    if hwnd == UserHandle::NULL {
        return false;
    }

    state.active = true;
    state.hwnd = hwnd;

    drop(state);

    // Run dialog
    let result = run_mixer_dialog(hwnd);

    // Clean up
    let mut state = MIXER_STATE.lock();
    state.active = false;
    state.hwnd = UserHandle::NULL;

    result
}

/// Close volume mixer
pub fn close_volume_mixer() {
    let mut state = MIXER_STATE.lock();

    if state.active {
        if state.hwnd != UserHandle::NULL {
            super::window::destroy_window(state.hwnd);
        }

        state.active = false;
        state.hwnd = UserHandle::NULL;
    }
}

// ============================================================================
// Dialog Creation
// ============================================================================

/// Create mixer dialog
fn create_mixer_dialog(_owner: HWND) -> HWND {
    UserHandle::NULL
}

/// Run mixer dialog
fn run_mixer_dialog(_hwnd: HWND) -> bool {
    true
}

// ============================================================================
// Dialog Procedure
// ============================================================================

/// Volume mixer dialog procedure
pub fn mixer_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    _lparam: isize,
) -> isize {
    match msg {
        super::message::WM_COMMAND => {
            handle_mixer_command(hwnd, wparam as u32)
        }
        super::message::WM_CLOSE => {
            close_volume_mixer();
            0
        }
        _ => 0,
    }
}

/// Handle mixer dialog commands
fn handle_mixer_command(_hwnd: HWND, command: u32) -> isize {
    let id = command as u16;

    match id {
        1 | 2 => {
            // OK / Cancel
            close_volume_mixer();
            0
        }
        100 => {
            // Device selection changed
            // Would update channel display
            0
        }
        101 => {
            // Master mute checkbox
            toggle_mute();
            0
        }
        102 => {
            // Options menu
            0
        }
        _ => {
            // Channel sliders
            if id >= 200 && id < 200 + MAX_CHANNELS as u16 {
                // Channel volume changed
                let channel_idx = (id - 200) as usize;
                let high = (command >> 16) as u16;

                if let Some(channel) = get_channel(channel_idx) {
                    set_channel_volume(channel.id, high);
                }
            } else if id >= 300 && id < 300 + MAX_CHANNELS as u16 {
                // Channel mute checkbox
                let channel_idx = (id - 300) as usize;

                if let Some(channel) = get_channel(channel_idx) {
                    let muted = (channel.flags & vol_flags::MUTED) != 0;
                    set_channel_muted(channel.id, !muted);
                }
            }
            0
        }
    }
}

/// Volume popup window procedure
pub fn popup_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    match msg {
        super::message::WM_LBUTTONUP => {
            // Mute button clicked
            let y = (lparam as u32 >> 16) as i32;
            if y > 100 {
                // Mute area
                toggle_mute();
            }
            0
        }
        super::message::WM_KILLFOCUS => {
            hide_volume_popup();
            0
        }
        super::message::WM_CLOSE => {
            hide_volume_popup();
            0
        }
        _ => {
            let _ = (hwnd, wparam);
            0
        }
    }
}

// ============================================================================
// Volume Icon
// ============================================================================

/// Get volume icon based on current state
pub fn get_volume_icon() -> u32 {
    if is_muted() {
        3 // Muted icon
    } else {
        let vol = get_master_volume();
        if vol == 0 {
            0 // No sound
        } else if vol < 22000 {
            1 // Low
        } else if vol < 44000 {
            2 // Medium
        } else {
            3 // High
        }
    }
}

/// Get volume percentage (0-100)
pub fn get_volume_percent() -> u8 {
    ((get_master_volume() as u32 * 100) / 65535) as u8
}

/// Set volume by percentage (0-100)
pub fn set_volume_percent(percent: u8) -> bool {
    let volume = ((percent as u32).min(100) * 65535 / 100) as u16;
    set_master_volume(volume)
}
