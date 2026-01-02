//! Shell Hardware Detection Service (ShellHWDetection)
//!
//! The Shell Hardware Detection service monitors for hardware events
//! and triggers appropriate AutoPlay actions. It detects when removable
//! media is inserted and provides notifications to shell extensions.
//!
//! # Features
//!
//! - **Device Arrival**: Detect when devices are connected
//! - **Media Insertion**: Detect when media is inserted into drives
//! - **AutoPlay Handling**: Trigger AutoPlay for appropriate media
//! - **Content Detection**: Identify media content types
//! - **Handler Selection**: Determine appropriate handler for content
//!
//! # Supported Content Types
//!
//! - Audio CD
//! - DVD Movie
//! - Mixed content
//! - Blank media
//! - Pictures
//! - Music files
//! - Video files
//! - Software/Data

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum monitored devices
const MAX_DEVICES: usize = 32;

/// Maximum pending events
const MAX_EVENTS: usize = 64;

/// Maximum handlers
const MAX_HANDLERS: usize = 32;

/// Maximum device name length
const MAX_DEVICE_NAME: usize = 64;

/// Maximum handler name length
const MAX_HANDLER_NAME: usize = 128;

/// Maximum path length
const MAX_PATH: usize = 260;

/// Content type flags
pub mod content_type {
    pub const UNKNOWN: u32 = 0x00000000;
    pub const AUDIO_CD: u32 = 0x00000001;
    pub const DVD_MOVIE: u32 = 0x00000002;
    pub const AUDIO_FILES: u32 = 0x00000004;
    pub const IMAGE_FILES: u32 = 0x00000008;
    pub const VIDEO_FILES: u32 = 0x00000010;
    pub const MIXED_CONTENT: u32 = 0x00000020;
    pub const BLANK_CD: u32 = 0x00000040;
    pub const BLANK_DVD: u32 = 0x00000080;
    pub const SOFTWARE: u32 = 0x00000100;
    pub const DOCUMENT: u32 = 0x00000200;
}

/// Device type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// Unknown device
    Unknown = 0,
    /// CD-ROM drive
    CdRom = 1,
    /// DVD drive
    Dvd = 2,
    /// Removable disk (USB, etc.)
    Removable = 3,
    /// Memory card reader
    CardReader = 4,
    /// Digital camera
    Camera = 5,
    /// Portable media player
    MediaPlayer = 6,
    /// Mobile phone
    Phone = 7,
    /// Scanner
    Scanner = 8,
}

impl DeviceType {
    const fn empty() -> Self {
        DeviceType::Unknown
    }
}

/// Event type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// Device arrived
    DeviceArrival = 0,
    /// Device removed
    DeviceRemoval = 1,
    /// Media inserted
    MediaInsert = 2,
    /// Media ejected
    MediaEject = 3,
    /// Device change (configuration)
    DeviceChange = 4,
}

impl EventType {
    const fn empty() -> Self {
        EventType::DeviceArrival
    }
}

/// AutoPlay action
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoPlayAction {
    /// No action
    None = 0,
    /// Play media
    Play = 1,
    /// Open folder to view files
    OpenFolder = 2,
    /// Import pictures
    ImportPictures = 3,
    /// Import video
    ImportVideo = 4,
    /// Burn files
    Burn = 5,
    /// Take no action
    TakeNoAction = 6,
    /// Ask me every time
    PromptUser = 7,
    /// Run program
    RunProgram = 8,
}

impl AutoPlayAction {
    const fn empty() -> Self {
        AutoPlayAction::None
    }
}

/// Device information
#[repr(C)]
#[derive(Clone)]
pub struct DeviceInfo {
    /// Device ID
    pub device_id: u32,
    /// Device name
    pub name: [u8; MAX_DEVICE_NAME],
    /// Device type
    pub device_type: DeviceType,
    /// Drive letter (if applicable)
    pub drive_letter: u8,
    /// Has media inserted
    pub has_media: bool,
    /// Content type flags
    pub content_type: u32,
    /// Volume label
    pub volume_label: [u8; 32],
    /// AutoPlay enabled for this device
    pub autoplay_enabled: bool,
    /// Device path
    pub device_path: [u8; MAX_PATH],
    /// Entry is valid
    pub valid: bool,
}

impl DeviceInfo {
    const fn empty() -> Self {
        DeviceInfo {
            device_id: 0,
            name: [0; MAX_DEVICE_NAME],
            device_type: DeviceType::empty(),
            drive_letter: 0,
            has_media: false,
            content_type: 0,
            volume_label: [0; 32],
            autoplay_enabled: true,
            device_path: [0; MAX_PATH],
            valid: false,
        }
    }
}

/// Hardware event
#[repr(C)]
#[derive(Clone)]
pub struct HardwareEvent {
    /// Event ID
    pub event_id: u64,
    /// Event type
    pub event_type: EventType,
    /// Device ID
    pub device_id: u32,
    /// Content type (for media events)
    pub content_type: u32,
    /// Event timestamp
    pub timestamp: i64,
    /// Processed flag
    pub processed: bool,
    /// Entry is valid
    pub valid: bool,
}

impl HardwareEvent {
    const fn empty() -> Self {
        HardwareEvent {
            event_id: 0,
            event_type: EventType::empty(),
            device_id: 0,
            content_type: 0,
            timestamp: 0,
            processed: false,
            valid: false,
        }
    }
}

/// AutoPlay handler
#[repr(C)]
#[derive(Clone)]
pub struct AutoPlayHandler {
    /// Handler name
    pub name: [u8; MAX_HANDLER_NAME],
    /// Content types handled
    pub content_types: u32,
    /// Device types handled
    pub device_types: u32,
    /// Action to perform
    pub action: AutoPlayAction,
    /// Command to execute
    pub command: [u8; MAX_PATH],
    /// Is default handler
    pub is_default: bool,
    /// Entry is valid
    pub valid: bool,
}

impl AutoPlayHandler {
    const fn empty() -> Self {
        AutoPlayHandler {
            name: [0; MAX_HANDLER_NAME],
            content_types: 0,
            device_types: 0,
            action: AutoPlayAction::empty(),
            command: [0; MAX_PATH],
            is_default: false,
            valid: false,
        }
    }
}

/// Shell Hardware Detection state
pub struct ShellHwState {
    /// Service is running
    pub running: bool,
    /// Monitored devices
    pub devices: [DeviceInfo; MAX_DEVICES],
    /// Device count
    pub device_count: usize,
    /// Pending events
    pub events: [HardwareEvent; MAX_EVENTS],
    /// Event count
    pub event_count: usize,
    /// AutoPlay handlers
    pub handlers: [AutoPlayHandler; MAX_HANDLERS],
    /// Handler count
    pub handler_count: usize,
    /// Next event ID
    pub next_event_id: u64,
    /// Service start time
    pub start_time: i64,
    /// AutoPlay globally enabled
    pub autoplay_enabled: bool,
}

impl ShellHwState {
    const fn new() -> Self {
        ShellHwState {
            running: false,
            devices: [const { DeviceInfo::empty() }; MAX_DEVICES],
            device_count: 0,
            events: [const { HardwareEvent::empty() }; MAX_EVENTS],
            event_count: 0,
            handlers: [const { AutoPlayHandler::empty() }; MAX_HANDLERS],
            handler_count: 0,
            next_event_id: 1,
            start_time: 0,
            autoplay_enabled: true,
        }
    }
}

/// Global state
static SHELLHW_STATE: Mutex<ShellHwState> = Mutex::new(ShellHwState::new());

/// Statistics
static TOTAL_EVENTS: AtomicU64 = AtomicU64::new(0);
static AUTOPLAY_TRIGGERED: AtomicU64 = AtomicU64::new(0);
static DEVICES_DETECTED: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize Shell Hardware Detection service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = SHELLHW_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    // Register default AutoPlay handlers
    register_default_handlers(&mut state);

    crate::serial_println!("[SHELLHW] Shell Hardware Detection service initialized");
}

/// Register default AutoPlay handlers
fn register_default_handlers(state: &mut ShellHwState) {
    // Windows Media Player for audio
    let idx = 0;
    let name = b"Play using Windows Media Player";
    state.handlers[idx].name[..name.len()].copy_from_slice(name);
    state.handlers[idx].content_types = content_type::AUDIO_CD | content_type::AUDIO_FILES;
    state.handlers[idx].device_types = (1 << DeviceType::CdRom as u32) | (1 << DeviceType::Removable as u32);
    state.handlers[idx].action = AutoPlayAction::Play;
    let cmd = b"wmplayer.exe /play";
    state.handlers[idx].command[..cmd.len()].copy_from_slice(cmd);
    state.handlers[idx].is_default = true;
    state.handlers[idx].valid = true;

    // Open folder handler
    let idx = 1;
    let name = b"Open folder to view files";
    state.handlers[idx].name[..name.len()].copy_from_slice(name);
    state.handlers[idx].content_types = 0xFFFFFFFF; // All content
    state.handlers[idx].device_types = 0xFFFFFFFF; // All devices
    state.handlers[idx].action = AutoPlayAction::OpenFolder;
    let cmd = b"explorer.exe";
    state.handlers[idx].command[..cmd.len()].copy_from_slice(cmd);
    state.handlers[idx].valid = true;

    // DVD Player
    let idx = 2;
    let name = b"Play DVD movie";
    state.handlers[idx].name[..name.len()].copy_from_slice(name);
    state.handlers[idx].content_types = content_type::DVD_MOVIE;
    state.handlers[idx].device_types = 1 << DeviceType::Dvd as u32;
    state.handlers[idx].action = AutoPlayAction::Play;
    let cmd = b"dvdplay.exe";
    state.handlers[idx].command[..cmd.len()].copy_from_slice(cmd);
    state.handlers[idx].is_default = true;
    state.handlers[idx].valid = true;

    // Picture import
    let idx = 3;
    let name = b"Copy pictures to a folder";
    state.handlers[idx].name[..name.len()].copy_from_slice(name);
    state.handlers[idx].content_types = content_type::IMAGE_FILES;
    state.handlers[idx].device_types = (1 << DeviceType::Camera as u32) | (1 << DeviceType::CardReader as u32);
    state.handlers[idx].action = AutoPlayAction::ImportPictures;
    let cmd = b"rundll32.exe shimgvw.dll,ImageView_Fullscreen";
    state.handlers[idx].command[..cmd.len()].copy_from_slice(cmd);
    state.handlers[idx].valid = true;

    state.handler_count = 4;
}

/// Register a device for monitoring
pub fn register_device(
    name: &[u8],
    device_type: DeviceType,
    drive_letter: u8,
    device_path: &[u8],
) -> Result<u32, u32> {
    let mut state = SHELLHW_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.devices.iter().position(|d| !d.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let device_id = slot as u32;
    let global_autoplay = state.autoplay_enabled;

    let device = &mut state.devices[slot];
    device.device_id = device_id;

    let name_len = name.len().min(MAX_DEVICE_NAME);
    device.name[..name_len].copy_from_slice(&name[..name_len]);

    device.device_type = device_type;
    device.drive_letter = drive_letter;
    device.has_media = false;
    device.content_type = content_type::UNKNOWN;
    device.autoplay_enabled = global_autoplay;

    let path_len = device_path.len().min(MAX_PATH);
    device.device_path[..path_len].copy_from_slice(&device_path[..path_len]);

    device.valid = true;

    state.device_count += 1;
    DEVICES_DETECTED.fetch_add(1, Ordering::SeqCst);

    // Generate device arrival event
    drop(state);
    generate_event(device_id, EventType::DeviceArrival, content_type::UNKNOWN);

    Ok(device_id)
}

/// Unregister a device
pub fn unregister_device(device_id: u32) -> Result<(), u32> {
    let mut state = SHELLHW_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = device_id as usize;
    if idx >= MAX_DEVICES || !state.devices[idx].valid {
        return Err(0x80070057);
    }

    // Generate removal event before removing
    let content = state.devices[idx].content_type;
    drop(state);
    generate_event(device_id, EventType::DeviceRemoval, content);

    let mut state = SHELLHW_STATE.lock();
    state.devices[idx].valid = false;
    state.device_count = state.device_count.saturating_sub(1);

    Ok(())
}

/// Notify media insertion
pub fn notify_media_insert(device_id: u32, content_type_flags: u32, volume_label: &[u8]) -> Result<(), u32> {
    let mut state = SHELLHW_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = device_id as usize;
    if idx >= MAX_DEVICES || !state.devices[idx].valid {
        return Err(0x80070057);
    }

    state.devices[idx].has_media = true;
    state.devices[idx].content_type = content_type_flags;

    let label_len = volume_label.len().min(32);
    state.devices[idx].volume_label[..label_len].copy_from_slice(&volume_label[..label_len]);

    let autoplay_enabled = state.devices[idx].autoplay_enabled && state.autoplay_enabled;

    drop(state);

    generate_event(device_id, EventType::MediaInsert, content_type_flags);

    if autoplay_enabled {
        trigger_autoplay(device_id, content_type_flags);
    }

    Ok(())
}

/// Notify media eject
pub fn notify_media_eject(device_id: u32) -> Result<(), u32> {
    let mut state = SHELLHW_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = device_id as usize;
    if idx >= MAX_DEVICES || !state.devices[idx].valid {
        return Err(0x80070057);
    }

    let content = state.devices[idx].content_type;

    state.devices[idx].has_media = false;
    state.devices[idx].content_type = content_type::UNKNOWN;
    state.devices[idx].volume_label = [0; 32];

    drop(state);
    generate_event(device_id, EventType::MediaEject, content);

    Ok(())
}

/// Generate a hardware event
fn generate_event(device_id: u32, event_type: EventType, content: u32) {
    let mut state = SHELLHW_STATE.lock();

    if !state.running {
        return;
    }

    let slot = state.events.iter().position(|e| !e.valid);
    let slot = match slot {
        Some(s) => s,
        None => {
            // Overwrite oldest processed event
            state.events.iter().position(|e| e.processed).unwrap_or(0)
        }
    };

    let event_id = state.next_event_id;
    state.next_event_id += 1;

    let event = &mut state.events[slot];
    event.event_id = event_id;
    event.event_type = event_type;
    event.device_id = device_id;
    event.content_type = content;
    event.timestamp = crate::rtl::time::rtl_get_system_time();
    event.processed = false;
    event.valid = true;

    if !state.events[slot].valid {
        state.event_count += 1;
    }

    TOTAL_EVENTS.fetch_add(1, Ordering::SeqCst);
}

/// Trigger AutoPlay for content
fn trigger_autoplay(device_id: u32, content_type_flags: u32) {
    let state = SHELLHW_STATE.lock();

    let idx = device_id as usize;
    if idx >= MAX_DEVICES || !state.devices[idx].valid {
        return;
    }

    let device_type_mask = 1 << (state.devices[idx].device_type as u32);

    // Find matching default handler
    let _handler = state.handlers.iter().find(|h| {
        h.valid
            && h.is_default
            && (h.content_types & content_type_flags) != 0
            && (h.device_types & device_type_mask) != 0
    });

    // In a real implementation, this would launch the handler
    AUTOPLAY_TRIGGERED.fetch_add(1, Ordering::SeqCst);
}

/// Get pending events
pub fn get_pending_events() -> ([HardwareEvent; MAX_EVENTS], usize) {
    let state = SHELLHW_STATE.lock();
    let mut result = [const { HardwareEvent::empty() }; MAX_EVENTS];
    let mut count = 0;

    for event in state.events.iter() {
        if event.valid && !event.processed && count < MAX_EVENTS {
            result[count] = event.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Mark event as processed
pub fn mark_event_processed(event_id: u64) -> Result<(), u32> {
    let mut state = SHELLHW_STATE.lock();

    let event = state.events.iter_mut().find(|e| e.valid && e.event_id == event_id);
    match event {
        Some(e) => {
            e.processed = true;
            Ok(())
        }
        None => Err(0x80070057),
    }
}

/// Enumerate devices
pub fn enum_devices() -> ([DeviceInfo; MAX_DEVICES], usize) {
    let state = SHELLHW_STATE.lock();
    let mut result = [const { DeviceInfo::empty() }; MAX_DEVICES];
    let mut count = 0;

    for device in state.devices.iter() {
        if device.valid && count < MAX_DEVICES {
            result[count] = device.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get device by drive letter
pub fn get_device_by_drive(drive_letter: u8) -> Option<DeviceInfo> {
    let state = SHELLHW_STATE.lock();

    state.devices.iter()
        .find(|d| d.valid && d.drive_letter == drive_letter)
        .cloned()
}

/// Enumerate AutoPlay handlers
pub fn enum_handlers() -> ([AutoPlayHandler; MAX_HANDLERS], usize) {
    let state = SHELLHW_STATE.lock();
    let mut result = [const { AutoPlayHandler::empty() }; MAX_HANDLERS];
    let mut count = 0;

    for handler in state.handlers.iter() {
        if handler.valid && count < MAX_HANDLERS {
            result[count] = handler.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Set AutoPlay enabled globally
pub fn set_autoplay_enabled(enabled: bool) {
    let mut state = SHELLHW_STATE.lock();
    state.autoplay_enabled = enabled;
}

/// Set AutoPlay enabled for device
pub fn set_device_autoplay(device_id: u32, enabled: bool) -> Result<(), u32> {
    let mut state = SHELLHW_STATE.lock();

    let idx = device_id as usize;
    if idx >= MAX_DEVICES || !state.devices[idx].valid {
        return Err(0x80070057);
    }

    state.devices[idx].autoplay_enabled = enabled;
    Ok(())
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64) {
    (
        TOTAL_EVENTS.load(Ordering::SeqCst),
        AUTOPLAY_TRIGGERED.load(Ordering::SeqCst),
        DEVICES_DETECTED.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = SHELLHW_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = SHELLHW_STATE.lock();
    state.running = false;

    // Clear events
    for event in state.events.iter_mut() {
        event.valid = false;
    }
    state.event_count = 0;

    crate::serial_println!("[SHELLHW] Shell Hardware Detection service stopped");
}
