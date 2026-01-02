//! Telephony Service (TAPI)
//!
//! The Telephony service provides support for the Telephony Application
//! Programming Interface (TAPI) which allows applications to control
//! modems, PBX systems, and other telephony devices.
//!
//! # Features
//!
//! - **Line Device Management**: Manage phone lines and channels
//! - **Call Control**: Make, answer, transfer, conference calls
//! - **Media Control**: Access call audio streams
//! - **Address Management**: Handle phone numbers and addressing
//! - **Provider Management**: Load telephony service providers
//!
//! # TAPI Versions
//!
//! - TAPI 2.x: Traditional Win32 API
//! - TAPI 3.x: COM-based API with media streaming
//!
//! # Providers
//!
//! - Unimodem: Standard modem support
//! - NDIS WAN: WAN miniport drivers
//! - H.323: IP telephony
//! - SIP: Session Initiation Protocol

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum line devices
const MAX_LINES: usize = 16;

/// Maximum phone devices
const MAX_PHONES: usize = 8;

/// Maximum service providers
const MAX_PROVIDERS: usize = 8;

/// Maximum calls
const MAX_CALLS: usize = 32;

/// Maximum addresses per line
const MAX_ADDRESSES: usize = 8;

/// Maximum device name length
const MAX_DEVICE_NAME: usize = 64;

/// Maximum provider name length
const MAX_PROVIDER_NAME: usize = 64;

/// Maximum address length
const MAX_ADDRESS: usize = 64;

/// Line device capabilities
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineDevCaps {
    /// Voice calls
    Voice = 0x0001,
    /// Data calls
    Data = 0x0002,
    /// Fax calls
    Fax = 0x0004,
    /// ISDN support
    Isdn = 0x0008,
    /// Digital
    Digital = 0x0010,
    /// Interactive voice
    Interactive = 0x0020,
}

/// Call state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// Idle (no call)
    Idle = 0,
    /// Offering (incoming call)
    Offering = 1,
    /// Accepted (answered but not connected)
    Accepted = 2,
    /// Dialtone available
    Dialtone = 3,
    /// Dialing in progress
    Dialing = 4,
    /// Ringback (outgoing call ringing)
    Ringback = 5,
    /// Busy signal
    Busy = 6,
    /// Connected (call in progress)
    Connected = 7,
    /// On hold
    OnHold = 8,
    /// Proceeding (call being established)
    Proceeding = 9,
    /// Disconnected
    Disconnected = 10,
    /// Special info (recording)
    SpecialInfo = 11,
}

impl CallState {
    const fn empty() -> Self {
        CallState::Idle
    }
}

/// Line state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineState {
    /// Line is idle
    Idle = 0,
    /// Line is in service
    InService = 1,
    /// Line is out of service
    OutOfService = 2,
    /// Line is in maintenance mode
    Maintenance = 3,
    /// Line is ringing
    Ringing = 4,
    /// Line has message waiting
    MessageWait = 5,
}

impl LineState {
    const fn empty() -> Self {
        LineState::Idle
    }
}

/// Line device information
#[repr(C)]
#[derive(Clone)]
pub struct LineDevice {
    /// Device ID
    pub device_id: u32,
    /// Device name
    pub name: [u8; MAX_DEVICE_NAME],
    /// Provider ID
    pub provider_id: u32,
    /// Permanent line ID
    pub permanent_line_id: u32,
    /// Device capabilities
    pub caps: u32,
    /// Current state
    pub state: LineState,
    /// Number of addresses
    pub num_addresses: u32,
    /// Addresses
    pub addresses: [[u8; MAX_ADDRESS]; MAX_ADDRESSES],
    /// Max calls on line
    pub max_num_calls: u32,
    /// Current active calls
    pub active_calls: u32,
    /// Media modes supported
    pub media_modes: u32,
    /// Bearer modes supported
    pub bearer_modes: u32,
    /// Line is open
    pub is_open: bool,
    /// Entry is valid
    pub valid: bool,
}

impl LineDevice {
    const fn empty() -> Self {
        LineDevice {
            device_id: 0,
            name: [0; MAX_DEVICE_NAME],
            provider_id: 0,
            permanent_line_id: 0,
            caps: 0,
            state: LineState::empty(),
            num_addresses: 0,
            addresses: [[0; MAX_ADDRESS]; MAX_ADDRESSES],
            max_num_calls: 1,
            active_calls: 0,
            media_modes: 0,
            bearer_modes: 0,
            is_open: false,
            valid: false,
        }
    }
}

/// Phone device information
#[repr(C)]
#[derive(Clone)]
pub struct PhoneDevice {
    /// Device ID
    pub device_id: u32,
    /// Device name
    pub name: [u8; MAX_DEVICE_NAME],
    /// Provider ID
    pub provider_id: u32,
    /// Permanent phone ID
    pub permanent_phone_id: u32,
    /// Phone state
    pub state: u32,
    /// Handset hookswitch mode
    pub handset_hookswitch: u32,
    /// Speaker hookswitch mode
    pub speaker_hookswitch: u32,
    /// Headset hookswitch mode
    pub headset_hookswitch: u32,
    /// Display text
    pub display: [u8; 64],
    /// Phone is open
    pub is_open: bool,
    /// Entry is valid
    pub valid: bool,
}

impl PhoneDevice {
    const fn empty() -> Self {
        PhoneDevice {
            device_id: 0,
            name: [0; MAX_DEVICE_NAME],
            provider_id: 0,
            permanent_phone_id: 0,
            state: 0,
            handset_hookswitch: 0,
            speaker_hookswitch: 0,
            headset_hookswitch: 0,
            display: [0; 64],
            is_open: false,
            valid: false,
        }
    }
}

/// Call information
#[repr(C)]
#[derive(Clone)]
pub struct CallInfo {
    /// Call handle
    pub call_handle: u64,
    /// Line device ID
    pub line_id: u32,
    /// Address index
    pub address_id: u32,
    /// Call state
    pub state: CallState,
    /// Called party ID
    pub called_id: [u8; MAX_ADDRESS],
    /// Calling party ID
    pub caller_id: [u8; MAX_ADDRESS],
    /// Call origin (inbound/outbound)
    pub origin: u32,
    /// Call reason
    pub reason: u32,
    /// Media mode
    pub media_mode: u32,
    /// Call start time
    pub start_time: i64,
    /// Connect time
    pub connect_time: i64,
    /// Disconnect time
    pub disconnect_time: i64,
    /// Entry is valid
    pub valid: bool,
}

impl CallInfo {
    const fn empty() -> Self {
        CallInfo {
            call_handle: 0,
            line_id: 0,
            address_id: 0,
            state: CallState::empty(),
            called_id: [0; MAX_ADDRESS],
            caller_id: [0; MAX_ADDRESS],
            origin: 0,
            reason: 0,
            media_mode: 0,
            start_time: 0,
            connect_time: 0,
            disconnect_time: 0,
            valid: false,
        }
    }
}

/// Telephony Service Provider (TSP)
#[repr(C)]
#[derive(Clone)]
pub struct ServiceProvider {
    /// Provider ID
    pub provider_id: u32,
    /// Provider name
    pub name: [u8; MAX_PROVIDER_NAME],
    /// Provider filename
    pub filename: [u8; MAX_PROVIDER_NAME],
    /// Version
    pub version: u32,
    /// Number of line devices
    pub num_lines: u32,
    /// Number of phone devices
    pub num_phones: u32,
    /// Is loaded
    pub loaded: bool,
    /// Entry is valid
    pub valid: bool,
}

impl ServiceProvider {
    const fn empty() -> Self {
        ServiceProvider {
            provider_id: 0,
            name: [0; MAX_PROVIDER_NAME],
            filename: [0; MAX_PROVIDER_NAME],
            version: 0x00020000, // TAPI 2.0
            num_lines: 0,
            num_phones: 0,
            loaded: false,
            valid: false,
        }
    }
}

/// Media modes
pub mod media_mode {
    pub const UNKNOWN: u32 = 0x00000002;
    pub const INTERACTIVEVOICE: u32 = 0x00000004;
    pub const AUTOMATEDVOICE: u32 = 0x00000008;
    pub const DATAMODEM: u32 = 0x00000010;
    pub const G3FAX: u32 = 0x00000020;
    pub const TDD: u32 = 0x00000040;
    pub const G4FAX: u32 = 0x00000080;
    pub const DIGITALDATA: u32 = 0x00000100;
    pub const TELETEX: u32 = 0x00000200;
    pub const VIDEOTEX: u32 = 0x00000400;
    pub const TELEX: u32 = 0x00000800;
    pub const MIXED: u32 = 0x00001000;
    pub const ADSI: u32 = 0x00002000;
    pub const VOICEVIEW: u32 = 0x00004000;
}

/// Bearer modes
pub mod bearer_mode {
    pub const VOICE: u32 = 0x00000001;
    pub const SPEECH: u32 = 0x00000002;
    pub const MULTIUSE: u32 = 0x00000004;
    pub const DATA: u32 = 0x00000008;
    pub const ALTSPEECHDATA: u32 = 0x00000010;
    pub const NONCALLSIGNALING: u32 = 0x00000020;
    pub const PASSTHROUGH: u32 = 0x00000040;
    pub const RESTRICTEDDATA: u32 = 0x00000080;
}

/// Telephony service state
pub struct TelephonyState {
    /// Service is running
    pub running: bool,
    /// TAPI version
    pub version: u32,
    /// Line devices
    pub lines: [LineDevice; MAX_LINES],
    /// Line count
    pub line_count: usize,
    /// Phone devices
    pub phones: [PhoneDevice; MAX_PHONES],
    /// Phone count
    pub phone_count: usize,
    /// Service providers
    pub providers: [ServiceProvider; MAX_PROVIDERS],
    /// Provider count
    pub provider_count: usize,
    /// Active calls
    pub calls: [CallInfo; MAX_CALLS],
    /// Call count
    pub call_count: usize,
    /// Next call handle
    pub next_call_handle: u64,
    /// Service start time
    pub start_time: i64,
}

impl TelephonyState {
    const fn new() -> Self {
        TelephonyState {
            running: false,
            version: 0x00020002, // TAPI 2.2
            lines: [const { LineDevice::empty() }; MAX_LINES],
            line_count: 0,
            phones: [const { PhoneDevice::empty() }; MAX_PHONES],
            phone_count: 0,
            providers: [const { ServiceProvider::empty() }; MAX_PROVIDERS],
            provider_count: 0,
            calls: [const { CallInfo::empty() }; MAX_CALLS],
            call_count: 0,
            next_call_handle: 1,
            start_time: 0,
        }
    }
}

/// Global telephony state
static TELEPHONY_STATE: Mutex<TelephonyState> = Mutex::new(TelephonyState::new());

/// Statistics
static TOTAL_CALLS: AtomicU64 = AtomicU64::new(0);
static SUCCESSFUL_CALLS: AtomicU64 = AtomicU64::new(0);
static FAILED_CALLS: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize Telephony service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = TELEPHONY_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    // Register built-in Unimodem provider
    register_builtin_providers(&mut state);

    crate::serial_println!("[TAPISRV] Telephony service initialized");
}

/// Register built-in service providers
fn register_builtin_providers(state: &mut TelephonyState) {
    // Unimodem Service Provider
    let unimodem_slot = 0;
    state.providers[unimodem_slot].provider_id = 1;
    let unimodem_name = b"Unimodem Service Provider";
    state.providers[unimodem_slot].name[..unimodem_name.len()].copy_from_slice(unimodem_name);
    let unimodem_file = b"unimdm.tsp";
    state.providers[unimodem_slot].filename[..unimodem_file.len()].copy_from_slice(unimodem_file);
    state.providers[unimodem_slot].version = 0x00020000;
    state.providers[unimodem_slot].loaded = true;
    state.providers[unimodem_slot].valid = true;
    state.provider_count = 1;
}

/// Get number of line devices
pub fn get_num_lines() -> u32 {
    let state = TELEPHONY_STATE.lock();
    state.line_count as u32
}

/// Get number of phone devices
pub fn get_num_phones() -> u32 {
    let state = TELEPHONY_STATE.lock();
    state.phone_count as u32
}

/// Register a line device
pub fn register_line(
    name: &[u8],
    provider_id: u32,
    caps: u32,
    media_modes: u32,
) -> Result<u32, u32> {
    let mut state = TELEPHONY_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.lines.iter().position(|l| !l.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let device_id = slot as u32;

    let line = &mut state.lines[slot];
    line.device_id = device_id;

    let name_len = name.len().min(MAX_DEVICE_NAME);
    line.name[..name_len].copy_from_slice(&name[..name_len]);

    line.provider_id = provider_id;
    line.permanent_line_id = device_id + 0x10000;
    line.caps = caps;
    line.media_modes = media_modes;
    line.bearer_modes = bearer_mode::VOICE | bearer_mode::DATA;
    line.state = LineState::InService;
    line.num_addresses = 1;
    line.max_num_calls = 1;
    line.valid = true;

    state.line_count += 1;

    Ok(device_id)
}

/// Unregister a line device
pub fn unregister_line(device_id: u32) -> Result<(), u32> {
    let mut state = TELEPHONY_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = device_id as usize;
    if idx >= MAX_LINES || !state.lines[idx].valid {
        return Err(0x80000013); // LINEERR_BADDEVICEID
    }

    // Check for active calls
    if state.lines[idx].active_calls > 0 {
        return Err(0x80000015); // LINEERR_INUSE
    }

    state.lines[idx].valid = false;
    state.line_count = state.line_count.saturating_sub(1);

    Ok(())
}

/// Open a line device
pub fn line_open(device_id: u32, media_modes: u32) -> Result<u64, u32> {
    let mut state = TELEPHONY_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = device_id as usize;
    if idx >= MAX_LINES || !state.lines[idx].valid {
        return Err(0x80000013); // LINEERR_BADDEVICEID
    }

    if state.lines[idx].is_open {
        return Err(0x80000015); // LINEERR_INUSE
    }

    // Verify media modes are supported
    let supported = state.lines[idx].media_modes;
    if (media_modes & !supported) != 0 {
        return Err(0x80000021); // LINEERR_INVALMEDIAMODE
    }

    state.lines[idx].is_open = true;

    // Return line handle (device_id + 1 to avoid 0)
    Ok((device_id + 1) as u64)
}

/// Close a line device
pub fn line_close(line_handle: u64) -> Result<(), u32> {
    let mut state = TELEPHONY_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let device_id = (line_handle - 1) as usize;
    if device_id >= MAX_LINES || !state.lines[device_id].valid {
        return Err(0x80000011); // LINEERR_INVALLINEHANDLE
    }

    // Drop active calls on this line
    let line_id = device_id as u32;
    for call in state.calls.iter_mut() {
        if call.valid && call.line_id == line_id {
            call.state = CallState::Disconnected;
            call.disconnect_time = crate::rtl::time::rtl_get_system_time();
        }
    }
    state.lines[device_id].active_calls = 0;

    state.lines[device_id].is_open = false;

    Ok(())
}

/// Make a call
pub fn line_make_call(
    line_handle: u64,
    dest_address: &[u8],
) -> Result<u64, u32> {
    let mut state = TELEPHONY_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let device_id = (line_handle - 1) as usize;
    if device_id >= MAX_LINES || !state.lines[device_id].valid {
        return Err(0x80000011); // LINEERR_INVALLINEHANDLE
    }

    if !state.lines[device_id].is_open {
        return Err(0x80000015); // LINEERR_INUSE
    }

    // Check for available call slots
    if state.lines[device_id].active_calls >= state.lines[device_id].max_num_calls {
        return Err(0x80000002); // LINEERR_CALLUNAVAIL
    }

    // Find free call slot
    let call_slot = state.calls.iter().position(|c| !c.valid);
    let call_slot = match call_slot {
        Some(s) => s,
        None => return Err(0x80000004), // LINEERR_NOMEM
    };

    let call_handle = state.next_call_handle;
    state.next_call_handle += 1;

    let now = crate::rtl::time::rtl_get_system_time();

    let call = &mut state.calls[call_slot];
    call.call_handle = call_handle;
    call.line_id = device_id as u32;
    call.address_id = 0;
    call.state = CallState::Dialing;
    call.origin = 1; // Outbound

    let dest_len = dest_address.len().min(MAX_ADDRESS);
    call.called_id[..dest_len].copy_from_slice(&dest_address[..dest_len]);

    call.media_mode = media_mode::INTERACTIVEVOICE;
    call.start_time = now;
    call.connect_time = 0;
    call.disconnect_time = 0;
    call.valid = true;
    // Simulate call progression (in real impl would be async)
    call.state = CallState::Proceeding;

    state.call_count += 1;
    state.lines[device_id].active_calls += 1;

    TOTAL_CALLS.fetch_add(1, Ordering::SeqCst);

    Ok(call_handle)
}

/// Answer a call
pub fn line_answer(call_handle: u64) -> Result<(), u32> {
    let mut state = TELEPHONY_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let call = state.calls.iter_mut().find(|c| c.valid && c.call_handle == call_handle);
    let call = match call {
        Some(c) => c,
        None => return Err(0x80000018), // LINEERR_INVALCALLHANDLE
    };

    if call.state != CallState::Offering {
        return Err(0x80000017); // LINEERR_INVALCALLSTATE
    }

    call.state = CallState::Connected;
    call.connect_time = crate::rtl::time::rtl_get_system_time();

    Ok(())
}

/// Drop (disconnect) a call
pub fn line_drop(call_handle: u64) -> Result<(), u32> {
    let mut state = TELEPHONY_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let call_idx = state.calls.iter().position(|c| c.valid && c.call_handle == call_handle);
    let call_idx = match call_idx {
        Some(idx) => idx,
        None => return Err(0x80000018), // LINEERR_INVALCALLHANDLE
    };

    // Get line_id before modifying call
    let line_id = state.calls[call_idx].line_id as usize;
    let was_connected = state.calls[call_idx].state == CallState::Connected;

    let call = &mut state.calls[call_idx];
    call.state = CallState::Disconnected;
    call.disconnect_time = crate::rtl::time::rtl_get_system_time();

    if was_connected {
        SUCCESSFUL_CALLS.fetch_add(1, Ordering::SeqCst);
    } else {
        FAILED_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    if line_id < MAX_LINES {
        state.lines[line_id].active_calls = state.lines[line_id].active_calls.saturating_sub(1);
    }

    Ok(())
}

/// Deallocate a call
pub fn line_deallocate_call(call_handle: u64) -> Result<(), u32> {
    let mut state = TELEPHONY_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let call = state.calls.iter_mut().find(|c| c.valid && c.call_handle == call_handle);
    let call = match call {
        Some(c) => c,
        None => return Err(0x80000018), // LINEERR_INVALCALLHANDLE
    };

    if call.state != CallState::Idle && call.state != CallState::Disconnected {
        return Err(0x80000017); // LINEERR_INVALCALLSTATE
    }

    call.valid = false;
    state.call_count = state.call_count.saturating_sub(1);

    Ok(())
}

/// Get line device capabilities
pub fn line_get_dev_caps(device_id: u32) -> Option<LineDevice> {
    let state = TELEPHONY_STATE.lock();

    let idx = device_id as usize;
    if idx >= MAX_LINES || !state.lines[idx].valid {
        return None;
    }

    Some(state.lines[idx].clone())
}

/// Get call info
pub fn line_get_call_info(call_handle: u64) -> Option<CallInfo> {
    let state = TELEPHONY_STATE.lock();

    state.calls.iter()
        .find(|c| c.valid && c.call_handle == call_handle)
        .cloned()
}

/// Enumerate line devices
pub fn enum_lines() -> ([LineDevice; MAX_LINES], usize) {
    let state = TELEPHONY_STATE.lock();
    let mut result = [const { LineDevice::empty() }; MAX_LINES];
    let mut count = 0;

    for line in state.lines.iter() {
        if line.valid && count < MAX_LINES {
            result[count] = line.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Enumerate service providers
pub fn enum_providers() -> ([ServiceProvider; MAX_PROVIDERS], usize) {
    let state = TELEPHONY_STATE.lock();
    let mut result = [const { ServiceProvider::empty() }; MAX_PROVIDERS];
    let mut count = 0;

    for provider in state.providers.iter() {
        if provider.valid && count < MAX_PROVIDERS {
            result[count] = provider.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64) {
    (
        TOTAL_CALLS.load(Ordering::SeqCst),
        SUCCESSFUL_CALLS.load(Ordering::SeqCst),
        FAILED_CALLS.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = TELEPHONY_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = TELEPHONY_STATE.lock();
    state.running = false;

    // Drop all active calls
    for call in state.calls.iter_mut() {
        if call.valid {
            call.state = CallState::Disconnected;
            call.disconnect_time = crate::rtl::time::rtl_get_system_time();
        }
    }

    // Close all lines
    for line in state.lines.iter_mut() {
        if line.valid {
            line.is_open = false;
            line.active_calls = 0;
        }
    }

    crate::serial_println!("[TAPISRV] Telephony service stopped");
}
