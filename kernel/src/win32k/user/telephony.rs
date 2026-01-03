//! Telephony (TAPI) Management implementation
//!
//! Provides configuration and management of telephony service providers,
//! lines, addresses, and dialing rules.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use crate::win32k::user::UserHandle;

/// Local type alias for window handles
type HWND = UserHandle;

/// Maximum providers
const MAX_PROVIDERS: usize = 16;

/// Maximum lines per provider
const MAX_LINES: usize = 32;

/// Maximum locations
const MAX_LOCATIONS: usize = 16;

/// Maximum calling cards
const MAX_CARDS: usize = 32;

/// Maximum area codes
const MAX_AREA_CODES: usize = 64;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum phone number length
const MAX_PHONE_LEN: usize = 48;

/// Line type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LineType {
    /// Analog line
    Analog = 0,
    /// ISDN line
    Isdn = 1,
    /// VoIP line
    Voip = 2,
    /// Cellular
    Cellular = 3,
    /// Virtual line
    Virtual = 4,
}

impl LineType {
    /// Create new line type
    pub const fn new() -> Self {
        Self::Analog
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Analog => "Analog",
            Self::Isdn => "ISDN",
            Self::Voip => "VoIP",
            Self::Cellular => "Cellular",
            Self::Virtual => "Virtual",
        }
    }
}

impl Default for LineType {
    fn default() -> Self {
        Self::new()
    }
}

/// Line status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LineStatus {
    /// Line is idle
    Idle = 0,
    /// Line is in use
    InUse = 1,
    /// Line is ringing
    Ringing = 2,
    /// Line is connected
    Connected = 3,
    /// Line is on hold
    OnHold = 4,
    /// Line is disconnected
    Disconnected = 5,
    /// Line has error
    Error = 6,
    /// Line is unavailable
    Unavailable = 7,
}

impl LineStatus {
    /// Create new status
    pub const fn new() -> Self {
        Self::Idle
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::InUse => "In Use",
            Self::Ringing => "Ringing",
            Self::Connected => "Connected",
            Self::OnHold => "On Hold",
            Self::Disconnected => "Disconnected",
            Self::Error => "Error",
            Self::Unavailable => "Unavailable",
        }
    }
}

impl Default for LineStatus {
    fn default() -> Self {
        Self::new()
    }
}

// Media mode capabilities
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MediaModes: u32 {
        /// Unknown media mode
        const UNKNOWN = 0x00000002;
        /// Interactive voice
        const INTERACTIVE_VOICE = 0x00000004;
        /// Automated voice
        const AUTOMATED_VOICE = 0x00000008;
        /// Data modem
        const DATAMODEM = 0x00000010;
        /// G3 fax
        const G3FAX = 0x00000020;
        /// G4 fax
        const G4FAX = 0x00000080;
        /// TDD (Telecommunications Device for the Deaf)
        const TDD = 0x00000100;
        /// Digital data
        const DIGITALDATA = 0x00000200;
        /// TELETEX
        const TELETEX = 0x00000400;
        /// VIDEOTEX
        const VIDEOTEX = 0x00000800;
        /// Video telephony
        const VIDEO = 0x00008000;
        /// VoIP
        const VOIP = 0x00800000;
    }
}

impl Default for MediaModes {
    fn default() -> Self {
        Self::INTERACTIVE_VOICE
    }
}

// Bearer mode capabilities
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BearerModes: u32 {
        /// Voice
        const VOICE = 0x00000001;
        /// Speech
        const SPEECH = 0x00000002;
        /// Data
        const DATA = 0x00000010;
        /// Alternate speech/data
        const ALTSPEECHDATA = 0x00000020;
        /// Non-call signaling
        const NONCALLSIGNALING = 0x00000040;
        /// Pass-through
        const PASSTHROUGH = 0x00000080;
    }
}

impl Default for BearerModes {
    fn default() -> Self {
        Self::VOICE
    }
}

/// Telephony line
#[derive(Clone)]
pub struct TapiLine {
    /// Line ID
    pub line_id: u32,
    /// Provider ID
    pub provider_id: u32,
    /// Line name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Line type
    pub line_type: LineType,
    /// Current status
    pub status: LineStatus,
    /// Permanent line ID (hardware ID)
    pub permanent_id: u32,
    /// Number of addresses
    pub num_addresses: u32,
    /// Media modes supported
    pub media_modes: MediaModes,
    /// Bearer modes supported
    pub bearer_modes: BearerModes,
    /// Max data rate
    pub max_rate: u32,
    /// Can do caller ID
    pub caller_id: bool,
    /// Can do call waiting
    pub call_waiting: bool,
    /// Can do three-way calling
    pub three_way: bool,
    /// Can do transfer
    pub transfer: bool,
    /// In use flag
    pub in_use: bool,
}

impl TapiLine {
    /// Create new line
    pub const fn new() -> Self {
        Self {
            line_id: 0,
            provider_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            line_type: LineType::Analog,
            status: LineStatus::Idle,
            permanent_id: 0,
            num_addresses: 1,
            media_modes: MediaModes::INTERACTIVE_VOICE,
            bearer_modes: BearerModes::VOICE,
            max_rate: 0,
            caller_id: false,
            call_waiting: false,
            three_way: false,
            transfer: false,
            in_use: false,
        }
    }

    /// Set line name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

impl Default for TapiLine {
    fn default() -> Self {
        Self::new()
    }
}

/// Telephony Service Provider
#[derive(Clone)]
pub struct TapiProvider {
    /// Provider ID
    pub provider_id: u32,
    /// Provider name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// DLL file name
    pub dll_name: [u8; MAX_NAME_LEN],
    /// DLL name length
    pub dll_len: usize,
    /// Is enabled
    pub enabled: bool,
    /// Is removable
    pub removable: bool,
    /// Reserved
    pub reserved: [u8; 2],
    /// Lines
    pub lines: [TapiLine; MAX_LINES],
    /// Line count
    pub line_count: usize,
    /// Provider version
    pub version: u32,
    /// In use flag
    pub in_use: bool,
}

impl TapiProvider {
    /// Create new provider
    pub const fn new() -> Self {
        Self {
            provider_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            dll_name: [0; MAX_NAME_LEN],
            dll_len: 0,
            enabled: true,
            removable: true,
            reserved: [0; 2],
            lines: [const { TapiLine::new() }; MAX_LINES],
            line_count: 0,
            version: 0x00030001, // TAPI 3.1
            in_use: false,
        }
    }

    /// Set provider name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Set DLL name
    pub fn set_dll(&mut self, dll: &[u8]) {
        let len = dll.len().min(MAX_NAME_LEN);
        self.dll_name[..len].copy_from_slice(&dll[..len]);
        self.dll_len = len;
    }
}

impl Default for TapiProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Dialing location
#[derive(Clone)]
pub struct DialingLocation {
    /// Location ID
    pub location_id: u32,
    /// Location name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Country code
    pub country_code: u32,
    /// Area/city code
    pub area_code: [u8; 16],
    /// Area code length
    pub area_len: usize,
    /// Local access code (to get outside line)
    pub local_access: [u8; 16],
    /// Local access length
    pub local_len: usize,
    /// Long distance access code
    pub long_access: [u8; 16],
    /// Long distance length
    pub long_len: usize,
    /// International access code
    pub intl_access: [u8; 16],
    /// International length
    pub intl_len: usize,
    /// Disable call waiting code
    pub disable_cw: [u8; 16],
    /// Disable CW length
    pub cw_len: usize,
    /// Use tone dialing
    pub tone_dial: bool,
    /// Has call waiting
    pub has_call_waiting: bool,
    /// Reserved
    pub reserved: [u8; 2],
    /// In use flag
    pub in_use: bool,
}

impl DialingLocation {
    /// Create new location
    pub const fn new() -> Self {
        Self {
            location_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            country_code: 1, // USA
            area_code: [0; 16],
            area_len: 0,
            local_access: [0; 16],
            local_len: 0,
            long_access: [0; 16],
            long_len: 0,
            intl_access: [0; 16],
            intl_len: 0,
            disable_cw: [0; 16],
            cw_len: 0,
            tone_dial: true,
            has_call_waiting: false,
            reserved: [0; 2],
            in_use: false,
        }
    }

    /// Set location name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Set area code
    pub fn set_area_code(&mut self, code: &[u8]) {
        let len = code.len().min(16);
        self.area_code[..len].copy_from_slice(&code[..len]);
        self.area_len = len;
    }
}

impl Default for DialingLocation {
    fn default() -> Self {
        Self::new()
    }
}

/// Calling card
#[derive(Clone)]
pub struct CallingCard {
    /// Card ID
    pub card_id: u32,
    /// Card name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Card number
    pub number: [u8; 32],
    /// Number length
    pub number_len: usize,
    /// PIN
    pub pin: [u8; 16],
    /// PIN length
    pub pin_len: usize,
    /// Local dialing rule
    pub local_rule: [u8; MAX_PHONE_LEN],
    /// Local rule length
    pub local_len: usize,
    /// Long distance dialing rule
    pub long_rule: [u8; MAX_PHONE_LEN],
    /// Long distance rule length
    pub long_len: usize,
    /// International dialing rule
    pub intl_rule: [u8; MAX_PHONE_LEN],
    /// International rule length
    pub intl_len: usize,
    /// In use flag
    pub in_use: bool,
}

impl CallingCard {
    /// Create new calling card
    pub const fn new() -> Self {
        Self {
            card_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            number: [0; 32],
            number_len: 0,
            pin: [0; 16],
            pin_len: 0,
            local_rule: [0; MAX_PHONE_LEN],
            local_len: 0,
            long_rule: [0; MAX_PHONE_LEN],
            long_len: 0,
            intl_rule: [0; MAX_PHONE_LEN],
            intl_len: 0,
            in_use: false,
        }
    }

    /// Set card name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

impl Default for CallingCard {
    fn default() -> Self {
        Self::new()
    }
}

/// Area code rule
#[derive(Clone)]
pub struct AreaCodeRule {
    /// Rule ID
    pub rule_id: u32,
    /// Area code this rule applies to
    pub area_code: [u8; 16],
    /// Area code length
    pub area_len: usize,
    /// Prefixes (first digits after area code)
    pub prefixes: [u8; 32],
    /// Prefixes length
    pub prefix_len: usize,
    /// Dial area code
    pub dial_area_code: bool,
    /// Dial as long distance (1 prefix)
    pub dial_1: bool,
    /// Reserved
    pub reserved: [u8; 2],
    /// Location ID this rule belongs to
    pub location_id: u32,
    /// In use flag
    pub in_use: bool,
}

impl AreaCodeRule {
    /// Create new rule
    pub const fn new() -> Self {
        Self {
            rule_id: 0,
            area_code: [0; 16],
            area_len: 0,
            prefixes: [0; 32],
            prefix_len: 0,
            dial_area_code: true,
            dial_1: false,
            reserved: [0; 2],
            location_id: 0,
            in_use: false,
        }
    }

    /// Set area code
    pub fn set_area_code(&mut self, code: &[u8]) {
        let len = code.len().min(16);
        self.area_code[..len].copy_from_slice(&code[..len]);
        self.area_len = len;
    }
}

impl Default for AreaCodeRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Telephony state
pub struct TelephonyState {
    /// Providers
    pub providers: [TapiProvider; MAX_PROVIDERS],
    /// Provider count
    pub provider_count: usize,
    /// Locations
    pub locations: [DialingLocation; MAX_LOCATIONS],
    /// Location count
    pub location_count: usize,
    /// Current location ID
    pub current_location: u32,
    /// Calling cards
    pub cards: [CallingCard; MAX_CARDS],
    /// Card count
    pub card_count: usize,
    /// Area code rules
    pub area_rules: [AreaCodeRule; MAX_AREA_CODES],
    /// Area rule count
    pub rule_count: usize,
    /// Next ID
    pub next_id: u32,
    /// TAPI version
    pub tapi_version: u32,
}

impl TelephonyState {
    /// Create new state
    pub const fn new() -> Self {
        Self {
            providers: [const { TapiProvider::new() }; MAX_PROVIDERS],
            provider_count: 0,
            locations: [const { DialingLocation::new() }; MAX_LOCATIONS],
            location_count: 0,
            current_location: 0,
            cards: [const { CallingCard::new() }; MAX_CARDS],
            card_count: 0,
            area_rules: [const { AreaCodeRule::new() }; MAX_AREA_CODES],
            rule_count: 0,
            next_id: 1,
            tapi_version: 0x00030001,
        }
    }

    /// Find provider by ID
    pub fn find_provider(&self, provider_id: u32) -> Option<usize> {
        for (i, prov) in self.providers.iter().enumerate() {
            if prov.in_use && prov.provider_id == provider_id {
                return Some(i);
            }
        }
        None
    }

    /// Find location by ID
    pub fn find_location(&self, location_id: u32) -> Option<usize> {
        for (i, loc) in self.locations.iter().enumerate() {
            if loc.in_use && loc.location_id == location_id {
                return Some(i);
            }
        }
        None
    }
}

impl Default for TelephonyState {
    fn default() -> Self {
        Self::new()
    }
}

/// Global state
static TAPI_STATE: SpinLock<TelephonyState> = SpinLock::new(TelephonyState::new());

/// Initialization flag
static TAPI_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Statistics
static TAPI_OPERATION_COUNT: AtomicU32 = AtomicU32::new(0);

/// Error codes
pub mod error {
    pub const SUCCESS: u32 = 0;
    pub const NOT_INITIALIZED: u32 = 0x1A010001;
    pub const PROVIDER_NOT_FOUND: u32 = 0x1A010002;
    pub const LINE_NOT_FOUND: u32 = 0x1A010003;
    pub const LOCATION_NOT_FOUND: u32 = 0x1A010004;
    pub const ALREADY_EXISTS: u32 = 0x1A010005;
    pub const NO_MORE_OBJECTS: u32 = 0x1A010006;
    pub const INVALID_PARAMETER: u32 = 0x1A010007;
    pub const LINE_BUSY: u32 = 0x1A010008;
}

/// Initialize Telephony
pub fn init() {
    if TAPI_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = TAPI_STATE.lock();

    // Reserve IDs first
    let provider_id = state.next_id;
    let line_id = state.next_id + 1;
    let location_id = state.next_id + 2;
    state.next_id += 3;

    // Create default TAPI provider (Unimodem)
    {
        let provider = &mut state.providers[0];
        provider.in_use = true;
        provider.provider_id = provider_id;
        provider.set_name(b"Unimodem 5 Service Provider");
        provider.set_dll(b"unimdm.tsp");
        provider.enabled = true;

        // Create default modem line
        let line = &mut provider.lines[0];
        line.in_use = true;
        line.line_id = line_id;
        line.provider_id = provider_id;
        line.set_name(b"Standard Modem");
        line.line_type = LineType::Analog;
        line.status = LineStatus::Idle;
        line.num_addresses = 1;
        line.media_modes = MediaModes::DATAMODEM | MediaModes::G3FAX | MediaModes::INTERACTIVE_VOICE;
        line.bearer_modes = BearerModes::VOICE | BearerModes::DATA;
        line.max_rate = 56000;
        line.caller_id = true;

        provider.line_count = 1;
    }

    state.provider_count = 1;

    // Create default location
    {
        let location = &mut state.locations[0];
        location.in_use = true;
        location.location_id = location_id;
        location.set_name(b"My Location");
        location.country_code = 1;
        location.set_area_code(b"555");
        location.tone_dial = true;
    }

    state.location_count = 1;
    state.current_location = location_id;
}

/// Add a provider
pub fn add_provider(name: &[u8], dll: &[u8]) -> Result<u32, u32> {
    if !TAPI_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = TAPI_STATE.lock();

    // Find free slot
    let mut slot_idx = None;
    for (i, prov) in state.providers.iter().enumerate() {
        if !prov.in_use {
            slot_idx = Some(i);
            break;
        }
    }

    let idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::NO_MORE_OBJECTS),
    };

    let provider_id = state.next_id;
    state.next_id += 1;

    let provider = &mut state.providers[idx];
    provider.in_use = true;
    provider.provider_id = provider_id;
    provider.set_name(name);
    provider.set_dll(dll);
    provider.enabled = true;

    state.provider_count += 1;
    TAPI_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(provider_id)
}

/// Remove a provider
pub fn remove_provider(provider_id: u32) -> Result<(), u32> {
    if !TAPI_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = TAPI_STATE.lock();

    let idx = match state.find_provider(provider_id) {
        Some(i) => i,
        None => return Err(error::PROVIDER_NOT_FOUND),
    };

    if !state.providers[idx].removable {
        return Err(error::INVALID_PARAMETER);
    }

    state.providers[idx].in_use = false;
    state.provider_count = state.provider_count.saturating_sub(1);

    TAPI_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Add a location
pub fn add_location(name: &[u8], country_code: u32, area_code: &[u8]) -> Result<u32, u32> {
    if !TAPI_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = TAPI_STATE.lock();

    // Find free slot
    let mut slot_idx = None;
    for (i, loc) in state.locations.iter().enumerate() {
        if !loc.in_use {
            slot_idx = Some(i);
            break;
        }
    }

    let idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::NO_MORE_OBJECTS),
    };

    let location_id = state.next_id;
    state.next_id += 1;

    let location = &mut state.locations[idx];
    location.in_use = true;
    location.location_id = location_id;
    location.set_name(name);
    location.country_code = country_code;
    location.set_area_code(area_code);
    location.tone_dial = true;

    state.location_count += 1;
    TAPI_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(location_id)
}

/// Set current location
pub fn set_current_location(location_id: u32) -> Result<(), u32> {
    if !TAPI_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = TAPI_STATE.lock();

    if state.find_location(location_id).is_none() {
        return Err(error::LOCATION_NOT_FOUND);
    }

    state.current_location = location_id;

    TAPI_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Get provider count
pub fn get_provider_count() -> usize {
    if !TAPI_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = TAPI_STATE.lock();
    state.provider_count
}

/// Get line count
pub fn get_line_count() -> usize {
    if !TAPI_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = TAPI_STATE.lock();
    state.providers.iter().filter(|p| p.in_use).map(|p| p.line_count).sum()
}

/// Get location count
pub fn get_location_count() -> usize {
    if !TAPI_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = TAPI_STATE.lock();
    state.location_count
}

/// Create Telephony dialog
pub fn create_telephony_dialog(parent: HWND) -> HWND {
    if !TAPI_INITIALIZED.load(Ordering::SeqCst) {
        init();
    }

    let id = 0x1A710000u32;
    let _parent = parent;

    UserHandle::from_raw(id)
}

/// Dialog messages
pub mod messages {
    pub const TAPI_REFRESH: u32 = 0x0880;
    pub const TAPI_ADD_PROVIDER: u32 = 0x0881;
    pub const TAPI_REMOVE_PROVIDER: u32 = 0x0882;
    pub const TAPI_CONFIGURE_PROVIDER: u32 = 0x0883;
    pub const TAPI_ADD_LOCATION: u32 = 0x0884;
    pub const TAPI_EDIT_LOCATION: u32 = 0x0885;
    pub const TAPI_DELETE_LOCATION: u32 = 0x0886;
    pub const TAPI_CALLING_CARD: u32 = 0x0887;
    pub const TAPI_AREA_RULES: u32 = 0x0888;
}

/// Get statistics
pub fn get_statistics() -> (usize, usize, usize, u32) {
    let state = TAPI_STATE.lock();
    let lines: usize = state.providers.iter().filter(|p| p.in_use).map(|p| p.line_count).sum();
    let op_count = TAPI_OPERATION_COUNT.load(Ordering::Relaxed);
    (state.provider_count, lines, state.location_count, op_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telephony_init() {
        init();
        assert!(TAPI_INITIALIZED.load(Ordering::SeqCst));
    }

    #[test]
    fn test_line_type() {
        assert_eq!(LineType::Isdn.display_name(), "ISDN");
    }

    #[test]
    fn test_line_status() {
        assert_eq!(LineStatus::Ringing.display_name(), "Ringing");
    }
}
