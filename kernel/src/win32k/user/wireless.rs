//! Wireless Network Settings
//!
//! Implements wireless network configuration following Windows Server 2003.
//! Provides 802.11 wireless network management, security settings, and profiles.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - Wireless Zero Configuration (WZC) service
//! - 802.11 wireless networking
//! - WEP/WPA security protocols

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum wireless networks to track
const MAX_NETWORKS: usize = 32;

/// Maximum wireless profiles
const MAX_PROFILES: usize = 16;

/// Maximum SSID length
const MAX_SSID: usize = 32;

/// Maximum passphrase length
const MAX_PASSPHRASE: usize = 64;

/// Maximum profile name length
const MAX_PROFILE_NAME: usize = 64;

/// MAC address length
const MAC_LEN: usize = 6;

// ============================================================================
// Authentication Type
// ============================================================================

/// Wireless authentication type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthType {
    /// Open (no authentication)
    #[default]
    Open = 0,
    /// Shared key authentication
    Shared = 1,
    /// WEP authentication
    Wep = 2,
    /// WPA Personal (WPA-PSK)
    WpaPsk = 3,
    /// WPA Enterprise (WPA-EAP)
    WpaEap = 4,
    /// WPA2 Personal (WPA2-PSK)
    Wpa2Psk = 5,
    /// WPA2 Enterprise (WPA2-EAP)
    Wpa2Eap = 6,
}

impl AuthType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthType::Open => "Open",
            AuthType::Shared => "Shared",
            AuthType::Wep => "WEP",
            AuthType::WpaPsk => "WPA-PSK",
            AuthType::WpaEap => "WPA-EAP",
            AuthType::Wpa2Psk => "WPA2-PSK",
            AuthType::Wpa2Eap => "WPA2-EAP",
        }
    }
}

// ============================================================================
// Encryption Type
// ============================================================================

/// Wireless encryption type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncryptionType {
    /// No encryption
    #[default]
    None = 0,
    /// WEP (40-bit or 104-bit)
    Wep = 1,
    /// TKIP (used with WPA)
    Tkip = 2,
    /// AES/CCMP (used with WPA2)
    Aes = 3,
}

impl EncryptionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EncryptionType::None => "None",
            EncryptionType::Wep => "WEP",
            EncryptionType::Tkip => "TKIP",
            EncryptionType::Aes => "AES",
        }
    }
}

// ============================================================================
// Network Type
// ============================================================================

/// Wireless network type (BSS type)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkType {
    /// Infrastructure (access point)
    #[default]
    Infrastructure = 0,
    /// Ad-hoc (peer-to-peer)
    AdHoc = 1,
    /// Any type
    Any = 2,
}

// ============================================================================
// Signal Strength
// ============================================================================

/// Signal strength level
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignalStrength {
    /// No signal
    #[default]
    None = 0,
    /// Very weak (1 bar)
    VeryWeak = 1,
    /// Weak (2 bars)
    Weak = 2,
    /// Fair (3 bars)
    Fair = 3,
    /// Good (4 bars)
    Good = 4,
    /// Excellent (5 bars)
    Excellent = 5,
}

impl SignalStrength {
    pub fn from_rssi(rssi: i32) -> Self {
        // RSSI typically ranges from -100 dBm (weak) to -30 dBm (strong)
        if rssi >= -50 {
            SignalStrength::Excellent
        } else if rssi >= -60 {
            SignalStrength::Good
        } else if rssi >= -70 {
            SignalStrength::Fair
        } else if rssi >= -80 {
            SignalStrength::Weak
        } else if rssi >= -90 {
            SignalStrength::VeryWeak
        } else {
            SignalStrength::None
        }
    }
}

// ============================================================================
// Wireless Network
// ============================================================================

/// Discovered wireless network
#[derive(Debug, Clone, Copy)]
pub struct WirelessNetwork {
    /// SSID (network name)
    pub ssid: [u8; MAX_SSID],
    /// SSID length
    pub ssid_len: usize,
    /// BSSID (access point MAC)
    pub bssid: [u8; MAC_LEN],
    /// Network type
    pub network_type: NetworkType,
    /// Authentication type
    pub auth_type: AuthType,
    /// Encryption type
    pub encryption: EncryptionType,
    /// Signal strength in dBm
    pub rssi: i32,
    /// Channel number
    pub channel: u8,
    /// Is network secured
    pub is_secured: bool,
    /// Is network hidden (non-broadcast)
    pub is_hidden: bool,
    /// Last seen timestamp
    pub last_seen: u64,
}

impl WirelessNetwork {
    pub const fn new() -> Self {
        Self {
            ssid: [0u8; MAX_SSID],
            ssid_len: 0,
            bssid: [0u8; MAC_LEN],
            network_type: NetworkType::Infrastructure,
            auth_type: AuthType::Open,
            encryption: EncryptionType::None,
            rssi: -100,
            channel: 0,
            is_secured: false,
            is_hidden: false,
            last_seen: 0,
        }
    }

    pub fn set_ssid(&mut self, ssid: &[u8]) {
        let len = ssid.len().min(MAX_SSID);
        self.ssid[..len].copy_from_slice(&ssid[..len]);
        self.ssid_len = len;
    }

    pub fn signal_strength(&self) -> SignalStrength {
        SignalStrength::from_rssi(self.rssi)
    }
}

impl Default for WirelessNetwork {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Wireless Profile
// ============================================================================

/// Saved wireless network profile
#[derive(Debug, Clone, Copy)]
pub struct WirelessProfile {
    /// Profile name
    pub name: [u8; MAX_PROFILE_NAME],
    /// Name length
    pub name_len: usize,
    /// SSID
    pub ssid: [u8; MAX_SSID],
    /// SSID length
    pub ssid_len: usize,
    /// Network type
    pub network_type: NetworkType,
    /// Authentication type
    pub auth_type: AuthType,
    /// Encryption type
    pub encryption: EncryptionType,
    /// Network key/passphrase (stored securely)
    pub key: [u8; MAX_PASSPHRASE],
    /// Key length
    pub key_len: usize,
    /// Key index (for WEP)
    pub key_index: u8,
    /// Auto-connect to this network
    pub auto_connect: bool,
    /// Connect even when SSID is not broadcasting
    pub connect_hidden: bool,
    /// Profile priority (lower = higher priority)
    pub priority: u32,
    /// Profile is valid
    pub is_valid: bool,
}

impl WirelessProfile {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_PROFILE_NAME],
            name_len: 0,
            ssid: [0u8; MAX_SSID],
            ssid_len: 0,
            network_type: NetworkType::Infrastructure,
            auth_type: AuthType::Open,
            encryption: EncryptionType::None,
            key: [0u8; MAX_PASSPHRASE],
            key_len: 0,
            key_index: 0,
            auto_connect: true,
            connect_hidden: false,
            priority: 0,
            is_valid: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_PROFILE_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_ssid(&mut self, ssid: &[u8]) {
        let len = ssid.len().min(MAX_SSID);
        self.ssid[..len].copy_from_slice(&ssid[..len]);
        self.ssid_len = len;
    }

    pub fn set_key(&mut self, key: &[u8]) {
        let len = key.len().min(MAX_PASSPHRASE);
        self.key[..len].copy_from_slice(&key[..len]);
        self.key_len = len;
    }
}

impl Default for WirelessProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Wireless Adapter
// ============================================================================

/// Wireless adapter state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AdapterState {
    /// Adapter not present
    #[default]
    NotPresent = 0,
    /// Adapter disabled
    Disabled = 1,
    /// Not connected
    Disconnected = 2,
    /// Connecting
    Connecting = 3,
    /// Connected
    Connected = 4,
    /// Disconnecting
    Disconnecting = 5,
}

/// Wireless adapter info
#[derive(Debug, Clone, Copy)]
pub struct WirelessAdapter {
    /// Adapter name
    pub name: [u8; 64],
    /// Name length
    pub name_len: usize,
    /// Adapter description
    pub description: [u8; 128],
    /// Description length
    pub desc_len: usize,
    /// MAC address
    pub mac_address: [u8; MAC_LEN],
    /// Current state
    pub state: AdapterState,
    /// Currently connected SSID
    pub connected_ssid: [u8; MAX_SSID],
    /// Connected SSID length
    pub connected_ssid_len: usize,
    /// Connected BSSID
    pub connected_bssid: [u8; MAC_LEN],
    /// Current signal strength
    pub signal_strength: SignalStrength,
    /// Current channel
    pub channel: u8,
    /// Current link speed in Mbps
    pub link_speed: u32,
    /// Supports WPA
    pub supports_wpa: bool,
    /// Supports WPA2
    pub supports_wpa2: bool,
}

impl WirelessAdapter {
    pub const fn new() -> Self {
        Self {
            name: [0u8; 64],
            name_len: 0,
            description: [0u8; 128],
            desc_len: 0,
            mac_address: [0u8; MAC_LEN],
            state: AdapterState::NotPresent,
            connected_ssid: [0u8; MAX_SSID],
            connected_ssid_len: 0,
            connected_bssid: [0u8; MAC_LEN],
            signal_strength: SignalStrength::None,
            channel: 0,
            link_speed: 0,
            supports_wpa: true,
            supports_wpa2: true,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(64);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_description(&mut self, desc: &[u8]) {
        let len = desc.len().min(128);
        self.description[..len].copy_from_slice(&desc[..len]);
        self.desc_len = len;
    }
}

impl Default for WirelessAdapter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Wireless Zero Configuration Settings
// ============================================================================

/// WZC (Wireless Zero Configuration) settings
#[derive(Debug, Clone, Copy)]
pub struct WzcSettings {
    /// Use Windows to configure wireless settings
    pub use_windows_config: bool,
    /// Automatically connect to available networks
    pub auto_connect: bool,
    /// Connect to non-preferred networks
    pub connect_non_preferred: bool,
    /// Automatically connect to ad-hoc networks
    pub auto_connect_adhoc: bool,
    /// Notify when wireless networks are available
    pub notify_available: bool,
}

impl WzcSettings {
    pub const fn new() -> Self {
        Self {
            use_windows_config: true,
            auto_connect: true,
            connect_non_preferred: false,
            auto_connect_adhoc: false,
            notify_available: true,
        }
    }
}

impl Default for WzcSettings {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Wireless State
// ============================================================================

/// Global wireless state
struct WirelessState {
    /// Available networks from last scan
    networks: [WirelessNetwork; MAX_NETWORKS],
    /// Number of available networks
    network_count: usize,
    /// Saved profiles
    profiles: [WirelessProfile; MAX_PROFILES],
    /// Number of saved profiles
    profile_count: usize,
    /// Primary wireless adapter
    adapter: WirelessAdapter,
    /// WZC settings
    wzc_settings: WzcSettings,
    /// Last scan timestamp
    last_scan: u64,
    /// Scan in progress
    scanning: bool,
}

impl WirelessState {
    pub const fn new() -> Self {
        Self {
            networks: [const { WirelessNetwork::new() }; MAX_NETWORKS],
            network_count: 0,
            profiles: [const { WirelessProfile::new() }; MAX_PROFILES],
            profile_count: 0,
            adapter: WirelessAdapter::new(),
            wzc_settings: WzcSettings::new(),
            last_scan: 0,
            scanning: false,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static WIRELESS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static WIRELESS_STATE: SpinLock<WirelessState> = SpinLock::new(WirelessState::new());

// Statistics
static SCAN_COUNT: AtomicU32 = AtomicU32::new(0);
static CONNECTION_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static SUCCESSFUL_CONNECTIONS: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize wireless settings
pub fn init() {
    if WIRELESS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = WIRELESS_STATE.lock();

    // Initialize a simulated wireless adapter
    init_adapter(&mut state);

    // Add some sample networks for testing
    add_sample_networks(&mut state);

    // Add a sample saved profile
    add_sample_profiles(&mut state);

    crate::serial_println!("[WIN32K] Wireless settings initialized");
}

/// Initialize simulated wireless adapter
fn init_adapter(state: &mut WirelessState) {
    state.adapter.set_name(b"Wireless Network Connection");
    state.adapter.set_description(b"Intel PRO/Wireless 2200BG Network Connection");
    state.adapter.mac_address = [0x00, 0x13, 0xCE, 0x55, 0x12, 0x34];
    state.adapter.state = AdapterState::Disconnected;
    state.adapter.supports_wpa = true;
    state.adapter.supports_wpa2 = true;
}

/// Add sample networks for testing
fn add_sample_networks(state: &mut WirelessState) {
    let samples: [(&[u8], AuthType, EncryptionType, i32, u8); 6] = [
        (b"HomeNetwork", AuthType::Wpa2Psk, EncryptionType::Aes, -45, 6),
        (b"OfficeWifi", AuthType::Wpa2Eap, EncryptionType::Aes, -55, 11),
        (b"CoffeeShop", AuthType::Open, EncryptionType::None, -65, 1),
        (b"GuestNetwork", AuthType::WpaPsk, EncryptionType::Tkip, -70, 6),
        (b"Linksys", AuthType::Wep, EncryptionType::Wep, -80, 11),
        (b"NETGEAR", AuthType::Wpa2Psk, EncryptionType::Aes, -85, 1),
    ];

    for (ssid, auth, enc, rssi, channel) in samples.iter() {
        if state.network_count >= MAX_NETWORKS {
            break;
        }
        let mut net = WirelessNetwork::new();
        net.set_ssid(ssid);
        net.auth_type = *auth;
        net.encryption = *enc;
        net.rssi = *rssi;
        net.channel = *channel;
        net.is_secured = *auth != AuthType::Open;
        net.network_type = NetworkType::Infrastructure;
        // Generate a fake BSSID
        net.bssid = [0x00, 0x11, 0x22, state.network_count as u8, 0x44, 0x55];
        state.networks[state.network_count] = net;
        state.network_count += 1;
    }
}

/// Add sample saved profiles
fn add_sample_profiles(state: &mut WirelessState) {
    let mut profile = WirelessProfile::new();
    profile.set_name(b"HomeNetwork");
    profile.set_ssid(b"HomeNetwork");
    profile.auth_type = AuthType::Wpa2Psk;
    profile.encryption = EncryptionType::Aes;
    profile.auto_connect = true;
    profile.priority = 1;
    profile.is_valid = true;
    state.profiles[0] = profile;
    state.profile_count = 1;
}

// ============================================================================
// Adapter Management
// ============================================================================

/// Get wireless adapter info
pub fn get_adapter() -> WirelessAdapter {
    WIRELESS_STATE.lock().adapter
}

/// Enable wireless adapter
pub fn enable_adapter() -> bool {
    let mut state = WIRELESS_STATE.lock();
    if state.adapter.state == AdapterState::NotPresent {
        return false;
    }
    if state.adapter.state == AdapterState::Disabled {
        state.adapter.state = AdapterState::Disconnected;
    }
    true
}

/// Disable wireless adapter
pub fn disable_adapter() -> bool {
    let mut state = WIRELESS_STATE.lock();
    if state.adapter.state == AdapterState::NotPresent {
        return false;
    }
    state.adapter.state = AdapterState::Disabled;
    true
}

/// Check if adapter is enabled
pub fn is_adapter_enabled() -> bool {
    let state = WIRELESS_STATE.lock();
    state.adapter.state != AdapterState::NotPresent &&
    state.adapter.state != AdapterState::Disabled
}

/// Check if connected to a network
pub fn is_connected() -> bool {
    WIRELESS_STATE.lock().adapter.state == AdapterState::Connected
}

// ============================================================================
// Network Scanning
// ============================================================================

/// Start a network scan
pub fn start_scan() -> bool {
    let mut state = WIRELESS_STATE.lock();

    if state.adapter.state == AdapterState::NotPresent ||
       state.adapter.state == AdapterState::Disabled {
        return false;
    }

    if state.scanning {
        return false;
    }

    state.scanning = true;
    SCAN_COUNT.fetch_add(1, Ordering::Relaxed);

    // In a real implementation, this would trigger hardware scan
    // For now, we'll just simulate completion
    state.scanning = false;
    state.last_scan = 0; // Would be current timestamp

    true
}

/// Check if scan is in progress
pub fn is_scanning() -> bool {
    WIRELESS_STATE.lock().scanning
}

/// Get available networks count
pub fn get_network_count() -> usize {
    WIRELESS_STATE.lock().network_count
}

/// Get network by index
pub fn get_network(index: usize) -> Option<WirelessNetwork> {
    let state = WIRELESS_STATE.lock();
    if index < state.network_count {
        Some(state.networks[index])
    } else {
        None
    }
}

/// Find network by SSID
pub fn find_network_by_ssid(ssid: &[u8]) -> Option<WirelessNetwork> {
    let state = WIRELESS_STATE.lock();
    for i in 0..state.network_count {
        let net = &state.networks[i];
        if net.ssid_len == ssid.len() && &net.ssid[..net.ssid_len] == ssid {
            return Some(*net);
        }
    }
    None
}

// ============================================================================
// Network Connection
// ============================================================================

/// Connect to a network
pub fn connect(ssid: &[u8], key: Option<&[u8]>) -> bool {
    let mut state = WIRELESS_STATE.lock();

    if state.adapter.state == AdapterState::NotPresent ||
       state.adapter.state == AdapterState::Disabled {
        return false;
    }

    CONNECTION_ATTEMPTS.fetch_add(1, Ordering::Relaxed);

    // Find the network
    let mut network_idx = None;
    for i in 0..state.network_count {
        let net = &state.networks[i];
        if net.ssid_len == ssid.len() && &net.ssid[..net.ssid_len] == ssid {
            network_idx = Some(i);
            break;
        }
    }

    let idx = match network_idx {
        Some(i) => i,
        None => return false,
    };

    // Copy network info we need before mutating state
    let network_ssid_len = state.networks[idx].ssid_len;
    let network_ssid = state.networks[idx].ssid;
    let network_bssid = state.networks[idx].bssid;
    let network_signal = state.networks[idx].signal_strength();
    let network_channel = state.networks[idx].channel;
    let network_is_secured = state.networks[idx].is_secured;

    // Check if key is required
    if network_is_secured && key.is_none() {
        return false;
    }

    // Simulate connection
    state.adapter.state = AdapterState::Connected;
    state.adapter.connected_ssid[..network_ssid_len].copy_from_slice(&network_ssid[..network_ssid_len]);
    state.adapter.connected_ssid_len = network_ssid_len;
    state.adapter.connected_bssid = network_bssid;
    state.adapter.signal_strength = network_signal;
    state.adapter.channel = network_channel;
    state.adapter.link_speed = 54; // 54 Mbps for 802.11g

    SUCCESSFUL_CONNECTIONS.fetch_add(1, Ordering::Relaxed);

    true
}

/// Disconnect from current network
pub fn disconnect() -> bool {
    let mut state = WIRELESS_STATE.lock();

    if state.adapter.state != AdapterState::Connected {
        return false;
    }

    state.adapter.state = AdapterState::Disconnected;
    state.adapter.connected_ssid_len = 0;
    state.adapter.connected_bssid = [0u8; MAC_LEN];
    state.adapter.signal_strength = SignalStrength::None;
    state.adapter.channel = 0;
    state.adapter.link_speed = 0;

    true
}

/// Get current connection info
pub fn get_connection_info() -> Option<(WirelessNetwork, u32)> {
    let state = WIRELESS_STATE.lock();

    if state.adapter.state != AdapterState::Connected {
        return None;
    }

    // Find the connected network
    for i in 0..state.network_count {
        let net = &state.networks[i];
        if net.ssid_len == state.adapter.connected_ssid_len &&
           &net.ssid[..net.ssid_len] == &state.adapter.connected_ssid[..state.adapter.connected_ssid_len] {
            return Some((*net, state.adapter.link_speed));
        }
    }

    None
}

// ============================================================================
// Profile Management
// ============================================================================

/// Get saved profile count
pub fn get_profile_count() -> usize {
    WIRELESS_STATE.lock().profile_count
}

/// Get profile by index
pub fn get_profile(index: usize) -> Option<WirelessProfile> {
    let state = WIRELESS_STATE.lock();
    if index < state.profile_count {
        Some(state.profiles[index])
    } else {
        None
    }
}

/// Add or update a profile
pub fn save_profile(profile: &WirelessProfile) -> bool {
    let mut state = WIRELESS_STATE.lock();

    // Check if profile with same SSID exists
    for i in 0..state.profile_count {
        if state.profiles[i].ssid_len == profile.ssid_len &&
           &state.profiles[i].ssid[..profile.ssid_len] == &profile.ssid[..profile.ssid_len] {
            // Update existing
            state.profiles[i] = *profile;
            state.profiles[i].is_valid = true;
            return true;
        }
    }

    // Add new profile
    if state.profile_count >= MAX_PROFILES {
        return false;
    }

    let idx = state.profile_count;
    state.profiles[idx] = *profile;
    state.profiles[idx].is_valid = true;
    state.profile_count += 1;

    true
}

/// Remove a profile by index
pub fn remove_profile(index: usize) -> bool {
    let mut state = WIRELESS_STATE.lock();

    if index >= state.profile_count {
        return false;
    }

    // Shift remaining profiles
    for i in index..state.profile_count - 1 {
        state.profiles[i] = state.profiles[i + 1];
    }
    state.profile_count -= 1;

    true
}

/// Set profile priority
pub fn set_profile_priority(index: usize, priority: u32) -> bool {
    let mut state = WIRELESS_STATE.lock();

    if index >= state.profile_count {
        return false;
    }

    state.profiles[index].priority = priority;
    true
}

/// Move profile up in priority list
pub fn move_profile_up(index: usize) -> bool {
    let mut state = WIRELESS_STATE.lock();

    if index == 0 || index >= state.profile_count {
        return false;
    }

    // Swap with previous
    let temp = state.profiles[index - 1];
    state.profiles[index - 1] = state.profiles[index];
    state.profiles[index] = temp;

    true
}

/// Move profile down in priority list
pub fn move_profile_down(index: usize) -> bool {
    let mut state = WIRELESS_STATE.lock();

    if index >= state.profile_count - 1 {
        return false;
    }

    // Swap with next
    let temp = state.profiles[index + 1];
    state.profiles[index + 1] = state.profiles[index];
    state.profiles[index] = temp;

    true
}

// ============================================================================
// WZC Settings
// ============================================================================

/// Get WZC settings
pub fn get_wzc_settings() -> WzcSettings {
    WIRELESS_STATE.lock().wzc_settings
}

/// Set WZC settings
pub fn set_wzc_settings(settings: WzcSettings) {
    WIRELESS_STATE.lock().wzc_settings = settings;
}

/// Enable/disable Windows wireless configuration
pub fn set_use_windows_config(enabled: bool) {
    WIRELESS_STATE.lock().wzc_settings.use_windows_config = enabled;
}

/// Enable/disable auto-connect
pub fn set_auto_connect(enabled: bool) {
    WIRELESS_STATE.lock().wzc_settings.auto_connect = enabled;
}

// ============================================================================
// Statistics
// ============================================================================

/// Wireless statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct WirelessStats {
    pub initialized: bool,
    pub adapter_present: bool,
    pub adapter_enabled: bool,
    pub is_connected: bool,
    pub network_count: usize,
    pub profile_count: usize,
    pub scan_count: u32,
    pub connection_attempts: u32,
    pub successful_connections: u32,
}

/// Get wireless statistics
pub fn get_stats() -> WirelessStats {
    let state = WIRELESS_STATE.lock();
    WirelessStats {
        initialized: WIRELESS_INITIALIZED.load(Ordering::Relaxed),
        adapter_present: state.adapter.state != AdapterState::NotPresent,
        adapter_enabled: state.adapter.state != AdapterState::NotPresent &&
                        state.adapter.state != AdapterState::Disabled,
        is_connected: state.adapter.state == AdapterState::Connected,
        network_count: state.network_count,
        profile_count: state.profile_count,
        scan_count: SCAN_COUNT.load(Ordering::Relaxed),
        connection_attempts: CONNECTION_ATTEMPTS.load(Ordering::Relaxed),
        successful_connections: SUCCESSFUL_CONNECTIONS.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Wireless dialog handle
pub type HWIRELESSDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create wireless settings dialog
pub fn create_wireless_dialog(_parent: super::super::HWND) -> HWIRELESSDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}

/// Wireless dialog tab
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WirelessTab {
    /// Wireless Networks tab
    #[default]
    Networks = 0,
    /// Advanced settings
    Advanced = 1,
}

/// Get wireless dialog tab count
pub fn get_tab_count() -> u32 {
    2
}

/// Get tab name
pub fn get_tab_name(tab: WirelessTab) -> &'static str {
    match tab {
        WirelessTab::Networks => "Wireless Networks",
        WirelessTab::Advanced => "Advanced",
    }
}

// ============================================================================
// Ad-hoc Network Creation
// ============================================================================

/// Create an ad-hoc network
pub fn create_adhoc_network(
    ssid: &[u8],
    auth_type: AuthType,
    encryption: EncryptionType,
    key: Option<&[u8]>,
) -> bool {
    let mut state = WIRELESS_STATE.lock();

    if state.adapter.state == AdapterState::NotPresent ||
       state.adapter.state == AdapterState::Disabled {
        return false;
    }

    // Disconnect from any current network
    if state.adapter.state == AdapterState::Connected {
        state.adapter.state = AdapterState::Disconnected;
    }

    // Add ad-hoc network to list
    if state.network_count >= MAX_NETWORKS {
        return false;
    }

    let mac_address = state.adapter.mac_address;
    let mut net = WirelessNetwork::new();
    net.set_ssid(ssid);
    net.network_type = NetworkType::AdHoc;
    net.auth_type = auth_type;
    net.encryption = encryption;
    net.rssi = 0; // Local network
    net.channel = 6; // Default channel
    net.is_secured = auth_type != AuthType::Open;
    net.bssid = mac_address; // Use our MAC as BSSID

    let net_idx = state.network_count;
    state.networks[net_idx] = net;
    state.network_count += 1;

    // Auto-connect to our own ad-hoc network
    state.adapter.state = AdapterState::Connected;
    let len = ssid.len().min(MAX_SSID);
    state.adapter.connected_ssid[..len].copy_from_slice(&ssid[..len]);
    state.adapter.connected_ssid_len = len;
    state.adapter.connected_bssid = mac_address;
    state.adapter.signal_strength = SignalStrength::Excellent;
    state.adapter.channel = 6;
    state.adapter.link_speed = 11; // 11 Mbps for ad-hoc

    // Create profile if key provided
    if let Some(key_data) = key {
        let mut profile = WirelessProfile::new();
        profile.set_name(ssid);
        profile.set_ssid(ssid);
        profile.network_type = NetworkType::AdHoc;
        profile.auth_type = auth_type;
        profile.encryption = encryption;
        profile.set_key(key_data);
        profile.auto_connect = false;
        profile.is_valid = true;

        if state.profile_count < MAX_PROFILES {
            let prof_idx = state.profile_count;
            state.profiles[prof_idx] = profile;
            state.profile_count += 1;
        }
    }

    true
}
