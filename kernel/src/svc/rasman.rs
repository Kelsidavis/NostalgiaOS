//! Remote Access Service (RasMan)
//!
//! The Remote Access Service manages dial-up and VPN connections,
//! providing the core infrastructure for remote connectivity.
//!
//! # Features
//!
//! - **Dial-up Connections**: Modem-based dial-up networking
//! - **VPN Connections**: PPTP, L2TP/IPSec tunneling
//! - **Connection Management**: Establish, monitor, disconnect
//! - **Phonebook Support**: Connection profile storage
//!
//! # Connection Types
//!
//! - Dial-up (modem, ISDN)
//! - PPTP VPN
//! - L2TP/IPSec VPN
//! - Direct cable connection
//!
//! # Architecture
//!
//! - RasMan (this service) - Connection management
//! - RasSrv - Dial-in server (separate)
//! - RasAuto - Auto-dial support

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum connections
const MAX_CONNECTIONS: usize = 16;

/// Maximum phonebook entries
const MAX_PHONEBOOK: usize = 64;

/// Maximum devices
const MAX_DEVICES: usize = 16;

/// Maximum name length
const MAX_NAME: usize = 64;

/// Maximum phone number length
const MAX_PHONE: usize = 32;

/// Connection type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// Dial-up modem
    Modem = 0,
    /// ISDN
    Isdn = 1,
    /// PPTP VPN
    Pptp = 2,
    /// L2TP/IPSec VPN
    L2tp = 3,
    /// Direct cable
    Direct = 4,
    /// Broadband (PPPoE)
    Broadband = 5,
}

impl ConnectionType {
    const fn empty() -> Self {
        ConnectionType::Modem
    }
}

/// Connection state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Disconnected
    Disconnected = 0,
    /// Opening port
    OpeningPort = 1,
    /// Port opened
    PortOpened = 2,
    /// Connecting device
    ConnectingDevice = 3,
    /// Device connected
    DeviceConnected = 4,
    /// Authenticating
    Authenticating = 5,
    /// Auth acknowledged
    AuthAck = 6,
    /// Auth confirmed
    AuthConfirmed = 7,
    /// Connected
    Connected = 8,
    /// Disconnecting
    Disconnecting = 9,
}

impl ConnectionState {
    const fn empty() -> Self {
        ConnectionState::Disconnected
    }
}

/// Authentication protocol
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProtocol {
    /// PAP - Password Authentication Protocol
    Pap = 0,
    /// CHAP - Challenge Handshake
    Chap = 1,
    /// MS-CHAPv1
    MsChapV1 = 2,
    /// MS-CHAPv2
    MsChapV2 = 3,
    /// EAP - Extensible Authentication
    Eap = 4,
}

impl AuthProtocol {
    const fn empty() -> Self {
        AuthProtocol::MsChapV2
    }
}

/// RAS device
#[repr(C)]
#[derive(Clone)]
pub struct RasDevice {
    /// Device ID
    pub device_id: u32,
    /// Device name
    pub name: [u8; MAX_NAME],
    /// Device type (modem, VPN adapter)
    pub device_type: [u8; 32],
    /// Is available
    pub available: bool,
    /// Currently in use
    pub in_use: bool,
    /// Entry is valid
    pub valid: bool,
}

impl RasDevice {
    const fn empty() -> Self {
        RasDevice {
            device_id: 0,
            name: [0; MAX_NAME],
            device_type: [0; 32],
            available: true,
            in_use: false,
            valid: false,
        }
    }
}

/// Phonebook entry
#[repr(C)]
#[derive(Clone)]
pub struct PhonebookEntry {
    /// Entry ID
    pub entry_id: u64,
    /// Entry name
    pub name: [u8; MAX_NAME],
    /// Phone number or server address
    pub address: [u8; MAX_PHONE],
    /// Connection type
    pub conn_type: ConnectionType,
    /// Authentication protocol
    pub auth_protocol: AuthProtocol,
    /// Username (encrypted or reference)
    pub username: [u8; 32],
    /// Domain
    pub domain: [u8; 32],
    /// Save password flag
    pub save_password: bool,
    /// Auto-dial flag
    pub auto_dial: bool,
    /// Device ID (preferred device)
    pub device_id: u32,
    /// VPN uses specific local IP
    pub use_specific_ip: bool,
    /// Local IP for VPN
    pub local_ip: [u8; 4],
    /// Use default gateway on remote
    pub use_default_gateway: bool,
    /// Entry is valid
    pub valid: bool,
}

impl PhonebookEntry {
    const fn empty() -> Self {
        PhonebookEntry {
            entry_id: 0,
            name: [0; MAX_NAME],
            address: [0; MAX_PHONE],
            conn_type: ConnectionType::empty(),
            auth_protocol: AuthProtocol::empty(),
            username: [0; 32],
            domain: [0; 32],
            save_password: false,
            auto_dial: false,
            device_id: 0,
            use_specific_ip: false,
            local_ip: [0; 4],
            use_default_gateway: true,
            valid: false,
        }
    }
}

/// Active connection
#[repr(C)]
#[derive(Clone)]
pub struct RasConnection {
    /// Connection handle
    pub handle: u64,
    /// Phonebook entry ID
    pub entry_id: u64,
    /// Entry name (copy for convenience)
    pub entry_name: [u8; MAX_NAME],
    /// Connection type
    pub conn_type: ConnectionType,
    /// Current state
    pub state: ConnectionState,
    /// Device ID in use
    pub device_id: u32,
    /// Remote IP address
    pub remote_ip: [u8; 4],
    /// Local IP assigned
    pub local_ip: [u8; 4],
    /// Primary DNS
    pub dns_primary: [u8; 4],
    /// Secondary DNS
    pub dns_secondary: [u8; 4],
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Connection start time
    pub start_time: i64,
    /// Last error code
    pub last_error: u32,
    /// Entry is valid
    pub valid: bool,
}

impl RasConnection {
    const fn empty() -> Self {
        RasConnection {
            handle: 0,
            entry_id: 0,
            entry_name: [0; MAX_NAME],
            conn_type: ConnectionType::empty(),
            state: ConnectionState::empty(),
            device_id: 0,
            remote_ip: [0; 4],
            local_ip: [0; 4],
            dns_primary: [0; 4],
            dns_secondary: [0; 4],
            bytes_sent: 0,
            bytes_received: 0,
            start_time: 0,
            last_error: 0,
            valid: false,
        }
    }
}

/// RasMan service state
pub struct RasManState {
    /// Service is running
    pub running: bool,
    /// Devices
    pub devices: [RasDevice; MAX_DEVICES],
    /// Device count
    pub device_count: usize,
    /// Phonebook entries
    pub phonebook: [PhonebookEntry; MAX_PHONEBOOK],
    /// Phonebook entry count
    pub phonebook_count: usize,
    /// Active connections
    pub connections: [RasConnection; MAX_CONNECTIONS],
    /// Connection count
    pub connection_count: usize,
    /// Next entry ID
    pub next_entry_id: u64,
    /// Next connection handle
    pub next_handle: u64,
    /// Auto-dial enabled
    pub auto_dial_enabled: bool,
    /// Service start time
    pub start_time: i64,
}

impl RasManState {
    const fn new() -> Self {
        RasManState {
            running: false,
            devices: [const { RasDevice::empty() }; MAX_DEVICES],
            device_count: 0,
            phonebook: [const { PhonebookEntry::empty() }; MAX_PHONEBOOK],
            phonebook_count: 0,
            connections: [const { RasConnection::empty() }; MAX_CONNECTIONS],
            connection_count: 0,
            next_entry_id: 1,
            next_handle: 0x1000,
            auto_dial_enabled: true,
            start_time: 0,
        }
    }
}

/// Global state
static RASMAN_STATE: Mutex<RasManState> = Mutex::new(RasManState::new());

/// Statistics
static CONNECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static CONNECTIONS_FAILED: AtomicU64 = AtomicU64::new(0);
static BYTES_SENT: AtomicU64 = AtomicU64::new(0);
static BYTES_RECEIVED: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize RasMan service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = RASMAN_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    // Register default VPN adapter
    let vpn_name = b"WAN Miniport (PPTP)";
    let vpn_type = b"vpn";
    state.devices[0].device_id = 1;
    state.devices[0].name[..vpn_name.len()].copy_from_slice(vpn_name);
    state.devices[0].device_type[..vpn_type.len()].copy_from_slice(vpn_type);
    state.devices[0].available = true;
    state.devices[0].valid = true;

    let l2tp_name = b"WAN Miniport (L2TP)";
    state.devices[1].device_id = 2;
    state.devices[1].name[..l2tp_name.len()].copy_from_slice(l2tp_name);
    state.devices[1].device_type[..vpn_type.len()].copy_from_slice(vpn_type);
    state.devices[1].available = true;
    state.devices[1].valid = true;

    state.device_count = 2;

    crate::serial_println!("[RASMAN] Remote Access Service initialized");
}

/// Register a RAS device
pub fn register_device(name: &[u8], device_type: &[u8]) -> Result<u32, u32> {
    let mut state = RASMAN_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.devices.iter().position(|d| !d.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let device_id = (slot as u32) + 1;
    let name_len = name.len().min(MAX_NAME);
    let type_len = device_type.len().min(32);

    state.device_count += 1;

    let device = &mut state.devices[slot];
    device.device_id = device_id;
    device.name = [0; MAX_NAME];
    device.name[..name_len].copy_from_slice(&name[..name_len]);
    device.device_type = [0; 32];
    device.device_type[..type_len].copy_from_slice(&device_type[..type_len]);
    device.available = true;
    device.in_use = false;
    device.valid = true;

    Ok(device_id)
}

/// Create a phonebook entry
pub fn create_entry(
    name: &[u8],
    address: &[u8],
    conn_type: ConnectionType,
) -> Result<u64, u32> {
    let mut state = RASMAN_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let name_len = name.len().min(MAX_NAME);

    // Check for duplicate
    for entry in state.phonebook.iter() {
        if entry.valid && entry.name[..name_len] == name[..name_len] {
            return Err(0x80070055);
        }
    }

    let slot = state.phonebook.iter().position(|e| !e.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let entry_id = state.next_entry_id;
    state.next_entry_id += 1;
    state.phonebook_count += 1;

    let addr_len = address.len().min(MAX_PHONE);

    let entry = &mut state.phonebook[slot];
    entry.entry_id = entry_id;
    entry.name = [0; MAX_NAME];
    entry.name[..name_len].copy_from_slice(&name[..name_len]);
    entry.address = [0; MAX_PHONE];
    entry.address[..addr_len].copy_from_slice(&address[..addr_len]);
    entry.conn_type = conn_type;
    entry.auth_protocol = AuthProtocol::MsChapV2;
    entry.use_default_gateway = true;
    entry.valid = true;

    Ok(entry_id)
}

/// Delete a phonebook entry
pub fn delete_entry(entry_id: u64) -> Result<(), u32> {
    let mut state = RASMAN_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Check if entry is in use
    for conn in state.connections.iter() {
        if conn.valid && conn.entry_id == entry_id {
            return Err(0x80070005); // Access denied - in use
        }
    }

    let idx = state.phonebook.iter()
        .position(|e| e.valid && e.entry_id == entry_id);

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.phonebook[idx].valid = false;
    state.phonebook_count = state.phonebook_count.saturating_sub(1);

    Ok(())
}

/// Update phonebook entry credentials
pub fn set_entry_credentials(
    entry_id: u64,
    username: &[u8],
    domain: &[u8],
    save_password: bool,
) -> Result<(), u32> {
    let mut state = RASMAN_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let entry = state.phonebook.iter_mut()
        .find(|e| e.valid && e.entry_id == entry_id);

    let entry = match entry {
        Some(e) => e,
        None => return Err(0x80070057),
    };

    let user_len = username.len().min(32);
    let dom_len = domain.len().min(32);

    entry.username = [0; 32];
    entry.username[..user_len].copy_from_slice(&username[..user_len]);
    entry.domain = [0; 32];
    entry.domain[..dom_len].copy_from_slice(&domain[..dom_len]);
    entry.save_password = save_password;

    Ok(())
}

/// Dial (establish) a connection
pub fn dial(entry_id: u64) -> Result<u64, u32> {
    let mut state = RASMAN_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Find the phonebook entry
    let entry_idx = state.phonebook.iter()
        .position(|e| e.valid && e.entry_id == entry_id);

    let entry_idx = match entry_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    // Find available connection slot
    let conn_slot = state.connections.iter().position(|c| !c.valid);
    let conn_slot = match conn_slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    // Find available device
    let device_idx = state.devices.iter()
        .position(|d| d.valid && d.available && !d.in_use);

    let device_idx = match device_idx {
        Some(i) => i,
        None => {
            CONNECTIONS_FAILED.fetch_add(1, Ordering::SeqCst);
            return Err(0x80070005);
        }
    };

    let handle = state.next_handle;
    state.next_handle += 1;
    let now = crate::rtl::time::rtl_get_system_time();

    // Copy entry info
    let entry_name = state.phonebook[entry_idx].name;
    let conn_type = state.phonebook[entry_idx].conn_type;
    let device_id = state.devices[device_idx].device_id;

    state.devices[device_idx].in_use = true;
    state.connection_count += 1;

    let conn = &mut state.connections[conn_slot];
    conn.handle = handle;
    conn.entry_id = entry_id;
    conn.entry_name = entry_name;
    conn.conn_type = conn_type;
    conn.state = ConnectionState::OpeningPort;
    conn.device_id = device_id;
    conn.start_time = now;
    conn.last_error = 0;
    conn.valid = true;

    // Simulate connection establishment
    conn.state = ConnectionState::Connected;
    conn.local_ip = [10, 0, 0, 100];
    conn.remote_ip = [10, 0, 0, 1];
    conn.dns_primary = [8, 8, 8, 8];
    conn.dns_secondary = [8, 8, 4, 4];

    CONNECTIONS_TOTAL.fetch_add(1, Ordering::SeqCst);

    Ok(handle)
}

/// Hang up (disconnect)
pub fn hangup(handle: u64) -> Result<(), u32> {
    let mut state = RASMAN_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let conn_idx = state.connections.iter()
        .position(|c| c.valid && c.handle == handle);

    let conn_idx = match conn_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let device_id = state.connections[conn_idx].device_id;
    let bytes_sent = state.connections[conn_idx].bytes_sent;
    let bytes_recv = state.connections[conn_idx].bytes_received;

    // Update statistics
    BYTES_SENT.fetch_add(bytes_sent, Ordering::SeqCst);
    BYTES_RECEIVED.fetch_add(bytes_recv, Ordering::SeqCst);

    // Release the device
    for device in state.devices.iter_mut() {
        if device.valid && device.device_id == device_id {
            device.in_use = false;
            break;
        }
    }

    state.connections[conn_idx].state = ConnectionState::Disconnected;
    state.connections[conn_idx].valid = false;
    state.connection_count = state.connection_count.saturating_sub(1);

    Ok(())
}

/// Get connection status
pub fn get_connection_status(handle: u64) -> Option<RasConnection> {
    let state = RASMAN_STATE.lock();

    state.connections.iter()
        .find(|c| c.valid && c.handle == handle)
        .cloned()
}

/// Get all active connections
pub fn enum_connections() -> ([RasConnection; MAX_CONNECTIONS], usize) {
    let state = RASMAN_STATE.lock();
    let mut result = [const { RasConnection::empty() }; MAX_CONNECTIONS];
    let mut count = 0;

    for conn in state.connections.iter() {
        if conn.valid && count < MAX_CONNECTIONS {
            result[count] = conn.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get phonebook entries
pub fn enum_entries() -> ([PhonebookEntry; MAX_PHONEBOOK], usize) {
    let state = RASMAN_STATE.lock();
    let mut result = [const { PhonebookEntry::empty() }; MAX_PHONEBOOK];
    let mut count = 0;

    for entry in state.phonebook.iter() {
        if entry.valid && count < MAX_PHONEBOOK {
            result[count] = entry.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get devices
pub fn enum_devices() -> ([RasDevice; MAX_DEVICES], usize) {
    let state = RASMAN_STATE.lock();
    let mut result = [const { RasDevice::empty() }; MAX_DEVICES];
    let mut count = 0;

    for device in state.devices.iter() {
        if device.valid && count < MAX_DEVICES {
            result[count] = device.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Update connection statistics
pub fn update_stats(handle: u64, bytes_sent: u64, bytes_recv: u64) -> Result<(), u32> {
    let mut state = RASMAN_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let conn = state.connections.iter_mut()
        .find(|c| c.valid && c.handle == handle);

    let conn = match conn {
        Some(c) => c,
        None => return Err(0x80070057),
    };

    conn.bytes_sent += bytes_sent;
    conn.bytes_received += bytes_recv;

    Ok(())
}

/// Enable/disable auto-dial
pub fn set_auto_dial(enabled: bool) {
    let mut state = RASMAN_STATE.lock();
    state.auto_dial_enabled = enabled;
}

/// Check if auto-dial is enabled
pub fn is_auto_dial_enabled() -> bool {
    let state = RASMAN_STATE.lock();
    state.auto_dial_enabled
}

/// Get entry for auto-dial to address
pub fn get_auto_dial_entry(_address: &[u8]) -> Option<u64> {
    let state = RASMAN_STATE.lock();

    if !state.auto_dial_enabled {
        return None;
    }

    // Find entry with auto-dial enabled matching the address pattern
    state.phonebook.iter()
        .find(|e| e.valid && e.auto_dial)
        .map(|e| e.entry_id)
}

/// Set entry auto-dial
pub fn set_entry_auto_dial(entry_id: u64, auto_dial: bool) -> Result<(), u32> {
    let mut state = RASMAN_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let entry = state.phonebook.iter_mut()
        .find(|e| e.valid && e.entry_id == entry_id);

    let entry = match entry {
        Some(e) => e,
        None => return Err(0x80070057),
    };

    entry.auto_dial = auto_dial;

    Ok(())
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64, u64) {
    (
        CONNECTIONS_TOTAL.load(Ordering::SeqCst),
        CONNECTIONS_FAILED.load(Ordering::SeqCst),
        BYTES_SENT.load(Ordering::SeqCst),
        BYTES_RECEIVED.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = RASMAN_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = RASMAN_STATE.lock();
    state.running = false;

    // Disconnect all active connections
    for conn in state.connections.iter_mut() {
        if conn.valid {
            conn.state = ConnectionState::Disconnected;
            conn.valid = false;
        }
    }
    state.connection_count = 0;

    // Release all devices
    for device in state.devices.iter_mut() {
        device.in_use = false;
    }

    crate::serial_println!("[RASMAN] Remote Access Service stopped");
}
