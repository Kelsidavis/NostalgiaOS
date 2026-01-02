//! WINS Manager
//!
//! Windows Server 2003 WINS Manager snap-in implementation.
//! Provides NetBIOS name server management.
//!
//! # Features
//!
//! - Active registrations
//! - Static mappings
//! - Replication partners
//! - Database management
//! - Scavenging
//!
//! # References
//!
//! Based on Windows Server 2003 WINS Manager snap-in

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::UserHandle;

/// HWND type alias
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum WINS servers
const MAX_SERVERS: usize = 8;

/// Maximum name registrations per server
const MAX_REGISTRATIONS: usize = 512;

/// Maximum static mappings per server
const MAX_STATIC_MAPPINGS: usize = 64;

/// Maximum replication partners
const MAX_REPLICATION_PARTNERS: usize = 16;

/// Maximum NetBIOS name length
const MAX_NETBIOS_NAME: usize = 16;

/// Maximum description length
const MAX_DESC_LEN: usize = 128;

// ============================================================================
// NetBIOS Name Type
// ============================================================================

/// NetBIOS name type (suffix)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetBiosNameType {
    /// Workstation (0x00)
    #[default]
    Workstation = 0x00,
    /// Messenger service (0x03)
    Messenger = 0x03,
    /// Server (0x20)
    Server = 0x20,
    /// Domain master browser (0x1B)
    DomainMasterBrowser = 0x1B,
    /// Master browser (0x1D)
    MasterBrowser = 0x1D,
    /// Browser service elections (0x1E)
    BrowserElection = 0x1E,
    /// Domain controllers (0x1C)
    DomainController = 0x1C,
    /// User (0x01)
    User = 0x01,
}

impl NetBiosNameType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Workstation => "Workstation",
            Self::Messenger => "Messenger",
            Self::Server => "File Server",
            Self::DomainMasterBrowser => "Domain Master Browser",
            Self::MasterBrowser => "Master Browser",
            Self::BrowserElection => "Browser Election",
            Self::DomainController => "Domain Controller",
            Self::User => "User",
        }
    }

    pub const fn suffix(&self) -> u8 {
        *self as u8
    }
}

// ============================================================================
// Record Type
// ============================================================================

/// WINS record type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecordType {
    /// Unique name
    #[default]
    Unique = 0,
    /// Group name (normal group)
    Group = 1,
    /// Internet group (special group)
    InternetGroup = 2,
    /// Multihomed (multiple addresses)
    Multihomed = 3,
}

impl RecordType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unique => "Unique",
            Self::Group => "Group",
            Self::InternetGroup => "Internet Group",
            Self::Multihomed => "Multihomed",
        }
    }
}

// ============================================================================
// Record State
// ============================================================================

/// WINS record state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecordState {
    /// Active registration
    #[default]
    Active = 0,
    /// Released
    Released = 1,
    /// Tombstoned (marked for deletion)
    Tombstoned = 2,
    /// Deleted
    Deleted = 3,
}

impl RecordState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "Active",
            Self::Released => "Released",
            Self::Tombstoned => "Tombstoned",
            Self::Deleted => "Deleted",
        }
    }
}

// ============================================================================
// WINS Registration
// ============================================================================

/// WINS name registration
#[derive(Clone, Copy)]
pub struct WinsRegistration {
    /// NetBIOS name (15 chars + suffix)
    pub name: [u8; MAX_NETBIOS_NAME],
    /// Name length (excluding suffix)
    pub name_len: u8,
    /// Name type (suffix)
    pub name_type: NetBiosNameType,
    /// Record type
    pub record_type: RecordType,
    /// Record state
    pub state: RecordState,
    /// IP address(es) - up to 4 for multihomed
    pub ip_addresses: [[u8; 4]; 4],
    /// Number of IP addresses
    pub ip_count: u8,
    /// Version ID (for replication)
    pub version_id: u64,
    /// Expiration time (epoch seconds)
    pub expiration: u64,
    /// Owner server (version ID high bits identify owner)
    pub owner_id: u32,
    /// Static registration (doesn't expire)
    pub is_static: bool,
    /// Registration is in use
    pub in_use: bool,
}

impl WinsRegistration {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NETBIOS_NAME],
            name_len: 0,
            name_type: NetBiosNameType::Workstation,
            record_type: RecordType::Unique,
            state: RecordState::Active,
            ip_addresses: [[0u8; 4]; 4],
            ip_count: 0,
            version_id: 0,
            expiration: 0,
            owner_id: 0,
            is_static: false,
            in_use: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(15); // NetBIOS name is 15 chars + suffix
        self.name[..len].copy_from_slice(&name[..len]);
        // Pad with spaces
        for i in len..15 {
            self.name[i] = b' ';
        }
        self.name_len = len as u8;
    }

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Add an IP address (for multihomed)
    pub fn add_ip(&mut self, ip: [u8; 4]) -> bool {
        if self.ip_count < 4 {
            let idx = self.ip_count as usize;
            self.ip_addresses[idx] = ip;
            self.ip_count += 1;
            true
        } else {
            false
        }
    }

    /// Get primary IP address
    pub fn primary_ip(&self) -> [u8; 4] {
        if self.ip_count > 0 {
            self.ip_addresses[0]
        } else {
            [0, 0, 0, 0]
        }
    }
}

// ============================================================================
// Replication Partner
// ============================================================================

/// Replication partner type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PartnerType {
    /// Push partner (sends updates)
    #[default]
    Push = 0,
    /// Pull partner (receives updates)
    Pull = 1,
    /// Push/Pull partner
    PushPull = 2,
}

impl PartnerType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Push => "Push",
            Self::Pull => "Pull",
            Self::PushPull => "Push/Pull",
        }
    }
}

/// Replication partner
#[derive(Clone, Copy)]
pub struct ReplicationPartner {
    /// Partner server name
    pub name: [u8; MAX_DESC_LEN],
    /// Name length
    pub name_len: u8,
    /// Partner IP address
    pub ip_address: [u8; 4],
    /// Partner type
    pub partner_type: PartnerType,
    /// Replication interval (seconds)
    pub replication_interval: u32,
    /// Start time for pull replication (hour 0-23)
    pub start_hour: u8,
    /// Update count threshold for push
    pub update_count: u32,
    /// Last replication time
    pub last_replication: u64,
    /// Partner is in use
    pub in_use: bool,
}

impl ReplicationPartner {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_DESC_LEN],
            name_len: 0,
            ip_address: [0u8; 4],
            partner_type: PartnerType::Push,
            replication_interval: 1800, // 30 minutes default
            start_hour: 0,
            update_count: 0,
            last_replication: 0,
            in_use: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_DESC_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u8;
    }
}

// ============================================================================
// WINS Server
// ============================================================================

/// WINS Server configuration
pub struct WinsServer {
    /// Server name
    pub name: [u8; MAX_DESC_LEN],
    /// Name length
    pub name_len: u8,
    /// Server IP address
    pub ip_address: [u8; 4],
    /// Is local server
    pub is_local: bool,
    /// Registrations
    pub registrations: [WinsRegistration; MAX_REGISTRATIONS],
    /// Registration count
    pub registration_count: u32,
    /// Replication partners
    pub partners: [ReplicationPartner; MAX_REPLICATION_PARTNERS],
    /// Partner count
    pub partner_count: u32,
    /// Next version ID
    pub next_version_id: u64,
    /// Renewal interval (seconds)
    pub renewal_interval: u32,
    /// Extinction interval (seconds)
    pub extinction_interval: u32,
    /// Extinction timeout (seconds)
    pub extinction_timeout: u32,
    /// Verify interval (seconds)
    pub verify_interval: u32,
    /// Enable burst handling
    pub burst_handling: bool,
    /// Burst queue size
    pub burst_queue_size: u32,
    /// Server is in use
    pub in_use: bool,
}

impl WinsServer {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_DESC_LEN],
            name_len: 0,
            ip_address: [0u8; 4],
            is_local: false,
            registrations: [const { WinsRegistration::new() }; MAX_REGISTRATIONS],
            registration_count: 0,
            partners: [const { ReplicationPartner::new() }; MAX_REPLICATION_PARTNERS],
            partner_count: 0,
            next_version_id: 1,
            renewal_interval: 360000,      // 100 hours
            extinction_interval: 360000,    // 100 hours
            extinction_timeout: 360000,     // 100 hours
            verify_interval: 2073600,       // 24 days
            burst_handling: true,
            burst_queue_size: 500,
            in_use: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_DESC_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u8;
    }

    /// Register a name
    pub fn register_name(
        &mut self,
        name: &[u8],
        name_type: NetBiosNameType,
        record_type: RecordType,
        ip: [u8; 4],
        expiration: u64,
    ) -> Option<usize> {
        // Check for existing registration
        for (i, reg) in self.registrations.iter_mut().enumerate() {
            if reg.in_use && reg.get_name() == name && reg.name_type == name_type {
                // Update existing registration
                reg.ip_addresses[0] = ip;
                reg.ip_count = 1;
                reg.state = RecordState::Active;
                reg.expiration = expiration;
                reg.version_id = self.next_version_id;
                self.next_version_id += 1;
                return Some(i);
            }
        }

        // Create new registration
        for (i, reg) in self.registrations.iter_mut().enumerate() {
            if !reg.in_use {
                reg.set_name(name);
                reg.name_type = name_type;
                reg.record_type = record_type;
                reg.ip_addresses[0] = ip;
                reg.ip_count = 1;
                reg.state = RecordState::Active;
                reg.expiration = expiration;
                reg.version_id = self.next_version_id;
                reg.is_static = false;
                reg.in_use = true;
                self.next_version_id += 1;
                self.registration_count += 1;
                return Some(i);
            }
        }
        None
    }

    /// Release a name
    pub fn release_name(&mut self, name: &[u8], name_type: NetBiosNameType, ip: [u8; 4]) -> bool {
        for reg in self.registrations.iter_mut() {
            if reg.in_use && reg.get_name() == name && reg.name_type == name_type {
                // For multihomed, only release specific IP
                if reg.record_type == RecordType::Multihomed && reg.ip_count > 1 {
                    let mut found = false;
                    for i in 0..reg.ip_count as usize {
                        if reg.ip_addresses[i] == ip {
                            // Remove this IP
                            for j in i..(reg.ip_count as usize - 1) {
                                reg.ip_addresses[j] = reg.ip_addresses[j + 1];
                            }
                            reg.ip_count -= 1;
                            found = true;
                            break;
                        }
                    }
                    if found && reg.ip_count > 0 {
                        return true;
                    }
                }
                reg.state = RecordState::Released;
                reg.version_id = self.next_version_id;
                self.next_version_id += 1;
                return true;
            }
        }
        false
    }

    /// Query a name
    pub fn query_name(&self, name: &[u8], name_type: NetBiosNameType) -> Option<&WinsRegistration> {
        for reg in self.registrations.iter() {
            if reg.in_use && reg.state == RecordState::Active {
                if reg.get_name() == name && reg.name_type == name_type {
                    return Some(reg);
                }
            }
        }
        None
    }

    /// Add static mapping
    pub fn add_static_mapping(
        &mut self,
        name: &[u8],
        name_type: NetBiosNameType,
        record_type: RecordType,
        ip: [u8; 4],
    ) -> Option<usize> {
        for (i, reg) in self.registrations.iter_mut().enumerate() {
            if !reg.in_use {
                reg.set_name(name);
                reg.name_type = name_type;
                reg.record_type = record_type;
                reg.ip_addresses[0] = ip;
                reg.ip_count = 1;
                reg.state = RecordState::Active;
                reg.expiration = 0; // Never expires
                reg.version_id = self.next_version_id;
                reg.is_static = true;
                reg.in_use = true;
                self.next_version_id += 1;
                self.registration_count += 1;
                return Some(i);
            }
        }
        None
    }
}

// ============================================================================
// Manager State
// ============================================================================

/// WINS Manager state
struct WinsManagerState {
    /// WINS servers
    servers: [WinsServer; MAX_SERVERS],
    /// Server count
    server_count: u32,
    /// Selected server
    selected_server: Option<usize>,
    /// Dialog handle
    dialog_handle: HWND,
    /// View mode (0=servers, 1=registrations, 2=replication, 3=static)
    view_mode: u8,
}

impl WinsManagerState {
    pub const fn new() -> Self {
        Self {
            servers: [const { WinsServer::new() }; MAX_SERVERS],
            server_count: 0,
            selected_server: None,
            dialog_handle: UserHandle::from_raw(0),
            view_mode: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static WINS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static WINS_MANAGER: SpinLock<WinsManagerState> = SpinLock::new(WinsManagerState::new());

// Statistics
static TOTAL_REGISTRATIONS: AtomicU32 = AtomicU32::new(0);
static QUERIES_RECEIVED: AtomicU32 = AtomicU32::new(0);
static RELEASES_RECEIVED: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize WINS Manager
pub fn init() {
    if WINS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = WINS_MANAGER.lock();

    // Add local WINS server
    let srv = &mut state.servers[0];
    srv.set_name(b"wins1");
    srv.ip_address = [192, 168, 1, 1];
    srv.is_local = true;
    srv.in_use = true;

    // Register self
    srv.register_name(
        b"WINS1",
        NetBiosNameType::Workstation,
        RecordType::Unique,
        [192, 168, 1, 1],
        0, // No expiration for self
    );
    if let Some(idx) = srv.registrations.iter().position(|r| r.in_use) {
        srv.registrations[idx].is_static = true;
    }

    srv.register_name(
        b"WINS1",
        NetBiosNameType::Server,
        RecordType::Unique,
        [192, 168, 1, 1],
        0,
    );

    state.server_count = 1;
    TOTAL_REGISTRATIONS.store(2, Ordering::Relaxed);

    crate::serial_println!("[WIN32K] WINS Manager initialized");
}

// ============================================================================
// Server Management
// ============================================================================

/// Add a WINS server
pub fn add_server(name: &[u8], ip: [u8; 4]) -> Option<usize> {
    let mut state = WINS_MANAGER.lock();

    for (i, server) in state.servers.iter_mut().enumerate() {
        if !server.in_use {
            server.set_name(name);
            server.ip_address = ip;
            server.is_local = false;
            server.in_use = true;
            state.server_count += 1;
            return Some(i);
        }
    }
    None
}

/// Remove a WINS server
pub fn remove_server(index: usize) -> bool {
    let mut state = WINS_MANAGER.lock();

    if index < MAX_SERVERS && state.servers[index].in_use && !state.servers[index].is_local {
        state.servers[index].in_use = false;
        state.server_count = state.server_count.saturating_sub(1);
        true
    } else {
        false
    }
}

// ============================================================================
// Name Registration
// ============================================================================

/// Register a NetBIOS name
pub fn register_name(
    server_index: usize,
    name: &[u8],
    name_type: NetBiosNameType,
    record_type: RecordType,
    ip: [u8; 4],
    ttl_seconds: u64,
    current_time: u64,
) -> Option<usize> {
    let mut state = WINS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        let expiration = if ttl_seconds > 0 { current_time + ttl_seconds } else { 0 };
        let result = state.servers[server_index].register_name(
            name, name_type, record_type, ip, expiration
        );
        if result.is_some() {
            TOTAL_REGISTRATIONS.fetch_add(1, Ordering::Relaxed);
        }
        result
    } else {
        None
    }
}

/// Release a NetBIOS name
pub fn release_name(
    server_index: usize,
    name: &[u8],
    name_type: NetBiosNameType,
    ip: [u8; 4],
) -> bool {
    let mut state = WINS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        let result = state.servers[server_index].release_name(name, name_type, ip);
        if result {
            RELEASES_RECEIVED.fetch_add(1, Ordering::Relaxed);
        }
        result
    } else {
        false
    }
}

/// Query a NetBIOS name
pub fn query_name(
    server_index: usize,
    name: &[u8],
    name_type: NetBiosNameType,
) -> Option<[u8; 4]> {
    let state = WINS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        QUERIES_RECEIVED.fetch_add(1, Ordering::Relaxed);
        if let Some(reg) = state.servers[server_index].query_name(name, name_type) {
            return Some(reg.primary_ip());
        }
    }
    None
}

// ============================================================================
// Static Mappings
// ============================================================================

/// Add a static mapping
pub fn add_static_mapping(
    server_index: usize,
    name: &[u8],
    name_type: NetBiosNameType,
    record_type: RecordType,
    ip: [u8; 4],
) -> Option<usize> {
    let mut state = WINS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        let result = state.servers[server_index].add_static_mapping(
            name, name_type, record_type, ip
        );
        if result.is_some() {
            TOTAL_REGISTRATIONS.fetch_add(1, Ordering::Relaxed);
        }
        result
    } else {
        None
    }
}

/// Delete a static mapping
pub fn delete_static_mapping(server_index: usize, registration_index: usize) -> bool {
    let mut state = WINS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        if registration_index < MAX_REGISTRATIONS {
            let reg = &mut state.servers[server_index].registrations[registration_index];
            if reg.in_use && reg.is_static {
                reg.in_use = false;
                state.servers[server_index].registration_count =
                    state.servers[server_index].registration_count.saturating_sub(1);
                TOTAL_REGISTRATIONS.fetch_sub(1, Ordering::Relaxed);
                return true;
            }
        }
    }
    false
}

// ============================================================================
// Replication Partners
// ============================================================================

/// Add a replication partner
pub fn add_replication_partner(
    server_index: usize,
    name: &[u8],
    ip: [u8; 4],
    partner_type: PartnerType,
) -> Option<usize> {
    let mut state = WINS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        for (i, partner) in state.servers[server_index].partners.iter_mut().enumerate() {
            if !partner.in_use {
                partner.set_name(name);
                partner.ip_address = ip;
                partner.partner_type = partner_type;
                partner.in_use = true;
                state.servers[server_index].partner_count += 1;
                return Some(i);
            }
        }
    }
    None
}

/// Remove a replication partner
pub fn remove_replication_partner(server_index: usize, partner_index: usize) -> bool {
    let mut state = WINS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        if partner_index < MAX_REPLICATION_PARTNERS {
            if state.servers[server_index].partners[partner_index].in_use {
                state.servers[server_index].partners[partner_index].in_use = false;
                state.servers[server_index].partner_count =
                    state.servers[server_index].partner_count.saturating_sub(1);
                return true;
            }
        }
    }
    false
}

/// Trigger replication with partner
pub fn replicate_now(server_index: usize, partner_index: usize, current_time: u64) -> bool {
    let mut state = WINS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        if partner_index < MAX_REPLICATION_PARTNERS {
            if state.servers[server_index].partners[partner_index].in_use {
                state.servers[server_index].partners[partner_index].last_replication = current_time;
                // In real implementation, would initiate replication
                return true;
            }
        }
    }
    false
}

// ============================================================================
// Database Operations
// ============================================================================

/// Scavenge database (remove expired/tombstoned records)
pub fn scavenge_database(server_index: usize, current_time: u64) -> u32 {
    let mut state = WINS_MANAGER.lock();
    let mut removed = 0u32;

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        for reg in state.servers[server_index].registrations.iter_mut() {
            if reg.in_use && !reg.is_static {
                // Check expiration
                if reg.expiration > 0 && current_time > reg.expiration {
                    if reg.state == RecordState::Active {
                        reg.state = RecordState::Released;
                    } else if reg.state == RecordState::Released {
                        reg.state = RecordState::Tombstoned;
                    } else if reg.state == RecordState::Tombstoned {
                        reg.in_use = false;
                        removed += 1;
                    }
                }
            }
        }

        if removed > 0 {
            state.servers[server_index].registration_count =
                state.servers[server_index].registration_count.saturating_sub(removed);
            TOTAL_REGISTRATIONS.fetch_sub(removed, Ordering::Relaxed);
        }
    }

    removed
}

/// Verify database consistency
pub fn verify_database(server_index: usize) -> bool {
    let state = WINS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        // In real implementation, would verify with other WINS servers
        true
    } else {
        false
    }
}

/// Compact database
pub fn compact_database(server_index: usize) -> bool {
    let state = WINS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        // In real implementation, would compact WINS database file
        true
    } else {
        false
    }
}

// ============================================================================
// Dialog Management
// ============================================================================

/// Show WINS Manager dialog
pub fn show_dialog(parent: HWND) -> HWND {
    let mut state = WINS_MANAGER.lock();

    let handle = UserHandle::from_raw(0xE401);
    state.dialog_handle = handle;
    state.selected_server = Some(0);
    state.view_mode = 1; // Registrations view

    let _ = parent;
    handle
}

/// Close WINS Manager dialog
pub fn close_dialog() {
    let mut state = WINS_MANAGER.lock();
    state.dialog_handle = UserHandle::from_raw(0);
}

/// Select a server
pub fn select_server(index: usize) {
    let mut state = WINS_MANAGER.lock();
    if index < MAX_SERVERS && state.servers[index].in_use {
        state.selected_server = Some(index);
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// WINS statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct WinsStats {
    pub initialized: bool,
    pub server_count: u32,
    pub total_registrations: u32,
    pub queries_received: u32,
    pub releases_received: u32,
}

/// Get WINS statistics
pub fn get_stats() -> WinsStats {
    let state = WINS_MANAGER.lock();
    WinsStats {
        initialized: WINS_INITIALIZED.load(Ordering::Relaxed),
        server_count: state.server_count,
        total_registrations: TOTAL_REGISTRATIONS.load(Ordering::Relaxed),
        queries_received: QUERIES_RECEIVED.load(Ordering::Relaxed),
        releases_received: RELEASES_RECEIVED.load(Ordering::Relaxed),
    }
}

/// Get server statistics
pub fn get_server_stats(server_index: usize) -> Option<(u32, u32, u64)> {
    let state = WINS_MANAGER.lock();

    if server_index < MAX_SERVERS && state.servers[server_index].in_use {
        Some((
            state.servers[server_index].registration_count,
            state.servers[server_index].partner_count,
            state.servers[server_index].next_version_id,
        ))
    } else {
        None
    }
}
