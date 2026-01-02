//! DHCP Manager (dhcpmgmt.msc)
//!
//! Windows Server 2003 DHCP Management snap-in implementation.
//! Provides DHCP scope, reservation, and option management.
//!
//! # Features
//!
//! - Scope management (address pools)
//! - Reservations (static IP assignments)
//! - DHCP options (gateway, DNS, etc.)
//! - Exclusion ranges
//! - Lease management
//! - Superscopes and multicast scopes
//!
//! # References
//!
//! Based on Windows Server 2003 DHCP Manager snap-in

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::UserHandle;

/// HWND type alias
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of scopes
const MAX_SCOPES: usize = 32;

/// Maximum reservations per scope
const MAX_RESERVATIONS: usize = 128;

/// Maximum leases per scope
const MAX_LEASES: usize = 256;

/// Maximum exclusion ranges per scope
const MAX_EXCLUSIONS: usize = 16;

/// Maximum DHCP options per scope
const MAX_OPTIONS: usize = 32;

/// Maximum description length
const MAX_DESC_LEN: usize = 128;

/// Maximum hostname length
const MAX_HOSTNAME_LEN: usize = 64;

// ============================================================================
// Scope State
// ============================================================================

/// DHCP scope state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScopeState {
    /// Scope is active and distributing addresses
    #[default]
    Active = 0,
    /// Scope is inactive (not distributing)
    Inactive = 1,
    /// Scope is being deleted
    Deleting = 2,
}

impl ScopeState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "Active",
            Self::Inactive => "Inactive",
            Self::Deleting => "Deleting",
        }
    }
}

// ============================================================================
// DHCP Option Codes
// ============================================================================

/// Common DHCP option codes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DhcpOption {
    /// Subnet mask
    #[default]
    SubnetMask = 1,
    /// Router (default gateway)
    Router = 3,
    /// DNS servers
    DnsServer = 6,
    /// Domain name
    DomainName = 15,
    /// Broadcast address
    Broadcast = 28,
    /// Requested IP address
    RequestedIp = 50,
    /// Lease time
    LeaseTime = 51,
    /// DHCP message type
    MessageType = 53,
    /// Server identifier
    ServerIdentifier = 54,
    /// Parameter request list
    ParameterList = 55,
    /// Renewal time (T1)
    RenewalTime = 58,
    /// Rebinding time (T2)
    RebindingTime = 59,
    /// Vendor class identifier
    VendorClass = 60,
    /// Client identifier
    ClientIdentifier = 61,
    /// TFTP server name
    TftpServer = 66,
    /// Bootfile name
    Bootfile = 67,
    /// WINS servers
    WinsServer = 44,
    /// WINS node type
    WinsNodeType = 46,
}

impl DhcpOption {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SubnetMask => "Subnet Mask",
            Self::Router => "Router",
            Self::DnsServer => "DNS Servers",
            Self::DomainName => "Domain Name",
            Self::Broadcast => "Broadcast Address",
            Self::RequestedIp => "Requested IP",
            Self::LeaseTime => "Lease Time",
            Self::MessageType => "Message Type",
            Self::ServerIdentifier => "Server Identifier",
            Self::ParameterList => "Parameter List",
            Self::RenewalTime => "Renewal Time",
            Self::RebindingTime => "Rebinding Time",
            Self::VendorClass => "Vendor Class",
            Self::ClientIdentifier => "Client Identifier",
            Self::TftpServer => "TFTP Server",
            Self::Bootfile => "Bootfile",
            Self::WinsServer => "WINS Servers",
            Self::WinsNodeType => "WINS Node Type",
        }
    }
}

// ============================================================================
// Lease State
// ============================================================================

/// DHCP lease state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LeaseState {
    /// Lease is active
    #[default]
    Active = 0,
    /// Lease offered but not acknowledged
    Offered = 1,
    /// Lease is expired
    Expired = 2,
    /// Lease is a reservation
    Reservation = 3,
}

impl LeaseState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "Active",
            Self::Offered => "Offered",
            Self::Expired => "Expired",
            Self::Reservation => "Reservation",
        }
    }
}

// ============================================================================
// IP Address Range
// ============================================================================

/// IP address range (for exclusions)
#[derive(Clone, Copy, Default)]
pub struct IpRange {
    /// Start IP address
    pub start: [u8; 4],
    /// End IP address
    pub end: [u8; 4],
    /// Range is in use
    pub in_use: bool,
}

impl IpRange {
    pub const fn new() -> Self {
        Self {
            start: [0u8; 4],
            end: [0u8; 4],
            in_use: false,
        }
    }

    /// Check if an IP is within this range
    pub fn contains(&self, ip: [u8; 4]) -> bool {
        let ip_val = u32::from_be_bytes(ip);
        let start_val = u32::from_be_bytes(self.start);
        let end_val = u32::from_be_bytes(self.end);
        ip_val >= start_val && ip_val <= end_val
    }

    /// Get number of addresses in range
    pub fn count(&self) -> u32 {
        let start_val = u32::from_be_bytes(self.start);
        let end_val = u32::from_be_bytes(self.end);
        end_val.saturating_sub(start_val) + 1
    }
}

// ============================================================================
// DHCP Option Entry
// ============================================================================

/// DHCP option configuration
#[derive(Clone, Copy)]
pub struct OptionEntry {
    /// Option code
    pub code: u8,
    /// Option data
    pub data: [u8; 64],
    /// Data length
    pub data_len: u8,
    /// Option is configured
    pub in_use: bool,
}

impl OptionEntry {
    pub const fn new() -> Self {
        Self {
            code: 0,
            data: [0u8; 64],
            data_len: 0,
            in_use: false,
        }
    }

    pub fn set_data(&mut self, data: &[u8]) {
        let len = data.len().min(64);
        self.data[..len].copy_from_slice(&data[..len]);
        self.data_len = len as u8;
    }

    pub fn get_data(&self) -> &[u8] {
        &self.data[..self.data_len as usize]
    }
}

// ============================================================================
// DHCP Reservation
// ============================================================================

/// DHCP reservation (static assignment)
#[derive(Clone, Copy)]
pub struct Reservation {
    /// Reserved IP address
    pub ip: [u8; 4],
    /// Client MAC address
    pub mac: [u8; 6],
    /// Client hostname
    pub hostname: [u8; MAX_HOSTNAME_LEN],
    /// Hostname length
    pub hostname_len: u8,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub desc_len: u8,
    /// Reservation is in use
    pub in_use: bool,
    /// Support BOOTP
    pub support_bootp: bool,
    /// Support DHCP
    pub support_dhcp: bool,
}

impl Reservation {
    pub const fn new() -> Self {
        Self {
            ip: [0u8; 4],
            mac: [0u8; 6],
            hostname: [0u8; MAX_HOSTNAME_LEN],
            hostname_len: 0,
            description: [0u8; MAX_DESC_LEN],
            desc_len: 0,
            in_use: false,
            support_bootp: false,
            support_dhcp: true,
        }
    }

    pub fn set_hostname(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_HOSTNAME_LEN);
        self.hostname[..len].copy_from_slice(&name[..len]);
        self.hostname_len = len as u8;
    }

    pub fn get_hostname(&self) -> &[u8] {
        &self.hostname[..self.hostname_len as usize]
    }

    pub fn set_description(&mut self, desc: &[u8]) {
        let len = desc.len().min(MAX_DESC_LEN);
        self.description[..len].copy_from_slice(&desc[..len]);
        self.desc_len = len as u8;
    }
}

// ============================================================================
// DHCP Lease
// ============================================================================

/// Active DHCP lease
#[derive(Clone, Copy)]
pub struct Lease {
    /// Leased IP address
    pub ip: [u8; 4],
    /// Client MAC address
    pub mac: [u8; 6],
    /// Client hostname
    pub hostname: [u8; MAX_HOSTNAME_LEN],
    /// Hostname length
    pub hostname_len: u8,
    /// Lease state
    pub state: LeaseState,
    /// Lease start time (epoch seconds)
    pub start_time: u64,
    /// Lease expiry time (epoch seconds)
    pub expiry_time: u64,
    /// Lease is in use
    pub in_use: bool,
    /// Unique lease identifier
    pub lease_id: u32,
}

impl Lease {
    pub const fn new() -> Self {
        Self {
            ip: [0u8; 4],
            mac: [0u8; 6],
            hostname: [0u8; MAX_HOSTNAME_LEN],
            hostname_len: 0,
            state: LeaseState::Active,
            start_time: 0,
            expiry_time: 0,
            in_use: false,
            lease_id: 0,
        }
    }

    pub fn set_hostname(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_HOSTNAME_LEN);
        self.hostname[..len].copy_from_slice(&name[..len]);
        self.hostname_len = len as u8;
    }

    pub fn get_hostname(&self) -> &[u8] {
        &self.hostname[..self.hostname_len as usize]
    }

    /// Check if lease is expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.expiry_time
    }

    /// Get remaining lease time in seconds
    pub fn remaining_time(&self, current_time: u64) -> u64 {
        if current_time >= self.expiry_time {
            0
        } else {
            self.expiry_time - current_time
        }
    }
}

// ============================================================================
// DHCP Scope
// ============================================================================

/// DHCP scope (address pool)
pub struct DhcpScope {
    /// Scope name
    pub name: [u8; MAX_DESC_LEN],
    /// Name length
    pub name_len: u8,
    /// Scope description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub desc_len: u8,
    /// Scope network address
    pub network: [u8; 4],
    /// Subnet mask
    pub mask: [u8; 4],
    /// Start of address pool
    pub pool_start: [u8; 4],
    /// End of address pool
    pub pool_end: [u8; 4],
    /// Default gateway (router)
    pub gateway: [u8; 4],
    /// DNS servers (up to 4)
    pub dns_servers: [[u8; 4]; 4],
    /// Number of DNS servers
    pub dns_count: u8,
    /// Domain name
    pub domain_name: [u8; MAX_DESC_LEN],
    /// Domain name length
    pub domain_len: u8,
    /// Lease duration (seconds)
    pub lease_duration: u32,
    /// Scope state
    pub state: ScopeState,
    /// Scope is in use
    pub in_use: bool,
    /// Exclusion ranges
    pub exclusions: [IpRange; MAX_EXCLUSIONS],
    /// Exclusion count
    pub exclusion_count: u8,
    /// Reservations
    pub reservations: [Reservation; MAX_RESERVATIONS],
    /// Reservation count
    pub reservation_count: u32,
    /// Active leases
    pub leases: [Lease; MAX_LEASES],
    /// Lease count
    pub lease_count: u32,
    /// Next lease ID
    pub next_lease_id: u32,
    /// Scope options
    pub options: [OptionEntry; MAX_OPTIONS],
    /// Option count
    pub option_count: u8,
    /// Conflict detection attempts
    pub conflict_detection: u8,
    /// Allow BOOTP clients
    pub allow_bootp: bool,
}

impl DhcpScope {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_DESC_LEN],
            name_len: 0,
            description: [0u8; MAX_DESC_LEN],
            desc_len: 0,
            network: [0u8; 4],
            mask: [0u8; 4],
            pool_start: [0u8; 4],
            pool_end: [0u8; 4],
            gateway: [0u8; 4],
            dns_servers: [[0u8; 4]; 4],
            dns_count: 0,
            domain_name: [0u8; MAX_DESC_LEN],
            domain_len: 0,
            lease_duration: 691200, // 8 days default
            state: ScopeState::Active,
            in_use: false,
            exclusions: [const { IpRange::new() }; MAX_EXCLUSIONS],
            exclusion_count: 0,
            reservations: [const { Reservation::new() }; MAX_RESERVATIONS],
            reservation_count: 0,
            leases: [const { Lease::new() }; MAX_LEASES],
            lease_count: 0,
            next_lease_id: 1,
            options: [const { OptionEntry::new() }; MAX_OPTIONS],
            option_count: 0,
            conflict_detection: 0,
            allow_bootp: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_DESC_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u8;
    }

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    pub fn set_description(&mut self, desc: &[u8]) {
        let len = desc.len().min(MAX_DESC_LEN);
        self.description[..len].copy_from_slice(&desc[..len]);
        self.desc_len = len as u8;
    }

    /// Calculate number of addresses in pool
    pub fn pool_size(&self) -> u32 {
        let start = u32::from_be_bytes(self.pool_start);
        let end = u32::from_be_bytes(self.pool_end);
        end.saturating_sub(start) + 1
    }

    /// Calculate available addresses
    pub fn available_count(&self) -> u32 {
        let total = self.pool_size();
        let excluded: u32 = self.exclusions.iter()
            .filter(|e| e.in_use)
            .map(|e| e.count())
            .sum();
        let leased = self.lease_count;
        total.saturating_sub(excluded).saturating_sub(leased)
    }

    /// Check if IP is available
    pub fn is_ip_available(&self, ip: [u8; 4]) -> bool {
        // Check if in pool range
        let ip_val = u32::from_be_bytes(ip);
        let start = u32::from_be_bytes(self.pool_start);
        let end = u32::from_be_bytes(self.pool_end);

        if ip_val < start || ip_val > end {
            return false;
        }

        // Check exclusions
        for excl in self.exclusions.iter() {
            if excl.in_use && excl.contains(ip) {
                return false;
            }
        }

        // Check reservations
        for res in self.reservations.iter() {
            if res.in_use && res.ip == ip {
                return false;
            }
        }

        // Check active leases
        for lease in self.leases.iter() {
            if lease.in_use && lease.ip == ip && lease.state == LeaseState::Active {
                return false;
            }
        }

        true
    }

    /// Find next available IP
    pub fn find_available_ip(&self) -> Option<[u8; 4]> {
        let start = u32::from_be_bytes(self.pool_start);
        let end = u32::from_be_bytes(self.pool_end);

        for ip_val in start..=end {
            let ip = ip_val.to_be_bytes();
            if self.is_ip_available(ip) {
                return Some(ip);
            }
        }
        None
    }

    /// Add an exclusion range
    pub fn add_exclusion(&mut self, start: [u8; 4], end: [u8; 4]) -> bool {
        for excl in self.exclusions.iter_mut() {
            if !excl.in_use {
                excl.start = start;
                excl.end = end;
                excl.in_use = true;
                self.exclusion_count += 1;
                return true;
            }
        }
        false
    }

    /// Add a reservation
    pub fn add_reservation(&mut self, ip: [u8; 4], mac: [u8; 6], hostname: &[u8]) -> Option<usize> {
        for (i, res) in self.reservations.iter_mut().enumerate() {
            if !res.in_use {
                res.ip = ip;
                res.mac = mac;
                res.set_hostname(hostname);
                res.support_dhcp = true;
                res.in_use = true;
                self.reservation_count += 1;
                return Some(i);
            }
        }
        None
    }

    /// Create a lease
    pub fn create_lease(&mut self, ip: [u8; 4], mac: [u8; 6], hostname: &[u8], current_time: u64) -> Option<usize> {
        for (i, lease) in self.leases.iter_mut().enumerate() {
            if !lease.in_use {
                lease.ip = ip;
                lease.mac = mac;
                lease.set_hostname(hostname);
                lease.state = LeaseState::Active;
                lease.start_time = current_time;
                lease.expiry_time = current_time + self.lease_duration as u64;
                lease.lease_id = self.next_lease_id;
                lease.in_use = true;
                self.next_lease_id += 1;
                self.lease_count += 1;
                return Some(i);
            }
        }
        None
    }

    /// Release a lease
    pub fn release_lease(&mut self, ip: [u8; 4]) -> bool {
        for lease in self.leases.iter_mut() {
            if lease.in_use && lease.ip == ip {
                lease.in_use = false;
                self.lease_count = self.lease_count.saturating_sub(1);
                return true;
            }
        }
        false
    }

    /// Expire old leases
    pub fn expire_leases(&mut self, current_time: u64) -> u32 {
        let mut expired = 0u32;
        for lease in self.leases.iter_mut() {
            if lease.in_use && lease.state == LeaseState::Active {
                if lease.is_expired(current_time) {
                    lease.state = LeaseState::Expired;
                    expired += 1;
                }
            }
        }
        expired
    }
}

// ============================================================================
// DHCP Server Configuration
// ============================================================================

/// DHCP server configuration
pub struct DhcpServerConfig {
    /// Server name
    pub server_name: [u8; MAX_HOSTNAME_LEN],
    /// Name length
    pub name_len: u8,
    /// Server IP address
    pub server_ip: [u8; 4],
    /// Enable conflict detection
    pub conflict_detection: bool,
    /// Conflict detection attempts
    pub conflict_attempts: u8,
    /// Audit logging enabled
    pub audit_logging: bool,
    /// Audit log path
    pub audit_path: [u8; 256],
    /// Audit path length
    pub audit_path_len: u8,
    /// Enable DNS dynamic updates
    pub dns_update: bool,
    /// Discard DNS records on lease expiry
    pub dns_cleanup: bool,
    /// Database backup interval (minutes)
    pub backup_interval: u32,
    /// Database backup path
    pub backup_path: [u8; 256],
    /// Backup path length
    pub backup_path_len: u8,
}

impl DhcpServerConfig {
    pub const fn new() -> Self {
        Self {
            server_name: [0u8; MAX_HOSTNAME_LEN],
            name_len: 0,
            server_ip: [0u8; 4],
            conflict_detection: false,
            conflict_attempts: 2,
            audit_logging: true,
            audit_path: [0u8; 256],
            audit_path_len: 0,
            dns_update: true,
            dns_cleanup: true,
            backup_interval: 60,
            backup_path: [0u8; 256],
            backup_path_len: 0,
        }
    }
}

// ============================================================================
// DHCP Manager State
// ============================================================================

/// DHCP manager state
struct DhcpManagerState {
    /// DHCP scopes
    scopes: [DhcpScope; MAX_SCOPES],
    /// Scope count
    scope_count: u32,
    /// Server configuration
    config: DhcpServerConfig,
    /// Dialog handle
    dialog_handle: HWND,
    /// Selected scope index
    selected_scope: Option<usize>,
    /// View mode
    view_mode: u8,
}

impl DhcpManagerState {
    pub const fn new() -> Self {
        Self {
            scopes: [const { DhcpScope::new() }; MAX_SCOPES],
            scope_count: 0,
            config: DhcpServerConfig::new(),
            dialog_handle: UserHandle::from_raw(0),
            selected_scope: None,
            view_mode: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static DHCP_INITIALIZED: AtomicBool = AtomicBool::new(false);
static DHCP_MANAGER: SpinLock<DhcpManagerState> = SpinLock::new(DhcpManagerState::new());

// Statistics
static SCOPE_COUNT: AtomicU32 = AtomicU32::new(0);
static ACTIVE_LEASES: AtomicU32 = AtomicU32::new(0);
static OFFERS_SENT: AtomicU32 = AtomicU32::new(0);
static ACKS_SENT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize DHCP Manager
pub fn init() {
    if DHCP_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = DHCP_MANAGER.lock();

    // Set server name
    let name = b"dhcp1";
    state.config.server_name[..name.len()].copy_from_slice(name);
    state.config.name_len = name.len() as u8;
    state.config.server_ip = [192, 168, 1, 1];

    // Create default scope
    create_default_scope(&mut state);

    crate::serial_println!("[WIN32K] DHCP Manager initialized");
}

/// Create a default DHCP scope
fn create_default_scope(state: &mut DhcpManagerState) {
    let scope = &mut state.scopes[0];
    scope.set_name(b"Default Scope");
    scope.set_description(b"Primary DHCP scope for 192.168.1.0/24");
    scope.network = [192, 168, 1, 0];
    scope.mask = [255, 255, 255, 0];
    scope.pool_start = [192, 168, 1, 100];
    scope.pool_end = [192, 168, 1, 200];
    scope.gateway = [192, 168, 1, 1];
    scope.dns_servers[0] = [192, 168, 1, 1];
    scope.dns_count = 1;
    scope.lease_duration = 691200; // 8 days
    scope.state = ScopeState::Active;
    scope.in_use = true;

    // Set domain name
    let domain = b"localdomain";
    scope.domain_name[..domain.len()].copy_from_slice(domain);
    scope.domain_len = domain.len() as u8;

    state.scope_count = 1;
    SCOPE_COUNT.store(1, Ordering::Relaxed);
}

// ============================================================================
// Scope Management
// ============================================================================

/// Create a new DHCP scope
pub fn create_scope(
    name: &[u8],
    network: [u8; 4],
    mask: [u8; 4],
    pool_start: [u8; 4],
    pool_end: [u8; 4],
) -> Option<usize> {
    let mut state = DHCP_MANAGER.lock();

    for (i, scope) in state.scopes.iter_mut().enumerate() {
        if !scope.in_use {
            scope.set_name(name);
            scope.network = network;
            scope.mask = mask;
            scope.pool_start = pool_start;
            scope.pool_end = pool_end;
            scope.state = ScopeState::Inactive; // Start inactive until configured
            scope.in_use = true;

            state.scope_count += 1;
            SCOPE_COUNT.fetch_add(1, Ordering::Relaxed);

            return Some(i);
        }
    }
    None
}

/// Delete a DHCP scope
pub fn delete_scope(index: usize) -> bool {
    let mut state = DHCP_MANAGER.lock();

    if index < MAX_SCOPES && state.scopes[index].in_use {
        // Release all leases first
        state.scopes[index].lease_count = 0;
        state.scopes[index].in_use = false;
        state.scope_count = state.scope_count.saturating_sub(1);
        SCOPE_COUNT.fetch_sub(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// Activate a scope
pub fn activate_scope(index: usize) -> bool {
    let mut state = DHCP_MANAGER.lock();

    if index < MAX_SCOPES && state.scopes[index].in_use {
        state.scopes[index].state = ScopeState::Active;
        true
    } else {
        false
    }
}

/// Deactivate a scope
pub fn deactivate_scope(index: usize) -> bool {
    let mut state = DHCP_MANAGER.lock();

    if index < MAX_SCOPES && state.scopes[index].in_use {
        state.scopes[index].state = ScopeState::Inactive;
        true
    } else {
        false
    }
}

/// Get scope info
pub fn get_scope_info(index: usize) -> Option<(ScopeState, u32, u32, u32)> {
    let state = DHCP_MANAGER.lock();

    if index < MAX_SCOPES && state.scopes[index].in_use {
        Some((
            state.scopes[index].state,
            state.scopes[index].pool_size(),
            state.scopes[index].lease_count,
            state.scopes[index].available_count(),
        ))
    } else {
        None
    }
}

// ============================================================================
// Reservation Management
// ============================================================================

/// Add a reservation to a scope
pub fn add_reservation(scope_index: usize, ip: [u8; 4], mac: [u8; 6], hostname: &[u8]) -> Option<usize> {
    let mut state = DHCP_MANAGER.lock();

    if scope_index < MAX_SCOPES && state.scopes[scope_index].in_use {
        state.scopes[scope_index].add_reservation(ip, mac, hostname)
    } else {
        None
    }
}

/// Remove a reservation
pub fn remove_reservation(scope_index: usize, reservation_index: usize) -> bool {
    let mut state = DHCP_MANAGER.lock();

    if scope_index < MAX_SCOPES && state.scopes[scope_index].in_use {
        if reservation_index < MAX_RESERVATIONS {
            if state.scopes[scope_index].reservations[reservation_index].in_use {
                state.scopes[scope_index].reservations[reservation_index].in_use = false;
                state.scopes[scope_index].reservation_count =
                    state.scopes[scope_index].reservation_count.saturating_sub(1);
                return true;
            }
        }
    }
    false
}

// ============================================================================
// Exclusion Management
// ============================================================================

/// Add an exclusion range
pub fn add_exclusion(scope_index: usize, start: [u8; 4], end: [u8; 4]) -> bool {
    let mut state = DHCP_MANAGER.lock();

    if scope_index < MAX_SCOPES && state.scopes[scope_index].in_use {
        state.scopes[scope_index].add_exclusion(start, end)
    } else {
        false
    }
}

/// Remove an exclusion range
pub fn remove_exclusion(scope_index: usize, exclusion_index: usize) -> bool {
    let mut state = DHCP_MANAGER.lock();

    if scope_index < MAX_SCOPES && state.scopes[scope_index].in_use {
        if exclusion_index < MAX_EXCLUSIONS {
            if state.scopes[scope_index].exclusions[exclusion_index].in_use {
                state.scopes[scope_index].exclusions[exclusion_index].in_use = false;
                state.scopes[scope_index].exclusion_count =
                    state.scopes[scope_index].exclusion_count.saturating_sub(1);
                return true;
            }
        }
    }
    false
}

// ============================================================================
// Lease Operations
// ============================================================================

/// Request a lease (DHCP DISCOVER/REQUEST simulation)
pub fn request_lease(scope_index: usize, mac: [u8; 6], hostname: &[u8], current_time: u64) -> Option<[u8; 4]> {
    let mut state = DHCP_MANAGER.lock();

    if scope_index < MAX_SCOPES && state.scopes[scope_index].in_use {
        if state.scopes[scope_index].state != ScopeState::Active {
            return None;
        }

        // Check for existing reservation - find reserved IP first
        let mut reserved_ip: Option<[u8; 4]> = None;
        for res in state.scopes[scope_index].reservations.iter() {
            if res.in_use && res.mac == mac {
                reserved_ip = Some(res.ip);
                break;
            }
        }

        if let Some(ip) = reserved_ip {
            // Found reservation, create lease for reserved IP
            if state.scopes[scope_index].create_lease(ip, mac, hostname, current_time).is_some() {
                ACTIVE_LEASES.fetch_add(1, Ordering::Relaxed);
                ACKS_SENT.fetch_add(1, Ordering::Relaxed);
                return Some(ip);
            }
        }

        // Check for existing lease (renewal) - get lease duration first
        let lease_duration = state.scopes[scope_index].lease_duration;
        for lease in state.scopes[scope_index].leases.iter_mut() {
            if lease.in_use && lease.mac == mac && lease.state == LeaseState::Active {
                // Renew existing lease
                let lease_ip = lease.ip;
                lease.start_time = current_time;
                lease.expiry_time = current_time + lease_duration as u64;
                ACKS_SENT.fetch_add(1, Ordering::Relaxed);
                return Some(lease_ip);
            }
        }

        // Find a new IP
        if let Some(ip) = state.scopes[scope_index].find_available_ip() {
            if state.scopes[scope_index].create_lease(ip, mac, hostname, current_time).is_some() {
                ACTIVE_LEASES.fetch_add(1, Ordering::Relaxed);
                OFFERS_SENT.fetch_add(1, Ordering::Relaxed);
                ACKS_SENT.fetch_add(1, Ordering::Relaxed);
                return Some(ip);
            }
        }
    }
    None
}

/// Release a lease (DHCP RELEASE)
pub fn release_lease(scope_index: usize, ip: [u8; 4]) -> bool {
    let mut state = DHCP_MANAGER.lock();

    if scope_index < MAX_SCOPES && state.scopes[scope_index].in_use {
        if state.scopes[scope_index].release_lease(ip) {
            ACTIVE_LEASES.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

/// Delete a lease (admin action)
pub fn delete_lease(scope_index: usize, lease_index: usize) -> bool {
    let mut state = DHCP_MANAGER.lock();

    if scope_index < MAX_SCOPES && state.scopes[scope_index].in_use {
        if lease_index < MAX_LEASES && state.scopes[scope_index].leases[lease_index].in_use {
            state.scopes[scope_index].leases[lease_index].in_use = false;
            state.scopes[scope_index].lease_count =
                state.scopes[scope_index].lease_count.saturating_sub(1);
            ACTIVE_LEASES.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

// ============================================================================
// DHCP Options
// ============================================================================

/// Set scope option
pub fn set_scope_option(scope_index: usize, option_code: u8, data: &[u8]) -> bool {
    let mut state = DHCP_MANAGER.lock();

    if scope_index < MAX_SCOPES && state.scopes[scope_index].in_use {
        // Check if option already exists
        for opt in state.scopes[scope_index].options.iter_mut() {
            if opt.in_use && opt.code == option_code {
                opt.set_data(data);
                return true;
            }
        }
        // Add new option
        for opt in state.scopes[scope_index].options.iter_mut() {
            if !opt.in_use {
                opt.code = option_code;
                opt.set_data(data);
                opt.in_use = true;
                state.scopes[scope_index].option_count += 1;
                return true;
            }
        }
    }
    false
}

/// Remove scope option
pub fn remove_scope_option(scope_index: usize, option_code: u8) -> bool {
    let mut state = DHCP_MANAGER.lock();

    if scope_index < MAX_SCOPES && state.scopes[scope_index].in_use {
        for opt in state.scopes[scope_index].options.iter_mut() {
            if opt.in_use && opt.code == option_code {
                opt.in_use = false;
                state.scopes[scope_index].option_count =
                    state.scopes[scope_index].option_count.saturating_sub(1);
                return true;
            }
        }
    }
    false
}

// ============================================================================
// Dialog Management
// ============================================================================

/// Show DHCP Manager dialog
pub fn show_dialog(parent: HWND) -> HWND {
    let mut state = DHCP_MANAGER.lock();

    let handle = UserHandle::from_raw(0xDC01);
    state.dialog_handle = handle;
    state.selected_scope = None;
    state.view_mode = 0;

    handle
}

/// Close DHCP Manager dialog
pub fn close_dialog() {
    let mut state = DHCP_MANAGER.lock();
    state.dialog_handle = UserHandle::from_raw(0);
}

/// Select a scope
pub fn select_scope(index: usize) {
    let mut state = DHCP_MANAGER.lock();
    if index < MAX_SCOPES && state.scopes[index].in_use {
        state.selected_scope = Some(index);
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// DHCP Manager statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct DhcpStats {
    pub initialized: bool,
    pub scope_count: u32,
    pub active_leases: u32,
    pub offers_sent: u32,
    pub acks_sent: u32,
}

/// Get DHCP Manager statistics
pub fn get_stats() -> DhcpStats {
    DhcpStats {
        initialized: DHCP_INITIALIZED.load(Ordering::Relaxed),
        scope_count: SCOPE_COUNT.load(Ordering::Relaxed),
        active_leases: ACTIVE_LEASES.load(Ordering::Relaxed),
        offers_sent: OFFERS_SENT.load(Ordering::Relaxed),
        acks_sent: ACKS_SENT.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Maintenance
// ============================================================================

/// Process expired leases across all scopes
pub fn process_expired_leases(current_time: u64) -> u32 {
    let mut state = DHCP_MANAGER.lock();
    let mut total_expired = 0u32;

    for scope in state.scopes.iter_mut() {
        if scope.in_use {
            let expired = scope.expire_leases(current_time);
            total_expired += expired;
        }
    }

    if total_expired > 0 {
        ACTIVE_LEASES.fetch_sub(total_expired, Ordering::Relaxed);
    }

    total_expired
}

/// Get scope statistics
pub fn get_scope_statistics(scope_index: usize) -> Option<(u32, u32, u32, u32)> {
    let state = DHCP_MANAGER.lock();

    if scope_index < MAX_SCOPES && state.scopes[scope_index].in_use {
        let total = state.scopes[scope_index].pool_size();
        let used = state.scopes[scope_index].lease_count;
        let reserved = state.scopes[scope_index].reservation_count;
        let available = state.scopes[scope_index].available_count();
        Some((total, used, reserved, available))
    } else {
        None
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Format IP address to buffer
pub fn format_ip(ip: [u8; 4], buffer: &mut [u8]) -> usize {
    let mut pos = 0;
    for (i, &octet) in ip.iter().enumerate() {
        if i > 0 && pos < buffer.len() {
            buffer[pos] = b'.';
            pos += 1;
        }
        if octet >= 100 && pos < buffer.len() {
            buffer[pos] = b'0' + (octet / 100);
            pos += 1;
        }
        if octet >= 10 && pos < buffer.len() {
            buffer[pos] = b'0' + ((octet / 10) % 10);
            pos += 1;
        }
        if pos < buffer.len() {
            buffer[pos] = b'0' + (octet % 10);
            pos += 1;
        }
    }
    pos
}

/// Format MAC address to buffer
pub fn format_mac(mac: [u8; 6], buffer: &mut [u8]) -> usize {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut pos = 0;

    for (i, &byte) in mac.iter().enumerate() {
        if i > 0 && pos < buffer.len() {
            buffer[pos] = b'-';
            pos += 1;
        }
        if pos + 1 < buffer.len() {
            buffer[pos] = HEX[(byte >> 4) as usize];
            buffer[pos + 1] = HEX[(byte & 0x0F) as usize];
            pos += 2;
        }
    }
    pos
}
