//! Windows Firewall (ICF - Internet Connection Firewall)
//!
//! Windows Firewall provides network packet filtering:
//!
//! - **Inbound Filtering**: Block/allow incoming connections
//! - **Outbound Filtering**: Block/allow outgoing connections
//! - **Application Rules**: Per-application network access
//! - **Port Rules**: TCP/UDP port-based filtering
//! - **Profile Support**: Domain, Private, Public profiles
//! - **Logging**: Dropped packet logging
//!
//! # Registry Location
//!
//! `HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`

extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};
use crate::ke::SpinLock;
use alloc::vec::Vec;

// ============================================================================
// Firewall Constants
// ============================================================================

/// Maximum firewall rules
pub const MAX_RULES: usize = 128;

/// Maximum application path length
pub const MAX_APP_PATH: usize = 260;

/// Maximum rule name length
pub const MAX_RULE_NAME: usize = 64;

/// Maximum rule description length
pub const MAX_RULE_DESC: usize = 128;

/// Maximum IP address length
pub const MAX_IP_ADDR: usize = 46;

// ============================================================================
// Firewall Profile
// ============================================================================

/// Firewall profile type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum FirewallProfile {
    /// Domain network profile
    Domain = 1,
    /// Private network profile
    #[default]
    Private = 2,
    /// Public network profile
    Public = 4,
    /// All profiles
    All = 7,
}

impl FirewallProfile {
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => FirewallProfile::Domain,
            2 => FirewallProfile::Private,
            4 => FirewallProfile::Public,
            7 => FirewallProfile::All,
            _ => FirewallProfile::Private,
        }
    }
}

// ============================================================================
// Rule Direction
// ============================================================================

/// Rule direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum RuleDirection {
    /// Inbound (incoming connections)
    #[default]
    Inbound = 1,
    /// Outbound (outgoing connections)
    Outbound = 2,
}

// ============================================================================
// Rule Action
// ============================================================================

/// Rule action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum RuleAction {
    /// Block the connection
    Block = 0,
    /// Allow the connection
    #[default]
    Allow = 1,
}

// ============================================================================
// Protocol
// ============================================================================

/// Network protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum Protocol {
    /// Any protocol
    #[default]
    Any = 0,
    /// ICMP
    Icmp = 1,
    /// TCP
    Tcp = 6,
    /// UDP
    Udp = 17,
    /// ICMPv6
    Icmpv6 = 58,
}

impl Protocol {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Protocol::Any,
            1 => Protocol::Icmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            58 => Protocol::Icmpv6,
            _ => Protocol::Any,
        }
    }
}

// ============================================================================
// Port Range
// ============================================================================

/// Port specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSpec {
    /// Any port
    Any,
    /// Single port
    Single(u16),
    /// Port range (start, end)
    Range(u16, u16),
}

impl Default for PortSpec {
    fn default() -> Self {
        PortSpec::Any
    }
}

impl PortSpec {
    /// Check if a port matches this spec
    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortSpec::Any => true,
            PortSpec::Single(p) => port == *p,
            PortSpec::Range(start, end) => port >= *start && port <= *end,
        }
    }
}

// ============================================================================
// IP Address Spec
// ============================================================================

/// IP address specification
#[derive(Debug, Clone, Copy)]
pub enum IpSpec {
    /// Any address
    Any,
    /// Local subnet
    LocalSubnet,
    /// Specific IPv4 address
    Ipv4([u8; 4]),
    /// IPv4 with subnet mask
    Ipv4Subnet([u8; 4], u8),
}

impl Default for IpSpec {
    fn default() -> Self {
        IpSpec::Any
    }
}

impl IpSpec {
    /// Check if an IP matches this spec
    pub fn matches(&self, ip: [u8; 4]) -> bool {
        match self {
            IpSpec::Any => true,
            IpSpec::LocalSubnet => {
                // Simple local subnet check (192.168.x.x or 10.x.x.x or 172.16-31.x.x)
                ip[0] == 192 && ip[1] == 168 ||
                ip[0] == 10 ||
                ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31
            }
            IpSpec::Ipv4(addr) => ip == *addr,
            IpSpec::Ipv4Subnet(addr, mask) => {
                let mask_bits = *mask as u32;
                if mask_bits == 0 {
                    return true;
                }
                let mask_val = !((1u32 << (32 - mask_bits)) - 1);
                let ip_u32 = u32::from_be_bytes(ip);
                let addr_u32 = u32::from_be_bytes(*addr);
                (ip_u32 & mask_val) == (addr_u32 & mask_val)
            }
        }
    }
}

// ============================================================================
// Error Codes
// ============================================================================

/// Firewall error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FirewallError {
    /// Success
    Success = 0,
    /// Rule not found
    RuleNotFound = 0x80070002,
    /// Invalid parameter
    InvalidParameter = 0x80070057,
    /// Maximum rules reached
    MaxRulesReached = 0x80070111,
    /// Rule already exists
    RuleAlreadyExists = 0x80070112,
    /// Access denied
    AccessDenied = 0x80070005,
    /// Service not running
    NotRunning = 0x80070113,
}

// ============================================================================
// Firewall Rule
// ============================================================================

/// Firewall rule definition
#[repr(C)]
pub struct FirewallRule {
    /// Rule name
    pub name: [u8; MAX_RULE_NAME],
    /// Rule description
    pub description: [u8; MAX_RULE_DESC],
    /// Application path (empty = any app)
    pub application: [u8; MAX_APP_PATH],
    /// Profiles this rule applies to
    pub profiles: u32,
    /// Direction (inbound/outbound)
    pub direction: RuleDirection,
    /// Action (allow/block)
    pub action: RuleAction,
    /// Protocol
    pub protocol: Protocol,
    /// Local port spec
    pub local_port: PortSpec,
    /// Remote port spec
    pub remote_port: PortSpec,
    /// Local address spec
    pub local_address: IpSpec,
    /// Remote address spec
    pub remote_address: IpSpec,
    /// Rule enabled
    pub enabled: bool,
    /// Edge traversal allowed
    pub edge_traversal: bool,
    /// Rule priority (higher = evaluated first)
    pub priority: u32,
    /// Rule valid
    pub valid: bool,
}

impl FirewallRule {
    pub const fn empty() -> Self {
        Self {
            name: [0; MAX_RULE_NAME],
            description: [0; MAX_RULE_DESC],
            application: [0; MAX_APP_PATH],
            profiles: FirewallProfile::All as u32,
            direction: RuleDirection::Inbound,
            action: RuleAction::Block,
            protocol: Protocol::Any,
            local_port: PortSpec::Any,
            remote_port: PortSpec::Any,
            local_address: IpSpec::Any,
            remote_address: IpSpec::Any,
            enabled: true,
            edge_traversal: false,
            priority: 0,
            valid: false,
        }
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_RULE_NAME - 1);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name[len] = 0;
    }

    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(MAX_RULE_NAME);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub fn set_description(&mut self, desc: &str) {
        let bytes = desc.as_bytes();
        let len = bytes.len().min(MAX_RULE_DESC - 1);
        self.description[..len].copy_from_slice(&bytes[..len]);
        self.description[len] = 0;
    }

    pub fn set_application(&mut self, app: &str) {
        let bytes = app.as_bytes();
        let len = bytes.len().min(MAX_APP_PATH - 1);
        self.application[..len].copy_from_slice(&bytes[..len]);
        self.application[len] = 0;
    }

    pub fn application_str(&self) -> &str {
        let len = self.application.iter().position(|&b| b == 0).unwrap_or(MAX_APP_PATH);
        core::str::from_utf8(&self.application[..len]).unwrap_or("")
    }

    /// Check if this rule matches a connection
    pub fn matches(
        &self,
        profile: FirewallProfile,
        direction: RuleDirection,
        protocol: Protocol,
        local_ip: [u8; 4],
        local_port: u16,
        remote_ip: [u8; 4],
        remote_port: u16,
    ) -> bool {
        if !self.enabled || !self.valid {
            return false;
        }

        // Check profile
        if (self.profiles & (profile as u32)) == 0 {
            return false;
        }

        // Check direction
        if self.direction != direction {
            return false;
        }

        // Check protocol
        if self.protocol != Protocol::Any && self.protocol != protocol {
            return false;
        }

        // Check ports
        if !self.local_port.matches(local_port) {
            return false;
        }
        if !self.remote_port.matches(remote_port) {
            return false;
        }

        // Check addresses
        if !self.local_address.matches(local_ip) {
            return false;
        }
        if !self.remote_address.matches(remote_ip) {
            return false;
        }

        true
    }
}

// ============================================================================
// Profile Settings
// ============================================================================

/// Per-profile firewall settings
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProfileSettings {
    /// Firewall enabled for this profile
    pub enabled: bool,
    /// Block all inbound connections
    pub block_all_inbound: bool,
    /// Default inbound action
    pub default_inbound_action: RuleAction,
    /// Default outbound action
    pub default_outbound_action: RuleAction,
    /// Allow local firewall rules
    pub allow_local_rules: bool,
    /// Allow local IPsec rules
    pub allow_local_ipsec_rules: bool,
    /// Notify on blocked
    pub notify_on_blocked: bool,
    /// Allow unicast responses
    pub allow_unicast_response: bool,
    /// Log dropped packets
    pub log_dropped: bool,
    /// Log successful connections
    pub log_successful: bool,
}

impl ProfileSettings {
    pub const fn new() -> Self {
        Self {
            enabled: true,
            block_all_inbound: false,
            default_inbound_action: RuleAction::Block,
            default_outbound_action: RuleAction::Allow,
            allow_local_rules: true,
            allow_local_ipsec_rules: true,
            notify_on_blocked: false,
            allow_unicast_response: true,
            log_dropped: false,
            log_successful: false,
        }
    }
}

impl Default for ProfileSettings {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Firewall State
// ============================================================================

/// Firewall configuration
#[repr(C)]
pub struct FirewallConfig {
    /// Domain profile settings
    pub domain: ProfileSettings,
    /// Private profile settings
    pub private: ProfileSettings,
    /// Public profile settings
    pub public: ProfileSettings,
    /// Current active profile
    pub current_profile: FirewallProfile,
    /// Log file path
    pub log_file: [u8; MAX_APP_PATH],
    /// Maximum log file size (KB)
    pub max_log_size_kb: u32,
}

impl FirewallConfig {
    pub const fn new() -> Self {
        Self {
            domain: ProfileSettings::new(),
            private: ProfileSettings::new(),
            public: ProfileSettings::new(),
            current_profile: FirewallProfile::Private,
            log_file: [0; MAX_APP_PATH],
            max_log_size_kb: 4096,
        }
    }

    pub fn get_profile_settings(&self, profile: FirewallProfile) -> &ProfileSettings {
        match profile {
            FirewallProfile::Domain => &self.domain,
            FirewallProfile::Private => &self.private,
            FirewallProfile::Public => &self.public,
            FirewallProfile::All => &self.private, // Default to private
        }
    }

    pub fn get_profile_settings_mut(&mut self, profile: FirewallProfile) -> &mut ProfileSettings {
        match profile {
            FirewallProfile::Domain => &mut self.domain,
            FirewallProfile::Private => &mut self.private,
            FirewallProfile::Public => &mut self.public,
            FirewallProfile::All => &mut self.private,
        }
    }
}

/// Firewall state
#[repr(C)]
pub struct FirewallState {
    /// Configuration
    pub config: FirewallConfig,
    /// Firewall rules
    pub rules: [FirewallRule; MAX_RULES],
    /// Rule count
    pub rule_count: usize,
    /// Service running
    pub running: bool,
}

impl FirewallState {
    pub const fn new() -> Self {
        Self {
            config: FirewallConfig::new(),
            rules: [const { FirewallRule::empty() }; MAX_RULES],
            rule_count: 0,
            running: false,
        }
    }
}

/// Global firewall state
static FIREWALL_STATE: SpinLock<FirewallState> = SpinLock::new(FirewallState::new());

/// Firewall statistics
pub struct FirewallStats {
    /// Packets allowed
    pub packets_allowed: AtomicU64,
    /// Packets blocked
    pub packets_blocked: AtomicU64,
    /// Inbound allowed
    pub inbound_allowed: AtomicU64,
    /// Inbound blocked
    pub inbound_blocked: AtomicU64,
    /// Outbound allowed
    pub outbound_allowed: AtomicU64,
    /// Outbound blocked
    pub outbound_blocked: AtomicU64,
    /// Rules matched
    pub rules_matched: AtomicU64,
    /// Default action applied
    pub default_action_applied: AtomicU64,
}

impl FirewallStats {
    pub const fn new() -> Self {
        Self {
            packets_allowed: AtomicU64::new(0),
            packets_blocked: AtomicU64::new(0),
            inbound_allowed: AtomicU64::new(0),
            inbound_blocked: AtomicU64::new(0),
            outbound_allowed: AtomicU64::new(0),
            outbound_blocked: AtomicU64::new(0),
            rules_matched: AtomicU64::new(0),
            default_action_applied: AtomicU64::new(0),
        }
    }
}

static FIREWALL_STATS: FirewallStats = FirewallStats::new();

// ============================================================================
// Firewall API
// ============================================================================

/// Add a firewall rule
pub fn add_rule(rule: FirewallRule) -> Result<usize, FirewallError> {
    let mut state = FIREWALL_STATE.lock();

    if !state.running {
        return Err(FirewallError::NotRunning);
    }

    // Copy name before moving rule
    let mut name_buf = [0u8; MAX_RULE_NAME];
    let name_len = rule.name.iter().position(|&b| b == 0).unwrap_or(MAX_RULE_NAME);
    name_buf[..name_len].copy_from_slice(&rule.name[..name_len]);
    let direction = rule.direction;
    let action = rule.action;

    // Check for existing rule with same name
    let rule_name = core::str::from_utf8(&name_buf[..name_len]).unwrap_or("");
    for i in 0..MAX_RULES {
        if state.rules[i].valid && state.rules[i].name_str() == rule_name {
            return Err(FirewallError::RuleAlreadyExists);
        }
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_RULES {
        if !state.rules[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(FirewallError::MaxRulesReached),
    };

    state.rules[slot] = rule;
    state.rules[slot].valid = true;
    state.rule_count += 1;

    crate::serial_println!("[FIREWALL] Added rule '{}' ({:?} {:?})",
        rule_name, direction, action);

    Ok(slot)
}

/// Create and add a simple port rule
pub fn add_port_rule(
    name: &str,
    direction: RuleDirection,
    action: RuleAction,
    protocol: Protocol,
    port: u16,
) -> Result<usize, FirewallError> {
    let mut rule = FirewallRule::empty();
    rule.set_name(name);
    rule.direction = direction;
    rule.action = action;
    rule.protocol = protocol;

    if direction == RuleDirection::Inbound {
        rule.local_port = PortSpec::Single(port);
    } else {
        rule.remote_port = PortSpec::Single(port);
    }

    add_rule(rule)
}

/// Create and add an application rule
pub fn add_app_rule(
    name: &str,
    app_path: &str,
    direction: RuleDirection,
    action: RuleAction,
) -> Result<usize, FirewallError> {
    let mut rule = FirewallRule::empty();
    rule.set_name(name);
    rule.set_application(app_path);
    rule.direction = direction;
    rule.action = action;

    add_rule(rule)
}

/// Delete a rule by name
pub fn delete_rule(name: &str) -> Result<(), FirewallError> {
    let mut state = FIREWALL_STATE.lock();

    if !state.running {
        return Err(FirewallError::NotRunning);
    }

    for i in 0..MAX_RULES {
        if state.rules[i].valid && state.rules[i].name_str() == name {
            state.rules[i].valid = false;
            state.rule_count = state.rule_count.saturating_sub(1);
            crate::serial_println!("[FIREWALL] Deleted rule '{}'", name);
            return Ok(());
        }
    }

    Err(FirewallError::RuleNotFound)
}

/// Enable/disable a rule
pub fn set_rule_enabled(name: &str, enabled: bool) -> Result<(), FirewallError> {
    let mut state = FIREWALL_STATE.lock();

    for i in 0..MAX_RULES {
        if state.rules[i].valid && state.rules[i].name_str() == name {
            state.rules[i].enabled = enabled;
            crate::serial_println!("[FIREWALL] Rule '{}' {}",
                name, if enabled { "enabled" } else { "disabled" });
            return Ok(());
        }
    }

    Err(FirewallError::RuleNotFound)
}

/// Enable/disable firewall for a profile
pub fn set_firewall_enabled(profile: FirewallProfile, enabled: bool) -> Result<(), FirewallError> {
    let mut state = FIREWALL_STATE.lock();

    let settings = state.config.get_profile_settings_mut(profile);
    settings.enabled = enabled;

    crate::serial_println!("[FIREWALL] {:?} profile {}",
        profile, if enabled { "enabled" } else { "disabled" });

    Ok(())
}

/// Set default action for a profile
pub fn set_default_action(
    profile: FirewallProfile,
    direction: RuleDirection,
    action: RuleAction,
) -> Result<(), FirewallError> {
    let mut state = FIREWALL_STATE.lock();

    let settings = state.config.get_profile_settings_mut(profile);
    match direction {
        RuleDirection::Inbound => settings.default_inbound_action = action,
        RuleDirection::Outbound => settings.default_outbound_action = action,
    }

    crate::serial_println!("[FIREWALL] {:?} default {:?} action set to {:?}",
        profile, direction, action);

    Ok(())
}

/// Set current profile
pub fn set_current_profile(profile: FirewallProfile) -> Result<(), FirewallError> {
    let mut state = FIREWALL_STATE.lock();
    state.config.current_profile = profile;
    crate::serial_println!("[FIREWALL] Current profile set to {:?}", profile);
    Ok(())
}

/// Enumerate rules
pub fn enumerate_rules() -> Vec<([u8; MAX_RULE_NAME], RuleDirection, RuleAction, bool)> {
    let state = FIREWALL_STATE.lock();
    let mut result = Vec::new();

    for i in 0..MAX_RULES {
        if state.rules[i].valid {
            result.push((
                state.rules[i].name,
                state.rules[i].direction,
                state.rules[i].action,
                state.rules[i].enabled,
            ));
        }
    }

    result
}

// ============================================================================
// Packet Filtering
// ============================================================================

/// Check if a connection should be allowed
pub fn check_connection(
    direction: RuleDirection,
    protocol: Protocol,
    local_ip: [u8; 4],
    local_port: u16,
    remote_ip: [u8; 4],
    remote_port: u16,
) -> RuleAction {
    let state = FIREWALL_STATE.lock();

    if !state.running {
        return RuleAction::Allow;
    }

    let profile = state.config.current_profile;
    let settings = state.config.get_profile_settings(profile);

    if !settings.enabled {
        FIREWALL_STATS.packets_allowed.fetch_add(1, Ordering::Relaxed);
        return RuleAction::Allow;
    }

    // Check rules in priority order (higher priority first)
    let mut matching_rule: Option<(usize, u32)> = None;

    for i in 0..MAX_RULES {
        if state.rules[i].matches(profile, direction, protocol,
            local_ip, local_port, remote_ip, remote_port) {
            let priority = state.rules[i].priority;
            if matching_rule.is_none() || priority > matching_rule.unwrap().1 {
                matching_rule = Some((i, priority));
            }
        }
    }

    let action = if let Some((idx, _)) = matching_rule {
        FIREWALL_STATS.rules_matched.fetch_add(1, Ordering::Relaxed);
        state.rules[idx].action
    } else {
        FIREWALL_STATS.default_action_applied.fetch_add(1, Ordering::Relaxed);
        match direction {
            RuleDirection::Inbound => settings.default_inbound_action,
            RuleDirection::Outbound => settings.default_outbound_action,
        }
    };

    // Update statistics
    match (direction, action) {
        (RuleDirection::Inbound, RuleAction::Allow) => {
            FIREWALL_STATS.inbound_allowed.fetch_add(1, Ordering::Relaxed);
            FIREWALL_STATS.packets_allowed.fetch_add(1, Ordering::Relaxed);
        }
        (RuleDirection::Inbound, RuleAction::Block) => {
            FIREWALL_STATS.inbound_blocked.fetch_add(1, Ordering::Relaxed);
            FIREWALL_STATS.packets_blocked.fetch_add(1, Ordering::Relaxed);
        }
        (RuleDirection::Outbound, RuleAction::Allow) => {
            FIREWALL_STATS.outbound_allowed.fetch_add(1, Ordering::Relaxed);
            FIREWALL_STATS.packets_allowed.fetch_add(1, Ordering::Relaxed);
        }
        (RuleDirection::Outbound, RuleAction::Block) => {
            FIREWALL_STATS.outbound_blocked.fetch_add(1, Ordering::Relaxed);
            FIREWALL_STATS.packets_blocked.fetch_add(1, Ordering::Relaxed);
        }
    }

    action
}

/// Check inbound TCP connection
pub fn check_inbound_tcp(
    local_port: u16,
    remote_ip: [u8; 4],
    remote_port: u16,
) -> bool {
    check_connection(
        RuleDirection::Inbound,
        Protocol::Tcp,
        [0, 0, 0, 0],
        local_port,
        remote_ip,
        remote_port,
    ) == RuleAction::Allow
}

/// Check outbound TCP connection
pub fn check_outbound_tcp(
    local_port: u16,
    remote_ip: [u8; 4],
    remote_port: u16,
) -> bool {
    check_connection(
        RuleDirection::Outbound,
        Protocol::Tcp,
        [0, 0, 0, 0],
        local_port,
        remote_ip,
        remote_port,
    ) == RuleAction::Allow
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get firewall statistics
pub fn get_statistics() -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        FIREWALL_STATS.packets_allowed.load(Ordering::Relaxed),
        FIREWALL_STATS.packets_blocked.load(Ordering::Relaxed),
        FIREWALL_STATS.inbound_allowed.load(Ordering::Relaxed),
        FIREWALL_STATS.inbound_blocked.load(Ordering::Relaxed),
        FIREWALL_STATS.outbound_allowed.load(Ordering::Relaxed),
        FIREWALL_STATS.outbound_blocked.load(Ordering::Relaxed),
        FIREWALL_STATS.rules_matched.load(Ordering::Relaxed),
        FIREWALL_STATS.default_action_applied.load(Ordering::Relaxed),
    )
}

/// Get rule count
pub fn get_rule_count() -> usize {
    let state = FIREWALL_STATE.lock();
    state.rule_count
}

/// Check if firewall is running
pub fn is_running() -> bool {
    let state = FIREWALL_STATE.lock();
    state.running
}

/// Get current profile
pub fn get_current_profile() -> FirewallProfile {
    let state = FIREWALL_STATE.lock();
    state.config.current_profile
}

/// Check if firewall is enabled for current profile
pub fn is_enabled() -> bool {
    let state = FIREWALL_STATE.lock();
    let profile = state.config.current_profile;
    state.config.get_profile_settings(profile).enabled
}

// ============================================================================
// Default Rules
// ============================================================================

/// Add default firewall rules
fn add_default_rules(state: &mut FirewallState) {
    // Allow ICMP echo (ping)
    let mut icmp_rule = FirewallRule::empty();
    icmp_rule.set_name("Core Networking - ICMP Echo");
    icmp_rule.set_description("Allow incoming ICMP echo requests (ping)");
    icmp_rule.direction = RuleDirection::Inbound;
    icmp_rule.action = RuleAction::Allow;
    icmp_rule.protocol = Protocol::Icmp;
    icmp_rule.enabled = true;
    icmp_rule.valid = true;
    state.rules[0] = icmp_rule;

    // Allow NetBIOS
    let mut netbios_rule = FirewallRule::empty();
    netbios_rule.set_name("File and Printer Sharing - NetBIOS");
    netbios_rule.set_description("Allow NetBIOS name service");
    netbios_rule.direction = RuleDirection::Inbound;
    netbios_rule.action = RuleAction::Allow;
    netbios_rule.protocol = Protocol::Udp;
    netbios_rule.local_port = PortSpec::Range(137, 139);
    netbios_rule.enabled = true;
    netbios_rule.valid = true;
    state.rules[1] = netbios_rule;

    // Allow SMB
    let mut smb_rule = FirewallRule::empty();
    smb_rule.set_name("File and Printer Sharing - SMB");
    smb_rule.set_description("Allow SMB file sharing");
    smb_rule.direction = RuleDirection::Inbound;
    smb_rule.action = RuleAction::Allow;
    smb_rule.protocol = Protocol::Tcp;
    smb_rule.local_port = PortSpec::Single(445);
    smb_rule.enabled = true;
    smb_rule.valid = true;
    state.rules[2] = smb_rule;

    // Allow Remote Desktop (disabled by default)
    let mut rdp_rule = FirewallRule::empty();
    rdp_rule.set_name("Remote Desktop");
    rdp_rule.set_description("Allow Remote Desktop connections");
    rdp_rule.direction = RuleDirection::Inbound;
    rdp_rule.action = RuleAction::Allow;
    rdp_rule.protocol = Protocol::Tcp;
    rdp_rule.local_port = PortSpec::Single(3389);
    rdp_rule.enabled = false; // Disabled by default
    rdp_rule.valid = true;
    state.rules[3] = rdp_rule;

    state.rule_count = 4;
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Windows Firewall
pub fn init() {
    crate::serial_println!("[FIREWALL] Initializing Windows Firewall...");

    let mut state = FIREWALL_STATE.lock();

    // Set log file path
    let log_path = b"\\SystemRoot\\pfirewall.log";
    state.config.log_file[..log_path.len()].copy_from_slice(log_path);

    // Add default rules
    add_default_rules(&mut state);

    state.running = true;

    crate::serial_println!("[FIREWALL] Windows Firewall initialized ({} rules)",
        state.rule_count);
}

/// Shutdown Windows Firewall
pub fn shutdown() {
    crate::serial_println!("[FIREWALL] Shutting down Windows Firewall...");

    let mut state = FIREWALL_STATE.lock();
    state.running = false;

    let (allowed, blocked, _, _, _, _, matched, default) = get_statistics();
    crate::serial_println!("[FIREWALL] Stats: {} allowed, {} blocked, {} matched, {} default",
        allowed, blocked, matched, default);
}
