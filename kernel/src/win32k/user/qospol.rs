//! QoS (Quality of Service) Policy Management
//!
//! This module implements the Win32k USER subsystem support for
//! QoS Policy management in Windows Server 2003.
//!
//! # Windows Server 2003 Reference
//!
//! QoS policies enable administrators to prioritize network traffic,
//! control bandwidth allocation, and ensure critical applications
//! receive adequate network resources.
//!
//! Key components:
//! - QoS policies (DSCP marking, throttling)
//! - Application-based rules
//! - Port and protocol rules
//! - Traffic scheduling

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;
use crate::win32k::user::UserHandle;

/// Type alias for window handles
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of policies
const MAX_POLICIES: usize = 128;

/// Maximum number of rules per policy
const MAX_RULES: usize = 256;

/// Maximum number of flow entries
const MAX_FLOWS: usize = 512;

/// Maximum name length
const MAX_NAME_LEN: usize = 128;

/// Maximum path length
const MAX_PATH_LEN: usize = 260;

// ============================================================================
// Enumerations
// ============================================================================

/// Policy type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PolicyType {
    /// DSCP-based marking
    DscpMarking = 0,
    /// Throttle rate limiting
    Throttle = 1,
    /// Priority scheduling
    Priority = 2,
    /// Combined (DSCP + throttle)
    Combined = 3,
}

impl Default for PolicyType {
    fn default() -> Self {
        Self::DscpMarking
    }
}

/// Rule match type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RuleMatchType {
    /// Match by application path
    Application = 0,
    /// Match by source port
    SourcePort = 1,
    /// Match by destination port
    DestinationPort = 2,
    /// Match by protocol
    Protocol = 3,
    /// Match by source IP
    SourceIp = 4,
    /// Match by destination IP
    DestinationIp = 5,
    /// Match by URL pattern
    UrlPattern = 6,
}

impl Default for RuleMatchType {
    fn default() -> Self {
        Self::Application
    }
}

/// DSCP values (Differentiated Services Code Point)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DscpValue {
    /// Best Effort (default)
    BestEffort = 0,
    /// Class Selector 1 (scavenger)
    Cs1 = 8,
    /// Assured Forwarding 11
    Af11 = 10,
    /// Assured Forwarding 12
    Af12 = 12,
    /// Assured Forwarding 13
    Af13 = 14,
    /// Class Selector 2
    Cs2 = 16,
    /// Assured Forwarding 21
    Af21 = 18,
    /// Assured Forwarding 22
    Af22 = 20,
    /// Assured Forwarding 23
    Af23 = 22,
    /// Class Selector 3
    Cs3 = 24,
    /// Assured Forwarding 31
    Af31 = 26,
    /// Assured Forwarding 32
    Af32 = 28,
    /// Assured Forwarding 33
    Af33 = 30,
    /// Class Selector 4
    Cs4 = 32,
    /// Assured Forwarding 41
    Af41 = 34,
    /// Assured Forwarding 42
    Af42 = 36,
    /// Assured Forwarding 43
    Af43 = 38,
    /// Class Selector 5
    Cs5 = 40,
    /// Expedited Forwarding (voice)
    Ef = 46,
    /// Class Selector 6
    Cs6 = 48,
    /// Class Selector 7
    Cs7 = 56,
}

impl Default for DscpValue {
    fn default() -> Self {
        Self::BestEffort
    }
}

/// Protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    /// Any protocol
    Any = 0,
    /// TCP
    Tcp = 6,
    /// UDP
    Udp = 17,
    /// ICMP
    Icmp = 1,
    /// GRE
    Gre = 47,
}

impl Default for Protocol {
    fn default() -> Self {
        Self::Any
    }
}

/// Policy status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PolicyStatus {
    /// Disabled
    Disabled = 0,
    /// Enabled
    Enabled = 1,
    /// Error
    Error = 2,
}

impl Default for PolicyStatus {
    fn default() -> Self {
        Self::Disabled
    }
}

/// Flow state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FlowState {
    /// Inactive
    Inactive = 0,
    /// Active
    Active = 1,
    /// Throttled
    Throttled = 2,
    /// Blocked
    Blocked = 3,
}

impl Default for FlowState {
    fn default() -> Self {
        Self::Inactive
    }
}

// ============================================================================
// Structures
// ============================================================================

/// QoS Policy
#[derive(Debug)]
pub struct QosPolicy {
    /// Policy ID
    pub id: u32,
    /// Active flag
    pub active: bool,
    /// Policy name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_NAME_LEN],
    /// Description length
    pub desc_len: usize,
    /// Policy type
    pub policy_type: PolicyType,
    /// Status
    pub status: PolicyStatus,
    /// DSCP value to apply
    pub dscp_value: DscpValue,
    /// Throttle rate (Kbps, 0 = no limit)
    pub throttle_rate: u32,
    /// Priority (0-7, higher = more important)
    pub priority: u8,
    /// Number of rules
    pub rule_count: u32,
    /// Packets matched
    pub packets_matched: u64,
    /// Bytes matched
    pub bytes_matched: u64,
    /// Created time
    pub created_time: u64,
    /// Window handle
    pub hwnd: HWND,
}

impl QosPolicy {
    /// Create new policy
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            description: [0u8; MAX_NAME_LEN],
            desc_len: 0,
            policy_type: PolicyType::DscpMarking,
            status: PolicyStatus::Disabled,
            dscp_value: DscpValue::BestEffort,
            throttle_rate: 0,
            priority: 4,
            rule_count: 0,
            packets_matched: 0,
            bytes_matched: 0,
            created_time: 0,
            hwnd: UserHandle::NULL,
        }
    }
}

/// QoS Rule
#[derive(Debug)]
pub struct QosRule {
    /// Rule ID
    pub id: u32,
    /// Active flag
    pub active: bool,
    /// Rule name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Parent policy ID
    pub policy_id: u32,
    /// Match type
    pub match_type: RuleMatchType,
    /// Application path (for Application match)
    pub app_path: [u8; MAX_PATH_LEN],
    /// App path length
    pub app_path_len: usize,
    /// Protocol (for Protocol match)
    pub protocol: Protocol,
    /// Port (for port-based match)
    pub port: u16,
    /// Port range end (0 = single port)
    pub port_end: u16,
    /// IP address (for IP-based match)
    pub ip_address: [u8; 4],
    /// IP mask
    pub ip_mask: [u8; 4],
    /// URL pattern (for URL match)
    pub url_pattern: [u8; MAX_NAME_LEN],
    /// URL pattern length
    pub url_pattern_len: usize,
    /// Rule enabled
    pub enabled: bool,
    /// Rule order/priority
    pub order: u32,
}

impl QosRule {
    /// Create new rule
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            policy_id: 0,
            match_type: RuleMatchType::Application,
            app_path: [0u8; MAX_PATH_LEN],
            app_path_len: 0,
            protocol: Protocol::Any,
            port: 0,
            port_end: 0,
            ip_address: [0u8; 4],
            ip_mask: [255, 255, 255, 255],
            url_pattern: [0u8; MAX_NAME_LEN],
            url_pattern_len: 0,
            enabled: true,
            order: 0,
        }
    }
}

/// Active flow entry
#[derive(Debug)]
pub struct FlowEntry {
    /// Flow ID
    pub id: u32,
    /// Active flag
    pub active: bool,
    /// Source IP
    pub src_ip: [u8; 4],
    /// Source port
    pub src_port: u16,
    /// Destination IP
    pub dst_ip: [u8; 4],
    /// Destination port
    pub dst_port: u16,
    /// Protocol
    pub protocol: Protocol,
    /// Applied policy ID
    pub policy_id: u32,
    /// Flow state
    pub state: FlowState,
    /// Applied DSCP
    pub dscp: DscpValue,
    /// Current rate (bps)
    pub current_rate: u64,
    /// Packets forwarded
    pub packets: u64,
    /// Bytes forwarded
    pub bytes: u64,
    /// First seen time
    pub first_seen: u64,
    /// Last seen time
    pub last_seen: u64,
}

impl FlowEntry {
    /// Create new flow
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            src_ip: [0u8; 4],
            src_port: 0,
            dst_ip: [0u8; 4],
            dst_port: 0,
            protocol: Protocol::Any,
            policy_id: 0,
            state: FlowState::Inactive,
            dscp: DscpValue::BestEffort,
            current_rate: 0,
            packets: 0,
            bytes: 0,
            first_seen: 0,
            last_seen: 0,
        }
    }
}

/// QoS Statistics
#[derive(Debug)]
pub struct QosStatistics {
    /// Total policies
    pub total_policies: u32,
    /// Active policies
    pub active_policies: u32,
    /// Total rules
    pub total_rules: u32,
    /// Active flows
    pub active_flows: u32,
    /// Total packets processed
    pub packets_processed: u64,
    /// Total bytes processed
    pub bytes_processed: u64,
    /// Packets throttled
    pub packets_throttled: u64,
    /// Packets dropped
    pub packets_dropped: u64,
}

impl QosStatistics {
    /// Create new statistics
    pub const fn new() -> Self {
        Self {
            total_policies: 0,
            active_policies: 0,
            total_rules: 0,
            active_flows: 0,
            packets_processed: 0,
            bytes_processed: 0,
            packets_throttled: 0,
            packets_dropped: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// QoS state
struct QosState {
    /// Policies
    policies: [QosPolicy; MAX_POLICIES],
    /// Rules
    rules: [QosRule; MAX_RULES],
    /// Active flows
    flows: [FlowEntry; MAX_FLOWS],
    /// Statistics
    stats: QosStatistics,
    /// Next ID counter
    next_id: u32,
}

impl QosState {
    /// Create new state
    const fn new() -> Self {
        Self {
            policies: [const { QosPolicy::new() }; MAX_POLICIES],
            rules: [const { QosRule::new() }; MAX_RULES],
            flows: [const { FlowEntry::new() }; MAX_FLOWS],
            stats: QosStatistics::new(),
            next_id: 1,
        }
    }
}

/// Global state
static QOS_STATE: SpinLock<QosState> = SpinLock::new(QosState::new());

/// Module initialized flag
static QOS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Policy count
static POLICY_COUNT: AtomicU32 = AtomicU32::new(0);

/// Rule count
static RULE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Total bytes processed
static TOTAL_BYTES: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Policy Functions
// ============================================================================

/// Create a QoS policy
pub fn create_policy(
    name: &[u8],
    policy_type: PolicyType,
    dscp_value: DscpValue,
    throttle_rate: u32,
) -> Result<u32, u32> {
    let mut state = QOS_STATE.lock();

    let slot = state.policies.iter().position(|p| !p.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let id = state.next_id;
    state.next_id += 1;

    let policy = &mut state.policies[slot];
    policy.id = id;
    policy.active = true;

    let name_len = name.len().min(MAX_NAME_LEN);
    policy.name[..name_len].copy_from_slice(&name[..name_len]);
    policy.name_len = name_len;

    policy.policy_type = policy_type;
    policy.dscp_value = dscp_value;
    policy.throttle_rate = throttle_rate;
    policy.status = PolicyStatus::Disabled;
    policy.created_time = 0;
    policy.hwnd = UserHandle::from_raw(id);

    state.stats.total_policies += 1;
    POLICY_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(id)
}

/// Delete a policy
pub fn delete_policy(policy_id: u32) -> Result<(), u32> {
    let mut state = QOS_STATE.lock();

    // Find policy index
    let policy_idx = state.policies.iter().position(|p| p.active && p.id == policy_id);
    let policy_idx = match policy_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    // Count and remove rules
    let mut rules_removed = 0u32;
    for rule in state.rules.iter_mut() {
        if rule.active && rule.policy_id == policy_id {
            rule.active = false;
            rules_removed += 1;
        }
    }

    let was_enabled = state.policies[policy_idx].status == PolicyStatus::Enabled;
    state.policies[policy_idx].active = false;

    // Update stats
    state.stats.total_rules = state.stats.total_rules.saturating_sub(rules_removed);
    RULE_COUNT.fetch_sub(rules_removed, Ordering::Relaxed);

    if was_enabled {
        state.stats.active_policies = state.stats.active_policies.saturating_sub(1);
    }
    state.stats.total_policies = state.stats.total_policies.saturating_sub(1);
    POLICY_COUNT.fetch_sub(1, Ordering::Relaxed);

    Ok(())
}

/// Enable a policy
pub fn enable_policy(policy_id: u32) -> Result<(), u32> {
    let mut state = QOS_STATE.lock();

    let policy_idx = state.policies.iter().position(|p| p.active && p.id == policy_id);
    let policy_idx = match policy_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    if state.policies[policy_idx].status != PolicyStatus::Enabled {
        state.policies[policy_idx].status = PolicyStatus::Enabled;
        state.stats.active_policies += 1;
    }

    Ok(())
}

/// Disable a policy
pub fn disable_policy(policy_id: u32) -> Result<(), u32> {
    let mut state = QOS_STATE.lock();

    let policy_idx = state.policies.iter().position(|p| p.active && p.id == policy_id);
    let policy_idx = match policy_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    if state.policies[policy_idx].status == PolicyStatus::Enabled {
        state.stats.active_policies = state.stats.active_policies.saturating_sub(1);
    }
    state.policies[policy_idx].status = PolicyStatus::Disabled;

    Ok(())
}

/// Set policy DSCP value
pub fn set_policy_dscp(policy_id: u32, dscp: DscpValue) -> Result<(), u32> {
    let mut state = QOS_STATE.lock();

    let policy = state.policies.iter_mut().find(|p| p.active && p.id == policy_id);

    match policy {
        Some(p) => {
            p.dscp_value = dscp;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Set policy throttle rate
pub fn set_policy_throttle(policy_id: u32, rate_kbps: u32) -> Result<(), u32> {
    let mut state = QOS_STATE.lock();

    let policy = state.policies.iter_mut().find(|p| p.active && p.id == policy_id);

    match policy {
        Some(p) => {
            p.throttle_rate = rate_kbps;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Get policy count
pub fn get_policy_count() -> u32 {
    POLICY_COUNT.load(Ordering::Relaxed)
}

// ============================================================================
// Rule Functions
// ============================================================================

/// Add an application rule
pub fn add_app_rule(policy_id: u32, name: &[u8], app_path: &[u8]) -> Result<u32, u32> {
    let mut state = QOS_STATE.lock();

    // Verify policy exists
    let policy_idx = state.policies.iter().position(|p| p.active && p.id == policy_id);
    if policy_idx.is_none() {
        return Err(0x80070002);
    }
    let policy_idx = policy_idx.unwrap();

    let slot = state.rules.iter().position(|r| !r.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let id = state.next_id;
    state.next_id += 1;

    let rule = &mut state.rules[slot];
    rule.id = id;
    rule.active = true;

    let name_len = name.len().min(MAX_NAME_LEN);
    rule.name[..name_len].copy_from_slice(&name[..name_len]);
    rule.name_len = name_len;

    rule.policy_id = policy_id;
    rule.match_type = RuleMatchType::Application;

    let path_len = app_path.len().min(MAX_PATH_LEN);
    rule.app_path[..path_len].copy_from_slice(&app_path[..path_len]);
    rule.app_path_len = path_len;

    rule.enabled = true;

    // Update policy rule count
    state.policies[policy_idx].rule_count += 1;
    state.stats.total_rules += 1;
    RULE_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(id)
}

/// Add a port rule
pub fn add_port_rule(
    policy_id: u32,
    name: &[u8],
    match_type: RuleMatchType,
    protocol: Protocol,
    port: u16,
    port_end: u16,
) -> Result<u32, u32> {
    let mut state = QOS_STATE.lock();

    // Verify policy exists
    let policy_idx = state.policies.iter().position(|p| p.active && p.id == policy_id);
    if policy_idx.is_none() {
        return Err(0x80070002);
    }
    let policy_idx = policy_idx.unwrap();

    let slot = state.rules.iter().position(|r| !r.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let id = state.next_id;
    state.next_id += 1;

    let rule = &mut state.rules[slot];
    rule.id = id;
    rule.active = true;

    let name_len = name.len().min(MAX_NAME_LEN);
    rule.name[..name_len].copy_from_slice(&name[..name_len]);
    rule.name_len = name_len;

    rule.policy_id = policy_id;
    rule.match_type = match_type;
    rule.protocol = protocol;
    rule.port = port;
    rule.port_end = port_end;
    rule.enabled = true;

    // Update policy rule count
    state.policies[policy_idx].rule_count += 1;
    state.stats.total_rules += 1;
    RULE_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(id)
}

/// Delete a rule
pub fn delete_rule(rule_id: u32) -> Result<(), u32> {
    let mut state = QOS_STATE.lock();

    // Find rule index
    let rule_idx = state.rules.iter().position(|r| r.active && r.id == rule_id);
    let rule_idx = match rule_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    let policy_id = state.rules[rule_idx].policy_id;
    state.rules[rule_idx].active = false;

    // Update policy rule count
    if let Some(p) = state.policies.iter_mut().find(|p| p.active && p.id == policy_id) {
        p.rule_count = p.rule_count.saturating_sub(1);
    }

    state.stats.total_rules = state.stats.total_rules.saturating_sub(1);
    RULE_COUNT.fetch_sub(1, Ordering::Relaxed);

    Ok(())
}

/// Enable or disable a rule
pub fn set_rule_enabled(rule_id: u32, enabled: bool) -> Result<(), u32> {
    let mut state = QOS_STATE.lock();

    let rule = state.rules.iter_mut().find(|r| r.active && r.id == rule_id);

    match rule {
        Some(r) => {
            r.enabled = enabled;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Get rule count
pub fn get_rule_count() -> u32 {
    RULE_COUNT.load(Ordering::Relaxed)
}

// ============================================================================
// Flow Functions
// ============================================================================

/// Create a flow entry
pub fn create_flow(
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    protocol: Protocol,
    policy_id: u32,
) -> Result<u32, u32> {
    let mut state = QOS_STATE.lock();

    let slot = state.flows.iter().position(|f| !f.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let id = state.next_id;
    state.next_id += 1;

    // Get DSCP from policy first
    let dscp = state.policies.iter()
        .find(|p| p.active && p.id == policy_id)
        .map(|p| p.dscp_value)
        .unwrap_or(DscpValue::BestEffort);

    state.flows[slot].id = id;
    state.flows[slot].active = true;
    state.flows[slot].src_ip = src_ip;
    state.flows[slot].src_port = src_port;
    state.flows[slot].dst_ip = dst_ip;
    state.flows[slot].dst_port = dst_port;
    state.flows[slot].protocol = protocol;
    state.flows[slot].policy_id = policy_id;
    state.flows[slot].state = FlowState::Active;
    state.flows[slot].first_seen = 0;
    state.flows[slot].last_seen = 0;
    state.flows[slot].dscp = dscp;

    state.stats.active_flows += 1;

    Ok(id)
}

/// Remove a flow
pub fn remove_flow(flow_id: u32) -> Result<(), u32> {
    let mut state = QOS_STATE.lock();

    let flow = state.flows.iter_mut().find(|f| f.active && f.id == flow_id);

    match flow {
        Some(f) => {
            f.active = false;
            f.state = FlowState::Inactive;
            state.stats.active_flows = state.stats.active_flows.saturating_sub(1);
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Update flow statistics
pub fn update_flow_stats(flow_id: u32, packets: u64, bytes: u64) {
    let mut state = QOS_STATE.lock();

    let flow_idx = state.flows.iter().position(|f| f.active && f.id == flow_id);
    let flow_idx = match flow_idx {
        Some(idx) => idx,
        None => return,
    };

    // Get policy_id first
    let policy_id = state.flows[flow_idx].policy_id;

    // Update flow stats
    state.flows[flow_idx].packets += packets;
    state.flows[flow_idx].bytes += bytes;
    state.flows[flow_idx].last_seen = 0;

    // Update global stats
    state.stats.packets_processed += packets;
    state.stats.bytes_processed += bytes;
    TOTAL_BYTES.fetch_add(bytes, Ordering::Relaxed);

    // Update policy stats
    if let Some(p) = state.policies.iter_mut().find(|p| p.active && p.id == policy_id) {
        p.packets_matched += packets;
        p.bytes_matched += bytes;
    }
}

/// Set flow state
pub fn set_flow_state(flow_id: u32, new_state: FlowState) -> Result<(), u32> {
    let mut state = QOS_STATE.lock();

    let flow = state.flows.iter_mut().find(|f| f.active && f.id == flow_id);

    match flow {
        Some(f) => {
            f.state = new_state;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

// ============================================================================
// Statistics Functions
// ============================================================================

/// Record throttled packet
pub fn record_throttled() {
    let mut state = QOS_STATE.lock();
    state.stats.packets_throttled += 1;
}

/// Record dropped packet
pub fn record_dropped() {
    let mut state = QOS_STATE.lock();
    state.stats.packets_dropped += 1;
}

/// Get statistics
pub fn get_statistics() -> QosStatistics {
    let state = QOS_STATE.lock();
    QosStatistics {
        total_policies: state.stats.total_policies,
        active_policies: state.stats.active_policies,
        total_rules: state.stats.total_rules,
        active_flows: state.stats.active_flows,
        packets_processed: state.stats.packets_processed,
        bytes_processed: state.stats.bytes_processed,
        packets_throttled: state.stats.packets_throttled,
        packets_dropped: state.stats.packets_dropped,
    }
}

/// Get total bytes processed
pub fn get_total_bytes() -> u64 {
    TOTAL_BYTES.load(Ordering::Relaxed)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize QoS module
pub fn init() -> Result<(), &'static str> {
    if QOS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let mut state = QOS_STATE.lock();

    // Reserve ID for example policy
    let policy_id = state.next_id;
    let rule_id = state.next_id + 1;
    state.next_id += 2;

    // Create example VoIP policy
    {
        let policy = &mut state.policies[0];
        policy.id = policy_id;
        policy.active = true;
        let name = b"VoIP Priority";
        policy.name[..name.len()].copy_from_slice(name);
        policy.name_len = name.len();
        let desc = b"Prioritize voice traffic";
        policy.description[..desc.len()].copy_from_slice(desc);
        policy.desc_len = desc.len();
        policy.policy_type = PolicyType::DscpMarking;
        policy.dscp_value = DscpValue::Ef;
        policy.priority = 7;
        policy.status = PolicyStatus::Enabled;
        policy.hwnd = UserHandle::from_raw(policy_id);
    }

    // Create SIP rule for VoIP policy
    {
        let rule = &mut state.rules[0];
        rule.id = rule_id;
        rule.active = true;
        let name = b"SIP Traffic";
        rule.name[..name.len()].copy_from_slice(name);
        rule.name_len = name.len();
        rule.policy_id = policy_id;
        rule.match_type = RuleMatchType::DestinationPort;
        rule.protocol = Protocol::Udp;
        rule.port = 5060;
        rule.enabled = true;
    }

    state.policies[0].rule_count = 1;
    state.stats.total_policies = 1;
    state.stats.active_policies = 1;
    state.stats.total_rules = 1;

    POLICY_COUNT.store(1, Ordering::Relaxed);
    RULE_COUNT.store(1, Ordering::Relaxed);

    Ok(())
}

/// Check if module is initialized
pub fn is_initialized() -> bool {
    QOS_INITIALIZED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_type() {
        assert_eq!(PolicyType::default(), PolicyType::DscpMarking);
        assert_eq!(PolicyType::Throttle as u32, 1);
    }

    #[test]
    fn test_dscp_value() {
        assert_eq!(DscpValue::default(), DscpValue::BestEffort);
        assert_eq!(DscpValue::Ef as u8, 46);
    }

    #[test]
    fn test_protocol() {
        assert_eq!(Protocol::default(), Protocol::Any);
        assert_eq!(Protocol::Tcp as u8, 6);
    }
}
