//! Security Auditing Subsystem
//!
//! Provides security audit functionality:
//! - Audit event types and categories
//! - Audit record queuing and logging
//! - Component-based audit filtering
//! - Crash-on-audit-fail support (C2 compliance)
//!
//! Based on Windows Server 2003 base/ntos/se/adtinit.c and adtlog.c

use crate::ke::SpinLock;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

extern crate alloc;

/// Default audit queue bounds
pub const SEP_ADT_MIN_LIST_LENGTH: usize = 16;
pub const SEP_ADT_MAX_LIST_LENGTH: usize = 256;

/// Maximum audit parameters
pub const SE_MAX_AUDIT_PARAMETERS: usize = 32;

/// Audit event IDs
pub mod audit_event_id {
    /// System events
    pub const SE_AUDITID_SYSTEM_RESTART: u32 = 512;
    pub const SE_AUDITID_SYSTEM_SHUTDOWN: u32 = 513;
    pub const SE_AUDITID_AUTH_PACKAGE_LOAD: u32 = 514;
    pub const SE_AUDITID_LOGON_PROC_REGISTER: u32 = 515;
    pub const SE_AUDITID_AUDITS_DISCARDED: u32 = 516;
    pub const SE_AUDITID_AUDIT_LOG_CLEARED: u32 = 517;

    /// Logon/Logoff events
    pub const SE_AUDITID_SUCCESSFUL_LOGON: u32 = 528;
    pub const SE_AUDITID_UNKNOWN_USER_OR_PWD: u32 = 529;
    pub const SE_AUDITID_ACCOUNT_TIME_RESTR: u32 = 530;
    pub const SE_AUDITID_ACCOUNT_DISABLED: u32 = 531;
    pub const SE_AUDITID_ACCOUNT_EXPIRED: u32 = 532;
    pub const SE_AUDITID_WORKSTATION_DENIED: u32 = 533;
    pub const SE_AUDITID_ACCOUNT_LOGON_TYPE: u32 = 534;
    pub const SE_AUDITID_LOGOFF: u32 = 538;
    pub const SE_AUDITID_ACCOUNT_LOCKED: u32 = 539;

    /// Object access events
    pub const SE_AUDITID_OPEN_HANDLE: u32 = 560;
    pub const SE_AUDITID_CLOSE_HANDLE: u32 = 562;
    pub const SE_AUDITID_OPEN_OBJECT_FOR_DELETE: u32 = 563;
    pub const SE_AUDITID_DELETE_OBJECT: u32 = 564;

    /// Privilege use events
    pub const SE_AUDITID_ASSIGN_SPECIAL_PRIV: u32 = 576;
    pub const SE_AUDITID_PRIVILEGED_SERVICE: u32 = 577;
    pub const SE_AUDITID_PRIVILEGED_OBJECT: u32 = 578;

    /// Process tracking events
    pub const SE_AUDITID_PROCESS_CREATED: u32 = 592;
    pub const SE_AUDITID_PROCESS_EXIT: u32 = 593;
    pub const SE_AUDITID_DUPLICATE_HANDLE: u32 = 594;
    pub const SE_AUDITID_INDIRECT_ACCESS: u32 = 595;

    /// Policy change events
    pub const SE_AUDITID_POLICY_CHANGE: u32 = 612;
    pub const SE_AUDITID_USER_RIGHT_ASSIGNED: u32 = 608;
    pub const SE_AUDITID_USER_RIGHT_REMOVED: u32 = 609;
    pub const SE_AUDITID_TRUSTED_DOMAIN_ADD: u32 = 610;
    pub const SE_AUDITID_TRUSTED_DOMAIN_REM: u32 = 611;

    /// Account management events
    pub const SE_AUDITID_USER_CREATED: u32 = 624;
    pub const SE_AUDITID_USER_CHANGE: u32 = 642;
    pub const SE_AUDITID_USER_DELETED: u32 = 630;
    pub const SE_AUDITID_GLOBAL_GROUP_CREATED: u32 = 631;
    pub const SE_AUDITID_GLOBAL_GROUP_ADD: u32 = 632;
    pub const SE_AUDITID_GLOBAL_GROUP_REM: u32 = 633;
    pub const SE_AUDITID_GLOBAL_GROUP_DELETED: u32 = 634;
    pub const SE_AUDITID_LOCAL_GROUP_CREATED: u32 = 635;
    pub const SE_AUDITID_LOCAL_GROUP_ADD: u32 = 636;
    pub const SE_AUDITID_LOCAL_GROUP_REM: u32 = 637;
    pub const SE_AUDITID_LOCAL_GROUP_DELETED: u32 = 638;
}

/// Audit event categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuditEventCategory {
    /// System events (startup, shutdown, etc.)
    System = 0,
    /// Logon/Logoff events
    Logon = 1,
    /// Object access events
    ObjectAccess = 2,
    /// Privilege use events
    PrivilegeUse = 3,
    /// Detailed tracking events
    DetailedTracking = 4,
    /// Policy change events
    PolicyChange = 5,
    /// Account management events
    AccountManagement = 6,
    /// Directory service access (not used in 2003)
    DirectoryServiceAccess = 7,
    /// Account logon events
    AccountLogon = 8,
}

/// Audit event type (success/failure)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuditEventType {
    /// Successful event
    Success = 0,
    /// Failed event
    Failure = 1,
}

/// Audit parameter types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuditParameterType {
    /// No parameter
    None = 0,
    /// Unsigned long value
    Ulong = 1,
    /// Hex unsigned long
    HexUlong = 2,
    /// Unicode string
    String = 3,
    /// File specification
    FileSpec = 4,
    /// SID value
    Sid = 5,
    /// Logon ID (LUID)
    LogonId = 6,
    /// No logon ID
    NoLogonId = 7,
    /// Access mask
    AccessMask = 8,
    /// Privilege set
    Privs = 9,
    /// Object types
    ObjectTypes = 10,
    /// Time value
    Time = 11,
    /// Pointer value
    Ptr = 12,
}

/// Single audit parameter
#[derive(Debug, Clone)]
pub struct AuditParameter {
    /// Parameter type
    pub param_type: AuditParameterType,
    /// Parameter length
    pub length: usize,
    /// Parameter data (as string for simplicity)
    pub data: String,
}

impl AuditParameter {
    pub fn none() -> Self {
        Self {
            param_type: AuditParameterType::None,
            length: 0,
            data: String::new(),
        }
    }

    pub fn ulong(value: u64) -> Self {
        Self {
            param_type: AuditParameterType::Ulong,
            length: 8,
            data: alloc::format!("{}", value),
        }
    }

    pub fn hex_ulong(value: u64) -> Self {
        Self {
            param_type: AuditParameterType::HexUlong,
            length: 8,
            data: alloc::format!("{:#x}", value),
        }
    }

    pub fn string(s: &str) -> Self {
        Self {
            param_type: AuditParameterType::String,
            length: s.len(),
            data: String::from(s),
        }
    }

    pub fn sid(sid_string: &str) -> Self {
        Self {
            param_type: AuditParameterType::Sid,
            length: sid_string.len(),
            data: String::from(sid_string),
        }
    }

    pub fn access_mask(mask: u32) -> Self {
        Self {
            param_type: AuditParameterType::AccessMask,
            length: 4,
            data: alloc::format!("{:#x}", mask),
        }
    }
}

/// Audit parameter array
#[derive(Debug, Clone)]
pub struct AuditParameterArray {
    /// Audit event category
    pub category: AuditEventCategory,
    /// Audit event ID
    pub audit_id: u32,
    /// Event type (success/failure)
    pub event_type: AuditEventType,
    /// Parameter count
    pub parameter_count: usize,
    /// Parameters
    pub parameters: [Option<AuditParameter>; SE_MAX_AUDIT_PARAMETERS],
    /// Total length
    pub length: usize,
    /// Self-relative flag
    pub self_relative: bool,
}

impl AuditParameterArray {
    pub fn new(category: AuditEventCategory, audit_id: u32, event_type: AuditEventType) -> Self {
        const NONE: Option<AuditParameter> = None;
        Self {
            category,
            audit_id,
            event_type,
            parameter_count: 0,
            parameters: [NONE; SE_MAX_AUDIT_PARAMETERS],
            length: 0,
            self_relative: false,
        }
    }

    /// Add a parameter
    pub fn add_parameter(&mut self, param: AuditParameter) -> bool {
        if self.parameter_count >= SE_MAX_AUDIT_PARAMETERS {
            return false;
        }
        self.length += param.length;
        self.parameters[self.parameter_count] = Some(param);
        self.parameter_count += 1;
        true
    }
}

/// Audit work item for the queue
#[derive(Debug, Clone)]
pub struct AuditWorkItem {
    /// Timestamp
    pub timestamp: u64,
    /// Audit parameters
    pub parameters: AuditParameterArray,
}

/// Audit queue bounds
#[derive(Debug, Clone, Copy)]
pub struct AuditBounds {
    /// High water mark (upper bound)
    pub upper_bound: usize,
    /// Low water mark (lower bound)
    pub lower_bound: usize,
}

impl Default for AuditBounds {
    fn default() -> Self {
        Self {
            upper_bound: SEP_ADT_MAX_LIST_LENGTH,
            lower_bound: SEP_ADT_MIN_LIST_LENGTH,
        }
    }
}

/// Audit options
#[derive(Debug, Clone, Copy)]
pub struct AuditOptions {
    /// Do not audit close object events
    pub do_not_audit_close_object_events: bool,
    /// Full privilege auditing
    pub full_privilege_auditing: bool,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            do_not_audit_close_object_events: false,
            full_privilege_auditing: false,
        }
    }
}

/// Audit category policy
#[derive(Debug, Clone, Copy, Default)]
pub struct AuditPolicy {
    /// Audit success events
    pub audit_success: bool,
    /// Audit failure events
    pub audit_failure: bool,
}

/// Audit subsystem state
#[derive(Debug)]
pub struct AuditState {
    /// Audit queue
    queue: VecDeque<AuditWorkItem>,
    /// Queue bounds
    bounds: AuditBounds,
    /// Audit options
    options: AuditOptions,
    /// Category policies
    policies: [AuditPolicy; 9],
    /// Currently discarding audits
    discarding: bool,
    /// Discarded event count
    discarded_count: u64,
    /// Crash on audit fail flag
    crash_on_fail: bool,
}

impl AuditState {
    pub const fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            bounds: AuditBounds {
                upper_bound: SEP_ADT_MAX_LIST_LENGTH,
                lower_bound: SEP_ADT_MIN_LIST_LENGTH,
            },
            options: AuditOptions {
                do_not_audit_close_object_events: false,
                full_privilege_auditing: false,
            },
            policies: [AuditPolicy {
                audit_success: false,
                audit_failure: false,
            }; 9],
            discarding: false,
            discarded_count: 0,
            crash_on_fail: false,
        }
    }
}

/// Global audit state
static mut AUDIT_STATE: Option<SpinLock<AuditState>> = None;

/// Statistics
static AUDITS_GENERATED: AtomicU64 = AtomicU64::new(0);
static AUDITS_LOGGED: AtomicU64 = AtomicU64::new(0);
static AUDITS_DISCARDED: AtomicU64 = AtomicU64::new(0);
static AUDITS_FAILED: AtomicU64 = AtomicU64::new(0);
static AUDIT_INITIALIZED: AtomicBool = AtomicBool::new(false);

fn get_audit_state() -> &'static SpinLock<AuditState> {
    unsafe {
        AUDIT_STATE
            .as_ref()
            .expect("Audit subsystem not initialized")
    }
}

/// Validate audit bounds
fn sep_adt_validate_bounds(upper: usize, lower: usize) -> bool {
    if lower >= upper {
        return false;
    }
    if lower < 16 {
        return false;
    }
    if (upper - lower) < 16 {
        return false;
    }
    true
}

/// Initialize audit subsystem
pub fn sep_adt_init() {
    unsafe {
        AUDIT_STATE = Some(SpinLock::new(AuditState::new()));
    }

    // Initialize default policies - enable failure auditing for critical categories
    let state = get_audit_state();
    let mut guard = state.lock();

    // Enable system event auditing
    guard.policies[AuditEventCategory::System as usize] = AuditPolicy {
        audit_success: true,
        audit_failure: true,
    };

    // Enable logon auditing
    guard.policies[AuditEventCategory::Logon as usize] = AuditPolicy {
        audit_success: true,
        audit_failure: true,
    };

    // Enable object access failure auditing
    guard.policies[AuditEventCategory::ObjectAccess as usize] = AuditPolicy {
        audit_success: false,
        audit_failure: true,
    };

    // Enable privilege use auditing
    guard.policies[AuditEventCategory::PrivilegeUse as usize] = AuditPolicy {
        audit_success: false,
        audit_failure: true,
    };

    // Enable policy change auditing
    guard.policies[AuditEventCategory::PolicyChange as usize] = AuditPolicy {
        audit_success: true,
        audit_failure: true,
    };

    // Enable account management auditing
    guard.policies[AuditEventCategory::AccountManagement as usize] = AuditPolicy {
        audit_success: true,
        audit_failure: true,
    };

    drop(guard);

    AUDIT_INITIALIZED.store(true, Ordering::SeqCst);
    crate::serial_println!("[SE] Audit subsystem initialized");
}

/// Set audit queue bounds
pub fn sep_adt_set_bounds(upper: usize, lower: usize) -> bool {
    if !sep_adt_validate_bounds(upper, lower) {
        return false;
    }

    let state = get_audit_state();
    let mut guard = state.lock();

    guard.bounds.upper_bound = upper;
    guard.bounds.lower_bound = lower;

    crate::serial_println!(
        "[SE] Audit bounds set: lower={}, upper={}",
        lower,
        upper
    );

    true
}

/// Get audit queue bounds
pub fn sep_adt_get_bounds() -> AuditBounds {
    let state = get_audit_state();
    let guard = state.lock();
    guard.bounds
}

/// Set crash on audit fail
pub fn sep_adt_set_crash_on_fail(enabled: bool) {
    let state = get_audit_state();
    let mut guard = state.lock();
    guard.crash_on_fail = enabled;

    crate::serial_println!("[SE] Crash on audit fail: {}", enabled);
}

/// Get crash on audit fail setting
pub fn sep_adt_get_crash_on_fail() -> bool {
    let state = get_audit_state();
    let guard = state.lock();
    guard.crash_on_fail
}

/// Set audit policy for a category
pub fn sep_adt_set_policy(category: AuditEventCategory, policy: AuditPolicy) {
    let state = get_audit_state();
    let mut guard = state.lock();

    let index = category as usize;
    if index < guard.policies.len() {
        guard.policies[index] = policy;
        crate::serial_println!(
            "[SE] Audit policy for {:?}: success={}, failure={}",
            category,
            policy.audit_success,
            policy.audit_failure
        );
    }
}

/// Get audit policy for a category
pub fn sep_adt_get_policy(category: AuditEventCategory) -> AuditPolicy {
    let state = get_audit_state();
    let guard = state.lock();

    let index = category as usize;
    if index < guard.policies.len() {
        guard.policies[index]
    } else {
        AuditPolicy::default()
    }
}

/// Set audit options
pub fn sep_adt_set_options(options: AuditOptions) {
    let state = get_audit_state();
    let mut guard = state.lock();
    guard.options = options;

    crate::serial_println!(
        "[SE] Audit options: do_not_audit_close={}, full_privilege={}",
        options.do_not_audit_close_object_events,
        options.full_privilege_auditing
    );
}

/// Get audit options
pub fn sep_adt_get_options() -> AuditOptions {
    let state = get_audit_state();
    let guard = state.lock();
    guard.options
}

/// Check if audit should be generated for event
pub fn sep_adt_should_audit(category: AuditEventCategory, event_type: AuditEventType) -> bool {
    if !AUDIT_INITIALIZED.load(Ordering::SeqCst) {
        return false;
    }

    let state = get_audit_state();
    let guard = state.lock();

    let index = category as usize;
    if index >= guard.policies.len() {
        return false;
    }

    let policy = &guard.policies[index];
    match event_type {
        AuditEventType::Success => policy.audit_success,
        AuditEventType::Failure => policy.audit_failure,
    }
}

/// Log an audit record
pub fn sep_adt_log_audit_record(parameters: AuditParameterArray) {
    AUDITS_GENERATED.fetch_add(1, Ordering::Relaxed);

    // Check if we should audit this event
    if !sep_adt_should_audit(parameters.category, parameters.event_type) {
        return;
    }

    let state = get_audit_state();
    let mut guard = state.lock();

    // Check if discarding
    if guard.discarding {
        // Check if we're below low water mark
        if guard.queue.len() < guard.bounds.lower_bound {
            guard.discarding = false;
            // Generate discarded audits event
            let discarded = guard.discarded_count;
            guard.discarded_count = 0;
            crate::serial_println!("[SE] Audit: {} events were discarded", discarded);
        } else {
            guard.discarded_count += 1;
            AUDITS_DISCARDED.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }

    // Check queue bounds
    let force_queue = guard.crash_on_fail
        || parameters.audit_id == audit_event_id::SE_AUDITID_AUDITS_DISCARDED;

    if guard.queue.len() >= guard.bounds.upper_bound && !force_queue {
        // Start discarding
        guard.discarding = true;
        guard.discarded_count += 1;
        AUDITS_DISCARDED.fetch_add(1, Ordering::Relaxed);

        // Handle crash on fail
        if guard.crash_on_fail {
            sep_audit_failed_internal();
        }
        return;
    }

    // Create work item
    let work_item = AuditWorkItem {
        timestamp: unsafe { core::arch::x86_64::_rdtsc() },
        parameters,
    };

    // Queue the audit
    guard.queue.push_back(work_item);
    AUDITS_LOGGED.fetch_add(1, Ordering::Relaxed);

    // Log to serial for immediate visibility
    let params = &guard.queue.back().unwrap().parameters;
    crate::serial_println!(
        "[AUDIT] Category={:?} ID={} Type={:?}",
        params.category,
        params.audit_id,
        params.event_type
    );
}

/// Handle audit failure (C2 compliance)
fn sep_audit_failed_internal() {
    AUDITS_FAILED.fetch_add(1, Ordering::Relaxed);
    // In a real implementation, this would bugcheck the system
    // For now, just log
    crate::serial_println!("[SE] AUDIT FAILED - Would bugcheck on C2 system");
}

/// Dequeue an audit work item
pub fn sep_adt_dequeue_work_item() -> Option<AuditWorkItem> {
    let state = get_audit_state();
    let mut guard = state.lock();
    guard.queue.pop_front()
}

/// Get queue length
pub fn sep_adt_get_queue_length() -> usize {
    let state = get_audit_state();
    let guard = state.lock();
    guard.queue.len()
}

/// Clear audit queue
pub fn sep_adt_clear_queue() {
    let state = get_audit_state();
    let mut guard = state.lock();
    guard.queue.clear();
    guard.discarding = false;
    guard.discarded_count = 0;

    crate::serial_println!("[SE] Audit queue cleared");
}

/// Get recent audit records
pub fn sep_adt_get_recent(count: usize) -> Vec<AuditWorkItem> {
    let state = get_audit_state();
    let guard = state.lock();

    let take_count = count.min(guard.queue.len());
    guard.queue.iter().rev().take(take_count).cloned().collect()
}

/// Get audit statistics
pub fn sep_adt_get_stats() -> (u64, u64, u64, u64, usize) {
    let state = get_audit_state();
    let guard = state.lock();

    (
        AUDITS_GENERATED.load(Ordering::Relaxed),
        AUDITS_LOGGED.load(Ordering::Relaxed),
        AUDITS_DISCARDED.load(Ordering::Relaxed),
        AUDITS_FAILED.load(Ordering::Relaxed),
        guard.queue.len(),
    )
}

/// Get audit policies as array
pub fn sep_adt_get_all_policies() -> [(AuditEventCategory, AuditPolicy); 9] {
    let state = get_audit_state();
    let guard = state.lock();

    [
        (AuditEventCategory::System, guard.policies[0]),
        (AuditEventCategory::Logon, guard.policies[1]),
        (AuditEventCategory::ObjectAccess, guard.policies[2]),
        (AuditEventCategory::PrivilegeUse, guard.policies[3]),
        (AuditEventCategory::DetailedTracking, guard.policies[4]),
        (AuditEventCategory::PolicyChange, guard.policies[5]),
        (AuditEventCategory::AccountManagement, guard.policies[6]),
        (AuditEventCategory::DirectoryServiceAccess, guard.policies[7]),
        (AuditEventCategory::AccountLogon, guard.policies[8]),
    ]
}

// Convenience functions for common audit events

/// Audit a successful logon
pub fn se_audit_logon_success(user_sid: &str, logon_type: u32, source: &str) {
    let mut params = AuditParameterArray::new(
        AuditEventCategory::Logon,
        audit_event_id::SE_AUDITID_SUCCESSFUL_LOGON,
        AuditEventType::Success,
    );
    params.add_parameter(AuditParameter::sid(user_sid));
    params.add_parameter(AuditParameter::ulong(logon_type as u64));
    params.add_parameter(AuditParameter::string(source));
    sep_adt_log_audit_record(params);
}

/// Audit a failed logon
pub fn se_audit_logon_failure(user_name: &str, reason: u32) {
    let mut params = AuditParameterArray::new(
        AuditEventCategory::Logon,
        audit_event_id::SE_AUDITID_UNKNOWN_USER_OR_PWD,
        AuditEventType::Failure,
    );
    params.add_parameter(AuditParameter::string(user_name));
    params.add_parameter(AuditParameter::hex_ulong(reason as u64));
    sep_adt_log_audit_record(params);
}

/// Audit a logoff
pub fn se_audit_logoff(user_sid: &str, logon_id: u64) {
    let mut params = AuditParameterArray::new(
        AuditEventCategory::Logon,
        audit_event_id::SE_AUDITID_LOGOFF,
        AuditEventType::Success,
    );
    params.add_parameter(AuditParameter::sid(user_sid));
    params.add_parameter(AuditParameter::hex_ulong(logon_id));
    sep_adt_log_audit_record(params);
}

/// Audit object access
pub fn se_audit_object_access(
    object_name: &str,
    object_type: &str,
    access_mask: u32,
    success: bool,
) {
    let event_type = if success {
        AuditEventType::Success
    } else {
        AuditEventType::Failure
    };

    let mut params = AuditParameterArray::new(
        AuditEventCategory::ObjectAccess,
        audit_event_id::SE_AUDITID_OPEN_HANDLE,
        event_type,
    );
    params.add_parameter(AuditParameter::string(object_name));
    params.add_parameter(AuditParameter::string(object_type));
    params.add_parameter(AuditParameter::access_mask(access_mask));
    sep_adt_log_audit_record(params);
}

/// Audit privilege use
pub fn se_audit_privilege_use(privilege_name: &str, success: bool) {
    let event_type = if success {
        AuditEventType::Success
    } else {
        AuditEventType::Failure
    };

    let mut params = AuditParameterArray::new(
        AuditEventCategory::PrivilegeUse,
        audit_event_id::SE_AUDITID_PRIVILEGED_SERVICE,
        event_type,
    );
    params.add_parameter(AuditParameter::string(privilege_name));
    sep_adt_log_audit_record(params);
}

/// Audit process creation
pub fn se_audit_process_created(process_name: &str, process_id: u64, parent_id: u64) {
    let mut params = AuditParameterArray::new(
        AuditEventCategory::DetailedTracking,
        audit_event_id::SE_AUDITID_PROCESS_CREATED,
        AuditEventType::Success,
    );
    params.add_parameter(AuditParameter::string(process_name));
    params.add_parameter(AuditParameter::hex_ulong(process_id));
    params.add_parameter(AuditParameter::hex_ulong(parent_id));
    sep_adt_log_audit_record(params);
}

/// Audit process exit
pub fn se_audit_process_exit(process_id: u64, exit_code: u32) {
    let mut params = AuditParameterArray::new(
        AuditEventCategory::DetailedTracking,
        audit_event_id::SE_AUDITID_PROCESS_EXIT,
        AuditEventType::Success,
    );
    params.add_parameter(AuditParameter::hex_ulong(process_id));
    params.add_parameter(AuditParameter::hex_ulong(exit_code as u64));
    sep_adt_log_audit_record(params);
}

/// Audit policy change
pub fn se_audit_policy_change(policy_type: &str, old_value: &str, new_value: &str) {
    let mut params = AuditParameterArray::new(
        AuditEventCategory::PolicyChange,
        audit_event_id::SE_AUDITID_POLICY_CHANGE,
        AuditEventType::Success,
    );
    params.add_parameter(AuditParameter::string(policy_type));
    params.add_parameter(AuditParameter::string(old_value));
    params.add_parameter(AuditParameter::string(new_value));
    sep_adt_log_audit_record(params);
}

/// Audit user created
pub fn se_audit_user_created(account_name: &str, account_sid: &str) {
    let mut params = AuditParameterArray::new(
        AuditEventCategory::AccountManagement,
        audit_event_id::SE_AUDITID_USER_CREATED,
        AuditEventType::Success,
    );
    params.add_parameter(AuditParameter::string(account_name));
    params.add_parameter(AuditParameter::sid(account_sid));
    sep_adt_log_audit_record(params);
}

/// Audit system startup
pub fn se_audit_system_startup() {
    let params = AuditParameterArray::new(
        AuditEventCategory::System,
        audit_event_id::SE_AUDITID_SYSTEM_RESTART,
        AuditEventType::Success,
    );
    sep_adt_log_audit_record(params);
}

/// Audit system shutdown
pub fn se_audit_system_shutdown() {
    let params = AuditParameterArray::new(
        AuditEventCategory::System,
        audit_event_id::SE_AUDITID_SYSTEM_SHUTDOWN,
        AuditEventType::Success,
    );
    sep_adt_log_audit_record(params);
}

/// Get category name
pub fn audit_category_name(category: AuditEventCategory) -> &'static str {
    match category {
        AuditEventCategory::System => "System",
        AuditEventCategory::Logon => "Logon/Logoff",
        AuditEventCategory::ObjectAccess => "Object Access",
        AuditEventCategory::PrivilegeUse => "Privilege Use",
        AuditEventCategory::DetailedTracking => "Detailed Tracking",
        AuditEventCategory::PolicyChange => "Policy Change",
        AuditEventCategory::AccountManagement => "Account Management",
        AuditEventCategory::DirectoryServiceAccess => "Directory Service",
        AuditEventCategory::AccountLogon => "Account Logon",
    }
}
