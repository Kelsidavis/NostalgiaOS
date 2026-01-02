//! Alerter Service
//!
//! The Alerter service notifies selected users and computers of
//! administrative alerts. It works with the Messenger service to
//! deliver alert messages.
//!
//! # Features
//!
//! - **Alert Recipients**: Manage list of alert recipients
//! - **Alert Types**: Different alert categories (print, admin, etc.)
//! - **Alert Delivery**: Send alerts via Messenger service
//! - **Alert Logging**: Log alerts to event log
//!
//! # Alert Sources
//!
//! - Print spooler (job completion, errors)
//! - UPS service (power events)
//! - Server service (share access issues)
//! - Replicator service (replication events)
//!
//! # Alert Names
//!
//! Recipients are registered by NetBIOS name or username.

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum alert recipients
const MAX_RECIPIENTS: usize = 32;

/// Maximum name length
const MAX_NAME: usize = 20;

/// Maximum alert message length
const MAX_ALERT_LEN: usize = 512;

/// Maximum queued alerts
const MAX_ALERTS: usize = 64;

/// Alert type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertType {
    /// Print job alerts
    Print = 0,
    /// Administrative alerts
    Admin = 1,
    /// User alerts
    User = 2,
    /// UPS/Power alerts
    Ups = 3,
    /// Error/Warning alerts
    Error = 4,
    /// Custom alerts
    Custom = 5,
}

impl AlertType {
    const fn empty() -> Self {
        AlertType::Admin
    }
}

/// Alert severity
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSeverity {
    /// Informational
    Info = 0,
    /// Warning
    Warning = 1,
    /// Error
    Error = 2,
    /// Critical
    Critical = 3,
}

impl AlertSeverity {
    const fn empty() -> Self {
        AlertSeverity::Info
    }
}

/// Alert recipient
#[repr(C)]
#[derive(Clone)]
pub struct AlertRecipient {
    /// Recipient name (user or computer)
    pub name: [u8; MAX_NAME],
    /// Is computer name (vs username)
    pub is_computer: bool,
    /// Receive print alerts
    pub print_alerts: bool,
    /// Receive admin alerts
    pub admin_alerts: bool,
    /// Receive UPS alerts
    pub ups_alerts: bool,
    /// Receive error alerts
    pub error_alerts: bool,
    /// Entry is valid
    pub valid: bool,
}

impl AlertRecipient {
    const fn empty() -> Self {
        AlertRecipient {
            name: [0; MAX_NAME],
            is_computer: true,
            print_alerts: true,
            admin_alerts: true,
            ups_alerts: true,
            error_alerts: true,
            valid: false,
        }
    }
}

/// Queued alert
#[repr(C)]
#[derive(Clone)]
pub struct QueuedAlert {
    /// Alert ID
    pub alert_id: u64,
    /// Alert type
    pub alert_type: AlertType,
    /// Severity
    pub severity: AlertSeverity,
    /// Source (service/component)
    pub source: [u8; 32],
    /// Message text
    pub message: [u8; MAX_ALERT_LEN],
    /// Message length
    pub message_len: usize,
    /// Timestamp
    pub timestamp: i64,
    /// Recipients notified count
    pub notified: u32,
    /// Is pending
    pub pending: bool,
    /// Entry is valid
    pub valid: bool,
}

impl QueuedAlert {
    const fn empty() -> Self {
        QueuedAlert {
            alert_id: 0,
            alert_type: AlertType::empty(),
            severity: AlertSeverity::empty(),
            source: [0; 32],
            message: [0; MAX_ALERT_LEN],
            message_len: 0,
            timestamp: 0,
            notified: 0,
            pending: true,
            valid: false,
        }
    }
}

/// Alerter service state
pub struct AlerterState {
    /// Service is running
    pub running: bool,
    /// Alert recipients
    pub recipients: [AlertRecipient; MAX_RECIPIENTS],
    /// Recipient count
    pub recipient_count: usize,
    /// Queued alerts
    pub alerts: [QueuedAlert; MAX_ALERTS],
    /// Alert count
    pub alert_count: usize,
    /// Next alert ID
    pub next_alert_id: u64,
    /// Service start time
    pub start_time: i64,
}

impl AlerterState {
    const fn new() -> Self {
        AlerterState {
            running: false,
            recipients: [const { AlertRecipient::empty() }; MAX_RECIPIENTS],
            recipient_count: 0,
            alerts: [const { QueuedAlert::empty() }; MAX_ALERTS],
            alert_count: 0,
            next_alert_id: 1,
            start_time: 0,
        }
    }
}

/// Global state
static ALERTER_STATE: Mutex<AlerterState> = Mutex::new(AlerterState::new());

/// Statistics
static ALERTS_RAISED: AtomicU64 = AtomicU64::new(0);
static ALERTS_DELIVERED: AtomicU64 = AtomicU64::new(0);
static ALERTS_FAILED: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize Alerter service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = ALERTER_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    // Add default administrator recipient
    let admin_name = b"Administrator";
    state.recipients[0].name[..admin_name.len()].copy_from_slice(admin_name);
    state.recipients[0].is_computer = false;
    state.recipients[0].valid = true;
    state.recipient_count = 1;

    crate::serial_println!("[ALERTER] Alerter service initialized");
}

/// Add an alert recipient
pub fn add_recipient(
    name: &[u8],
    is_computer: bool,
) -> Result<usize, u32> {
    let mut state = ALERTER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let name_len = name.len().min(MAX_NAME);

    // Check for duplicate
    for recipient in state.recipients.iter() {
        if recipient.valid && recipient.name[..name_len] == name[..name_len] {
            return Err(0x80070055); // ERROR_DUP_NAME
        }
    }

    let slot = state.recipients.iter().position(|r| !r.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    state.recipients[slot].name = [0; MAX_NAME];
    state.recipients[slot].name[..name_len].copy_from_slice(&name[..name_len]);
    state.recipients[slot].is_computer = is_computer;
    state.recipients[slot].print_alerts = true;
    state.recipients[slot].admin_alerts = true;
    state.recipients[slot].ups_alerts = true;
    state.recipients[slot].error_alerts = true;
    state.recipients[slot].valid = true;
    state.recipient_count += 1;

    Ok(slot)
}

/// Remove an alert recipient
pub fn remove_recipient(name: &[u8]) -> Result<(), u32> {
    let mut state = ALERTER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let name_len = name.len().min(MAX_NAME);

    let idx = state.recipients.iter().position(|r| {
        r.valid && r.name[..name_len] == name[..name_len]
    });

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.recipients[idx].valid = false;
    state.recipient_count = state.recipient_count.saturating_sub(1);

    Ok(())
}

/// Configure recipient alert types
pub fn configure_recipient(
    name: &[u8],
    print_alerts: bool,
    admin_alerts: bool,
    ups_alerts: bool,
    error_alerts: bool,
) -> Result<(), u32> {
    let mut state = ALERTER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let name_len = name.len().min(MAX_NAME);

    let recipient = state.recipients.iter_mut()
        .find(|r| r.valid && r.name[..name_len] == name[..name_len]);

    let recipient = match recipient {
        Some(r) => r,
        None => return Err(0x80070057),
    };

    recipient.print_alerts = print_alerts;
    recipient.admin_alerts = admin_alerts;
    recipient.ups_alerts = ups_alerts;
    recipient.error_alerts = error_alerts;

    Ok(())
}

/// Raise an alert
pub fn raise_alert(
    alert_type: AlertType,
    severity: AlertSeverity,
    source: &[u8],
    message: &[u8],
) -> Result<u64, u32> {
    let mut state = ALERTER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.alerts.iter().position(|a| !a.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let alert_id = state.next_alert_id;
    state.next_alert_id += 1;

    let now = crate::rtl::time::rtl_get_system_time();
    state.alert_count += 1;

    let source_len = source.len().min(32);
    let message_len = message.len().min(MAX_ALERT_LEN);

    let alert = &mut state.alerts[slot];
    alert.alert_id = alert_id;
    alert.alert_type = alert_type;
    alert.severity = severity;
    alert.source[..source_len].copy_from_slice(&source[..source_len]);
    alert.message[..message_len].copy_from_slice(&message[..message_len]);
    alert.message_len = message_len;
    alert.timestamp = now;
    alert.pending = true;
    alert.notified = 0;
    alert.valid = true;

    ALERTS_RAISED.fetch_add(1, Ordering::SeqCst);

    // Deliver to recipients
    let recipients_to_notify: [([u8; MAX_NAME], usize); MAX_RECIPIENTS] =
        core::array::from_fn(|i| (state.recipients[i].name, i));

    let recipients_valid: [bool; MAX_RECIPIENTS] =
        core::array::from_fn(|i| {
            let r = &state.recipients[i];
            if !r.valid {
                return false;
            }
            match alert_type {
                AlertType::Print => r.print_alerts,
                AlertType::Admin | AlertType::Custom => r.admin_alerts,
                AlertType::Ups => r.ups_alerts,
                AlertType::Error => r.error_alerts,
                AlertType::User => true,
            }
        });

    drop(state);

    let mut notified = 0u32;

    for (i, (name, _)) in recipients_to_notify.iter().enumerate() {
        if recipients_valid[i] {
            // Would send via Messenger service
            // For now just count
            notified += 1;
            ALERTS_DELIVERED.fetch_add(1, Ordering::SeqCst);
        }
    }

    // Update notified count
    let mut state = ALERTER_STATE.lock();
    if let Some(alert) = state.alerts.iter_mut().find(|a| a.valid && a.alert_id == alert_id) {
        alert.notified = notified;
        alert.pending = false;
    }

    Ok(alert_id)
}

/// Raise a print alert
pub fn raise_print_alert(
    printer: &[u8],
    job_name: &[u8],
    status: &[u8],
) -> Result<u64, u32> {
    let mut message = [0u8; MAX_ALERT_LEN];
    let mut pos = 0;

    let prefix = b"Print job on ";
    let len = prefix.len().min(MAX_ALERT_LEN - pos);
    message[pos..pos + len].copy_from_slice(&prefix[..len]);
    pos += len;

    let len = printer.len().min(MAX_ALERT_LEN - pos);
    message[pos..pos + len].copy_from_slice(&printer[..len]);
    pos += len;

    let sep = b": ";
    let len = sep.len().min(MAX_ALERT_LEN - pos);
    message[pos..pos + len].copy_from_slice(&sep[..len]);
    pos += len;

    let len = job_name.len().min(MAX_ALERT_LEN - pos);
    message[pos..pos + len].copy_from_slice(&job_name[..len]);
    pos += len;

    let sep2 = b" - ";
    let len = sep2.len().min(MAX_ALERT_LEN - pos);
    message[pos..pos + len].copy_from_slice(&sep2[..len]);
    pos += len;

    let len = status.len().min(MAX_ALERT_LEN - pos);
    message[pos..pos + len].copy_from_slice(&status[..len]);
    pos += len;

    raise_alert(AlertType::Print, AlertSeverity::Info, b"Spooler", &message[..pos])
}

/// Raise an admin alert
pub fn raise_admin_alert(
    source: &[u8],
    message: &[u8],
    severity: AlertSeverity,
) -> Result<u64, u32> {
    raise_alert(AlertType::Admin, severity, source, message)
}

/// Raise a UPS alert
pub fn raise_ups_alert(
    event: &[u8],
    severity: AlertSeverity,
) -> Result<u64, u32> {
    raise_alert(AlertType::Ups, severity, b"UPS", event)
}

/// Get recipients
pub fn get_recipients() -> ([AlertRecipient; MAX_RECIPIENTS], usize) {
    let state = ALERTER_STATE.lock();
    let mut result = [const { AlertRecipient::empty() }; MAX_RECIPIENTS];
    let mut count = 0;

    for recipient in state.recipients.iter() {
        if recipient.valid && count < MAX_RECIPIENTS {
            result[count] = recipient.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get pending alerts
pub fn get_pending_alerts() -> ([QueuedAlert; MAX_ALERTS], usize) {
    let state = ALERTER_STATE.lock();
    let mut result = [const { QueuedAlert::empty() }; MAX_ALERTS];
    let mut count = 0;

    for alert in state.alerts.iter() {
        if alert.valid && alert.pending && count < MAX_ALERTS {
            result[count] = alert.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get all alerts
pub fn get_all_alerts() -> ([QueuedAlert; MAX_ALERTS], usize) {
    let state = ALERTER_STATE.lock();
    let mut result = [const { QueuedAlert::empty() }; MAX_ALERTS];
    let mut count = 0;

    for alert in state.alerts.iter() {
        if alert.valid && count < MAX_ALERTS {
            result[count] = alert.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Clear delivered alerts
pub fn clear_delivered() {
    let mut state = ALERTER_STATE.lock();

    if !state.running {
        return;
    }

    let mut removed = 0usize;
    for alert in state.alerts.iter_mut() {
        if alert.valid && !alert.pending {
            alert.valid = false;
            removed += 1;
        }
    }

    state.alert_count = state.alert_count.saturating_sub(removed);
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64) {
    (
        ALERTS_RAISED.load(Ordering::SeqCst),
        ALERTS_DELIVERED.load(Ordering::SeqCst),
        ALERTS_FAILED.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = ALERTER_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = ALERTER_STATE.lock();
    state.running = false;

    crate::serial_println!("[ALERTER] Alerter service stopped");
}
