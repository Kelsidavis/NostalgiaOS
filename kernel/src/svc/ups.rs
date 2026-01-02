//! UPS Service (Uninterruptible Power Supply)
//!
//! The UPS service monitors uninterruptible power supplies and manages
//! system power events including graceful shutdown on power failure.
//!
//! # Features
//!
//! - **UPS Monitoring**: Monitor UPS status via serial port
//! - **Power Alerts**: Alert users on power events
//! - **Shutdown Management**: Graceful shutdown on battery low
//! - **Event Logging**: Log power events to event log
//!
//! # Supported Interfaces
//!
//! - Serial (RS-232) interface
//! - USB HID interface (limited)
//! - Simple signaling (basic)
//! - Smart signaling (advanced)
//!
//! # Power Events
//!
//! - Power failure detection
//! - Power restored
//! - Low battery warning
//! - Shutdown imminent

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum UPS devices
const MAX_DEVICES: usize = 4;

/// UPS interface type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsInterface {
    /// None/unknown
    None = 0,
    /// Simple signaling (basic contact closure)
    Simple = 1,
    /// Smart signaling (bidirectional)
    Smart = 2,
    /// Serial (RS-232)
    Serial = 3,
    /// USB HID
    Usb = 4,
}

impl UpsInterface {
    const fn empty() -> Self {
        UpsInterface::None
    }
}

/// UPS status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsStatus {
    /// Unknown status
    Unknown = 0,
    /// On line (AC power)
    OnLine = 1,
    /// On battery
    OnBattery = 2,
    /// Low battery
    LowBattery = 3,
    /// Shutdown imminent
    ShuttingDown = 4,
    /// UPS offline/error
    Offline = 5,
}

impl UpsStatus {
    const fn empty() -> Self {
        UpsStatus::Unknown
    }
}

/// Shutdown reason
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// No shutdown
    None = 0,
    /// Low battery
    LowBattery = 1,
    /// On battery timeout
    BatteryTimeout = 2,
    /// User requested
    UserRequested = 3,
    /// UPS failure
    UpsFailure = 4,
}

/// UPS configuration
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UpsConfig {
    /// Serial port (COM1-4)
    pub port: u8,
    /// Baud rate
    pub baud_rate: u32,
    /// Time on battery before first warning (seconds)
    pub first_warning_delay: u32,
    /// Warning interval (seconds)
    pub warning_interval: u32,
    /// Time on battery before shutdown (seconds)
    pub shutdown_wait: u32,
    /// Run command file on power fail
    pub run_cmd_on_power_fail: bool,
    /// Command file path
    pub command_file: [u8; 128],
    /// Enable shutdown on low battery
    pub low_battery_shutdown: bool,
    /// Send notifications
    pub enable_notifications: bool,
}

impl UpsConfig {
    const fn default_config() -> Self {
        UpsConfig {
            port: 1, // COM1
            baud_rate: 2400,
            first_warning_delay: 5,
            warning_interval: 120,
            shutdown_wait: 300, // 5 minutes
            run_cmd_on_power_fail: false,
            command_file: [0; 128],
            low_battery_shutdown: true,
            enable_notifications: true,
        }
    }
}

/// UPS device information
#[repr(C)]
#[derive(Clone)]
pub struct UpsDevice {
    /// Device ID
    pub device_id: u32,
    /// Device name
    pub name: [u8; 64],
    /// Interface type
    pub interface: UpsInterface,
    /// Current status
    pub status: UpsStatus,
    /// Battery charge (0-100)
    pub battery_percent: u8,
    /// Estimated runtime (minutes)
    pub runtime_minutes: u32,
    /// Input voltage (volts * 10)
    pub input_voltage: u16,
    /// Output voltage (volts * 10)
    pub output_voltage: u16,
    /// Load percentage (0-100)
    pub load_percent: u8,
    /// Last status change
    pub last_status_change: i64,
    /// Power fail start time (0 if on line)
    pub power_fail_time: i64,
    /// Configuration
    pub config: UpsConfig,
    /// Is connected
    pub connected: bool,
    /// Entry is valid
    pub valid: bool,
}

impl UpsDevice {
    const fn empty() -> Self {
        UpsDevice {
            device_id: 0,
            name: [0; 64],
            interface: UpsInterface::empty(),
            status: UpsStatus::empty(),
            battery_percent: 100,
            runtime_minutes: 0,
            input_voltage: 0,
            output_voltage: 0,
            load_percent: 0,
            last_status_change: 0,
            power_fail_time: 0,
            config: UpsConfig::default_config(),
            connected: false,
            valid: false,
        }
    }
}

/// UPS event
#[repr(C)]
#[derive(Clone)]
pub struct UpsEvent {
    /// Event ID
    pub event_id: u64,
    /// Device ID
    pub device_id: u32,
    /// Event type (status change)
    pub old_status: UpsStatus,
    /// New status
    pub new_status: UpsStatus,
    /// Timestamp
    pub timestamp: i64,
    /// Entry is valid
    pub valid: bool,
}

impl UpsEvent {
    const fn empty() -> Self {
        UpsEvent {
            event_id: 0,
            device_id: 0,
            old_status: UpsStatus::empty(),
            new_status: UpsStatus::empty(),
            timestamp: 0,
            valid: false,
        }
    }
}

/// Maximum event log entries
const MAX_EVENTS: usize = 32;

/// UPS service state
pub struct UpsState {
    /// Service is running
    pub running: bool,
    /// UPS devices
    pub devices: [UpsDevice; MAX_DEVICES],
    /// Device count
    pub device_count: usize,
    /// Next device ID
    pub next_device_id: u32,
    /// Event log
    pub events: [UpsEvent; MAX_EVENTS],
    /// Event count
    pub event_count: usize,
    /// Next event ID
    pub next_event_id: u64,
    /// Shutdown pending
    pub shutdown_pending: bool,
    /// Shutdown reason
    pub shutdown_reason: ShutdownReason,
    /// Service start time
    pub start_time: i64,
}

impl UpsState {
    const fn new() -> Self {
        UpsState {
            running: false,
            devices: [const { UpsDevice::empty() }; MAX_DEVICES],
            device_count: 0,
            next_device_id: 1,
            events: [const { UpsEvent::empty() }; MAX_EVENTS],
            event_count: 0,
            next_event_id: 1,
            shutdown_pending: false,
            shutdown_reason: ShutdownReason::None,
            start_time: 0,
        }
    }
}

/// Global state
static UPS_STATE: Mutex<UpsState> = Mutex::new(UpsState::new());

/// Statistics
static POWER_FAILURES: AtomicU64 = AtomicU64::new(0);
static POWER_RESTORES: AtomicU64 = AtomicU64::new(0);
static LOW_BATTERY_EVENTS: AtomicU64 = AtomicU64::new(0);
static SHUTDOWNS_INITIATED: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize UPS service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = UPS_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    crate::serial_println!("[UPS] UPS service initialized");
}

/// Register a UPS device
pub fn register_device(
    name: &[u8],
    interface: UpsInterface,
    port: u8,
) -> Result<u32, u32> {
    let mut state = UPS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.devices.iter().position(|d| !d.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let device_id = state.next_device_id;
    state.next_device_id += 1;
    state.device_count += 1;

    let name_len = name.len().min(64);

    let device = &mut state.devices[slot];
    device.device_id = device_id;
    device.name = [0; 64];
    device.name[..name_len].copy_from_slice(&name[..name_len]);
    device.interface = interface;
    device.status = UpsStatus::OnLine;
    device.battery_percent = 100;
    device.config.port = port;
    device.connected = true;
    device.last_status_change = crate::rtl::time::rtl_get_system_time();
    device.valid = true;

    Ok(device_id)
}

/// Unregister a UPS device
pub fn unregister_device(device_id: u32) -> Result<(), u32> {
    let mut state = UPS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.devices.iter()
        .position(|d| d.valid && d.device_id == device_id);

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.devices[idx].valid = false;
    state.device_count = state.device_count.saturating_sub(1);

    Ok(())
}

/// Update UPS status
pub fn update_status(
    device_id: u32,
    status: UpsStatus,
    battery_percent: u8,
    runtime_minutes: u32,
) -> Result<(), u32> {
    let mut state = UPS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Find device index first
    let device_idx = state.devices.iter()
        .position(|d| d.valid && d.device_id == device_id);

    let device_idx = match device_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let old_status = state.devices[device_idx].status;
    let now = crate::rtl::time::rtl_get_system_time();
    let mut log_event = false;

    if old_status != status {
        // Status changed - update device
        state.devices[device_idx].last_status_change = now;
        log_event = true;

        // Track power fail start time
        if status == UpsStatus::OnBattery || status == UpsStatus::LowBattery {
            if state.devices[device_idx].power_fail_time == 0 {
                state.devices[device_idx].power_fail_time = now;
                POWER_FAILURES.fetch_add(1, Ordering::SeqCst);
            }
        } else if status == UpsStatus::OnLine {
            state.devices[device_idx].power_fail_time = 0;
            if old_status == UpsStatus::OnBattery || old_status == UpsStatus::LowBattery {
                POWER_RESTORES.fetch_add(1, Ordering::SeqCst);
            }
        }

        if status == UpsStatus::LowBattery {
            LOW_BATTERY_EVENTS.fetch_add(1, Ordering::SeqCst);
        }
    }

    // Update device status
    state.devices[device_idx].status = status;
    state.devices[device_idx].battery_percent = battery_percent;
    state.devices[device_idx].runtime_minutes = runtime_minutes;

    // Log event if status changed
    if log_event {
        let event_id = state.next_event_id;
        state.next_event_id += 1;

        if let Some(slot) = state.events.iter().position(|e| !e.valid) {
            let event = &mut state.events[slot];
            event.event_id = event_id;
            event.device_id = device_id;
            event.old_status = old_status;
            event.new_status = status;
            event.timestamp = now;
            event.valid = true;
            state.event_count += 1;
        }
    }

    Ok(())
}

/// Update voltage readings
pub fn update_voltage(
    device_id: u32,
    input_voltage: u16,
    output_voltage: u16,
    load_percent: u8,
) -> Result<(), u32> {
    let mut state = UPS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let device = state.devices.iter_mut()
        .find(|d| d.valid && d.device_id == device_id);

    let device = match device {
        Some(d) => d,
        None => return Err(0x80070057),
    };

    device.input_voltage = input_voltage;
    device.output_voltage = output_voltage;
    device.load_percent = load_percent;

    Ok(())
}

/// Configure UPS
pub fn configure_device(device_id: u32, config: UpsConfig) -> Result<(), u32> {
    let mut state = UPS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let device = state.devices.iter_mut()
        .find(|d| d.valid && d.device_id == device_id);

    let device = match device {
        Some(d) => d,
        None => return Err(0x80070057),
    };

    device.config = config;

    Ok(())
}

/// Get UPS configuration
pub fn get_config(device_id: u32) -> Option<UpsConfig> {
    let state = UPS_STATE.lock();

    state.devices.iter()
        .find(|d| d.valid && d.device_id == device_id)
        .map(|d| d.config)
}

/// Get device status
pub fn get_status(device_id: u32) -> Option<UpsDevice> {
    let state = UPS_STATE.lock();

    state.devices.iter()
        .find(|d| d.valid && d.device_id == device_id)
        .cloned()
}

/// List UPS devices
pub fn list_devices() -> ([UpsDevice; MAX_DEVICES], usize) {
    let state = UPS_STATE.lock();
    let mut result = [const { UpsDevice::empty() }; MAX_DEVICES];
    let mut count = 0;

    for device in state.devices.iter() {
        if device.valid && count < MAX_DEVICES {
            result[count] = device.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Check if any UPS is on battery
pub fn is_on_battery() -> bool {
    let state = UPS_STATE.lock();

    state.devices.iter()
        .any(|d| d.valid && (d.status == UpsStatus::OnBattery || d.status == UpsStatus::LowBattery))
}

/// Check if low battery
pub fn is_low_battery() -> bool {
    let state = UPS_STATE.lock();

    state.devices.iter()
        .any(|d| d.valid && d.status == UpsStatus::LowBattery)
}

/// Initiate shutdown
pub fn initiate_shutdown(reason: ShutdownReason) -> Result<(), u32> {
    let mut state = UPS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    if state.shutdown_pending {
        return Err(0x80070057); // Already pending
    }

    state.shutdown_pending = true;
    state.shutdown_reason = reason;

    SHUTDOWNS_INITIATED.fetch_add(1, Ordering::SeqCst);

    // Would send alert to Alerter service here
    // Would start shutdown countdown

    Ok(())
}

/// Cancel shutdown
pub fn cancel_shutdown() -> Result<(), u32> {
    let mut state = UPS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    state.shutdown_pending = false;
    state.shutdown_reason = ShutdownReason::None;

    Ok(())
}

/// Check if shutdown pending
pub fn is_shutdown_pending() -> bool {
    let state = UPS_STATE.lock();
    state.shutdown_pending
}

/// Get shutdown reason
pub fn get_shutdown_reason() -> ShutdownReason {
    let state = UPS_STATE.lock();
    state.shutdown_reason
}

/// Get event log
pub fn get_events() -> ([UpsEvent; MAX_EVENTS], usize) {
    let state = UPS_STATE.lock();
    let mut result = [const { UpsEvent::empty() }; MAX_EVENTS];
    let mut count = 0;

    for event in state.events.iter() {
        if event.valid && count < MAX_EVENTS {
            result[count] = event.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Clear event log
pub fn clear_events() {
    let mut state = UPS_STATE.lock();

    for event in state.events.iter_mut() {
        event.valid = false;
    }
    state.event_count = 0;
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64, u64) {
    (
        POWER_FAILURES.load(Ordering::SeqCst),
        POWER_RESTORES.load(Ordering::SeqCst),
        LOW_BATTERY_EVENTS.load(Ordering::SeqCst),
        SHUTDOWNS_INITIATED.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = UPS_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = UPS_STATE.lock();
    state.running = false;

    // Mark all devices as disconnected
    for device in state.devices.iter_mut() {
        if device.valid {
            device.connected = false;
        }
    }

    crate::serial_println!("[UPS] UPS service stopped");
}
