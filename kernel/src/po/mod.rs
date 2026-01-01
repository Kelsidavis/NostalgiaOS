//! Power Manager (po)
//!
//! The Power Manager handles system and device power states, following the
//! Windows NT power management model.
//!
//! ## System Power States (S-States)
//! - **S0**: Working state (fully on)
//! - **S1**: Sleeping with CPU context maintained
//! - **S2**: Sleeping with CPU context lost (not commonly used)
//! - **S3**: Suspend to RAM (standby/sleep)
//! - **S4**: Suspend to disk (hibernate)
//! - **S5**: Soft off (shutdown)
//!
//! ## Device Power States (D-States)
//! - **D0**: Fully on
//! - **D1**: Light sleep (device-specific)
//! - **D2**: Deeper sleep (device-specific)
//! - **D3**: Off (no power)
//!
//! ## Key Components
//! - **Power Policy**: System-wide power policy management
//! - **Power IRPs**: Power state change requests through I/O stack
//! - **Idle Detection**: Automatic device power-down when idle
//!
//! # Usage
//! ```ignore
//! use kernel::po;
//!
//! // Get current system power state
//! let state = po::get_system_power_state();
//!
//! // Initiate system sleep
//! po::set_system_power_state(SystemPowerState::S3);
//! ```

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicBool, Ordering};
use spin::Mutex;

pub mod idle;
pub mod shutdown;

// Re-export idle detection types
pub use idle::{
    IdleDeviceEntry,
    IdleDeviceSnapshot,
    IdleStats,
    po_register_device_for_idle_detection,
    po_unregister_device_for_idle_detection,
    po_set_device_busy,
    po_set_device_busy_by_ptr,
    po_is_device_idle,
    po_get_idle_device_power_state,
    po_set_device_wake_capable,
    po_enable_idle_detection,
    po_is_idle_detection_enabled,
    po_idle_tick,
    po_force_idle_scan,
    po_get_idle_stats,
    po_get_idle_device_snapshots,
};

// Re-export shutdown types
pub use shutdown::{
    ShutdownWorkCallback,
    ShutdownStats,
    ShutdownReason,
    ShutdownMajorReason,
    ShutdownMinorReason,
    po_request_shutdown_wait,
    po_cancel_shutdown_wait,
    po_queue_shutdown_work_item,
    po_cancel_shutdown_work_item,
    po_request_shutdown_event,
    is_shutdown_in_progress,
    is_shutdown_complete,
    execute_graceful_shutdown,
    get_shutdown_stats,
    get_shutdown_thread_count,
    get_shutdown_work_count,
    set_shutdown_reason,
    get_shutdown_reason,
};

// ============================================================================
// System Power States
// ============================================================================

/// System power states (S-states)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemPowerState {
    /// Unspecified power state
    Unspecified = 0,
    /// S0 - Working (fully on)
    Working = 1,
    /// S1 - Sleeping with context maintained (standby)
    Sleeping1 = 2,
    /// S2 - Sleeping with context lost (rarely used)
    Sleeping2 = 3,
    /// S3 - Suspend to RAM (sleep/standby)
    Sleeping3 = 4,
    /// S4 - Hibernate (suspend to disk)
    Hibernate = 5,
    /// S5 - Soft off (shutdown)
    Shutdown = 6,
    /// Maximum value for bounds checking
    Maximum = 7,
}

impl From<u8> for SystemPowerState {
    fn from(value: u8) -> Self {
        match value {
            1 => SystemPowerState::Working,
            2 => SystemPowerState::Sleeping1,
            3 => SystemPowerState::Sleeping2,
            4 => SystemPowerState::Sleeping3,
            5 => SystemPowerState::Hibernate,
            6 => SystemPowerState::Shutdown,
            _ => SystemPowerState::Unspecified,
        }
    }
}

/// Device power states (D-states)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePowerState {
    /// Unspecified power state
    Unspecified = 0,
    /// D0 - Full power
    D0 = 1,
    /// D1 - Device-specific low power
    D1 = 2,
    /// D2 - Device-specific lower power
    D2 = 3,
    /// D3 - Device off
    D3 = 4,
    /// Maximum value for bounds checking
    Maximum = 5,
}

impl From<u8> for DevicePowerState {
    fn from(value: u8) -> Self {
        match value {
            1 => DevicePowerState::D0,
            2 => DevicePowerState::D1,
            3 => DevicePowerState::D2,
            4 => DevicePowerState::D3,
            _ => DevicePowerState::Unspecified,
        }
    }
}

// ============================================================================
// Power Action
// ============================================================================

/// Power action types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerAction {
    /// No action
    None = 0,
    /// Reserved
    Reserved = 1,
    /// Sleep (S1-S3)
    Sleep = 2,
    /// Hibernate (S4)
    Hibernate = 3,
    /// Shutdown (S5)
    Shutdown = 4,
    /// Warm reset (restart)
    WarmEject = 5,
    /// Shutdown + reset
    ShutdownReset = 6,
    /// Shutdown + power off
    ShutdownOff = 7,
}

/// Power action policy flags
pub mod power_action_flags {
    /// Query apps before action
    pub const QUERY_ALLOWED: u32 = 0x00000001;
    /// Send UI notification
    pub const UI_ALLOWED: u32 = 0x00000002;
    /// Override apps that refuse
    pub const OVERRIDE_APPS: u32 = 0x00000004;
    /// Light sleep state
    pub const LIGHTEST_FIRST: u32 = 0x10000000;
    /// Lock console on resume
    pub const LOCK_CONSOLE: u32 = 0x20000000;
    /// Disable wake events
    pub const DISABLE_WAKE_EVENT: u32 = 0x40000000;
    /// Critical action (no delays)
    pub const CRITICAL: u32 = 0x80000000;
}

// ============================================================================
// Power Capabilities
// ============================================================================

/// System power capabilities
#[derive(Debug, Clone)]
pub struct SystemPowerCapabilities {
    /// Power button present
    pub power_button_present: bool,
    /// Sleep button present
    pub sleep_button_present: bool,
    /// Lid switch present
    pub lid_present: bool,
    /// System supports S1 (standby)
    pub system_s1: bool,
    /// System supports S2
    pub system_s2: bool,
    /// System supports S3 (sleep)
    pub system_s3: bool,
    /// System supports S4 (hibernate)
    pub system_s4: bool,
    /// System supports S5 (soft off)
    pub system_s5: bool,
    /// Hibernate file present
    pub hiberfile_present: bool,
    /// Full wake support
    pub full_wake: bool,
    /// Video dim support
    pub video_dim_present: bool,
    /// APM present
    pub apm_present: bool,
    /// UPS present
    pub ups_present: bool,
    /// Thermal control present
    pub thermal_control: bool,
    /// Processor throttling support
    pub processor_throttle: bool,
    /// Processor supports performance states
    pub processor_perf_states: bool,
    /// Disk spindown support
    pub disk_spindown: bool,
    /// AC power present
    pub ac_online: bool,
}

impl Default for SystemPowerCapabilities {
    fn default() -> Self {
        Self {
            power_button_present: true,
            sleep_button_present: false,
            lid_present: false,
            system_s1: false,
            system_s2: false,
            system_s3: false,
            system_s4: false,
            system_s5: true,  // Soft off always supported
            hiberfile_present: false,
            full_wake: false,
            video_dim_present: false,
            apm_present: false,
            ups_present: false,
            thermal_control: false,
            processor_throttle: false,
            processor_perf_states: false,
            disk_spindown: false,
            ac_online: true,  // Assume AC power by default
        }
    }
}

// ============================================================================
// Power Policy
// ============================================================================

/// System power policy
#[derive(Debug, Clone)]
pub struct SystemPowerPolicy {
    /// Revision number
    pub revision: u32,
    /// Power button action
    pub power_button_action: PowerAction,
    /// Sleep button action
    pub sleep_button_action: PowerAction,
    /// Lid close action
    pub lid_close_action: PowerAction,
    /// Idle timeout (seconds, 0 = disabled)
    pub idle_timeout: u32,
    /// Idle action
    pub idle_action: PowerAction,
    /// Minimum sleep state
    pub min_sleep: SystemPowerState,
    /// Maximum sleep state
    pub max_sleep: SystemPowerState,
    /// Dynamic throttling
    pub dynamic_throttle: bool,
    /// Fan throttle tolerance (percent)
    pub fan_throttle_tolerance: u8,
    /// Forced throttle (percent, 0 = none)
    pub forced_throttle: u8,
    /// Minimum throttle (percent)
    pub min_throttle: u8,
    /// Video timeout (seconds, 0 = disabled)
    pub video_timeout: u32,
    /// Spindown timeout (seconds, 0 = disabled)
    pub spindown_timeout: u32,
}

impl Default for SystemPowerPolicy {
    fn default() -> Self {
        Self {
            revision: 1,
            power_button_action: PowerAction::Shutdown,
            sleep_button_action: PowerAction::Sleep,
            lid_close_action: PowerAction::Sleep,
            idle_timeout: 0, // Disabled
            idle_action: PowerAction::Sleep,
            min_sleep: SystemPowerState::Sleeping1,
            max_sleep: SystemPowerState::Sleeping3,
            dynamic_throttle: false,
            fan_throttle_tolerance: 100,
            forced_throttle: 0,
            min_throttle: 100,
            video_timeout: 0,
            spindown_timeout: 0,
        }
    }
}

// ============================================================================
// Global Power Manager State
// ============================================================================

/// Current system power state
static SYSTEM_POWER_STATE: AtomicU8 = AtomicU8::new(SystemPowerState::Working as u8);

/// Power manager initialized flag
static PO_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Power manager flags
static PO_FLAGS: AtomicU32 = AtomicU32::new(0);

/// Power capabilities
static POWER_CAPABILITIES: Mutex<SystemPowerCapabilities> = Mutex::new(SystemPowerCapabilities {
    power_button_present: true,
    sleep_button_present: false,
    lid_present: false,
    system_s1: false,
    system_s2: false,
    system_s3: false,
    system_s4: false,
    system_s5: true,
    hiberfile_present: false,
    full_wake: false,
    video_dim_present: false,
    apm_present: false,
    ups_present: false,
    thermal_control: false,
    processor_throttle: false,
    processor_perf_states: false,
    disk_spindown: false,
    ac_online: true,
});

/// System power policy
static POWER_POLICY: Mutex<SystemPowerPolicy> = Mutex::new(SystemPowerPolicy {
    revision: 1,
    power_button_action: PowerAction::Shutdown,
    sleep_button_action: PowerAction::Sleep,
    lid_close_action: PowerAction::Sleep,
    idle_timeout: 0,
    idle_action: PowerAction::Sleep,
    min_sleep: SystemPowerState::Sleeping1,
    max_sleep: SystemPowerState::Sleeping3,
    dynamic_throttle: false,
    fan_throttle_tolerance: 100,
    forced_throttle: 0,
    min_throttle: 100,
    video_timeout: 0,
    spindown_timeout: 0,
});

/// Power manager flags
pub mod po_flags {
    /// System is on AC power
    pub const AC_POWER: u32 = 0x00000001;
    /// System is on battery power
    pub const BATTERY_POWER: u32 = 0x00000002;
    /// Low battery condition
    pub const LOW_BATTERY: u32 = 0x00000004;
    /// Critical battery condition
    pub const CRITICAL_BATTERY: u32 = 0x00000008;
    /// Power action in progress
    pub const ACTION_IN_PROGRESS: u32 = 0x00000010;
    /// Wake event pending
    pub const WAKE_PENDING: u32 = 0x00000020;
}

// ============================================================================
// Power Manager Functions
// ============================================================================

/// Initialize the Power Manager
pub fn init() {
    // Detect power capabilities from ACPI
    if crate::hal::acpi::is_initialized() {
        let mut caps = POWER_CAPABILITIES.lock();

        // Read sleep state capabilities from ACPI
        let sleep_info = crate::hal::acpi::get_sleep_capabilities();
        caps.system_s1 = sleep_info.s1_supported;
        caps.system_s2 = sleep_info.s2_supported;
        caps.system_s3 = sleep_info.s3_supported;
        caps.system_s4 = sleep_info.s4_supported;
        caps.system_s5 = sleep_info.s5_supported;

        // Read PM control info
        let pm_info = crate::hal::acpi::get_pm_control_info();

        crate::serial_println!("[PO] ACPI capabilities detected:");
        crate::serial_println!("[PO]   S1={}, S2={}, S3={}, S4={}, S5={}",
            caps.system_s1, caps.system_s2, caps.system_s3, caps.system_s4, caps.system_s5);
        crate::serial_println!("[PO]   PM1a_ctrl={:#x}, SCI={}",
            pm_info.pm1a_control, pm_info.sci_interrupt);

        // Assume power button present (standard on PC)
        caps.power_button_present = true;

        // Enable ACPI mode if not already enabled
        let _ = crate::hal::acpi::enable_acpi();
    }

    // Set initial state to Working
    SYSTEM_POWER_STATE.store(SystemPowerState::Working as u8, Ordering::SeqCst);

    // Assume AC power
    PO_FLAGS.store(po_flags::AC_POWER, Ordering::SeqCst);

    // Initialize idle detection subsystem
    idle::init();

    // Initialize shutdown support
    shutdown::init();

    PO_INITIALIZED.store(true, Ordering::SeqCst);

    crate::serial_println!("[PO] Power manager initialized");
}

/// Check if power manager is initialized
pub fn is_initialized() -> bool {
    PO_INITIALIZED.load(Ordering::SeqCst)
}

/// Get current system power state
pub fn get_system_power_state() -> SystemPowerState {
    SystemPowerState::from(SYSTEM_POWER_STATE.load(Ordering::SeqCst))
}

/// Set system power state
///
/// # Arguments
/// * `state` - Target power state
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(status)` on failure
pub fn set_system_power_state(state: SystemPowerState) -> Result<(), i32> {
    // Check if transition is valid
    let current = get_system_power_state();

    // Can't transition from shutdown
    if current == SystemPowerState::Shutdown {
        return Err(-1); // STATUS_INVALID_DEVICE_STATE
    }

    // Check if target state is supported
    let caps = POWER_CAPABILITIES.lock();
    let supported = match state {
        SystemPowerState::Working => true,
        SystemPowerState::Sleeping1 => caps.system_s1,
        SystemPowerState::Sleeping2 => caps.system_s2,
        SystemPowerState::Sleeping3 => caps.system_s3,
        SystemPowerState::Hibernate => caps.system_s4,
        SystemPowerState::Shutdown => caps.system_s5,
        _ => false,
    };
    drop(caps);

    if !supported && state != SystemPowerState::Working {
        crate::serial_println!("[PO] Power state {:?} not supported", state);
        return Err(-2); // STATUS_NOT_SUPPORTED
    }

    // Mark action in progress
    PO_FLAGS.fetch_or(po_flags::ACTION_IN_PROGRESS, Ordering::SeqCst);

    // Record the power event for statistics
    record_power_event(state);

    // Broadcast query for suspend permission (for sleep states)
    match state {
        SystemPowerState::Sleeping1 |
        SystemPowerState::Sleeping2 |
        SystemPowerState::Sleeping3 |
        SystemPowerState::Hibernate => {
            broadcast_power_event(PowerBroadcast::QuerySuspend, state as usize);
        }
        _ => {}
    }

    // Notify all registered devices to transition to appropriate D-state
    notify_devices_of_system_power_change(state);

    // Perform state transition
    let result = match state {
        SystemPowerState::Working => {
            // Resume from sleep - already handled during wake
            SYSTEM_POWER_STATE.store(state as u8, Ordering::SeqCst);
            broadcast_power_event(PowerBroadcast::ResumeSuspend, 0);
            Ok(())
        }
        SystemPowerState::Shutdown => {
            SYSTEM_POWER_STATE.store(state as u8, Ordering::SeqCst);
            crate::serial_println!("[PO] System shutdown initiated");

            // Stop all services gracefully
            crate::svc::database::stop_all_services();

            // Perform actual shutdown via ACPI
            unsafe {
                crate::hal::acpi::shutdown();
            }
            // Note: shutdown() never returns
        }
        SystemPowerState::Sleeping1 => {
            crate::serial_println!("[PO] Entering S1 (standby)...");
            broadcast_power_event(PowerBroadcast::Suspend, 1);
            SYSTEM_POWER_STATE.store(state as u8, Ordering::SeqCst);

            // Enter S1 via ACPI
            let result = unsafe { crate::hal::acpi::enter_sleep_state(1) };

            // If we return, we woke up
            if result.is_ok() {
                SYSTEM_POWER_STATE.store(SystemPowerState::Working as u8, Ordering::SeqCst);
                broadcast_power_event(PowerBroadcast::ResumeSuspend, 0);
                crate::serial_println!("[PO] Resumed from S1");
                Ok(())
            } else {
                crate::serial_println!("[PO] S1 entry failed");
                Err(-3)
            }
        }
        SystemPowerState::Sleeping2 => {
            crate::serial_println!("[PO] Entering S2...");
            broadcast_power_event(PowerBroadcast::Suspend, 2);
            SYSTEM_POWER_STATE.store(state as u8, Ordering::SeqCst);

            let result = unsafe { crate::hal::acpi::enter_sleep_state(2) };

            if result.is_ok() {
                SYSTEM_POWER_STATE.store(SystemPowerState::Working as u8, Ordering::SeqCst);
                broadcast_power_event(PowerBroadcast::ResumeSuspend, 0);
                Ok(())
            } else {
                Err(-3)
            }
        }
        SystemPowerState::Sleeping3 => {
            crate::serial_println!("[PO] Entering S3 (suspend to RAM)...");
            broadcast_power_event(PowerBroadcast::Suspend, 3);
            SYSTEM_POWER_STATE.store(state as u8, Ordering::SeqCst);

            // Save processor state before S3
            // TODO: Implement CPU context save

            let result = unsafe { crate::hal::acpi::enter_sleep_state(3) };

            // For S3, we normally don't return here - resume starts from BIOS
            // If we do return, either S3 failed or wasn't really S3
            if result.is_ok() {
                SYSTEM_POWER_STATE.store(SystemPowerState::Working as u8, Ordering::SeqCst);
                broadcast_power_event(PowerBroadcast::ResumeSuspend, 0);
                crate::serial_println!("[PO] Resumed from S3");
                Ok(())
            } else {
                crate::serial_println!("[PO] S3 entry failed");
                Err(-3)
            }
        }
        SystemPowerState::Hibernate => {
            crate::serial_println!("[PO] System hibernate requested");
            broadcast_power_event(PowerBroadcast::Suspend, 4);
            SYSTEM_POWER_STATE.store(state as u8, Ordering::SeqCst);

            // TODO: Write memory to hibernate file
            // For now, just enter S4 via ACPI
            let result = unsafe { crate::hal::acpi::enter_sleep_state(4) };

            if result.is_ok() {
                SYSTEM_POWER_STATE.store(SystemPowerState::Working as u8, Ordering::SeqCst);
                broadcast_power_event(PowerBroadcast::ResumeSuspend, 0);
                Ok(())
            } else {
                crate::serial_println!("[PO] S4 entry failed");
                Err(-3)
            }
        }
        _ => Ok(()),
    };

    // Clear action in progress
    PO_FLAGS.fetch_and(!po_flags::ACTION_IN_PROGRESS, Ordering::SeqCst);

    result
}

/// Notify all managed devices of system power state change
fn notify_devices_of_system_power_change(system_state: SystemPowerState) {
    // Determine target D-state based on S-state
    let target_d_state = match system_state {
        SystemPowerState::Working => DevicePowerState::D0,
        SystemPowerState::Sleeping1 => DevicePowerState::D1,
        SystemPowerState::Sleeping2 => DevicePowerState::D2,
        SystemPowerState::Sleeping3 |
        SystemPowerState::Hibernate |
        SystemPowerState::Shutdown => DevicePowerState::D3,
        _ => DevicePowerState::D0,
    };

    let _guard = DEVICE_POWER_LOCK.lock();

    unsafe {
        for entry in DEVICE_POWER_STATES.iter_mut() {
            if entry.device != 0 {
                entry.target_state = target_d_state;
                entry.transitioning = true;
                // In a full implementation, this would send power IRPs
                entry.state = target_d_state;
                entry.transitioning = false;
            }
        }
    }

    crate::serial_println!("[PO] Notified devices to enter {:?}", target_d_state);
}

/// Get power capabilities
pub fn get_capabilities() -> SystemPowerCapabilities {
    POWER_CAPABILITIES.lock().clone()
}

/// Get current power policy
pub fn get_policy() -> SystemPowerPolicy {
    POWER_POLICY.lock().clone()
}

/// Set power policy
pub fn set_policy(policy: SystemPowerPolicy) {
    *POWER_POLICY.lock() = policy;
    crate::serial_println!("[PO] Power policy updated");
}

/// Check if system is on AC power
pub fn is_ac_power() -> bool {
    (PO_FLAGS.load(Ordering::SeqCst) & po_flags::AC_POWER) != 0
}

/// Check if system is on battery power
pub fn is_battery_power() -> bool {
    (PO_FLAGS.load(Ordering::SeqCst) & po_flags::BATTERY_POWER) != 0
}

/// Check if a power action is in progress
pub fn is_action_in_progress() -> bool {
    (PO_FLAGS.load(Ordering::SeqCst) & po_flags::ACTION_IN_PROGRESS) != 0
}

/// Initiate system shutdown
///
/// This function initiates a graceful system shutdown. It will:
/// 1. Stop all running services
/// 2. Notify all devices to enter D3 (off) state
/// 3. Perform ACPI S5 shutdown
///
/// This function does not return on success.
pub fn shutdown() -> ! {
    crate::serial_println!("[PO] Initiating system shutdown...");

    // Mark action in progress
    PO_FLAGS.fetch_or(po_flags::ACTION_IN_PROGRESS, Ordering::SeqCst);
    SYSTEM_POWER_STATE.store(SystemPowerState::Shutdown as u8, Ordering::SeqCst);

    // Record shutdown event
    {
        let mut stats = POWER_STATS.lock();
        stats.shutdown_count += 1;
    }

    // Stop all services gracefully
    let stopped = crate::svc::database::stop_all_services();
    crate::serial_println!("[PO] Stopped {} services", stopped);

    // Notify all devices to enter D3
    notify_devices_of_system_power_change(SystemPowerState::Shutdown);

    // Perform ACPI shutdown
    unsafe {
        crate::hal::acpi::shutdown()
    }
}

/// Initiate system restart
///
/// This function initiates a system restart. It will:
/// 1. Stop all running services
/// 2. Notify all devices
/// 3. Perform ACPI reset
///
/// This function does not return on success.
pub fn restart() -> ! {
    crate::serial_println!("[PO] Initiating system restart...");

    // Mark action in progress
    PO_FLAGS.fetch_or(po_flags::ACTION_IN_PROGRESS, Ordering::SeqCst);

    // Stop all services gracefully
    let stopped = crate::svc::database::stop_all_services();
    crate::serial_println!("[PO] Stopped {} services", stopped);

    // Notify all devices to enter D3
    notify_devices_of_system_power_change(SystemPowerState::Shutdown);

    // Perform ACPI reset
    unsafe {
        crate::hal::acpi::reset()
    }
}

// ============================================================================
// Processor Power Management
// ============================================================================

/// Processor performance state (P-state)
#[derive(Debug, Clone, Copy)]
pub struct ProcessorPerfState {
    /// Frequency in MHz
    pub frequency: u32,
    /// Percentage of maximum performance
    pub percentage: u8,
    /// Power consumption in milliwatts
    pub power: u32,
    /// Transition latency in microseconds
    pub latency: u32,
}

/// Current processor throttle level (0-100%)
static PROCESSOR_THROTTLE: AtomicU8 = AtomicU8::new(100);

/// Get current processor throttle level
pub fn get_processor_throttle() -> u8 {
    PROCESSOR_THROTTLE.load(Ordering::SeqCst)
}

/// Set processor throttle level
///
/// # Arguments
/// * `level` - Throttle level (0-100, where 100 = full speed)
pub fn set_processor_throttle(level: u8) {
    let level = level.min(100);
    PROCESSOR_THROTTLE.store(level, Ordering::SeqCst);
    // TODO: Actually apply throttling via MSRs or ACPI
    crate::serial_println!("[PO] Processor throttle set to {}%", level);
}

// ============================================================================
// Idle Detection
// ============================================================================

/// Idle detection state for a device
#[derive(Debug, Clone)]
pub struct IdleState {
    /// Device is idle
    pub is_idle: bool,
    /// Idle time in seconds
    pub idle_time: u32,
    /// Conservation idle timeout
    pub conservation_idle_time: u32,
    /// Performance idle timeout
    pub performance_idle_time: u32,
}

impl Default for IdleState {
    fn default() -> Self {
        Self {
            is_idle: false,
            idle_time: 0,
            conservation_idle_time: 60,  // 60 seconds default
            performance_idle_time: 300,  // 5 minutes default
        }
    }
}

/// Register device for idle detection (legacy wrapper)
///
/// For full functionality, use po_register_device_for_idle_detection
pub fn register_device_for_idle(
    conservation_timeout: u32,
    performance_timeout: u32,
) -> Option<u32> {
    // Use a placeholder device address since legacy API doesn't provide one
    po_register_device_for_idle_detection(
        0x1000, // Placeholder device
        conservation_timeout,
        performance_timeout,
        DevicePowerState::D3,
    )
}

/// Unregister device from idle detection (legacy wrapper)
pub fn unregister_device_for_idle(handle: u32) {
    po_unregister_device_for_idle_detection(handle);
}

/// Report device busy (reset idle timer) (legacy wrapper)
pub fn device_busy(handle: u32) {
    po_set_device_busy(handle);
}

/// Report device idle
pub fn device_idle(handle: u32) {
    // Device idle is handled automatically by timeout
    // This is just a hint that can be used for immediate idle transition
    let _ = handle;
}

// ============================================================================
// Power Notifications
// ============================================================================

/// Power broadcast event types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerBroadcast {
    /// Query for permission to suspend
    QuerySuspend = 0,
    /// Query for permission to suspend denied
    QuerySuspendFailed = 2,
    /// Resume from suspend (automatic)
    ResumeAutomatic = 18,
    /// Resume from suspend (user input)
    ResumeSuspend = 7,
    /// Resume from critical suspend
    ResumeCritical = 6,
    /// Suspend initiated
    Suspend = 4,
    /// AC/DC power source change
    PowerStatusChange = 10,
    /// Battery status change
    BatteryLow = 9,
    /// Power setting change
    PowerSettingChange = 32787,
}

/// Maximum number of power notification callbacks
const MAX_POWER_CALLBACKS: usize = 32;

/// Power notification callback type
pub type PowerNotificationCallback = fn(event: PowerBroadcast, data: usize);

/// Power notification registrations
static mut POWER_CALLBACKS: [Option<PowerNotificationCallback>; MAX_POWER_CALLBACKS] = [None; MAX_POWER_CALLBACKS];
static POWER_CALLBACK_LOCK: Mutex<()> = Mutex::new(());

/// Register for power notifications
///
/// Returns a handle to unregister, or None if registration fails
pub fn register_power_notification(callback: PowerNotificationCallback) -> Option<usize> {
    let _guard = POWER_CALLBACK_LOCK.lock();

    unsafe {
        for (i, slot) in POWER_CALLBACKS.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(callback);
                return Some(i);
            }
        }
    }
    None
}

/// Unregister power notification
pub fn unregister_power_notification(handle: usize) {
    let _guard = POWER_CALLBACK_LOCK.lock();

    if handle < MAX_POWER_CALLBACKS {
        unsafe {
            POWER_CALLBACKS[handle] = None;
        }
    }
}

/// Broadcast power event to registered callbacks
fn broadcast_power_event(event: PowerBroadcast, data: usize) {
    let _guard = POWER_CALLBACK_LOCK.lock();

    unsafe {
        for callback in POWER_CALLBACKS.iter().flatten() {
            callback(event, data);
        }
    }
}

// ============================================================================
// Battery Status
// ============================================================================

/// Battery status information
#[derive(Debug, Clone, Copy)]
pub struct BatteryStatus {
    /// Battery present
    pub present: bool,
    /// Battery charging
    pub charging: bool,
    /// Battery discharging
    pub discharging: bool,
    /// Battery level (0-100%)
    pub level: u8,
    /// Estimated remaining time in minutes (0 = unknown)
    pub remaining_time: u32,
    /// Full charge capacity (mWh)
    pub full_capacity: u32,
    /// Current capacity (mWh)
    pub current_capacity: u32,
    /// Voltage (mV)
    pub voltage: u32,
    /// Current draw (mA)
    pub current: i32,
}

impl Default for BatteryStatus {
    fn default() -> Self {
        Self {
            present: false,
            charging: false,
            discharging: false,
            level: 100,
            remaining_time: 0,
            full_capacity: 0,
            current_capacity: 0,
            voltage: 0,
            current: 0,
        }
    }
}

/// Current battery status
static BATTERY_STATUS: Mutex<BatteryStatus> = Mutex::new(BatteryStatus {
    present: false,
    charging: false,
    discharging: false,
    level: 100,
    remaining_time: 0,
    full_capacity: 0,
    current_capacity: 0,
    voltage: 0,
    current: 0,
});

/// Get current battery status
pub fn get_battery_status() -> BatteryStatus {
    *BATTERY_STATUS.lock()
}

/// Update battery status (called by ACPI/battery driver)
pub fn update_battery_status(status: BatteryStatus) {
    let old_level = BATTERY_STATUS.lock().level;
    *BATTERY_STATUS.lock() = status;

    // Check for low battery and broadcast if needed
    if status.level <= 10 && old_level > 10 {
        broadcast_power_event(PowerBroadcast::BatteryLow, status.level as usize);
    }
}

// ============================================================================
// Power Statistics
// ============================================================================

/// Power manager statistics
#[derive(Debug, Clone, Copy)]
pub struct PowerStats {
    /// Total sleep events
    pub sleep_count: u32,
    /// Total wake events
    pub wake_count: u32,
    /// Total hibernate events
    pub hibernate_count: u32,
    /// Total shutdown events
    pub shutdown_count: u32,
    /// Current uptime in seconds
    pub uptime_seconds: u64,
    /// Total S1 time in seconds
    pub s1_time: u64,
    /// Total S3 time in seconds
    pub s3_time: u64,
    /// Total S4 time in seconds
    pub s4_time: u64,
    /// Last sleep timestamp
    pub last_sleep_time: u64,
    /// Last wake timestamp
    pub last_wake_time: u64,
}

impl Default for PowerStats {
    fn default() -> Self {
        Self::new()
    }
}

impl PowerStats {
    pub const fn new() -> Self {
        Self {
            sleep_count: 0,
            wake_count: 0,
            hibernate_count: 0,
            shutdown_count: 0,
            uptime_seconds: 0,
            s1_time: 0,
            s3_time: 0,
            s4_time: 0,
            last_sleep_time: 0,
            last_wake_time: 0,
        }
    }
}

/// Global power statistics
static POWER_STATS: Mutex<PowerStats> = Mutex::new(PowerStats::new());

/// Get power statistics
pub fn get_power_stats() -> PowerStats {
    *POWER_STATS.lock()
}

/// Record a power event for statistics
fn record_power_event(state: SystemPowerState) {
    let mut stats = POWER_STATS.lock();

    match state {
        SystemPowerState::Sleeping1 |
        SystemPowerState::Sleeping2 |
        SystemPowerState::Sleeping3 => {
            stats.sleep_count += 1;
            stats.last_sleep_time = crate::rtl::rtl_get_system_time() as u64;
        }
        SystemPowerState::Hibernate => {
            stats.hibernate_count += 1;
        }
        SystemPowerState::Shutdown => {
            stats.shutdown_count += 1;
        }
        SystemPowerState::Working => {
            // Resume from sleep
            stats.wake_count += 1;
            stats.last_wake_time = crate::rtl::rtl_get_system_time() as u64;
        }
        _ => {}
    }
}

// ============================================================================
// Device Power State Management
// ============================================================================

/// Device power state entry
#[derive(Debug, Clone, Copy)]
pub struct DevicePowerEntry {
    /// Device object pointer
    pub device: usize,
    /// Current power state
    pub state: DevicePowerState,
    /// Target power state (during transition)
    pub target_state: DevicePowerState,
    /// Device is in transition
    pub transitioning: bool,
}

impl DevicePowerEntry {
    pub const fn new() -> Self {
        Self {
            device: 0,
            state: DevicePowerState::D0,
            target_state: DevicePowerState::D0,
            transitioning: false,
        }
    }
}

/// Maximum tracked devices
const MAX_POWER_DEVICES: usize = 64;

/// Device power state tracking
static mut DEVICE_POWER_STATES: [DevicePowerEntry; MAX_POWER_DEVICES] = [DevicePowerEntry::new(); MAX_POWER_DEVICES];
static DEVICE_POWER_LOCK: Mutex<()> = Mutex::new(());

/// Register a device for power management
pub fn register_device_power(device: usize) -> Option<usize> {
    let _guard = DEVICE_POWER_LOCK.lock();

    unsafe {
        for (i, entry) in DEVICE_POWER_STATES.iter_mut().enumerate() {
            if entry.device == 0 {
                entry.device = device;
                entry.state = DevicePowerState::D0;
                entry.target_state = DevicePowerState::D0;
                entry.transitioning = false;
                return Some(i);
            }
        }
    }
    None
}

/// Unregister a device from power management
pub fn unregister_device_power(device: usize) {
    let _guard = DEVICE_POWER_LOCK.lock();

    unsafe {
        for entry in DEVICE_POWER_STATES.iter_mut() {
            if entry.device == device {
                entry.device = 0;
                break;
            }
        }
    }
}

/// Set device power state
pub fn set_device_power_state(device: usize, state: DevicePowerState) -> bool {
    let _guard = DEVICE_POWER_LOCK.lock();

    unsafe {
        for entry in DEVICE_POWER_STATES.iter_mut() {
            if entry.device == device {
                entry.target_state = state;
                entry.transitioning = true;
                // In a full implementation, this would send a power IRP
                entry.state = state;
                entry.transitioning = false;
                return true;
            }
        }
    }
    false
}

/// Get device power state
pub fn get_device_power_state(device: usize) -> Option<DevicePowerState> {
    let _guard = DEVICE_POWER_LOCK.lock();

    unsafe {
        for entry in DEVICE_POWER_STATES.iter() {
            if entry.device == device {
                return Some(entry.state);
            }
        }
    }
    None
}

/// Get count of devices in each power state
pub fn get_device_power_state_counts() -> [u32; 5] {
    let mut counts = [0u32; 5];
    let _guard = DEVICE_POWER_LOCK.lock();

    unsafe {
        for entry in DEVICE_POWER_STATES.iter() {
            if entry.device != 0 {
                let idx = entry.state as usize;
                if idx < 5 {
                    counts[idx] += 1;
                }
            }
        }
    }

    counts
}

// ============================================================================
// Power Snapshot for Diagnostics
// ============================================================================

/// Power manager snapshot for shell diagnostics
#[derive(Debug, Clone, Copy)]
pub struct PowerSnapshot {
    /// Current system power state
    pub system_state: SystemPowerState,
    /// Power flags
    pub flags: u32,
    /// Processor throttle level
    pub throttle: u8,
    /// Battery level
    pub battery_level: u8,
    /// Battery present
    pub battery_present: bool,
    /// AC power
    pub ac_power: bool,
    /// Device power state counts [Unspec, D0, D1, D2, D3]
    pub device_counts: [u32; 5],
}

/// Get power manager snapshot
pub fn get_power_snapshot() -> PowerSnapshot {
    let battery = get_battery_status();
    let device_counts = get_device_power_state_counts();

    PowerSnapshot {
        system_state: get_system_power_state(),
        flags: PO_FLAGS.load(Ordering::SeqCst),
        throttle: get_processor_throttle(),
        battery_level: battery.level,
        battery_present: battery.present,
        ac_power: is_ac_power(),
        device_counts,
    }
}
