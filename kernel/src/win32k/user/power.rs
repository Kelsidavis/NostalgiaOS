//! Power Management UI
//!
//! Power management dialogs and notifications.
//! Based on Windows Server 2003 powrprof.h.
//!
//! # Features
//!
//! - Power scheme management
//! - Battery status
//! - Sleep/hibernate control
//! - Power notifications
//!
//! # References
//!
//! - `public/sdk/inc/powrprof.h` - Power Profile API
//! - `base/ntos/po/` - Power manager

use crate::ke::spinlock::SpinLock;

// ============================================================================
// System Power State (SYSTEM_POWER_STATE)
// ============================================================================

/// Unspecified
pub const POWER_SYSTEM_UNSPECIFIED: u32 = 0;

/// Working (S0)
pub const POWER_SYSTEM_WORKING: u32 = 1;

/// Sleeping 1 (S1)
pub const POWER_SYSTEM_SLEEPING1: u32 = 2;

/// Sleeping 2 (S2)
pub const POWER_SYSTEM_SLEEPING2: u32 = 3;

/// Sleeping 3 (S3 - Suspend to RAM)
pub const POWER_SYSTEM_SLEEPING3: u32 = 4;

/// Hibernate (S4)
pub const POWER_SYSTEM_HIBERNATE: u32 = 5;

/// Shutdown (S5)
pub const POWER_SYSTEM_SHUTDOWN: u32 = 6;

/// Maximum
pub const POWER_SYSTEM_MAXIMUM: u32 = 7;

// ============================================================================
// Device Power State (DEVICE_POWER_STATE)
// ============================================================================

/// Unspecified
pub const POWER_DEVICE_UNSPECIFIED: u32 = 0;

/// Full on (D0)
pub const POWER_DEVICE_D0: u32 = 1;

/// Low power (D1)
pub const POWER_DEVICE_D1: u32 = 2;

/// Lower power (D2)
pub const POWER_DEVICE_D2: u32 = 3;

/// Off (D3)
pub const POWER_DEVICE_D3: u32 = 4;

/// Maximum
pub const POWER_DEVICE_MAXIMUM: u32 = 5;

// ============================================================================
// Power Action (POWER_ACTION)
// ============================================================================

/// None
pub const POWER_ACTION_NONE: u32 = 0;

/// Reserved
pub const POWER_ACTION_RESERVED: u32 = 1;

/// Sleep
pub const POWER_ACTION_SLEEP: u32 = 2;

/// Hibernate
pub const POWER_ACTION_HIBERNATE: u32 = 3;

/// Shutdown
pub const POWER_ACTION_SHUTDOWN: u32 = 4;

/// Shutdown reset
pub const POWER_ACTION_SHUTDOWN_RESET: u32 = 5;

/// Shutdown off
pub const POWER_ACTION_SHUTDOWN_OFF: u32 = 6;

/// Warm eject
pub const POWER_ACTION_WARM_EJECT: u32 = 7;

// ============================================================================
// Power Action Flags
// ============================================================================

/// Query allowed
pub const POWER_ACTION_QUERY_ALLOWED: u32 = 0x00000001;

/// UI allowed
pub const POWER_ACTION_UI_ALLOWED: u32 = 0x00000002;

/// Override apps
pub const POWER_ACTION_OVERRIDE_APPS: u32 = 0x00000004;

/// Light est
pub const POWER_ACTION_LIGHTEST_FIRST: u32 = 0x10000000;

/// Lock console
pub const POWER_ACTION_LOCK_CONSOLE: u32 = 0x20000000;

/// Disable wakes
pub const POWER_ACTION_DISABLE_WAKES: u32 = 0x40000000;

/// Critical
pub const POWER_ACTION_CRITICAL: u32 = 0x80000000;

// ============================================================================
// Battery Flag (BATTERY_FLAG_*)
// ============================================================================

/// High (> 66%)
pub const BATTERY_FLAG_HIGH: u8 = 1;

/// Low (< 33%)
pub const BATTERY_FLAG_LOW: u8 = 2;

/// Critical (< 5%)
pub const BATTERY_FLAG_CRITICAL: u8 = 4;

/// Charging
pub const BATTERY_FLAG_CHARGING: u8 = 8;

/// No battery
pub const BATTERY_FLAG_NO_BATTERY: u8 = 128;

/// Unknown status
pub const BATTERY_FLAG_UNKNOWN: u8 = 255;

// ============================================================================
// AC Line Status
// ============================================================================

/// Offline
pub const AC_LINE_OFFLINE: u8 = 0;

/// Online
pub const AC_LINE_ONLINE: u8 = 1;

/// Backup power
pub const AC_LINE_BACKUP_POWER: u8 = 2;

/// Unknown
pub const AC_LINE_UNKNOWN: u8 = 255;

// ============================================================================
// Power Broadcast Messages (PBT_*)
// ============================================================================

/// AC power status change
pub const PBT_APMPOWERSTATUSCHANGE: u32 = 0x000A;

/// Resume suspend
pub const PBT_APMRESUMESUSPEND: u32 = 0x0007;

/// Resume standby
pub const PBT_APMRESUMESTANDBY: u32 = 0x0008;

/// Resume automatic
pub const PBT_APMRESUMEAUTOMATIC: u32 = 0x0012;

/// Suspend
pub const PBT_APMSUSPEND: u32 = 0x0004;

/// Standby
pub const PBT_APMSTANDBY: u32 = 0x0005;

/// Query suspend
pub const PBT_APMQUERYSUSPEND: u32 = 0x0000;

/// Query standby
pub const PBT_APMQUERYSTANDBY: u32 = 0x0001;

/// Query suspend failed
pub const PBT_APMQUERYSUSPENDFAILED: u32 = 0x0002;

/// Query standby failed
pub const PBT_APMQUERYSTANDBYFAILED: u32 = 0x0003;

/// OEM event
pub const PBT_APMOEMEVENT: u32 = 0x000B;

/// Resume critical
pub const PBT_APMRESUMECRITICAL: u32 = 0x0006;

/// Battery low
pub const PBT_APMBATTERYLOW: u32 = 0x0009;

/// Power setting change
pub const PBT_POWERSETTINGCHANGE: u32 = 0x8013;

// ============================================================================
// Constants
// ============================================================================

/// Maximum power schemes
pub const MAX_POWER_SCHEMES: usize = 8;

/// Maximum scheme name length
pub const MAX_SCHEME_NAME: usize = 64;

/// Maximum description length
pub const MAX_DESCRIPTION: usize = 256;

// ============================================================================
// System Power Status
// ============================================================================

/// System power status
#[derive(Clone, Copy)]
pub struct SystemPowerStatus {
    /// AC line status
    pub ac_line_status: u8,
    /// Battery flag
    pub battery_flag: u8,
    /// Battery life percent
    pub battery_life_percent: u8,
    /// Reserved
    pub reserved1: u8,
    /// Battery life time (seconds, -1 if unknown)
    pub battery_life_time: i32,
    /// Battery full life time (seconds, -1 if unknown)
    pub battery_full_life_time: i32,
}

impl SystemPowerStatus {
    /// Create default status (AC power, no battery)
    pub const fn new() -> Self {
        Self {
            ac_line_status: AC_LINE_ONLINE,
            battery_flag: BATTERY_FLAG_NO_BATTERY,
            battery_life_percent: 255,
            reserved1: 0,
            battery_life_time: -1,
            battery_full_life_time: -1,
        }
    }
}

// ============================================================================
// Power Action Policy
// ============================================================================

/// Power action policy
#[derive(Clone, Copy)]
pub struct PowerActionPolicy {
    /// Action
    pub action: u32,
    /// Flags
    pub flags: u32,
    /// Event code
    pub event_code: u32,
}

impl PowerActionPolicy {
    /// Create default policy
    pub const fn new() -> Self {
        Self {
            action: POWER_ACTION_NONE,
            flags: 0,
            event_code: 0,
        }
    }
}

// ============================================================================
// Power Scheme
// ============================================================================

/// Power scheme
#[derive(Clone)]
pub struct PowerScheme {
    /// Is this slot in use
    pub in_use: bool,
    /// Scheme ID
    pub id: u32,
    /// Name
    pub name: [u8; MAX_SCHEME_NAME],
    /// Description
    pub description: [u8; MAX_DESCRIPTION],
    /// Is active scheme
    pub is_active: bool,
    /// Idle timeout AC (seconds)
    pub idle_timeout_ac: u32,
    /// Idle timeout DC (seconds)
    pub idle_timeout_dc: u32,
    /// Idle action AC
    pub idle_action_ac: PowerActionPolicy,
    /// Idle action DC
    pub idle_action_dc: PowerActionPolicy,
    /// Video timeout AC (seconds)
    pub video_timeout_ac: u32,
    /// Video timeout DC (seconds)
    pub video_timeout_dc: u32,
    /// Spindown timeout AC (seconds)
    pub spindown_timeout_ac: u32,
    /// Spindown timeout DC (seconds)
    pub spindown_timeout_dc: u32,
}

impl PowerScheme {
    /// Create empty scheme
    pub const fn new() -> Self {
        Self {
            in_use: false,
            id: 0,
            name: [0; MAX_SCHEME_NAME],
            description: [0; MAX_DESCRIPTION],
            is_active: false,
            idle_timeout_ac: 0,
            idle_timeout_dc: 0,
            idle_action_ac: PowerActionPolicy::new(),
            idle_action_dc: PowerActionPolicy::new(),
            video_timeout_ac: 0,
            video_timeout_dc: 0,
            spindown_timeout_ac: 0,
            spindown_timeout_dc: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global power schemes
static POWER_SCHEMES: SpinLock<[PowerScheme; MAX_POWER_SCHEMES]> =
    SpinLock::new([const { PowerScheme::new() }; MAX_POWER_SCHEMES]);

/// Current power status
static POWER_STATUS: SpinLock<SystemPowerStatus> = SpinLock::new(SystemPowerStatus::new());

/// Active scheme ID
static ACTIVE_SCHEME: SpinLock<u32> = SpinLock::new(0);

/// Next scheme ID
static NEXT_SCHEME_ID: SpinLock<u32> = SpinLock::new(1);

// ============================================================================
// Public API
// ============================================================================

/// Initialize power management UI
pub fn init() {
    register_default_schemes();
    crate::serial_println!("[USER] Power management UI initialized");
}

/// Register default power schemes
fn register_default_schemes() {
    let defaults: &[(&[u8], &[u8], u32, u32, u32, u32)] = &[
        (b"Home/Office Desk", b"For desktop computers", 0, 0, 900, 1200),
        (b"Portable/Laptop", b"For laptop computers", 300, 180, 300, 180),
        (b"Presentation", b"Never turn off display", 0, 0, 0, 0),
        (b"Always On", b"Computer never sleeps", 0, 0, 0, 0),
        (b"Minimal Power Management", b"Minimal power savings", 0, 0, 1800, 1800),
        (b"Max Battery", b"Maximum battery life", 120, 60, 120, 60),
    ];

    let mut schemes = POWER_SCHEMES.lock();
    let mut next_id = NEXT_SCHEME_ID.lock();

    for (i, &(name, desc, idle_ac, idle_dc, video_ac, video_dc)) in defaults.iter().enumerate() {
        if i >= MAX_POWER_SCHEMES {
            break;
        }

        let scheme = &mut schemes[i];
        scheme.in_use = true;
        scheme.id = *next_id;
        *next_id += 1;

        let name_len = super::strhelp::str_len(name).min(MAX_SCHEME_NAME - 1);
        scheme.name[..name_len].copy_from_slice(&name[..name_len]);
        scheme.name[name_len] = 0;

        let desc_len = super::strhelp::str_len(desc).min(MAX_DESCRIPTION - 1);
        scheme.description[..desc_len].copy_from_slice(&desc[..desc_len]);
        scheme.description[desc_len] = 0;

        scheme.idle_timeout_ac = idle_ac;
        scheme.idle_timeout_dc = idle_dc;
        scheme.video_timeout_ac = video_ac;
        scheme.video_timeout_dc = video_dc;

        if i == 0 {
            scheme.is_active = true;
            let active_id = scheme.id;
            drop(schemes);
            drop(next_id);
            *ACTIVE_SCHEME.lock() = active_id;
            return;
        }
    }
}

/// Get system power status
pub fn get_system_power_status(status: &mut SystemPowerStatus) -> bool {
    *status = *POWER_STATUS.lock();
    true
}

/// Set system power state
pub fn set_system_power_state(suspend: bool, force: bool) -> bool {
    let _ = force;

    if suspend {
        // Would initiate suspend
        crate::serial_println!("[POWER] System suspend requested");
    }

    true
}

/// Set suspend state
pub fn set_suspend_state(hibernate: bool, force: bool, wake_events: bool) -> bool {
    let _ = (force, wake_events);

    if hibernate {
        crate::serial_println!("[POWER] Hibernate requested");
    } else {
        crate::serial_println!("[POWER] Suspend requested");
    }

    true
}

/// Request wake up latency
pub fn request_wakeup_latency(latency: u32) -> bool {
    let _ = latency;
    true
}

/// Is power suspend allowed
pub fn is_power_suspend_allowed() -> bool {
    true
}

/// Is power hibernate allowed
pub fn is_power_hibernate_allowed() -> bool {
    true
}

/// Get power capabilities
pub fn get_pwr_capabilities(caps: &mut PowerCapabilities) -> bool {
    caps.power_button_present = true;
    caps.sleep_button_present = false;
    caps.lid_present = false;
    caps.system_s1 = true;
    caps.system_s2 = true;
    caps.system_s3 = true;
    caps.system_s4 = true;
    caps.system_s5 = true;
    caps.hiberfile_present = false;
    caps.full_wake = true;
    caps.video_dim_present = false;
    caps.apm_present = false;
    caps.ups_present = false;
    caps.thermal_control = false;
    caps.processor_throttle = false;
    caps.processor_min_throttle = 100;
    caps.processor_max_throttle = 100;
    caps.disk_spindown = true;
    caps.system_batteries_present = false;
    caps.batteries_are_short_term = false;

    true
}

/// Power capabilities
#[derive(Clone, Copy, Default)]
pub struct PowerCapabilities {
    pub power_button_present: bool,
    pub sleep_button_present: bool,
    pub lid_present: bool,
    pub system_s1: bool,
    pub system_s2: bool,
    pub system_s3: bool,
    pub system_s4: bool,
    pub system_s5: bool,
    pub hiberfile_present: bool,
    pub full_wake: bool,
    pub video_dim_present: bool,
    pub apm_present: bool,
    pub ups_present: bool,
    pub thermal_control: bool,
    pub processor_throttle: bool,
    pub processor_min_throttle: u8,
    pub processor_max_throttle: u8,
    pub disk_spindown: bool,
    pub system_batteries_present: bool,
    pub batteries_are_short_term: bool,
}

// ============================================================================
// Power Scheme Functions
// ============================================================================

/// Enumerate power schemes
pub fn enum_pwr_schemes(count: &mut u32) -> bool {
    let schemes = POWER_SCHEMES.lock();
    let mut c = 0u32;

    for scheme in schemes.iter() {
        if scheme.in_use {
            c += 1;
        }
    }

    *count = c;
    true
}

/// Get active power scheme
pub fn get_active_pwr_scheme(scheme_id: &mut u32) -> bool {
    *scheme_id = *ACTIVE_SCHEME.lock();
    true
}

/// Set active power scheme
pub fn set_active_pwr_scheme(scheme_id: u32) -> bool {
    let mut schemes = POWER_SCHEMES.lock();

    // Find and validate scheme
    let mut found = false;
    for scheme in schemes.iter_mut() {
        if scheme.in_use {
            if scheme.id == scheme_id {
                scheme.is_active = true;
                found = true;
            } else {
                scheme.is_active = false;
            }
        }
    }

    if found {
        drop(schemes);
        *ACTIVE_SCHEME.lock() = scheme_id;
        true
    } else {
        false
    }
}

/// Read power scheme
pub fn read_pwr_scheme(scheme_id: u32, scheme: &mut PowerScheme) -> bool {
    let schemes = POWER_SCHEMES.lock();

    for s in schemes.iter() {
        if s.in_use && s.id == scheme_id {
            *scheme = s.clone();
            return true;
        }
    }

    false
}

/// Write power scheme
pub fn write_pwr_scheme(
    scheme_id: Option<u32>,
    name: &[u8],
    description: &[u8],
) -> Option<u32> {
    let mut schemes = POWER_SCHEMES.lock();
    let mut next_id = NEXT_SCHEME_ID.lock();

    // Update existing or create new
    if let Some(id) = scheme_id {
        for scheme in schemes.iter_mut() {
            if scheme.in_use && scheme.id == id {
                let name_len = super::strhelp::str_len(name).min(MAX_SCHEME_NAME - 1);
                scheme.name[..name_len].copy_from_slice(&name[..name_len]);
                scheme.name[name_len] = 0;

                let desc_len = super::strhelp::str_len(description).min(MAX_DESCRIPTION - 1);
                scheme.description[..desc_len].copy_from_slice(&description[..desc_len]);
                scheme.description[desc_len] = 0;

                return Some(id);
            }
        }
        return None;
    }

    // Create new scheme
    for scheme in schemes.iter_mut() {
        if !scheme.in_use {
            let id = *next_id;
            *next_id += 1;

            scheme.in_use = true;
            scheme.id = id;

            let name_len = super::strhelp::str_len(name).min(MAX_SCHEME_NAME - 1);
            scheme.name[..name_len].copy_from_slice(&name[..name_len]);
            scheme.name[name_len] = 0;

            let desc_len = super::strhelp::str_len(description).min(MAX_DESCRIPTION - 1);
            scheme.description[..desc_len].copy_from_slice(&description[..desc_len]);
            scheme.description[desc_len] = 0;

            return Some(id);
        }
    }

    None
}

/// Delete power scheme
pub fn delete_pwr_scheme(scheme_id: u32) -> bool {
    let mut schemes = POWER_SCHEMES.lock();
    let active = *ACTIVE_SCHEME.lock();

    // Can't delete active scheme
    if scheme_id == active {
        return false;
    }

    for scheme in schemes.iter_mut() {
        if scheme.in_use && scheme.id == scheme_id {
            *scheme = PowerScheme::new();
            return true;
        }
    }

    false
}

// ============================================================================
// Power Setting Functions
// ============================================================================

/// Register for power setting notifications
pub fn register_power_setting_notification(
    _recipient: usize,
    _power_setting_guid: &[u8; 16],
    _flags: u32,
) -> usize {
    // Return a fake registration handle
    1
}

/// Unregister power setting notification
pub fn unregister_power_setting_notification(handle: usize) -> bool {
    let _ = handle;
    true
}

// ============================================================================
// Battery Functions
// ============================================================================

/// Get battery state
pub fn get_battery_state() -> BatteryState {
    let status = POWER_STATUS.lock();

    BatteryState {
        ac_online: status.ac_line_status == AC_LINE_ONLINE,
        battery_present: status.battery_flag != BATTERY_FLAG_NO_BATTERY,
        charging: (status.battery_flag & BATTERY_FLAG_CHARGING) != 0,
        percent: if status.battery_life_percent == 255 {
            None
        } else {
            Some(status.battery_life_percent)
        },
        time_remaining: if status.battery_life_time < 0 {
            None
        } else {
            Some(status.battery_life_time as u32)
        },
    }
}

/// Battery state
#[derive(Clone, Copy)]
pub struct BatteryState {
    pub ac_online: bool,
    pub battery_present: bool,
    pub charging: bool,
    pub percent: Option<u8>,
    pub time_remaining: Option<u32>,
}

/// Set simulated battery state (for testing)
pub fn set_battery_state(ac_online: bool, percent: Option<u8>, charging: bool) {
    let mut status = POWER_STATUS.lock();

    status.ac_line_status = if ac_online { AC_LINE_ONLINE } else { AC_LINE_OFFLINE };

    if let Some(p) = percent {
        status.battery_flag = if charging {
            BATTERY_FLAG_CHARGING
        } else if p > 66 {
            BATTERY_FLAG_HIGH
        } else if p > 33 {
            0
        } else if p > 5 {
            BATTERY_FLAG_LOW
        } else {
            BATTERY_FLAG_CRITICAL
        };
        status.battery_life_percent = p;
    } else {
        status.battery_flag = BATTERY_FLAG_NO_BATTERY;
        status.battery_life_percent = 255;
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> PowerStats {
    let schemes = POWER_SCHEMES.lock();
    let status = POWER_STATUS.lock();
    let active = *ACTIVE_SCHEME.lock();

    let mut count = 0;
    for scheme in schemes.iter() {
        if scheme.in_use {
            count += 1;
        }
    }

    PowerStats {
        max_schemes: MAX_POWER_SCHEMES,
        registered_schemes: count,
        active_scheme_id: active,
        ac_online: status.ac_line_status == AC_LINE_ONLINE,
        battery_present: status.battery_flag != BATTERY_FLAG_NO_BATTERY,
        battery_percent: if status.battery_life_percent == 255 {
            None
        } else {
            Some(status.battery_life_percent)
        },
    }
}

/// Power statistics
#[derive(Debug, Clone)]
pub struct PowerStats {
    pub max_schemes: usize,
    pub registered_schemes: usize,
    pub active_scheme_id: u32,
    pub ac_online: bool,
    pub battery_present: bool,
    pub battery_percent: Option<u8>,
}
