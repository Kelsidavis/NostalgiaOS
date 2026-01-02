//! System Properties Dialog
//!
//! Kernel-mode system properties control panel following Windows NT patterns.
//! Provides computer name, hardware, advanced, system restore, and remote settings.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/cpls/system/` - System control panel

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// Constants
// ============================================================================

/// Maximum computer name length
const MAX_COMPUTER_NAME: usize = 15;

/// Maximum domain/workgroup name length
const MAX_DOMAIN_NAME: usize = 255;

/// Maximum description length
const MAX_DESCRIPTION: usize = 256;

/// Maximum environment variable name
const MAX_ENV_NAME: usize = 128;

/// Maximum environment variable value
const MAX_ENV_VALUE: usize = 32767;

/// Maximum environment variables
const MAX_ENV_VARS: usize = 64;

/// Maximum hardware profiles
const MAX_HW_PROFILES: usize = 8;

/// Maximum profile name length
const MAX_PROFILE_NAME: usize = 80;

/// Startup/recovery action
pub mod recovery_action {
    /// Write event to system log
    pub const WRITE_EVENT: u32 = 0x0001;
    /// Send administrative alert
    pub const SEND_ALERT: u32 = 0x0002;
    /// Automatically restart
    pub const AUTO_RESTART: u32 = 0x0004;
    /// Write debugging information
    pub const WRITE_DEBUG: u32 = 0x0008;
    /// Overwrite existing file
    pub const OVERWRITE: u32 = 0x0010;
    /// Disable automatic restart on system failure
    pub const DISABLE_AUTO_RESTART: u32 = 0x0020;
}

/// Performance options
pub mod performance_option {
    /// Adjust for best appearance
    pub const BEST_APPEARANCE: u32 = 0;
    /// Adjust for best performance
    pub const BEST_PERFORMANCE: u32 = 1;
    /// Custom
    pub const CUSTOM: u32 = 2;
}

/// Visual effects
pub mod visual_effect {
    pub const ANIMATE_WINDOWS: u32 = 0x00000001;
    pub const ANIMATE_LISTBOX: u32 = 0x00000002;
    pub const ANIMATE_MENU_FADE: u32 = 0x00000004;
    pub const ANIMATE_TOOLTIP_FADE: u32 = 0x00000008;
    pub const SMOOTH_SCROLL: u32 = 0x00000010;
    pub const SHOW_SHADOWS: u32 = 0x00000020;
    pub const SMOOTH_FONTS: u32 = 0x00000040;
    pub const SHOW_DESKTOP_ICONS: u32 = 0x00000080;
    pub const SHOW_WINDOW_CONTENTS: u32 = 0x00000100;
    pub const SLIDE_TASKBAR: u32 = 0x00000200;
    pub const USE_DROP_SHADOWS: u32 = 0x00000400;
    pub const USE_VISUAL_STYLES: u32 = 0x00000800;
}

/// Data execution prevention
pub mod dep_policy {
    /// DEP for essential Windows programs only
    pub const ESSENTIAL_ONLY: u32 = 0;
    /// DEP for all programs
    pub const ALL_PROGRAMS: u32 = 1;
    /// DEP always off
    pub const ALWAYS_OFF: u32 = 2;
    /// DEP always on
    pub const ALWAYS_ON: u32 = 3;
}

// ============================================================================
// Types
// ============================================================================

/// Computer identification
#[derive(Clone, Copy)]
pub struct ComputerInfo {
    /// Computer name
    pub name: [u8; MAX_COMPUTER_NAME],
    /// Name length
    pub name_len: u8,
    /// Full computer name (with domain)
    pub full_name: [u8; MAX_COMPUTER_NAME + MAX_DOMAIN_NAME + 1],
    /// Full name length
    pub full_name_len: u16,
    /// Description
    pub description: [u8; MAX_DESCRIPTION],
    /// Description length
    pub desc_len: u16,
    /// Domain name (or workgroup if not domain member)
    pub domain: [u8; MAX_DOMAIN_NAME],
    /// Domain length
    pub domain_len: u16,
    /// Is domain member
    pub is_domain_member: bool,
}

impl ComputerInfo {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_COMPUTER_NAME],
            name_len: 0,
            full_name: [0; MAX_COMPUTER_NAME + MAX_DOMAIN_NAME + 1],
            full_name_len: 0,
            description: [0; MAX_DESCRIPTION],
            desc_len: 0,
            domain: [0; MAX_DOMAIN_NAME],
            domain_len: 0,
            is_domain_member: false,
        }
    }
}

/// Hardware profile
#[derive(Clone, Copy)]
pub struct HardwareProfile {
    /// Profile name
    pub name: [u8; MAX_PROFILE_NAME],
    /// Name length
    pub name_len: u8,
    /// Profile ID
    pub profile_id: u32,
    /// Is current profile
    pub is_current: bool,
    /// Preference order
    pub preference: u32,
    /// Is portable
    pub is_portable: bool,
    /// Docking state (0=unknown, 1=docked, 2=undocked)
    pub docking_state: u8,
}

impl HardwareProfile {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_PROFILE_NAME],
            name_len: 0,
            profile_id: 0,
            is_current: false,
            preference: 0,
            is_portable: false,
            docking_state: 0,
        }
    }
}

/// Environment variable
#[derive(Clone, Copy)]
pub struct EnvVariable {
    /// Variable name
    pub name: [u8; MAX_ENV_NAME],
    /// Name length
    pub name_len: u8,
    /// Variable value
    pub value: [u8; MAX_ENV_VALUE],
    /// Value length
    pub value_len: u16,
    /// Is system variable (vs user)
    pub is_system: bool,
}

impl EnvVariable {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_ENV_NAME],
            name_len: 0,
            value: [0; MAX_ENV_VALUE],
            value_len: 0,
            is_system: false,
        }
    }
}

/// Startup and recovery settings
#[derive(Clone, Copy)]
pub struct StartupRecovery {
    /// Default operating system (index)
    pub default_os: u8,
    /// Timeout (seconds, 0 = don't display)
    pub timeout: u32,
    /// Recovery actions (recovery_action flags)
    pub recovery_actions: u32,
    /// Debug info type (0=none, 1=small, 2=kernel, 3=complete)
    pub debug_info_type: u8,
    /// Dump file path
    pub dump_file: [u8; 260],
    /// Dump file length
    pub dump_file_len: u16,
}

impl StartupRecovery {
    pub const fn new() -> Self {
        Self {
            default_os: 0,
            timeout: 30,
            recovery_actions: recovery_action::WRITE_EVENT | recovery_action::AUTO_RESTART,
            debug_info_type: 1, // Small memory dump
            dump_file: [0; 260],
            dump_file_len: 0,
        }
    }
}

/// Performance settings
#[derive(Clone, Copy)]
pub struct PerformanceSettings {
    /// Performance option (performance_option)
    pub option: u32,
    /// Visual effects flags
    pub visual_effects: u32,
    /// Processor scheduling (0=programs, 1=background services)
    pub processor_scheduling: u8,
    /// Memory usage (0=programs, 1=system cache)
    pub memory_usage: u8,
    /// Virtual memory size (MB, 0 = system managed)
    pub virtual_memory: u32,
    /// DEP policy
    pub dep_policy: u32,
}

impl PerformanceSettings {
    pub const fn new() -> Self {
        Self {
            option: performance_option::CUSTOM,
            visual_effects: visual_effect::ANIMATE_WINDOWS |
                           visual_effect::SMOOTH_SCROLL |
                           visual_effect::SMOOTH_FONTS |
                           visual_effect::USE_VISUAL_STYLES,
            processor_scheduling: 0,
            memory_usage: 0,
            virtual_memory: 0,
            dep_policy: dep_policy::ESSENTIAL_ONLY,
        }
    }
}

/// Remote settings
#[derive(Clone, Copy)]
pub struct RemoteSettings {
    /// Allow Remote Assistance
    pub remote_assistance: bool,
    /// Allow Remote Desktop connections
    pub remote_desktop: bool,
    /// Allow connections from any version
    pub allow_any_version: bool,
    /// Require Network Level Authentication
    pub require_nla: bool,
}

impl RemoteSettings {
    pub const fn new() -> Self {
        Self {
            remote_assistance: false,
            remote_desktop: false,
            allow_any_version: false,
            require_nla: true,
        }
    }
}

/// System properties state
pub struct SystemProperties {
    /// Computer info
    pub computer: ComputerInfo,
    /// Startup/recovery
    pub startup: StartupRecovery,
    /// Performance
    pub performance: PerformanceSettings,
    /// Remote settings
    pub remote: RemoteSettings,
}

impl SystemProperties {
    pub const fn new() -> Self {
        Self {
            computer: ComputerInfo::new(),
            startup: StartupRecovery::new(),
            performance: PerformanceSettings::new(),
            remote: RemoteSettings::new(),
        }
    }
}

/// System properties dialog state
struct SystemDialog {
    /// Parent window
    parent: HWND,
    /// Current tab
    current_tab: u32,
    /// Modified flag
    modified: bool,
}

impl SystemDialog {
    const fn new() -> Self {
        Self {
            parent: UserHandle::NULL,
            current_tab: 0,
            modified: false,
        }
    }
}

// ============================================================================
// Static State
// ============================================================================

/// Module initialized
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// System properties
static PROPERTIES: SpinLock<SystemProperties> = SpinLock::new(SystemProperties::new());

/// Hardware profiles
static PROFILES: SpinLock<[HardwareProfile; MAX_HW_PROFILES]> =
    SpinLock::new([const { HardwareProfile::new() }; MAX_HW_PROFILES]);

/// Profile count
static PROFILE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Environment variables
static ENV_VARS: SpinLock<[EnvVariable; MAX_ENV_VARS]> =
    SpinLock::new([const { EnvVariable::new() }; MAX_ENV_VARS]);

/// Environment variable count
static ENV_COUNT: AtomicU32 = AtomicU32::new(0);

/// Dialog state
static DIALOG: SpinLock<SystemDialog> = SpinLock::new(SystemDialog::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize system properties
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Initialize computer info
    init_computer_info();

    // Initialize hardware profiles
    init_hardware_profiles();

    // Initialize environment variables
    init_environment_variables();

    crate::serial_println!("[SYSPROPS] System properties initialized");
}

/// Initialize computer info
fn init_computer_info() {
    let mut props = PROPERTIES.lock();

    let name = b"NOSTALGOS";
    let nlen = name.len();
    props.computer.name[..nlen].copy_from_slice(name);
    props.computer.name_len = nlen as u8;

    let workgroup = b"WORKGROUP";
    let wlen = workgroup.len();
    props.computer.domain[..wlen].copy_from_slice(workgroup);
    props.computer.domain_len = wlen as u16;

    props.computer.is_domain_member = false;

    // Build full name
    let full_name = b"NOSTALGOS";
    let flen = full_name.len();
    props.computer.full_name[..flen].copy_from_slice(full_name);
    props.computer.full_name_len = flen as u16;

    // Set dump file path
    let dump = b"%SystemRoot%\\MEMORY.DMP";
    let dlen = dump.len();
    props.startup.dump_file[..dlen].copy_from_slice(dump);
    props.startup.dump_file_len = dlen as u16;
}

/// Initialize hardware profiles
fn init_hardware_profiles() {
    let mut profiles = PROFILES.lock();
    let mut count = 0;

    // Default profile
    {
        let profile = &mut profiles[count];
        let name = b"Profile 1 (Current)";
        let nlen = name.len();
        profile.name[..nlen].copy_from_slice(name);
        profile.name_len = nlen as u8;
        profile.profile_id = 1;
        profile.is_current = true;
        profile.preference = 1;
        count += 1;
    }

    PROFILE_COUNT.store(count as u32, Ordering::Release);
}

/// Initialize default environment variables
fn init_environment_variables() {
    let mut vars = ENV_VARS.lock();
    let mut count = 0;

    let defaults: &[(&[u8], &[u8], bool)] = &[
        (b"SystemRoot", b"C:\\Windows", true),
        (b"SystemDrive", b"C:", true),
        (b"windir", b"C:\\Windows", true),
        (b"COMPUTERNAME", b"NOSTALGOS", true),
        (b"OS", b"Windows_NT", true),
        (b"PROCESSOR_ARCHITECTURE", b"AMD64", true),
        (b"NUMBER_OF_PROCESSORS", b"1", true),
        (b"TEMP", b"%USERPROFILE%\\Local Settings\\Temp", false),
        (b"TMP", b"%USERPROFILE%\\Local Settings\\Temp", false),
    ];

    for (name, value, is_system) in defaults.iter() {
        if count >= MAX_ENV_VARS {
            break;
        }

        let var = &mut vars[count];

        let nlen = name.len().min(MAX_ENV_NAME);
        var.name[..nlen].copy_from_slice(&name[..nlen]);
        var.name_len = nlen as u8;

        let vlen = value.len().min(MAX_ENV_VALUE);
        var.value[..vlen].copy_from_slice(&value[..vlen]);
        var.value_len = vlen as u16;

        var.is_system = *is_system;
        count += 1;
    }

    ENV_COUNT.store(count as u32, Ordering::Release);
}

// ============================================================================
// Computer Name and Domain
// ============================================================================

/// Get computer name
pub fn get_computer_name(buffer: &mut [u8]) -> usize {
    let props = PROPERTIES.lock();
    let len = (props.computer.name_len as usize).min(buffer.len());
    buffer[..len].copy_from_slice(&props.computer.name[..len]);
    len
}

/// Set computer name (requires restart)
pub fn set_computer_name(name: &[u8]) -> bool {
    if name.len() > MAX_COMPUTER_NAME {
        return false;
    }

    // Validate computer name
    for &c in name {
        if !c.is_ascii_alphanumeric() && c != b'-' {
            return false;
        }
    }

    let mut props = PROPERTIES.lock();
    let len = name.len();
    props.computer.name[..len].copy_from_slice(name);
    props.computer.name_len = len as u8;

    true
}

/// Get domain/workgroup name
pub fn get_domain_name(buffer: &mut [u8]) -> (usize, bool) {
    let props = PROPERTIES.lock();
    let len = (props.computer.domain_len as usize).min(buffer.len());
    buffer[..len].copy_from_slice(&props.computer.domain[..len]);
    (len, props.computer.is_domain_member)
}

/// Get computer description
pub fn get_computer_description(buffer: &mut [u8]) -> usize {
    let props = PROPERTIES.lock();
    let len = (props.computer.desc_len as usize).min(buffer.len());
    buffer[..len].copy_from_slice(&props.computer.description[..len]);
    len
}

/// Set computer description
pub fn set_computer_description(desc: &[u8]) {
    let mut props = PROPERTIES.lock();
    let len = desc.len().min(MAX_DESCRIPTION);
    props.computer.description[..len].copy_from_slice(&desc[..len]);
    props.computer.desc_len = len as u16;
}

// ============================================================================
// Hardware Profiles
// ============================================================================

/// Get hardware profile count
pub fn get_profile_count() -> u32 {
    PROFILE_COUNT.load(Ordering::Acquire)
}

/// Get hardware profile by index
pub fn get_profile(index: usize, profile: &mut HardwareProfile) -> bool {
    let profiles = PROFILES.lock();
    let count = PROFILE_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    *profile = profiles[index];
    true
}

/// Get current hardware profile
pub fn get_current_profile() -> Option<usize> {
    let profiles = PROFILES.lock();
    let count = PROFILE_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        if profiles[i].is_current {
            return Some(i);
        }
    }
    None
}

// ============================================================================
// Environment Variables
// ============================================================================

/// Get environment variable count
pub fn get_env_count() -> u32 {
    ENV_COUNT.load(Ordering::Acquire)
}

/// Get environment variable by index
pub fn get_env_var(index: usize, name: &mut [u8], value: &mut [u8]) -> Option<bool> {
    let vars = ENV_VARS.lock();
    let count = ENV_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return None;
    }

    let var = &vars[index];

    let nlen = (var.name_len as usize).min(name.len());
    name[..nlen].copy_from_slice(&var.name[..nlen]);

    let vlen = (var.value_len as usize).min(value.len());
    value[..vlen].copy_from_slice(&var.value[..vlen]);

    Some(var.is_system)
}

/// Get environment variable by name
pub fn get_env_value(name: &[u8], value: &mut [u8]) -> usize {
    let vars = ENV_VARS.lock();
    let count = ENV_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let nlen = vars[i].name_len as usize;
        if &vars[i].name[..nlen] == name {
            let vlen = (vars[i].value_len as usize).min(value.len());
            value[..vlen].copy_from_slice(&vars[i].value[..vlen]);
            return vlen;
        }
    }
    0
}

/// Set environment variable
pub fn set_env_var(name: &[u8], value: &[u8], is_system: bool) -> bool {
    let mut vars = ENV_VARS.lock();
    let count = ENV_COUNT.load(Ordering::Acquire) as usize;

    // Find existing
    for i in 0..count {
        let nlen = vars[i].name_len as usize;
        if &vars[i].name[..nlen] == name {
            let vlen = value.len().min(MAX_ENV_VALUE);
            vars[i].value[..vlen].copy_from_slice(&value[..vlen]);
            vars[i].value_len = vlen as u16;
            return true;
        }
    }

    // Add new
    if count < MAX_ENV_VARS {
        let var = &mut vars[count];

        let nlen = name.len().min(MAX_ENV_NAME);
        var.name[..nlen].copy_from_slice(&name[..nlen]);
        var.name_len = nlen as u8;

        let vlen = value.len().min(MAX_ENV_VALUE);
        var.value[..vlen].copy_from_slice(&value[..vlen]);
        var.value_len = vlen as u16;

        var.is_system = is_system;
        ENV_COUNT.store((count + 1) as u32, Ordering::Release);
        return true;
    }

    false
}

/// Delete environment variable
pub fn delete_env_var(name: &[u8]) -> bool {
    let mut vars = ENV_VARS.lock();
    let count = ENV_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let nlen = vars[i].name_len as usize;
        if &vars[i].name[..nlen] == name {
            for j in i..(count - 1) {
                vars[j] = vars[j + 1];
            }
            vars[count - 1] = EnvVariable::new();
            ENV_COUNT.store((count - 1) as u32, Ordering::Release);
            return true;
        }
    }
    false
}

// ============================================================================
// Startup and Recovery
// ============================================================================

/// Get startup/recovery settings
pub fn get_startup_recovery(settings: &mut StartupRecovery) {
    *settings = PROPERTIES.lock().startup;
}

/// Set startup/recovery settings
pub fn set_startup_recovery(settings: &StartupRecovery) {
    PROPERTIES.lock().startup = *settings;
}

// ============================================================================
// Performance Settings
// ============================================================================

/// Get performance settings
pub fn get_performance_settings(settings: &mut PerformanceSettings) {
    *settings = PROPERTIES.lock().performance;
}

/// Set performance settings
pub fn set_performance_settings(settings: &PerformanceSettings) {
    PROPERTIES.lock().performance = *settings;
}

/// Apply performance preset
pub fn apply_performance_preset(preset: u32) {
    let mut props = PROPERTIES.lock();

    match preset {
        performance_option::BEST_APPEARANCE => {
            props.performance.option = preset;
            props.performance.visual_effects = 0xFFFFFFFF; // All effects on
        }
        performance_option::BEST_PERFORMANCE => {
            props.performance.option = preset;
            props.performance.visual_effects = 0; // All effects off
        }
        _ => {
            props.performance.option = performance_option::CUSTOM;
        }
    }
}

// ============================================================================
// Remote Settings
// ============================================================================

/// Get remote settings
pub fn get_remote_settings(settings: &mut RemoteSettings) {
    *settings = PROPERTIES.lock().remote;
}

/// Set remote settings
pub fn set_remote_settings(settings: &RemoteSettings) {
    PROPERTIES.lock().remote = *settings;
}

/// Check if remote desktop is enabled
pub fn is_remote_desktop_enabled() -> bool {
    PROPERTIES.lock().remote.remote_desktop
}

/// Enable or disable remote desktop
pub fn set_remote_desktop_enabled(enabled: bool) {
    PROPERTIES.lock().remote.remote_desktop = enabled;
}

// ============================================================================
// Dialog API
// ============================================================================

/// Show system properties dialog
pub fn show_system_properties(parent: HWND, tab: u32) -> bool {
    let mut dialog = DIALOG.lock();

    dialog.parent = parent;
    dialog.current_tab = tab;
    dialog.modified = false;

    // Would show property sheet with tabs:
    // - General (system info display)
    // - Computer Name
    // - Hardware (device manager, profiles)
    // - Advanced (performance, startup, env vars)
    // - System Restore
    // - Remote

    true
}

/// Show device manager
pub fn show_device_manager(parent: HWND) -> bool {
    let _ = parent;
    // Would launch device manager MMC snap-in
    true
}

/// Show performance options
pub fn show_performance_options(parent: HWND) -> bool {
    let _ = parent;
    // Would show performance options dialog
    true
}

/// Show environment variables
pub fn show_environment_variables(parent: HWND) -> bool {
    let _ = parent;
    // Would show environment variables dialog
    true
}
