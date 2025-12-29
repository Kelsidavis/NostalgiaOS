//! Service Types and Constants
//!
//! Defines the fundamental types, states, and constants used by the
//! Service Control Manager.

use core::sync::atomic::{AtomicU32, Ordering};

// ============================================================================
// Service Type Constants
// ============================================================================

/// Service type flags
pub mod service_type {
    /// Kernel-mode driver
    pub const KERNEL_DRIVER: u32 = 0x00000001;
    /// File system driver
    pub const FILE_SYSTEM_DRIVER: u32 = 0x00000002;
    /// Driver adapter (reserved)
    pub const ADAPTER: u32 = 0x00000004;
    /// Driver recognizer (reserved)
    pub const RECOGNIZER_DRIVER: u32 = 0x00000008;
    /// Driver type mask
    pub const DRIVER: u32 = KERNEL_DRIVER | FILE_SYSTEM_DRIVER | RECOGNIZER_DRIVER;

    /// Service runs in its own process
    pub const WIN32_OWN_PROCESS: u32 = 0x00000010;
    /// Service shares a process with others
    pub const WIN32_SHARE_PROCESS: u32 = 0x00000020;
    /// Win32 service type mask
    pub const WIN32: u32 = WIN32_OWN_PROCESS | WIN32_SHARE_PROCESS;

    /// Service can interact with desktop
    pub const INTERACTIVE_PROCESS: u32 = 0x00000100;
}

/// Service start type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum ServiceStartType {
    /// Started by the OS loader before kernel init
    BootStart = 0,
    /// Started during kernel Phase 1 initialization
    SystemStart = 1,
    /// Started automatically after system boot
    AutoStart = 2,
    /// Started on demand by applications
    #[default]
    DemandStart = 3,
    /// Service is disabled and cannot be started
    Disabled = 4,
}

impl ServiceStartType {
    /// Convert from u32
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => ServiceStartType::BootStart,
            1 => ServiceStartType::SystemStart,
            2 => ServiceStartType::AutoStart,
            3 => ServiceStartType::DemandStart,
            4 => ServiceStartType::Disabled,
            _ => ServiceStartType::DemandStart,
        }
    }
}

/// Service error control
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum ServiceErrorControl {
    /// Ignore errors, continue startup
    #[default]
    Ignore = 0,
    /// Log error but continue startup
    Normal = 1,
    /// Use last-known-good configuration
    Severe = 2,
    /// Fail system startup if service fails
    Critical = 3,
}

impl ServiceErrorControl {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => ServiceErrorControl::Ignore,
            1 => ServiceErrorControl::Normal,
            2 => ServiceErrorControl::Severe,
            3 => ServiceErrorControl::Critical,
            _ => ServiceErrorControl::Ignore,
        }
    }
}

// ============================================================================
// Service State
// ============================================================================

/// Current service state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum ServiceState {
    /// Service is not running
    #[default]
    Stopped = 1,
    /// Service is starting
    StartPending = 2,
    /// Service is stopping
    StopPending = 3,
    /// Service is running
    Running = 4,
    /// Service is about to continue
    ContinuePending = 5,
    /// Service is pausing
    PausePending = 6,
    /// Service is paused
    Paused = 7,
}

impl ServiceState {
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => ServiceState::Stopped,
            2 => ServiceState::StartPending,
            3 => ServiceState::StopPending,
            4 => ServiceState::Running,
            5 => ServiceState::ContinuePending,
            6 => ServiceState::PausePending,
            7 => ServiceState::Paused,
            _ => ServiceState::Stopped,
        }
    }

    /// Check if service is running or pending
    pub fn is_running_or_pending(&self) -> bool {
        matches!(
            self,
            ServiceState::Running
                | ServiceState::StartPending
                | ServiceState::ContinuePending
                | ServiceState::PausePending
                | ServiceState::Paused
        )
    }
}

// ============================================================================
// Service Control Codes
// ============================================================================

/// Service control commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServiceControl {
    /// Stop the service
    Stop = 1,
    /// Pause the service
    Pause = 2,
    /// Continue the service
    Continue = 3,
    /// Query service status (interrogate)
    Interrogate = 4,
    /// Notify service of shutdown
    Shutdown = 5,
    /// Notify of parameter change
    ParamChange = 6,
    /// Notify of network binding change
    NetBindAdd = 7,
    NetBindRemove = 8,
    NetBindEnable = 9,
    NetBindDisable = 10,
    /// Device event notification
    DeviceEvent = 11,
    /// Hardware profile change
    HardwareProfileChange = 12,
    /// Power event
    PowerEvent = 13,
    /// Session change
    SessionChange = 14,
}

impl ServiceControl {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(ServiceControl::Stop),
            2 => Some(ServiceControl::Pause),
            3 => Some(ServiceControl::Continue),
            4 => Some(ServiceControl::Interrogate),
            5 => Some(ServiceControl::Shutdown),
            6 => Some(ServiceControl::ParamChange),
            7 => Some(ServiceControl::NetBindAdd),
            8 => Some(ServiceControl::NetBindRemove),
            9 => Some(ServiceControl::NetBindEnable),
            10 => Some(ServiceControl::NetBindDisable),
            11 => Some(ServiceControl::DeviceEvent),
            12 => Some(ServiceControl::HardwareProfileChange),
            13 => Some(ServiceControl::PowerEvent),
            14 => Some(ServiceControl::SessionChange),
            _ => None,
        }
    }
}

/// Controls accepted by service
pub mod service_accept {
    pub const STOP: u32 = 0x00000001;
    pub const PAUSE_CONTINUE: u32 = 0x00000002;
    pub const SHUTDOWN: u32 = 0x00000004;
    pub const PARAMCHANGE: u32 = 0x00000008;
    pub const NETBINDCHANGE: u32 = 0x00000010;
    pub const HARDWAREPROFILECHANGE: u32 = 0x00000020;
    pub const POWEREVENT: u32 = 0x00000040;
    pub const SESSIONCHANGE: u32 = 0x00000080;
}

// ============================================================================
// Service Access Rights
// ============================================================================

/// Service access rights
pub mod service_access {
    /// Query service configuration
    pub const QUERY_CONFIG: u32 = 0x0001;
    /// Change service configuration
    pub const CHANGE_CONFIG: u32 = 0x0002;
    /// Query service status
    pub const QUERY_STATUS: u32 = 0x0004;
    /// Enumerate dependent services
    pub const ENUMERATE_DEPENDENTS: u32 = 0x0008;
    /// Start the service
    pub const START: u32 = 0x0010;
    /// Stop the service
    pub const STOP: u32 = 0x0020;
    /// Pause or continue the service
    pub const PAUSE_CONTINUE: u32 = 0x0040;
    /// Query the service
    pub const INTERROGATE: u32 = 0x0080;
    /// Issue user-defined control codes
    pub const USER_DEFINED_CONTROL: u32 = 0x0100;

    /// All access rights
    pub const ALL_ACCESS: u32 = 0x01FF;
}

/// SCM access rights
pub mod scm_access {
    /// Connect to SCM
    pub const CONNECT: u32 = 0x0001;
    /// Create a service
    pub const CREATE_SERVICE: u32 = 0x0002;
    /// Enumerate services
    pub const ENUMERATE_SERVICE: u32 = 0x0004;
    /// Lock service database
    pub const LOCK: u32 = 0x0008;
    /// Query lock status
    pub const QUERY_LOCK_STATUS: u32 = 0x0010;
    /// Modify boot config
    pub const MODIFY_BOOT_CONFIG: u32 = 0x0020;

    /// All access rights
    pub const ALL_ACCESS: u32 = 0x003F;
}

// ============================================================================
// Service Record
// ============================================================================

/// Maximum service name length
pub const MAX_SERVICE_NAME: usize = 256;

/// Maximum image path length
pub const MAX_IMAGE_PATH: usize = 260;

/// Maximum dependencies
pub const MAX_DEPENDENCIES: usize = 16;

/// Service record - runtime representation of a service
#[repr(C)]
pub struct ServiceRecord {
    /// Service name (null-terminated)
    pub name: [u8; MAX_SERVICE_NAME],
    /// Display name (null-terminated)
    pub display_name: [u8; MAX_SERVICE_NAME],
    /// Image path (null-terminated)
    pub image_path: [u8; MAX_IMAGE_PATH],

    /// Service type (SERVICE_KERNEL_DRIVER, etc.)
    pub service_type: u32,
    /// Start type (BootStart, SystemStart, etc.)
    pub start_type: ServiceStartType,
    /// Error control (Ignore, Normal, Severe, Critical)
    pub error_control: ServiceErrorControl,

    /// Current service state
    pub current_state: AtomicU32,
    /// Controls accepted by service
    pub controls_accepted: u32,
    /// Win32 exit code
    pub exit_code: u32,
    /// Service-specific exit code
    pub service_exit_code: u32,
    /// Check point for long operations
    pub check_point: u32,
    /// Wait hint for long operations (ms)
    pub wait_hint: u32,

    /// Process ID (for Win32 services)
    pub process_id: u32,
    /// Service flags
    pub flags: u32,

    /// Number of dependencies
    pub dependency_count: usize,
    /// Service dependencies (by name)
    pub dependencies: [[u8; MAX_SERVICE_NAME]; MAX_DEPENDENCIES],

    /// Registry key handle (if open)
    pub registry_key: usize,

    /// Service is registered in database
    pub registered: bool,
}

impl ServiceRecord {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_SERVICE_NAME],
            display_name: [0; MAX_SERVICE_NAME],
            image_path: [0; MAX_IMAGE_PATH],
            service_type: 0,
            start_type: ServiceStartType::DemandStart,
            error_control: ServiceErrorControl::Ignore,
            current_state: AtomicU32::new(ServiceState::Stopped as u32),
            controls_accepted: 0,
            exit_code: 0,
            service_exit_code: 0,
            check_point: 0,
            wait_hint: 0,
            process_id: 0,
            flags: 0,
            dependency_count: 0,
            dependencies: [[0; MAX_SERVICE_NAME]; MAX_DEPENDENCIES],
            registry_key: 0,
            registered: false,
        }
    }

    /// Get the service name as a string
    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(MAX_SERVICE_NAME);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    /// Set the service name
    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_SERVICE_NAME - 1);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name[len] = 0;
    }

    /// Get the display name as a string
    pub fn display_name_str(&self) -> &str {
        let len = self
            .display_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_SERVICE_NAME);
        core::str::from_utf8(&self.display_name[..len]).unwrap_or("")
    }

    /// Set the display name
    pub fn set_display_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_SERVICE_NAME - 1);
        self.display_name[..len].copy_from_slice(&bytes[..len]);
        self.display_name[len] = 0;
    }

    /// Get the image path as a string
    pub fn image_path_str(&self) -> &str {
        let len = self
            .image_path
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_IMAGE_PATH);
        core::str::from_utf8(&self.image_path[..len]).unwrap_or("")
    }

    /// Set the image path
    pub fn set_image_path(&mut self, path: &str) {
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_IMAGE_PATH - 1);
        self.image_path[..len].copy_from_slice(&bytes[..len]);
        self.image_path[len] = 0;
    }

    /// Get current state
    pub fn state(&self) -> ServiceState {
        ServiceState::from_u32(self.current_state.load(Ordering::SeqCst))
    }

    /// Set current state
    pub fn set_state(&self, state: ServiceState) {
        self.current_state.store(state as u32, Ordering::SeqCst);
    }

    /// Check if service is a driver
    pub fn is_driver(&self) -> bool {
        (self.service_type & service_type::DRIVER) != 0
    }

    /// Check if service is a Win32 service
    pub fn is_win32_service(&self) -> bool {
        (self.service_type & service_type::WIN32) != 0
    }

    /// Add a dependency
    pub fn add_dependency(&mut self, name: &str) -> bool {
        if self.dependency_count >= MAX_DEPENDENCIES {
            return false;
        }

        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_SERVICE_NAME - 1);
        self.dependencies[self.dependency_count][..len].copy_from_slice(&bytes[..len]);
        self.dependencies[self.dependency_count][len] = 0;
        self.dependency_count += 1;
        true
    }

    /// Get dependency by index
    pub fn get_dependency(&self, index: usize) -> Option<&str> {
        if index >= self.dependency_count {
            return None;
        }
        let len = self.dependencies[index]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_SERVICE_NAME);
        core::str::from_utf8(&self.dependencies[index][..len]).ok()
    }
}

impl Default for ServiceRecord {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Service Status
// ============================================================================

/// Service status structure (returned by QueryServiceStatus)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ServiceStatus {
    /// Type of service
    pub service_type: u32,
    /// Current state
    pub current_state: u32,
    /// Controls accepted
    pub controls_accepted: u32,
    /// Win32 exit code
    pub win32_exit_code: u32,
    /// Service-specific exit code
    pub service_specific_exit_code: u32,
    /// Check point
    pub check_point: u32,
    /// Wait hint (ms)
    pub wait_hint: u32,
}

impl ServiceStatus {
    pub const fn new() -> Self {
        Self {
            service_type: 0,
            current_state: ServiceState::Stopped as u32,
            controls_accepted: 0,
            win32_exit_code: 0,
            service_specific_exit_code: 0,
            check_point: 0,
            wait_hint: 0,
        }
    }

    /// Create from a service record
    pub fn from_record(record: &ServiceRecord) -> Self {
        Self {
            service_type: record.service_type,
            current_state: record.current_state.load(Ordering::SeqCst),
            controls_accepted: record.controls_accepted,
            win32_exit_code: record.exit_code,
            service_specific_exit_code: record.service_exit_code,
            check_point: record.check_point,
            wait_hint: record.wait_hint,
        }
    }
}

impl Default for ServiceStatus {
    fn default() -> Self {
        Self::new()
    }
}

/// Service status with process info (extended)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ServiceStatusProcess {
    /// Basic status
    pub status: ServiceStatus,
    /// Process ID
    pub process_id: u32,
    /// Service flags
    pub service_flags: u32,
}

impl ServiceStatusProcess {
    pub const fn new() -> Self {
        Self {
            status: ServiceStatus::new(),
            process_id: 0,
            service_flags: 0,
        }
    }
}

impl Default for ServiceStatusProcess {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Service Flags
// ============================================================================

/// Service record flags
pub mod service_flags {
    /// Service runs in System process
    pub const RUNS_IN_SYSTEM_PROCESS: u32 = 0x00000001;
}
