//! Service Control Operations
//!
//! Implements the service control functions:
//! - StartService
//! - StopService
//! - ControlService
//! - QueryServiceStatus
//! - ChangeServiceConfig

use super::types::*;
use super::database;

/// NTSTATUS codes for service operations
pub mod status {
    /// Success
    pub const SUCCESS: i32 = 0;
    /// Service does not exist
    pub const SERVICE_DOES_NOT_EXIST: i32 = 0xC0000424u32 as i32;
    /// Service already running
    pub const SERVICE_ALREADY_RUNNING: i32 = 0xC00000ACu32 as i32;
    /// Service not active
    pub const SERVICE_NOT_ACTIVE: i32 = 0xC0000022u32 as i32;
    /// Service cannot accept control
    pub const SERVICE_CANNOT_ACCEPT_CTRL: i32 = 0xC00000A0u32 as i32;
    /// Service disabled
    pub const SERVICE_DISABLED: i32 = 0xC0000008u32 as i32;
    /// Circular dependency
    pub const CIRCULAR_DEPENDENCY: i32 = 0xC0000217u32 as i32;
    /// Dependent services running
    pub const DEPENDENT_SERVICES_RUNNING: i32 = 0xC000041Bu32 as i32;
    /// Service marked for delete
    pub const SERVICE_MARKED_FOR_DELETE: i32 = 0xC0000434u32 as i32;
    /// Invalid service control
    pub const INVALID_SERVICE_CONTROL: i32 = 0xC000041Cu32 as i32;
}

// ============================================================================
// Service Control Functions
// ============================================================================

/// Start a service
///
/// # Arguments
/// * `service_name` - Name of the service to start
///
/// # Returns
/// NTSTATUS code indicating success or failure
pub fn scm_start_service(service_name: &str) -> i32 {
    // Find the service
    let service = match database::find_service(service_name) {
        Some(s) => s,
        None => return status::SERVICE_DOES_NOT_EXIST,
    };

    // Check if already running
    let state = service.state();
    if state == ServiceState::Running || state == ServiceState::StartPending {
        return status::SERVICE_ALREADY_RUNNING;
    }

    // Check if disabled
    if service.start_type == ServiceStartType::Disabled {
        return status::SERVICE_DISABLED;
    }

    // Check dependencies
    if !check_dependencies_running(service) {
        // Start dependencies first
        if !start_dependencies(service) {
            return status::CIRCULAR_DEPENDENCY;
        }
    }

    // Transition to StartPending
    service.set_state(ServiceState::StartPending);

    crate::serial_println!("[SVC] Starting service: {}", service_name);

    // Start based on service type
    let result = if service.is_driver() {
        start_driver_service(service)
    } else if service.is_win32_service() {
        start_win32_service(service)
    } else {
        status::SUCCESS // Unknown type, just mark as running
    };

    if result == status::SUCCESS {
        service.set_state(ServiceState::Running);
        crate::serial_println!("[SVC] Service started: {}", service_name);
    } else {
        service.set_state(ServiceState::Stopped);
        crate::serial_println!("[SVC] Service failed to start: {}", service_name);
    }

    result
}

/// Stop a service
///
/// # Arguments
/// * `service_name` - Name of the service to stop
///
/// # Returns
/// NTSTATUS code indicating success or failure
pub fn scm_stop_service(service_name: &str) -> i32 {
    let service = match database::find_service(service_name) {
        Some(s) => s,
        None => return status::SERVICE_DOES_NOT_EXIST,
    };

    // Check current state
    let state = service.state();
    if state == ServiceState::Stopped || state == ServiceState::StopPending {
        return status::SERVICE_NOT_ACTIVE;
    }

    // Check if service accepts stop control
    if (service.controls_accepted & service_accept::STOP) == 0 {
        return status::SERVICE_CANNOT_ACCEPT_CTRL;
    }

    // Check for dependent services still running
    if has_running_dependents(service_name) {
        return status::DEPENDENT_SERVICES_RUNNING;
    }

    // Transition to StopPending
    service.set_state(ServiceState::StopPending);

    crate::serial_println!("[SVC] Stopping service: {}", service_name);

    // Stop based on service type
    let result = if service.is_driver() {
        stop_driver_service(service)
    } else if service.is_win32_service() {
        stop_win32_service(service)
    } else {
        status::SUCCESS
    };

    if result == status::SUCCESS {
        service.set_state(ServiceState::Stopped);
        crate::serial_println!("[SVC] Service stopped: {}", service_name);
    } else {
        // Revert state on failure
        service.set_state(ServiceState::Running);
        crate::serial_println!("[SVC] Service failed to stop: {}", service_name);
    }

    result
}

/// Send a control code to a service
///
/// # Arguments
/// * `service_name` - Name of the service
/// * `control` - Control code to send
///
/// # Returns
/// NTSTATUS code indicating success or failure
pub fn scm_control_service(service_name: &str, control: ServiceControl) -> i32 {
    let service = match database::find_service(service_name) {
        Some(s) => s,
        None => return status::SERVICE_DOES_NOT_EXIST,
    };

    match control {
        ServiceControl::Stop => {
            return scm_stop_service(service_name);
        }
        ServiceControl::Pause => {
            return control_pause(service);
        }
        ServiceControl::Continue => {
            return control_continue(service);
        }
        ServiceControl::Interrogate => {
            // Just return current status
            return status::SUCCESS;
        }
        ServiceControl::Shutdown => {
            return control_shutdown(service);
        }
        _ => {
            // User-defined or other controls
            if service.is_win32_service() {
                return send_control_to_service(service, control);
            }
            return status::INVALID_SERVICE_CONTROL;
        }
    }
}

/// Query service status
///
/// # Arguments
/// * `service_name` - Name of the service
///
/// # Returns
/// ServiceStatus structure or None if service not found
pub fn scm_query_service_status(service_name: &str) -> Option<ServiceStatus> {
    let service = database::find_service(service_name)?;
    Some(ServiceStatus::from_record(service))
}

/// Query service status with process info
pub fn scm_query_service_status_ex(service_name: &str) -> Option<ServiceStatusProcess> {
    let service = database::find_service(service_name)?;
    Some(ServiceStatusProcess {
        status: ServiceStatus::from_record(service),
        process_id: service.process_id,
        service_flags: service.flags,
    })
}

/// Change service configuration
pub fn scm_change_service_config(
    service_name: &str,
    service_type: Option<u32>,
    start_type: Option<ServiceStartType>,
    error_control: Option<ServiceErrorControl>,
    image_path: Option<&str>,
    display_name: Option<&str>,
) -> i32 {
    let service = match database::find_service(service_name) {
        Some(s) => s,
        None => return status::SERVICE_DOES_NOT_EXIST,
    };

    // Update fields if provided
    if let Some(t) = service_type {
        service.service_type = t;
    }
    if let Some(s) = start_type {
        service.start_type = s;
    }
    if let Some(e) = error_control {
        service.error_control = e;
    }
    if let Some(p) = image_path {
        service.set_image_path(p);
    }
    if let Some(d) = display_name {
        service.set_display_name(d);
    }

    // Update registry
    update_service_registry(service);

    status::SUCCESS
}

// ============================================================================
// Internal Control Handlers
// ============================================================================

/// Handle pause control
fn control_pause(service: &mut ServiceRecord) -> i32 {
    if (service.controls_accepted & service_accept::PAUSE_CONTINUE) == 0 {
        return status::SERVICE_CANNOT_ACCEPT_CTRL;
    }

    if service.state() != ServiceState::Running {
        return status::SERVICE_NOT_ACTIVE;
    }

    service.set_state(ServiceState::PausePending);

    // For Win32 services, send control to service process
    if service.is_win32_service() {
        let result = send_control_to_service(service, ServiceControl::Pause);
        if result != status::SUCCESS {
            service.set_state(ServiceState::Running);
            return result;
        }
    }

    service.set_state(ServiceState::Paused);
    status::SUCCESS
}

/// Handle continue control
fn control_continue(service: &mut ServiceRecord) -> i32 {
    if (service.controls_accepted & service_accept::PAUSE_CONTINUE) == 0 {
        return status::SERVICE_CANNOT_ACCEPT_CTRL;
    }

    if service.state() != ServiceState::Paused {
        return status::SERVICE_NOT_ACTIVE;
    }

    service.set_state(ServiceState::ContinuePending);

    // For Win32 services, send control to service process
    if service.is_win32_service() {
        let result = send_control_to_service(service, ServiceControl::Continue);
        if result != status::SUCCESS {
            service.set_state(ServiceState::Paused);
            return result;
        }
    }

    service.set_state(ServiceState::Running);
    status::SUCCESS
}

/// Handle shutdown control
fn control_shutdown(service: &mut ServiceRecord) -> i32 {
    if (service.controls_accepted & service_accept::SHUTDOWN) == 0 {
        // Service doesn't want shutdown notification, just stop it
        return status::SUCCESS;
    }

    if service.is_win32_service() {
        let _ = send_control_to_service(service, ServiceControl::Shutdown);
    }

    // Give service time to clean up, then stop
    service.set_state(ServiceState::StopPending);
    service.set_state(ServiceState::Stopped);

    status::SUCCESS
}

// ============================================================================
// Service Type Handlers
// ============================================================================

/// Start a driver service
fn start_driver_service(service: &mut ServiceRecord) -> i32 {
    let image_path = service.image_path_str();

    if image_path.is_empty() {
        // Built-in driver, already loaded
        return status::SUCCESS;
    }

    // TODO: Load driver from image path
    // This would involve:
    // 1. Loading the driver image (PE file)
    // 2. Relocating it
    // 3. Calling DriverEntry

    crate::serial_println!(
        "[SVC] Would load driver: {} from {}",
        service.name_str(),
        image_path
    );

    status::SUCCESS
}

/// Stop a driver service
fn stop_driver_service(service: &mut ServiceRecord) -> i32 {
    // TODO: Unload driver
    // This would involve calling DriverUnload

    crate::serial_println!("[SVC] Would unload driver: {}", service.name_str());

    status::SUCCESS
}

/// Start a Win32 service
fn start_win32_service(service: &mut ServiceRecord) -> i32 {
    let image_path = service.image_path_str();

    if image_path.is_empty() {
        return status::SERVICE_DOES_NOT_EXIST;
    }

    // TODO: Create service process
    // This would involve:
    // 1. Creating a process with image_path
    // 2. Passing service parameters
    // 3. Waiting for service to register with SCM

    crate::serial_println!(
        "[SVC] Would start Win32 service: {} ({})",
        service.name_str(),
        image_path
    );

    // For now, generate a fake PID
    service.process_id = 1000 + (database::service_count() as u32);

    status::SUCCESS
}

/// Stop a Win32 service
fn stop_win32_service(service: &mut ServiceRecord) -> i32 {
    if service.process_id == 0 {
        return status::SERVICE_NOT_ACTIVE;
    }

    // Send stop control
    let result = send_control_to_service(service, ServiceControl::Stop);

    // TODO: Wait for process to exit
    // If it doesn't exit, terminate it

    service.process_id = 0;

    result
}

/// Send a control code to a Win32 service
fn send_control_to_service(service: &mut ServiceRecord, control: ServiceControl) -> i32 {
    if service.process_id == 0 {
        return status::SERVICE_NOT_ACTIVE;
    }

    // TODO: Send control via LPC/ALPC to service process
    // The service process has a control handler that receives these

    crate::serial_println!(
        "[SVC] Would send control {:?} to service {} (PID {})",
        control,
        service.name_str(),
        service.process_id
    );

    status::SUCCESS
}

// ============================================================================
// Dependency Management
// ============================================================================

/// Check if all dependencies of a service are running
fn check_dependencies_running(service: &ServiceRecord) -> bool {
    for i in 0..service.dependency_count {
        if let Some(dep_name) = service.get_dependency(i) {
            if let Some(dep) = database::find_service(dep_name) {
                if dep.state() != ServiceState::Running {
                    return false;
                }
            } else {
                return false; // Dependency doesn't exist
            }
        }
    }
    true
}

/// Start all dependencies of a service
fn start_dependencies(service: &ServiceRecord) -> bool {
    for i in 0..service.dependency_count {
        if let Some(dep_name) = service.get_dependency(i) {
            if let Some(dep) = database::find_service(dep_name) {
                if dep.state() != ServiceState::Running {
                    // Recursively start dependency
                    let result = scm_start_service(dep_name);
                    if result != status::SUCCESS && result != status::SERVICE_ALREADY_RUNNING {
                        return false;
                    }
                }
            } else {
                return false;
            }
        }
    }
    true
}

/// Check if any services depend on this one and are running
fn has_running_dependents(service_name: &str) -> bool {
    let mut has_dependents = false;

    database::enumerate_services(|svc| {
        if svc.state() == ServiceState::Running {
            for i in 0..svc.dependency_count {
                if let Some(dep) = svc.get_dependency(i) {
                    if dep == service_name {
                        has_dependents = true;
                        return false; // Stop enumeration
                    }
                }
            }
        }
        true // Continue enumeration
    });

    has_dependents
}

/// Update service configuration in registry
fn update_service_registry(service: &ServiceRecord) {
    let name = service.name_str();
    let (path_buf, path_len) = super::database::build_service_key_path(name);
    let path = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return,
    };

    unsafe {
        crate::cm::cm_write_dword(path, "Type", service.service_type);
        crate::cm::cm_write_dword(path, "Start", service.start_type as u32);
        crate::cm::cm_write_dword(path, "ErrorControl", service.error_control as u32);
    }
}

// ============================================================================
// Shutdown Support
// ============================================================================

/// Shutdown all services
///
/// Called during system shutdown to stop all services gracefully.
pub fn scm_shutdown_all_services() {
    crate::serial_println!("[SVC] Shutting down all services...");

    // First, send shutdown notification to all services that want it
    database::enumerate_services(|svc| {
        if svc.state() == ServiceState::Running {
            if (svc.controls_accepted & service_accept::SHUTDOWN) != 0 {
                crate::serial_println!("[SVC] Notifying {} of shutdown", svc.name_str());
            }
        }
        true
    });

    // Then stop all Win32 services
    let mut stopped = 0u32;
    database::enumerate_services(|svc| {
        if svc.state() == ServiceState::Running && svc.is_win32_service() {
            let name = svc.name_str();
            // Need to clone name since we can't hold reference during mutation
            let mut name_buf = [0u8; MAX_SERVICE_NAME];
            let len = name.len().min(MAX_SERVICE_NAME - 1);
            name_buf[..len].copy_from_slice(&name.as_bytes()[..len]);

            if let Ok(name_str) = core::str::from_utf8(&name_buf[..len]) {
                let _ = scm_stop_service(name_str);
                stopped += 1;
            }
        }
        true
    });

    crate::serial_println!("[SVC] Stopped {} services", stopped);
}
