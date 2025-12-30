//! Service Database
//!
//! Manages the runtime service database, backed by the registry.
//! Services are stored in: HKLM\System\CurrentControlSet\Services\<ServiceName>

use core::sync::atomic::{AtomicU32, Ordering};
use crate::ke::SpinLock;
use super::types::*;

/// Maximum number of services in the database
pub const MAX_SERVICES: usize = 256;

/// Service database
static mut SERVICE_DATABASE: [ServiceRecord; MAX_SERVICES] = {
    const INIT: ServiceRecord = ServiceRecord::new();
    [INIT; MAX_SERVICES]
};

/// Service database lock
static DATABASE_LOCK: SpinLock<()> = SpinLock::new(());

/// Number of registered services
static SERVICE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Database initialized flag
static mut DATABASE_INITIALIZED: bool = false;

// ============================================================================
// Registry Keys (Constants)
// ============================================================================

/// Base registry path for services (relative to HKLM)
pub const SERVICES_KEY_PATH: &str = "MACHINE\\SYSTEM\\CurrentControlSet\\Services";

/// Registry value names
pub mod registry_values {
    pub const TYPE: &str = "Type";
    pub const START: &str = "Start";
    pub const ERROR_CONTROL: &str = "ErrorControl";
    pub const IMAGE_PATH: &str = "ImagePath";
    pub const DISPLAY_NAME: &str = "DisplayName";
    pub const DESCRIPTION: &str = "Description";
    pub const OBJECT_NAME: &str = "ObjectName";
    pub const DEPEND_ON_SERVICE: &str = "DependOnService";
    pub const DEPEND_ON_GROUP: &str = "DependOnGroup";
    pub const GROUP: &str = "Group";
    pub const TAG: &str = "Tag";
}

// ============================================================================
// Database Initialization
// ============================================================================

/// Initialize the service database
///
/// Loads service definitions from the registry and creates the
/// CurrentControlSet\Services key if it doesn't exist.
pub fn init_service_database() {
    let _guard = DATABASE_LOCK.lock();

    unsafe {
        if DATABASE_INITIALIZED {
            return;
        }

        crate::serial_println!("[SVC] Initializing service database...");

        // Create the Services key in registry if needed
        create_services_registry_key();

        // Register built-in kernel services
        register_builtin_services();

        // Load services from registry
        load_services_from_registry();

        DATABASE_INITIALIZED = true;

        let count = SERVICE_COUNT.load(Ordering::SeqCst);
        crate::serial_println!("[SVC]   {} services registered", count);
    }
}

/// Create the Services registry key
fn create_services_registry_key() {
    unsafe {
        // Create CurrentControlSet key
        let _ = crate::cm::cm_create_key("MACHINE\\SYSTEM\\CurrentControlSet", 0);

        // Create Services key under CurrentControlSet
        let _ = crate::cm::cm_create_key(SERVICES_KEY_PATH, 0);
    }
}

/// Register built-in kernel services
///
/// These represent the core kernel "drivers" that are always present.
fn register_builtin_services() {
    // Register kernel executive as a pseudo-service
    register_kernel_service(
        "Kernel",
        "Windows NT Kernel",
        service_type::KERNEL_DRIVER,
        ServiceStartType::BootStart,
    );

    // Register HAL as a pseudo-service
    register_kernel_service(
        "HAL",
        "Hardware Abstraction Layer",
        service_type::KERNEL_DRIVER,
        ServiceStartType::BootStart,
    );

    // Register file system drivers
    register_kernel_service(
        "FatFs",
        "FAT File System Driver",
        service_type::FILE_SYSTEM_DRIVER,
        ServiceStartType::BootStart,
    );

    // Register block device drivers
    register_kernel_service(
        "AtaPort",
        "ATA/IDE Controller Driver",
        service_type::KERNEL_DRIVER,
        ServiceStartType::BootStart,
    );

    register_kernel_service(
        "RamDisk",
        "RAM Disk Driver",
        service_type::KERNEL_DRIVER,
        ServiceStartType::SystemStart,
    );
}

/// Register a kernel-mode service (driver already loaded)
fn register_kernel_service(
    name: &str,
    display_name: &str,
    svc_type: u32,
    start_type: ServiceStartType,
) {
    unsafe {
        let count = SERVICE_COUNT.load(Ordering::SeqCst) as usize;
        if count >= MAX_SERVICES {
            return;
        }

        let record = &mut SERVICE_DATABASE[count];
        record.registered = true;
        record.set_name(name);
        record.set_display_name(display_name);
        record.service_type = svc_type;
        record.start_type = start_type;
        record.error_control = ServiceErrorControl::Normal;

        // Kernel services are always running
        record.set_state(ServiceState::Running);
        record.controls_accepted = 0; // Cannot stop kernel services

        SERVICE_COUNT.fetch_add(1, Ordering::SeqCst);
    }
}

/// Load services from the registry
fn load_services_from_registry() {
    unsafe {
        // Open Services key
        let services_handle = match crate::cm::cm_open_key(SERVICES_KEY_PATH) {
            Ok(h) => h,
            Err(_) => return,
        };

        // Enumerate all subkeys (each subkey is a service)
        let mut index = 0;
        loop {
            let subkey_handle = match crate::cm::cm_enumerate_key(services_handle, index) {
                Ok(h) => h,
                Err(_) => break,
            };

            // Get the subkey name
            if let Some(name) = crate::cm::cm_get_key_name(subkey_handle) {
                // Skip built-in services we already registered
                if !is_builtin_service(name) {
                    load_service_from_key(name);
                }
            }

            index += 1;
        }
    }
}

/// Check if a service name is a built-in
fn is_builtin_service(name: &str) -> bool {
    matches!(name, "Kernel" | "HAL" | "FatFs" | "AtaPort" | "RamDisk")
}

/// Build full service key path
pub fn build_service_key_path(name: &str) -> ([u8; 512], usize) {
    let mut buf = [0u8; 512];
    let prefix = SERVICES_KEY_PATH.as_bytes();
    let name_bytes = name.as_bytes();

    let mut offset = 0;
    buf[offset..offset + prefix.len()].copy_from_slice(prefix);
    offset += prefix.len();
    buf[offset] = b'\\';
    offset += 1;
    let copy_len = name_bytes.len().min(buf.len() - offset - 1);
    buf[offset..offset + copy_len].copy_from_slice(&name_bytes[..copy_len]);
    offset += copy_len;

    (buf, offset)
}

/// Load a single service from registry
fn load_service_from_key(name: &str) {
    let (path_buf, path_len) = build_service_key_path(name);
    let path = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return,
    };

    unsafe {
        let count = SERVICE_COUNT.load(Ordering::SeqCst) as usize;
        if count >= MAX_SERVICES {
            return;
        }

        let record = &mut SERVICE_DATABASE[count];
        record.registered = true;
        record.set_name(name);

        // Read Type value
        if let Some(type_val) = crate::cm::cm_read_dword(path, "Type") {
            record.service_type = type_val;
        }

        // Read Start value
        if let Some(start_val) = crate::cm::cm_read_dword(path, "Start") {
            record.start_type = ServiceStartType::from_u32(start_val);
        }

        // Read ErrorControl value
        if let Some(err_val) = crate::cm::cm_read_dword(path, "ErrorControl") {
            record.error_control = ServiceErrorControl::from_u32(err_val);
        }

        // Read DisplayName
        if let Some(display) = crate::cm::cm_read_string(path, "DisplayName") {
            record.set_display_name(display);
        } else {
            record.set_display_name(name);
        }

        // Read ImagePath
        if let Some(image_path) = crate::cm::cm_read_string(path, "ImagePath") {
            record.set_image_path(image_path);
        }

        // Service starts in Stopped state
        record.set_state(ServiceState::Stopped);

        SERVICE_COUNT.fetch_add(1, Ordering::SeqCst);
    }
}

// ============================================================================
// Service Database Operations
// ============================================================================

/// Find a service by name
pub fn find_service(name: &str) -> Option<&'static mut ServiceRecord> {
    let _guard = DATABASE_LOCK.lock();

    unsafe {
        let count = SERVICE_COUNT.load(Ordering::SeqCst) as usize;
        for i in 0..count {
            if SERVICE_DATABASE[i].registered && SERVICE_DATABASE[i].name_str() == name {
                return Some(&mut SERVICE_DATABASE[i]);
            }
        }
    }

    None
}

/// Find a service by index
pub fn get_service_by_index(index: usize) -> Option<&'static ServiceRecord> {
    if index >= MAX_SERVICES {
        return None;
    }

    let _guard = DATABASE_LOCK.lock();

    unsafe {
        if SERVICE_DATABASE[index].registered {
            Some(&SERVICE_DATABASE[index])
        } else {
            None
        }
    }
}

/// Get the number of registered services
pub fn service_count() -> u32 {
    SERVICE_COUNT.load(Ordering::SeqCst)
}

/// Create a new service
///
/// Adds a service to the database and creates registry entries.
pub fn create_service(
    name: &str,
    display_name: &str,
    svc_type: u32,
    start_type: ServiceStartType,
    error_control: ServiceErrorControl,
    image_path: &str,
) -> Option<usize> {
    let _guard = DATABASE_LOCK.lock();

    unsafe {
        // Check if service already exists
        let count = SERVICE_COUNT.load(Ordering::SeqCst) as usize;
        for i in 0..count {
            if SERVICE_DATABASE[i].registered && SERVICE_DATABASE[i].name_str() == name {
                return None; // Already exists
            }
        }

        if count >= MAX_SERVICES {
            return None;
        }

        // Create the service record
        let record = &mut SERVICE_DATABASE[count];
        record.registered = true;
        record.set_name(name);
        record.set_display_name(display_name);
        record.service_type = svc_type;
        record.start_type = start_type;
        record.error_control = error_control;
        record.set_image_path(image_path);
        record.set_state(ServiceState::Stopped);

        // Create registry entries
        create_service_registry_entries(name, svc_type, start_type, error_control, image_path);

        SERVICE_COUNT.fetch_add(1, Ordering::SeqCst);

        crate::serial_println!("[SVC] Created service: {}", name);

        Some(count)
    }
}

/// Create registry entries for a service
fn create_service_registry_entries(
    name: &str,
    svc_type: u32,
    start_type: ServiceStartType,
    error_control: ServiceErrorControl,
    image_path: &str,
) {
    let (path_buf, path_len) = build_service_key_path(name);
    let path = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return,
    };

    unsafe {
        // Create the service key
        let _ = crate::cm::cm_create_key(path, 0);

        // Set values
        crate::cm::cm_write_dword(path, "Type", svc_type);
        crate::cm::cm_write_dword(path, "Start", start_type as u32);
        crate::cm::cm_write_dword(path, "ErrorControl", error_control as u32);
        crate::cm::cm_write_string(path, "ImagePath", image_path);
    }
}

/// Delete a service
pub fn delete_service(name: &str) -> bool {
    let _guard = DATABASE_LOCK.lock();

    unsafe {
        let count = SERVICE_COUNT.load(Ordering::SeqCst) as usize;
        for i in 0..count {
            if SERVICE_DATABASE[i].registered && SERVICE_DATABASE[i].name_str() == name {
                // Check if service is stopped
                if SERVICE_DATABASE[i].state() != ServiceState::Stopped {
                    return false; // Cannot delete running service
                }

                // Mark as unregistered
                SERVICE_DATABASE[i].registered = false;

                // Delete from registry
                delete_service_registry_entries(name);

                crate::serial_println!("[SVC] Deleted service: {}", name);
                return true;
            }
        }
    }

    false
}

/// Delete registry entries for a service
fn delete_service_registry_entries(name: &str) {
    let (path_buf, path_len) = build_service_key_path(name);
    let path = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return,
    };

    unsafe {
        crate::cm::cm_delete_key(path);
    }
}

/// Start services by start type
///
/// Starts all services with the given start type.
/// Returns the number of services started.
pub fn start_services_by_start_type(start_type: ServiceStartType) -> u32 {
    let mut started = 0u32;

    unsafe {
        let count = SERVICE_COUNT.load(Ordering::SeqCst) as usize;

        // First pass: collect services to start (respecting dependencies)
        let mut to_start: [usize; MAX_SERVICES] = [0; MAX_SERVICES];
        let mut to_start_count = 0usize;

        for i in 0..count {
            if SERVICE_DATABASE[i].registered
                && SERVICE_DATABASE[i].start_type == start_type
                && SERVICE_DATABASE[i].state() == ServiceState::Stopped
            {
                to_start[to_start_count] = i;
                to_start_count += 1;
            }
        }

        // Second pass: start services (TODO: dependency ordering)
        for i in 0..to_start_count {
            let idx = to_start[i];
            if start_service_internal(idx) {
                started += 1;
            }
        }
    }

    started
}

/// Start a service by index (internal)
unsafe fn start_service_internal(index: usize) -> bool {
    if index >= MAX_SERVICES {
        return false;
    }

    let record = &mut SERVICE_DATABASE[index];
    if !record.registered {
        return false;
    }

    // Check current state
    if record.state() != ServiceState::Stopped {
        return false;
    }

    // Transition to StartPending
    record.set_state(ServiceState::StartPending);

    let name = record.name_str();
    crate::serial_println!("[SVC] Starting service: {}", name);

    // Handle based on service type
    if record.is_driver() {
        // Driver services: load the driver
        // For built-in drivers, they're already loaded
        // For loadable drivers, we'd call the driver loader here
        record.set_state(ServiceState::Running);
        return true;
    } else if record.is_win32_service() {
        // Win32 service: create the service process
        // TODO: Process creation for services
        // For now, just mark as running for placeholder
        record.set_state(ServiceState::Running);
        return true;
    }

    // Unknown service type
    record.set_state(ServiceState::Stopped);
    false
}

/// Enumerate services
pub fn enumerate_services<F>(mut callback: F)
where
    F: FnMut(&ServiceRecord) -> bool,
{
    let _guard = DATABASE_LOCK.lock();

    unsafe {
        let count = SERVICE_COUNT.load(Ordering::SeqCst) as usize;
        for i in 0..count {
            if SERVICE_DATABASE[i].registered {
                if !callback(&SERVICE_DATABASE[i]) {
                    break;
                }
            }
        }
    }
}

/// Get services by type
pub fn get_services_by_type(svc_type: u32) -> u32 {
    let _guard = DATABASE_LOCK.lock();

    let mut count = 0u32;

    unsafe {
        let total = SERVICE_COUNT.load(Ordering::SeqCst) as usize;
        for i in 0..total {
            if SERVICE_DATABASE[i].registered
                && (SERVICE_DATABASE[i].service_type & svc_type) != 0
            {
                count += 1;
            }
        }
    }

    count
}

/// Get services by state
pub fn get_services_by_state(state: ServiceState) -> u32 {
    let _guard = DATABASE_LOCK.lock();

    let mut count = 0u32;

    unsafe {
        let total = SERVICE_COUNT.load(Ordering::SeqCst) as usize;
        for i in 0..total {
            if SERVICE_DATABASE[i].registered && SERVICE_DATABASE[i].state() == state {
                count += 1;
            }
        }
    }

    count
}

// ============================================================================
// Service Dependency Management
// ============================================================================

/// Maximum depth for dependency resolution (prevents infinite loops)
const MAX_DEPENDENCY_DEPTH: usize = 16;

/// Result of dependency check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyCheckResult {
    /// All dependencies are satisfied (running)
    Satisfied,
    /// One or more dependencies are not running
    NotSatisfied,
    /// Dependency not found in database
    NotFound,
    /// Circular dependency detected
    Circular,
}

/// Check if all dependencies for a service are satisfied
pub fn check_dependencies(service_name: &str) -> DependencyCheckResult {
    let _guard = DATABASE_LOCK.lock();

    unsafe {
        check_dependencies_internal(service_name, 0, &mut [false; MAX_SERVICES])
    }
}

/// Internal dependency checking with cycle detection
unsafe fn check_dependencies_internal(
    service_name: &str,
    depth: usize,
    visited: &mut [bool; MAX_SERVICES],
) -> DependencyCheckResult {
    if depth >= MAX_DEPENDENCY_DEPTH {
        return DependencyCheckResult::Circular;
    }

    // Find the service
    let idx = match find_service_index(service_name) {
        Some(i) => i,
        None => return DependencyCheckResult::NotFound,
    };

    // Check for circular dependency
    if visited[idx] {
        return DependencyCheckResult::Circular;
    }
    visited[idx] = true;

    let record = &SERVICE_DATABASE[idx];

    // Check each dependency
    for i in 0..record.dependency_count {
        if let Some(dep_name) = record.get_dependency(i) {
            // Find the dependency
            let dep_idx = match find_service_index(dep_name) {
                Some(i) => i,
                None => {
                    crate::serial_println!("[SVC] Dependency not found: {}", dep_name);
                    return DependencyCheckResult::NotFound;
                }
            };

            let dep_record = &SERVICE_DATABASE[dep_idx];

            // Check if dependency is running
            if dep_record.state() != ServiceState::Running {
                return DependencyCheckResult::NotSatisfied;
            }

            // Recursively check dependency's dependencies
            match check_dependencies_internal(dep_name, depth + 1, visited) {
                DependencyCheckResult::Satisfied => {}
                other => return other,
            }
        }
    }

    DependencyCheckResult::Satisfied
}

/// Find service index by name
unsafe fn find_service_index(name: &str) -> Option<usize> {
    let count = SERVICE_COUNT.load(Ordering::SeqCst) as usize;
    for i in 0..count {
        if SERVICE_DATABASE[i].registered && SERVICE_DATABASE[i].name_str() == name {
            return Some(i);
        }
    }
    None
}

/// Get dependency order for starting services
///
/// Returns a list of service indices in the order they should be started
/// (dependencies first).
pub fn get_dependency_order(start_type: ServiceStartType) -> [usize; MAX_SERVICES] {
    let _guard = DATABASE_LOCK.lock();

    let mut order = [0usize; MAX_SERVICES];
    let mut order_count = 0usize;
    let mut added = [false; MAX_SERVICES];

    unsafe {
        let count = SERVICE_COUNT.load(Ordering::SeqCst) as usize;

        // Keep adding services until we've processed all eligible services
        let mut changed = true;
        while changed {
            changed = false;

            for i in 0..count {
                if added[i] {
                    continue;
                }

                let record = &SERVICE_DATABASE[i];
                if !record.registered || record.start_type != start_type {
                    added[i] = true; // Mark as processed (not eligible)
                    continue;
                }

                // Check if all dependencies are already in the order list
                let mut deps_satisfied = true;
                for j in 0..record.dependency_count {
                    if let Some(dep_name) = record.get_dependency(j) {
                        if let Some(dep_idx) = find_service_index(dep_name) {
                            if !added[dep_idx] {
                                // If dependency is eligible and not yet added
                                let dep_record = &SERVICE_DATABASE[dep_idx];
                                if dep_record.registered && dep_record.start_type == start_type {
                                    deps_satisfied = false;
                                    break;
                                }
                            }
                        }
                    }
                }

                if deps_satisfied {
                    order[order_count] = i;
                    order_count += 1;
                    added[i] = true;
                    changed = true;
                }
            }
        }

        // Add any remaining services (circular dependencies or missing deps)
        for i in 0..count {
            if !added[i] {
                let record = &SERVICE_DATABASE[i];
                if record.registered && record.start_type == start_type {
                    order[order_count] = i;
                    order_count += 1;
                }
            }
        }
    }

    order
}

// ============================================================================
// Service Control Operations
// ============================================================================

/// Stop a service by name
pub fn stop_service(name: &str) -> bool {
    let _guard = DATABASE_LOCK.lock();

    unsafe {
        if let Some(idx) = find_service_index(name) {
            stop_service_internal(idx)
        } else {
            false
        }
    }
}

/// Stop a service by index (internal)
unsafe fn stop_service_internal(index: usize) -> bool {
    if index >= MAX_SERVICES {
        return false;
    }

    let record = &mut SERVICE_DATABASE[index];
    if !record.registered {
        return false;
    }

    // Check current state
    if record.state() == ServiceState::Stopped {
        return true; // Already stopped
    }

    if record.state() != ServiceState::Running && record.state() != ServiceState::Paused {
        return false; // Can't stop from this state
    }

    // Transition to StopPending
    record.set_state(ServiceState::StopPending);

    let name = record.name_str();
    crate::serial_println!("[SVC] Stopping service: {}", name);

    // Handle based on service type
    if record.is_driver() {
        // Driver: would unload the driver
        record.set_state(ServiceState::Stopped);
        return true;
    } else if record.is_win32_service() {
        // Win32 service: would send control message and terminate process
        if record.process_id != 0 {
            // TODO: Send ServiceControl::Stop to service
            // TODO: Terminate process if needed
        }
        record.set_state(ServiceState::Stopped);
        record.process_id = 0;
        return true;
    }

    record.set_state(ServiceState::Stopped);
    true
}

/// Pause a service by name
pub fn pause_service(name: &str) -> bool {
    let _guard = DATABASE_LOCK.lock();

    unsafe {
        if let Some(idx) = find_service_index(name) {
            pause_service_internal(idx)
        } else {
            false
        }
    }
}

/// Pause a service by index (internal)
unsafe fn pause_service_internal(index: usize) -> bool {
    if index >= MAX_SERVICES {
        return false;
    }

    let record = &mut SERVICE_DATABASE[index];
    if !record.registered {
        return false;
    }

    // Check if service accepts pause
    if (record.controls_accepted & super::types::service_accept::PAUSE_CONTINUE) == 0 {
        return false;
    }

    // Check current state
    if record.state() != ServiceState::Running {
        return false;
    }

    // Transition to PausePending
    record.set_state(ServiceState::PausePending);

    let name = record.name_str();
    crate::serial_println!("[SVC] Pausing service: {}", name);

    // TODO: Send ServiceControl::Pause to service

    record.set_state(ServiceState::Paused);
    true
}

/// Continue a paused service by name
pub fn continue_service(name: &str) -> bool {
    let _guard = DATABASE_LOCK.lock();

    unsafe {
        if let Some(idx) = find_service_index(name) {
            continue_service_internal(idx)
        } else {
            false
        }
    }
}

/// Continue a service by index (internal)
unsafe fn continue_service_internal(index: usize) -> bool {
    if index >= MAX_SERVICES {
        return false;
    }

    let record = &mut SERVICE_DATABASE[index];
    if !record.registered {
        return false;
    }

    // Check if service accepts continue
    if (record.controls_accepted & super::types::service_accept::PAUSE_CONTINUE) == 0 {
        return false;
    }

    // Check current state
    if record.state() != ServiceState::Paused {
        return false;
    }

    // Transition to ContinuePending
    record.set_state(ServiceState::ContinuePending);

    let name = record.name_str();
    crate::serial_println!("[SVC] Continuing service: {}", name);

    // TODO: Send ServiceControl::Continue to service

    record.set_state(ServiceState::Running);
    true
}

/// Send a control code to a service
pub fn control_service(name: &str, control: super::types::ServiceControl) -> bool {
    match control {
        super::types::ServiceControl::Stop => stop_service(name),
        super::types::ServiceControl::Pause => pause_service(name),
        super::types::ServiceControl::Continue => continue_service(name),
        super::types::ServiceControl::Interrogate => {
            // Just return current status - success if service exists
            let _guard = DATABASE_LOCK.lock();
            unsafe { find_service_index(name).is_some() }
        }
        _ => {
            // Other controls are not yet implemented
            false
        }
    }
}

/// Get service status by name
pub fn get_service_status(name: &str) -> Option<ServiceStatus> {
    let _guard = DATABASE_LOCK.lock();

    unsafe {
        if let Some(idx) = find_service_index(name) {
            let record = &SERVICE_DATABASE[idx];
            Some(ServiceStatus {
                service_type: record.service_type,
                current_state: record.state(),
                controls_accepted: record.controls_accepted,
                win32_exit_code: record.exit_code,
                service_specific_exit_code: record.service_exit_code,
                check_point: record.check_point,
                wait_hint: record.wait_hint,
            })
        } else {
            None
        }
    }
}

/// Service status structure
#[derive(Debug, Clone, Copy)]
pub struct ServiceStatus {
    /// Service type
    pub service_type: u32,
    /// Current state
    pub current_state: ServiceState,
    /// Controls accepted
    pub controls_accepted: u32,
    /// Win32 exit code
    pub win32_exit_code: u32,
    /// Service-specific exit code
    pub service_specific_exit_code: u32,
    /// Check point for pending operations
    pub check_point: u32,
    /// Wait hint for pending operations
    pub wait_hint: u32,
}

/// Stop all running services in reverse dependency order
pub fn stop_all_services() -> u32 {
    let _guard = DATABASE_LOCK.lock();

    let mut stopped = 0u32;

    unsafe {
        // Get services in start order, then reverse for stop order
        let order = get_dependency_order_all();
        let count = SERVICE_COUNT.load(Ordering::SeqCst) as usize;

        // Iterate in reverse order
        for i in (0..count).rev() {
            let idx = order[i];
            if idx < MAX_SERVICES && SERVICE_DATABASE[idx].registered {
                if SERVICE_DATABASE[idx].state() == ServiceState::Running {
                    if stop_service_internal(idx) {
                        stopped += 1;
                    }
                }
            }
        }
    }

    crate::serial_println!("[SVC] Stopped {} services", stopped);
    stopped
}

/// Get dependency order for all running services
unsafe fn get_dependency_order_all() -> [usize; MAX_SERVICES] {
    let mut order = [0usize; MAX_SERVICES];
    let mut order_count = 0usize;
    let mut added = [false; MAX_SERVICES];

    let count = SERVICE_COUNT.load(Ordering::SeqCst) as usize;

    // Keep adding services until we've processed all
    let mut changed = true;
    while changed {
        changed = false;

        for i in 0..count {
            if added[i] {
                continue;
            }

            let record = &SERVICE_DATABASE[i];
            if !record.registered {
                added[i] = true;
                continue;
            }

            // Check if all dependencies are already in the order list
            let mut deps_satisfied = true;
            for j in 0..record.dependency_count {
                if let Some(dep_name) = record.get_dependency(j) {
                    if let Some(dep_idx) = find_service_index(dep_name) {
                        if !added[dep_idx] && SERVICE_DATABASE[dep_idx].registered {
                            deps_satisfied = false;
                            break;
                        }
                    }
                }
            }

            if deps_satisfied {
                order[order_count] = i;
                order_count += 1;
                added[i] = true;
                changed = true;
            }
        }
    }

    // Add any remaining services
    for i in 0..count {
        if !added[i] && SERVICE_DATABASE[i].registered {
            order[order_count] = i;
            order_count += 1;
        }
    }

    order
}
