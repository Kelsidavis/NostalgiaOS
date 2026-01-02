//! Service Control Manager (svc)
//!
//! The Service Control Manager (SCM) manages system services including:
//!
//! - **Service Database**: Registry-backed service configuration
//! - **Service Lifecycle**: Start, stop, pause, continue operations
//! - **Dependency Management**: Service dependency ordering
//! - **Driver Services**: Kernel driver loading and management
//! - **Process Services**: Service process creation and monitoring
//!
//! # Service Types
//!
//! - `SERVICE_KERNEL_DRIVER`: Kernel-mode driver (e.g., file system, disk)
//! - `SERVICE_FILE_SYSTEM_DRIVER`: File system driver
//! - `SERVICE_WIN32_OWN_PROCESS`: Service runs in its own process
//! - `SERVICE_WIN32_SHARE_PROCESS`: Service shares process with others
//!
//! # Service Start Types
//!
//! - `SERVICE_BOOT_START`: Started by OS loader
//! - `SERVICE_SYSTEM_START`: Started by OS during Phase 1
//! - `SERVICE_AUTO_START`: Started after system boot
//! - `SERVICE_DEMAND_START`: Started on demand
//! - `SERVICE_DISABLED`: Cannot be started
//!
//! # Registry Location
//!
//! Services are defined in: `HKLM\System\CurrentControlSet\Services\<ServiceName>`
//!
//! Each service key contains:
//! - `Type`: Service type (REG_DWORD)
//! - `Start`: Start type (REG_DWORD)
//! - `ErrorControl`: Error handling mode (REG_DWORD)
//! - `ImagePath`: Path to executable (REG_EXPAND_SZ)
//! - `DisplayName`: Human-readable name (REG_SZ)
//! - `Description`: Service description (REG_SZ)
//! - `ObjectName`: Account to run as (REG_SZ)
//! - `DependOnService`: Dependencies (REG_MULTI_SZ)
//! - `DependOnGroup`: Group dependencies (REG_MULTI_SZ)

pub mod types;
pub mod database;
pub mod control;
pub mod bits;
pub mod scheduler;
pub mod wuauserv;
pub mod spooler;
pub mod vss;
pub mod cryptsvc;
pub mod eventlog;
pub mod remreg;
pub mod msdtc;
pub mod dnsclient;
pub mod wmi;
pub mod w32time;
pub mod seclogon;
pub mod lanmanwks;
pub mod lanmansrv;
pub mod tapisrv;
pub mod appexp;
pub mod shellhw;
pub mod pnpsvc;
pub mod themes;
pub mod wersvc;
pub mod termsrv;
pub mod rpcss;
pub mod dhcpc;

pub use types::*;
pub use database::*;
pub use control::*;

use core::sync::atomic::{AtomicBool, Ordering};

/// SCM initialized flag
static SCM_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the Service Control Manager
///
/// This should be called during Phase 1 initialization after the
/// registry (CM) is available.
pub fn scm_initialize() {
    if SCM_INITIALIZED.swap(true, Ordering::SeqCst) {
        return; // Already initialized
    }

    crate::serial_println!("[SVC] Initializing Service Control Manager...");

    // Initialize the service database
    database::init_service_database();

    // Initialize BITS
    bits::init();

    // Initialize Task Scheduler
    scheduler::init();

    // Initialize Windows Update
    wuauserv::init();

    // Initialize Print Spooler
    spooler::init();

    // Initialize Volume Shadow Copy Service
    vss::init();

    // Initialize Cryptographic Services
    cryptsvc::init();

    // Initialize Event Log Service
    eventlog::init();

    // Initialize Remote Registry Service
    remreg::init();

    // Initialize Distributed Transaction Coordinator
    msdtc::init();

    // Initialize DNS Client Service
    dnsclient::init();

    // Initialize Windows Management Instrumentation
    wmi::init();

    // Initialize Windows Time Service
    w32time::init();

    // Initialize Secondary Logon (RunAs)
    seclogon::init();

    // Initialize Workstation service
    lanmanwks::init();

    // Initialize Server service
    lanmansrv::init();

    // Initialize Telephony service
    tapisrv::init();

    // Initialize Application Experience service
    appexp::init();

    // Initialize Shell Hardware Detection service
    shellhw::init();

    // Initialize Plug and Play service
    pnpsvc::init();

    // Initialize Themes service
    themes::init();

    // Initialize Windows Error Reporting service
    wersvc::init();

    // Initialize Terminal Services
    termsrv::init();

    // Initialize RPC Service
    rpcss::init();

    // Initialize DHCP Client service
    dhcpc::init();

    // Start boot-start drivers (already loaded by bootloader)
    // These are just registered, not actually started yet

    // Start system-start services
    start_system_services();

    crate::serial_println!("[SVC] Service Control Manager initialized");
}

/// Start system-start services
///
/// Called during Phase 1 init to start all SERVICE_SYSTEM_START services.
fn start_system_services() {
    crate::serial_println!("[SVC] Starting system services...");

    let count = database::start_services_by_start_type(ServiceStartType::SystemStart);

    crate::serial_println!("[SVC]   {} system services started", count);
}

/// Start auto-start services
///
/// Called after system initialization to start SERVICE_AUTO_START services.
pub fn start_auto_services() {
    crate::serial_println!("[SVC] Starting auto-start services...");

    let count = database::start_services_by_start_type(ServiceStartType::AutoStart);

    crate::serial_println!("[SVC]   {} auto-start services started", count);
}

/// Check if SCM is initialized
pub fn scm_is_initialized() -> bool {
    SCM_INITIALIZED.load(Ordering::SeqCst)
}
