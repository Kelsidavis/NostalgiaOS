//! COM+ System Application Service (COMSysApp)
//!
//! COM+ provides enterprise services for component-based applications
//! including transactions, object pooling, and role-based security.
//!
//! # Features
//!
//! - **Applications**: COM+ application management
//! - **Components**: Component registration and activation
//! - **Transactions**: Distributed transaction support
//! - **Object Pooling**: Reusable object instances
//! - **JIT Activation**: Just-in-time object activation
//! - **Role-Based Security**: Security roles for components
//!
//! # COM+ Applications
//!
//! - Server applications: Run in dllhost.exe
//! - Library applications: Run in-process
//!
//! # Key Services
//!
//! - DTC integration for transactions
//! - Queued components for async processing
//! - Event system for loosely-coupled events

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum COM+ applications
const MAX_APPLICATIONS: usize = 64;

/// Maximum components per application
const MAX_COMPONENTS: usize = 256;

/// Maximum application name length
const MAX_APP_NAME: usize = 64;

/// Maximum component name length
const MAX_COMPONENT_NAME: usize = 128;

/// Application type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationType {
    /// Server application (out-of-process)
    Server = 0,
    /// Library application (in-process)
    Library = 1,
}

impl ApplicationType {
    const fn empty() -> Self {
        ApplicationType::Server
    }
}

/// Application activation type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationType {
    /// Local activation only
    Local = 0,
    /// Allow remote activation
    Remote = 1,
}

impl ActivationType {
    const fn empty() -> Self {
        ActivationType::Local
    }
}

/// Application state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationState {
    /// Not running
    Stopped = 0,
    /// Starting up
    Starting = 1,
    /// Running
    Running = 2,
    /// Shutting down
    Stopping = 3,
    /// Paused
    Paused = 4,
}

impl ApplicationState {
    const fn empty() -> Self {
        ApplicationState::Stopped
    }
}

/// Transaction isolation level
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    /// Any level
    Any = 0,
    /// Read uncommitted
    ReadUncommitted = 1,
    /// Read committed
    ReadCommitted = 2,
    /// Repeatable read
    RepeatableRead = 3,
    /// Serializable
    Serializable = 4,
}

impl IsolationLevel {
    const fn empty() -> Self {
        IsolationLevel::ReadCommitted
    }
}

/// Transaction attribute
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionOption {
    /// Ignored
    Disabled = 0,
    /// Not supported
    NotSupported = 1,
    /// Supported
    Supported = 2,
    /// Required
    Required = 3,
    /// Requires new
    RequiresNew = 4,
}

impl TransactionOption {
    const fn empty() -> Self {
        TransactionOption::Disabled
    }
}

/// Component info
#[repr(C)]
#[derive(Clone)]
pub struct ComponentInfo {
    /// Component ID (CLSID)
    pub clsid: u128,
    /// Component name
    pub name: [u8; MAX_COMPONENT_NAME],
    /// Application index
    pub app_idx: usize,
    /// Transaction option
    pub transaction: TransactionOption,
    /// Isolation level
    pub isolation: IsolationLevel,
    /// Object pooling enabled
    pub pooling_enabled: bool,
    /// Minimum pool size
    pub pool_min: u32,
    /// Maximum pool size
    pub pool_max: u32,
    /// Current pool size
    pub pool_current: u32,
    /// JIT activation enabled
    pub jit_enabled: bool,
    /// Constructor string
    pub constructor_string: [u8; 64],
    /// Instance count
    pub instance_count: u32,
    /// Activation count
    pub activation_count: u64,
    /// Entry is valid
    pub valid: bool,
}

impl ComponentInfo {
    const fn empty() -> Self {
        ComponentInfo {
            clsid: 0,
            name: [0; MAX_COMPONENT_NAME],
            app_idx: 0,
            transaction: TransactionOption::empty(),
            isolation: IsolationLevel::empty(),
            pooling_enabled: false,
            pool_min: 0,
            pool_max: 10,
            pool_current: 0,
            jit_enabled: false,
            constructor_string: [0; 64],
            instance_count: 0,
            activation_count: 0,
            valid: false,
        }
    }
}

/// Security role
#[repr(C)]
#[derive(Clone)]
pub struct SecurityRole {
    /// Role name
    pub name: [u8; 32],
    /// Role description
    pub description: [u8; 64],
    /// Role is valid
    pub valid: bool,
}

impl SecurityRole {
    const fn empty() -> Self {
        SecurityRole {
            name: [0; 32],
            description: [0; 64],
            valid: false,
        }
    }
}

/// Maximum roles per application
const MAX_ROLES: usize = 16;

/// COM+ Application
#[repr(C)]
#[derive(Clone)]
pub struct ComPlusApplication {
    /// Application ID (GUID)
    pub app_id: u128,
    /// Application name
    pub name: [u8; MAX_APP_NAME],
    /// Application type
    pub app_type: ApplicationType,
    /// Activation type
    pub activation: ActivationType,
    /// Current state
    pub state: ApplicationState,
    /// Process ID (for server apps)
    pub process_id: u32,
    /// Identity (RunAs account)
    pub identity: [u8; 64],
    /// Component-level security enabled
    pub security_enabled: bool,
    /// Authorization level
    pub auth_level: u32,
    /// Impersonation level
    pub impersonation_level: u32,
    /// Queued component support
    pub queued_enabled: bool,
    /// CRM (Compensating Resource Manager) enabled
    pub crm_enabled: bool,
    /// 3GB memory support
    pub large_memory: bool,
    /// Security roles
    pub roles: [SecurityRole; MAX_ROLES],
    /// Role count
    pub role_count: usize,
    /// Created timestamp
    pub created_time: i64,
    /// Last started timestamp
    pub last_started: i64,
    /// Entry is valid
    pub valid: bool,
}

impl ComPlusApplication {
    const fn empty() -> Self {
        ComPlusApplication {
            app_id: 0,
            name: [0; MAX_APP_NAME],
            app_type: ApplicationType::empty(),
            activation: ActivationType::empty(),
            state: ApplicationState::empty(),
            process_id: 0,
            identity: [0; 64],
            security_enabled: false,
            auth_level: 0,
            impersonation_level: 0,
            queued_enabled: false,
            crm_enabled: false,
            large_memory: false,
            roles: [const { SecurityRole::empty() }; MAX_ROLES],
            role_count: 0,
            created_time: 0,
            last_started: 0,
            valid: false,
        }
    }
}

/// COM+ System Application state
pub struct ComSysAppState {
    /// Service is running
    pub running: bool,
    /// Applications
    pub applications: [ComPlusApplication; MAX_APPLICATIONS],
    /// Application count
    pub app_count: usize,
    /// Components
    pub components: [ComponentInfo; MAX_COMPONENTS],
    /// Component count
    pub component_count: usize,
    /// Next application ID
    pub next_app_id: u128,
    /// Service start time
    pub start_time: i64,
}

impl ComSysAppState {
    const fn new() -> Self {
        ComSysAppState {
            running: false,
            applications: [const { ComPlusApplication::empty() }; MAX_APPLICATIONS],
            app_count: 0,
            components: [const { ComponentInfo::empty() }; MAX_COMPONENTS],
            component_count: 0,
            next_app_id: 1,
            start_time: 0,
        }
    }
}

/// Global state
static COMSYSAPP_STATE: Mutex<ComSysAppState> = Mutex::new(ComSysAppState::new());

/// Statistics
static APPS_CREATED: AtomicU64 = AtomicU64::new(0);
static COMPONENTS_REGISTERED: AtomicU64 = AtomicU64::new(0);
static ACTIVATIONS: AtomicU64 = AtomicU64::new(0);
static TRANSACTIONS_STARTED: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize COM+ System Application service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = COMSYSAPP_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    crate::serial_println!("[COMSYSAPP] COM+ System Application service initialized");
}

/// Create a new COM+ application
pub fn create_application(
    name: &[u8],
    app_type: ApplicationType,
) -> Result<u128, u32> {
    let mut state = COMSYSAPP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Check for duplicate name
    for app in state.applications.iter() {
        if app.valid && &app.name[..name.len().min(MAX_APP_NAME)] == &name[..name.len().min(MAX_APP_NAME)] {
            return Err(0x80070055); // ERROR_DUP_NAME
        }
    }

    let slot = state.applications.iter().position(|a| !a.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let app_id = state.next_app_id;
    state.next_app_id += 1;

    let now = crate::rtl::time::rtl_get_system_time();
    state.app_count += 1;

    let name_len = name.len().min(MAX_APP_NAME);

    let app = &mut state.applications[slot];
    app.app_id = app_id;
    app.name[..name_len].copy_from_slice(&name[..name_len]);
    app.app_type = app_type;
    app.activation = ActivationType::Local;
    app.state = ApplicationState::Stopped;
    app.process_id = 0;
    app.security_enabled = true;
    app.auth_level = 2; // RPC_C_AUTHN_LEVEL_CONNECT
    app.impersonation_level = 2; // RPC_C_IMP_LEVEL_IDENTIFY
    app.created_time = now;
    app.valid = true;

    APPS_CREATED.fetch_add(1, Ordering::SeqCst);

    Ok(app_id)
}

/// Delete a COM+ application
pub fn delete_application(app_id: u128) -> Result<(), u32> {
    let mut state = COMSYSAPP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.applications.iter().position(|a| a.valid && a.app_id == app_id);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    // Check if running
    if state.applications[idx].state == ApplicationState::Running {
        return Err(0x80070005); // Access denied - must stop first
    }

    // Remove all components for this application
    let mut removed = 0usize;
    for comp in state.components.iter_mut() {
        if comp.valid && comp.app_idx == idx {
            comp.valid = false;
            removed += 1;
        }
    }
    state.component_count = state.component_count.saturating_sub(removed);

    state.applications[idx].valid = false;
    state.app_count = state.app_count.saturating_sub(1);

    Ok(())
}

/// Start a COM+ application
pub fn start_application(app_id: u128) -> Result<(), u32> {
    let mut state = COMSYSAPP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.applications.iter().position(|a| a.valid && a.app_id == app_id);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let app = &mut state.applications[idx];

    if app.state == ApplicationState::Running {
        return Ok(()); // Already running
    }

    app.state = ApplicationState::Starting;

    // For server applications, would launch dllhost.exe
    if app.app_type == ApplicationType::Server {
        // Simulated process ID
        app.process_id = 1000 + (idx as u32);
    }

    app.state = ApplicationState::Running;
    app.last_started = crate::rtl::time::rtl_get_system_time();

    Ok(())
}

/// Stop a COM+ application
pub fn stop_application(app_id: u128) -> Result<(), u32> {
    let mut state = COMSYSAPP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.applications.iter().position(|a| a.valid && a.app_id == app_id);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let app = &mut state.applications[idx];

    if app.state == ApplicationState::Stopped {
        return Ok(()); // Already stopped
    }

    app.state = ApplicationState::Stopping;

    // Clear component instances
    for comp in state.components.iter_mut() {
        if comp.valid && comp.app_idx == idx {
            comp.instance_count = 0;
            comp.pool_current = 0;
        }
    }

    let app = &mut state.applications[idx];
    app.state = ApplicationState::Stopped;
    app.process_id = 0;

    Ok(())
}

/// Register a component in an application
pub fn register_component(
    app_id: u128,
    clsid: u128,
    name: &[u8],
) -> Result<usize, u32> {
    let mut state = COMSYSAPP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let app_idx = state.applications.iter().position(|a| a.valid && a.app_id == app_id);
    let app_idx = match app_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    // Check for duplicate CLSID
    for comp in state.components.iter() {
        if comp.valid && comp.clsid == clsid {
            return Err(0x80070055); // ERROR_DUP_NAME
        }
    }

    let slot = state.components.iter().position(|c| !c.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    state.component_count += 1;

    let name_len = name.len().min(MAX_COMPONENT_NAME);

    let comp = &mut state.components[slot];
    comp.clsid = clsid;
    comp.name[..name_len].copy_from_slice(&name[..name_len]);
    comp.app_idx = app_idx;
    comp.transaction = TransactionOption::Disabled;
    comp.isolation = IsolationLevel::ReadCommitted;
    comp.pooling_enabled = false;
    comp.pool_min = 0;
    comp.pool_max = 10;
    comp.jit_enabled = true;
    comp.valid = true;

    COMPONENTS_REGISTERED.fetch_add(1, Ordering::SeqCst);

    Ok(slot)
}

/// Unregister a component
pub fn unregister_component(clsid: u128) -> Result<(), u32> {
    let mut state = COMSYSAPP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.components.iter().position(|c| c.valid && c.clsid == clsid);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    // Check if instances exist
    if state.components[idx].instance_count > 0 {
        return Err(0x80070005); // Access denied - instances active
    }

    state.components[idx].valid = false;
    state.component_count = state.component_count.saturating_sub(1);

    Ok(())
}

/// Configure component transaction
pub fn set_component_transaction(
    clsid: u128,
    transaction: TransactionOption,
    isolation: IsolationLevel,
) -> Result<(), u32> {
    let mut state = COMSYSAPP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let comp = state.components.iter_mut()
        .find(|c| c.valid && c.clsid == clsid);

    let comp = match comp {
        Some(c) => c,
        None => return Err(0x80070057),
    };

    comp.transaction = transaction;
    comp.isolation = isolation;

    Ok(())
}

/// Configure component pooling
pub fn set_component_pooling(
    clsid: u128,
    enabled: bool,
    min_size: u32,
    max_size: u32,
) -> Result<(), u32> {
    let mut state = COMSYSAPP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let comp = state.components.iter_mut()
        .find(|c| c.valid && c.clsid == clsid);

    let comp = match comp {
        Some(c) => c,
        None => return Err(0x80070057),
    };

    comp.pooling_enabled = enabled;
    comp.pool_min = min_size;
    comp.pool_max = max_size;

    Ok(())
}

/// Activate a component (create instance)
pub fn activate_component(clsid: u128) -> Result<u64, u32> {
    let mut state = COMSYSAPP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.components.iter().position(|c| c.valid && c.clsid == clsid);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let app_idx = state.components[idx].app_idx;

    // Check if application is running (for server apps)
    if state.applications[app_idx].app_type == ApplicationType::Server
        && state.applications[app_idx].state != ApplicationState::Running
    {
        return Err(0x800401F0); // CO_E_SERVER_NOT_PAUSED or similar
    }

    let comp = &mut state.components[idx];

    // Check pooling
    if comp.pooling_enabled && comp.pool_current > 0 {
        // Return pooled object (simulated)
        comp.pool_current -= 1;
        comp.activation_count += 1;
        ACTIVATIONS.fetch_add(1, Ordering::SeqCst);
        return Ok(comp.activation_count);
    }

    // Create new instance
    comp.instance_count += 1;
    comp.activation_count += 1;
    ACTIVATIONS.fetch_add(1, Ordering::SeqCst);

    // Start transaction if required
    if comp.transaction == TransactionOption::Required || comp.transaction == TransactionOption::RequiresNew {
        TRANSACTIONS_STARTED.fetch_add(1, Ordering::SeqCst);
    }

    Ok(comp.activation_count)
}

/// Deactivate a component (release instance)
pub fn deactivate_component(clsid: u128) -> Result<(), u32> {
    let mut state = COMSYSAPP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let comp = state.components.iter_mut()
        .find(|c| c.valid && c.clsid == clsid);

    let comp = match comp {
        Some(c) => c,
        None => return Err(0x80070057),
    };

    if comp.instance_count == 0 {
        return Err(0x80070015); // ERROR_NOT_READY
    }

    comp.instance_count -= 1;

    // Return to pool if pooling enabled
    if comp.pooling_enabled && comp.pool_current < comp.pool_max {
        comp.pool_current += 1;
    }

    Ok(())
}

/// Add a security role to an application
pub fn add_role(app_id: u128, name: &[u8], description: &[u8]) -> Result<usize, u32> {
    let mut state = COMSYSAPP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let app = state.applications.iter_mut()
        .find(|a| a.valid && a.app_id == app_id);

    let app = match app {
        Some(a) => a,
        None => return Err(0x80070057),
    };

    if app.role_count >= MAX_ROLES {
        return Err(0x8007000E);
    }

    let slot = app.roles.iter().position(|r| !r.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let role = &mut app.roles[slot];
    let name_len = name.len().min(32);
    role.name[..name_len].copy_from_slice(&name[..name_len]);

    let desc_len = description.len().min(64);
    role.description[..desc_len].copy_from_slice(&description[..desc_len]);

    role.valid = true;
    app.role_count += 1;

    Ok(slot)
}

/// Get application info
pub fn get_application(app_id: u128) -> Option<ComPlusApplication> {
    let state = COMSYSAPP_STATE.lock();

    state.applications.iter()
        .find(|a| a.valid && a.app_id == app_id)
        .cloned()
}

/// Get application by name
pub fn get_application_by_name(name: &[u8]) -> Option<ComPlusApplication> {
    let state = COMSYSAPP_STATE.lock();
    let name_len = name.len().min(MAX_APP_NAME);

    state.applications.iter()
        .find(|a| a.valid && a.name[..name_len] == name[..name_len])
        .cloned()
}

/// Get component info
pub fn get_component(clsid: u128) -> Option<ComponentInfo> {
    let state = COMSYSAPP_STATE.lock();

    state.components.iter()
        .find(|c| c.valid && c.clsid == clsid)
        .cloned()
}

/// Enumerate applications
pub fn enum_applications() -> ([ComPlusApplication; MAX_APPLICATIONS], usize) {
    let state = COMSYSAPP_STATE.lock();
    let mut result = [const { ComPlusApplication::empty() }; MAX_APPLICATIONS];
    let mut count = 0;

    for app in state.applications.iter() {
        if app.valid && count < MAX_APPLICATIONS {
            result[count] = app.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Enumerate components for an application
pub fn enum_components(app_id: u128) -> ([ComponentInfo; MAX_COMPONENTS], usize) {
    let state = COMSYSAPP_STATE.lock();
    let mut result = [const { ComponentInfo::empty() }; MAX_COMPONENTS];
    let mut count = 0;

    let app_idx = state.applications.iter().position(|a| a.valid && a.app_id == app_id);
    let app_idx = match app_idx {
        Some(i) => i,
        None => return (result, 0),
    };

    for comp in state.components.iter() {
        if comp.valid && comp.app_idx == app_idx && count < MAX_COMPONENTS {
            result[count] = comp.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get running application count
pub fn get_running_count() -> usize {
    let state = COMSYSAPP_STATE.lock();
    state.applications.iter()
        .filter(|a| a.valid && a.state == ApplicationState::Running)
        .count()
}

/// Get total instance count
pub fn get_total_instances() -> u32 {
    let state = COMSYSAPP_STATE.lock();
    state.components.iter()
        .filter(|c| c.valid)
        .map(|c| c.instance_count)
        .sum()
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64, u64) {
    (
        APPS_CREATED.load(Ordering::SeqCst),
        COMPONENTS_REGISTERED.load(Ordering::SeqCst),
        ACTIVATIONS.load(Ordering::SeqCst),
        TRANSACTIONS_STARTED.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = COMSYSAPP_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = COMSYSAPP_STATE.lock();
    state.running = false;

    // Stop all running applications
    for app in state.applications.iter_mut() {
        if app.valid && app.state == ApplicationState::Running {
            app.state = ApplicationState::Stopped;
            app.process_id = 0;
        }
    }

    crate::serial_println!("[COMSYSAPP] COM+ System Application service stopped");
}
