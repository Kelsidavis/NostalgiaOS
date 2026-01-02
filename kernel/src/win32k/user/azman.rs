//! Authorization Manager
//!
//! Windows Server 2003 Authorization Manager snap-in implementation.
//! Provides role-based access control (RBAC) management.
//!
//! # Features
//!
//! - Authorization stores (XML, AD)
//! - Applications
//! - Operations and tasks
//! - Roles and role assignments
//! - Scopes
//! - Business rules (scripting)
//!
//! # References
//!
//! Based on Windows Server 2003 Authorization Manager (azman.msc)

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::UserHandle;
use bitflags::bitflags;

/// HWND type alias
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum authorization stores
const MAX_STORES: usize = 8;

/// Maximum applications per store
const MAX_APPLICATIONS: usize = 16;

/// Maximum operations per application
const MAX_OPERATIONS: usize = 64;

/// Maximum tasks per application
const MAX_TASKS: usize = 32;

/// Maximum roles per application
const MAX_ROLES: usize = 32;

/// Maximum scopes per application
const MAX_SCOPES: usize = 16;

/// Maximum role assignments
const MAX_ASSIGNMENTS: usize = 64;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum description length
const MAX_DESC_LEN: usize = 256;

/// Maximum script length
const MAX_SCRIPT_LEN: usize = 1024;

// ============================================================================
// Store Type
// ============================================================================

/// Authorization store type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum StoreType {
    /// XML file store
    #[default]
    Xml = 0,
    /// Active Directory store
    ActiveDirectory = 1,
    /// SQL Server store (Windows Server 2003 R2+)
    SqlServer = 2,
}

impl StoreType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Xml => "XML File",
            Self::ActiveDirectory => "Active Directory",
            Self::SqlServer => "SQL Server",
        }
    }
}

// ============================================================================
// Script Language
// ============================================================================

/// Business rule script language
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ScriptLanguage {
    /// VBScript
    #[default]
    VbScript = 0,
    /// JScript
    JScript = 1,
}

impl ScriptLanguage {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::VbScript => "VBScript",
            Self::JScript => "JScript",
        }
    }
}

bitflags! {
    /// Application flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ApplicationFlags: u32 {
        /// Application is enabled
        const ENABLED = 0x0001;
        /// Generate audits
        const GENERATE_AUDITS = 0x0002;
        /// Allow delegation
        const ALLOW_DELEGATION = 0x0004;
        /// Apply role definition to this application
        const APPLY_STORE_SACL = 0x0008;
    }
}

// ============================================================================
// Operation
// ============================================================================

/// Authorization operation (low-level permission)
#[derive(Clone, Copy)]
pub struct Operation {
    /// Operation in use
    pub in_use: bool,
    /// Operation ID (unique within application)
    pub operation_id: u32,
    /// Operation name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub description_len: usize,
}

impl Operation {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            operation_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            description: [0u8; MAX_DESC_LEN],
            description_len: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_description(&mut self, desc: &[u8]) {
        let len = desc.len().min(MAX_DESC_LEN);
        self.description[..len].copy_from_slice(&desc[..len]);
        self.description_len = len;
    }
}

// ============================================================================
// Task
// ============================================================================

/// Authorization task (collection of operations)
#[derive(Clone, Copy)]
pub struct Task {
    /// Task in use
    pub in_use: bool,
    /// Task name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub description_len: usize,
    /// Operations included in this task (by ID)
    pub operations: [u32; 16],
    /// Operation count
    pub operation_count: usize,
    /// Nested tasks (by index)
    pub nested_tasks: [u8; 8],
    /// Nested task count
    pub nested_task_count: usize,
    /// Business rule enabled
    pub has_biz_rule: bool,
    /// Business rule language
    pub biz_rule_language: ScriptLanguage,
    /// Business rule script
    pub biz_rule: [u8; MAX_SCRIPT_LEN],
    /// Script length
    pub biz_rule_len: usize,
}

impl Task {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            description: [0u8; MAX_DESC_LEN],
            description_len: 0,
            operations: [0u32; 16],
            operation_count: 0,
            nested_tasks: [0u8; 8],
            nested_task_count: 0,
            has_biz_rule: false,
            biz_rule_language: ScriptLanguage::VbScript,
            biz_rule: [0u8; MAX_SCRIPT_LEN],
            biz_rule_len: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn add_operation(&mut self, operation_id: u32) -> bool {
        if self.operation_count >= 16 {
            return false;
        }
        self.operations[self.operation_count] = operation_id;
        self.operation_count += 1;
        true
    }
}

// ============================================================================
// Role Definition
// ============================================================================

/// Role definition
#[derive(Clone, Copy)]
pub struct RoleDefinition {
    /// Role in use
    pub in_use: bool,
    /// Role name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub description_len: usize,
    /// Tasks included (by index)
    pub tasks: [u8; 16],
    /// Task count
    pub task_count: usize,
    /// Operations directly included (by ID)
    pub operations: [u32; 16],
    /// Operation count
    pub operation_count: usize,
    /// Nested roles (by index)
    pub nested_roles: [u8; 8],
    /// Nested role count
    pub nested_role_count: usize,
}

impl RoleDefinition {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            description: [0u8; MAX_DESC_LEN],
            description_len: 0,
            tasks: [0u8; 16],
            task_count: 0,
            operations: [0u32; 16],
            operation_count: 0,
            nested_roles: [0u8; 8],
            nested_role_count: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn add_task(&mut self, task_index: u8) -> bool {
        if self.task_count >= 16 {
            return false;
        }
        self.tasks[self.task_count] = task_index;
        self.task_count += 1;
        true
    }

    pub fn add_operation(&mut self, operation_id: u32) -> bool {
        if self.operation_count >= 16 {
            return false;
        }
        self.operations[self.operation_count] = operation_id;
        self.operation_count += 1;
        true
    }
}

// ============================================================================
// Role Assignment
// ============================================================================

/// Role assignment (assigns role to user/group)
#[derive(Clone, Copy)]
pub struct RoleAssignment {
    /// Assignment in use
    pub in_use: bool,
    /// Role index
    pub role_index: u8,
    /// Scope index (255 = application scope)
    pub scope_index: u8,
    /// Member type (0=user, 1=group, 2=application group)
    pub member_type: u8,
    /// Member SID or name
    pub member: [u8; 64],
    /// Member length
    pub member_len: usize,
}

impl RoleAssignment {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            role_index: 0,
            scope_index: 255,
            member_type: 0,
            member: [0u8; 64],
            member_len: 0,
        }
    }

    pub fn set_member(&mut self, member: &[u8]) {
        let len = member.len().min(64);
        self.member[..len].copy_from_slice(&member[..len]);
        self.member_len = len;
    }
}

// ============================================================================
// Scope
// ============================================================================

/// Authorization scope (subset of application)
#[derive(Clone, Copy)]
pub struct Scope {
    /// Scope in use
    pub in_use: bool,
    /// Scope name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub description_len: usize,
    /// Business rule enabled
    pub has_biz_rule: bool,
    /// Business rule language
    pub biz_rule_language: ScriptLanguage,
}

impl Scope {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            description: [0u8; MAX_DESC_LEN],
            description_len: 0,
            has_biz_rule: false,
            biz_rule_language: ScriptLanguage::VbScript,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

// ============================================================================
// Application
// ============================================================================

/// Authorization application
#[derive(Clone, Copy)]
pub struct AzApplication {
    /// Application in use
    pub in_use: bool,
    /// Application name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub description_len: usize,
    /// Version
    pub version: [u8; 32],
    /// Version length
    pub version_len: usize,
    /// Application flags
    pub flags: ApplicationFlags,
    /// Operations
    pub operations: [Operation; MAX_OPERATIONS],
    /// Operation count
    pub operation_count: usize,
    /// Next operation ID
    pub next_operation_id: u32,
    /// Tasks
    pub tasks: [Task; MAX_TASKS],
    /// Task count
    pub task_count: usize,
    /// Role definitions
    pub roles: [RoleDefinition; MAX_ROLES],
    /// Role count
    pub role_count: usize,
    /// Scopes
    pub scopes: [Scope; MAX_SCOPES],
    /// Scope count
    pub scope_count: usize,
    /// Role assignments
    pub assignments: [RoleAssignment; MAX_ASSIGNMENTS],
    /// Assignment count
    pub assignment_count: usize,
}

impl AzApplication {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            description: [0u8; MAX_DESC_LEN],
            description_len: 0,
            version: [0u8; 32],
            version_len: 0,
            flags: ApplicationFlags::ENABLED,
            operations: [const { Operation::new() }; MAX_OPERATIONS],
            operation_count: 0,
            next_operation_id: 1,
            tasks: [const { Task::new() }; MAX_TASKS],
            task_count: 0,
            roles: [const { RoleDefinition::new() }; MAX_ROLES],
            role_count: 0,
            scopes: [const { Scope::new() }; MAX_SCOPES],
            scope_count: 0,
            assignments: [const { RoleAssignment::new() }; MAX_ASSIGNMENTS],
            assignment_count: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Add an operation
    pub fn add_operation(&mut self, name: &[u8]) -> Option<u32> {
        if self.operation_count >= MAX_OPERATIONS {
            return None;
        }

        let op = &mut self.operations[self.operation_count];
        op.in_use = true;
        op.operation_id = self.next_operation_id;
        op.set_name(name);

        let id = self.next_operation_id;
        self.next_operation_id += 1;
        self.operation_count += 1;
        Some(id)
    }

    /// Add a task
    pub fn add_task(&mut self, name: &[u8]) -> Option<usize> {
        if self.task_count >= MAX_TASKS {
            return None;
        }

        let task = &mut self.tasks[self.task_count];
        task.in_use = true;
        task.set_name(name);

        let idx = self.task_count;
        self.task_count += 1;
        Some(idx)
    }

    /// Add a role definition
    pub fn add_role(&mut self, name: &[u8]) -> Option<usize> {
        if self.role_count >= MAX_ROLES {
            return None;
        }

        let role = &mut self.roles[self.role_count];
        role.in_use = true;
        role.set_name(name);

        let idx = self.role_count;
        self.role_count += 1;
        Some(idx)
    }

    /// Add a scope
    pub fn add_scope(&mut self, name: &[u8]) -> Option<usize> {
        if self.scope_count >= MAX_SCOPES {
            return None;
        }

        let scope = &mut self.scopes[self.scope_count];
        scope.in_use = true;
        scope.set_name(name);

        let idx = self.scope_count;
        self.scope_count += 1;
        Some(idx)
    }
}

// ============================================================================
// Authorization Store
// ============================================================================

/// Authorization store
#[derive(Clone, Copy)]
pub struct AzStore {
    /// Store in use
    pub in_use: bool,
    /// Store type
    pub store_type: StoreType,
    /// Store path/connection string
    pub path: [u8; 260],
    /// Path length
    pub path_len: usize,
    /// Store description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub description_len: usize,
    /// Store is writable
    pub writable: bool,
    /// Generate audits
    pub generate_audits: bool,
    /// Applications
    pub applications: [AzApplication; MAX_APPLICATIONS],
    /// Application count
    pub application_count: usize,
}

impl AzStore {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            store_type: StoreType::Xml,
            path: [0u8; 260],
            path_len: 0,
            description: [0u8; MAX_DESC_LEN],
            description_len: 0,
            writable: true,
            generate_audits: false,
            applications: [const { AzApplication::new() }; MAX_APPLICATIONS],
            application_count: 0,
        }
    }

    pub fn set_path(&mut self, path: &[u8]) {
        let len = path.len().min(260);
        self.path[..len].copy_from_slice(&path[..len]);
        self.path_len = len;
    }

    /// Add an application
    pub fn add_application(&mut self, name: &[u8]) -> Option<usize> {
        if self.application_count >= MAX_APPLICATIONS {
            return None;
        }

        let app = &mut self.applications[self.application_count];
        app.in_use = true;
        app.set_name(name);
        app.flags = ApplicationFlags::ENABLED;

        let idx = self.application_count;
        self.application_count += 1;
        Some(idx)
    }
}

// ============================================================================
// Manager State
// ============================================================================

/// Authorization Manager state
struct AzManagerState {
    /// Authorization stores
    stores: [AzStore; MAX_STORES],
    /// Store count
    store_count: usize,
    /// Selected store
    selected_store: Option<usize>,
    /// Selected application
    selected_app: Option<usize>,
    /// Dialog handle
    dialog_handle: HWND,
    /// Developer mode
    developer_mode: bool,
}

impl AzManagerState {
    pub const fn new() -> Self {
        Self {
            stores: [const { AzStore::new() }; MAX_STORES],
            store_count: 0,
            selected_store: None,
            selected_app: None,
            dialog_handle: UserHandle::from_raw(0),
            developer_mode: false,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static AZ_INITIALIZED: AtomicBool = AtomicBool::new(false);
static AZ_MANAGER: SpinLock<AzManagerState> = SpinLock::new(AzManagerState::new());

// Statistics
static STORE_COUNT: AtomicU32 = AtomicU32::new(0);
static APP_COUNT: AtomicU32 = AtomicU32::new(0);
static ACCESS_CHECK_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Authorization Manager
pub fn init() {
    if AZ_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }
    // No default stores - stores must be created or opened
}

// ============================================================================
// Store Management
// ============================================================================

/// Create a new authorization store
pub fn create_store(store_type: StoreType, path: &[u8]) -> Option<usize> {
    let mut state = AZ_MANAGER.lock();

    if state.store_count >= MAX_STORES {
        return None;
    }

    let idx = state.store_count;
    let store = &mut state.stores[idx];
    store.in_use = true;
    store.store_type = store_type;
    store.set_path(path);
    store.writable = true;

    state.store_count += 1;
    STORE_COUNT.fetch_add(1, Ordering::Relaxed);

    Some(idx)
}

/// Open an existing authorization store
pub fn open_store(store_type: StoreType, path: &[u8], writable: bool) -> Option<usize> {
    let mut state = AZ_MANAGER.lock();

    // Check if already open
    for (i, store) in state.stores.iter().enumerate() {
        if store.in_use && store.path[..store.path_len] == path[..path.len().min(store.path_len)] {
            return Some(i);
        }
    }

    if state.store_count >= MAX_STORES {
        return None;
    }

    let idx = state.store_count;
    let store = &mut state.stores[idx];
    store.in_use = true;
    store.store_type = store_type;
    store.set_path(path);
    store.writable = writable;

    state.store_count += 1;
    STORE_COUNT.fetch_add(1, Ordering::Relaxed);

    Some(idx)
}

/// Close an authorization store
pub fn close_store(index: usize) -> bool {
    let mut state = AZ_MANAGER.lock();

    if index >= MAX_STORES || !state.stores[index].in_use {
        return false;
    }

    let app_count = state.stores[index].application_count;
    state.stores[index] = AzStore::new();
    state.store_count = state.store_count.saturating_sub(1);

    STORE_COUNT.fetch_sub(1, Ordering::Relaxed);
    APP_COUNT.fetch_sub(app_count as u32, Ordering::Relaxed);

    true
}

/// Get store by index
pub fn get_store(index: usize) -> Option<AzStore> {
    let state = AZ_MANAGER.lock();
    if index < MAX_STORES && state.stores[index].in_use {
        Some(state.stores[index])
    } else {
        None
    }
}

// ============================================================================
// Application Management
// ============================================================================

/// Create an application in a store
pub fn create_application(store_index: usize, name: &[u8]) -> Option<usize> {
    let mut state = AZ_MANAGER.lock();

    if store_index >= MAX_STORES || !state.stores[store_index].in_use {
        return None;
    }

    if !state.stores[store_index].writable {
        return None;
    }

    let result = state.stores[store_index].add_application(name);
    if result.is_some() {
        APP_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// Delete an application
pub fn delete_application(store_index: usize, app_index: usize) -> bool {
    let mut state = AZ_MANAGER.lock();

    if store_index >= MAX_STORES || !state.stores[store_index].in_use {
        return false;
    }

    let store = &mut state.stores[store_index];
    if app_index >= store.application_count || !store.applications[app_index].in_use {
        return false;
    }

    store.applications[app_index] = AzApplication::new();
    APP_COUNT.fetch_sub(1, Ordering::Relaxed);

    true
}

/// Get application
pub fn get_application(store_index: usize, app_index: usize) -> Option<AzApplication> {
    let state = AZ_MANAGER.lock();

    if store_index >= MAX_STORES || !state.stores[store_index].in_use {
        return None;
    }

    let store = &state.stores[store_index];
    if app_index >= store.application_count || !store.applications[app_index].in_use {
        return None;
    }

    Some(store.applications[app_index])
}

// ============================================================================
// Operation Management
// ============================================================================

/// Add an operation to an application
pub fn add_operation(store_index: usize, app_index: usize, name: &[u8]) -> Option<u32> {
    let mut state = AZ_MANAGER.lock();

    if store_index >= MAX_STORES || !state.stores[store_index].in_use {
        return None;
    }

    let store = &mut state.stores[store_index];
    if app_index >= store.application_count || !store.applications[app_index].in_use {
        return None;
    }

    store.applications[app_index].add_operation(name)
}

/// Delete an operation
pub fn delete_operation(store_index: usize, app_index: usize, operation_id: u32) -> bool {
    let mut state = AZ_MANAGER.lock();

    if store_index >= MAX_STORES || !state.stores[store_index].in_use {
        return false;
    }

    let store = &mut state.stores[store_index];
    if app_index >= store.application_count || !store.applications[app_index].in_use {
        return false;
    }

    let app = &mut store.applications[app_index];
    for op in app.operations.iter_mut() {
        if op.in_use && op.operation_id == operation_id {
            *op = Operation::new();
            return true;
        }
    }
    false
}

// ============================================================================
// Task Management
// ============================================================================

/// Add a task to an application
pub fn add_task(store_index: usize, app_index: usize, name: &[u8]) -> Option<usize> {
    let mut state = AZ_MANAGER.lock();

    if store_index >= MAX_STORES || !state.stores[store_index].in_use {
        return None;
    }

    let store = &mut state.stores[store_index];
    if app_index >= store.application_count || !store.applications[app_index].in_use {
        return None;
    }

    store.applications[app_index].add_task(name)
}

/// Add operation to task
pub fn add_operation_to_task(
    store_index: usize,
    app_index: usize,
    task_index: usize,
    operation_id: u32,
) -> bool {
    let mut state = AZ_MANAGER.lock();

    if store_index >= MAX_STORES || !state.stores[store_index].in_use {
        return false;
    }

    let store = &mut state.stores[store_index];
    if app_index >= store.application_count || !store.applications[app_index].in_use {
        return false;
    }

    let app = &mut store.applications[app_index];
    if task_index >= app.task_count || !app.tasks[task_index].in_use {
        return false;
    }

    app.tasks[task_index].add_operation(operation_id)
}

// ============================================================================
// Role Management
// ============================================================================

/// Add a role definition to an application
pub fn add_role(store_index: usize, app_index: usize, name: &[u8]) -> Option<usize> {
    let mut state = AZ_MANAGER.lock();

    if store_index >= MAX_STORES || !state.stores[store_index].in_use {
        return None;
    }

    let store = &mut state.stores[store_index];
    if app_index >= store.application_count || !store.applications[app_index].in_use {
        return None;
    }

    store.applications[app_index].add_role(name)
}

/// Add task to role
pub fn add_task_to_role(
    store_index: usize,
    app_index: usize,
    role_index: usize,
    task_index: usize,
) -> bool {
    let mut state = AZ_MANAGER.lock();

    if store_index >= MAX_STORES || !state.stores[store_index].in_use {
        return false;
    }

    let store = &mut state.stores[store_index];
    if app_index >= store.application_count || !store.applications[app_index].in_use {
        return false;
    }

    let app = &mut store.applications[app_index];
    if role_index >= app.role_count || !app.roles[role_index].in_use {
        return false;
    }

    if task_index >= app.task_count {
        return false;
    }

    app.roles[role_index].add_task(task_index as u8)
}

// ============================================================================
// Role Assignment
// ============================================================================

/// Assign a role to a user/group
pub fn assign_role(
    store_index: usize,
    app_index: usize,
    role_index: usize,
    member: &[u8],
    member_type: u8,
    scope_index: Option<usize>,
) -> bool {
    let mut state = AZ_MANAGER.lock();

    if store_index >= MAX_STORES || !state.stores[store_index].in_use {
        return false;
    }

    let store = &mut state.stores[store_index];
    if app_index >= store.application_count || !store.applications[app_index].in_use {
        return false;
    }

    let app = &mut store.applications[app_index];
    if role_index >= app.role_count || !app.roles[role_index].in_use {
        return false;
    }

    if app.assignment_count >= MAX_ASSIGNMENTS {
        return false;
    }

    let assignment = &mut app.assignments[app.assignment_count];
    assignment.in_use = true;
    assignment.role_index = role_index as u8;
    assignment.scope_index = scope_index.map(|s| s as u8).unwrap_or(255);
    assignment.member_type = member_type;
    assignment.set_member(member);

    app.assignment_count += 1;
    true
}

/// Remove a role assignment
pub fn remove_role_assignment(
    store_index: usize,
    app_index: usize,
    assignment_index: usize,
) -> bool {
    let mut state = AZ_MANAGER.lock();

    if store_index >= MAX_STORES || !state.stores[store_index].in_use {
        return false;
    }

    let store = &mut state.stores[store_index];
    if app_index >= store.application_count || !store.applications[app_index].in_use {
        return false;
    }

    let app = &mut store.applications[app_index];
    if assignment_index >= app.assignment_count || !app.assignments[assignment_index].in_use {
        return false;
    }

    app.assignments[assignment_index] = RoleAssignment::new();
    true
}

// ============================================================================
// Access Check
// ============================================================================

/// Check if a user has access to perform an operation
pub fn access_check(
    store_index: usize,
    app_index: usize,
    member: &[u8],
    operation_id: u32,
    scope_name: Option<&[u8]>,
) -> bool {
    let state = AZ_MANAGER.lock();

    ACCESS_CHECK_COUNT.fetch_add(1, Ordering::Relaxed);

    if store_index >= MAX_STORES || !state.stores[store_index].in_use {
        return false;
    }

    let store = &state.stores[store_index];
    if app_index >= store.application_count || !store.applications[app_index].in_use {
        return false;
    }

    let app = &store.applications[app_index];

    // Find scope index if specified
    let target_scope = if let Some(name) = scope_name {
        let mut found = None;
        for (i, scope) in app.scopes.iter().enumerate() {
            if scope.in_use && scope.name[..scope.name_len] == name[..name.len().min(scope.name_len)] {
                found = Some(i as u8);
                break;
            }
        }
        found
    } else {
        None
    };

    // Check role assignments for this member
    for assignment in app.assignments.iter() {
        if !assignment.in_use {
            continue;
        }

        // Check if member matches
        if assignment.member[..assignment.member_len] != member[..member.len().min(assignment.member_len)] {
            continue;
        }

        // Check scope
        if let Some(scope_idx) = target_scope {
            if assignment.scope_index != 255 && assignment.scope_index != scope_idx {
                continue;
            }
        }

        // Get the role
        let role_idx = assignment.role_index as usize;
        if role_idx >= app.role_count || !app.roles[role_idx].in_use {
            continue;
        }

        let role = &app.roles[role_idx];

        // Check if operation is directly in role
        for i in 0..role.operation_count {
            if role.operations[i] == operation_id {
                return true;
            }
        }

        // Check tasks in role
        for i in 0..role.task_count {
            let task_idx = role.tasks[i] as usize;
            if task_idx < app.task_count && app.tasks[task_idx].in_use {
                let task = &app.tasks[task_idx];
                for j in 0..task.operation_count {
                    if task.operations[j] == operation_id {
                        return true;
                    }
                }
            }
        }
    }

    false
}

// ============================================================================
// Scope Management
// ============================================================================

/// Add a scope to an application
pub fn add_scope(store_index: usize, app_index: usize, name: &[u8]) -> Option<usize> {
    let mut state = AZ_MANAGER.lock();

    if store_index >= MAX_STORES || !state.stores[store_index].in_use {
        return None;
    }

    let store = &mut state.stores[store_index];
    if app_index >= store.application_count || !store.applications[app_index].in_use {
        return None;
    }

    store.applications[app_index].add_scope(name)
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_statistics() -> (u32, u32, u32) {
    (
        STORE_COUNT.load(Ordering::Relaxed),
        APP_COUNT.load(Ordering::Relaxed),
        ACCESS_CHECK_COUNT.load(Ordering::Relaxed),
    )
}

// ============================================================================
// Dialog Functions
// ============================================================================

/// Show Authorization Manager main window
pub fn show_dialog(_parent: HWND) -> HWND {
    let mut state = AZ_MANAGER.lock();
    let handle = UserHandle::from_raw(0xA201);
    state.dialog_handle = handle;
    handle
}

/// Show new store wizard
pub fn show_new_store_wizard() -> HWND {
    UserHandle::from_raw(0xA202)
}

/// Show open store dialog
pub fn show_open_store_dialog() -> HWND {
    UserHandle::from_raw(0xA203)
}

/// Show store properties
pub fn show_store_properties(_store_index: usize) -> HWND {
    UserHandle::from_raw(0xA204)
}

/// Show new application wizard
pub fn show_new_application_wizard() -> HWND {
    UserHandle::from_raw(0xA205)
}

/// Show application properties
pub fn show_application_properties(_store_index: usize, _app_index: usize) -> HWND {
    UserHandle::from_raw(0xA206)
}

/// Show new operation dialog
pub fn show_new_operation_dialog() -> HWND {
    UserHandle::from_raw(0xA207)
}

/// Show new task dialog
pub fn show_new_task_dialog() -> HWND {
    UserHandle::from_raw(0xA208)
}

/// Show new role dialog
pub fn show_new_role_dialog() -> HWND {
    UserHandle::from_raw(0xA209)
}

/// Show role assignment dialog
pub fn show_role_assignment_dialog() -> HWND {
    UserHandle::from_raw(0xA20A)
}

/// Toggle developer mode
pub fn set_developer_mode(enabled: bool) {
    let mut state = AZ_MANAGER.lock();
    state.developer_mode = enabled;
}

/// Get developer mode status
pub fn is_developer_mode() -> bool {
    AZ_MANAGER.lock().developer_mode
}

/// Close dialog
pub fn close_dialog() {
    let mut state = AZ_MANAGER.lock();
    state.dialog_handle = UserHandle::from_raw(0);
}
