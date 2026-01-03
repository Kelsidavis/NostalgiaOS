//! Windows Management Instrumentation (WMI)
//!
//! WMI provides a uniform interface for accessing management information:
//!
//! - **CIM Repository**: Stores class definitions and instances
//! - **Providers**: Supply management data and handle operations
//! - **Namespaces**: Organize classes hierarchically
//! - **Query Language**: WQL for querying management data
//! - **Events**: Subscription-based event notifications
//!
//! # Architecture
//!
//! - WMI Service (winmgmt): Core WMI service
//! - CIM Object Manager (CIMOM): Manages the CIM repository
//! - Providers: Supply data (Win32 provider, WDM provider, etc.)
//!
//! # Key Namespaces
//!
//! - `root\cimv2`: Standard Windows classes (Win32_*)
//! - `root\default`: Default namespace
//! - `root\security`: Security classes
//! - `root\wmi`: WDM/ETW classes

extern crate alloc;

use crate::ke::SpinLock;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum WMI namespaces
pub const MAX_NAMESPACES: usize = 4;

/// Maximum WMI classes per namespace
pub const MAX_CLASSES: usize = 16;

/// Maximum WMI providers
pub const MAX_PROVIDERS: usize = 8;

/// Maximum WMI instances
pub const MAX_INSTANCES: usize = 32;

/// Maximum properties per class
pub const MAX_PROPERTIES: usize = 8;

/// Maximum event subscriptions
pub const MAX_SUBSCRIPTIONS: usize = 8;

/// Maximum name length
pub const MAX_NAME: usize = 64;

/// Maximum value length
pub const MAX_VALUE: usize = 64;

// ============================================================================
// Types
// ============================================================================

/// WMI data types (CIM types)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CimType {
    /// Signed 8-bit integer
    Sint8 = 16,
    /// Unsigned 8-bit integer
    Uint8 = 17,
    /// Signed 16-bit integer
    Sint16 = 2,
    /// Unsigned 16-bit integer
    Uint16 = 18,
    /// Signed 32-bit integer
    Sint32 = 3,
    /// Unsigned 32-bit integer
    Uint32 = 19,
    /// Signed 64-bit integer
    Sint64 = 20,
    /// Unsigned 64-bit integer
    Uint64 = 21,
    /// 32-bit float
    Real32 = 4,
    /// 64-bit float
    Real64 = 5,
    /// Boolean
    Boolean = 11,
    /// String
    String = 8,
    /// DateTime
    DateTime = 101,
    /// Reference (object path)
    Reference = 102,
    /// Object (embedded)
    Object = 13,
}

impl Default for CimType {
    fn default() -> Self {
        Self::String
    }
}

/// Property qualifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct PropertyQualifiers(pub u32);

impl PropertyQualifiers {
    pub const NONE: u32 = 0;
    pub const KEY: u32 = 0x0001;
    pub const READ: u32 = 0x0002;
    pub const WRITE: u32 = 0x0004;
    pub const INDEXED: u32 = 0x0008;
    pub const NOT_NULL: u32 = 0x0010;

    pub fn is_key(&self) -> bool {
        (self.0 & Self::KEY) != 0
    }

    pub fn is_read(&self) -> bool {
        (self.0 & Self::READ) != 0
    }

    pub fn is_write(&self) -> bool {
        (self.0 & Self::WRITE) != 0
    }
}

/// WMI error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WmiError {
    /// Success
    Ok = 0,
    /// Service not running
    NotRunning = 1,
    /// Namespace not found
    NamespaceNotFound = 2,
    /// Class not found
    ClassNotFound = 3,
    /// Instance not found
    InstanceNotFound = 4,
    /// Provider not found
    ProviderNotFound = 5,
    /// Invalid query
    InvalidQuery = 6,
    /// Access denied
    AccessDenied = 7,
    /// Out of memory
    OutOfMemory = 8,
    /// Invalid parameter
    InvalidParameter = 9,
    /// Provider failure
    ProviderFailure = 10,
    /// Already exists
    AlreadyExists = 11,
    /// Not supported
    NotSupported = 12,
}

// ============================================================================
// Property
// ============================================================================

/// A WMI class property
#[derive(Clone)]
pub struct WmiProperty {
    /// Property is valid
    pub valid: bool,
    /// Property name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Data type
    pub cim_type: CimType,
    /// Qualifiers
    pub qualifiers: PropertyQualifiers,
    /// Is array
    pub is_array: bool,
}

impl WmiProperty {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            name: [0; MAX_NAME],
            name_len: 0,
            cim_type: CimType::String,
            qualifiers: PropertyQualifiers(0),
            is_array: false,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name_len = len;
    }
}

// ============================================================================
// Class
// ============================================================================

/// A WMI class definition
#[derive(Clone)]
pub struct WmiClass {
    /// Class is valid
    pub valid: bool,
    /// Class name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Parent class name
    pub parent: [u8; MAX_NAME],
    /// Parent name length
    pub parent_len: usize,
    /// Namespace index
    pub namespace_idx: usize,
    /// Properties
    pub properties: [WmiProperty; MAX_PROPERTIES],
    /// Property count
    pub property_count: usize,
    /// Is abstract
    pub is_abstract: bool,
    /// Is dynamic (provider-supplied)
    pub is_dynamic: bool,
    /// Provider index (if dynamic)
    pub provider_idx: Option<usize>,
}

impl WmiClass {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            name: [0; MAX_NAME],
            name_len: 0,
            parent: [0; MAX_NAME],
            parent_len: 0,
            namespace_idx: 0,
            properties: [const { WmiProperty::empty() }; MAX_PROPERTIES],
            property_count: 0,
            is_abstract: false,
            is_dynamic: false,
            provider_idx: None,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name_len = len;
    }

    pub fn parent_str(&self) -> &str {
        core::str::from_utf8(&self.parent[..self.parent_len]).unwrap_or("")
    }

    pub fn set_parent(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_NAME);
        self.parent[..len].copy_from_slice(&bytes[..len]);
        self.parent_len = len;
    }

    pub fn add_property(&mut self, name: &str, cim_type: CimType, qualifiers: PropertyQualifiers) -> bool {
        if self.property_count >= MAX_PROPERTIES {
            return false;
        }
        let idx = self.property_count;
        self.properties[idx].valid = true;
        self.properties[idx].set_name(name);
        self.properties[idx].cim_type = cim_type;
        self.properties[idx].qualifiers = qualifiers;
        self.properties[idx].is_array = false;
        self.property_count += 1;
        true
    }
}

// ============================================================================
// Instance
// ============================================================================

/// A property value
#[derive(Clone)]
pub struct PropertyValue {
    /// Value is set
    pub valid: bool,
    /// Property index
    pub property_idx: usize,
    /// String value
    pub str_value: [u8; MAX_VALUE],
    /// String length
    pub str_len: usize,
    /// Integer value
    pub int_value: i64,
    /// Boolean value
    pub bool_value: bool,
}

impl PropertyValue {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            property_idx: 0,
            str_value: [0; MAX_VALUE],
            str_len: 0,
            int_value: 0,
            bool_value: false,
        }
    }

    pub fn str_value_str(&self) -> &str {
        core::str::from_utf8(&self.str_value[..self.str_len]).unwrap_or("")
    }

    pub fn set_str_value(&mut self, val: &str) {
        let bytes = val.as_bytes();
        let len = bytes.len().min(MAX_VALUE);
        self.str_value[..len].copy_from_slice(&bytes[..len]);
        self.str_len = len;
    }
}

/// A WMI instance
#[derive(Clone)]
pub struct WmiInstance {
    /// Instance is valid
    pub valid: bool,
    /// Class index
    pub class_idx: usize,
    /// Instance path/key
    pub path: [u8; MAX_VALUE],
    /// Path length
    pub path_len: usize,
    /// Property values
    pub values: [PropertyValue; MAX_PROPERTIES],
    /// Value count
    pub value_count: usize,
}

impl WmiInstance {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            class_idx: 0,
            path: [0; MAX_VALUE],
            path_len: 0,
            values: [const { PropertyValue::empty() }; MAX_PROPERTIES],
            value_count: 0,
        }
    }

    pub fn path_str(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }

    pub fn set_path(&mut self, path: &str) {
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_VALUE);
        self.path[..len].copy_from_slice(&bytes[..len]);
        self.path_len = len;
    }
}

// ============================================================================
// Namespace
// ============================================================================

/// A WMI namespace
#[derive(Clone)]
pub struct WmiNamespace {
    /// Namespace is valid
    pub valid: bool,
    /// Namespace path (e.g., "root\cimv2")
    pub path: [u8; MAX_NAME],
    /// Path length
    pub path_len: usize,
    /// Parent namespace index (None for root)
    pub parent_idx: Option<usize>,
    /// Class count in this namespace
    pub class_count: usize,
}

impl WmiNamespace {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            path: [0; MAX_NAME],
            path_len: 0,
            parent_idx: None,
            class_count: 0,
        }
    }

    pub fn path_str(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }

    pub fn set_path(&mut self, path: &str) {
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_NAME);
        self.path[..len].copy_from_slice(&bytes[..len]);
        self.path_len = len;
    }
}

// ============================================================================
// Provider
// ============================================================================

/// A WMI provider
#[derive(Clone)]
pub struct WmiProvider {
    /// Provider is valid
    pub valid: bool,
    /// Provider name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// CLSID
    pub clsid: [u8; 38],
    /// Is instance provider
    pub is_instance_provider: bool,
    /// Is method provider
    pub is_method_provider: bool,
    /// Is event provider
    pub is_event_provider: bool,
    /// Is property provider
    pub is_property_provider: bool,
    /// Registration time
    pub registered_at: i64,
    /// Query count
    pub query_count: u64,
}

impl WmiProvider {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            name: [0; MAX_NAME],
            name_len: 0,
            clsid: [0; 38],
            is_instance_provider: false,
            is_method_provider: false,
            is_event_provider: false,
            is_property_provider: false,
            registered_at: 0,
            query_count: 0,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name_len = len;
    }
}

// ============================================================================
// Event Subscription
// ============================================================================

/// An event subscription
#[derive(Clone)]
pub struct EventSubscription {
    /// Subscription is valid
    pub valid: bool,
    /// Subscription ID
    pub id: u32,
    /// Query (WQL)
    pub query: [u8; MAX_VALUE],
    /// Query length
    pub query_len: usize,
    /// Namespace index
    pub namespace_idx: usize,
    /// Created at
    pub created_at: i64,
    /// Events delivered
    pub events_delivered: u64,
}

impl EventSubscription {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            id: 0,
            query: [0; MAX_VALUE],
            query_len: 0,
            namespace_idx: 0,
            created_at: 0,
            events_delivered: 0,
        }
    }
}

// ============================================================================
// Service State
// ============================================================================

/// WMI service state
struct WmiState {
    /// Service running
    running: bool,
    /// Namespaces
    namespaces: [WmiNamespace; MAX_NAMESPACES],
    /// Namespace count
    namespace_count: usize,
    /// Classes
    classes: [WmiClass; MAX_CLASSES],
    /// Class count
    class_count: usize,
    /// Instances
    instances: [WmiInstance; MAX_INSTANCES],
    /// Instance count
    instance_count: usize,
    /// Providers
    providers: [WmiProvider; MAX_PROVIDERS],
    /// Provider count
    provider_count: usize,
    /// Event subscriptions
    subscriptions: [EventSubscription; MAX_SUBSCRIPTIONS],
    /// Subscription count
    subscription_count: usize,
    /// Next subscription ID
    next_sub_id: u32,
}

impl WmiState {
    const fn new() -> Self {
        Self {
            running: false,
            namespaces: [const { WmiNamespace::empty() }; MAX_NAMESPACES],
            namespace_count: 0,
            classes: [const { WmiClass::empty() }; MAX_CLASSES],
            class_count: 0,
            instances: [const { WmiInstance::empty() }; MAX_INSTANCES],
            instance_count: 0,
            providers: [const { WmiProvider::empty() }; MAX_PROVIDERS],
            provider_count: 0,
            subscriptions: [const { EventSubscription::empty() }; MAX_SUBSCRIPTIONS],
            subscription_count: 0,
            next_sub_id: 1,
        }
    }
}

static WMI_STATE: SpinLock<WmiState> = SpinLock::new(WmiState::new());

/// Statistics
struct WmiStats {
    /// Queries executed
    queries: AtomicU64,
    /// Successful queries
    successful_queries: AtomicU64,
    /// Failed queries
    failed_queries: AtomicU64,
    /// Instances enumerated
    instances_enumerated: AtomicU64,
    /// Methods executed
    methods_executed: AtomicU64,
    /// Events delivered
    events_delivered: AtomicU64,
    /// Provider calls
    provider_calls: AtomicU64,
}

impl WmiStats {
    const fn new() -> Self {
        Self {
            queries: AtomicU64::new(0),
            successful_queries: AtomicU64::new(0),
            failed_queries: AtomicU64::new(0),
            instances_enumerated: AtomicU64::new(0),
            methods_executed: AtomicU64::new(0),
            events_delivered: AtomicU64::new(0),
            provider_calls: AtomicU64::new(0),
        }
    }
}

static WMI_STATS: WmiStats = WmiStats::new();

// ============================================================================
// Namespace Management
// ============================================================================

/// Create a namespace
pub fn create_namespace(path: &str, parent_idx: Option<usize>) -> Result<usize, WmiError> {
    let mut state = WMI_STATE.lock();

    if !state.running {
        return Err(WmiError::NotRunning);
    }

    // Check for duplicate
    for i in 0..MAX_NAMESPACES {
        if state.namespaces[i].valid && state.namespaces[i].path_str().eq_ignore_ascii_case(path) {
            return Ok(i);
        }
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_NAMESPACES {
        if !state.namespaces[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(WmiError::OutOfMemory),
    };

    let ns = &mut state.namespaces[slot];
    ns.valid = true;
    ns.set_path(path);
    ns.parent_idx = parent_idx;
    ns.class_count = 0;

    state.namespace_count += 1;

    crate::serial_println!("[WMI] Created namespace '{}'", path);

    Ok(slot)
}

/// Find namespace by path
pub fn find_namespace(path: &str) -> Option<usize> {
    let state = WMI_STATE.lock();

    for i in 0..MAX_NAMESPACES {
        if state.namespaces[i].valid && state.namespaces[i].path_str().eq_ignore_ascii_case(path) {
            return Some(i);
        }
    }

    None
}

/// Get namespace count
pub fn get_namespace_count() -> usize {
    let state = WMI_STATE.lock();
    state.namespace_count
}

// ============================================================================
// Class Management
// ============================================================================

/// Create a class
pub fn create_class(
    namespace_idx: usize,
    name: &str,
    parent: Option<&str>,
) -> Result<usize, WmiError> {
    let mut state = WMI_STATE.lock();

    if !state.running {
        return Err(WmiError::NotRunning);
    }

    if namespace_idx >= MAX_NAMESPACES || !state.namespaces[namespace_idx].valid {
        return Err(WmiError::NamespaceNotFound);
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_CLASSES {
        if !state.classes[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(WmiError::OutOfMemory),
    };

    let class = &mut state.classes[slot];
    class.valid = true;
    class.set_name(name);
    if let Some(p) = parent {
        class.set_parent(p);
    }
    class.namespace_idx = namespace_idx;
    class.property_count = 0;
    class.is_abstract = false;
    class.is_dynamic = false;
    class.provider_idx = None;

    state.class_count += 1;
    state.namespaces[namespace_idx].class_count += 1;

    Ok(slot)
}

/// Find class by name in namespace
pub fn find_class(namespace_idx: usize, name: &str) -> Option<usize> {
    let state = WMI_STATE.lock();

    for i in 0..MAX_CLASSES {
        if state.classes[i].valid
            && state.classes[i].namespace_idx == namespace_idx
            && state.classes[i].name_str().eq_ignore_ascii_case(name)
        {
            return Some(i);
        }
    }

    None
}

/// Add property to class
pub fn add_class_property(
    class_idx: usize,
    name: &str,
    cim_type: CimType,
    qualifiers: PropertyQualifiers,
) -> Result<(), WmiError> {
    let mut state = WMI_STATE.lock();

    if class_idx >= MAX_CLASSES || !state.classes[class_idx].valid {
        return Err(WmiError::ClassNotFound);
    }

    if !state.classes[class_idx].add_property(name, cim_type, qualifiers) {
        return Err(WmiError::OutOfMemory);
    }

    Ok(())
}

/// Get class count
pub fn get_class_count() -> usize {
    let state = WMI_STATE.lock();
    state.class_count
}

// ============================================================================
// Instance Management
// ============================================================================

/// Create an instance
pub fn create_instance(class_idx: usize, path: &str) -> Result<usize, WmiError> {
    let mut state = WMI_STATE.lock();

    if !state.running {
        return Err(WmiError::NotRunning);
    }

    if class_idx >= MAX_CLASSES || !state.classes[class_idx].valid {
        return Err(WmiError::ClassNotFound);
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_INSTANCES {
        if !state.instances[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(WmiError::OutOfMemory),
    };

    let instance = &mut state.instances[slot];
    instance.valid = true;
    instance.class_idx = class_idx;
    instance.set_path(path);
    instance.value_count = 0;

    state.instance_count += 1;

    Ok(slot)
}

/// Set instance property value (string)
pub fn set_instance_string(
    instance_idx: usize,
    property_name: &str,
    value: &str,
) -> Result<(), WmiError> {
    let mut state = WMI_STATE.lock();

    if instance_idx >= MAX_INSTANCES || !state.instances[instance_idx].valid {
        return Err(WmiError::InstanceNotFound);
    }

    let class_idx = state.instances[instance_idx].class_idx;

    // Find property in class
    let mut prop_idx = None;
    for i in 0..state.classes[class_idx].property_count {
        if state.classes[class_idx].properties[i].name_str().eq_ignore_ascii_case(property_name) {
            prop_idx = Some(i);
            break;
        }
    }

    let prop_idx = match prop_idx {
        Some(i) => i,
        None => return Err(WmiError::InvalidParameter),
    };

    // Find or create value slot
    let value_count = state.instances[instance_idx].value_count;
    let mut val_slot = None;
    for i in 0..value_count {
        if state.instances[instance_idx].values[i].property_idx == prop_idx {
            val_slot = Some(i);
            break;
        }
    }

    let val_slot = match val_slot {
        Some(i) => i,
        None => {
            if value_count >= MAX_PROPERTIES {
                return Err(WmiError::OutOfMemory);
            }
            state.instances[instance_idx].value_count += 1;
            value_count
        }
    };

    let val = &mut state.instances[instance_idx].values[val_slot];
    val.valid = true;
    val.property_idx = prop_idx;
    val.set_str_value(value);

    Ok(())
}

/// Set instance property value (integer)
pub fn set_instance_int(
    instance_idx: usize,
    property_name: &str,
    value: i64,
) -> Result<(), WmiError> {
    let mut state = WMI_STATE.lock();

    if instance_idx >= MAX_INSTANCES || !state.instances[instance_idx].valid {
        return Err(WmiError::InstanceNotFound);
    }

    let class_idx = state.instances[instance_idx].class_idx;

    // Find property in class
    let mut prop_idx = None;
    for i in 0..state.classes[class_idx].property_count {
        if state.classes[class_idx].properties[i].name_str().eq_ignore_ascii_case(property_name) {
            prop_idx = Some(i);
            break;
        }
    }

    let prop_idx = match prop_idx {
        Some(i) => i,
        None => return Err(WmiError::InvalidParameter),
    };

    let value_count = state.instances[instance_idx].value_count;
    let mut val_slot = None;
    for i in 0..value_count {
        if state.instances[instance_idx].values[i].property_idx == prop_idx {
            val_slot = Some(i);
            break;
        }
    }

    let val_slot = match val_slot {
        Some(i) => i,
        None => {
            if value_count >= MAX_PROPERTIES {
                return Err(WmiError::OutOfMemory);
            }
            state.instances[instance_idx].value_count += 1;
            value_count
        }
    };

    let val = &mut state.instances[instance_idx].values[val_slot];
    val.valid = true;
    val.property_idx = prop_idx;
    val.int_value = value;

    Ok(())
}

/// Get instance count
pub fn get_instance_count() -> usize {
    let state = WMI_STATE.lock();
    state.instance_count
}

/// Enumerate instances of a class
pub fn enumerate_instances(class_idx: usize) -> usize {
    let state = WMI_STATE.lock();
    let mut count = 0;

    for i in 0..MAX_INSTANCES {
        if state.instances[i].valid && state.instances[i].class_idx == class_idx {
            count += 1;
        }
    }

    WMI_STATS.instances_enumerated.fetch_add(count as u64, Ordering::Relaxed);

    count
}

// ============================================================================
// Provider Management
// ============================================================================

/// Register a provider
pub fn register_provider(
    name: &str,
    is_instance: bool,
    is_method: bool,
    is_event: bool,
) -> Result<usize, WmiError> {
    let mut state = WMI_STATE.lock();

    if !state.running {
        return Err(WmiError::NotRunning);
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_PROVIDERS {
        if !state.providers[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(WmiError::OutOfMemory),
    };

    let provider = &mut state.providers[slot];
    provider.valid = true;
    provider.set_name(name);
    provider.is_instance_provider = is_instance;
    provider.is_method_provider = is_method;
    provider.is_event_provider = is_event;
    provider.is_property_provider = false;
    provider.registered_at = crate::rtl::time::rtl_get_system_time();
    provider.query_count = 0;

    state.provider_count += 1;

    crate::serial_println!("[WMI] Registered provider '{}'", name);

    Ok(slot)
}

/// Get provider count
pub fn get_provider_count() -> usize {
    let state = WMI_STATE.lock();
    state.provider_count
}

// ============================================================================
// Query Execution
// ============================================================================

/// Execute a WQL query (simplified)
pub fn execute_query(namespace_path: &str, query: &str) -> Result<usize, WmiError> {
    WMI_STATS.queries.fetch_add(1, Ordering::Relaxed);

    let namespace_idx = match find_namespace(namespace_path) {
        Some(i) => i,
        None => {
            WMI_STATS.failed_queries.fetch_add(1, Ordering::Relaxed);
            return Err(WmiError::NamespaceNotFound);
        }
    };

    // Simple query parsing - just extract class name from "SELECT * FROM ClassName"
    let query_upper = query.to_ascii_uppercase();
    if !query_upper.contains("SELECT") || !query_upper.contains("FROM") {
        WMI_STATS.failed_queries.fetch_add(1, Ordering::Relaxed);
        return Err(WmiError::InvalidQuery);
    }

    // For now, return instance count as result
    let state = WMI_STATE.lock();
    let mut count = 0;

    for i in 0..MAX_INSTANCES {
        if state.instances[i].valid {
            let class_idx = state.instances[i].class_idx;
            if state.classes[class_idx].namespace_idx == namespace_idx {
                count += 1;
            }
        }
    }

    WMI_STATS.successful_queries.fetch_add(1, Ordering::Relaxed);
    WMI_STATS.instances_enumerated.fetch_add(count as u64, Ordering::Relaxed);

    Ok(count)
}

// ============================================================================
// Statistics
// ============================================================================

/// Get WMI statistics
pub fn get_statistics() -> (u64, u64, u64, u64, u64, u64, u64) {
    (
        WMI_STATS.queries.load(Ordering::Relaxed),
        WMI_STATS.successful_queries.load(Ordering::Relaxed),
        WMI_STATS.failed_queries.load(Ordering::Relaxed),
        WMI_STATS.instances_enumerated.load(Ordering::Relaxed),
        WMI_STATS.methods_executed.load(Ordering::Relaxed),
        WMI_STATS.events_delivered.load(Ordering::Relaxed),
        WMI_STATS.provider_calls.load(Ordering::Relaxed),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = WMI_STATE.lock();
    state.running
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialized flag
static WMI_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize WMI service
pub fn init() {
    if WMI_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[WMI] Initializing Windows Management Instrumentation...");

    {
        let mut state = WMI_STATE.lock();
        state.running = true;
    }

    // Create default namespaces
    let root_idx = create_namespace("root", None).unwrap_or(0);
    let _ = create_namespace("root\\default", Some(root_idx));
    let cimv2_idx = create_namespace("root\\cimv2", Some(root_idx)).unwrap_or(0);
    let _ = create_namespace("root\\security", Some(root_idx));
    let _ = create_namespace("root\\wmi", Some(root_idx));

    // Register default providers
    let _ = register_provider("CIMWin32", true, true, false);
    let _ = register_provider("WDMProvider", true, false, true);
    let _ = register_provider("SecurityProvider", true, false, false);

    // Create some basic Win32 classes
    if let Ok(class_idx) = create_class(cimv2_idx, "Win32_OperatingSystem", None) {
        let _ = add_class_property(class_idx, "Name", CimType::String,
            PropertyQualifiers(PropertyQualifiers::KEY | PropertyQualifiers::READ));
        let _ = add_class_property(class_idx, "Version", CimType::String,
            PropertyQualifiers(PropertyQualifiers::READ));
        let _ = add_class_property(class_idx, "BuildNumber", CimType::String,
            PropertyQualifiers(PropertyQualifiers::READ));
        let _ = add_class_property(class_idx, "Manufacturer", CimType::String,
            PropertyQualifiers(PropertyQualifiers::READ));

        // Create instance
        if let Ok(inst_idx) = create_instance(class_idx, "Win32_OperatingSystem.Name=\"NostalgiaOS\"") {
            let _ = set_instance_string(inst_idx, "Name", "NostalgiaOS");
            let _ = set_instance_string(inst_idx, "Version", "5.2.3790");
            let _ = set_instance_string(inst_idx, "BuildNumber", "3790");
            let _ = set_instance_string(inst_idx, "Manufacturer", "Nostalgia Project");
        }
    }

    if let Ok(class_idx) = create_class(cimv2_idx, "Win32_ComputerSystem", None) {
        let _ = add_class_property(class_idx, "Name", CimType::String,
            PropertyQualifiers(PropertyQualifiers::KEY | PropertyQualifiers::READ));
        let _ = add_class_property(class_idx, "Domain", CimType::String,
            PropertyQualifiers(PropertyQualifiers::READ));
        let _ = add_class_property(class_idx, "TotalPhysicalMemory", CimType::Uint64,
            PropertyQualifiers(PropertyQualifiers::READ));

        if let Ok(inst_idx) = create_instance(class_idx, "Win32_ComputerSystem.Name=\"NOSTALGIAOS\"") {
            let _ = set_instance_string(inst_idx, "Name", "NOSTALGIAOS");
            let _ = set_instance_string(inst_idx, "Domain", "WORKGROUP");
            let _ = set_instance_int(inst_idx, "TotalPhysicalMemory", 536870912); // 512MB
        }
    }

    if let Ok(class_idx) = create_class(cimv2_idx, "Win32_Processor", None) {
        let _ = add_class_property(class_idx, "DeviceID", CimType::String,
            PropertyQualifiers(PropertyQualifiers::KEY | PropertyQualifiers::READ));
        let _ = add_class_property(class_idx, "Name", CimType::String,
            PropertyQualifiers(PropertyQualifiers::READ));
        let _ = add_class_property(class_idx, "NumberOfCores", CimType::Uint32,
            PropertyQualifiers(PropertyQualifiers::READ));
    }

    crate::serial_println!("[WMI] Windows Management Instrumentation initialized");
    crate::serial_println!("[WMI]   Namespaces: 5");
    crate::serial_println!("[WMI]   Providers: 3");
    crate::serial_println!("[WMI]   Classes: 3");
}
