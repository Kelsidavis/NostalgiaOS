//! Windows Management Instrumentation (WMI) Kernel Infrastructure
//!
//! WMI provides a standardized interface for:
//! - Querying system and device configuration
//! - Setting system and device parameters
//! - Receiving system events
//! - Managing devices through MOF (Managed Object Format) schemas
//!
//! # Architecture
//!
//! ```text
//! User Mode                Kernel Mode
//! ┌─────────────┐         ┌─────────────────────────────┐
//! │ WMI Service │ <-----> │    WMI Kernel Interface     │
//! └─────────────┘         ├─────────────────────────────┤
//!                         │  Data Block Registration    │
//!                         │  IRP_MJ_SYSTEM_CONTROL      │
//!                         ├─────────────────────────────┤
//!                         │    WMI Providers            │
//!                         │  (Driver-specific blocks)   │
//!                         └─────────────────────────────┘
//! ```
//!
//! Based on Windows Server 2003 base/ntos/wmi/

pub mod data;
pub mod irp;
pub mod provider;

pub use data::*;
pub use irp::*;
pub use provider::*;

use crate::etw::Guid;
use crate::ke::SpinLock;
use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

extern crate alloc;

// ============================================================================
// WMI Registration Action Constants (from wmi.c)
// ============================================================================

/// Register device for WMI
pub const WMIREG_ACTION_REGISTER: u32 = 1;
/// Deregister device from WMI
pub const WMIREG_ACTION_DEREGISTER: u32 = 2;
/// Re-register (deregister then register)
pub const WMIREG_ACTION_REREGISTER: u32 = 3;
/// Update GUIDs for device
pub const WMIREG_ACTION_UPDATE_GUIDS: u32 = 4;
/// Block IRPs for device
pub const WMIREG_ACTION_BLOCK_IRPS: u32 = 5;

/// Callback registration flag
pub const WMIREG_FLAG_CALLBACK: u32 = 0x80000000;
/// Trace provider flag
pub const WMIREG_FLAG_TRACE_PROVIDER: u32 = 0x00010000;
/// Expensive data collection
pub const WMIREG_FLAG_EXPENSIVE: u32 = 0x00000001;
/// Instance list provided
pub const WMIREG_FLAG_INSTANCE_LIST: u32 = 0x00000004;
/// Instance base name provided
pub const WMIREG_FLAG_INSTANCE_BASENAME: u32 = 0x00000008;
/// PDO instance names
pub const WMIREG_FLAG_INSTANCE_PDO: u32 = 0x00000020;
/// Event-only GUID
pub const WMIREG_FLAG_EVENT_ONLY_GUID: u32 = 0x00000040;
/// Remove GUID from registration
pub const WMIREG_FLAG_REMOVE_GUID: u32 = 0x00010000;

/// Maximum event size (64KB default)
pub const DEFAULT_MAX_WNODE_EVENT_SIZE: u32 = 0x10000;

/// WMI initialized flag
static WMI_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Next provider ID
static NEXT_PROVIDER_ID: AtomicU32 = AtomicU32::new(1);

// ============================================================================
// WMI Event Notification (from notify.c)
// ============================================================================

/// WMI event entry for notification queue
#[derive(Clone)]
pub struct WmiEventEntry {
    /// Event GUID
    pub guid: Guid,
    /// Provider ID
    pub provider_id: u32,
    /// Event data size
    pub data_size: u32,
    /// Event timestamp
    pub timestamp: u64,
    /// Instance index
    pub instance_index: u32,
    /// Event flags
    pub flags: u32,
}

/// Maximum pending events
const MAX_PENDING_EVENTS: usize = 256;

/// WMI runtime statistics
pub struct WmiRuntimeStats {
    /// Total queries performed
    pub total_queries: AtomicU64,
    /// Total sets performed
    pub total_sets: AtomicU64,
    /// Total methods executed
    pub total_methods: AtomicU64,
    /// Total events fired
    pub total_events: AtomicU64,
    /// Total events dropped (queue full)
    pub events_dropped: AtomicU64,
    /// Total registrations
    pub total_registrations: AtomicU64,
    /// Total deregistrations
    pub total_deregistrations: AtomicU64,
}

impl WmiRuntimeStats {
    pub const fn new() -> Self {
        Self {
            total_queries: AtomicU64::new(0),
            total_sets: AtomicU64::new(0),
            total_methods: AtomicU64::new(0),
            total_events: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            total_registrations: AtomicU64::new(0),
            total_deregistrations: AtomicU64::new(0),
        }
    }
}

/// Global runtime statistics
static WMI_STATS: WmiRuntimeStats = WmiRuntimeStats::new();

/// WMI global state
pub struct WmiState {
    /// Registered data blocks by GUID
    data_blocks: SpinLock<BTreeMap<Guid, Arc<WmiDataBlock>>>,
    /// Registered providers by ID
    providers: SpinLock<BTreeMap<u32, Arc<WmiProvider>>>,
    /// Provider ID to GUID mapping
    provider_guids: SpinLock<BTreeMap<u32, Vec<Guid>>>,
    /// Pending event queue
    event_queue: SpinLock<VecDeque<WmiEventEntry>>,
    /// Event notifications enabled
    events_enabled: SpinLock<BTreeMap<Guid, bool>>,
    /// Registered devices by address
    registered_devices: SpinLock<BTreeMap<usize, u32>>,
    /// Trace providers
    trace_providers: SpinLock<Vec<u32>>,
}

impl WmiState {
    pub const fn new() -> Self {
        Self {
            data_blocks: SpinLock::new(BTreeMap::new()),
            providers: SpinLock::new(BTreeMap::new()),
            provider_guids: SpinLock::new(BTreeMap::new()),
            event_queue: SpinLock::new(VecDeque::new()),
            events_enabled: SpinLock::new(BTreeMap::new()),
            registered_devices: SpinLock::new(BTreeMap::new()),
            trace_providers: SpinLock::new(Vec::new()),
        }
    }
}

static mut WMI_STATE: Option<WmiState> = None;

fn get_wmi_state() -> &'static WmiState {
    unsafe { WMI_STATE.as_ref().expect("WMI not initialized") }
}

/// Initialize WMI subsystem
pub fn wmi_initialize() -> bool {
    if WMI_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return true; // Already initialized
    }

    unsafe {
        WMI_STATE = Some(WmiState::new());
    }

    crate::serial_println!("[WMI] Windows Management Instrumentation initialized");
    true
}

/// Register a WMI data block
pub fn wmi_register_data_block(block: WmiDataBlock) -> Option<u32> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return None;
    }

    let state = get_wmi_state();
    let guid = block.guid;
    let provider_id = block.provider_id;
    let arc_block = Arc::new(block);

    {
        let mut blocks = state.data_blocks.lock();
        if blocks.contains_key(&guid) {
            return None; // GUID already registered
        }
        blocks.insert(guid, arc_block);
    }

    {
        let mut provider_guids = state.provider_guids.lock();
        provider_guids
            .entry(provider_id)
            .or_insert_with(Vec::new)
            .push(guid);
    }

    crate::serial_println!(
        "[WMI] Registered data block {:?} for provider {}",
        guid,
        provider_id
    );

    Some(provider_id)
}

/// Unregister a WMI data block
pub fn wmi_unregister_data_block(guid: &Guid) -> bool {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return false;
    }

    let state = get_wmi_state();
    let mut blocks = state.data_blocks.lock();
    blocks.remove(guid).is_some()
}

/// Query a WMI data block
pub fn wmi_query_data_block(
    guid: &Guid,
    instance_index: u32,
    buffer: &mut [u8],
) -> Result<usize, WmiError> {
    WMI_STATS.total_queries.fetch_add(1, Ordering::Relaxed);

    let state = get_wmi_state();
    let blocks = state.data_blocks.lock();

    let block = blocks.get(guid).ok_or(WmiError::GuidNotFound)?;

    if instance_index >= block.instance_count {
        return Err(WmiError::InvalidInstance);
    }

    // Call the query callback if registered
    if let Some(ref callback) = block.query_callback {
        callback(instance_index, buffer)
    } else {
        Err(WmiError::NotSupported)
    }
}

/// Set WMI data block data
pub fn wmi_set_data_block(
    guid: &Guid,
    instance_index: u32,
    buffer: &[u8],
) -> Result<(), WmiError> {
    WMI_STATS.total_sets.fetch_add(1, Ordering::Relaxed);

    let state = get_wmi_state();
    let blocks = state.data_blocks.lock();

    let block = blocks.get(guid).ok_or(WmiError::GuidNotFound)?;

    if instance_index >= block.instance_count {
        return Err(WmiError::InvalidInstance);
    }

    if !block.flags.contains(WmiDataBlockFlags::WRITABLE) {
        return Err(WmiError::ReadOnly);
    }

    // Call the set callback if registered
    if let Some(ref callback) = block.set_callback {
        callback(instance_index, buffer)
    } else {
        Err(WmiError::NotSupported)
    }
}

/// Execute a WMI method
pub fn wmi_execute_method(
    guid: &Guid,
    instance_index: u32,
    method_id: u32,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, WmiError> {
    WMI_STATS.total_methods.fetch_add(1, Ordering::Relaxed);

    let state = get_wmi_state();
    let blocks = state.data_blocks.lock();

    let block = blocks.get(guid).ok_or(WmiError::GuidNotFound)?;

    if instance_index >= block.instance_count {
        return Err(WmiError::InvalidInstance);
    }

    // Call the method callback if registered
    if let Some(ref callback) = block.method_callback {
        callback(instance_index, method_id, input, output)
    } else {
        Err(WmiError::NotSupported)
    }
}

/// Register a WMI provider
pub fn wmi_register_provider(
    name: &str,
    device_object: usize,
) -> Option<u32> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return None;
    }

    WMI_STATS.total_registrations.fetch_add(1, Ordering::Relaxed);

    let provider_id = NEXT_PROVIDER_ID.fetch_add(1, Ordering::SeqCst);

    let provider = WmiProvider::new(provider_id, name, device_object);
    let state = get_wmi_state();

    {
        let mut providers = state.providers.lock();
        providers.insert(provider_id, Arc::new(provider));
    }

    {
        let mut provider_guids = state.provider_guids.lock();
        provider_guids.insert(provider_id, Vec::new());
    }

    // Track device to provider mapping
    {
        let mut devices = state.registered_devices.lock();
        devices.insert(device_object, provider_id);
    }

    crate::serial_println!(
        "[WMI] Registered provider '{}' (id={})",
        name,
        provider_id
    );

    Some(provider_id)
}

/// Unregister a WMI provider
pub fn wmi_unregister_provider(provider_id: u32) -> bool {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return false;
    }

    WMI_STATS.total_deregistrations.fetch_add(1, Ordering::Relaxed);

    let state = get_wmi_state();

    // Remove all data blocks for this provider
    {
        let provider_guids = state.provider_guids.lock();
        if let Some(guids) = provider_guids.get(&provider_id) {
            let mut blocks = state.data_blocks.lock();
            for guid in guids {
                blocks.remove(guid);
            }
        }
    }

    // Remove the provider
    {
        let mut providers = state.providers.lock();
        providers.remove(&provider_id);
    }

    // Remove the GUID list
    {
        let mut provider_guids = state.provider_guids.lock();
        provider_guids.remove(&provider_id);
    }

    // Remove device mapping
    {
        let mut devices = state.registered_devices.lock();
        devices.retain(|_, &mut v| v != provider_id);
    }

    // Remove from trace providers
    {
        let mut traces = state.trace_providers.lock();
        traces.retain(|&id| id != provider_id);
    }

    true
}

/// WMI error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WmiError {
    /// GUID not found
    GuidNotFound,
    /// Invalid instance index
    InvalidInstance,
    /// Buffer too small
    BufferTooSmall,
    /// Operation not supported
    NotSupported,
    /// Data block is read-only
    ReadOnly,
    /// Invalid parameter
    InvalidParameter,
    /// Provider not found
    ProviderNotFound,
    /// Insufficient resources
    InsufficientResources,
}

/// WMI statistics
#[derive(Debug, Default, Clone)]
pub struct WmiStatistics {
    /// Number of registered data blocks
    pub data_blocks: u32,
    /// Number of registered providers
    pub providers: u32,
    /// Total queries
    pub total_queries: u64,
    /// Total sets
    pub total_sets: u64,
    /// Total method executions
    pub total_methods: u64,
    /// Total events fired
    pub total_events: u64,
    /// Events dropped (queue full)
    pub events_dropped: u64,
    /// Total registrations
    pub total_registrations: u64,
    /// Total deregistrations
    pub total_deregistrations: u64,
    /// Pending events in queue
    pub pending_events: u32,
    /// Registered devices
    pub registered_devices: u32,
    /// Trace providers
    pub trace_providers: u32,
}

/// Get WMI statistics
pub fn wmi_get_statistics() -> WmiStatistics {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return WmiStatistics::default();
    }

    let state = get_wmi_state();
    let blocks = state.data_blocks.lock();
    let providers = state.providers.lock();
    let events = state.event_queue.lock();
    let devices = state.registered_devices.lock();
    let traces = state.trace_providers.lock();

    WmiStatistics {
        data_blocks: blocks.len() as u32,
        providers: providers.len() as u32,
        total_queries: WMI_STATS.total_queries.load(Ordering::Relaxed),
        total_sets: WMI_STATS.total_sets.load(Ordering::Relaxed),
        total_methods: WMI_STATS.total_methods.load(Ordering::Relaxed),
        total_events: WMI_STATS.total_events.load(Ordering::Relaxed),
        events_dropped: WMI_STATS.events_dropped.load(Ordering::Relaxed),
        total_registrations: WMI_STATS.total_registrations.load(Ordering::Relaxed),
        total_deregistrations: WMI_STATS.total_deregistrations.load(Ordering::Relaxed),
        pending_events: events.len() as u32,
        registered_devices: devices.len() as u32,
        trace_providers: traces.len() as u32,
    }
}

// ============================================================================
// IoWMIWriteEvent - Fire WMI Events (from notify.c)
// ============================================================================

/// Fire a WMI event
/// This is the kernel equivalent of IoWMIWriteEvent
pub fn wmi_write_event(
    guid: &Guid,
    provider_id: u32,
    instance_index: u32,
    data_size: u32,
    flags: u32,
) -> Result<(), WmiError> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return Err(WmiError::NotSupported);
    }

    // Check if events are enabled for this GUID
    let state = get_wmi_state();
    {
        let enabled = state.events_enabled.lock();
        if let Some(&is_enabled) = enabled.get(guid) {
            if !is_enabled {
                return Ok(()); // Events disabled, silently succeed
            }
        }
    }

    // Create event entry
    let event = WmiEventEntry {
        guid: *guid,
        provider_id,
        data_size,
        timestamp: crate::hal::rtc::get_system_time(),
        instance_index,
        flags,
    };

    // Queue the event
    {
        let mut queue = state.event_queue.lock();
        if queue.len() >= MAX_PENDING_EVENTS {
            WMI_STATS.events_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(WmiError::InsufficientResources);
        }
        queue.push_back(event);
    }

    WMI_STATS.total_events.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Enable events for a GUID
pub fn wmi_enable_events(guid: &Guid) -> Result<(), WmiError> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return Err(WmiError::NotSupported);
    }

    let state = get_wmi_state();
    let mut enabled = state.events_enabled.lock();
    enabled.insert(*guid, true);

    Ok(())
}

/// Disable events for a GUID
pub fn wmi_disable_events(guid: &Guid) -> Result<(), WmiError> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return Err(WmiError::NotSupported);
    }

    let state = get_wmi_state();
    let mut enabled = state.events_enabled.lock();
    enabled.insert(*guid, false);

    Ok(())
}

/// Get next pending event (for notification processing)
pub fn wmi_get_next_event() -> Option<WmiEventEntry> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return None;
    }

    let state = get_wmi_state();
    let mut queue = state.event_queue.lock();
    queue.pop_front()
}

/// Get pending event count
pub fn wmi_pending_event_count() -> usize {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = get_wmi_state();
    let queue = state.event_queue.lock();
    queue.len()
}

// ============================================================================
// IoWMIRegistrationControl - Device Registration (from register.c)
// ============================================================================

/// IoWMIRegistrationControl equivalent
/// Registers or deregisters a device for WMI
pub fn wmi_registration_control(
    device_object: usize,
    action: u32,
) -> Result<u32, WmiError> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return Err(WmiError::NotSupported);
    }

    let is_trace_provider = (action & WMIREG_FLAG_TRACE_PROVIDER) != 0;
    let base_action = action & !(WMIREG_FLAG_CALLBACK | WMIREG_FLAG_TRACE_PROVIDER);

    match base_action {
        WMIREG_ACTION_REGISTER => {
            // Create a default provider name
            let name = alloc::format!("Device_{:016X}", device_object);
            if let Some(provider_id) = wmi_register_provider(&name, device_object) {
                // Track as trace provider if needed
                if is_trace_provider {
                    let state = get_wmi_state();
                    let mut traces = state.trace_providers.lock();
                    if !traces.contains(&provider_id) {
                        traces.push(provider_id);
                    }
                }
                Ok(provider_id)
            } else {
                Err(WmiError::InsufficientResources)
            }
        }
        WMIREG_ACTION_DEREGISTER => {
            let state = get_wmi_state();
            let provider_id = {
                let devices = state.registered_devices.lock();
                devices.get(&device_object).copied()
            };

            if let Some(id) = provider_id {
                wmi_unregister_provider(id);
                Ok(0)
            } else {
                Err(WmiError::ProviderNotFound)
            }
        }
        WMIREG_ACTION_REREGISTER => {
            // Deregister then register
            let _ = wmi_registration_control(device_object, WMIREG_ACTION_DEREGISTER);
            wmi_registration_control(device_object, WMIREG_ACTION_REGISTER | (action & WMIREG_FLAG_TRACE_PROVIDER))
        }
        WMIREG_ACTION_UPDATE_GUIDS => {
            // Just succeed for now
            Ok(0)
        }
        WMIREG_ACTION_BLOCK_IRPS => {
            // Mark device as blocked (not implemented yet)
            Ok(0)
        }
        _ => Err(WmiError::InvalidParameter),
    }
}

/// Find provider ID by device object
pub fn wmi_find_provider_by_device(device_object: usize) -> Option<u32> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return None;
    }

    let state = get_wmi_state();
    let devices = state.registered_devices.lock();
    devices.get(&device_object).copied()
}

/// Check if a device is registered as a trace provider
pub fn wmi_is_trace_provider(provider_id: u32) -> bool {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return false;
    }

    let state = get_wmi_state();
    let traces = state.trace_providers.lock();
    traces.contains(&provider_id)
}

/// Get all trace providers
pub fn wmi_get_trace_providers() -> Vec<u32> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return Vec::new();
    }

    let state = get_wmi_state();
    let traces = state.trace_providers.lock();
    traces.clone()
}

/// Check if WMI is initialized
pub fn wmi_is_initialized() -> bool {
    WMI_INITIALIZED.load(Ordering::SeqCst)
}
