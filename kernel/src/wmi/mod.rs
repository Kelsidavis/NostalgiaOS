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
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

extern crate alloc;

/// WMI initialized flag
static WMI_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Next provider ID
static NEXT_PROVIDER_ID: AtomicU32 = AtomicU32::new(1);

/// WMI global state
pub struct WmiState {
    /// Registered data blocks by GUID
    data_blocks: SpinLock<BTreeMap<Guid, Arc<WmiDataBlock>>>,
    /// Registered providers by ID
    providers: SpinLock<BTreeMap<u32, Arc<WmiProvider>>>,
    /// Provider ID to GUID mapping
    provider_guids: SpinLock<BTreeMap<u32, Vec<Guid>>>,
}

impl WmiState {
    pub const fn new() -> Self {
        Self {
            data_blocks: SpinLock::new(BTreeMap::new()),
            providers: SpinLock::new(BTreeMap::new()),
            provider_guids: SpinLock::new(BTreeMap::new()),
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
}

/// Get WMI statistics
pub fn wmi_get_statistics() -> WmiStatistics {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return WmiStatistics::default();
    }

    let state = get_wmi_state();
    let blocks = state.data_blocks.lock();
    let providers = state.providers.lock();

    WmiStatistics {
        data_blocks: blocks.len() as u32,
        providers: providers.len() as u32,
        total_queries: 0,
        total_sets: 0,
        total_methods: 0,
    }
}
