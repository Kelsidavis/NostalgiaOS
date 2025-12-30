//! WMI IRP Handling
//!
//! Implements IRP_MJ_SYSTEM_CONTROL minor functions for WMI.

use super::{WmiError, WnodeFlags};
use crate::etw::Guid;

/// WMI IRP minor function codes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WmiMinorFunction {
    /// Query all data blocks for a GUID
    QueryAllData = 0x00,
    /// Query single instance
    QuerySingleInstance = 0x01,
    /// Change single instance
    ChangeSingleInstance = 0x02,
    /// Change single item
    ChangeSingleItem = 0x03,
    /// Enable events
    EnableEvents = 0x04,
    /// Disable events
    DisableEvents = 0x05,
    /// Enable collection
    EnableCollection = 0x06,
    /// Disable collection
    DisableCollection = 0x07,
    /// Register info (driver registration)
    RegInfo = 0x08,
    /// Execute method
    ExecuteMethod = 0x09,
    /// Set trace notify
    SetTraceNotify = 0x0A,
    /// Registration info extended
    RegInfoEx = 0x0B,
}

impl WmiMinorFunction {
    /// Create from u8 value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(WmiMinorFunction::QueryAllData),
            0x01 => Some(WmiMinorFunction::QuerySingleInstance),
            0x02 => Some(WmiMinorFunction::ChangeSingleInstance),
            0x03 => Some(WmiMinorFunction::ChangeSingleItem),
            0x04 => Some(WmiMinorFunction::EnableEvents),
            0x05 => Some(WmiMinorFunction::DisableEvents),
            0x06 => Some(WmiMinorFunction::EnableCollection),
            0x07 => Some(WmiMinorFunction::DisableCollection),
            0x08 => Some(WmiMinorFunction::RegInfo),
            0x09 => Some(WmiMinorFunction::ExecuteMethod),
            0x0A => Some(WmiMinorFunction::SetTraceNotify),
            0x0B => Some(WmiMinorFunction::RegInfoEx),
            _ => None,
        }
    }
}

/// WMI IRP parameters
#[repr(C)]
#[derive(Clone, Copy)]
pub union WmiIrpParameters {
    /// Query all data parameters
    pub query_all_data: QueryAllDataParameters,
    /// Query single instance parameters
    pub query_single_instance: QuerySingleInstanceParameters,
    /// Change single instance parameters
    pub change_single_instance: ChangeSingleInstanceParameters,
    /// Change single item parameters
    pub change_single_item: ChangeSingleItemParameters,
    /// Enable/disable events parameters
    pub enable_disable_events: EnableDisableEventsParameters,
    /// Enable/disable collection parameters
    pub enable_disable_collection: EnableDisableCollectionParameters,
    /// Execute method parameters
    pub execute_method: ExecuteMethodParameters,
}

/// Query all data IRP parameters
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct QueryAllDataParameters {
    /// Buffer size
    pub buffer_size: u32,
    /// Data path (GUID pointer)
    pub data_path: usize,
}

/// Query single instance IRP parameters
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct QuerySingleInstanceParameters {
    /// Buffer size
    pub buffer_size: u32,
    /// Data path (GUID pointer)
    pub data_path: usize,
}

/// Change single instance IRP parameters
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ChangeSingleInstanceParameters {
    /// Buffer size
    pub buffer_size: u32,
    /// Data path (GUID pointer)
    pub data_path: usize,
}

/// Change single item IRP parameters
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ChangeSingleItemParameters {
    /// Buffer size
    pub buffer_size: u32,
    /// Data path (GUID pointer)
    pub data_path: usize,
}

/// Enable/disable events IRP parameters
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EnableDisableEventsParameters {
    /// Data path (GUID pointer)
    pub data_path: usize,
}

/// Enable/disable collection IRP parameters
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EnableDisableCollectionParameters {
    /// Data path (GUID pointer)
    pub data_path: usize,
}

/// Execute method IRP parameters
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ExecuteMethodParameters {
    /// Buffer size
    pub buffer_size: u32,
    /// Data path (GUID pointer)
    pub data_path: usize,
}

/// WMI IRP result
#[derive(Debug)]
pub enum WmiIrpResult {
    /// IRP completed successfully
    Success,
    /// IRP completed with status
    Status(i32),
    /// IRP not handled (pass to next driver)
    NotHandled,
    /// IRP pending
    Pending,
}

/// Default WMI IRP handler callback type
pub type WmiIrpHandler = fn(
    minor: WmiMinorFunction,
    guid: &Guid,
    instance_index: u32,
    buffer: &mut [u8],
) -> WmiIrpResult;

/// Process a WMI IRP
pub fn wmi_handle_irp(
    minor: WmiMinorFunction,
    guid: &Guid,
    instance_index: u32,
    buffer: &mut [u8],
) -> WmiIrpResult {
    match minor {
        WmiMinorFunction::QueryAllData => {
            match super::wmi_query_data_block(guid, instance_index, buffer) {
                Ok(_size) => WmiIrpResult::Success,
                Err(WmiError::GuidNotFound) => WmiIrpResult::NotHandled,
                Err(WmiError::BufferTooSmall) => {
                    WmiIrpResult::Status(-2147483643) // STATUS_BUFFER_TOO_SMALL
                }
                Err(_) => WmiIrpResult::Status(-1073741823), // STATUS_UNSUCCESSFUL
            }
        }
        WmiMinorFunction::QuerySingleInstance => {
            match super::wmi_query_data_block(guid, instance_index, buffer) {
                Ok(_size) => WmiIrpResult::Success,
                Err(WmiError::GuidNotFound) => WmiIrpResult::NotHandled,
                Err(WmiError::InvalidInstance) => {
                    WmiIrpResult::Status(-1073741824) // STATUS_WMI_INSTANCE_NOT_FOUND
                }
                Err(_) => WmiIrpResult::Status(-1073741823), // STATUS_UNSUCCESSFUL
            }
        }
        WmiMinorFunction::ChangeSingleInstance => {
            match super::wmi_set_data_block(guid, instance_index, buffer) {
                Ok(()) => WmiIrpResult::Success,
                Err(WmiError::GuidNotFound) => WmiIrpResult::NotHandled,
                Err(WmiError::ReadOnly) => {
                    WmiIrpResult::Status(-1073741812) // STATUS_WMI_READ_ONLY
                }
                Err(_) => WmiIrpResult::Status(-1073741823), // STATUS_UNSUCCESSFUL
            }
        }
        WmiMinorFunction::ChangeSingleItem => {
            // For single item, we'd parse the item ID from the WNODE
            // For now, treat as change single instance
            match super::wmi_set_data_block(guid, instance_index, buffer) {
                Ok(()) => WmiIrpResult::Success,
                Err(_) => WmiIrpResult::NotHandled,
            }
        }
        WmiMinorFunction::ExecuteMethod => {
            // Parse method ID from buffer (in WNODE_METHOD_ITEM)
            let method_id = 0u32; // Would extract from WNODE
            let mut output = [0u8; 256];
            match super::wmi_execute_method(guid, instance_index, method_id, buffer, &mut output) {
                Ok(_size) => WmiIrpResult::Success,
                Err(_) => WmiIrpResult::NotHandled,
            }
        }
        WmiMinorFunction::EnableEvents
        | WmiMinorFunction::DisableEvents
        | WmiMinorFunction::EnableCollection
        | WmiMinorFunction::DisableCollection => {
            // These are optional - drivers can handle or not
            WmiIrpResult::Success
        }
        WmiMinorFunction::RegInfo | WmiMinorFunction::RegInfoEx => {
            // Registration info - would need to parse and store
            WmiIrpResult::Success
        }
        WmiMinorFunction::SetTraceNotify => {
            // ETW integration
            WmiIrpResult::Success
        }
    }
}

/// WMI system control request context
#[derive(Debug, Clone)]
pub struct WmiSystemControlContext {
    /// Minor function code
    pub minor_function: WmiMinorFunction,
    /// Provider ID
    pub provider_id: u32,
    /// Data path (points to GUID)
    pub data_path: usize,
    /// Buffer length
    pub buffer_length: u32,
    /// Buffer pointer
    pub buffer: usize,
}

/// Create a WMI WNODE header for a response
pub fn wmi_build_wnode_header(
    guid: &Guid,
    provider_id: u32,
    buffer_size: u32,
    flags: u32,
) -> super::data::WnodeHeader {
    use super::data::WnodeHeader;

    WnodeHeader {
        buffer_size,
        provider_id,
        version: 1,
        linkage: 0,
        timestamp: crate::hal::rtc::get_system_time() as i64,
        guid: *guid,
        client_context: 0,
        flags,
    }
}

/// WMI library helper - handles common WMI IRP patterns
pub struct WmiLibContext {
    /// Provider ID
    pub provider_id: u32,
    /// GUIDs this provider handles
    pub guids: &'static [Guid],
}

impl WmiLibContext {
    /// Create new WMI library context
    pub const fn new(provider_id: u32, guids: &'static [Guid]) -> Self {
        Self {
            provider_id,
            guids,
        }
    }

    /// Check if this context handles a GUID
    pub fn handles_guid(&self, guid: &Guid) -> bool {
        self.guids.iter().any(|g| g == guid)
    }
}
