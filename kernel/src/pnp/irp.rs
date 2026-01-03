//! PnP IRP Handling
//!
//! Defines PnP IRP minor codes and handling.

use super::{DeviceCapabilities, DeviceRelationType};
use crate::io::DeviceObject;

/// PnP IRP minor function codes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnpMinorFunction {
    /// Start the device
    StartDevice = 0x00,
    /// Query if device can be removed
    QueryRemoveDevice = 0x01,
    /// Device is being removed
    RemoveDevice = 0x02,
    /// Device removal cancelled
    CancelRemoveDevice = 0x03,
    /// Query if device can be stopped
    QueryStopDevice = 0x05,
    /// Stop the device
    StopDevice = 0x04,
    /// Device stop cancelled
    CancelStopDevice = 0x06,
    /// Query device relations
    QueryDeviceRelations = 0x07,
    /// Query device interface
    QueryInterface = 0x08,
    /// Query device capabilities
    QueryCapabilities = 0x09,
    /// Query device resources
    QueryResources = 0x0A,
    /// Query resource requirements
    QueryResourceRequirements = 0x0B,
    /// Query device text
    QueryDeviceText = 0x0C,
    /// Filter resource requirements
    FilterResourceRequirements = 0x0D,
    /// Read device config
    ReadConfig = 0x0F,
    /// Write device config
    WriteConfig = 0x10,
    /// Device ejected
    Eject = 0x11,
    /// Set device lock
    SetLock = 0x12,
    /// Query device ID
    QueryId = 0x13,
    /// Query PnP device state
    QueryPnpDeviceState = 0x14,
    /// Query bus information
    QueryBusInformation = 0x15,
    /// Device usage notification
    DeviceUsageNotification = 0x16,
    /// Device surprise removal
    SurpriseRemoval = 0x17,
    /// Query legacy bus information
    QueryLegacyBusInformation = 0x18,
}

/// Device ID type for QueryId
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusQueryIdType {
    /// Device ID
    DeviceId = 0,
    /// Hardware IDs
    HardwareIds = 1,
    /// Compatible IDs
    CompatibleIds = 2,
    /// Instance ID
    InstanceId = 3,
    /// Device serial number
    DeviceSerialNumber = 4,
    /// Container ID
    ContainerId = 5,
}

/// Device text type for QueryDeviceText
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceTextType {
    /// Device description
    DeviceDescription = 0,
    /// Location information
    LocationInformation = 1,
}

/// PnP device state flags
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct PnpDeviceState: u32 {
        /// Device disabled
        const DISABLED = 0x00000001;
        /// Device removal pending
        const DONT_DISPLAY_IN_UI = 0x00000002;
        /// Device failed enumeration
        const FAILED = 0x00000004;
        /// Device not disableable
        const NOT_DISABLEABLE = 0x00000008;
        /// Device needs rebalance
        const PAGE_FILE_SUPPORTED = 0x00000020;
        /// Device has translation
        const TRANSLATION_REQUIRED = 0x00000040;
        /// Device removed
        const REMOVED = 0x00000080;
        /// Device resource requirements changed
        const RESOURCE_REQUIREMENTS_CHANGED = 0x00000100;
        /// Device is assigning resources
        const USING_WDF_PNP_STATE = 0x00000200;
    }
}

/// PnP IRP parameters union
#[repr(C)]
#[derive(Clone, Copy)]
pub union PnpIrpParameters {
    /// StartDevice parameters
    pub start_device: StartDeviceParameters,
    /// QueryDeviceRelations parameters
    pub query_device_relations: QueryDeviceRelationsParameters,
    /// QueryInterface parameters
    pub query_interface: QueryInterfaceParameters,
    /// QueryCapabilities parameters
    pub query_capabilities: QueryCapabilitiesParameters,
    /// QueryDeviceText parameters
    pub query_device_text: QueryDeviceTextParameters,
    /// QueryId parameters
    pub query_id: QueryIdParameters,
    /// UsageNotification parameters
    pub usage_notification: UsageNotificationParameters,
}

/// StartDevice IRP parameters
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct StartDeviceParameters {
    /// Allocated resources
    pub allocated_resources: *const super::CmResourceList,
    /// Translated resources
    pub allocated_resources_translated: *const super::CmResourceList,
}

/// QueryDeviceRelations IRP parameters
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct QueryDeviceRelationsParameters {
    /// Relation type
    pub relation_type: u32,
}

/// QueryInterface IRP parameters
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct QueryInterfaceParameters {
    /// Interface type GUID
    pub interface_type: *const crate::etw::Guid,
    /// Size of interface
    pub size: u16,
    /// Version
    pub version: u16,
    /// Interface pointer (output)
    pub interface: *mut u8,
    /// Interface-specific data
    pub interface_specific_data: *mut u8,
}

impl Default for QueryInterfaceParameters {
    fn default() -> Self {
        Self {
            interface_type: core::ptr::null(),
            size: 0,
            version: 0,
            interface: core::ptr::null_mut(),
            interface_specific_data: core::ptr::null_mut(),
        }
    }
}

/// QueryCapabilities IRP parameters
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct QueryCapabilitiesParameters {
    /// Capabilities structure pointer
    pub capabilities: *mut DeviceCapabilities,
}

impl Default for QueryCapabilitiesParameters {
    fn default() -> Self {
        Self {
            capabilities: core::ptr::null_mut(),
        }
    }
}

/// QueryDeviceText IRP parameters
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct QueryDeviceTextParameters {
    /// Text type
    pub device_text_type: u32,
    /// Locale ID
    pub locale_id: u32,
}

/// QueryId IRP parameters
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct QueryIdParameters {
    /// ID type
    pub id_type: u32,
}

/// UsageNotification IRP parameters
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UsageNotificationParameters {
    /// In path (true if device is in path)
    pub in_path: bool,
    /// Padding
    pub reserved: [u8; 3],
    /// Usage type
    pub usage_type: u32,
}

/// Device usage type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceUsageType {
    /// Paging file
    Paging = 1,
    /// Hibernation file
    Hibernation = 2,
    /// Dump file
    DumpFile = 3,
    /// Boot device
    Boot = 4,
}

/// PnP IRP handler result
#[derive(Debug)]
pub enum PnpIrpResult {
    /// IRP completed successfully
    Success,
    /// IRP completed with status
    Status(i32),
    /// IRP passed down
    PassDown,
    /// IRP pending
    Pending,
}

/// Default PnP IRP handler
pub fn default_pnp_handler(_device: &DeviceObject, minor: PnpMinorFunction) -> PnpIrpResult {
    match minor {
        PnpMinorFunction::StartDevice => {
            // Default: succeed
            PnpIrpResult::Success
        }
        PnpMinorFunction::QueryRemoveDevice
        | PnpMinorFunction::QueryStopDevice => {
            // Default: allow
            PnpIrpResult::Success
        }
        PnpMinorFunction::CancelRemoveDevice
        | PnpMinorFunction::CancelStopDevice => {
            // Default: succeed
            PnpIrpResult::Success
        }
        PnpMinorFunction::RemoveDevice
        | PnpMinorFunction::StopDevice => {
            // Default: succeed
            PnpIrpResult::Success
        }
        PnpMinorFunction::SurpriseRemoval => {
            // Default: succeed
            PnpIrpResult::Success
        }
        PnpMinorFunction::QueryDeviceRelations => {
            // Default: pass down
            PnpIrpResult::PassDown
        }
        PnpMinorFunction::QueryCapabilities => {
            // Default: pass down
            PnpIrpResult::PassDown
        }
        PnpMinorFunction::QueryId => {
            // Default: pass down
            PnpIrpResult::PassDown
        }
        PnpMinorFunction::QueryDeviceText => {
            // Default: pass down
            PnpIrpResult::PassDown
        }
        PnpMinorFunction::QueryBusInformation => {
            // Default: pass down
            PnpIrpResult::PassDown
        }
        PnpMinorFunction::QueryPnpDeviceState => {
            // Default: succeed
            PnpIrpResult::Success
        }
        PnpMinorFunction::QueryResources
        | PnpMinorFunction::QueryResourceRequirements
        | PnpMinorFunction::FilterResourceRequirements => {
            // Default: pass down
            PnpIrpResult::PassDown
        }
        PnpMinorFunction::QueryInterface => {
            // Default: not supported
            PnpIrpResult::Status(-1073741637) // STATUS_NOT_SUPPORTED
        }
        PnpMinorFunction::ReadConfig
        | PnpMinorFunction::WriteConfig => {
            // Default: not supported
            PnpIrpResult::Status(-1073741637) // STATUS_NOT_SUPPORTED
        }
        PnpMinorFunction::Eject => {
            // Default: succeed
            PnpIrpResult::Success
        }
        PnpMinorFunction::SetLock => {
            // Default: not supported
            PnpIrpResult::Status(-1073741637) // STATUS_NOT_SUPPORTED
        }
        PnpMinorFunction::DeviceUsageNotification => {
            // Default: succeed
            PnpIrpResult::Success
        }
        PnpMinorFunction::QueryLegacyBusInformation => {
            // Default: not supported
            PnpIrpResult::Status(-1073741637) // STATUS_NOT_SUPPORTED
        }
    }
}

/// Build a StartDevice IRP
pub fn build_start_device_irp(
    resources: Option<&super::CmResourceList>,
    translated: Option<&super::CmResourceList>,
) -> StartDeviceParameters {
    StartDeviceParameters {
        allocated_resources: resources
            .map(|r| r as *const _)
            .unwrap_or(core::ptr::null()),
        allocated_resources_translated: translated
            .map(|t| t as *const _)
            .unwrap_or(core::ptr::null()),
    }
}

/// Build a QueryDeviceRelations IRP
pub fn build_query_relations_irp(relation_type: DeviceRelationType) -> QueryDeviceRelationsParameters {
    QueryDeviceRelationsParameters {
        relation_type: relation_type as u32,
    }
}

/// Build a QueryId IRP
pub fn build_query_id_irp(id_type: BusQueryIdType) -> QueryIdParameters {
    QueryIdParameters {
        id_type: id_type as u32,
    }
}

/// Build a QueryDeviceText IRP
pub fn build_query_text_irp(text_type: DeviceTextType, locale_id: u32) -> QueryDeviceTextParameters {
    QueryDeviceTextParameters {
        device_text_type: text_type as u32,
        locale_id,
    }
}
