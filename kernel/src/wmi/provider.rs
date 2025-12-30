//! WMI Provider Registration
//!
//! Manages WMI data providers (typically device drivers).

use alloc::string::String;
use alloc::vec::Vec;
use crate::etw::Guid;

extern crate alloc;

/// WMI provider state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WmiProviderState {
    /// Provider not registered
    #[default]
    Unregistered = 0,
    /// Provider is registered
    Registered = 1,
    /// Provider is being removed
    Removing = 2,
}

/// WMI provider information
#[derive(Clone)]
pub struct WmiProvider {
    /// Provider ID
    pub id: u32,
    /// Provider name
    pub name: String,
    /// Device object pointer
    pub device_object: usize,
    /// Provider state
    pub state: WmiProviderState,
    /// Registered GUIDs
    pub guids: Vec<Guid>,
    /// Provider flags
    pub flags: WmiProviderFlags,
}

impl WmiProvider {
    /// Create a new provider
    pub fn new(id: u32, name: &str, device_object: usize) -> Self {
        Self {
            id,
            name: String::from(name),
            device_object,
            state: WmiProviderState::Registered,
            guids: Vec::new(),
            flags: WmiProviderFlags::empty(),
        }
    }

    /// Add a GUID to this provider
    pub fn add_guid(&mut self, guid: Guid) {
        if !self.guids.contains(&guid) {
            self.guids.push(guid);
        }
    }

    /// Remove a GUID from this provider
    pub fn remove_guid(&mut self, guid: &Guid) {
        self.guids.retain(|g| g != guid);
    }

    /// Check if provider handles a GUID
    pub fn handles_guid(&self, guid: &Guid) -> bool {
        self.guids.contains(guid)
    }
}

impl core::fmt::Debug for WmiProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WmiProvider")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("state", &self.state)
            .field("guid_count", &self.guids.len())
            .finish()
    }
}

/// WMI provider flags
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct WmiProviderFlags: u32 {
        /// Provider handles expensive data blocks
        const HAS_EXPENSIVE = 0x00000001;
        /// Provider generates events
        const HAS_EVENTS = 0x00000002;
        /// Provider has methods
        const HAS_METHODS = 0x00000004;
        /// Provider uses PDO instance names
        const PDO_NAMES = 0x00000008;
    }
}

/// Well-known WMI GUIDs
pub mod wmi_guids {
    use crate::etw::Guid;

    /// MSWmi_Guid - base WMI class
    pub const MSWMI_GUID: Guid = Guid {
        data1: 0x585e3a80,
        data2: 0xbf74,
        data3: 0x11d0,
        data4: [0xa0, 0x6c, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20],
    };

    /// WMI_GUID_REG_GUID - registration GUID
    pub const WMI_REG_GUID: Guid = Guid {
        data1: 0x4c8b_4100,
        data2: 0x76d3,
        data3: 0x11d0,
        data4: [0xa0, 0x6c, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20],
    };

    /// Storage device info GUID
    pub const STORAGE_DEVICE_INFO: Guid = Guid {
        data1: 0x5303_1a30,
        data2: 0x6c40,
        data3: 0x11d2,
        data4: [0xb4, 0x2b, 0x00, 0xc0, 0x4f, 0x98, 0x7d, 0xcd],
    };

    /// Disk performance GUID
    pub const DISK_PERFORMANCE: Guid = Guid {
        data1: 0xbdd8_6532,
        data2: 0xba58,
        data3: 0x11d0,
        data4: [0xa0, 0x6c, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20],
    };

    /// MSWmi_MofData_GUID - MOF data
    pub const MSWMI_MOFDATA: Guid = Guid {
        data1: 0x2506_2332,
        data2: 0xbf74,
        data3: 0x11d0,
        data4: [0xa0, 0x6c, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20],
    };
}

/// WMI request block - passed to drivers for IRP_MJ_SYSTEM_CONTROL
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WmiRequestBlock {
    /// GUID being queried
    pub guid: Guid,
    /// Flags for this request
    pub flags: u32,
    /// Provider ID
    pub provider_id: u32,
    /// Data path size
    pub data_path_size: u32,
    /// Instance index
    pub instance_index: u32,
}

/// WMI query type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WmiQueryType {
    /// Query all data
    AllData = 0,
    /// Query single instance
    SingleInstance = 1,
    /// Query single item
    SingleItem = 2,
}

/// MOF class definition (simplified)
#[derive(Debug, Clone)]
pub struct MofClass {
    /// Class name
    pub name: String,
    /// Class GUID
    pub guid: Guid,
    /// Superclass name (if any)
    pub superclass: Option<String>,
    /// Properties
    pub properties: Vec<MofProperty>,
    /// Methods
    pub methods: Vec<MofMethod>,
}

/// MOF property definition
#[derive(Debug, Clone)]
pub struct MofProperty {
    /// Property name
    pub name: String,
    /// Property type
    pub property_type: MofType,
    /// Qualifiers
    pub qualifiers: Vec<String>,
}

/// MOF method definition
#[derive(Debug, Clone)]
pub struct MofMethod {
    /// Method name
    pub name: String,
    /// Method ID
    pub method_id: u32,
    /// Input parameters
    pub in_params: Vec<MofProperty>,
    /// Output parameters
    pub out_params: Vec<MofProperty>,
}

/// MOF data types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MofType {
    /// Boolean
    Boolean,
    /// Signed 8-bit
    Sint8,
    /// Unsigned 8-bit
    Uint8,
    /// Signed 16-bit
    Sint16,
    /// Unsigned 16-bit
    Uint16,
    /// Signed 32-bit
    Sint32,
    /// Unsigned 32-bit
    Uint32,
    /// Signed 64-bit
    Sint64,
    /// Unsigned 64-bit
    Uint64,
    /// Real 32-bit
    Real32,
    /// Real 64-bit
    Real64,
    /// String
    String,
    /// DateTime
    DateTime,
    /// Reference to another object
    Reference,
    /// Object (embedded)
    Object,
}
