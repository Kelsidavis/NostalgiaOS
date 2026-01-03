//! WMI Data Block Definitions
//!
//! Defines structures for WMI data blocks that drivers use to expose
//! management information.

use super::WmiError;
use crate::etw::Guid;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

extern crate alloc;

/// WNODE header structure - shared with ETW
/// This is at the start of all WMI data blocks
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WnodeHeader {
    /// Size of entire buffer including header
    pub buffer_size: u32,
    /// Provider ID
    pub provider_id: u32,
    /// Version and linkage (union with historical context)
    pub version: u32,
    pub linkage: u32,
    /// Timestamp or kernel handle (union)
    pub timestamp: i64,
    /// GUID for this data block
    pub guid: Guid,
    /// Client context
    pub client_context: u32,
    /// Flags (see WnodeFlags)
    pub flags: u32,
}

impl Default for WnodeHeader {
    fn default() -> Self {
        Self {
            buffer_size: core::mem::size_of::<Self>() as u32,
            provider_id: 0,
            version: 0,
            linkage: 0,
            timestamp: 0,
            guid: Guid::zero(),
            client_context: 0,
            flags: 0,
        }
    }
}

/// WNODE flags
#[allow(non_snake_case)]
pub mod WnodeFlags {
    /// WNODE contains all data for all instances
    pub const ALL_DATA: u32 = 0x00000001;
    /// WNODE contains single instance data
    pub const SINGLE_INSTANCE: u32 = 0x00000002;
    /// WNODE contains single item data
    pub const SINGLE_ITEM: u32 = 0x00000004;
    /// WNODE is an event
    pub const EVENT_ITEM: u32 = 0x00000008;
    /// All instances have fixed size
    pub const FIXED_INSTANCE_SIZE: u32 = 0x00000010;
    /// Buffer is too small
    pub const TOO_SMALL: u32 = 0x00000020;
    /// Instances are same as previous query
    pub const INSTANCES_SAME: u32 = 0x00000040;
    /// Static instance names
    pub const STATIC_INSTANCE_NAMES: u32 = 0x00000080;
    /// Internal use
    pub const INTERNAL: u32 = 0x00000100;
    /// Use timestamp as-is
    pub const USE_TIMESTAMP: u32 = 0x00000200;
    /// Event should persist
    pub const PERSIST_EVENT: u32 = 0x00000400;
    /// Event reference
    pub const EVENT_REFERENCE: u32 = 0x00002000;
    /// ANSI instance names
    pub const ANSI_INSTANCE_NAMES: u32 = 0x00004000;
    /// Method item
    pub const METHOD_ITEM: u32 = 0x00008000;
    /// PDO instance names
    pub const PDO_INSTANCE_NAMES: u32 = 0x00010000;
    /// Traced GUID (ETW)
    pub const TRACED_GUID: u32 = 0x00020000;
    /// Log WNODE
    pub const LOG_WNODE: u32 = 0x00040000;
    /// Use GUID pointer
    pub const USE_GUID_PTR: u32 = 0x00080000;
    /// Use MOF pointer
    pub const USE_MOF_PTR: u32 = 0x00100000;
    /// No header
    pub const NO_HEADER: u32 = 0x00200000;
    /// Severity mask
    pub const SEVERITY_MASK: u32 = 0xff000000;
}

/// WNODE_ALL_DATA - contains data for all instances
#[repr(C)]
#[derive(Debug, Clone)]
pub struct WnodeAllData {
    /// Header
    pub header: WnodeHeader,
    /// Offset to first data block
    pub data_block_offset: u32,
    /// Number of instances
    pub instance_count: u32,
    /// Offset to instance name offsets array
    pub offset_instance_name_offsets: u32,
    /// Fixed instance size (if FIXED_INSTANCE_SIZE flag set)
    pub fixed_instance_size: u32,
}

/// WNODE_SINGLE_INSTANCE - contains data for one instance
#[repr(C)]
#[derive(Debug, Clone)]
pub struct WnodeSingleInstance {
    /// Header
    pub header: WnodeHeader,
    /// Offset to instance name
    pub offset_instance_name: u32,
    /// Instance index (for static names)
    pub instance_index: u32,
    /// Offset to data block
    pub data_block_offset: u32,
    /// Size of data block
    pub size_data_block: u32,
}

/// WNODE_SINGLE_ITEM - contains single item data
#[repr(C)]
#[derive(Debug, Clone)]
pub struct WnodeSingleItem {
    /// Header
    pub header: WnodeHeader,
    /// Offset to instance name
    pub offset_instance_name: u32,
    /// Instance index
    pub instance_index: u32,
    /// Item ID
    pub item_id: u32,
    /// Offset to data
    pub data_block_offset: u32,
    /// Size of data
    pub size_data_item: u32,
}

/// WNODE_METHOD_ITEM - method invocation
#[repr(C)]
#[derive(Debug, Clone)]
pub struct WnodeMethodItem {
    /// Header
    pub header: WnodeHeader,
    /// Offset to instance name
    pub offset_instance_name: u32,
    /// Instance index
    pub instance_index: u32,
    /// Method ID
    pub method_id: u32,
    /// Offset to input data
    pub data_block_offset: u32,
    /// Size of input data
    pub size_data_block: u32,
}

/// WNODE_EVENT_ITEM - event notification
#[repr(C)]
#[derive(Debug, Clone)]
pub struct WnodeEventItem {
    /// Header
    pub header: WnodeHeader,
}

/// WNODE_EVENT_REFERENCE - reference to event data
#[repr(C)]
#[derive(Debug, Clone)]
pub struct WnodeEventReference {
    /// Header
    pub header: WnodeHeader,
    /// Target GUID
    pub target_guid: Guid,
    /// Target data block size
    pub target_data_block_size: u32,
    /// Target instance index
    pub target_instance_index: u32,
}

/// WNODE_TOO_SMALL - returned when buffer is too small
#[repr(C)]
#[derive(Debug, Clone)]
pub struct WnodeTooSmall {
    /// Header
    pub header: WnodeHeader,
    /// Required size
    pub size_needed: u32,
}

// Data block flags
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct WmiDataBlockFlags: u32 {
        /// Data block is expensive to collect
        const EXPENSIVE = 0x00000001;
        /// Data block can be modified
        const WRITABLE = 0x00000002;
        /// Uses dynamic instance names
        const DYNAMIC_INSTANCE_NAMES = 0x00000004;
        /// Uses PDO instance names
        const PDO_INSTANCE_NAMES = 0x00000008;
        /// Data block generates events
        const EVENT_ONLY = 0x00000010;
        /// Has methods
        const HAS_METHODS = 0x00000020;
        /// Instance names from base name + index
        const INSTANCE_BASENAME = 0x00000040;
    }
}

/// Query callback type
pub type WmiQueryCallback = Box<dyn Fn(u32, &mut [u8]) -> Result<usize, WmiError> + Send + Sync>;

/// Set callback type
pub type WmiSetCallback = Box<dyn Fn(u32, &[u8]) -> Result<(), WmiError> + Send + Sync>;

/// Method callback type
pub type WmiMethodCallback =
    Box<dyn Fn(u32, u32, &[u8], &mut [u8]) -> Result<usize, WmiError> + Send + Sync>;

/// WMI data block registration
pub struct WmiDataBlock {
    /// GUID for this data block
    pub guid: Guid,
    /// Provider ID that owns this block
    pub provider_id: u32,
    /// Data block flags
    pub flags: WmiDataBlockFlags,
    /// Number of instances
    pub instance_count: u32,
    /// Instance name base (for INSTANCE_BASENAME)
    pub instance_base_name: String,
    /// Static instance names
    pub instance_names: Vec<String>,
    /// Data block size (if fixed)
    pub data_block_size: u32,
    /// Query callback
    pub query_callback: Option<WmiQueryCallback>,
    /// Set callback
    pub set_callback: Option<WmiSetCallback>,
    /// Method callback
    pub method_callback: Option<WmiMethodCallback>,
}

impl WmiDataBlock {
    /// Create a new data block registration
    pub fn new(guid: Guid, provider_id: u32) -> Self {
        Self {
            guid,
            provider_id,
            flags: WmiDataBlockFlags::empty(),
            instance_count: 1,
            instance_base_name: String::new(),
            instance_names: Vec::new(),
            data_block_size: 0,
            query_callback: None,
            set_callback: None,
            method_callback: None,
        }
    }

    /// Set the data block as writable
    pub fn writable(mut self) -> Self {
        self.flags |= WmiDataBlockFlags::WRITABLE;
        self
    }

    /// Set the data block as expensive to collect
    pub fn expensive(mut self) -> Self {
        self.flags |= WmiDataBlockFlags::EXPENSIVE;
        self
    }

    /// Set instance count
    pub fn with_instances(mut self, count: u32) -> Self {
        self.instance_count = count;
        self
    }

    /// Add static instance name
    pub fn with_instance_name(mut self, name: String) -> Self {
        self.instance_names.push(name);
        self
    }

    /// Set fixed data block size
    pub fn with_size(mut self, size: u32) -> Self {
        self.data_block_size = size;
        self
    }

    /// Set query callback
    pub fn with_query<F>(mut self, callback: F) -> Self
    where
        F: Fn(u32, &mut [u8]) -> Result<usize, WmiError> + Send + Sync + 'static,
    {
        self.query_callback = Some(Box::new(callback));
        self
    }

    /// Set set callback
    pub fn with_set<F>(mut self, callback: F) -> Self
    where
        F: Fn(u32, &[u8]) -> Result<(), WmiError> + Send + Sync + 'static,
    {
        self.set_callback = Some(Box::new(callback));
        self.flags |= WmiDataBlockFlags::WRITABLE;
        self
    }

    /// Set method callback
    pub fn with_method<F>(mut self, callback: F) -> Self
    where
        F: Fn(u32, u32, &[u8], &mut [u8]) -> Result<usize, WmiError> + Send + Sync + 'static,
    {
        self.method_callback = Some(Box::new(callback));
        self.flags |= WmiDataBlockFlags::HAS_METHODS;
        self
    }
}

impl core::fmt::Debug for WmiDataBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WmiDataBlock")
            .field("guid", &self.guid)
            .field("provider_id", &self.provider_id)
            .field("flags", &self.flags)
            .field("instance_count", &self.instance_count)
            .finish()
    }
}

/// MOF resource descriptor
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MofResourceInfo {
    /// Image path
    pub image_path: String,
    /// Resource name
    pub resource_name: String,
}

/// WMI registration info for a device
#[repr(C)]
#[derive(Debug, Clone)]
pub struct WmiRegInfo {
    /// Size of this structure
    pub buffer_size: u32,
    /// Next WmiRegInfo offset (0 if last)
    pub next_wmi_reg_info: u32,
    /// Registry path
    pub registry_path: u32,
    /// MOF resource name
    pub mof_resource_name: u32,
    /// Number of GUIDs
    pub guid_count: u32,
}

/// GUID registration info
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WmiGuidRegistrationInfo {
    /// GUID
    pub guid: Guid,
    /// Flags
    pub flags: u32,
    /// Instance count
    pub instance_count: u32,
    /// Instance name list or base name
    pub instance_name_list: u32,
}

/// WMI registration flags
#[allow(non_snake_case)]
pub mod WmiRegFlags {
    /// Register with expensive flag
    pub const EXPENSIVE: u32 = 0x00000001;
    /// Block generates trace events
    pub const TRACE_FLAG: u32 = 0x00010000;
    /// Block generates trace events
    pub const EVENT_ONLY_GUID: u32 = 0x00000040;
}
