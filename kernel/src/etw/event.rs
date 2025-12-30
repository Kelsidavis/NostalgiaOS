//! ETW Event Structures
//!
//! Defines event structures for trace logging.

use super::Guid;
use alloc::vec::Vec;

extern crate alloc;

/// WNODE header - base structure for all WMI/ETW data
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WnodeHeader {
    /// Size of entire buffer including header
    pub buffer_size: u32,
    /// Provider ID for routing
    pub provider_id: u32,
    /// Timestamp
    pub timestamp: u64,
    /// Provider GUID
    pub guid: Guid,
    /// Client context (clock type, etc.)
    pub client_context: u32,
    /// WNODE flags
    pub flags: WnodeFlags,
}

impl Default for WnodeHeader {
    fn default() -> Self {
        Self {
            buffer_size: core::mem::size_of::<WnodeHeader>() as u32,
            provider_id: 0,
            timestamp: 0,
            guid: Guid::zero(),
            client_context: 0,
            flags: WnodeFlags::empty(),
        }
    }
}

bitflags::bitflags! {
    /// WNODE flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct WnodeFlags: u32 {
        /// Event contains valid data
        const ALL_DATA = 0x00000001;
        /// Single instance
        const SINGLE_INSTANCE = 0x00000002;
        /// Single item
        const SINGLE_ITEM = 0x00000004;
        /// Event indication
        const EVENT_ITEM = 0x00000008;
        /// Fixed instance size
        const FIXED_INSTANCE_SIZE = 0x00000010;
        /// Too small buffer
        const TOO_SMALL = 0x00000020;
        /// Static instance names
        const STATIC_INSTANCE_NAMES = 0x00000040;
        /// PDO instance names
        const PDO_INSTANCE_NAMES = 0x00000080;
        /// Method call
        const METHOD_ITEM = 0x00000100;
        /// Uses GUID for routing
        const TRACED_GUID = 0x00020000;
        /// Log WNODE
        const LOG_WNODE = 0x00040000;
        /// Uses MOF names
        const USE_MOF_PTR = 0x00100000;
        /// Timestamp is valid
        const USE_TIMESTAMP = 0x00200000;
        /// Message format
        const NO_HEADER = 0x01000000;
        /// Send in real-time
        const SEND_DATA_BLOCK = 0x02000000;
        /// Versioned GUID
        const VERSIONED_PROPERTIES = 0x04000000;
    }
}

/// Event descriptor - identifies a specific event type
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EventDescriptor {
    /// Event ID
    pub id: u16,
    /// Event version
    pub version: u8,
    /// Event channel
    pub channel: u8,
    /// Event level (severity)
    pub level: u8,
    /// Event opcode
    pub opcode: u8,
    /// Event task
    pub task: u16,
    /// Event keyword (category flags)
    pub keyword: u64,
}

impl EventDescriptor {
    pub const fn new(id: u16, version: u8, level: EventLevel, opcode: EventOpcode) -> Self {
        Self {
            id,
            version,
            channel: 0,
            level: level as u8,
            opcode: opcode as u8,
            task: 0,
            keyword: 0,
        }
    }

    pub const fn with_keyword(mut self, keyword: u64) -> Self {
        self.keyword = keyword;
        self
    }

    pub const fn with_task(mut self, task: u16) -> Self {
        self.task = task;
        self
    }
}

/// Event level (severity)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EventLevel {
    /// Log always
    LogAlways = 0,
    /// Critical error
    Critical = 1,
    /// Error
    Error = 2,
    /// Warning
    Warning = 3,
    /// Informational
    #[default]
    Informational = 4,
    /// Verbose/debug
    Verbose = 5,
}

/// Event opcode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EventOpcode {
    /// No opcode
    #[default]
    Info = 0,
    /// Activity start
    Start = 1,
    /// Activity stop
    Stop = 2,
    /// Data collection start
    DataCollectionStart = 3,
    /// Data collection stop
    DataCollectionStop = 4,
    /// Extension
    Extension = 5,
    /// Reply
    Reply = 6,
    /// Resume
    Resume = 7,
    /// Suspend
    Suspend = 8,
    /// Send
    Send = 9,
    /// Receive
    Receive = 240,
}

/// Trace event header - full event with context
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TraceEventHeader {
    /// Size of this header + data
    pub size: u16,
    /// Header type
    pub header_type: u16,
    /// Event flags
    pub flags: TraceEventFlags,
    /// Event class (type + level)
    pub event_class: u32,
    /// Thread ID
    pub thread_id: u32,
    /// Process ID
    pub process_id: u32,
    /// Timestamp
    pub timestamp: u64,
    /// GUID
    pub guid: Guid,
    /// Kernel time
    pub kernel_time: u32,
    /// User time
    pub user_time: u32,
}

bitflags::bitflags! {
    /// Trace event flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct TraceEventFlags: u32 {
        /// Extended info present
        const EXTENDED_INFO = 0x0001;
        /// Private session
        const PRIVATE_SESSION = 0x0002;
        /// String only
        const STRING_ONLY = 0x0004;
        /// Trace message
        const TRACE_MESSAGE = 0x0008;
        /// No copy needed
        const NO_CPUTIME = 0x0010;
        /// 32-bit header
        const USE_HEADER_32 = 0x0020;
        /// Processor index
        const PROC_INDEX = 0x0040;
    }
}

/// Kernel event group for categorization
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelEventGroup {
    Process = 0,
    Thread = 1,
    DiskIo = 2,
    FileIo = 3,
    Registry = 4,
    Network = 5,
    PageFault = 6,
}

/// Kernel event type within a group
/// Note: Types are unique per group, not globally
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelEventSubtype {
    // Common subtypes
    Create = 1,
    Delete = 2,
    Start = 3,
    End = 4,
    Open = 5,
    Close = 6,
    Read = 10,
    Write = 11,
    Query = 13,
    SetValue = 14,
    Flush = 20,
    Send = 30,
    Receive = 31,
}

/// Process event data
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessEventData {
    /// Process ID
    pub process_id: u32,
    /// Parent process ID
    pub parent_id: u32,
    /// Session ID
    pub session_id: u32,
    /// Exit status
    pub exit_status: i32,
    /// Directory table base
    pub directory_table_base: u64,
    /// User SID length
    pub sid_length: u32,
    // Followed by: image filename, command line
}

/// Thread event data
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadEventData {
    /// Process ID
    pub process_id: u32,
    /// Thread ID
    pub thread_id: u32,
    /// Stack base
    pub stack_base: u64,
    /// Stack limit
    pub stack_limit: u64,
    /// User stack base
    pub user_stack_base: u64,
    /// User stack limit
    pub user_stack_limit: u64,
    /// Affinity
    pub affinity: u64,
    /// Win32 start address
    pub win32_start_addr: u64,
    /// TEB base
    pub teb_base: u64,
    /// Subsystem thread ID
    pub sub_process_tag: u32,
    /// Base priority
    pub base_priority: u8,
    /// Page priority
    pub page_priority: u8,
    /// I/O priority
    pub io_priority: u8,
    /// Thread flags
    pub thread_flags: u8,
}

/// Disk I/O event data
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DiskIoEventData {
    /// Disk number
    pub disk_number: u32,
    /// IRP flags
    pub irp_flags: u32,
    /// Transfer size
    pub transfer_size: u32,
    /// Reserved
    pub reserved: u32,
    /// Byte offset
    pub byte_offset: u64,
    /// File object
    pub file_object: u64,
    /// IRP
    pub irp: u64,
    /// High resolution response time
    pub high_res_response_time: u64,
    /// Issuing thread ID
    pub issuing_thread_id: u32,
}

/// Page fault event data
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PageFaultEventData {
    /// Virtual address
    pub virtual_address: u64,
    /// Program counter
    pub program_counter: u64,
}

/// Builder for trace events
pub struct EventBuilder {
    header: TraceEventHeader,
    data: Vec<u8>,
}

impl EventBuilder {
    /// Create a new event builder
    pub fn new(guid: Guid, event_type: u8, level: EventLevel) -> Self {
        Self {
            header: TraceEventHeader {
                size: core::mem::size_of::<TraceEventHeader>() as u16,
                header_type: 0,
                flags: TraceEventFlags::empty(),
                event_class: (event_type as u32) | ((level as u32) << 8),
                thread_id: 0,
                process_id: 0,
                timestamp: crate::hal::rtc::get_system_time(),
                guid,
                kernel_time: 0,
                user_time: 0,
            },
            data: Vec::new(),
        }
    }

    /// Set thread/process context
    pub fn with_context(mut self, thread_id: u32, process_id: u32) -> Self {
        self.header.thread_id = thread_id;
        self.header.process_id = process_id;
        self
    }

    /// Add raw data
    pub fn with_data(mut self, data: &[u8]) -> Self {
        self.data.extend_from_slice(data);
        self.header.size += data.len() as u16;
        self
    }

    /// Add a typed value
    pub fn with_value<T: Copy>(mut self, value: &T) -> Self {
        let bytes = unsafe {
            core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
        };
        self.data.extend_from_slice(bytes);
        self.header.size += core::mem::size_of::<T>() as u16;
        self
    }

    /// Build into WNODE header for logging
    pub fn build(self) -> WnodeHeader {
        WnodeHeader {
            buffer_size: self.header.size as u32,
            provider_id: 0,
            timestamp: self.header.timestamp,
            guid: self.header.guid,
            client_context: 0,
            flags: WnodeFlags::TRACED_GUID | WnodeFlags::USE_TIMESTAMP,
        }
    }
}
