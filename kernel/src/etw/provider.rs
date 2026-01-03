//! ETW Trace Provider Management
//!
//! Manages trace providers that generate events.

use super::Guid;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Provider handle (opaque)
pub type ProviderHandle = u64;

/// Provider enable callback type
pub type ProviderEnableCallback = fn(guid: &Guid, is_enable: bool, level: u8, match_any: u64, match_all: u64, context: usize);

/// Next provider handle
static NEXT_PROVIDER_HANDLE: AtomicU64 = AtomicU64::new(1);

/// Trace provider - a component that generates trace events
pub struct TraceProvider {
    /// Provider GUID
    guid: Guid,
    /// Provider handle
    handle: ProviderHandle,
    /// Is provider enabled
    enabled: AtomicBool,
    /// Enable level
    level: AtomicU8,
    /// Enable match-any keywords
    match_any_keyword: AtomicU64,
    /// Enable match-all keywords
    match_all_keyword: AtomicU64,
    /// Enable callback
    callback: Option<ProviderEnableCallback>,
    /// Callback context
    callback_context: usize,
    /// Events generated
    events_generated: AtomicU64,
}

/// Atomic u8 wrapper
struct AtomicU8(core::sync::atomic::AtomicU8);

impl AtomicU8 {
    const fn new(val: u8) -> Self {
        Self(core::sync::atomic::AtomicU8::new(val))
    }

    fn load(&self, order: Ordering) -> u8 {
        self.0.load(order)
    }

    fn store(&self, val: u8, order: Ordering) {
        self.0.store(val, order)
    }
}

impl TraceProvider {
    /// Create a new trace provider
    pub fn new(guid: Guid, callback: ProviderEnableCallback, context: usize) -> Self {
        let handle = NEXT_PROVIDER_HANDLE.fetch_add(1, Ordering::SeqCst);

        Self {
            guid,
            handle,
            enabled: AtomicBool::new(false),
            level: AtomicU8::new(0),
            match_any_keyword: AtomicU64::new(0),
            match_all_keyword: AtomicU64::new(0),
            callback: Some(callback),
            callback_context: context,
            events_generated: AtomicU64::new(0),
        }
    }

    /// Get provider GUID
    pub fn guid(&self) -> Guid {
        self.guid
    }

    /// Get provider handle
    pub fn handle(&self) -> ProviderHandle {
        self.handle
    }

    /// Check if provider is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Check if provider is enabled for a specific level and keyword
    pub fn is_enabled_for(&self, level: u8, keyword: u64) -> bool {
        if !self.is_enabled() {
            return false;
        }

        let provider_level = self.level.load(Ordering::SeqCst);
        if level > provider_level {
            return false;
        }

        let match_any = self.match_any_keyword.load(Ordering::SeqCst);
        let match_all = self.match_all_keyword.load(Ordering::SeqCst);

        // Check keyword matching
        if match_any != 0 && (keyword & match_any) == 0 {
            return false;
        }

        if match_all != 0 && (keyword & match_all) != match_all {
            return false;
        }

        true
    }

    /// Enable the provider
    pub fn enable(&self, level: u8, match_any: u64, match_all: u64) {
        self.level.store(level, Ordering::SeqCst);
        self.match_any_keyword.store(match_any, Ordering::SeqCst);
        self.match_all_keyword.store(match_all, Ordering::SeqCst);
        self.enabled.store(true, Ordering::SeqCst);

        // Invoke callback
        if let Some(callback) = self.callback {
            callback(&self.guid, true, level, match_any, match_all, self.callback_context);
        }
    }

    /// Disable the provider
    pub fn disable(&self) {
        let was_enabled = self.enabled.swap(false, Ordering::SeqCst);

        if was_enabled {
            if let Some(callback) = self.callback {
                callback(&self.guid, false, 0, 0, 0, self.callback_context);
            }
        }
    }

    /// Get enable level
    pub fn level(&self) -> u8 {
        self.level.load(Ordering::SeqCst)
    }

    /// Get match-any keywords
    pub fn match_any_keyword(&self) -> u64 {
        self.match_any_keyword.load(Ordering::SeqCst)
    }

    /// Get match-all keywords
    pub fn match_all_keyword(&self) -> u64 {
        self.match_all_keyword.load(Ordering::SeqCst)
    }

    /// Increment event counter
    pub fn record_event(&self) {
        self.events_generated.fetch_add(1, Ordering::SeqCst);
    }

    /// Get events generated count
    pub fn events_generated(&self) -> u64 {
        self.events_generated.load(Ordering::SeqCst)
    }
}

impl core::fmt::Debug for TraceProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TraceProvider")
            .field("guid", &self.guid)
            .field("handle", &self.handle)
            .field("enabled", &self.is_enabled())
            .field("level", &self.level.load(Ordering::SeqCst))
            .field("events", &self.events_generated.load(Ordering::SeqCst))
            .finish()
    }
}

/// Provider registration information
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ProviderRegistration {
    /// Provider GUID
    pub guid: Guid,
    /// Provider name
    pub name: [u16; 256],
    /// Is registered
    pub is_registered: bool,
    /// Is enabled
    pub is_enabled: bool,
    /// Enable level
    pub level: u8,
}

impl Default for ProviderRegistration {
    fn default() -> Self {
        Self {
            guid: Guid::zero(),
            name: [0u16; 256],
            is_registered: false,
            is_enabled: false,
            level: 0,
        }
    }
}

/// Kernel provider - generates kernel trace events
pub struct KernelProvider {
    /// Base provider
    inner: TraceProvider,
    /// Kernel trace flags
    flags: AtomicU32,
}

/// Kernel trace flags (GROUP_MASK)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelTraceFlag {
    /// Process events
    Process = 0x00000001,
    /// Thread events
    Thread = 0x00000002,
    /// Image load events
    ImageLoad = 0x00000004,
    /// Disk I/O events
    DiskIo = 0x00000100,
    /// Disk file I/O name events
    DiskFileIo = 0x00000200,
    /// Page faults
    PageFault = 0x00001000,
    /// Hard page faults
    HardFault = 0x00002000,
    /// Network events
    Network = 0x00010000,
    /// Registry events
    Registry = 0x00020000,
    /// Driver events
    DbgPrint = 0x00040000,
    /// Job events
    Job = 0x00080000,
    /// ALPC events
    Alpc = 0x00100000,
    /// Split I/O events
    SplitIo = 0x00200000,
    /// Pool events
    Pool = 0x00400000,
    /// Context switch events
    ContextSwitch = 0x01000000,
    /// Interrupt events
    Interrupt = 0x02000000,
    /// DPC events
    Dpc = 0x04000000,
    /// Power events
    Power = 0x08000000,
    /// Syscall events
    Syscall = 0x10000000,
    /// Object events
    Object = 0x20000000,
    /// Handle events
    Handle = 0x40000000,
    /// Heap events
    Heap = 0x80000000,
}

impl KernelProvider {
    /// Create a new kernel provider
    pub fn new() -> Self {
        fn kernel_callback(_guid: &Guid, _is_enable: bool, _level: u8, _match_any: u64, _match_all: u64, _context: usize) {
            // Kernel provider callback - update tracing state
        }

        Self {
            inner: TraceProvider::new(
                super::providers::KERNEL_PROCESS, // Use process GUID as base
                kernel_callback,
                0,
            ),
            flags: AtomicU32::new(0),
        }
    }

    /// Get trace flags
    pub fn flags(&self) -> u32 {
        self.flags.load(Ordering::SeqCst)
    }

    /// Set trace flags
    pub fn set_flags(&self, flags: u32) {
        self.flags.store(flags, Ordering::SeqCst);
    }

    /// Check if a specific trace is enabled
    pub fn is_trace_enabled(&self, flag: KernelTraceFlag) -> bool {
        (self.flags() & (flag as u32)) != 0
    }

    /// Enable a specific trace
    pub fn enable_trace(&self, flag: KernelTraceFlag) {
        let old = self.flags.load(Ordering::SeqCst);
        self.flags.store(old | (flag as u32), Ordering::SeqCst);
    }

    /// Disable a specific trace
    pub fn disable_trace(&self, flag: KernelTraceFlag) {
        let old = self.flags.load(Ordering::SeqCst);
        self.flags.store(old & !(flag as u32), Ordering::SeqCst);
    }
}

impl Default for KernelProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// MOF (Managed Object Format) class description
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MofClassInfo {
    /// Class GUID
    pub guid: Guid,
    /// Class name (null-terminated)
    pub name: [u16; 64],
    /// Number of properties
    pub property_count: u32,
    /// Flags
    pub flags: u32,
}

impl Default for MofClassInfo {
    fn default() -> Self {
        Self {
            guid: Guid::zero(),
            name: [0u16; 64],
            property_count: 0,
            flags: 0,
        }
    }
}

/// MOF property description
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MofPropertyInfo {
    /// Property name (null-terminated)
    pub name: [u16; 64],
    /// Property type
    pub property_type: MofPropertyType,
    /// Property qualifier
    pub qualifier: u32,
    /// Offset in data block
    pub offset: u32,
}

/// MOF property types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MofPropertyType {
    /// Boolean
    #[default]
    Boolean = 0,
    /// Signed 8-bit integer
    Sint8 = 1,
    /// Unsigned 8-bit integer
    Uint8 = 2,
    /// Signed 16-bit integer
    Sint16 = 3,
    /// Unsigned 16-bit integer
    Uint16 = 4,
    /// Signed 32-bit integer
    Sint32 = 5,
    /// Unsigned 32-bit integer
    Uint32 = 6,
    /// Signed 64-bit integer
    Sint64 = 7,
    /// Unsigned 64-bit integer
    Uint64 = 8,
    /// 32-bit floating point
    Real32 = 9,
    /// 64-bit floating point
    Real64 = 10,
    /// String
    String = 11,
    /// Datetime
    Datetime = 12,
    /// GUID
    Guid = 13,
    /// Binary data
    Binary = 14,
    /// Pointer
    Pointer = 15,
    /// SID (Security Identifier)
    Sid = 16,
}
