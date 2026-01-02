//! Mini-Filter Manager (FLTMGR)
//!
//! Provides a simplified framework for file system filter drivers.
//! Mini-filters register callback routines for file system operations
//! and are ordered by altitude (priority).
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    User Application                          │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Filter Manager                            │
//! │  ┌─────────────────────────────────────────────────────────┐│
//! │  │  MiniFilter A (Altitude 389900) - Anti-Virus           ││
//! │  └─────────────────────────────────────────────────────────┘│
//! │  ┌─────────────────────────────────────────────────────────┐│
//! │  │  MiniFilter B (Altitude 320000) - Encryption           ││
//! │  └─────────────────────────────────────────────────────────┘│
//! │  ┌─────────────────────────────────────────────────────────┐│
//! │  │  MiniFilter C (Altitude 180000) - Quota                ││
//! │  └─────────────────────────────────────────────────────────┘│
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    File System (NTFS/FAT)                    │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Altitude Ranges
//!
//! - 420000-429999: Filter (Top level)
//! - 400000-409999: FSFilter Top
//! - 360000-389999: FSFilter Anti-Virus
//! - 340000-349999: FSFilter Replication
//! - 320000-329999: FSFilter Continuous Backup
//! - 300000-309999: FSFilter Content Screener
//! - 260000-269999: FSFilter Quota Management
//! - 240000-249999: FSFilter System Recovery
//! - 220000-229999: FSFilter Cluster File System
//! - 180000-189999: FSFilter HSM
//! - 140000-149999: FSFilter Compression
//! - 100000-109999: FSFilter Encryption
//! - 80000-89999: FSFilter Virtualization
//! - 60000-69999: FSFilter Physical Quota
//! - 40000-49999: FSFilter Open File
//! - 20000-29999: FSFilter Security Enhancer
//!
//! # References
//!
//! Based on Windows Filter Manager concepts (post-Windows Server 2003)

extern crate alloc;

use crate::ke::spinlock::SpinLock;
use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum registered mini-filters
pub const MAX_MINIFILTERS: usize = 32;

/// Maximum filter instances
pub const MAX_INSTANCES: usize = 128;

/// Maximum callback operations
pub const MAX_CALLBACKS: usize = 32;

/// Communication port buffer size
pub const PORT_BUFFER_SIZE: usize = 4096;

// ============================================================================
// Callback Operation Types
// ============================================================================

/// Filter callback operation major function
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FltOperation {
    /// No operation
    #[default]
    None = 0,
    /// Create (IRP_MJ_CREATE)
    Create = 1,
    /// Close (IRP_MJ_CLOSE)
    Close = 2,
    /// Read (IRP_MJ_READ)
    Read = 3,
    /// Write (IRP_MJ_WRITE)
    Write = 4,
    /// Query information (IRP_MJ_QUERY_INFORMATION)
    QueryInformation = 5,
    /// Set information (IRP_MJ_SET_INFORMATION)
    SetInformation = 6,
    /// Query EA (IRP_MJ_QUERY_EA)
    QueryEa = 7,
    /// Set EA (IRP_MJ_SET_EA)
    SetEa = 8,
    /// Flush buffers (IRP_MJ_FLUSH_BUFFERS)
    FlushBuffers = 9,
    /// Query volume information (IRP_MJ_QUERY_VOLUME_INFORMATION)
    QueryVolumeInformation = 10,
    /// Set volume information (IRP_MJ_SET_VOLUME_INFORMATION)
    SetVolumeInformation = 11,
    /// Directory control (IRP_MJ_DIRECTORY_CONTROL)
    DirectoryControl = 12,
    /// File system control (IRP_MJ_FILE_SYSTEM_CONTROL)
    FileSystemControl = 13,
    /// Device control (IRP_MJ_DEVICE_CONTROL)
    DeviceControl = 14,
    /// Shutdown (IRP_MJ_SHUTDOWN)
    Shutdown = 15,
    /// Lock control (IRP_MJ_LOCK_CONTROL)
    LockControl = 16,
    /// Cleanup (IRP_MJ_CLEANUP)
    Cleanup = 17,
    /// Query security (IRP_MJ_QUERY_SECURITY)
    QuerySecurity = 18,
    /// Set security (IRP_MJ_SET_SECURITY)
    SetSecurity = 19,
    /// PnP (IRP_MJ_PNP)
    Pnp = 20,
    /// Acquire for section sync
    AcquireForSectionSync = 21,
    /// Release for section sync
    ReleaseForSectionSync = 22,
    /// Acquire for mod write
    AcquireForModWrite = 23,
    /// Release for mod write
    ReleaseForModWrite = 24,
    /// Acquire for cc flush
    AcquireForCcFlush = 25,
    /// Release for cc flush
    ReleaseForCcFlush = 26,
    /// Fast I/O check
    FastIoCheck = 27,
    /// Network query open
    NetworkQueryOpen = 28,
    /// MDL read
    MdlRead = 29,
    /// MDL read complete
    MdlReadComplete = 30,
    /// MDL write
    MdlWrite = 31,
}

impl FltOperation {
    /// Get operation name
    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Create => "Create",
            Self::Close => "Close",
            Self::Read => "Read",
            Self::Write => "Write",
            Self::QueryInformation => "QueryInformation",
            Self::SetInformation => "SetInformation",
            Self::QueryEa => "QueryEa",
            Self::SetEa => "SetEa",
            Self::FlushBuffers => "FlushBuffers",
            Self::QueryVolumeInformation => "QueryVolumeInformation",
            Self::SetVolumeInformation => "SetVolumeInformation",
            Self::DirectoryControl => "DirectoryControl",
            Self::FileSystemControl => "FileSystemControl",
            Self::DeviceControl => "DeviceControl",
            Self::Shutdown => "Shutdown",
            Self::LockControl => "LockControl",
            Self::Cleanup => "Cleanup",
            Self::QuerySecurity => "QuerySecurity",
            Self::SetSecurity => "SetSecurity",
            Self::Pnp => "Pnp",
            Self::AcquireForSectionSync => "AcquireForSectionSync",
            Self::ReleaseForSectionSync => "ReleaseForSectionSync",
            Self::AcquireForModWrite => "AcquireForModWrite",
            Self::ReleaseForModWrite => "ReleaseForModWrite",
            Self::AcquireForCcFlush => "AcquireForCcFlush",
            Self::ReleaseForCcFlush => "ReleaseForCcFlush",
            Self::FastIoCheck => "FastIoCheck",
            Self::NetworkQueryOpen => "NetworkQueryOpen",
            Self::MdlRead => "MdlRead",
            Self::MdlReadComplete => "MdlReadComplete",
            Self::MdlWrite => "MdlWrite",
        }
    }
}

// ============================================================================
// Callback Return Status
// ============================================================================

/// Pre-operation callback return status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FltPreopCallbackStatus {
    /// Success, continue processing
    #[default]
    Success = 0,
    /// Pending, will complete later
    Pending = 1,
    /// Disallow fastio, use normal path
    DisallowFastio = 2,
    /// Complete the operation (skip further processing)
    Complete = 3,
    /// Synchronize (wait for post-op)
    Synchronize = 4,
}

/// Post-operation callback return status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FltPostopCallbackStatus {
    /// Finished processing
    #[default]
    FinishedProcessing = 0,
    /// More processing required
    MoreProcessingRequired = 1,
}

// ============================================================================
// Callback Data
// ============================================================================

/// Filter callback data (passed to callbacks)
#[derive(Clone)]
pub struct FltCallbackData {
    /// Operation being performed
    pub operation: FltOperation,
    /// Target file path
    pub file_path: [u8; 260],
    /// File path length
    pub file_path_len: usize,
    /// I/O parameters (operation-specific)
    pub io_params: FltIoParams,
    /// I/O status
    pub io_status: i32,
    /// Information (bytes transferred)
    pub information: usize,
    /// Requestor process ID
    pub requestor_pid: u32,
    /// Is this a paging I/O
    pub paging_io: bool,
    /// Is this a cached I/O
    pub cached_io: bool,
    /// Caller's flags
    pub flags: u32,
}

impl FltCallbackData {
    /// Create empty callback data
    pub const fn empty() -> Self {
        Self {
            operation: FltOperation::None,
            file_path: [0; 260],
            file_path_len: 0,
            io_params: FltIoParams::empty(),
            io_status: 0,
            information: 0,
            requestor_pid: 0,
            paging_io: false,
            cached_io: false,
            flags: 0,
        }
    }

    /// Get file path as string
    pub fn file_path_str(&self) -> &str {
        core::str::from_utf8(&self.file_path[..self.file_path_len]).unwrap_or("")
    }

    /// Set file path
    pub fn set_file_path(&mut self, path: &str) {
        let bytes = path.as_bytes();
        let len = bytes.len().min(259);
        self.file_path[..len].copy_from_slice(&bytes[..len]);
        self.file_path_len = len;
    }
}

impl Default for FltCallbackData {
    fn default() -> Self {
        Self::empty()
    }
}

/// I/O parameters (union-like for different operations)
#[derive(Clone, Copy)]
pub struct FltIoParams {
    /// For read/write: offset
    pub offset: u64,
    /// For read/write: length
    pub length: u32,
    /// For create: access mask
    pub access_mask: u32,
    /// For create: share access
    pub share_access: u32,
    /// For create: disposition
    pub disposition: u32,
    /// For create: options
    pub options: u32,
    /// Generic parameter 1
    pub param1: usize,
    /// Generic parameter 2
    pub param2: usize,
}

impl FltIoParams {
    pub const fn empty() -> Self {
        Self {
            offset: 0,
            length: 0,
            access_mask: 0,
            share_access: 0,
            disposition: 0,
            options: 0,
            param1: 0,
            param2: 0,
        }
    }
}

impl Default for FltIoParams {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Callback Function Types
// ============================================================================

/// Pre-operation callback function
pub type FltPreOperationCallback = fn(
    data: &mut FltCallbackData,
    filter: &FltFilter,
    context: usize,
) -> FltPreopCallbackStatus;

/// Post-operation callback function
pub type FltPostOperationCallback = fn(
    data: &mut FltCallbackData,
    filter: &FltFilter,
    context: usize,
    status: FltPreopCallbackStatus,
) -> FltPostopCallbackStatus;

/// Operation callback registration
#[derive(Clone, Copy)]
pub struct FltOperationCallback {
    /// Operation type
    pub operation: FltOperation,
    /// Pre-operation callback (optional)
    pub pre_callback: Option<FltPreOperationCallback>,
    /// Post-operation callback (optional)
    pub post_callback: Option<FltPostOperationCallback>,
    /// Flags
    pub flags: u32,
}

impl FltOperationCallback {
    pub const fn empty() -> Self {
        Self {
            operation: FltOperation::None,
            pre_callback: None,
            post_callback: None,
            flags: 0,
        }
    }
}

impl Default for FltOperationCallback {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Filter Registration
// ============================================================================

/// Filter registration structure
#[derive(Clone)]
pub struct FltRegistration {
    /// Filter name
    pub name: [u8; 64],
    /// Filter name length
    pub name_len: usize,
    /// Filter altitude (priority)
    pub altitude: u32,
    /// Filter flags
    pub flags: u32,
    /// Operation callbacks
    pub callbacks: [FltOperationCallback; MAX_CALLBACKS],
    /// Number of callbacks
    pub callback_count: usize,
    /// Instance setup callback
    pub instance_setup: Option<fn(&FltInstance) -> bool>,
    /// Instance teardown callback
    pub instance_teardown: Option<fn(&FltInstance)>,
    /// Filter unload callback
    pub filter_unload: Option<fn(&FltFilter)>,
}

impl FltRegistration {
    /// Create empty registration
    pub const fn empty() -> Self {
        Self {
            name: [0; 64],
            name_len: 0,
            altitude: 0,
            flags: 0,
            callbacks: [const { FltOperationCallback::empty() }; MAX_CALLBACKS],
            callback_count: 0,
            instance_setup: None,
            instance_teardown: None,
            filter_unload: None,
        }
    }

    /// Set filter name
    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(63);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name_len = len;
    }

    /// Get name as string
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }

    /// Add operation callback
    pub fn add_callback(
        &mut self,
        operation: FltOperation,
        pre: Option<FltPreOperationCallback>,
        post: Option<FltPostOperationCallback>,
    ) -> bool {
        if self.callback_count >= MAX_CALLBACKS {
            return false;
        }

        self.callbacks[self.callback_count] = FltOperationCallback {
            operation,
            pre_callback: pre,
            post_callback: post,
            flags: 0,
        };
        self.callback_count += 1;
        true
    }
}

impl Default for FltRegistration {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Filter Object
// ============================================================================

/// Mini-filter object
pub struct FltFilter {
    /// Filter is registered
    pub registered: bool,
    /// Filter ID
    pub filter_id: u32,
    /// Filter registration
    pub registration: FltRegistration,
    /// Reference count
    pub ref_count: AtomicU32,
    /// Number of instances
    pub instance_count: u32,
    /// Operations intercepted
    pub ops_intercepted: AtomicU64,
    /// Operations blocked
    pub ops_blocked: AtomicU64,
}

impl FltFilter {
    /// Create empty filter
    pub const fn empty() -> Self {
        Self {
            registered: false,
            filter_id: 0,
            registration: FltRegistration::empty(),
            ref_count: AtomicU32::new(0),
            instance_count: 0,
            ops_intercepted: AtomicU64::new(0),
            ops_blocked: AtomicU64::new(0),
        }
    }

    /// Get filter name
    pub fn name(&self) -> &str {
        self.registration.name_str()
    }

    /// Get altitude
    pub fn altitude(&self) -> u32 {
        self.registration.altitude
    }

    /// Find callback for operation
    pub fn get_callback(&self, op: FltOperation) -> Option<&FltOperationCallback> {
        for cb in self.registration.callbacks.iter().take(self.registration.callback_count) {
            if cb.operation == op {
                return Some(cb);
            }
        }
        None
    }
}

impl Default for FltFilter {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Filter Instance
// ============================================================================

/// Filter instance (attached to a volume)
#[derive(Clone)]
pub struct FltInstance {
    /// Instance is active
    pub active: bool,
    /// Instance ID
    pub instance_id: u32,
    /// Filter ID this instance belongs to
    pub filter_id: u32,
    /// Volume name
    pub volume_name: [u8; 64],
    /// Volume name length
    pub volume_name_len: usize,
    /// Instance context (user data)
    pub context: usize,
    /// Instance flags
    pub flags: u32,
}

impl FltInstance {
    /// Create empty instance
    pub const fn empty() -> Self {
        Self {
            active: false,
            instance_id: 0,
            filter_id: 0,
            volume_name: [0; 64],
            volume_name_len: 0,
            context: 0,
            flags: 0,
        }
    }

    /// Get volume name as string
    pub fn volume_name_str(&self) -> &str {
        core::str::from_utf8(&self.volume_name[..self.volume_name_len]).unwrap_or("")
    }

    /// Set volume name
    pub fn set_volume_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(63);
        self.volume_name[..len].copy_from_slice(&bytes[..len]);
        self.volume_name_len = len;
    }
}

impl Default for FltInstance {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Communication Port
// ============================================================================

/// Filter communication port (for user-mode communication)
#[derive(Clone)]
pub struct FltPort {
    /// Port is active
    pub active: bool,
    /// Port ID
    pub port_id: u32,
    /// Filter ID that owns this port
    pub filter_id: u32,
    /// Port name
    pub port_name: [u8; 64],
    /// Port name length
    pub port_name_len: usize,
    /// Message buffer
    pub buffer: [u8; PORT_BUFFER_SIZE],
    /// Pending message length
    pub pending_len: usize,
    /// Connect callback
    pub connect_callback: Option<fn(port_id: u32) -> bool>,
    /// Disconnect callback
    pub disconnect_callback: Option<fn(port_id: u32)>,
    /// Message callback
    pub message_callback: Option<fn(port_id: u32, msg: &[u8]) -> Option<Vec<u8>>>,
}

impl FltPort {
    /// Create empty port
    pub const fn empty() -> Self {
        Self {
            active: false,
            port_id: 0,
            filter_id: 0,
            port_name: [0; 64],
            port_name_len: 0,
            buffer: [0; PORT_BUFFER_SIZE],
            pending_len: 0,
            connect_callback: None,
            disconnect_callback: None,
            message_callback: None,
        }
    }

    /// Get port name as string
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.port_name[..self.port_name_len]).unwrap_or("")
    }

    /// Set port name
    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(63);
        self.port_name[..len].copy_from_slice(&bytes[..len]);
        self.port_name_len = len;
    }
}

impl Default for FltPort {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Filter Manager State
// ============================================================================

/// Filter manager state
struct FltMgrState {
    /// Registered filters
    filters: [FltFilter; MAX_MINIFILTERS],
    /// Filter instances
    instances: [FltInstance; MAX_INSTANCES],
    /// Communication ports
    ports: [FltPort; 16],
    /// Next filter ID
    next_filter_id: u32,
    /// Next instance ID
    next_instance_id: u32,
    /// Next port ID
    next_port_id: u32,
    /// Is initialized
    initialized: bool,
}

impl FltMgrState {
    const fn new() -> Self {
        Self {
            filters: [const { FltFilter::empty() }; MAX_MINIFILTERS],
            instances: [const { FltInstance::empty() }; MAX_INSTANCES],
            ports: [const { FltPort::empty() }; 16],
            next_filter_id: 1,
            next_instance_id: 1,
            next_port_id: 1,
            initialized: false,
        }
    }
}

static FLTMGR_STATE: SpinLock<FltMgrState> = SpinLock::new(FltMgrState::new());

// ============================================================================
// Filter Registration API
// ============================================================================

/// Register a mini-filter
pub fn flt_register_filter(registration: &FltRegistration) -> Option<u32> {
    let mut state = FLTMGR_STATE.lock();
    let filter_id = state.next_filter_id;

    // Find free slot
    let mut found_slot = None;
    for idx in 0..MAX_MINIFILTERS {
        if !state.filters[idx].registered {
            state.filters[idx].registered = true;
            state.filters[idx].filter_id = filter_id;
            state.filters[idx].registration = registration.clone();
            state.filters[idx].ref_count = AtomicU32::new(1);
            state.filters[idx].instance_count = 0;
            found_slot = Some(idx);
            break;
        }
    }

    if found_slot.is_some() {
        crate::serial_println!(
            "[FLTMGR] Registered filter '{}' (ID={}, altitude={})",
            registration.name_str(),
            filter_id,
            registration.altitude
        );
        state.next_filter_id += 1;
        Some(filter_id)
    } else {
        None
    }
}

/// Unregister a mini-filter
pub fn flt_unregister_filter(filter_id: u32) -> bool {
    let mut state = FLTMGR_STATE.lock();

    // Find the filter
    let mut found_idx = None;
    for idx in 0..MAX_MINIFILTERS {
        if state.filters[idx].registered && state.filters[idx].filter_id == filter_id {
            found_idx = Some(idx);
            break;
        }
    }

    if let Some(idx) = found_idx {
        // Call unload callback
        if let Some(unload) = state.filters[idx].registration.filter_unload {
            // Safety: We need a pointer to call the callback
            let filter_ptr = &mut state.filters[idx] as *mut FltFilter;
            unload(unsafe { &mut *filter_ptr });
        }

        let name = String::from(state.filters[idx].registration.name_str());

        // Detach all instances
        for inst_idx in 0..MAX_INSTANCES {
            if state.instances[inst_idx].active && state.instances[inst_idx].filter_id == filter_id {
                state.instances[inst_idx].active = false;
            }
        }

        state.filters[idx] = FltFilter::empty();

        crate::serial_println!("[FLTMGR] Unregistered filter '{}'", name);
        true
    } else {
        false
    }
}

/// Start filtering (activate filter)
pub fn flt_start_filtering(filter_id: u32) -> bool {
    let state = FLTMGR_STATE.lock();

    for filter in state.filters.iter() {
        if filter.registered && filter.filter_id == filter_id {
            crate::serial_println!("[FLTMGR] Started filtering for '{}'", filter.name());
            return true;
        }
    }

    false
}

// ============================================================================
// Instance Management API
// ============================================================================

/// Attach filter instance to volume
pub fn flt_attach_volume(filter_id: u32, volume_name: &str) -> Option<u32> {
    let mut state = FLTMGR_STATE.lock();

    // Verify filter exists and find its index
    let mut filter_idx = None;
    for idx in 0..MAX_MINIFILTERS {
        if state.filters[idx].registered && state.filters[idx].filter_id == filter_id {
            filter_idx = Some(idx);
            break;
        }
    }
    let filter_idx = filter_idx?;

    let instance_id = state.next_instance_id;

    // Find free instance slot
    let mut instance_idx = None;
    for idx in 0..MAX_INSTANCES {
        if !state.instances[idx].active {
            state.instances[idx].active = true;
            state.instances[idx].instance_id = instance_id;
            state.instances[idx].filter_id = filter_id;
            state.instances[idx].set_volume_name(volume_name);
            state.instances[idx].context = 0;
            state.instances[idx].flags = 0;
            instance_idx = Some(idx);
            break;
        }
    }

    if let Some(inst_idx) = instance_idx {
        state.filters[filter_idx].instance_count += 1;

        // Call instance setup callback
        if let Some(setup) = state.filters[filter_idx].registration.instance_setup {
            let instance_ptr = &mut state.instances[inst_idx] as *mut FltInstance;
            if !setup(unsafe { &mut *instance_ptr }) {
                state.instances[inst_idx].active = false;
                state.filters[filter_idx].instance_count -= 1;
                return None;
            }
        }

        crate::serial_println!(
            "[FLTMGR] Attached filter {} to volume '{}' (instance {})",
            filter_id,
            volume_name,
            instance_id
        );

        state.next_instance_id += 1;
        Some(instance_id)
    } else {
        None
    }
}

/// Detach filter instance from volume
pub fn flt_detach_volume(instance_id: u32) -> bool {
    let mut state = FLTMGR_STATE.lock();

    // Find the instance
    let mut instance_idx = None;
    for idx in 0..MAX_INSTANCES {
        if state.instances[idx].active && state.instances[idx].instance_id == instance_id {
            instance_idx = Some(idx);
            break;
        }
    }

    if let Some(inst_idx) = instance_idx {
        let filter_id = state.instances[inst_idx].filter_id;
        let volume_name = String::from(state.instances[inst_idx].volume_name_str());

        // Find the filter and call teardown callback
        for flt_idx in 0..MAX_MINIFILTERS {
            if state.filters[flt_idx].registered && state.filters[flt_idx].filter_id == filter_id {
                if let Some(teardown) = state.filters[flt_idx].registration.instance_teardown {
                    let instance_ptr = &mut state.instances[inst_idx] as *mut FltInstance;
                    teardown(unsafe { &mut *instance_ptr });
                }
                state.filters[flt_idx].instance_count = state.filters[flt_idx].instance_count.saturating_sub(1);
                break;
            }
        }

        crate::serial_println!(
            "[FLTMGR] Detached instance {} from volume '{}'",
            instance_id,
            volume_name
        );

        state.instances[inst_idx].active = false;
        true
    } else {
        false
    }
}

// ============================================================================
// Communication Port API
// ============================================================================

/// Create communication port
pub fn flt_create_communication_port(
    filter_id: u32,
    port_name: &str,
    connect: Option<fn(u32) -> bool>,
    disconnect: Option<fn(u32)>,
    message: Option<fn(u32, &[u8]) -> Option<Vec<u8>>>,
) -> Option<u32> {
    let mut state = FLTMGR_STATE.lock();

    // Verify filter exists
    let mut filter_exists = false;
    for idx in 0..MAX_MINIFILTERS {
        if state.filters[idx].registered && state.filters[idx].filter_id == filter_id {
            filter_exists = true;
            break;
        }
    }
    if !filter_exists {
        return None;
    }

    let port_id = state.next_port_id;

    // Find free port slot
    let mut found_slot = None;
    for idx in 0..MAX_CALLBACKS {
        if !state.ports[idx].active {
            state.ports[idx].active = true;
            state.ports[idx].port_id = port_id;
            state.ports[idx].filter_id = filter_id;
            state.ports[idx].set_name(port_name);
            state.ports[idx].connect_callback = connect;
            state.ports[idx].disconnect_callback = disconnect;
            state.ports[idx].message_callback = message;
            found_slot = Some(idx);
            break;
        }
    }

    if found_slot.is_some() {
        crate::serial_println!(
            "[FLTMGR] Created communication port '{}' (ID={})",
            port_name,
            port_id
        );
        state.next_port_id += 1;
        Some(port_id)
    } else {
        None
    }
}

/// Close communication port
pub fn flt_close_communication_port(port_id: u32) -> bool {
    let mut state = FLTMGR_STATE.lock();

    for port in state.ports.iter_mut() {
        if port.active && port.port_id == port_id {
            crate::serial_println!("[FLTMGR] Closed communication port '{}'", port.name_str());
            *port = FltPort::empty();
            return true;
        }
    }

    false
}

/// Send message to port
pub fn flt_send_message(port_id: u32, message: &[u8]) -> Option<Vec<u8>> {
    let callback = {
        let state = FLTMGR_STATE.lock();
        let mut found_callback = None;
        for idx in 0..MAX_CALLBACKS {
            if state.ports[idx].active && state.ports[idx].port_id == port_id {
                found_callback = state.ports[idx].message_callback;
                break;
            }
        }
        found_callback
    };

    if let Some(cb) = callback {
        cb(port_id, message)
    } else {
        None
    }
}

// ============================================================================
// Callback Invocation
// ============================================================================

/// Invoke pre-operation callbacks for all filters
pub fn flt_invoke_pre_callbacks(data: &mut FltCallbackData) -> FltPreopCallbackStatus {
    // Collect filter info first
    let filter_refs: Vec<(u32, u32)> = {
        let state = FLTMGR_STATE.lock();
        let mut refs = Vec::new();
        for idx in 0..MAX_MINIFILTERS {
            if state.filters[idx].registered {
                refs.push((state.filters[idx].filter_id, state.filters[idx].altitude()));
            }
        }
        refs
    };

    // Sort by altitude (highest first for pre-callbacks)
    let mut sorted_refs = filter_refs;
    sorted_refs.sort_by(|a, b| b.1.cmp(&a.1));

    let mut result = FltPreopCallbackStatus::Success;

    for (filter_id, _) in sorted_refs {
        // Find the callback for this filter
        let callback_info: Option<(FltPreOperationCallback, usize)> = {
            let state = FLTMGR_STATE.lock();
            let mut info = None;
            for idx in 0..MAX_MINIFILTERS {
                if state.filters[idx].registered && state.filters[idx].filter_id == filter_id {
                    if let Some(cb) = state.filters[idx].get_callback(data.operation) {
                        if let Some(pre) = cb.pre_callback {
                            state.filters[idx].ops_intercepted.fetch_add(1, Ordering::Relaxed);
                            info = Some((pre, idx));
                        }
                    }
                    break;
                }
            }
            info
        };

        if let Some((pre_callback, filter_idx)) = callback_info {
            // Get filter reference for callback (filters are static)
            let filter_ref = {
                let state = FLTMGR_STATE.lock();
                unsafe { &*(&state.filters[filter_idx] as *const FltFilter) }
            };

            result = pre_callback(data, filter_ref, 0);

            if result == FltPreopCallbackStatus::Complete {
                // Filter completed the operation, stop processing
                let state = FLTMGR_STATE.lock();
                for idx in 0..MAX_MINIFILTERS {
                    if state.filters[idx].filter_id == filter_id {
                        state.filters[idx].ops_blocked.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }
                return result;
            }
        }
    }

    result
}

/// Invoke post-operation callbacks for all filters
pub fn flt_invoke_post_callbacks(
    data: &mut FltCallbackData,
    pre_status: FltPreopCallbackStatus,
) -> FltPostopCallbackStatus {
    // Collect filter info first
    let filter_refs: Vec<(u32, u32)> = {
        let state = FLTMGR_STATE.lock();
        let mut refs = Vec::new();
        for idx in 0..MAX_MINIFILTERS {
            if state.filters[idx].registered {
                refs.push((state.filters[idx].filter_id, state.filters[idx].altitude()));
            }
        }
        refs
    };

    // Sort by altitude (lowest first for post-callbacks)
    let mut sorted_refs = filter_refs;
    sorted_refs.sort_by(|a, b| a.1.cmp(&b.1));

    let mut result = FltPostopCallbackStatus::FinishedProcessing;

    for (filter_id, _) in sorted_refs {
        // Find the callback for this filter
        let callback_info: Option<(FltPostOperationCallback, usize)> = {
            let state = FLTMGR_STATE.lock();
            let mut info = None;
            for idx in 0..MAX_MINIFILTERS {
                if state.filters[idx].registered && state.filters[idx].filter_id == filter_id {
                    if let Some(cb) = state.filters[idx].get_callback(data.operation) {
                        if let Some(post) = cb.post_callback {
                            info = Some((post, idx));
                        }
                    }
                    break;
                }
            }
            info
        };

        if let Some((post_callback, filter_idx)) = callback_info {
            // Get filter reference for callback (filters are static)
            let filter_ref = {
                let state = FLTMGR_STATE.lock();
                unsafe { &*(&state.filters[filter_idx] as *const FltFilter) }
            };

            result = post_callback(data, filter_ref, 0, pre_status);
        }
    }

    result
}

// ============================================================================
// Statistics and Query
// ============================================================================

/// Filter manager statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct FltMgrStats {
    /// Number of registered filters
    pub filter_count: usize,
    /// Number of active instances
    pub instance_count: usize,
    /// Number of active ports
    pub port_count: usize,
    /// Total operations intercepted
    pub total_intercepted: u64,
    /// Total operations blocked
    pub total_blocked: u64,
}

/// Get filter manager statistics
pub fn get_fltmgr_stats() -> FltMgrStats {
    let state = FLTMGR_STATE.lock();

    let mut stats = FltMgrStats::default();

    for filter in state.filters.iter() {
        if filter.registered {
            stats.filter_count += 1;
            stats.total_intercepted += filter.ops_intercepted.load(Ordering::Relaxed);
            stats.total_blocked += filter.ops_blocked.load(Ordering::Relaxed);
        }
    }

    stats.instance_count = state.instances.iter().filter(|i| i.active).count();
    stats.port_count = state.ports.iter().filter(|p| p.active).count();

    stats
}

/// Filter snapshot for inspection
#[derive(Clone)]
pub struct FltFilterSnapshot {
    pub filter_id: u32,
    pub name: [u8; 64],
    pub name_len: usize,
    pub altitude: u32,
    pub instance_count: u32,
    pub ops_intercepted: u64,
    pub ops_blocked: u64,
}

impl FltFilterSnapshot {
    pub const fn empty() -> Self {
        Self {
            filter_id: 0,
            name: [0; 64],
            name_len: 0,
            altitude: 0,
            instance_count: 0,
            ops_intercepted: 0,
            ops_blocked: 0,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }
}

/// Get snapshots of all registered filters
pub fn get_filter_snapshots(max_count: usize) -> (Vec<FltFilterSnapshot>, usize) {
    let state = FLTMGR_STATE.lock();
    let mut snapshots = Vec::new();
    let mut count = 0;

    let limit = max_count.min(MAX_MINIFILTERS);

    for filter in state.filters.iter() {
        if count >= limit {
            break;
        }

        if filter.registered {
            let mut snap = FltFilterSnapshot::empty();
            snap.filter_id = filter.filter_id;
            snap.name = filter.registration.name;
            snap.name_len = filter.registration.name_len;
            snap.altitude = filter.registration.altitude;
            snap.instance_count = filter.instance_count;
            snap.ops_intercepted = filter.ops_intercepted.load(Ordering::Relaxed);
            snap.ops_blocked = filter.ops_blocked.load(Ordering::Relaxed);
            snapshots.push(snap);
            count += 1;
        }
    }

    (snapshots, count)
}

/// List all registered filters
pub fn list_filters() {
    let state = FLTMGR_STATE.lock();

    crate::serial_println!("[FLTMGR] Registered mini-filters:");

    for filter in state.filters.iter() {
        if filter.registered {
            crate::serial_println!(
                "  {} (ID={}, altitude={}, instances={}, intercepted={}, blocked={})",
                filter.name(),
                filter.filter_id,
                filter.altitude(),
                filter.instance_count,
                filter.ops_intercepted.load(Ordering::Relaxed),
                filter.ops_blocked.load(Ordering::Relaxed)
            );
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the filter manager
pub fn init() {
    let mut state = FLTMGR_STATE.lock();

    if state.initialized {
        return;
    }

    state.initialized = true;

    crate::serial_println!("[FLTMGR] Filter Manager initialized (max {} filters)", MAX_MINIFILTERS);
}
