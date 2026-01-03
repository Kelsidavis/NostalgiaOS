//! ALPC (Advanced Local Procedure Call) Extensions
//!
//! ALPC extends classic LPC with:
//! - Views (shared memory sections for large data transfers)
//! - Completion ports (async I/O completion notification)
//! - Security contexts (impersonation support)
//! - Message attributes (extended metadata)
//! - Cancellation support
//!
//! Based on Windows NT LPC extensions and Vista+ ALPC.

use super::port::{PortFlags, MAX_PORTS};
use core::sync::atomic::{AtomicBool, Ordering};

/// Maximum number of views per port
pub const MAX_VIEWS_PER_PORT: usize = 4;

/// Maximum view size (1 MB)
pub const MAX_VIEW_SIZE: usize = 1024 * 1024;

/// ALPC port attributes
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AlpcPortAttributes {
    /// Port flags
    pub flags: u32,
    /// Security QoS settings
    pub security_qos: SecurityQos,
    /// Maximum message length
    pub max_message_length: usize,
    /// Memory size limit
    pub memory_bandwidth_limit: usize,
    /// Maximum pool usage
    pub max_pool_usage: usize,
    /// Maximum section size for views
    pub max_section_size: usize,
    /// Maximum view size
    pub max_view_size: usize,
    /// Maximum total section size
    pub max_total_section_size: usize,
    /// Duplicate object types
    pub dup_object_types: u32,
}

impl AlpcPortAttributes {
    /// Create default attributes
    pub const fn new() -> Self {
        Self {
            flags: 0,
            security_qos: SecurityQos::new(),
            max_message_length: 512,
            memory_bandwidth_limit: 0,
            max_pool_usage: 64 * 1024,
            max_section_size: MAX_VIEW_SIZE,
            max_view_size: MAX_VIEW_SIZE,
            max_total_section_size: MAX_VIEW_SIZE * MAX_VIEWS_PER_PORT,
            dup_object_types: 0,
        }
    }
}

/// ALPC port attribute flags
#[allow(non_snake_case)]
pub mod AlpcPortAttributeFlags {
    /// Accept dup handles
    pub const ACCEPT_DUP_HANDLES: u32 = 0x80000;
    /// Accept indirect handles
    pub const ACCEPT_INDIRECT_HANDLES: u32 = 0x20000;
    /// Allow impersonation
    pub const ALLOW_IMPERSONATION: u32 = 0x10000;
    /// Allow LPC requests
    pub const ALLOW_LPC_REQUESTS: u32 = 0x40000;
    /// Waitable port
    pub const WAITABLE_PORT: u32 = 0x100000;
    /// Allow multi-handle attribute
    pub const ALLOW_MULTI_HANDLE_ATTRIBUTE: u32 = 0x200000;
}

/// Security Quality of Service for impersonation
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SecurityQos {
    /// Length of structure
    pub length: u32,
    /// Impersonation level
    pub impersonation_level: ImpersonationLevel,
    /// Context tracking mode
    pub context_tracking_mode: ContextTrackingMode,
    /// Effective only flag
    pub effective_only: bool,
}

impl SecurityQos {
    pub const fn new() -> Self {
        Self {
            length: core::mem::size_of::<Self>() as u32,
            impersonation_level: ImpersonationLevel::Anonymous,
            context_tracking_mode: ContextTrackingMode::Static,
            effective_only: false,
        }
    }
}

impl Default for SecurityQos {
    fn default() -> Self {
        Self::new()
    }
}

/// Impersonation level
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImpersonationLevel {
    /// Anonymous - no impersonation
    #[default]
    Anonymous = 0,
    /// Identification - can query token
    Identification = 1,
    /// Impersonation - can impersonate locally
    Impersonation = 2,
    /// Delegation - can impersonate remotely
    Delegation = 3,
}

/// Security context tracking mode
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContextTrackingMode {
    /// Static context - captured at connection time
    #[default]
    Static = 0,
    /// Dynamic context - updated on each call
    Dynamic = 1,
}

/// ALPC message attributes
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AlpcMessageAttributes {
    /// Allocated attributes mask
    pub allocated_attributes: u32,
    /// Valid attributes mask
    pub valid_attributes: u32,
}

/// ALPC message attribute flags
#[allow(non_snake_case)]
pub mod AlpcMessageAttributeFlags {
    /// Work on behalf ticket
    pub const WORK_ON_BEHALF_OF: u32 = 0x2000000;
    /// Direct receive attribute
    pub const DIRECT: u32 = 0x10000000;
    /// Token attribute
    pub const TOKEN: u32 = 0x80000000;
    /// Handle attribute
    pub const HANDLE: u32 = 0x10000000;
    /// Context attribute
    pub const CONTEXT: u32 = 0x20000000;
    /// View attribute
    pub const VIEW: u32 = 0x40000000;
    /// Security attribute
    pub const SECURITY: u32 = 0x80000000;
}

/// ALPC data view for shared memory
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AlpcDataView {
    /// View flags
    pub flags: u32,
    /// Section handle (kernel handle to section object)
    pub section_handle: u64,
    /// View base address
    pub view_base: usize,
    /// View size
    pub view_size: usize,
}

impl AlpcDataView {
    pub const fn empty() -> Self {
        Self {
            flags: 0,
            section_handle: 0,
            view_base: 0,
            view_size: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.view_base != 0 && self.view_size > 0
    }
}

impl Default for AlpcDataView {
    fn default() -> Self {
        Self::empty()
    }
}

/// ALPC data view flags
#[allow(non_snake_case)]
pub mod AlpcDataViewFlags {
    /// View is valid
    pub const VALID: u32 = 0x0001;
    /// View is mapped into caller
    pub const MAPPED_IN_CALLER: u32 = 0x0002;
    /// View is mapped into target
    pub const MAPPED_IN_TARGET: u32 = 0x0004;
    /// View should be released on close
    pub const RELEASE_ON_CLOSE: u32 = 0x10000;
}

/// ALPC security attribute for impersonation
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AlpcSecurityAttribute {
    /// Flags
    pub flags: u32,
    /// Security QoS
    pub qos: SecurityQos,
    /// Context handle
    pub context_handle: u64,
}

/// ALPC context attribute
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AlpcContextAttribute {
    /// Port context
    pub port_context: usize,
    /// Message context
    pub message_context: usize,
    /// Sequence number
    pub sequence: u32,
    /// Message ID
    pub message_id: u32,
    /// Callback ID
    pub callback_id: u32,
}

/// ALPC handle attribute for handle passing
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AlpcHandleAttribute {
    /// Flags
    pub flags: u32,
    /// Reserved
    pub reserved: u32,
    /// Handle in the client
    pub handle: u64,
    /// Object attributes for duplicate
    pub object_attributes: u32,
    /// Desired access for duplicate
    pub desired_access: u32,
    /// Granted access (output)
    pub granted_access: u32,
}

/// ALPC completion information
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AlpcCompletionInfo {
    /// Completion port handle
    pub completion_port: u64,
    /// Completion key
    pub completion_key: usize,
}

/// ALPC port extension data attached to LpcPort
#[derive(Clone, Copy)]
pub struct AlpcPortExtension {
    /// ALPC enabled flag
    pub enabled: bool,
    /// Port attributes
    pub attributes: AlpcPortAttributes,
    /// Data views
    pub views: [AlpcDataView; MAX_VIEWS_PER_PORT],
    /// Number of active views
    pub view_count: u8,
    /// Completion port info (optional)
    pub completion_info: Option<AlpcCompletionInfo>,
    /// Waitable event state
    pub event_signaled: bool,
    /// Security context handle
    pub security_context: u64,
    /// Port context (user-provided)
    pub port_context: usize,
    /// Total section bytes mapped
    pub total_section_bytes: usize,
}

impl AlpcPortExtension {
    pub const fn new() -> Self {
        Self {
            enabled: false,
            attributes: AlpcPortAttributes::new(),
            views: [AlpcDataView::empty(); MAX_VIEWS_PER_PORT],
            view_count: 0,
            completion_info: None,
            event_signaled: false,
            security_context: 0,
            port_context: 0,
            total_section_bytes: 0,
        }
    }

    /// Enable ALPC features on this port
    pub fn enable(&mut self, attributes: AlpcPortAttributes) {
        self.enabled = true;
        self.attributes = attributes;
    }

    /// Add a view to the port
    pub fn add_view(&mut self, view: AlpcDataView) -> bool {
        if self.view_count as usize >= MAX_VIEWS_PER_PORT {
            return false;
        }
        if self.total_section_bytes + view.view_size > self.attributes.max_total_section_size {
            return false;
        }

        self.views[self.view_count as usize] = view;
        self.view_count += 1;
        self.total_section_bytes += view.view_size;
        true
    }

    /// Remove a view by index
    pub fn remove_view(&mut self, index: usize) -> bool {
        if index >= self.view_count as usize {
            return false;
        }

        let size = self.views[index].view_size;

        // Shift remaining views
        for i in index..(self.view_count as usize - 1) {
            self.views[i] = self.views[i + 1];
        }
        self.view_count -= 1;
        self.total_section_bytes -= size;
        self.views[self.view_count as usize] = AlpcDataView::empty();

        true
    }

    /// Get a view by index
    pub fn get_view(&self, index: usize) -> Option<&AlpcDataView> {
        if index < self.view_count as usize {
            Some(&self.views[index])
        } else {
            None
        }
    }

    /// Set completion port
    pub fn set_completion_port(&mut self, port: u64, key: usize) {
        self.completion_info = Some(AlpcCompletionInfo {
            completion_port: port,
            completion_key: key,
        });
    }

    /// Signal the waitable event
    pub fn signal_event(&mut self) {
        if self.attributes.flags & AlpcPortAttributeFlags::WAITABLE_PORT != 0 {
            self.event_signaled = true;
        }
    }

    /// Reset the waitable event
    pub fn reset_event(&mut self) {
        self.event_signaled = false;
    }

    /// Check if event is signaled
    pub fn is_event_signaled(&self) -> bool {
        self.event_signaled
    }
}

impl Default for AlpcPortExtension {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// ALPC Extension Storage
// =============================================================================

/// Global ALPC extension storage for ports
static mut ALPC_EXTENSIONS: [AlpcPortExtension; MAX_PORTS] = {
    const INIT: AlpcPortExtension = AlpcPortExtension::new();
    [INIT; MAX_PORTS]
};

/// ALPC initialized flag
static ALPC_INITIALIZED: AtomicBool = AtomicBool::new(false);

// =============================================================================
// ALPC API Functions
// =============================================================================

/// Initialize ALPC subsystem
pub fn init() {
    if ALPC_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        crate::serial_println!("[ALPC] Advanced LPC subsystem initialized");
    }
}

/// Enable ALPC features on an existing port
pub unsafe fn alpc_enable_port(port_index: u16, attributes: AlpcPortAttributes) -> bool {
    let idx = port_index as usize;
    if idx >= MAX_PORTS {
        return false;
    }

    let ext = &mut ALPC_EXTENSIONS[idx];
    ext.enable(attributes);

    crate::serial_println!("[ALPC] Enabled ALPC features on port {}", port_index);
    true
}

/// Create an ALPC port (combines LPC port creation with ALPC enablement)
pub unsafe fn alpc_create_port(
    name: &str,
    port_type: super::port::LpcPortType,
    attributes: AlpcPortAttributes,
) -> Option<u16> {
    // Create underlying LPC port
    let port_index = super::port::lpc_create_port(name, port_type, attributes.max_message_length as u32)?;

    // Enable ALPC extensions
    let ext = &mut ALPC_EXTENSIONS[port_index as usize];
    ext.enable(attributes);

    // Set ALPC flag on port
    if let Some(port) = super::port::get_port_mut(port_index) {
        port.flags |= PortFlags::ALPC_PORT;
    }

    crate::serial_println!(
        "[ALPC] Created ALPC port {} (name='{}', waitable={})",
        port_index,
        name,
        (attributes.flags & AlpcPortAttributeFlags::WAITABLE_PORT) != 0
    );

    Some(port_index)
}

/// Create a data view (shared memory section)
pub unsafe fn alpc_create_data_view(
    port_index: u16,
    size: usize,
) -> Option<usize> {
    let idx = port_index as usize;
    if idx >= MAX_PORTS {
        return None;
    }

    let ext = &mut ALPC_EXTENSIONS[idx];
    if !ext.enabled {
        return None;
    }

    if size > ext.attributes.max_view_size {
        return None;
    }

    // In a real implementation, this would:
    // 1. Create a section object
    // 2. Map it into the port's address space
    // 3. Return the base address

    // For now, simulate with a placeholder
    let view = AlpcDataView {
        flags: AlpcDataViewFlags::VALID | AlpcDataViewFlags::MAPPED_IN_CALLER,
        section_handle: 0, // Would be a real section handle
        view_base: 0x100000 + (ext.view_count as usize * 0x10000), // Placeholder address
        view_size: size,
    };

    if ext.add_view(view) {
        let view_idx = ext.view_count as usize - 1;
        crate::serial_println!(
            "[ALPC] Created data view {} on port {} (size={})",
            view_idx,
            port_index,
            size
        );
        Some(ext.views[view_idx].view_base)
    } else {
        None
    }
}

/// Delete a data view
pub unsafe fn alpc_delete_data_view(port_index: u16, view_base: usize) -> bool {
    let idx = port_index as usize;
    if idx >= MAX_PORTS {
        return false;
    }

    let ext = &mut ALPC_EXTENSIONS[idx];
    if !ext.enabled {
        return false;
    }

    // Find and remove the view
    for i in 0..ext.view_count as usize {
        if ext.views[i].view_base == view_base {
            ext.remove_view(i);
            crate::serial_println!(
                "[ALPC] Deleted data view at {:#x} from port {}",
                view_base,
                port_index
            );
            return true;
        }
    }

    false
}

/// Associate a completion port with an ALPC port
pub unsafe fn alpc_set_completion_port(
    port_index: u16,
    completion_port: u64,
    completion_key: usize,
) -> bool {
    let idx = port_index as usize;
    if idx >= MAX_PORTS {
        return false;
    }

    let ext = &mut ALPC_EXTENSIONS[idx];
    if !ext.enabled {
        return false;
    }

    ext.set_completion_port(completion_port, completion_key);
    crate::serial_println!(
        "[ALPC] Set completion port for ALPC port {} (key={:#x})",
        port_index,
        completion_key
    );
    true
}

/// Send message with view (for large data)
pub unsafe fn alpc_send_with_view(
    port_index: u16,
    view_index: usize,
    data_offset: usize,
    data_length: usize,
) -> bool {
    let idx = port_index as usize;
    if idx >= MAX_PORTS {
        return false;
    }

    let ext = &ALPC_EXTENSIONS[idx];
    if !ext.enabled {
        return false;
    }

    if view_index >= ext.view_count as usize {
        return false;
    }

    let view = &ext.views[view_index];
    if data_offset + data_length > view.view_size {
        return false;
    }

    // In real implementation:
    // 1. Create message with view attribute
    // 2. Queue message referencing the view
    // 3. Receiver maps the same section to access data

    crate::serial_println!(
        "[ALPC] Sent message with view {} on port {} (offset={}, len={})",
        view_index,
        port_index,
        data_offset,
        data_length
    );

    true
}

/// Get ALPC port extension data
pub unsafe fn alpc_get_extension(port_index: u16) -> Option<&'static AlpcPortExtension> {
    let idx = port_index as usize;
    if idx >= MAX_PORTS {
        return None;
    }
    Some(&ALPC_EXTENSIONS[idx])
}

/// Get mutable ALPC port extension data
pub unsafe fn alpc_get_extension_mut(port_index: u16) -> Option<&'static mut AlpcPortExtension> {
    let idx = port_index as usize;
    if idx >= MAX_PORTS {
        return None;
    }
    Some(&mut ALPC_EXTENSIONS[idx])
}

/// Query ALPC information
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpcInformationClass {
    /// Basic port information
    BasicInformation = 0,
    /// Associated completion information
    AssociatedCompletionInformation = 1,
    /// Connected status
    ConnectedStatus = 2,
    /// Security attributes
    SecurityAttr = 3,
    /// View information
    ViewInformation = 4,
    /// Port attributes
    PortAttributes = 5,
}

/// ALPC basic information structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AlpcBasicInformation {
    /// Port flags
    pub flags: u32,
    /// Sequence number
    pub sequence_number: u32,
    /// Port context
    pub port_context: usize,
}

/// Query ALPC port information
pub unsafe fn alpc_query_information(
    port_index: u16,
    info_class: AlpcInformationClass,
    buffer: &mut [u8],
) -> Option<usize> {
    let idx = port_index as usize;
    if idx >= MAX_PORTS {
        return None;
    }

    let ext = &ALPC_EXTENSIONS[idx];
    if !ext.enabled {
        return None;
    }

    match info_class {
        AlpcInformationClass::BasicInformation => {
            if buffer.len() < core::mem::size_of::<AlpcBasicInformation>() {
                return None;
            }
            let info = AlpcBasicInformation {
                flags: ext.attributes.flags,
                sequence_number: 0,
                port_context: ext.port_context,
            };
            let info_bytes = core::slice::from_raw_parts(
                &info as *const _ as *const u8,
                core::mem::size_of::<AlpcBasicInformation>(),
            );
            buffer[..info_bytes.len()].copy_from_slice(info_bytes);
            Some(info_bytes.len())
        }
        AlpcInformationClass::ViewInformation => {
            // Return view count and sizes
            if buffer.len() < 8 {
                return None;
            }
            buffer[0..4].copy_from_slice(&(ext.view_count as u32).to_le_bytes());
            buffer[4..8].copy_from_slice(&(ext.total_section_bytes as u32).to_le_bytes());
            Some(8)
        }
        _ => None,
    }
}

/// ALPC port statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct AlpcStatistics {
    /// Number of ALPC-enabled ports
    pub alpc_ports: u32,
    /// Total views allocated
    pub total_views: u32,
    /// Total view bytes
    pub total_view_bytes: usize,
    /// Ports with completion ports
    pub ports_with_completion: u32,
}

/// Get ALPC statistics
pub fn alpc_get_statistics() -> AlpcStatistics {
    let mut stats = AlpcStatistics::default();

    unsafe {
        for i in 0..MAX_PORTS {
            let ext = &ALPC_EXTENSIONS[i];
            if ext.enabled {
                stats.alpc_ports += 1;
                stats.total_views += ext.view_count as u32;
                stats.total_view_bytes += ext.total_section_bytes;
                if ext.completion_info.is_some() {
                    stats.ports_with_completion += 1;
                }
            }
        }
    }

    stats
}
