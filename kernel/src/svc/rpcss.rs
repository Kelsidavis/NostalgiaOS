//! Remote Procedure Call Service (RpcSs)
//!
//! The RPC service provides the endpoint mapper and other RPC services.
//! It is a fundamental Windows service that enables inter-process
//! communication and distributed computing.
//!
//! # Features
//!
//! - **Endpoint Mapper**: Map RPC interfaces to endpoints
//! - **Protocol Sequences**: Support multiple transport protocols
//! - **Security**: Authentication and authorization
//! - **COM Activation**: Support COM/DCOM object activation
//!
//! # Protocol Sequences
//!
//! - ncalrpc: Local RPC (named pipes)
//! - ncacn_np: Named pipes over SMB
//! - ncacn_ip_tcp: TCP/IP
//! - ncacn_http: HTTP
//!
//! # Endpoint Types
//!
//! - Static endpoints: Fixed, well-known ports
//! - Dynamic endpoints: Allocated by endpoint mapper

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum registered endpoints
const MAX_ENDPOINTS: usize = 128;

/// Maximum registered interfaces
const MAX_INTERFACES: usize = 64;

/// Maximum active bindings
const MAX_BINDINGS: usize = 64;

/// Maximum interface name length
const MAX_IF_NAME: usize = 64;

/// Maximum endpoint string length
const MAX_ENDPOINT: usize = 64;

/// Maximum annotation length
const MAX_ANNOTATION: usize = 128;

/// Protocol sequence
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolSeq {
    /// Local RPC (LRPC)
    Lrpc = 0,
    /// Named pipes
    NamedPipe = 1,
    /// TCP/IP
    TcpIp = 2,
    /// HTTP
    Http = 3,
    /// NetBIOS
    NetBios = 4,
    /// SPX
    Spx = 5,
}

impl ProtocolSeq {
    const fn empty() -> Self {
        ProtocolSeq::Lrpc
    }

    /// Get protocol sequence string
    pub fn as_str(&self) -> &'static [u8] {
        match self {
            ProtocolSeq::Lrpc => b"ncalrpc",
            ProtocolSeq::NamedPipe => b"ncacn_np",
            ProtocolSeq::TcpIp => b"ncacn_ip_tcp",
            ProtocolSeq::Http => b"ncacn_http",
            ProtocolSeq::NetBios => b"ncacn_nb",
            ProtocolSeq::Spx => b"ncacn_spx",
        }
    }
}

/// Interface ID (UUID)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InterfaceId {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl InterfaceId {
    const fn empty() -> Self {
        InterfaceId {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        }
    }

    /// Create from components
    pub const fn new(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Self {
        InterfaceId {
            data1: d1,
            data2: d2,
            data3: d3,
            data4: d4,
        }
    }
}

/// Registered endpoint
#[repr(C)]
#[derive(Clone)]
pub struct Endpoint {
    /// Interface ID
    pub interface_id: InterfaceId,
    /// Interface version (major)
    pub version_major: u16,
    /// Interface version (minor)
    pub version_minor: u16,
    /// Protocol sequence
    pub protocol: ProtocolSeq,
    /// Endpoint string (port, pipe name, etc.)
    pub endpoint: [u8; MAX_ENDPOINT],
    /// Object UUID (optional)
    pub object_uuid: InterfaceId,
    /// Annotation
    pub annotation: [u8; MAX_ANNOTATION],
    /// Is dynamic endpoint
    pub is_dynamic: bool,
    /// Entry is valid
    pub valid: bool,
}

impl Endpoint {
    const fn empty() -> Self {
        Endpoint {
            interface_id: InterfaceId::empty(),
            version_major: 0,
            version_minor: 0,
            protocol: ProtocolSeq::empty(),
            endpoint: [0; MAX_ENDPOINT],
            object_uuid: InterfaceId::empty(),
            annotation: [0; MAX_ANNOTATION],
            is_dynamic: false,
            valid: false,
        }
    }
}

/// Registered interface
#[repr(C)]
#[derive(Clone)]
pub struct Interface {
    /// Interface ID
    pub interface_id: InterfaceId,
    /// Interface name
    pub name: [u8; MAX_IF_NAME],
    /// Version major
    pub version_major: u16,
    /// Version minor
    pub version_minor: u16,
    /// Manager type UUID
    pub manager_type: InterfaceId,
    /// Manager entry point (simulated)
    pub manager_epv: u64,
    /// Max calls
    pub max_calls: u32,
    /// Registration flags
    pub flags: u32,
    /// Entry is valid
    pub valid: bool,
}

impl Interface {
    const fn empty() -> Self {
        Interface {
            interface_id: InterfaceId::empty(),
            name: [0; MAX_IF_NAME],
            version_major: 0,
            version_minor: 0,
            manager_type: InterfaceId::empty(),
            manager_epv: 0,
            max_calls: 0,
            flags: 0,
            valid: false,
        }
    }
}

/// RPC binding handle
#[repr(C)]
#[derive(Clone)]
pub struct Binding {
    /// Binding handle ID
    pub handle_id: u64,
    /// Interface ID
    pub interface_id: InterfaceId,
    /// Protocol sequence
    pub protocol: ProtocolSeq,
    /// Network address
    pub network_addr: [u8; 64],
    /// Endpoint
    pub endpoint: [u8; MAX_ENDPOINT],
    /// Object UUID
    pub object_uuid: InterfaceId,
    /// Authentication level
    pub auth_level: u32,
    /// Is connected
    pub connected: bool,
    /// Entry is valid
    pub valid: bool,
}

impl Binding {
    const fn empty() -> Self {
        Binding {
            handle_id: 0,
            interface_id: InterfaceId::empty(),
            protocol: ProtocolSeq::empty(),
            network_addr: [0; 64],
            endpoint: [0; MAX_ENDPOINT],
            object_uuid: InterfaceId::empty(),
            auth_level: 0,
            connected: false,
            valid: false,
        }
    }
}

/// Authentication level
pub mod auth_level {
    pub const DEFAULT: u32 = 0;
    pub const NONE: u32 = 1;
    pub const CONNECT: u32 = 2;
    pub const CALL: u32 = 3;
    pub const PKT: u32 = 4;
    pub const PKT_INTEGRITY: u32 = 5;
    pub const PKT_PRIVACY: u32 = 6;
}

/// RPC service state
pub struct RpcState {
    /// Service is running
    pub running: bool,
    /// Registered endpoints
    pub endpoints: [Endpoint; MAX_ENDPOINTS],
    /// Endpoint count
    pub endpoint_count: usize,
    /// Registered interfaces
    pub interfaces: [Interface; MAX_INTERFACES],
    /// Interface count
    pub interface_count: usize,
    /// Active bindings
    pub bindings: [Binding; MAX_BINDINGS],
    /// Binding count
    pub binding_count: usize,
    /// Next binding handle
    pub next_binding_handle: u64,
    /// Next dynamic port
    pub next_dynamic_port: u16,
    /// Service start time
    pub start_time: i64,
}

impl RpcState {
    const fn new() -> Self {
        RpcState {
            running: false,
            endpoints: [const { Endpoint::empty() }; MAX_ENDPOINTS],
            endpoint_count: 0,
            interfaces: [const { Interface::empty() }; MAX_INTERFACES],
            interface_count: 0,
            bindings: [const { Binding::empty() }; MAX_BINDINGS],
            binding_count: 0,
            next_binding_handle: 1,
            next_dynamic_port: 49152, // Start of dynamic port range
            start_time: 0,
        }
    }
}

/// Global state
static RPC_STATE: Mutex<RpcState> = Mutex::new(RpcState::new());

/// Statistics
static TOTAL_CALLS: AtomicU64 = AtomicU64::new(0);
static ENDPOINTS_REGISTERED: AtomicU64 = AtomicU64::new(0);
static BINDINGS_CREATED: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize RPC service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = RPC_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    // Register well-known endpoints
    register_wellknown_endpoints(&mut state);

    crate::serial_println!("[RPCSS] RPC Service initialized");
}

/// Register well-known system endpoints
fn register_wellknown_endpoints(state: &mut RpcState) {
    // Endpoint Mapper interface
    let epmap_iid = InterfaceId::new(
        0xe1af8308, 0x5d1f, 0x11c9,
        [0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa]
    );

    let idx = 0;
    state.endpoints[idx].interface_id = epmap_iid;
    state.endpoints[idx].version_major = 3;
    state.endpoints[idx].version_minor = 0;
    state.endpoints[idx].protocol = ProtocolSeq::TcpIp;
    let endpoint = b"135";
    state.endpoints[idx].endpoint[..endpoint.len()].copy_from_slice(endpoint);
    let annotation = b"Endpoint Mapper";
    state.endpoints[idx].annotation[..annotation.len()].copy_from_slice(annotation);
    state.endpoints[idx].is_dynamic = false;
    state.endpoints[idx].valid = true;

    state.endpoint_count = 1;
    ENDPOINTS_REGISTERED.fetch_add(1, Ordering::SeqCst);
}

/// Register an endpoint
pub fn register_endpoint(
    interface_id: &InterfaceId,
    version_major: u16,
    version_minor: u16,
    protocol: ProtocolSeq,
    endpoint: &[u8],
    annotation: &[u8],
) -> Result<usize, u32> {
    let mut state = RPC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.endpoints.iter().position(|e| !e.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let ep = &mut state.endpoints[slot];
    ep.interface_id = *interface_id;
    ep.version_major = version_major;
    ep.version_minor = version_minor;
    ep.protocol = protocol;

    let ep_len = endpoint.len().min(MAX_ENDPOINT);
    ep.endpoint[..ep_len].copy_from_slice(&endpoint[..ep_len]);

    let ann_len = annotation.len().min(MAX_ANNOTATION);
    ep.annotation[..ann_len].copy_from_slice(&annotation[..ann_len]);

    ep.is_dynamic = false;
    ep.valid = true;

    state.endpoint_count += 1;
    ENDPOINTS_REGISTERED.fetch_add(1, Ordering::SeqCst);

    Ok(slot)
}

/// Unregister an endpoint
pub fn unregister_endpoint(
    interface_id: &InterfaceId,
    protocol: ProtocolSeq,
) -> Result<(), u32> {
    let mut state = RPC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.endpoints.iter().position(|e| {
        e.valid && e.interface_id == *interface_id && e.protocol == protocol
    });

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.endpoints[idx].valid = false;
    state.endpoint_count = state.endpoint_count.saturating_sub(1);

    Ok(())
}

/// Lookup endpoint
pub fn lookup_endpoint(
    interface_id: &InterfaceId,
    protocol: ProtocolSeq,
) -> Option<Endpoint> {
    let state = RPC_STATE.lock();

    state.endpoints.iter()
        .find(|e| e.valid && e.interface_id == *interface_id && e.protocol == protocol)
        .cloned()
}

/// Allocate dynamic endpoint
pub fn allocate_dynamic_endpoint(
    interface_id: &InterfaceId,
    version_major: u16,
    version_minor: u16,
    protocol: ProtocolSeq,
    annotation: &[u8],
) -> Result<(usize, u16), u32> {
    let mut state = RPC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.endpoints.iter().position(|e| !e.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let port = state.next_dynamic_port;
    state.next_dynamic_port += 1;
    if state.next_dynamic_port > 65535 {
        state.next_dynamic_port = 49152;
    }

    let ep = &mut state.endpoints[slot];
    ep.interface_id = *interface_id;
    ep.version_major = version_major;
    ep.version_minor = version_minor;
    ep.protocol = protocol;

    // Format port as string
    let mut port_str = [0u8; MAX_ENDPOINT];
    let port_len = format_u16(port, &mut port_str);
    ep.endpoint[..port_len].copy_from_slice(&port_str[..port_len]);

    let ann_len = annotation.len().min(MAX_ANNOTATION);
    ep.annotation[..ann_len].copy_from_slice(&annotation[..ann_len]);

    ep.is_dynamic = true;
    ep.valid = true;

    state.endpoint_count += 1;
    ENDPOINTS_REGISTERED.fetch_add(1, Ordering::SeqCst);

    Ok((slot, port))
}

/// Format u16 as decimal string
fn format_u16(mut n: u16, buf: &mut [u8]) -> usize {
    if n == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }

    let mut temp = [0u8; 5];
    let mut i = 0;
    while n > 0 && i < 5 {
        temp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }

    let len = i;
    for j in 0..len {
        if j < buf.len() {
            buf[j] = temp[len - 1 - j];
        }
    }

    len
}

/// Register an interface
pub fn register_interface(
    interface_id: &InterfaceId,
    name: &[u8],
    version_major: u16,
    version_minor: u16,
    max_calls: u32,
    flags: u32,
) -> Result<usize, u32> {
    let mut state = RPC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.interfaces.iter().position(|i| !i.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let iface = &mut state.interfaces[slot];
    iface.interface_id = *interface_id;

    let name_len = name.len().min(MAX_IF_NAME);
    iface.name[..name_len].copy_from_slice(&name[..name_len]);

    iface.version_major = version_major;
    iface.version_minor = version_minor;
    iface.max_calls = max_calls;
    iface.flags = flags;
    iface.valid = true;

    state.interface_count += 1;

    Ok(slot)
}

/// Unregister an interface
pub fn unregister_interface(interface_id: &InterfaceId) -> Result<(), u32> {
    let mut state = RPC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.interfaces.iter().position(|i| {
        i.valid && i.interface_id == *interface_id
    });

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.interfaces[idx].valid = false;
    state.interface_count = state.interface_count.saturating_sub(1);

    Ok(())
}

/// Create a binding handle
pub fn create_binding(
    interface_id: &InterfaceId,
    protocol: ProtocolSeq,
    network_addr: &[u8],
    endpoint: &[u8],
) -> Result<u64, u32> {
    let mut state = RPC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.bindings.iter().position(|b| !b.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let handle_id = state.next_binding_handle;
    state.next_binding_handle += 1;

    let binding = &mut state.bindings[slot];
    binding.handle_id = handle_id;
    binding.interface_id = *interface_id;
    binding.protocol = protocol;

    let addr_len = network_addr.len().min(64);
    binding.network_addr[..addr_len].copy_from_slice(&network_addr[..addr_len]);

    let ep_len = endpoint.len().min(MAX_ENDPOINT);
    binding.endpoint[..ep_len].copy_from_slice(&endpoint[..ep_len]);

    binding.auth_level = auth_level::DEFAULT;
    binding.connected = false;
    binding.valid = true;

    state.binding_count += 1;
    BINDINGS_CREATED.fetch_add(1, Ordering::SeqCst);

    Ok(handle_id)
}

/// Free a binding handle
pub fn free_binding(handle_id: u64) -> Result<(), u32> {
    let mut state = RPC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.bindings.iter().position(|b| b.valid && b.handle_id == handle_id);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.bindings[idx].valid = false;
    state.binding_count = state.binding_count.saturating_sub(1);

    Ok(())
}

/// Set binding authentication
pub fn set_binding_auth(handle_id: u64, auth_level: u32) -> Result<(), u32> {
    let mut state = RPC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let binding = state.bindings.iter_mut()
        .find(|b| b.valid && b.handle_id == handle_id);

    match binding {
        Some(b) => {
            b.auth_level = auth_level;
            Ok(())
        }
        None => Err(0x80070057),
    }
}

/// Enumerate endpoints
pub fn enum_endpoints() -> ([Endpoint; MAX_ENDPOINTS], usize) {
    let state = RPC_STATE.lock();
    let mut result = [const { Endpoint::empty() }; MAX_ENDPOINTS];
    let mut count = 0;

    for ep in state.endpoints.iter() {
        if ep.valid && count < MAX_ENDPOINTS {
            result[count] = ep.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Enumerate interfaces
pub fn enum_interfaces() -> ([Interface; MAX_INTERFACES], usize) {
    let state = RPC_STATE.lock();
    let mut result = [const { Interface::empty() }; MAX_INTERFACES];
    let mut count = 0;

    for iface in state.interfaces.iter() {
        if iface.valid && count < MAX_INTERFACES {
            result[count] = iface.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Record RPC call
pub fn record_call() {
    TOTAL_CALLS.fetch_add(1, Ordering::SeqCst);
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64) {
    (
        TOTAL_CALLS.load(Ordering::SeqCst),
        ENDPOINTS_REGISTERED.load(Ordering::SeqCst),
        BINDINGS_CREATED.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = RPC_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = RPC_STATE.lock();
    state.running = false;

    // Close all bindings
    for binding in state.bindings.iter_mut() {
        binding.valid = false;
    }
    state.binding_count = 0;

    crate::serial_println!("[RPCSS] RPC Service stopped");
}
