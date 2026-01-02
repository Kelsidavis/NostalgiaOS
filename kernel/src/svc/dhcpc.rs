//! DHCP Client Service (Dhcp)
//!
//! The DHCP Client service manages dynamic IP address configuration
//! by communicating with DHCP servers on the network.
//!
//! # Features
//!
//! - **Address Acquisition**: Obtain IP addresses via DHCP
//! - **Lease Management**: Track and renew address leases
//! - **Option Processing**: Handle DHCP options (DNS, gateway, etc.)
//! - **Interface Binding**: Manage per-interface DHCP state
//!
//! # DHCP Message Types
//!
//! - DISCOVER: Find DHCP servers
//! - OFFER: Server offers an address
//! - REQUEST: Client requests offered address
//! - ACK: Server confirms assignment
//! - NAK: Server denies request
//! - RELEASE: Client releases address
//! - INFORM: Client requests config only
//!
//! # DHCP Options
//!
//! - Subnet mask (1)
//! - Router/Gateway (3)
//! - DNS servers (6)
//! - Domain name (15)
//! - Lease time (51)
//! - Server identifier (54)

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum network interfaces
const MAX_INTERFACES: usize = 8;

/// Maximum DNS servers per interface
const MAX_DNS_SERVERS: usize = 4;

/// Maximum domain name length
const MAX_DOMAIN: usize = 64;

/// DHCP state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpState {
    /// Not started
    Init = 0,
    /// Selecting (sent DISCOVER)
    Selecting = 1,
    /// Requesting (sent REQUEST)
    Requesting = 2,
    /// Bound (have valid lease)
    Bound = 3,
    /// Renewing (renewing lease)
    Renewing = 4,
    /// Rebinding (failed renew, trying any server)
    Rebinding = 5,
    /// Static (not using DHCP)
    Static = 6,
    /// Disabled
    Disabled = 7,
}

impl DhcpState {
    const fn empty() -> Self {
        DhcpState::Init
    }
}

/// IPv4 address
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Ipv4Addr {
    pub octets: [u8; 4],
}

impl Ipv4Addr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Addr { octets: [a, b, c, d] }
    }

    pub const fn zero() -> Self {
        Ipv4Addr { octets: [0, 0, 0, 0] }
    }

    pub fn is_zero(&self) -> bool {
        self.octets == [0, 0, 0, 0]
    }
}

/// DHCP lease information
#[repr(C)]
#[derive(Clone)]
pub struct DhcpLease {
    /// Assigned IP address
    pub address: Ipv4Addr,
    /// Subnet mask
    pub subnet_mask: Ipv4Addr,
    /// Default gateway
    pub gateway: Ipv4Addr,
    /// DHCP server address
    pub dhcp_server: Ipv4Addr,
    /// DNS servers
    pub dns_servers: [Ipv4Addr; MAX_DNS_SERVERS],
    /// DNS server count
    pub dns_count: usize,
    /// Domain name
    pub domain: [u8; MAX_DOMAIN],
    /// Lease duration (seconds)
    pub lease_time: u32,
    /// Renewal time (T1, seconds)
    pub t1_time: u32,
    /// Rebind time (T2, seconds)
    pub t2_time: u32,
    /// Lease obtained timestamp
    pub obtained: i64,
    /// Lease expires timestamp
    pub expires: i64,
}

impl DhcpLease {
    const fn empty() -> Self {
        DhcpLease {
            address: Ipv4Addr::zero(),
            subnet_mask: Ipv4Addr::zero(),
            gateway: Ipv4Addr::zero(),
            dhcp_server: Ipv4Addr::zero(),
            dns_servers: [const { Ipv4Addr::zero() }; MAX_DNS_SERVERS],
            dns_count: 0,
            domain: [0; MAX_DOMAIN],
            lease_time: 0,
            t1_time: 0,
            t2_time: 0,
            obtained: 0,
            expires: 0,
        }
    }
}

/// Network interface DHCP state
#[repr(C)]
#[derive(Clone)]
pub struct InterfaceDhcp {
    /// Interface index
    pub if_index: u32,
    /// Interface name
    pub if_name: [u8; 32],
    /// MAC address
    pub mac_addr: [u8; 6],
    /// DHCP state
    pub state: DhcpState,
    /// Current lease
    pub lease: DhcpLease,
    /// DHCP enabled
    pub enabled: bool,
    /// Transaction ID (XID)
    pub xid: u32,
    /// Retry count
    pub retries: u32,
    /// Last state change
    pub state_change_time: i64,
    /// Entry is valid
    pub valid: bool,
}

impl InterfaceDhcp {
    const fn empty() -> Self {
        InterfaceDhcp {
            if_index: 0,
            if_name: [0; 32],
            mac_addr: [0; 6],
            state: DhcpState::empty(),
            lease: DhcpLease::empty(),
            enabled: true,
            xid: 0,
            retries: 0,
            state_change_time: 0,
            valid: false,
        }
    }
}

/// DHCP Client state
pub struct DhcpClientState {
    /// Service is running
    pub running: bool,
    /// Interfaces
    pub interfaces: [InterfaceDhcp; MAX_INTERFACES],
    /// Interface count
    pub interface_count: usize,
    /// Next transaction ID
    pub next_xid: u32,
    /// Service start time
    pub start_time: i64,
}

impl DhcpClientState {
    const fn new() -> Self {
        DhcpClientState {
            running: false,
            interfaces: [const { InterfaceDhcp::empty() }; MAX_INTERFACES],
            interface_count: 0,
            next_xid: 1,
            start_time: 0,
        }
    }
}

/// Global state
static DHCP_STATE: Mutex<DhcpClientState> = Mutex::new(DhcpClientState::new());

/// Statistics
static DISCOVERS_SENT: AtomicU64 = AtomicU64::new(0);
static OFFERS_RECEIVED: AtomicU64 = AtomicU64::new(0);
static LEASES_OBTAINED: AtomicU64 = AtomicU64::new(0);
static LEASES_RENEWED: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize DHCP Client service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = DHCP_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    // Generate initial XID from time
    state.next_xid = (state.start_time as u32) ^ 0x12345678;

    crate::serial_println!("[DHCPC] DHCP Client service initialized");
}

/// Register a network interface for DHCP
pub fn register_interface(
    if_index: u32,
    if_name: &[u8],
    mac_addr: &[u8; 6],
) -> Result<usize, u32> {
    let mut state = DHCP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Check if already registered
    for iface in state.interfaces.iter() {
        if iface.valid && iface.if_index == if_index {
            return Err(0x80070055); // ERROR_DUP_NAME
        }
    }

    let slot = state.interfaces.iter().position(|i| !i.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let iface = &mut state.interfaces[slot];
    iface.if_index = if_index;

    let name_len = if_name.len().min(32);
    iface.if_name[..name_len].copy_from_slice(&if_name[..name_len]);

    iface.mac_addr = *mac_addr;
    iface.state = DhcpState::Init;
    iface.enabled = true;
    iface.xid = 0;
    iface.retries = 0;
    iface.state_change_time = crate::rtl::time::rtl_get_system_time();
    iface.valid = true;

    state.interface_count += 1;

    Ok(slot)
}

/// Unregister a network interface
pub fn unregister_interface(if_index: u32) -> Result<(), u32> {
    let mut state = DHCP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.interfaces.iter().position(|i| i.valid && i.if_index == if_index);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    // Release lease if bound
    if state.interfaces[idx].state == DhcpState::Bound {
        // Would send DHCPRELEASE here
    }

    state.interfaces[idx].valid = false;
    state.interface_count = state.interface_count.saturating_sub(1);

    Ok(())
}

/// Start DHCP on an interface
pub fn start_dhcp(if_index: u32) -> Result<(), u32> {
    let mut state = DHCP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Generate new XID before finding interface
    let xid = state.next_xid;
    state.next_xid = state.next_xid.wrapping_add(1);

    let iface = state.interfaces.iter_mut()
        .find(|i| i.valid && i.if_index == if_index);

    let iface = match iface {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    if !iface.enabled {
        return Err(0x80070005);
    }

    iface.xid = xid;
    iface.state = DhcpState::Selecting;
    iface.retries = 0;
    iface.state_change_time = crate::rtl::time::rtl_get_system_time();

    // Would send DHCPDISCOVER here
    DISCOVERS_SENT.fetch_add(1, Ordering::SeqCst);

    Ok(())
}

/// Process DHCP offer (simulated for now)
pub fn process_offer(
    if_index: u32,
    offered_addr: Ipv4Addr,
    server_addr: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    gateway: Ipv4Addr,
    dns_servers: &[Ipv4Addr],
    lease_time: u32,
) -> Result<(), u32> {
    let mut state = DHCP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let iface = state.interfaces.iter_mut()
        .find(|i| i.valid && i.if_index == if_index);

    let iface = match iface {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    if iface.state != DhcpState::Selecting {
        return Err(0x80070015); // ERROR_NOT_READY
    }

    OFFERS_RECEIVED.fetch_add(1, Ordering::SeqCst);

    // Store offer in lease (will be confirmed on ACK)
    iface.lease.address = offered_addr;
    iface.lease.subnet_mask = subnet_mask;
    iface.lease.gateway = gateway;
    iface.lease.dhcp_server = server_addr;
    iface.lease.lease_time = lease_time;
    iface.lease.t1_time = lease_time / 2;
    iface.lease.t2_time = (lease_time * 7) / 8;

    let dns_count = dns_servers.len().min(MAX_DNS_SERVERS);
    for (i, dns) in dns_servers.iter().take(dns_count).enumerate() {
        iface.lease.dns_servers[i] = *dns;
    }
    iface.lease.dns_count = dns_count;

    // Move to requesting state
    iface.state = DhcpState::Requesting;
    iface.state_change_time = crate::rtl::time::rtl_get_system_time();

    // Would send DHCPREQUEST here

    Ok(())
}

/// Process DHCP ACK (simulated)
pub fn process_ack(if_index: u32) -> Result<(), u32> {
    let mut state = DHCP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let iface = state.interfaces.iter_mut()
        .find(|i| i.valid && i.if_index == if_index);

    let iface = match iface {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    if iface.state != DhcpState::Requesting && iface.state != DhcpState::Renewing {
        return Err(0x80070015);
    }

    let now = crate::rtl::time::rtl_get_system_time();

    iface.lease.obtained = now;
    // Convert lease time from seconds to 100ns units
    iface.lease.expires = now + (iface.lease.lease_time as i64 * 10_000_000);

    let was_renewing = iface.state == DhcpState::Renewing;

    iface.state = DhcpState::Bound;
    iface.state_change_time = now;
    iface.retries = 0;

    if was_renewing {
        LEASES_RENEWED.fetch_add(1, Ordering::SeqCst);
    } else {
        LEASES_OBTAINED.fetch_add(1, Ordering::SeqCst);
    }

    Ok(())
}

/// Release DHCP lease
pub fn release_lease(if_index: u32) -> Result<(), u32> {
    let mut state = DHCP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let iface = state.interfaces.iter_mut()
        .find(|i| i.valid && i.if_index == if_index);

    let iface = match iface {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    if iface.state != DhcpState::Bound {
        return Err(0x80070015);
    }

    // Would send DHCPRELEASE here

    iface.lease = DhcpLease::empty();
    iface.state = DhcpState::Init;
    iface.state_change_time = crate::rtl::time::rtl_get_system_time();

    Ok(())
}

/// Renew DHCP lease
pub fn renew_lease(if_index: u32) -> Result<(), u32> {
    let mut state = DHCP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let iface = state.interfaces.iter_mut()
        .find(|i| i.valid && i.if_index == if_index);

    let iface = match iface {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    if iface.state != DhcpState::Bound {
        return Err(0x80070015);
    }

    iface.state = DhcpState::Renewing;
    iface.state_change_time = crate::rtl::time::rtl_get_system_time();

    // Would send DHCPREQUEST to current server here

    Ok(())
}

/// Get interface DHCP info
pub fn get_interface_info(if_index: u32) -> Option<InterfaceDhcp> {
    let state = DHCP_STATE.lock();

    state.interfaces.iter()
        .find(|i| i.valid && i.if_index == if_index)
        .cloned()
}

/// Get current lease for interface
pub fn get_lease(if_index: u32) -> Option<DhcpLease> {
    let state = DHCP_STATE.lock();

    state.interfaces.iter()
        .find(|i| i.valid && i.if_index == if_index && i.state == DhcpState::Bound)
        .map(|i| i.lease.clone())
}

/// Enumerate interfaces
pub fn enum_interfaces() -> ([InterfaceDhcp; MAX_INTERFACES], usize) {
    let state = DHCP_STATE.lock();
    let mut result = [const { InterfaceDhcp::empty() }; MAX_INTERFACES];
    let mut count = 0;

    for iface in state.interfaces.iter() {
        if iface.valid && count < MAX_INTERFACES {
            result[count] = iface.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Enable/disable DHCP on interface
pub fn set_enabled(if_index: u32, enabled: bool) -> Result<(), u32> {
    let mut state = DHCP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let iface = state.interfaces.iter_mut()
        .find(|i| i.valid && i.if_index == if_index);

    let iface = match iface {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    iface.enabled = enabled;

    if !enabled && iface.state == DhcpState::Bound {
        // Release lease when disabling
        iface.lease = DhcpLease::empty();
        iface.state = DhcpState::Disabled;
        iface.state_change_time = crate::rtl::time::rtl_get_system_time();
    }

    Ok(())
}

/// Check for lease expiration
pub fn check_lease_expiration() {
    let mut state = DHCP_STATE.lock();

    if !state.running {
        return;
    }

    let now = crate::rtl::time::rtl_get_system_time();

    for iface in state.interfaces.iter_mut() {
        if !iface.valid || iface.state != DhcpState::Bound {
            continue;
        }

        // Check if lease expired
        if now >= iface.lease.expires {
            iface.state = DhcpState::Init;
            iface.state_change_time = now;
            continue;
        }

        // Check if time to renew (T1)
        let t1_time = iface.lease.obtained + (iface.lease.t1_time as i64 * 10_000_000);
        if now >= t1_time && iface.state == DhcpState::Bound {
            iface.state = DhcpState::Renewing;
            iface.state_change_time = now;
        }

        // Check if time to rebind (T2)
        let t2_time = iface.lease.obtained + (iface.lease.t2_time as i64 * 10_000_000);
        if now >= t2_time && iface.state == DhcpState::Renewing {
            iface.state = DhcpState::Rebinding;
            iface.state_change_time = now;
        }
    }
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64, u64) {
    (
        DISCOVERS_SENT.load(Ordering::SeqCst),
        OFFERS_RECEIVED.load(Ordering::SeqCst),
        LEASES_OBTAINED.load(Ordering::SeqCst),
        LEASES_RENEWED.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = DHCP_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = DHCP_STATE.lock();
    state.running = false;

    // Release all leases
    for iface in state.interfaces.iter_mut() {
        if iface.valid && iface.state == DhcpState::Bound {
            // Would send DHCPRELEASE here
            iface.state = DhcpState::Init;
        }
    }

    crate::serial_println!("[DHCPC] DHCP Client service stopped");
}
