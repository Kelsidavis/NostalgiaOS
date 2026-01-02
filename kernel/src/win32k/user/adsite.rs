//! Active Directory Sites and Services (dssite.msc) implementation
//!
//! Provides management of AD replication topology, sites, site links,
//! subnets, and intersite transport configuration.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use crate::win32k::user::UserHandle;

/// Local type alias for window handles
type HWND = UserHandle;

/// Maximum sites
const MAX_SITES: usize = 64;

/// Maximum site links
const MAX_SITE_LINKS: usize = 128;

/// Maximum subnets
const MAX_SUBNETS: usize = 256;

/// Maximum servers per site
const MAX_SERVERS: usize = 32;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum description length
const MAX_DESC_LEN: usize = 128;

/// Transport type for site links
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TransportType {
    /// IP (RPC over IP)
    Ip = 0,
    /// SMTP (mail-based replication)
    Smtp = 1,
}

impl TransportType {
    /// Create new transport type
    pub const fn new() -> Self {
        Self::Ip
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Ip => "IP",
            Self::Smtp => "SMTP",
        }
    }
}

impl Default for TransportType {
    fn default() -> Self {
        Self::new()
    }
}

/// Server role type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServerRole {
    /// Standard domain controller
    DomainController = 0,
    /// Global catalog server
    GlobalCatalog = 1,
    /// Bridgehead server (preferred)
    BridgeheadPreferred = 2,
    /// Bridgehead server (active)
    BridgeheadActive = 3,
}

impl ServerRole {
    /// Create new server role
    pub const fn new() -> Self {
        Self::DomainController
    }
}

impl Default for ServerRole {
    fn default() -> Self {
        Self::new()
    }
}

/// NTDS Settings options
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NtdsOptions: u32 {
        /// Is global catalog
        const IS_GC = 0x00000001;
        /// Disable inbound replication
        const DISABLE_INBOUND_REPL = 0x00000002;
        /// Disable outbound replication
        const DISABLE_OUTBOUND_REPL = 0x00000004;
        /// Disable NTDS connection translation
        const DISABLE_NTDSCONN_XLATE = 0x00000008;
    }
}

impl Default for NtdsOptions {
    fn default() -> Self {
        Self::empty()
    }
}

/// Site link options
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SiteLinkOptions: u32 {
        /// Use notification for replication
        const USE_NOTIFY = 0x00000001;
        /// Two-way sync enabled
        const TWOWAY_SYNC = 0x00000002;
        /// Disable compression
        const DISABLE_COMPRESSION = 0x00000004;
    }
}

impl Default for SiteLinkOptions {
    fn default() -> Self {
        Self::empty()
    }
}

/// Replication schedule (168 hours = 1 week)
#[derive(Clone)]
pub struct ReplicationSchedule {
    /// Schedule bitmap (1 bit per hour, 168 bits = 21 bytes)
    /// Bit set = replication available during that hour
    pub schedule: [u8; 21],
}

impl ReplicationSchedule {
    /// Create new schedule (all hours available)
    pub const fn new() -> Self {
        Self {
            schedule: [0xFF; 21],
        }
    }

    /// Create schedule with no availability
    pub const fn none() -> Self {
        Self {
            schedule: [0; 21],
        }
    }

    /// Check if hour is available (0-167)
    pub fn is_available(&self, hour: u8) -> bool {
        if hour >= 168 {
            return false;
        }
        let byte_idx = (hour / 8) as usize;
        let bit_idx = hour % 8;
        (self.schedule[byte_idx] & (1 << bit_idx)) != 0
    }

    /// Set hour availability
    pub fn set_available(&mut self, hour: u8, available: bool) {
        if hour >= 168 {
            return;
        }
        let byte_idx = (hour / 8) as usize;
        let bit_idx = hour % 8;
        if available {
            self.schedule[byte_idx] |= 1 << bit_idx;
        } else {
            self.schedule[byte_idx] &= !(1 << bit_idx);
        }
    }
}

impl Default for ReplicationSchedule {
    fn default() -> Self {
        Self::new()
    }
}

/// Subnet definition
#[derive(Clone)]
pub struct Subnet {
    /// Subnet ID
    pub subnet_id: u32,
    /// Subnet address (e.g., "192.168.1.0")
    pub address: [u8; 16],
    /// Address length
    pub addr_len: usize,
    /// Subnet mask bits (e.g., 24 for /24)
    pub mask_bits: u8,
    /// Reserved
    pub reserved: [u8; 3],
    /// Name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub desc_len: usize,
    /// Associated site ID
    pub site_id: u32,
    /// Location
    pub location: [u8; MAX_NAME_LEN],
    /// Location length
    pub location_len: usize,
    /// In use flag
    pub in_use: bool,
}

impl Subnet {
    /// Create new subnet
    pub const fn new() -> Self {
        Self {
            subnet_id: 0,
            address: [0; 16],
            addr_len: 0,
            mask_bits: 0,
            reserved: [0; 3],
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            description: [0; MAX_DESC_LEN],
            desc_len: 0,
            site_id: 0,
            location: [0; MAX_NAME_LEN],
            location_len: 0,
            in_use: false,
        }
    }

    /// Set address
    pub fn set_address(&mut self, addr: &[u8], mask: u8) {
        let len = addr.len().min(16);
        self.address[..len].copy_from_slice(&addr[..len]);
        self.addr_len = len;
        self.mask_bits = mask;
    }

    /// Set name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

impl Default for Subnet {
    fn default() -> Self {
        Self::new()
    }
}

/// Server in a site
#[derive(Clone)]
pub struct SiteServer {
    /// Server ID
    pub server_id: u32,
    /// Server name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// DNS host name
    pub dns_name: [u8; MAX_NAME_LEN],
    /// DNS name length
    pub dns_len: usize,
    /// Server role
    pub role: ServerRole,
    /// NTDS options
    pub ntds_options: NtdsOptions,
    /// Is bridgehead server
    pub is_bridgehead: bool,
    /// Is inter-site topology generator
    pub is_istg: bool,
    /// Reserved
    pub reserved: [u8; 2],
    /// NTDS settings DN
    pub ntds_dn: [u8; 128],
    /// NTDS DN length
    pub ntds_dn_len: usize,
    /// Parent site ID
    pub site_id: u32,
    /// In use flag
    pub in_use: bool,
}

impl SiteServer {
    /// Create new server
    pub const fn new() -> Self {
        Self {
            server_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            dns_name: [0; MAX_NAME_LEN],
            dns_len: 0,
            role: ServerRole::DomainController,
            ntds_options: NtdsOptions::empty(),
            is_bridgehead: false,
            is_istg: false,
            reserved: [0; 2],
            ntds_dn: [0; 128],
            ntds_dn_len: 0,
            site_id: 0,
            in_use: false,
        }
    }

    /// Set server name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Is global catalog
    pub fn is_gc(&self) -> bool {
        self.ntds_options.contains(NtdsOptions::IS_GC)
    }
}

impl Default for SiteServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Site link
#[derive(Clone)]
pub struct SiteLink {
    /// Site link ID
    pub link_id: u32,
    /// Name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub desc_len: usize,
    /// Transport type
    pub transport: TransportType,
    /// Cost
    pub cost: u32,
    /// Replication interval (minutes)
    pub repl_interval: u32,
    /// Options
    pub options: SiteLinkOptions,
    /// Linked site IDs
    pub sites: [u32; 16],
    /// Number of linked sites
    pub site_count: usize,
    /// Replication schedule
    pub schedule: ReplicationSchedule,
    /// In use flag
    pub in_use: bool,
}

impl SiteLink {
    /// Create new site link
    pub const fn new() -> Self {
        Self {
            link_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            description: [0; MAX_DESC_LEN],
            desc_len: 0,
            transport: TransportType::Ip,
            cost: 100,
            repl_interval: 180, // 3 hours default
            options: SiteLinkOptions::empty(),
            sites: [0; 16],
            site_count: 0,
            schedule: ReplicationSchedule::new(),
            in_use: false,
        }
    }

    /// Set name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Add site to link
    pub fn add_site(&mut self, site_id: u32) -> bool {
        if self.site_count >= 16 {
            return false;
        }
        // Check for duplicates
        for i in 0..self.site_count {
            if self.sites[i] == site_id {
                return true;
            }
        }
        self.sites[self.site_count] = site_id;
        self.site_count += 1;
        true
    }

    /// Remove site from link
    pub fn remove_site(&mut self, site_id: u32) -> bool {
        for i in 0..self.site_count {
            if self.sites[i] == site_id {
                for j in i..self.site_count - 1 {
                    self.sites[j] = self.sites[j + 1];
                }
                self.site_count -= 1;
                return true;
            }
        }
        false
    }
}

impl Default for SiteLink {
    fn default() -> Self {
        Self::new()
    }
}

/// Site link bridge
#[derive(Clone)]
pub struct SiteLinkBridge {
    /// Bridge ID
    pub bridge_id: u32,
    /// Name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Transport type
    pub transport: TransportType,
    /// Linked site link IDs
    pub links: [u32; 16],
    /// Number of linked site links
    pub link_count: usize,
    /// In use flag
    pub in_use: bool,
}

impl SiteLinkBridge {
    /// Create new bridge
    pub const fn new() -> Self {
        Self {
            bridge_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            transport: TransportType::Ip,
            links: [0; 16],
            link_count: 0,
            in_use: false,
        }
    }

    /// Set name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

impl Default for SiteLinkBridge {
    fn default() -> Self {
        Self::new()
    }
}

/// Site
#[derive(Clone)]
pub struct Site {
    /// Site ID
    pub site_id: u32,
    /// Name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub desc_len: usize,
    /// Distinguished name
    pub dn: [u8; 128],
    /// DN length
    pub dn_len: usize,
    /// Location
    pub location: [u8; MAX_NAME_LEN],
    /// Location length
    pub location_len: usize,
    /// Servers in site
    pub servers: [SiteServer; MAX_SERVERS],
    /// Server count
    pub server_count: usize,
    /// Inter-site topology generator server ID
    pub istg_server_id: u32,
    /// Site options
    pub options: u32,
    /// In use flag
    pub in_use: bool,
}

impl Site {
    /// Create new site
    pub const fn new() -> Self {
        Self {
            site_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            description: [0; MAX_DESC_LEN],
            desc_len: 0,
            dn: [0; 128],
            dn_len: 0,
            location: [0; MAX_NAME_LEN],
            location_len: 0,
            servers: [const { SiteServer::new() }; MAX_SERVERS],
            server_count: 0,
            istg_server_id: 0,
            options: 0,
            in_use: false,
        }
    }

    /// Set name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Get name
    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Find server by ID
    pub fn find_server(&self, server_id: u32) -> Option<usize> {
        for (i, server) in self.servers.iter().enumerate() {
            if server.in_use && server.server_id == server_id {
                return Some(i);
            }
        }
        None
    }
}

impl Default for Site {
    fn default() -> Self {
        Self::new()
    }
}

/// AD Sites and Services state
pub struct AdSiteState {
    /// Sites
    pub sites: [Site; MAX_SITES],
    /// Site count
    pub site_count: usize,
    /// Site links
    pub site_links: [SiteLink; MAX_SITE_LINKS],
    /// Site link count
    pub link_count: usize,
    /// Subnets
    pub subnets: [Subnet; MAX_SUBNETS],
    /// Subnet count
    pub subnet_count: usize,
    /// Site link bridges
    pub bridges: [SiteLinkBridge; 32],
    /// Bridge count
    pub bridge_count: usize,
    /// Next object ID
    pub next_id: u32,
    /// Bridge all site links (IP)
    pub bridge_all_ip: bool,
    /// Bridge all site links (SMTP)
    pub bridge_all_smtp: bool,
    /// Reserved
    pub reserved: [u8; 2],
    /// Connected to forest
    pub connected: bool,
    /// Forest name
    pub forest: [u8; MAX_NAME_LEN],
    /// Forest name length
    pub forest_len: usize,
}

impl AdSiteState {
    /// Create new state
    pub const fn new() -> Self {
        Self {
            sites: [const { Site::new() }; MAX_SITES],
            site_count: 0,
            site_links: [const { SiteLink::new() }; MAX_SITE_LINKS],
            link_count: 0,
            subnets: [const { Subnet::new() }; MAX_SUBNETS],
            subnet_count: 0,
            bridges: [const { SiteLinkBridge::new() }; 32],
            bridge_count: 0,
            next_id: 1,
            bridge_all_ip: true,
            bridge_all_smtp: true,
            reserved: [0; 2],
            connected: false,
            forest: [0; MAX_NAME_LEN],
            forest_len: 0,
        }
    }

    /// Find site by ID
    pub fn find_site(&self, site_id: u32) -> Option<usize> {
        for (i, site) in self.sites.iter().enumerate() {
            if site.in_use && site.site_id == site_id {
                return Some(i);
            }
        }
        None
    }

    /// Find site link by ID
    pub fn find_link(&self, link_id: u32) -> Option<usize> {
        for (i, link) in self.site_links.iter().enumerate() {
            if link.in_use && link.link_id == link_id {
                return Some(i);
            }
        }
        None
    }

    /// Find subnet by ID
    pub fn find_subnet(&self, subnet_id: u32) -> Option<usize> {
        for (i, subnet) in self.subnets.iter().enumerate() {
            if subnet.in_use && subnet.subnet_id == subnet_id {
                return Some(i);
            }
        }
        None
    }
}

impl Default for AdSiteState {
    fn default() -> Self {
        Self::new()
    }
}

/// Global state
static ADSITE_STATE: SpinLock<AdSiteState> = SpinLock::new(AdSiteState::new());

/// Initialization flag
static ADSITE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Statistics
static ADSITE_OPERATION_COUNT: AtomicU32 = AtomicU32::new(0);

/// Error codes
pub mod error {
    pub const SUCCESS: u32 = 0;
    pub const NOT_INITIALIZED: u32 = 0xA5000001;
    pub const NOT_CONNECTED: u32 = 0xA5000002;
    pub const SITE_NOT_FOUND: u32 = 0xA5000003;
    pub const LINK_NOT_FOUND: u32 = 0xA5000004;
    pub const SUBNET_NOT_FOUND: u32 = 0xA5000005;
    pub const SERVER_NOT_FOUND: u32 = 0xA5000006;
    pub const ALREADY_EXISTS: u32 = 0xA5000007;
    pub const INVALID_PARAMETER: u32 = 0xA5000008;
    pub const NO_MORE_OBJECTS: u32 = 0xA5000009;
    pub const IN_USE: u32 = 0xA500000A;
}

/// Initialize AD Sites and Services
pub fn init() {
    if ADSITE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = ADSITE_STATE.lock();

    // Set forest name
    let forest_name = b"forest.local";
    let len = forest_name.len();
    state.forest[..len].copy_from_slice(forest_name);
    state.forest_len = len;
    state.connected = true;

    // Create Default-First-Site-Name
    let site_id = state.next_id;
    state.next_id += 1;

    let site = &mut state.sites[0];
    site.in_use = true;
    site.site_id = site_id;
    site.set_name(b"Default-First-Site-Name");
    state.site_count = 1;

    // Create default DC server in site
    let server_id = state.next_id;
    state.next_id += 1;

    let server = &mut state.sites[0].servers[0];
    server.in_use = true;
    server.server_id = server_id;
    server.set_name(b"DC1");
    server.role = ServerRole::DomainController;
    server.ntds_options = NtdsOptions::IS_GC;
    server.is_istg = true;
    server.site_id = site_id;
    state.sites[0].server_count = 1;
    state.sites[0].istg_server_id = server_id;

    // Create DEFAULTIPSITELINK
    let link_id = state.next_id;
    state.next_id += 1;

    let link = &mut state.site_links[0];
    link.in_use = true;
    link.link_id = link_id;
    link.set_name(b"DEFAULTIPSITELINK");
    link.transport = TransportType::Ip;
    link.cost = 100;
    link.repl_interval = 180;
    link.sites[0] = site_id;
    link.site_count = 1;
    state.link_count = 1;
}

/// Create a new site
pub fn create_site(name: &[u8]) -> Result<u32, u32> {
    if !ADSITE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADSITE_STATE.lock();

    if !state.connected {
        return Err(error::NOT_CONNECTED);
    }

    // Find free slot
    let mut slot_idx = None;
    for (i, site) in state.sites.iter().enumerate() {
        if !site.in_use {
            slot_idx = Some(i);
            break;
        }
    }

    let idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::NO_MORE_OBJECTS),
    };

    let site_id = state.next_id;
    state.next_id += 1;

    let site = &mut state.sites[idx];
    site.in_use = true;
    site.site_id = site_id;
    site.set_name(name);

    state.site_count += 1;
    ADSITE_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(site_id)
}

/// Delete a site
pub fn delete_site(site_id: u32) -> Result<(), u32> {
    if !ADSITE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADSITE_STATE.lock();

    let idx = match state.find_site(site_id) {
        Some(i) => i,
        None => return Err(error::SITE_NOT_FOUND),
    };

    // Check if site has servers
    if state.sites[idx].server_count > 0 {
        return Err(error::IN_USE);
    }

    state.sites[idx].in_use = false;
    state.site_count = state.site_count.saturating_sub(1);

    // Remove from site links
    for link in state.site_links.iter_mut() {
        if link.in_use {
            link.remove_site(site_id);
        }
    }

    ADSITE_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Create a site link
pub fn create_site_link(
    name: &[u8],
    transport: TransportType,
    site_ids: &[u32],
    cost: u32,
) -> Result<u32, u32> {
    if !ADSITE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    if site_ids.len() < 2 {
        return Err(error::INVALID_PARAMETER);
    }

    let mut state = ADSITE_STATE.lock();

    // Find free slot
    let mut slot_idx = None;
    for (i, link) in state.site_links.iter().enumerate() {
        if !link.in_use {
            slot_idx = Some(i);
            break;
        }
    }

    let idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::NO_MORE_OBJECTS),
    };

    let link_id = state.next_id;
    state.next_id += 1;

    let link = &mut state.site_links[idx];
    link.in_use = true;
    link.link_id = link_id;
    link.set_name(name);
    link.transport = transport;
    link.cost = cost;
    link.repl_interval = 180;

    for &site_id in site_ids.iter().take(16) {
        link.add_site(site_id);
    }

    state.link_count += 1;
    ADSITE_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(link_id)
}

/// Delete a site link
pub fn delete_site_link(link_id: u32) -> Result<(), u32> {
    if !ADSITE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADSITE_STATE.lock();

    let idx = match state.find_link(link_id) {
        Some(i) => i,
        None => return Err(error::LINK_NOT_FOUND),
    };

    state.site_links[idx].in_use = false;
    state.link_count = state.link_count.saturating_sub(1);

    ADSITE_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Set site link cost
pub fn set_link_cost(link_id: u32, cost: u32) -> Result<(), u32> {
    if !ADSITE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADSITE_STATE.lock();

    let idx = match state.find_link(link_id) {
        Some(i) => i,
        None => return Err(error::LINK_NOT_FOUND),
    };

    state.site_links[idx].cost = cost;

    ADSITE_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Set site link replication interval
pub fn set_link_interval(link_id: u32, interval_minutes: u32) -> Result<(), u32> {
    if !ADSITE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    if interval_minutes < 15 {
        return Err(error::INVALID_PARAMETER);
    }

    let mut state = ADSITE_STATE.lock();

    let idx = match state.find_link(link_id) {
        Some(i) => i,
        None => return Err(error::LINK_NOT_FOUND),
    };

    state.site_links[idx].repl_interval = interval_minutes;

    ADSITE_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Create a subnet
pub fn create_subnet(address: &[u8], mask_bits: u8, site_id: u32) -> Result<u32, u32> {
    if !ADSITE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADSITE_STATE.lock();

    // Verify site exists
    if state.find_site(site_id).is_none() {
        return Err(error::SITE_NOT_FOUND);
    }

    // Find free slot
    let mut slot_idx = None;
    for (i, subnet) in state.subnets.iter().enumerate() {
        if !subnet.in_use {
            slot_idx = Some(i);
            break;
        }
    }

    let idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::NO_MORE_OBJECTS),
    };

    let subnet_id = state.next_id;
    state.next_id += 1;

    let subnet = &mut state.subnets[idx];
    subnet.in_use = true;
    subnet.subnet_id = subnet_id;
    subnet.set_address(address, mask_bits);
    subnet.site_id = site_id;

    state.subnet_count += 1;
    ADSITE_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(subnet_id)
}

/// Delete a subnet
pub fn delete_subnet(subnet_id: u32) -> Result<(), u32> {
    if !ADSITE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADSITE_STATE.lock();

    let idx = match state.find_subnet(subnet_id) {
        Some(i) => i,
        None => return Err(error::SUBNET_NOT_FOUND),
    };

    state.subnets[idx].in_use = false;
    state.subnet_count = state.subnet_count.saturating_sub(1);

    ADSITE_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Move subnet to different site
pub fn move_subnet(subnet_id: u32, new_site_id: u32) -> Result<(), u32> {
    if !ADSITE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADSITE_STATE.lock();

    // Verify new site exists
    if state.find_site(new_site_id).is_none() {
        return Err(error::SITE_NOT_FOUND);
    }

    let idx = match state.find_subnet(subnet_id) {
        Some(i) => i,
        None => return Err(error::SUBNET_NOT_FOUND),
    };

    state.subnets[idx].site_id = new_site_id;

    ADSITE_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Force replication now
pub fn replicate_now(server_id: u32) -> Result<(), u32> {
    if !ADSITE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let state = ADSITE_STATE.lock();

    // Find server across all sites
    let mut found = false;
    for site in state.sites.iter() {
        if site.in_use && site.find_server(server_id).is_some() {
            found = true;
            break;
        }
    }

    if !found {
        return Err(error::SERVER_NOT_FOUND);
    }

    // In real implementation, would trigger KCC and replication

    ADSITE_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Get site count
pub fn get_site_count() -> usize {
    if !ADSITE_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = ADSITE_STATE.lock();
    state.site_count
}

/// Get subnet count
pub fn get_subnet_count() -> usize {
    if !ADSITE_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = ADSITE_STATE.lock();
    state.subnet_count
}

/// Create AD Sites and Services window
pub fn create_adsite_dialog(parent: HWND) -> HWND {
    if !ADSITE_INITIALIZED.load(Ordering::SeqCst) {
        init();
    }

    let id = 0xA51E0000u32;
    let _parent = parent;

    UserHandle::from_raw(id)
}

/// Dialog messages
pub mod messages {
    pub const ADSITE_REFRESH: u32 = 0x0750;
    pub const ADSITE_CREATE_SITE: u32 = 0x0751;
    pub const ADSITE_DELETE_SITE: u32 = 0x0752;
    pub const ADSITE_CREATE_LINK: u32 = 0x0753;
    pub const ADSITE_DELETE_LINK: u32 = 0x0754;
    pub const ADSITE_CREATE_SUBNET: u32 = 0x0755;
    pub const ADSITE_DELETE_SUBNET: u32 = 0x0756;
    pub const ADSITE_PROPERTIES: u32 = 0x0757;
    pub const ADSITE_REPLICATE_NOW: u32 = 0x0758;
    pub const ADSITE_CHECK_TOPOLOGY: u32 = 0x0759;
}

/// Get statistics
pub fn get_statistics() -> (usize, usize, usize, u32) {
    let state = ADSITE_STATE.lock();
    let op_count = ADSITE_OPERATION_COUNT.load(Ordering::Relaxed);
    (state.site_count, state.link_count, state.subnet_count, op_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adsite_init() {
        init();
        assert!(ADSITE_INITIALIZED.load(Ordering::SeqCst));
    }

    #[test]
    fn test_replication_schedule() {
        let mut sched = ReplicationSchedule::new();
        assert!(sched.is_available(0));
        sched.set_available(0, false);
        assert!(!sched.is_available(0));
    }

    #[test]
    fn test_transport_type() {
        assert_eq!(TransportType::Ip.display_name(), "IP");
    }
}
