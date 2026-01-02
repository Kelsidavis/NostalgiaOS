//! Computer Browser Service
//!
//! The Computer Browser service maintains an up-to-date list of computers
//! on the network and supplies this list to programs that request it.
//! This powers Network Neighborhood/My Network Places browsing.
//!
//! # Browser Roles
//!
//! - **Master Browser**: Maintains the browse list for a subnet
//! - **Backup Browser**: Receives copy of browse list from master
//! - **Potential Browser**: Can become backup if needed
//! - **Non-Browser**: Does not participate in browsing
//!
//! # Features
//!
//! - **Browse List**: Track computers on the network
//! - **Domain List**: Track domains/workgroups
//! - **Master Election**: Elect master browser for subnet
//! - **Announcement Processing**: Handle server announcements
//!
//! # Protocol
//!
//! Uses NetBIOS over TCP/IP for announcements and elections.
//! Servers announce themselves periodically; browsers collect these.

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum computers in browse list
const MAX_COMPUTERS: usize = 256;

/// Maximum domains/workgroups
const MAX_DOMAINS: usize = 32;

/// Maximum computer name length
const MAX_COMPUTER_NAME: usize = 16;

/// Maximum domain name length
const MAX_DOMAIN_NAME: usize = 16;

/// Maximum comment length
const MAX_COMMENT: usize = 80;

/// Browser role
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserRole {
    /// Not participating in browsing
    NonBrowser = 0,
    /// Can become backup browser
    PotentialBrowser = 1,
    /// Backup browser
    BackupBrowser = 2,
    /// Master browser for subnet
    MasterBrowser = 3,
    /// Domain master browser
    DomainMaster = 4,
}

impl BrowserRole {
    const fn empty() -> Self {
        BrowserRole::PotentialBrowser
    }
}

/// Server type flags (from lmserver.h SV_TYPE_*)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerType {
    /// Workstation (shares resources)
    Workstation = 0x00000001,
    /// Server (LanmanServer running)
    Server = 0x00000002,
    /// SQL Server
    SqlServer = 0x00000004,
    /// Domain Controller
    DomainCtrl = 0x00000008,
    /// Backup Domain Controller
    BackupDomainCtrl = 0x00000010,
    /// Time source
    TimeSource = 0x00000020,
    /// Apple File Protocol server
    Afp = 0x00000040,
    /// Novell server
    Novell = 0x00000080,
    /// LAN Manager 2.x Domain Member
    DomainMember = 0x00000100,
    /// Print server
    PrintQueue = 0x00000200,
    /// Dialin server
    Dialin = 0x00000400,
    /// Xenix server
    Xenix = 0x00000800,
    /// NT Workstation
    NtWorkstation = 0x00001000,
    /// Windows for Workgroups
    Wfw = 0x00002000,
    /// NT Server
    NtServer = 0x00008000,
    /// Potential Browser
    PotentialBrowser = 0x00010000,
    /// Backup Browser
    BackupBrowser = 0x00020000,
    /// Master Browser
    MasterBrowser = 0x00040000,
    /// Domain Master Browser
    DomainMaster = 0x00080000,
    /// Windows 2000 or later
    Windows = 0x00400000,
    /// Terminal Server
    TerminalServer = 0x02000000,
    /// Domain Enum
    DomainEnum = 0x80000000,
}

/// Computer entry in browse list
#[repr(C)]
#[derive(Clone)]
pub struct ComputerEntry {
    /// Computer name (NetBIOS)
    pub name: [u8; MAX_COMPUTER_NAME],
    /// Server type flags
    pub server_type: u32,
    /// Comment/description
    pub comment: [u8; MAX_COMMENT],
    /// Major version
    pub version_major: u8,
    /// Minor version
    pub version_minor: u8,
    /// Domain/workgroup name
    pub domain: [u8; MAX_DOMAIN_NAME],
    /// Last announcement time
    pub last_announcement: i64,
    /// Announcement period (seconds)
    pub announce_period: u32,
    /// Entry is valid
    pub valid: bool,
}

impl ComputerEntry {
    const fn empty() -> Self {
        ComputerEntry {
            name: [0; MAX_COMPUTER_NAME],
            server_type: 0,
            comment: [0; MAX_COMMENT],
            version_major: 5,
            version_minor: 2,
            domain: [0; MAX_DOMAIN_NAME],
            last_announcement: 0,
            announce_period: 720, // 12 minutes default
            valid: false,
        }
    }
}

/// Domain/workgroup entry
#[repr(C)]
#[derive(Clone)]
pub struct DomainEntry {
    /// Domain name
    pub name: [u8; MAX_DOMAIN_NAME],
    /// Master browser name
    pub master_browser: [u8; MAX_COMPUTER_NAME],
    /// Is domain (vs workgroup)
    pub is_domain: bool,
    /// Computer count in domain
    pub computer_count: u32,
    /// Last update time
    pub last_update: i64,
    /// Entry is valid
    pub valid: bool,
}

impl DomainEntry {
    const fn empty() -> Self {
        DomainEntry {
            name: [0; MAX_DOMAIN_NAME],
            master_browser: [0; MAX_COMPUTER_NAME],
            is_domain: false,
            computer_count: 0,
            last_update: 0,
            valid: false,
        }
    }
}

/// Browser election criteria
#[repr(C)]
#[derive(Clone)]
pub struct ElectionCriteria {
    /// OS version (higher = more priority)
    pub os_version: u32,
    /// Election version (browser protocol version)
    pub election_version: u8,
    /// Browser criteria bits
    pub criteria: u32,
    /// Uptime in seconds
    pub uptime: u32,
}

impl ElectionCriteria {
    const fn default() -> Self {
        ElectionCriteria {
            os_version: 0x00050002, // NT 5.2
            election_version: 1,
            criteria: 0x00010000, // Potential browser
            uptime: 0,
        }
    }
}

/// Browser service state
pub struct BrowserState {
    /// Service is running
    pub running: bool,
    /// Our role
    pub role: BrowserRole,
    /// Our computer name
    pub computer_name: [u8; MAX_COMPUTER_NAME],
    /// Our domain/workgroup
    pub domain_name: [u8; MAX_DOMAIN_NAME],
    /// Our server type flags
    pub server_type: u32,
    /// Election criteria
    pub election: ElectionCriteria,
    /// Browse list
    pub computers: [ComputerEntry; MAX_COMPUTERS],
    /// Computer count
    pub computer_count: usize,
    /// Domains list
    pub domains: [DomainEntry; MAX_DOMAINS],
    /// Domain count
    pub domain_count: usize,
    /// Announcement period (seconds)
    pub announce_period: u32,
    /// Last announcement time
    pub last_announce: i64,
    /// Is master browser
    pub is_master: bool,
    /// Election in progress
    pub election_in_progress: bool,
    /// Service start time
    pub start_time: i64,
}

impl BrowserState {
    const fn new() -> Self {
        BrowserState {
            running: false,
            role: BrowserRole::empty(),
            computer_name: [0; MAX_COMPUTER_NAME],
            domain_name: [0; MAX_DOMAIN_NAME],
            server_type: 0x00011003, // Workstation | Server | Potential Browser | NT
            election: ElectionCriteria::default(),
            computers: [const { ComputerEntry::empty() }; MAX_COMPUTERS],
            computer_count: 0,
            domains: [const { DomainEntry::empty() }; MAX_DOMAINS],
            domain_count: 0,
            announce_period: 720, // 12 minutes
            last_announce: 0,
            is_master: false,
            election_in_progress: false,
            start_time: 0,
        }
    }
}

/// Global state
static BROWSER_STATE: Mutex<BrowserState> = Mutex::new(BrowserState::new());

/// Statistics
static ANNOUNCEMENTS_SENT: AtomicU64 = AtomicU64::new(0);
static ANNOUNCEMENTS_RECEIVED: AtomicU64 = AtomicU64::new(0);
static ELECTIONS_PARTICIPATED: AtomicU64 = AtomicU64::new(0);
static ELECTIONS_WON: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize Browser service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = BROWSER_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    // Set default computer name
    let name = b"NOSTALGOS";
    state.computer_name[..name.len()].copy_from_slice(name);

    // Set default workgroup
    let domain = b"WORKGROUP";
    state.domain_name[..domain.len()].copy_from_slice(domain);

    // Extract values before mutable borrows
    let server_type = state.server_type;
    let start_time = state.start_time;

    // Add ourselves to the browse list
    let self_entry = &mut state.computers[0];
    self_entry.name[..name.len()].copy_from_slice(name);
    self_entry.domain[..domain.len()].copy_from_slice(domain);
    self_entry.server_type = server_type;
    self_entry.version_major = 5;
    self_entry.version_minor = 2;
    self_entry.last_announcement = start_time;
    self_entry.valid = true;

    state.computer_count = 1;

    // Add our domain
    let domain_entry = &mut state.domains[0];
    domain_entry.name[..domain.len()].copy_from_slice(domain);
    domain_entry.is_domain = false;
    domain_entry.computer_count = 1;
    domain_entry.last_update = start_time;
    domain_entry.valid = true;

    state.domain_count = 1;

    crate::serial_println!("[BROWSER] Computer Browser service initialized");
}

/// Process a server announcement
pub fn process_announcement(
    name: &[u8],
    domain: &[u8],
    server_type: u32,
    version_major: u8,
    version_minor: u8,
    comment: &[u8],
    announce_period: u32,
) -> Result<(), u32> {
    let mut state = BROWSER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    ANNOUNCEMENTS_RECEIVED.fetch_add(1, Ordering::SeqCst);

    let now = crate::rtl::time::rtl_get_system_time();
    let name_len = name.len().min(MAX_COMPUTER_NAME);

    // Check if computer already exists
    let existing = state.computers.iter().position(|c| {
        c.valid && c.name[..name_len] == name[..name_len]
    });

    let slot = match existing {
        Some(idx) => idx,
        None => {
            // Find free slot
            match state.computers.iter().position(|c| !c.valid) {
                Some(s) => {
                    state.computer_count += 1;
                    s
                }
                None => return Err(0x8007000E),
            }
        }
    };

    let computer = &mut state.computers[slot];
    computer.name = [0; MAX_COMPUTER_NAME];
    computer.name[..name_len].copy_from_slice(&name[..name_len]);
    computer.server_type = server_type;
    computer.version_major = version_major;
    computer.version_minor = version_minor;
    computer.announce_period = announce_period;
    computer.last_announcement = now;
    computer.valid = true;

    let domain_len = domain.len().min(MAX_DOMAIN_NAME);
    computer.domain = [0; MAX_DOMAIN_NAME];
    computer.domain[..domain_len].copy_from_slice(&domain[..domain_len]);

    let comment_len = comment.len().min(MAX_COMMENT);
    computer.comment = [0; MAX_COMMENT];
    computer.comment[..comment_len].copy_from_slice(&comment[..comment_len]);

    // Update domain computer count
    for dom in state.domains.iter_mut() {
        if dom.valid && dom.name[..domain_len] == domain[..domain_len] {
            dom.last_update = now;
        }
    }

    Ok(())
}

/// Send our announcement
pub fn send_announcement() -> Result<(), u32> {
    let mut state = BROWSER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let now = crate::rtl::time::rtl_get_system_time();
    state.last_announce = now;

    // Extract our computer name before mutable borrow
    let our_name = state.computer_name;

    // Update our entry
    if let Some(entry) = state.computers.iter_mut().find(|c| {
        c.valid && c.name == our_name
    }) {
        entry.last_announcement = now;
    }

    ANNOUNCEMENTS_SENT.fetch_add(1, Ordering::SeqCst);

    // Would send actual NetBIOS datagram here

    Ok(())
}

/// Force an election
pub fn force_election() -> Result<(), u32> {
    let mut state = BROWSER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    state.election_in_progress = true;
    state.election.uptime = ((crate::rtl::time::rtl_get_system_time() - state.start_time) / 10_000_000) as u32;

    ELECTIONS_PARTICIPATED.fetch_add(1, Ordering::SeqCst);

    // Would send election request datagram here

    Ok(())
}

/// Process an election packet
pub fn process_election(
    computer_name: &[u8],
    criteria: &ElectionCriteria,
) -> Result<bool, u32> {
    let mut state = BROWSER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    state.election_in_progress = true;

    // Compare criteria (simplified)
    let our_priority = (state.election.os_version as u64) << 32
        | (state.election.criteria as u64) << 16
        | (state.election.uptime as u64);

    let their_priority = (criteria.os_version as u64) << 32
        | (criteria.criteria as u64) << 16
        | (criteria.uptime as u64);

    // Extract values before mutable borrows
    let our_computer_name = state.computer_name;
    let our_domain_name = state.domain_name;
    let name_len = our_computer_name.iter().position(|&c| c == 0).unwrap_or(MAX_COMPUTER_NAME);
    let their_name_len = computer_name.len().min(MAX_COMPUTER_NAME);

    if our_priority > their_priority {
        // We win, become master
        state.role = BrowserRole::MasterBrowser;
        state.is_master = true;
        state.server_type |= 0x00040000; // SV_TYPE_MASTER_BROWSER
        let new_server_type = state.server_type;

        // Update our entry
        for computer in state.computers.iter_mut() {
            if computer.valid && computer.name == our_computer_name {
                computer.server_type = new_server_type;
            }
        }

        // Update domain master browser
        for domain in state.domains.iter_mut() {
            if domain.valid && domain.name == our_domain_name {
                domain.master_browser = [0; MAX_COMPUTER_NAME];
                domain.master_browser[..name_len].copy_from_slice(&our_computer_name[..name_len]);
            }
        }

        state.election_in_progress = false;
        ELECTIONS_WON.fetch_add(1, Ordering::SeqCst);
        return Ok(true);
    }

    // They win
    state.role = BrowserRole::BackupBrowser;
    state.is_master = false;
    state.server_type &= !0x00040000; // Clear master bit
    state.server_type |= 0x00020000; // Set backup bit

    // Record new master
    for domain in state.domains.iter_mut() {
        if domain.valid && domain.name == our_domain_name {
            domain.master_browser = [0; MAX_COMPUTER_NAME];
            domain.master_browser[..their_name_len].copy_from_slice(&computer_name[..their_name_len]);
        }
    }

    state.election_in_progress = false;

    Ok(false)
}

/// Get browse list for a domain
pub fn get_browse_list(domain: &[u8]) -> ([ComputerEntry; MAX_COMPUTERS], usize) {
    let state = BROWSER_STATE.lock();
    let mut result = [const { ComputerEntry::empty() }; MAX_COMPUTERS];
    let mut count = 0;

    let domain_len = domain.len().min(MAX_DOMAIN_NAME);

    for computer in state.computers.iter() {
        if computer.valid && count < MAX_COMPUTERS {
            if domain.is_empty() || computer.domain[..domain_len] == domain[..domain_len] {
                result[count] = computer.clone();
                count += 1;
            }
        }
    }

    (result, count)
}

/// Get domain/workgroup list
pub fn get_domain_list() -> ([DomainEntry; MAX_DOMAINS], usize) {
    let state = BROWSER_STATE.lock();
    let mut result = [const { DomainEntry::empty() }; MAX_DOMAINS];
    let mut count = 0;

    for domain in state.domains.iter() {
        if domain.valid && count < MAX_DOMAINS {
            result[count] = domain.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get computer info
pub fn get_computer(name: &[u8]) -> Option<ComputerEntry> {
    let state = BROWSER_STATE.lock();
    let name_len = name.len().min(MAX_COMPUTER_NAME);

    state.computers.iter()
        .find(|c| c.valid && c.name[..name_len] == name[..name_len])
        .cloned()
}

/// Get master browser for domain
pub fn get_master_browser(domain: &[u8]) -> Option<[u8; MAX_COMPUTER_NAME]> {
    let state = BROWSER_STATE.lock();
    let domain_len = domain.len().min(MAX_DOMAIN_NAME);

    state.domains.iter()
        .find(|d| d.valid && d.name[..domain_len] == domain[..domain_len])
        .map(|d| d.master_browser)
}

/// Check for stale entries
pub fn check_stale_entries() {
    let mut state = BROWSER_STATE.lock();

    if !state.running {
        return;
    }

    let now = crate::rtl::time::rtl_get_system_time();
    let mut removed = 0usize;

    // Extract our name before mutable borrow
    let our_name = state.computer_name;

    // Remove computers that haven't announced in 3 periods
    for computer in state.computers.iter_mut() {
        if computer.valid {
            let stale_time = (computer.announce_period as i64) * 3 * 10_000_000;
            if now - computer.last_announcement > stale_time {
                // Don't remove ourselves
                if computer.name != our_name {
                    computer.valid = false;
                    removed += 1;
                }
            }
        }
    }

    state.computer_count = state.computer_count.saturating_sub(removed);
}

/// Set our role
pub fn set_role(role: BrowserRole) -> Result<(), u32> {
    let mut state = BROWSER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    state.role = role;

    // Update server type flags
    state.server_type &= !(0x00010000 | 0x00020000 | 0x00040000 | 0x00080000);
    match role {
        BrowserRole::NonBrowser => {}
        BrowserRole::PotentialBrowser => {
            state.server_type |= 0x00010000;
        }
        BrowserRole::BackupBrowser => {
            state.server_type |= 0x00020000;
        }
        BrowserRole::MasterBrowser => {
            state.server_type |= 0x00040000;
            state.is_master = true;
        }
        BrowserRole::DomainMaster => {
            state.server_type |= 0x00080000;
            state.is_master = true;
        }
    }

    Ok(())
}

/// Get our role
pub fn get_role() -> BrowserRole {
    let state = BROWSER_STATE.lock();
    state.role
}

/// Set computer name
pub fn set_computer_name(name: &[u8]) {
    let mut state = BROWSER_STATE.lock();

    let name_len = name.len().min(MAX_COMPUTER_NAME);
    state.computer_name = [0; MAX_COMPUTER_NAME];
    state.computer_name[..name_len].copy_from_slice(&name[..name_len]);
}

/// Set domain/workgroup name
pub fn set_domain_name(name: &[u8]) {
    let mut state = BROWSER_STATE.lock();

    let name_len = name.len().min(MAX_DOMAIN_NAME);
    state.domain_name = [0; MAX_DOMAIN_NAME];
    state.domain_name[..name_len].copy_from_slice(&name[..name_len]);
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64, u64) {
    (
        ANNOUNCEMENTS_SENT.load(Ordering::SeqCst),
        ANNOUNCEMENTS_RECEIVED.load(Ordering::SeqCst),
        ELECTIONS_PARTICIPATED.load(Ordering::SeqCst),
        ELECTIONS_WON.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = BROWSER_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = BROWSER_STATE.lock();
    state.running = false;
    state.is_master = false;
    state.role = BrowserRole::NonBrowser;

    crate::serial_println!("[BROWSER] Computer Browser service stopped");
}
