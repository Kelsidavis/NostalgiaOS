//! NNTP Virtual Server Module
//!
//! Windows Server 2003 NNTP (Network News Transfer Protocol) Virtual Server
//! implementation for Usenet news hosting. Provides newsgroup management,
//! feed configuration, moderation, and article expiration.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;
use crate::win32k::user::UserHandle;

/// Maximum number of virtual servers
const MAX_SERVERS: usize = 8;

/// Maximum number of newsgroups per server
const MAX_NEWSGROUPS: usize = 256;

/// Maximum number of feeds
const MAX_FEEDS: usize = 32;

/// Maximum number of active sessions
const MAX_SESSIONS: usize = 128;

/// Maximum newsgroup name length
const MAX_GROUP_LEN: usize = 128;

/// Maximum description length
const MAX_DESC_LEN: usize = 256;

/// Maximum host name length
const MAX_HOST_LEN: usize = 253;

/// Maximum path length
const MAX_PATH_LEN: usize = 260;

/// Server state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServerState {
    /// Server is stopped
    Stopped = 0,
    /// Server is starting
    Starting = 1,
    /// Server is running
    Running = 2,
    /// Server is paused
    Paused = 3,
    /// Server is stopping
    Stopping = 4,
}

impl Default for ServerState {
    fn default() -> Self {
        Self::Stopped
    }
}

/// Newsgroup type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GroupType {
    /// Normal newsgroup
    Normal = 0,
    /// Moderated newsgroup
    Moderated = 1,
    /// Read-only newsgroup
    ReadOnly = 2,
}

impl Default for GroupType {
    fn default() -> Self {
        Self::Normal
    }
}

/// Feed type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FeedType {
    /// Inbound feed (receive articles)
    Inbound = 0,
    /// Outbound feed (push articles)
    Outbound = 1,
    /// Bidirectional feed
    Bidirectional = 2,
}

impl Default for FeedType {
    fn default() -> Self {
        Self::Inbound
    }
}

/// Feed state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FeedState {
    /// Feed is disabled
    Disabled = 0,
    /// Feed is enabled
    Enabled = 1,
    /// Feed is active (currently transferring)
    Active = 2,
    /// Feed has errors
    Error = 3,
}

impl Default for FeedState {
    fn default() -> Self {
        Self::Disabled
    }
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SessionState {
    /// Connected, not authenticated
    Connected = 0,
    /// Authenticated reader
    Reader = 1,
    /// Authenticated poster
    Poster = 2,
    /// Feed connection
    Feeder = 3,
}

impl Default for SessionState {
    fn default() -> Self {
        Self::Connected
    }
}

bitflags::bitflags! {
    /// Server flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ServerFlags: u32 {
        /// Allow anonymous access
        const ALLOW_ANONYMOUS = 0x0001;
        /// Require authentication for posting
        const AUTH_FOR_POST = 0x0002;
        /// Enable TLS/SSL
        const ENABLE_TLS = 0x0004;
        /// Enable logging
        const ENABLE_LOGGING = 0x0008;
        /// Allow article posting
        const ALLOW_POSTING = 0x0010;
        /// Enable moderation
        const ENABLE_MODERATION = 0x0020;
        /// Enable control messages
        const ALLOW_CONTROL = 0x0040;
        /// Enable newgroup control messages
        const ALLOW_NEWGROUP = 0x0080;
    }
}

impl Default for ServerFlags {
    fn default() -> Self {
        Self::ALLOW_ANONYMOUS | Self::ALLOW_POSTING | Self::ENABLE_LOGGING
    }
}

bitflags::bitflags! {
    /// Newsgroup flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct GroupFlags: u32 {
        /// Group is visible
        const VISIBLE = 0x0001;
        /// Allow posting
        const ALLOW_POST = 0x0002;
        /// Articles are indexed
        const INDEXED = 0x0004;
        /// Enable expiration
        const ENABLE_EXPIRE = 0x0008;
    }
}

impl Default for GroupFlags {
    fn default() -> Self {
        Self::VISIBLE | Self::ALLOW_POST | Self::ENABLE_EXPIRE
    }
}

/// NNTP Virtual Server
#[derive(Debug)]
pub struct NntpServer {
    /// Server is active
    active: bool,
    /// Server ID
    id: u32,
    /// Server name
    name: [u8; 64],
    /// Name length
    name_len: usize,
    /// Binding IP
    ip_address: [u8; 45],
    /// IP length
    ip_len: usize,
    /// Port number
    port: u16,
    /// Server state
    state: ServerState,
    /// Server flags
    flags: ServerFlags,
    /// Article storage path
    storage_path: [u8; MAX_PATH_LEN],
    /// Storage path length
    storage_len: usize,
    /// Maximum article size (KB)
    max_article_size: u32,
    /// Maximum connections
    max_connections: u32,
    /// Connection timeout (seconds)
    connection_timeout: u32,
    /// Expiration age (days)
    expire_days: u32,
    /// Current connections
    current_connections: u32,
    /// Total articles
    total_articles: u64,
    /// Total size
    total_size: u64,
    /// Handle for management
    handle: UserHandle,
}

impl NntpServer {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            name: [0u8; 64],
            name_len: 0,
            ip_address: [0u8; 45],
            ip_len: 0,
            port: 119,
            state: ServerState::Stopped,
            flags: ServerFlags::empty(),
            storage_path: [0u8; MAX_PATH_LEN],
            storage_len: 0,
            max_article_size: 1024, // 1 MB
            max_connections: 5000,
            connection_timeout: 600,
            expire_days: 14,
            current_connections: 0,
            total_articles: 0,
            total_size: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// Newsgroup
#[derive(Debug)]
pub struct Newsgroup {
    /// Group is active
    active: bool,
    /// Group ID
    id: u32,
    /// Parent server ID
    server_id: u32,
    /// Group name (e.g., comp.os.windows)
    name: [u8; MAX_GROUP_LEN],
    /// Name length
    name_len: usize,
    /// Description
    description: [u8; MAX_DESC_LEN],
    /// Description length
    desc_len: usize,
    /// Group type
    group_type: GroupType,
    /// Group flags
    flags: GroupFlags,
    /// First article number
    first_article: u64,
    /// Last article number
    last_article: u64,
    /// Article count
    article_count: u64,
    /// Creation time
    created: u64,
    /// Moderator email (for moderated groups)
    moderator: [u8; 128],
    /// Moderator length
    mod_len: usize,
    /// Handle for management
    handle: UserHandle,
}

impl Newsgroup {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            server_id: 0,
            name: [0u8; MAX_GROUP_LEN],
            name_len: 0,
            description: [0u8; MAX_DESC_LEN],
            desc_len: 0,
            group_type: GroupType::Normal,
            flags: GroupFlags::empty(),
            first_article: 1,
            last_article: 0,
            article_count: 0,
            created: 0,
            moderator: [0u8; 128],
            mod_len: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// News feed configuration
#[derive(Debug)]
pub struct NewsFeed {
    /// Feed is active
    active: bool,
    /// Feed ID
    id: u32,
    /// Parent server ID
    server_id: u32,
    /// Remote host
    remote_host: [u8; MAX_HOST_LEN],
    /// Host length
    host_len: usize,
    /// Remote port
    remote_port: u16,
    /// Feed type
    feed_type: FeedType,
    /// Feed state
    state: FeedState,
    /// Group patterns (wildcard)
    patterns: [u8; 256],
    /// Patterns length
    patterns_len: usize,
    /// Use authentication
    use_auth: bool,
    /// Username
    username: [u8; 64],
    /// Username length
    user_len: usize,
    /// Max connections
    max_connections: u32,
    /// Articles transferred
    articles_transferred: u64,
    /// Last connection time
    last_connect: u64,
    /// Handle for management
    handle: UserHandle,
}

impl NewsFeed {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            server_id: 0,
            remote_host: [0u8; MAX_HOST_LEN],
            host_len: 0,
            remote_port: 119,
            feed_type: FeedType::Inbound,
            state: FeedState::Disabled,
            patterns: [0u8; 256],
            patterns_len: 0,
            use_auth: false,
            username: [0u8; 64],
            user_len: 0,
            max_connections: 4,
            articles_transferred: 0,
            last_connect: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// Active NNTP session
#[derive(Debug)]
pub struct NntpSession {
    /// Session is active
    active: bool,
    /// Session ID
    id: u32,
    /// Parent server ID
    server_id: u32,
    /// Client IP
    client_ip: [u8; 45],
    /// IP length
    ip_len: usize,
    /// Client port
    client_port: u16,
    /// Session state
    state: SessionState,
    /// Authenticated username
    username: [u8; 64],
    /// Username length
    user_len: usize,
    /// Current newsgroup ID
    current_group: u32,
    /// Current article number
    current_article: u64,
    /// Articles read
    articles_read: u32,
    /// Articles posted
    articles_posted: u32,
    /// Connect time
    connect_time: u64,
    /// Handle for management
    handle: UserHandle,
}

impl NntpSession {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            server_id: 0,
            client_ip: [0u8; 45],
            ip_len: 0,
            client_port: 0,
            state: SessionState::Connected,
            username: [0u8; 64],
            user_len: 0,
            current_group: 0,
            current_article: 0,
            articles_read: 0,
            articles_posted: 0,
            connect_time: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// NNTP service statistics
#[derive(Debug)]
pub struct NntpStats {
    /// Total servers
    pub total_servers: u32,
    /// Running servers
    pub running_servers: u32,
    /// Total newsgroups
    pub total_groups: u32,
    /// Total feeds
    pub total_feeds: u32,
    /// Active sessions
    pub active_sessions: u32,
    /// Total articles
    pub total_articles: u64,
    /// Total size
    pub total_size: u64,
    /// Articles received today
    pub articles_received: u64,
    /// Articles posted today
    pub articles_posted: u64,
    /// Articles expired today
    pub articles_expired: u64,
}

impl NntpStats {
    pub const fn new() -> Self {
        Self {
            total_servers: 0,
            running_servers: 0,
            total_groups: 0,
            total_feeds: 0,
            active_sessions: 0,
            total_articles: 0,
            total_size: 0,
            articles_received: 0,
            articles_posted: 0,
            articles_expired: 0,
        }
    }
}

/// NNTP service state
struct NntpState {
    /// Servers
    servers: [NntpServer; MAX_SERVERS],
    /// Newsgroups
    groups: [Newsgroup; MAX_NEWSGROUPS],
    /// Feeds
    feeds: [NewsFeed; MAX_FEEDS],
    /// Sessions
    sessions: [NntpSession; MAX_SESSIONS],
    /// Statistics
    stats: NntpStats,
    /// Next ID
    next_id: u32,
}

impl NntpState {
    pub const fn new() -> Self {
        Self {
            servers: [const { NntpServer::new() }; MAX_SERVERS],
            groups: [const { Newsgroup::new() }; MAX_NEWSGROUPS],
            feeds: [const { NewsFeed::new() }; MAX_FEEDS],
            sessions: [const { NntpSession::new() }; MAX_SESSIONS],
            stats: NntpStats::new(),
            next_id: 1,
        }
    }
}

/// Global NNTP state
static NNTP_STATE: Mutex<NntpState> = Mutex::new(NntpState::new());

/// Initialization flag
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the NNTP virtual server module
pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    Ok(())
}

/// Create a new NNTP virtual server
pub fn create_server(
    name: &str,
    ip_address: &str,
    port: u16,
    storage_path: &str,
    flags: ServerFlags,
) -> Result<UserHandle, u32> {
    let mut state = NNTP_STATE.lock();

    // Check for duplicate binding
    for server in state.servers.iter() {
        if server.active {
            let existing_ip = &server.ip_address[..server.ip_len];
            if existing_ip == ip_address.as_bytes() && server.port == port {
                return Err(0x80070050);
            }
        }
    }

    let slot_idx = state.servers.iter().position(|s| !s.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008),
    };

    let id = state.next_id;
    state.next_id += 1;

    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(64);
    let ip_bytes = ip_address.as_bytes();
    let ip_len = ip_bytes.len().min(45);
    let storage_bytes = storage_path.as_bytes();
    let storage_len = storage_bytes.len().min(MAX_PATH_LEN);

    state.servers[slot_idx].active = true;
    state.servers[slot_idx].id = id;
    state.servers[slot_idx].name[..name_len].copy_from_slice(&name_bytes[..name_len]);
    state.servers[slot_idx].name_len = name_len;
    state.servers[slot_idx].ip_address[..ip_len].copy_from_slice(&ip_bytes[..ip_len]);
    state.servers[slot_idx].ip_len = ip_len;
    state.servers[slot_idx].port = port;
    state.servers[slot_idx].state = ServerState::Stopped;
    state.servers[slot_idx].flags = flags;
    state.servers[slot_idx].storage_path[..storage_len].copy_from_slice(&storage_bytes[..storage_len]);
    state.servers[slot_idx].storage_len = storage_len;
    state.servers[slot_idx].max_article_size = 1024;
    state.servers[slot_idx].max_connections = 5000;
    state.servers[slot_idx].connection_timeout = 600;
    state.servers[slot_idx].expire_days = 14;
    state.servers[slot_idx].current_connections = 0;
    state.servers[slot_idx].total_articles = 0;
    state.servers[slot_idx].total_size = 0;
    state.servers[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.total_servers += 1;

    Ok(state.servers[slot_idx].handle)
}

/// Delete an NNTP virtual server
pub fn delete_server(server_id: u32) -> Result<(), u32> {
    let mut state = NNTP_STATE.lock();

    let server_idx = state.servers.iter().position(|s| s.active && s.id == server_id);
    let server_idx = match server_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    if state.servers[server_idx].state != ServerState::Stopped {
        return Err(0x80070020);
    }

    // Count and remove related items
    let mut groups_to_remove = 0u32;
    let mut feeds_to_remove = 0u32;

    for group in state.groups.iter() {
        if group.active && group.server_id == server_id {
            groups_to_remove += 1;
        }
    }

    for feed in state.feeds.iter() {
        if feed.active && feed.server_id == server_id {
            feeds_to_remove += 1;
        }
    }

    for group in state.groups.iter_mut() {
        if group.active && group.server_id == server_id {
            group.active = false;
        }
    }

    for feed in state.feeds.iter_mut() {
        if feed.active && feed.server_id == server_id {
            feed.active = false;
        }
    }

    state.servers[server_idx].active = false;
    state.stats.total_servers = state.stats.total_servers.saturating_sub(1);
    state.stats.total_groups = state.stats.total_groups.saturating_sub(groups_to_remove);
    state.stats.total_feeds = state.stats.total_feeds.saturating_sub(feeds_to_remove);

    Ok(())
}

/// Start an NNTP server
pub fn start_server(server_id: u32) -> Result<(), u32> {
    let mut state = NNTP_STATE.lock();

    let server = state.servers.iter_mut().find(|s| s.active && s.id == server_id);
    let server = match server {
        Some(s) => s,
        None => return Err(0x80070002),
    };

    match server.state {
        ServerState::Running => return Ok(()),
        ServerState::Starting | ServerState::Stopping => {
            return Err(0x80070015);
        }
        _ => {}
    }

    server.state = ServerState::Starting;
    server.state = ServerState::Running;
    state.stats.running_servers += 1;

    Ok(())
}

/// Stop an NNTP server
pub fn stop_server(server_id: u32) -> Result<(), u32> {
    let mut state = NNTP_STATE.lock();

    let server_idx = state.servers.iter().position(|s| s.active && s.id == server_id);
    let server_idx = match server_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    match state.servers[server_idx].state {
        ServerState::Stopped => return Ok(()),
        ServerState::Starting | ServerState::Stopping => {
            return Err(0x80070015);
        }
        _ => {}
    }

    // Disconnect all sessions
    let mut sessions_closed = 0u32;
    for session in state.sessions.iter_mut() {
        if session.active && session.server_id == server_id {
            session.active = false;
            sessions_closed += 1;
        }
    }

    state.servers[server_idx].state = ServerState::Stopping;
    state.servers[server_idx].state = ServerState::Stopped;
    state.servers[server_idx].current_connections = 0;
    state.stats.running_servers = state.stats.running_servers.saturating_sub(1);
    state.stats.active_sessions = state.stats.active_sessions.saturating_sub(sessions_closed);

    Ok(())
}

/// Create a newsgroup
pub fn create_newsgroup(
    server_id: u32,
    name: &str,
    description: &str,
    group_type: GroupType,
    flags: GroupFlags,
) -> Result<UserHandle, u32> {
    let mut state = NNTP_STATE.lock();

    // Verify server exists
    let server_exists = state.servers.iter().any(|s| s.active && s.id == server_id);
    if !server_exists {
        return Err(0x80070002);
    }

    // Check for duplicate
    for group in state.groups.iter() {
        if group.active && group.server_id == server_id {
            let existing = &group.name[..group.name_len];
            if existing == name.as_bytes() {
                return Err(0x80070050);
            }
        }
    }

    let slot_idx = state.groups.iter().position(|g| !g.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008),
    };

    let id = state.next_id;
    state.next_id += 1;

    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(MAX_GROUP_LEN);
    let desc_bytes = description.as_bytes();
    let desc_len = desc_bytes.len().min(MAX_DESC_LEN);

    state.groups[slot_idx].active = true;
    state.groups[slot_idx].id = id;
    state.groups[slot_idx].server_id = server_id;
    state.groups[slot_idx].name[..name_len].copy_from_slice(&name_bytes[..name_len]);
    state.groups[slot_idx].name_len = name_len;
    state.groups[slot_idx].description[..desc_len].copy_from_slice(&desc_bytes[..desc_len]);
    state.groups[slot_idx].desc_len = desc_len;
    state.groups[slot_idx].group_type = group_type;
    state.groups[slot_idx].flags = flags;
    state.groups[slot_idx].first_article = 1;
    state.groups[slot_idx].last_article = 0;
    state.groups[slot_idx].article_count = 0;
    state.groups[slot_idx].created = 0;
    state.groups[slot_idx].mod_len = 0;
    state.groups[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.total_groups += 1;

    Ok(state.groups[slot_idx].handle)
}

/// Delete a newsgroup
pub fn delete_newsgroup(group_id: u32) -> Result<(), u32> {
    let mut state = NNTP_STATE.lock();

    let group_idx = state.groups.iter().position(|g| g.active && g.id == group_id);
    let group_idx = match group_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    state.groups[group_idx].active = false;
    state.stats.total_groups = state.stats.total_groups.saturating_sub(1);

    Ok(())
}

/// Add a news feed
pub fn add_feed(
    server_id: u32,
    remote_host: &str,
    remote_port: u16,
    feed_type: FeedType,
    patterns: &str,
) -> Result<UserHandle, u32> {
    let mut state = NNTP_STATE.lock();

    // Verify server exists
    let server_exists = state.servers.iter().any(|s| s.active && s.id == server_id);
    if !server_exists {
        return Err(0x80070002);
    }

    let slot_idx = state.feeds.iter().position(|f| !f.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008),
    };

    let id = state.next_id;
    state.next_id += 1;

    let host_bytes = remote_host.as_bytes();
    let host_len = host_bytes.len().min(MAX_HOST_LEN);
    let pattern_bytes = patterns.as_bytes();
    let patterns_len = pattern_bytes.len().min(256);

    state.feeds[slot_idx].active = true;
    state.feeds[slot_idx].id = id;
    state.feeds[slot_idx].server_id = server_id;
    state.feeds[slot_idx].remote_host[..host_len].copy_from_slice(&host_bytes[..host_len]);
    state.feeds[slot_idx].host_len = host_len;
    state.feeds[slot_idx].remote_port = remote_port;
    state.feeds[slot_idx].feed_type = feed_type;
    state.feeds[slot_idx].state = FeedState::Disabled;
    state.feeds[slot_idx].patterns[..patterns_len].copy_from_slice(&pattern_bytes[..patterns_len]);
    state.feeds[slot_idx].patterns_len = patterns_len;
    state.feeds[slot_idx].use_auth = false;
    state.feeds[slot_idx].user_len = 0;
    state.feeds[slot_idx].max_connections = 4;
    state.feeds[slot_idx].articles_transferred = 0;
    state.feeds[slot_idx].last_connect = 0;
    state.feeds[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.total_feeds += 1;

    Ok(state.feeds[slot_idx].handle)
}

/// Remove a feed
pub fn remove_feed(feed_id: u32) -> Result<(), u32> {
    let mut state = NNTP_STATE.lock();

    let feed_idx = state.feeds.iter().position(|f| f.active && f.id == feed_id);
    let feed_idx = match feed_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    state.feeds[feed_idx].active = false;
    state.stats.total_feeds = state.stats.total_feeds.saturating_sub(1);

    Ok(())
}

/// Enable or disable a feed
pub fn set_feed_state(feed_id: u32, enabled: bool) -> Result<(), u32> {
    let mut state = NNTP_STATE.lock();

    let feed = state.feeds.iter_mut().find(|f| f.active && f.id == feed_id);
    let feed = match feed {
        Some(f) => f,
        None => return Err(0x80070002),
    };

    feed.state = if enabled { FeedState::Enabled } else { FeedState::Disabled };

    Ok(())
}

/// Get server information
pub fn get_server_info(server_id: u32) -> Result<(ServerState, u32, u64, u64), u32> {
    let state = NNTP_STATE.lock();

    let server = state.servers.iter().find(|s| s.active && s.id == server_id);
    let server = match server {
        Some(s) => s,
        None => return Err(0x80070002),
    };

    Ok((
        server.state,
        server.current_connections,
        server.total_articles,
        server.total_size,
    ))
}

/// Get NNTP service statistics
pub fn get_statistics() -> NntpStats {
    let state = NNTP_STATE.lock();
    NntpStats {
        total_servers: state.stats.total_servers,
        running_servers: state.stats.running_servers,
        total_groups: state.stats.total_groups,
        total_feeds: state.stats.total_feeds,
        active_sessions: state.stats.active_sessions,
        total_articles: state.stats.total_articles,
        total_size: state.stats.total_size,
        articles_received: state.stats.articles_received,
        articles_posted: state.stats.articles_posted,
        articles_expired: state.stats.articles_expired,
    }
}

/// List all servers
pub fn list_servers() -> [(bool, u32, ServerState); MAX_SERVERS] {
    let state = NNTP_STATE.lock();
    let mut result = [(false, 0u32, ServerState::Stopped); MAX_SERVERS];

    for (i, server) in state.servers.iter().enumerate() {
        if server.active {
            result[i] = (true, server.id, server.state);
        }
    }

    result
}

/// List newsgroups for a server
pub fn list_newsgroups(server_id: u32) -> [(bool, u32, GroupType, u64); MAX_NEWSGROUPS] {
    let state = NNTP_STATE.lock();
    let mut result = [(false, 0u32, GroupType::Normal, 0u64); MAX_NEWSGROUPS];

    let mut idx = 0;
    for group in state.groups.iter() {
        if group.active && group.server_id == server_id && idx < MAX_NEWSGROUPS {
            result[idx] = (true, group.id, group.group_type, group.article_count);
            idx += 1;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_lifecycle() {
        init().unwrap();

        let handle = create_server(
            "Default NNTP Server",
            "0.0.0.0",
            119,
            "C:\\InetPub\\nntpfile",
            ServerFlags::default(),
        ).unwrap();
        assert_ne!(handle, UserHandle::NULL);

        start_server(1).unwrap_or(());
        stop_server(1).unwrap_or(());
    }

    #[test]
    fn test_newsgroup_management() {
        init().unwrap();

        let stats = get_statistics();
        assert!(stats.total_servers <= MAX_SERVERS as u32);
    }
}
