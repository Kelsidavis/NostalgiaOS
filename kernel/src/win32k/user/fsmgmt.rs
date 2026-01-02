//! Shared Folders
//!
//! Implements Shared Folders management following Windows Server 2003.
//! Provides share, session, and open file management.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - fsmgmt.msc - Shared Folders snap-in
//! - Net share / net session / net file commands
//! - Server service (lanmanserver)

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum shares
const MAX_SHARES: usize = 64;

/// Maximum sessions
const MAX_SESSIONS: usize = 128;

/// Maximum open files
const MAX_OPEN_FILES: usize = 256;

/// Maximum path length
const MAX_PATH: usize = 260;

/// Maximum name length
const MAX_NAME: usize = 64;

// ============================================================================
// Share Type
// ============================================================================

/// Share type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShareType {
    /// Disk share
    #[default]
    Disk = 0,
    /// Print queue
    Print = 1,
    /// Device
    Device = 2,
    /// IPC (interprocess communication)
    Ipc = 3,
    /// Special administrative share
    Special = 0x80000000,
}

impl ShareType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShareType::Disk => "Disk",
            ShareType::Print => "Print",
            ShareType::Device => "Device",
            ShareType::Ipc => "IPC",
            ShareType::Special => "Special",
        }
    }
}

// ============================================================================
// Share Permissions
// ============================================================================

bitflags::bitflags! {
    /// Share permissions
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SharePermissions: u32 {
        const READ = 0x0001;
        const WRITE = 0x0002;
        const CREATE = 0x0004;
        const EXECUTE = 0x0020;
        const DELETE = 0x0010;
        const CHANGE_PERMISSIONS = 0x0040;
        const TAKE_OWNERSHIP = 0x0080;

        const READ_ONLY = Self::READ.bits();
        const CHANGE = Self::READ.bits() | Self::WRITE.bits() | Self::CREATE.bits() | Self::DELETE.bits();
        const FULL_CONTROL = 0x00FF;
    }
}

// ============================================================================
// Share Entry
// ============================================================================

/// Network share
#[derive(Debug, Clone, Copy)]
pub struct ShareEntry {
    /// Share ID
    pub share_id: u32,
    /// Share name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Local path
    pub path: [u8; MAX_PATH],
    /// Path length
    pub path_len: usize,
    /// Description
    pub description: [u8; MAX_NAME],
    /// Description length
    pub desc_len: usize,
    /// Share type
    pub share_type: ShareType,
    /// Is hidden ($ suffix)
    pub is_hidden: bool,
    /// Maximum users (-1 = unlimited)
    pub max_users: i32,
    /// Current users
    pub current_users: u32,
    /// Permissions
    pub permissions: SharePermissions,
    /// Caching mode
    pub caching: CachingMode,
}

impl ShareEntry {
    pub const fn new() -> Self {
        Self {
            share_id: 0,
            name: [0u8; MAX_NAME],
            name_len: 0,
            path: [0u8; MAX_PATH],
            path_len: 0,
            description: [0u8; MAX_NAME],
            desc_len: 0,
            share_type: ShareType::Disk,
            is_hidden: false,
            max_users: -1,
            current_users: 0,
            permissions: SharePermissions::FULL_CONTROL,
            caching: CachingMode::Manual,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
        // Check for hidden share
        self.is_hidden = len > 0 && self.name[len - 1] == b'$';
    }

    pub fn set_path(&mut self, path: &[u8]) {
        let len = path.len().min(MAX_PATH);
        self.path[..len].copy_from_slice(&path[..len]);
        self.path_len = len;
    }

    pub fn set_description(&mut self, desc: &[u8]) {
        let len = desc.len().min(MAX_NAME);
        self.description[..len].copy_from_slice(&desc[..len]);
        self.desc_len = len;
    }
}

impl Default for ShareEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Offline caching mode
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CachingMode {
    /// Manual caching for documents
    #[default]
    Manual = 0,
    /// Automatic caching for documents
    Automatic = 1,
    /// Automatic caching for programs
    Programs = 2,
    /// No caching
    None = 3,
}

// ============================================================================
// Session Entry
// ============================================================================

/// Client session
#[derive(Debug, Clone, Copy)]
pub struct SessionEntry {
    /// Session ID
    pub session_id: u32,
    /// Client computer name
    pub computer: [u8; MAX_NAME],
    /// Computer name length
    pub computer_len: usize,
    /// Username
    pub username: [u8; MAX_NAME],
    /// Username length
    pub username_len: usize,
    /// Client type (e.g., "Windows 2003")
    pub client_type: [u8; 32],
    /// Client type length
    pub client_len: usize,
    /// Open files count
    pub open_files: u32,
    /// Connected time (seconds)
    pub connected_time: u64,
    /// Idle time (seconds)
    pub idle_time: u64,
    /// Is guest logon
    pub is_guest: bool,
    /// Transport (e.g., "NetBT")
    pub transport: [u8; 16],
    /// Transport length
    pub transport_len: usize,
}

impl SessionEntry {
    pub const fn new() -> Self {
        Self {
            session_id: 0,
            computer: [0u8; MAX_NAME],
            computer_len: 0,
            username: [0u8; MAX_NAME],
            username_len: 0,
            client_type: [0u8; 32],
            client_len: 0,
            open_files: 0,
            connected_time: 0,
            idle_time: 0,
            is_guest: false,
            transport: [0u8; 16],
            transport_len: 0,
        }
    }

    pub fn set_computer(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.computer[..len].copy_from_slice(&name[..len]);
        self.computer_len = len;
    }

    pub fn set_username(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.username[..len].copy_from_slice(&name[..len]);
        self.username_len = len;
    }
}

impl Default for SessionEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Open File Entry
// ============================================================================

/// Open file
#[derive(Debug, Clone, Copy)]
pub struct OpenFileEntry {
    /// File ID
    pub file_id: u32,
    /// Session ID
    pub session_id: u32,
    /// File path
    pub path: [u8; MAX_PATH],
    /// Path length
    pub path_len: usize,
    /// Username
    pub username: [u8; MAX_NAME],
    /// Username length
    pub username_len: usize,
    /// Access mode
    pub access_mode: AccessMode,
    /// Lock count
    pub locks: u32,
}

impl OpenFileEntry {
    pub const fn new() -> Self {
        Self {
            file_id: 0,
            session_id: 0,
            path: [0u8; MAX_PATH],
            path_len: 0,
            username: [0u8; MAX_NAME],
            username_len: 0,
            access_mode: AccessMode::Read,
            locks: 0,
        }
    }

    pub fn set_path(&mut self, path: &[u8]) {
        let len = path.len().min(MAX_PATH);
        self.path[..len].copy_from_slice(&path[..len]);
        self.path_len = len;
    }

    pub fn set_username(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.username[..len].copy_from_slice(&name[..len]);
        self.username_len = len;
    }
}

impl Default for OpenFileEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// File access mode
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessMode {
    /// Read access
    #[default]
    Read = 0,
    /// Write access
    Write = 1,
    /// Read and Write access
    ReadWrite = 2,
}

impl AccessMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AccessMode::Read => "Read",
            AccessMode::Write => "Write",
            AccessMode::ReadWrite => "Read + Write",
        }
    }
}

// ============================================================================
// Shared Folders State
// ============================================================================

/// Shared Folders state
struct FsmgmtState {
    /// Shares
    shares: [ShareEntry; MAX_SHARES],
    /// Share count
    share_count: usize,
    /// Next share ID
    next_share_id: u32,
    /// Sessions
    sessions: [SessionEntry; MAX_SESSIONS],
    /// Session count
    session_count: usize,
    /// Next session ID
    next_session_id: u32,
    /// Open files
    open_files: [OpenFileEntry; MAX_OPEN_FILES],
    /// Open file count
    file_count: usize,
    /// Next file ID
    next_file_id: u32,
    /// Selected share ID
    selected_share: u32,
}

impl FsmgmtState {
    pub const fn new() -> Self {
        Self {
            shares: [const { ShareEntry::new() }; MAX_SHARES],
            share_count: 0,
            next_share_id: 1,
            sessions: [const { SessionEntry::new() }; MAX_SESSIONS],
            session_count: 0,
            next_session_id: 1,
            open_files: [const { OpenFileEntry::new() }; MAX_OPEN_FILES],
            file_count: 0,
            next_file_id: 1,
            selected_share: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static FSMGMT_INITIALIZED: AtomicBool = AtomicBool::new(false);
static FSMGMT_STATE: SpinLock<FsmgmtState> = SpinLock::new(FsmgmtState::new());

// Statistics
static SHARES_CREATED: AtomicU32 = AtomicU32::new(0);
static TOTAL_CONNECTIONS: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Shared Folders
pub fn init() {
    if FSMGMT_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = FSMGMT_STATE.lock();

    // Add administrative shares
    add_admin_shares(&mut state);

    // Add sample sessions
    add_sample_sessions(&mut state);

    crate::serial_println!("[WIN32K] Shared Folders initialized");
}

/// Add administrative shares
fn add_admin_shares(state: &mut FsmgmtState) {
    let shares: [(&[u8], &[u8], &[u8], ShareType); 6] = [
        (b"ADMIN$", b"C:\\WINDOWS", b"Remote Admin", ShareType::Special),
        (b"C$", b"C:\\", b"Default share", ShareType::Special),
        (b"IPC$", b"", b"Remote IPC", ShareType::Ipc),
        (b"print$", b"C:\\WINDOWS\\system32\\spool\\drivers", b"Printer Drivers", ShareType::Disk),
        (b"NETLOGON", b"C:\\WINDOWS\\SYSVOL\\sysvol\\domain\\scripts", b"Logon server share", ShareType::Disk),
        (b"SYSVOL", b"C:\\WINDOWS\\SYSVOL\\sysvol", b"Logon server share", ShareType::Disk),
    ];

    for (name, path, desc, stype) in shares.iter() {
        if state.share_count >= MAX_SHARES {
            break;
        }
        let mut share = ShareEntry::new();
        share.share_id = state.next_share_id;
        state.next_share_id += 1;
        share.set_name(name);
        share.set_path(path);
        share.set_description(desc);
        share.share_type = *stype;

        let idx = state.share_count;
        state.shares[idx] = share;
        state.share_count += 1;
    }
}

/// Add sample sessions
fn add_sample_sessions(state: &mut FsmgmtState) {
    let mut session = SessionEntry::new();
    session.session_id = state.next_session_id;
    state.next_session_id += 1;
    session.set_computer(b"\\\\WORKSTATION1");
    session.set_username(b"Administrator");
    let client = b"Windows Server 2003";
    let clen = client.len().min(32);
    session.client_type[..clen].copy_from_slice(&client[..clen]);
    session.client_len = clen;
    session.open_files = 2;
    session.connected_time = 3600;
    session.idle_time = 120;
    let transport = b"NetBT_Tcpip";
    let tlen = transport.len().min(16);
    session.transport[..tlen].copy_from_slice(&transport[..tlen]);
    session.transport_len = tlen;

    state.sessions[0] = session;
    state.session_count = 1;

    // Add sample open files for this session
    let files: [(&[u8], AccessMode); 2] = [
        (b"C:\\Documents\\report.docx", AccessMode::ReadWrite),
        (b"C:\\Shared\\data.xlsx", AccessMode::Read),
    ];

    for (path, mode) in files.iter() {
        if state.file_count >= MAX_OPEN_FILES {
            break;
        }
        let mut file = OpenFileEntry::new();
        file.file_id = state.next_file_id;
        state.next_file_id += 1;
        file.session_id = 1;
        file.set_path(path);
        file.set_username(b"Administrator");
        file.access_mode = *mode;

        let idx = state.file_count;
        state.open_files[idx] = file;
        state.file_count += 1;
    }
}

// ============================================================================
// Share Management
// ============================================================================

/// Get share count
pub fn get_share_count() -> usize {
    FSMGMT_STATE.lock().share_count
}

/// Get share by index
pub fn get_share(index: usize) -> Option<ShareEntry> {
    let state = FSMGMT_STATE.lock();
    if index < state.share_count {
        Some(state.shares[index])
    } else {
        None
    }
}

/// Get share by name
pub fn get_share_by_name(name: &[u8]) -> Option<ShareEntry> {
    let state = FSMGMT_STATE.lock();
    for i in 0..state.share_count {
        if state.shares[i].name_len == name.len() &&
           &state.shares[i].name[..state.shares[i].name_len] == name {
            return Some(state.shares[i]);
        }
    }
    None
}

/// Create new share
pub fn create_share(name: &[u8], path: &[u8], description: &[u8], max_users: i32) -> Option<u32> {
    let mut state = FSMGMT_STATE.lock();

    if state.share_count >= MAX_SHARES {
        return None;
    }

    // Check for duplicate name
    for i in 0..state.share_count {
        if state.shares[i].name_len == name.len() &&
           &state.shares[i].name[..state.shares[i].name_len] == name {
            return None;
        }
    }

    let share_id = state.next_share_id;
    state.next_share_id += 1;

    let mut share = ShareEntry::new();
    share.share_id = share_id;
    share.set_name(name);
    share.set_path(path);
    share.set_description(description);
    share.max_users = max_users;

    let idx = state.share_count;
    state.shares[idx] = share;
    state.share_count += 1;

    SHARES_CREATED.fetch_add(1, Ordering::Relaxed);
    Some(share_id)
}

/// Delete share
pub fn delete_share(share_id: u32) -> bool {
    let mut state = FSMGMT_STATE.lock();

    // Cannot delete admin shares
    for i in 0..state.share_count {
        if state.shares[i].share_id == share_id {
            if state.shares[i].share_type == ShareType::Special ||
               state.shares[i].share_type == ShareType::Ipc {
                return false;
            }
            break;
        }
    }

    let mut found_index = None;
    for i in 0..state.share_count {
        if state.shares[i].share_id == share_id {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..state.share_count - 1 {
            state.shares[i] = state.shares[i + 1];
        }
        state.share_count -= 1;
        true
    } else {
        false
    }
}

/// Set share permissions
pub fn set_share_permissions(share_id: u32, permissions: SharePermissions) -> bool {
    let mut state = FSMGMT_STATE.lock();
    for i in 0..state.share_count {
        if state.shares[i].share_id == share_id {
            state.shares[i].permissions = permissions;
            return true;
        }
    }
    false
}

/// Set share max users
pub fn set_share_max_users(share_id: u32, max_users: i32) -> bool {
    let mut state = FSMGMT_STATE.lock();
    for i in 0..state.share_count {
        if state.shares[i].share_id == share_id {
            state.shares[i].max_users = max_users;
            return true;
        }
    }
    false
}

/// Select share
pub fn select_share(share_id: u32) {
    FSMGMT_STATE.lock().selected_share = share_id;
}

/// Get selected share
pub fn get_selected_share() -> u32 {
    FSMGMT_STATE.lock().selected_share
}

// ============================================================================
// Session Management
// ============================================================================

/// Get session count
pub fn get_session_count() -> usize {
    FSMGMT_STATE.lock().session_count
}

/// Get session by index
pub fn get_session(index: usize) -> Option<SessionEntry> {
    let state = FSMGMT_STATE.lock();
    if index < state.session_count {
        Some(state.sessions[index])
    } else {
        None
    }
}

/// Disconnect session
pub fn disconnect_session(session_id: u32) -> bool {
    let mut state = FSMGMT_STATE.lock();

    let mut found_index = None;
    for i in 0..state.session_count {
        if state.sessions[i].session_id == session_id {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        // Close all files for this session
        let mut i = 0;
        while i < state.file_count {
            if state.open_files[i].session_id == session_id {
                for j in i..state.file_count - 1 {
                    state.open_files[j] = state.open_files[j + 1];
                }
                state.file_count -= 1;
            } else {
                i += 1;
            }
        }

        // Remove session
        for i in index..state.session_count - 1 {
            state.sessions[i] = state.sessions[i + 1];
        }
        state.session_count -= 1;
        true
    } else {
        false
    }
}

/// Disconnect all sessions
pub fn disconnect_all_sessions() -> u32 {
    let mut state = FSMGMT_STATE.lock();
    let count = state.session_count as u32;
    state.session_count = 0;
    state.file_count = 0;
    count
}

// ============================================================================
// Open Files Management
// ============================================================================

/// Get open file count
pub fn get_open_file_count() -> usize {
    FSMGMT_STATE.lock().file_count
}

/// Get open file by index
pub fn get_open_file(index: usize) -> Option<OpenFileEntry> {
    let state = FSMGMT_STATE.lock();
    if index < state.file_count {
        Some(state.open_files[index])
    } else {
        None
    }
}

/// Close open file
pub fn close_open_file(file_id: u32) -> bool {
    let mut state = FSMGMT_STATE.lock();

    let mut found_index = None;
    let mut session_id = 0;
    for i in 0..state.file_count {
        if state.open_files[i].file_id == file_id {
            found_index = Some(i);
            session_id = state.open_files[i].session_id;
            break;
        }
    }

    if let Some(index) = found_index {
        // Update session open file count
        for i in 0..state.session_count {
            if state.sessions[i].session_id == session_id && state.sessions[i].open_files > 0 {
                state.sessions[i].open_files -= 1;
                break;
            }
        }

        // Remove file entry
        for i in index..state.file_count - 1 {
            state.open_files[i] = state.open_files[i + 1];
        }
        state.file_count -= 1;
        true
    } else {
        false
    }
}

/// Close all open files
pub fn close_all_open_files() -> u32 {
    let mut state = FSMGMT_STATE.lock();
    let count = state.file_count as u32;
    state.file_count = 0;

    // Reset open file counts in sessions
    for i in 0..state.session_count {
        state.sessions[i].open_files = 0;
    }

    count
}

// ============================================================================
// Statistics
// ============================================================================

/// Shared Folders statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct FsmgmtStats {
    pub initialized: bool,
    pub share_count: usize,
    pub session_count: usize,
    pub open_file_count: usize,
    pub hidden_shares: usize,
    pub shares_created: u32,
    pub total_connections: u64,
}

/// Get Shared Folders statistics
pub fn get_stats() -> FsmgmtStats {
    let state = FSMGMT_STATE.lock();
    let hidden = state.shares[..state.share_count].iter().filter(|s| s.is_hidden).count();
    FsmgmtStats {
        initialized: FSMGMT_INITIALIZED.load(Ordering::Relaxed),
        share_count: state.share_count,
        session_count: state.session_count,
        open_file_count: state.file_count,
        hidden_shares: hidden,
        shares_created: SHARES_CREATED.load(Ordering::Relaxed),
        total_connections: TOTAL_CONNECTIONS.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Shared Folders dialog handle
pub type HFSMGMTDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Shared Folders dialog
pub fn create_fsmgmt_dialog(_parent: super::super::HWND) -> HFSMGMTDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}
