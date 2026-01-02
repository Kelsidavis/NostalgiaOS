//! File Replication Service (NTFRS/FRS)
//!
//! The File Replication Service replicates files and folders stored
//! in the SYSVOL shared folder on domain controllers and DFS targets.
//!
//! # Features
//!
//! - **SYSVOL Replication**: Domain controller policies and scripts
//! - **DFS Replication**: Distributed file system target sync
//! - **Multi-Master**: Bidirectional replication
//! - **Conflict Resolution**: Last-writer-wins or manual
//!
//! # Replication Topology
//!
//! - Ring topology for small sites
//! - Hub-spoke for larger deployments
//! - Custom topologies via AD sites
//!
//! # Change Detection
//!
//! - USN journal monitoring
//! - Staging folder for large files
//! - Compression during transfer

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum replica sets
const MAX_REPLICA_SETS: usize = 16;

/// Maximum members per replica set
const MAX_MEMBERS: usize = 32;

/// Maximum files in staging
const MAX_STAGING: usize = 64;

/// Maximum path length
const MAX_PATH: usize = 260;

/// Maximum name length
const MAX_NAME: usize = 64;

/// Replica set type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicaSetType {
    /// SYSVOL replication
    Sysvol = 0,
    /// DFS replication
    Dfs = 1,
    /// Custom replication
    Custom = 2,
}

impl ReplicaSetType {
    const fn empty() -> Self {
        ReplicaSetType::Custom
    }
}

/// Member state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberState {
    /// Uninitialized
    Uninitialized = 0,
    /// Initial sync in progress
    InitialSync = 1,
    /// Online and syncing
    Online = 2,
    /// Paused
    Paused = 3,
    /// Error state
    Error = 4,
    /// Offline
    Offline = 5,
}

impl MemberState {
    const fn empty() -> Self {
        MemberState::Uninitialized
    }
}

/// Replication schedule (simplified)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReplicationSchedule {
    /// Hours enabled (24 bits for each hour)
    pub hours_enabled: u32,
    /// Days enabled (7 bits, Sunday=0)
    pub days_enabled: u8,
    /// Replication interval in minutes
    pub interval_minutes: u32,
    /// Bandwidth throttle (0 = unlimited, Kbps otherwise)
    pub bandwidth_limit: u32,
}

impl ReplicationSchedule {
    const fn default_schedule() -> Self {
        ReplicationSchedule {
            hours_enabled: 0x00FFFFFF, // All 24 hours
            days_enabled: 0x7F,         // All 7 days
            interval_minutes: 15,
            bandwidth_limit: 0,
        }
    }
}

/// Replica set member
#[repr(C)]
#[derive(Clone)]
pub struct ReplicaMember {
    /// Member ID
    pub member_id: u64,
    /// Server name
    pub server_name: [u8; MAX_NAME],
    /// Local path on that server
    pub local_path: [u8; MAX_PATH],
    /// Member state
    pub state: MemberState,
    /// Last sync time
    pub last_sync: i64,
    /// Last sync USN
    pub last_usn: u64,
    /// Inbound partner (for ring)
    pub inbound_partner: u64,
    /// Is hub (for hub-spoke)
    pub is_hub: bool,
    /// Files synced count
    pub files_synced: u64,
    /// Conflicts count
    pub conflicts: u64,
    /// Errors count
    pub errors: u64,
    /// Entry is valid
    pub valid: bool,
}

impl ReplicaMember {
    const fn empty() -> Self {
        ReplicaMember {
            member_id: 0,
            server_name: [0; MAX_NAME],
            local_path: [0; MAX_PATH],
            state: MemberState::empty(),
            last_sync: 0,
            last_usn: 0,
            inbound_partner: 0,
            is_hub: false,
            files_synced: 0,
            conflicts: 0,
            errors: 0,
            valid: false,
        }
    }
}

/// Staging file entry
#[repr(C)]
#[derive(Clone)]
pub struct StagingEntry {
    /// File ID
    pub file_id: u64,
    /// Original path
    pub path: [u8; MAX_PATH],
    /// File size
    pub size: u64,
    /// Is compressed
    pub compressed: bool,
    /// Staging path
    pub staging_path: [u8; MAX_PATH],
    /// Created time
    pub created: i64,
    /// Replica set ID
    pub replica_set_id: u64,
    /// Source member ID
    pub source_member: u64,
    /// Entry is valid
    pub valid: bool,
}

impl StagingEntry {
    const fn empty() -> Self {
        StagingEntry {
            file_id: 0,
            path: [0; MAX_PATH],
            size: 0,
            compressed: false,
            staging_path: [0; MAX_PATH],
            created: 0,
            replica_set_id: 0,
            source_member: 0,
            valid: false,
        }
    }
}

/// Replica set
#[repr(C)]
#[derive(Clone)]
pub struct ReplicaSet {
    /// Set ID
    pub set_id: u64,
    /// Set name
    pub name: [u8; MAX_NAME],
    /// Set type
    pub set_type: ReplicaSetType,
    /// Members
    pub members: [ReplicaMember; MAX_MEMBERS],
    /// Member count
    pub member_count: usize,
    /// Next member ID
    pub next_member_id: u64,
    /// Schedule
    pub schedule: ReplicationSchedule,
    /// Is enabled
    pub enabled: bool,
    /// Created time
    pub created: i64,
    /// Entry is valid
    pub valid: bool,
}

impl ReplicaSet {
    const fn empty() -> Self {
        ReplicaSet {
            set_id: 0,
            name: [0; MAX_NAME],
            set_type: ReplicaSetType::empty(),
            members: [const { ReplicaMember::empty() }; MAX_MEMBERS],
            member_count: 0,
            next_member_id: 1,
            schedule: ReplicationSchedule::default_schedule(),
            enabled: true,
            created: 0,
            valid: false,
        }
    }
}

/// NTFRS service state
pub struct NtfrsState {
    /// Service is running
    pub running: bool,
    /// Replica sets
    pub replica_sets: [ReplicaSet; MAX_REPLICA_SETS],
    /// Replica set count
    pub set_count: usize,
    /// Next set ID
    pub next_set_id: u64,
    /// Staging entries
    pub staging: [StagingEntry; MAX_STAGING],
    /// Staging count
    pub staging_count: usize,
    /// Next file ID
    pub next_file_id: u64,
    /// Local server name
    pub server_name: [u8; MAX_NAME],
    /// Staging folder path
    pub staging_path: [u8; MAX_PATH],
    /// Service start time
    pub start_time: i64,
}

impl NtfrsState {
    const fn new() -> Self {
        NtfrsState {
            running: false,
            replica_sets: [const { ReplicaSet::empty() }; MAX_REPLICA_SETS],
            set_count: 0,
            next_set_id: 1,
            staging: [const { StagingEntry::empty() }; MAX_STAGING],
            staging_count: 0,
            next_file_id: 1,
            server_name: [0; MAX_NAME],
            staging_path: [0; MAX_PATH],
            start_time: 0,
        }
    }
}

/// Global state
static NTFRS_STATE: Mutex<NtfrsState> = Mutex::new(NtfrsState::new());

/// Statistics
static FILES_REPLICATED: AtomicU64 = AtomicU64::new(0);
static BYTES_REPLICATED: AtomicU64 = AtomicU64::new(0);
static CONFLICTS_DETECTED: AtomicU64 = AtomicU64::new(0);
static REPLICATION_ERRORS: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize NTFRS service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = NTFRS_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    let name = b"NOSTALGOS";
    state.server_name[..name.len()].copy_from_slice(name);

    let staging = b"C:\\Windows\\NTFRS\\Staging";
    state.staging_path[..staging.len()].copy_from_slice(staging);

    crate::serial_println!("[NTFRS] File Replication Service initialized");
}

/// Create a replica set
pub fn create_replica_set(
    name: &[u8],
    set_type: ReplicaSetType,
) -> Result<u64, u32> {
    let mut state = NTFRS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let name_len = name.len().min(MAX_NAME);

    // Check for duplicate
    for set in state.replica_sets.iter() {
        if set.valid && set.name[..name_len] == name[..name_len] {
            return Err(0x80070055);
        }
    }

    let slot = state.replica_sets.iter().position(|s| !s.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let set_id = state.next_set_id;
    state.next_set_id += 1;
    state.set_count += 1;

    let now = crate::rtl::time::rtl_get_system_time();

    let replica_set = &mut state.replica_sets[slot];
    replica_set.set_id = set_id;
    replica_set.name = [0; MAX_NAME];
    replica_set.name[..name_len].copy_from_slice(&name[..name_len]);
    replica_set.set_type = set_type;
    replica_set.schedule = ReplicationSchedule::default_schedule();
    replica_set.enabled = true;
    replica_set.created = now;
    replica_set.valid = true;

    Ok(set_id)
}

/// Delete a replica set
pub fn delete_replica_set(set_id: u64) -> Result<(), u32> {
    let mut state = NTFRS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.replica_sets.iter()
        .position(|s| s.valid && s.set_id == set_id);

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    // Clear all members
    for member in state.replica_sets[idx].members.iter_mut() {
        member.valid = false;
    }

    state.replica_sets[idx].valid = false;
    state.set_count = state.set_count.saturating_sub(1);

    Ok(())
}

/// Add a member to a replica set
pub fn add_member(
    set_id: u64,
    server_name: &[u8],
    local_path: &[u8],
    is_hub: bool,
) -> Result<u64, u32> {
    let mut state = NTFRS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let set_idx = state.replica_sets.iter()
        .position(|s| s.valid && s.set_id == set_id);

    let set_idx = match set_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let member_slot = state.replica_sets[set_idx].members.iter()
        .position(|m| !m.valid);

    let member_slot = match member_slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let member_id = state.replica_sets[set_idx].next_member_id;
    state.replica_sets[set_idx].next_member_id += 1;
    state.replica_sets[set_idx].member_count += 1;

    let server_len = server_name.len().min(MAX_NAME);
    let path_len = local_path.len().min(MAX_PATH);

    let member = &mut state.replica_sets[set_idx].members[member_slot];
    member.member_id = member_id;
    member.server_name = [0; MAX_NAME];
    member.server_name[..server_len].copy_from_slice(&server_name[..server_len]);
    member.local_path = [0; MAX_PATH];
    member.local_path[..path_len].copy_from_slice(&local_path[..path_len]);
    member.state = MemberState::Uninitialized;
    member.is_hub = is_hub;
    member.valid = true;

    Ok(member_id)
}

/// Remove a member from a replica set
pub fn remove_member(set_id: u64, member_id: u64) -> Result<(), u32> {
    let mut state = NTFRS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let set_idx = state.replica_sets.iter()
        .position(|s| s.valid && s.set_id == set_id);

    let set_idx = match set_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let member_idx = state.replica_sets[set_idx].members.iter()
        .position(|m| m.valid && m.member_id == member_id);

    let member_idx = match member_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.replica_sets[set_idx].members[member_idx].valid = false;
    state.replica_sets[set_idx].member_count =
        state.replica_sets[set_idx].member_count.saturating_sub(1);

    Ok(())
}

/// Set inbound partner (for ring topology)
pub fn set_inbound_partner(
    set_id: u64,
    member_id: u64,
    partner_id: u64,
) -> Result<(), u32> {
    let mut state = NTFRS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let set_idx = state.replica_sets.iter()
        .position(|s| s.valid && s.set_id == set_id);

    let set_idx = match set_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let member = state.replica_sets[set_idx].members.iter_mut()
        .find(|m| m.valid && m.member_id == member_id);

    let member = match member {
        Some(m) => m,
        None => return Err(0x80070057),
    };

    member.inbound_partner = partner_id;

    Ok(())
}

/// Start initial sync for a member
pub fn start_initial_sync(set_id: u64, member_id: u64) -> Result<(), u32> {
    let mut state = NTFRS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let set_idx = state.replica_sets.iter()
        .position(|s| s.valid && s.set_id == set_id);

    let set_idx = match set_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let member = state.replica_sets[set_idx].members.iter_mut()
        .find(|m| m.valid && m.member_id == member_id);

    let member = match member {
        Some(m) => m,
        None => return Err(0x80070057),
    };

    member.state = MemberState::InitialSync;

    // In real implementation, would start sync process
    // For now, simulate completion
    member.state = MemberState::Online;
    member.last_sync = crate::rtl::time::rtl_get_system_time();

    Ok(())
}

/// Set member state
pub fn set_member_state(
    set_id: u64,
    member_id: u64,
    new_state: MemberState,
) -> Result<(), u32> {
    let mut state = NTFRS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let set_idx = state.replica_sets.iter()
        .position(|s| s.valid && s.set_id == set_id);

    let set_idx = match set_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let member = state.replica_sets[set_idx].members.iter_mut()
        .find(|m| m.valid && m.member_id == member_id);

    let member = match member {
        Some(m) => m,
        None => return Err(0x80070057),
    };

    member.state = new_state;

    Ok(())
}

/// Set replication schedule
pub fn set_schedule(
    set_id: u64,
    schedule: ReplicationSchedule,
) -> Result<(), u32> {
    let mut state = NTFRS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let replica_set = state.replica_sets.iter_mut()
        .find(|s| s.valid && s.set_id == set_id);

    let replica_set = match replica_set {
        Some(s) => s,
        None => return Err(0x80070057),
    };

    replica_set.schedule = schedule;

    Ok(())
}

/// Enable/disable replica set
pub fn set_enabled(set_id: u64, enabled: bool) -> Result<(), u32> {
    let mut state = NTFRS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let replica_set = state.replica_sets.iter_mut()
        .find(|s| s.valid && s.set_id == set_id);

    let replica_set = match replica_set {
        Some(s) => s,
        None => return Err(0x80070057),
    };

    replica_set.enabled = enabled;

    Ok(())
}

/// Stage a file for replication
pub fn stage_file(
    set_id: u64,
    source_member: u64,
    path: &[u8],
    size: u64,
) -> Result<u64, u32> {
    let mut state = NTFRS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.staging.iter().position(|s| !s.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let file_id = state.next_file_id;
    state.next_file_id += 1;
    state.staging_count += 1;

    let now = crate::rtl::time::rtl_get_system_time();
    let path_len = path.len().min(MAX_PATH);

    // Extract staging path before taking mutable reference
    let staging_base = state.staging_path;
    let mut staging_full = [0u8; MAX_PATH];
    let base_len = staging_base.iter()
        .position(|&c| c == 0)
        .unwrap_or(MAX_PATH);
    staging_full[..base_len].copy_from_slice(&staging_base[..base_len]);

    let entry = &mut state.staging[slot];
    entry.file_id = file_id;
    entry.path = [0; MAX_PATH];
    entry.path[..path_len].copy_from_slice(&path[..path_len]);
    entry.size = size;
    entry.compressed = size > 64 * 1024; // Compress files > 64KB
    entry.replica_set_id = set_id;
    entry.source_member = source_member;
    entry.created = now;
    entry.staging_path = staging_full;
    entry.valid = true;

    Ok(file_id)
}

/// Complete staging (file replicated)
pub fn complete_staging(file_id: u64) -> Result<(), u32> {
    let mut state = NTFRS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.staging.iter()
        .position(|s| s.valid && s.file_id == file_id);

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let size = state.staging[idx].size;
    state.staging[idx].valid = false;
    state.staging_count = state.staging_count.saturating_sub(1);

    FILES_REPLICATED.fetch_add(1, Ordering::SeqCst);
    BYTES_REPLICATED.fetch_add(size, Ordering::SeqCst);

    Ok(())
}

/// Report conflict
pub fn report_conflict(
    set_id: u64,
    member_id: u64,
    _path: &[u8],
) -> Result<(), u32> {
    let mut state = NTFRS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let set_idx = state.replica_sets.iter()
        .position(|s| s.valid && s.set_id == set_id);

    let set_idx = match set_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let member = state.replica_sets[set_idx].members.iter_mut()
        .find(|m| m.valid && m.member_id == member_id);

    let member = match member {
        Some(m) => m,
        None => return Err(0x80070057),
    };

    member.conflicts += 1;
    CONFLICTS_DETECTED.fetch_add(1, Ordering::SeqCst);

    Ok(())
}

/// Get replica sets
pub fn enum_replica_sets() -> ([ReplicaSet; MAX_REPLICA_SETS], usize) {
    let state = NTFRS_STATE.lock();
    let mut result = [const { ReplicaSet::empty() }; MAX_REPLICA_SETS];
    let mut count = 0;

    for set in state.replica_sets.iter() {
        if set.valid && count < MAX_REPLICA_SETS {
            result[count] = set.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get replica set info
pub fn get_replica_set(set_id: u64) -> Option<ReplicaSet> {
    let state = NTFRS_STATE.lock();

    state.replica_sets.iter()
        .find(|s| s.valid && s.set_id == set_id)
        .cloned()
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64, u64) {
    (
        FILES_REPLICATED.load(Ordering::SeqCst),
        BYTES_REPLICATED.load(Ordering::SeqCst),
        CONFLICTS_DETECTED.load(Ordering::SeqCst),
        REPLICATION_ERRORS.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = NTFRS_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = NTFRS_STATE.lock();
    state.running = false;

    // Set all members offline
    for set in state.replica_sets.iter_mut() {
        if set.valid {
            for member in set.members.iter_mut() {
                if member.valid {
                    member.state = MemberState::Offline;
                }
            }
        }
    }

    crate::serial_println!("[NTFRS] File Replication Service stopped");
}
