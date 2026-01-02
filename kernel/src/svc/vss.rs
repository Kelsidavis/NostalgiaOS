//! Volume Shadow Copy Service (VSS)
//!
//! The Volume Shadow Copy Service provides the infrastructure for creating
//! point-in-time copies (shadow copies) of volumes. This enables:
//!
//! - **Backup Applications**: Take consistent backups of open files
//! - **System Restore**: Create restore points
//! - **Previous Versions**: Allow users to restore previous file versions
//!
//! # Architecture
//!
//! VSS uses a coordinator model with three types of components:
//! - **Requesters**: Applications that request shadow copies (backup software)
//! - **Providers**: Components that create/manage shadow copies (volume, software, hardware)
//! - **Writers**: Applications that prepare their data for consistent snapshots
//!
//! # Shadow Copy Process
//!
//! 1. Requester initiates shadow copy request
//! 2. VSS freezes application writes via writer notification
//! 3. Provider creates the shadow copy
//! 4. VSS thaws applications
//! 5. Requester accesses shadow copy for backup

extern crate alloc;

use crate::ke::SpinLock;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of shadow copies per volume
pub const MAX_SHADOW_COPIES: usize = 64;

/// Maximum number of volumes tracked
pub const MAX_VOLUMES: usize = 26;

/// Maximum number of VSS writers
pub const MAX_WRITERS: usize = 32;

/// Maximum number of VSS providers
pub const MAX_PROVIDERS: usize = 8;

/// Maximum name length
pub const MAX_NAME_LEN: usize = 64;

/// Maximum path length
pub const MAX_PATH_LEN: usize = 260;

/// Shadow copy set GUID length
pub const GUID_LEN: usize = 16;

// ============================================================================
// Types
// ============================================================================

/// Shadow copy identifier (GUID-like)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VssId {
    pub data: [u8; GUID_LEN],
}

impl VssId {
    pub const fn empty() -> Self {
        Self { data: [0; GUID_LEN] }
    }

    pub fn is_empty(&self) -> bool {
        self.data.iter().all(|&b| b == 0)
    }

    pub fn generate(seed: u64) -> Self {
        let mut data = [0u8; GUID_LEN];
        let mut val = seed;
        for i in 0..GUID_LEN {
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            data[i] = (val >> 16) as u8;
        }
        Self { data }
    }
}

/// Shadow copy state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ShadowCopyState {
    /// Unknown state
    Unknown = 0,
    /// Preparing for creation
    Preparing = 1,
    /// Processing writers
    ProcessingPrepare = 2,
    /// Writers prepared
    PreparedToCommit = 3,
    /// Committing shadow copy
    Committing = 4,
    /// Committed successfully
    Committed = 5,
    /// Creating shadow copy
    Creating = 6,
    /// Shadow copy created
    Created = 7,
    /// Processing post-commit
    ProcessingPostCommit = 8,
    /// Complete and available
    Complete = 9,
    /// Aborted
    Aborted = 10,
    /// Deleted
    Deleted = 11,
}

impl Default for ShadowCopyState {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Shadow copy attributes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct ShadowCopyAttributes(pub u32);

impl ShadowCopyAttributes {
    pub const NONE: u32 = 0;
    /// Persistent shadow copy (survives reboots)
    pub const PERSISTENT: u32 = 0x00000001;
    /// No auto-release on backup complete
    pub const NO_AUTO_RELEASE: u32 = 0x00000002;
    /// Hardware-based shadow copy
    pub const HARDWARE: u32 = 0x00000004;
    /// Differential copy (only changes stored)
    pub const DIFFERENTIAL: u32 = 0x00000008;
    /// Full copy (complete volume copy)
    pub const PLEX: u32 = 0x00000010;
    /// Imported from another machine
    pub const IMPORTED: u32 = 0x00000020;
    /// Exposed as a drive letter
    pub const EXPOSED_LOCALLY: u32 = 0x00000040;
    /// Exposed as a network share
    pub const EXPOSED_REMOTELY: u32 = 0x00000080;
    /// Auto-recover supported
    pub const AUTORECOVER: u32 = 0x00000100;
    /// Rollback supported
    pub const ROLLBACK_RECOVERY: u32 = 0x00000200;
    /// Delayed post snapshot
    pub const DELAYED_POSTSNAPSHOT: u32 = 0x00000400;
    /// Transportable snapshot
    pub const TRANSPORTABLE: u32 = 0x00010000;
    /// No writers involved
    pub const NO_WRITERS: u32 = 0x00020000;

    pub fn is_persistent(&self) -> bool {
        (self.0 & Self::PERSISTENT) != 0
    }

    pub fn is_hardware(&self) -> bool {
        (self.0 & Self::HARDWARE) != 0
    }

    pub fn is_differential(&self) -> bool {
        (self.0 & Self::DIFFERENTIAL) != 0
    }

    pub fn is_exposed_locally(&self) -> bool {
        (self.0 & Self::EXPOSED_LOCALLY) != 0
    }

    pub fn is_exposed_remotely(&self) -> bool {
        (self.0 & Self::EXPOSED_REMOTELY) != 0
    }
}

/// Shadow copy context for backup operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VssContext {
    /// Default backup context
    Backup = 0,
    /// File share backup
    FileShareBackup = 0x00000010,
    /// NAS (Network Attached Storage) backup
    NasRollback = 0x00000019,
    /// Application rollback
    AppRollback = 0x00000009,
    /// Client accessible snapshot
    ClientAccessible = 0x0000001d,
    /// All contexts
    All = 0xffffffff,
}

impl Default for VssContext {
    fn default() -> Self {
        Self::Backup
    }
}

/// VSS writer state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WriterState {
    /// Unknown state
    Unknown = 0,
    /// Stable/idle
    Stable = 1,
    /// Waiting for freeze
    WaitingForFreeze = 2,
    /// Waiting for thaw
    WaitingForThaw = 3,
    /// Waiting for post-snapshot
    WaitingForPostSnapshot = 4,
    /// Waiting for backup complete
    WaitingForBackupComplete = 5,
    /// Failed during freeze
    FailedAtIdentify = 6,
    /// Failed at prepare backup
    FailedAtPrepareBackup = 7,
    /// Failed at prepare snapshot
    FailedAtPrepareSnapshot = 8,
    /// Failed at freeze
    FailedAtFreeze = 9,
    /// Failed at thaw
    FailedAtThaw = 10,
    /// Failed at post-snapshot
    FailedAtPostSnapshot = 11,
    /// Failed at backup complete
    FailedAtBackupComplete = 12,
    /// Failed at pre-restore
    FailedAtPreRestore = 13,
    /// Failed at post-restore
    FailedAtPostRestore = 14,
    /// Failed at backup shutdown
    FailedAtBackupShutdown = 15,
}

impl Default for WriterState {
    fn default() -> Self {
        Self::Unknown
    }
}

/// VSS provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ProviderType {
    /// Unknown provider
    Unknown = 0,
    /// System provider (default Microsoft provider)
    System = 1,
    /// Software-based provider
    Software = 2,
    /// Hardware-based provider
    Hardware = 3,
    /// File share provider
    FileShare = 4,
}

impl Default for ProviderType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// VSS backup type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BackupType {
    /// Undefined
    Undefined = 0,
    /// Full backup
    Full = 1,
    /// Incremental backup
    Incremental = 2,
    /// Differential backup
    Differential = 3,
    /// Log backup
    Log = 4,
    /// Copy backup (doesn't affect incremental/differential)
    Copy = 5,
}

impl Default for BackupType {
    fn default() -> Self {
        Self::Undefined
    }
}

/// VSS error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VssError {
    /// Success
    Ok = 0,
    /// General error
    Error = 1,
    /// Bad state
    BadState = 2,
    /// Provider vetoed operation
    ProviderVeto = 3,
    /// Revert in progress
    RevertInProgress = 4,
    /// Not supported
    NotSupported = 5,
    /// Maximum snapshots reached
    MaximumNumberOfSnapshotsReached = 6,
    /// Writer infrastructure error
    WriterInfrastructure = 7,
    /// Writer not responding
    WriterNotResponding = 8,
    /// Volume not supported
    VolumeNotSupported = 9,
    /// Volume not found
    VolumeNotFound = 10,
    /// Unexpected provider error
    UnexpectedProviderError = 11,
    /// Corrupt XML
    CorruptXmlDocument = 12,
    /// Invalid XML document
    InvalidXmlDocument = 13,
    /// Maximum diffarea exceeded
    MaximumDiffareaAssociationsReached = 14,
    /// Insufficient storage
    InsufficientStorage = 15,
    /// Object not found
    ObjectNotFound = 16,
    /// Object already exists
    ObjectAlreadyExists = 17,
    /// Shadow copy set in progress
    SnapshotSetInProgress = 18,
    /// Provider not registered
    ProviderNotRegistered = 19,
    /// Writer already subscribed
    WriterAlreadySubscribed = 20,
    /// Writer class ID already registered
    WriterClassIdAlreadyRegistered = 21,
    /// Unsupported context
    UnsupportedContext = 22,
    /// Volume in use
    VolumeInUse = 23,
    /// Maximum shadow copy set snapshots reached
    MaximumSnapshotSetSnapshotsReached = 24,
    /// Flush writes timed out
    FlushWritesTimedOut = 25,
    /// Hold writes timed out
    HoldWritesTimedOut = 26,
}

// ============================================================================
// Shadow Copy Structure
// ============================================================================

/// A shadow copy (snapshot)
#[derive(Clone)]
pub struct ShadowCopy {
    /// Whether this entry is valid
    pub valid: bool,
    /// Shadow copy ID (GUID)
    pub id: VssId,
    /// Shadow copy set ID
    pub set_id: VssId,
    /// Provider ID that created this copy
    pub provider_id: VssId,
    /// Current state
    pub state: ShadowCopyState,
    /// Attributes
    pub attributes: ShadowCopyAttributes,
    /// Volume name (e.g., "C:")
    pub volume: [u8; 4],
    /// Original volume GUID path
    pub original_volume: [u8; MAX_PATH_LEN],
    /// Shadow copy device name
    pub device_name: [u8; MAX_PATH_LEN],
    /// Exposed name (drive letter or share)
    pub exposed_name: [u8; MAX_PATH_LEN],
    /// Exposed path
    pub exposed_path: [u8; MAX_PATH_LEN],
    /// Creation timestamp (ticks)
    pub created_at: u64,
    /// Size in bytes
    pub size: u64,
    /// Used space for diff area
    pub diff_space_used: u64,
    /// Maximum diff area size
    pub diff_space_max: u64,
    /// Service machine name
    pub service_machine: [u8; MAX_NAME_LEN],
}

impl ShadowCopy {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            id: VssId::empty(),
            set_id: VssId::empty(),
            provider_id: VssId::empty(),
            state: ShadowCopyState::Unknown,
            attributes: ShadowCopyAttributes(0),
            volume: [0; 4],
            original_volume: [0; MAX_PATH_LEN],
            device_name: [0; MAX_PATH_LEN],
            exposed_name: [0; MAX_PATH_LEN],
            exposed_path: [0; MAX_PATH_LEN],
            created_at: 0,
            size: 0,
            diff_space_used: 0,
            diff_space_max: 0,
            service_machine: [0; MAX_NAME_LEN],
        }
    }

    pub fn volume_str(&self) -> &str {
        let len = self.volume.iter().position(|&b| b == 0).unwrap_or(4);
        core::str::from_utf8(&self.volume[..len]).unwrap_or("")
    }

    pub fn set_volume(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(4);
        self.volume[..len].copy_from_slice(&bytes[..len]);
        if len < 4 {
            self.volume[len..].fill(0);
        }
    }
}

// ============================================================================
// VSS Writer
// ============================================================================

/// A VSS writer (application that participates in shadow copies)
#[derive(Clone)]
pub struct VssWriter {
    /// Whether this entry is valid
    pub valid: bool,
    /// Writer ID
    pub id: VssId,
    /// Writer instance ID
    pub instance_id: VssId,
    /// Writer name
    pub name: [u8; MAX_NAME_LEN],
    /// Current state
    pub state: WriterState,
    /// Last error
    pub last_error: VssError,
    /// Failure message
    pub failure_msg: [u8; MAX_NAME_LEN],
    /// Subscribed to VSS notifications
    pub subscribed: bool,
    /// In backup session
    pub in_session: bool,
    /// Number of components
    pub component_count: u32,
}

impl VssWriter {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            id: VssId::empty(),
            instance_id: VssId::empty(),
            name: [0; MAX_NAME_LEN],
            state: WriterState::Unknown,
            last_error: VssError::Ok,
            failure_msg: [0; MAX_NAME_LEN],
            subscribed: false,
            in_session: false,
            component_count: 0,
        }
    }

    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(MAX_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&bytes[..len]);
        if len < MAX_NAME_LEN {
            self.name[len..].fill(0);
        }
    }
}

// ============================================================================
// VSS Provider
// ============================================================================

/// A VSS provider (implements shadow copy creation)
#[derive(Clone)]
pub struct VssProvider {
    /// Whether this entry is valid
    pub valid: bool,
    /// Provider ID
    pub id: VssId,
    /// Provider name
    pub name: [u8; MAX_NAME_LEN],
    /// Provider type
    pub provider_type: ProviderType,
    /// Version string
    pub version: [u8; 32],
    /// Class ID
    pub clsid: VssId,
    /// Is default provider
    pub is_default: bool,
    /// Snapshots created
    pub snapshot_count: u32,
}

impl VssProvider {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            id: VssId::empty(),
            name: [0; MAX_NAME_LEN],
            provider_type: ProviderType::Unknown,
            version: [0; 32],
            clsid: VssId::empty(),
            is_default: false,
            snapshot_count: 0,
        }
    }

    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(MAX_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&bytes[..len]);
        if len < MAX_NAME_LEN {
            self.name[len..].fill(0);
        }
    }

    pub fn version_str(&self) -> &str {
        let len = self.version.iter().position(|&b| b == 0).unwrap_or(32);
        core::str::from_utf8(&self.version[..len]).unwrap_or("")
    }

    pub fn set_version(&mut self, version: &str) {
        let bytes = version.as_bytes();
        let len = bytes.len().min(32);
        self.version[..len].copy_from_slice(&bytes[..len]);
        if len < 32 {
            self.version[len..].fill(0);
        }
    }
}

// ============================================================================
// Shadow Copy Set (Backup Session)
// ============================================================================

/// A shadow copy set (one backup session)
#[derive(Clone)]
pub struct ShadowCopySet {
    /// Whether this entry is valid
    pub valid: bool,
    /// Set ID
    pub id: VssId,
    /// Context for this set
    pub context: VssContext,
    /// Backup type
    pub backup_type: BackupType,
    /// Current state
    pub state: ShadowCopyState,
    /// Shadow copy count in this set
    pub shadow_copy_count: usize,
    /// Shadow copy IDs in this set
    pub shadow_copies: [VssId; MAX_VOLUMES],
    /// Provider for this set
    pub provider_id: VssId,
    /// Creation timestamp
    pub created_at: u64,
}

impl ShadowCopySet {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            id: VssId::empty(),
            context: VssContext::Backup,
            backup_type: BackupType::Undefined,
            state: ShadowCopyState::Unknown,
            shadow_copy_count: 0,
            shadow_copies: [const { VssId::empty() }; MAX_VOLUMES],
            provider_id: VssId::empty(),
            created_at: 0,
        }
    }
}

// ============================================================================
// VSS State
// ============================================================================

/// Global VSS state
struct VssState {
    /// Service running
    running: bool,
    /// Shadow copies (global list)
    shadow_copies: [ShadowCopy; MAX_SHADOW_COPIES],
    /// Shadow copy count
    shadow_copy_count: usize,
    /// Writers
    writers: [VssWriter; MAX_WRITERS],
    /// Writer count
    writer_count: usize,
    /// Providers
    providers: [VssProvider; MAX_PROVIDERS],
    /// Provider count
    provider_count: usize,
    /// Current shadow copy set (for in-progress operation)
    current_set: Option<ShadowCopySet>,
    /// Next ID seed
    id_seed: u64,
}

impl VssState {
    const fn new() -> Self {
        Self {
            running: false,
            shadow_copies: [const { ShadowCopy::empty() }; MAX_SHADOW_COPIES],
            shadow_copy_count: 0,
            writers: [const { VssWriter::empty() }; MAX_WRITERS],
            writer_count: 0,
            providers: [const { VssProvider::empty() }; MAX_PROVIDERS],
            provider_count: 0,
            current_set: None,
            id_seed: 0x12345678,
        }
    }

    fn generate_id(&mut self) -> VssId {
        self.id_seed = self.id_seed.wrapping_mul(1103515245).wrapping_add(12345);
        VssId::generate(self.id_seed)
    }
}

/// Global VSS state
static VSS_STATE: SpinLock<VssState> = SpinLock::new(VssState::new());

/// VSS statistics
struct VssStats {
    /// Total shadow copies created
    copies_created: AtomicU64,
    /// Total shadow copies deleted
    copies_deleted: AtomicU64,
    /// Backup sessions started
    sessions_started: AtomicU64,
    /// Backup sessions completed
    sessions_completed: AtomicU64,
    /// Backup sessions aborted
    sessions_aborted: AtomicU64,
    /// Writer freeze operations
    writer_freezes: AtomicU64,
    /// Writer thaw operations
    writer_thaws: AtomicU64,
    /// Writer failures
    writer_failures: AtomicU64,
}

impl VssStats {
    const fn new() -> Self {
        Self {
            copies_created: AtomicU64::new(0),
            copies_deleted: AtomicU64::new(0),
            sessions_started: AtomicU64::new(0),
            sessions_completed: AtomicU64::new(0),
            sessions_aborted: AtomicU64::new(0),
            writer_freezes: AtomicU64::new(0),
            writer_thaws: AtomicU64::new(0),
            writer_failures: AtomicU64::new(0),
        }
    }
}

static VSS_STATS: VssStats = VssStats::new();

// ============================================================================
// Provider Management
// ============================================================================

/// Register a VSS provider
pub fn register_provider(
    name: &str,
    provider_type: ProviderType,
    version: &str,
    is_default: bool,
) -> Result<VssId, VssError> {
    let mut state = VSS_STATE.lock();

    if !state.running {
        return Err(VssError::BadState);
    }

    if state.provider_count >= MAX_PROVIDERS {
        return Err(VssError::MaximumNumberOfSnapshotsReached);
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_PROVIDERS {
        if !state.providers[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(VssError::MaximumNumberOfSnapshotsReached),
    };

    let id = state.generate_id();
    let clsid = state.generate_id();
    let provider = &mut state.providers[slot];
    provider.valid = true;
    provider.id = id;
    provider.set_name(name);
    provider.provider_type = provider_type;
    provider.set_version(version);
    provider.clsid = clsid;
    provider.is_default = is_default;
    provider.snapshot_count = 0;

    state.provider_count += 1;

    crate::serial_println!("[VSS] Registered provider '{}'", name);

    Ok(id)
}

/// Unregister a VSS provider
pub fn unregister_provider(id: VssId) -> Result<(), VssError> {
    let mut state = VSS_STATE.lock();

    for i in 0..MAX_PROVIDERS {
        if state.providers[i].valid && state.providers[i].id == id {
            state.providers[i].valid = false;
            state.provider_count = state.provider_count.saturating_sub(1);
            crate::serial_println!("[VSS] Unregistered provider");
            return Ok(());
        }
    }

    Err(VssError::ProviderNotRegistered)
}

/// Get default provider
pub fn get_default_provider() -> Option<VssId> {
    let state = VSS_STATE.lock();

    for i in 0..MAX_PROVIDERS {
        if state.providers[i].valid && state.providers[i].is_default {
            return Some(state.providers[i].id);
        }
    }

    // Return first available if no default
    for i in 0..MAX_PROVIDERS {
        if state.providers[i].valid {
            return Some(state.providers[i].id);
        }
    }

    None
}

// ============================================================================
// Writer Management
// ============================================================================

/// Register a VSS writer
pub fn register_writer(name: &str) -> Result<VssId, VssError> {
    let mut state = VSS_STATE.lock();

    if !state.running {
        return Err(VssError::BadState);
    }

    if state.writer_count >= MAX_WRITERS {
        return Err(VssError::WriterAlreadySubscribed);
    }

    // Check for duplicate
    for i in 0..MAX_WRITERS {
        if state.writers[i].valid && state.writers[i].name_str() == name {
            return Err(VssError::WriterClassIdAlreadyRegistered);
        }
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_WRITERS {
        if !state.writers[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(VssError::WriterAlreadySubscribed),
    };

    let id = state.generate_id();
    let instance_id = state.generate_id();
    let writer = &mut state.writers[slot];
    writer.valid = true;
    writer.id = id;
    writer.instance_id = instance_id;
    writer.set_name(name);
    writer.state = WriterState::Stable;
    writer.subscribed = true;
    writer.in_session = false;
    writer.component_count = 0;

    state.writer_count += 1;

    crate::serial_println!("[VSS] Registered writer '{}'", name);

    Ok(id)
}

/// Unregister a VSS writer
pub fn unregister_writer(id: VssId) -> Result<(), VssError> {
    let mut state = VSS_STATE.lock();

    for i in 0..MAX_WRITERS {
        if state.writers[i].valid && state.writers[i].id == id {
            state.writers[i].valid = false;
            state.writer_count = state.writer_count.saturating_sub(1);
            return Ok(());
        }
    }

    Err(VssError::ObjectNotFound)
}

/// Get writer status
pub fn get_writer_status(id: VssId) -> Option<(WriterState, VssError)> {
    let state = VSS_STATE.lock();

    for i in 0..MAX_WRITERS {
        if state.writers[i].valid && state.writers[i].id == id {
            return Some((state.writers[i].state, state.writers[i].last_error));
        }
    }

    None
}

// ============================================================================
// Shadow Copy Operations
// ============================================================================

/// Start a new shadow copy set (begin backup session)
pub fn start_shadow_copy_set(context: VssContext) -> Result<VssId, VssError> {
    let mut state = VSS_STATE.lock();

    if !state.running {
        return Err(VssError::BadState);
    }

    if state.current_set.is_some() {
        return Err(VssError::SnapshotSetInProgress);
    }

    let set_id = state.generate_id();
    let set = ShadowCopySet {
        valid: true,
        id: set_id,
        context,
        backup_type: BackupType::Undefined,
        state: ShadowCopyState::Preparing,
        shadow_copy_count: 0,
        shadow_copies: [const { VssId::empty() }; MAX_VOLUMES],
        provider_id: VssId::empty(),
        created_at: crate::rtl::time::rtl_get_system_time() as u64,
    };

    state.current_set = Some(set);

    VSS_STATS.sessions_started.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[VSS] Started shadow copy set");

    Ok(set_id)
}

/// Add a volume to the current shadow copy set
pub fn add_to_shadow_copy_set(
    set_id: VssId,
    volume: &str,
) -> Result<VssId, VssError> {
    let mut state = VSS_STATE.lock();

    let set = match &mut state.current_set {
        Some(s) if s.id == set_id => s,
        _ => return Err(VssError::ObjectNotFound),
    };

    if set.shadow_copy_count >= MAX_VOLUMES {
        return Err(VssError::MaximumSnapshotSetSnapshotsReached);
    }

    // Find free shadow copy slot
    let mut slot = None;
    for i in 0..MAX_SHADOW_COPIES {
        if !state.shadow_copies[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(VssError::MaximumNumberOfSnapshotsReached),
    };

    let copy_id = state.generate_id();
    let shadow = &mut state.shadow_copies[slot];
    shadow.valid = true;
    shadow.id = copy_id;
    shadow.set_id = set_id;
    shadow.state = ShadowCopyState::Preparing;
    shadow.attributes = ShadowCopyAttributes(0);
    shadow.set_volume(volume);
    shadow.created_at = crate::rtl::time::rtl_get_system_time() as u64;

    // Get set reference again after shadow_copies borrow is done
    if let Some(ref mut set) = state.current_set {
        let idx = set.shadow_copy_count;
        set.shadow_copies[idx] = copy_id;
        set.shadow_copy_count += 1;
    }

    crate::serial_println!("[VSS] Added volume '{}' to shadow copy set", volume);

    Ok(copy_id)
}

/// Prepare for backup (notify writers)
pub fn prepare_for_backup(set_id: VssId) -> Result<(), VssError> {
    let mut state = VSS_STATE.lock();

    let is_valid_set = state.current_set.as_ref()
        .map(|s| s.id == set_id)
        .unwrap_or(false);

    if !is_valid_set {
        return Err(VssError::ObjectNotFound);
    }

    // Notify all writers to prepare
    for i in 0..MAX_WRITERS {
        if state.writers[i].valid && state.writers[i].subscribed {
            state.writers[i].state = WriterState::WaitingForFreeze;
            state.writers[i].in_session = true;
        }
    }

    if let Some(ref mut set) = state.current_set {
        set.state = ShadowCopyState::ProcessingPrepare;
    }

    crate::serial_println!("[VSS] Prepared writers for backup");

    Ok(())
}

/// Execute shadow copy (freeze I/O, take snapshot, thaw)
pub fn do_shadow_copy_set(set_id: VssId) -> Result<(), VssError> {
    let mut state = VSS_STATE.lock();

    let is_valid_set = state.current_set.as_ref()
        .map(|s| s.id == set_id)
        .unwrap_or(false);

    if !is_valid_set {
        return Err(VssError::ObjectNotFound);
    }

    // Freeze writers
    for i in 0..MAX_WRITERS {
        if state.writers[i].valid && state.writers[i].in_session {
            state.writers[i].state = WriterState::WaitingForThaw;
            VSS_STATS.writer_freezes.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Extract shadow copy IDs before modifying
    let (copy_count, copy_ids) = if let Some(ref set) = state.current_set {
        let mut ids = [VssId::empty(); MAX_VOLUMES];
        for i in 0..set.shadow_copy_count {
            ids[i] = set.shadow_copies[i];
        }
        (set.shadow_copy_count, ids)
    } else {
        (0, [VssId::empty(); MAX_VOLUMES])
    };

    // Create shadow copies
    for i in 0..copy_count {
        let copy_id = copy_ids[i];
        for j in 0..MAX_SHADOW_COPIES {
            if state.shadow_copies[j].valid && state.shadow_copies[j].id == copy_id {
                state.shadow_copies[j].state = ShadowCopyState::Created;
                VSS_STATS.copies_created.fetch_add(1, Ordering::Relaxed);
                state.shadow_copy_count += 1;
            }
        }
    }

    // Thaw writers
    for i in 0..MAX_WRITERS {
        if state.writers[i].valid && state.writers[i].in_session {
            state.writers[i].state = WriterState::WaitingForPostSnapshot;
            VSS_STATS.writer_thaws.fetch_add(1, Ordering::Relaxed);
        }
    }

    if let Some(ref mut set) = state.current_set {
        set.state = ShadowCopyState::Created;
    }

    crate::serial_println!("[VSS] Shadow copy set created successfully");

    Ok(())
}

/// Complete backup (notify writers, release resources)
pub fn backup_complete(set_id: VssId, succeeded: bool) -> Result<(), VssError> {
    let mut state = VSS_STATE.lock();

    let is_valid_set = state.current_set.as_ref()
        .map(|s| s.id == set_id)
        .unwrap_or(false);

    if !is_valid_set {
        return Err(VssError::ObjectNotFound);
    }

    // Notify writers backup complete
    for i in 0..MAX_WRITERS {
        if state.writers[i].valid && state.writers[i].in_session {
            state.writers[i].state = WriterState::Stable;
            state.writers[i].in_session = false;
        }
    }

    if succeeded {
        if let Some(ref mut set) = state.current_set {
            set.state = ShadowCopyState::Complete;
        }
        VSS_STATS.sessions_completed.fetch_add(1, Ordering::Relaxed);
        crate::serial_println!("[VSS] Backup session completed successfully");
    } else {
        if let Some(ref mut set) = state.current_set {
            set.state = ShadowCopyState::Aborted;
        }
        VSS_STATS.sessions_aborted.fetch_add(1, Ordering::Relaxed);
        crate::serial_println!("[VSS] Backup session aborted");
    }

    state.current_set = None;

    Ok(())
}

/// Abort shadow copy set
pub fn abort_shadow_copy_set(set_id: VssId) -> Result<(), VssError> {
    backup_complete(set_id, false)
}

/// Delete a shadow copy
pub fn delete_shadow_copy(id: VssId) -> Result<(), VssError> {
    let mut state = VSS_STATE.lock();

    for i in 0..MAX_SHADOW_COPIES {
        if state.shadow_copies[i].valid && state.shadow_copies[i].id == id {
            state.shadow_copies[i].valid = false;
            state.shadow_copies[i].state = ShadowCopyState::Deleted;
            state.shadow_copy_count = state.shadow_copy_count.saturating_sub(1);
            VSS_STATS.copies_deleted.fetch_add(1, Ordering::Relaxed);
            crate::serial_println!("[VSS] Deleted shadow copy");
            return Ok(());
        }
    }

    Err(VssError::ObjectNotFound)
}

/// Delete shadow copies for a volume
pub fn delete_shadow_copies_for_volume(volume: &str) -> u32 {
    let mut state = VSS_STATE.lock();
    let mut deleted = 0u32;

    for i in 0..MAX_SHADOW_COPIES {
        if state.shadow_copies[i].valid && state.shadow_copies[i].volume_str() == volume {
            state.shadow_copies[i].valid = false;
            state.shadow_copies[i].state = ShadowCopyState::Deleted;
            state.shadow_copy_count = state.shadow_copy_count.saturating_sub(1);
            deleted += 1;
            VSS_STATS.copies_deleted.fetch_add(1, Ordering::Relaxed);
        }
    }

    if deleted > 0 {
        crate::serial_println!("[VSS] Deleted {} shadow copies for volume '{}'", deleted, volume);
    }

    deleted
}

// ============================================================================
// Query Functions
// ============================================================================

/// Get shadow copy count
pub fn get_shadow_copy_count() -> usize {
    let state = VSS_STATE.lock();
    state.shadow_copy_count
}

/// Get shadow copy count for volume
pub fn get_shadow_copy_count_for_volume(volume: &str) -> usize {
    let state = VSS_STATE.lock();
    let mut count = 0;

    for i in 0..MAX_SHADOW_COPIES {
        if state.shadow_copies[i].valid && state.shadow_copies[i].volume_str() == volume {
            count += 1;
        }
    }

    count
}

/// Get shadow copy by ID
pub fn get_shadow_copy(id: VssId) -> Option<ShadowCopy> {
    let state = VSS_STATE.lock();

    for i in 0..MAX_SHADOW_COPIES {
        if state.shadow_copies[i].valid && state.shadow_copies[i].id == id {
            return Some(state.shadow_copies[i].clone());
        }
    }

    None
}

/// Get list of shadow copies for volume
pub fn list_shadow_copies_for_volume(volume: &str, out: &mut [VssId]) -> usize {
    let state = VSS_STATE.lock();
    let mut count = 0;

    for i in 0..MAX_SHADOW_COPIES {
        if count >= out.len() {
            break;
        }
        if state.shadow_copies[i].valid && state.shadow_copies[i].volume_str() == volume {
            out[count] = state.shadow_copies[i].id;
            count += 1;
        }
    }

    count
}

/// Get writer count
pub fn get_writer_count() -> usize {
    let state = VSS_STATE.lock();
    state.writer_count
}

/// Get provider count
pub fn get_provider_count() -> usize {
    let state = VSS_STATE.lock();
    state.provider_count
}

/// Get VSS statistics
pub fn get_statistics() -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        VSS_STATS.copies_created.load(Ordering::Relaxed),
        VSS_STATS.copies_deleted.load(Ordering::Relaxed),
        VSS_STATS.sessions_started.load(Ordering::Relaxed),
        VSS_STATS.sessions_completed.load(Ordering::Relaxed),
        VSS_STATS.sessions_aborted.load(Ordering::Relaxed),
        VSS_STATS.writer_freezes.load(Ordering::Relaxed),
        VSS_STATS.writer_thaws.load(Ordering::Relaxed),
        VSS_STATS.writer_failures.load(Ordering::Relaxed),
    )
}

/// Check if VSS is running
pub fn is_running() -> bool {
    let state = VSS_STATE.lock();
    state.running
}

// ============================================================================
// Initialization
// ============================================================================

/// VSS initialized flag
static VSS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the Volume Shadow Copy Service
pub fn init() {
    if VSS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[VSS] Initializing Volume Shadow Copy Service...");

    {
        let mut state = VSS_STATE.lock();
        state.running = true;
    }

    // Register default system provider
    let _ = register_provider(
        "Microsoft Software Shadow Copy Provider 1.0",
        ProviderType::System,
        "1.0.0.0",
        true,
    );

    // Register some default writers
    let _ = register_writer("System Writer");
    let _ = register_writer("Registry Writer");
    let _ = register_writer("COM+ REGDB Writer");
    let _ = register_writer("WMI Writer");
    let _ = register_writer("MSSearch Service Writer");
    let _ = register_writer("NTDS Writer");
    let _ = register_writer("DHCP Writer");
    let _ = register_writer("WINS Writer");
    let _ = register_writer("Certificate Authority Writer");
    let _ = register_writer("IIS Metabase Writer");
    let _ = register_writer("IIS Config Writer");

    crate::serial_println!("[VSS] Volume Shadow Copy Service initialized");
    crate::serial_println!("[VSS]   Providers: 1");
    crate::serial_println!("[VSS]   Writers: 11");
}
