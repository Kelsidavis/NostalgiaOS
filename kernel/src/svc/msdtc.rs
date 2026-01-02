//! Microsoft Distributed Transaction Coordinator (MSDTC)
//!
//! The DTC coordinates transactions that span multiple resource managers:
//!
//! - **Two-Phase Commit**: Ensures atomicity across distributed resources
//! - **Transaction Recovery**: Recovers in-doubt transactions after failures
//! - **Logging**: Persistent transaction log for recovery
//! - **Network Transactions**: XA/OLE transactions across machines
//!
//! # Transaction Model
//!
//! MSDTC implements the X/Open DTP (Distributed Transaction Processing) model:
//! - TM (Transaction Manager): Coordinates the transaction
//! - RM (Resource Manager): Manages transactional resources (databases, etc.)
//! - AP (Application Program): Initiates and controls transactions
//!
//! # Two-Phase Commit Protocol
//!
//! Phase 1 (Prepare): TM asks all RMs if they can commit
//! Phase 2 (Commit/Abort): Based on votes, TM tells all RMs to commit or abort

extern crate alloc;

use crate::ke::SpinLock;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum transactions
pub const MAX_TRANSACTIONS: usize = 256;

/// Maximum resource managers
pub const MAX_RESOURCE_MANAGERS: usize = 32;

/// Maximum participants per transaction
pub const MAX_PARTICIPANTS: usize = 8;

/// Transaction ID length (GUID-like)
pub const TRANSACTION_ID_LEN: usize = 16;

/// Maximum RM name length
pub const MAX_RM_NAME: usize = 64;

// ============================================================================
// Types
// ============================================================================

/// Transaction identifier (GUID-like)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransactionId {
    pub data: [u8; TRANSACTION_ID_LEN],
}

impl TransactionId {
    pub const fn empty() -> Self {
        Self { data: [0; TRANSACTION_ID_LEN] }
    }

    pub fn is_empty(&self) -> bool {
        self.data.iter().all(|&b| b == 0)
    }

    pub fn generate(seed: u64) -> Self {
        let mut data = [0u8; TRANSACTION_ID_LEN];
        let mut val = seed;
        for i in 0..TRANSACTION_ID_LEN {
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            data[i] = (val >> 16) as u8;
        }
        Self { data }
    }
}

/// Transaction state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TransactionState {
    /// Not started
    None = 0,
    /// Active transaction
    Active = 1,
    /// Preparing (Phase 1)
    Preparing = 2,
    /// Prepared (all participants ready)
    Prepared = 3,
    /// Committing (Phase 2 - commit)
    Committing = 4,
    /// Committed successfully
    Committed = 5,
    /// Aborting (Phase 2 - rollback)
    Aborting = 6,
    /// Aborted
    Aborted = 7,
    /// In-doubt (coordinator failure)
    InDoubt = 8,
    /// Heuristically committed
    HeuristicallyCommitted = 9,
    /// Heuristically aborted
    HeuristicallyAborted = 10,
}

impl Default for TransactionState {
    fn default() -> Self {
        Self::None
    }
}

impl TransactionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Active => "Active",
            Self::Preparing => "Preparing",
            Self::Prepared => "Prepared",
            Self::Committing => "Committing",
            Self::Committed => "Committed",
            Self::Aborting => "Aborting",
            Self::Aborted => "Aborted",
            Self::InDoubt => "In-Doubt",
            Self::HeuristicallyCommitted => "Heuristically Committed",
            Self::HeuristicallyAborted => "Heuristically Aborted",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self,
            Self::Committed | Self::Aborted |
            Self::HeuristicallyCommitted | Self::HeuristicallyAborted
        )
    }
}

/// Participant vote
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Vote {
    /// Not yet voted
    Pending = 0,
    /// Commit vote
    Commit = 1,
    /// Abort vote (read-only)
    ReadOnly = 2,
    /// Abort vote (failure)
    Abort = 3,
}

impl Default for Vote {
    fn default() -> Self {
        Self::Pending
    }
}

/// Transaction isolation level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum IsolationLevel {
    /// Read uncommitted
    ReadUncommitted = 0,
    /// Read committed (default)
    ReadCommitted = 1,
    /// Repeatable read
    RepeatableRead = 2,
    /// Serializable
    Serializable = 3,
}

impl Default for IsolationLevel {
    fn default() -> Self {
        Self::ReadCommitted
    }
}

/// DTC error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DtcError {
    /// Success
    Ok = 0,
    /// Service not running
    NotRunning = 1,
    /// Transaction not found
    TransactionNotFound = 2,
    /// Invalid state for operation
    InvalidState = 3,
    /// Too many transactions
    TooManyTransactions = 4,
    /// Resource manager not found
    RmNotFound = 5,
    /// Too many resource managers
    TooManyRms = 6,
    /// Already enlisted
    AlreadyEnlisted = 7,
    /// Prepare failed
    PrepareFailed = 8,
    /// Commit failed
    CommitFailed = 9,
    /// Abort failed
    AbortFailed = 10,
    /// Timeout
    Timeout = 11,
    /// Log write failed
    LogFailed = 12,
}

// ============================================================================
// Transaction Participant
// ============================================================================

/// A participant in a transaction (resource manager instance)
#[derive(Clone)]
pub struct Participant {
    /// Entry is valid
    pub valid: bool,
    /// Resource manager index
    pub rm_index: usize,
    /// Enlistment time
    pub enlisted_at: i64,
    /// Current vote
    pub vote: Vote,
    /// Prepared
    pub prepared: bool,
    /// Committed
    pub committed: bool,
}

impl Participant {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            rm_index: 0,
            enlisted_at: 0,
            vote: Vote::Pending,
            prepared: false,
            committed: false,
        }
    }
}

// ============================================================================
// Transaction
// ============================================================================

/// A distributed transaction
#[derive(Clone)]
pub struct Transaction {
    /// Entry is valid
    pub valid: bool,
    /// Transaction ID
    pub id: TransactionId,
    /// Current state
    pub state: TransactionState,
    /// Isolation level
    pub isolation: IsolationLevel,
    /// Participants
    pub participants: [Participant; MAX_PARTICIPANTS],
    /// Participant count
    pub participant_count: usize,
    /// Start time
    pub start_time: i64,
    /// Prepare start time
    pub prepare_time: i64,
    /// Commit/abort time
    pub complete_time: i64,
    /// Timeout (ms)
    pub timeout_ms: u32,
    /// Description
    pub description: [u8; 64],
}

impl Transaction {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            id: TransactionId::empty(),
            state: TransactionState::None,
            isolation: IsolationLevel::ReadCommitted,
            participants: [const { Participant::empty() }; MAX_PARTICIPANTS],
            participant_count: 0,
            start_time: 0,
            prepare_time: 0,
            complete_time: 0,
            timeout_ms: 60000, // 60 seconds
            description: [0; 64],
        }
    }

    pub fn description_str(&self) -> &str {
        let len = self.description.iter().position(|&b| b == 0).unwrap_or(64);
        core::str::from_utf8(&self.description[..len]).unwrap_or("")
    }

    pub fn set_description(&mut self, desc: &str) {
        let bytes = desc.as_bytes();
        let len = bytes.len().min(64);
        self.description[..len].copy_from_slice(&bytes[..len]);
        if len < 64 {
            self.description[len..].fill(0);
        }
    }
}

// ============================================================================
// Resource Manager
// ============================================================================

/// A resource manager registration
#[derive(Clone)]
pub struct ResourceManager {
    /// Entry is valid
    pub valid: bool,
    /// RM identifier
    pub id: TransactionId,
    /// RM name
    pub name: [u8; MAX_RM_NAME],
    /// Registration time
    pub registered_at: i64,
    /// Active transaction count
    pub active_txns: u32,
    /// Total transactions
    pub total_txns: u32,
    /// Commits
    pub commits: u32,
    /// Aborts
    pub aborts: u32,
    /// Is available
    pub available: bool,
}

impl ResourceManager {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            id: TransactionId::empty(),
            name: [0; MAX_RM_NAME],
            registered_at: 0,
            active_txns: 0,
            total_txns: 0,
            commits: 0,
            aborts: 0,
            available: true,
        }
    }

    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(MAX_RM_NAME);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_RM_NAME);
        self.name[..len].copy_from_slice(&bytes[..len]);
        if len < MAX_RM_NAME {
            self.name[len..].fill(0);
        }
    }
}

// ============================================================================
// Service State
// ============================================================================

/// DTC service state
struct DtcState {
    /// Service running
    running: bool,
    /// Transactions
    transactions: [Transaction; MAX_TRANSACTIONS],
    /// Transaction count
    txn_count: usize,
    /// Resource managers
    resource_managers: [ResourceManager; MAX_RESOURCE_MANAGERS],
    /// RM count
    rm_count: usize,
    /// Next transaction seed
    txn_seed: u64,
    /// Default timeout (ms)
    default_timeout: u32,
    /// Network DTC access enabled
    network_dtc_enabled: bool,
    /// XA transactions enabled
    xa_enabled: bool,
}

impl DtcState {
    const fn new() -> Self {
        Self {
            running: false,
            transactions: [const { Transaction::empty() }; MAX_TRANSACTIONS],
            txn_count: 0,
            resource_managers: [const { ResourceManager::empty() }; MAX_RESOURCE_MANAGERS],
            rm_count: 0,
            txn_seed: 0x12345678ABCD,
            default_timeout: 60000,
            network_dtc_enabled: true,
            xa_enabled: true,
        }
    }

    fn generate_id(&mut self) -> TransactionId {
        self.txn_seed = self.txn_seed.wrapping_mul(1103515245).wrapping_add(12345);
        TransactionId::generate(self.txn_seed)
    }
}

static DTC_STATE: SpinLock<DtcState> = SpinLock::new(DtcState::new());

/// Statistics
struct DtcStats {
    /// Transactions started
    txns_started: AtomicU64,
    /// Transactions committed
    txns_committed: AtomicU64,
    /// Transactions aborted
    txns_aborted: AtomicU64,
    /// In-doubt transactions
    in_doubt_txns: AtomicU64,
    /// Active transactions
    active_txns: AtomicU64,
    /// Prepare phase starts
    prepares_started: AtomicU64,
    /// Successful prepares
    prepares_succeeded: AtomicU64,
    /// Failed prepares
    prepares_failed: AtomicU64,
    /// Total enlistments
    enlistments: AtomicU64,
}

impl DtcStats {
    const fn new() -> Self {
        Self {
            txns_started: AtomicU64::new(0),
            txns_committed: AtomicU64::new(0),
            txns_aborted: AtomicU64::new(0),
            in_doubt_txns: AtomicU64::new(0),
            active_txns: AtomicU64::new(0),
            prepares_started: AtomicU64::new(0),
            prepares_succeeded: AtomicU64::new(0),
            prepares_failed: AtomicU64::new(0),
            enlistments: AtomicU64::new(0),
        }
    }
}

static DTC_STATS: DtcStats = DtcStats::new();

// ============================================================================
// Resource Manager Management
// ============================================================================

/// Register a resource manager
pub fn register_rm(name: &str) -> Result<TransactionId, DtcError> {
    let mut state = DTC_STATE.lock();

    if !state.running {
        return Err(DtcError::NotRunning);
    }

    if state.rm_count >= MAX_RESOURCE_MANAGERS {
        return Err(DtcError::TooManyRms);
    }

    // Check for duplicate
    for i in 0..MAX_RESOURCE_MANAGERS {
        if state.resource_managers[i].valid && state.resource_managers[i].name_str() == name {
            return Ok(state.resource_managers[i].id);
        }
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_RESOURCE_MANAGERS {
        if !state.resource_managers[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(DtcError::TooManyRms),
    };

    let id = state.generate_id();
    let rm = &mut state.resource_managers[slot];
    rm.valid = true;
    rm.id = id;
    rm.set_name(name);
    rm.registered_at = crate::rtl::time::rtl_get_system_time();
    rm.active_txns = 0;
    rm.total_txns = 0;
    rm.commits = 0;
    rm.aborts = 0;
    rm.available = true;

    state.rm_count += 1;

    crate::serial_println!("[MSDTC] Registered resource manager '{}'", name);

    Ok(id)
}

/// Unregister a resource manager
pub fn unregister_rm(id: TransactionId) -> Result<(), DtcError> {
    let mut state = DTC_STATE.lock();

    for i in 0..MAX_RESOURCE_MANAGERS {
        if state.resource_managers[i].valid && state.resource_managers[i].id == id {
            if state.resource_managers[i].active_txns > 0 {
                return Err(DtcError::InvalidState);
            }
            state.resource_managers[i].valid = false;
            state.rm_count = state.rm_count.saturating_sub(1);
            return Ok(());
        }
    }

    Err(DtcError::RmNotFound)
}

/// Get RM count
pub fn get_rm_count() -> usize {
    let state = DTC_STATE.lock();
    state.rm_count
}

// ============================================================================
// Transaction Management
// ============================================================================

/// Begin a new transaction
pub fn begin_transaction(
    isolation: IsolationLevel,
    timeout_ms: Option<u32>,
    description: Option<&str>,
) -> Result<TransactionId, DtcError> {
    let mut state = DTC_STATE.lock();

    if !state.running {
        return Err(DtcError::NotRunning);
    }

    if state.txn_count >= MAX_TRANSACTIONS {
        return Err(DtcError::TooManyTransactions);
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_TRANSACTIONS {
        if !state.transactions[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(DtcError::TooManyTransactions),
    };

    let txn_id = state.generate_id();
    let timeout = timeout_ms.unwrap_or(state.default_timeout);

    let txn = &mut state.transactions[slot];
    txn.valid = true;
    txn.id = txn_id;
    txn.state = TransactionState::Active;
    txn.isolation = isolation;
    txn.participant_count = 0;
    txn.start_time = crate::rtl::time::rtl_get_system_time();
    txn.prepare_time = 0;
    txn.complete_time = 0;
    txn.timeout_ms = timeout;
    if let Some(desc) = description {
        txn.set_description(desc);
    }

    state.txn_count += 1;

    DTC_STATS.txns_started.fetch_add(1, Ordering::Relaxed);
    DTC_STATS.active_txns.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[MSDTC] Transaction started");

    Ok(txn_id)
}

/// Enlist a resource manager in a transaction
pub fn enlist(txn_id: TransactionId, rm_id: TransactionId) -> Result<(), DtcError> {
    let mut state = DTC_STATE.lock();

    if !state.running {
        return Err(DtcError::NotRunning);
    }

    // Find transaction
    let mut txn_idx = None;
    for i in 0..MAX_TRANSACTIONS {
        if state.transactions[i].valid && state.transactions[i].id == txn_id {
            txn_idx = Some(i);
            break;
        }
    }

    let txn_idx = match txn_idx {
        Some(i) => i,
        None => return Err(DtcError::TransactionNotFound),
    };

    if state.transactions[txn_idx].state != TransactionState::Active {
        return Err(DtcError::InvalidState);
    }

    // Find resource manager
    let mut rm_idx = None;
    for i in 0..MAX_RESOURCE_MANAGERS {
        if state.resource_managers[i].valid && state.resource_managers[i].id == rm_id {
            rm_idx = Some(i);
            break;
        }
    }

    let rm_idx = match rm_idx {
        Some(i) => i,
        None => return Err(DtcError::RmNotFound),
    };

    // Check if already enlisted
    let txn = &state.transactions[txn_idx];
    for i in 0..txn.participant_count {
        if txn.participants[i].valid && txn.participants[i].rm_index == rm_idx {
            return Err(DtcError::AlreadyEnlisted);
        }
    }

    if state.transactions[txn_idx].participant_count >= MAX_PARTICIPANTS {
        return Err(DtcError::TooManyRms);
    }

    // Add participant
    let participant_idx = state.transactions[txn_idx].participant_count;
    let participant = &mut state.transactions[txn_idx].participants[participant_idx];
    participant.valid = true;
    participant.rm_index = rm_idx;
    participant.enlisted_at = crate::rtl::time::rtl_get_system_time();
    participant.vote = Vote::Pending;
    participant.prepared = false;
    participant.committed = false;

    state.transactions[txn_idx].participant_count += 1;
    state.resource_managers[rm_idx].active_txns += 1;
    state.resource_managers[rm_idx].total_txns += 1;

    DTC_STATS.enlistments.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Prepare a transaction (Phase 1)
pub fn prepare(txn_id: TransactionId) -> Result<(), DtcError> {
    let mut state = DTC_STATE.lock();

    if !state.running {
        return Err(DtcError::NotRunning);
    }

    // Find transaction
    let mut txn_idx = None;
    for i in 0..MAX_TRANSACTIONS {
        if state.transactions[i].valid && state.transactions[i].id == txn_id {
            txn_idx = Some(i);
            break;
        }
    }

    let txn_idx = match txn_idx {
        Some(i) => i,
        None => return Err(DtcError::TransactionNotFound),
    };

    if state.transactions[txn_idx].state != TransactionState::Active {
        return Err(DtcError::InvalidState);
    }

    state.transactions[txn_idx].state = TransactionState::Preparing;
    state.transactions[txn_idx].prepare_time = crate::rtl::time::rtl_get_system_time();

    DTC_STATS.prepares_started.fetch_add(1, Ordering::Relaxed);

    // In a real implementation, we would notify all RMs to prepare
    // For now, mark all as prepared with commit vote
    for i in 0..state.transactions[txn_idx].participant_count {
        state.transactions[txn_idx].participants[i].vote = Vote::Commit;
        state.transactions[txn_idx].participants[i].prepared = true;
    }

    state.transactions[txn_idx].state = TransactionState::Prepared;

    DTC_STATS.prepares_succeeded.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[MSDTC] Transaction prepared");

    Ok(())
}

/// Commit a transaction (Phase 2)
pub fn commit(txn_id: TransactionId) -> Result<(), DtcError> {
    let mut state = DTC_STATE.lock();

    if !state.running {
        return Err(DtcError::NotRunning);
    }

    // Find transaction
    let mut txn_idx = None;
    for i in 0..MAX_TRANSACTIONS {
        if state.transactions[i].valid && state.transactions[i].id == txn_id {
            txn_idx = Some(i);
            break;
        }
    }

    let txn_idx = match txn_idx {
        Some(i) => i,
        None => return Err(DtcError::TransactionNotFound),
    };

    let current_state = state.transactions[txn_idx].state;
    if current_state != TransactionState::Active &&
       current_state != TransactionState::Prepared {
        return Err(DtcError::InvalidState);
    }

    // If not prepared, prepare first
    if current_state == TransactionState::Active {
        state.transactions[txn_idx].state = TransactionState::Preparing;
        for i in 0..state.transactions[txn_idx].participant_count {
            state.transactions[txn_idx].participants[i].vote = Vote::Commit;
            state.transactions[txn_idx].participants[i].prepared = true;
        }
        state.transactions[txn_idx].state = TransactionState::Prepared;
    }

    // Commit
    state.transactions[txn_idx].state = TransactionState::Committing;

    // Mark all participants as committed
    for i in 0..state.transactions[txn_idx].participant_count {
        let rm_idx = state.transactions[txn_idx].participants[i].rm_index;
        state.transactions[txn_idx].participants[i].committed = true;
        state.resource_managers[rm_idx].active_txns =
            state.resource_managers[rm_idx].active_txns.saturating_sub(1);
        state.resource_managers[rm_idx].commits += 1;
    }

    state.transactions[txn_idx].state = TransactionState::Committed;
    state.transactions[txn_idx].complete_time = crate::rtl::time::rtl_get_system_time();

    DTC_STATS.txns_committed.fetch_add(1, Ordering::Relaxed);
    DTC_STATS.active_txns.fetch_sub(1, Ordering::Relaxed);

    crate::serial_println!("[MSDTC] Transaction committed");

    Ok(())
}

/// Abort a transaction
pub fn abort(txn_id: TransactionId) -> Result<(), DtcError> {
    let mut state = DTC_STATE.lock();

    if !state.running {
        return Err(DtcError::NotRunning);
    }

    // Find transaction
    let mut txn_idx = None;
    for i in 0..MAX_TRANSACTIONS {
        if state.transactions[i].valid && state.transactions[i].id == txn_id {
            txn_idx = Some(i);
            break;
        }
    }

    let txn_idx = match txn_idx {
        Some(i) => i,
        None => return Err(DtcError::TransactionNotFound),
    };

    let current_state = state.transactions[txn_idx].state;
    if current_state.is_terminal() {
        return Err(DtcError::InvalidState);
    }

    state.transactions[txn_idx].state = TransactionState::Aborting;

    // Rollback all participants
    for i in 0..state.transactions[txn_idx].participant_count {
        let rm_idx = state.transactions[txn_idx].participants[i].rm_index;
        state.resource_managers[rm_idx].active_txns =
            state.resource_managers[rm_idx].active_txns.saturating_sub(1);
        state.resource_managers[rm_idx].aborts += 1;
    }

    state.transactions[txn_idx].state = TransactionState::Aborted;
    state.transactions[txn_idx].complete_time = crate::rtl::time::rtl_get_system_time();

    DTC_STATS.txns_aborted.fetch_add(1, Ordering::Relaxed);
    DTC_STATS.active_txns.fetch_sub(1, Ordering::Relaxed);

    crate::serial_println!("[MSDTC] Transaction aborted");

    Ok(())
}

/// Get transaction state
pub fn get_transaction_state(txn_id: TransactionId) -> Option<TransactionState> {
    let state = DTC_STATE.lock();

    for i in 0..MAX_TRANSACTIONS {
        if state.transactions[i].valid && state.transactions[i].id == txn_id {
            return Some(state.transactions[i].state);
        }
    }

    None
}

/// Get active transaction count
pub fn get_active_count() -> usize {
    let state = DTC_STATE.lock();
    let mut count = 0;
    for i in 0..MAX_TRANSACTIONS {
        if state.transactions[i].valid && !state.transactions[i].state.is_terminal() {
            count += 1;
        }
    }
    count
}

/// Clean up completed transactions
pub fn cleanup_completed() -> usize {
    let mut state = DTC_STATE.lock();
    let mut cleaned = 0;

    for i in 0..MAX_TRANSACTIONS {
        if state.transactions[i].valid && state.transactions[i].state.is_terminal() {
            state.transactions[i].valid = false;
            state.txn_count = state.txn_count.saturating_sub(1);
            cleaned += 1;
        }
    }

    cleaned
}

// ============================================================================
// Configuration
// ============================================================================

/// Enable/disable network DTC access
pub fn set_network_dtc_enabled(enabled: bool) {
    let mut state = DTC_STATE.lock();
    state.network_dtc_enabled = enabled;
    crate::serial_println!("[MSDTC] Network DTC: {}",
        if enabled { "enabled" } else { "disabled" });
}

/// Enable/disable XA transactions
pub fn set_xa_enabled(enabled: bool) {
    let mut state = DTC_STATE.lock();
    state.xa_enabled = enabled;
}

/// Set default transaction timeout
pub fn set_default_timeout(timeout_ms: u32) {
    let mut state = DTC_STATE.lock();
    state.default_timeout = timeout_ms;
}

// ============================================================================
// Statistics
// ============================================================================

/// Get DTC statistics
pub fn get_statistics() -> (u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        DTC_STATS.txns_started.load(Ordering::Relaxed),
        DTC_STATS.txns_committed.load(Ordering::Relaxed),
        DTC_STATS.txns_aborted.load(Ordering::Relaxed),
        DTC_STATS.in_doubt_txns.load(Ordering::Relaxed),
        DTC_STATS.active_txns.load(Ordering::Relaxed),
        DTC_STATS.prepares_started.load(Ordering::Relaxed),
        DTC_STATS.prepares_succeeded.load(Ordering::Relaxed),
        DTC_STATS.prepares_failed.load(Ordering::Relaxed),
        DTC_STATS.enlistments.load(Ordering::Relaxed),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = DTC_STATE.lock();
    state.running
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialized flag
static DTC_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize MSDTC
pub fn init() {
    if DTC_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[MSDTC] Initializing Distributed Transaction Coordinator...");

    {
        let mut state = DTC_STATE.lock();
        state.running = true;
        state.network_dtc_enabled = true;
        state.xa_enabled = true;
        state.default_timeout = 60000;
    }

    // Register some default resource managers
    let _ = register_rm("SQL Server");
    let _ = register_rm("MSMQ");
    let _ = register_rm("File System");

    crate::serial_println!("[MSDTC] Distributed Transaction Coordinator initialized");
    crate::serial_println!("[MSDTC]   Resource managers: 3");
    crate::serial_println!("[MSDTC]   Network DTC: enabled");
}
