//! KTM - Kernel Transaction Manager
//!
//! KTM provides kernel-mode transaction support for resource managers.
//! It implements the two-phase commit protocol and integrates with CLFS
//! for transaction logging.
//!
//! Key concepts:
//! - Transaction: Unit of work that can be committed or rolled back
//! - Resource Manager: Component that manages transacted resources
//! - Enlistment: Association between transaction and resource manager
//! - Transaction Manager: Coordinates transactions (this module)
//!
//! Transactions follow ACID properties:
//! - Atomicity: All or nothing
//! - Consistency: Valid state transitions
//! - Isolation: Concurrent transactions don't interfere
//! - Durability: Committed changes persist

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// Maximum transaction managers
const MAX_TRANSACTION_MANAGERS: usize = 8;

/// Maximum resource managers per TM
const MAX_RESOURCE_MANAGERS: usize = 32;

/// Maximum transactions per TM
const MAX_TRANSACTIONS: usize = 256;

/// Maximum enlistments per transaction
const MAX_ENLISTMENTS: usize = 8;

/// Maximum name length
const MAX_NAME_LEN: usize = 256;

/// Transaction timeout (ms)
const DEFAULT_TIMEOUT: u64 = 60000;

// ============================================================================
// GUIDs
// ============================================================================

/// Simple GUID structure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// Create a null GUID
    pub const fn null() -> Self {
        Self {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        }
    }

    /// Generate a pseudo-random GUID (simplified)
    pub fn generate(seed: u64) -> Self {
        Self {
            data1: (seed & 0xFFFFFFFF) as u32,
            data2: ((seed >> 32) & 0xFFFF) as u16,
            data3: ((seed >> 48) & 0x0FFF) as u16 | 0x4000, // Version 4
            data4: [
                ((seed >> 8) as u8 & 0x3F) | 0x80, // Variant
                (seed >> 16) as u8,
                (seed >> 24) as u8,
                (seed >> 32) as u8,
                (seed >> 40) as u8,
                (seed >> 48) as u8,
                (seed >> 56) as u8,
                seed as u8,
            ],
        }
    }

    pub fn is_null(&self) -> bool {
        self.data1 == 0 && self.data2 == 0 && self.data3 == 0 && self.data4 == [0; 8]
    }
}

impl Default for Guid {
    fn default() -> Self {
        Self::null()
    }
}

// ============================================================================
// Transaction States
// ============================================================================

/// Transaction state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    /// Transaction is active
    Active,
    /// Preparing to commit (phase 1)
    PrePreparing,
    /// Ready to commit
    Prepared,
    /// Committing (phase 2)
    Committing,
    /// Successfully committed
    Committed,
    /// Rolling back
    Aborting,
    /// Successfully aborted
    Aborted,
    /// In doubt (recovery needed)
    InDoubt,
    /// Forced commit during recovery
    ForcedCommit,
    /// Forced abort during recovery
    ForcedAbort,
}

/// Resource manager state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceManagerState {
    /// RM is offline
    Offline,
    /// RM is starting
    Starting,
    /// RM is online
    Online,
    /// RM is recovering
    Recovering,
    /// RM is shutting down
    ShuttingDown,
}

/// Enlistment state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnlistmentState {
    /// Enlistment is active
    Active,
    /// Preparing
    Preparing,
    /// Prepared
    Prepared,
    /// Committing
    Committing,
    /// Committed
    Committed,
    /// Aborting
    Aborting,
    /// Aborted
    Aborted,
}

// ============================================================================
// Transaction Notifications
// ============================================================================

/// Notification mask
pub mod notification_mask {
    pub const PREPREPARE: u32 = 0x0001;
    pub const PREPARE: u32 = 0x0002;
    pub const COMMIT: u32 = 0x0004;
    pub const ROLLBACK: u32 = 0x0008;
    pub const PREPREPARE_COMPLETE: u32 = 0x0010;
    pub const PREPARE_COMPLETE: u32 = 0x0020;
    pub const COMMIT_COMPLETE: u32 = 0x0040;
    pub const ROLLBACK_COMPLETE: u32 = 0x0080;
    pub const RECOVER: u32 = 0x0100;
    pub const SINGLE_PHASE_COMMIT: u32 = 0x0200;
    pub const ALL: u32 = 0x03FF;
}

// ============================================================================
// Enlistment
// ============================================================================

/// An enlistment in a transaction
#[derive(Clone)]
pub struct Enlistment {
    /// Enlistment ID
    pub id: u32,
    /// Enlistment GUID
    pub guid: Guid,
    /// Resource manager ID
    pub resource_manager_id: u32,
    /// Transaction ID
    pub transaction_id: u32,
    /// Enlistment state
    pub state: EnlistmentState,
    /// Notification mask
    pub notification_mask: u32,
    /// Active flag
    pub active: bool,
}

impl Default for Enlistment {
    fn default() -> Self {
        Self {
            id: 0,
            guid: Guid::null(),
            resource_manager_id: 0,
            transaction_id: 0,
            state: EnlistmentState::Active,
            notification_mask: notification_mask::ALL,
            active: false,
        }
    }
}

// ============================================================================
// Transaction
// ============================================================================

/// A transaction
#[derive(Clone)]
pub struct Transaction {
    /// Transaction ID
    pub id: u32,
    /// Transaction GUID
    pub guid: Guid,
    /// Description
    pub description: [u8; 128],
    /// Description length
    pub description_len: usize,
    /// Transaction state
    pub state: TransactionState,
    /// Timeout (ms)
    pub timeout: u64,
    /// Creation time
    pub created: u64,
    /// Enlistments
    pub enlistments: [Enlistment; MAX_ENLISTMENTS],
    /// Enlistment count
    pub enlistment_count: usize,
    /// Next enlistment ID
    pub next_enlistment_id: u32,
    /// Parent transaction ID (for nested transactions)
    pub parent_id: Option<u32>,
    /// Isolation level
    pub isolation_level: IsolationLevel,
    /// Active flag
    pub active: bool,
}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            id: 0,
            guid: Guid::null(),
            description: [0; 128],
            description_len: 0,
            state: TransactionState::Active,
            timeout: DEFAULT_TIMEOUT,
            created: 0,
            enlistments: core::array::from_fn(|_| Enlistment::default()),
            enlistment_count: 0,
            next_enlistment_id: 1,
            parent_id: None,
            isolation_level: IsolationLevel::ReadCommitted,
            active: false,
        }
    }
}

/// Isolation level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    /// Read uncommitted data
    ReadUncommitted,
    /// Read only committed data
    ReadCommitted,
    /// Repeatable read
    RepeatableRead,
    /// Serializable
    Serializable,
    /// Snapshot isolation
    Snapshot,
}

// ============================================================================
// Resource Manager
// ============================================================================

/// A resource manager
#[derive(Clone)]
pub struct ResourceManager {
    /// Resource manager ID
    pub id: u32,
    /// Resource manager GUID
    pub guid: Guid,
    /// Name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// State
    pub state: ResourceManagerState,
    /// CLFS log ID (if any)
    pub log_id: Option<u32>,
    /// Transactions participated in
    pub transaction_count: u64,
    /// Active flag
    pub active: bool,
}

impl Default for ResourceManager {
    fn default() -> Self {
        Self {
            id: 0,
            guid: Guid::null(),
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            state: ResourceManagerState::Offline,
            log_id: None,
            transaction_count: 0,
            active: false,
        }
    }
}

// ============================================================================
// Transaction Manager
// ============================================================================

/// A transaction manager
#[derive(Clone)]
pub struct TransactionManager {
    /// TM ID
    pub id: u32,
    /// TM GUID
    pub guid: Guid,
    /// Name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Log path
    pub log_path: [u8; MAX_NAME_LEN],
    /// Log path length
    pub log_path_len: usize,
    /// CLFS log ID
    pub log_id: Option<u32>,
    /// Resource managers
    pub resource_managers: [ResourceManager; MAX_RESOURCE_MANAGERS],
    /// RM count
    pub rm_count: usize,
    /// Next RM ID
    pub next_rm_id: u32,
    /// Transactions
    pub transactions: [Transaction; MAX_TRANSACTIONS],
    /// Transaction count
    pub transaction_count: usize,
    /// Next transaction ID
    pub next_transaction_id: u32,
    /// Active flag
    pub active: bool,
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self {
            id: 0,
            guid: Guid::null(),
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            log_path: [0; MAX_NAME_LEN],
            log_path_len: 0,
            log_id: None,
            resource_managers: core::array::from_fn(|_| ResourceManager::default()),
            rm_count: 0,
            next_rm_id: 1,
            transactions: core::array::from_fn(|_| Transaction::default()),
            transaction_count: 0,
            next_transaction_id: 1,
            active: false,
        }
    }
}

// ============================================================================
// KTM Statistics
// ============================================================================

/// KTM statistics
#[derive(Debug)]
pub struct KtmStatistics {
    /// Active TMs
    pub active_tms: AtomicU32,
    /// Active RMs
    pub active_rms: AtomicU32,
    /// Active transactions
    pub active_transactions: AtomicU32,
    /// Committed transactions
    pub committed: AtomicU64,
    /// Aborted transactions
    pub aborted: AtomicU64,
    /// In-doubt transactions
    pub in_doubt: AtomicU64,
}

impl Default for KtmStatistics {
    fn default() -> Self {
        Self {
            active_tms: AtomicU32::new(0),
            active_rms: AtomicU32::new(0),
            active_transactions: AtomicU32::new(0),
            committed: AtomicU64::new(0),
            aborted: AtomicU64::new(0),
            in_doubt: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// KTM Errors
// ============================================================================

/// KTM error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum KtmError {
    /// Success
    Success = 0,
    /// Not initialized
    NotInitialized = -1,
    /// Invalid parameter
    InvalidParameter = -2,
    /// TM not found
    TmNotFound = -3,
    /// RM not found
    RmNotFound = -4,
    /// Transaction not found
    TransactionNotFound = -5,
    /// Enlistment not found
    EnlistmentNotFound = -6,
    /// Already exists
    AlreadyExists = -7,
    /// Too many TMs
    TooManyTms = -8,
    /// Too many RMs
    TooManyRms = -9,
    /// Too many transactions
    TooManyTransactions = -10,
    /// Too many enlistments
    TooManyEnlistments = -11,
    /// Invalid state
    InvalidState = -12,
    /// Transaction aborted
    TransactionAborted = -13,
    /// Transaction committed
    TransactionCommitted = -14,
    /// Timeout
    Timeout = -15,
    /// Recovery failed
    RecoveryFailed = -16,
}

// ============================================================================
// KTM Global State
// ============================================================================

/// KTM global state
pub struct KtmState {
    /// Transaction managers
    pub tms: [TransactionManager; MAX_TRANSACTION_MANAGERS],
    /// Next TM ID
    pub next_tm_id: u32,
    /// GUID seed
    pub guid_seed: u64,
    /// Statistics
    pub statistics: KtmStatistics,
    /// Initialized flag
    pub initialized: bool,
}

impl KtmState {
    const fn new() -> Self {
        Self {
            tms: [const { TransactionManager {
                id: 0,
                guid: Guid { data1: 0, data2: 0, data3: 0, data4: [0; 8] },
                name: [0; MAX_NAME_LEN],
                name_len: 0,
                log_path: [0; MAX_NAME_LEN],
                log_path_len: 0,
                log_id: None,
                resource_managers: [const { ResourceManager {
                    id: 0,
                    guid: Guid { data1: 0, data2: 0, data3: 0, data4: [0; 8] },
                    name: [0; MAX_NAME_LEN],
                    name_len: 0,
                    state: ResourceManagerState::Offline,
                    log_id: None,
                    transaction_count: 0,
                    active: false,
                }}; MAX_RESOURCE_MANAGERS],
                rm_count: 0,
                next_rm_id: 1,
                transactions: [const { Transaction {
                    id: 0,
                    guid: Guid { data1: 0, data2: 0, data3: 0, data4: [0; 8] },
                    description: [0; 128],
                    description_len: 0,
                    state: TransactionState::Active,
                    timeout: DEFAULT_TIMEOUT,
                    created: 0,
                    enlistments: [const { Enlistment {
                        id: 0,
                        guid: Guid { data1: 0, data2: 0, data3: 0, data4: [0; 8] },
                        resource_manager_id: 0,
                        transaction_id: 0,
                        state: EnlistmentState::Active,
                        notification_mask: notification_mask::ALL,
                        active: false,
                    }}; MAX_ENLISTMENTS],
                    enlistment_count: 0,
                    next_enlistment_id: 1,
                    parent_id: None,
                    isolation_level: IsolationLevel::ReadCommitted,
                    active: false,
                }}; MAX_TRANSACTIONS],
                transaction_count: 0,
                next_transaction_id: 1,
                active: false,
            }}; MAX_TRANSACTION_MANAGERS],
            next_tm_id: 1,
            guid_seed: 0x12345678_9ABCDEF0,
            statistics: KtmStatistics {
                active_tms: AtomicU32::new(0),
                active_rms: AtomicU32::new(0),
                active_transactions: AtomicU32::new(0),
                committed: AtomicU64::new(0),
                aborted: AtomicU64::new(0),
                in_doubt: AtomicU64::new(0),
            },
            initialized: false,
        }
    }
}

/// Global KTM state
static KTM_STATE: SpinLock<KtmState> = SpinLock::new(KtmState::new());

// ============================================================================
// Transaction Manager Operations
// ============================================================================

/// Create a transaction manager
pub fn tm_create(name: &str, log_path: Option<&str>) -> Result<u32, KtmError> {
    let mut state = KTM_STATE.lock();

    if !state.initialized {
        return Err(KtmError::NotInitialized);
    }

    let name_bytes = name.as_bytes();
    if name_bytes.len() > MAX_NAME_LEN {
        return Err(KtmError::InvalidParameter);
    }

    // Find free slot
    let mut slot_idx = None;
    for idx in 0..MAX_TRANSACTION_MANAGERS {
        if !state.tms[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(KtmError::TooManyTms)?;

    let tm_id = state.next_tm_id;
    state.next_tm_id += 1;

    state.guid_seed = state.guid_seed.wrapping_add(1);
    let guid = Guid::generate(state.guid_seed);

    state.tms[idx].id = tm_id;
    state.tms[idx].guid = guid;
    state.tms[idx].name_len = name_bytes.len();
    state.tms[idx].name[..name_bytes.len()].copy_from_slice(name_bytes);

    if let Some(log) = log_path {
        let log_bytes = log.as_bytes();
        let len = core::cmp::min(log_bytes.len(), MAX_NAME_LEN);
        state.tms[idx].log_path_len = len;
        state.tms[idx].log_path[..len].copy_from_slice(&log_bytes[..len]);
    }

    state.tms[idx].active = true;
    state.statistics.active_tms.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[KTM] Created transaction manager '{}'", name);

    Ok(tm_id)
}

/// Delete a transaction manager
pub fn tm_delete(tm_id: u32) -> Result<(), KtmError> {
    let mut state = KTM_STATE.lock();

    if !state.initialized {
        return Err(KtmError::NotInitialized);
    }

    for idx in 0..MAX_TRANSACTION_MANAGERS {
        if state.tms[idx].active && state.tms[idx].id == tm_id {
            // Check for active transactions
            if state.tms[idx].transaction_count > 0 {
                return Err(KtmError::InvalidState);
            }

            state.tms[idx].active = false;
            state.statistics.active_tms.fetch_sub(1, Ordering::Relaxed);
            state.statistics.active_rms.fetch_sub(state.tms[idx].rm_count as u32, Ordering::Relaxed);

            return Ok(());
        }
    }

    Err(KtmError::TmNotFound)
}

// ============================================================================
// Resource Manager Operations
// ============================================================================

/// Create a resource manager
pub fn rm_create(tm_id: u32, name: &str) -> Result<u32, KtmError> {
    let mut state = KTM_STATE.lock();

    if !state.initialized {
        return Err(KtmError::NotInitialized);
    }

    let tm_idx = find_tm_index(&state, tm_id)?;

    if state.tms[tm_idx].rm_count >= MAX_RESOURCE_MANAGERS {
        return Err(KtmError::TooManyRms);
    }

    let name_bytes = name.as_bytes();
    if name_bytes.len() > MAX_NAME_LEN {
        return Err(KtmError::InvalidParameter);
    }

    // Find free RM slot
    let mut rm_idx = None;
    for idx in 0..MAX_RESOURCE_MANAGERS {
        if !state.tms[tm_idx].resource_managers[idx].active {
            rm_idx = Some(idx);
            break;
        }
    }

    let ridx = rm_idx.ok_or(KtmError::TooManyRms)?;

    let rm_id = state.tms[tm_idx].next_rm_id;
    state.tms[tm_idx].next_rm_id += 1;

    state.guid_seed = state.guid_seed.wrapping_add(1);
    let guid = Guid::generate(state.guid_seed);

    state.tms[tm_idx].resource_managers[ridx].id = rm_id;
    state.tms[tm_idx].resource_managers[ridx].guid = guid;
    state.tms[tm_idx].resource_managers[ridx].name_len = name_bytes.len();
    state.tms[tm_idx].resource_managers[ridx].name[..name_bytes.len()].copy_from_slice(name_bytes);
    state.tms[tm_idx].resource_managers[ridx].state = ResourceManagerState::Online;
    state.tms[tm_idx].resource_managers[ridx].active = true;

    state.tms[tm_idx].rm_count += 1;
    state.statistics.active_rms.fetch_add(1, Ordering::Relaxed);

    Ok(rm_id)
}

/// Delete a resource manager
pub fn rm_delete(tm_id: u32, rm_id: u32) -> Result<(), KtmError> {
    let mut state = KTM_STATE.lock();

    if !state.initialized {
        return Err(KtmError::NotInitialized);
    }

    let tm_idx = find_tm_index(&state, tm_id)?;

    for ridx in 0..MAX_RESOURCE_MANAGERS {
        if state.tms[tm_idx].resource_managers[ridx].active
            && state.tms[tm_idx].resource_managers[ridx].id == rm_id
        {
            state.tms[tm_idx].resource_managers[ridx].state = ResourceManagerState::Offline;
            state.tms[tm_idx].resource_managers[ridx].active = false;
            state.tms[tm_idx].rm_count -= 1;
            state.statistics.active_rms.fetch_sub(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(KtmError::RmNotFound)
}

// ============================================================================
// Transaction Operations
// ============================================================================

/// Create a transaction
pub fn transaction_create(tm_id: u32, description: Option<&str>) -> Result<u32, KtmError> {
    let mut state = KTM_STATE.lock();

    if !state.initialized {
        return Err(KtmError::NotInitialized);
    }

    let tm_idx = find_tm_index(&state, tm_id)?;

    if state.tms[tm_idx].transaction_count >= MAX_TRANSACTIONS {
        return Err(KtmError::TooManyTransactions);
    }

    // Find free transaction slot
    let mut tx_idx = None;
    for idx in 0..MAX_TRANSACTIONS {
        if !state.tms[tm_idx].transactions[idx].active {
            tx_idx = Some(idx);
            break;
        }
    }

    let tidx = tx_idx.ok_or(KtmError::TooManyTransactions)?;

    let tx_id = state.tms[tm_idx].next_transaction_id;
    state.tms[tm_idx].next_transaction_id += 1;

    state.guid_seed = state.guid_seed.wrapping_add(1);
    let guid = Guid::generate(state.guid_seed);

    state.tms[tm_idx].transactions[tidx].id = tx_id;
    state.tms[tm_idx].transactions[tidx].guid = guid;
    state.tms[tm_idx].transactions[tidx].state = TransactionState::Active;
    state.tms[tm_idx].transactions[tidx].timeout = DEFAULT_TIMEOUT;
    state.tms[tm_idx].transactions[tidx].active = true;

    if let Some(desc) = description {
        let desc_bytes = desc.as_bytes();
        let len = core::cmp::min(desc_bytes.len(), 128);
        state.tms[tm_idx].transactions[tidx].description_len = len;
        state.tms[tm_idx].transactions[tidx].description[..len].copy_from_slice(&desc_bytes[..len]);
    }

    state.tms[tm_idx].transaction_count += 1;
    state.statistics.active_transactions.fetch_add(1, Ordering::Relaxed);

    Ok(tx_id)
}

/// Commit a transaction
pub fn transaction_commit(tm_id: u32, tx_id: u32) -> Result<(), KtmError> {
    let mut state = KTM_STATE.lock();

    if !state.initialized {
        return Err(KtmError::NotInitialized);
    }

    let tm_idx = find_tm_index(&state, tm_id)?;
    let tx_idx = find_transaction_index(&state.tms[tm_idx], tx_id)?;

    let current_state = state.tms[tm_idx].transactions[tx_idx].state;

    match current_state {
        TransactionState::Active | TransactionState::Prepared => {
            // Two-phase commit
            // Phase 1: Prepare
            state.tms[tm_idx].transactions[tx_idx].state = TransactionState::PrePreparing;

            // Notify enlistments (simplified)
            for eidx in 0..MAX_ENLISTMENTS {
                if state.tms[tm_idx].transactions[tx_idx].enlistments[eidx].active {
                    state.tms[tm_idx].transactions[tx_idx].enlistments[eidx].state =
                        EnlistmentState::Preparing;
                }
            }

            state.tms[tm_idx].transactions[tx_idx].state = TransactionState::Prepared;

            // Phase 2: Commit
            state.tms[tm_idx].transactions[tx_idx].state = TransactionState::Committing;

            for eidx in 0..MAX_ENLISTMENTS {
                if state.tms[tm_idx].transactions[tx_idx].enlistments[eidx].active {
                    state.tms[tm_idx].transactions[tx_idx].enlistments[eidx].state =
                        EnlistmentState::Committed;
                }
            }

            state.tms[tm_idx].transactions[tx_idx].state = TransactionState::Committed;
            state.statistics.committed.fetch_add(1, Ordering::Relaxed);

            Ok(())
        }
        TransactionState::Committed => Err(KtmError::TransactionCommitted),
        TransactionState::Aborted => Err(KtmError::TransactionAborted),
        _ => Err(KtmError::InvalidState),
    }
}

/// Rollback a transaction
pub fn transaction_rollback(tm_id: u32, tx_id: u32) -> Result<(), KtmError> {
    let mut state = KTM_STATE.lock();

    if !state.initialized {
        return Err(KtmError::NotInitialized);
    }

    let tm_idx = find_tm_index(&state, tm_id)?;
    let tx_idx = find_transaction_index(&state.tms[tm_idx], tx_id)?;

    let current_state = state.tms[tm_idx].transactions[tx_idx].state;

    match current_state {
        TransactionState::Active
        | TransactionState::PrePreparing
        | TransactionState::Prepared => {
            state.tms[tm_idx].transactions[tx_idx].state = TransactionState::Aborting;

            // Notify enlistments to abort
            for eidx in 0..MAX_ENLISTMENTS {
                if state.tms[tm_idx].transactions[tx_idx].enlistments[eidx].active {
                    state.tms[tm_idx].transactions[tx_idx].enlistments[eidx].state =
                        EnlistmentState::Aborted;
                }
            }

            state.tms[tm_idx].transactions[tx_idx].state = TransactionState::Aborted;
            state.statistics.aborted.fetch_add(1, Ordering::Relaxed);

            Ok(())
        }
        TransactionState::Committed => Err(KtmError::TransactionCommitted),
        TransactionState::Aborted => Err(KtmError::TransactionAborted),
        _ => Err(KtmError::InvalidState),
    }
}

// ============================================================================
// Enlistment Operations
// ============================================================================

/// Create an enlistment
pub fn enlistment_create(
    tm_id: u32,
    rm_id: u32,
    tx_id: u32,
    notification_mask: u32,
) -> Result<u32, KtmError> {
    let mut state = KTM_STATE.lock();

    if !state.initialized {
        return Err(KtmError::NotInitialized);
    }

    let tm_idx = find_tm_index(&state, tm_id)?;

    // Verify RM exists
    let mut rm_found = false;
    for ridx in 0..MAX_RESOURCE_MANAGERS {
        if state.tms[tm_idx].resource_managers[ridx].active
            && state.tms[tm_idx].resource_managers[ridx].id == rm_id
        {
            rm_found = true;
            break;
        }
    }
    if !rm_found {
        return Err(KtmError::RmNotFound);
    }

    let tx_idx = find_transaction_index(&state.tms[tm_idx], tx_id)?;

    if state.tms[tm_idx].transactions[tx_idx].enlistment_count >= MAX_ENLISTMENTS {
        return Err(KtmError::TooManyEnlistments);
    }

    // Find free enlistment slot
    let mut en_idx = None;
    for idx in 0..MAX_ENLISTMENTS {
        if !state.tms[tm_idx].transactions[tx_idx].enlistments[idx].active {
            en_idx = Some(idx);
            break;
        }
    }

    let eidx = en_idx.ok_or(KtmError::TooManyEnlistments)?;

    let en_id = state.tms[tm_idx].transactions[tx_idx].next_enlistment_id;
    state.tms[tm_idx].transactions[tx_idx].next_enlistment_id += 1;

    state.guid_seed = state.guid_seed.wrapping_add(1);
    let guid = Guid::generate(state.guid_seed);

    state.tms[tm_idx].transactions[tx_idx].enlistments[eidx].id = en_id;
    state.tms[tm_idx].transactions[tx_idx].enlistments[eidx].guid = guid;
    state.tms[tm_idx].transactions[tx_idx].enlistments[eidx].resource_manager_id = rm_id;
    state.tms[tm_idx].transactions[tx_idx].enlistments[eidx].transaction_id = tx_id;
    state.tms[tm_idx].transactions[tx_idx].enlistments[eidx].notification_mask = notification_mask;
    state.tms[tm_idx].transactions[tx_idx].enlistments[eidx].state = EnlistmentState::Active;
    state.tms[tm_idx].transactions[tx_idx].enlistments[eidx].active = true;

    state.tms[tm_idx].transactions[tx_idx].enlistment_count += 1;

    Ok(en_id)
}

// ============================================================================
// Query Functions
// ============================================================================

/// List transaction managers
pub fn tm_list() -> Vec<(u32, String)> {
    let state = KTM_STATE.lock();
    let mut result = Vec::new();

    for idx in 0..MAX_TRANSACTION_MANAGERS {
        if state.tms[idx].active {
            let name = core::str::from_utf8(&state.tms[idx].name[..state.tms[idx].name_len])
                .map(String::from)
                .unwrap_or_default();
            result.push((state.tms[idx].id, name));
        }
    }

    result
}

/// List transactions in a TM
pub fn transaction_list(tm_id: u32) -> Result<Vec<(u32, TransactionState, usize)>, KtmError> {
    let state = KTM_STATE.lock();

    if !state.initialized {
        return Err(KtmError::NotInitialized);
    }

    let tm_idx = find_tm_index(&state, tm_id)?;
    let mut result = Vec::new();

    for tidx in 0..MAX_TRANSACTIONS {
        if state.tms[tm_idx].transactions[tidx].active {
            result.push((
                state.tms[tm_idx].transactions[tidx].id,
                state.tms[tm_idx].transactions[tidx].state,
                state.tms[tm_idx].transactions[tidx].enlistment_count,
            ));
        }
    }

    Ok(result)
}

/// Get KTM statistics
pub fn ktm_get_statistics() -> KtmStatistics {
    let state = KTM_STATE.lock();

    KtmStatistics {
        active_tms: AtomicU32::new(state.statistics.active_tms.load(Ordering::Relaxed)),
        active_rms: AtomicU32::new(state.statistics.active_rms.load(Ordering::Relaxed)),
        active_transactions: AtomicU32::new(state.statistics.active_transactions.load(Ordering::Relaxed)),
        committed: AtomicU64::new(state.statistics.committed.load(Ordering::Relaxed)),
        aborted: AtomicU64::new(state.statistics.aborted.load(Ordering::Relaxed)),
        in_doubt: AtomicU64::new(state.statistics.in_doubt.load(Ordering::Relaxed)),
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn find_tm_index(state: &KtmState, tm_id: u32) -> Result<usize, KtmError> {
    for idx in 0..MAX_TRANSACTION_MANAGERS {
        if state.tms[idx].active && state.tms[idx].id == tm_id {
            return Ok(idx);
        }
    }
    Err(KtmError::TmNotFound)
}

fn find_transaction_index(tm: &TransactionManager, tx_id: u32) -> Result<usize, KtmError> {
    for idx in 0..MAX_TRANSACTIONS {
        if tm.transactions[idx].active && tm.transactions[idx].id == tx_id {
            return Ok(idx);
        }
    }
    Err(KtmError::TransactionNotFound)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize KTM
pub fn init() {
    crate::serial_println!("[KTM] Initializing Kernel Transaction Manager...");

    {
        let mut state = KTM_STATE.lock();
        state.initialized = true;
    }

    crate::serial_println!("[KTM] KTM initialized");
}
