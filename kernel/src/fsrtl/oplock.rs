//! Opportunistic Lock (Oplock) Support
//!
//! Oplocks allow clients to cache file data locally for improved performance.
//! When another client requests access that would invalidate the cache,
//! the oplock is "broken" and the caching client must flush/invalidate.
//!
//! Oplock types (NT 5.2):
//! - Level 1 (Exclusive): Client has exclusive access, can cache reads and writes
//! - Level 2 (Shared): Multiple readers, can cache reads only
//! - Batch: For batch file operations, delays close
//! - Filter: For filter drivers, non-breaking level 2
//!
//! This implementation is NT 5.2 (Windows Server 2003) compatible.
//!
//! # Break Notification Flow
//! 1. Operation that would conflict with oplock calls fsrtl_check_oplock_ex
//! 2. If break needed, fsrtl_oplock_break_notify initiates the break
//! 3. Break notification IRP is completed to notify oplock holder
//! 4. Oplock holder flushes caches and calls fsrtl_oplock_break_acknowledge
//! 5. Waiting IRPs are completed and operations can proceed

use crate::ex::fast_mutex::FastMutex;

/// Oplock types
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OplockType {
    /// No oplock held
    None = 0,
    /// Level 1 - exclusive, can cache reads and writes
    Level1 = 1,
    /// Batch oplock - exclusive with delayed close
    Batch = 2,
    /// Filter oplock - non-breaking shared read
    Filter = 3,
    /// Level 2 - shared, can cache reads
    Level2 = 4,
}

/// Oplock break status
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OplockBreakStatus {
    /// No break in progress
    None = 0,
    /// Breaking to Level 2
    ToLevel2 = 1,
    /// Breaking to None
    ToNone = 2,
}

/// Oplock flags
pub mod oplock_flags {
    /// Pending oplock break
    pub const OPLOCK_FLAG_BREAK_IN_PROGRESS: u32 = 0x0001;
    /// Oplock has been acknowledged
    pub const OPLOCK_FLAG_BREAK_ACK_PENDING: u32 = 0x0002;
    /// Break notification has been sent
    pub const OPLOCK_FLAG_BREAK_NOTIFY_SENT: u32 = 0x0004;
    /// Oplock is closing
    pub const OPLOCK_FLAG_CLOSING: u32 = 0x0008;
    /// Oplock is exclusive (Level1, Batch, or Filter)
    pub const OPLOCK_FLAG_EXCLUSIVE: u32 = 0x0010;
    /// Pending close for batch oplock
    pub const OPLOCK_FLAG_CLOSE_PENDING: u32 = 0x0020;
}

/// FSCTL codes for oplock operations
pub mod fsctl_oplock {
    /// Request a Level 1 oplock
    pub const FSCTL_REQUEST_OPLOCK_LEVEL_1: u32 = 0x00090000;
    /// Request a Level 2 oplock
    pub const FSCTL_REQUEST_OPLOCK_LEVEL_2: u32 = 0x00090004;
    /// Request a Batch oplock
    pub const FSCTL_REQUEST_BATCH_OPLOCK: u32 = 0x00090008;
    /// Request a Filter oplock
    pub const FSCTL_REQUEST_FILTER_OPLOCK: u32 = 0x0009000C;
    /// Acknowledge an oplock break
    pub const FSCTL_OPLOCK_BREAK_ACKNOWLEDGE: u32 = 0x00090010;
    /// Close pending (Batch oplock)
    pub const FSCTL_OPBATCH_ACK_CLOSE_PENDING: u32 = 0x00090014;
    /// Notify when oplock break occurs
    pub const FSCTL_OPLOCK_BREAK_NOTIFY: u32 = 0x00090018;
    /// Acknowledge break to no oplock
    pub const FSCTL_OPLOCK_BREAK_ACK_NO_2: u32 = 0x00090050;
}

/// FILE_OPLOCK_BROKEN_TO_* constants for IoStatusBlock.Information
pub mod oplock_break_info {
    /// Oplock broken to Level 2
    pub const FILE_OPLOCK_BROKEN_TO_LEVEL_2: usize = 0x00000007;
    /// Oplock broken to None
    pub const FILE_OPLOCK_BROKEN_TO_NONE: usize = 0x00000008;
}

/// Request types that can break an oplock
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OplockBreakRequest {
    /// Read request
    Read = 0,
    /// Write request
    Write = 1,
    /// Handle create with write access
    HandleCreate = 2,
    /// Lock request
    Lock = 3,
    /// Flush request
    Flush = 4,
    /// Close handle (for batch)
    Close = 5,
}

/// Oplock wait completion callback type
///
/// Called when an oplock break completes and a waiting IRP can proceed.
///
/// # Arguments
/// * `context` - User-provided context pointer
/// * `irp` - The IRP that was waiting (pointer as usize for FFI compatibility)
pub type OplockWaitCompleteRoutine = fn(context: usize, irp: usize);

/// Oplock pre-post IRP routine
///
/// Called before an IRP is queued to wait for oplock break.
/// Allows filesystem to save any necessary state.
pub type OplockPrePostIrpRoutine = fn(context: usize, irp: usize);

/// Information about an oplock wait
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OplockWaitInfo {
    /// File object waiting for oplock break
    pub file_object: usize,
    /// IRP associated with this wait (pointer as usize)
    pub irp: usize,
    /// Request that caused the break
    pub break_request: OplockBreakRequest,
    /// Whether the waiter has been signaled
    pub signaled: bool,
    /// Completion routine to call when break acknowledged
    pub completion_routine: Option<OplockWaitCompleteRoutine>,
    /// Context for completion routine
    pub completion_context: usize,
    /// Timestamp when wait was queued (for timeout handling)
    pub queue_time: u64,
}

impl OplockWaitInfo {
    pub const fn new() -> Self {
        Self {
            file_object: 0,
            irp: 0,
            break_request: OplockBreakRequest::Read,
            signaled: false,
            completion_routine: None,
            completion_context: 0,
            queue_time: 0,
        }
    }
}

impl Default for OplockWaitInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum waiters for oplock break
const MAX_OPLOCK_WAITERS: usize = 16;

/// Maximum Level 2 oplock holders
const MAX_LEVEL2_HOLDERS: usize = 32;

/// Level 2 oplock holder info
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Level2OplockInfo {
    /// File object holding Level 2 oplock
    pub file_object: usize,
    /// IRP for break notification
    pub irp: usize,
    /// Process ID
    pub process_id: usize,
}

impl Level2OplockInfo {
    pub const fn new() -> Self {
        Self {
            file_object: 0,
            irp: 0,
            process_id: 0,
        }
    }
}

/// Oplock statistics for monitoring
#[derive(Debug, Clone, Copy, Default)]
pub struct OplockStats {
    /// Total oplocks granted
    pub total_granted: u64,
    /// Level 1 oplocks granted
    pub level1_granted: u64,
    /// Batch oplocks granted
    pub batch_granted: u64,
    /// Filter oplocks granted
    pub filter_granted: u64,
    /// Level 2 oplocks granted
    pub level2_granted: u64,
    /// Total oplock breaks initiated
    pub total_breaks: u64,
    /// Breaks to Level 2
    pub breaks_to_level2: u64,
    /// Breaks to None
    pub breaks_to_none: u64,
    /// Break acknowledgements received
    pub break_acks: u64,
    /// Waiters queued for break completion
    pub waiters_queued: u64,
    /// Waiters completed
    pub waiters_completed: u64,
}

/// Global oplock statistics
static OPLOCK_STATS: spin::Mutex<OplockStats> = spin::Mutex::new(OplockStats {
    total_granted: 0,
    level1_granted: 0,
    batch_granted: 0,
    filter_granted: 0,
    level2_granted: 0,
    total_breaks: 0,
    breaks_to_level2: 0,
    breaks_to_none: 0,
    break_acks: 0,
    waiters_queued: 0,
    waiters_completed: 0,
});

/// Get current oplock statistics
pub fn fsrtl_get_oplock_stats() -> OplockStats {
    *OPLOCK_STATS.lock()
}

/// Oplock structure
///
/// Manages opportunistic locks for a single file stream.
#[repr(C)]
pub struct Oplock {
    /// Synchronization mutex
    mutex: FastMutex,
    /// Current oplock type
    oplock_type: OplockType,
    /// Oplock flags
    flags: u32,
    /// File object holding the exclusive oplock
    exclusive_file_object: usize,
    /// Process ID of exclusive oplock holder
    exclusive_process_id: usize,
    /// Current break status
    break_status: OplockBreakStatus,
    /// Number of Level 2 oplock holders
    level2_count: u32,
    /// Level 2 holders (for breaking all Level 2 oplocks)
    level2_holders: [Level2OplockInfo; MAX_LEVEL2_HOLDERS],
    /// Pending IRP for oplock break notification (exclusive holder)
    pending_break_irp: usize,
    /// Waiters for oplock break completion
    waiters: [OplockWaitInfo; MAX_OPLOCK_WAITERS],
    /// Number of waiters
    waiter_count: u32,
    /// Oplock break timeout in milliseconds (0 = default)
    break_timeout_ms: u32,
}

impl Oplock {
    /// Create a new empty oplock structure
    pub const fn new() -> Self {
        const EMPTY_WAITER: OplockWaitInfo = OplockWaitInfo::new();
        const EMPTY_LEVEL2: Level2OplockInfo = Level2OplockInfo::new();
        Self {
            mutex: FastMutex::new(),
            oplock_type: OplockType::None,
            flags: 0,
            exclusive_file_object: 0,
            exclusive_process_id: 0,
            break_status: OplockBreakStatus::None,
            level2_count: 0,
            level2_holders: [EMPTY_LEVEL2; MAX_LEVEL2_HOLDERS],
            pending_break_irp: 0,
            waiters: [EMPTY_WAITER; MAX_OPLOCK_WAITERS],
            waiter_count: 0,
            break_timeout_ms: 35000, // Default 35 second timeout
        }
    }

    /// Check if an oplock is held
    pub fn is_oplock_held(&self) -> bool {
        self.oplock_type != OplockType::None
    }

    /// Check if a break is in progress
    pub fn is_break_in_progress(&self) -> bool {
        self.flags & oplock_flags::OPLOCK_FLAG_BREAK_IN_PROGRESS != 0
    }

    /// Check if this is an exclusive oplock (Level 1, Batch, or Filter)
    pub fn is_exclusive(&self) -> bool {
        matches!(
            self.oplock_type,
            OplockType::Level1 | OplockType::Batch | OplockType::Filter
        )
    }

    /// Get current oplock type
    pub fn get_type(&self) -> OplockType {
        self.oplock_type
    }

    /// Get break status
    pub fn get_break_status(&self) -> OplockBreakStatus {
        self.break_status
    }

    /// Get waiter count
    pub fn get_waiter_count(&self) -> u32 {
        self.waiter_count
    }
}

impl Default for Oplock {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Initialize an oplock structure
pub fn fsrtl_initialize_oplock(oplock: &mut Oplock) {
    oplock.mutex.init();
    oplock.oplock_type = OplockType::None;
    oplock.flags = 0;
    oplock.exclusive_file_object = 0;
    oplock.exclusive_process_id = 0;
    oplock.break_status = OplockBreakStatus::None;
    oplock.level2_count = 0;
    for i in 0..MAX_LEVEL2_HOLDERS {
        oplock.level2_holders[i] = Level2OplockInfo::new();
    }
    oplock.pending_break_irp = 0;
    oplock.waiter_count = 0;
    oplock.break_timeout_ms = 35000;
}

/// Uninitialize an oplock structure
pub fn fsrtl_uninitialize_oplock(oplock: &mut Oplock) {
    oplock.mutex.acquire();

    // Clear all state
    oplock.oplock_type = OplockType::None;
    oplock.flags = 0;
    oplock.exclusive_file_object = 0;
    oplock.level2_count = 0;
    oplock.waiter_count = 0;

    oplock.mutex.release();
}

/// Request an oplock
///
/// # Arguments
/// * `oplock` - The oplock structure
/// * `file_object` - File object requesting the oplock
/// * `process_id` - Process ID of requester
/// * `requested_type` - Type of oplock requested
///
/// # Returns
/// true if oplock was granted, false if not possible
pub fn fsrtl_request_oplock(
    oplock: &mut Oplock,
    file_object: usize,
    process_id: usize,
    requested_type: OplockType,
) -> bool {
    oplock.mutex.acquire();

    let result = request_oplock_internal(oplock, file_object, process_id, requested_type);

    oplock.mutex.release();

    result
}

fn request_oplock_internal(
    oplock: &mut Oplock,
    file_object: usize,
    process_id: usize,
    requested_type: OplockType,
) -> bool {
    // Can't grant oplock during break
    if oplock.is_break_in_progress() {
        return false;
    }

    match requested_type {
        OplockType::None => true,

        OplockType::Level1 | OplockType::Batch | OplockType::Filter => {
            // Exclusive oplocks require no existing oplock
            if oplock.oplock_type != OplockType::None {
                return false;
            }

            oplock.oplock_type = requested_type;
            oplock.exclusive_file_object = file_object;
            oplock.exclusive_process_id = process_id;
            true
        }

        OplockType::Level2 => {
            // Level 2 can coexist with other Level 2 or be granted if no exclusive
            match oplock.oplock_type {
                OplockType::None => {
                    oplock.oplock_type = OplockType::Level2;
                    oplock.level2_count = 1;
                    true
                }
                OplockType::Level2 => {
                    oplock.level2_count += 1;
                    true
                }
                _ => false,
            }
        }
    }
}

/// Check if an operation would break an oplock
///
/// # Arguments
/// * `oplock` - The oplock structure
/// * `file_object` - File object performing the operation
/// * `request` - Type of operation
///
/// # Returns
/// OplockBreakStatus indicating what break (if any) would occur
pub fn fsrtl_check_oplock(
    oplock: &Oplock,
    file_object: usize,
    request: OplockBreakRequest,
) -> OplockBreakStatus {
    // No oplock = no break needed
    if oplock.oplock_type == OplockType::None {
        return OplockBreakStatus::None;
    }

    // Same file object doesn't break its own oplock
    if oplock.exclusive_file_object == file_object {
        return OplockBreakStatus::None;
    }

    match (oplock.oplock_type, request) {
        // Level 1/Batch: write access breaks to none, read access breaks to level 2
        (OplockType::Level1 | OplockType::Batch, OplockBreakRequest::Write) => {
            OplockBreakStatus::ToNone
        }
        (OplockType::Level1 | OplockType::Batch, OplockBreakRequest::HandleCreate) => {
            OplockBreakStatus::ToNone
        }
        (OplockType::Level1 | OplockType::Batch, OplockBreakRequest::Lock) => {
            OplockBreakStatus::ToNone
        }
        (OplockType::Level1, OplockBreakRequest::Read) => {
            OplockBreakStatus::ToLevel2
        }
        (OplockType::Batch, OplockBreakRequest::Read) => {
            OplockBreakStatus::ToLevel2
        }
        (OplockType::Batch, OplockBreakRequest::Close) => {
            OplockBreakStatus::ToNone
        }

        // Filter oplock is non-breaking
        (OplockType::Filter, _) => {
            OplockBreakStatus::None
        }

        // Level 2: only writes break the oplock
        (OplockType::Level2, OplockBreakRequest::Write) => {
            OplockBreakStatus::ToNone
        }
        (OplockType::Level2, OplockBreakRequest::Lock) => {
            OplockBreakStatus::ToNone
        }
        (OplockType::Level2, _) => {
            OplockBreakStatus::None
        }

        (OplockType::None, _) => OplockBreakStatus::None,

        // Default: no break
        _ => OplockBreakStatus::None,
    }
}

/// Initiate an oplock break
///
/// # Arguments
/// * `oplock` - The oplock structure
/// * `break_to` - What level to break to
///
/// # Returns
/// true if break was initiated, false if no break needed
pub fn fsrtl_oplock_break_notify(
    oplock: &mut Oplock,
    break_to: OplockBreakStatus,
) -> bool {
    oplock.mutex.acquire();

    let result = if oplock.oplock_type == OplockType::None {
        false
    } else if oplock.is_break_in_progress() {
        // Already breaking - update target if breaking further
        if break_to == OplockBreakStatus::ToNone
           && oplock.break_status == OplockBreakStatus::ToLevel2
        {
            oplock.break_status = OplockBreakStatus::ToNone;
        }
        true
    } else {
        // Start the break
        oplock.flags |= oplock_flags::OPLOCK_FLAG_BREAK_IN_PROGRESS;
        oplock.break_status = break_to;

        // TODO: Complete pending IRP to notify oplock holder

        true
    };

    oplock.mutex.release();

    result
}

/// Acknowledge an oplock break
///
/// Called by the oplock holder after flushing caches.
///
/// # Arguments
/// * `oplock` - The oplock structure
/// * `file_object` - File object acknowledging the break
/// * `new_level` - Level to transition to (must match break_status)
pub fn fsrtl_oplock_break_acknowledge(
    oplock: &mut Oplock,
    file_object: usize,
    new_level: OplockType,
) -> bool {
    oplock.mutex.acquire();

    let result = acknowledge_break_internal(oplock, file_object, new_level);

    oplock.mutex.release();

    result
}

fn acknowledge_break_internal(
    oplock: &mut Oplock,
    file_object: usize,
    new_level: OplockType,
) -> bool {
    // Must be the oplock holder
    if oplock.exclusive_file_object != file_object {
        return false;
    }

    // Must be breaking
    if !oplock.is_break_in_progress() {
        return false;
    }

    // Validate the new level matches break status
    let valid = match oplock.break_status {
        OplockBreakStatus::ToNone => new_level == OplockType::None,
        OplockBreakStatus::ToLevel2 => {
            new_level == OplockType::Level2 || new_level == OplockType::None
        }
        OplockBreakStatus::None => false,
    };

    if !valid {
        return false;
    }

    // Complete the break
    oplock.flags &= !oplock_flags::OPLOCK_FLAG_BREAK_IN_PROGRESS;
    oplock.break_status = OplockBreakStatus::None;

    if new_level == OplockType::None {
        oplock.oplock_type = OplockType::None;
        oplock.exclusive_file_object = 0;
        oplock.exclusive_process_id = 0;
    } else {
        oplock.oplock_type = new_level;
        if new_level == OplockType::Level2 {
            oplock.level2_count = 1;
        }
    }

    // Signal waiters
    signal_waiters(oplock);

    true
}

/// Release an oplock
///
/// Called when the file is closed or oplock is voluntarily released.
pub fn fsrtl_oplock_release(
    oplock: &mut Oplock,
    file_object: usize,
) {
    oplock.mutex.acquire();

    match oplock.oplock_type {
        OplockType::Level1 | OplockType::Batch | OplockType::Filter => {
            if oplock.exclusive_file_object == file_object {
                oplock.oplock_type = OplockType::None;
                oplock.flags = 0;
                oplock.exclusive_file_object = 0;
                oplock.exclusive_process_id = 0;
                oplock.break_status = OplockBreakStatus::None;

                // Signal any waiters
                signal_waiters(oplock);
            }
        }
        OplockType::Level2 => {
            // Decrement level 2 count
            if oplock.level2_count > 0 {
                oplock.level2_count -= 1;
                if oplock.level2_count == 0 {
                    oplock.oplock_type = OplockType::None;
                }
            }
        }
        OplockType::None => {}
    }

    oplock.mutex.release();
}

/// Get current oplock type
pub fn fsrtl_get_oplock_type(oplock: &Oplock) -> OplockType {
    oplock.oplock_type
}

/// Check if oplocks are present on a file
pub fn fsrtl_current_batch_oplock(oplock: &Oplock) -> bool {
    oplock.oplock_type == OplockType::Batch
}

/// Check if there's an oplock break in progress
pub fn fsrtl_oplock_is_fast_io_possible(oplock: &Oplock) -> bool {
    // Fast I/O is not possible if there's an exclusive oplock we don't own
    // or if a break is in progress
    !oplock.is_break_in_progress() &&
    (oplock.oplock_type == OplockType::None || oplock.oplock_type == OplockType::Level2)
}

// ============================================================================
// FSCTL Handler
// ============================================================================

/// NT Status codes for oplock operations
pub mod oplock_status {
    /// Success
    pub const STATUS_SUCCESS: i32 = 0;
    /// IRP is pending
    pub const STATUS_PENDING: i32 = 0x00000103u32 as i32;
    /// Oplock not granted
    pub const STATUS_OPLOCK_NOT_GRANTED: i32 = 0xC00000E2u32 as i32;
    /// Oplock break in progress
    pub const STATUS_OPLOCK_BREAK_IN_PROGRESS: i32 = 0x00000108u32 as i32;
    /// Invalid oplock protocol
    pub const STATUS_INVALID_OPLOCK_PROTOCOL: i32 = 0xC00000E3u32 as i32;
    /// Cancelled
    pub const STATUS_CANCELLED: i32 = 0xC0000120u32 as i32;
}

/// Handle FSCTL oplock operations
///
/// This is the main entry point for filesystem oplock FSCTL handling.
///
/// # Arguments
/// * `oplock` - The oplock structure
/// * `fsctl_code` - The FSCTL code (FSCTL_REQUEST_OPLOCK_*, etc.)
/// * `file_object` - File object for this operation
/// * `process_id` - Process ID of caller
/// * `open_count` - Number of open handles to this file
///
/// # Returns
/// NTSTATUS code
pub fn fsrtl_oplock_fsctrl(
    oplock: &mut Oplock,
    fsctl_code: u32,
    file_object: usize,
    process_id: usize,
    open_count: u32,
) -> i32 {
    use fsctl_oplock::*;

    match fsctl_code {
        FSCTL_REQUEST_OPLOCK_LEVEL_1 => {
            // Level 1 requires single opener
            if open_count != 1 {
                return oplock_status::STATUS_OPLOCK_NOT_GRANTED;
            }
            if fsrtl_request_oplock(oplock, file_object, process_id, OplockType::Level1) {
                update_stats(|s| {
                    s.total_granted += 1;
                    s.level1_granted += 1;
                });
                oplock_status::STATUS_PENDING
            } else {
                oplock_status::STATUS_OPLOCK_NOT_GRANTED
            }
        }

        FSCTL_REQUEST_BATCH_OPLOCK => {
            if open_count != 1 {
                return oplock_status::STATUS_OPLOCK_NOT_GRANTED;
            }
            if fsrtl_request_oplock(oplock, file_object, process_id, OplockType::Batch) {
                update_stats(|s| {
                    s.total_granted += 1;
                    s.batch_granted += 1;
                });
                oplock_status::STATUS_PENDING
            } else {
                oplock_status::STATUS_OPLOCK_NOT_GRANTED
            }
        }

        FSCTL_REQUEST_FILTER_OPLOCK => {
            if open_count != 1 {
                return oplock_status::STATUS_OPLOCK_NOT_GRANTED;
            }
            if fsrtl_request_oplock(oplock, file_object, process_id, OplockType::Filter) {
                update_stats(|s| {
                    s.total_granted += 1;
                    s.filter_granted += 1;
                });
                oplock_status::STATUS_PENDING
            } else {
                oplock_status::STATUS_OPLOCK_NOT_GRANTED
            }
        }

        FSCTL_REQUEST_OPLOCK_LEVEL_2 => {
            if fsrtl_request_oplock(oplock, file_object, process_id, OplockType::Level2) {
                update_stats(|s| {
                    s.total_granted += 1;
                    s.level2_granted += 1;
                });
                oplock_status::STATUS_PENDING
            } else {
                oplock_status::STATUS_OPLOCK_NOT_GRANTED
            }
        }

        FSCTL_OPLOCK_BREAK_ACKNOWLEDGE => {
            // Acknowledge break and transition to Level 2
            if fsrtl_oplock_break_acknowledge(oplock, file_object, OplockType::Level2) {
                update_stats(|s| s.break_acks += 1);
                oplock_status::STATUS_SUCCESS
            } else {
                oplock_status::STATUS_INVALID_OPLOCK_PROTOCOL
            }
        }

        FSCTL_OPLOCK_BREAK_ACK_NO_2 => {
            // Acknowledge break to None
            if fsrtl_oplock_break_acknowledge(oplock, file_object, OplockType::None) {
                update_stats(|s| s.break_acks += 1);
                oplock_status::STATUS_SUCCESS
            } else {
                oplock_status::STATUS_INVALID_OPLOCK_PROTOCOL
            }
        }

        FSCTL_OPBATCH_ACK_CLOSE_PENDING => {
            // Batch oplock close pending
            oplock.mutex.acquire();
            if oplock.oplock_type == OplockType::Batch
                && oplock.exclusive_file_object == file_object
            {
                oplock.flags |= oplock_flags::OPLOCK_FLAG_CLOSE_PENDING;
            }
            oplock.mutex.release();
            oplock_status::STATUS_SUCCESS
        }

        FSCTL_OPLOCK_BREAK_NOTIFY => {
            // Request notification when oplock break occurs
            oplock.mutex.acquire();
            let result = if oplock.is_break_in_progress() {
                // Break already in progress, return immediately
                oplock_status::STATUS_SUCCESS
            } else if oplock.oplock_type == OplockType::None {
                // No oplock, return immediately
                oplock_status::STATUS_SUCCESS
            } else {
                // Queue for notification
                oplock_status::STATUS_PENDING
            };
            oplock.mutex.release();
            result
        }

        _ => oplock_status::STATUS_INVALID_OPLOCK_PROTOCOL,
    }
}

/// Extended oplock check with wait capability
///
/// Checks if an operation would break an oplock and optionally waits
/// for the break to complete.
///
/// # Arguments
/// * `oplock` - The oplock structure
/// * `file_object` - File object performing operation
/// * `request` - Type of operation
/// * `irp` - IRP to queue if wait needed (pointer as usize)
/// * `completion_routine` - Callback when wait completes
/// * `completion_context` - Context for callback
///
/// # Returns
/// NTSTATUS code (STATUS_SUCCESS or STATUS_PENDING)
pub fn fsrtl_check_oplock_ex(
    oplock: &mut Oplock,
    file_object: usize,
    request: OplockBreakRequest,
    irp: usize,
    completion_routine: Option<OplockWaitCompleteRoutine>,
    completion_context: usize,
) -> i32 {
    oplock.mutex.acquire();

    // Check what break is needed
    let break_status = fsrtl_check_oplock(oplock, file_object, request);

    let result = match break_status {
        OplockBreakStatus::None => {
            // No break needed
            oplock.mutex.release();
            return oplock_status::STATUS_SUCCESS;
        }
        OplockBreakStatus::ToLevel2 | OplockBreakStatus::ToNone => {
            // Need to break
            if !oplock.is_break_in_progress() {
                // Initiate the break
                oplock.flags |= oplock_flags::OPLOCK_FLAG_BREAK_IN_PROGRESS;
                oplock.break_status = break_status;

                update_stats(|s| {
                    s.total_breaks += 1;
                    match break_status {
                        OplockBreakStatus::ToLevel2 => s.breaks_to_level2 += 1,
                        OplockBreakStatus::ToNone => s.breaks_to_none += 1,
                        _ => {}
                    }
                });

                // Complete the pending IRP to notify oplock holder
                if oplock.pending_break_irp != 0 {
                    // In a full implementation, we'd complete this IRP here
                    // with FILE_OPLOCK_BROKEN_TO_LEVEL_2 or _TO_NONE
                    oplock.flags |= oplock_flags::OPLOCK_FLAG_BREAK_NOTIFY_SENT;
                }
            }

            // Queue the caller to wait for break completion
            if add_waiter_ex(oplock, file_object, irp, request, completion_routine, completion_context) {
                update_stats(|s| s.waiters_queued += 1);
                oplock_status::STATUS_PENDING
            } else {
                // Couldn't add waiter - wait synchronously is required
                oplock_status::STATUS_OPLOCK_BREAK_IN_PROGRESS
            }
        }
    };

    oplock.mutex.release();
    result
}

/// Break all Level 2 oplocks
///
/// Called when an operation requires breaking all shared oplocks.
pub fn fsrtl_break_level2_oplocks(oplock: &mut Oplock) {
    oplock.mutex.acquire();

    if oplock.oplock_type == OplockType::Level2 && oplock.level2_count > 0 {
        // Notify all Level 2 holders
        for i in 0..oplock.level2_count as usize {
            if i < MAX_LEVEL2_HOLDERS {
                let holder = &oplock.level2_holders[i];
                if holder.irp != 0 {
                    // In a full implementation, complete this IRP with
                    // FILE_OPLOCK_BROKEN_TO_NONE
                }
            }
        }

        // Clear all Level 2 oplocks
        oplock.level2_count = 0;
        oplock.oplock_type = OplockType::None;
        for i in 0..MAX_LEVEL2_HOLDERS {
            oplock.level2_holders[i] = Level2OplockInfo::new();
        }

        update_stats(|s| s.total_breaks += 1);
    }

    oplock.mutex.release();
}

// ============================================================================
// Internal Helper Functions
// ============================================================================

/// Update global oplock statistics
fn update_stats<F: FnOnce(&mut OplockStats)>(f: F) {
    let mut stats = OPLOCK_STATS.lock();
    f(&mut stats);
}

/// Signal all waiters that the oplock break is complete
fn signal_waiters(oplock: &mut Oplock) {
    for i in 0..oplock.waiter_count as usize {
        let waiter = &mut oplock.waiters[i];
        waiter.signaled = true;

        // Call completion routine if present
        if let Some(routine) = waiter.completion_routine {
            routine(waiter.completion_context, waiter.irp);
        }

        update_stats(|s| s.waiters_completed += 1);
    }

    // Clear all waiters
    for i in 0..oplock.waiter_count as usize {
        oplock.waiters[i] = OplockWaitInfo::new();
    }
    oplock.waiter_count = 0;
}

/// Add a waiter for oplock break completion (extended version)
fn add_waiter_ex(
    oplock: &mut Oplock,
    file_object: usize,
    irp: usize,
    request: OplockBreakRequest,
    completion_routine: Option<OplockWaitCompleteRoutine>,
    completion_context: usize,
) -> bool {
    if oplock.waiter_count >= MAX_OPLOCK_WAITERS as u32 {
        return false;
    }

    let idx = oplock.waiter_count as usize;
    oplock.waiters[idx] = OplockWaitInfo {
        file_object,
        irp,
        break_request: request,
        signaled: false,
        completion_routine,
        completion_context,
        queue_time: crate::hal::rtc::get_system_time(),
    };
    oplock.waiter_count += 1;

    true
}

/// Add a waiter for oplock break completion (simple version)
fn add_waiter(
    oplock: &mut Oplock,
    file_object: usize,
    request: OplockBreakRequest,
) -> bool {
    add_waiter_ex(oplock, file_object, 0, request, None, 0)
}
