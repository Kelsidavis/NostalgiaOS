//! File Byte-Range Locking
//!
//! Provides byte-range locking for file systems to manage exclusive
//! and shared access to file regions.
//!
//! Key features:
//! - Exclusive and shared locks
//! - Lock key support for lock owner identification
//! - Fast lock check routines for DPC-level use
//! - Custom completion and unlock callbacks
//!
//! This implementation is NT 5.2 (Windows Server 2003) compatible.

use crate::ex::fast_mutex::FastMutex;

/// Maximum number of file locks per file (static limit)
const MAX_LOCKS_PER_FILE: usize = 64;

/// Lock type flags
pub mod lock_flags {
    /// Exclusive lock (write access)
    pub const EXCLUSIVE_LOCK: u32 = 0x01;
    /// Fail immediately if lock not available
    pub const FAIL_IMMEDIATELY: u32 = 0x02;
}

/// Information about a single file lock
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileLockInfo {
    /// Starting byte offset of the locked range
    pub starting_byte: i64,
    /// Length of the locked range in bytes
    pub length: i64,
    /// Whether this is an exclusive lock
    pub exclusive_lock: bool,
    /// Lock key (typically process-specific)
    pub key: u32,
    /// File object that owns this lock
    pub file_object: usize, // *mut FileObject
    /// Process ID of lock owner
    pub process_id: usize,
    /// Ending byte offset (computed)
    pub ending_byte: i64,
}

impl FileLockInfo {
    pub const fn new() -> Self {
        Self {
            starting_byte: 0,
            length: 0,
            exclusive_lock: false,
            key: 0,
            file_object: 0,
            process_id: 0,
            ending_byte: 0,
        }
    }

    /// Check if this lock overlaps with a range
    pub fn overlaps(&self, start: i64, end: i64) -> bool {
        self.starting_byte < end && self.ending_byte > start
    }

    /// Check if this lock conflicts with a requested lock
    pub fn conflicts_with(&self, start: i64, length: i64, exclusive: bool) -> bool {
        let end = start + length;

        // No overlap means no conflict
        if !self.overlaps(start, end) {
            return false;
        }

        // Exclusive locks always conflict with overlapping locks
        // Shared locks only conflict with exclusive locks
        self.exclusive_lock || exclusive
    }
}

impl Default for FileLockInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// File lock structure
///
/// Manages all locks for a single file stream.
#[repr(C)]
pub struct FileLock {
    /// Synchronization mutex
    mutex: FastMutex,
    /// Whether fast I/O is questionable due to locks
    pub fast_io_is_questionable: bool,
    /// Number of locks currently held
    lock_count: u32,
    /// Array of locks
    locks: [FileLockInfo; MAX_LOCKS_PER_FILE],
    /// Last returned lock info (for enumeration)
    pub last_returned_lock_info: FileLockInfo,
    /// Index of last returned lock
    last_returned_index: usize,
}

impl FileLock {
    /// Create a new empty file lock structure
    pub const fn new() -> Self {
        const EMPTY_LOCK: FileLockInfo = FileLockInfo::new();
        Self {
            mutex: FastMutex::new(),
            fast_io_is_questionable: false,
            lock_count: 0,
            locks: [EMPTY_LOCK; MAX_LOCKS_PER_FILE],
            last_returned_lock_info: FileLockInfo::new(),
            last_returned_index: 0,
        }
    }
}

impl Default for FileLock {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Initialize a file lock structure
pub fn fsrtl_initialize_file_lock(lock: &mut FileLock) {
    lock.mutex.init();
    lock.fast_io_is_questionable = false;
    lock.lock_count = 0;
    lock.last_returned_index = 0;
}

/// Uninitialize a file lock structure
pub fn fsrtl_uninitialize_file_lock(lock: &mut FileLock) {
    // Clear all locks
    lock.lock_count = 0;
    lock.fast_io_is_questionable = false;
}

/// Process a file lock operation
///
/// # Arguments
/// * `lock` - The file lock structure
/// * `file_object` - File object requesting the lock
/// * `process_id` - Process ID of requester
/// * `starting_byte` - Start of range to lock
/// * `length` - Length of range to lock
/// * `key` - Lock key for identification
/// * `fail_immediately` - Whether to fail if lock not available
/// * `exclusive` - Whether to request exclusive lock
///
/// # Returns
/// true if lock granted, false if denied or would block
pub fn fsrtl_process_file_lock(
    lock: &mut FileLock,
    file_object: usize,
    process_id: usize,
    starting_byte: i64,
    length: i64,
    key: u32,
    fail_immediately: bool,
    exclusive: bool,
) -> bool {
    lock.mutex.acquire();

    let result = process_lock_internal(
        lock,
        file_object,
        process_id,
        starting_byte,
        length,
        key,
        fail_immediately,
        exclusive,
    );

    lock.mutex.release();

    result
}

fn process_lock_internal(
    lock: &mut FileLock,
    file_object: usize,
    process_id: usize,
    starting_byte: i64,
    length: i64,
    key: u32,
    fail_immediately: bool,
    exclusive: bool,
) -> bool {
    // Check for conflicts with existing locks
    for i in 0..lock.lock_count as usize {
        let existing = &lock.locks[i];

        // Same owner with same key can always extend/overlap their own locks
        if existing.file_object == file_object && existing.key == key {
            continue;
        }

        if existing.conflicts_with(starting_byte, length, exclusive) {
            if fail_immediately {
                return false;
            }
            // Would need to wait - for now just fail
            return false;
        }
    }

    // No conflicts - grant the lock
    if lock.lock_count >= MAX_LOCKS_PER_FILE as u32 {
        return false; // Too many locks
    }

    let idx = lock.lock_count as usize;
    lock.locks[idx] = FileLockInfo {
        starting_byte,
        length,
        exclusive_lock: exclusive,
        key,
        file_object,
        process_id,
        ending_byte: starting_byte + length,
    };
    lock.lock_count += 1;

    // Update fast I/O flag
    if exclusive {
        lock.fast_io_is_questionable = true;
    }

    true
}

/// Check if a read operation would conflict with locks
///
/// This is the fast path for checking read access.
pub fn fsrtl_check_lock_for_read_access(
    lock: &FileLock,
    file_object: usize,
    starting_byte: i64,
    length: i64,
    key: u32,
) -> bool {
    // Fast path: no locks means no conflict
    if lock.lock_count == 0 {
        return true;
    }

    unsafe { (*(lock as *const FileLock as *mut FileLock)).mutex.acquire() };

    let result = check_read_internal(lock, file_object, starting_byte, length, key);

    unsafe { (*(lock as *const FileLock as *mut FileLock)).mutex.release() };

    result
}

fn check_read_internal(
    lock: &FileLock,
    file_object: usize,
    starting_byte: i64,
    length: i64,
    key: u32,
) -> bool {
    let end = starting_byte + length;

    for i in 0..lock.lock_count as usize {
        let existing = &lock.locks[i];

        // Our own locks don't block us
        if existing.file_object == file_object && existing.key == key {
            continue;
        }

        // Only exclusive locks block reads
        if existing.exclusive_lock && existing.overlaps(starting_byte, end) {
            return false;
        }
    }

    true
}

/// Check if a write operation would conflict with locks
///
/// This is the fast path for checking write access.
pub fn fsrtl_check_lock_for_write_access(
    lock: &FileLock,
    file_object: usize,
    starting_byte: i64,
    length: i64,
    key: u32,
) -> bool {
    // Fast path: no locks means no conflict
    if lock.lock_count == 0 {
        return true;
    }

    unsafe { (*(lock as *const FileLock as *mut FileLock)).mutex.acquire() };

    let result = check_write_internal(lock, file_object, starting_byte, length, key);

    unsafe { (*(lock as *const FileLock as *mut FileLock)).mutex.release() };

    result
}

fn check_write_internal(
    lock: &FileLock,
    file_object: usize,
    starting_byte: i64,
    length: i64,
    key: u32,
) -> bool {
    let end = starting_byte + length;

    for i in 0..lock.lock_count as usize {
        let existing = &lock.locks[i];

        // Our own locks don't block us
        if existing.file_object == file_object && existing.key == key {
            continue;
        }

        // Any lock blocks writes
        if existing.overlaps(starting_byte, end) {
            return false;
        }
    }

    true
}

/// Fast lock acquisition (non-IRP based)
///
/// Attempts to acquire a lock immediately.
pub fn fsrtl_fast_lock(
    lock: &mut FileLock,
    file_object: usize,
    process_id: usize,
    starting_byte: i64,
    length: i64,
    key: u32,
    exclusive: bool,
) -> bool {
    fsrtl_process_file_lock(lock, file_object, process_id, starting_byte, length, key, true, exclusive)
}

/// Unlock a single lock
pub fn fsrtl_fast_unlock_single(
    lock: &mut FileLock,
    file_object: usize,
    starting_byte: i64,
    length: i64,
    key: u32,
) -> bool {
    lock.mutex.acquire();

    let result = unlock_single_internal(lock, file_object, starting_byte, length, key);

    lock.mutex.release();

    result
}

fn unlock_single_internal(
    lock: &mut FileLock,
    file_object: usize,
    starting_byte: i64,
    length: i64,
    key: u32,
) -> bool {
    for i in 0..lock.lock_count as usize {
        let existing = &lock.locks[i];

        if existing.file_object == file_object
            && existing.key == key
            && existing.starting_byte == starting_byte
            && existing.length == length
        {
            // Remove this lock by shifting remaining locks down
            for j in i..(lock.lock_count as usize - 1) {
                lock.locks[j] = lock.locks[j + 1];
            }
            lock.lock_count -= 1;

            // Update fast I/O flag
            update_fast_io_flag(lock);

            return true;
        }
    }

    false
}

/// Unlock all locks owned by a file object
pub fn fsrtl_fast_unlock_all(lock: &mut FileLock, file_object: usize) -> bool {
    lock.mutex.acquire();

    let mut removed = false;
    let mut i = 0;
    while i < lock.lock_count as usize {
        if lock.locks[i].file_object == file_object {
            // Remove this lock
            for j in i..(lock.lock_count as usize - 1) {
                lock.locks[j] = lock.locks[j + 1];
            }
            lock.lock_count -= 1;
            removed = true;
            // Don't increment i, check the new lock at this position
        } else {
            i += 1;
        }
    }

    update_fast_io_flag(lock);

    lock.mutex.release();

    removed
}

/// Unlock all locks owned by a file object with a specific key
pub fn fsrtl_fast_unlock_all_by_key(lock: &mut FileLock, file_object: usize, key: u32) -> bool {
    lock.mutex.acquire();

    let mut removed = false;
    let mut i = 0;
    while i < lock.lock_count as usize {
        if lock.locks[i].file_object == file_object && lock.locks[i].key == key {
            // Remove this lock
            for j in i..(lock.lock_count as usize - 1) {
                lock.locks[j] = lock.locks[j + 1];
            }
            lock.lock_count -= 1;
            removed = true;
        } else {
            i += 1;
        }
    }

    update_fast_io_flag(lock);

    lock.mutex.release();

    removed
}

/// Get the next lock for enumeration
///
/// # Arguments
/// * `lock` - The file lock structure
/// * `restart` - Whether to restart enumeration from the beginning
///
/// # Returns
/// The next lock info, or None if no more locks
pub fn fsrtl_get_next_file_lock(lock: &mut FileLock, restart: bool) -> Option<FileLockInfo> {
    lock.mutex.acquire();

    let result = if restart {
        lock.last_returned_index = 0;
        if lock.lock_count > 0 {
            lock.last_returned_lock_info = lock.locks[0];
            lock.last_returned_index = 1;
            Some(lock.locks[0])
        } else {
            None
        }
    } else if lock.last_returned_index < lock.lock_count as usize {
        let info = lock.locks[lock.last_returned_index];
        lock.last_returned_lock_info = info;
        lock.last_returned_index += 1;
        Some(info)
    } else {
        None
    };

    lock.mutex.release();

    result
}

/// Update the fast I/O questionable flag based on current locks
fn update_fast_io_flag(lock: &mut FileLock) {
    lock.fast_io_is_questionable = false;
    for i in 0..lock.lock_count as usize {
        if lock.locks[i].exclusive_lock {
            lock.fast_io_is_questionable = true;
            break;
        }
    }
}
