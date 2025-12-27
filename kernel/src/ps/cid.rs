//! Client ID (CID) Table
//!
//! The CID table provides unique identifiers for processes and threads.
//! Each process has a unique Process ID (PID) and each thread has a
//! unique Thread ID (TID). Together they form a CLIENT_ID.
//!
//! # CID Table Structure
//! The table uses a simple array-based approach with:
//! - Entry 0 reserved for the System process
//! - Entries store pointers to EPROCESS or ETHREAD
//! - A bitmap tracks which entries are in use

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::ke::SpinLock;

/// Client ID - identifies a process/thread pair
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientId {
    /// Process ID
    pub unique_process: u32,
    /// Thread ID
    pub unique_thread: u32,
}

impl ClientId {
    /// Create a new client ID
    pub const fn new(process_id: u32, thread_id: u32) -> Self {
        Self {
            unique_process: process_id,
            unique_thread: thread_id,
        }
    }

    /// Create a null client ID
    pub const fn null() -> Self {
        Self {
            unique_process: 0,
            unique_thread: 0,
        }
    }
}

impl Default for ClientId {
    fn default() -> Self {
        Self::null()
    }
}

/// Maximum number of processes
pub const MAX_PROCESSES: usize = 64;

/// Maximum number of threads
pub const MAX_THREADS: usize = 256;

/// CID table entry type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CidEntryType {
    /// Entry is free
    Free = 0,
    /// Entry contains a process
    Process = 1,
    /// Entry contains a thread
    Thread = 2,
}

/// CID table entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CidTableEntry {
    /// Object pointer (EPROCESS or ETHREAD)
    pub object: *mut u8,
    /// Entry type
    pub entry_type: CidEntryType,
}

impl CidTableEntry {
    pub const fn new() -> Self {
        Self {
            object: ptr::null_mut(),
            entry_type: CidEntryType::Free,
        }
    }

    pub fn is_free(&self) -> bool {
        self.entry_type == CidEntryType::Free
    }
}

impl Default for CidTableEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Process ID table
static mut PROCESS_TABLE: [CidTableEntry; MAX_PROCESSES] = {
    const INIT: CidTableEntry = CidTableEntry::new();
    [INIT; MAX_PROCESSES]
};

/// Thread ID table
static mut THREAD_TABLE: [CidTableEntry; MAX_THREADS] = {
    const INIT: CidTableEntry = CidTableEntry::new();
    [INIT; MAX_THREADS]
};

/// Next process ID hint (for faster allocation)
static NEXT_PID: AtomicU32 = AtomicU32::new(1);

/// Next thread ID hint
static NEXT_TID: AtomicU32 = AtomicU32::new(1);

/// CID table lock
static CID_LOCK: SpinLock<()> = SpinLock::new(());

/// Allocate a process ID
///
/// # Returns
/// A new unique process ID, or 0 if table is full
pub unsafe fn ps_allocate_process_id(process: *mut u8) -> u32 {
    let _guard = CID_LOCK.lock();

    let start = NEXT_PID.load(Ordering::Relaxed) as usize;

    // Search from hint to end
    for i in start..MAX_PROCESSES {
        if PROCESS_TABLE[i].is_free() {
            PROCESS_TABLE[i].object = process;
            PROCESS_TABLE[i].entry_type = CidEntryType::Process;
            NEXT_PID.store((i + 1) as u32, Ordering::Relaxed);
            return i as u32;
        }
    }

    // Search from beginning to hint
    for i in 1..start {
        if PROCESS_TABLE[i].is_free() {
            PROCESS_TABLE[i].object = process;
            PROCESS_TABLE[i].entry_type = CidEntryType::Process;
            NEXT_PID.store((i + 1) as u32, Ordering::Relaxed);
            return i as u32;
        }
    }

    0 // Table full
}

/// Free a process ID
pub unsafe fn ps_free_process_id(pid: u32) {
    let _guard = CID_LOCK.lock();

    let index = pid as usize;
    if index > 0 && index < MAX_PROCESSES {
        PROCESS_TABLE[index] = CidTableEntry::new();
    }
}

/// Look up a process by ID
pub unsafe fn ps_lookup_process_by_id(pid: u32) -> *mut u8 {
    let _guard = CID_LOCK.lock();

    let index = pid as usize;
    if index < MAX_PROCESSES && PROCESS_TABLE[index].entry_type == CidEntryType::Process {
        PROCESS_TABLE[index].object
    } else {
        ptr::null_mut()
    }
}

/// Allocate a thread ID
///
/// # Returns
/// A new unique thread ID, or 0 if table is full
pub unsafe fn ps_allocate_thread_id(thread: *mut u8) -> u32 {
    let _guard = CID_LOCK.lock();

    let start = NEXT_TID.load(Ordering::Relaxed) as usize;

    // Search from hint to end
    for i in start..MAX_THREADS {
        if THREAD_TABLE[i].is_free() {
            THREAD_TABLE[i].object = thread;
            THREAD_TABLE[i].entry_type = CidEntryType::Thread;
            NEXT_TID.store((i + 1) as u32, Ordering::Relaxed);
            return i as u32;
        }
    }

    // Search from beginning to hint
    for i in 1..start {
        if THREAD_TABLE[i].is_free() {
            THREAD_TABLE[i].object = thread;
            THREAD_TABLE[i].entry_type = CidEntryType::Thread;
            NEXT_TID.store((i + 1) as u32, Ordering::Relaxed);
            return i as u32;
        }
    }

    0 // Table full
}

/// Free a thread ID
pub unsafe fn ps_free_thread_id(tid: u32) {
    let _guard = CID_LOCK.lock();

    let index = tid as usize;
    if index > 0 && index < MAX_THREADS {
        THREAD_TABLE[index] = CidTableEntry::new();
    }
}

/// Look up a thread by ID
pub unsafe fn ps_lookup_thread_by_id(tid: u32) -> *mut u8 {
    let _guard = CID_LOCK.lock();

    let index = tid as usize;
    if index < MAX_THREADS && THREAD_TABLE[index].entry_type == CidEntryType::Thread {
        THREAD_TABLE[index].object
    } else {
        ptr::null_mut()
    }
}

/// Initialize the CID table
///
/// # Safety
/// Must be called once during kernel initialization
pub unsafe fn init_cid_table() {
    // Entry 0 is reserved for the System process (PID 0)
    // It will be set up when the system process is created
    crate::serial_println!("[PS] CID table initialized");
}

/// Register the system process (PID 0)
pub unsafe fn ps_register_system_process(process: *mut u8) {
    let _guard = CID_LOCK.lock();
    PROCESS_TABLE[0].object = process;
    PROCESS_TABLE[0].entry_type = CidEntryType::Process;
}
