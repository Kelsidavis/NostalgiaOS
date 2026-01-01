//! Executive Event Pair Object
//!
//! Event pairs provide efficient synchronization between two threads,
//! typically a client and server. They are optimized for fast context
//! switching in LPC (Local Procedure Call) scenarios.
//!
//! # Design
//!
//! An event pair contains two events:
//! - **High Event**: Typically signaled by the server
//! - **Low Event**: Typically signaled by the client
//!
//! The SetHighWaitLow and SetLowWaitHigh operations atomically signal
//! one event and wait on the other, enabling efficient ping-pong
//! communication without race conditions.
//!
//! # Usage Pattern
//!
//! ```text
//! Client                     Server
//! ------                     ------
//! SetLowWaitHigh() ------>   (wakes up)
//!   (waits)                  Process request
//!   (wakes up)    <------    SetHighWaitLow()
//! Process reply                (waits)
//! SetLowWaitHigh() ------>   (wakes up)
//! ...                        ...
//! ```
//!
//! # NT Functions
//!
//! - `NtCreateEventPair` - Create a new event pair
//! - `NtOpenEventPair` - Open an existing event pair
//! - `NtSetHighEventPair` - Signal the high event
//! - `NtSetLowEventPair` - Signal the low event
//! - `NtWaitHighEventPair` - Wait for high event
//! - `NtWaitLowEventPair` - Wait for low event
//! - `NtSetHighWaitLowEventPair` - Signal high, wait low (atomic)
//! - `NtSetLowWaitHighEventPair` - Signal low, wait high (atomic)

use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use crate::ke::event::{KEvent, EventType};
use crate::ke::spinlock::SpinLock;

/// Maximum number of event pairs
pub const MAX_EVENT_PAIRS: usize = 256;

/// Event pair access rights
pub mod access_rights {
    pub const SYNCHRONIZE: u32 = 0x00100000;
    pub const EVENT_PAIR_ALL_ACCESS: u32 = 0x001F0000;
}

/// Kernel Event Pair structure (KEVENT_PAIR)
#[repr(C)]
pub struct KEventPair {
    /// Low event (client side)
    pub event_low: KEvent,
    /// High event (server side)
    pub event_high: KEvent,
}

impl Default for KEventPair {
    fn default() -> Self {
        Self::new()
    }
}

impl KEventPair {
    /// Create a new kernel event pair
    pub const fn new() -> Self {
        Self {
            event_low: KEvent::new(),
            event_high: KEvent::new(),
        }
    }

    /// Initialize the event pair (KeInitializeEventPair)
    pub fn init(&mut self) {
        self.event_low.init(EventType::Synchronization, false);
        self.event_high.init(EventType::Synchronization, false);
    }
}

/// Executive Event Pair structure (EEVENT_PAIR)
#[repr(C)]
pub struct EEventPair {
    /// Kernel event pair
    pub kernel_event_pair: KEventPair,
}

impl Default for EEventPair {
    fn default() -> Self {
        Self::new()
    }
}

impl EEventPair {
    pub const fn new() -> Self {
        Self {
            kernel_event_pair: KEventPair::new(),
        }
    }
}

/// Event pair handle entry
#[repr(C)]
pub struct EventPairEntry {
    /// Entry is in use
    pub in_use: bool,
    /// Handle value
    pub handle: u32,
    /// The event pair
    pub event_pair: EEventPair,
    /// Reference count
    pub ref_count: u32,
    /// Name (optional, for named event pairs)
    pub name: [u8; 64],
    /// Name length
    pub name_len: u32,
}

impl Default for EventPairEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl EventPairEntry {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            handle: 0,
            event_pair: EEventPair::new(),
            ref_count: 0,
            name: [0; 64],
            name_len: 0,
        }
    }
}

/// Global event pair table
static mut EVENT_PAIR_TABLE: [EventPairEntry; MAX_EVENT_PAIRS] = {
    const INIT: EventPairEntry = EventPairEntry::new();
    [INIT; MAX_EVENT_PAIRS]
};

/// Lock for event pair operations
static EVENT_PAIR_LOCK: SpinLock<()> = SpinLock::new(());

/// Next handle value
static NEXT_HANDLE: AtomicU32 = AtomicU32::new(1);

/// Performance counters
static SET_HIGH_COUNT: AtomicU32 = AtomicU32::new(0);
static SET_LOW_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// NT System Call Implementations
// ============================================================================

/// Create an event pair object (NtCreateEventPair)
///
/// Creates a new event pair and returns a handle to it.
///
/// # Arguments
/// * `event_pair_handle` - Receives the handle
/// * `desired_access` - Access rights requested
/// * `name` - Optional name for the event pair
///
/// # Returns
/// STATUS_SUCCESS or error code
pub unsafe fn nt_create_event_pair(
    event_pair_handle: *mut u32,
    _desired_access: u32,
    name: Option<&str>,
) -> i32 {
    if event_pair_handle.is_null() {
        return -1073741811; // STATUS_INVALID_PARAMETER
    }

    let _guard = EVENT_PAIR_LOCK.lock();

    // Find free slot
    let slot = {
        let mut found = None;
        for i in 0..MAX_EVENT_PAIRS {
            if !EVENT_PAIR_TABLE[i].in_use {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => i,
            None => return -1073741670, // STATUS_INSUFFICIENT_RESOURCES
        }
    };

    // Initialize the entry
    let entry = &mut EVENT_PAIR_TABLE[slot];
    entry.in_use = true;
    entry.handle = NEXT_HANDLE.fetch_add(1, Ordering::AcqRel);
    entry.event_pair.kernel_event_pair.init();
    entry.ref_count = 1;

    // Store name if provided
    if let Some(n) = name {
        let name_bytes = n.as_bytes();
        let copy_len = name_bytes.len().min(63);
        entry.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        entry.name_len = copy_len as u32;
    } else {
        entry.name_len = 0;
    }

    *event_pair_handle = entry.handle;

    0 // STATUS_SUCCESS
}

/// Open an existing event pair (NtOpenEventPair)
///
/// Opens an existing named event pair.
///
/// # Arguments
/// * `event_pair_handle` - Receives the handle
/// * `desired_access` - Access rights requested
/// * `name` - Name of the event pair to open
///
/// # Returns
/// STATUS_SUCCESS or error code
pub unsafe fn nt_open_event_pair(
    event_pair_handle: *mut u32,
    _desired_access: u32,
    name: &str,
) -> i32 {
    if event_pair_handle.is_null() || name.is_empty() {
        return -1073741811; // STATUS_INVALID_PARAMETER
    }

    let _guard = EVENT_PAIR_LOCK.lock();
    let name_bytes = name.as_bytes();

    for i in 0..MAX_EVENT_PAIRS {
        if EVENT_PAIR_TABLE[i].in_use {
            let len = EVENT_PAIR_TABLE[i].name_len as usize;
            if len == name_bytes.len() {
                let stored_name = &EVENT_PAIR_TABLE[i].name[..len];
                if stored_name == name_bytes {
                    EVENT_PAIR_TABLE[i].ref_count += 1;
                    *event_pair_handle = EVENT_PAIR_TABLE[i].handle;
                    return 0; // STATUS_SUCCESS
                }
            }
        }
    }

    -1073741772 // STATUS_OBJECT_NAME_NOT_FOUND
}

/// Close an event pair handle (NtClose equivalent)
pub unsafe fn nt_close_event_pair(event_pair_handle: u32) -> i32 {
    let _guard = EVENT_PAIR_LOCK.lock();

    for i in 0..MAX_EVENT_PAIRS {
        if EVENT_PAIR_TABLE[i].in_use && EVENT_PAIR_TABLE[i].handle == event_pair_handle {
            EVENT_PAIR_TABLE[i].ref_count = EVENT_PAIR_TABLE[i].ref_count.saturating_sub(1);
            if EVENT_PAIR_TABLE[i].ref_count == 0 {
                EVENT_PAIR_TABLE[i].in_use = false;
            }
            return 0; // STATUS_SUCCESS
        }
    }

    -1073741816 // STATUS_INVALID_HANDLE
}

/// Get event pair by handle
unsafe fn get_event_pair(handle: u32) -> Option<&'static mut EEventPair> {
    for i in 0..MAX_EVENT_PAIRS {
        if EVENT_PAIR_TABLE[i].in_use && EVENT_PAIR_TABLE[i].handle == handle {
            return Some(&mut EVENT_PAIR_TABLE[i].event_pair);
        }
    }
    None
}

/// Set the high event (NtSetHighEventPair)
///
/// Signals the high event, releasing any waiting threads.
pub unsafe fn nt_set_high_event_pair(event_pair_handle: u32) -> i32 {
    let _guard = EVENT_PAIR_LOCK.lock();

    if let Some(pair) = get_event_pair(event_pair_handle) {
        pair.kernel_event_pair.event_high.set();
        SET_HIGH_COUNT.fetch_add(1, Ordering::Relaxed);
        0 // STATUS_SUCCESS
    } else {
        -1073741816 // STATUS_INVALID_HANDLE
    }
}

/// Set the low event (NtSetLowEventPair)
///
/// Signals the low event, releasing any waiting threads.
pub unsafe fn nt_set_low_event_pair(event_pair_handle: u32) -> i32 {
    let _guard = EVENT_PAIR_LOCK.lock();

    if let Some(pair) = get_event_pair(event_pair_handle) {
        pair.kernel_event_pair.event_low.set();
        SET_LOW_COUNT.fetch_add(1, Ordering::Relaxed);
        0 // STATUS_SUCCESS
    } else {
        -1073741816 // STATUS_INVALID_HANDLE
    }
}

/// Wait for the high event (NtWaitHighEventPair)
///
/// Waits until the high event is signaled.
pub unsafe fn nt_wait_high_event_pair(event_pair_handle: u32) -> i32 {
    // Get the event pair (with lock)
    let event_ptr = {
        let _guard = EVENT_PAIR_LOCK.lock();

        match get_event_pair(event_pair_handle) {
            Some(pair) => &pair.kernel_event_pair.event_high as *const KEvent,
            None => return -1073741816, // STATUS_INVALID_HANDLE
        }
    };

    // Wait outside lock
    (*event_ptr).wait();
    0 // STATUS_SUCCESS
}

/// Wait for the low event (NtWaitLowEventPair)
///
/// Waits until the low event is signaled.
pub unsafe fn nt_wait_low_event_pair(event_pair_handle: u32) -> i32 {
    let event_ptr = {
        let _guard = EVENT_PAIR_LOCK.lock();

        match get_event_pair(event_pair_handle) {
            Some(pair) => &pair.kernel_event_pair.event_low as *const KEvent,
            None => return -1073741816,
        }
    };

    (*event_ptr).wait();
    0 // STATUS_SUCCESS
}

/// Set high event and wait for low event (NtSetHighWaitLowEventPair)
///
/// Atomically signals the high event and waits for the low event.
/// This is the typical server-side operation.
pub unsafe fn nt_set_high_wait_low_event_pair(event_pair_handle: u32) -> i32 {
    let (high_ptr, low_ptr) = {
        let _guard = EVENT_PAIR_LOCK.lock();

        match get_event_pair(event_pair_handle) {
            Some(pair) => (
                &pair.kernel_event_pair.event_high as *const KEvent,
                &pair.kernel_event_pair.event_low as *const KEvent,
            ),
            None => return -1073741816,
        }
    };

    // Set high event (signal server complete)
    (*(high_ptr as *mut KEvent)).set();
    SET_HIGH_COUNT.fetch_add(1, Ordering::Relaxed);

    // Wait for low event (wait for client)
    (*low_ptr).wait();

    0 // STATUS_SUCCESS
}

/// Set low event and wait for high event (NtSetLowWaitHighEventPair)
///
/// Atomically signals the low event and waits for the high event.
/// This is the typical client-side operation.
pub unsafe fn nt_set_low_wait_high_event_pair(event_pair_handle: u32) -> i32 {
    let (high_ptr, low_ptr) = {
        let _guard = EVENT_PAIR_LOCK.lock();

        match get_event_pair(event_pair_handle) {
            Some(pair) => (
                &pair.kernel_event_pair.event_high as *const KEvent,
                &pair.kernel_event_pair.event_low as *const KEvent,
            ),
            None => return -1073741816,
        }
    };

    // Set low event (signal client request)
    (*(low_ptr as *mut KEvent)).set();
    SET_LOW_COUNT.fetch_add(1, Ordering::Relaxed);

    // Wait for high event (wait for server)
    (*high_ptr).wait();

    0 // STATUS_SUCCESS
}

// ============================================================================
// Kernel Mode Functions
// ============================================================================

/// Initialize a kernel event pair (KeInitializeEventPair)
pub fn ke_initialize_event_pair(event_pair: &mut KEventPair) {
    event_pair.init();
}

/// Set the low event of an event pair (KeSetLowEventPair)
pub fn ke_set_low_event_pair(event_pair: &mut KEventPair) {
    unsafe { event_pair.event_low.set(); }
    SET_LOW_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Set the high event of an event pair (KeSetHighEventPair)
pub fn ke_set_high_event_pair(event_pair: &mut KEventPair) {
    unsafe { event_pair.event_high.set(); }
    SET_HIGH_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Wait for the low event (KeWaitForLowEventPair)
pub fn ke_wait_for_low_event_pair(event_pair: &KEventPair) {
    unsafe { event_pair.event_low.wait(); }
}

/// Wait for the high event (KeWaitForHighEventPair)
pub fn ke_wait_for_high_event_pair(event_pair: &KEventPair) {
    unsafe { event_pair.event_high.wait(); }
}

// ============================================================================
// Statistics and Diagnostics
// ============================================================================

/// Event pair statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct EventPairStats {
    /// Number of active event pairs
    pub active_pairs: u32,
    /// Total set high operations
    pub set_high_count: u32,
    /// Total set low operations
    pub set_low_count: u32,
    /// Total creates
    pub creates: u32,
}

/// Get event pair statistics
pub fn get_event_pair_stats() -> EventPairStats {
    let mut active = 0u32;

    unsafe {
        let _guard = EVENT_PAIR_LOCK.lock();
        for i in 0..MAX_EVENT_PAIRS {
            if EVENT_PAIR_TABLE[i].in_use {
                active += 1;
            }
        }
    }

    EventPairStats {
        active_pairs: active,
        set_high_count: SET_HIGH_COUNT.load(Ordering::Relaxed),
        set_low_count: SET_LOW_COUNT.load(Ordering::Relaxed),
        creates: NEXT_HANDLE.load(Ordering::Relaxed) - 1,
    }
}

/// Get active event pair count
pub fn get_active_event_pair_count() -> u32 {
    let mut count = 0u32;

    unsafe {
        let _guard = EVENT_PAIR_LOCK.lock();
        for i in 0..MAX_EVENT_PAIRS {
            if EVENT_PAIR_TABLE[i].in_use {
                count += 1;
            }
        }
    }

    count
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize event pair support
pub fn init() {
    unsafe {
        for i in 0..MAX_EVENT_PAIRS {
            EVENT_PAIR_TABLE[i] = EventPairEntry::new();
        }
    }

    NEXT_HANDLE.store(1, Ordering::Release);
    SET_HIGH_COUNT.store(0, Ordering::Release);
    SET_LOW_COUNT.store(0, Ordering::Release);

    crate::serial_println!("[EX] Event pair support initialized");
}
