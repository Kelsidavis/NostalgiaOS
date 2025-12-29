//! I/O Completion Ports (IOCP)
//!
//! I/O Completion Ports provide a highly efficient mechanism for handling
//! asynchronous I/O completion in Windows NT. They allow multiple threads
//! to efficiently wait on and process completed I/O operations.
//!
//! # Key Features
//!
//! - **Thread Pool Integration**: Limits concurrent threads to avoid context switch overhead
//! - **LIFO Thread Wake**: Most recently blocked thread handles completion (cache efficiency)
//! - **Multiple File Association**: Single port can handle completions from many files
//! - **Arbitrary Completion Posting**: Applications can post custom completions
//!
//! # NT API
//!
//! - `NtCreateIoCompletion` - Create a completion port
//! - `NtSetIoCompletion` - Post a completion packet
//! - `NtRemoveIoCompletion` - Wait for and retrieve a completion
//! - `NtQueryIoCompletion` - Query port state

use core::ptr;
use crate::ke::list::ListEntry;
use crate::ke::dispatcher::{DispatcherHeader, DispatcherType};
use crate::ke::spinlock::SpinLock;
// KEvent reserved for future wait-on-completion-port implementation

/// Maximum number of completion ports in the system
pub const MAX_COMPLETION_PORTS: usize = 64;

/// Maximum queued completions per port
pub const MAX_QUEUED_COMPLETIONS: usize = 256;

/// Default concurrent thread count (0 = number of processors)
pub const DEFAULT_CONCURRENCY: u32 = 0;

/// I/O Completion Port object
#[repr(C)]
pub struct IoCompletionPort {
    /// Dispatcher header for wait support
    pub header: DispatcherHeader,

    /// Lock protecting the completion queue
    lock: SpinLock<()>,

    /// Queue of completed I/O packets
    completion_queue: CompletionQueue,

    /// Maximum concurrent threads allowed
    concurrency_limit: u32,

    /// Current count of active threads
    active_threads: u32,

    /// List of threads waiting to dequeue
    waiting_threads: ListEntry,

    /// Total completions processed
    completions_processed: u64,

    /// Port is active (not closed)
    active: bool,
}

/// A queued completion packet
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoCompletionPacket {
    /// Completion key (user-defined, associated with file handle)
    pub key: usize,

    /// Overlapped pointer (user-defined context)
    pub overlapped: usize,

    /// I/O status (NTSTATUS)
    pub status: i32,

    /// Bytes transferred
    pub information: usize,
}

impl IoCompletionPacket {
    /// Create a new completion packet
    pub const fn new(key: usize, overlapped: usize, status: i32, information: usize) -> Self {
        Self {
            key,
            overlapped,
            status,
            information,
        }
    }

    /// Create an empty packet
    pub const fn empty() -> Self {
        Self {
            key: 0,
            overlapped: 0,
            status: 0,
            information: 0,
        }
    }
}

/// Queue of completion packets
struct CompletionQueue {
    /// Ring buffer of packets
    packets: [IoCompletionPacket; MAX_QUEUED_COMPLETIONS],

    /// Head index (next to dequeue)
    head: usize,

    /// Tail index (next to enqueue)
    tail: usize,

    /// Current count
    count: usize,
}

impl CompletionQueue {
    /// Create a new empty queue
    const fn new() -> Self {
        Self {
            packets: [IoCompletionPacket::empty(); MAX_QUEUED_COMPLETIONS],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Check if queue is empty
    fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if queue is full
    fn is_full(&self) -> bool {
        self.count >= MAX_QUEUED_COMPLETIONS
    }

    /// Enqueue a packet
    fn enqueue(&mut self, packet: IoCompletionPacket) -> bool {
        if self.is_full() {
            return false;
        }

        self.packets[self.tail] = packet;
        self.tail = (self.tail + 1) % MAX_QUEUED_COMPLETIONS;
        self.count += 1;
        true
    }

    /// Dequeue a packet
    fn dequeue(&mut self) -> Option<IoCompletionPacket> {
        if self.is_empty() {
            return None;
        }

        let packet = self.packets[self.head];
        self.head = (self.head + 1) % MAX_QUEUED_COMPLETIONS;
        self.count -= 1;
        Some(packet)
    }

    /// Get current queue depth
    fn len(&self) -> usize {
        self.count
    }
}

impl IoCompletionPort {
    /// Create a new I/O completion port
    pub fn new(concurrency: u32) -> Self {
        let limit = if concurrency == 0 {
            // Default to number of processors (for now, assume 1)
            1
        } else {
            concurrency
        };

        Self {
            header: DispatcherHeader::new(DispatcherType::IoCompletion),
            lock: SpinLock::new(()),
            completion_queue: CompletionQueue::new(),
            concurrency_limit: limit,
            active_threads: 0,
            waiting_threads: ListEntry::new(),
            completions_processed: 0,
            active: true,
        }
    }

    /// Initialize the completion port
    pub fn init(&mut self, concurrency: u32) {
        let limit = if concurrency == 0 { 1 } else { concurrency };
        self.concurrency_limit = limit;
        self.active = true;
        self.waiting_threads.init_head();
    }

    /// Post a completion packet to the port
    ///
    /// # Arguments
    /// * `key` - Completion key (typically associated with file handle)
    /// * `overlapped` - Overlapped context pointer
    /// * `status` - I/O status code
    /// * `information` - Bytes transferred or other info
    ///
    /// # Returns
    /// `true` if packet was queued, `false` if queue is full
    pub unsafe fn post_completion(
        &mut self,
        key: usize,
        overlapped: usize,
        status: i32,
        information: usize,
    ) -> bool {
        if !self.active {
            return false;
        }

        let _guard = self.lock.lock();

        let packet = IoCompletionPacket::new(key, overlapped, status, information);

        if !self.completion_queue.enqueue(packet) {
            return false;
        }

        // Signal waiting threads
        self.header.set_signal_state(1);

        // Wake one waiting thread if any
        self.wake_one_waiter();

        true
    }

    /// Wait for and retrieve a completion packet
    ///
    /// # Arguments
    /// * `timeout_ms` - Timeout in milliseconds (None = infinite)
    ///
    /// # Returns
    /// `Some(packet)` if a completion was retrieved, `None` on timeout
    pub unsafe fn get_completion(&mut self, timeout_ms: Option<u64>) -> Option<IoCompletionPacket> {
        if !self.active {
            return None;
        }

        // Try to get a packet immediately
        {
            let _guard = self.lock.lock();

            if let Some(packet) = self.completion_queue.dequeue() {
                self.completions_processed += 1;

                // Update signal state
                if self.completion_queue.is_empty() {
                    self.header.set_signal_state(0);
                }

                return Some(packet);
            }
        }

        // No packet available - need to wait
        if let Some(0) = timeout_ms {
            // Zero timeout means don't wait
            return None;
        }

        // Block waiting for completion
        self.wait_for_completion(timeout_ms)
    }

    /// Internal: wait for a completion to be posted
    unsafe fn wait_for_completion(&mut self, timeout_ms: Option<u64>) -> Option<IoCompletionPacket> {
        let prcb = crate::ke::prcb::get_current_prcb_mut();
        let thread = prcb.current_thread;

        if thread.is_null() {
            return None;
        }

        // Increment active thread count
        {
            let _guard = self.lock.lock();
            self.active_threads += 1;
        }

        // Wait loop
        let start_tick = crate::hal::apic::get_tick_count();
        let timeout_ticks = timeout_ms.unwrap_or(u64::MAX);

        loop {
            // Check for completion
            {
                let _guard = self.lock.lock();

                if let Some(packet) = self.completion_queue.dequeue() {
                    self.active_threads -= 1;
                    self.completions_processed += 1;

                    if self.completion_queue.is_empty() {
                        self.header.set_signal_state(0);
                    }

                    return Some(packet);
                }
            }

            // Check timeout
            let elapsed = crate::hal::apic::get_tick_count().saturating_sub(start_tick);
            if elapsed >= timeout_ticks {
                // Decrement active count and return
                let _guard = self.lock.lock();
                self.active_threads -= 1;
                return None;
            }

            // Yield and try again
            crate::ke::scheduler::ki_yield();
        }
    }

    /// Wake one waiting thread
    unsafe fn wake_one_waiter(&self) {
        // In a full implementation, this would wake the most recently
        // blocked thread (LIFO order for cache efficiency)
        // For now, signaling the dispatcher header handles this
    }

    /// Get the current queue depth
    pub fn queue_depth(&self) -> usize {
        self.completion_queue.len()
    }

    /// Get the number of active threads
    pub fn active_thread_count(&self) -> u32 {
        self.active_threads
    }

    /// Get the concurrency limit
    pub fn concurrency_limit(&self) -> u32 {
        self.concurrency_limit
    }

    /// Get total completions processed
    pub fn completions_processed(&self) -> u64 {
        self.completions_processed
    }

    /// Check if the port is active
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Close the completion port
    pub fn close(&mut self) {
        self.active = false;

        // Signal to wake any waiting threads
        unsafe {
            self.header.set_signal_state(1);
        }
    }
}

// ============================================================================
// Global Completion Port Pool
// ============================================================================

/// Pool of completion ports
static mut COMPLETION_PORT_POOL: [IoCompletionPort; MAX_COMPLETION_PORTS] = {
    const INIT: IoCompletionPort = IoCompletionPort {
        header: DispatcherHeader::new(DispatcherType::IoCompletion),
        lock: SpinLock::new(()),
        completion_queue: CompletionQueue::new(),
        concurrency_limit: 1,
        active_threads: 0,
        waiting_threads: ListEntry::new(),
        completions_processed: 0,
        active: false,
    };
    [INIT; MAX_COMPLETION_PORTS]
};

/// Bitmap tracking allocated ports
static mut COMPLETION_PORT_BITMAP: u64 = 0;

/// Lock for port allocation
static COMPLETION_PORT_LOCK: SpinLock<()> = SpinLock::new(());

/// Allocate a new completion port
///
/// # Arguments
/// * `concurrency` - Maximum concurrent threads (0 = number of processors)
///
/// # Returns
/// Pointer to the allocated port, or null if none available
pub unsafe fn io_create_completion_port(concurrency: u32) -> *mut IoCompletionPort {
    let _guard = COMPLETION_PORT_LOCK.lock();

    // Find a free slot
    for i in 0..MAX_COMPLETION_PORTS {
        if COMPLETION_PORT_BITMAP & (1 << i) == 0 {
            // Allocate this slot
            COMPLETION_PORT_BITMAP |= 1 << i;

            let port = &mut COMPLETION_PORT_POOL[i];
            port.init(concurrency);
            port.waiting_threads.init_head();

            return port as *mut IoCompletionPort;
        }
    }

    ptr::null_mut()
}

/// Free a completion port
pub unsafe fn io_close_completion_port(port: *mut IoCompletionPort) {
    if port.is_null() {
        return;
    }

    let _guard = COMPLETION_PORT_LOCK.lock();

    // Find which slot this is
    let base = COMPLETION_PORT_POOL.as_ptr() as usize;
    let port_addr = port as usize;
    let port_size = core::mem::size_of::<IoCompletionPort>();

    if port_addr >= base && port_addr < base + MAX_COMPLETION_PORTS * port_size {
        let index = (port_addr - base) / port_size;

        // Close the port
        (*port).close();

        // Free the slot
        COMPLETION_PORT_BITMAP &= !(1 << index);
    }
}

/// Post a completion to a port
pub unsafe fn io_set_completion(
    port: *mut IoCompletionPort,
    key: usize,
    overlapped: usize,
    status: i32,
    information: usize,
) -> bool {
    if port.is_null() {
        return false;
    }

    (*port).post_completion(key, overlapped, status, information)
}

/// Remove a completion from a port (wait for completion)
pub unsafe fn io_remove_completion(
    port: *mut IoCompletionPort,
    timeout_ms: Option<u64>,
) -> Option<IoCompletionPacket> {
    if port.is_null() {
        return None;
    }

    (*port).get_completion(timeout_ms)
}

/// Query completion port information
#[repr(C)]
pub struct IoCompletionInfo {
    pub queue_depth: u32,
    pub active_threads: u32,
    pub concurrency_limit: u32,
    pub completions_processed: u64,
}

pub unsafe fn io_query_completion(port: *mut IoCompletionPort) -> Option<IoCompletionInfo> {
    if port.is_null() {
        return None;
    }

    let p = &*port;
    Some(IoCompletionInfo {
        queue_depth: p.queue_depth() as u32,
        active_threads: p.active_thread_count(),
        concurrency_limit: p.concurrency_limit(),
        completions_processed: p.completions_processed(),
    })
}

// ============================================================================
// File Object Association
// ============================================================================

/// Associate a file object with a completion port
///
/// After association, completed I/O on the file will post to the port.
pub unsafe fn io_associate_file_completion_port(
    file: *mut super::file::FileObject,
    port: *mut IoCompletionPort,
    key: usize,
) -> bool {
    if file.is_null() || port.is_null() {
        return false;
    }

    let ctx = (*file).completion_context;
    if ctx.is_null() {
        return false;
    }

    // Store the completion context in the file object
    (*ctx).port = port as *mut u8;
    (*ctx).key = key as *mut u8;

    true
}

/// Post completion for a completed IRP
///
/// Called by the I/O completion path when an async IRP completes
/// on a file associated with a completion port.
pub unsafe fn io_post_irp_completion(
    file: *mut super::file::FileObject,
    status: i32,
    information: usize,
    overlapped: usize,
) {
    if file.is_null() {
        return;
    }

    let ctx = (*file).completion_context;
    if ctx.is_null() {
        return;
    }

    if (*ctx).port.is_null() {
        return;
    }

    let port = (*ctx).port as *mut IoCompletionPort;
    (*port).post_completion((*ctx).key as usize, overlapped, status, information);
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the I/O completion port subsystem
pub fn init() {
    unsafe {
        COMPLETION_PORT_BITMAP = 0;

        // Initialize all ports as inactive
        for port in COMPLETION_PORT_POOL.iter_mut() {
            port.active = false;
            port.waiting_threads.init_head();
        }
    }

    crate::serial_println!("[IO] Completion port subsystem initialized");
}

// ============================================================================
// Completion Port Inspection (for debugging)
// ============================================================================

/// Completion port pool statistics
#[derive(Debug, Clone, Copy)]
pub struct CompletionPortStats {
    /// Total number of ports in pool
    pub total_ports: usize,
    /// Number of allocated ports
    pub allocated_ports: usize,
    /// Number of free ports
    pub free_ports: usize,
    /// Total completions processed across all ports
    pub total_completions: u64,
}

/// Snapshot of an allocated completion port
#[derive(Debug, Clone, Copy)]
pub struct CompletionPortSnapshot {
    /// Port address
    pub address: u64,
    /// Is active
    pub active: bool,
    /// Concurrency limit
    pub concurrency_limit: u32,
    /// Active threads
    pub active_threads: u32,
    /// Queued completions
    pub queued_count: usize,
    /// Total completions processed
    pub completions_processed: u64,
}

/// Get completion port pool statistics
pub fn io_get_iocp_stats() -> CompletionPortStats {
    unsafe {
        let allocated = COMPLETION_PORT_BITMAP.count_ones() as usize;
        let mut total_completions = 0u64;

        for i in 0..MAX_COMPLETION_PORTS {
            if COMPLETION_PORT_BITMAP & (1 << i) != 0 {
                total_completions += COMPLETION_PORT_POOL[i].completions_processed;
            }
        }

        CompletionPortStats {
            total_ports: MAX_COMPLETION_PORTS,
            allocated_ports: allocated,
            free_ports: MAX_COMPLETION_PORTS - allocated,
            total_completions,
        }
    }
}

/// Get snapshots of allocated completion ports
pub fn io_get_iocp_snapshots(max_count: usize) -> ([CompletionPortSnapshot; 16], usize) {
    let mut snapshots = [CompletionPortSnapshot {
        address: 0,
        active: false,
        concurrency_limit: 0,
        active_threads: 0,
        queued_count: 0,
        completions_processed: 0,
    }; 16];

    let max_count = max_count.min(16);
    let mut count = 0;

    unsafe {
        for i in 0..MAX_COMPLETION_PORTS {
            if count >= max_count {
                break;
            }
            if COMPLETION_PORT_BITMAP & (1 << i) != 0 {
                let port = &COMPLETION_PORT_POOL[i];

                snapshots[count] = CompletionPortSnapshot {
                    address: &COMPLETION_PORT_POOL[i] as *const _ as u64,
                    active: port.active,
                    concurrency_limit: port.concurrency_limit,
                    active_threads: port.active_threads,
                    queued_count: port.completion_queue.count,
                    completions_processed: port.completions_processed,
                };
                count += 1;
            }
        }
    }

    (snapshots, count)
}
