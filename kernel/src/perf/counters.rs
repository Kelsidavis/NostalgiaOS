//! Performance Counters
//!
//! Implements Windows-compatible performance counters for system monitoring.
//! These counters are exposed through the performance monitoring API.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use crate::ke::SpinLock;

/// Maximum number of performance counter objects
pub const MAX_PERF_OBJECTS: usize = 64;

/// Maximum counters per object
pub const MAX_COUNTERS_PER_OBJECT: usize = 32;

/// Performance counter type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CounterType {
    /// 32-bit counter
    Counter32 = 0x00000000,
    /// 64-bit counter
    Counter64 = 0x00000100,
    /// 32-bit counter displaying as rate
    RateCounter32 = 0x00010000,
    /// 64-bit counter displaying as rate
    RateCounter64 = 0x00010100,
    /// Raw fraction (current/base)
    RawFraction = 0x00020000,
    /// Large raw fraction
    LargeRawFraction = 0x00020100,
    /// Elapsed time counter
    ElapsedTime = 0x00030000,
    /// Sample counter
    SampleCounter = 0x00040000,
    /// Precision counter (100ns units)
    PrecisionCounter = 0x00050000,
    /// Text counter (for display)
    Text = 0x00060000,
}

/// Performance counter definition
#[derive(Clone)]
pub struct PerfCounterDef {
    /// Counter ID
    pub id: u32,
    /// Counter type
    pub counter_type: CounterType,
    /// Counter name
    pub name: [u8; 64],
    pub name_len: usize,
    /// Counter help text
    pub help: [u8; 128],
    pub help_len: usize,
    /// Default scale
    pub default_scale: i32,
    /// Detail level (novice, advanced, expert, wizard)
    pub detail_level: u32,
}

impl PerfCounterDef {
    pub const fn new() -> Self {
        Self {
            id: 0,
            counter_type: CounterType::Counter64,
            name: [0; 64],
            name_len: 0,
            help: [0; 128],
            help_len: 0,
            default_scale: 0,
            detail_level: 100, // Novice
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }
}

/// Performance object (collection of counters)
pub struct PerfObject {
    /// Object ID
    pub id: u32,
    /// Object name
    pub name: [u8; 64],
    pub name_len: usize,
    /// Object help text
    pub help: [u8; 128],
    pub help_len: usize,
    /// Counter definitions
    pub counters: [PerfCounterDef; MAX_COUNTERS_PER_OBJECT],
    /// Number of active counters
    pub counter_count: usize,
    /// Instance support
    pub supports_instances: bool,
    /// Active
    pub active: bool,
}

impl PerfObject {
    pub const fn new() -> Self {
        const COUNTER_DEF: PerfCounterDef = PerfCounterDef::new();
        Self {
            id: 0,
            name: [0; 64],
            name_len: 0,
            help: [0; 128],
            help_len: 0,
            counters: [COUNTER_DEF; MAX_COUNTERS_PER_OBJECT],
            counter_count: 0,
            supports_instances: false,
            active: false,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }
}

/// Well-known performance object IDs (matching Windows)
pub mod object_ids {
    pub const SYSTEM: u32 = 2;
    pub const MEMORY: u32 = 4;
    pub const CACHE: u32 = 86;
    pub const PROCESSOR: u32 = 238;
    pub const PROCESS: u32 = 230;
    pub const THREAD: u32 = 232;
    pub const PHYSICAL_DISK: u32 = 234;
    pub const LOGICAL_DISK: u32 = 236;
    pub const NETWORK_INTERFACE: u32 = 510;
    pub const TCP: u32 = 638;
    pub const UDP: u32 = 658;
    pub const IP: u32 = 546;
    pub const ICMP: u32 = 582;
    pub const OBJECTS: u32 = 260;
    pub const PAGING_FILE: u32 = 700;
    pub const REDIRECTOR: u32 = 262;
    pub const SERVER: u32 = 330;
}

/// Performance object table
static mut PERF_OBJECTS: [PerfObject; MAX_PERF_OBJECTS] = {
    const PERF_OBJ: PerfObject = PerfObject::new();
    [PERF_OBJ; MAX_PERF_OBJECTS]
};
static PERF_LOCK: SpinLock<()> = SpinLock::new(());
static OBJECT_COUNT: AtomicU32 = AtomicU32::new(0);
static QUERIES_PERFORMED: AtomicU64 = AtomicU64::new(0);

/// Initialize performance counters
pub fn init() {
    crate::serial_println!("[PERF] Initializing performance counters");

    // Register built-in performance objects
    register_system_object();
    register_memory_object();
    register_processor_object();
    register_process_object();
    register_network_object();

    crate::serial_println!("[PERF] Registered {} performance objects",
        OBJECT_COUNT.load(Ordering::Relaxed));
}

/// Register System performance object
fn register_system_object() {
    let _guard = PERF_LOCK.lock();

    unsafe {
        let idx = OBJECT_COUNT.load(Ordering::Relaxed) as usize;
        if idx >= MAX_PERF_OBJECTS {
            return;
        }

        let obj = &mut PERF_OBJECTS[idx];
        obj.id = object_ids::SYSTEM;
        let name = b"System";
        obj.name[..name.len()].copy_from_slice(name);
        obj.name_len = name.len();
        let help = b"System performance object";
        obj.help[..help.len()].copy_from_slice(help);
        obj.help_len = help.len();
        obj.supports_instances = false;
        obj.active = true;

        // Add counters
        add_counter(obj, 1, "Processor Queue Length", CounterType::Counter32);
        add_counter(obj, 2, "Context Switches/sec", CounterType::RateCounter64);
        add_counter(obj, 3, "System Calls/sec", CounterType::RateCounter64);
        add_counter(obj, 4, "Processes", CounterType::Counter32);
        add_counter(obj, 5, "Threads", CounterType::Counter32);
        add_counter(obj, 6, "System Up Time", CounterType::ElapsedTime);
        add_counter(obj, 7, "Exception Dispatches/sec", CounterType::RateCounter64);
        add_counter(obj, 8, "File Read Operations/sec", CounterType::RateCounter64);
        add_counter(obj, 9, "File Write Operations/sec", CounterType::RateCounter64);

        OBJECT_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Register Memory performance object
fn register_memory_object() {
    let _guard = PERF_LOCK.lock();

    unsafe {
        let idx = OBJECT_COUNT.load(Ordering::Relaxed) as usize;
        if idx >= MAX_PERF_OBJECTS {
            return;
        }

        let obj = &mut PERF_OBJECTS[idx];
        obj.id = object_ids::MEMORY;
        let name = b"Memory";
        obj.name[..name.len()].copy_from_slice(name);
        obj.name_len = name.len();
        let help = b"Memory performance object";
        obj.help[..help.len()].copy_from_slice(help);
        obj.help_len = help.len();
        obj.supports_instances = false;
        obj.active = true;

        // Add counters
        add_counter(obj, 1, "Available Bytes", CounterType::Counter64);
        add_counter(obj, 2, "Committed Bytes", CounterType::Counter64);
        add_counter(obj, 3, "Commit Limit", CounterType::Counter64);
        add_counter(obj, 4, "Page Faults/sec", CounterType::RateCounter64);
        add_counter(obj, 5, "Pages/sec", CounterType::RateCounter64);
        add_counter(obj, 6, "Pool Nonpaged Bytes", CounterType::Counter64);
        add_counter(obj, 7, "Pool Paged Bytes", CounterType::Counter64);
        add_counter(obj, 8, "Cache Bytes", CounterType::Counter64);
        add_counter(obj, 9, "Free System Page Table Entries", CounterType::Counter32);

        OBJECT_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Register Processor performance object
fn register_processor_object() {
    let _guard = PERF_LOCK.lock();

    unsafe {
        let idx = OBJECT_COUNT.load(Ordering::Relaxed) as usize;
        if idx >= MAX_PERF_OBJECTS {
            return;
        }

        let obj = &mut PERF_OBJECTS[idx];
        obj.id = object_ids::PROCESSOR;
        let name = b"Processor";
        obj.name[..name.len()].copy_from_slice(name);
        obj.name_len = name.len();
        let help = b"Processor performance object";
        obj.help[..help.len()].copy_from_slice(help);
        obj.help_len = help.len();
        obj.supports_instances = true;
        obj.active = true;

        // Add counters
        add_counter(obj, 1, "% Processor Time", CounterType::PrecisionCounter);
        add_counter(obj, 2, "% User Time", CounterType::PrecisionCounter);
        add_counter(obj, 3, "% Privileged Time", CounterType::PrecisionCounter);
        add_counter(obj, 4, "% Idle Time", CounterType::PrecisionCounter);
        add_counter(obj, 5, "% Interrupt Time", CounterType::PrecisionCounter);
        add_counter(obj, 6, "% DPC Time", CounterType::PrecisionCounter);
        add_counter(obj, 7, "Interrupts/sec", CounterType::RateCounter64);
        add_counter(obj, 8, "DPCs Queued/sec", CounterType::RateCounter64);

        OBJECT_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Register Process performance object
fn register_process_object() {
    let _guard = PERF_LOCK.lock();

    unsafe {
        let idx = OBJECT_COUNT.load(Ordering::Relaxed) as usize;
        if idx >= MAX_PERF_OBJECTS {
            return;
        }

        let obj = &mut PERF_OBJECTS[idx];
        obj.id = object_ids::PROCESS;
        let name = b"Process";
        obj.name[..name.len()].copy_from_slice(name);
        obj.name_len = name.len();
        let help = b"Process performance object";
        obj.help[..help.len()].copy_from_slice(help);
        obj.help_len = help.len();
        obj.supports_instances = true;
        obj.active = true;

        // Add counters
        add_counter(obj, 1, "% Processor Time", CounterType::PrecisionCounter);
        add_counter(obj, 2, "Working Set", CounterType::Counter64);
        add_counter(obj, 3, "Virtual Bytes", CounterType::Counter64);
        add_counter(obj, 4, "Private Bytes", CounterType::Counter64);
        add_counter(obj, 5, "Thread Count", CounterType::Counter32);
        add_counter(obj, 6, "Handle Count", CounterType::Counter32);
        add_counter(obj, 7, "Page Faults/sec", CounterType::RateCounter64);
        add_counter(obj, 8, "Pool Nonpaged Bytes", CounterType::Counter64);
        add_counter(obj, 9, "Pool Paged Bytes", CounterType::Counter64);
        add_counter(obj, 10, "Elapsed Time", CounterType::ElapsedTime);
        add_counter(obj, 11, "ID Process", CounterType::Counter32);

        OBJECT_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Register Network Interface performance object
fn register_network_object() {
    let _guard = PERF_LOCK.lock();

    unsafe {
        let idx = OBJECT_COUNT.load(Ordering::Relaxed) as usize;
        if idx >= MAX_PERF_OBJECTS {
            return;
        }

        let obj = &mut PERF_OBJECTS[idx];
        obj.id = object_ids::NETWORK_INTERFACE;
        let name = b"Network Interface";
        obj.name[..name.len()].copy_from_slice(name);
        obj.name_len = name.len();
        let help = b"Network interface performance object";
        obj.help[..help.len()].copy_from_slice(help);
        obj.help_len = help.len();
        obj.supports_instances = true;
        obj.active = true;

        // Add counters
        add_counter(obj, 1, "Bytes Total/sec", CounterType::RateCounter64);
        add_counter(obj, 2, "Bytes Received/sec", CounterType::RateCounter64);
        add_counter(obj, 3, "Bytes Sent/sec", CounterType::RateCounter64);
        add_counter(obj, 4, "Packets/sec", CounterType::RateCounter64);
        add_counter(obj, 5, "Packets Received/sec", CounterType::RateCounter64);
        add_counter(obj, 6, "Packets Sent/sec", CounterType::RateCounter64);
        add_counter(obj, 7, "Packets Received Errors", CounterType::Counter64);
        add_counter(obj, 8, "Packets Outbound Errors", CounterType::Counter64);
        add_counter(obj, 9, "Current Bandwidth", CounterType::Counter64);

        OBJECT_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Helper to add a counter to an object
fn add_counter(obj: &mut PerfObject, id: u32, name: &str, counter_type: CounterType) {
    if obj.counter_count >= MAX_COUNTERS_PER_OBJECT {
        return;
    }

    let counter = &mut obj.counters[obj.counter_count];
    counter.id = id;
    counter.counter_type = counter_type;

    let name_bytes = name.as_bytes();
    let len = name_bytes.len().min(63);
    counter.name[..len].copy_from_slice(&name_bytes[..len]);
    counter.name_len = len;

    counter.default_scale = 0;
    counter.detail_level = 100;

    obj.counter_count += 1;
}

/// Get performance object by ID
pub fn get_object(id: u32) -> Option<&'static PerfObject> {
    let _guard = PERF_LOCK.lock();

    unsafe {
        for i in 0..OBJECT_COUNT.load(Ordering::Relaxed) as usize {
            if PERF_OBJECTS[i].active && PERF_OBJECTS[i].id == id {
                return Some(&PERF_OBJECTS[i]);
            }
        }
    }

    None
}

/// Get list of all registered objects
pub fn enumerate_objects() -> Vec<u32> {
    let _guard = PERF_LOCK.lock();
    let mut result = Vec::new();

    unsafe {
        for i in 0..OBJECT_COUNT.load(Ordering::Relaxed) as usize {
            if PERF_OBJECTS[i].active {
                result.push(PERF_OBJECTS[i].id);
            }
        }
    }

    result
}

/// Get object count
pub fn get_object_count() -> u32 {
    OBJECT_COUNT.load(Ordering::Relaxed)
}

/// Query counter value (returns real-time value from kernel)
pub fn query_counter(object_id: u32, counter_id: u32, instance: u32) -> Option<u64> {
    match object_id {
        object_ids::SYSTEM => query_system_counter(counter_id),
        object_ids::MEMORY => query_memory_counter(counter_id),
        object_ids::PROCESSOR => query_processor_counter(counter_id, instance),
        object_ids::PROCESS => query_process_counter(counter_id, instance),
        object_ids::NETWORK_INTERFACE => query_network_counter(counter_id, instance),
        _ => None,
    }
}

fn query_system_counter(counter_id: u32) -> Option<u64> {
    let perf_stats = super::get_stats();
    let cid_stats = crate::ps::get_cid_stats();

    match counter_id {
        2 => Some(perf_stats.context_switches), // Context Switches/sec
        3 => Some(perf_stats.syscall_count),    // System Calls/sec
        4 => Some(cid_stats.active_processes as u64), // Processes
        5 => Some(cid_stats.active_threads as u64),   // Threads
        6 => Some(crate::hal::apic::get_tick_count() / 1_000_000), // Up Time (seconds)
        _ => None,
    }
}

fn query_memory_counter(counter_id: u32) -> Option<u64> {
    let pool_stats = crate::mm::mm_get_pool_stats();
    let mm_stats = crate::mm::mm_get_stats();

    match counter_id {
        1 => Some(mm_stats.free_bytes()),                    // Available Bytes
        2 => Some(pool_stats.bytes_allocated as u64),        // Committed Bytes
        3 => Some(pool_stats.total_size as u64),             // Commit Limit
        6 => Some(pool_stats.bytes_allocated as u64),        // Pool Nonpaged Bytes (using allocated)
        7 => Some(pool_stats.bytes_free as u64),             // Pool Paged Bytes (using free)
        _ => None,
    }
}

fn query_processor_counter(counter_id: u32, _instance: u32) -> Option<u64> {
    let perf_stats = super::get_stats();

    match counter_id {
        7 => Some(perf_stats.interrupt_count), // Interrupts/sec
        8 => Some(perf_stats.dpc_count),       // DPCs Queued/sec
        _ => None,
    }
}

fn query_process_counter(counter_id: u32, pid: u32) -> Option<u64> {
    // Would query specific process - for now return aggregate
    let cid_stats = crate::ps::get_cid_stats();

    match counter_id {
        5 => Some(cid_stats.active_threads as u64 / cid_stats.active_processes.max(1) as u64),
        11 => Some(pid as u64),
        _ => None,
    }
}

fn query_network_counter(counter_id: u32, _instance: u32) -> Option<u64> {
    let net_stats = crate::net::get_stats();

    match counter_id {
        1 => Some(net_stats.bytes_received + net_stats.bytes_transmitted),
        2 => Some(net_stats.bytes_received),
        3 => Some(net_stats.bytes_transmitted),
        4 => Some(net_stats.packets_received + net_stats.packets_transmitted),
        5 => Some(net_stats.packets_received),
        6 => Some(net_stats.packets_transmitted),
        7 => Some(net_stats.receive_errors),
        8 => Some(net_stats.transmit_errors),
        _ => None,
    }
}

// ============================================================================
// Counter Statistics
// ============================================================================

/// Counter subsystem statistics
#[derive(Debug, Clone, Copy)]
pub struct CounterStats {
    /// Number of registered objects
    pub objects_registered: u32,
    /// Total number of counters across all objects
    pub total_counters: u32,
    /// Number of counter queries performed
    pub queries_performed: u64,
}

/// Get counter statistics
pub fn get_stats() -> CounterStats {
    let objects = OBJECT_COUNT.load(Ordering::Relaxed);

    // Count total counters across all objects
    let mut total_counters = 0u32;
    let _guard = PERF_LOCK.lock();
    unsafe {
        for i in 0..objects as usize {
            if PERF_OBJECTS[i].active {
                total_counters += PERF_OBJECTS[i].counter_count as u32;
            }
        }
    }

    CounterStats {
        objects_registered: objects,
        total_counters,
        queries_performed: QUERIES_PERFORMED.load(Ordering::Relaxed),
    }
}

/// Increment query counter
pub fn record_query() {
    QUERIES_PERFORMED.fetch_add(1, Ordering::Relaxed);
}
