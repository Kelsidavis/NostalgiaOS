//! Deadlock Detection
//!
//! Detects potential deadlocks by building a lock acquisition graph
//! and checking for cycles.
//!
//! The deadlock verifier tracks:
//! - Resource initialization
//! - Resource acquisition
//! - Resource release
//! - Resource deallocation
//!
//! It builds a graph where nodes are locks and edges represent
//! "lock A was held while acquiring lock B". A cycle in this graph
//! indicates a potential deadlock.

use super::{vf_increment_stat, vf_is_option_enabled, vf_report_violation, VerifierBugcheck, VerifierOptions, VerifierStat};
use crate::ke::SpinLock;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

extern crate alloc;

/// Resource types that can deadlock
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResourceType {
    /// Spinlock
    SpinLock,
    /// Fast mutex
    FastMutex,
    /// Guarded mutex
    GuardedMutex,
    /// ERESOURCE (reader/writer lock)
    EResource,
    /// Mutex (dispatcher object)
    Mutex,
    /// Critical section (user mode, for completeness)
    CriticalSection,
}

impl ResourceType {
    pub fn name(self) -> &'static str {
        match self {
            ResourceType::SpinLock => "SpinLock",
            ResourceType::FastMutex => "FastMutex",
            ResourceType::GuardedMutex => "GuardedMutex",
            ResourceType::EResource => "ERESOURCE",
            ResourceType::Mutex => "Mutex",
            ResourceType::CriticalSection => "CriticalSection",
        }
    }

    /// Whether recursive acquisition is allowed
    pub fn recursive_ok(self) -> bool {
        matches!(self, ResourceType::Mutex | ResourceType::CriticalSection)
    }

    /// Whether reverse release order is allowed
    pub fn reverse_release_ok(self) -> bool {
        matches!(self, ResourceType::SpinLock)
    }
}

/// Resource node in the deadlock graph
#[derive(Debug, Clone)]
pub struct DeadlockResource {
    /// Resource address
    pub address: usize,
    /// Resource type
    pub resource_type: ResourceType,
    /// Initialization timestamp
    pub init_time: u64,
    /// Current owner thread (0 if not held)
    pub owner_thread: usize,
    /// Acquisition count (for recursive locks)
    pub acquire_count: u32,
    /// Last acquire timestamp
    pub last_acquire_time: u64,
    /// Graph node index
    pub node_index: usize,
}

/// Graph node representing a lock
#[derive(Debug, Clone)]
pub struct GraphNode {
    /// Resource this node represents
    pub resource: usize,
    /// Resources acquired while holding this resource (edges)
    pub children: BTreeSet<usize>,
    /// Resources that were held when acquiring this one (parent edges)
    pub parents: BTreeSet<usize>,
    /// Sequence number for age tracking
    pub sequence: u64,
}

impl GraphNode {
    pub fn new(resource: usize, sequence: u64) -> Self {
        Self {
            resource,
            children: BTreeSet::new(),
            parents: BTreeSet::new(),
            sequence,
        }
    }
}

/// Thread lock state
#[derive(Debug, Clone)]
pub struct ThreadLockState {
    /// Thread ID
    pub thread_id: usize,
    /// Stack of currently held resources (most recent last)
    pub held_resources: Vec<usize>,
}

impl ThreadLockState {
    pub fn new(thread_id: usize) -> Self {
        Self {
            thread_id,
            held_resources: Vec::new(),
        }
    }
}

/// Deadlock detection state
#[derive(Debug)]
pub struct DeadlockState {
    /// Resources by address
    resources: BTreeMap<usize, DeadlockResource>,
    /// Lock graph nodes by resource address
    graph: BTreeMap<usize, GraphNode>,
    /// Per-thread lock state
    threads: BTreeMap<usize, ThreadLockState>,
    /// Monotonic sequence counter
    sequence: u64,
    /// Age window for graph trimming
    age_window: u64,
    /// Trim threshold (resources with more than this many nodes get trimmed)
    trim_threshold: usize,
    /// Detection enabled
    enabled: bool,
    /// Strict mode (complain about uninitialized resources)
    strict: bool,
    /// Very strict mode (complain about release without acquire)
    very_strict: bool,
    /// Only verify spinlocks
    spinlocks_only: bool,
    /// Count of resets (when we get confused)
    resets: u64,
}

impl DeadlockState {
    pub const fn new() -> Self {
        Self {
            resources: BTreeMap::new(),
            graph: BTreeMap::new(),
            threads: BTreeMap::new(),
            sequence: 0,
            age_window: 0x2000,
            trim_threshold: 0x100,
            enabled: false,
            strict: false,
            very_strict: false,
            spinlocks_only: false,
            resets: 0,
        }
    }
}

/// Global deadlock state
static mut DEADLOCK_STATE: Option<SpinLock<DeadlockState>> = None;

fn get_deadlock_state() -> &'static SpinLock<DeadlockState> {
    unsafe {
        DEADLOCK_STATE
            .as_ref()
            .expect("Deadlock verifier not initialized")
    }
}

/// Initialize deadlock detection
pub fn vf_deadlock_init() {
    unsafe {
        DEADLOCK_STATE = Some(SpinLock::new(DeadlockState::new()));
    }

    // Enable if option is set
    if vf_is_option_enabled(VerifierOptions::DETECT_DEADLOCKS) {
        let state = get_deadlock_state();
        let mut guard = state.lock();
        guard.enabled = true;

        if vf_is_option_enabled(VerifierOptions::DEADLOCK_STRICT) {
            guard.strict = true;
            guard.very_strict = true;
        }

        if vf_is_option_enabled(VerifierOptions::DEADLOCK_SPINLOCKS_ONLY) {
            guard.spinlocks_only = true;
        }
    }

    crate::serial_println!("[VERIFIER] Deadlock detection initialized");
}

/// Initialize a resource for tracking
pub fn vf_deadlock_initialize_resource(address: usize, resource_type: ResourceType) {
    let state = get_deadlock_state();
    let mut guard = state.lock();

    if !guard.enabled {
        return;
    }

    if guard.spinlocks_only && resource_type != ResourceType::SpinLock {
        return;
    }

    if guard.resources.contains_key(&address) && guard.very_strict {
        // Double initialization
        vf_report_violation(
            VerifierBugcheck::DriverVerifierDetectedViolation,
            "unknown",
            address,
            resource_type as usize,
            0,
            0x3001, // Double init
        );
        return;
    }

    let node_index = guard.graph.len();
    let sequence = guard.sequence;
    guard.sequence += 1;

    let resource = DeadlockResource {
        address,
        resource_type,
        init_time: unsafe { core::arch::x86_64::_rdtsc() },
        owner_thread: 0,
        acquire_count: 0,
        last_acquire_time: 0,
        node_index,
    };

    guard.resources.insert(address, resource);
    guard.graph.insert(address, GraphNode::new(address, sequence));
}

/// Get current thread ID (placeholder)
fn get_current_thread_id() -> usize {
    // In real implementation, would get from KPCR/TEB
    0
}

/// Record resource acquisition
pub fn vf_deadlock_acquire_resource(address: usize, resource_type: ResourceType) {
    let state = get_deadlock_state();
    let mut guard = state.lock();

    if !guard.enabled {
        return;
    }

    if guard.spinlocks_only && resource_type != ResourceType::SpinLock {
        return;
    }

    vf_increment_stat(VerifierStat::DeadlockChecks);

    let thread_id = get_current_thread_id();

    // Auto-initialize if not present (for resources initialized outside verifier)
    if !guard.resources.contains_key(&address) {
        let node_index = guard.graph.len();
        let sequence = guard.sequence;
        guard.sequence += 1;

        let resource = DeadlockResource {
            address,
            resource_type,
            init_time: unsafe { core::arch::x86_64::_rdtsc() },
            owner_thread: 0,
            acquire_count: 0,
            last_acquire_time: 0,
            node_index,
        };

        guard.resources.insert(address, resource);
        guard.graph.insert(address, GraphNode::new(address, sequence));
    }

    // Get or create thread state
    let thread_state = guard
        .threads
        .entry(thread_id)
        .or_insert_with(|| ThreadLockState::new(thread_id));

    // Check for recursive acquisition
    if thread_state.held_resources.contains(&address) {
        if let Some(resource) = guard.resources.get(&address) {
            if !resource.resource_type.recursive_ok() {
                vf_report_violation(
                    VerifierBugcheck::DeadlockDetected,
                    "unknown",
                    address,
                    thread_id,
                    resource_type as usize,
                    0x3002, // Recursive non-recursive lock
                );
            }
        }
        return;
    }

    // Add edges from all currently held resources to this one
    // First, collect the held resources to avoid borrow conflicts
    let held_resources: Vec<usize> = thread_state.held_resources.clone();
    let current_sequence = guard.sequence;

    for held in held_resources {
        if let Some(node) = guard.graph.get_mut(&held) {
            node.children.insert(address);
            node.sequence = current_sequence;
        }
        if let Some(node) = guard.graph.get_mut(&address) {
            node.parents.insert(held);
            node.sequence = current_sequence;
        }
    }

    guard.sequence += 1;

    // Check for cycles (potential deadlock)
    if has_cycle(&guard.graph, address) {
        vf_report_violation(
            VerifierBugcheck::DeadlockDetected,
            "unknown",
            address,
            thread_id,
            resource_type as usize,
            0x3003, // Cycle detected
        );
        vf_increment_stat(VerifierStat::DeadlockDetections);
    }

    // Update thread state
    let thread_state = guard.threads.get_mut(&thread_id).unwrap();
    thread_state.held_resources.push(address);

    // Update resource state
    if let Some(resource) = guard.resources.get_mut(&address) {
        resource.owner_thread = thread_id;
        resource.acquire_count += 1;
        resource.last_acquire_time = unsafe { core::arch::x86_64::_rdtsc() };
    }
}

/// Record resource release
pub fn vf_deadlock_release_resource(address: usize) {
    let state = get_deadlock_state();
    let mut guard = state.lock();

    if !guard.enabled {
        return;
    }

    let thread_id = get_current_thread_id();

    // Check thread state - need to handle borrows carefully
    // First, get resource info without holding threads borrow
    let resource_allows_reverse = guard
        .resources
        .get(&address)
        .map(|r| r.resource_type.reverse_release_ok())
        .unwrap_or(true);
    let strict = guard.strict;
    let very_strict = guard.very_strict;

    let (should_report_out_of_order, should_report_release_without_acquire, should_remove_thread) = {
        let mut out_of_order = false;
        let mut release_without_acquire = false;
        let mut remove_thread = false;

        if let Some(thread_state) = guard.threads.get_mut(&thread_id) {
            if let Some(pos) = thread_state.held_resources.iter().position(|&x| x == address) {
                // Check for out-of-order release
                if pos != thread_state.held_resources.len() - 1 {
                    if !resource_allows_reverse && strict {
                        out_of_order = true;
                    }
                }
                thread_state.held_resources.remove(pos);

                // Clean up thread state if no more locks held
                if thread_state.held_resources.is_empty() {
                    remove_thread = true;
                }
            } else if very_strict {
                release_without_acquire = true;
            }
        }
        (out_of_order, release_without_acquire, remove_thread)
    };

    if should_report_out_of_order {
        vf_report_violation(
            VerifierBugcheck::DriverVerifierDetectedViolation,
            "unknown",
            address,
            thread_id,
            0,
            0x3004, // Out of order release
        );
    }

    if should_report_release_without_acquire {
        vf_report_violation(
            VerifierBugcheck::DriverVerifierDetectedViolation,
            "unknown",
            address,
            thread_id,
            0,
            0x3005, // Release without acquire
        );
    }

    if should_remove_thread {
        guard.threads.remove(&thread_id);
    }

    // Update resource state
    if let Some(resource) = guard.resources.get_mut(&address) {
        if resource.acquire_count > 0 {
            resource.acquire_count -= 1;
        }
        if resource.acquire_count == 0 {
            resource.owner_thread = 0;
        }
    }
}

/// Record resource deallocation
pub fn vf_deadlock_free_resource(address: usize) {
    let state = get_deadlock_state();
    let mut guard = state.lock();

    if !guard.enabled {
        return;
    }

    // Check if resource is still held
    if let Some(resource) = guard.resources.get(&address) {
        if resource.owner_thread != 0 {
            vf_report_violation(
                VerifierBugcheck::DriverVerifierDetectedViolation,
                "unknown",
                address,
                resource.owner_thread,
                resource.acquire_count as usize,
                0x3006, // Free while held
            );
        }
    }

    // Remove from graph
    if let Some(node) = guard.graph.remove(&address) {
        // Remove references from other nodes
        for parent in &node.parents {
            if let Some(parent_node) = guard.graph.get_mut(parent) {
                parent_node.children.remove(&address);
            }
        }
        for child in &node.children {
            if let Some(child_node) = guard.graph.get_mut(child) {
                child_node.parents.remove(&address);
            }
        }
    }

    guard.resources.remove(&address);
}

/// Check if adding an edge creates a cycle (DFS-based)
fn has_cycle(graph: &BTreeMap<usize, GraphNode>, start: usize) -> bool {
    let mut visited = BTreeSet::new();
    let mut stack = BTreeSet::new();

    fn dfs(
        graph: &BTreeMap<usize, GraphNode>,
        node: usize,
        visited: &mut BTreeSet<usize>,
        stack: &mut BTreeSet<usize>,
    ) -> bool {
        visited.insert(node);
        stack.insert(node);

        if let Some(n) = graph.get(&node) {
            for &child in &n.children {
                if !visited.contains(&child) {
                    if dfs(graph, child, visited, stack) {
                        return true;
                    }
                } else if stack.contains(&child) {
                    return true; // Back edge = cycle
                }
            }
        }

        stack.remove(&node);
        false
    }

    dfs(graph, start, &mut visited, &mut stack)
}

/// Get deadlock detection statistics
#[derive(Debug, Clone, Default)]
pub struct DeadlockStats {
    /// Number of tracked resources
    pub resources: usize,
    /// Number of graph nodes
    pub graph_nodes: usize,
    /// Number of edges
    pub graph_edges: usize,
    /// Number of active threads holding locks
    pub threads_with_locks: usize,
    /// Total locks currently held
    pub total_locks_held: usize,
    /// Number of resets
    pub resets: u64,
}

pub fn vf_deadlock_get_stats() -> DeadlockStats {
    let state = get_deadlock_state();
    let guard = state.lock();

    let graph_edges: usize = guard.graph.values().map(|n| n.children.len()).sum();
    let total_locks_held: usize = guard.threads.values().map(|t| t.held_resources.len()).sum();

    DeadlockStats {
        resources: guard.resources.len(),
        graph_nodes: guard.graph.len(),
        graph_edges,
        threads_with_locks: guard.threads.len(),
        total_locks_held,
        resets: guard.resets,
    }
}

/// Trim old nodes from the graph
pub fn vf_deadlock_trim_graph() {
    let state = get_deadlock_state();
    let mut guard = state.lock();

    if !guard.enabled {
        return;
    }

    let current_seq = guard.sequence;
    let age_window = guard.age_window;
    let trim_threshold = guard.trim_threshold;

    // Find nodes that are old and have many children
    let to_trim: Vec<usize> = guard
        .graph
        .iter()
        .filter(|(_, node)| {
            current_seq.saturating_sub(node.sequence) > age_window
                && node.children.len() > trim_threshold
        })
        .map(|(addr, _)| *addr)
        .collect();

    for addr in to_trim {
        if let Some(node) = guard.graph.get_mut(&addr) {
            // Trim oldest children
            let children: Vec<_> = node.children.iter().cloned().collect();
            for child in children.into_iter().take(node.children.len() / 2) {
                node.children.remove(&child);
            }
        }
    }
}
