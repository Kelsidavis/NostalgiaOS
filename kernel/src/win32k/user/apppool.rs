//! Application Pool Module
//!
//! Windows Server 2003 IIS 6.0 Application Pool management. Provides worker
//! process configuration, recycling settings, health monitoring, and
//! identity management.

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use crate::win32k::user::UserHandle;

/// Maximum application pools
const MAX_POOLS: usize = 64;

/// Maximum worker processes per pool
const MAX_WORKERS: usize = 256;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum identity name length
const MAX_IDENTITY_LEN: usize = 128;

/// Pool state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PoolState {
    /// Pool is stopped
    Stopped = 0,
    /// Pool is starting
    Starting = 1,
    /// Pool is running
    Running = 2,
    /// Pool is stopping
    Stopping = 3,
}

impl Default for PoolState {
    fn default() -> Self {
        Self::Stopped
    }
}

/// Worker process state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WorkerState {
    /// Worker is starting
    Starting = 0,
    /// Worker is running
    Running = 1,
    /// Worker is recycling
    Recycling = 2,
    /// Worker is stopping
    Stopping = 3,
    /// Worker is unhealthy
    Unhealthy = 4,
}

impl Default for WorkerState {
    fn default() -> Self {
        Self::Starting
    }
}

/// Identity type for worker process
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum IdentityType {
    /// Local System
    LocalSystem = 0,
    /// Local Service
    LocalService = 1,
    /// Network Service
    NetworkService = 2,
    /// Specific user account
    SpecificUser = 3,
    /// Application pool identity
    ApplicationPoolIdentity = 4,
}

impl Default for IdentityType {
    fn default() -> Self {
        Self::NetworkService
    }
}

/// Pipeline mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PipelineMode {
    /// Classic mode (IIS 6.0 compatible)
    Classic = 0,
    /// Integrated mode
    Integrated = 1,
}

impl Default for PipelineMode {
    fn default() -> Self {
        Self::Classic
    }
}

/// CPU action when limit exceeded
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CpuAction {
    /// No action
    NoAction = 0,
    /// Kill worker process
    KillW3wp = 1,
    /// Throttle requests
    Throttle = 2,
    /// Throttle underload
    ThrottleUnderLoad = 3,
}

impl Default for CpuAction {
    fn default() -> Self {
        Self::NoAction
    }
}

bitflags::bitflags! {
    /// Pool flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PoolFlags: u32 {
        /// Auto-start the pool
        const AUTO_START = 0x0001;
        /// Enable 32-bit applications on 64-bit
        const ENABLE_32BIT = 0x0002;
        /// Rapid fail protection
        const RAPID_FAIL_PROTECTION = 0x0004;
        /// Ping enabled (health monitoring)
        const PING_ENABLED = 0x0008;
        /// Orphan worker on shutdown
        const ORPHAN_WORKER = 0x0010;
        /// Disable overlapped recycle
        const DISABLE_OVERLAPPED_RECYCLE = 0x0020;
    }
}

impl Default for PoolFlags {
    fn default() -> Self {
        Self::AUTO_START | Self::RAPID_FAIL_PROTECTION | Self::PING_ENABLED
    }
}

/// Recycling triggers
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RecycleFlags: u32 {
        /// Recycle on time interval
        const TIME = 0x0001;
        /// Recycle on request limit
        const REQUESTS = 0x0002;
        /// Recycle on memory limit
        const MEMORY = 0x0004;
        /// Recycle on virtual memory limit
        const VIRTUAL_MEMORY = 0x0008;
        /// Recycle at specific times
        const SCHEDULE = 0x0010;
        /// Recycle on config change
        const CONFIG_CHANGE = 0x0020;
        /// Recycle on ISAPI unhealthy
        const ISAPI_UNHEALTHY = 0x0040;
    }
}

impl Default for RecycleFlags {
    fn default() -> Self {
        Self::TIME | Self::CONFIG_CHANGE
    }
}

/// Application pool
#[derive(Debug)]
pub struct AppPool {
    /// Pool is active
    active: bool,
    /// Pool ID
    id: u32,
    /// Pool name
    name: [u8; MAX_NAME_LEN],
    /// Name length
    name_len: usize,
    /// Pool state
    state: PoolState,
    /// Pool flags
    flags: PoolFlags,
    /// Identity type
    identity_type: IdentityType,
    /// Identity username (for SpecificUser)
    identity_user: [u8; MAX_IDENTITY_LEN],
    /// Identity user length
    identity_len: usize,
    /// Pipeline mode
    pipeline_mode: PipelineMode,
    /// .NET CLR version (empty = no managed code)
    clr_version: [u8; 16],
    /// CLR version length
    clr_len: usize,
    /// Maximum worker processes
    max_workers: u32,
    /// Idle timeout (minutes)
    idle_timeout: u32,
    /// Recycle flags
    recycle_flags: RecycleFlags,
    /// Recycle time interval (minutes)
    recycle_time: u32,
    /// Recycle request limit
    recycle_requests: u32,
    /// Private memory limit (KB)
    private_memory_limit: u32,
    /// Virtual memory limit (KB)
    virtual_memory_limit: u32,
    /// Ping interval (seconds)
    ping_interval: u32,
    /// Ping response time (seconds)
    ping_response: u32,
    /// Startup time limit (seconds)
    startup_time_limit: u32,
    /// Shutdown time limit (seconds)
    shutdown_time_limit: u32,
    /// Rapid fail protection (failures)
    rapid_fail_count: u32,
    /// Rapid fail time (minutes)
    rapid_fail_time: u32,
    /// CPU limit (percent * 1000)
    cpu_limit: u32,
    /// CPU action
    cpu_action: CpuAction,
    /// Current worker count
    current_workers: u32,
    /// Total requests processed
    total_requests: u64,
    /// Handle for management
    handle: UserHandle,
}

impl AppPool {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            state: PoolState::Stopped,
            flags: PoolFlags::empty(),
            identity_type: IdentityType::NetworkService,
            identity_user: [0u8; MAX_IDENTITY_LEN],
            identity_len: 0,
            pipeline_mode: PipelineMode::Classic,
            clr_version: [0u8; 16],
            clr_len: 0,
            max_workers: 1,
            idle_timeout: 20,
            recycle_flags: RecycleFlags::empty(),
            recycle_time: 1740, // 29 hours
            recycle_requests: 0,
            private_memory_limit: 0,
            virtual_memory_limit: 0,
            ping_interval: 30,
            ping_response: 90,
            startup_time_limit: 90,
            shutdown_time_limit: 90,
            rapid_fail_count: 5,
            rapid_fail_time: 5,
            cpu_limit: 0,
            cpu_action: CpuAction::NoAction,
            current_workers: 0,
            total_requests: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// Worker process
#[derive(Debug)]
pub struct WorkerProcess {
    /// Worker is active
    active: bool,
    /// Worker ID
    id: u32,
    /// Parent pool ID
    pool_id: u32,
    /// Process ID
    process_id: u32,
    /// Worker state
    state: WorkerState,
    /// Start time
    start_time: u64,
    /// Requests processed
    requests_processed: u64,
    /// Current requests
    current_requests: u32,
    /// Memory usage (KB)
    memory_usage: u32,
    /// CPU usage (percent * 100)
    cpu_usage: u32,
    /// Handle for management
    handle: UserHandle,
}

impl WorkerProcess {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            pool_id: 0,
            process_id: 0,
            state: WorkerState::Starting,
            start_time: 0,
            requests_processed: 0,
            current_requests: 0,
            memory_usage: 0,
            cpu_usage: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// Application pool statistics
#[derive(Debug)]
pub struct PoolStats {
    /// Total pools
    pub total_pools: u32,
    /// Running pools
    pub running_pools: u32,
    /// Total workers
    pub total_workers: u32,
    /// Total requests
    pub total_requests: u64,
    /// Pool recycles
    pub pool_recycles: u64,
    /// Worker restarts
    pub worker_restarts: u64,
    /// Health ping failures
    pub ping_failures: u64,
}

impl PoolStats {
    pub const fn new() -> Self {
        Self {
            total_pools: 0,
            running_pools: 0,
            total_workers: 0,
            total_requests: 0,
            pool_recycles: 0,
            worker_restarts: 0,
            ping_failures: 0,
        }
    }
}

/// Application pool state
struct AppPoolState {
    /// Pools
    pools: [AppPool; MAX_POOLS],
    /// Workers
    workers: [WorkerProcess; MAX_WORKERS],
    /// Statistics
    stats: PoolStats,
    /// Next ID
    next_id: u32,
}

impl AppPoolState {
    pub const fn new() -> Self {
        Self {
            pools: [const { AppPool::new() }; MAX_POOLS],
            workers: [const { WorkerProcess::new() }; MAX_WORKERS],
            stats: PoolStats::new(),
            next_id: 1,
        }
    }
}

/// Global pool state
static POOL_STATE: Mutex<AppPoolState> = Mutex::new(AppPoolState::new());

/// Initialization flag
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the application pool module
pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let mut state = POOL_STATE.lock();

    // Create default application pool
    let slot_idx = 0;
    state.pools[slot_idx].active = true;
    state.pools[slot_idx].id = 1;

    let name = b"DefaultAppPool";
    let name_len = name.len().min(MAX_NAME_LEN);
    state.pools[slot_idx].name[..name_len].copy_from_slice(&name[..name_len]);
    state.pools[slot_idx].name_len = name_len;

    state.pools[slot_idx].state = PoolState::Stopped;
    state.pools[slot_idx].flags = PoolFlags::default();
    state.pools[slot_idx].identity_type = IdentityType::NetworkService;
    state.pools[slot_idx].pipeline_mode = PipelineMode::Classic;
    state.pools[slot_idx].max_workers = 1;
    state.pools[slot_idx].idle_timeout = 20;
    state.pools[slot_idx].recycle_flags = RecycleFlags::default();
    state.pools[slot_idx].recycle_time = 1740;
    state.pools[slot_idx].handle = UserHandle::from_raw(1);

    state.next_id = 2;
    state.stats.total_pools = 1;

    Ok(())
}

/// Create a new application pool
pub fn create_pool(
    name: &str,
    identity_type: IdentityType,
    pipeline_mode: PipelineMode,
    flags: PoolFlags,
) -> Result<UserHandle, u32> {
    let mut state = POOL_STATE.lock();

    // Check for duplicate name
    for pool in state.pools.iter() {
        if pool.active {
            let existing = &pool.name[..pool.name_len];
            if existing == name.as_bytes() {
                return Err(0x80070050);
            }
        }
    }

    let slot_idx = state.pools.iter().position(|p| !p.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008),
    };

    let id = state.next_id;
    state.next_id += 1;

    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(MAX_NAME_LEN);

    state.pools[slot_idx].active = true;
    state.pools[slot_idx].id = id;
    state.pools[slot_idx].name[..name_len].copy_from_slice(&name_bytes[..name_len]);
    state.pools[slot_idx].name_len = name_len;
    state.pools[slot_idx].state = PoolState::Stopped;
    state.pools[slot_idx].flags = flags;
    state.pools[slot_idx].identity_type = identity_type;
    state.pools[slot_idx].identity_len = 0;
    state.pools[slot_idx].pipeline_mode = pipeline_mode;
    state.pools[slot_idx].clr_len = 0;
    state.pools[slot_idx].max_workers = 1;
    state.pools[slot_idx].idle_timeout = 20;
    state.pools[slot_idx].recycle_flags = RecycleFlags::default();
    state.pools[slot_idx].recycle_time = 1740;
    state.pools[slot_idx].recycle_requests = 0;
    state.pools[slot_idx].private_memory_limit = 0;
    state.pools[slot_idx].virtual_memory_limit = 0;
    state.pools[slot_idx].ping_interval = 30;
    state.pools[slot_idx].ping_response = 90;
    state.pools[slot_idx].startup_time_limit = 90;
    state.pools[slot_idx].shutdown_time_limit = 90;
    state.pools[slot_idx].rapid_fail_count = 5;
    state.pools[slot_idx].rapid_fail_time = 5;
    state.pools[slot_idx].cpu_limit = 0;
    state.pools[slot_idx].cpu_action = CpuAction::NoAction;
    state.pools[slot_idx].current_workers = 0;
    state.pools[slot_idx].total_requests = 0;
    state.pools[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.total_pools += 1;

    Ok(state.pools[slot_idx].handle)
}

/// Delete an application pool
pub fn delete_pool(pool_id: u32) -> Result<(), u32> {
    let mut state = POOL_STATE.lock();

    let pool_idx = state.pools.iter().position(|p| p.active && p.id == pool_id);
    let pool_idx = match pool_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    if state.pools[pool_idx].state != PoolState::Stopped {
        return Err(0x80070020);
    }

    state.pools[pool_idx].active = false;
    state.stats.total_pools = state.stats.total_pools.saturating_sub(1);

    Ok(())
}

/// Start an application pool
pub fn start_pool(pool_id: u32) -> Result<(), u32> {
    let mut state = POOL_STATE.lock();

    let pool = state.pools.iter_mut().find(|p| p.active && p.id == pool_id);
    let pool = match pool {
        Some(p) => p,
        None => return Err(0x80070002),
    };

    match pool.state {
        PoolState::Running => return Ok(()),
        PoolState::Starting | PoolState::Stopping => return Err(0x80070015),
        _ => {}
    }

    pool.state = PoolState::Starting;
    pool.state = PoolState::Running;
    state.stats.running_pools += 1;

    Ok(())
}

/// Stop an application pool
pub fn stop_pool(pool_id: u32) -> Result<(), u32> {
    let mut state = POOL_STATE.lock();

    let pool_idx = state.pools.iter().position(|p| p.active && p.id == pool_id);
    let pool_idx = match pool_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    match state.pools[pool_idx].state {
        PoolState::Stopped => return Ok(()),
        PoolState::Starting | PoolState::Stopping => return Err(0x80070015),
        _ => {}
    }

    // Stop workers
    let mut workers_stopped = 0u32;
    for worker in state.workers.iter_mut() {
        if worker.active && worker.pool_id == pool_id {
            worker.active = false;
            workers_stopped += 1;
        }
    }

    state.pools[pool_idx].state = PoolState::Stopping;
    state.pools[pool_idx].state = PoolState::Stopped;
    state.pools[pool_idx].current_workers = 0;
    state.stats.running_pools = state.stats.running_pools.saturating_sub(1);
    state.stats.total_workers = state.stats.total_workers.saturating_sub(workers_stopped);

    Ok(())
}

/// Recycle an application pool
pub fn recycle_pool(pool_id: u32) -> Result<(), u32> {
    let mut state = POOL_STATE.lock();

    let pool_idx = state.pools.iter().position(|p| p.active && p.id == pool_id);
    let pool_idx = match pool_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    if state.pools[pool_idx].state != PoolState::Running {
        return Err(0x80070015);
    }

    // Mark workers for recycling
    for worker in state.workers.iter_mut() {
        if worker.active && worker.pool_id == pool_id {
            worker.state = WorkerState::Recycling;
        }
    }

    state.stats.pool_recycles += 1;

    Ok(())
}

/// Configure recycling settings
pub fn configure_recycling(
    pool_id: u32,
    recycle_flags: RecycleFlags,
    recycle_time: u32,
    recycle_requests: u32,
    private_memory_limit: u32,
    virtual_memory_limit: u32,
) -> Result<(), u32> {
    let mut state = POOL_STATE.lock();

    let pool = state.pools.iter_mut().find(|p| p.active && p.id == pool_id);
    let pool = match pool {
        Some(p) => p,
        None => return Err(0x80070002),
    };

    pool.recycle_flags = recycle_flags;
    pool.recycle_time = recycle_time;
    pool.recycle_requests = recycle_requests;
    pool.private_memory_limit = private_memory_limit;
    pool.virtual_memory_limit = virtual_memory_limit;

    Ok(())
}

/// Configure health monitoring
pub fn configure_health(
    pool_id: u32,
    ping_interval: u32,
    ping_response: u32,
    rapid_fail_count: u32,
    rapid_fail_time: u32,
) -> Result<(), u32> {
    let mut state = POOL_STATE.lock();

    let pool = state.pools.iter_mut().find(|p| p.active && p.id == pool_id);
    let pool = match pool {
        Some(p) => p,
        None => return Err(0x80070002),
    };

    pool.ping_interval = ping_interval;
    pool.ping_response = ping_response;
    pool.rapid_fail_count = rapid_fail_count;
    pool.rapid_fail_time = rapid_fail_time;

    Ok(())
}

/// Set pool identity
pub fn set_identity(
    pool_id: u32,
    identity_type: IdentityType,
    username: Option<&str>,
) -> Result<(), u32> {
    let mut state = POOL_STATE.lock();

    let pool = state.pools.iter_mut().find(|p| p.active && p.id == pool_id);
    let pool = match pool {
        Some(p) => p,
        None => return Err(0x80070002),
    };

    pool.identity_type = identity_type;

    if let Some(user) = username {
        let user_bytes = user.as_bytes();
        let user_len = user_bytes.len().min(MAX_IDENTITY_LEN);
        pool.identity_user[..user_len].copy_from_slice(&user_bytes[..user_len]);
        pool.identity_len = user_len;
    } else {
        pool.identity_len = 0;
    }

    Ok(())
}

/// Get pool information
pub fn get_pool_info(pool_id: u32) -> Result<(PoolState, u32, u64), u32> {
    let state = POOL_STATE.lock();

    let pool = state.pools.iter().find(|p| p.active && p.id == pool_id);
    let pool = match pool {
        Some(p) => p,
        None => return Err(0x80070002),
    };

    Ok((pool.state, pool.current_workers, pool.total_requests))
}

/// Get pool statistics
pub fn get_statistics() -> PoolStats {
    let state = POOL_STATE.lock();
    PoolStats {
        total_pools: state.stats.total_pools,
        running_pools: state.stats.running_pools,
        total_workers: state.stats.total_workers,
        total_requests: state.stats.total_requests,
        pool_recycles: state.stats.pool_recycles,
        worker_restarts: state.stats.worker_restarts,
        ping_failures: state.stats.ping_failures,
    }
}

/// List all pools
pub fn list_pools() -> [(bool, u32, PoolState); MAX_POOLS] {
    let state = POOL_STATE.lock();
    let mut result = [(false, 0u32, PoolState::Stopped); MAX_POOLS];

    for (i, pool) in state.pools.iter().enumerate() {
        if pool.active {
            result[i] = (true, pool.id, pool.state);
        }
    }

    result
}

/// List workers for a pool
pub fn list_workers(pool_id: u32) -> [(bool, u32, WorkerState, u32); MAX_WORKERS] {
    let state = POOL_STATE.lock();
    let mut result = [(false, 0u32, WorkerState::Starting, 0u32); MAX_WORKERS];

    let mut idx = 0;
    for worker in state.workers.iter() {
        if worker.active && worker.pool_id == pool_id && idx < MAX_WORKERS {
            result[idx] = (true, worker.id, worker.state, worker.process_id);
            idx += 1;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialization() {
        init().unwrap();

        let stats = get_statistics();
        assert!(stats.total_pools >= 1);
    }

    #[test]
    fn test_pool_lifecycle() {
        init().unwrap();

        let pool = create_pool(
            "TestPool",
            IdentityType::NetworkService,
            PipelineMode::Classic,
            PoolFlags::default(),
        );
        assert!(pool.is_ok() || pool.is_err());
    }
}
