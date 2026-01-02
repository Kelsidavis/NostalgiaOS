//! Task Manager
//!
//! Implements the Windows Task Manager following Windows Server 2003.
//! Provides process, performance, networking, and user session monitoring.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - taskmgr.exe - Windows Task Manager
//! - Applications, Processes, Performance, Networking, Users tabs

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum processes displayed
const MAX_PROCESSES: usize = 256;

/// Maximum applications displayed
const MAX_APPLICATIONS: usize = 64;

/// Maximum network adapters
const MAX_ADAPTERS: usize = 8;

/// Maximum users
const MAX_USERS: usize = 16;

/// Maximum name length
const MAX_NAME: usize = 64;

/// CPU history size
const CPU_HISTORY_SIZE: usize = 60;

// ============================================================================
// Task Manager Tab
// ============================================================================

/// Task Manager tab
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TaskManagerTab {
    /// Applications tab
    #[default]
    Applications = 0,
    /// Processes tab
    Processes = 1,
    /// Performance tab
    Performance = 2,
    /// Networking tab
    Networking = 3,
    /// Users tab
    Users = 4,
}

impl TaskManagerTab {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskManagerTab::Applications => "Applications",
            TaskManagerTab::Processes => "Processes",
            TaskManagerTab::Performance => "Performance",
            TaskManagerTab::Networking => "Networking",
            TaskManagerTab::Users => "Users",
        }
    }
}

// ============================================================================
// Application Status
// ============================================================================

/// Application status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppStatus {
    /// Running
    #[default]
    Running = 0,
    /// Not Responding
    NotResponding = 1,
}

impl AppStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AppStatus::Running => "Running",
            AppStatus::NotResponding => "Not Responding",
        }
    }
}

// ============================================================================
// Process Priority
// ============================================================================

/// Process priority class
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PriorityClass {
    /// Realtime
    Realtime = 24,
    /// High
    High = 13,
    /// Above Normal
    AboveNormal = 10,
    /// Normal
    #[default]
    Normal = 8,
    /// Below Normal
    BelowNormal = 6,
    /// Low (Idle)
    Low = 4,
}

impl PriorityClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            PriorityClass::Realtime => "Realtime",
            PriorityClass::High => "High",
            PriorityClass::AboveNormal => "Above Normal",
            PriorityClass::Normal => "Normal",
            PriorityClass::BelowNormal => "Below Normal",
            PriorityClass::Low => "Low",
        }
    }
}

// ============================================================================
// Application Entry
// ============================================================================

/// Application entry (Applications tab)
#[derive(Debug, Clone, Copy)]
pub struct ApplicationEntry {
    /// Window handle
    pub hwnd: u32,
    /// Task name (window title)
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Status
    pub status: AppStatus,
    /// Process ID
    pub pid: u32,
}

impl ApplicationEntry {
    pub const fn new() -> Self {
        Self {
            hwnd: 0,
            name: [0u8; MAX_NAME],
            name_len: 0,
            status: AppStatus::Running,
            pid: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

impl Default for ApplicationEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Process Entry
// ============================================================================

/// Process entry (Processes tab)
#[derive(Debug, Clone, Copy)]
pub struct ProcessEntry {
    /// Process ID
    pub pid: u32,
    /// Image name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// User name
    pub user_name: [u8; 32],
    /// User name length
    pub user_len: usize,
    /// CPU usage (percentage * 100)
    pub cpu_usage: u32,
    /// Memory usage (working set in KB)
    pub mem_usage: u64,
    /// Peak memory (KB)
    pub peak_mem: u64,
    /// Page faults
    pub page_faults: u64,
    /// Handle count
    pub handles: u32,
    /// Thread count
    pub threads: u32,
    /// Priority class
    pub priority: PriorityClass,
    /// Base priority
    pub base_priority: u8,
    /// Session ID
    pub session_id: u32,
    /// CPU time (100ns units)
    pub cpu_time: u64,
}

impl ProcessEntry {
    pub const fn new() -> Self {
        Self {
            pid: 0,
            name: [0u8; MAX_NAME],
            name_len: 0,
            user_name: [0u8; 32],
            user_len: 0,
            cpu_usage: 0,
            mem_usage: 0,
            peak_mem: 0,
            page_faults: 0,
            handles: 0,
            threads: 1,
            priority: PriorityClass::Normal,
            base_priority: 8,
            session_id: 0,
            cpu_time: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_user(&mut self, user: &[u8]) {
        let len = user.len().min(32);
        self.user_name[..len].copy_from_slice(&user[..len]);
        self.user_len = len;
    }
}

impl Default for ProcessEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Performance Data
// ============================================================================

/// Performance data (Performance tab)
#[derive(Debug, Clone, Copy)]
pub struct PerformanceData {
    /// CPU usage history (percentage)
    pub cpu_history: [u8; CPU_HISTORY_SIZE],
    /// Current CPU usage index
    pub cpu_index: usize,
    /// Current CPU usage
    pub cpu_usage: u8,
    /// Kernel CPU time percentage
    pub kernel_time: u8,
    /// Total physical memory (KB)
    pub total_physical: u64,
    /// Available physical memory (KB)
    pub available_physical: u64,
    /// System cache (KB)
    pub system_cache: u64,
    /// Commit charge total (KB)
    pub commit_total: u64,
    /// Commit charge limit (KB)
    pub commit_limit: u64,
    /// Commit charge peak (KB)
    pub commit_peak: u64,
    /// Kernel memory paged (KB)
    pub kernel_paged: u64,
    /// Kernel memory nonpaged (KB)
    pub kernel_nonpaged: u64,
    /// Total handles
    pub total_handles: u32,
    /// Total threads
    pub total_threads: u32,
    /// Total processes
    pub total_processes: u32,
    /// Page file usage (KB)
    pub page_file_usage: u64,
    /// Uptime (seconds)
    pub uptime: u64,
}

impl PerformanceData {
    pub const fn new() -> Self {
        Self {
            cpu_history: [0; CPU_HISTORY_SIZE],
            cpu_index: 0,
            cpu_usage: 0,
            kernel_time: 0,
            total_physical: 512 * 1024, // 512 MB default
            available_physical: 256 * 1024,
            system_cache: 64 * 1024,
            commit_total: 128 * 1024,
            commit_limit: 1024 * 1024,
            commit_peak: 192 * 1024,
            kernel_paged: 32 * 1024,
            kernel_nonpaged: 8 * 1024,
            total_handles: 0,
            total_threads: 0,
            total_processes: 0,
            page_file_usage: 64 * 1024,
            uptime: 0,
        }
    }

    pub fn add_cpu_sample(&mut self, usage: u8) {
        self.cpu_history[self.cpu_index] = usage;
        self.cpu_index = (self.cpu_index + 1) % CPU_HISTORY_SIZE;
        self.cpu_usage = usage;
    }
}

impl Default for PerformanceData {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Network Adapter
// ============================================================================

/// Network adapter info (Networking tab)
#[derive(Debug, Clone, Copy)]
pub struct NetworkAdapter {
    /// Adapter name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Network utilization (percentage * 100)
    pub utilization: u32,
    /// Link speed (bits/sec)
    pub link_speed: u64,
    /// State (connected/disconnected)
    pub connected: bool,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Unicast packets sent
    pub unicast_sent: u64,
    /// Unicast packets received
    pub unicast_received: u64,
    /// Usage history
    pub history: [u8; 60],
    /// History index
    pub history_index: usize,
}

impl NetworkAdapter {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME],
            name_len: 0,
            utilization: 0,
            link_speed: 100_000_000, // 100 Mbps default
            connected: true,
            bytes_sent: 0,
            bytes_received: 0,
            unicast_sent: 0,
            unicast_received: 0,
            history: [0; 60],
            history_index: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

impl Default for NetworkAdapter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// User Session
// ============================================================================

/// User session (Users tab)
#[derive(Debug, Clone, Copy)]
pub struct UserSession {
    /// Session ID
    pub session_id: u32,
    /// User name
    pub user_name: [u8; 32],
    /// User name length
    pub user_len: usize,
    /// Session status
    pub status: SessionStatus,
    /// Client name (for remote sessions)
    pub client_name: [u8; 32],
    /// Client name length
    pub client_len: usize,
}

impl UserSession {
    pub const fn new() -> Self {
        Self {
            session_id: 0,
            user_name: [0u8; 32],
            user_len: 0,
            status: SessionStatus::Active,
            client_name: [0u8; 32],
            client_len: 0,
        }
    }

    pub fn set_user(&mut self, user: &[u8]) {
        let len = user.len().min(32);
        self.user_name[..len].copy_from_slice(&user[..len]);
        self.user_len = len;
    }

    pub fn set_client(&mut self, client: &[u8]) {
        let len = client.len().min(32);
        self.client_name[..len].copy_from_slice(&client[..len]);
        self.client_len = len;
    }
}

impl Default for UserSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Session status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionStatus {
    /// Active
    #[default]
    Active = 0,
    /// Disconnected
    Disconnected = 1,
}

// ============================================================================
// Task Manager Options
// ============================================================================

/// Task Manager display options
#[derive(Debug, Clone, Copy)]
pub struct TaskManagerOptions {
    /// Always on top
    pub always_on_top: bool,
    /// Minimize on use
    pub minimize_on_use: bool,
    /// Hide when minimized
    pub hide_when_minimized: bool,
    /// Show 16-bit tasks
    pub show_16bit_tasks: bool,
    /// Update speed (0=Paused, 1=Low, 2=Normal, 4=High)
    pub update_speed: u8,
    /// Show kernel times in performance graph
    pub show_kernel_times: bool,
    /// Show one graph per CPU
    pub one_graph_per_cpu: bool,
    /// CPU history shown
    pub cpu_history: bool,
}

impl TaskManagerOptions {
    pub const fn new() -> Self {
        Self {
            always_on_top: false,
            minimize_on_use: true,
            hide_when_minimized: false,
            show_16bit_tasks: true,
            update_speed: 2, // Normal
            show_kernel_times: false,
            one_graph_per_cpu: false,
            cpu_history: true,
        }
    }
}

impl Default for TaskManagerOptions {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Process Columns
// ============================================================================

bitflags::bitflags! {
    /// Visible process columns
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ProcessColumns: u32 {
        const IMAGE_NAME = 0x0001;
        const PID = 0x0002;
        const USER_NAME = 0x0004;
        const SESSION_ID = 0x0008;
        const CPU = 0x0010;
        const CPU_TIME = 0x0020;
        const MEM_USAGE = 0x0040;
        const PEAK_MEM = 0x0080;
        const PAGE_FAULTS = 0x0100;
        const HANDLES = 0x0200;
        const THREADS = 0x0400;
        const BASE_PRIORITY = 0x0800;

        const DEFAULT = Self::IMAGE_NAME.bits() | Self::PID.bits() |
                       Self::CPU.bits() | Self::MEM_USAGE.bits();
    }
}

// ============================================================================
// Task Manager State
// ============================================================================

/// Task Manager state
struct TaskManagerState {
    /// Applications
    applications: [ApplicationEntry; MAX_APPLICATIONS],
    /// Application count
    app_count: usize,
    /// Processes
    processes: [ProcessEntry; MAX_PROCESSES],
    /// Process count
    process_count: usize,
    /// Performance data
    performance: PerformanceData,
    /// Network adapters
    adapters: [NetworkAdapter; MAX_ADAPTERS],
    /// Adapter count
    adapter_count: usize,
    /// User sessions
    users: [UserSession; MAX_USERS],
    /// User count
    user_count: usize,
    /// Current tab
    current_tab: TaskManagerTab,
    /// Options
    options: TaskManagerOptions,
    /// Visible columns
    columns: ProcessColumns,
    /// Sort column
    sort_column: u8,
    /// Sort ascending
    sort_ascending: bool,
    /// Selected process PID
    selected_pid: u32,
}

impl TaskManagerState {
    pub const fn new() -> Self {
        Self {
            applications: [const { ApplicationEntry::new() }; MAX_APPLICATIONS],
            app_count: 0,
            processes: [const { ProcessEntry::new() }; MAX_PROCESSES],
            process_count: 0,
            performance: PerformanceData::new(),
            adapters: [const { NetworkAdapter::new() }; MAX_ADAPTERS],
            adapter_count: 0,
            users: [const { UserSession::new() }; MAX_USERS],
            user_count: 0,
            current_tab: TaskManagerTab::Applications,
            options: TaskManagerOptions::new(),
            columns: ProcessColumns::DEFAULT,
            sort_column: 0,
            sort_ascending: true,
            selected_pid: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static TASKMGR_INITIALIZED: AtomicBool = AtomicBool::new(false);
static TASKMGR_STATE: SpinLock<TaskManagerState> = SpinLock::new(TaskManagerState::new());

// Statistics
static REFRESH_COUNT: AtomicU64 = AtomicU64::new(0);
static END_TASK_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Task Manager
pub fn init() {
    if TASKMGR_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = TASKMGR_STATE.lock();

    // Add sample processes
    add_sample_processes(&mut state);

    // Add sample applications
    add_sample_applications(&mut state);

    // Add sample network adapters
    add_sample_adapters(&mut state);

    // Add sample users
    add_sample_users(&mut state);

    // Initialize performance data
    init_performance(&mut state);

    crate::serial_println!("[WIN32K] Task Manager initialized");
}

/// Add sample processes
fn add_sample_processes(state: &mut TaskManagerState) {
    let processes: [(&[u8], &[u8], u32, u64, u32, u32); 15] = [
        (b"System Idle Process", b"SYSTEM", 0, 0, 0, 1),
        (b"System", b"SYSTEM", 4, 256, 512, 64),
        (b"smss.exe", b"SYSTEM", 328, 384, 21, 3),
        (b"csrss.exe", b"SYSTEM", 396, 2048, 372, 11),
        (b"winlogon.exe", b"SYSTEM", 420, 4096, 148, 18),
        (b"services.exe", b"SYSTEM", 464, 3584, 243, 15),
        (b"lsass.exe", b"SYSTEM", 476, 1536, 312, 21),
        (b"svchost.exe", b"SYSTEM", 612, 4608, 87, 12),
        (b"svchost.exe", b"NETWORK SERVICE", 684, 3072, 156, 24),
        (b"svchost.exe", b"LOCAL SERVICE", 848, 2560, 98, 8),
        (b"spoolsv.exe", b"SYSTEM", 1124, 5120, 124, 10),
        (b"explorer.exe", b"Administrator", 1432, 16384, 1248, 14),
        (b"taskmgr.exe", b"Administrator", 2156, 4096, 89, 3),
        (b"cmd.exe", b"Administrator", 2244, 1024, 32, 1),
        (b"notepad.exe", b"Administrator", 2356, 2048, 45, 1),
    ];

    for (name, user, pid, mem, handles, threads) in processes.iter() {
        if state.process_count >= MAX_PROCESSES {
            break;
        }
        let mut proc = ProcessEntry::new();
        proc.pid = *pid;
        proc.set_name(name);
        proc.set_user(user);
        proc.mem_usage = *mem;
        proc.peak_mem = *mem + 512;
        proc.handles = *handles;
        proc.threads = *threads;
        proc.cpu_usage = if *pid == 0 { 9500 } else { (*pid % 500) as u32 };

        let idx = state.process_count;
        state.processes[idx] = proc;
        state.process_count += 1;
    }

    state.performance.total_processes = state.process_count as u32;
    state.performance.total_threads = state.processes[..state.process_count]
        .iter()
        .map(|p| p.threads)
        .sum();
    state.performance.total_handles = state.processes[..state.process_count]
        .iter()
        .map(|p| p.handles)
        .sum();
}

/// Add sample applications
fn add_sample_applications(state: &mut TaskManagerState) {
    let apps: [(&[u8], u32, u32); 4] = [
        (b"Windows Task Manager", 2156, 1),
        (b"Command Prompt", 2244, 2),
        (b"Untitled - Notepad", 2356, 3),
        (b"Windows Explorer", 1432, 4),
    ];

    for (name, pid, hwnd) in apps.iter() {
        if state.app_count >= MAX_APPLICATIONS {
            break;
        }
        let mut app = ApplicationEntry::new();
        app.set_name(name);
        app.pid = *pid;
        app.hwnd = *hwnd;
        app.status = AppStatus::Running;

        let idx = state.app_count;
        state.applications[idx] = app;
        state.app_count += 1;
    }
}

/// Add sample network adapters
fn add_sample_adapters(state: &mut TaskManagerState) {
    let mut adapter = NetworkAdapter::new();
    adapter.set_name(b"Local Area Connection");
    adapter.link_speed = 1_000_000_000; // 1 Gbps
    adapter.connected = true;
    adapter.bytes_sent = 1024 * 1024 * 50;
    adapter.bytes_received = 1024 * 1024 * 200;

    state.adapters[0] = adapter;
    state.adapter_count = 1;
}

/// Add sample users
fn add_sample_users(state: &mut TaskManagerState) {
    let mut user = UserSession::new();
    user.session_id = 0;
    user.set_user(b"Administrator");
    user.status = SessionStatus::Active;

    state.users[0] = user;
    state.user_count = 1;
}

/// Initialize performance data
fn init_performance(state: &mut TaskManagerState) {
    // Add some CPU history
    for i in 0..30 {
        state.performance.add_cpu_sample(((i * 3) % 100) as u8);
    }
}

// ============================================================================
// Application Management
// ============================================================================

/// Get application count
pub fn get_application_count() -> usize {
    TASKMGR_STATE.lock().app_count
}

/// Get application by index
pub fn get_application(index: usize) -> Option<ApplicationEntry> {
    let state = TASKMGR_STATE.lock();
    if index < state.app_count {
        Some(state.applications[index])
    } else {
        None
    }
}

/// End task (application)
pub fn end_task(hwnd: u32) -> bool {
    let mut state = TASKMGR_STATE.lock();

    let mut found_index = None;
    for i in 0..state.app_count {
        if state.applications[i].hwnd == hwnd {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..state.app_count - 1 {
            state.applications[i] = state.applications[i + 1];
        }
        state.app_count -= 1;
        END_TASK_COUNT.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// Switch to application
pub fn switch_to(_hwnd: u32) -> bool {
    // Would bring window to foreground
    true
}

// ============================================================================
// Process Management
// ============================================================================

/// Get process count
pub fn get_process_count() -> usize {
    TASKMGR_STATE.lock().process_count
}

/// Get process by index
pub fn get_process(index: usize) -> Option<ProcessEntry> {
    let state = TASKMGR_STATE.lock();
    if index < state.process_count {
        Some(state.processes[index])
    } else {
        None
    }
}

/// Get process by PID
pub fn get_process_by_pid(pid: u32) -> Option<ProcessEntry> {
    let state = TASKMGR_STATE.lock();
    for i in 0..state.process_count {
        if state.processes[i].pid == pid {
            return Some(state.processes[i]);
        }
    }
    None
}

/// End process
pub fn end_process(pid: u32) -> bool {
    let mut state = TASKMGR_STATE.lock();

    // Don't allow ending System or System Idle Process
    if pid == 0 || pid == 4 {
        return false;
    }

    let mut found_index = None;
    for i in 0..state.process_count {
        if state.processes[i].pid == pid {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..state.process_count - 1 {
            state.processes[i] = state.processes[i + 1];
        }
        state.process_count -= 1;
        state.performance.total_processes = state.process_count as u32;
        true
    } else {
        false
    }
}

/// Set process priority
pub fn set_process_priority(pid: u32, priority: PriorityClass) -> bool {
    let mut state = TASKMGR_STATE.lock();
    for i in 0..state.process_count {
        if state.processes[i].pid == pid {
            state.processes[i].priority = priority;
            state.processes[i].base_priority = priority as u8;
            return true;
        }
    }
    false
}

/// Select process
pub fn select_process(pid: u32) {
    TASKMGR_STATE.lock().selected_pid = pid;
}

/// Get selected process PID
pub fn get_selected_process() -> u32 {
    TASKMGR_STATE.lock().selected_pid
}

// ============================================================================
// Performance Data
// ============================================================================

/// Get performance data
pub fn get_performance() -> PerformanceData {
    TASKMGR_STATE.lock().performance
}

/// Update CPU usage
pub fn update_cpu_usage(usage: u8, kernel: u8) {
    let mut state = TASKMGR_STATE.lock();
    state.performance.add_cpu_sample(usage);
    state.performance.kernel_time = kernel;
    REFRESH_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Update memory stats
pub fn update_memory_stats(available: u64, commit_total: u64) {
    let mut state = TASKMGR_STATE.lock();
    state.performance.available_physical = available;
    state.performance.commit_total = commit_total;
    if commit_total > state.performance.commit_peak {
        state.performance.commit_peak = commit_total;
    }
}

// ============================================================================
// Network Data
// ============================================================================

/// Get network adapter count
pub fn get_adapter_count() -> usize {
    TASKMGR_STATE.lock().adapter_count
}

/// Get network adapter by index
pub fn get_adapter(index: usize) -> Option<NetworkAdapter> {
    let state = TASKMGR_STATE.lock();
    if index < state.adapter_count {
        Some(state.adapters[index])
    } else {
        None
    }
}

// ============================================================================
// User Sessions
// ============================================================================

/// Get user session count
pub fn get_user_count() -> usize {
    TASKMGR_STATE.lock().user_count
}

/// Get user session by index
pub fn get_user(index: usize) -> Option<UserSession> {
    let state = TASKMGR_STATE.lock();
    if index < state.user_count {
        Some(state.users[index])
    } else {
        None
    }
}

/// Disconnect user session
pub fn disconnect_user(session_id: u32) -> bool {
    let mut state = TASKMGR_STATE.lock();
    for i in 0..state.user_count {
        if state.users[i].session_id == session_id {
            state.users[i].status = SessionStatus::Disconnected;
            return true;
        }
    }
    false
}

/// Log off user session
pub fn logoff_user(session_id: u32) -> bool {
    let mut state = TASKMGR_STATE.lock();

    let mut found_index = None;
    for i in 0..state.user_count {
        if state.users[i].session_id == session_id {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..state.user_count - 1 {
            state.users[i] = state.users[i + 1];
        }
        state.user_count -= 1;
        true
    } else {
        false
    }
}

// ============================================================================
// Options and Settings
// ============================================================================

/// Get current tab
pub fn get_current_tab() -> TaskManagerTab {
    TASKMGR_STATE.lock().current_tab
}

/// Set current tab
pub fn set_current_tab(tab: TaskManagerTab) {
    TASKMGR_STATE.lock().current_tab = tab;
}

/// Get options
pub fn get_options() -> TaskManagerOptions {
    TASKMGR_STATE.lock().options
}

/// Set always on top
pub fn set_always_on_top(on_top: bool) {
    TASKMGR_STATE.lock().options.always_on_top = on_top;
}

/// Set update speed
pub fn set_update_speed(speed: u8) {
    TASKMGR_STATE.lock().options.update_speed = speed.min(4);
}

/// Set show kernel times
pub fn set_show_kernel_times(show: bool) {
    TASKMGR_STATE.lock().options.show_kernel_times = show;
}

/// Get visible columns
pub fn get_visible_columns() -> ProcessColumns {
    TASKMGR_STATE.lock().columns
}

/// Set visible columns
pub fn set_visible_columns(columns: ProcessColumns) {
    TASKMGR_STATE.lock().columns = columns;
}

// ============================================================================
// Statistics
// ============================================================================

/// Task Manager statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct TaskManagerStats {
    pub initialized: bool,
    pub app_count: usize,
    pub process_count: usize,
    pub adapter_count: usize,
    pub user_count: usize,
    pub refresh_count: u64,
    pub end_task_count: u32,
}

/// Get Task Manager statistics
pub fn get_stats() -> TaskManagerStats {
    let state = TASKMGR_STATE.lock();
    TaskManagerStats {
        initialized: TASKMGR_INITIALIZED.load(Ordering::Relaxed),
        app_count: state.app_count,
        process_count: state.process_count,
        adapter_count: state.adapter_count,
        user_count: state.user_count,
        refresh_count: REFRESH_COUNT.load(Ordering::Relaxed),
        end_task_count: END_TASK_COUNT.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Task Manager dialog handle
pub type HTASKMGRDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Task Manager dialog
pub fn create_taskmgr_dialog(_parent: super::super::HWND) -> HTASKMGRDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}
