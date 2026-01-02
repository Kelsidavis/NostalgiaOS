//! Task Scheduler Service
//!
//! The Windows Task Scheduler provides scheduled task execution:
//!
//! - **Task Management**: Create, modify, delete scheduled tasks
//! - **Triggers**: Time-based, event-based, logon, startup, idle
//! - **Actions**: Execute programs, send email, show message
//! - **Conditions**: Network, power, idle state requirements
//! - **Security**: Run as specific user, with elevated privileges
//!
//! # Registry Location
//!
//! `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule`
//!
//! Tasks are stored in:
//! `%SystemRoot%\Tasks\` (legacy .job files)
//! `%SystemRoot%\System32\Tasks\` (XML format, Vista+)

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;
use alloc::vec::Vec;

// ============================================================================
// Task Scheduler Constants
// ============================================================================

/// Maximum scheduled tasks
pub const MAX_TASKS: usize = 64;

/// Maximum triggers per task
pub const MAX_TRIGGERS: usize = 8;

/// Maximum actions per task
pub const MAX_ACTIONS: usize = 4;

/// Maximum task name length
pub const MAX_TASK_NAME: usize = 128;

/// Maximum path length
pub const MAX_PATH: usize = 260;

/// Maximum command line arguments length
pub const MAX_ARGUMENTS: usize = 512;

/// Maximum description length
pub const MAX_DESCRIPTION: usize = 256;

/// Maximum author length
pub const MAX_AUTHOR: usize = 64;

// ============================================================================
// Task State
// ============================================================================

/// Task state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum TaskState {
    /// Task is unknown
    Unknown = 0,
    /// Task is disabled
    #[default]
    Disabled = 1,
    /// Task is queued (waiting for trigger)
    Queued = 2,
    /// Task is ready to run
    Ready = 3,
    /// Task is currently running
    Running = 4,
}

impl TaskState {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => TaskState::Unknown,
            1 => TaskState::Disabled,
            2 => TaskState::Queued,
            3 => TaskState::Ready,
            4 => TaskState::Running,
            _ => TaskState::Unknown,
        }
    }
}

// ============================================================================
// Trigger Types
// ============================================================================

/// Trigger type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum TriggerType {
    /// No trigger
    #[default]
    None = 0,
    /// One-time trigger
    Time = 1,
    /// Daily trigger
    Daily = 2,
    /// Weekly trigger
    Weekly = 3,
    /// Monthly trigger
    Monthly = 4,
    /// Monthly day-of-week trigger
    MonthlyDow = 5,
    /// Idle trigger
    Idle = 6,
    /// Registration trigger (on task creation)
    Registration = 7,
    /// Boot trigger (system startup)
    Boot = 8,
    /// Logon trigger (user logon)
    Logon = 9,
    /// Session state change trigger
    SessionStateChange = 10,
    /// Event trigger (event log)
    Event = 11,
}

impl TriggerType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => TriggerType::None,
            1 => TriggerType::Time,
            2 => TriggerType::Daily,
            3 => TriggerType::Weekly,
            4 => TriggerType::Monthly,
            5 => TriggerType::MonthlyDow,
            6 => TriggerType::Idle,
            7 => TriggerType::Registration,
            8 => TriggerType::Boot,
            9 => TriggerType::Logon,
            10 => TriggerType::SessionStateChange,
            11 => TriggerType::Event,
            _ => TriggerType::None,
        }
    }
}

// ============================================================================
// Action Types
// ============================================================================

/// Action type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum ActionType {
    /// Execute a program
    #[default]
    Execute = 0,
    /// Send an email (deprecated)
    SendEmail = 5,
    /// Show a message (deprecated)
    ShowMessage = 6,
    /// COM handler
    ComHandler = 7,
}

impl ActionType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => ActionType::Execute,
            5 => ActionType::SendEmail,
            6 => ActionType::ShowMessage,
            7 => ActionType::ComHandler,
            _ => ActionType::Execute,
        }
    }
}

// ============================================================================
// Run Level
// ============================================================================

/// Task run level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum RunLevel {
    /// Least privileges (default user)
    #[default]
    LeastPrivilege = 0,
    /// Highest available privileges (admin if available)
    HighestAvailable = 1,
}

// ============================================================================
// Logon Type
// ============================================================================

/// Task logon type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum LogonType {
    /// No logon type specified
    #[default]
    None = 0,
    /// Use password for logon
    Password = 1,
    /// Run only when user is logged on
    InteractiveToken = 3,
    /// Use group membership for logon
    Group = 4,
    /// Use Service For User logon
    ServiceForUser = 5,
    /// Interactive or password
    InteractiveTokenOrPassword = 6,
}

// ============================================================================
// Compatibility Mode
// ============================================================================

/// Task compatibility mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum Compatibility {
    /// Task Scheduler 1.0 (AT compatible)
    #[default]
    At = 0,
    /// Windows Vista and later
    V1 = 1,
    /// Windows 7 and later
    V2 = 2,
    /// Windows 8 and later
    V2_1 = 3,
    /// Windows 10 and later
    V2_2 = 4,
}

// ============================================================================
// Instance Policy
// ============================================================================

/// Multiple instances policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum InstancePolicy {
    /// Run new instance in parallel
    #[default]
    Parallel = 0,
    /// Queue new instance
    Queue = 1,
    /// Ignore new instance if running
    IgnoreNew = 2,
    /// Stop existing instance
    StopExisting = 3,
}

// ============================================================================
// Error Codes
// ============================================================================

/// Task Scheduler error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TaskError {
    /// Success
    Success = 0,
    /// Task not found
    TaskNotFound = 0x80041322,
    /// Invalid parameter
    InvalidParameter = 0x80041313,
    /// Maximum tasks reached
    MaxTasksReached = 0x80041324,
    /// Maximum triggers reached
    MaxTriggersReached = 0x80041325,
    /// Access denied
    AccessDenied = 0x80041305,
    /// Invalid task
    InvalidTask = 0x80041323,
    /// Invalid state
    InvalidState = 0x80041326,
    /// Task already exists
    TaskAlreadyExists = 0x80041327,
    /// Service not running
    ServiceNotRunning = 0x80041328,
}

// ============================================================================
// Trigger
// ============================================================================

/// Task trigger configuration
#[repr(C)]
#[derive(Clone)]
pub struct TaskTrigger {
    /// Trigger type
    pub trigger_type: TriggerType,
    /// Start time (tick count or scheduled time)
    pub start_time: u64,
    /// End time (optional, 0 = no end)
    pub end_time: u64,
    /// Repetition interval (seconds, 0 = no repeat)
    pub repetition_interval: u32,
    /// Repetition duration (seconds, 0 = indefinite)
    pub repetition_duration: u32,
    /// Stop at duration end
    pub stop_at_duration_end: bool,
    /// Trigger enabled
    pub enabled: bool,
    /// Trigger ID
    pub id: [u8; 32],

    // For daily/weekly/monthly triggers
    /// Days interval (for daily)
    pub days_interval: u16,
    /// Days of week bitmap (for weekly)
    pub days_of_week: u8,
    /// Weeks interval (for weekly)
    pub weeks_interval: u16,
    /// Days of month bitmap (for monthly)
    pub days_of_month: u32,
    /// Months of year bitmap
    pub months_of_year: u16,

    // For logon trigger
    /// User ID for logon trigger
    pub user_id: [u8; 64],

    /// Trigger valid
    pub valid: bool,
}

impl TaskTrigger {
    pub const fn empty() -> Self {
        Self {
            trigger_type: TriggerType::None,
            start_time: 0,
            end_time: 0,
            repetition_interval: 0,
            repetition_duration: 0,
            stop_at_duration_end: false,
            enabled: true,
            id: [0; 32],
            days_interval: 1,
            days_of_week: 0,
            weeks_interval: 1,
            days_of_month: 0,
            months_of_year: 0,
            user_id: [0; 64],
            valid: false,
        }
    }

    /// Create a one-time trigger
    pub fn one_time(start_time: u64) -> Self {
        let mut trigger = Self::empty();
        trigger.trigger_type = TriggerType::Time;
        trigger.start_time = start_time;
        trigger.valid = true;
        trigger
    }

    /// Create a daily trigger
    pub fn daily(start_time: u64, days_interval: u16) -> Self {
        let mut trigger = Self::empty();
        trigger.trigger_type = TriggerType::Daily;
        trigger.start_time = start_time;
        trigger.days_interval = days_interval;
        trigger.valid = true;
        trigger
    }

    /// Create a boot trigger
    pub fn at_boot() -> Self {
        let mut trigger = Self::empty();
        trigger.trigger_type = TriggerType::Boot;
        trigger.valid = true;
        trigger
    }

    /// Create a logon trigger
    pub fn at_logon() -> Self {
        let mut trigger = Self::empty();
        trigger.trigger_type = TriggerType::Logon;
        trigger.valid = true;
        trigger
    }

    /// Check if trigger should fire now
    pub fn should_fire(&self, current_time: u64) -> bool {
        if !self.valid || !self.enabled {
            return false;
        }

        // Check if past end time
        if self.end_time > 0 && current_time > self.end_time {
            return false;
        }

        match self.trigger_type {
            TriggerType::Time => {
                current_time >= self.start_time
            }
            TriggerType::Boot | TriggerType::Registration => {
                // These fire once after task creation/boot
                true
            }
            TriggerType::Daily | TriggerType::Weekly | TriggerType::Monthly => {
                // Simplified: check if start time passed
                current_time >= self.start_time
            }
            _ => false,
        }
    }
}

// ============================================================================
// Action
// ============================================================================

/// Task action configuration
#[repr(C)]
#[derive(Clone)]
pub struct TaskAction {
    /// Action type
    pub action_type: ActionType,
    /// Program path (for Execute)
    pub path: [u8; MAX_PATH],
    /// Command line arguments
    pub arguments: [u8; MAX_ARGUMENTS],
    /// Working directory
    pub working_directory: [u8; MAX_PATH],
    /// Action ID
    pub id: [u8; 32],
    /// Action valid
    pub valid: bool,
}

impl TaskAction {
    pub const fn empty() -> Self {
        Self {
            action_type: ActionType::Execute,
            path: [0; MAX_PATH],
            arguments: [0; MAX_ARGUMENTS],
            working_directory: [0; MAX_PATH],
            id: [0; 32],
            valid: false,
        }
    }

    /// Create an execute action
    pub fn execute(path: &str, arguments: &str) -> Self {
        let mut action = Self::empty();
        action.action_type = ActionType::Execute;
        action.set_path(path);
        action.set_arguments(arguments);
        action.valid = true;
        action
    }

    pub fn set_path(&mut self, path: &str) {
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_PATH - 1);
        self.path[..len].copy_from_slice(&bytes[..len]);
        self.path[len] = 0;
    }

    pub fn path_str(&self) -> &str {
        let len = self.path.iter().position(|&b| b == 0).unwrap_or(MAX_PATH);
        core::str::from_utf8(&self.path[..len]).unwrap_or("")
    }

    pub fn set_arguments(&mut self, args: &str) {
        let bytes = args.as_bytes();
        let len = bytes.len().min(MAX_ARGUMENTS - 1);
        self.arguments[..len].copy_from_slice(&bytes[..len]);
        self.arguments[len] = 0;
    }

    pub fn arguments_str(&self) -> &str {
        let len = self.arguments.iter().position(|&b| b == 0).unwrap_or(MAX_ARGUMENTS);
        core::str::from_utf8(&self.arguments[..len]).unwrap_or("")
    }
}

// ============================================================================
// Task Settings
// ============================================================================

/// Task settings
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TaskSettings {
    /// Allow task to be run on demand
    pub allow_demand_start: bool,
    /// Start when available (if scheduled start was missed)
    pub start_when_available: bool,
    /// Restart on failure
    pub restart_on_failure: bool,
    /// Number of restart attempts
    pub restart_count: u32,
    /// Restart interval (seconds)
    pub restart_interval: u32,
    /// Execution time limit (seconds, 0 = no limit)
    pub execution_time_limit: u32,
    /// Delete task after expiration
    pub delete_expired_task_after: u32,
    /// Priority (0-10, default 7)
    pub priority: u32,
    /// Multiple instances policy
    pub multiple_instances: InstancePolicy,
    /// Compatibility mode
    pub compatibility: Compatibility,
    /// Hidden task
    pub hidden: bool,
    /// Run only if idle
    pub run_only_if_idle: bool,
    /// Idle duration required (seconds)
    pub idle_duration: u32,
    /// Wait for idle timeout (seconds)
    pub idle_wait_timeout: u32,
    /// Stop if no longer idle
    pub stop_on_idle_end: bool,
    /// Restart on idle resume
    pub restart_on_idle: bool,
    /// Disallow start on batteries
    pub disallow_start_on_batteries: bool,
    /// Stop if going on batteries
    pub stop_on_batteries: bool,
    /// Allow hard terminate
    pub allow_hard_terminate: bool,
    /// Wake to run
    pub wake_to_run: bool,
    /// Run only if network available
    pub run_only_if_network_available: bool,
    /// Network name (if network required)
    pub network_name: [u8; 64],
}

impl TaskSettings {
    pub const fn new() -> Self {
        Self {
            allow_demand_start: true,
            start_when_available: false,
            restart_on_failure: false,
            restart_count: 0,
            restart_interval: 0,
            execution_time_limit: 72 * 3600, // 72 hours
            delete_expired_task_after: 0,
            priority: 7,
            multiple_instances: InstancePolicy::IgnoreNew,
            compatibility: Compatibility::V2,
            hidden: false,
            run_only_if_idle: false,
            idle_duration: 0,
            idle_wait_timeout: 0,
            stop_on_idle_end: false,
            restart_on_idle: false,
            disallow_start_on_batteries: false,
            stop_on_batteries: false,
            allow_hard_terminate: true,
            wake_to_run: false,
            run_only_if_network_available: false,
            network_name: [0; 64],
        }
    }
}

impl Default for TaskSettings {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Principal (Security Context)
// ============================================================================

/// Task principal (security context)
#[repr(C)]
#[derive(Clone)]
pub struct TaskPrincipal {
    /// Principal ID
    pub id: [u8; 64],
    /// User ID to run as
    pub user_id: [u8; 64],
    /// Logon type
    pub logon_type: LogonType,
    /// Run level
    pub run_level: RunLevel,
    /// Display name
    pub display_name: [u8; 64],
}

impl TaskPrincipal {
    pub const fn new() -> Self {
        Self {
            id: [0; 64],
            user_id: [0; 64],
            logon_type: LogonType::InteractiveToken,
            run_level: RunLevel::LeastPrivilege,
            display_name: [0; 64],
        }
    }

    pub fn set_user_id(&mut self, user: &str) {
        let bytes = user.as_bytes();
        let len = bytes.len().min(63);
        self.user_id[..len].copy_from_slice(&bytes[..len]);
        self.user_id[len] = 0;
    }

    pub fn user_id_str(&self) -> &str {
        let len = self.user_id.iter().position(|&b| b == 0).unwrap_or(64);
        core::str::from_utf8(&self.user_id[..len]).unwrap_or("")
    }
}

impl Default for TaskPrincipal {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Task Run Instance
// ============================================================================

/// Running task instance
#[repr(C)]
pub struct TaskInstance {
    /// Instance ID
    pub instance_id: u64,
    /// Task ID reference
    pub task_id: u64,
    /// Start time
    pub start_time: u64,
    /// Current state
    pub state: AtomicU32,
    /// Action index being executed
    pub current_action: u32,
    /// Process ID (if running external program)
    pub process_id: u32,
    /// Exit code (when finished)
    pub exit_code: i32,
    /// Instance active
    pub active: bool,
}

impl TaskInstance {
    pub const fn empty() -> Self {
        Self {
            instance_id: 0,
            task_id: 0,
            start_time: 0,
            state: AtomicU32::new(TaskState::Queued as u32),
            current_action: 0,
            process_id: 0,
            exit_code: 0,
            active: false,
        }
    }

    pub fn get_state(&self) -> TaskState {
        TaskState::from_u32(self.state.load(Ordering::SeqCst))
    }

    pub fn set_state(&self, state: TaskState) {
        self.state.store(state as u32, Ordering::SeqCst);
    }
}

// ============================================================================
// Task Definition
// ============================================================================

/// Complete task definition
#[repr(C)]
pub struct Task {
    /// Task ID (unique)
    pub task_id: u64,
    /// Task name
    pub name: [u8; MAX_TASK_NAME],
    /// Task path (folder location)
    pub path: [u8; MAX_PATH],
    /// Description
    pub description: [u8; MAX_DESCRIPTION],
    /// Author
    pub author: [u8; MAX_AUTHOR],

    /// Task state
    pub state: AtomicU32,
    /// Last run time
    pub last_run_time: u64,
    /// Last run result
    pub last_run_result: i32,
    /// Next run time
    pub next_run_time: u64,
    /// Number of times run
    pub run_count: u64,

    /// Registration date
    pub registration_date: u64,

    /// Triggers
    pub triggers: [TaskTrigger; MAX_TRIGGERS],
    /// Trigger count
    pub trigger_count: usize,

    /// Actions
    pub actions: [TaskAction; MAX_ACTIONS],
    /// Action count
    pub action_count: usize,

    /// Settings
    pub settings: TaskSettings,

    /// Principal
    pub principal: TaskPrincipal,

    /// Task enabled
    pub enabled: bool,
    /// Task valid
    pub valid: bool,
}

impl Task {
    pub const fn empty() -> Self {
        Self {
            task_id: 0,
            name: [0; MAX_TASK_NAME],
            path: [0; MAX_PATH],
            description: [0; MAX_DESCRIPTION],
            author: [0; MAX_AUTHOR],
            state: AtomicU32::new(TaskState::Disabled as u32),
            last_run_time: 0,
            last_run_result: 0,
            next_run_time: 0,
            run_count: 0,
            registration_date: 0,
            triggers: [const { TaskTrigger::empty() }; MAX_TRIGGERS],
            trigger_count: 0,
            actions: [const { TaskAction::empty() }; MAX_ACTIONS],
            action_count: 0,
            settings: TaskSettings::new(),
            principal: TaskPrincipal::new(),
            enabled: true,
            valid: false,
        }
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_TASK_NAME - 1);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name[len] = 0;
    }

    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(MAX_TASK_NAME);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub fn set_path(&mut self, path: &str) {
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_PATH - 1);
        self.path[..len].copy_from_slice(&bytes[..len]);
        self.path[len] = 0;
    }

    pub fn path_str(&self) -> &str {
        let len = self.path.iter().position(|&b| b == 0).unwrap_or(MAX_PATH);
        core::str::from_utf8(&self.path[..len]).unwrap_or("")
    }

    pub fn set_description(&mut self, desc: &str) {
        let bytes = desc.as_bytes();
        let len = bytes.len().min(MAX_DESCRIPTION - 1);
        self.description[..len].copy_from_slice(&bytes[..len]);
        self.description[len] = 0;
    }

    pub fn get_state(&self) -> TaskState {
        TaskState::from_u32(self.state.load(Ordering::SeqCst))
    }

    pub fn set_state(&self, state: TaskState) {
        self.state.store(state as u32, Ordering::SeqCst);
    }

    /// Add a trigger
    pub fn add_trigger(&mut self, trigger: TaskTrigger) -> Result<(), TaskError> {
        if self.trigger_count >= MAX_TRIGGERS {
            return Err(TaskError::MaxTriggersReached);
        }
        self.triggers[self.trigger_count] = trigger;
        self.trigger_count += 1;
        Ok(())
    }

    /// Add an action
    pub fn add_action(&mut self, action: TaskAction) -> Result<(), TaskError> {
        if self.action_count >= MAX_ACTIONS {
            return Err(TaskError::InvalidParameter);
        }
        self.actions[self.action_count] = action;
        self.action_count += 1;
        Ok(())
    }

    /// Calculate next run time based on triggers
    pub fn calculate_next_run(&mut self, current_time: u64) {
        let mut earliest: u64 = u64::MAX;

        for i in 0..self.trigger_count {
            if !self.triggers[i].valid || !self.triggers[i].enabled {
                continue;
            }

            let trigger_time = match self.triggers[i].trigger_type {
                TriggerType::Time => {
                    if self.triggers[i].start_time > current_time {
                        self.triggers[i].start_time
                    } else {
                        u64::MAX
                    }
                }
                TriggerType::Daily => {
                    // Simplified: next occurrence after current time
                    let mut next = self.triggers[i].start_time;
                    let interval_ms = self.triggers[i].days_interval as u64 * 24 * 60 * 60 * 1000;
                    while next <= current_time {
                        next += interval_ms;
                    }
                    next
                }
                _ => u64::MAX,
            };

            if trigger_time < earliest {
                earliest = trigger_time;
            }
        }

        self.next_run_time = if earliest == u64::MAX { 0 } else { earliest };
    }
}

// ============================================================================
// Scheduler State
// ============================================================================

/// Maximum running instances
pub const MAX_INSTANCES: usize = 16;

/// Scheduler service state
#[repr(C)]
pub struct SchedulerState {
    /// Registered tasks
    pub tasks: [Task; MAX_TASKS],
    /// Task count
    pub task_count: usize,
    /// Next task ID
    pub next_task_id: u64,
    /// Running instances
    pub instances: [TaskInstance; MAX_INSTANCES],
    /// Instance count
    pub instance_count: usize,
    /// Next instance ID
    pub next_instance_id: u64,
    /// Service running
    pub running: bool,
}

impl SchedulerState {
    pub const fn new() -> Self {
        Self {
            tasks: [const { Task::empty() }; MAX_TASKS],
            task_count: 0,
            next_task_id: 1,
            instances: [const { TaskInstance::empty() }; MAX_INSTANCES],
            instance_count: 0,
            next_instance_id: 1,
            running: false,
        }
    }
}

/// Global scheduler state
static SCHEDULER_STATE: SpinLock<SchedulerState> = SpinLock::new(SchedulerState::new());

/// Scheduler statistics
pub struct SchedulerStats {
    /// Tasks created
    pub tasks_created: AtomicU64,
    /// Tasks deleted
    pub tasks_deleted: AtomicU64,
    /// Tasks run
    pub tasks_run: AtomicU64,
    /// Task runs succeeded
    pub runs_succeeded: AtomicU64,
    /// Task runs failed
    pub runs_failed: AtomicU64,
    /// Missed runs (task missed scheduled time)
    pub missed_runs: AtomicU64,
}

impl SchedulerStats {
    pub const fn new() -> Self {
        Self {
            tasks_created: AtomicU64::new(0),
            tasks_deleted: AtomicU64::new(0),
            tasks_run: AtomicU64::new(0),
            runs_succeeded: AtomicU64::new(0),
            runs_failed: AtomicU64::new(0),
            missed_runs: AtomicU64::new(0),
        }
    }
}

static SCHEDULER_STATS: SchedulerStats = SchedulerStats::new();

// ============================================================================
// Scheduler API
// ============================================================================

/// Create a new scheduled task
pub fn create_task(name: &str, path: &str) -> Result<u64, TaskError> {
    let mut state = SCHEDULER_STATE.lock();

    if !state.running {
        return Err(TaskError::ServiceNotRunning);
    }

    // Check for existing task with same name
    for i in 0..MAX_TASKS {
        if state.tasks[i].valid && state.tasks[i].name_str() == name {
            return Err(TaskError::TaskAlreadyExists);
        }
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_TASKS {
        if !state.tasks[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(TaskError::MaxTasksReached),
    };

    let task_id = state.next_task_id;
    state.next_task_id += 1;

    let current_time = crate::hal::apic::get_tick_count();

    let task = &mut state.tasks[slot];
    *task = Task::empty();
    task.task_id = task_id;
    task.set_name(name);
    task.set_path(path);
    task.registration_date = current_time;
    task.set_state(TaskState::Disabled);
    task.valid = true;

    state.task_count += 1;

    SCHEDULER_STATS.tasks_created.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[SCHEDULER] Created task {} '{}'", task_id, name);

    Ok(task_id)
}

/// Add trigger to task
pub fn add_task_trigger(task_id: u64, trigger: TaskTrigger) -> Result<(), TaskError> {
    let mut state = SCHEDULER_STATE.lock();

    let task = find_task_mut(&mut state, task_id)?;

    task.add_trigger(trigger)?;

    let current_time = crate::hal::apic::get_tick_count();
    task.calculate_next_run(current_time);

    Ok(())
}

/// Add action to task
pub fn add_task_action(task_id: u64, action: TaskAction) -> Result<(), TaskError> {
    let mut state = SCHEDULER_STATE.lock();

    let task = find_task_mut(&mut state, task_id)?;

    task.add_action(action)?;

    Ok(())
}

/// Enable a task
pub fn enable_task(task_id: u64) -> Result<(), TaskError> {
    let mut state = SCHEDULER_STATE.lock();

    let task = find_task_mut(&mut state, task_id)?;

    if task.action_count == 0 {
        return Err(TaskError::InvalidTask);
    }

    task.enabled = true;
    task.set_state(TaskState::Ready);

    let current_time = crate::hal::apic::get_tick_count();
    task.calculate_next_run(current_time);

    crate::serial_println!("[SCHEDULER] Enabled task {} '{}'",
        task_id, task.name_str());

    Ok(())
}

/// Disable a task
pub fn disable_task(task_id: u64) -> Result<(), TaskError> {
    let mut state = SCHEDULER_STATE.lock();

    let task = find_task_mut(&mut state, task_id)?;

    task.enabled = false;
    task.set_state(TaskState::Disabled);

    crate::serial_println!("[SCHEDULER] Disabled task {} '{}'",
        task_id, task.name_str());

    Ok(())
}

/// Delete a task
pub fn delete_task(task_id: u64) -> Result<(), TaskError> {
    let mut state = SCHEDULER_STATE.lock();

    let task = find_task_mut(&mut state, task_id)?;

    let name = task.name_str();
    crate::serial_println!("[SCHEDULER] Deleting task {} '{}'", task_id, name);

    task.valid = false;
    state.task_count = state.task_count.saturating_sub(1);

    SCHEDULER_STATS.tasks_deleted.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Run a task immediately (on demand)
pub fn run_task(task_id: u64) -> Result<u64, TaskError> {
    let mut state = SCHEDULER_STATE.lock();

    // Verify task exists and is ready
    {
        let task = find_task_mut(&mut state, task_id)?;

        if !task.enabled {
            return Err(TaskError::InvalidState);
        }

        if task.action_count == 0 {
            return Err(TaskError::InvalidTask);
        }

        if !task.settings.allow_demand_start {
            return Err(TaskError::AccessDenied);
        }
    }

    // Check if already running
    let task_state = {
        let task = find_task_mut(&mut state, task_id)?;
        task.get_state()
    };

    if task_state == TaskState::Running {
        let policy = {
            let task = find_task_mut(&mut state, task_id)?;
            task.settings.multiple_instances
        };
        match policy {
            InstancePolicy::IgnoreNew => return Err(TaskError::InvalidState),
            InstancePolicy::StopExisting => {
                // Would stop existing, for now just proceed
            }
            _ => {}
        }
    }

    // Find free instance slot
    let mut slot = None;
    for i in 0..MAX_INSTANCES {
        if !state.instances[i].active {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(TaskError::InvalidState),
    };

    let instance_id = state.next_instance_id;
    state.next_instance_id += 1;

    let current_time = crate::hal::apic::get_tick_count();

    state.instances[slot] = TaskInstance::empty();
    state.instances[slot].instance_id = instance_id;
    state.instances[slot].task_id = task_id;
    state.instances[slot].start_time = current_time;
    state.instances[slot].set_state(TaskState::Running);
    state.instances[slot].active = true;

    state.instance_count += 1;

    // Update task state
    {
        let task = find_task_mut(&mut state, task_id)?;
        task.set_state(TaskState::Running);
        task.last_run_time = current_time;
        task.run_count += 1;
    }

    SCHEDULER_STATS.tasks_run.fetch_add(1, Ordering::Relaxed);

    let task_name = {
        let task = find_task_mut(&mut state, task_id)?;
        task.name_str()
    };

    crate::serial_println!("[SCHEDULER] Running task {} '{}' (instance {})",
        task_id, task_name, instance_id);

    Ok(instance_id)
}

/// Get task state
pub fn get_task_state(task_id: u64) -> Result<TaskState, TaskError> {
    let state = SCHEDULER_STATE.lock();

    for i in 0..MAX_TASKS {
        if state.tasks[i].valid && state.tasks[i].task_id == task_id {
            return Ok(state.tasks[i].get_state());
        }
    }

    Err(TaskError::TaskNotFound)
}

/// Enumerate all tasks
pub fn enumerate_tasks() -> Vec<u64> {
    let state = SCHEDULER_STATE.lock();
    let mut result = Vec::new();

    for i in 0..MAX_TASKS {
        if state.tasks[i].valid {
            result.push(state.tasks[i].task_id);
        }
    }

    result
}

/// Get task info
pub fn get_task_info(task_id: u64) -> Result<(TaskState, u64, u64, i32), TaskError> {
    let state = SCHEDULER_STATE.lock();

    for i in 0..MAX_TASKS {
        if state.tasks[i].valid && state.tasks[i].task_id == task_id {
            return Ok((
                state.tasks[i].get_state(),
                state.tasks[i].last_run_time,
                state.tasks[i].next_run_time,
                state.tasks[i].last_run_result,
            ));
        }
    }

    Err(TaskError::TaskNotFound)
}

// ============================================================================
// Scheduler Processing
// ============================================================================

/// Process scheduled tasks (called periodically)
pub fn process_tasks() {
    let mut state = SCHEDULER_STATE.lock();

    if !state.running {
        return;
    }

    let current_time = crate::hal::apic::get_tick_count();

    // Check each enabled task
    for i in 0..MAX_TASKS {
        if !state.tasks[i].valid || !state.tasks[i].enabled {
            continue;
        }

        let task_state = state.tasks[i].get_state();
        if task_state == TaskState::Running {
            continue;
        }

        // Check triggers
        for j in 0..state.tasks[i].trigger_count {
            if state.tasks[i].triggers[j].should_fire(current_time) {
                // Trigger fired - queue task for execution
                let task_id = state.tasks[i].task_id;
                let task_name = state.tasks[i].name_str();

                crate::serial_println!("[SCHEDULER] Trigger fired for task {} '{}'",
                    task_id, task_name);

                state.tasks[i].set_state(TaskState::Queued);

                // For one-time triggers, disable after firing
                if state.tasks[i].triggers[j].trigger_type == TriggerType::Time {
                    state.tasks[i].triggers[j].enabled = false;
                }

                break;
            }
        }

        // Update next run time
        state.tasks[i].calculate_next_run(current_time);
    }

    // Process running instances
    for i in 0..MAX_INSTANCES {
        if !state.instances[i].active {
            continue;
        }

        // Check execution time limit
        let task_id = state.instances[i].task_id;

        // Find task settings
        let mut time_limit = 0u32;
        for j in 0..MAX_TASKS {
            if state.tasks[j].valid && state.tasks[j].task_id == task_id {
                time_limit = state.tasks[j].settings.execution_time_limit;
                break;
            }
        }

        if time_limit > 0 {
            let elapsed = current_time - state.instances[i].start_time;
            if elapsed > (time_limit as u64 * 1000) {
                // Task exceeded time limit
                crate::serial_println!("[SCHEDULER] Task instance {} exceeded time limit",
                    state.instances[i].instance_id);

                state.instances[i].set_state(TaskState::Ready);
                state.instances[i].exit_code = -1;
                state.instances[i].active = false;
                state.instance_count = state.instance_count.saturating_sub(1);

                SCHEDULER_STATS.runs_failed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Complete a running task instance
pub fn complete_instance(instance_id: u64, exit_code: i32) -> Result<(), TaskError> {
    let mut state = SCHEDULER_STATE.lock();

    for i in 0..MAX_INSTANCES {
        if state.instances[i].active && state.instances[i].instance_id == instance_id {
            state.instances[i].set_state(TaskState::Ready);
            state.instances[i].exit_code = exit_code;
            state.instances[i].active = false;
            state.instance_count = state.instance_count.saturating_sub(1);

            // Update task
            let task_id = state.instances[i].task_id;
            for j in 0..MAX_TASKS {
                if state.tasks[j].valid && state.tasks[j].task_id == task_id {
                    state.tasks[j].set_state(TaskState::Ready);
                    state.tasks[j].last_run_result = exit_code;
                    break;
                }
            }

            if exit_code == 0 {
                SCHEDULER_STATS.runs_succeeded.fetch_add(1, Ordering::Relaxed);
            } else {
                SCHEDULER_STATS.runs_failed.fetch_add(1, Ordering::Relaxed);
            }

            crate::serial_println!("[SCHEDULER] Instance {} completed with exit code {}",
                instance_id, exit_code);

            return Ok(());
        }
    }

    Err(TaskError::TaskNotFound)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Find task by ID (mutable)
fn find_task_mut(state: &mut SchedulerState, task_id: u64) -> Result<&mut Task, TaskError> {
    for i in 0..MAX_TASKS {
        if state.tasks[i].valid && state.tasks[i].task_id == task_id {
            return Ok(&mut state.tasks[i]);
        }
    }
    Err(TaskError::TaskNotFound)
}

/// Get scheduler statistics
pub fn get_statistics() -> (u64, u64, u64, u64, u64, u64) {
    (
        SCHEDULER_STATS.tasks_created.load(Ordering::Relaxed),
        SCHEDULER_STATS.tasks_deleted.load(Ordering::Relaxed),
        SCHEDULER_STATS.tasks_run.load(Ordering::Relaxed),
        SCHEDULER_STATS.runs_succeeded.load(Ordering::Relaxed),
        SCHEDULER_STATS.runs_failed.load(Ordering::Relaxed),
        SCHEDULER_STATS.missed_runs.load(Ordering::Relaxed),
    )
}

/// Get task count
pub fn get_task_count() -> usize {
    let state = SCHEDULER_STATE.lock();
    state.task_count
}

/// Get running instance count
pub fn get_instance_count() -> usize {
    let state = SCHEDULER_STATE.lock();
    state.instance_count
}

/// Check if scheduler is running
pub fn is_running() -> bool {
    let state = SCHEDULER_STATE.lock();
    state.running
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the Task Scheduler service
pub fn init() {
    crate::serial_println!("[SCHEDULER] Initializing Task Scheduler Service...");

    let mut state = SCHEDULER_STATE.lock();
    state.running = true;

    crate::serial_println!("[SCHEDULER] Task Scheduler initialized (max {} tasks)",
        MAX_TASKS);
}

/// Shutdown the Task Scheduler service
pub fn shutdown() {
    crate::serial_println!("[SCHEDULER] Shutting down Task Scheduler...");

    let mut state = SCHEDULER_STATE.lock();

    // Cancel all running instances
    for i in 0..MAX_INSTANCES {
        if state.instances[i].active {
            state.instances[i].active = false;
        }
    }

    state.running = false;

    let (created, deleted, run, succeeded, failed, _) = get_statistics();
    crate::serial_println!("[SCHEDULER] Stats: {} created, {} deleted, {} run ({} ok, {} failed)",
        created, deleted, run, succeeded, failed);
}
