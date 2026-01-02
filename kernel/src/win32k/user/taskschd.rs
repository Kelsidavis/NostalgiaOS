//! Task Scheduler UI
//!
//! Implements Windows Task Scheduler UI and basic scheduling APIs.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/mstask.h` - Task scheduler definitions
//! - `admin/services/sched/` - Task scheduler service

use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use super::HWND;

// ============================================================================
// Constants
// ============================================================================

/// Maximum scheduled tasks
const MAX_TASKS: usize = 64;

/// Maximum task name length
const MAX_TASK_NAME: usize = 256;

/// Maximum command length
const MAX_COMMAND: usize = 260;

/// Maximum parameters length
const MAX_PARAMS: usize = 512;

/// Maximum working directory length
const MAX_WORKDIR: usize = 260;

/// Maximum comment length
const MAX_COMMENT: usize = 512;

/// Maximum triggers per task
const MAX_TRIGGERS: usize = 8;

// ============================================================================
// Task Status
// ============================================================================

/// Task status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TaskStatus {
    #[default]
    Ready = 0,
    Running = 1,
    Suspended = 2,
    LastRunFailed = 3,
    Disabled = 4,
    NotScheduled = 5,
    NoMoreRuns = 6,
    NoValidTriggers = 7,
}

/// Task flags
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct TaskFlags: u32 {
        /// Interactive task
        const INTERACTIVE = 0x00000001;
        /// Delete when done
        const DELETE_WHEN_DONE = 0x00000002;
        /// Disabled
        const DISABLED = 0x00000004;
        /// Start only if idle
        const START_ONLY_IF_IDLE = 0x00000010;
        /// Kill on idle end
        const KILL_ON_IDLE_END = 0x00000020;
        /// Don't start if on batteries
        const DONT_START_IF_ON_BATTERIES = 0x00000040;
        /// Kill if going on batteries
        const KILL_IF_GOING_ON_BATTERIES = 0x00000080;
        /// Run only if docked
        const RUN_ONLY_IF_DOCKED = 0x00000100;
        /// Hidden
        const HIDDEN = 0x00000200;
        /// Run only if logged on
        const RUN_ONLY_IF_LOGGED_ON = 0x00002000;
        /// System required
        const SYSTEM_REQUIRED = 0x00001000;
        /// Restart on idle resume
        const RESTART_ON_IDLE_RESUME = 0x00000800;
    }
}

// ============================================================================
// Trigger Types
// ============================================================================

/// Trigger type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TriggerType {
    #[default]
    Once = 0,
    Daily = 1,
    Weekly = 2,
    MonthlyDate = 3,
    MonthlyDow = 4,
    OnIdle = 5,
    OnRegistration = 6,
    OnBoot = 7,
    OnLogon = 8,
    OnSessionStateChange = 11,
}

/// Days of the week
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct WeekDays: u8 {
        const SUNDAY = 0x01;
        const MONDAY = 0x02;
        const TUESDAY = 0x04;
        const WEDNESDAY = 0x08;
        const THURSDAY = 0x10;
        const FRIDAY = 0x20;
        const SATURDAY = 0x40;
        const ALL = 0x7F;
    }
}

/// Months of the year
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct Months: u16 {
        const JANUARY = 0x001;
        const FEBRUARY = 0x002;
        const MARCH = 0x004;
        const APRIL = 0x008;
        const MAY = 0x010;
        const JUNE = 0x020;
        const JULY = 0x040;
        const AUGUST = 0x080;
        const SEPTEMBER = 0x100;
        const OCTOBER = 0x200;
        const NOVEMBER = 0x400;
        const DECEMBER = 0x800;
        const ALL = 0xFFF;
    }
}

/// Week of month
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WeekOfMonth {
    #[default]
    First = 1,
    Second = 2,
    Third = 3,
    Fourth = 4,
    Last = 5,
}

// ============================================================================
// Trigger Structure
// ============================================================================

/// Task trigger
#[derive(Debug, Clone, Copy)]
pub struct TaskTrigger {
    pub in_use: bool,
    pub trigger_type: TriggerType,
    pub start_hour: u16,
    pub start_minute: u16,
    pub start_day: u16,
    pub start_month: u16,
    pub start_year: u16,
    pub end_day: u16,
    pub end_month: u16,
    pub end_year: u16,
    pub has_end_date: bool,
    pub interval_days: u16,
    pub week_days: WeekDays,
    pub months: Months,
    pub days_of_month: u32,
    pub week_of_month: WeekOfMonth,
    pub random_delay_minutes: u16,
    pub repetition_interval: u32,
    pub repetition_duration: u32,
    pub enabled: bool,
}

impl TaskTrigger {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            trigger_type: TriggerType::Once,
            start_hour: 0,
            start_minute: 0,
            start_day: 1,
            start_month: 1,
            start_year: 2003,
            end_day: 0,
            end_month: 0,
            end_year: 0,
            has_end_date: false,
            interval_days: 1,
            week_days: WeekDays::empty(),
            months: Months::ALL,
            days_of_month: 0,
            week_of_month: WeekOfMonth::First,
            random_delay_minutes: 0,
            repetition_interval: 0,
            repetition_duration: 0,
            enabled: true,
        }
    }
}

impl Default for TaskTrigger {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Task Structure
// ============================================================================

/// Scheduled task
#[derive(Debug)]
struct ScheduledTask {
    in_use: bool,
    id: u32,
    name: [u8; MAX_TASK_NAME],
    command: [u8; MAX_COMMAND],
    parameters: [u8; MAX_PARAMS],
    working_dir: [u8; MAX_WORKDIR],
    comment: [u8; MAX_COMMENT],
    account_name: [u8; 256],
    flags: TaskFlags,
    status: TaskStatus,
    priority: u32,
    max_run_time: u32,
    idle_wait: u32,
    triggers: [TaskTrigger; MAX_TRIGGERS],
    trigger_count: usize,
    last_run: u64,
    next_run: u64,
    exit_code: u32,
}

impl ScheduledTask {
    const fn new() -> Self {
        Self {
            in_use: false,
            id: 0,
            name: [0u8; MAX_TASK_NAME],
            command: [0u8; MAX_COMMAND],
            parameters: [0u8; MAX_PARAMS],
            working_dir: [0u8; MAX_WORKDIR],
            comment: [0u8; MAX_COMMENT],
            account_name: [0u8; 256],
            flags: TaskFlags::empty(),
            status: TaskStatus::Ready,
            priority: 5, // Normal priority
            max_run_time: 72 * 60 * 60 * 1000, // 72 hours in ms
            idle_wait: 10 * 60 * 1000, // 10 minutes
            triggers: [const { TaskTrigger::new() }; MAX_TRIGGERS],
            trigger_count: 0,
            last_run: 0,
            next_run: 0,
            exit_code: 0,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static TASKSCHD_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NEXT_TASK_ID: AtomicU32 = AtomicU32::new(1);
static TASKS: SpinLock<[ScheduledTask; MAX_TASKS]> = SpinLock::new(
    [const { ScheduledTask::new() }; MAX_TASKS]
);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize task scheduler UI
pub fn init() {
    if TASKSCHD_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[TASKSCHD] Initializing task scheduler UI...");
    crate::serial_println!("[TASKSCHD] Task scheduler UI initialized");
}

// ============================================================================
// Task Management Functions
// ============================================================================

/// Create a new scheduled task
pub fn create_task(name: &[u8]) -> Option<u32> {
    let mut tasks = TASKS.lock();

    // Check if task with this name exists
    for task in tasks.iter() {
        if task.in_use && name_matches(&task.name, name) {
            return None;
        }
    }

    // Find free slot
    let slot_idx = tasks.iter().position(|t| !t.in_use);
    let idx = match slot_idx {
        Some(i) => i,
        None => return None,
    };

    let id = NEXT_TASK_ID.fetch_add(1, Ordering::SeqCst);

    let task = &mut tasks[idx];
    *task = ScheduledTask::new();
    task.in_use = true;
    task.id = id;

    let name_len = str_len(name).min(MAX_TASK_NAME - 1);
    task.name[..name_len].copy_from_slice(&name[..name_len]);
    task.name[name_len] = 0;

    Some(id)
}

/// Delete a scheduled task
pub fn delete_task(id: u32) -> bool {
    let mut tasks = TASKS.lock();

    for task in tasks.iter_mut() {
        if task.in_use && task.id == id {
            task.in_use = false;
            return true;
        }
    }

    false
}

/// Delete task by name
pub fn delete_task_by_name(name: &[u8]) -> bool {
    let mut tasks = TASKS.lock();

    for task in tasks.iter_mut() {
        if task.in_use && name_matches(&task.name, name) {
            task.in_use = false;
            return true;
        }
    }

    false
}

/// Find task by name
pub fn find_task(name: &[u8]) -> Option<u32> {
    let tasks = TASKS.lock();

    for task in tasks.iter() {
        if task.in_use && name_matches(&task.name, name) {
            return Some(task.id);
        }
    }

    None
}

// ============================================================================
// Task Configuration Functions
// ============================================================================

/// Set task command
pub fn set_task_command(id: u32, command: &[u8], params: Option<&[u8]>, workdir: Option<&[u8]>) -> bool {
    let mut tasks = TASKS.lock();

    for task in tasks.iter_mut() {
        if task.in_use && task.id == id {
            let cmd_len = str_len(command).min(MAX_COMMAND - 1);
            task.command[..cmd_len].copy_from_slice(&command[..cmd_len]);
            task.command[cmd_len] = 0;

            if let Some(p) = params {
                let p_len = str_len(p).min(MAX_PARAMS - 1);
                task.parameters[..p_len].copy_from_slice(&p[..p_len]);
                task.parameters[p_len] = 0;
            }

            if let Some(w) = workdir {
                let w_len = str_len(w).min(MAX_WORKDIR - 1);
                task.working_dir[..w_len].copy_from_slice(&w[..w_len]);
                task.working_dir[w_len] = 0;
            }

            return true;
        }
    }

    false
}

/// Set task comment
pub fn set_task_comment(id: u32, comment: &[u8]) -> bool {
    let mut tasks = TASKS.lock();

    for task in tasks.iter_mut() {
        if task.in_use && task.id == id {
            let len = str_len(comment).min(MAX_COMMENT - 1);
            task.comment[..len].copy_from_slice(&comment[..len]);
            task.comment[len] = 0;
            return true;
        }
    }

    false
}

/// Set task flags
pub fn set_task_flags(id: u32, flags: TaskFlags) -> bool {
    let mut tasks = TASKS.lock();

    for task in tasks.iter_mut() {
        if task.in_use && task.id == id {
            task.flags = flags;
            task.status = if flags.contains(TaskFlags::DISABLED) {
                TaskStatus::Disabled
            } else {
                TaskStatus::Ready
            };
            return true;
        }
    }

    false
}

/// Set task account
pub fn set_task_account(id: u32, account: &[u8], password: Option<&[u8]>) -> bool {
    let _ = password;

    let mut tasks = TASKS.lock();

    for task in tasks.iter_mut() {
        if task.in_use && task.id == id {
            let len = str_len(account).min(255);
            task.account_name[..len].copy_from_slice(&account[..len]);
            task.account_name[len] = 0;
            return true;
        }
    }

    false
}

/// Set task priority
pub fn set_task_priority(id: u32, priority: u32) -> bool {
    let mut tasks = TASKS.lock();

    for task in tasks.iter_mut() {
        if task.in_use && task.id == id {
            task.priority = priority;
            return true;
        }
    }

    false
}

/// Set task max run time
pub fn set_task_max_run_time(id: u32, milliseconds: u32) -> bool {
    let mut tasks = TASKS.lock();

    for task in tasks.iter_mut() {
        if task.in_use && task.id == id {
            task.max_run_time = milliseconds;
            return true;
        }
    }

    false
}

// ============================================================================
// Trigger Functions
// ============================================================================

/// Add trigger to task
pub fn add_task_trigger(id: u32, trigger: &TaskTrigger) -> bool {
    let mut tasks = TASKS.lock();

    for task in tasks.iter_mut() {
        if task.in_use && task.id == id {
            if task.trigger_count >= MAX_TRIGGERS {
                return false;
            }

            let mut new_trigger = *trigger;
            new_trigger.in_use = true;
            task.triggers[task.trigger_count] = new_trigger;
            task.trigger_count += 1;
            return true;
        }
    }

    false
}

/// Remove trigger from task
pub fn remove_task_trigger(id: u32, trigger_index: usize) -> bool {
    let mut tasks = TASKS.lock();

    for task in tasks.iter_mut() {
        if task.in_use && task.id == id {
            if trigger_index >= task.trigger_count {
                return false;
            }

            // Shift remaining triggers
            for i in trigger_index..task.trigger_count - 1 {
                task.triggers[i] = task.triggers[i + 1];
            }

            task.trigger_count -= 1;
            task.triggers[task.trigger_count].in_use = false;
            return true;
        }
    }

    false
}

/// Get trigger count
pub fn get_trigger_count(id: u32) -> Option<usize> {
    let tasks = TASKS.lock();

    for task in tasks.iter() {
        if task.in_use && task.id == id {
            return Some(task.trigger_count);
        }
    }

    None
}

// ============================================================================
// Task Status Functions
// ============================================================================

/// Get task status
pub fn get_task_status(id: u32) -> Option<TaskStatus> {
    let tasks = TASKS.lock();

    for task in tasks.iter() {
        if task.in_use && task.id == id {
            return Some(task.status);
        }
    }

    None
}

/// Get task last run time
pub fn get_task_last_run(id: u32) -> Option<u64> {
    let tasks = TASKS.lock();

    for task in tasks.iter() {
        if task.in_use && task.id == id {
            return Some(task.last_run);
        }
    }

    None
}

/// Get task next run time
pub fn get_task_next_run(id: u32) -> Option<u64> {
    let tasks = TASKS.lock();

    for task in tasks.iter() {
        if task.in_use && task.id == id {
            return Some(task.next_run);
        }
    }

    None
}

/// Get task exit code
pub fn get_task_exit_code(id: u32) -> Option<u32> {
    let tasks = TASKS.lock();

    for task in tasks.iter() {
        if task.in_use && task.id == id {
            return Some(task.exit_code);
        }
    }

    None
}

// ============================================================================
// Task Control Functions
// ============================================================================

/// Run task now
pub fn run_task(id: u32) -> bool {
    let mut tasks = TASKS.lock();

    for task in tasks.iter_mut() {
        if task.in_use && task.id == id {
            if task.status == TaskStatus::Disabled {
                return false;
            }

            task.status = TaskStatus::Running;
            crate::serial_println!("[TASKSCHD] Running task {}", id);
            return true;
        }
    }

    false
}

/// Stop running task
pub fn stop_task(id: u32) -> bool {
    let mut tasks = TASKS.lock();

    for task in tasks.iter_mut() {
        if task.in_use && task.id == id {
            if task.status == TaskStatus::Running {
                task.status = TaskStatus::Ready;
                crate::serial_println!("[TASKSCHD] Stopped task {}", id);
                return true;
            }
            return false;
        }
    }

    false
}

/// Enable/disable task
pub fn enable_task(id: u32, enable: bool) -> bool {
    let mut tasks = TASKS.lock();

    for task in tasks.iter_mut() {
        if task.in_use && task.id == id {
            if enable {
                task.flags.remove(TaskFlags::DISABLED);
                task.status = TaskStatus::Ready;
            } else {
                task.flags.insert(TaskFlags::DISABLED);
                task.status = TaskStatus::Disabled;
            }
            return true;
        }
    }

    false
}

// ============================================================================
// Task Enumeration
// ============================================================================

/// Task enumeration callback
pub type TaskEnumCallback = fn(id: u32, name: &[u8], status: TaskStatus, lparam: usize) -> bool;

/// Enumerate all tasks
pub fn enum_tasks(callback: TaskEnumCallback, lparam: usize) -> bool {
    let tasks = TASKS.lock();

    for task in tasks.iter() {
        if task.in_use {
            let name_len = str_len(&task.name);
            if !callback(task.id, &task.name[..name_len], task.status, lparam) {
                return false;
            }
        }
    }

    true
}

/// Get task count
pub fn get_task_count() -> u32 {
    let tasks = TASKS.lock();
    tasks.iter().filter(|t| t.in_use).count() as u32
}

// ============================================================================
// Task Scheduler UI
// ============================================================================

/// Show task properties dialog
pub fn show_task_properties(hwnd: HWND, id: u32) -> bool {
    let _ = (hwnd, id);

    crate::serial_println!("[TASKSCHD] Task properties dialog for task {}", id);
    true
}

/// Show new task wizard
pub fn show_new_task_wizard(hwnd: HWND) -> Option<u32> {
    let _ = hwnd;

    crate::serial_println!("[TASKSCHD] New task wizard");
    None
}

/// Show task scheduler folder
pub fn show_task_scheduler_folder(hwnd: HWND) -> bool {
    let _ = hwnd;

    crate::serial_println!("[TASKSCHD] Task scheduler folder");
    true
}

// ============================================================================
// Helper Functions
// ============================================================================

fn str_len(s: &[u8]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

fn name_matches(stored: &[u8], search: &[u8]) -> bool {
    let stored_len = str_len(stored);
    let search_len = str_len(search);

    if stored_len != search_len {
        return false;
    }

    for i in 0..stored_len {
        if stored[i].to_ascii_uppercase() != search[i].to_ascii_uppercase() {
            return false;
        }
    }

    true
}

// ============================================================================
// Statistics
// ============================================================================

/// Task scheduler statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct TaskSchdStats {
    pub initialized: bool,
    pub task_count: u32,
    pub running_count: u32,
    pub disabled_count: u32,
}

/// Get task scheduler statistics
pub fn get_stats() -> TaskSchdStats {
    let tasks = TASKS.lock();

    let mut running = 0u32;
    let mut disabled = 0u32;
    let mut total = 0u32;

    for task in tasks.iter() {
        if task.in_use {
            total += 1;
            match task.status {
                TaskStatus::Running => running += 1,
                TaskStatus::Disabled => disabled += 1,
                _ => {}
            }
        }
    }

    TaskSchdStats {
        initialized: TASKSCHD_INITIALIZED.load(Ordering::Relaxed),
        task_count: total,
        running_count: running,
        disabled_count: disabled,
    }
}
