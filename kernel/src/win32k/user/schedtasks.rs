//! Scheduled Tasks
//!
//! Kernel-mode task scheduler UI following Windows NT patterns.
//! Provides task creation, scheduling, and management.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `admin/services/sched/` - Task scheduler service
//! - `shell/ext/scheduled/` - Scheduled tasks shell extension

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// Constants
// ============================================================================

/// Maximum scheduled tasks
const MAX_TASKS: usize = 128;

/// Maximum task name length
const MAX_NAME: usize = 256;

/// Maximum command length
const MAX_COMMAND: usize = 512;

/// Maximum arguments length
const MAX_ARGS: usize = 512;

/// Maximum working directory length
const MAX_WORKDIR: usize = 260;

/// Maximum comment length
const MAX_COMMENT: usize = 512;

/// Maximum account name length
const MAX_ACCOUNT: usize = 256;

/// Maximum triggers per task
const MAX_TRIGGERS: usize = 8;

/// Task status
pub mod task_status {
    /// Task is ready (enabled)
    pub const READY: u32 = 0;
    /// Task is running
    pub const RUNNING: u32 = 1;
    /// Task is disabled
    pub const DISABLED: u32 = 2;
    /// Task has never run
    pub const NEVER_RUN: u32 = 3;
    /// Task is queued
    pub const QUEUED: u32 = 4;
}

/// Task result codes
pub mod task_result {
    /// Task completed successfully
    pub const SUCCESS: u32 = 0;
    /// Task failed
    pub const FAILED: u32 = 1;
    /// Task was terminated
    pub const TERMINATED: u32 = 2;
    /// Task not scheduled
    pub const NOT_SCHEDULED: u32 = 0x00041303;
    /// Task has not run
    pub const HAS_NOT_RUN: u32 = 0x00041304;
}

/// Trigger types
pub mod trigger_type {
    /// Run once at specified time
    pub const ONCE: u32 = 0;
    /// Run daily
    pub const DAILY: u32 = 1;
    /// Run weekly
    pub const WEEKLY: u32 = 2;
    /// Run monthly
    pub const MONTHLY: u32 = 3;
    /// Run monthly on specific day of week
    pub const MONTHLY_DOW: u32 = 4;
    /// Run when system starts
    pub const ON_LOGON: u32 = 5;
    /// Run when system boots
    pub const ON_BOOT: u32 = 6;
    /// Run when idle
    pub const ON_IDLE: u32 = 7;
    /// Run on event
    pub const ON_EVENT: u32 = 8;
}

/// Days of week flags
pub mod days_of_week {
    pub const SUNDAY: u8 = 0x01;
    pub const MONDAY: u8 = 0x02;
    pub const TUESDAY: u8 = 0x04;
    pub const WEDNESDAY: u8 = 0x08;
    pub const THURSDAY: u8 = 0x10;
    pub const FRIDAY: u8 = 0x20;
    pub const SATURDAY: u8 = 0x40;
    pub const ALL: u8 = 0x7F;
}

/// Months flags
pub mod months {
    pub const JANUARY: u16 = 0x0001;
    pub const FEBRUARY: u16 = 0x0002;
    pub const MARCH: u16 = 0x0004;
    pub const APRIL: u16 = 0x0008;
    pub const MAY: u16 = 0x0010;
    pub const JUNE: u16 = 0x0020;
    pub const JULY: u16 = 0x0040;
    pub const AUGUST: u16 = 0x0080;
    pub const SEPTEMBER: u16 = 0x0100;
    pub const OCTOBER: u16 = 0x0200;
    pub const NOVEMBER: u16 = 0x0400;
    pub const DECEMBER: u16 = 0x0800;
    pub const ALL: u16 = 0x0FFF;
}

/// Task flags
pub mod task_flags {
    /// Run only if logged on
    pub const RUN_ONLY_IF_LOGGED_ON: u32 = 0x0001;
    /// Don't start if on batteries
    pub const DONT_START_ON_BATTERIES: u32 = 0x0002;
    /// Stop if going on batteries
    pub const STOP_ON_BATTERIES: u32 = 0x0004;
    /// Run only if network available
    pub const RUN_IF_CONNECTED: u32 = 0x0008;
    /// Delete when done
    pub const DELETE_WHEN_DONE: u32 = 0x0010;
    /// Wake to run
    pub const WAKE_TO_RUN: u32 = 0x0020;
    /// Hidden task
    pub const HIDDEN: u32 = 0x0040;
    /// Run with highest privileges
    pub const RUN_HIGHEST: u32 = 0x0080;
    /// Allow on demand
    pub const ALLOW_ON_DEMAND: u32 = 0x0100;
    /// Allow hard terminate
    pub const ALLOW_HARD_TERMINATE: u32 = 0x0200;
}

// ============================================================================
// Types
// ============================================================================

/// Task trigger
#[derive(Clone, Copy)]
pub struct TaskTrigger {
    /// Trigger type
    pub trigger_type: u32,
    /// Start date (YYYYMMDD)
    pub start_date: u32,
    /// End date (0 = no end)
    pub end_date: u32,
    /// Start time (HHMM in 24h)
    pub start_time: u16,
    /// Duration (minutes, 0 = no limit)
    pub duration: u32,
    /// Interval (depends on trigger type)
    pub interval: u32,
    /// Days of week (for weekly)
    pub days_of_week: u8,
    /// Days of month (bitmask for monthly)
    pub days_of_month: u32,
    /// Months of year (for monthly)
    pub months_of_year: u16,
    /// Random delay (minutes)
    pub random_delay: u32,
    /// Repeat interval (minutes)
    pub repeat_interval: u32,
    /// Repeat duration (minutes)
    pub repeat_duration: u32,
    /// Stop at duration end
    pub stop_at_end: bool,
    /// Trigger enabled
    pub enabled: bool,
}

impl TaskTrigger {
    pub const fn new() -> Self {
        Self {
            trigger_type: trigger_type::ONCE,
            start_date: 0,
            end_date: 0,
            start_time: 0,
            duration: 0,
            interval: 1,
            days_of_week: 0,
            days_of_month: 0,
            months_of_year: months::ALL,
            random_delay: 0,
            repeat_interval: 0,
            repeat_duration: 0,
            stop_at_end: false,
            enabled: true,
        }
    }
}

/// Scheduled task
#[derive(Clone, Copy)]
pub struct ScheduledTask {
    /// Task name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: u16,
    /// Command to run
    pub command: [u8; MAX_COMMAND],
    /// Command length
    pub cmd_len: u16,
    /// Arguments
    pub arguments: [u8; MAX_ARGS],
    /// Arguments length
    pub args_len: u16,
    /// Working directory
    pub work_dir: [u8; MAX_WORKDIR],
    /// Work dir length
    pub work_dir_len: u16,
    /// Comment/description
    pub comment: [u8; MAX_COMMENT],
    /// Comment length
    pub comment_len: u16,
    /// Account to run as
    pub account: [u8; MAX_ACCOUNT],
    /// Account length
    pub account_len: u16,
    /// Task status
    pub status: u32,
    /// Last run result
    pub last_result: u32,
    /// Last run time (timestamp)
    pub last_run: u64,
    /// Next run time (timestamp)
    pub next_run: u64,
    /// Task flags
    pub flags: u32,
    /// Max run time (minutes, 0 = no limit)
    pub max_runtime: u32,
    /// Idle wait time (minutes)
    pub idle_wait: u32,
    /// Priority (0=realtime to 5=idle)
    pub priority: u8,
    /// Triggers
    pub triggers: [TaskTrigger; MAX_TRIGGERS],
    /// Trigger count
    pub trigger_count: u8,
}

impl ScheduledTask {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_NAME],
            name_len: 0,
            command: [0; MAX_COMMAND],
            cmd_len: 0,
            arguments: [0; MAX_ARGS],
            args_len: 0,
            work_dir: [0; MAX_WORKDIR],
            work_dir_len: 0,
            comment: [0; MAX_COMMENT],
            comment_len: 0,
            account: [0; MAX_ACCOUNT],
            account_len: 0,
            status: task_status::NEVER_RUN,
            last_result: task_result::HAS_NOT_RUN,
            last_run: 0,
            next_run: 0,
            flags: task_flags::ALLOW_ON_DEMAND | task_flags::ALLOW_HARD_TERMINATE,
            max_runtime: 72 * 60, // 72 hours default
            idle_wait: 10,
            priority: 4, // Normal
            triggers: [const { TaskTrigger::new() }; MAX_TRIGGERS],
            trigger_count: 0,
        }
    }
}

/// Task folder (for hierarchical organization)
#[derive(Clone, Copy)]
pub struct TaskFolder {
    /// Folder name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: u16,
    /// Parent folder index (-1 for root)
    pub parent: i16,
    /// Number of tasks in folder
    pub task_count: u32,
}

impl TaskFolder {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_NAME],
            name_len: 0,
            parent: -1,
            task_count: 0,
        }
    }
}

/// Scheduled tasks dialog state
struct ScheduledDialog {
    /// Parent window
    parent: HWND,
    /// Selected task index
    selected: i32,
    /// View mode (0=icons, 1=details)
    view_mode: u32,
    /// Show hidden tasks
    show_hidden: bool,
}

impl ScheduledDialog {
    const fn new() -> Self {
        Self {
            parent: UserHandle::NULL,
            selected: -1,
            view_mode: 1,
            show_hidden: false,
        }
    }
}

// ============================================================================
// Static State
// ============================================================================

/// Module initialized
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Scheduled tasks
static TASKS: SpinLock<[ScheduledTask; MAX_TASKS]> =
    SpinLock::new([const { ScheduledTask::new() }; MAX_TASKS]);

/// Task count
static TASK_COUNT: AtomicU32 = AtomicU32::new(0);

/// Dialog state
static DIALOG: SpinLock<ScheduledDialog> = SpinLock::new(ScheduledDialog::new());

/// Next task ID
static NEXT_TASK_ID: AtomicU32 = AtomicU32::new(1);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize scheduled tasks
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Initialize sample tasks
    init_sample_tasks();

    crate::serial_println!("[SCHEDTASKS] Scheduled tasks initialized");
}

/// Initialize sample system tasks
fn init_sample_tasks() {
    let mut tasks = TASKS.lock();
    let mut count = 0;

    // Disk Cleanup
    {
        let task = &mut tasks[count];
        let name = b"Disk Cleanup";
        let nlen = name.len();
        task.name[..nlen].copy_from_slice(name);
        task.name_len = nlen as u16;

        let cmd = b"cleanmgr.exe";
        let clen = cmd.len();
        task.command[..clen].copy_from_slice(cmd);
        task.cmd_len = clen as u16;

        let args = b"/sagerun:1";
        let alen = args.len();
        task.arguments[..alen].copy_from_slice(args);
        task.args_len = alen as u16;

        let comment = b"Clean up temporary files and free disk space";
        let cmlen = comment.len();
        task.comment[..cmlen].copy_from_slice(comment);
        task.comment_len = cmlen as u16;

        task.triggers[0].trigger_type = trigger_type::WEEKLY;
        task.triggers[0].days_of_week = days_of_week::SUNDAY;
        task.triggers[0].start_time = 0300; // 3:00 AM
        task.triggers[0].enabled = true;
        task.trigger_count = 1;
        task.status = task_status::READY;
        task.flags |= task_flags::RUN_HIGHEST;

        count += 1;
    }

    // Windows Update
    {
        let task = &mut tasks[count];
        let name = b"Windows Update";
        let nlen = name.len();
        task.name[..nlen].copy_from_slice(name);
        task.name_len = nlen as u16;

        let cmd = b"wuauclt.exe";
        let clen = cmd.len();
        task.command[..clen].copy_from_slice(cmd);
        task.cmd_len = clen as u16;

        let args = b"/detectnow";
        let alen = args.len();
        task.arguments[..alen].copy_from_slice(args);
        task.args_len = alen as u16;

        let comment = b"Check for and install Windows updates";
        let cmlen = comment.len();
        task.comment[..cmlen].copy_from_slice(comment);
        task.comment_len = cmlen as u16;

        task.triggers[0].trigger_type = trigger_type::DAILY;
        task.triggers[0].start_time = 0300;
        task.triggers[0].enabled = true;
        task.trigger_count = 1;
        task.status = task_status::READY;
        task.flags |= task_flags::RUN_HIGHEST | task_flags::RUN_IF_CONNECTED;

        count += 1;
    }

    // Disk Defragmenter
    {
        let task = &mut tasks[count];
        let name = b"Disk Defragmenter";
        let nlen = name.len();
        task.name[..nlen].copy_from_slice(name);
        task.name_len = nlen as u16;

        let cmd = b"defrag.exe";
        let clen = cmd.len();
        task.command[..clen].copy_from_slice(cmd);
        task.cmd_len = clen as u16;

        let args = b"C: -f";
        let alen = args.len();
        task.arguments[..alen].copy_from_slice(args);
        task.args_len = alen as u16;

        let comment = b"Defragment hard drives for optimal performance";
        let cmlen = comment.len();
        task.comment[..cmlen].copy_from_slice(comment);
        task.comment_len = cmlen as u16;

        task.triggers[0].trigger_type = trigger_type::WEEKLY;
        task.triggers[0].days_of_week = days_of_week::WEDNESDAY;
        task.triggers[0].start_time = 0100;
        task.triggers[0].enabled = true;
        task.trigger_count = 1;
        task.status = task_status::READY;
        task.flags |= task_flags::DONT_START_ON_BATTERIES | task_flags::STOP_ON_BATTERIES;

        count += 1;
    }

    TASK_COUNT.store(count as u32, Ordering::Release);
}

// ============================================================================
// Task Management
// ============================================================================

/// Get number of scheduled tasks
pub fn get_task_count() -> u32 {
    TASK_COUNT.load(Ordering::Acquire)
}

/// Get task by index
pub fn get_task(index: usize, task: &mut ScheduledTask) -> bool {
    let tasks = TASKS.lock();
    let count = TASK_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    *task = tasks[index];
    true
}

/// Find task by name
pub fn find_task(name: &[u8]) -> Option<usize> {
    let tasks = TASKS.lock();
    let count = TASK_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = tasks[i].name_len as usize;
        if &tasks[i].name[..len] == name {
            return Some(i);
        }
    }
    None
}

/// Create a new task
pub fn create_task(task: &ScheduledTask) -> Option<u32> {
    let mut tasks = TASKS.lock();
    let count = TASK_COUNT.load(Ordering::Acquire) as usize;

    if count >= MAX_TASKS {
        return None;
    }

    let task_id = NEXT_TASK_ID.fetch_add(1, Ordering::SeqCst);
    tasks[count] = *task;

    TASK_COUNT.store((count + 1) as u32, Ordering::Release);

    Some(task_id)
}

/// Delete a task
pub fn delete_task(name: &[u8]) -> bool {
    let mut tasks = TASKS.lock();
    let count = TASK_COUNT.load(Ordering::Acquire) as usize;

    let mut found_index = None;
    for i in 0..count {
        let len = tasks[i].name_len as usize;
        if &tasks[i].name[..len] == name {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..(count - 1) {
            tasks[i] = tasks[i + 1];
        }
        tasks[count - 1] = ScheduledTask::new();
        TASK_COUNT.store((count - 1) as u32, Ordering::Release);
        return true;
    }

    false
}

/// Enable or disable a task
pub fn set_task_enabled(name: &[u8], enabled: bool) -> bool {
    let mut tasks = TASKS.lock();
    let count = TASK_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = tasks[i].name_len as usize;
        if &tasks[i].name[..len] == name {
            tasks[i].status = if enabled {
                task_status::READY
            } else {
                task_status::DISABLED
            };
            return true;
        }
    }
    false
}

/// Run a task immediately
pub fn run_task(name: &[u8]) -> bool {
    let mut tasks = TASKS.lock();
    let count = TASK_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = tasks[i].name_len as usize;
        if &tasks[i].name[..len] == name {
            if tasks[i].status == task_status::DISABLED {
                return false;
            }
            tasks[i].status = task_status::RUNNING;
            // Would spawn process to run the task
            return true;
        }
    }
    false
}

/// Stop a running task
pub fn stop_task(name: &[u8]) -> bool {
    let mut tasks = TASKS.lock();
    let count = TASK_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = tasks[i].name_len as usize;
        if &tasks[i].name[..len] == name {
            if tasks[i].status == task_status::RUNNING {
                tasks[i].status = task_status::READY;
                tasks[i].last_result = task_result::TERMINATED;
                // Would terminate the running process
                return true;
            }
            return false;
        }
    }
    false
}

/// Update task last run info
pub fn update_task_run(name: &[u8], result: u32, run_time: u64) {
    let mut tasks = TASKS.lock();
    let count = TASK_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = tasks[i].name_len as usize;
        if &tasks[i].name[..len] == name {
            tasks[i].last_run = run_time;
            tasks[i].last_result = result;
            tasks[i].status = task_status::READY;
            // Would calculate next run time
            return;
        }
    }
}

// ============================================================================
// Dialog API
// ============================================================================

/// Show scheduled tasks folder
pub fn show_scheduled_tasks(parent: HWND) -> bool {
    let mut dialog = DIALOG.lock();

    dialog.parent = parent;
    dialog.selected = -1;
    dialog.view_mode = 1;
    dialog.show_hidden = false;

    // Would show explorer-style folder with:
    // - Task icons
    // - Add Scheduled Task wizard
    // - Context menu with Run, End, Properties

    true
}

/// Show create task wizard
pub fn show_create_wizard(parent: HWND) -> bool {
    let _ = parent;
    // Would show Scheduled Task Wizard
    true
}

/// Show task properties
pub fn show_task_properties(parent: HWND, name: &[u8]) -> bool {
    let _ = (parent, name);
    // Would show task properties dialog with tabs:
    // - Task, Triggers, Actions, Conditions, Settings
    true
}

/// Show task history
pub fn show_task_history(parent: HWND, name: &[u8]) -> bool {
    let _ = (parent, name);
    // Would show task run history
    true
}
