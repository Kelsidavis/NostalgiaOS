//! Explorer Process Manager
//!
//! Manages the explorer shell as a restartable process. This allows explorer
//! to be killed and restarted without affecting the rest of the system.
//!
//! # Architecture
//!
//! Explorer runs as a managed "process" within the kernel. While not a true
//! user-mode process (it runs in kernel space), it can be:
//! - Started on boot
//! - Stopped (killed) via taskkill or programmatically
//! - Restarted automatically or manually
//!
//! # Usage
//!
//! ```
//! // Start explorer
//! explorer::process::start();
//!
//! // Stop explorer
//! explorer::process::stop();
//!
//! // Restart explorer
//! explorer::process::restart();
//! ```

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::SpinLock;

// ============================================================================
// Process State
// ============================================================================

/// Explorer process ID (always 1 for the shell)
pub const EXPLORER_PID: u32 = 1;

/// Explorer process state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Not started
    NotStarted,
    /// Starting up
    Starting,
    /// Running normally
    Running,
    /// Stopping (shutdown in progress)
    Stopping,
    /// Stopped/Terminated
    Stopped,
    /// Crashed (can be restarted)
    Crashed,
}

/// Explorer process info
pub struct ExplorerProcess {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub name: &'static str,
    /// Image name (for tasklist)
    pub image_name: &'static str,
    /// Current state
    state: SpinLock<ProcessState>,
    /// Running flag (for quick checks)
    running: AtomicBool,
    /// Restart requested flag
    restart_requested: AtomicBool,
    /// Restart count
    restart_count: AtomicU32,
    /// Thread ID (if running)
    thread_id: AtomicU32,
}

impl ExplorerProcess {
    const fn new() -> Self {
        Self {
            pid: EXPLORER_PID,
            name: "Windows Explorer",
            image_name: "explorer.exe",
            state: SpinLock::new(ProcessState::NotStarted),
            running: AtomicBool::new(false),
            restart_requested: AtomicBool::new(false),
            restart_count: AtomicU32::new(0),
            thread_id: AtomicU32::new(0),
        }
    }
}

/// Global explorer process
static EXPLORER_PROCESS: ExplorerProcess = ExplorerProcess::new();

// ============================================================================
// Public API
// ============================================================================

/// Initialize the explorer process manager
pub fn init() {
    crate::serial_println!("[EXPLORER] Process manager initialized");
}

/// Start the explorer process
///
/// This initializes the explorer shell (desktop, taskbar, etc.) and
/// starts the message loop. Called automatically on boot.
pub fn start() -> bool {
    let mut state = EXPLORER_PROCESS.state.lock();

    match *state {
        ProcessState::Running => {
            crate::serial_println!("[EXPLORER] Already running");
            return true;
        }
        ProcessState::Starting => {
            crate::serial_println!("[EXPLORER] Already starting");
            return true;
        }
        _ => {}
    }

    *state = ProcessState::Starting;
    drop(state);

    crate::serial_println!("[EXPLORER] Starting explorer.exe (PID {})", EXPLORER_PID);

    // Initialize the shell components
    super::init();

    // Mark as running
    let mut state = EXPLORER_PROCESS.state.lock();
    *state = ProcessState::Running;
    EXPLORER_PROCESS.running.store(true, Ordering::SeqCst);

    crate::serial_println!("[EXPLORER] explorer.exe started successfully");

    true
}

/// Run the explorer message loop
///
/// This should be called after start() to run the main message pump.
/// Returns when explorer is stopped.
pub fn run() {
    if !EXPLORER_PROCESS.running.load(Ordering::SeqCst) {
        crate::serial_println!("[EXPLORER] Not running, cannot enter message loop");
        return;
    }

    crate::serial_println!("[EXPLORER] Entering message loop");

    // Run the message pump (this blocks until stopped)
    super::run_message_loop();

    // Check if restart was requested
    if EXPLORER_PROCESS.restart_requested.load(Ordering::SeqCst) {
        EXPLORER_PROCESS.restart_requested.store(false, Ordering::SeqCst);

        let count = EXPLORER_PROCESS.restart_count.fetch_add(1, Ordering::SeqCst);
        crate::serial_println!("[EXPLORER] Restart #{} requested, restarting...", count + 1);

        // Small delay before restart
        for _ in 0..100 {
            unsafe { core::arch::asm!("pause"); }
        }

        // Restart
        if start() {
            run();
        }
    }
}

/// Stop the explorer process
///
/// This gracefully shuts down explorer, closing all shell windows.
/// Returns true if explorer was stopped successfully.
pub fn stop() -> bool {
    let mut state = EXPLORER_PROCESS.state.lock();

    match *state {
        ProcessState::Stopped | ProcessState::NotStarted => {
            crate::serial_println!("[EXPLORER] Not running");
            return true;
        }
        ProcessState::Stopping => {
            crate::serial_println!("[EXPLORER] Already stopping");
            return true;
        }
        _ => {}
    }

    *state = ProcessState::Stopping;
    drop(state);

    crate::serial_println!("[EXPLORER] Stopping explorer.exe (PID {})", EXPLORER_PID);

    // Signal the shell to stop
    super::stop();
    EXPLORER_PROCESS.running.store(false, Ordering::SeqCst);

    // Mark as stopped
    let mut state = EXPLORER_PROCESS.state.lock();
    *state = ProcessState::Stopped;

    crate::serial_println!("[EXPLORER] explorer.exe stopped");

    true
}

/// Restart the explorer process
///
/// This stops explorer (if running) and starts it again.
/// Useful when explorer becomes unresponsive or after configuration changes.
pub fn restart() -> bool {
    crate::serial_println!("[EXPLORER] Restart requested");

    // If running, request restart and stop
    if EXPLORER_PROCESS.running.load(Ordering::SeqCst) {
        EXPLORER_PROCESS.restart_requested.store(true, Ordering::SeqCst);
        stop();
        return true;
    }

    // Not running, just start
    start()
}

/// Kill the explorer process (forceful termination)
///
/// This immediately terminates explorer without cleanup.
/// Should only be used when explorer is unresponsive.
pub fn kill() -> bool {
    crate::serial_println!("[EXPLORER] Killing explorer.exe (PID {})", EXPLORER_PID);

    // Force stop
    super::stop();
    EXPLORER_PROCESS.running.store(false, Ordering::SeqCst);

    let mut state = EXPLORER_PROCESS.state.lock();
    *state = ProcessState::Stopped;

    crate::serial_println!("[EXPLORER] explorer.exe killed");

    true
}

/// Check if explorer is running
pub fn is_running() -> bool {
    EXPLORER_PROCESS.running.load(Ordering::SeqCst)
}

/// Get explorer process state
pub fn get_state() -> ProcessState {
    *EXPLORER_PROCESS.state.lock()
}

/// Get explorer process info for tasklist
pub fn get_process_info() -> ExplorerProcessInfo {
    ExplorerProcessInfo {
        pid: EXPLORER_PROCESS.pid,
        name: EXPLORER_PROCESS.name,
        image_name: EXPLORER_PROCESS.image_name,
        state: get_state(),
        restart_count: EXPLORER_PROCESS.restart_count.load(Ordering::Relaxed),
    }
}

/// Explorer process info (for tasklist display)
#[derive(Debug, Clone, Copy)]
pub struct ExplorerProcessInfo {
    pub pid: u32,
    pub name: &'static str,
    pub image_name: &'static str,
    pub state: ProcessState,
    pub restart_count: u32,
}

// ============================================================================
// Process Registration
// ============================================================================

/// Register explorer as a system process
///
/// This makes explorer visible to tasklist and manageable via taskkill.
pub fn register_with_process_manager() {
    // Register with the kernel process manager
    unsafe {
        // Create a pseudo-EPROCESS for explorer
        let proc = crate::ps::create::ps_create_system_process(b"explorer.exe");
        if !proc.is_null() {
            (*proc).unique_process_id = EXPLORER_PID;
            EXPLORER_PROCESS.thread_id.store(EXPLORER_PID, Ordering::SeqCst);
            crate::serial_println!("[EXPLORER] Registered with process manager as PID {}", EXPLORER_PID);
        }
    }
}

/// Check if a PID is the explorer process
pub fn is_explorer_pid(pid: u32) -> bool {
    pid == EXPLORER_PID
}

/// Handle taskkill for explorer
///
/// Called when taskkill targets explorer. Returns true if handled.
pub fn handle_taskkill(pid: u32, force: bool) -> bool {
    if pid != EXPLORER_PID {
        return false;
    }

    if force {
        kill()
    } else {
        stop()
    }
}
