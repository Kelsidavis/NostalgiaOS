//! Run Dialog
//!
//! Provides the Windows Run dialog (Win+R) implementation following
//! the shell32 RunFileDlg pattern.
//!
//! # References
//!
//! - Windows Server 2003 shell32 run dialog
//! - RunFileDlg API

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle};

// ============================================================================
// Constants
// ============================================================================

/// Maximum command line length
const MAX_COMMAND_LENGTH: usize = 2048;

/// Maximum history entries
const MAX_HISTORY_ENTRIES: usize = 26;

/// Maximum browse filter length
const MAX_FILTER_LENGTH: usize = 256;

/// Run dialog flags (RFF_*)
pub mod run_flags {
    /// Prevent access to subfolders
    pub const NOBROWSE: u32 = 0x00000001;
    /// No working directory edit
    pub const NODEFAULT: u32 = 0x00000002;
    /// No calc extension
    pub const CALCDIRECTORY: u32 = 0x00000004;
    /// No validate
    pub const NOLABEL: u32 = 0x00000008;
    /// No separate memory
    pub const NOSEPARATEMEM: u32 = 0x00000020;
}

/// Run dialog result
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunResult {
    /// User cancelled
    Cancelled = 0,
    /// Command executed successfully
    Success = 1,
    /// Command not found
    NotFound = 2,
    /// Access denied
    AccessDenied = 3,
    /// Invalid path
    InvalidPath = 4,
    /// Execution error
    ExecutionError = 5,
}

/// Run command type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunCommandType {
    #[default]
    /// Normal application
    Application = 0,
    /// Document (open with associated app)
    Document = 1,
    /// URL
    Url = 2,
    /// Shell command (control panel, etc)
    ShellCommand = 3,
    /// Console application
    Console = 4,
    /// Administrative tool
    AdminTool = 5,
}

// ============================================================================
// Structures
// ============================================================================

/// Run dialog configuration
#[derive(Debug, Clone, Copy)]
pub struct RunDialogConfig {
    /// Parent window
    pub hwnd_parent: HWND,
    /// Dialog flags
    pub flags: u32,
    /// Working directory path hash
    pub working_dir_hash: u64,
    /// Icon resource ID
    pub icon_id: u32,
    /// Title text offset in buffer
    pub title_offset: u16,
    /// Description text offset
    pub description_offset: u16,
    /// Filter offset
    pub filter_offset: u16,
}

impl RunDialogConfig {
    pub const fn new() -> Self {
        Self {
            hwnd_parent: UserHandle::NULL,
            flags: 0,
            working_dir_hash: 0,
            icon_id: 0,
            title_offset: 0,
            description_offset: 0,
            filter_offset: 0,
        }
    }
}

/// Run history entry
#[derive(Debug, Clone, Copy)]
pub struct RunHistoryEntry {
    /// Entry is valid
    pub valid: bool,
    /// Command hash (for deduplication)
    pub command_hash: u64,
    /// Command type
    pub command_type: RunCommandType,
    /// Last used timestamp
    pub last_used: u64,
    /// Use count
    pub use_count: u32,
    /// Command length
    pub command_len: u16,
    /// Command bytes (first part)
    pub command: [u8; 128],
}

impl RunHistoryEntry {
    const fn new() -> Self {
        Self {
            valid: false,
            command_hash: 0,
            command_type: RunCommandType::Application,
            last_used: 0,
            use_count: 0,
            command_len: 0,
            command: [0; 128],
        }
    }
}

/// Run dialog state
#[derive(Debug, Clone, Copy)]
pub struct RunDialogState {
    /// Dialog is active
    pub active: bool,
    /// Dialog handle
    pub hwnd: HWND,
    /// Current command length
    pub command_len: u16,
    /// Autocomplete suggestion index
    pub autocomplete_index: i32,
    /// Browse mode active
    pub browse_mode: bool,
}

impl RunDialogState {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            command_len: 0,
            autocomplete_index: -1,
            browse_mode: false,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static RUNDLG_INITIALIZED: AtomicBool = AtomicBool::new(false);
static RUNDLG_LOCK: SpinLock<()> = SpinLock::new(());
static RUN_COUNT: AtomicU32 = AtomicU32::new(0);

static HISTORY: SpinLock<[RunHistoryEntry; MAX_HISTORY_ENTRIES]> =
    SpinLock::new([const { RunHistoryEntry::new() }; MAX_HISTORY_ENTRIES]);

static CURRENT_STATE: SpinLock<RunDialogState> = SpinLock::new(RunDialogState::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize run dialog subsystem
pub fn init() {
    let _guard = RUNDLG_LOCK.lock();

    if RUNDLG_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[RUNDLG] Initializing run dialog...");

    // Initialize common history entries
    init_common_history();

    RUNDLG_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[RUNDLG] Run dialog initialized");
}

/// Initialize common history entries
fn init_common_history() {
    let common_commands: &[(&[u8], RunCommandType)] = &[
        (b"cmd", RunCommandType::Console),
        (b"notepad", RunCommandType::Application),
        (b"calc", RunCommandType::Application),
        (b"mspaint", RunCommandType::Application),
        (b"regedit", RunCommandType::AdminTool),
        (b"taskmgr", RunCommandType::Application),
        (b"control", RunCommandType::ShellCommand),
        (b"devmgmt.msc", RunCommandType::AdminTool),
        (b"services.msc", RunCommandType::AdminTool),
        (b"eventvwr.msc", RunCommandType::AdminTool),
    ];

    let mut history = HISTORY.lock();
    let mut idx = 0;

    for (cmd, cmd_type) in common_commands {
        if idx >= MAX_HISTORY_ENTRIES {
            break;
        }

        let entry = &mut history[idx];
        entry.valid = true;
        entry.command_hash = hash_command(cmd);
        entry.command_type = *cmd_type;
        entry.last_used = 0;
        entry.use_count = 0;
        entry.command_len = cmd.len().min(128) as u16;
        entry.command[..entry.command_len as usize].copy_from_slice(&cmd[..entry.command_len as usize]);

        idx += 1;
    }
}

// ============================================================================
// Run Dialog API
// ============================================================================

/// Show the run dialog
pub fn run_file_dlg(
    hwnd_parent: HWND,
    icon: u32,
    working_dir: Option<&[u8]>,
    title: Option<&[u8]>,
    description: Option<&[u8]>,
    flags: u32,
) -> bool {
    if !RUNDLG_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = CURRENT_STATE.lock();

    if state.active {
        // Already showing a run dialog
        return false;
    }

    // Create the run dialog
    let config = RunDialogConfig {
        hwnd_parent,
        flags,
        working_dir_hash: working_dir.map(hash_command).unwrap_or(0),
        icon_id: icon,
        title_offset: 0,
        description_offset: 0,
        filter_offset: 0,
    };

    // Create dialog window
    let hwnd = create_run_dialog_window(&config, title, description);

    if hwnd == UserHandle::NULL {
        return false;
    }

    state.active = true;
    state.hwnd = hwnd;
    state.command_len = 0;
    state.autocomplete_index = -1;
    state.browse_mode = false;

    RUN_COUNT.fetch_add(1, Ordering::Relaxed);

    true
}

/// Show the run dialog with default settings
pub fn run_file_dlg_simple(hwnd_parent: HWND) -> bool {
    run_file_dlg(hwnd_parent, 0, None, None, None, 0)
}

/// Execute a command from the run dialog
pub fn run_execute_command(command: &[u8]) -> RunResult {
    if command.is_empty() {
        return RunResult::InvalidPath;
    }

    // Determine command type
    let command_type = classify_command(command);

    // Add to history
    add_to_history(command, command_type);

    // Execute based on type
    match command_type {
        RunCommandType::Url => execute_url(command),
        RunCommandType::ShellCommand => execute_shell_command(command),
        RunCommandType::Document => execute_document(command),
        RunCommandType::Console => execute_console(command),
        RunCommandType::AdminTool => execute_admin_tool(command),
        RunCommandType::Application => execute_application(command),
    }
}

/// Close the run dialog
pub fn run_close_dialog() {
    let mut state = CURRENT_STATE.lock();

    if state.active {
        // Destroy dialog window
        if state.hwnd != UserHandle::NULL {
            super::window::destroy_window(state.hwnd);
        }

        state.active = false;
        state.hwnd = UserHandle::NULL;
    }
}

/// Get run dialog state
pub fn run_get_state() -> RunDialogState {
    *CURRENT_STATE.lock()
}

// ============================================================================
// History Management
// ============================================================================

/// Add command to history
pub fn add_to_history(command: &[u8], command_type: RunCommandType) {
    let command_hash = hash_command(command);
    let mut history = HISTORY.lock();

    // Check if already in history
    for entry in history.iter_mut() {
        if entry.valid && entry.command_hash == command_hash {
            entry.use_count += 1;
            entry.last_used = get_timestamp();
            return;
        }
    }

    // Find slot (oldest entry or empty)
    let mut oldest_idx = 0;
    let mut oldest_time = u64::MAX;

    for (idx, entry) in history.iter().enumerate() {
        if !entry.valid {
            oldest_idx = idx;
            break;
        }
        if entry.last_used < oldest_time {
            oldest_time = entry.last_used;
            oldest_idx = idx;
        }
    }

    // Add new entry
    let entry = &mut history[oldest_idx];
    entry.valid = true;
    entry.command_hash = command_hash;
    entry.command_type = command_type;
    entry.last_used = get_timestamp();
    entry.use_count = 1;
    entry.command_len = command.len().min(128) as u16;
    entry.command[..entry.command_len as usize].copy_from_slice(&command[..entry.command_len as usize]);
}

/// Get history entries
/// Returns array of entries and count of valid entries
pub fn get_history() -> ([RunHistoryEntry; MAX_HISTORY_ENTRIES], usize) {
    let history = HISTORY.lock();
    let mut entries = [RunHistoryEntry::new(); MAX_HISTORY_ENTRIES];
    let mut count = 0;

    for entry in history.iter() {
        if entry.valid && count < MAX_HISTORY_ENTRIES {
            entries[count] = *entry;
            count += 1;
        }
    }

    // Simple bubble sort by last used (most recent first)
    for i in 0..count {
        for j in 0..(count - i - 1) {
            if entries[j].last_used < entries[j + 1].last_used {
                entries.swap(j, j + 1);
            }
        }
    }

    (entries, count)
}

/// Clear history
pub fn clear_history() {
    let mut history = HISTORY.lock();
    for entry in history.iter_mut() {
        entry.valid = false;
    }
}

/// Get autocomplete suggestions
/// Returns array of matching entries and count
pub fn get_autocomplete_suggestions(prefix: &[u8]) -> ([RunHistoryEntry; MAX_HISTORY_ENTRIES], usize) {
    let mut matches = [RunHistoryEntry::new(); MAX_HISTORY_ENTRIES];
    let mut count = 0;

    if prefix.is_empty() {
        return (matches, 0);
    }

    let history = HISTORY.lock();

    // Convert prefix to lowercase
    let mut prefix_lower = [0u8; 128];
    let prefix_len = prefix.len().min(128);
    for (i, &b) in prefix[..prefix_len].iter().enumerate() {
        prefix_lower[i] = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
    }

    for entry in history.iter() {
        if !entry.valid || count >= MAX_HISTORY_ENTRIES {
            continue;
        }

        // Convert command to lowercase and check prefix
        let mut cmd_lower = [0u8; 128];
        let cmd_len = entry.command_len as usize;
        for (i, &b) in entry.command[..cmd_len].iter().enumerate() {
            cmd_lower[i] = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
        }

        // Check if command starts with prefix
        if cmd_len >= prefix_len && cmd_lower[..prefix_len] == prefix_lower[..prefix_len] {
            matches[count] = *entry;
            count += 1;
        }
    }

    // Simple bubble sort by use count (most used first)
    for i in 0..count {
        for j in 0..(count - i - 1) {
            if matches[j].use_count < matches[j + 1].use_count {
                matches.swap(j, j + 1);
            }
        }
    }

    (matches, count)
}

// ============================================================================
// Command Classification
// ============================================================================

/// Classify a command
fn classify_command(command: &[u8]) -> RunCommandType {
    // Check for URL
    if command.starts_with(b"http://") || command.starts_with(b"https://") ||
       command.starts_with(b"ftp://") || command.starts_with(b"file://") {
        return RunCommandType::Url;
    }

    // Check for shell commands
    let shell_commands: &[&[u8]] = &[
        b"control", b"shell:", b"::{", b"explorer",
    ];
    for &sc in shell_commands {
        if command.starts_with(sc) {
            return RunCommandType::ShellCommand;
        }
    }

    // Check for admin tools (MSC files)
    if command.ends_with(b".msc") {
        return RunCommandType::AdminTool;
    }

    // Check for console apps
    let console_apps: &[&[u8]] = &[
        b"cmd", b"cmd.exe", b"powershell", b"powershell.exe",
    ];
    // Convert command to lowercase for comparison
    let mut cmd_lower = [0u8; 128];
    let cmd_len = command.len().min(128);
    for (i, &b) in command[..cmd_len].iter().enumerate() {
        cmd_lower[i] = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
    }
    for &app in console_apps {
        if cmd_len == app.len() && cmd_lower[..cmd_len] == *app {
            return RunCommandType::Console;
        }
    }

    // Check for documents
    let doc_extensions: &[&[u8]] = &[
        b".txt", b".doc", b".docx", b".xls", b".xlsx",
        b".pdf", b".rtf", b".htm", b".html",
    ];
    for &ext in doc_extensions {
        if command.ends_with(ext) {
            return RunCommandType::Document;
        }
    }

    RunCommandType::Application
}

// ============================================================================
// Command Execution
// ============================================================================

/// Execute URL
fn execute_url(_url: &[u8]) -> RunResult {
    // Would launch default browser with URL
    RunResult::Success
}

/// Execute shell command
fn execute_shell_command(_command: &[u8]) -> RunResult {
    // Would execute shell command (control panel, etc)
    RunResult::Success
}

/// Execute document
fn execute_document(_path: &[u8]) -> RunResult {
    // Would open document with associated application
    RunResult::Success
}

/// Execute console application
fn execute_console(_command: &[u8]) -> RunResult {
    // Would launch command in new console window
    RunResult::Success
}

/// Execute admin tool
fn execute_admin_tool(_command: &[u8]) -> RunResult {
    // Would launch MMC snap-in
    RunResult::Success
}

/// Execute application
fn execute_application(_command: &[u8]) -> RunResult {
    // Would launch application
    RunResult::Success
}

// ============================================================================
// Dialog Window
// ============================================================================

/// Create run dialog window
fn create_run_dialog_window(
    _config: &RunDialogConfig,
    _title: Option<&[u8]>,
    _description: Option<&[u8]>,
) -> HWND {
    // Would create the actual dialog window
    UserHandle::NULL
}

/// Handle run dialog messages
pub fn run_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    match msg {
        super::message::WM_COMMAND => {
            let id = wparam as u16;
            match id {
                1 => {
                    // OK button - execute command
                    let state = CURRENT_STATE.lock();
                    if state.active && state.hwnd == hwnd {
                        // Get command text and execute
                        // run_execute_command(...)
                        drop(state);
                        run_close_dialog();
                    }
                    1
                }
                2 => {
                    // Cancel button
                    run_close_dialog();
                    0
                }
                3 => {
                    // Browse button
                    let mut state = CURRENT_STATE.lock();
                    if state.active && state.hwnd == hwnd {
                        state.browse_mode = true;
                    }
                    0
                }
                _ => 0,
            }
        }
        super::message::WM_CLOSE => {
            run_close_dialog();
            0
        }
        _ => 0,
    }
}

// ============================================================================
// Path Expansion
// ============================================================================

/// Expand environment variables in path
pub fn expand_run_path(path: &[u8], buffer: &mut [u8]) -> usize {
    // Simple expansion - would use environ module
    let len = path.len().min(buffer.len());
    buffer[..len].copy_from_slice(&path[..len]);
    len
}

/// Resolve command to full path
pub fn resolve_command_path(command: &[u8], buffer: &mut [u8]) -> Option<usize> {
    // Would search PATH for the command
    let len = command.len().min(buffer.len());
    buffer[..len].copy_from_slice(&command[..len]);
    Some(len)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Hash a command for quick comparison
fn hash_command(command: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;

    for &byte in command {
        let b = if byte >= b'A' && byte <= b'Z' { byte + 32 } else { byte };
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }

    hash
}

/// Get current timestamp
fn get_timestamp() -> u64 {
    // Would use proper time source
    0
}

// ============================================================================
// Special Commands
// ============================================================================

/// Well-known shortcuts
pub mod shortcuts {
    pub const CMD: &[u8] = b"cmd";
    pub const POWERSHELL: &[u8] = b"powershell";
    pub const NOTEPAD: &[u8] = b"notepad";
    pub const CALC: &[u8] = b"calc";
    pub const MSPAINT: &[u8] = b"mspaint";
    pub const REGEDIT: &[u8] = b"regedit";
    pub const TASKMGR: &[u8] = b"taskmgr";
    pub const CONTROL: &[u8] = b"control";
    pub const DEVMGMT: &[u8] = b"devmgmt.msc";
    pub const SERVICES: &[u8] = b"services.msc";
    pub const EVENTVWR: &[u8] = b"eventvwr.msc";
    pub const COMPMGMT: &[u8] = b"compmgmt.msc";
    pub const DISKMGMT: &[u8] = b"diskmgmt.msc";
    pub const SYSDM: &[u8] = b"sysdm.cpl";
    pub const APPWIZ: &[u8] = b"appwiz.cpl";
    pub const INETCPL: &[u8] = b"inetcpl.cpl";
    pub const NCPA: &[u8] = b"ncpa.cpl";
    pub const DESK: &[u8] = b"desk.cpl";
    pub const MAIN: &[u8] = b"main.cpl";
    pub const TIMEDATE: &[u8] = b"timedate.cpl";
}

/// Execute a well-known shortcut
pub fn run_shortcut(shortcut: &[u8]) -> RunResult {
    run_execute_command(shortcut)
}
