//! Windows Remote Management (WinRM)
//!
//! WinRM implements the WS-Management protocol for remote management:
//!
//! - **Remote Shell**: Execute commands on remote systems
//! - **Remote PowerShell**: PowerShell remoting support
//! - **Event Subscriptions**: Remote event collection
//! - **Hardware Management**: IPMI/BMC support
//!
//! Uses HTTP/HTTPS on ports 5985/5986 with SOAP-based messaging.

extern crate alloc;

use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use crate::ke::SpinLock;
use crate::hal::apic::get_tick_count;

// ============================================================================
// Constants
// ============================================================================

/// WinRM HTTP port
pub const WINRM_HTTP_PORT: u16 = 5985;

/// WinRM HTTPS port
pub const WINRM_HTTPS_PORT: u16 = 5986;

/// Maximum sessions
pub const MAX_WINRM_SESSIONS: usize = 4;

/// Maximum shells per session
pub const MAX_SHELLS: usize = 2;

/// Maximum commands per shell
pub const MAX_COMMANDS: usize = 4;

/// Maximum subscriptions
pub const MAX_SUBSCRIPTIONS: usize = 4;

/// Maximum message size
pub const MAX_MESSAGE_SIZE: usize = 4096;

/// Command output buffer size
pub const OUTPUT_BUFFER_SIZE: usize = 256;

/// WS-Management namespace
pub const WSMAN_NAMESPACE: &str = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd";

// ============================================================================
// Error Types
// ============================================================================

/// WinRM error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WinRmError {
    /// Success
    Success = 0,
    /// Invalid parameter
    InvalidParameter = 0x80070057,
    /// Access denied
    AccessDenied = 0x80070005,
    /// Session not found
    SessionNotFound = 0x80338000,
    /// Shell not found
    ShellNotFound = 0x80338001,
    /// Command not found
    CommandNotFound = 0x80338002,
    /// Operation timeout
    OperationTimeout = 0x80338029,
    /// Quota exceeded
    QuotaExceeded = 0x8033802D,
    /// Service not available
    ServiceNotAvailable = 0x803380E5,
    /// Shell terminated
    ShellTerminated = 0x80338030,
    /// Not initialized
    NotInitialized = 0x80338031,
    /// Invalid message
    InvalidMessage = 0x80338032,
    /// Authentication failed
    AuthenticationFailed = 0x80338033,
    /// Encryption required
    EncryptionRequired = 0x80338034,
    /// Subscription not found
    SubscriptionNotFound = 0x80338035,
}

// ============================================================================
// Session and Shell Types
// ============================================================================

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionState {
    /// Not established
    NotEstablished = 0,
    /// Authenticating
    Authenticating = 1,
    /// Active
    Active = 2,
    /// Disconnected
    Disconnected = 3,
    /// Closed
    Closed = 4,
}

/// Shell state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ShellState {
    /// Not created
    NotCreated = 0,
    /// Idle
    Idle = 1,
    /// Running
    Running = 2,
    /// Terminated
    Terminated = 3,
}

/// Command state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandState {
    /// Pending
    Pending = 0,
    /// Running
    Running = 1,
    /// Done
    Done = 2,
    /// Failed
    Failed = 3,
}

/// Authentication type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthType {
    /// Basic authentication
    Basic = 0,
    /// NTLM (Negotiate)
    Negotiate = 1,
    /// Kerberos
    Kerberos = 2,
    /// CredSSP
    CredSSP = 3,
    /// Certificate
    Certificate = 4,
}

// ============================================================================
// Data Structures
// ============================================================================

/// WinRM session
#[derive(Debug, Clone)]
pub struct WinRmSession {
    /// Session in use
    pub in_use: bool,
    /// Session ID
    pub session_id: u64,
    /// Session state
    pub state: SessionState,
    /// Authentication type
    pub auth_type: AuthType,
    /// Client address
    pub client_addr: [u8; 16],
    pub client_addr_len: usize,
    /// Username
    pub username: [u8; 64],
    pub username_len: usize,
    /// Creation time
    pub creation_time: u64,
    /// Last activity
    pub last_activity: u64,
    /// Operation timeout (ms)
    pub operation_timeout: u32,
    /// Maximum envelope size
    pub max_envelope_size: u32,
    /// Shells for this session
    pub shells: [WinRmShell; MAX_SHELLS],
    pub shell_count: usize,
}

impl WinRmSession {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            session_id: 0,
            state: SessionState::NotEstablished,
            auth_type: AuthType::Negotiate,
            client_addr: [0u8; 16],
            client_addr_len: 0,
            username: [0u8; 64],
            username_len: 0,
            creation_time: 0,
            last_activity: 0,
            operation_timeout: 60000, // 60 seconds default
            max_envelope_size: MAX_MESSAGE_SIZE as u32,
            shells: [const { WinRmShell::empty() }; MAX_SHELLS],
            shell_count: 0,
        }
    }
}

/// Remote shell
#[derive(Debug, Clone)]
pub struct WinRmShell {
    /// Shell in use
    pub in_use: bool,
    /// Shell ID
    pub shell_id: u64,
    /// Shell state
    pub state: ShellState,
    /// Working directory
    pub working_dir: [u8; 256],
    pub working_dir_len: usize,
    /// Environment variables count
    pub env_count: usize,
    /// Creation time
    pub creation_time: u64,
    /// Idle timeout (ms)
    pub idle_timeout: u32,
    /// Commands in this shell
    pub commands: [WinRmCommand; MAX_COMMANDS],
    pub command_count: usize,
}

impl WinRmShell {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            shell_id: 0,
            state: ShellState::NotCreated,
            working_dir: [0u8; 256],
            working_dir_len: 0,
            env_count: 0,
            creation_time: 0,
            idle_timeout: 180000, // 3 minutes default
            commands: [const { WinRmCommand::empty() }; MAX_COMMANDS],
            command_count: 0,
        }
    }
}

/// Remote command
#[derive(Debug, Clone)]
pub struct WinRmCommand {
    /// Command in use
    pub in_use: bool,
    /// Command ID
    pub command_id: u64,
    /// Command state
    pub state: CommandState,
    /// Command line
    pub command_line: [u8; 512],
    pub command_line_len: usize,
    /// Exit code
    pub exit_code: i32,
    /// Standard output
    pub stdout: [u8; OUTPUT_BUFFER_SIZE],
    pub stdout_len: usize,
    /// Standard error
    pub stderr: [u8; OUTPUT_BUFFER_SIZE],
    pub stderr_len: usize,
    /// Start time
    pub start_time: u64,
    /// End time (0 if still running)
    pub end_time: u64,
}

impl WinRmCommand {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            command_id: 0,
            state: CommandState::Pending,
            command_line: [0u8; 512],
            command_line_len: 0,
            exit_code: 0,
            stdout: [0u8; OUTPUT_BUFFER_SIZE],
            stdout_len: 0,
            stderr: [0u8; OUTPUT_BUFFER_SIZE],
            stderr_len: 0,
            start_time: 0,
            end_time: 0,
        }
    }
}

/// Event subscription
#[derive(Debug, Clone)]
pub struct EventSubscription {
    /// Subscription in use
    pub in_use: bool,
    /// Subscription ID
    pub subscription_id: u64,
    /// Event source
    pub source: [u8; 128],
    pub source_len: usize,
    /// Filter query
    pub filter: [u8; 256],
    pub filter_len: usize,
    /// Delivery mode
    pub delivery_mode: DeliveryMode,
    /// Creation time
    pub creation_time: u64,
    /// Expiration time (0 = no expiry)
    pub expiration_time: u64,
    /// Events delivered
    pub events_delivered: u64,
}

impl EventSubscription {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            subscription_id: 0,
            source: [0u8; 128],
            source_len: 0,
            filter: [0u8; 256],
            filter_len: 0,
            delivery_mode: DeliveryMode::Push,
            creation_time: 0,
            expiration_time: 0,
            events_delivered: 0,
        }
    }
}

/// Event delivery mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryMode {
    /// Push (server sends events)
    Push = 0,
    /// Pull (client polls for events)
    Pull = 1,
}

/// WinRM configuration
#[derive(Debug, Clone)]
pub struct WinRmConfig {
    /// Service enabled
    pub enabled: bool,
    /// Allow HTTP (unencrypted)
    pub allow_http: bool,
    /// Allow basic authentication
    pub allow_basic: bool,
    /// Allow negotiate authentication
    pub allow_negotiate: bool,
    /// Allow Kerberos authentication
    pub allow_kerberos: bool,
    /// Allow CredSSP authentication
    pub allow_credssp: bool,
    /// Maximum concurrent users
    pub max_concurrent_users: u32,
    /// Maximum shells per user
    pub max_shells_per_user: u32,
    /// Maximum memory per shell (MB)
    pub max_memory_per_shell: u32,
    /// Maximum processes per shell
    pub max_processes_per_shell: u32,
    /// Idle timeout (seconds)
    pub idle_timeout_secs: u32,
    /// Maximum concurrent operations
    pub max_concurrent_ops: u32,
}

impl WinRmConfig {
    pub const fn new() -> Self {
        Self {
            enabled: true,
            allow_http: false, // HTTPS only by default
            allow_basic: false,
            allow_negotiate: true,
            allow_kerberos: true,
            allow_credssp: false,
            max_concurrent_users: 5,
            max_shells_per_user: 5,
            max_memory_per_shell: 150, // 150 MB
            max_processes_per_shell: 15,
            idle_timeout_secs: 7200, // 2 hours
            max_concurrent_ops: 100,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// WinRM service state
struct WinRmState {
    /// Initialized flag
    initialized: bool,
    /// Configuration
    config: WinRmConfig,
    /// Active sessions
    sessions: [WinRmSession; MAX_WINRM_SESSIONS],
    session_count: usize,
    /// Event subscriptions
    subscriptions: [EventSubscription; MAX_SUBSCRIPTIONS],
    subscription_count: usize,
    /// Next session ID
    next_session_id: u64,
    /// Next shell ID
    next_shell_id: u64,
    /// Next command ID
    next_command_id: u64,
    /// Next subscription ID
    next_subscription_id: u64,
}

impl WinRmState {
    const fn new() -> Self {
        Self {
            initialized: false,
            config: WinRmConfig::new(),
            sessions: [const { WinRmSession::empty() }; MAX_WINRM_SESSIONS],
            session_count: 0,
            subscriptions: [const { EventSubscription::empty() }; MAX_SUBSCRIPTIONS],
            subscription_count: 0,
            next_session_id: 1,
            next_shell_id: 1,
            next_command_id: 1,
            next_subscription_id: 1,
        }
    }
}

static WINRM_STATE: SpinLock<WinRmState> = SpinLock::new(WinRmState::new());

/// WinRM statistics
struct WinRmStats {
    /// Sessions created
    sessions_created: AtomicU64,
    /// Sessions closed
    sessions_closed: AtomicU64,
    /// Shells created
    shells_created: AtomicU64,
    /// Commands executed
    commands_executed: AtomicU64,
    /// Commands succeeded
    commands_succeeded: AtomicU64,
    /// Commands failed
    commands_failed: AtomicU64,
    /// Authentication failures
    auth_failures: AtomicU64,
    /// Events delivered
    events_delivered: AtomicU64,
}

static WINRM_STATS: WinRmStats = WinRmStats {
    sessions_created: AtomicU64::new(0),
    sessions_closed: AtomicU64::new(0),
    shells_created: AtomicU64::new(0),
    commands_executed: AtomicU64::new(0),
    commands_succeeded: AtomicU64::new(0),
    commands_failed: AtomicU64::new(0),
    auth_failures: AtomicU64::new(0),
    events_delivered: AtomicU64::new(0),
};

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the WinRM service
pub fn init() {
    crate::serial_println!("[WINRM] Initializing Windows Remote Management...");

    let mut state = WINRM_STATE.lock();

    if state.initialized {
        crate::serial_println!("[WINRM] Already initialized");
        return;
    }

    state.initialized = true;

    crate::serial_println!("[WINRM] Windows Remote Management initialized");
}

// ============================================================================
// Session Management
// ============================================================================

/// Create a new WinRM session
pub fn winrm_create_session(auth_type: AuthType) -> Result<u64, WinRmError> {
    let mut state = WINRM_STATE.lock();

    if !state.initialized {
        return Err(WinRmError::NotInitialized);
    }

    if !state.config.enabled {
        return Err(WinRmError::ServiceNotAvailable);
    }

    if state.session_count >= MAX_WINRM_SESSIONS {
        return Err(WinRmError::QuotaExceeded);
    }

    // Check authentication type allowed
    match auth_type {
        AuthType::Basic if !state.config.allow_basic => {
            WINRM_STATS.auth_failures.fetch_add(1, Ordering::Relaxed);
            return Err(WinRmError::AuthenticationFailed);
        }
        AuthType::Negotiate if !state.config.allow_negotiate => {
            WINRM_STATS.auth_failures.fetch_add(1, Ordering::Relaxed);
            return Err(WinRmError::AuthenticationFailed);
        }
        AuthType::Kerberos if !state.config.allow_kerberos => {
            WINRM_STATS.auth_failures.fetch_add(1, Ordering::Relaxed);
            return Err(WinRmError::AuthenticationFailed);
        }
        AuthType::CredSSP if !state.config.allow_credssp => {
            WINRM_STATS.auth_failures.fetch_add(1, Ordering::Relaxed);
            return Err(WinRmError::AuthenticationFailed);
        }
        _ => {}
    }

    let session_id = state.next_session_id;
    state.next_session_id += 1;

    for i in 0..MAX_WINRM_SESSIONS {
        if !state.sessions[i].in_use {
            state.sessions[i].in_use = true;
            state.sessions[i].session_id = session_id;
            state.sessions[i].state = SessionState::Authenticating;
            state.sessions[i].auth_type = auth_type;
            state.sessions[i].creation_time = get_tick_count();
            state.sessions[i].last_activity = state.sessions[i].creation_time;

            state.session_count += 1;
            WINRM_STATS.sessions_created.fetch_add(1, Ordering::Relaxed);

            return Ok(session_id);
        }
    }

    Err(WinRmError::QuotaExceeded)
}

/// Complete session authentication
pub fn winrm_authenticate_session(session_id: u64, username: &[u8]) -> Result<(), WinRmError> {
    let mut state = WINRM_STATE.lock();

    if !state.initialized {
        return Err(WinRmError::NotInitialized);
    }

    for i in 0..MAX_WINRM_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            let ulen = username.len().min(64);
            state.sessions[i].username[..ulen].copy_from_slice(&username[..ulen]);
            state.sessions[i].username_len = ulen;
            state.sessions[i].state = SessionState::Active;
            state.sessions[i].last_activity = get_tick_count();

            return Ok(());
        }
    }

    Err(WinRmError::SessionNotFound)
}

/// Close a session
pub fn winrm_close_session(session_id: u64) -> Result<(), WinRmError> {
    let mut state = WINRM_STATE.lock();

    if !state.initialized {
        return Err(WinRmError::NotInitialized);
    }

    for i in 0..MAX_WINRM_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            state.sessions[i] = WinRmSession::empty();
            if state.session_count > 0 {
                state.session_count -= 1;
            }
            WINRM_STATS.sessions_closed.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(WinRmError::SessionNotFound)
}

// ============================================================================
// Shell Operations
// ============================================================================

/// Create a remote shell
pub fn winrm_create_shell(session_id: u64) -> Result<u64, WinRmError> {
    let mut state = WINRM_STATE.lock();

    if !state.initialized {
        return Err(WinRmError::NotInitialized);
    }

    let max_shells = state.config.max_shells_per_user as usize;

    for i in 0..MAX_WINRM_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            if state.sessions[i].state != SessionState::Active {
                return Err(WinRmError::SessionNotFound);
            }

            if state.sessions[i].shell_count >= max_shells.min(MAX_SHELLS) {
                return Err(WinRmError::QuotaExceeded);
            }

            let shell_id = state.next_shell_id;
            state.next_shell_id += 1;

            for j in 0..MAX_SHELLS {
                if !state.sessions[i].shells[j].in_use {
                    state.sessions[i].shells[j].in_use = true;
                    state.sessions[i].shells[j].shell_id = shell_id;
                    state.sessions[i].shells[j].state = ShellState::Idle;
                    state.sessions[i].shells[j].creation_time = get_tick_count();

                    // Set default working directory
                    let workdir = b"C:\\Windows\\System32";
                    state.sessions[i].shells[j].working_dir[..workdir.len()].copy_from_slice(workdir);
                    state.sessions[i].shells[j].working_dir_len = workdir.len();

                    state.sessions[i].shell_count += 1;
                    state.sessions[i].last_activity = get_tick_count();

                    WINRM_STATS.shells_created.fetch_add(1, Ordering::Relaxed);

                    return Ok(shell_id);
                }
            }

            return Err(WinRmError::QuotaExceeded);
        }
    }

    Err(WinRmError::SessionNotFound)
}

/// Delete a shell
pub fn winrm_delete_shell(session_id: u64, shell_id: u64) -> Result<(), WinRmError> {
    let mut state = WINRM_STATE.lock();

    if !state.initialized {
        return Err(WinRmError::NotInitialized);
    }

    for i in 0..MAX_WINRM_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            for j in 0..MAX_SHELLS {
                if state.sessions[i].shells[j].in_use
                    && state.sessions[i].shells[j].shell_id == shell_id
                {
                    state.sessions[i].shells[j] = WinRmShell::empty();
                    if state.sessions[i].shell_count > 0 {
                        state.sessions[i].shell_count -= 1;
                    }
                    return Ok(());
                }
            }
            return Err(WinRmError::ShellNotFound);
        }
    }

    Err(WinRmError::SessionNotFound)
}

// ============================================================================
// Command Operations
// ============================================================================

/// Run a command in a shell
pub fn winrm_run_command(
    session_id: u64,
    shell_id: u64,
    command_line: &[u8],
) -> Result<u64, WinRmError> {
    let mut state = WINRM_STATE.lock();

    if !state.initialized {
        return Err(WinRmError::NotInitialized);
    }

    if command_line.len() > 512 {
        return Err(WinRmError::InvalidParameter);
    }

    for i in 0..MAX_WINRM_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            for j in 0..MAX_SHELLS {
                if state.sessions[i].shells[j].in_use
                    && state.sessions[i].shells[j].shell_id == shell_id
                {
                    if state.sessions[i].shells[j].state == ShellState::Terminated {
                        return Err(WinRmError::ShellTerminated);
                    }

                    if state.sessions[i].shells[j].command_count >= MAX_COMMANDS {
                        return Err(WinRmError::QuotaExceeded);
                    }

                    let command_id = state.next_command_id;
                    state.next_command_id += 1;

                    for k in 0..MAX_COMMANDS {
                        if !state.sessions[i].shells[j].commands[k].in_use {
                            let cmd = &mut state.sessions[i].shells[j].commands[k];
                            cmd.in_use = true;
                            cmd.command_id = command_id;
                            cmd.state = CommandState::Running;
                            cmd.command_line[..command_line.len()].copy_from_slice(command_line);
                            cmd.command_line_len = command_line.len();
                            cmd.start_time = get_tick_count();

                            state.sessions[i].shells[j].command_count += 1;
                            state.sessions[i].shells[j].state = ShellState::Running;
                            state.sessions[i].last_activity = get_tick_count();

                            WINRM_STATS.commands_executed.fetch_add(1, Ordering::Relaxed);

                            return Ok(command_id);
                        }
                    }

                    return Err(WinRmError::QuotaExceeded);
                }
            }
            return Err(WinRmError::ShellNotFound);
        }
    }

    Err(WinRmError::SessionNotFound)
}

/// Complete a command (set output and exit code)
pub fn winrm_complete_command(
    session_id: u64,
    shell_id: u64,
    command_id: u64,
    exit_code: i32,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<(), WinRmError> {
    let mut state = WINRM_STATE.lock();

    if !state.initialized {
        return Err(WinRmError::NotInitialized);
    }

    for i in 0..MAX_WINRM_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            for j in 0..MAX_SHELLS {
                if state.sessions[i].shells[j].in_use
                    && state.sessions[i].shells[j].shell_id == shell_id
                {
                    for k in 0..MAX_COMMANDS {
                        if state.sessions[i].shells[j].commands[k].in_use
                            && state.sessions[i].shells[j].commands[k].command_id == command_id
                        {
                            let cmd = &mut state.sessions[i].shells[j].commands[k];
                            cmd.exit_code = exit_code;
                            cmd.state = if exit_code == 0 {
                                CommandState::Done
                            } else {
                                CommandState::Failed
                            };
                            cmd.end_time = get_tick_count();

                            let out_len = stdout.len().min(OUTPUT_BUFFER_SIZE);
                            cmd.stdout[..out_len].copy_from_slice(&stdout[..out_len]);
                            cmd.stdout_len = out_len;

                            let err_len = stderr.len().min(OUTPUT_BUFFER_SIZE);
                            cmd.stderr[..err_len].copy_from_slice(&stderr[..err_len]);
                            cmd.stderr_len = err_len;

                            if exit_code == 0 {
                                WINRM_STATS.commands_succeeded.fetch_add(1, Ordering::Relaxed);
                            } else {
                                WINRM_STATS.commands_failed.fetch_add(1, Ordering::Relaxed);
                            }

                            // Check if shell should go idle
                            let mut has_running = false;
                            for m in 0..MAX_COMMANDS {
                                if state.sessions[i].shells[j].commands[m].in_use
                                    && state.sessions[i].shells[j].commands[m].state == CommandState::Running
                                {
                                    has_running = true;
                                    break;
                                }
                            }
                            if !has_running {
                                state.sessions[i].shells[j].state = ShellState::Idle;
                            }

                            return Ok(());
                        }
                    }
                    return Err(WinRmError::CommandNotFound);
                }
            }
            return Err(WinRmError::ShellNotFound);
        }
    }

    Err(WinRmError::SessionNotFound)
}

/// Get command output
pub fn winrm_get_command_output(
    session_id: u64,
    shell_id: u64,
    command_id: u64,
) -> Result<(CommandState, i32, Vec<u8>, Vec<u8>), WinRmError> {
    let state = WINRM_STATE.lock();

    if !state.initialized {
        return Err(WinRmError::NotInitialized);
    }

    for i in 0..MAX_WINRM_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            for j in 0..MAX_SHELLS {
                if state.sessions[i].shells[j].in_use
                    && state.sessions[i].shells[j].shell_id == shell_id
                {
                    for k in 0..MAX_COMMANDS {
                        if state.sessions[i].shells[j].commands[k].in_use
                            && state.sessions[i].shells[j].commands[k].command_id == command_id
                        {
                            let cmd = &state.sessions[i].shells[j].commands[k];
                            let stdout = cmd.stdout[..cmd.stdout_len].to_vec();
                            let stderr = cmd.stderr[..cmd.stderr_len].to_vec();
                            return Ok((cmd.state, cmd.exit_code, stdout, stderr));
                        }
                    }
                    return Err(WinRmError::CommandNotFound);
                }
            }
            return Err(WinRmError::ShellNotFound);
        }
    }

    Err(WinRmError::SessionNotFound)
}

// ============================================================================
// Event Subscriptions
// ============================================================================

/// Create an event subscription
pub fn winrm_create_subscription(
    source: &[u8],
    filter: &[u8],
    delivery_mode: DeliveryMode,
) -> Result<u64, WinRmError> {
    let mut state = WINRM_STATE.lock();

    if !state.initialized {
        return Err(WinRmError::NotInitialized);
    }

    if source.len() > 128 || filter.len() > 256 {
        return Err(WinRmError::InvalidParameter);
    }

    if state.subscription_count >= MAX_SUBSCRIPTIONS {
        return Err(WinRmError::QuotaExceeded);
    }

    let subscription_id = state.next_subscription_id;
    state.next_subscription_id += 1;

    for i in 0..MAX_SUBSCRIPTIONS {
        if !state.subscriptions[i].in_use {
            let sub = &mut state.subscriptions[i];
            sub.in_use = true;
            sub.subscription_id = subscription_id;
            sub.source[..source.len()].copy_from_slice(source);
            sub.source_len = source.len();
            sub.filter[..filter.len()].copy_from_slice(filter);
            sub.filter_len = filter.len();
            sub.delivery_mode = delivery_mode;
            sub.creation_time = get_tick_count();

            state.subscription_count += 1;

            return Ok(subscription_id);
        }
    }

    Err(WinRmError::QuotaExceeded)
}

/// Delete an event subscription
pub fn winrm_delete_subscription(subscription_id: u64) -> Result<(), WinRmError> {
    let mut state = WINRM_STATE.lock();

    if !state.initialized {
        return Err(WinRmError::NotInitialized);
    }

    for i in 0..MAX_SUBSCRIPTIONS {
        if state.subscriptions[i].in_use
            && state.subscriptions[i].subscription_id == subscription_id
        {
            state.subscriptions[i] = EventSubscription::empty();
            if state.subscription_count > 0 {
                state.subscription_count -= 1;
            }
            return Ok(());
        }
    }

    Err(WinRmError::SubscriptionNotFound)
}

// ============================================================================
// Configuration
// ============================================================================

/// Set WinRM configuration
pub fn winrm_set_config(config: &WinRmConfig) -> Result<(), WinRmError> {
    let mut state = WINRM_STATE.lock();

    if !state.initialized {
        return Err(WinRmError::NotInitialized);
    }

    state.config = config.clone();
    Ok(())
}

/// Get WinRM configuration
pub fn winrm_get_config() -> Result<WinRmConfig, WinRmError> {
    let state = WINRM_STATE.lock();

    if !state.initialized {
        return Err(WinRmError::NotInitialized);
    }

    Ok(state.config.clone())
}

// ============================================================================
// Statistics
// ============================================================================

/// WinRM statistics snapshot
#[derive(Debug, Clone, Default)]
pub struct WinRmStatsSnapshot {
    pub sessions_created: u64,
    pub sessions_closed: u64,
    pub shells_created: u64,
    pub commands_executed: u64,
    pub commands_succeeded: u64,
    pub commands_failed: u64,
    pub auth_failures: u64,
    pub events_delivered: u64,
    pub active_sessions: usize,
    pub active_subscriptions: usize,
}

/// Get WinRM statistics
pub fn winrm_get_stats() -> WinRmStatsSnapshot {
    let state = WINRM_STATE.lock();

    WinRmStatsSnapshot {
        sessions_created: WINRM_STATS.sessions_created.load(Ordering::Relaxed),
        sessions_closed: WINRM_STATS.sessions_closed.load(Ordering::Relaxed),
        shells_created: WINRM_STATS.shells_created.load(Ordering::Relaxed),
        commands_executed: WINRM_STATS.commands_executed.load(Ordering::Relaxed),
        commands_succeeded: WINRM_STATS.commands_succeeded.load(Ordering::Relaxed),
        commands_failed: WINRM_STATS.commands_failed.load(Ordering::Relaxed),
        auth_failures: WINRM_STATS.auth_failures.load(Ordering::Relaxed),
        events_delivered: WINRM_STATS.events_delivered.load(Ordering::Relaxed),
        active_sessions: state.session_count,
        active_subscriptions: state.subscription_count,
    }
}

/// Check if WinRM is initialized
pub fn winrm_is_initialized() -> bool {
    WINRM_STATE.lock().initialized
}

/// Check if WinRM service is enabled
pub fn winrm_is_enabled() -> bool {
    let state = WINRM_STATE.lock();
    state.initialized && state.config.enabled
}

/// Get auth type name
pub fn auth_type_name(auth: AuthType) -> &'static str {
    match auth {
        AuthType::Basic => "Basic",
        AuthType::Negotiate => "Negotiate",
        AuthType::Kerberos => "Kerberos",
        AuthType::CredSSP => "CredSSP",
        AuthType::Certificate => "Certificate",
    }
}

/// Get session state name
pub fn session_state_name(state: SessionState) -> &'static str {
    match state {
        SessionState::NotEstablished => "Not Established",
        SessionState::Authenticating => "Authenticating",
        SessionState::Active => "Active",
        SessionState::Disconnected => "Disconnected",
        SessionState::Closed => "Closed",
    }
}
