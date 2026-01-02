//! Secondary Logon Service (seclogon)
//!
//! The Secondary Logon service enables users to start processes under
//! different credentials. This is the underlying service for "Run As"
//! functionality in Windows.
//!
//! # Features
//!
//! - **Credential Management**: Securely handles alternate credentials
//! - **Process Creation**: Spawns processes with different security context
//! - **Profile Loading**: Optionally loads user profile for alternate user
//! - **Network Credentials**: Supports network-only credential usage
//!
//! # Run As Modes
//!
//! - `LOGON_WITH_PROFILE`: Load user profile (slower, full environment)
//! - `LOGON_NETCREDENTIALS_ONLY`: Network access only with different creds
//!
//! # Security
//!
//! - Requires SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege
//! - Credentials are handled securely in protected memory
//! - Process inherits security context from specified credentials

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum pending run-as requests
const MAX_PENDING_REQUESTS: usize = 32;

/// Maximum command line length
const MAX_CMDLINE: usize = 260;

/// Maximum username length
const MAX_USERNAME: usize = 64;

/// Maximum domain length
const MAX_DOMAIN: usize = 64;

/// Maximum working directory length
const MAX_WORKDIR: usize = 260;

/// Maximum desktop name length
const MAX_DESKTOP: usize = 64;

/// Logon flags
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogonFlags {
    /// Log on with profile (loads user registry hive)
    WithProfile = 0x0001,
    /// Network credentials only (local access uses current user)
    NetCredentialsOnly = 0x0002,
}

/// Logon type for CreateProcessWithLogon
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogonType {
    /// Interactive logon
    Interactive = 2,
    /// Network logon
    Network = 3,
    /// Batch logon
    Batch = 4,
    /// Service logon
    Service = 5,
    /// Network cleartext logon
    NetworkCleartext = 8,
    /// New credentials logon
    NewCredentials = 9,
}

impl LogonType {
    const fn empty() -> Self {
        LogonType::Interactive
    }
}

/// Request status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStatus {
    /// Request is pending
    Pending = 0,
    /// Request is being processed
    Processing = 1,
    /// Request completed successfully
    Completed = 2,
    /// Request failed
    Failed = 3,
    /// Request was cancelled
    Cancelled = 4,
}

impl RequestStatus {
    const fn empty() -> Self {
        RequestStatus::Pending
    }
}

/// Run-as request
#[repr(C)]
#[derive(Clone)]
pub struct RunAsRequest {
    /// Request ID
    pub request_id: u64,
    /// Requesting process ID
    pub client_pid: u32,
    /// Target username
    pub username: [u8; MAX_USERNAME],
    /// Target domain (optional)
    pub domain: [u8; MAX_DOMAIN],
    /// Command line to execute
    pub command_line: [u8; MAX_CMDLINE],
    /// Working directory
    pub working_directory: [u8; MAX_WORKDIR],
    /// Desktop name (winsta\desktop)
    pub desktop: [u8; MAX_DESKTOP],
    /// Logon flags
    pub flags: u32,
    /// Logon type
    pub logon_type: LogonType,
    /// Request status
    pub status: RequestStatus,
    /// Created process ID (if successful)
    pub result_pid: u32,
    /// Error code (if failed)
    pub error_code: u32,
    /// Request timestamp
    pub request_time: i64,
    /// Completion timestamp
    pub completion_time: i64,
    /// Load user profile
    pub load_profile: bool,
    /// Inherit environment from caller
    pub inherit_environment: bool,
    /// Request is valid/in use
    pub valid: bool,
}

impl RunAsRequest {
    const fn empty() -> Self {
        RunAsRequest {
            request_id: 0,
            client_pid: 0,
            username: [0; MAX_USERNAME],
            domain: [0; MAX_DOMAIN],
            command_line: [0; MAX_CMDLINE],
            working_directory: [0; MAX_WORKDIR],
            desktop: [0; MAX_DESKTOP],
            flags: 0,
            logon_type: LogonType::empty(),
            status: RequestStatus::empty(),
            result_pid: 0,
            error_code: 0,
            request_time: 0,
            completion_time: 0,
            load_profile: false,
            inherit_environment: true,
            valid: false,
        }
    }
}

/// Credential cache entry
#[repr(C)]
#[derive(Clone)]
pub struct CachedCredential {
    /// Username
    pub username: [u8; MAX_USERNAME],
    /// Domain
    pub domain: [u8; MAX_DOMAIN],
    /// Token handle (cached for reuse)
    pub token_handle: u64,
    /// Profile loaded
    pub profile_loaded: bool,
    /// Last used timestamp
    pub last_used: i64,
    /// Use count
    pub use_count: u64,
    /// Entry is valid
    pub valid: bool,
}

impl CachedCredential {
    const fn empty() -> Self {
        CachedCredential {
            username: [0; MAX_USERNAME],
            domain: [0; MAX_DOMAIN],
            token_handle: 0,
            profile_loaded: false,
            last_used: 0,
            use_count: 0,
            valid: false,
        }
    }
}

/// Maximum cached credentials
const MAX_CACHED_CREDENTIALS: usize = 8;

/// Secondary logon service state
pub struct SecondaryLogonState {
    /// Service is running
    pub running: bool,
    /// Pending requests
    pub requests: [RunAsRequest; MAX_PENDING_REQUESTS],
    /// Request count
    pub request_count: usize,
    /// Cached credentials
    pub credential_cache: [CachedCredential; MAX_CACHED_CREDENTIALS],
    /// Cache entry count
    pub cache_count: usize,
    /// Service start time
    pub start_time: i64,
}

impl SecondaryLogonState {
    const fn new() -> Self {
        SecondaryLogonState {
            running: false,
            requests: [const { RunAsRequest::empty() }; MAX_PENDING_REQUESTS],
            request_count: 0,
            credential_cache: [const { CachedCredential::empty() }; MAX_CACHED_CREDENTIALS],
            cache_count: 0,
            start_time: 0,
        }
    }
}

/// Global secondary logon state
static SECLOGON_STATE: Mutex<SecondaryLogonState> = Mutex::new(SecondaryLogonState::new());

/// Statistics
static TOTAL_REQUESTS: AtomicU64 = AtomicU64::new(0);
static SUCCESSFUL_LOGONS: AtomicU64 = AtomicU64::new(0);
static FAILED_LOGONS: AtomicU64 = AtomicU64::new(0);
static CACHED_LOGONS: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Next request ID
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Initialize Secondary Logon service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = SECLOGON_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    crate::serial_println!("[SECLOGON] Secondary Logon service initialized");
}

/// Submit a run-as request
pub fn submit_request(
    username: &[u8],
    domain: &[u8],
    command_line: &[u8],
    working_dir: &[u8],
    flags: u32,
    logon_type: LogonType,
) -> Result<u64, u32> {
    let mut state = SECLOGON_STATE.lock();

    if !state.running {
        return Err(0x80070426); // ERROR_SERVICE_NOT_ACTIVE
    }

    // Find free request slot
    let slot = state.requests.iter().position(|r| !r.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E), // ERROR_OUTOFMEMORY
    };

    let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::SeqCst);
    let request_time = crate::rtl::time::rtl_get_system_time();

    let request = &mut state.requests[slot];
    request.request_id = request_id;
    request.client_pid = 0; // Would come from calling process

    // Copy username
    let uname_len = username.len().min(MAX_USERNAME);
    request.username[..uname_len].copy_from_slice(&username[..uname_len]);

    // Copy domain
    let domain_len = domain.len().min(MAX_DOMAIN);
    request.domain[..domain_len].copy_from_slice(&domain[..domain_len]);

    // Copy command line
    let cmd_len = command_line.len().min(MAX_CMDLINE);
    request.command_line[..cmd_len].copy_from_slice(&command_line[..cmd_len]);

    // Copy working directory
    let work_len = working_dir.len().min(MAX_WORKDIR);
    request.working_directory[..work_len].copy_from_slice(&working_dir[..work_len]);

    request.flags = flags;
    request.logon_type = logon_type;
    request.status = RequestStatus::Pending;
    request.result_pid = 0;
    request.error_code = 0;
    request.request_time = request_time;
    request.completion_time = 0;
    request.load_profile = (flags & LogonFlags::WithProfile as u32) != 0;
    request.inherit_environment = true;
    request.valid = true;

    state.request_count += 1;
    TOTAL_REQUESTS.fetch_add(1, Ordering::SeqCst);

    // Process immediately in this simplified implementation
    drop(state);
    process_request(request_id);

    Ok(request_id)
}

/// Process a pending request
fn process_request(request_id: u64) {
    let mut state = SECLOGON_STATE.lock();

    // Find the request index first
    let req_idx = match state.requests.iter().position(|r| r.valid && r.request_id == request_id) {
        Some(idx) => idx,
        None => return,
    };

    // Extract username and domain for cache check before mutable borrow
    let username = state.requests[req_idx].username;
    let domain = state.requests[req_idx].domain;

    // Check credential cache
    let cached = check_credential_cache(&state.credential_cache, &username, &domain);

    if cached.is_some() {
        CACHED_LOGONS.fetch_add(1, Ordering::SeqCst);
    }

    // Now get mutable reference
    let request = &mut state.requests[req_idx];
    request.status = RequestStatus::Processing;

    // Simulate logon process
    // In a real implementation, this would:
    // 1. Call LogonUser or similar
    // 2. Create primary token
    // 3. Load user profile if requested
    // 4. Create process with new token

    let logon_success = perform_logon(request);

    let completion_time = crate::rtl::time::rtl_get_system_time();

    if logon_success {
        request.status = RequestStatus::Completed;
        request.result_pid = 1000 + (request_id as u32 % 1000); // Simulated PID
        request.error_code = 0;
        SUCCESSFUL_LOGONS.fetch_add(1, Ordering::SeqCst);
    } else {
        request.status = RequestStatus::Failed;
        request.result_pid = 0;
        request.error_code = 0x8007052E; // ERROR_LOGON_FAILURE
        FAILED_LOGONS.fetch_add(1, Ordering::SeqCst);
    }

    request.completion_time = completion_time;
}

/// Check credential cache for matching entry
fn check_credential_cache(
    cache: &[CachedCredential; MAX_CACHED_CREDENTIALS],
    username: &[u8; MAX_USERNAME],
    domain: &[u8; MAX_DOMAIN],
) -> Option<usize> {
    cache.iter().position(|c| {
        c.valid && c.username == *username && c.domain == *domain
    })
}

/// Perform the actual logon (simulated)
fn perform_logon(request: &RunAsRequest) -> bool {
    // Check for valid username
    let has_username = request.username.iter().any(|&b| b != 0);
    if !has_username {
        return false;
    }

    // Check for valid command
    let has_command = request.command_line.iter().any(|&b| b != 0);
    if !has_command {
        return false;
    }

    // Simulate successful logon for valid requests
    true
}

/// Get request status
pub fn get_request_status(request_id: u64) -> Option<(RequestStatus, u32, u32)> {
    let state = SECLOGON_STATE.lock();

    state.requests.iter()
        .find(|r| r.valid && r.request_id == request_id)
        .map(|r| (r.status, r.result_pid, r.error_code))
}

/// Cancel a pending request
pub fn cancel_request(request_id: u64) -> bool {
    let mut state = SECLOGON_STATE.lock();

    if let Some(request) = state.requests.iter_mut()
        .find(|r| r.valid && r.request_id == request_id)
    {
        if request.status == RequestStatus::Pending {
            request.status = RequestStatus::Cancelled;
            request.completion_time = crate::rtl::time::rtl_get_system_time();
            return true;
        }
    }

    false
}

/// Clean up completed requests
pub fn cleanup_completed_requests(max_age_ms: i64) {
    let mut state = SECLOGON_STATE.lock();
    let now = crate::rtl::time::rtl_get_system_time();
    let mut cleaned = 0usize;

    for request in state.requests.iter_mut() {
        if !request.valid {
            continue;
        }

        let is_finished = matches!(
            request.status,
            RequestStatus::Completed | RequestStatus::Failed | RequestStatus::Cancelled
        );

        if is_finished && request.completion_time > 0 {
            let age = (now - request.completion_time) / 10_000; // Convert to ms
            if age > max_age_ms {
                request.valid = false;
                cleaned += 1;
            }
        }
    }

    state.request_count = state.request_count.saturating_sub(cleaned);
}

/// Cache credentials for reuse
pub fn cache_credential(
    username: &[u8],
    domain: &[u8],
    token_handle: u64,
    profile_loaded: bool,
) -> Result<(), u32> {
    let mut state = SECLOGON_STATE.lock();

    // Find existing or empty slot
    let slot = state.credential_cache.iter().position(|c| {
        !c.valid || (c.username[..username.len().min(MAX_USERNAME)] == username[..username.len().min(MAX_USERNAME)]
            && c.domain[..domain.len().min(MAX_DOMAIN)] == domain[..domain.len().min(MAX_DOMAIN)])
    });

    let slot = match slot {
        Some(s) => s,
        None => {
            // Evict oldest entry
            let oldest = state.credential_cache.iter()
                .enumerate()
                .filter(|(_, c)| c.valid)
                .min_by_key(|(_, c)| c.last_used)
                .map(|(i, _)| i);

            match oldest {
                Some(o) => o,
                None => return Err(0x8007000E), // ERROR_OUTOFMEMORY
            }
        }
    };

    let now = crate::rtl::time::rtl_get_system_time();
    let entry = &mut state.credential_cache[slot];

    // Copy username
    entry.username = [0; MAX_USERNAME];
    let uname_len = username.len().min(MAX_USERNAME);
    entry.username[..uname_len].copy_from_slice(&username[..uname_len]);

    // Copy domain
    entry.domain = [0; MAX_DOMAIN];
    let domain_len = domain.len().min(MAX_DOMAIN);
    entry.domain[..domain_len].copy_from_slice(&domain[..domain_len]);

    entry.token_handle = token_handle;
    entry.profile_loaded = profile_loaded;
    entry.last_used = now;
    entry.use_count = 1;
    entry.valid = true;

    if slot >= state.cache_count {
        state.cache_count = slot + 1;
    }

    Ok(())
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64, u64) {
    (
        TOTAL_REQUESTS.load(Ordering::SeqCst),
        SUCCESSFUL_LOGONS.load(Ordering::SeqCst),
        FAILED_LOGONS.load(Ordering::SeqCst),
        CACHED_LOGONS.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = SECLOGON_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = SECLOGON_STATE.lock();
    state.running = false;

    // Cancel all pending requests
    for request in state.requests.iter_mut() {
        if request.valid && request.status == RequestStatus::Pending {
            request.status = RequestStatus::Cancelled;
            request.completion_time = crate::rtl::time::rtl_get_system_time();
        }
    }

    // Clear credential cache
    for cred in state.credential_cache.iter_mut() {
        cred.valid = false;
    }
    state.cache_count = 0;

    crate::serial_println!("[SECLOGON] Secondary Logon service stopped");
}

/// CreateProcessWithLogonW API simulation
pub fn create_process_with_logon(
    username: &[u8],
    domain: &[u8],
    command_line: &[u8],
    logon_flags: u32,
    creation_flags: u32,
    working_dir: &[u8],
) -> Result<(u32, u32), u32> {
    let _ = creation_flags; // Would be used for process creation

    let logon_type = if (logon_flags & LogonFlags::NetCredentialsOnly as u32) != 0 {
        LogonType::NewCredentials
    } else {
        LogonType::Interactive
    };

    let request_id = submit_request(
        username,
        domain,
        command_line,
        working_dir,
        logon_flags,
        logon_type,
    )?;

    // Get result
    if let Some((status, pid, error)) = get_request_status(request_id) {
        match status {
            RequestStatus::Completed => Ok((pid, 0)), // (process_id, thread_id)
            RequestStatus::Failed => Err(error),
            _ => Err(0x80004005), // E_FAIL
        }
    } else {
        Err(0x80004005) // E_FAIL
    }
}

/// CreateProcessWithTokenW API simulation
pub fn create_process_with_token(
    token_handle: u64,
    logon_flags: u32,
    command_line: &[u8],
    creation_flags: u32,
    working_dir: &[u8],
) -> Result<(u32, u32), u32> {
    let _ = creation_flags;
    let _ = logon_flags;
    let _ = token_handle;

    // Validate token (simulated)
    if token_handle == 0 {
        return Err(0x80070006); // ERROR_INVALID_HANDLE
    }

    // Validate command line
    let has_command = command_line.iter().any(|&b| b != 0);
    if !has_command {
        return Err(0x80070057); // ERROR_INVALID_PARAMETER
    }

    // Create process with existing token
    let _ = working_dir;

    // Simulated success
    let pid = (crate::rtl::time::rtl_get_system_time() as u32) % 10000 + 1000;
    Ok((pid, 0))
}

/// Get pending request count
pub fn get_pending_count() -> usize {
    let state = SECLOGON_STATE.lock();
    state.requests.iter().filter(|r| r.valid && r.status == RequestStatus::Pending).count()
}

/// Get active request IDs
pub fn get_active_requests() -> ([u64; MAX_PENDING_REQUESTS], usize) {
    let state = SECLOGON_STATE.lock();
    let mut ids = [0u64; MAX_PENDING_REQUESTS];
    let mut count = 0;

    for request in state.requests.iter() {
        if request.valid && matches!(request.status, RequestStatus::Pending | RequestStatus::Processing) {
            if count < MAX_PENDING_REQUESTS {
                ids[count] = request.request_id;
                count += 1;
            }
        }
    }

    (ids, count)
}
