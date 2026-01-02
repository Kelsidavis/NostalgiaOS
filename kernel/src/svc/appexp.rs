//! Application Experience Service (AELookupSvc)
//!
//! The Application Experience service provides application compatibility
//! support by processing compatibility lookup requests and applying
//! appropriate shims and fixes for legacy applications.
//!
//! # Features
//!
//! - **Compatibility Database**: Query shim database (SDB files)
//! - **Application Lookup**: Find compatibility entries for executables
//! - **Shim Application**: Apply compatibility fixes at runtime
//! - **Telemetry**: Report application compatibility data (optional)
//!
//! # Shim Types
//!
//! - Compatibility shims (API redirects)
//! - Compatibility layers (HeapEnableTerminationOnCorruption)
//! - Application patches (binary patches)
//! - Compatibility flags
//!
//! # Database Files
//!
//! - sysmain.sdb: Main system compatibility database
//! - drvmain.sdb: Driver compatibility database
//! - apphelp.sdb: Application help database

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum shim entries
const MAX_SHIMS: usize = 64;

/// Maximum layers
const MAX_LAYERS: usize = 32;

/// Maximum database entries
const MAX_DB_ENTRIES: usize = 128;

/// Maximum pending lookups
const MAX_LOOKUPS: usize = 32;

/// Maximum name length
const MAX_NAME: usize = 128;

/// Maximum path length
const MAX_PATH: usize = 260;

/// Shim type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShimType {
    /// API shim (redirect/hook API)
    ApiShim = 0,
    /// Compatibility layer
    Layer = 1,
    /// Binary patch
    Patch = 2,
    /// Application fix
    AppFix = 3,
    /// Flag modification
    Flag = 4,
}

impl ShimType {
    const fn empty() -> Self {
        ShimType::ApiShim
    }
}

/// Shim definition
#[repr(C)]
#[derive(Clone)]
pub struct ShimDef {
    /// Shim name
    pub name: [u8; MAX_NAME],
    /// Shim type
    pub shim_type: ShimType,
    /// DLL containing the shim
    pub dll_name: [u8; MAX_NAME],
    /// Description
    pub description: [u8; MAX_NAME],
    /// Shim GUID
    pub guid: [u8; 16],
    /// Is enabled
    pub enabled: bool,
    /// Entry is valid
    pub valid: bool,
}

impl ShimDef {
    const fn empty() -> Self {
        ShimDef {
            name: [0; MAX_NAME],
            shim_type: ShimType::empty(),
            dll_name: [0; MAX_NAME],
            description: [0; MAX_NAME],
            guid: [0; 16],
            enabled: true,
            valid: false,
        }
    }
}

/// Compatibility layer
#[repr(C)]
#[derive(Clone)]
pub struct CompatLayer {
    /// Layer name
    pub name: [u8; MAX_NAME],
    /// Description
    pub description: [u8; MAX_NAME],
    /// Shims in this layer (indices)
    pub shim_indices: [u16; 16],
    /// Number of shims
    pub shim_count: usize,
    /// Entry is valid
    pub valid: bool,
}

impl CompatLayer {
    const fn empty() -> Self {
        CompatLayer {
            name: [0; MAX_NAME],
            description: [0; MAX_NAME],
            shim_indices: [0; 16],
            shim_count: 0,
            valid: false,
        }
    }
}

/// Database entry (application match)
#[repr(C)]
#[derive(Clone)]
pub struct DbEntry {
    /// Application name
    pub app_name: [u8; MAX_NAME],
    /// Application path (pattern)
    pub app_path: [u8; MAX_PATH],
    /// Vendor name
    pub vendor: [u8; MAX_NAME],
    /// Version info
    pub version: u32,
    /// Applied shim indices
    pub shim_indices: [u16; 8],
    /// Number of applied shims
    pub shim_count: usize,
    /// Layer name (if any)
    pub layer: [u8; MAX_NAME],
    /// Flags
    pub flags: u32,
    /// Entry is valid
    pub valid: bool,
}

impl DbEntry {
    const fn empty() -> Self {
        DbEntry {
            app_name: [0; MAX_NAME],
            app_path: [0; MAX_PATH],
            vendor: [0; MAX_NAME],
            version: 0,
            shim_indices: [0; 8],
            shim_count: 0,
            layer: [0; MAX_NAME],
            flags: 0,
            valid: false,
        }
    }
}

/// Lookup result
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupResult {
    /// No compatibility info found
    NotFound = 0,
    /// Found, no action needed
    NoAction = 1,
    /// Found, shims to apply
    ApplyShims = 2,
    /// Found, layer to apply
    ApplyLayer = 3,
    /// Blocked application
    Blocked = 4,
    /// Needs elevation
    RequiresElevation = 5,
}

impl LookupResult {
    const fn empty() -> Self {
        LookupResult::NotFound
    }
}

/// Lookup request
#[repr(C)]
#[derive(Clone)]
pub struct LookupRequest {
    /// Request ID
    pub request_id: u64,
    /// Executable path
    pub exe_path: [u8; MAX_PATH],
    /// Executable name
    pub exe_name: [u8; MAX_NAME],
    /// Process ID (if running)
    pub process_id: u32,
    /// Result
    pub result: LookupResult,
    /// Matched DB entry index
    pub db_entry_idx: Option<usize>,
    /// Request time
    pub request_time: i64,
    /// Completed
    pub completed: bool,
    /// Entry is valid
    pub valid: bool,
}

impl LookupRequest {
    const fn empty() -> Self {
        LookupRequest {
            request_id: 0,
            exe_path: [0; MAX_PATH],
            exe_name: [0; MAX_NAME],
            process_id: 0,
            result: LookupResult::empty(),
            db_entry_idx: None,
            request_time: 0,
            completed: false,
            valid: false,
        }
    }
}

/// Application Experience service state
pub struct AppExpState {
    /// Service is running
    pub running: bool,
    /// Shim definitions
    pub shims: [ShimDef; MAX_SHIMS],
    /// Shim count
    pub shim_count: usize,
    /// Compatibility layers
    pub layers: [CompatLayer; MAX_LAYERS],
    /// Layer count
    pub layer_count: usize,
    /// Database entries
    pub db_entries: [DbEntry; MAX_DB_ENTRIES],
    /// DB entry count
    pub db_entry_count: usize,
    /// Pending lookups
    pub lookups: [LookupRequest; MAX_LOOKUPS],
    /// Lookup count
    pub lookup_count: usize,
    /// Next request ID
    pub next_request_id: u64,
    /// Service start time
    pub start_time: i64,
    /// Telemetry enabled
    pub telemetry_enabled: bool,
}

impl AppExpState {
    const fn new() -> Self {
        AppExpState {
            running: false,
            shims: [const { ShimDef::empty() }; MAX_SHIMS],
            shim_count: 0,
            layers: [const { CompatLayer::empty() }; MAX_LAYERS],
            layer_count: 0,
            db_entries: [const { DbEntry::empty() }; MAX_DB_ENTRIES],
            db_entry_count: 0,
            lookups: [const { LookupRequest::empty() }; MAX_LOOKUPS],
            lookup_count: 0,
            next_request_id: 1,
            start_time: 0,
            telemetry_enabled: false,
        }
    }
}

/// Global state
static APPEXP_STATE: Mutex<AppExpState> = Mutex::new(AppExpState::new());

/// Statistics
static TOTAL_LOOKUPS: AtomicU64 = AtomicU64::new(0);
static SHIMS_APPLIED: AtomicU64 = AtomicU64::new(0);
static APPS_BLOCKED: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize Application Experience service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = APPEXP_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    // Register built-in shims
    register_builtin_shims(&mut state);

    // Register built-in layers
    register_builtin_layers(&mut state);

    crate::serial_println!("[APPEXP] Application Experience service initialized");
}

/// Register built-in compatibility shims
fn register_builtin_shims(state: &mut AppExpState) {
    // CorrectFilePaths shim
    let idx = 0;
    let shim_name = b"CorrectFilePaths";
    state.shims[idx].name[..shim_name.len()].copy_from_slice(shim_name);
    state.shims[idx].shim_type = ShimType::ApiShim;
    let dll = b"acgenral.dll";
    state.shims[idx].dll_name[..dll.len()].copy_from_slice(dll);
    state.shims[idx].valid = true;

    // VirtualRegistry shim
    let idx = 1;
    let shim_name = b"VirtualRegistry";
    state.shims[idx].name[..shim_name.len()].copy_from_slice(shim_name);
    state.shims[idx].shim_type = ShimType::ApiShim;
    let dll = b"acgenral.dll";
    state.shims[idx].dll_name[..dll.len()].copy_from_slice(dll);
    state.shims[idx].valid = true;

    // Win2000VersionLie shim
    let idx = 2;
    let shim_name = b"Win2000VersionLie";
    state.shims[idx].name[..shim_name.len()].copy_from_slice(shim_name);
    state.shims[idx].shim_type = ShimType::ApiShim;
    let dll = b"acgenral.dll";
    state.shims[idx].dll_name[..dll.len()].copy_from_slice(dll);
    state.shims[idx].valid = true;

    // WinXPVersionLie shim
    let idx = 3;
    let shim_name = b"WinXPVersionLie";
    state.shims[idx].name[..shim_name.len()].copy_from_slice(shim_name);
    state.shims[idx].shim_type = ShimType::ApiShim;
    let dll = b"acgenral.dll";
    state.shims[idx].dll_name[..dll.len()].copy_from_slice(dll);
    state.shims[idx].valid = true;

    // HeapClearAllocation shim
    let idx = 4;
    let shim_name = b"HeapClearAllocation";
    state.shims[idx].name[..shim_name.len()].copy_from_slice(shim_name);
    state.shims[idx].shim_type = ShimType::ApiShim;
    let dll = b"acgenral.dll";
    state.shims[idx].dll_name[..dll.len()].copy_from_slice(dll);
    state.shims[idx].valid = true;

    // IgnoreFreeLibrary shim
    let idx = 5;
    let shim_name = b"IgnoreFreeLibrary";
    state.shims[idx].name[..shim_name.len()].copy_from_slice(shim_name);
    state.shims[idx].shim_type = ShimType::ApiShim;
    let dll = b"acgenral.dll";
    state.shims[idx].dll_name[..dll.len()].copy_from_slice(dll);
    state.shims[idx].valid = true;

    state.shim_count = 6;
}

/// Register built-in compatibility layers
fn register_builtin_layers(state: &mut AppExpState) {
    // Windows XP (SP3) compatibility mode
    let idx = 0;
    let layer_name = b"WinXPSP3";
    state.layers[idx].name[..layer_name.len()].copy_from_slice(layer_name);
    let desc = b"Windows XP (Service Pack 3)";
    state.layers[idx].description[..desc.len()].copy_from_slice(desc);
    state.layers[idx].shim_indices[0] = 3; // WinXPVersionLie
    state.layers[idx].shim_count = 1;
    state.layers[idx].valid = true;

    // Windows 2000 compatibility mode
    let idx = 1;
    let layer_name = b"Win2000";
    state.layers[idx].name[..layer_name.len()].copy_from_slice(layer_name);
    let desc = b"Windows 2000";
    state.layers[idx].description[..desc.len()].copy_from_slice(desc);
    state.layers[idx].shim_indices[0] = 2; // Win2000VersionLie
    state.layers[idx].shim_count = 1;
    state.layers[idx].valid = true;

    // Run as Administrator
    let idx = 2;
    let layer_name = b"RunAsAdmin";
    state.layers[idx].name[..layer_name.len()].copy_from_slice(layer_name);
    let desc = b"Run this program as administrator";
    state.layers[idx].description[..desc.len()].copy_from_slice(desc);
    state.layers[idx].shim_count = 0;
    state.layers[idx].valid = true;

    // Disable visual themes
    let idx = 3;
    let layer_name = b"DisableThemes";
    state.layers[idx].name[..layer_name.len()].copy_from_slice(layer_name);
    let desc = b"Disable visual themes";
    state.layers[idx].description[..desc.len()].copy_from_slice(desc);
    state.layers[idx].shim_count = 0;
    state.layers[idx].valid = true;

    state.layer_count = 4;
}

/// Lookup compatibility info for an executable
pub fn lookup_exe(exe_path: &[u8]) -> Result<u64, u32> {
    let mut state = APPEXP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.lookups.iter().position(|l| !l.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let request_id = state.next_request_id;
    state.next_request_id += 1;

    let now = crate::rtl::time::rtl_get_system_time();

    let lookup = &mut state.lookups[slot];
    lookup.request_id = request_id;

    let path_len = exe_path.len().min(MAX_PATH);
    lookup.exe_path[..path_len].copy_from_slice(&exe_path[..path_len]);

    // Extract filename from path
    let name_start = exe_path.iter().rposition(|&b| b == b'\\' || b == b'/').map(|i| i + 1).unwrap_or(0);
    let name_len = (path_len - name_start).min(MAX_NAME);
    lookup.exe_name[..name_len].copy_from_slice(&exe_path[name_start..name_start + name_len]);

    lookup.process_id = 0;
    lookup.request_time = now;
    lookup.completed = false;
    lookup.valid = true;

    state.lookup_count += 1;

    // Process lookup immediately
    drop(state);
    process_lookup(request_id);

    TOTAL_LOOKUPS.fetch_add(1, Ordering::SeqCst);

    Ok(request_id)
}

/// Process a lookup request
fn process_lookup(request_id: u64) {
    let mut state = APPEXP_STATE.lock();

    // Find the lookup
    let lookup_idx = match state.lookups.iter().position(|l| l.valid && l.request_id == request_id) {
        Some(idx) => idx,
        None => return,
    };

    // Extract exe_name for matching before mutable borrow
    let exe_name = state.lookups[lookup_idx].exe_name;

    // Search database for matching entry and extract needed info
    let db_match_info: Option<(usize, u32, usize, u8)> = state.db_entries.iter().enumerate()
        .find(|(_, entry)| {
            if !entry.valid {
                return false;
            }
            // Simple name match
            entry.app_name[..exe_name.len().min(MAX_NAME)] == exe_name[..exe_name.len().min(MAX_NAME)]
        })
        .map(|(idx, entry)| (idx, entry.flags, entry.shim_count, entry.layer[0]));

    let lookup = &mut state.lookups[lookup_idx];

    if let Some((idx, flags, shim_count, has_layer)) = db_match_info {
        lookup.db_entry_idx = Some(idx);

        if flags & 0x1 != 0 {
            // Blocked flag
            lookup.result = LookupResult::Blocked;
            APPS_BLOCKED.fetch_add(1, Ordering::SeqCst);
        } else if shim_count > 0 {
            lookup.result = LookupResult::ApplyShims;
            SHIMS_APPLIED.fetch_add(1, Ordering::SeqCst);
        } else if has_layer != 0 {
            lookup.result = LookupResult::ApplyLayer;
            SHIMS_APPLIED.fetch_add(1, Ordering::SeqCst);
        } else {
            lookup.result = LookupResult::NoAction;
        }
    } else {
        lookup.result = LookupResult::NotFound;
        lookup.db_entry_idx = None;
    }

    lookup.completed = true;
}

/// Get lookup result
pub fn get_lookup_result(request_id: u64) -> Option<(LookupResult, Option<usize>)> {
    let state = APPEXP_STATE.lock();

    state.lookups.iter()
        .find(|l| l.valid && l.request_id == request_id && l.completed)
        .map(|l| (l.result, l.db_entry_idx))
}

/// Add a database entry
pub fn add_db_entry(
    app_name: &[u8],
    app_path: &[u8],
    vendor: &[u8],
    shims: &[u16],
    layer: &[u8],
    flags: u32,
) -> Result<usize, u32> {
    let mut state = APPEXP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.db_entries.iter().position(|e| !e.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let entry = &mut state.db_entries[slot];

    let name_len = app_name.len().min(MAX_NAME);
    entry.app_name[..name_len].copy_from_slice(&app_name[..name_len]);

    let path_len = app_path.len().min(MAX_PATH);
    entry.app_path[..path_len].copy_from_slice(&app_path[..path_len]);

    let vendor_len = vendor.len().min(MAX_NAME);
    entry.vendor[..vendor_len].copy_from_slice(&vendor[..vendor_len]);

    let shim_count = shims.len().min(8);
    entry.shim_indices[..shim_count].copy_from_slice(&shims[..shim_count]);
    entry.shim_count = shim_count;

    let layer_len = layer.len().min(MAX_NAME);
    entry.layer[..layer_len].copy_from_slice(&layer[..layer_len]);

    entry.flags = flags;
    entry.valid = true;

    state.db_entry_count += 1;

    Ok(slot)
}

/// Remove a database entry
pub fn remove_db_entry(index: usize) -> Result<(), u32> {
    let mut state = APPEXP_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    if index >= MAX_DB_ENTRIES || !state.db_entries[index].valid {
        return Err(0x80070057);
    }

    state.db_entries[index].valid = false;
    state.db_entry_count = state.db_entry_count.saturating_sub(1);

    Ok(())
}

/// Enumerate shims
pub fn enum_shims() -> ([ShimDef; MAX_SHIMS], usize) {
    let state = APPEXP_STATE.lock();
    let mut result = [const { ShimDef::empty() }; MAX_SHIMS];
    let mut count = 0;

    for shim in state.shims.iter() {
        if shim.valid && count < MAX_SHIMS {
            result[count] = shim.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Enumerate layers
pub fn enum_layers() -> ([CompatLayer; MAX_LAYERS], usize) {
    let state = APPEXP_STATE.lock();
    let mut result = [const { CompatLayer::empty() }; MAX_LAYERS];
    let mut count = 0;

    for layer in state.layers.iter() {
        if layer.valid && count < MAX_LAYERS {
            result[count] = layer.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get shim by name
pub fn get_shim_by_name(name: &[u8]) -> Option<ShimDef> {
    let state = APPEXP_STATE.lock();
    let name_len = name.len().min(MAX_NAME);

    state.shims.iter()
        .find(|s| s.valid && s.name[..name_len] == name[..name_len])
        .cloned()
}

/// Get layer by name
pub fn get_layer_by_name(name: &[u8]) -> Option<CompatLayer> {
    let state = APPEXP_STATE.lock();
    let name_len = name.len().min(MAX_NAME);

    state.layers.iter()
        .find(|l| l.valid && l.name[..name_len] == name[..name_len])
        .cloned()
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64) {
    (
        TOTAL_LOOKUPS.load(Ordering::SeqCst),
        SHIMS_APPLIED.load(Ordering::SeqCst),
        APPS_BLOCKED.load(Ordering::SeqCst),
    )
}

/// Set telemetry enabled
pub fn set_telemetry(enabled: bool) {
    let mut state = APPEXP_STATE.lock();
    state.telemetry_enabled = enabled;
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = APPEXP_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = APPEXP_STATE.lock();
    state.running = false;

    // Clear pending lookups
    for lookup in state.lookups.iter_mut() {
        lookup.valid = false;
    }
    state.lookup_count = 0;

    crate::serial_println!("[APPEXP] Application Experience service stopped");
}
