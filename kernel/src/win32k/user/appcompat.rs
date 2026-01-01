//! Application Compatibility Support
//!
//! Implements Windows application compatibility infrastructure including
//! shim database queries, compatibility layers, and version spoofing.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/appcompat/shims/` - Shim engine
//! - `windows/appcompat/sdbapi/` - Shim database API
//! - `base/appcompat/` - AppCompat infrastructure

use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum shim entries
const MAX_SHIMS: usize = 128;

/// Maximum compatibility layers
const MAX_LAYERS: usize = 32;

/// Maximum application entries
const MAX_APP_ENTRIES: usize = 64;

/// Maximum path length
const MAX_PATH: usize = 260;

/// Maximum shim name length
const MAX_SHIM_NAME: usize = 64;

/// Maximum layer name length
const MAX_LAYER_NAME: usize = 64;

// ============================================================================
// Compatibility Flags
// ============================================================================

bitflags::bitflags! {
    /// Application compatibility flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct CompatFlags: u32 {
        /// Disable heap metadata protection
        const DISABLE_HEAP_METADATA = 0x00000001;
        /// Disable NX (DEP)
        const DISABLE_NX = 0x00000002;
        /// Disable SEHOP
        const DISABLE_SEHOP = 0x00000004;
        /// Run as invoker (not admin)
        const RUN_AS_INVOKER = 0x00000008;
        /// Disable visual themes
        const DISABLE_THEMES = 0x00000010;
        /// Run in 640x480 resolution
        const RES_640X480 = 0x00000020;
        /// Run in 256 colors
        const COLOR_256 = 0x00000040;
        /// Disable display scaling on high DPI
        const DISABLE_DPI_SCALING = 0x00000080;
        /// Disable fullscreen optimizations
        const DISABLE_FULLSCREEN_OPT = 0x00000100;
        /// Register for restart
        const REGISTER_RESTART = 0x00000200;
        /// Disable DWM composition
        const DISABLE_DWM = 0x00000400;
        /// High DPI aware
        const HIGH_DPI_AWARE = 0x00000800;
        /// Per-monitor DPI aware
        const PER_MONITOR_DPI_AWARE = 0x00001000;
    }
}

// ============================================================================
// Windows Version Spoofing
// ============================================================================

/// Windows version for compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub sp_major: u16,
    pub sp_minor: u16,
}

impl WinVersion {
    pub const fn new(major: u32, minor: u32, build: u32) -> Self {
        Self {
            major,
            minor,
            build,
            sp_major: 0,
            sp_minor: 0,
        }
    }

    pub const fn with_sp(major: u32, minor: u32, build: u32, sp_major: u16, sp_minor: u16) -> Self {
        Self {
            major,
            minor,
            build,
            sp_major,
            sp_minor,
        }
    }
}

impl Default for WinVersion {
    fn default() -> Self {
        // Default to Windows Server 2003 SP2
        Self::with_sp(5, 2, 3790, 2, 0)
    }
}

/// Predefined Windows versions
pub mod versions {
    use super::WinVersion;

    pub const WIN95: WinVersion = WinVersion::new(4, 0, 950);
    pub const WIN98: WinVersion = WinVersion::new(4, 10, 1998);
    pub const WIN98SE: WinVersion = WinVersion::new(4, 10, 2222);
    pub const WINME: WinVersion = WinVersion::new(4, 90, 3000);
    pub const NT4: WinVersion = WinVersion::with_sp(4, 0, 1381, 6, 0);
    pub const WIN2000: WinVersion = WinVersion::with_sp(5, 0, 2195, 4, 0);
    pub const WINXP: WinVersion = WinVersion::with_sp(5, 1, 2600, 3, 0);
    pub const WINXP64: WinVersion = WinVersion::with_sp(5, 2, 3790, 2, 0);
    pub const WIN2003: WinVersion = WinVersion::with_sp(5, 2, 3790, 2, 0);
    pub const VISTA: WinVersion = WinVersion::with_sp(6, 0, 6002, 2, 0);
    pub const WIN7: WinVersion = WinVersion::with_sp(6, 1, 7601, 1, 0);
    pub const WIN8: WinVersion = WinVersion::new(6, 2, 9200);
    pub const WIN81: WinVersion = WinVersion::new(6, 3, 9600);
    pub const WIN10: WinVersion = WinVersion::new(10, 0, 19041);
}

// ============================================================================
// Shim Types
// ============================================================================

/// Shim type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShimType {
    #[default]
    Generic = 0,
    /// API hook shim
    ApiHook = 1,
    /// IAT patch shim
    IatPatch = 2,
    /// Compatibility layer
    Layer = 3,
    /// Version lie
    VersionLie = 4,
    /// Flag shim
    FlagShim = 5,
}

/// Shim entry
#[derive(Debug)]
struct ShimEntry {
    in_use: bool,
    name: [u8; MAX_SHIM_NAME],
    shim_type: ShimType,
    description: [u8; 128],
    dll_name: [u8; MAX_PATH],
    enabled: bool,
}

impl ShimEntry {
    const fn new() -> Self {
        Self {
            in_use: false,
            name: [0u8; MAX_SHIM_NAME],
            shim_type: ShimType::Generic,
            description: [0u8; 128],
            dll_name: [0u8; MAX_PATH],
            enabled: true,
        }
    }
}

// ============================================================================
// Compatibility Layer
// ============================================================================

/// Compatibility layer entry
#[derive(Debug)]
struct CompatLayer {
    in_use: bool,
    name: [u8; MAX_LAYER_NAME],
    flags: CompatFlags,
    version_spoof: Option<WinVersion>,
    shim_indices: [usize; 16],
    shim_count: usize,
}

impl CompatLayer {
    const fn new() -> Self {
        Self {
            in_use: false,
            name: [0u8; MAX_LAYER_NAME],
            flags: CompatFlags::empty(),
            version_spoof: None,
            shim_indices: [0usize; 16],
            shim_count: 0,
        }
    }
}

// ============================================================================
// Application Entry
// ============================================================================

/// Application compatibility entry
#[derive(Debug)]
struct AppCompatEntry {
    in_use: bool,
    exe_path: [u8; MAX_PATH],
    exe_name: [u8; MAX_PATH],
    layer_name: [u8; MAX_LAYER_NAME],
    flags: CompatFlags,
    version_spoof: Option<WinVersion>,
}

impl AppCompatEntry {
    const fn new() -> Self {
        Self {
            in_use: false,
            exe_path: [0u8; MAX_PATH],
            exe_name: [0u8; MAX_PATH],
            layer_name: [0u8; MAX_LAYER_NAME],
            flags: CompatFlags::empty(),
            version_spoof: None,
        }
    }
}

// ============================================================================
// Shim Database (SDB) Types
// ============================================================================

/// Shim database handle
pub type HSDB = u32;

/// Invalid database handle
pub const INVALID_SDB_HANDLE: HSDB = 0;

/// Database entry tag types
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdbTagType {
    Null = 0x1000,
    Byte = 0x2000,
    Word = 0x3000,
    Dword = 0x4000,
    Qword = 0x5000,
    StringRef = 0x6000,
    List = 0x7000,
    String = 0x8000,
    Binary = 0x9000,
}

/// Common SDB tags
pub mod sdb_tags {
    pub const TAG_DATABASE: u16 = 0x7001;
    pub const TAG_LIBRARY: u16 = 0x7002;
    pub const TAG_INEXCLUDE: u16 = 0x7003;
    pub const TAG_SHIM: u16 = 0x7004;
    pub const TAG_PATCH: u16 = 0x7005;
    pub const TAG_APP: u16 = 0x7006;
    pub const TAG_EXE: u16 = 0x7007;
    pub const TAG_MATCHING_FILE: u16 = 0x7008;
    pub const TAG_SHIM_REF: u16 = 0x7009;
    pub const TAG_PATCH_REF: u16 = 0x700A;
    pub const TAG_LAYER: u16 = 0x700B;
    pub const TAG_FILE: u16 = 0x700C;
    pub const TAG_APPHELP: u16 = 0x700D;
    pub const TAG_LINK: u16 = 0x700E;
    pub const TAG_DATA: u16 = 0x700F;

    pub const TAG_NAME: u16 = 0x6001;
    pub const TAG_DESCRIPTION: u16 = 0x6002;
    pub const TAG_MODULE: u16 = 0x6003;
    pub const TAG_API: u16 = 0x6004;
    pub const TAG_VENDOR: u16 = 0x6005;
    pub const TAG_APP_NAME: u16 = 0x6006;
    pub const TAG_COMMAND_LINE: u16 = 0x6007;
    pub const TAG_COMPANY_NAME: u16 = 0x6008;
    pub const TAG_PRODUCT_NAME: u16 = 0x6009;
    pub const TAG_PRODUCT_VERSION: u16 = 0x600A;
    pub const TAG_FILE_DESCRIPTION: u16 = 0x600B;
    pub const TAG_FILE_VERSION: u16 = 0x600C;
    pub const TAG_INTERNAL_NAME: u16 = 0x600D;
    pub const TAG_LEGAL_COPYRIGHT: u16 = 0x600E;
    pub const TAG_ORIGINAL_FILENAME: u16 = 0x600F;

    pub const TAG_SIZE: u16 = 0x4001;
    pub const TAG_CHECKSUM: u16 = 0x4002;
    pub const TAG_SHIM_TAGID: u16 = 0x4003;
    pub const TAG_PATCH_TAGID: u16 = 0x4004;
    pub const TAG_OS_PLATFORM: u16 = 0x4005;
    pub const TAG_RUNTIME_PLATFORM: u16 = 0x4006;
}

// ============================================================================
// State
// ============================================================================

static APPCOMPAT_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NEXT_SDB_HANDLE: AtomicU32 = AtomicU32::new(1);
static SHIMS: SpinLock<[ShimEntry; MAX_SHIMS]> = SpinLock::new(
    [const { ShimEntry::new() }; MAX_SHIMS]
);
static LAYERS: SpinLock<[CompatLayer; MAX_LAYERS]> = SpinLock::new(
    [const { CompatLayer::new() }; MAX_LAYERS]
);
static APP_ENTRIES: SpinLock<[AppCompatEntry; MAX_APP_ENTRIES]> = SpinLock::new(
    [const { AppCompatEntry::new() }; MAX_APP_ENTRIES]
);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize application compatibility subsystem
pub fn init() {
    if APPCOMPAT_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[APPCOMPAT] Initializing application compatibility...");

    // Register default shims
    register_default_shims();

    // Register default layers
    register_default_layers();

    crate::serial_println!("[APPCOMPAT] Application compatibility initialized");
}

/// Register default shims
fn register_default_shims() {
    let default_shims: &[(&[u8], ShimType, &[u8])] = &[
        (b"VersionLie", ShimType::VersionLie, b"Spoofs Windows version"),
        (b"ForceAdminAccess", ShimType::FlagShim, b"Forces admin access checks to pass"),
        (b"VirtualRegistry", ShimType::ApiHook, b"Virtualizes registry access"),
        (b"FileVersionLie", ShimType::ApiHook, b"Lies about file versions"),
        (b"WRPMitigation", ShimType::ApiHook, b"Handles WRP protected files"),
        (b"CorrectFilePaths", ShimType::ApiHook, b"Corrects hardcoded file paths"),
        (b"HandleBadPtr", ShimType::ApiHook, b"Handles bad pointer usage"),
        (b"DisableNXShowUI", ShimType::FlagShim, b"Disables DEP with UI"),
        (b"DisableThemes", ShimType::FlagShim, b"Disables visual themes"),
        (b"Force640x480", ShimType::FlagShim, b"Forces 640x480 resolution"),
        (b"Force256Colors", ShimType::FlagShim, b"Forces 256 color mode"),
        (b"IgnoreFontQuality", ShimType::ApiHook, b"Ignores font quality settings"),
        (b"EmulateSorting", ShimType::ApiHook, b"Emulates old sorting behavior"),
        (b"EmulateHeap", ShimType::ApiHook, b"Emulates old heap behavior"),
        (b"EmulateSlowCPU", ShimType::ApiHook, b"Emulates slow CPU timing"),
    ];

    let mut shims = SHIMS.lock();

    for (i, &(name, shim_type, desc)) in default_shims.iter().enumerate() {
        if i >= MAX_SHIMS {
            break;
        }

        let shim = &mut shims[i];
        shim.in_use = true;
        shim.shim_type = shim_type;
        shim.enabled = true;

        let name_len = name.len().min(MAX_SHIM_NAME - 1);
        shim.name[..name_len].copy_from_slice(&name[..name_len]);
        shim.name[name_len] = 0;

        let desc_len = desc.len().min(127);
        shim.description[..desc_len].copy_from_slice(&desc[..desc_len]);
        shim.description[desc_len] = 0;
    }
}

/// Register default compatibility layers
fn register_default_layers() {
    let default_layers: &[(&[u8], CompatFlags, Option<WinVersion>)] = &[
        (b"WIN95", CompatFlags::DISABLE_THEMES | CompatFlags::DISABLE_DPI_SCALING, Some(versions::WIN95)),
        (b"WIN98", CompatFlags::DISABLE_THEMES | CompatFlags::DISABLE_DPI_SCALING, Some(versions::WIN98)),
        (b"NT4SP5", CompatFlags::DISABLE_THEMES, Some(versions::NT4)),
        (b"WIN2000", CompatFlags::DISABLE_THEMES, Some(versions::WIN2000)),
        (b"WINXPSP2", CompatFlags::empty(), Some(versions::WINXP)),
        (b"WINXPSP3", CompatFlags::empty(), Some(versions::WINXP)),
        (b"VISTASP1", CompatFlags::empty(), Some(versions::VISTA)),
        (b"VISTASP2", CompatFlags::empty(), Some(versions::VISTA)),
        (b"WIN7RTM", CompatFlags::empty(), Some(versions::WIN7)),
        (b"WIN8RTM", CompatFlags::empty(), Some(versions::WIN8)),
        (b"DISABLETHEMES", CompatFlags::DISABLE_THEMES, None),
        (b"DISABLEDWM", CompatFlags::DISABLE_DWM, None),
        (b"HIGHDPIAWARE", CompatFlags::HIGH_DPI_AWARE, None),
        (b"DPIUNAWARE", CompatFlags::DISABLE_DPI_SCALING, None),
        (b"640X480", CompatFlags::RES_640X480, None),
        (b"256COLOR", CompatFlags::COLOR_256, None),
        (b"RUNASINVOKER", CompatFlags::RUN_AS_INVOKER, None),
    ];

    let mut layers = LAYERS.lock();

    for (i, &(name, flags, version)) in default_layers.iter().enumerate() {
        if i >= MAX_LAYERS {
            break;
        }

        let layer = &mut layers[i];
        layer.in_use = true;
        layer.flags = flags;
        layer.version_spoof = version;

        let name_len = name.len().min(MAX_LAYER_NAME - 1);
        layer.name[..name_len].copy_from_slice(&name[..name_len]);
        layer.name[name_len] = 0;
    }
}

// ============================================================================
// Shim Database Functions
// ============================================================================

/// Open a shim database
pub fn sdb_open_database(path: &[u8]) -> HSDB {
    let _ = path;

    // Would parse and load the SDB file
    let handle = NEXT_SDB_HANDLE.fetch_add(1, Ordering::SeqCst);

    crate::serial_println!("[APPCOMPAT] Opened shim database, handle {}", handle);

    handle
}

/// Close a shim database
pub fn sdb_close_database(hsdb: HSDB) {
    let _ = hsdb;
    crate::serial_println!("[APPCOMPAT] Closed shim database");
}

/// Get match for an executable
pub fn sdb_get_matching_exe(
    hsdb: HSDB,
    exe_path: &[u8],
) -> Option<u32> {
    let _ = (hsdb, exe_path);

    // Would search database for matching entry
    None
}

/// Read tag data
pub fn sdb_read_tag(hsdb: HSDB, tag_id: u32) -> Option<u32> {
    let _ = (hsdb, tag_id);

    None
}

/// Get first child tag
pub fn sdb_get_first_child(hsdb: HSDB, parent: u32) -> Option<u32> {
    let _ = (hsdb, parent);

    None
}

/// Get next child tag
pub fn sdb_get_next_child(hsdb: HSDB, parent: u32, current: u32) -> Option<u32> {
    let _ = (hsdb, parent, current);

    None
}

/// Get string from tag
pub fn sdb_read_string_tag(hsdb: HSDB, tag_id: u32, buffer: &mut [u8]) -> usize {
    let _ = (hsdb, tag_id);

    if !buffer.is_empty() {
        buffer[0] = 0;
    }

    0
}

// ============================================================================
// Application Compatibility Functions
// ============================================================================

/// Register an application for compatibility
pub fn register_app_compat(
    exe_path: &[u8],
    layer_name: Option<&[u8]>,
    flags: CompatFlags,
    version: Option<WinVersion>,
) -> bool {
    let mut entries = APP_ENTRIES.lock();

    // Find free slot
    let slot_idx = entries.iter().position(|e| !e.in_use);
    let idx = match slot_idx {
        Some(i) => i,
        None => return false,
    };

    let entry = &mut entries[idx];
    entry.in_use = true;
    entry.flags = flags;
    entry.version_spoof = version;

    let path_len = exe_path.len().min(MAX_PATH - 1);
    entry.exe_path[..path_len].copy_from_slice(&exe_path[..path_len]);
    entry.exe_path[path_len] = 0;

    // Extract exe name from path
    let name_start = exe_path.iter().rposition(|&c| c == b'\\' || c == b'/').map(|i| i + 1).unwrap_or(0);
    let name = &exe_path[name_start..];
    let name_len = name.len().min(MAX_PATH - 1);
    entry.exe_name[..name_len].copy_from_slice(&name[..name_len]);
    entry.exe_name[name_len] = 0;

    if let Some(layer) = layer_name {
        let layer_len = layer.len().min(MAX_LAYER_NAME - 1);
        entry.layer_name[..layer_len].copy_from_slice(&layer[..layer_len]);
        entry.layer_name[layer_len] = 0;
    }

    true
}

/// Unregister application compatibility
pub fn unregister_app_compat(exe_path: &[u8]) -> bool {
    let mut entries = APP_ENTRIES.lock();

    for entry in entries.iter_mut() {
        if entry.in_use && name_matches(&entry.exe_path, exe_path) {
            entry.in_use = false;
            return true;
        }
    }

    false
}

/// Get compatibility settings for an application
pub fn get_app_compat(exe_path: &[u8]) -> Option<(CompatFlags, Option<WinVersion>)> {
    let entries = APP_ENTRIES.lock();

    // First check by full path
    for entry in entries.iter() {
        if entry.in_use && name_matches(&entry.exe_path, exe_path) {
            let mut flags = entry.flags;
            let mut version = entry.version_spoof;

            // Apply layer settings
            if str_len(&entry.layer_name) > 0 {
                if let Some((layer_flags, layer_version)) = get_layer_settings(&entry.layer_name) {
                    flags |= layer_flags;
                    if version.is_none() {
                        version = layer_version;
                    }
                }
            }

            return Some((flags, version));
        }
    }

    // Then check by exe name only
    let name_start = exe_path.iter().rposition(|&c| c == b'\\' || c == b'/').map(|i| i + 1).unwrap_or(0);
    let exe_name = &exe_path[name_start..];

    for entry in entries.iter() {
        if entry.in_use && name_matches(&entry.exe_name, exe_name) {
            let mut flags = entry.flags;
            let mut version = entry.version_spoof;

            if str_len(&entry.layer_name) > 0 {
                if let Some((layer_flags, layer_version)) = get_layer_settings(&entry.layer_name) {
                    flags |= layer_flags;
                    if version.is_none() {
                        version = layer_version;
                    }
                }
            }

            return Some((flags, version));
        }
    }

    None
}

/// Get layer settings
fn get_layer_settings(layer_name: &[u8]) -> Option<(CompatFlags, Option<WinVersion>)> {
    let layers = LAYERS.lock();

    for layer in layers.iter() {
        if layer.in_use && name_matches(&layer.name, layer_name) {
            return Some((layer.flags, layer.version_spoof));
        }
    }

    None
}

// ============================================================================
// Layer Functions
// ============================================================================

/// Apply a compatibility layer by name
pub fn apply_layer(layer_name: &[u8]) -> Option<(CompatFlags, Option<WinVersion>)> {
    get_layer_settings(layer_name)
}

/// Get list of available layers
pub fn get_available_layers(names: &mut [[u8; MAX_LAYER_NAME]]) -> usize {
    let layers = LAYERS.lock();

    let mut count = 0;

    for layer in layers.iter() {
        if layer.in_use && count < names.len() {
            let len = str_len(&layer.name);
            names[count][..len].copy_from_slice(&layer.name[..len]);
            if len < MAX_LAYER_NAME {
                names[count][len] = 0;
            }
            count += 1;
        }
    }

    count
}

/// Register a custom layer
pub fn register_layer(
    name: &[u8],
    flags: CompatFlags,
    version: Option<WinVersion>,
) -> bool {
    let mut layers = LAYERS.lock();

    let slot_idx = layers.iter().position(|l| !l.in_use);
    let idx = match slot_idx {
        Some(i) => i,
        None => return false,
    };

    let layer = &mut layers[idx];
    layer.in_use = true;
    layer.flags = flags;
    layer.version_spoof = version;

    let name_len = name.len().min(MAX_LAYER_NAME - 1);
    layer.name[..name_len].copy_from_slice(&name[..name_len]);
    layer.name[name_len] = 0;

    true
}

// ============================================================================
// Version Spoofing
// ============================================================================

/// Get spoofed version for an application
pub fn get_spoofed_version(exe_path: &[u8]) -> Option<WinVersion> {
    if let Some((_, version)) = get_app_compat(exe_path) {
        version
    } else {
        None
    }
}

/// Set version spoof for an application
pub fn set_version_spoof(exe_path: &[u8], version: WinVersion) -> bool {
    let mut entries = APP_ENTRIES.lock();

    // Update existing entry
    for entry in entries.iter_mut() {
        if entry.in_use && name_matches(&entry.exe_path, exe_path) {
            entry.version_spoof = Some(version);
            return true;
        }
    }

    // Create new entry
    drop(entries);
    register_app_compat(exe_path, None, CompatFlags::empty(), Some(version))
}

// ============================================================================
// Shim Functions
// ============================================================================

/// Get shim by name
pub fn get_shim(name: &[u8]) -> Option<ShimType> {
    let shims = SHIMS.lock();

    for shim in shims.iter() {
        if shim.in_use && shim.enabled && name_matches(&shim.name, name) {
            return Some(shim.shim_type);
        }
    }

    None
}

/// Enable/disable a shim
pub fn set_shim_enabled(name: &[u8], enabled: bool) -> bool {
    let mut shims = SHIMS.lock();

    for shim in shims.iter_mut() {
        if shim.in_use && name_matches(&shim.name, name) {
            shim.enabled = enabled;
            return true;
        }
    }

    false
}

/// Get list of available shims
pub fn get_available_shims(names: &mut [[u8; MAX_SHIM_NAME]]) -> usize {
    let shims = SHIMS.lock();

    let mut count = 0;

    for shim in shims.iter() {
        if shim.in_use && count < names.len() {
            let len = str_len(&shim.name);
            names[count][..len].copy_from_slice(&shim.name[..len]);
            if len < MAX_SHIM_NAME {
                names[count][len] = 0;
            }
            count += 1;
        }
    }

    count
}

// ============================================================================
// Environment Variable Compat
// ============================================================================

/// Get __COMPAT_LAYER environment variable value
pub fn get_compat_layer_env(exe_path: &[u8], buffer: &mut [u8]) -> usize {
    if let Some((flags, _)) = get_app_compat(exe_path) {
        // Build layer string from flags
        let mut pos = 0;

        if flags.contains(CompatFlags::RUN_AS_INVOKER) {
            let s = b"RUNASINVOKER ";
            let len = s.len().min(buffer.len() - pos);
            buffer[pos..pos + len].copy_from_slice(&s[..len]);
            pos += len;
        }

        if flags.contains(CompatFlags::DISABLE_THEMES) {
            let s = b"DISABLETHEMES ";
            let len = s.len().min(buffer.len() - pos);
            buffer[pos..pos + len].copy_from_slice(&s[..len]);
            pos += len;
        }

        if flags.contains(CompatFlags::HIGH_DPI_AWARE) {
            let s = b"HIGHDPIAWARE ";
            let len = s.len().min(buffer.len() - pos);
            buffer[pos..pos + len].copy_from_slice(&s[..len]);
            pos += len;
        }

        // Null terminate
        if pos > 0 && pos < buffer.len() {
            buffer[pos - 1] = 0; // Replace trailing space with null
        } else if pos < buffer.len() {
            buffer[pos] = 0;
        }

        return pos;
    }

    if !buffer.is_empty() {
        buffer[0] = 0;
    }
    0
}

// ============================================================================
// AppHelp Functions
// ============================================================================

/// AppHelp message type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppHelpType {
    #[default]
    None = 0,
    /// Block the application
    Block = 1,
    /// Display a warning
    Warn = 2,
    /// Minor issues
    MinorProblem = 3,
    /// Reinstall recommendation
    Reinstall = 4,
    /// Message only
    Message = 5,
}

/// Check if application has AppHelp entry
pub fn check_app_help(exe_path: &[u8]) -> Option<(AppHelpType, [u8; 256])> {
    let _ = exe_path;

    // Would check shim database for AppHelp entries
    None
}

/// Display AppHelp dialog
pub fn show_app_help(
    hwnd_parent: super::HWND,
    help_type: AppHelpType,
    message: &[u8],
    app_name: &[u8],
) -> bool {
    let _ = (hwnd_parent, help_type, message, app_name);

    crate::serial_println!("[APPCOMPAT] AppHelp dialog requested");

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

/// Application compatibility statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct AppCompatStats {
    pub initialized: bool,
    pub shim_count: u32,
    pub layer_count: u32,
    pub app_entry_count: u32,
}

/// Get application compatibility statistics
pub fn get_stats() -> AppCompatStats {
    let shims = SHIMS.lock();
    let layers = LAYERS.lock();
    let entries = APP_ENTRIES.lock();

    AppCompatStats {
        initialized: APPCOMPAT_INITIALIZED.load(Ordering::Relaxed),
        shim_count: shims.iter().filter(|s| s.in_use).count() as u32,
        layer_count: layers.iter().filter(|l| l.in_use).count() as u32,
        app_entry_count: entries.iter().filter(|e| e.in_use).count() as u32,
    }
}
