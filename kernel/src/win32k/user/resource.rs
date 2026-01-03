//! Resource Manager - Windows Resource Loading
//!
//! Implements resource loading following the Windows NT resource architecture.
//! Resources are stored in PE files and organized by type, name, and language.
//!
//! # Resource Types
//!
//! - RT_STRING: String tables (stored in 16-string blocks)
//! - RT_ICON/RT_GROUP_ICON: Icons
//! - RT_CURSOR/RT_GROUP_CURSOR: Cursors
//! - RT_BITMAP: Bitmaps
//! - RT_DIALOG: Dialog templates
//! - RT_MENU: Menu templates
//! - RT_ACCELERATOR: Accelerator tables
//! - RT_RCDATA: Raw data
//!
//! # String Table Format
//!
//! String tables are stored in 16-string blocks:
//! - Resource ID = (string_id >> 4) + 1
//! - String index within block = string_id & 0x0F
//! - Each string is PASCAL-style: length word followed by Unicode chars
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/client/rtlres.c` - LoadStringOrError
//! - `windows/core/ntuser/client/clres.c` - Resource loading
//! - `base/win32/client/module.c` - FindResource/LoadResource

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::HINSTANCE;

// ============================================================================
// Resource Types (RT_*)
// ============================================================================

/// Cursor resource type
pub const RT_CURSOR: u32 = 1;
/// Bitmap resource type
pub const RT_BITMAP: u32 = 2;
/// Icon resource type
pub const RT_ICON: u32 = 3;
/// Menu resource type
pub const RT_MENU: u32 = 4;
/// Dialog template resource type
pub const RT_DIALOG: u32 = 5;
/// String table resource type
pub const RT_STRING: u32 = 6;
/// Font directory resource type
pub const RT_FONTDIR: u32 = 7;
/// Font resource type
pub const RT_FONT: u32 = 8;
/// Accelerator table resource type
pub const RT_ACCELERATOR: u32 = 9;
/// Raw data resource type
pub const RT_RCDATA: u32 = 10;
/// Message table resource type
pub const RT_MESSAGETABLE: u32 = 11;
/// Group cursor resource type
pub const RT_GROUP_CURSOR: u32 = 12;
/// Group icon resource type
pub const RT_GROUP_ICON: u32 = 14;
/// Version info resource type
pub const RT_VERSION: u32 = 16;
/// Dialog include resource type
pub const RT_DLGINCLUDE: u32 = 17;
/// Plug and Play resource type
pub const RT_PLUGPLAY: u32 = 19;
/// VxD resource type
pub const RT_VXD: u32 = 20;
/// Animated cursor resource type
pub const RT_ANICURSOR: u32 = 21;
/// Animated icon resource type
pub const RT_ANIICON: u32 = 22;
/// HTML resource type
pub const RT_HTML: u32 = 23;
/// Manifest resource type
pub const RT_MANIFEST: u32 = 24;

// ============================================================================
// Resource Handle Types
// ============================================================================

/// Resource info handle (from FindResource)
pub type HRSRC = u32;

/// Global memory handle (from LoadResource)
pub type HGLOBAL = u32;

// ============================================================================
// Configuration
// ============================================================================

/// Maximum number of loaded modules with resources
const MAX_MODULES: usize = 64;

/// Maximum number of cached resources per module
const MAX_RESOURCES_PER_MODULE: usize = 256;

/// Maximum string table entries
const MAX_STRING_TABLES: usize = 128;

/// Maximum string length for string table entries
const MAX_STRING_LENGTH: usize = 256;

/// Strings per block in string tables
const STRINGS_PER_BLOCK: usize = 16;

// ============================================================================
// Structures
// ============================================================================

/// Resource entry in a module
#[derive(Clone, Copy)]
struct ResourceEntry {
    /// Resource in use
    in_use: bool,
    /// Resource type
    res_type: u32,
    /// Resource name/ID
    res_id: u32,
    /// Language ID
    lang_id: u16,
    /// Resource data offset
    data_offset: usize,
    /// Resource data size
    data_size: usize,
    /// Lock count
    lock_count: u32,
}

impl ResourceEntry {
    const fn new() -> Self {
        Self {
            in_use: false,
            res_type: 0,
            res_id: 0,
            lang_id: 0,
            data_offset: 0,
            data_size: 0,
            lock_count: 0,
        }
    }
}

/// Loaded module with resources
#[derive(Clone, Copy)]
struct ResourceModule {
    /// Module in use
    in_use: bool,
    /// Module instance handle
    hinstance: HINSTANCE,
    /// Module base address
    base_address: usize,
    /// Resource directory offset
    resource_dir_offset: usize,
    /// Number of loaded resources
    resource_count: usize,
}

impl ResourceModule {
    const fn new() -> Self {
        Self {
            in_use: false,
            hinstance: HINSTANCE(0),
            base_address: 0,
            resource_dir_offset: 0,
            resource_count: 0,
        }
    }
}

/// String table block (16 strings)
#[derive(Clone, Copy)]
struct StringTableBlock {
    /// Block in use
    in_use: bool,
    /// Module instance
    hinstance: HINSTANCE,
    /// Block ID (1-based, corresponds to (string_id >> 4) + 1)
    block_id: u32,
    /// Language ID
    lang_id: u16,
    /// String lengths
    lengths: [u16; STRINGS_PER_BLOCK],
    /// String data (UTF-8 encoded for simplicity)
    strings: [[u8; MAX_STRING_LENGTH]; STRINGS_PER_BLOCK],
}

impl StringTableBlock {
    const fn new() -> Self {
        Self {
            in_use: false,
            hinstance: HINSTANCE(0),
            block_id: 0,
            lang_id: 0,
            lengths: [0; STRINGS_PER_BLOCK],
            strings: [[0; MAX_STRING_LENGTH]; STRINGS_PER_BLOCK],
        }
    }
}

/// System string table (kernel strings)
struct SystemStringTable {
    /// String ID
    id: u32,
    /// String value
    value: &'static str,
}

// ============================================================================
// Global State
// ============================================================================

/// Resource subsystem initialized
static RESOURCE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Resource subsystem lock
static RESOURCE_LOCK: SpinLock<()> = SpinLock::new(());

/// Loaded modules
static MODULES: SpinLock<[ResourceModule; MAX_MODULES]> =
    SpinLock::new([const { ResourceModule::new() }; MAX_MODULES]);

/// Cached resource entries
static RESOURCES: SpinLock<[ResourceEntry; MAX_RESOURCES_PER_MODULE]> =
    SpinLock::new([const { ResourceEntry::new() }; MAX_RESOURCES_PER_MODULE]);

/// String table cache
static STRING_TABLES: SpinLock<[StringTableBlock; MAX_STRING_TABLES]> =
    SpinLock::new([const { StringTableBlock::new() }; MAX_STRING_TABLES]);

/// Next resource handle
static NEXT_RSRC_HANDLE: AtomicU32 = AtomicU32::new(1);

/// Resource allocation count
static RESOURCE_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// System String Table
// ============================================================================

/// Default system strings
static SYSTEM_STRINGS: &[SystemStringTable] = &[
    SystemStringTable { id: 0, value: "" },
    SystemStringTable { id: 1, value: "OK" },
    SystemStringTable { id: 2, value: "Cancel" },
    SystemStringTable { id: 3, value: "&Abort" },
    SystemStringTable { id: 4, value: "&Retry" },
    SystemStringTable { id: 5, value: "&Ignore" },
    SystemStringTable { id: 6, value: "&Yes" },
    SystemStringTable { id: 7, value: "&No" },
    SystemStringTable { id: 8, value: "&Close" },
    SystemStringTable { id: 9, value: "Help" },
    SystemStringTable { id: 10, value: "Try &Again" },
    SystemStringTable { id: 11, value: "&Continue" },
    // Window control strings
    SystemStringTable { id: 100, value: "Error" },
    SystemStringTable { id: 101, value: "Warning" },
    SystemStringTable { id: 102, value: "Information" },
    SystemStringTable { id: 103, value: "Confirm" },
    SystemStringTable { id: 104, value: "Question" },
    // Menu strings
    SystemStringTable { id: 200, value: "&File" },
    SystemStringTable { id: 201, value: "&Edit" },
    SystemStringTable { id: 202, value: "&View" },
    SystemStringTable { id: 203, value: "&Help" },
    SystemStringTable { id: 210, value: "&New\tCtrl+N" },
    SystemStringTable { id: 211, value: "&Open...\tCtrl+O" },
    SystemStringTable { id: 212, value: "&Save\tCtrl+S" },
    SystemStringTable { id: 213, value: "Save &As..." },
    SystemStringTable { id: 214, value: "E&xit\tAlt+F4" },
    SystemStringTable { id: 220, value: "&Undo\tCtrl+Z" },
    SystemStringTable { id: 221, value: "Cu&t\tCtrl+X" },
    SystemStringTable { id: 222, value: "&Copy\tCtrl+C" },
    SystemStringTable { id: 223, value: "&Paste\tCtrl+V" },
    SystemStringTable { id: 224, value: "&Delete\tDel" },
    SystemStringTable { id: 225, value: "Select &All\tCtrl+A" },
    SystemStringTable { id: 230, value: "&Find...\tCtrl+F" },
    SystemStringTable { id: 231, value: "Find &Next\tF3" },
    SystemStringTable { id: 232, value: "&Replace...\tCtrl+H" },
    SystemStringTable { id: 233, value: "&Go To...\tCtrl+G" },
    // Common control strings
    SystemStringTable { id: 300, value: "&Print...\tCtrl+P" },
    SystemStringTable { id: 301, value: "Print Pre&view" },
    SystemStringTable { id: 302, value: "Page Set&up..." },
    SystemStringTable { id: 310, value: "&Properties" },
    SystemStringTable { id: 311, value: "&Options..." },
    SystemStringTable { id: 312, value: "Preferences..." },
    // System strings
    SystemStringTable { id: 400, value: "System" },
    SystemStringTable { id: 401, value: "Application" },
    SystemStringTable { id: 402, value: "Windows" },
    SystemStringTable { id: 403, value: "Program" },
    SystemStringTable { id: 410, value: "Untitled" },
    SystemStringTable { id: 411, value: "(Not Responding)" },
    SystemStringTable { id: 412, value: "Loading..." },
    SystemStringTable { id: 413, value: "Please wait..." },
    // Error strings
    SystemStringTable { id: 500, value: "Not enough memory to complete this operation." },
    SystemStringTable { id: 501, value: "Cannot find the specified file." },
    SystemStringTable { id: 502, value: "Access denied." },
    SystemStringTable { id: 503, value: "Invalid operation." },
    SystemStringTable { id: 504, value: "The operation was canceled." },
    SystemStringTable { id: 505, value: "An unknown error occurred." },
    // Dialog strings
    SystemStringTable { id: 600, value: "Apply" },
    SystemStringTable { id: 601, value: "Browse..." },
    SystemStringTable { id: 602, value: "Finish" },
    SystemStringTable { id: 603, value: "Back" },
    SystemStringTable { id: 604, value: "Next" },
    SystemStringTable { id: 605, value: "Reset" },
    SystemStringTable { id: 606, value: "Default" },
];

// ============================================================================
// Initialization
// ============================================================================

/// Initialize resource manager
pub fn init() {
    let _guard = RESOURCE_LOCK.lock();

    if RESOURCE_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[RESOURCE] Initializing Resource Manager...");

    // Initialize string tables with system strings
    init_system_string_tables();

    RESOURCE_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[RESOURCE] Resource Manager initialized");
}

/// Initialize system string tables
fn init_system_string_tables() {
    let mut tables = STRING_TABLES.lock();

    // Group system strings into blocks of 16
    // Each block contains strings with IDs from (block_id - 1) * 16 to block_id * 16 - 1
    for string_entry in SYSTEM_STRINGS {
        let block_id = (string_entry.id >> 4) + 1;
        let string_index = (string_entry.id & 0x0F) as usize;

        // Find or create block
        let mut block_idx = None;
        for (i, block) in tables.iter().enumerate() {
            if block.in_use && block.hinstance.0 == 0 && block.block_id == block_id {
                block_idx = Some(i);
                break;
            }
        }

        let idx = if let Some(idx) = block_idx {
            idx
        } else {
            // Find empty slot
            let mut found = None;
            for (i, block) in tables.iter().enumerate() {
                if !block.in_use {
                    found = Some(i);
                    break;
                }
            }

            if let Some(idx) = found {
                tables[idx].in_use = true;
                tables[idx].hinstance = HINSTANCE(0);
                tables[idx].block_id = block_id;
                tables[idx].lang_id = 0; // Neutral
                idx
            } else {
                continue; // No space
            }
        };

        // Copy string into block
        let bytes = string_entry.value.as_bytes();
        let len = bytes.len().min(MAX_STRING_LENGTH);
        tables[idx].lengths[string_index] = len as u16;
        for (i, &b) in bytes.iter().take(len).enumerate() {
            tables[idx].strings[string_index][i] = b;
        }
    }
}

// ============================================================================
// Resource Loading API
// ============================================================================

/// Find a resource in a module
///
/// # Arguments
/// * `hmodule` - Module instance (NULL for current process)
/// * `name` - Resource name or ID (MAKEINTRESOURCE)
/// * `res_type` - Resource type
///
/// # Returns
/// Resource info handle (HRSRC) or 0 if not found
pub fn find_resource(hmodule: HINSTANCE, name: u32, res_type: u32) -> HRSRC {
    find_resource_ex(hmodule, res_type, name, 0)
}

/// Find a resource with language
///
/// # Arguments
/// * `hmodule` - Module instance
/// * `res_type` - Resource type
/// * `name` - Resource name or ID
/// * `lang_id` - Language ID (0 for neutral)
///
/// # Returns
/// Resource info handle (HRSRC) or 0 if not found
pub fn find_resource_ex(hmodule: HINSTANCE, res_type: u32, name: u32, lang_id: u16) -> HRSRC {
    let mut resources = RESOURCES.lock();

    // Check if already cached
    for (i, res) in resources.iter().enumerate() {
        if res.in_use
            && (hmodule.0 == 0 || res.res_id >> 16 == hmodule.0)
            && res.res_type == res_type
            && (res.res_id & 0xFFFF) == name
            && (lang_id == 0 || res.lang_id == lang_id)
        {
            return (i + 1) as HRSRC;
        }
    }

    // Create new resource entry
    for (i, res) in resources.iter_mut().enumerate() {
        if !res.in_use {
            res.in_use = true;
            res.res_type = res_type;
            res.res_id = (hmodule.0 << 16) | name;
            res.lang_id = lang_id;
            res.data_offset = 0;
            res.data_size = 0;
            res.lock_count = 0;

            RESOURCE_COUNT.fetch_add(1, Ordering::Relaxed);
            return (i + 1) as HRSRC;
        }
    }

    0
}

/// Load a resource into memory
///
/// # Arguments
/// * `hmodule` - Module instance
/// * `hrsrc` - Resource info handle from FindResource
///
/// # Returns
/// Handle to loaded resource data or 0 on failure
pub fn load_resource(hmodule: HINSTANCE, hrsrc: HRSRC) -> HGLOBAL {
    let _hmodule = hmodule; // Will be used when PE parsing is implemented

    if hrsrc == 0 {
        return 0;
    }

    let mut resources = RESOURCES.lock();
    let idx = (hrsrc - 1) as usize;

    if idx >= resources.len() || !resources[idx].in_use {
        return 0;
    }

    // Increment lock count
    resources[idx].lock_count += 1;

    // Return resource handle (same as HRSRC for now)
    hrsrc as HGLOBAL
}

/// Get pointer to resource data
///
/// # Arguments
/// * `hres_data` - Handle from LoadResource
///
/// # Returns
/// Pointer to resource data or 0
pub fn lock_resource(hres_data: HGLOBAL) -> usize {
    if hres_data == 0 {
        return 0;
    }

    let resources = RESOURCES.lock();
    let idx = (hres_data - 1) as usize;

    if idx >= resources.len() || !resources[idx].in_use {
        return 0;
    }

    // Return data offset as pointer (will be actual address when PE parsing is done)
    resources[idx].data_offset
}

/// Get resource size
///
/// # Arguments
/// * `hmodule` - Module instance
/// * `hrsrc` - Resource info handle
///
/// # Returns
/// Size of resource in bytes
pub fn sizeof_resource(hmodule: HINSTANCE, hrsrc: HRSRC) -> u32 {
    let _hmodule = hmodule;

    if hrsrc == 0 {
        return 0;
    }

    let resources = RESOURCES.lock();
    let idx = (hrsrc - 1) as usize;

    if idx >= resources.len() || !resources[idx].in_use {
        return 0;
    }

    resources[idx].data_size as u32
}

/// Free a resource
///
/// # Arguments
/// * `hres_data` - Handle from LoadResource
///
/// # Returns
/// true if successful
pub fn free_resource(hres_data: HGLOBAL) -> bool {
    if hres_data == 0 {
        return false;
    }

    let mut resources = RESOURCES.lock();
    let idx = (hres_data - 1) as usize;

    if idx >= resources.len() || !resources[idx].in_use {
        return false;
    }

    // Decrement lock count
    if resources[idx].lock_count > 0 {
        resources[idx].lock_count -= 1;
    }

    // Don't actually free - resources are cached
    true
}

// ============================================================================
// String Loading API
// ============================================================================

/// Load a string from string table
///
/// # Arguments
/// * `hinstance` - Module instance (0 for system strings)
/// * `id` - String ID
/// * `buffer` - Output buffer
///
/// # Returns
/// Number of characters copied (not including null)
pub fn load_string(hinstance: HINSTANCE, id: u32, buffer: &mut [u8]) -> usize {
    load_string_ex(hinstance, id, buffer, 0)
}

/// Load a string with language
///
/// # Arguments
/// * `hinstance` - Module instance (0 for system strings)
/// * `id` - String ID
/// * `buffer` - Output buffer
/// * `lang_id` - Language ID (0 for default)
///
/// # Returns
/// Number of characters copied (not including null)
pub fn load_string_ex(hinstance: HINSTANCE, id: u32, buffer: &mut [u8], lang_id: u16) -> usize {
    if buffer.is_empty() {
        return 0;
    }

    let block_id = (id >> 4) + 1;
    let string_index = (id & 0x0F) as usize;

    let tables = STRING_TABLES.lock();

    // Find the string block
    for block in tables.iter() {
        if block.in_use
            && block.hinstance == hinstance
            && block.block_id == block_id
            && (lang_id == 0 || block.lang_id == lang_id)
        {
            let len = block.lengths[string_index] as usize;
            if len == 0 {
                buffer[0] = 0;
                return 0;
            }

            let copy_len = len.min(buffer.len() - 1);
            for i in 0..copy_len {
                buffer[i] = block.strings[string_index][i];
            }
            buffer[copy_len] = 0;

            return copy_len;
        }
    }

    // String not found
    buffer[0] = 0;
    0
}

/// Add a string table block
///
/// # Arguments
/// * `hinstance` - Module instance
/// * `block_id` - Block ID (1-based)
/// * `strings` - Array of 16 strings
/// * `lang_id` - Language ID
///
/// # Returns
/// true if successful
pub fn add_string_block(
    hinstance: HINSTANCE,
    block_id: u32,
    strings: &[&str; 16],
    lang_id: u16,
) -> bool {
    let mut tables = STRING_TABLES.lock();

    // Check if block already exists
    for block in tables.iter() {
        if block.in_use
            && block.hinstance == hinstance
            && block.block_id == block_id
            && block.lang_id == lang_id
        {
            return false; // Already exists
        }
    }

    // Find empty slot
    for block in tables.iter_mut() {
        if !block.in_use {
            block.in_use = true;
            block.hinstance = hinstance;
            block.block_id = block_id;
            block.lang_id = lang_id;

            for (i, &s) in strings.iter().enumerate() {
                let bytes = s.as_bytes();
                let len = bytes.len().min(MAX_STRING_LENGTH);
                block.lengths[i] = len as u16;
                for (j, &b) in bytes.iter().take(len).enumerate() {
                    block.strings[i][j] = b;
                }
            }

            return true;
        }
    }

    false
}

/// Set a single string in a string table
///
/// # Arguments
/// * `hinstance` - Module instance
/// * `id` - String ID
/// * `value` - String value
/// * `lang_id` - Language ID
///
/// # Returns
/// true if successful
pub fn set_string(hinstance: HINSTANCE, id: u32, value: &str, lang_id: u16) -> bool {
    let block_id = (id >> 4) + 1;
    let string_index = (id & 0x0F) as usize;

    let mut tables = STRING_TABLES.lock();

    // Find or create block
    let mut found_idx = None;
    for (i, block) in tables.iter().enumerate() {
        if block.in_use
            && block.hinstance == hinstance
            && block.block_id == block_id
            && (lang_id == 0 || block.lang_id == lang_id)
        {
            found_idx = Some(i);
            break;
        }
    }

    if found_idx.is_none() {
        // Create new block
        for (i, block) in tables.iter_mut().enumerate() {
            if !block.in_use {
                block.in_use = true;
                block.hinstance = hinstance;
                block.block_id = block_id;
                block.lang_id = lang_id;
                block.lengths = [0; STRINGS_PER_BLOCK];
                block.strings = [[0; MAX_STRING_LENGTH]; STRINGS_PER_BLOCK];
                found_idx = Some(i);
                break;
            }
        }
    }

    if let Some(idx) = found_idx {
        let bytes = value.as_bytes();
        let len = bytes.len().min(MAX_STRING_LENGTH);
        tables[idx].lengths[string_index] = len as u16;

        // Clear string first
        for j in 0..MAX_STRING_LENGTH {
            tables[idx].strings[string_index][j] = 0;
        }

        // Copy new value
        for (j, &b) in bytes.iter().take(len).enumerate() {
            tables[idx].strings[string_index][j] = b;
        }

        return true;
    }

    false
}

/// Remove a string table block
///
/// # Arguments
/// * `hinstance` - Module instance
/// * `block_id` - Block ID
///
/// # Returns
/// true if removed
pub fn remove_string_block(hinstance: HINSTANCE, block_id: u32) -> bool {
    let mut tables = STRING_TABLES.lock();

    for block in tables.iter_mut() {
        if block.in_use && block.hinstance == hinstance && block.block_id == block_id {
            block.in_use = false;
            return true;
        }
    }

    false
}

// ============================================================================
// Module Resource Management
// ============================================================================

/// Register a module for resource loading
///
/// # Arguments
/// * `hinstance` - Module instance handle
/// * `base_address` - Module base address in memory
/// * `resource_dir_offset` - Offset to resource directory
///
/// # Returns
/// true if successful
pub fn register_module(
    hinstance: HINSTANCE,
    base_address: usize,
    resource_dir_offset: usize,
) -> bool {
    let mut modules = MODULES.lock();

    // Check if already registered
    for module in modules.iter() {
        if module.in_use && module.hinstance == hinstance {
            return false;
        }
    }

    // Find empty slot
    for module in modules.iter_mut() {
        if !module.in_use {
            module.in_use = true;
            module.hinstance = hinstance;
            module.base_address = base_address;
            module.resource_dir_offset = resource_dir_offset;
            module.resource_count = 0;
            return true;
        }
    }

    false
}

/// Unregister a module
///
/// # Arguments
/// * `hinstance` - Module instance handle
///
/// # Returns
/// true if removed
pub fn unregister_module(hinstance: HINSTANCE) -> bool {
    let mut modules = MODULES.lock();

    for module in modules.iter_mut() {
        if module.in_use && module.hinstance == hinstance {
            module.in_use = false;

            // Clear associated resources
            let mut resources = RESOURCES.lock();
            for res in resources.iter_mut() {
                if res.in_use && (res.res_id >> 16) == hinstance.0 {
                    res.in_use = false;
                    RESOURCE_COUNT.fetch_sub(1, Ordering::Relaxed);
                }
            }

            // Clear associated string tables
            let mut tables = STRING_TABLES.lock();
            for table in tables.iter_mut() {
                if table.in_use && table.hinstance == hinstance {
                    table.in_use = false;
                }
            }

            return true;
        }
    }

    false
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Create an integer resource ID from a number
///
/// Equivalent to Windows MAKEINTRESOURCE macro
#[inline]
pub const fn make_int_resource(id: u16) -> u32 {
    id as u32
}

/// Check if a value is an integer resource ID
///
/// Equivalent to Windows IS_INTRESOURCE macro
#[inline]
pub const fn is_int_resource(value: u32) -> bool {
    // High word is 0 for integer resources
    (value >> 16) == 0
}

/// Get resource type name
pub fn get_resource_type_name(res_type: u32) -> &'static str {
    match res_type {
        RT_CURSOR => "CURSOR",
        RT_BITMAP => "BITMAP",
        RT_ICON => "ICON",
        RT_MENU => "MENU",
        RT_DIALOG => "DIALOG",
        RT_STRING => "STRING",
        RT_FONTDIR => "FONTDIR",
        RT_FONT => "FONT",
        RT_ACCELERATOR => "ACCELERATOR",
        RT_RCDATA => "RCDATA",
        RT_MESSAGETABLE => "MESSAGETABLE",
        RT_GROUP_CURSOR => "GROUP_CURSOR",
        RT_GROUP_ICON => "GROUP_ICON",
        RT_VERSION => "VERSION",
        RT_DLGINCLUDE => "DLGINCLUDE",
        RT_PLUGPLAY => "PLUGPLAY",
        RT_VXD => "VXD",
        RT_ANICURSOR => "ANICURSOR",
        RT_ANIICON => "ANIICON",
        RT_HTML => "HTML",
        RT_MANIFEST => "MANIFEST",
        _ => "UNKNOWN",
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Get number of cached resources
pub fn get_resource_count() -> u32 {
    RESOURCE_COUNT.load(Ordering::Relaxed)
}

/// Get number of registered modules
pub fn get_module_count() -> usize {
    let modules = MODULES.lock();
    modules.iter().filter(|m| m.in_use).count()
}

/// Get number of string table blocks
pub fn get_string_table_count() -> usize {
    let tables = STRING_TABLES.lock();
    tables.iter().filter(|t| t.in_use).count()
}
