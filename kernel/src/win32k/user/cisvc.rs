//! Indexing Service (cisvc)
//!
//! Windows Server 2003 Indexing Service snap-in implementation.
//! Provides content indexing and full-text search catalogs.
//!
//! # Features
//!
//! - Catalog management
//! - Index directories
//! - Property caching
//! - Query support
//! - Merge and scan operations
//!
//! # References
//!
//! Based on Windows Server 2003 Indexing Service snap-in

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::UserHandle;

/// HWND type alias
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum catalogs
const MAX_CATALOGS: usize = 16;

/// Maximum directories per catalog
const MAX_DIRECTORIES: usize = 32;

/// Maximum properties per catalog
const MAX_PROPERTIES: usize = 64;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum path length
const MAX_PATH_LEN: usize = 260;

// ============================================================================
// Catalog State
// ============================================================================

/// Catalog state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CatalogState {
    /// Catalog is stopped
    #[default]
    Stopped = 0,
    /// Catalog is started
    Started = 1,
    /// Catalog is starting
    Starting = 2,
    /// Catalog is stopping
    Stopping = 3,
    /// Catalog is paused
    Paused = 4,
    /// Read-only mode
    ReadOnly = 5,
}

impl CatalogState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Stopped => "Stopped",
            Self::Started => "Started",
            Self::Starting => "Starting",
            Self::Stopping => "Stopping",
            Self::Paused => "Paused",
            Self::ReadOnly => "Read Only",
        }
    }
}

// ============================================================================
// Directory Include/Exclude
// ============================================================================

/// Directory inclusion type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DirectoryType {
    /// Include directory in indexing
    #[default]
    Include = 0,
    /// Exclude directory from indexing
    Exclude = 1,
}

/// Indexed directory
#[derive(Clone, Copy)]
pub struct IndexedDirectory {
    /// Directory path
    pub path: [u8; MAX_PATH_LEN],
    /// Path length
    pub path_len: u16,
    /// Directory type (include/exclude)
    pub dir_type: DirectoryType,
    /// Alias (virtual root)
    pub alias: [u8; MAX_NAME_LEN],
    /// Alias length
    pub alias_len: u8,
    /// Directory is in use
    pub in_use: bool,
}

impl IndexedDirectory {
    pub const fn new() -> Self {
        Self {
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            dir_type: DirectoryType::Include,
            alias: [0u8; MAX_NAME_LEN],
            alias_len: 0,
            in_use: false,
        }
    }

    pub fn set_path(&mut self, path: &[u8]) {
        let len = path.len().min(MAX_PATH_LEN);
        self.path[..len].copy_from_slice(&path[..len]);
        self.path_len = len as u16;
    }

    pub fn get_path(&self) -> &[u8] {
        &self.path[..self.path_len as usize]
    }

    pub fn set_alias(&mut self, alias: &[u8]) {
        let len = alias.len().min(MAX_NAME_LEN);
        self.alias[..len].copy_from_slice(&alias[..len]);
        self.alias_len = len as u8;
    }
}

// ============================================================================
// Property Type
// ============================================================================

/// Property data type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PropertyType {
    /// String type
    #[default]
    String = 0,
    /// Integer type
    Integer = 1,
    /// Date/time type
    DateTime = 2,
    /// Boolean type
    Boolean = 3,
    /// GUID type
    Guid = 4,
}

impl PropertyType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::String => "String",
            Self::Integer => "Integer",
            Self::DateTime => "Date/Time",
            Self::Boolean => "Boolean",
            Self::Guid => "GUID",
        }
    }
}

/// Cached property
#[derive(Clone, Copy)]
pub struct CachedProperty {
    /// Property name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: u8,
    /// Property type
    pub prop_type: PropertyType,
    /// Property is cached
    pub cached: bool,
    /// Cache size (for variable-length)
    pub cache_size: u32,
    /// Property is in use
    pub in_use: bool,
}

impl CachedProperty {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            prop_type: PropertyType::String,
            cached: true,
            cache_size: 0,
            in_use: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u8;
    }

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

// ============================================================================
// Catalog
// ============================================================================

/// Index catalog
pub struct IndexCatalog {
    /// Catalog name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: u8,
    /// Catalog location (directory)
    pub location: [u8; MAX_PATH_LEN],
    /// Location length
    pub location_len: u16,
    /// Catalog state
    pub state: CatalogState,
    /// Indexed directories
    pub directories: [IndexedDirectory; MAX_DIRECTORIES],
    /// Directory count
    pub directory_count: u32,
    /// Cached properties
    pub properties: [CachedProperty; MAX_PROPERTIES],
    /// Property count
    pub property_count: u32,
    /// Total documents indexed
    pub documents_indexed: u64,
    /// Documents pending indexing
    pub documents_pending: u64,
    /// Deferred documents (locked files)
    pub documents_deferred: u64,
    /// Filtered documents (rejected)
    pub documents_filtered: u64,
    /// Total files processed
    pub files_total: u64,
    /// Unique keys (words) indexed
    pub unique_keys: u64,
    /// Index size in bytes
    pub index_size: u64,
    /// Property cache size in bytes
    pub prop_cache_size: u64,
    /// Last scan time
    pub last_scan: u64,
    /// Last merge time
    pub last_merge: u64,
    /// Catalog is in use
    pub in_use: bool,
    /// Generate abstracts
    pub generate_abstracts: bool,
    /// Abstract size (characters)
    pub abstract_size: u32,
    /// Tracking enabled (NTFS USN)
    pub tracking_enabled: bool,
}

impl IndexCatalog {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            location: [0u8; MAX_PATH_LEN],
            location_len: 0,
            state: CatalogState::Stopped,
            directories: [const { IndexedDirectory::new() }; MAX_DIRECTORIES],
            directory_count: 0,
            properties: [const { CachedProperty::new() }; MAX_PROPERTIES],
            property_count: 0,
            documents_indexed: 0,
            documents_pending: 0,
            documents_deferred: 0,
            documents_filtered: 0,
            files_total: 0,
            unique_keys: 0,
            index_size: 0,
            prop_cache_size: 0,
            last_scan: 0,
            last_merge: 0,
            in_use: false,
            generate_abstracts: true,
            abstract_size: 320,
            tracking_enabled: true,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u8;
    }

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    pub fn set_location(&mut self, location: &[u8]) {
        let len = location.len().min(MAX_PATH_LEN);
        self.location[..len].copy_from_slice(&location[..len]);
        self.location_len = len as u16;
    }

    /// Add a directory to the catalog
    pub fn add_directory(&mut self, path: &[u8], dir_type: DirectoryType, alias: &[u8]) -> Option<usize> {
        for (i, dir) in self.directories.iter_mut().enumerate() {
            if !dir.in_use {
                dir.set_path(path);
                dir.dir_type = dir_type;
                dir.set_alias(alias);
                dir.in_use = true;
                self.directory_count += 1;
                return Some(i);
            }
        }
        None
    }

    /// Remove a directory from the catalog
    pub fn remove_directory(&mut self, index: usize) -> bool {
        if index < MAX_DIRECTORIES && self.directories[index].in_use {
            self.directories[index].in_use = false;
            self.directory_count = self.directory_count.saturating_sub(1);
            true
        } else {
            false
        }
    }

    /// Add a cached property
    pub fn add_property(&mut self, name: &[u8], prop_type: PropertyType, cached: bool) -> Option<usize> {
        for (i, prop) in self.properties.iter_mut().enumerate() {
            if !prop.in_use {
                prop.set_name(name);
                prop.prop_type = prop_type;
                prop.cached = cached;
                prop.in_use = true;
                self.property_count += 1;
                return Some(i);
            }
        }
        None
    }
}

// ============================================================================
// Service Configuration
// ============================================================================

/// Indexing Service configuration
pub struct IndexingConfig {
    /// Service enabled
    pub enabled: bool,
    /// Filter files with unknown extensions
    pub filter_unknown: bool,
    /// Index files with unknown extensions
    pub index_unknown: bool,
    /// Generate characterizations (abstracts)
    pub characterizations: bool,
    /// Maximum catalogs
    pub max_catalogs: u32,
    /// Maximum threads
    pub max_threads: u32,
    /// Min idle time before indexing (seconds)
    pub idle_time: u32,
    /// Low disk space threshold (MB)
    pub disk_space_threshold: u32,
}

impl IndexingConfig {
    pub const fn new() -> Self {
        Self {
            enabled: true,
            filter_unknown: false,
            index_unknown: true,
            characterizations: true,
            max_catalogs: 16,
            max_threads: 4,
            idle_time: 0,
            disk_space_threshold: 50,
        }
    }
}

// ============================================================================
// Manager State
// ============================================================================

/// Indexing Service manager state
struct CisvcManagerState {
    /// Catalogs
    catalogs: [IndexCatalog; MAX_CATALOGS],
    /// Catalog count
    catalog_count: u32,
    /// Configuration
    config: IndexingConfig,
    /// Selected catalog
    selected_catalog: Option<usize>,
    /// Dialog handle
    dialog_handle: HWND,
    /// View mode (0=catalogs, 1=directories, 2=properties)
    view_mode: u8,
    /// Service running
    service_running: bool,
}

impl CisvcManagerState {
    pub const fn new() -> Self {
        Self {
            catalogs: [const { IndexCatalog::new() }; MAX_CATALOGS],
            catalog_count: 0,
            config: IndexingConfig::new(),
            selected_catalog: None,
            dialog_handle: UserHandle::from_raw(0),
            view_mode: 0,
            service_running: false,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static CISVC_INITIALIZED: AtomicBool = AtomicBool::new(false);
static CISVC_MANAGER: SpinLock<CisvcManagerState> = SpinLock::new(CisvcManagerState::new());

// Statistics
static TOTAL_DOCUMENTS: AtomicU64 = AtomicU64::new(0);
static QUERIES_EXECUTED: AtomicU32 = AtomicU32::new(0);
static MERGES_COMPLETED: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Indexing Service Manager
pub fn init() {
    if CISVC_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = CISVC_MANAGER.lock();

    // Create System catalog
    let cat = &mut state.catalogs[0];
    cat.set_name(b"System");
    cat.set_location(b"C:\\System Volume Information\\catalog.wci");
    cat.state = CatalogState::Stopped;
    cat.in_use = true;

    // Add default directory
    cat.add_directory(b"C:\\", DirectoryType::Include, b"/");

    // Add default cached properties
    cat.add_property(b"DocTitle", PropertyType::String, true);
    cat.add_property(b"DocAuthor", PropertyType::String, true);
    cat.add_property(b"DocSubject", PropertyType::String, true);
    cat.add_property(b"DocKeywords", PropertyType::String, true);
    cat.add_property(b"DocComments", PropertyType::String, true);
    cat.add_property(b"Size", PropertyType::Integer, true);
    cat.add_property(b"Write", PropertyType::DateTime, true);
    cat.add_property(b"Create", PropertyType::DateTime, true);
    cat.add_property(b"Access", PropertyType::DateTime, true);
    cat.add_property(b"Path", PropertyType::String, true);
    cat.add_property(b"Filename", PropertyType::String, true);

    state.catalog_count = 1;

    crate::serial_println!("[WIN32K] Indexing Service Manager initialized");
}

// ============================================================================
// Service Control
// ============================================================================

/// Start the Indexing Service
pub fn start_service() -> bool {
    let mut state = CISVC_MANAGER.lock();

    if !state.service_running {
        state.service_running = true;
        // Start all enabled catalogs
        for catalog in state.catalogs.iter_mut() {
            if catalog.in_use && catalog.state == CatalogState::Stopped {
                catalog.state = CatalogState::Starting;
                catalog.state = CatalogState::Started;
            }
        }
        true
    } else {
        false
    }
}

/// Stop the Indexing Service
pub fn stop_service() -> bool {
    let mut state = CISVC_MANAGER.lock();

    if state.service_running {
        // Stop all catalogs
        for catalog in state.catalogs.iter_mut() {
            if catalog.in_use && catalog.state == CatalogState::Started {
                catalog.state = CatalogState::Stopping;
                catalog.state = CatalogState::Stopped;
            }
        }
        state.service_running = false;
        true
    } else {
        false
    }
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = CISVC_MANAGER.lock();
    state.service_running
}

// ============================================================================
// Catalog Management
// ============================================================================

/// Create a new catalog
pub fn create_catalog(name: &[u8], location: &[u8]) -> Option<usize> {
    let mut state = CISVC_MANAGER.lock();

    for (i, catalog) in state.catalogs.iter_mut().enumerate() {
        if !catalog.in_use {
            catalog.set_name(name);
            catalog.set_location(location);
            catalog.state = CatalogState::Stopped;
            catalog.in_use = true;
            state.catalog_count += 1;
            return Some(i);
        }
    }
    None
}

/// Delete a catalog
pub fn delete_catalog(index: usize) -> bool {
    let mut state = CISVC_MANAGER.lock();

    if index < MAX_CATALOGS && state.catalogs[index].in_use {
        // Stop if running
        if state.catalogs[index].state == CatalogState::Started {
            state.catalogs[index].state = CatalogState::Stopped;
        }
        state.catalogs[index].in_use = false;
        state.catalog_count = state.catalog_count.saturating_sub(1);
        true
    } else {
        false
    }
}

/// Start a catalog
pub fn start_catalog(index: usize) -> bool {
    let mut state = CISVC_MANAGER.lock();

    if index < MAX_CATALOGS && state.catalogs[index].in_use {
        if state.catalogs[index].state == CatalogState::Stopped {
            state.catalogs[index].state = CatalogState::Starting;
            state.catalogs[index].state = CatalogState::Started;
            return true;
        }
    }
    false
}

/// Stop a catalog
pub fn stop_catalog(index: usize) -> bool {
    let mut state = CISVC_MANAGER.lock();

    if index < MAX_CATALOGS && state.catalogs[index].in_use {
        if state.catalogs[index].state == CatalogState::Started {
            state.catalogs[index].state = CatalogState::Stopping;
            state.catalogs[index].state = CatalogState::Stopped;
            return true;
        }
    }
    false
}

/// Pause a catalog
pub fn pause_catalog(index: usize) -> bool {
    let mut state = CISVC_MANAGER.lock();

    if index < MAX_CATALOGS && state.catalogs[index].in_use {
        if state.catalogs[index].state == CatalogState::Started {
            state.catalogs[index].state = CatalogState::Paused;
            return true;
        }
    }
    false
}

/// Resume a paused catalog
pub fn resume_catalog(index: usize) -> bool {
    let mut state = CISVC_MANAGER.lock();

    if index < MAX_CATALOGS && state.catalogs[index].in_use {
        if state.catalogs[index].state == CatalogState::Paused {
            state.catalogs[index].state = CatalogState::Started;
            return true;
        }
    }
    false
}

// ============================================================================
// Directory Management
// ============================================================================

/// Add a directory to a catalog
pub fn add_directory(
    catalog_index: usize,
    path: &[u8],
    dir_type: DirectoryType,
    alias: &[u8],
) -> Option<usize> {
    let mut state = CISVC_MANAGER.lock();

    if catalog_index < MAX_CATALOGS && state.catalogs[catalog_index].in_use {
        state.catalogs[catalog_index].add_directory(path, dir_type, alias)
    } else {
        None
    }
}

/// Remove a directory from a catalog
pub fn remove_directory(catalog_index: usize, directory_index: usize) -> bool {
    let mut state = CISVC_MANAGER.lock();

    if catalog_index < MAX_CATALOGS && state.catalogs[catalog_index].in_use {
        state.catalogs[catalog_index].remove_directory(directory_index)
    } else {
        false
    }
}

// ============================================================================
// Scan and Merge Operations
// ============================================================================

/// Force a full rescan of the catalog
pub fn rescan_catalog(index: usize, current_time: u64) -> bool {
    let mut state = CISVC_MANAGER.lock();

    if index < MAX_CATALOGS && state.catalogs[index].in_use {
        if state.catalogs[index].state == CatalogState::Started {
            state.catalogs[index].last_scan = current_time;
            // In real implementation, would start full directory scan
            return true;
        }
    }
    false
}

/// Force a merge of word lists into the index
pub fn merge_catalog(index: usize, current_time: u64) -> bool {
    let mut state = CISVC_MANAGER.lock();

    if index < MAX_CATALOGS && state.catalogs[index].in_use {
        if state.catalogs[index].state == CatalogState::Started {
            state.catalogs[index].last_merge = current_time;
            MERGES_COMPLETED.fetch_add(1, Ordering::Relaxed);
            // In real implementation, would merge word lists
            return true;
        }
    }
    false
}

/// Empty the catalog (delete all indexed content)
pub fn empty_catalog(index: usize) -> bool {
    let mut state = CISVC_MANAGER.lock();

    if index < MAX_CATALOGS && state.catalogs[index].in_use {
        let was_running = state.catalogs[index].state == CatalogState::Started;
        if was_running {
            state.catalogs[index].state = CatalogState::Stopped;
        }

        state.catalogs[index].documents_indexed = 0;
        state.catalogs[index].documents_pending = 0;
        state.catalogs[index].documents_deferred = 0;
        state.catalogs[index].documents_filtered = 0;
        state.catalogs[index].files_total = 0;
        state.catalogs[index].unique_keys = 0;
        state.catalogs[index].index_size = 0;

        if was_running {
            state.catalogs[index].state = CatalogState::Started;
        }
        true
    } else {
        false
    }
}

// ============================================================================
// Query Support
// ============================================================================

/// Execute a query (returns number of results, simulated)
pub fn execute_query(catalog_index: usize, _query: &[u8]) -> Option<u32> {
    let state = CISVC_MANAGER.lock();

    if catalog_index < MAX_CATALOGS && state.catalogs[catalog_index].in_use {
        if state.catalogs[catalog_index].state == CatalogState::Started {
            QUERIES_EXECUTED.fetch_add(1, Ordering::Relaxed);
            // In real implementation, would execute full-text query
            return Some(0); // No results in simulation
        }
    }
    None
}

// ============================================================================
// Property Management
// ============================================================================

/// Add a cached property to a catalog
pub fn add_property(
    catalog_index: usize,
    name: &[u8],
    prop_type: PropertyType,
    cached: bool,
) -> Option<usize> {
    let mut state = CISVC_MANAGER.lock();

    if catalog_index < MAX_CATALOGS && state.catalogs[catalog_index].in_use {
        state.catalogs[catalog_index].add_property(name, prop_type, cached)
    } else {
        None
    }
}

/// Remove a cached property
pub fn remove_property(catalog_index: usize, property_index: usize) -> bool {
    let mut state = CISVC_MANAGER.lock();

    if catalog_index < MAX_CATALOGS && state.catalogs[catalog_index].in_use {
        if property_index < MAX_PROPERTIES {
            if state.catalogs[catalog_index].properties[property_index].in_use {
                state.catalogs[catalog_index].properties[property_index].in_use = false;
                state.catalogs[catalog_index].property_count =
                    state.catalogs[catalog_index].property_count.saturating_sub(1);
                return true;
            }
        }
    }
    false
}

// ============================================================================
// Dialog Management
// ============================================================================

/// Show Indexing Service Manager dialog
pub fn show_dialog(parent: HWND) -> HWND {
    let mut state = CISVC_MANAGER.lock();

    let handle = UserHandle::from_raw(0xE501);
    state.dialog_handle = handle;
    state.selected_catalog = Some(0);
    state.view_mode = 0;

    let _ = parent;
    handle
}

/// Close Indexing Service Manager dialog
pub fn close_dialog() {
    let mut state = CISVC_MANAGER.lock();
    state.dialog_handle = UserHandle::from_raw(0);
}

/// Select a catalog
pub fn select_catalog(index: usize) {
    let mut state = CISVC_MANAGER.lock();
    if index < MAX_CATALOGS && state.catalogs[index].in_use {
        state.selected_catalog = Some(index);
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Indexing Service statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct CisvcStats {
    pub initialized: bool,
    pub service_running: bool,
    pub catalog_count: u32,
    pub total_documents: u64,
    pub queries_executed: u32,
    pub merges_completed: u32,
}

/// Get Indexing Service statistics
pub fn get_stats() -> CisvcStats {
    let state = CISVC_MANAGER.lock();
    CisvcStats {
        initialized: CISVC_INITIALIZED.load(Ordering::Relaxed),
        service_running: state.service_running,
        catalog_count: state.catalog_count,
        total_documents: TOTAL_DOCUMENTS.load(Ordering::Relaxed),
        queries_executed: QUERIES_EXECUTED.load(Ordering::Relaxed),
        merges_completed: MERGES_COMPLETED.load(Ordering::Relaxed),
    }
}

/// Get catalog statistics
pub fn get_catalog_stats(index: usize) -> Option<(CatalogState, u64, u64, u64, u64)> {
    let state = CISVC_MANAGER.lock();

    if index < MAX_CATALOGS && state.catalogs[index].in_use {
        let cat = &state.catalogs[index];
        Some((
            cat.state,
            cat.documents_indexed,
            cat.documents_pending,
            cat.unique_keys,
            cat.index_size,
        ))
    } else {
        None
    }
}
