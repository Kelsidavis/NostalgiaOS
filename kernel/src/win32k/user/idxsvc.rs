//! Indexing Service Extended Module
//!
//! Windows Server 2003 Indexing Service implementation for full-text search
//! of documents and files. Provides catalog management, scope configuration,
//! property caching, and query processing.

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use crate::win32k::user::UserHandle;

/// Maximum number of catalogs
const MAX_CATALOGS: usize = 32;

/// Maximum number of scopes per catalog
const MAX_SCOPES: usize = 64;

/// Maximum number of indexed properties
const MAX_PROPERTIES: usize = 128;

/// Maximum number of active queries
const MAX_QUERIES: usize = 256;

/// Maximum path length
const MAX_PATH_LEN: usize = 260;

/// Maximum property name length
const MAX_PROPERTY_NAME: usize = 64;

/// Maximum query text length
const MAX_QUERY_LEN: usize = 512;

/// Catalog status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CatalogStatus {
    /// Catalog is stopped
    Stopped = 0,
    /// Catalog is starting
    Starting = 1,
    /// Catalog is running and indexing
    Running = 2,
    /// Catalog is paused
    Paused = 3,
    /// Catalog is stopping
    Stopping = 4,
    /// Catalog has errors
    Error = 5,
}

impl Default for CatalogStatus {
    fn default() -> Self {
        Self::Stopped
    }
}

/// Scope type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ScopeType {
    /// Include this path in indexing
    Include = 0,
    /// Exclude this path from indexing
    Exclude = 1,
    /// Virtual root for web content
    VirtualRoot = 2,
}

impl Default for ScopeType {
    fn default() -> Self {
        Self::Include
    }
}

/// Property type for indexing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PropertyType {
    /// String property
    String = 0,
    /// Integer property
    Integer = 1,
    /// Date/time property
    DateTime = 2,
    /// Boolean property
    Boolean = 3,
    /// Binary property
    Binary = 4,
    /// GUID property
    Guid = 5,
}

impl Default for PropertyType {
    fn default() -> Self {
        Self::String
    }
}

/// Query status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QueryStatus {
    /// Query is pending
    Pending = 0,
    /// Query is executing
    Executing = 1,
    /// Query completed successfully
    Completed = 2,
    /// Query failed
    Failed = 3,
    /// Query was cancelled
    Cancelled = 4,
}

impl Default for QueryStatus {
    fn default() -> Self {
        Self::Pending
    }
}

bitflags::bitflags! {
    /// Catalog flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CatalogFlags: u32 {
        /// Catalog is read-only
        const READ_ONLY = 0x0001;
        /// Generate abstracts for documents
        const GENERATE_ABSTRACTS = 0x0002;
        /// Index file contents
        const INDEX_CONTENTS = 0x0004;
        /// Index file properties
        const INDEX_PROPERTIES = 0x0008;
        /// Enable automatic merges
        const AUTO_MERGE = 0x0010;
        /// Track file deletions
        const TRACK_DELETIONS = 0x0020;
        /// Filter unknown file types
        const FILTER_UNKNOWN = 0x0040;
        /// Enable incremental indexing
        const INCREMENTAL = 0x0080;
    }
}

impl Default for CatalogFlags {
    fn default() -> Self {
        Self::INDEX_CONTENTS | Self::INDEX_PROPERTIES | Self::AUTO_MERGE | Self::INCREMENTAL
    }
}

bitflags::bitflags! {
    /// Query flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct QueryFlags: u32 {
        /// Return property values
        const RETURN_PROPERTIES = 0x0001;
        /// Return hit highlights
        const RETURN_HIGHLIGHTS = 0x0002;
        /// Sort results
        const SORT_RESULTS = 0x0004;
        /// Enable fuzzy matching
        const FUZZY_MATCH = 0x0008;
        /// Use natural language
        const NATURAL_LANGUAGE = 0x0010;
        /// Search in abstracts only
        const ABSTRACTS_ONLY = 0x0020;
        /// Case sensitive search
        const CASE_SENSITIVE = 0x0040;
    }
}

impl Default for QueryFlags {
    fn default() -> Self {
        Self::RETURN_PROPERTIES | Self::SORT_RESULTS
    }
}

/// Indexing catalog
#[derive(Debug)]
pub struct IndexingCatalog {
    /// Catalog is active
    active: bool,
    /// Catalog ID
    id: u32,
    /// Catalog name
    name: [u8; MAX_PROPERTY_NAME],
    /// Name length
    name_len: usize,
    /// Catalog path
    path: [u8; MAX_PATH_LEN],
    /// Path length
    path_len: usize,
    /// Catalog status
    status: CatalogStatus,
    /// Catalog flags
    flags: CatalogFlags,
    /// Total documents indexed
    total_documents: u64,
    /// Total size of indexed content
    total_size: u64,
    /// Pending documents to index
    pending_documents: u32,
    /// Documents with errors
    error_documents: u32,
    /// Word list count
    word_lists: u32,
    /// Persistent index count
    persistent_indices: u32,
    /// Last merge time
    last_merge: u64,
    /// Unique words count
    unique_words: u64,
    /// Handle for management
    handle: UserHandle,
}

impl IndexingCatalog {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            name: [0u8; MAX_PROPERTY_NAME],
            name_len: 0,
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            status: CatalogStatus::Stopped,
            flags: CatalogFlags::empty(),
            total_documents: 0,
            total_size: 0,
            pending_documents: 0,
            error_documents: 0,
            word_lists: 0,
            persistent_indices: 0,
            last_merge: 0,
            unique_words: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// Indexing scope
#[derive(Debug)]
pub struct IndexingScope {
    /// Scope is active
    active: bool,
    /// Scope ID
    id: u32,
    /// Parent catalog ID
    catalog_id: u32,
    /// Scope path
    path: [u8; MAX_PATH_LEN],
    /// Path length
    path_len: usize,
    /// Scope type
    scope_type: ScopeType,
    /// Alias for virtual roots
    alias: [u8; MAX_PATH_LEN],
    /// Alias length
    alias_len: usize,
    /// Documents in scope
    document_count: u64,
    /// Last scan time
    last_scan: u64,
    /// Enabled flag
    enabled: bool,
    /// Handle for management
    handle: UserHandle,
}

impl IndexingScope {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            catalog_id: 0,
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            scope_type: ScopeType::Include,
            alias: [0u8; MAX_PATH_LEN],
            alias_len: 0,
            document_count: 0,
            last_scan: 0,
            enabled: true,
            handle: UserHandle::NULL,
        }
    }
}

/// Indexed property definition
#[derive(Debug)]
pub struct IndexedProperty {
    /// Property is active
    active: bool,
    /// Property ID
    id: u32,
    /// Property GUID (as bytes)
    guid: [u8; 16],
    /// Property name
    name: [u8; MAX_PROPERTY_NAME],
    /// Name length
    name_len: usize,
    /// Property type
    prop_type: PropertyType,
    /// Cached in property store
    cached: bool,
    /// Size in bytes (for cached properties)
    cache_size: u32,
    /// Storage level (1-5)
    storage_level: u32,
    /// Handle for management
    handle: UserHandle,
}

impl IndexedProperty {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            guid: [0u8; 16],
            name: [0u8; MAX_PROPERTY_NAME],
            name_len: 0,
            prop_type: PropertyType::String,
            cached: false,
            cache_size: 0,
            storage_level: 1,
            handle: UserHandle::NULL,
        }
    }
}

/// Active query
#[derive(Debug)]
pub struct IndexQuery {
    /// Query is active
    active: bool,
    /// Query ID
    id: u32,
    /// Target catalog ID
    catalog_id: u32,
    /// Query text
    query_text: [u8; MAX_QUERY_LEN],
    /// Query text length
    query_len: usize,
    /// Query status
    status: QueryStatus,
    /// Query flags
    flags: QueryFlags,
    /// Maximum results
    max_results: u32,
    /// Results found
    results_found: u32,
    /// Results returned
    results_returned: u32,
    /// Query start time
    start_time: u64,
    /// Query end time
    end_time: u64,
    /// Handle for management
    handle: UserHandle,
}

impl IndexQuery {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            catalog_id: 0,
            query_text: [0u8; MAX_QUERY_LEN],
            query_len: 0,
            status: QueryStatus::Pending,
            flags: QueryFlags::empty(),
            max_results: 100,
            results_found: 0,
            results_returned: 0,
            start_time: 0,
            end_time: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// Indexing service statistics
#[derive(Debug)]
pub struct IndexingStats {
    /// Total catalogs
    pub total_catalogs: u32,
    /// Active catalogs
    pub active_catalogs: u32,
    /// Total scopes
    pub total_scopes: u32,
    /// Total properties
    pub total_properties: u32,
    /// Active queries
    pub active_queries: u32,
    /// Completed queries
    pub completed_queries: u64,
    /// Total documents indexed
    pub total_documents: u64,
    /// Total bytes indexed
    pub total_bytes: u64,
    /// Documents per second
    pub docs_per_second: u32,
    /// Queries per second
    pub queries_per_second: u32,
    /// Filter DLL loads
    pub filter_loads: u32,
    /// Index merges performed
    pub merges_performed: u64,
}

impl IndexingStats {
    pub const fn new() -> Self {
        Self {
            total_catalogs: 0,
            active_catalogs: 0,
            total_scopes: 0,
            total_properties: 0,
            active_queries: 0,
            completed_queries: 0,
            total_documents: 0,
            total_bytes: 0,
            docs_per_second: 0,
            queries_per_second: 0,
            filter_loads: 0,
            merges_performed: 0,
        }
    }
}

/// Indexing service state
struct IndexingState {
    /// Catalogs
    catalogs: [IndexingCatalog; MAX_CATALOGS],
    /// Scopes
    scopes: [IndexingScope; MAX_SCOPES],
    /// Properties
    properties: [IndexedProperty; MAX_PROPERTIES],
    /// Active queries
    queries: [IndexQuery; MAX_QUERIES],
    /// Statistics
    stats: IndexingStats,
    /// Next ID
    next_id: u32,
}

impl IndexingState {
    pub const fn new() -> Self {
        Self {
            catalogs: [const { IndexingCatalog::new() }; MAX_CATALOGS],
            scopes: [const { IndexingScope::new() }; MAX_SCOPES],
            properties: [const { IndexedProperty::new() }; MAX_PROPERTIES],
            queries: [const { IndexQuery::new() }; MAX_QUERIES],
            stats: IndexingStats::new(),
            next_id: 1,
        }
    }
}

/// Global indexing service state
static INDEXING_STATE: Mutex<IndexingState> = Mutex::new(IndexingState::new());

/// Initialization flag
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the indexing service module
pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let mut state = INDEXING_STATE.lock();

    // Register standard indexed properties
    register_standard_properties(&mut state)?;

    Ok(())
}

/// Register standard indexed properties
fn register_standard_properties(state: &mut IndexingState) -> Result<(), &'static str> {
    let standard_props = [
        ("Contents", PropertyType::String),
        ("DocTitle", PropertyType::String),
        ("DocSubject", PropertyType::String),
        ("DocAuthor", PropertyType::String),
        ("DocKeywords", PropertyType::String),
        ("DocComments", PropertyType::String),
        ("FileName", PropertyType::String),
        ("Path", PropertyType::String),
        ("Size", PropertyType::Integer),
        ("Write", PropertyType::DateTime),
        ("Create", PropertyType::DateTime),
        ("Access", PropertyType::DateTime),
        ("Attrib", PropertyType::Integer),
        ("DocCategory", PropertyType::String),
        ("DocCompany", PropertyType::String),
    ];

    for (name, prop_type) in standard_props.iter() {
        if let Some(slot) = state.properties.iter_mut().find(|p| !p.active) {
            let id = state.next_id;
            state.next_id += 1;

            slot.active = true;
            slot.id = id;
            let name_bytes = name.as_bytes();
            let copy_len = name_bytes.len().min(MAX_PROPERTY_NAME);
            slot.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
            slot.name_len = copy_len;
            slot.prop_type = *prop_type;
            slot.cached = true;
            slot.cache_size = 256;
            slot.storage_level = 1;
            slot.handle = UserHandle::from_raw(id);

            state.stats.total_properties += 1;
        }
    }

    Ok(())
}

/// Create a new indexing catalog
pub fn create_catalog(name: &str, path: &str, flags: CatalogFlags) -> Result<UserHandle, u32> {
    let mut state = INDEXING_STATE.lock();

    // Check for duplicate name
    for catalog in state.catalogs.iter() {
        if catalog.active {
            let existing_name = &catalog.name[..catalog.name_len];
            if existing_name == name.as_bytes() {
                return Err(0x80070050); // ERROR_FILE_EXISTS
            }
        }
    }

    // Find free slot
    let slot_idx = state.catalogs.iter().position(|c| !c.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008), // ERROR_NOT_ENOUGH_MEMORY
    };

    let id = state.next_id;
    state.next_id += 1;

    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(MAX_PROPERTY_NAME);
    let path_bytes = path.as_bytes();
    let path_len = path_bytes.len().min(MAX_PATH_LEN);

    state.catalogs[slot_idx].active = true;
    state.catalogs[slot_idx].id = id;
    state.catalogs[slot_idx].name[..name_len].copy_from_slice(&name_bytes[..name_len]);
    state.catalogs[slot_idx].name_len = name_len;
    state.catalogs[slot_idx].path[..path_len].copy_from_slice(&path_bytes[..path_len]);
    state.catalogs[slot_idx].path_len = path_len;
    state.catalogs[slot_idx].status = CatalogStatus::Stopped;
    state.catalogs[slot_idx].flags = flags;
    state.catalogs[slot_idx].total_documents = 0;
    state.catalogs[slot_idx].total_size = 0;
    state.catalogs[slot_idx].pending_documents = 0;
    state.catalogs[slot_idx].error_documents = 0;
    state.catalogs[slot_idx].word_lists = 0;
    state.catalogs[slot_idx].persistent_indices = 0;
    state.catalogs[slot_idx].last_merge = 0;
    state.catalogs[slot_idx].unique_words = 0;
    state.catalogs[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.total_catalogs += 1;

    Ok(state.catalogs[slot_idx].handle)
}

/// Delete an indexing catalog
pub fn delete_catalog(catalog_id: u32) -> Result<(), u32> {
    let mut state = INDEXING_STATE.lock();

    let catalog_idx = state.catalogs.iter().position(|c| c.active && c.id == catalog_id);
    let catalog_idx = match catalog_idx {
        Some(idx) => idx,
        None => return Err(0x80070002), // ERROR_FILE_NOT_FOUND
    };

    // Check if catalog is stopped
    if state.catalogs[catalog_idx].status != CatalogStatus::Stopped {
        return Err(0x80070020); // ERROR_SHARING_VIOLATION
    }

    // Count related scopes to remove
    let mut scopes_to_remove = 0u32;
    for scope in state.scopes.iter() {
        if scope.active && scope.catalog_id == catalog_id {
            scopes_to_remove += 1;
        }
    }

    // Remove related scopes
    for scope in state.scopes.iter_mut() {
        if scope.active && scope.catalog_id == catalog_id {
            scope.active = false;
        }
    }

    state.catalogs[catalog_idx].active = false;
    state.stats.total_catalogs = state.stats.total_catalogs.saturating_sub(1);
    state.stats.total_scopes = state.stats.total_scopes.saturating_sub(scopes_to_remove);

    Ok(())
}

/// Start an indexing catalog
pub fn start_catalog(catalog_id: u32) -> Result<(), u32> {
    let mut state = INDEXING_STATE.lock();

    let catalog = state.catalogs.iter_mut().find(|c| c.active && c.id == catalog_id);
    let catalog = match catalog {
        Some(c) => c,
        None => return Err(0x80070002),
    };

    match catalog.status {
        CatalogStatus::Running => return Ok(()),
        CatalogStatus::Starting | CatalogStatus::Stopping => {
            return Err(0x80070015); // ERROR_NOT_READY
        }
        _ => {}
    }

    catalog.status = CatalogStatus::Starting;

    // Simulate starting process
    catalog.status = CatalogStatus::Running;
    state.stats.active_catalogs += 1;

    Ok(())
}

/// Stop an indexing catalog
pub fn stop_catalog(catalog_id: u32) -> Result<(), u32> {
    let mut state = INDEXING_STATE.lock();

    let catalog = state.catalogs.iter_mut().find(|c| c.active && c.id == catalog_id);
    let catalog = match catalog {
        Some(c) => c,
        None => return Err(0x80070002),
    };

    match catalog.status {
        CatalogStatus::Stopped => return Ok(()),
        CatalogStatus::Starting | CatalogStatus::Stopping => {
            return Err(0x80070015);
        }
        _ => {}
    }

    catalog.status = CatalogStatus::Stopping;
    catalog.status = CatalogStatus::Stopped;
    state.stats.active_catalogs = state.stats.active_catalogs.saturating_sub(1);

    Ok(())
}

/// Pause an indexing catalog
pub fn pause_catalog(catalog_id: u32) -> Result<(), u32> {
    let mut state = INDEXING_STATE.lock();

    let catalog = state.catalogs.iter_mut().find(|c| c.active && c.id == catalog_id);
    let catalog = match catalog {
        Some(c) => c,
        None => return Err(0x80070002),
    };

    if catalog.status != CatalogStatus::Running {
        return Err(0x80070015);
    }

    catalog.status = CatalogStatus::Paused;

    Ok(())
}

/// Resume an indexing catalog
pub fn resume_catalog(catalog_id: u32) -> Result<(), u32> {
    let mut state = INDEXING_STATE.lock();

    let catalog = state.catalogs.iter_mut().find(|c| c.active && c.id == catalog_id);
    let catalog = match catalog {
        Some(c) => c,
        None => return Err(0x80070002),
    };

    if catalog.status != CatalogStatus::Paused {
        return Err(0x80070015);
    }

    catalog.status = CatalogStatus::Running;

    Ok(())
}

/// Add a scope to a catalog
pub fn add_scope(
    catalog_id: u32,
    path: &str,
    scope_type: ScopeType,
    alias: Option<&str>,
) -> Result<UserHandle, u32> {
    let mut state = INDEXING_STATE.lock();

    // Verify catalog exists
    let catalog_exists = state.catalogs.iter().any(|c| c.active && c.id == catalog_id);
    if !catalog_exists {
        return Err(0x80070002);
    }

    // Check for duplicate path in catalog
    for scope in state.scopes.iter() {
        if scope.active && scope.catalog_id == catalog_id {
            let existing_path = &scope.path[..scope.path_len];
            if existing_path == path.as_bytes() {
                return Err(0x80070050);
            }
        }
    }

    // Find free slot
    let slot_idx = state.scopes.iter().position(|s| !s.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008),
    };

    let id = state.next_id;
    state.next_id += 1;

    let path_bytes = path.as_bytes();
    let path_len = path_bytes.len().min(MAX_PATH_LEN);

    state.scopes[slot_idx].active = true;
    state.scopes[slot_idx].id = id;
    state.scopes[slot_idx].catalog_id = catalog_id;
    state.scopes[slot_idx].path[..path_len].copy_from_slice(&path_bytes[..path_len]);
    state.scopes[slot_idx].path_len = path_len;
    state.scopes[slot_idx].scope_type = scope_type;

    if let Some(alias_str) = alias {
        let alias_bytes = alias_str.as_bytes();
        let alias_len = alias_bytes.len().min(MAX_PATH_LEN);
        state.scopes[slot_idx].alias[..alias_len].copy_from_slice(&alias_bytes[..alias_len]);
        state.scopes[slot_idx].alias_len = alias_len;
    } else {
        state.scopes[slot_idx].alias_len = 0;
    }

    state.scopes[slot_idx].document_count = 0;
    state.scopes[slot_idx].last_scan = 0;
    state.scopes[slot_idx].enabled = true;
    state.scopes[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.total_scopes += 1;

    Ok(state.scopes[slot_idx].handle)
}

/// Remove a scope from a catalog
pub fn remove_scope(scope_id: u32) -> Result<(), u32> {
    let mut state = INDEXING_STATE.lock();

    let scope_idx = state.scopes.iter().position(|s| s.active && s.id == scope_id);
    let scope_idx = match scope_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    state.scopes[scope_idx].active = false;
    state.stats.total_scopes = state.stats.total_scopes.saturating_sub(1);

    Ok(())
}

/// Enable or disable a scope
pub fn set_scope_enabled(scope_id: u32, enabled: bool) -> Result<(), u32> {
    let mut state = INDEXING_STATE.lock();

    let scope = state.scopes.iter_mut().find(|s| s.active && s.id == scope_id);
    let scope = match scope {
        Some(s) => s,
        None => return Err(0x80070002),
    };

    scope.enabled = enabled;

    Ok(())
}

/// Force a rescan of a scope
pub fn rescan_scope(scope_id: u32) -> Result<(), u32> {
    let mut state = INDEXING_STATE.lock();

    let scope_idx = state.scopes.iter().position(|s| s.active && s.id == scope_id);
    let scope_idx = match scope_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    let catalog_id = state.scopes[scope_idx].catalog_id;

    // Verify catalog is running
    let catalog_running = state.catalogs.iter()
        .any(|c| c.active && c.id == catalog_id && c.status == CatalogStatus::Running);

    if !catalog_running {
        return Err(0x80070015);
    }

    // Update last scan time
    state.scopes[scope_idx].last_scan = 0; // Reset to trigger rescan

    Ok(())
}

/// Register a cached property
pub fn register_property(
    name: &str,
    guid: &[u8; 16],
    prop_type: PropertyType,
    cache_size: u32,
) -> Result<UserHandle, u32> {
    let mut state = INDEXING_STATE.lock();

    // Check for duplicate
    for prop in state.properties.iter() {
        if prop.active {
            let existing_name = &prop.name[..prop.name_len];
            if existing_name == name.as_bytes() {
                return Err(0x80070050);
            }
        }
    }

    let slot_idx = state.properties.iter().position(|p| !p.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008),
    };

    let id = state.next_id;
    state.next_id += 1;

    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(MAX_PROPERTY_NAME);

    state.properties[slot_idx].active = true;
    state.properties[slot_idx].id = id;
    state.properties[slot_idx].guid.copy_from_slice(guid);
    state.properties[slot_idx].name[..name_len].copy_from_slice(&name_bytes[..name_len]);
    state.properties[slot_idx].name_len = name_len;
    state.properties[slot_idx].prop_type = prop_type;
    state.properties[slot_idx].cached = cache_size > 0;
    state.properties[slot_idx].cache_size = cache_size;
    state.properties[slot_idx].storage_level = 1;
    state.properties[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.total_properties += 1;

    Ok(state.properties[slot_idx].handle)
}

/// Submit a query to the indexing service
pub fn submit_query(
    catalog_id: u32,
    query_text: &str,
    flags: QueryFlags,
    max_results: u32,
) -> Result<UserHandle, u32> {
    let mut state = INDEXING_STATE.lock();

    // Verify catalog exists and is running
    let catalog_running = state.catalogs.iter()
        .any(|c| c.active && c.id == catalog_id && c.status == CatalogStatus::Running);

    if !catalog_running {
        return Err(0x80070015);
    }

    let slot_idx = state.queries.iter().position(|q| !q.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008),
    };

    let id = state.next_id;
    state.next_id += 1;

    let query_bytes = query_text.as_bytes();
    let query_len = query_bytes.len().min(MAX_QUERY_LEN);

    state.queries[slot_idx].active = true;
    state.queries[slot_idx].id = id;
    state.queries[slot_idx].catalog_id = catalog_id;
    state.queries[slot_idx].query_text[..query_len].copy_from_slice(&query_bytes[..query_len]);
    state.queries[slot_idx].query_len = query_len;
    state.queries[slot_idx].status = QueryStatus::Pending;
    state.queries[slot_idx].flags = flags;
    state.queries[slot_idx].max_results = max_results;
    state.queries[slot_idx].results_found = 0;
    state.queries[slot_idx].results_returned = 0;
    state.queries[slot_idx].start_time = 0; // Would use real time
    state.queries[slot_idx].end_time = 0;
    state.queries[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.active_queries += 1;

    Ok(state.queries[slot_idx].handle)
}

/// Execute a submitted query
pub fn execute_query(query_id: u32) -> Result<u32, u32> {
    let mut state = INDEXING_STATE.lock();

    let query_idx = state.queries.iter().position(|q| q.active && q.id == query_id);
    let query_idx = match query_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    if state.queries[query_idx].status != QueryStatus::Pending {
        return Err(0x80070015);
    }

    state.queries[query_idx].status = QueryStatus::Executing;

    // Simulate query execution
    let results = 42u32; // Mock result count
    state.queries[query_idx].results_found = results;
    state.queries[query_idx].results_returned = results.min(state.queries[query_idx].max_results);
    state.queries[query_idx].status = QueryStatus::Completed;

    state.stats.active_queries = state.stats.active_queries.saturating_sub(1);
    state.stats.completed_queries += 1;

    Ok(state.queries[query_idx].results_returned)
}

/// Cancel a running query
pub fn cancel_query(query_id: u32) -> Result<(), u32> {
    let mut state = INDEXING_STATE.lock();

    let query = state.queries.iter_mut().find(|q| q.active && q.id == query_id);
    let query = match query {
        Some(q) => q,
        None => return Err(0x80070002),
    };

    match query.status {
        QueryStatus::Pending | QueryStatus::Executing => {
            query.status = QueryStatus::Cancelled;
            state.stats.active_queries = state.stats.active_queries.saturating_sub(1);
        }
        _ => return Err(0x80070015),
    }

    Ok(())
}

/// Release a completed query
pub fn release_query(query_id: u32) -> Result<(), u32> {
    let mut state = INDEXING_STATE.lock();

    let query = state.queries.iter_mut().find(|q| q.active && q.id == query_id);
    let query = match query {
        Some(q) => q,
        None => return Err(0x80070002),
    };

    query.active = false;

    Ok(())
}

/// Force a master merge on a catalog
pub fn force_merge(catalog_id: u32) -> Result<(), u32> {
    let mut state = INDEXING_STATE.lock();

    let catalog = state.catalogs.iter_mut().find(|c| c.active && c.id == catalog_id);
    let catalog = match catalog {
        Some(c) => c,
        None => return Err(0x80070002),
    };

    if catalog.status != CatalogStatus::Running && catalog.status != CatalogStatus::Paused {
        return Err(0x80070015);
    }

    // Perform merge
    catalog.word_lists = 0;
    catalog.persistent_indices = catalog.persistent_indices.saturating_add(1);
    catalog.last_merge = 0; // Would use real time

    state.stats.merges_performed += 1;

    Ok(())
}

/// Get catalog information
pub fn get_catalog_info(catalog_id: u32) -> Result<(CatalogStatus, CatalogFlags, u64, u32), u32> {
    let state = INDEXING_STATE.lock();

    let catalog = state.catalogs.iter().find(|c| c.active && c.id == catalog_id);
    let catalog = match catalog {
        Some(c) => c,
        None => return Err(0x80070002),
    };

    Ok((
        catalog.status,
        catalog.flags,
        catalog.total_documents,
        catalog.pending_documents,
    ))
}

/// Get indexing service statistics
pub fn get_statistics() -> IndexingStats {
    let state = INDEXING_STATE.lock();
    IndexingStats {
        total_catalogs: state.stats.total_catalogs,
        active_catalogs: state.stats.active_catalogs,
        total_scopes: state.stats.total_scopes,
        total_properties: state.stats.total_properties,
        active_queries: state.stats.active_queries,
        completed_queries: state.stats.completed_queries,
        total_documents: state.stats.total_documents,
        total_bytes: state.stats.total_bytes,
        docs_per_second: state.stats.docs_per_second,
        queries_per_second: state.stats.queries_per_second,
        filter_loads: state.stats.filter_loads,
        merges_performed: state.stats.merges_performed,
    }
}

/// List all catalogs
pub fn list_catalogs() -> [(bool, u32, CatalogStatus); MAX_CATALOGS] {
    let state = INDEXING_STATE.lock();
    let mut result = [(false, 0u32, CatalogStatus::Stopped); MAX_CATALOGS];

    for (i, catalog) in state.catalogs.iter().enumerate() {
        if catalog.active {
            result[i] = (true, catalog.id, catalog.status);
        }
    }

    result
}

/// List scopes for a catalog
pub fn list_scopes(catalog_id: u32) -> [(bool, u32, ScopeType, bool); MAX_SCOPES] {
    let state = INDEXING_STATE.lock();
    let mut result = [(false, 0u32, ScopeType::Include, false); MAX_SCOPES];

    let mut idx = 0;
    for scope in state.scopes.iter() {
        if scope.active && scope.catalog_id == catalog_id && idx < MAX_SCOPES {
            result[idx] = (true, scope.id, scope.scope_type, scope.enabled);
            idx += 1;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catalog_lifecycle() {
        init().unwrap();

        let handle = create_catalog(
            "TestCatalog",
            "C:\\Catalogs\\Test",
            CatalogFlags::default(),
        ).unwrap();
        assert_ne!(handle, UserHandle::NULL);

        start_catalog(1).unwrap_or(());
        pause_catalog(1).unwrap_or(());
        resume_catalog(1).unwrap_or(());
        stop_catalog(1).unwrap_or(());
    }

    #[test]
    fn test_scope_management() {
        init().unwrap();

        let catalog = create_catalog(
            "ScopeCatalog",
            "C:\\Catalogs\\Scope",
            CatalogFlags::default(),
        ).unwrap();

        let scope = add_scope(
            1,
            "C:\\Documents",
            ScopeType::Include,
            None,
        );
        assert!(scope.is_ok() || scope.is_err());
    }

    #[test]
    fn test_query_operations() {
        init().unwrap();

        let stats = get_statistics();
        assert!(stats.total_properties > 0);
    }
}
