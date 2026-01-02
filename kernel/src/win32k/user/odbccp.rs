//! ODBC Data Sources
//!
//! Implements the ODBC Data Source Administrator following Windows Server 2003.
//! Provides ODBC driver and DSN management.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - odbcad32.exe - ODBC Data Source Administrator
//! - odbccp32.dll - ODBC Control Panel
//! - odbc32.dll - ODBC API

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum data sources
const MAX_DSN: usize = 64;

/// Maximum drivers
const MAX_DRIVERS: usize = 32;

/// Maximum name length
const MAX_NAME: usize = 64;

/// Maximum description length
const MAX_DESC: usize = 256;

/// Maximum connection string length
const MAX_CONNSTR: usize = 512;

// ============================================================================
// DSN Type
// ============================================================================

/// Data Source Name type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DsnType {
    /// User DSN (current user only)
    #[default]
    User = 0,
    /// System DSN (all users)
    System = 1,
    /// File DSN (stored in file)
    File = 2,
}

impl DsnType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DsnType::User => "User DSN",
            DsnType::System => "System DSN",
            DsnType::File => "File DSN",
        }
    }
}

// ============================================================================
// ODBC Driver
// ============================================================================

/// ODBC driver entry
#[derive(Debug, Clone, Copy)]
pub struct OdbcDriver {
    /// Driver name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC],
    /// Description length
    pub desc_len: usize,
    /// Driver file path
    pub driver_path: [u8; 260],
    /// Driver path length
    pub path_len: usize,
    /// Setup DLL path
    pub setup_path: [u8; 260],
    /// Setup path length
    pub setup_len: usize,
    /// Version
    pub version: [u8; 32],
    /// Version length
    pub version_len: usize,
    /// File usage (1 = one per connection, 2 = shared)
    pub file_usage: u32,
    /// API conformance level
    pub api_level: u32,
    /// SQL conformance level
    pub sql_level: u32,
}

impl OdbcDriver {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME],
            name_len: 0,
            description: [0u8; MAX_DESC],
            desc_len: 0,
            driver_path: [0u8; 260],
            path_len: 0,
            setup_path: [0u8; 260],
            setup_len: 0,
            version: [0u8; 32],
            version_len: 0,
            file_usage: 1,
            api_level: 2,
            sql_level: 1,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_description(&mut self, desc: &[u8]) {
        let len = desc.len().min(MAX_DESC);
        self.description[..len].copy_from_slice(&desc[..len]);
        self.desc_len = len;
    }

    pub fn set_driver_path(&mut self, path: &[u8]) {
        let len = path.len().min(260);
        self.driver_path[..len].copy_from_slice(&path[..len]);
        self.path_len = len;
    }

    pub fn set_version(&mut self, ver: &[u8]) {
        let len = ver.len().min(32);
        self.version[..len].copy_from_slice(&ver[..len]);
        self.version_len = len;
    }
}

impl Default for OdbcDriver {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Data Source
// ============================================================================

/// ODBC Data Source entry
#[derive(Debug, Clone, Copy)]
pub struct DataSource {
    /// DSN name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC],
    /// Description length
    pub desc_len: usize,
    /// Driver name
    pub driver: [u8; MAX_NAME],
    /// Driver name length
    pub driver_len: usize,
    /// DSN type
    pub dsn_type: DsnType,
    /// Server/database host
    pub server: [u8; MAX_NAME],
    /// Server length
    pub server_len: usize,
    /// Database name
    pub database: [u8; MAX_NAME],
    /// Database length
    pub database_len: usize,
    /// Port number (0 = default)
    pub port: u16,
    /// Use trusted connection (Windows auth)
    pub trusted_connection: bool,
    /// Connection string (for advanced config)
    pub connection_string: [u8; MAX_CONNSTR],
    /// Connection string length
    pub connstr_len: usize,
}

impl DataSource {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME],
            name_len: 0,
            description: [0u8; MAX_DESC],
            desc_len: 0,
            driver: [0u8; MAX_NAME],
            driver_len: 0,
            dsn_type: DsnType::User,
            server: [0u8; MAX_NAME],
            server_len: 0,
            database: [0u8; MAX_NAME],
            database_len: 0,
            port: 0,
            trusted_connection: false,
            connection_string: [0u8; MAX_CONNSTR],
            connstr_len: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_description(&mut self, desc: &[u8]) {
        let len = desc.len().min(MAX_DESC);
        self.description[..len].copy_from_slice(&desc[..len]);
        self.desc_len = len;
    }

    pub fn set_driver(&mut self, driver: &[u8]) {
        let len = driver.len().min(MAX_NAME);
        self.driver[..len].copy_from_slice(&driver[..len]);
        self.driver_len = len;
    }

    pub fn set_server(&mut self, server: &[u8]) {
        let len = server.len().min(MAX_NAME);
        self.server[..len].copy_from_slice(&server[..len]);
        self.server_len = len;
    }

    pub fn set_database(&mut self, db: &[u8]) {
        let len = db.len().min(MAX_NAME);
        self.database[..len].copy_from_slice(&db[..len]);
        self.database_len = len;
    }
}

impl Default for DataSource {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ODBC State
// ============================================================================

/// ODBC Administrator state
struct OdbcState {
    /// Installed drivers
    drivers: [OdbcDriver; MAX_DRIVERS],
    /// Driver count
    driver_count: usize,
    /// Data sources
    data_sources: [DataSource; MAX_DSN],
    /// Data source count
    dsn_count: usize,
    /// Tracing enabled
    tracing_enabled: bool,
    /// Trace file path
    trace_file: [u8; 260],
    /// Trace file length
    trace_file_len: usize,
    /// Connection pooling enabled
    pooling_enabled: bool,
    /// Pool timeout (seconds)
    pool_timeout: u32,
}

impl OdbcState {
    pub const fn new() -> Self {
        Self {
            drivers: [const { OdbcDriver::new() }; MAX_DRIVERS],
            driver_count: 0,
            data_sources: [const { DataSource::new() }; MAX_DSN],
            dsn_count: 0,
            tracing_enabled: false,
            trace_file: [0u8; 260],
            trace_file_len: 0,
            pooling_enabled: true,
            pool_timeout: 60,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static ODBC_INITIALIZED: AtomicBool = AtomicBool::new(false);
static ODBC_STATE: SpinLock<OdbcState> = SpinLock::new(OdbcState::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize ODBC Administrator
pub fn init() {
    if ODBC_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = ODBC_STATE.lock();

    // Add built-in drivers
    add_builtin_drivers(&mut state);

    // Add sample data sources
    add_sample_dsn(&mut state);

    // Set default trace file
    let trace_path = b"%SystemRoot%\\SQL.LOG";
    state.trace_file[..trace_path.len()].copy_from_slice(trace_path);
    state.trace_file_len = trace_path.len();

    crate::serial_println!("[WIN32K] ODBC Administrator initialized");
}

/// Add built-in ODBC drivers
fn add_builtin_drivers(state: &mut OdbcState) {
    let drivers: [(&[u8], &[u8], &[u8]); 10] = [
        (b"SQL Server", b"Microsoft SQL Server ODBC Driver", b"%SystemRoot%\\System32\\sqlsrv32.dll"),
        (b"Microsoft Access Driver (*.mdb)", b"Microsoft Access Driver", b"%SystemRoot%\\System32\\odbcjt32.dll"),
        (b"Microsoft Excel Driver (*.xls)", b"Microsoft Excel ODBC Driver", b"%SystemRoot%\\System32\\odbcjt32.dll"),
        (b"Microsoft Text Driver (*.txt; *.csv)", b"Microsoft Text ODBC Driver", b"%SystemRoot%\\System32\\odbcjt32.dll"),
        (b"Microsoft dBase Driver (*.dbf)", b"Microsoft dBASE ODBC Driver", b"%SystemRoot%\\System32\\odbcjt32.dll"),
        (b"Microsoft Paradox Driver (*.db)", b"Microsoft Paradox ODBC Driver", b"%SystemRoot%\\System32\\odbcjt32.dll"),
        (b"Microsoft ODBC for Oracle", b"Microsoft ODBC Driver for Oracle", b"%SystemRoot%\\System32\\msorcl32.dll"),
        (b"SQL Server Native Client", b"SQL Server Native Client ODBC Driver", b"%SystemRoot%\\System32\\sqlncli.dll"),
        (b"Microsoft FoxPro VFP Driver (*.dbf)", b"Microsoft Visual FoxPro Driver", b"%SystemRoot%\\System32\\vfpodbc.dll"),
        (b"Driver do Microsoft Access (*.mdb)", b"Microsoft Access Driver (Portuguese)", b"%SystemRoot%\\System32\\odbcjt32.dll"),
    ];

    for (name, desc, path) in drivers.iter() {
        if state.driver_count >= MAX_DRIVERS {
            break;
        }
        let mut driver = OdbcDriver::new();
        driver.set_name(name);
        driver.set_description(desc);
        driver.set_driver_path(path);
        driver.set_version(b"3.0");
        state.drivers[state.driver_count] = driver;
        state.driver_count += 1;
    }
}

/// Add sample data sources
fn add_sample_dsn(state: &mut OdbcState) {
    // Sample System DSN for local Access database
    let mut dsn1 = DataSource::new();
    dsn1.set_name(b"LocalAccessDB");
    dsn1.set_description(b"Local Access Database Sample");
    dsn1.set_driver(b"Microsoft Access Driver (*.mdb)");
    dsn1.dsn_type = DsnType::System;
    dsn1.set_database(b"C:\\Data\\sample.mdb");
    state.data_sources[0] = dsn1;

    // Sample User DSN for SQL Server
    let mut dsn2 = DataSource::new();
    dsn2.set_name(b"SQLServerDB");
    dsn2.set_description(b"SQL Server Connection");
    dsn2.set_driver(b"SQL Server");
    dsn2.dsn_type = DsnType::User;
    dsn2.set_server(b"localhost");
    dsn2.set_database(b"master");
    dsn2.trusted_connection = true;
    state.data_sources[1] = dsn2;

    state.dsn_count = 2;
}

// ============================================================================
// Driver Management
// ============================================================================

/// Get driver count
pub fn get_driver_count() -> usize {
    ODBC_STATE.lock().driver_count
}

/// Get driver by index
pub fn get_driver(index: usize) -> Option<OdbcDriver> {
    let state = ODBC_STATE.lock();
    if index < state.driver_count {
        Some(state.drivers[index])
    } else {
        None
    }
}

/// Find driver by name
pub fn find_driver(name: &[u8]) -> Option<OdbcDriver> {
    let state = ODBC_STATE.lock();
    for i in 0..state.driver_count {
        let drv = &state.drivers[i];
        if drv.name_len == name.len() && &drv.name[..drv.name_len] == name {
            return Some(*drv);
        }
    }
    None
}

// ============================================================================
// Data Source Management
// ============================================================================

/// Get data source count
pub fn get_dsn_count() -> usize {
    ODBC_STATE.lock().dsn_count
}

/// Get data source count by type
pub fn get_dsn_count_by_type(dsn_type: DsnType) -> usize {
    let state = ODBC_STATE.lock();
    let mut count = 0;
    for i in 0..state.dsn_count {
        if state.data_sources[i].dsn_type == dsn_type {
            count += 1;
        }
    }
    count
}

/// Get data source by index
pub fn get_dsn(index: usize) -> Option<DataSource> {
    let state = ODBC_STATE.lock();
    if index < state.dsn_count {
        Some(state.data_sources[index])
    } else {
        None
    }
}

/// Get data sources by type
pub fn get_dsn_by_type(dsn_type: DsnType) -> ([usize; 32], usize) {
    let state = ODBC_STATE.lock();
    let mut indices = [0usize; 32];
    let mut count = 0;

    for i in 0..state.dsn_count {
        if state.data_sources[i].dsn_type == dsn_type && count < 32 {
            indices[count] = i;
            count += 1;
        }
    }

    (indices, count)
}

/// Find data source by name
pub fn find_dsn(name: &[u8]) -> Option<DataSource> {
    let state = ODBC_STATE.lock();
    for i in 0..state.dsn_count {
        let dsn = &state.data_sources[i];
        if dsn.name_len == name.len() && &dsn.name[..dsn.name_len] == name {
            return Some(*dsn);
        }
    }
    None
}

/// Add a data source
pub fn add_dsn(dsn: &DataSource) -> bool {
    let mut state = ODBC_STATE.lock();
    if state.dsn_count >= MAX_DSN {
        return false;
    }

    let idx = state.dsn_count;
    state.data_sources[idx] = *dsn;
    state.dsn_count += 1;
    true
}

/// Remove a data source
pub fn remove_dsn(index: usize) -> bool {
    let mut state = ODBC_STATE.lock();
    if index >= state.dsn_count {
        return false;
    }

    // Shift remaining
    for i in index..state.dsn_count - 1 {
        state.data_sources[i] = state.data_sources[i + 1];
    }
    state.dsn_count -= 1;
    true
}

/// Update a data source
pub fn update_dsn(index: usize, dsn: &DataSource) -> bool {
    let mut state = ODBC_STATE.lock();
    if index >= state.dsn_count {
        return false;
    }

    state.data_sources[index] = *dsn;
    true
}

// ============================================================================
// Tracing Configuration
// ============================================================================

/// Enable/disable ODBC tracing
pub fn set_tracing_enabled(enabled: bool) {
    ODBC_STATE.lock().tracing_enabled = enabled;
}

/// Check if tracing is enabled
pub fn is_tracing_enabled() -> bool {
    ODBC_STATE.lock().tracing_enabled
}

/// Set trace file path
pub fn set_trace_file(path: &[u8]) {
    let mut state = ODBC_STATE.lock();
    let len = path.len().min(260);
    state.trace_file[..len].copy_from_slice(&path[..len]);
    state.trace_file_len = len;
}

/// Get trace file path
pub fn get_trace_file() -> ([u8; 260], usize) {
    let state = ODBC_STATE.lock();
    (state.trace_file, state.trace_file_len)
}

// ============================================================================
// Connection Pooling
// ============================================================================

/// Enable/disable connection pooling
pub fn set_pooling_enabled(enabled: bool) {
    ODBC_STATE.lock().pooling_enabled = enabled;
}

/// Check if pooling is enabled
pub fn is_pooling_enabled() -> bool {
    ODBC_STATE.lock().pooling_enabled
}

/// Set pool timeout
pub fn set_pool_timeout(seconds: u32) {
    ODBC_STATE.lock().pool_timeout = seconds;
}

/// Get pool timeout
pub fn get_pool_timeout() -> u32 {
    ODBC_STATE.lock().pool_timeout
}

// ============================================================================
// Statistics
// ============================================================================

/// ODBC statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct OdbcStats {
    pub initialized: bool,
    pub driver_count: usize,
    pub user_dsn_count: usize,
    pub system_dsn_count: usize,
    pub file_dsn_count: usize,
    pub tracing_enabled: bool,
    pub pooling_enabled: bool,
}

/// Get ODBC statistics
pub fn get_stats() -> OdbcStats {
    let state = ODBC_STATE.lock();
    let mut user = 0;
    let mut system = 0;
    let mut file = 0;

    for i in 0..state.dsn_count {
        match state.data_sources[i].dsn_type {
            DsnType::User => user += 1,
            DsnType::System => system += 1,
            DsnType::File => file += 1,
        }
    }

    OdbcStats {
        initialized: ODBC_INITIALIZED.load(Ordering::Relaxed),
        driver_count: state.driver_count,
        user_dsn_count: user,
        system_dsn_count: system,
        file_dsn_count: file,
        tracing_enabled: state.tracing_enabled,
        pooling_enabled: state.pooling_enabled,
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// ODBC dialog handle
pub type HODBCDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create ODBC Administrator dialog
pub fn create_odbc_dialog(_parent: super::super::HWND) -> HODBCDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}

/// ODBC dialog tab
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OdbcTab {
    /// User DSN tab
    #[default]
    UserDsn = 0,
    /// System DSN tab
    SystemDsn = 1,
    /// File DSN tab
    FileDsn = 2,
    /// Drivers tab
    Drivers = 3,
    /// Tracing tab
    Tracing = 4,
    /// Connection Pooling tab
    Pooling = 5,
    /// About tab
    About = 6,
}

/// Get tab count
pub fn get_tab_count() -> u32 {
    7
}

/// Get tab name
pub fn get_tab_name(tab: OdbcTab) -> &'static str {
    match tab {
        OdbcTab::UserDsn => "User DSN",
        OdbcTab::SystemDsn => "System DSN",
        OdbcTab::FileDsn => "File DSN",
        OdbcTab::Drivers => "Drivers",
        OdbcTab::Tracing => "Tracing",
        OdbcTab::Pooling => "Connection Pooling",
        OdbcTab::About => "About",
    }
}
