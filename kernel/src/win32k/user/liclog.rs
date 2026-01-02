//! License Logging Service Management
//!
//! This module implements the Win32k USER subsystem support for the
//! License Logging Service management in Windows Server 2003.
//!
//! # Windows Server 2003 Reference
//!
//! The License Logging Service tracks Client Access License (CAL) usage
//! for server products. It helps administrators monitor license compliance
//! and plan for capacity.
//!
//! Key components:
//! - Per-server and per-seat licensing modes
//! - Product license tracking
//! - Client usage history
//! - License compliance reports

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use crate::win32k::user::UserHandle;

/// Type alias for window handles
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of products
const MAX_PRODUCTS: usize = 64;

/// Maximum number of licenses
const MAX_LICENSES: usize = 256;

/// Maximum number of clients
const MAX_CLIENTS: usize = 512;

/// Maximum number of servers
const MAX_SERVERS: usize = 32;

/// Maximum name length
const MAX_NAME_LEN: usize = 128;

/// Maximum purchase record length
const MAX_PURCHASE_LEN: usize = 64;

// ============================================================================
// Enumerations
// ============================================================================

/// Licensing mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LicensingMode {
    /// Per-server mode (concurrent connections)
    PerServer = 0,
    /// Per-seat mode (per device/user)
    PerSeat = 1,
}

impl Default for LicensingMode {
    fn default() -> Self {
        Self::PerServer
    }
}

/// License status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LicenseStatus {
    /// License is valid
    Valid = 0,
    /// License is expired
    Expired = 1,
    /// License is revoked
    Revoked = 2,
    /// License is pending
    Pending = 3,
    /// License violation
    Violation = 4,
}

impl Default for LicenseStatus {
    fn default() -> Self {
        Self::Valid
    }
}

/// Client type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ClientType {
    /// Windows workstation
    Workstation = 0,
    /// Windows server
    Server = 1,
    /// Terminal Services client
    TerminalServices = 2,
    /// Other client
    Other = 3,
}

impl Default for ClientType {
    fn default() -> Self {
        Self::Workstation
    }
}

/// Product family
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ProductFamily {
    /// Windows Server
    WindowsServer = 0,
    /// SQL Server
    SqlServer = 1,
    /// Exchange Server
    ExchangeServer = 2,
    /// SharePoint
    SharePoint = 3,
    /// Other Microsoft product
    OtherMicrosoft = 4,
    /// Third-party product
    ThirdParty = 5,
}

impl Default for ProductFamily {
    fn default() -> Self {
        Self::WindowsServer
    }
}

/// Alert type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AlertType {
    /// No alerts
    None = 0,
    /// Warning (nearing limit)
    Warning = 1,
    /// Critical (at or over limit)
    Critical = 2,
    /// Violation detected
    Violation = 3,
}

impl Default for AlertType {
    fn default() -> Self {
        Self::None
    }
}

// ============================================================================
// Structures
// ============================================================================

/// Licensed product
#[derive(Debug)]
pub struct LicensedProduct {
    /// Product ID
    pub id: u32,
    /// Active flag
    pub active: bool,
    /// Product name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Product family
    pub family: ProductFamily,
    /// Version string
    pub version: [u8; 32],
    /// Version length
    pub version_len: usize,
    /// Licensing mode
    pub mode: LicensingMode,
    /// Total licenses purchased
    pub licenses_purchased: u32,
    /// Licenses in use
    pub licenses_in_use: u32,
    /// Peak concurrent usage
    pub peak_usage: u32,
    /// License status
    pub status: LicenseStatus,
    /// Alert type
    pub alert: AlertType,
    /// Warning threshold (percentage)
    pub warning_threshold: u8,
    /// Window handle
    pub hwnd: HWND,
}

impl LicensedProduct {
    /// Create new product
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            family: ProductFamily::WindowsServer,
            version: [0u8; 32],
            version_len: 0,
            mode: LicensingMode::PerServer,
            licenses_purchased: 0,
            licenses_in_use: 0,
            peak_usage: 0,
            status: LicenseStatus::Valid,
            alert: AlertType::None,
            warning_threshold: 80,
            hwnd: UserHandle::NULL,
        }
    }
}

/// License purchase record
#[derive(Debug)]
pub struct LicensePurchase {
    /// Purchase ID
    pub id: u32,
    /// Active flag
    pub active: bool,
    /// Product ID
    pub product_id: u32,
    /// Number of licenses
    pub quantity: u32,
    /// Purchase date
    pub purchase_date: u64,
    /// Expiration date (0 = perpetual)
    pub expiration_date: u64,
    /// Purchase order number
    pub po_number: [u8; MAX_PURCHASE_LEN],
    /// PO number length
    pub po_len: usize,
    /// Vendor name
    pub vendor: [u8; MAX_NAME_LEN],
    /// Vendor length
    pub vendor_len: usize,
    /// License key (first 32 chars)
    pub license_key: [u8; 32],
    /// License key length
    pub key_len: usize,
    /// Administrator who added
    pub added_by: [u8; MAX_NAME_LEN],
    /// Added by length
    pub added_by_len: usize,
    /// Notes
    pub notes: [u8; MAX_NAME_LEN],
    /// Notes length
    pub notes_len: usize,
}

impl LicensePurchase {
    /// Create new purchase record
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            product_id: 0,
            quantity: 0,
            purchase_date: 0,
            expiration_date: 0,
            po_number: [0u8; MAX_PURCHASE_LEN],
            po_len: 0,
            vendor: [0u8; MAX_NAME_LEN],
            vendor_len: 0,
            license_key: [0u8; 32],
            key_len: 0,
            added_by: [0u8; MAX_NAME_LEN],
            added_by_len: 0,
            notes: [0u8; MAX_NAME_LEN],
            notes_len: 0,
        }
    }
}

/// Client access record
#[derive(Debug)]
pub struct ClientAccess {
    /// Client ID
    pub id: u32,
    /// Active flag
    pub active: bool,
    /// Client name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Client type
    pub client_type: ClientType,
    /// Username
    pub username: [u8; MAX_NAME_LEN],
    /// Username length
    pub username_len: usize,
    /// IP address
    pub ip_address: [u8; 4],
    /// Product ID accessing
    pub product_id: u32,
    /// First access time
    pub first_access: u64,
    /// Last access time
    pub last_access: u64,
    /// Total access count
    pub access_count: u32,
    /// Currently connected
    pub is_connected: bool,
    /// Has assigned seat license
    pub has_seat_license: bool,
}

impl ClientAccess {
    /// Create new client access
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            client_type: ClientType::Workstation,
            username: [0u8; MAX_NAME_LEN],
            username_len: 0,
            ip_address: [0u8; 4],
            product_id: 0,
            first_access: 0,
            last_access: 0,
            access_count: 0,
            is_connected: false,
            has_seat_license: false,
        }
    }
}

/// Server in license group
#[derive(Debug)]
pub struct LicenseServer {
    /// Server ID
    pub id: u32,
    /// Active flag
    pub active: bool,
    /// Server name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Is enterprise server
    pub is_enterprise: bool,
    /// Is this server (local)
    pub is_local: bool,
    /// Last replicated time
    pub last_replicated: u64,
    /// Replication status
    pub replication_ok: bool,
    /// Products hosted
    pub product_count: u32,
    /// Total CALs
    pub total_cals: u32,
}

impl LicenseServer {
    /// Create new server
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            is_enterprise: false,
            is_local: false,
            last_replicated: 0,
            replication_ok: true,
            product_count: 0,
            total_cals: 0,
        }
    }
}

/// License statistics
#[derive(Debug)]
pub struct LicenseStatistics {
    /// Total products tracked
    pub total_products: u32,
    /// Total licenses
    pub total_licenses: u32,
    /// Licenses in use
    pub licenses_in_use: u32,
    /// Unique clients
    pub unique_clients: u32,
    /// Current violations
    pub violations: u32,
    /// Compliance percentage
    pub compliance_percent: u8,
}

impl LicenseStatistics {
    /// Create new statistics
    pub const fn new() -> Self {
        Self {
            total_products: 0,
            total_licenses: 0,
            licenses_in_use: 0,
            unique_clients: 0,
            violations: 0,
            compliance_percent: 100,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// License Logging state
struct LicLogState {
    /// Licensed products
    products: [LicensedProduct; MAX_PRODUCTS],
    /// License purchases
    purchases: [LicensePurchase; MAX_LICENSES],
    /// Client access records
    clients: [ClientAccess; MAX_CLIENTS],
    /// License servers
    servers: [LicenseServer; MAX_SERVERS],
    /// Statistics
    stats: LicenseStatistics,
    /// Next ID counter
    next_id: u32,
}

impl LicLogState {
    /// Create new state
    const fn new() -> Self {
        Self {
            products: [const { LicensedProduct::new() }; MAX_PRODUCTS],
            purchases: [const { LicensePurchase::new() }; MAX_LICENSES],
            clients: [const { ClientAccess::new() }; MAX_CLIENTS],
            servers: [const { LicenseServer::new() }; MAX_SERVERS],
            stats: LicenseStatistics::new(),
            next_id: 1,
        }
    }
}

/// Global state
static LICLOG_STATE: SpinLock<LicLogState> = SpinLock::new(LicLogState::new());

/// Module initialized flag
static LICLOG_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Product count
static PRODUCT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Client count
static CLIENT_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Product Functions
// ============================================================================

/// Register a licensed product
pub fn register_product(
    name: &[u8],
    family: ProductFamily,
    version: &[u8],
    mode: LicensingMode,
) -> Result<u32, u32> {
    let mut state = LICLOG_STATE.lock();

    let slot = state.products.iter().position(|p| !p.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let id = state.next_id;
    state.next_id += 1;

    let product = &mut state.products[slot];
    product.id = id;
    product.active = true;

    let name_len = name.len().min(MAX_NAME_LEN);
    product.name[..name_len].copy_from_slice(&name[..name_len]);
    product.name_len = name_len;

    product.family = family;

    let ver_len = version.len().min(32);
    product.version[..ver_len].copy_from_slice(&version[..ver_len]);
    product.version_len = ver_len;

    product.mode = mode;
    product.status = LicenseStatus::Valid;
    product.hwnd = UserHandle::from_raw(id);

    state.stats.total_products += 1;
    PRODUCT_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(id)
}

/// Remove a product
pub fn remove_product(product_id: u32) -> Result<(), u32> {
    let mut state = LICLOG_STATE.lock();

    let product = state.products.iter_mut().find(|p| p.active && p.id == product_id);

    match product {
        Some(p) => {
            p.active = false;
            state.stats.total_products = state.stats.total_products.saturating_sub(1);
            PRODUCT_COUNT.fetch_sub(1, Ordering::Relaxed);
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Set product licensing mode
pub fn set_product_mode(product_id: u32, mode: LicensingMode) -> Result<(), u32> {
    let mut state = LICLOG_STATE.lock();

    let product = state.products.iter_mut().find(|p| p.active && p.id == product_id);

    match product {
        Some(p) => {
            p.mode = mode;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Set warning threshold
pub fn set_warning_threshold(product_id: u32, threshold: u8) -> Result<(), u32> {
    let mut state = LICLOG_STATE.lock();

    let product = state.products.iter_mut().find(|p| p.active && p.id == product_id);

    match product {
        Some(p) => {
            p.warning_threshold = threshold.min(100);
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Get product count
pub fn get_product_count() -> u32 {
    PRODUCT_COUNT.load(Ordering::Relaxed)
}

// ============================================================================
// Purchase Functions
// ============================================================================

/// Add a license purchase
pub fn add_purchase(
    product_id: u32,
    quantity: u32,
    po_number: &[u8],
    vendor: &[u8],
) -> Result<u32, u32> {
    let mut state = LICLOG_STATE.lock();

    // Verify product exists
    let product_idx = state.products.iter().position(|p| p.active && p.id == product_id);
    let product_idx = match product_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    let slot = state.purchases.iter().position(|p| !p.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let id = state.next_id;
    state.next_id += 1;

    let purchase = &mut state.purchases[slot];
    purchase.id = id;
    purchase.active = true;
    purchase.product_id = product_id;
    purchase.quantity = quantity;
    purchase.purchase_date = 0; // Would use current time

    let po_len = po_number.len().min(MAX_PURCHASE_LEN);
    purchase.po_number[..po_len].copy_from_slice(&po_number[..po_len]);
    purchase.po_len = po_len;

    let vendor_len = vendor.len().min(MAX_NAME_LEN);
    purchase.vendor[..vendor_len].copy_from_slice(&vendor[..vendor_len]);
    purchase.vendor_len = vendor_len;

    // Update product license count
    state.products[product_idx].licenses_purchased += quantity;
    state.stats.total_licenses += quantity;

    Ok(id)
}

/// Remove a purchase
pub fn remove_purchase(purchase_id: u32) -> Result<(), u32> {
    let mut state = LICLOG_STATE.lock();

    // Find purchase index
    let purchase_idx = state.purchases.iter().position(|p| p.active && p.id == purchase_id);
    let purchase_idx = match purchase_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    let product_id = state.purchases[purchase_idx].product_id;
    let quantity = state.purchases[purchase_idx].quantity;

    state.purchases[purchase_idx].active = false;

    // Update product license count
    if let Some(p) = state.products.iter_mut().find(|p| p.active && p.id == product_id) {
        p.licenses_purchased = p.licenses_purchased.saturating_sub(quantity);
    }

    state.stats.total_licenses = state.stats.total_licenses.saturating_sub(quantity);

    Ok(())
}

/// Set purchase expiration
pub fn set_purchase_expiration(purchase_id: u32, expiration_date: u64) -> Result<(), u32> {
    let mut state = LICLOG_STATE.lock();

    let purchase = state.purchases.iter_mut().find(|p| p.active && p.id == purchase_id);

    match purchase {
        Some(p) => {
            p.expiration_date = expiration_date;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

// ============================================================================
// Client Functions
// ============================================================================

/// Record client access
pub fn record_client_access(
    name: &[u8],
    client_type: ClientType,
    username: &[u8],
    product_id: u32,
) -> Result<u32, u32> {
    let mut state = LICLOG_STATE.lock();

    // Check if client already exists
    let existing = state.clients.iter_mut().find(|c| {
        c.active && c.name[..c.name_len] == name[..name.len().min(c.name_len)]
    });

    if let Some(client) = existing {
        client.last_access = 0; // Would use current time
        client.access_count += 1;
        client.is_connected = true;
        return Ok(client.id);
    }

    // Add new client
    let slot = state.clients.iter().position(|c| !c.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let id = state.next_id;
    state.next_id += 1;

    let client = &mut state.clients[slot];
    client.id = id;
    client.active = true;

    let name_len = name.len().min(MAX_NAME_LEN);
    client.name[..name_len].copy_from_slice(&name[..name_len]);
    client.name_len = name_len;

    client.client_type = client_type;

    let user_len = username.len().min(MAX_NAME_LEN);
    client.username[..user_len].copy_from_slice(&username[..user_len]);
    client.username_len = user_len;

    client.product_id = product_id;
    client.first_access = 0; // Would use current time
    client.last_access = 0;
    client.access_count = 1;
    client.is_connected = true;

    state.stats.unique_clients += 1;
    CLIENT_COUNT.fetch_add(1, Ordering::Relaxed);

    // Update product usage
    if let Some(p) = state.products.iter_mut().find(|p| p.active && p.id == product_id) {
        p.licenses_in_use += 1;
        if p.licenses_in_use > p.peak_usage {
            p.peak_usage = p.licenses_in_use;
        }
        state.stats.licenses_in_use += 1;
    }

    Ok(id)
}

/// Record client disconnect
pub fn record_client_disconnect(client_id: u32) -> Result<(), u32> {
    let mut state = LICLOG_STATE.lock();

    // Find client index
    let client_idx = state.clients.iter().position(|c| c.active && c.id == client_id);
    let client_idx = match client_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    if !state.clients[client_idx].is_connected {
        return Ok(());
    }

    let product_id = state.clients[client_idx].product_id;

    state.clients[client_idx].is_connected = false;
    state.clients[client_idx].last_access = 0;

    // Update product usage
    if let Some(p) = state.products.iter_mut().find(|p| p.active && p.id == product_id) {
        p.licenses_in_use = p.licenses_in_use.saturating_sub(1);
        state.stats.licenses_in_use = state.stats.licenses_in_use.saturating_sub(1);
    }

    Ok(())
}

/// Assign seat license to client
pub fn assign_seat_license(client_id: u32) -> Result<(), u32> {
    let mut state = LICLOG_STATE.lock();

    let client = state.clients.iter_mut().find(|c| c.active && c.id == client_id);

    match client {
        Some(c) => {
            c.has_seat_license = true;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Get client count
pub fn get_client_count() -> u32 {
    CLIENT_COUNT.load(Ordering::Relaxed)
}

// ============================================================================
// Server Functions
// ============================================================================

/// Register a license server
pub fn register_server(name: &[u8], is_enterprise: bool, is_local: bool) -> Result<u32, u32> {
    let mut state = LICLOG_STATE.lock();

    let slot = state.servers.iter().position(|s| !s.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let id = state.next_id;
    state.next_id += 1;

    let server = &mut state.servers[slot];
    server.id = id;
    server.active = true;

    let name_len = name.len().min(MAX_NAME_LEN);
    server.name[..name_len].copy_from_slice(&name[..name_len]);
    server.name_len = name_len;

    server.is_enterprise = is_enterprise;
    server.is_local = is_local;
    server.replication_ok = true;

    Ok(id)
}

/// Remove a server
pub fn remove_server(server_id: u32) -> Result<(), u32> {
    let mut state = LICLOG_STATE.lock();

    let server = state.servers.iter_mut().find(|s| s.active && s.id == server_id);

    match server {
        Some(s) => {
            if s.is_local {
                return Err(0x80070005); // Can't remove local server
            }
            s.active = false;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Update replication status
pub fn update_replication_status(server_id: u32, success: bool) -> Result<(), u32> {
    let mut state = LICLOG_STATE.lock();

    let server = state.servers.iter_mut().find(|s| s.active && s.id == server_id);

    match server {
        Some(s) => {
            s.last_replicated = 0; // Would use current time
            s.replication_ok = success;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

// ============================================================================
// Statistics Functions
// ============================================================================

/// Check compliance and update alerts
pub fn check_compliance() -> Result<(), u32> {
    let mut state = LICLOG_STATE.lock();

    let mut violations = 0u32;

    for product in state.products.iter_mut() {
        if !product.active {
            continue;
        }

        // Calculate usage percentage
        let usage_percent = if product.licenses_purchased > 0 {
            (product.licenses_in_use * 100) / product.licenses_purchased
        } else {
            if product.licenses_in_use > 0 { 100 } else { 0 }
        };

        // Update alert status
        if product.licenses_in_use > product.licenses_purchased {
            product.alert = AlertType::Violation;
            product.status = LicenseStatus::Violation;
            violations += 1;
        } else if usage_percent >= 100 {
            product.alert = AlertType::Critical;
        } else if usage_percent >= product.warning_threshold as u32 {
            product.alert = AlertType::Warning;
        } else {
            product.alert = AlertType::None;
        }
    }

    state.stats.violations = violations;

    // Calculate overall compliance
    if state.stats.total_licenses > 0 {
        let compliant = state.stats.total_licenses.saturating_sub(
            state.stats.licenses_in_use.saturating_sub(state.stats.total_licenses)
        );
        state.stats.compliance_percent =
            ((compliant * 100) / state.stats.total_licenses).min(100) as u8;
    } else {
        state.stats.compliance_percent = 100;
    }

    Ok(())
}

/// Get license statistics
pub fn get_statistics() -> LicenseStatistics {
    let state = LICLOG_STATE.lock();
    LicenseStatistics {
        total_products: state.stats.total_products,
        total_licenses: state.stats.total_licenses,
        licenses_in_use: state.stats.licenses_in_use,
        unique_clients: state.stats.unique_clients,
        violations: state.stats.violations,
        compliance_percent: state.stats.compliance_percent,
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize License Logging module
pub fn init() -> Result<(), &'static str> {
    if LICLOG_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let mut state = LICLOG_STATE.lock();

    // Reserve IDs
    let server_id = state.next_id;
    let product_id = state.next_id + 1;
    state.next_id += 2;

    // Create local server entry
    {
        let server = &mut state.servers[0];
        server.id = server_id;
        server.active = true;
        let name = b"LOCALHOST";
        server.name[..name.len()].copy_from_slice(name);
        server.name_len = name.len();
        server.is_local = true;
        server.is_enterprise = false;
        server.replication_ok = true;
    }

    // Create Windows Server 2003 product entry
    {
        let product = &mut state.products[0];
        product.id = product_id;
        product.active = true;
        let name = b"Windows Server 2003";
        product.name[..name.len()].copy_from_slice(name);
        product.name_len = name.len();
        product.family = ProductFamily::WindowsServer;
        let version = b"5.2.3790";
        product.version[..version.len()].copy_from_slice(version);
        product.version_len = version.len();
        product.mode = LicensingMode::PerServer;
        product.hwnd = UserHandle::from_raw(product_id);
    }

    state.stats.total_products = 1;
    PRODUCT_COUNT.store(1, Ordering::Relaxed);

    Ok(())
}

/// Check if module is initialized
pub fn is_initialized() -> bool {
    LICLOG_INITIALIZED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_licensing_mode() {
        assert_eq!(LicensingMode::default(), LicensingMode::PerServer);
        assert_eq!(LicensingMode::PerSeat as u32, 1);
    }

    #[test]
    fn test_license_status() {
        assert_eq!(LicenseStatus::default(), LicenseStatus::Valid);
        assert_eq!(LicenseStatus::Violation as u32, 4);
    }

    #[test]
    fn test_product_family() {
        assert_eq!(ProductFamily::default(), ProductFamily::WindowsServer);
        assert_eq!(ProductFamily::SqlServer as u32, 1);
    }
}
