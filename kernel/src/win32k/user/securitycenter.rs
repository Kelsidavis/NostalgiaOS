//! Windows Security Center
//!
//! Implements the Security Center following Windows Server 2003 SP1.
//! Monitors firewall, automatic updates, and virus protection status.
//!
//! # References
//!
//! Based on Windows Server 2003 SP1:
//! - Security Center (wscui.cpl)
//! - Windows Security Center service

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum antivirus products
const MAX_AV_PRODUCTS: usize = 4;

/// Maximum name length
const MAX_NAME: usize = 64;

/// Maximum version length
const MAX_VERSION: usize = 32;

// ============================================================================
// Protection Status
// ============================================================================

/// Protection status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtectionStatus {
    /// Not monitored
    #[default]
    NotMonitored = 0,
    /// On (protected)
    On = 1,
    /// Off (not protected)
    Off = 2,
    /// Snoozed (temporarily disabled)
    Snoozed = 3,
    /// Expired (subscription expired)
    Expired = 4,
    /// Out of date
    OutOfDate = 5,
}

impl ProtectionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtectionStatus::NotMonitored => "Not Monitored",
            ProtectionStatus::On => "ON",
            ProtectionStatus::Off => "OFF",
            ProtectionStatus::Snoozed => "Snoozed",
            ProtectionStatus::Expired => "Expired",
            ProtectionStatus::OutOfDate => "Out of Date",
        }
    }

    pub fn is_protected(&self) -> bool {
        matches!(self, ProtectionStatus::On)
    }
}

// ============================================================================
// Security Area
// ============================================================================

/// Security area being monitored
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityArea {
    /// Firewall
    #[default]
    Firewall = 0,
    /// Automatic Updates
    AutomaticUpdates = 1,
    /// Virus Protection
    VirusProtection = 2,
}

impl SecurityArea {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityArea::Firewall => "Firewall",
            SecurityArea::AutomaticUpdates => "Automatic Updates",
            SecurityArea::VirusProtection => "Virus Protection",
        }
    }
}

// ============================================================================
// Antivirus Product
// ============================================================================

/// Antivirus product information
#[derive(Debug, Clone, Copy)]
pub struct AntivirusProduct {
    /// Product name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Company name
    pub company: [u8; MAX_NAME],
    /// Company length
    pub company_len: usize,
    /// Version
    pub version: [u8; MAX_VERSION],
    /// Version length
    pub version_len: usize,
    /// Product state
    pub state: ProtectionStatus,
    /// Definitions up to date
    pub definitions_current: bool,
    /// Real-time protection enabled
    pub realtime_enabled: bool,
    /// Last scan timestamp
    pub last_scan: u64,
    /// Definition date (days since epoch)
    pub definition_date: u32,
}

impl AntivirusProduct {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME],
            name_len: 0,
            company: [0u8; MAX_NAME],
            company_len: 0,
            version: [0u8; MAX_VERSION],
            version_len: 0,
            state: ProtectionStatus::Off,
            definitions_current: false,
            realtime_enabled: false,
            last_scan: 0,
            definition_date: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_company(&mut self, company: &[u8]) {
        let len = company.len().min(MAX_NAME);
        self.company[..len].copy_from_slice(&company[..len]);
        self.company_len = len;
    }

    pub fn set_version(&mut self, version: &[u8]) {
        let len = version.len().min(MAX_VERSION);
        self.version[..len].copy_from_slice(&version[..len]);
        self.version_len = len;
    }
}

impl Default for AntivirusProduct {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Security Center State
// ============================================================================

/// Security Center state
struct SecurityCenterState {
    /// Firewall status
    firewall_status: ProtectionStatus,
    /// Automatic Updates status
    updates_status: ProtectionStatus,
    /// Virus protection status
    virus_status: ProtectionStatus,
    /// Registered antivirus products
    av_products: [AntivirusProduct; MAX_AV_PRODUCTS],
    /// Number of AV products
    av_count: usize,
    /// Security Center service enabled
    service_enabled: bool,
    /// Alert notifications enabled
    alerts_enabled: bool,
    /// Firewall monitoring enabled
    monitor_firewall: bool,
    /// Updates monitoring enabled
    monitor_updates: bool,
    /// Virus protection monitoring enabled
    monitor_virus: bool,
}

impl SecurityCenterState {
    pub const fn new() -> Self {
        Self {
            firewall_status: ProtectionStatus::Off,
            updates_status: ProtectionStatus::Off,
            virus_status: ProtectionStatus::Off,
            av_products: [const { AntivirusProduct::new() }; MAX_AV_PRODUCTS],
            av_count: 0,
            service_enabled: true,
            alerts_enabled: true,
            monitor_firewall: true,
            monitor_updates: true,
            monitor_virus: true,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static SECCENTER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static SECCENTER_STATE: SpinLock<SecurityCenterState> = SpinLock::new(SecurityCenterState::new());

// Alert counters
static FIREWALL_ALERTS: AtomicU32 = AtomicU32::new(0);
static UPDATES_ALERTS: AtomicU32 = AtomicU32::new(0);
static VIRUS_ALERTS: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Security Center
pub fn init() {
    if SECCENTER_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = SECCENTER_STATE.lock();

    // Initialize with default status
    // In a real implementation, this would query actual services
    state.firewall_status = ProtectionStatus::On; // Windows Firewall enabled
    state.updates_status = ProtectionStatus::On;  // Automatic Updates enabled
    state.virus_status = ProtectionStatus::Off;   // No AV installed by default

    // Add sample AV product (simulating installed AV)
    add_sample_av_product(&mut state);

    state.service_enabled = true;
    state.alerts_enabled = true;

    crate::serial_println!("[WIN32K] Security Center initialized");
}

/// Add sample AV product
fn add_sample_av_product(state: &mut SecurityCenterState) {
    if state.av_count >= MAX_AV_PRODUCTS {
        return;
    }

    let mut av = AntivirusProduct::new();
    av.set_name(b"Windows Defender");
    av.set_company(b"Microsoft Corporation");
    av.set_version(b"1.1.1593.0");
    av.state = ProtectionStatus::On;
    av.definitions_current = true;
    av.realtime_enabled = true;
    av.definition_date = 12784; // Some arbitrary day

    state.av_products[0] = av;
    state.av_count = 1;
    state.virus_status = ProtectionStatus::On;
}

// ============================================================================
// Status Queries
// ============================================================================

/// Get overall security status
pub fn get_overall_status() -> ProtectionStatus {
    let state = SECCENTER_STATE.lock();

    if !state.service_enabled {
        return ProtectionStatus::NotMonitored;
    }

    // Check all monitored areas
    if state.monitor_firewall && !state.firewall_status.is_protected() {
        return ProtectionStatus::Off;
    }
    if state.monitor_updates && !state.updates_status.is_protected() {
        return ProtectionStatus::Off;
    }
    if state.monitor_virus && !state.virus_status.is_protected() {
        return ProtectionStatus::Off;
    }

    ProtectionStatus::On
}

/// Get firewall status
pub fn get_firewall_status() -> ProtectionStatus {
    SECCENTER_STATE.lock().firewall_status
}

/// Get automatic updates status
pub fn get_updates_status() -> ProtectionStatus {
    SECCENTER_STATE.lock().updates_status
}

/// Get virus protection status
pub fn get_virus_status() -> ProtectionStatus {
    SECCENTER_STATE.lock().virus_status
}

/// Get status for a specific area
pub fn get_status(area: SecurityArea) -> ProtectionStatus {
    let state = SECCENTER_STATE.lock();
    match area {
        SecurityArea::Firewall => state.firewall_status,
        SecurityArea::AutomaticUpdates => state.updates_status,
        SecurityArea::VirusProtection => state.virus_status,
    }
}

/// Check if all areas are protected
pub fn is_fully_protected() -> bool {
    get_overall_status().is_protected()
}

// ============================================================================
// Status Updates
// ============================================================================

/// Update firewall status
pub fn update_firewall_status(status: ProtectionStatus) {
    let mut state = SECCENTER_STATE.lock();
    let old_status = state.firewall_status;
    state.firewall_status = status;

    if old_status.is_protected() && !status.is_protected() && state.alerts_enabled {
        FIREWALL_ALERTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Update automatic updates status
pub fn update_updates_status(status: ProtectionStatus) {
    let mut state = SECCENTER_STATE.lock();
    let old_status = state.updates_status;
    state.updates_status = status;

    if old_status.is_protected() && !status.is_protected() && state.alerts_enabled {
        UPDATES_ALERTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Update virus protection status
pub fn update_virus_status(status: ProtectionStatus) {
    let mut state = SECCENTER_STATE.lock();
    let old_status = state.virus_status;
    state.virus_status = status;

    if old_status.is_protected() && !status.is_protected() && state.alerts_enabled {
        VIRUS_ALERTS.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// Antivirus Management
// ============================================================================

/// Get AV product count
pub fn get_av_product_count() -> usize {
    SECCENTER_STATE.lock().av_count
}

/// Get AV product by index
pub fn get_av_product(index: usize) -> Option<AntivirusProduct> {
    let state = SECCENTER_STATE.lock();
    if index < state.av_count {
        Some(state.av_products[index])
    } else {
        None
    }
}

/// Register an antivirus product
pub fn register_av_product(product: &AntivirusProduct) -> bool {
    let mut state = SECCENTER_STATE.lock();
    if state.av_count >= MAX_AV_PRODUCTS {
        return false;
    }

    let idx = state.av_count;
    state.av_products[idx] = *product;
    state.av_count += 1;

    // Update virus protection status based on product
    if product.state.is_protected() {
        state.virus_status = ProtectionStatus::On;
    }

    true
}

/// Unregister an antivirus product
pub fn unregister_av_product(index: usize) -> bool {
    let mut state = SECCENTER_STATE.lock();
    if index >= state.av_count {
        return false;
    }

    // Shift remaining products
    for i in index..state.av_count - 1 {
        state.av_products[i] = state.av_products[i + 1];
    }
    state.av_count -= 1;

    // Update virus status
    if state.av_count == 0 {
        state.virus_status = ProtectionStatus::Off;
    } else {
        // Check if any remaining product is active
        let mut any_active = false;
        for i in 0..state.av_count {
            if state.av_products[i].state.is_protected() {
                any_active = true;
                break;
            }
        }
        state.virus_status = if any_active { ProtectionStatus::On } else { ProtectionStatus::Off };
    }

    true
}

// ============================================================================
// Service Configuration
// ============================================================================

/// Enable/disable Security Center service
pub fn set_service_enabled(enabled: bool) {
    SECCENTER_STATE.lock().service_enabled = enabled;
}

/// Check if service is enabled
pub fn is_service_enabled() -> bool {
    SECCENTER_STATE.lock().service_enabled
}

/// Enable/disable alert notifications
pub fn set_alerts_enabled(enabled: bool) {
    SECCENTER_STATE.lock().alerts_enabled = enabled;
}

/// Check if alerts are enabled
pub fn are_alerts_enabled() -> bool {
    SECCENTER_STATE.lock().alerts_enabled
}

/// Set monitoring for a specific area
pub fn set_monitoring(area: SecurityArea, enabled: bool) {
    let mut state = SECCENTER_STATE.lock();
    match area {
        SecurityArea::Firewall => state.monitor_firewall = enabled,
        SecurityArea::AutomaticUpdates => state.monitor_updates = enabled,
        SecurityArea::VirusProtection => state.monitor_virus = enabled,
    }
}

/// Check if monitoring is enabled for an area
pub fn is_monitoring_enabled(area: SecurityArea) -> bool {
    let state = SECCENTER_STATE.lock();
    match area {
        SecurityArea::Firewall => state.monitor_firewall,
        SecurityArea::AutomaticUpdates => state.monitor_updates,
        SecurityArea::VirusProtection => state.monitor_virus,
    }
}

// ============================================================================
// Recommendations
// ============================================================================

/// Security recommendation
#[derive(Debug, Clone, Copy)]
pub struct SecurityRecommendation {
    /// Area of concern
    pub area: SecurityArea,
    /// Short title
    pub title: [u8; 64],
    /// Title length
    pub title_len: usize,
    /// Recommendation text
    pub text: [u8; 256],
    /// Text length
    pub text_len: usize,
    /// Is critical
    pub critical: bool,
}

impl SecurityRecommendation {
    pub const fn new() -> Self {
        Self {
            area: SecurityArea::Firewall,
            title: [0u8; 64],
            title_len: 0,
            text: [0u8; 256],
            text_len: 0,
            critical: false,
        }
    }
}

impl Default for SecurityRecommendation {
    fn default() -> Self {
        Self::new()
    }
}

/// Get security recommendations
pub fn get_recommendations() -> ([SecurityRecommendation; 4], usize) {
    let state = SECCENTER_STATE.lock();
    let mut recs = [const { SecurityRecommendation::new() }; 4];
    let mut count = 0;

    // Check firewall
    if state.monitor_firewall && !state.firewall_status.is_protected() {
        let mut rec = SecurityRecommendation::new();
        rec.area = SecurityArea::Firewall;
        let title = b"Turn on Firewall";
        rec.title[..title.len()].copy_from_slice(title);
        rec.title_len = title.len();
        let text = b"Windows Firewall is turned off. Your computer is at risk.";
        rec.text[..text.len()].copy_from_slice(text);
        rec.text_len = text.len();
        rec.critical = true;
        recs[count] = rec;
        count += 1;
    }

    // Check updates
    if state.monitor_updates && !state.updates_status.is_protected() {
        let mut rec = SecurityRecommendation::new();
        rec.area = SecurityArea::AutomaticUpdates;
        let title = b"Turn on Automatic Updates";
        rec.title[..title.len()].copy_from_slice(title);
        rec.title_len = title.len();
        let text = b"Automatic Updates are turned off. You may miss important security updates.";
        rec.text[..text.len()].copy_from_slice(text);
        rec.text_len = text.len();
        rec.critical = true;
        recs[count] = rec;
        count += 1;
    }

    // Check virus protection
    if state.monitor_virus && !state.virus_status.is_protected() {
        let mut rec = SecurityRecommendation::new();
        rec.area = SecurityArea::VirusProtection;
        let title = b"Install Antivirus Software";
        rec.title[..title.len()].copy_from_slice(title);
        rec.title_len = title.len();
        let text = b"No antivirus software is detected. Install antivirus software to protect your computer.";
        rec.text[..text.len()].copy_from_slice(text);
        rec.text_len = text.len();
        rec.critical = true;
        recs[count] = rec;
        count += 1;
    }

    (recs, count)
}

// ============================================================================
// Statistics
// ============================================================================

/// Security Center statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct SecurityCenterStats {
    pub initialized: bool,
    pub service_enabled: bool,
    pub overall_status: ProtectionStatus,
    pub firewall_status: ProtectionStatus,
    pub updates_status: ProtectionStatus,
    pub virus_status: ProtectionStatus,
    pub av_product_count: usize,
    pub firewall_alerts: u32,
    pub updates_alerts: u32,
    pub virus_alerts: u32,
}

/// Get Security Center statistics
pub fn get_stats() -> SecurityCenterStats {
    let state = SECCENTER_STATE.lock();
    SecurityCenterStats {
        initialized: SECCENTER_INITIALIZED.load(Ordering::Relaxed),
        service_enabled: state.service_enabled,
        overall_status: if state.service_enabled {
            if state.firewall_status.is_protected() &&
               state.updates_status.is_protected() &&
               state.virus_status.is_protected() {
                ProtectionStatus::On
            } else {
                ProtectionStatus::Off
            }
        } else {
            ProtectionStatus::NotMonitored
        },
        firewall_status: state.firewall_status,
        updates_status: state.updates_status,
        virus_status: state.virus_status,
        av_product_count: state.av_count,
        firewall_alerts: FIREWALL_ALERTS.load(Ordering::Relaxed),
        updates_alerts: UPDATES_ALERTS.load(Ordering::Relaxed),
        virus_alerts: VIRUS_ALERTS.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Security Center dialog handle
pub type HSECCENTERDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Security Center dialog
pub fn create_seccenter_dialog(_parent: super::super::HWND) -> HSECCENTERDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}
