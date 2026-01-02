//! Internet Options Control Panel
//!
//! Kernel-mode Internet options dialog following Windows NT patterns.
//! Provides browser settings, proxy configuration, security zones, and privacy settings.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/cpls/inetcpl/` - Internet control panel

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// Constants
// ============================================================================

/// Maximum URL length
const MAX_URL: usize = 2048;

/// Maximum proxy server length
const MAX_PROXY: usize = 256;

/// Maximum security zones
const MAX_ZONES: usize = 8;

/// Maximum sites per zone
const MAX_ZONE_SITES: usize = 128;

/// Maximum site URL length
const MAX_SITE_URL: usize = 256;

/// Maximum history days
const MAX_HISTORY_DAYS: u32 = 999;

/// Security zone IDs
pub mod zone {
    /// My Computer
    pub const LOCAL_MACHINE: u32 = 0;
    /// Local Intranet
    pub const INTRANET: u32 = 1;
    /// Trusted Sites
    pub const TRUSTED: u32 = 2;
    /// Internet
    pub const INTERNET: u32 = 3;
    /// Restricted Sites
    pub const RESTRICTED: u32 = 4;
}

/// Security level presets
pub mod security_level {
    /// High security
    pub const HIGH: u32 = 0x00012000;
    /// Medium-high security
    pub const MEDIUM_HIGH: u32 = 0x00010500;
    /// Medium security
    pub const MEDIUM: u32 = 0x00011000;
    /// Medium-low security
    pub const MEDIUM_LOW: u32 = 0x00010000;
    /// Low security
    pub const LOW: u32 = 0x00010500;
    /// Custom security
    pub const CUSTOM: u32 = 0;
}

/// Privacy level presets
pub mod privacy_level {
    /// Block all cookies
    pub const BLOCK_ALL: u32 = 0;
    /// High privacy
    pub const HIGH: u32 = 1;
    /// Medium-high privacy
    pub const MEDIUM_HIGH: u32 = 2;
    /// Medium privacy
    pub const MEDIUM: u32 = 3;
    /// Low privacy
    pub const LOW: u32 = 4;
    /// Accept all cookies
    pub const ACCEPT_ALL: u32 = 5;
}

/// Connection type
pub mod connection_type {
    /// No proxy
    pub const DIRECT: u32 = 0;
    /// Manual proxy configuration
    pub const PROXY: u32 = 1;
    /// Automatic proxy detection
    pub const AUTO_DETECT: u32 = 2;
    /// Automatic configuration script
    pub const AUTO_CONFIG: u32 = 3;
}

/// URL action flags
pub mod url_action {
    /// Allow action
    pub const ALLOW: u32 = 0;
    /// Prompt before action
    pub const PROMPT: u32 = 1;
    /// Disable action
    pub const DISALLOW: u32 = 3;
}

// ============================================================================
// Types
// ============================================================================

/// Security zone settings
#[derive(Clone, Copy)]
pub struct ZoneSettings {
    /// Zone ID
    pub zone_id: u32,
    /// Zone name
    pub name: [u8; 64],
    /// Name length
    pub name_len: u8,
    /// Security level
    pub level: u32,
    /// Custom settings enabled
    pub custom: bool,
    /// Run ActiveX controls
    pub activex_run: u32,
    /// Download signed ActiveX
    pub activex_download_signed: u32,
    /// Download unsigned ActiveX
    pub activex_download_unsigned: u32,
    /// Script ActiveX controls
    pub activex_script: u32,
    /// Active scripting
    pub scripting: u32,
    /// Java permissions
    pub java: u32,
    /// File download
    pub download: u32,
    /// Font download
    pub font_download: u32,
    /// Submit non-encrypted form data
    pub submit_nonencrypted: u32,
    /// Userdata persistence
    pub userdata_persistence: u32,
    /// Software channel permissions
    pub software_channel: u32,
}

impl ZoneSettings {
    pub const fn new() -> Self {
        Self {
            zone_id: 0,
            name: [0; 64],
            name_len: 0,
            level: security_level::MEDIUM,
            custom: false,
            activex_run: url_action::PROMPT,
            activex_download_signed: url_action::PROMPT,
            activex_download_unsigned: url_action::DISALLOW,
            activex_script: url_action::ALLOW,
            scripting: url_action::ALLOW,
            java: url_action::ALLOW,
            download: url_action::ALLOW,
            font_download: url_action::ALLOW,
            submit_nonencrypted: url_action::ALLOW,
            userdata_persistence: url_action::ALLOW,
            software_channel: url_action::PROMPT,
        }
    }
}

/// Zone site entry
#[derive(Clone, Copy)]
pub struct ZoneSite {
    /// Site URL pattern
    pub url: [u8; MAX_SITE_URL],
    /// URL length
    pub url_len: u16,
    /// Require HTTPS
    pub require_https: bool,
}

impl ZoneSite {
    pub const fn new() -> Self {
        Self {
            url: [0; MAX_SITE_URL],
            url_len: 0,
            require_https: false,
        }
    }
}

/// Proxy settings
#[derive(Clone, Copy)]
pub struct ProxySettings {
    /// Connection type
    pub connection_type: u32,
    /// HTTP proxy server
    pub http_proxy: [u8; MAX_PROXY],
    /// HTTP proxy length
    pub http_proxy_len: u8,
    /// HTTP proxy port
    pub http_port: u16,
    /// HTTPS proxy server
    pub https_proxy: [u8; MAX_PROXY],
    /// HTTPS proxy length
    pub https_proxy_len: u8,
    /// HTTPS proxy port
    pub https_port: u16,
    /// FTP proxy server
    pub ftp_proxy: [u8; MAX_PROXY],
    /// FTP proxy length
    pub ftp_proxy_len: u8,
    /// FTP proxy port
    pub ftp_port: u16,
    /// SOCKS proxy server
    pub socks_proxy: [u8; MAX_PROXY],
    /// SOCKS proxy length
    pub socks_proxy_len: u8,
    /// SOCKS proxy port
    pub socks_port: u16,
    /// Use same proxy for all protocols
    pub use_same_proxy: bool,
    /// Bypass proxy for local addresses
    pub bypass_local: bool,
    /// Bypass proxy list
    pub bypass_list: [u8; MAX_PROXY],
    /// Bypass list length
    pub bypass_list_len: u8,
    /// Auto config URL
    pub auto_config_url: [u8; MAX_URL],
    /// Auto config URL length
    pub auto_config_len: u16,
}

impl ProxySettings {
    pub const fn new() -> Self {
        Self {
            connection_type: connection_type::DIRECT,
            http_proxy: [0; MAX_PROXY],
            http_proxy_len: 0,
            http_port: 80,
            https_proxy: [0; MAX_PROXY],
            https_proxy_len: 0,
            https_port: 443,
            ftp_proxy: [0; MAX_PROXY],
            ftp_proxy_len: 0,
            ftp_port: 21,
            socks_proxy: [0; MAX_PROXY],
            socks_proxy_len: 0,
            socks_port: 1080,
            use_same_proxy: true,
            bypass_local: true,
            bypass_list: [0; MAX_PROXY],
            bypass_list_len: 0,
            auto_config_url: [0; MAX_URL],
            auto_config_len: 0,
        }
    }
}

/// Privacy settings
#[derive(Clone, Copy)]
pub struct PrivacySettings {
    /// Privacy level
    pub level: u32,
    /// Block third-party cookies
    pub block_third_party: bool,
    /// Block all cookies
    pub block_all: bool,
    /// Override cookie handling
    pub override_handling: bool,
    /// First party cookie action
    pub first_party: u32, // 0=accept, 1=block, 2=prompt
    /// Third party cookie action
    pub third_party: u32,
    /// Always allow session cookies
    pub allow_session: bool,
    /// Pop-up blocker enabled
    pub popup_blocker: bool,
    /// Pop-up blocker level
    pub popup_level: u32, // 0=all, 1=most, 2=low
}

impl PrivacySettings {
    pub const fn new() -> Self {
        Self {
            level: privacy_level::MEDIUM,
            block_third_party: false,
            block_all: false,
            override_handling: false,
            first_party: 0,
            third_party: 0,
            allow_session: true,
            popup_blocker: true,
            popup_level: 1,
        }
    }
}

/// Content settings
#[derive(Clone, Copy)]
pub struct ContentSettings {
    /// Content Advisor enabled
    pub content_advisor: bool,
    /// AutoComplete for forms
    pub autocomplete_forms: bool,
    /// AutoComplete for passwords
    pub autocomplete_passwords: bool,
    /// Prompt to save passwords
    pub prompt_passwords: bool,
    /// Enable InPrivate browsing
    pub inprivate_enabled: bool,
    /// Feeds enabled
    pub feeds_enabled: bool,
    /// Feed update interval (minutes)
    pub feed_interval: u32,
}

impl ContentSettings {
    pub const fn new() -> Self {
        Self {
            content_advisor: false,
            autocomplete_forms: true,
            autocomplete_passwords: false,
            prompt_passwords: true,
            inprivate_enabled: true,
            feeds_enabled: true,
            feed_interval: 60,
        }
    }
}

/// Advanced settings
#[derive(Clone, Copy)]
pub struct AdvancedSettings {
    /// Enable visual styles
    pub visual_styles: bool,
    /// Smooth scrolling
    pub smooth_scrolling: bool,
    /// Show pictures
    pub show_pictures: bool,
    /// Play animations
    pub play_animations: bool,
    /// Play videos
    pub play_videos: bool,
    /// Play sounds
    pub play_sounds: bool,
    /// Enable page transitions
    pub page_transitions: bool,
    /// Check for publisher certificate revocation
    pub check_revocation: bool,
    /// Check for server certificate revocation
    pub check_server_revocation: bool,
    /// Use SSL 2.0
    pub ssl2: bool,
    /// Use SSL 3.0
    pub ssl3: bool,
    /// Use TLS 1.0
    pub tls10: bool,
    /// Use TLS 1.1
    pub tls11: bool,
    /// Use TLS 1.2
    pub tls12: bool,
    /// Warn about invalid certificates
    pub warn_invalid_cert: bool,
    /// Warn about certificate mismatch
    pub warn_cert_mismatch: bool,
    /// Enable native XMLHTTP support
    pub native_xmlhttp: bool,
}

impl AdvancedSettings {
    pub const fn new() -> Self {
        Self {
            visual_styles: true,
            smooth_scrolling: true,
            show_pictures: true,
            play_animations: true,
            play_videos: true,
            play_sounds: true,
            page_transitions: true,
            check_revocation: true,
            check_server_revocation: false,
            ssl2: false,
            ssl3: false,
            tls10: true,
            tls11: true,
            tls12: true,
            warn_invalid_cert: true,
            warn_cert_mismatch: true,
            native_xmlhttp: true,
        }
    }
}

/// Internet options state
pub struct InternetOptions {
    /// Home page URL
    pub home_page: [u8; MAX_URL],
    /// Home page length
    pub home_page_len: u16,
    /// Use blank home page
    pub use_blank: bool,
    /// Use default home page
    pub use_default: bool,
    /// Temporary files folder size (MB)
    pub temp_size_mb: u32,
    /// History days to keep
    pub history_days: u32,
    /// Delete browsing history on exit
    pub delete_on_exit: bool,
    /// Proxy settings
    pub proxy: ProxySettings,
    /// Privacy settings
    pub privacy: PrivacySettings,
    /// Content settings
    pub content: ContentSettings,
    /// Advanced settings
    pub advanced: AdvancedSettings,
}

impl InternetOptions {
    pub const fn new() -> Self {
        Self {
            home_page: [0; MAX_URL],
            home_page_len: 0,
            use_blank: false,
            use_default: true,
            temp_size_mb: 250,
            history_days: 20,
            delete_on_exit: false,
            proxy: ProxySettings::new(),
            privacy: PrivacySettings::new(),
            content: ContentSettings::new(),
            advanced: AdvancedSettings::new(),
        }
    }
}

/// Internet options dialog state
struct InternetDialog {
    /// Parent window
    parent: HWND,
    /// Current page
    current_page: u32,
    /// Modified flag
    modified: bool,
}

impl InternetDialog {
    const fn new() -> Self {
        Self {
            parent: UserHandle::NULL,
            current_page: 0,
            modified: false,
        }
    }
}

// ============================================================================
// Static State
// ============================================================================

/// Module initialized
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Global internet options
static OPTIONS: SpinLock<InternetOptions> = SpinLock::new(InternetOptions::new());

/// Security zones
static ZONES: SpinLock<[ZoneSettings; MAX_ZONES]> =
    SpinLock::new([const { ZoneSettings::new() }; MAX_ZONES]);

/// Zone site lists
static ZONE_SITES: SpinLock<[[ZoneSite; MAX_ZONE_SITES]; MAX_ZONES]> =
    SpinLock::new([[const { ZoneSite::new() }; MAX_ZONE_SITES]; MAX_ZONES]);

/// Zone site counts
static ZONE_SITE_COUNTS: [AtomicU32; MAX_ZONES] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];

/// Dialog state
static DIALOG: SpinLock<InternetDialog> = SpinLock::new(InternetDialog::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize internet options
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Initialize security zones
    init_security_zones();

    // Set default home page
    init_default_options();

    crate::serial_println!("[INETCPL] Internet options initialized");
}

/// Initialize security zones
fn init_security_zones() {
    let mut zones = ZONES.lock();

    // Local Machine zone
    {
        let z = &mut zones[zone::LOCAL_MACHINE as usize];
        z.zone_id = zone::LOCAL_MACHINE;
        let name = b"My Computer";
        let len = name.len();
        z.name[..len].copy_from_slice(name);
        z.name_len = len as u8;
        z.level = security_level::LOW;
    }

    // Local Intranet zone
    {
        let z = &mut zones[zone::INTRANET as usize];
        z.zone_id = zone::INTRANET;
        let name = b"Local intranet";
        let len = name.len();
        z.name[..len].copy_from_slice(name);
        z.name_len = len as u8;
        z.level = security_level::MEDIUM_LOW;
    }

    // Trusted Sites zone
    {
        let z = &mut zones[zone::TRUSTED as usize];
        z.zone_id = zone::TRUSTED;
        let name = b"Trusted sites";
        let len = name.len();
        z.name[..len].copy_from_slice(name);
        z.name_len = len as u8;
        z.level = security_level::MEDIUM;
    }

    // Internet zone
    {
        let z = &mut zones[zone::INTERNET as usize];
        z.zone_id = zone::INTERNET;
        let name = b"Internet";
        let len = name.len();
        z.name[..len].copy_from_slice(name);
        z.name_len = len as u8;
        z.level = security_level::MEDIUM_HIGH;
    }

    // Restricted Sites zone
    {
        let z = &mut zones[zone::RESTRICTED as usize];
        z.zone_id = zone::RESTRICTED;
        let name = b"Restricted sites";
        let len = name.len();
        z.name[..len].copy_from_slice(name);
        z.name_len = len as u8;
        z.level = security_level::HIGH;
        z.activex_run = url_action::DISALLOW;
        z.activex_download_signed = url_action::DISALLOW;
        z.scripting = url_action::DISALLOW;
        z.download = url_action::DISALLOW;
    }
}

/// Initialize default internet options
fn init_default_options() {
    let mut options = OPTIONS.lock();

    let home = b"about:blank";
    let len = home.len();
    options.home_page[..len].copy_from_slice(home);
    options.home_page_len = len as u16;
    options.use_blank = true;
}

// ============================================================================
// Home Page Settings
// ============================================================================

/// Get home page URL
pub fn get_home_page(buffer: &mut [u8]) -> usize {
    let options = OPTIONS.lock();
    let len = (options.home_page_len as usize).min(buffer.len());
    buffer[..len].copy_from_slice(&options.home_page[..len]);
    len
}

/// Set home page URL
pub fn set_home_page(url: &[u8]) {
    let mut options = OPTIONS.lock();
    let len = url.len().min(MAX_URL);
    options.home_page[..len].copy_from_slice(&url[..len]);
    options.home_page_len = len as u16;
    options.use_blank = false;
    options.use_default = false;
}

/// Set home page to blank
pub fn set_home_page_blank() {
    let mut options = OPTIONS.lock();
    let blank = b"about:blank";
    let len = blank.len();
    options.home_page[..len].copy_from_slice(blank);
    options.home_page_len = len as u16;
    options.use_blank = true;
    options.use_default = false;
}

/// Set home page to default
pub fn set_home_page_default() {
    let mut options = OPTIONS.lock();
    let default = b"http://www.microsoft.com/";
    let len = default.len();
    options.home_page[..len].copy_from_slice(default);
    options.home_page_len = len as u16;
    options.use_blank = false;
    options.use_default = true;
}

// ============================================================================
// Temporary Files and History
// ============================================================================

/// Get temporary files size limit in MB
pub fn get_temp_files_size() -> u32 {
    OPTIONS.lock().temp_size_mb
}

/// Set temporary files size limit
pub fn set_temp_files_size(size_mb: u32) {
    OPTIONS.lock().temp_size_mb = size_mb.clamp(8, 1024);
}

/// Get history days
pub fn get_history_days() -> u32 {
    OPTIONS.lock().history_days
}

/// Set history days
pub fn set_history_days(days: u32) {
    OPTIONS.lock().history_days = days.min(MAX_HISTORY_DAYS);
}

/// Get delete on exit setting
pub fn get_delete_on_exit() -> bool {
    OPTIONS.lock().delete_on_exit
}

/// Set delete on exit setting
pub fn set_delete_on_exit(delete: bool) {
    OPTIONS.lock().delete_on_exit = delete;
}

/// Delete temporary internet files
pub fn delete_temp_files() -> u32 {
    // Would delete files from %USERPROFILE%\Local Settings\Temporary Internet Files
    0
}

/// Delete browsing history
pub fn delete_history() -> u32 {
    // Would delete history from registry and history files
    0
}

/// Delete cookies
pub fn delete_cookies() -> u32 {
    // Would delete cookies from cookie jar
    0
}

// ============================================================================
// Security Zones
// ============================================================================

/// Get security zone settings
pub fn get_zone_settings(zone_id: u32, settings: &mut ZoneSettings) -> bool {
    if zone_id as usize >= MAX_ZONES {
        return false;
    }

    *settings = ZONES.lock()[zone_id as usize];
    true
}

/// Set security zone settings
pub fn set_zone_settings(zone_id: u32, settings: &ZoneSettings) -> bool {
    if zone_id as usize >= MAX_ZONES {
        return false;
    }

    ZONES.lock()[zone_id as usize] = *settings;
    true
}

/// Get zone for a URL
pub fn get_zone_for_url(url: &[u8]) -> u32 {
    // Check if URL matches any zone sites
    for zone_id in [zone::TRUSTED, zone::RESTRICTED, zone::INTRANET] {
        let sites = ZONE_SITES.lock();
        let count = ZONE_SITE_COUNTS[zone_id as usize].load(Ordering::Acquire) as usize;

        for i in 0..count {
            let site = &sites[zone_id as usize][i];
            let site_len = site.url_len as usize;
            if url_matches_pattern(url, &site.url[..site_len]) {
                return zone_id;
            }
        }
    }

    // Check for local intranet patterns
    if is_intranet_url(url) {
        return zone::INTRANET;
    }

    // Default to Internet zone
    zone::INTERNET
}

/// Check if URL matches a pattern
fn url_matches_pattern(url: &[u8], pattern: &[u8]) -> bool {
    // Simple wildcard matching
    if pattern.is_empty() {
        return false;
    }

    if pattern.starts_with(b"*.") {
        // Domain wildcard
        let domain = &pattern[2..];
        if url.len() > domain.len() {
            let url_end = &url[url.len() - domain.len()..];
            return url_end == domain;
        }
    }

    url.starts_with(pattern)
}

/// Check if URL is an intranet URL
fn is_intranet_url(url: &[u8]) -> bool {
    // Check for single-word hostname (no dots)
    // Or local network addresses
    let has_dots = url.iter().any(|&c| c == b'.');
    !has_dots
}

/// Add site to a zone
pub fn add_zone_site(zone_id: u32, url: &[u8], require_https: bool) -> bool {
    if zone_id as usize >= MAX_ZONES {
        return false;
    }

    let count = ZONE_SITE_COUNTS[zone_id as usize].load(Ordering::Acquire) as usize;
    if count >= MAX_ZONE_SITES {
        return false;
    }

    let mut sites = ZONE_SITES.lock();
    let site = &mut sites[zone_id as usize][count];

    let len = url.len().min(MAX_SITE_URL);
    site.url[..len].copy_from_slice(&url[..len]);
    site.url_len = len as u16;
    site.require_https = require_https;

    ZONE_SITE_COUNTS[zone_id as usize].store((count + 1) as u32, Ordering::Release);

    true
}

/// Remove site from a zone
pub fn remove_zone_site(zone_id: u32, url: &[u8]) -> bool {
    if zone_id as usize >= MAX_ZONES {
        return false;
    }

    let count = ZONE_SITE_COUNTS[zone_id as usize].load(Ordering::Acquire) as usize;
    let mut sites = ZONE_SITES.lock();

    for i in 0..count {
        let site = &sites[zone_id as usize][i];
        let len = site.url_len as usize;
        if &site.url[..len] == url {
            // Shift remaining sites
            for j in i..(count - 1) {
                sites[zone_id as usize][j] = sites[zone_id as usize][j + 1];
            }
            sites[zone_id as usize][count - 1] = ZoneSite::new();
            ZONE_SITE_COUNTS[zone_id as usize].store((count - 1) as u32, Ordering::Release);
            return true;
        }
    }

    false
}

// ============================================================================
// Proxy Settings
// ============================================================================

/// Get proxy settings
pub fn get_proxy_settings(settings: &mut ProxySettings) {
    *settings = OPTIONS.lock().proxy;
}

/// Set proxy settings
pub fn set_proxy_settings(settings: &ProxySettings) {
    OPTIONS.lock().proxy = *settings;
}

/// Get connection type
pub fn get_connection_type() -> u32 {
    OPTIONS.lock().proxy.connection_type
}

/// Set connection type
pub fn set_connection_type(conn_type: u32) {
    OPTIONS.lock().proxy.connection_type = conn_type;
}

// ============================================================================
// Privacy Settings
// ============================================================================

/// Get privacy settings
pub fn get_privacy_settings(settings: &mut PrivacySettings) {
    *settings = OPTIONS.lock().privacy;
}

/// Set privacy settings
pub fn set_privacy_settings(settings: &PrivacySettings) {
    OPTIONS.lock().privacy = *settings;
}

/// Get privacy level
pub fn get_privacy_level() -> u32 {
    OPTIONS.lock().privacy.level
}

/// Set privacy level
pub fn set_privacy_level(level: u32) {
    OPTIONS.lock().privacy.level = level;
}

/// Get popup blocker state
pub fn get_popup_blocker() -> bool {
    OPTIONS.lock().privacy.popup_blocker
}

/// Set popup blocker state
pub fn set_popup_blocker(enabled: bool) {
    OPTIONS.lock().privacy.popup_blocker = enabled;
}

// ============================================================================
// Content Settings
// ============================================================================

/// Get content settings
pub fn get_content_settings(settings: &mut ContentSettings) {
    *settings = OPTIONS.lock().content;
}

/// Set content settings
pub fn set_content_settings(settings: &ContentSettings) {
    OPTIONS.lock().content = *settings;
}

/// Get AutoComplete settings
pub fn get_autocomplete() -> (bool, bool) {
    let options = OPTIONS.lock();
    (options.content.autocomplete_forms, options.content.autocomplete_passwords)
}

/// Set AutoComplete settings
pub fn set_autocomplete(forms: bool, passwords: bool) {
    let mut options = OPTIONS.lock();
    options.content.autocomplete_forms = forms;
    options.content.autocomplete_passwords = passwords;
}

// ============================================================================
// Advanced Settings
// ============================================================================

/// Get advanced settings
pub fn get_advanced_settings(settings: &mut AdvancedSettings) {
    *settings = OPTIONS.lock().advanced;
}

/// Set advanced settings
pub fn set_advanced_settings(settings: &AdvancedSettings) {
    OPTIONS.lock().advanced = *settings;
}

/// Reset advanced settings to defaults
pub fn reset_advanced_settings() {
    OPTIONS.lock().advanced = AdvancedSettings::new();
}

// ============================================================================
// Dialog API
// ============================================================================

/// Show Internet Options dialog
pub fn show_internet_options(parent: HWND) -> bool {
    let mut dialog = DIALOG.lock();

    dialog.parent = parent;
    dialog.current_page = 0;
    dialog.modified = false;

    // Would create property sheet with tabs:
    // - General (home page, temp files, history)
    // - Security (zones, levels)
    // - Privacy (cookies, popups)
    // - Content (certificates, autocomplete)
    // - Connections (proxy, dial-up)
    // - Programs (default programs)
    // - Advanced (all other settings)

    true
}

/// Apply internet options
pub fn apply_options() -> bool {
    // Settings are applied in real-time
    true
}

/// Reset all options to defaults
pub fn reset_all_options() {
    let mut options = OPTIONS.lock();
    *options = InternetOptions::new();
    init_default_options_internal(&mut options);
    drop(options);

    init_security_zones();
}

/// Internal default options initialization
fn init_default_options_internal(options: &mut InternetOptions) {
    let home = b"about:blank";
    let len = home.len();
    options.home_page[..len].copy_from_slice(home);
    options.home_page_len = len as u16;
    options.use_blank = true;
}
