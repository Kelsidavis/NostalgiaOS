//! System Information UI
//!
//! Implements Windows system information display and About dialogs.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/shell32/about.c` - About dialog
//! - `shell/shell32/sysinfo.c` - System information

use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, Ordering};
use super::HWND;

// ============================================================================
// Constants
// ============================================================================

/// Maximum string length
const MAX_STRING: usize = 256;

/// Maximum owner name length
const MAX_OWNER_NAME: usize = 256;

/// Maximum organization name length
const MAX_ORG_NAME: usize = 256;

/// Maximum product ID length
const MAX_PRODUCT_ID: usize = 64;

// ============================================================================
// System Version Information
// ============================================================================

/// Operating system version info
#[derive(Debug, Clone, Copy)]
pub struct OsVersionInfo {
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub platform_id: u32,
    pub csd_version: [u8; 128],
    pub service_pack_major: u16,
    pub service_pack_minor: u16,
    pub suite_mask: u16,
    pub product_type: u8,
}

impl OsVersionInfo {
    pub const fn new() -> Self {
        Self {
            major_version: 5,
            minor_version: 2,
            build_number: 3790,
            platform_id: 2, // VER_PLATFORM_WIN32_NT
            csd_version: [0u8; 128],
            service_pack_major: 2,
            service_pack_minor: 0,
            suite_mask: 0,
            product_type: 3, // VER_NT_SERVER
        }
    }
}

impl Default for OsVersionInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Platform IDs
pub mod platform {
    pub const VER_PLATFORM_WIN32S: u32 = 0;
    pub const VER_PLATFORM_WIN32_WINDOWS: u32 = 1;
    pub const VER_PLATFORM_WIN32_NT: u32 = 2;
}

/// Product types
pub mod product_type {
    pub const VER_NT_WORKSTATION: u8 = 1;
    pub const VER_NT_DOMAIN_CONTROLLER: u8 = 2;
    pub const VER_NT_SERVER: u8 = 3;
}

/// Suite masks
pub mod suite {
    pub const VER_SUITE_SMALLBUSINESS: u16 = 0x0001;
    pub const VER_SUITE_ENTERPRISE: u16 = 0x0002;
    pub const VER_SUITE_BACKOFFICE: u16 = 0x0004;
    pub const VER_SUITE_COMMUNICATIONS: u16 = 0x0008;
    pub const VER_SUITE_TERMINAL: u16 = 0x0010;
    pub const VER_SUITE_SMALLBUSINESS_RESTRICTED: u16 = 0x0020;
    pub const VER_SUITE_EMBEDDEDNT: u16 = 0x0040;
    pub const VER_SUITE_DATACENTER: u16 = 0x0080;
    pub const VER_SUITE_SINGLEUSERTS: u16 = 0x0100;
    pub const VER_SUITE_PERSONAL: u16 = 0x0200;
    pub const VER_SUITE_BLADE: u16 = 0x0400;
    pub const VER_SUITE_EMBEDDED_RESTRICTED: u16 = 0x0800;
    pub const VER_SUITE_SECURITY_APPLIANCE: u16 = 0x1000;
    pub const VER_SUITE_STORAGE_SERVER: u16 = 0x2000;
    pub const VER_SUITE_COMPUTE_SERVER: u16 = 0x4000;
}

// ============================================================================
// System Metrics
// ============================================================================

/// System info type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemInfoType {
    ProcessorArchitecture = 0,
    ProcessorType = 1,
    ProcessorLevel = 2,
    ProcessorRevision = 3,
    NumberOfProcessors = 4,
    PageSize = 5,
    AllocationGranularity = 6,
    MinimumApplicationAddress = 7,
    MaximumApplicationAddress = 8,
    ActiveProcessorMask = 9,
}

/// Processor architecture
pub mod processor_arch {
    pub const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;
    pub const PROCESSOR_ARCHITECTURE_MIPS: u16 = 1;
    pub const PROCESSOR_ARCHITECTURE_ALPHA: u16 = 2;
    pub const PROCESSOR_ARCHITECTURE_PPC: u16 = 3;
    pub const PROCESSOR_ARCHITECTURE_SHX: u16 = 4;
    pub const PROCESSOR_ARCHITECTURE_ARM: u16 = 5;
    pub const PROCESSOR_ARCHITECTURE_IA64: u16 = 6;
    pub const PROCESSOR_ARCHITECTURE_ALPHA64: u16 = 7;
    pub const PROCESSOR_ARCHITECTURE_MSIL: u16 = 8;
    pub const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
    pub const PROCESSOR_ARCHITECTURE_IA32_ON_WIN64: u16 = 10;
    pub const PROCESSOR_ARCHITECTURE_ARM64: u16 = 12;
    pub const PROCESSOR_ARCHITECTURE_UNKNOWN: u16 = 0xFFFF;
}

/// System information structure
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemInfo {
    pub processor_architecture: u16,
    pub reserved: u16,
    pub page_size: u32,
    pub minimum_application_address: usize,
    pub maximum_application_address: usize,
    pub active_processor_mask: usize,
    pub number_of_processors: u32,
    pub processor_type: u32,
    pub allocation_granularity: u32,
    pub processor_level: u16,
    pub processor_revision: u16,
}

impl SystemInfo {
    pub fn new() -> Self {
        Self {
            processor_architecture: processor_arch::PROCESSOR_ARCHITECTURE_AMD64,
            reserved: 0,
            page_size: 4096,
            minimum_application_address: 0x10000,
            maximum_application_address: 0x7FFFFFFFFFFF,
            active_processor_mask: 1,
            number_of_processors: 1,
            processor_type: 8664, // AMD64
            allocation_granularity: 65536,
            processor_level: 6,
            processor_revision: 0,
        }
    }
}

// ============================================================================
// Registration Info
// ============================================================================

/// Registration information
#[derive(Debug)]
struct RegistrationInfo {
    registered_owner: [u8; MAX_OWNER_NAME],
    registered_org: [u8; MAX_ORG_NAME],
    product_id: [u8; MAX_PRODUCT_ID],
}

impl RegistrationInfo {
    const fn new() -> Self {
        Self {
            registered_owner: [0u8; MAX_OWNER_NAME],
            registered_org: [0u8; MAX_ORG_NAME],
            product_id: [0u8; MAX_PRODUCT_ID],
        }
    }
}

// ============================================================================
// State
// ============================================================================

static SYSINFO_INITIALIZED: AtomicBool = AtomicBool::new(false);
static OS_VERSION: SpinLock<OsVersionInfo> = SpinLock::new(OsVersionInfo::new());
static SYSTEM_INFO: SpinLock<SystemInfo> = SpinLock::new(SystemInfo {
    processor_architecture: processor_arch::PROCESSOR_ARCHITECTURE_AMD64,
    reserved: 0,
    page_size: 4096,
    minimum_application_address: 0x10000,
    maximum_application_address: 0x7FFFFFFFFFFF,
    active_processor_mask: 1,
    number_of_processors: 1,
    processor_type: 8664,
    allocation_granularity: 65536,
    processor_level: 6,
    processor_revision: 0,
});
static REGISTRATION: SpinLock<RegistrationInfo> = SpinLock::new(RegistrationInfo::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize system information subsystem
pub fn init() {
    if SYSINFO_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[SYSINFO] Initializing system information...");

    // Set default registration info
    {
        let mut reg = REGISTRATION.lock();
        let owner = b"User";
        reg.registered_owner[..owner.len()].copy_from_slice(owner);

        let org = b"Organization";
        reg.registered_org[..org.len()].copy_from_slice(org);

        let product_id = b"00000-000-0000000-00000";
        reg.product_id[..product_id.len()].copy_from_slice(product_id);
    }

    // Set CSD version string
    {
        let mut ver = OS_VERSION.lock();
        let sp = b"Service Pack 2";
        ver.csd_version[..sp.len()].copy_from_slice(sp);
    }

    crate::serial_println!("[SYSINFO] System information initialized");
}

// ============================================================================
// Version Functions
// ============================================================================

/// Get OS version information
pub fn get_version_ex(info: &mut OsVersionInfo) -> bool {
    let ver = OS_VERSION.lock();
    *info = *ver;
    true
}

/// Get version numbers only
pub fn get_version() -> u32 {
    let ver = OS_VERSION.lock();
    ((ver.major_version & 0xFF) | ((ver.minor_version & 0xFF) << 8) |
     ((ver.build_number & 0xFFFF) << 16)) as u32
}

/// Verify version info
pub fn verify_version_info(
    info: &OsVersionInfo,
    type_mask: u32,
    condition_mask: u64,
) -> bool {
    let ver = OS_VERSION.lock();
    let _ = (type_mask, condition_mask);

    // Simplified version check
    ver.major_version >= info.major_version &&
    ver.minor_version >= info.minor_version
}

// ============================================================================
// System Info Functions
// ============================================================================

/// Get system information
pub fn get_system_info(info: &mut SystemInfo) {
    let sys = SYSTEM_INFO.lock();
    *info = *sys;
}

/// Get native system information (for WoW64)
pub fn get_native_system_info(info: &mut SystemInfo) {
    get_system_info(info);
}

/// Check if running under WoW64
pub fn is_wow64_process() -> bool {
    false // Native 64-bit
}

// ============================================================================
// Computer Name Functions
// ============================================================================

/// Computer name format
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ComputerNameFormat {
    #[default]
    NetBIOS = 0,
    DnsHostname = 1,
    DnsDomain = 2,
    DnsFullyQualified = 3,
    PhysicalNetBIOS = 4,
    PhysicalDnsHostname = 5,
    PhysicalDnsDomain = 6,
    PhysicalDnsFullyQualified = 7,
}

static COMPUTER_NAME: SpinLock<[u8; 256]> = SpinLock::new([0u8; 256]);

/// Get computer name
pub fn get_computer_name(buffer: &mut [u8]) -> Option<usize> {
    let name = COMPUTER_NAME.lock();
    let len = str_len(&*name);

    if len == 0 {
        let default = b"NOSTALGIAOS";
        let copy_len = default.len().min(buffer.len() - 1);
        buffer[..copy_len].copy_from_slice(&default[..copy_len]);
        buffer[copy_len] = 0;
        return Some(copy_len);
    }

    let copy_len = len.min(buffer.len() - 1);
    buffer[..copy_len].copy_from_slice(&name[..copy_len]);
    buffer[copy_len] = 0;
    Some(copy_len)
}

/// Get computer name (extended)
pub fn get_computer_name_ex(format: ComputerNameFormat, buffer: &mut [u8]) -> Option<usize> {
    match format {
        ComputerNameFormat::NetBIOS |
        ComputerNameFormat::PhysicalNetBIOS => {
            get_computer_name(buffer)
        }
        ComputerNameFormat::DnsHostname |
        ComputerNameFormat::PhysicalDnsHostname => {
            let mut name = [0u8; 256];
            if let Some(len) = get_computer_name(&mut name) {
                let copy_len = len.min(buffer.len() - 1);
                buffer[..copy_len].copy_from_slice(&name[..copy_len]);
                buffer[copy_len] = 0;
                Some(copy_len)
            } else {
                None
            }
        }
        ComputerNameFormat::DnsDomain |
        ComputerNameFormat::PhysicalDnsDomain => {
            let domain = b"localdomain";
            let copy_len = domain.len().min(buffer.len() - 1);
            buffer[..copy_len].copy_from_slice(&domain[..copy_len]);
            buffer[copy_len] = 0;
            Some(copy_len)
        }
        ComputerNameFormat::DnsFullyQualified |
        ComputerNameFormat::PhysicalDnsFullyQualified => {
            let mut hostname = [0u8; 128];
            if let Some(host_len) = get_computer_name(&mut hostname) {
                let domain = b".localdomain";
                let total = host_len + domain.len();

                if total >= buffer.len() {
                    return None;
                }

                buffer[..host_len].copy_from_slice(&hostname[..host_len]);
                buffer[host_len..host_len + domain.len()].copy_from_slice(domain);
                buffer[total] = 0;
                Some(total)
            } else {
                None
            }
        }
    }
}

/// Set computer name
pub fn set_computer_name(name: &[u8]) -> bool {
    let mut computer_name = COMPUTER_NAME.lock();
    let len = str_len(name).min(255);
    computer_name[..len].copy_from_slice(&name[..len]);
    computer_name[len] = 0;
    true
}

// ============================================================================
// User Name Functions
// ============================================================================

static USER_NAME: SpinLock<[u8; 256]> = SpinLock::new([0u8; 256]);

/// Get user name
pub fn get_user_name(buffer: &mut [u8]) -> Option<usize> {
    let name = USER_NAME.lock();
    let len = str_len(&*name);

    if len == 0 {
        let default = b"User";
        let copy_len = default.len().min(buffer.len() - 1);
        buffer[..copy_len].copy_from_slice(&default[..copy_len]);
        buffer[copy_len] = 0;
        return Some(copy_len);
    }

    let copy_len = len.min(buffer.len() - 1);
    buffer[..copy_len].copy_from_slice(&name[..copy_len]);
    buffer[copy_len] = 0;
    Some(copy_len)
}

/// Name format for GetUserNameEx
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExtendedNameFormat {
    #[default]
    Unknown = 0,
    FullyQualifiedDN = 1,
    SamCompatible = 2,
    Display = 3,
    UniqueId = 6,
    Canonical = 7,
    UserPrincipal = 8,
    CanonicalEx = 9,
    ServicePrincipal = 10,
    DnsDomain = 12,
}

/// Get user name (extended)
pub fn get_user_name_ex(format: ExtendedNameFormat, buffer: &mut [u8]) -> Option<usize> {
    match format {
        ExtendedNameFormat::SamCompatible => {
            // DOMAIN\User format
            let mut user = [0u8; 128];
            if let Some(user_len) = get_user_name(&mut user) {
                let prefix = b"NOSTALGIAOS\\";
                let total = prefix.len() + user_len;

                if total >= buffer.len() {
                    return None;
                }

                buffer[..prefix.len()].copy_from_slice(prefix);
                buffer[prefix.len()..total].copy_from_slice(&user[..user_len]);
                buffer[total] = 0;
                Some(total)
            } else {
                None
            }
        }
        ExtendedNameFormat::Display => {
            get_user_name(buffer)
        }
        ExtendedNameFormat::UserPrincipal => {
            // user@domain format
            let mut user = [0u8; 128];
            if let Some(user_len) = get_user_name(&mut user) {
                let suffix = b"@nostalgiaos.local";
                let total = user_len + suffix.len();

                if total >= buffer.len() {
                    return None;
                }

                buffer[..user_len].copy_from_slice(&user[..user_len]);
                buffer[user_len..total].copy_from_slice(suffix);
                buffer[total] = 0;
                Some(total)
            } else {
                None
            }
        }
        _ => get_user_name(buffer),
    }
}

// ============================================================================
// Registration Functions
// ============================================================================

/// Get registered owner
pub fn get_registered_owner(buffer: &mut [u8]) -> Option<usize> {
    let reg = REGISTRATION.lock();
    let len = str_len(&reg.registered_owner);
    let copy_len = len.min(buffer.len() - 1);
    buffer[..copy_len].copy_from_slice(&reg.registered_owner[..copy_len]);
    buffer[copy_len] = 0;
    Some(copy_len)
}

/// Get registered organization
pub fn get_registered_organization(buffer: &mut [u8]) -> Option<usize> {
    let reg = REGISTRATION.lock();
    let len = str_len(&reg.registered_org);
    let copy_len = len.min(buffer.len() - 1);
    buffer[..copy_len].copy_from_slice(&reg.registered_org[..copy_len]);
    buffer[copy_len] = 0;
    Some(copy_len)
}

/// Get product ID
pub fn get_product_id(buffer: &mut [u8]) -> Option<usize> {
    let reg = REGISTRATION.lock();
    let len = str_len(&reg.product_id);
    let copy_len = len.min(buffer.len() - 1);
    buffer[..copy_len].copy_from_slice(&reg.product_id[..copy_len]);
    buffer[copy_len] = 0;
    Some(copy_len)
}

// ============================================================================
// About Dialog
// ============================================================================

/// Show shell about dialog
pub fn shell_about(
    hwnd: HWND,
    app_name: &[u8],
    other_info: Option<&[u8]>,
    icon: u32,
) -> bool {
    let _ = (hwnd, app_name, other_info, icon);

    crate::serial_println!("[SYSINFO] About dialog requested");

    // Would display About Windows dialog
    true
}

/// Get Windows directory for about dialog
pub fn get_windows_directory_for_about(buffer: &mut [u8]) -> Option<usize> {
    let path = b"C:\\Windows";
    let len = path.len().min(buffer.len() - 1);
    buffer[..len].copy_from_slice(&path[..len]);
    buffer[len] = 0;
    Some(len)
}

// ============================================================================
// System Metrics
// ============================================================================

/// Get global memory status
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryStatus {
    pub memory_load: u32,
    pub total_phys: u64,
    pub avail_phys: u64,
    pub total_page_file: u64,
    pub avail_page_file: u64,
    pub total_virtual: u64,
    pub avail_virtual: u64,
    pub avail_extended_virtual: u64,
}

/// Get memory status
pub fn global_memory_status(status: &mut MemoryStatus) {
    status.memory_load = 50;
    status.total_phys = 512 * 1024 * 1024; // 512 MB
    status.avail_phys = 256 * 1024 * 1024; // 256 MB
    status.total_page_file = 1024 * 1024 * 1024; // 1 GB
    status.avail_page_file = 512 * 1024 * 1024;
    status.total_virtual = 0x7FFF_FFFF_FFFF; // 128 TB
    status.avail_virtual = 0x7FFF_FFFF_0000;
    status.avail_extended_virtual = 0;
}

/// Get system time as file time
pub fn get_system_time_as_file_time() -> u64 {
    // Would return current system time
    0
}

/// Get tick count
pub fn get_tick_count() -> u32 {
    // Would return milliseconds since boot
    0
}

/// Get tick count 64
pub fn get_tick_count_64() -> u64 {
    0
}

// ============================================================================
// Helper Functions
// ============================================================================

fn str_len(s: &[u8]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

// ============================================================================
// Statistics
// ============================================================================

/// System info statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct SysInfoStats {
    pub initialized: bool,
}

/// Get system info statistics
pub fn get_stats() -> SysInfoStats {
    SysInfoStats {
        initialized: SYSINFO_INITIALIZED.load(Ordering::Relaxed),
    }
}
