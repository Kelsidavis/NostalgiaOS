//! RTL Version Information
//!
//! Provides OS version information and comparison utilities:
//! - OS version structure (major, minor, build, service pack)
//! - Version comparison with condition masks
//! - Product type and suite information
//!
//! Based on Windows Server 2003 base/ntos/rtl/version.c

use core::sync::atomic::{AtomicU32, Ordering};

/// OS version information (extended)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OsVersionInfoEx {
    /// Structure size
    pub size: u32,
    /// Major version number
    pub major_version: u32,
    /// Minor version number
    pub minor_version: u32,
    /// Build number
    pub build_number: u32,
    /// Platform ID (2 = VER_PLATFORM_WIN32_NT)
    pub platform_id: u32,
    /// CSD version string (service pack)
    pub csd_version: [u16; 128],
    /// Service pack major version
    pub service_pack_major: u16,
    /// Service pack minor version
    pub service_pack_minor: u16,
    /// Suite mask
    pub suite_mask: u16,
    /// Product type
    pub product_type: u8,
    /// Reserved
    pub reserved: u8,
}

impl OsVersionInfoEx {
    pub const fn new() -> Self {
        Self {
            size: core::mem::size_of::<OsVersionInfoEx>() as u32,
            major_version: 0,
            minor_version: 0,
            build_number: 0,
            platform_id: 0,
            csd_version: [0; 128],
            service_pack_major: 0,
            service_pack_minor: 0,
            suite_mask: 0,
            product_type: 0,
            reserved: 0,
        }
    }
}

/// Version comparison conditions
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionCondition {
    /// Equal
    Equal = 1,
    /// Greater than
    Greater = 2,
    /// Greater than or equal
    GreaterEqual = 3,
    /// Less than
    Less = 4,
    /// Less than or equal
    LessEqual = 5,
    /// AND condition
    And = 6,
    /// OR condition
    Or = 7,
}

impl TryFrom<u32> for VersionCondition {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Equal),
            2 => Ok(Self::Greater),
            3 => Ok(Self::GreaterEqual),
            4 => Ok(Self::Less),
            5 => Ok(Self::LessEqual),
            6 => Ok(Self::And),
            7 => Ok(Self::Or),
            _ => Err(()),
        }
    }
}

/// Version type masks
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionType {
    /// Minor version
    MinorVersion = 0x0000001,
    /// Major version
    MajorVersion = 0x0000002,
    /// Build number
    BuildNumber = 0x0000004,
    /// Platform ID
    PlatformId = 0x0000008,
    /// Service pack minor
    ServicePackMinor = 0x0000010,
    /// Service pack major
    ServicePackMajor = 0x0000020,
    /// Suite mask
    SuiteName = 0x0000040,
    /// Product type
    ProductType = 0x0000080,
}

/// Product types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductType {
    /// Workstation
    Workstation = 1,
    /// Domain controller
    DomainController = 2,
    /// Server
    Server = 3,
}

impl TryFrom<u8> for ProductType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Workstation),
            2 => Ok(Self::DomainController),
            3 => Ok(Self::Server),
            _ => Err(()),
        }
    }
}

/// Suite mask bits
pub mod suite {
    pub const SMALLBUSINESS: u16 = 0x0001;
    pub const ENTERPRISE: u16 = 0x0002;
    pub const BACKOFFICE: u16 = 0x0004;
    pub const COMMUNICATIONS: u16 = 0x0008;
    pub const TERMINAL: u16 = 0x0010;
    pub const SMALLBUSINESS_RESTRICTED: u16 = 0x0020;
    pub const EMBEDDED_NT: u16 = 0x0040;
    pub const DATACENTER: u16 = 0x0080;
    pub const SINGLEUSERTS: u16 = 0x0100;
    pub const PERSONAL: u16 = 0x0200;
    pub const BLADE: u16 = 0x0400;
    pub const EMBEDDED_RESTRICTED: u16 = 0x0800;
    pub const SECURITY_APPLIANCE: u16 = 0x1000;
    pub const STORAGE_SERVER: u16 = 0x2000;
    pub const COMPUTE_SERVER: u16 = 0x4000;
}

/// Platform IDs
pub mod platform {
    pub const WIN32S: u32 = 0;
    pub const WIN32_WINDOWS: u32 = 1;
    pub const WIN32_NT: u32 = 2;
}

// Global version information
static NT_MAJOR_VERSION: AtomicU32 = AtomicU32::new(5);
static NT_MINOR_VERSION: AtomicU32 = AtomicU32::new(2);
static NT_BUILD_NUMBER: AtomicU32 = AtomicU32::new(3790);
static NT_CSD_VERSION: AtomicU32 = AtomicU32::new(0); // Service pack
static NT_PRODUCT_TYPE: AtomicU32 = AtomicU32::new(3); // Server
static NT_SUITE_MASK: AtomicU32 = AtomicU32::new(0);

/// Initialize version subsystem
pub fn rtl_version_init() {
    // Set NostalgiaOS version info (emulating Windows Server 2003)
    NT_MAJOR_VERSION.store(5, Ordering::Relaxed);
    NT_MINOR_VERSION.store(2, Ordering::Relaxed);
    NT_BUILD_NUMBER.store(3790, Ordering::Relaxed);
    NT_PRODUCT_TYPE.store(ProductType::Server as u32, Ordering::Relaxed);

    crate::serial_println!("[RTL] Version subsystem initialized (Windows Server 2003 compatible)");
}

/// Get OS version information
pub fn rtl_get_version(info: &mut OsVersionInfoEx) -> i32 {
    info.major_version = NT_MAJOR_VERSION.load(Ordering::Relaxed);
    info.minor_version = NT_MINOR_VERSION.load(Ordering::Relaxed);
    info.build_number = NT_BUILD_NUMBER.load(Ordering::Relaxed) & 0x3FFF;
    info.platform_id = platform::WIN32_NT;

    let csd = NT_CSD_VERSION.load(Ordering::Relaxed);
    info.service_pack_major = ((csd >> 8) & 0xFF) as u16;
    info.service_pack_minor = (csd & 0xFF) as u16;

    info.suite_mask = NT_SUITE_MASK.load(Ordering::Relaxed) as u16;
    info.product_type = NT_PRODUCT_TYPE.load(Ordering::Relaxed) as u8;

    0 // STATUS_SUCCESS
}

/// Get NT product type
pub fn rtl_get_nt_product_type() -> Option<ProductType> {
    let pt = NT_PRODUCT_TYPE.load(Ordering::Relaxed) as u8;
    ProductType::try_from(pt).ok()
}

/// Compare two version values
fn ver_compare(condition: VersionCondition, value1: u32, value2: u32) -> (bool, bool) {
    let equal = value1 == value2;
    let result = match condition {
        VersionCondition::Equal => value2 == value1,
        VersionCondition::Greater => value2 > value1,
        VersionCondition::GreaterEqual => value2 >= value1,
        VersionCondition::Less => value2 < value1,
        VersionCondition::LessEqual => value2 <= value1,
        _ => false,
    };
    (result, equal)
}

/// Extract condition from mask (new style)
fn get_condition_mask(condition_mask: u64, type_mask: u32) -> u32 {
    let shift = match type_mask {
        0x01 => 0,  // MinorVersion
        0x02 => 3,  // MajorVersion
        0x04 => 6,  // BuildNumber
        0x08 => 9,  // PlatformId
        0x10 => 12, // ServicePackMinor
        0x20 => 15, // ServicePackMajor
        0x40 => 18, // SuiteName
        0x80 => 21, // ProductType
        _ => 0,
    };
    ((condition_mask >> shift) & 0x07) as u32
}

/// Set condition in mask
pub fn ver_set_condition_mask(mut condition_mask: u64, type_mask: u32, condition: VersionCondition) -> u64 {
    // Set the new style bit
    condition_mask |= 0x8000000000000000;

    let shift = match type_mask {
        0x01 => 0,  // MinorVersion
        0x02 => 3,  // MajorVersion
        0x04 => 6,  // BuildNumber
        0x08 => 9,  // PlatformId
        0x10 => 12, // ServicePackMinor
        0x20 => 15, // ServicePackMajor
        0x40 => 18, // SuiteName
        0x80 => 21, // ProductType
        _ => return condition_mask,
    };

    condition_mask |= (condition as u64) << shift;
    condition_mask
}

/// Verify version info against current OS version
pub fn rtl_verify_version_info(
    version_info: &OsVersionInfoEx,
    type_mask: u32,
    condition_mask: u64,
) -> i32 {
    let mut current = OsVersionInfoEx::new();
    rtl_get_version(&mut current);

    let mut matches = true;
    let use_or = condition_mask & 0x8000000000000000 != 0
        && get_condition_mask(condition_mask, VersionType::MinorVersion as u32) == VersionCondition::Or as u32;

    // Check major version
    if type_mask & VersionType::MajorVersion as u32 != 0 {
        let cond = get_condition_mask(condition_mask, VersionType::MajorVersion as u32);
        if let Ok(condition) = VersionCondition::try_from(cond) {
            let (result, _) = ver_compare(condition, version_info.major_version, current.major_version);
            if use_or {
                matches = matches || result;
            } else {
                matches = matches && result;
            }
        }
    }

    // Check minor version
    if type_mask & VersionType::MinorVersion as u32 != 0 {
        let cond = get_condition_mask(condition_mask, VersionType::MinorVersion as u32);
        if let Ok(condition) = VersionCondition::try_from(cond) {
            let (result, _) = ver_compare(condition, version_info.minor_version, current.minor_version);
            if use_or {
                matches = matches || result;
            } else {
                matches = matches && result;
            }
        }
    }

    // Check build number
    if type_mask & VersionType::BuildNumber as u32 != 0 {
        let cond = get_condition_mask(condition_mask, VersionType::BuildNumber as u32);
        if let Ok(condition) = VersionCondition::try_from(cond) {
            let (result, _) = ver_compare(condition, version_info.build_number, current.build_number);
            if use_or {
                matches = matches || result;
            } else {
                matches = matches && result;
            }
        }
    }

    // Check platform ID
    if type_mask & VersionType::PlatformId as u32 != 0 {
        let cond = get_condition_mask(condition_mask, VersionType::PlatformId as u32);
        if let Ok(condition) = VersionCondition::try_from(cond) {
            let (result, _) = ver_compare(condition, version_info.platform_id, current.platform_id);
            if use_or {
                matches = matches || result;
            } else {
                matches = matches && result;
            }
        }
    }

    // Check service pack major
    if type_mask & VersionType::ServicePackMajor as u32 != 0 {
        let cond = get_condition_mask(condition_mask, VersionType::ServicePackMajor as u32);
        if let Ok(condition) = VersionCondition::try_from(cond) {
            let (result, _) = ver_compare(condition, version_info.service_pack_major as u32, current.service_pack_major as u32);
            if use_or {
                matches = matches || result;
            } else {
                matches = matches && result;
            }
        }
    }

    // Check service pack minor
    if type_mask & VersionType::ServicePackMinor as u32 != 0 {
        let cond = get_condition_mask(condition_mask, VersionType::ServicePackMinor as u32);
        if let Ok(condition) = VersionCondition::try_from(cond) {
            let (result, _) = ver_compare(condition, version_info.service_pack_minor as u32, current.service_pack_minor as u32);
            if use_or {
                matches = matches || result;
            } else {
                matches = matches && result;
            }
        }
    }

    // Check product type
    if type_mask & VersionType::ProductType as u32 != 0 {
        let cond = get_condition_mask(condition_mask, VersionType::ProductType as u32);
        if let Ok(condition) = VersionCondition::try_from(cond) {
            let (result, _) = ver_compare(condition, version_info.product_type as u32, current.product_type as u32);
            if use_or {
                matches = matches || result;
            } else {
                matches = matches && result;
            }
        }
    }

    // Check suite mask
    if type_mask & VersionType::SuiteName as u32 != 0 {
        let cond = get_condition_mask(condition_mask, VersionType::SuiteName as u32);
        let result = match cond {
            6 => (current.suite_mask & version_info.suite_mask) == version_info.suite_mask, // AND
            7 => (current.suite_mask & version_info.suite_mask) != 0, // OR
            _ => current.suite_mask == version_info.suite_mask,
        };
        if use_or {
            matches = matches || result;
        } else {
            matches = matches && result;
        }
    }

    if matches {
        0 // STATUS_SUCCESS
    } else {
        -1073741790 // STATUS_REVISION_MISMATCH
    }
}

/// Get version string
pub fn rtl_get_version_string() -> &'static str {
    "NostalgiaOS 5.2 Build 3790 (Windows Server 2003 Compatible)"
}

/// Get major version
pub fn rtl_get_major_version() -> u32 {
    NT_MAJOR_VERSION.load(Ordering::Relaxed)
}

/// Get minor version
pub fn rtl_get_minor_version() -> u32 {
    NT_MINOR_VERSION.load(Ordering::Relaxed)
}

/// Get build number
pub fn rtl_get_build_number() -> u32 {
    NT_BUILD_NUMBER.load(Ordering::Relaxed) & 0x3FFF
}

/// Check if running on Windows NT platform
pub fn rtl_is_nt_platform() -> bool {
    true // Always NT on NostalgiaOS
}

/// Check if running as server
pub fn rtl_is_server() -> bool {
    let pt = NT_PRODUCT_TYPE.load(Ordering::Relaxed) as u8;
    matches!(ProductType::try_from(pt), Ok(ProductType::Server) | Ok(ProductType::DomainController))
}

/// Check if running as workstation
pub fn rtl_is_workstation() -> bool {
    let pt = NT_PRODUCT_TYPE.load(Ordering::Relaxed) as u8;
    matches!(ProductType::try_from(pt), Ok(ProductType::Workstation))
}
