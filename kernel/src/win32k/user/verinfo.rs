//! Version Information Helpers
//!
//! Windows version resource access functions.
//! Based on Windows Server 2003 winver.h.
//!
//! # Features
//!
//! - Version resource parsing
//! - Fixed file info access
//! - String file info access
//! - Translation queries
//!
//! # References
//!
//! - `public/sdk/inc/winver.h` - Version functions

use crate::ke::spinlock::SpinLock;
use super::strhelp;

// ============================================================================
// VS_FIXEDFILEINFO Flags
// ============================================================================

/// File flags mask
pub const VS_FFI_FILEFLAGSMASK: u32 = 0x0000003F;

/// Debug flag
pub const VS_FF_DEBUG: u32 = 0x00000001;

/// Prerelease flag
pub const VS_FF_PRERELEASE: u32 = 0x00000002;

/// Patched flag
pub const VS_FF_PATCHED: u32 = 0x00000004;

/// Private build flag
pub const VS_FF_PRIVATEBUILD: u32 = 0x00000008;

/// Info inferred flag
pub const VS_FF_INFOINFERRED: u32 = 0x00000010;

/// Special build flag
pub const VS_FF_SPECIALBUILD: u32 = 0x00000020;

// ============================================================================
// File OS Types (VOS_*)
// ============================================================================

/// Unknown OS
pub const VOS_UNKNOWN: u32 = 0x00000000;

/// DOS
pub const VOS_DOS: u32 = 0x00010000;

/// OS/2 16-bit
pub const VOS_OS216: u32 = 0x00020000;

/// OS/2 32-bit
pub const VOS_OS232: u32 = 0x00030000;

/// Windows NT
pub const VOS_NT: u32 = 0x00040000;

/// Windows CE
pub const VOS_WINCE: u32 = 0x00050000;

/// Windows 16-bit
pub const VOS__WINDOWS16: u32 = 0x00000001;

/// PM 16-bit
pub const VOS__PM16: u32 = 0x00000002;

/// PM 32-bit
pub const VOS__PM32: u32 = 0x00000003;

/// Windows 32-bit
pub const VOS__WINDOWS32: u32 = 0x00000004;

/// DOS + Windows 16
pub const VOS_DOS_WINDOWS16: u32 = VOS_DOS | VOS__WINDOWS16;

/// DOS + Windows 32
pub const VOS_DOS_WINDOWS32: u32 = VOS_DOS | VOS__WINDOWS32;

/// NT + Windows 32
pub const VOS_NT_WINDOWS32: u32 = VOS_NT | VOS__WINDOWS32;

// ============================================================================
// File Types (VFT_*)
// ============================================================================

/// Unknown type
pub const VFT_UNKNOWN: u32 = 0x00000000;

/// Application
pub const VFT_APP: u32 = 0x00000001;

/// DLL
pub const VFT_DLL: u32 = 0x00000002;

/// Driver
pub const VFT_DRV: u32 = 0x00000003;

/// Font
pub const VFT_FONT: u32 = 0x00000004;

/// VXD
pub const VFT_VXD: u32 = 0x00000005;

/// Static library
pub const VFT_STATIC_LIB: u32 = 0x00000007;

// ============================================================================
// Driver Subtypes (VFT2_DRV_*)
// ============================================================================

/// Unknown driver
pub const VFT2_UNKNOWN: u32 = 0x00000000;

/// Printer driver
pub const VFT2_DRV_PRINTER: u32 = 0x00000001;

/// Keyboard driver
pub const VFT2_DRV_KEYBOARD: u32 = 0x00000002;

/// Language driver
pub const VFT2_DRV_LANGUAGE: u32 = 0x00000003;

/// Display driver
pub const VFT2_DRV_DISPLAY: u32 = 0x00000004;

/// Mouse driver
pub const VFT2_DRV_MOUSE: u32 = 0x00000005;

/// Network driver
pub const VFT2_DRV_NETWORK: u32 = 0x00000006;

/// System driver
pub const VFT2_DRV_SYSTEM: u32 = 0x00000007;

/// Installable driver
pub const VFT2_DRV_INSTALLABLE: u32 = 0x00000008;

/// Sound driver
pub const VFT2_DRV_SOUND: u32 = 0x00000009;

/// Comm driver
pub const VFT2_DRV_COMM: u32 = 0x0000000A;

/// Input method driver
pub const VFT2_DRV_INPUTMETHOD: u32 = 0x0000000B;

/// Versioned printer driver
pub const VFT2_DRV_VERSIONED_PRINTER: u32 = 0x0000000C;

// ============================================================================
// Font Subtypes (VFT2_FONT_*)
// ============================================================================

/// Raster font
pub const VFT2_FONT_RASTER: u32 = 0x00000001;

/// Vector font
pub const VFT2_FONT_VECTOR: u32 = 0x00000002;

/// TrueType font
pub const VFT2_FONT_TRUETYPE: u32 = 0x00000003;

// ============================================================================
// VS_FIXEDFILEINFO Structure
// ============================================================================

/// Fixed file version information
#[derive(Clone, Copy, Default)]
pub struct VsFixedFileInfo {
    /// Signature (0xFEEF04BD)
    pub signature: u32,
    /// Structure version
    pub struct_version: u32,
    /// File version MS
    pub file_version_ms: u32,
    /// File version LS
    pub file_version_ls: u32,
    /// Product version MS
    pub product_version_ms: u32,
    /// Product version LS
    pub product_version_ls: u32,
    /// File flags mask
    pub file_flags_mask: u32,
    /// File flags
    pub file_flags: u32,
    /// File OS
    pub file_os: u32,
    /// File type
    pub file_type: u32,
    /// File subtype
    pub file_subtype: u32,
    /// File date MS
    pub file_date_ms: u32,
    /// File date LS
    pub file_date_ls: u32,
}

impl VsFixedFileInfo {
    /// Signature value
    pub const SIGNATURE: u32 = 0xFEEF04BD;

    /// Create new with signature
    pub const fn new() -> Self {
        Self {
            signature: Self::SIGNATURE,
            struct_version: 0x00010000,
            file_version_ms: 0,
            file_version_ls: 0,
            product_version_ms: 0,
            product_version_ls: 0,
            file_flags_mask: VS_FFI_FILEFLAGSMASK,
            file_flags: 0,
            file_os: VOS_NT_WINDOWS32,
            file_type: VFT_APP,
            file_subtype: VFT2_UNKNOWN,
            file_date_ms: 0,
            file_date_ls: 0,
        }
    }

    /// Get file version as tuple (major, minor, build, revision)
    pub fn file_version(&self) -> (u16, u16, u16, u16) {
        (
            (self.file_version_ms >> 16) as u16,
            (self.file_version_ms & 0xFFFF) as u16,
            (self.file_version_ls >> 16) as u16,
            (self.file_version_ls & 0xFFFF) as u16,
        )
    }

    /// Get product version as tuple
    pub fn product_version(&self) -> (u16, u16, u16, u16) {
        (
            (self.product_version_ms >> 16) as u16,
            (self.product_version_ms & 0xFFFF) as u16,
            (self.product_version_ls >> 16) as u16,
            (self.product_version_ls & 0xFFFF) as u16,
        )
    }

    /// Set file version
    pub fn set_file_version(&mut self, major: u16, minor: u16, build: u16, revision: u16) {
        self.file_version_ms = ((major as u32) << 16) | (minor as u32);
        self.file_version_ls = ((build as u32) << 16) | (revision as u32);
    }

    /// Set product version
    pub fn set_product_version(&mut self, major: u16, minor: u16, build: u16, revision: u16) {
        self.product_version_ms = ((major as u32) << 16) | (minor as u32);
        self.product_version_ls = ((build as u32) << 16) | (revision as u32);
    }

    /// Check if debug build
    pub fn is_debug(&self) -> bool {
        (self.file_flags & VS_FF_DEBUG) != 0
    }

    /// Check if prerelease
    pub fn is_prerelease(&self) -> bool {
        (self.file_flags & VS_FF_PRERELEASE) != 0
    }
}

// ============================================================================
// Version Info Cache
// ============================================================================

/// Maximum cached version info entries
pub const MAX_VERSION_CACHE: usize = 16;

/// Maximum string value length
pub const MAX_STRING_VALUE: usize = 256;

/// String info entry
#[derive(Clone)]
pub struct StringInfoEntry {
    /// Name (e.g., "FileVersion")
    pub name: [u8; 64],
    /// Value
    pub value: [u8; MAX_STRING_VALUE],
}

impl StringInfoEntry {
    pub const fn new() -> Self {
        Self {
            name: [0; 64],
            value: [0; MAX_STRING_VALUE],
        }
    }
}

/// Version info cache entry
#[derive(Clone)]
pub struct VersionCacheEntry {
    /// Is this slot in use
    pub in_use: bool,
    /// File path
    pub path: [u8; 260],
    /// Fixed file info
    pub fixed_info: VsFixedFileInfo,
    /// Language/codepage
    pub lang_codepage: u32,
    /// String info entries
    pub strings: [StringInfoEntry; 16],
    /// String count
    pub string_count: usize,
}

impl VersionCacheEntry {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            path: [0; 260],
            fixed_info: VsFixedFileInfo::new(),
            lang_codepage: 0x040904B0, // US English, Unicode
            strings: [const { StringInfoEntry::new() }; 16],
            string_count: 0,
        }
    }

    /// Add string info
    pub fn add_string(&mut self, name: &[u8], value: &[u8]) -> bool {
        if self.string_count >= 16 {
            return false;
        }

        let name_len = strhelp::str_len(name).min(63);
        self.strings[self.string_count].name[..name_len].copy_from_slice(&name[..name_len]);
        self.strings[self.string_count].name[name_len] = 0;

        let value_len = strhelp::str_len(value).min(MAX_STRING_VALUE - 1);
        self.strings[self.string_count].value[..value_len].copy_from_slice(&value[..value_len]);
        self.strings[self.string_count].value[value_len] = 0;

        self.string_count += 1;
        true
    }

    /// Find string by name
    pub fn find_string(&self, name: &[u8]) -> Option<&[u8]> {
        for i in 0..self.string_count {
            if strhelp::str_cmp_i(&self.strings[i].name, name) == 0 {
                return Some(&self.strings[i].value);
            }
        }
        None
    }
}

/// Global version cache
static VERSION_CACHE: SpinLock<[VersionCacheEntry; MAX_VERSION_CACHE]> =
    SpinLock::new([const { VersionCacheEntry::new() }; MAX_VERSION_CACHE]);

// ============================================================================
// Standard String Names
// ============================================================================

/// Company name
pub const VS_COMPANYNAME: &[u8] = b"CompanyName";

/// File description
pub const VS_FILEDESCRIPTION: &[u8] = b"FileDescription";

/// File version string
pub const VS_FILEVERSION: &[u8] = b"FileVersion";

/// Internal name
pub const VS_INTERNALNAME: &[u8] = b"InternalName";

/// Legal copyright
pub const VS_LEGALCOPYRIGHT: &[u8] = b"LegalCopyright";

/// Legal trademarks
pub const VS_LEGALTRADEMARKS: &[u8] = b"LegalTrademarks";

/// Original filename
pub const VS_ORIGINALFILENAME: &[u8] = b"OriginalFilename";

/// Product name
pub const VS_PRODUCTNAME: &[u8] = b"ProductName";

/// Product version string
pub const VS_PRODUCTVERSION: &[u8] = b"ProductVersion";

/// Comments
pub const VS_COMMENTS: &[u8] = b"Comments";

/// Private build
pub const VS_PRIVATEBUILD: &[u8] = b"PrivateBuild";

/// Special build
pub const VS_SPECIALBUILD: &[u8] = b"SpecialBuild";

// ============================================================================
// Public API
// ============================================================================

/// Initialize version info
pub fn init() {
    crate::serial_println!("[USER] Version info helpers initialized");
}

/// Get version info size
pub fn get_file_version_info_size(filename: &[u8], handle: &mut u32) -> u32 {
    *handle = 0;

    // Check cache
    let cache = VERSION_CACHE.lock();
    for entry in cache.iter() {
        if entry.in_use && strhelp::str_cmp_i(&entry.path, filename) == 0 {
            // Return size of version data (simplified)
            return 1024;
        }
    }

    // In a real implementation, this would read the file
    // For now, return 0 (not found)
    let _ = filename;
    0
}

/// Get version info
pub fn get_file_version_info(filename: &[u8], _handle: u32, len: u32, data: &mut [u8]) -> bool {
    if len == 0 || data.is_empty() {
        return false;
    }

    // Check cache
    let cache = VERSION_CACHE.lock();
    for entry in cache.iter() {
        if entry.in_use && strhelp::str_cmp_i(&entry.path, filename) == 0 {
            // Copy fixed info to data buffer
            let fixed_size = core::mem::size_of::<VsFixedFileInfo>();
            if data.len() >= fixed_size {
                // Serialize fixed info
                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        &entry.fixed_info as *const _ as *const u8,
                        fixed_size,
                    )
                };
                data[..fixed_size].copy_from_slice(bytes);
            }
            return true;
        }
    }

    false
}

/// Query version value
pub fn ver_query_value<'a>(
    block: &'a [u8],
    sub_block: &[u8],
    buffer: &mut &'a [u8],
    len: &mut u32,
) -> bool {
    // Parse sub_block to determine what to return
    if strhelp::str_str(sub_block, b"\\").is_none() || sub_block == b"\\" {
        // Root query - return fixed file info
        if block.len() >= core::mem::size_of::<VsFixedFileInfo>() {
            *buffer = &block[..core::mem::size_of::<VsFixedFileInfo>()];
            *len = core::mem::size_of::<VsFixedFileInfo>() as u32;
            return true;
        }
    }

    // Check for StringFileInfo query
    if strhelp::str_str_i(sub_block, b"StringFileInfo").is_some() {
        // Would parse and return string value
        *len = 0;
        return false;
    }

    // Check for VarFileInfo\Translation
    if strhelp::str_str_i(sub_block, b"Translation").is_some() {
        // Would return translation array
        *len = 0;
        return false;
    }

    *len = 0;
    false
}

/// Register version info for a file (for simulation)
pub fn register_version_info(
    path: &[u8],
    fixed_info: &VsFixedFileInfo,
    strings: &[(&[u8], &[u8])],
) -> bool {
    let mut cache = VERSION_CACHE.lock();

    // Find or create entry
    let mut target_idx = None;
    for (i, entry) in cache.iter().enumerate() {
        if entry.in_use && strhelp::str_cmp_i(&entry.path, path) == 0 {
            target_idx = Some(i);
            break;
        }
    }

    if target_idx.is_none() {
        for (i, entry) in cache.iter().enumerate() {
            if !entry.in_use {
                target_idx = Some(i);
                break;
            }
        }
    }

    let idx = match target_idx {
        Some(i) => i,
        None => return false,
    };

    cache[idx].in_use = true;
    let path_len = strhelp::str_len(path).min(259);
    cache[idx].path[..path_len].copy_from_slice(&path[..path_len]);
    cache[idx].path[path_len] = 0;
    cache[idx].fixed_info = *fixed_info;
    cache[idx].string_count = 0;

    for (name, value) in strings {
        if !cache[idx].add_string(name, value) {
            break;
        }
    }

    true
}

/// Get cached fixed file info
pub fn get_cached_fixed_info(path: &[u8]) -> Option<VsFixedFileInfo> {
    let cache = VERSION_CACHE.lock();

    for entry in cache.iter() {
        if entry.in_use && strhelp::str_cmp_i(&entry.path, path) == 0 {
            return Some(entry.fixed_info);
        }
    }

    None
}

/// Get cached string info
pub fn get_cached_string_info(path: &[u8], name: &[u8], buffer: &mut [u8]) -> bool {
    let cache = VERSION_CACHE.lock();

    for entry in cache.iter() {
        if entry.in_use && strhelp::str_cmp_i(&entry.path, path) == 0 {
            if let Some(value) = entry.find_string(name) {
                let len = strhelp::str_len(value).min(buffer.len() - 1);
                buffer[..len].copy_from_slice(&value[..len]);
                buffer[len] = 0;
                return true;
            }
            return false;
        }
    }

    false
}

/// Format version as string
pub fn format_version(major: u16, minor: u16, build: u16, revision: u16, buffer: &mut [u8]) -> usize {
    use super::format;

    let args = [
        major as usize,
        minor as usize,
        build as usize,
        revision as usize,
    ];

    format::wsprintf(buffer, b"%u.%u.%u.%u", &args)
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> VersionInfoStats {
    let cache = VERSION_CACHE.lock();

    let mut cached = 0;
    for entry in cache.iter() {
        if entry.in_use {
            cached += 1;
        }
    }

    VersionInfoStats {
        max_cache_entries: MAX_VERSION_CACHE,
        cached_entries: cached,
    }
}

/// Version info statistics
#[derive(Debug, Clone, Copy)]
pub struct VersionInfoStats {
    pub max_cache_entries: usize,
    pub cached_entries: usize,
}
