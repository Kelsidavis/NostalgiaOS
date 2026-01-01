//! Shell Path Helper Functions
//!
//! Windows shell path manipulation functions.
//! Based on Windows Server 2003 shlwapi.h.
//!
//! # Features
//!
//! - Path canonicalization
//! - Path component extraction
//! - File type detection
//! - Special folder paths
//!
//! # References
//!
//! - `public/sdk/inc/shlwapi.h` - Path* functions

use super::strhelp::{self, is_alpha, is_path_sep, to_lower};

// ============================================================================
// File Attribute Constants
// ============================================================================

/// Read-only
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x00000001;

/// Hidden
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x00000002;

/// System
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x00000004;

/// Directory
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;

/// Archive
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x00000020;

/// Device
pub const FILE_ATTRIBUTE_DEVICE: u32 = 0x00000040;

/// Normal
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;

/// Temporary
pub const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x00000100;

/// Sparse file
pub const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x00000200;

/// Reparse point
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x00000400;

/// Compressed
pub const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x00000800;

/// Offline
pub const FILE_ATTRIBUTE_OFFLINE: u32 = 0x00001000;

/// Not content indexed
pub const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x00002000;

/// Encrypted
pub const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x00004000;

// ============================================================================
// Special Folder IDs (CSIDL)
// ============================================================================

/// Desktop
pub const CSIDL_DESKTOP: i32 = 0x0000;

/// Internet (IE)
pub const CSIDL_INTERNET: i32 = 0x0001;

/// Programs
pub const CSIDL_PROGRAMS: i32 = 0x0002;

/// Control Panel
pub const CSIDL_CONTROLS: i32 = 0x0003;

/// Printers
pub const CSIDL_PRINTERS: i32 = 0x0004;

/// My Documents
pub const CSIDL_PERSONAL: i32 = 0x0005;

/// Favorites
pub const CSIDL_FAVORITES: i32 = 0x0006;

/// Startup
pub const CSIDL_STARTUP: i32 = 0x0007;

/// Recent
pub const CSIDL_RECENT: i32 = 0x0008;

/// SendTo
pub const CSIDL_SENDTO: i32 = 0x0009;

/// Recycle Bin
pub const CSIDL_BITBUCKET: i32 = 0x000A;

/// Start Menu
pub const CSIDL_STARTMENU: i32 = 0x000B;

/// My Music
pub const CSIDL_MYMUSIC: i32 = 0x000D;

/// My Videos
pub const CSIDL_MYVIDEO: i32 = 0x000E;

/// Desktop Directory
pub const CSIDL_DESKTOPDIRECTORY: i32 = 0x0010;

/// My Computer
pub const CSIDL_DRIVES: i32 = 0x0011;

/// Network Neighborhood
pub const CSIDL_NETWORK: i32 = 0x0012;

/// NetHood
pub const CSIDL_NETHOOD: i32 = 0x0013;

/// Fonts
pub const CSIDL_FONTS: i32 = 0x0014;

/// Templates
pub const CSIDL_TEMPLATES: i32 = 0x0015;

/// Common Start Menu
pub const CSIDL_COMMON_STARTMENU: i32 = 0x0016;

/// Common Programs
pub const CSIDL_COMMON_PROGRAMS: i32 = 0x0017;

/// Common Startup
pub const CSIDL_COMMON_STARTUP: i32 = 0x0018;

/// Common Desktop
pub const CSIDL_COMMON_DESKTOPDIRECTORY: i32 = 0x0019;

/// AppData
pub const CSIDL_APPDATA: i32 = 0x001A;

/// PrintHood
pub const CSIDL_PRINTHOOD: i32 = 0x001B;

/// Local AppData
pub const CSIDL_LOCAL_APPDATA: i32 = 0x001C;

/// ALT Startup
pub const CSIDL_ALTSTARTUP: i32 = 0x001D;

/// Common ALT Startup
pub const CSIDL_COMMON_ALTSTARTUP: i32 = 0x001E;

/// Common Favorites
pub const CSIDL_COMMON_FAVORITES: i32 = 0x001F;

/// Internet Cache
pub const CSIDL_INTERNET_CACHE: i32 = 0x0020;

/// Cookies
pub const CSIDL_COOKIES: i32 = 0x0021;

/// History
pub const CSIDL_HISTORY: i32 = 0x0022;

/// Common AppData
pub const CSIDL_COMMON_APPDATA: i32 = 0x0023;

/// Windows
pub const CSIDL_WINDOWS: i32 = 0x0024;

/// System
pub const CSIDL_SYSTEM: i32 = 0x0025;

/// Program Files
pub const CSIDL_PROGRAM_FILES: i32 = 0x0026;

/// My Pictures
pub const CSIDL_MYPICTURES: i32 = 0x0027;

/// Profile
pub const CSIDL_PROFILE: i32 = 0x0028;

/// System (x86)
pub const CSIDL_SYSTEMX86: i32 = 0x0029;

/// Program Files (x86)
pub const CSIDL_PROGRAM_FILESX86: i32 = 0x002A;

/// Common Files
pub const CSIDL_PROGRAM_FILES_COMMON: i32 = 0x002B;

/// Common Files (x86)
pub const CSIDL_PROGRAM_FILES_COMMONX86: i32 = 0x002C;

/// Common Templates
pub const CSIDL_COMMON_TEMPLATES: i32 = 0x002D;

/// Common Documents
pub const CSIDL_COMMON_DOCUMENTS: i32 = 0x002E;

/// Common Administrative Tools
pub const CSIDL_COMMON_ADMINTOOLS: i32 = 0x002F;

/// Administrative Tools
pub const CSIDL_ADMINTOOLS: i32 = 0x0030;

/// Flag: Create if needed
pub const CSIDL_FLAG_CREATE: i32 = 0x8000;

// ============================================================================
// Path Functions
// ============================================================================

/// Check if path is a root
pub fn path_is_root(path: &[u8]) -> bool {
    let len = strhelp::str_len(path);
    if len == 0 {
        return false;
    }

    // "C:\" is a root
    if len == 3 && is_alpha(path[0]) && path[1] == b':' && is_path_sep(path[2]) {
        return true;
    }

    // "\" or "/" is a root
    if len == 1 && is_path_sep(path[0]) {
        return true;
    }

    // "\\server\share\" UNC root
    if len >= 2 && is_path_sep(path[0]) && is_path_sep(path[1]) {
        // Count backslashes to determine if this is a share root
        let mut slash_count = 0;
        for &c in &path[2..len] {
            if is_path_sep(c) {
                slash_count += 1;
            }
        }
        // \\server\share\ has exactly one slash after \\server
        return slash_count == 1 && is_path_sep(path[len - 1]);
    }

    false
}

/// Check if path is UNC
pub fn path_is_unc(path: &[u8]) -> bool {
    let len = strhelp::str_len(path);
    len >= 2 && is_path_sep(path[0]) && is_path_sep(path[1])
}

/// Check if path is UNC server
pub fn path_is_unc_server(path: &[u8]) -> bool {
    let len = strhelp::str_len(path);
    if len < 3 || !is_path_sep(path[0]) || !is_path_sep(path[1]) {
        return false;
    }

    // \\server (no share component)
    for &c in &path[2..len] {
        if is_path_sep(c) {
            return false;
        }
    }

    true
}

/// Check if path is UNC server share
pub fn path_is_unc_server_share(path: &[u8]) -> bool {
    let len = strhelp::str_len(path);
    if len < 5 || !is_path_sep(path[0]) || !is_path_sep(path[1]) {
        return false;
    }

    // \\server\share
    let mut slash_count = 0;
    for &c in &path[2..len] {
        if is_path_sep(c) {
            slash_count += 1;
        }
    }

    slash_count == 1
}

/// Strip path component
pub fn path_strip_path(path: &mut [u8]) {
    let filename_start = strhelp::path_find_filename(path);
    if filename_start > 0 {
        let len = strhelp::str_len(&path[filename_start..]);
        // Move filename to beginning
        for i in 0..len {
            path[i] = path[filename_start + i];
        }
        path[len] = 0;
    }
}

/// Strip to root
pub fn path_strip_to_root(path: &mut [u8]) -> bool {
    let len = strhelp::str_len(path);
    if len == 0 {
        return false;
    }

    // Handle drive letter
    if len >= 2 && is_alpha(path[0]) && path[1] == b':' {
        if len >= 3 && is_path_sep(path[2]) {
            path[3] = 0;
        } else {
            path[2] = b'\\';
            path[3] = 0;
        }
        return true;
    }

    // Handle UNC path
    if len >= 2 && is_path_sep(path[0]) && is_path_sep(path[1]) {
        // Find end of server\share
        let mut slash_count = 0;
        for i in 2..len {
            if is_path_sep(path[i]) {
                slash_count += 1;
                if slash_count == 2 {
                    path[i + 1] = 0;
                    return true;
                }
            }
        }
    }

    // Handle root path
    if is_path_sep(path[0]) {
        path[1] = 0;
        return true;
    }

    false
}

/// Remove extension from path
pub fn path_remove_extension(path: &mut [u8]) {
    if let Some(ext_pos) = strhelp::path_find_extension(path) {
        path[ext_pos] = 0;
    }
}

/// Add extension to path
pub fn path_add_extension(path: &mut [u8], ext: &[u8]) -> bool {
    let path_len = strhelp::str_len(path);
    let ext_len = strhelp::str_len(ext);

    // Check if already has extension
    if strhelp::path_find_extension(path).is_some() {
        return false;
    }

    // Check if there's room
    if path_len + ext_len + 1 >= path.len() {
        return false;
    }

    // Add dot if extension doesn't start with one
    let mut pos = path_len;
    if ext.is_empty() || ext[0] != b'.' {
        path[pos] = b'.';
        pos += 1;
    }

    // Copy extension
    for i in 0..ext_len {
        path[pos + i] = ext[i];
    }
    path[pos + ext_len] = 0;

    true
}

/// Rename extension in path
pub fn path_rename_extension(path: &mut [u8], ext: &[u8]) -> bool {
    path_remove_extension(path);
    path_add_extension(path, ext)
}

/// Remove trailing backslash
pub fn path_remove_backslash(path: &mut [u8]) -> Option<u8> {
    let len = strhelp::str_len(path);
    if len > 0 && is_path_sep(path[len - 1]) {
        let removed = path[len - 1];
        path[len - 1] = 0;
        return Some(removed);
    }
    None
}

/// Add trailing backslash
pub fn path_add_backslash(path: &mut [u8]) -> bool {
    let len = strhelp::str_len(path);
    if len == 0 || len >= path.len() - 1 {
        return false;
    }

    if !is_path_sep(path[len - 1]) {
        path[len] = b'\\';
        path[len + 1] = 0;
    }

    true
}

/// Check if path matches specification (wildcards)
pub fn path_match_spec(path: &[u8], spec: &[u8]) -> bool {
    let path_len = strhelp::str_len(path);
    let spec_len = strhelp::str_len(spec);

    match_wildcard(path, 0, path_len, spec, 0, spec_len)
}

/// Recursive wildcard matcher
fn match_wildcard(path: &[u8], mut pi: usize, plen: usize, spec: &[u8], mut si: usize, slen: usize) -> bool {
    while si < slen {
        if spec[si] == b'*' {
            // Skip consecutive stars
            while si < slen && spec[si] == b'*' {
                si += 1;
            }

            // * at end matches everything
            if si >= slen {
                return true;
            }

            // Try matching remaining pattern at each position
            while pi <= plen {
                if match_wildcard(path, pi, plen, spec, si, slen) {
                    return true;
                }
                pi += 1;
            }
            return false;
        } else if spec[si] == b'?' {
            // ? matches any single character
            if pi >= plen {
                return false;
            }
            pi += 1;
            si += 1;
        } else {
            // Literal match (case-insensitive)
            if pi >= plen {
                return false;
            }
            if to_lower(path[pi]) != to_lower(spec[si]) {
                return false;
            }
            pi += 1;
            si += 1;
        }
    }

    // Both must be exhausted for a match
    pi >= plen
}

/// Compact path to fit in width (ellipsis)
pub fn path_compact_path(path: &mut [u8], max_len: usize) {
    let len = strhelp::str_len(path);
    if len <= max_len || max_len < 4 {
        return;
    }

    // Find filename
    let filename_start = strhelp::path_find_filename(path);
    let filename_len = len - filename_start;

    // If filename alone is too long, truncate it
    if filename_len >= max_len - 3 {
        // ...filename (truncated)
        path[0] = b'.';
        path[1] = b'.';
        path[2] = b'.';
        let copy_len = (max_len - 3).min(filename_len);
        for i in 0..copy_len {
            path[3 + i] = path[filename_start + i];
        }
        path[3 + copy_len] = 0;
        return;
    }

    // Path\...\filename
    let available_for_path = max_len - filename_len - 4; // 4 for \...
    if available_for_path > 0 {
        // Keep beginning of path
        let keep = available_for_path.min(filename_start);
        // Insert ...
        path[keep] = b'\\';
        path[keep + 1] = b'.';
        path[keep + 2] = b'.';
        path[keep + 3] = b'.';
        // Copy filename
        for i in 0..filename_len {
            path[keep + 4 + i] = path[filename_start + i];
        }
        path[keep + 4 + filename_len] = 0;
    }
}

/// Canonicalize path (resolve . and ..)
pub fn path_canonicalize(dst: &mut [u8], src: &[u8]) -> bool {
    let src_len = strhelp::str_len(src);
    if src_len == 0 || dst.is_empty() {
        return false;
    }

    // Copy source to destination first
    let copy_len = src_len.min(dst.len() - 1);
    dst[..copy_len].copy_from_slice(&src[..copy_len]);
    dst[copy_len] = 0;

    // Process path components
    let mut write_pos = 0;
    let mut read_pos = 0;

    // Preserve drive letter or UNC prefix
    if src_len >= 2 && is_alpha(src[0]) && src[1] == b':' {
        dst[0] = src[0];
        dst[1] = b':';
        write_pos = 2;
        read_pos = 2;
        if src_len > 2 && is_path_sep(src[2]) {
            dst[2] = b'\\';
            write_pos = 3;
            read_pos = 3;
        }
    } else if src_len >= 2 && is_path_sep(src[0]) && is_path_sep(src[1]) {
        dst[0] = b'\\';
        dst[1] = b'\\';
        write_pos = 2;
        read_pos = 2;
    } else if is_path_sep(src[0]) {
        dst[0] = b'\\';
        write_pos = 1;
        read_pos = 1;
    }

    // Process each component
    while read_pos < src_len {
        // Skip separators
        while read_pos < src_len && is_path_sep(src[read_pos]) {
            read_pos += 1;
        }

        if read_pos >= src_len {
            break;
        }

        // Find end of component
        let comp_start = read_pos;
        while read_pos < src_len && !is_path_sep(src[read_pos]) {
            read_pos += 1;
        }
        let comp_len = read_pos - comp_start;

        // Check for . and ..
        if comp_len == 1 && src[comp_start] == b'.' {
            // Current dir, skip
            continue;
        } else if comp_len == 2 && src[comp_start] == b'.' && src[comp_start + 1] == b'.' {
            // Parent dir, go back
            if write_pos > 0 {
                // Find previous separator
                let mut back_pos = write_pos - 1;
                while back_pos > 0 && !is_path_sep(dst[back_pos - 1]) {
                    back_pos -= 1;
                }
                // Don't go past root
                if back_pos > 0 || !is_path_sep(dst[0]) {
                    write_pos = back_pos;
                }
            }
        } else {
            // Regular component
            if write_pos > 0 && !is_path_sep(dst[write_pos - 1]) {
                dst[write_pos] = b'\\';
                write_pos += 1;
            }
            // Copy component
            for i in 0..comp_len {
                if write_pos >= dst.len() - 1 {
                    break;
                }
                dst[write_pos] = src[comp_start + i];
                write_pos += 1;
            }
        }
    }

    // Ensure null termination
    if write_pos < dst.len() {
        dst[write_pos] = 0;
    }

    true
}

/// Get special folder path
pub fn sh_get_folder_path(csidl: i32, buffer: &mut [u8]) -> bool {
    let _create = (csidl & CSIDL_FLAG_CREATE) != 0;
    let folder_id = csidl & 0x7FFF;

    // Return mock paths for common folders
    let path: &[u8] = match folder_id {
        CSIDL_DESKTOP => b"C:\\Users\\Default\\Desktop",
        CSIDL_PERSONAL => b"C:\\Users\\Default\\Documents",
        CSIDL_APPDATA => b"C:\\Users\\Default\\AppData\\Roaming",
        CSIDL_LOCAL_APPDATA => b"C:\\Users\\Default\\AppData\\Local",
        CSIDL_WINDOWS => b"C:\\Windows",
        CSIDL_SYSTEM => b"C:\\Windows\\System32",
        CSIDL_PROGRAM_FILES => b"C:\\Program Files",
        CSIDL_PROGRAM_FILESX86 => b"C:\\Program Files (x86)",
        CSIDL_STARTMENU => b"C:\\Users\\Default\\Start Menu",
        CSIDL_PROGRAMS => b"C:\\Users\\Default\\Start Menu\\Programs",
        CSIDL_FONTS => b"C:\\Windows\\Fonts",
        CSIDL_TEMPLATES => b"C:\\Users\\Default\\Templates",
        CSIDL_COMMON_DOCUMENTS => b"C:\\Users\\Public\\Documents",
        _ => return false,
    };

    let len = path.len().min(buffer.len() - 1);
    buffer[..len].copy_from_slice(&path[..len]);
    buffer[len] = 0;

    true
}

// ============================================================================
// File Type Detection
// ============================================================================

/// Get file extension type
pub fn path_get_extension_type(ext: &[u8]) -> FileType {
    let ext_len = strhelp::str_len(ext);
    if ext_len == 0 {
        return FileType::Unknown;
    }

    // Skip leading dot if present
    let ext_start = if ext[0] == b'.' { 1 } else { 0 };
    let ext_slice = &ext[ext_start..ext_start + ext_len.saturating_sub(ext_start)];

    // Match common extensions (case-insensitive)
    if ext_matches(ext_slice, b"exe") || ext_matches(ext_slice, b"com") {
        FileType::Executable
    } else if ext_matches(ext_slice, b"dll") || ext_matches(ext_slice, b"ocx") {
        FileType::Library
    } else if ext_matches(ext_slice, b"bat") || ext_matches(ext_slice, b"cmd") {
        FileType::Script
    } else if ext_matches(ext_slice, b"txt") || ext_matches(ext_slice, b"log") {
        FileType::Text
    } else if ext_matches(ext_slice, b"doc") || ext_matches(ext_slice, b"docx") {
        FileType::Document
    } else if ext_matches(ext_slice, b"xls") || ext_matches(ext_slice, b"xlsx") {
        FileType::Spreadsheet
    } else if ext_matches(ext_slice, b"ppt") || ext_matches(ext_slice, b"pptx") {
        FileType::Presentation
    } else if ext_matches(ext_slice, b"pdf") {
        FileType::Pdf
    } else if ext_matches(ext_slice, b"jpg") || ext_matches(ext_slice, b"jpeg")
        || ext_matches(ext_slice, b"png") || ext_matches(ext_slice, b"gif")
        || ext_matches(ext_slice, b"bmp") || ext_matches(ext_slice, b"ico")
    {
        FileType::Image
    } else if ext_matches(ext_slice, b"mp3") || ext_matches(ext_slice, b"wav")
        || ext_matches(ext_slice, b"wma") || ext_matches(ext_slice, b"ogg")
    {
        FileType::Audio
    } else if ext_matches(ext_slice, b"mp4") || ext_matches(ext_slice, b"avi")
        || ext_matches(ext_slice, b"wmv") || ext_matches(ext_slice, b"mkv")
    {
        FileType::Video
    } else if ext_matches(ext_slice, b"zip") || ext_matches(ext_slice, b"rar")
        || ext_matches(ext_slice, b"7z") || ext_matches(ext_slice, b"tar")
    {
        FileType::Archive
    } else if ext_matches(ext_slice, b"html") || ext_matches(ext_slice, b"htm") {
        FileType::Html
    } else if ext_matches(ext_slice, b"xml") {
        FileType::Xml
    } else if ext_matches(ext_slice, b"ini") || ext_matches(ext_slice, b"cfg") {
        FileType::Config
    } else if ext_matches(ext_slice, b"sys") || ext_matches(ext_slice, b"drv") {
        FileType::Driver
    } else if ext_matches(ext_slice, b"lnk") {
        FileType::Shortcut
    } else {
        FileType::Unknown
    }
}

fn ext_matches(ext: &[u8], pattern: &[u8]) -> bool {
    strhelp::str_cmp_ni(ext, pattern, pattern.len()) == 0
}

/// File type categories
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileType {
    Unknown,
    Executable,
    Library,
    Script,
    Text,
    Document,
    Spreadsheet,
    Presentation,
    Pdf,
    Image,
    Audio,
    Video,
    Archive,
    Html,
    Xml,
    Config,
    Driver,
    Shortcut,
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize shell path helpers
pub fn init() {
    crate::serial_println!("[USER] Shell path helpers initialized");
}
