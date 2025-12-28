//! File System Path Utilities
//!
//! Provides path parsing and manipulation for file system operations.
//! Supports both Windows-style (C:\path) and Unix-style (/path) paths.
//!
//! # Path Formats
//! - `C:\Windows\System32` - Windows absolute path
//! - `\Device\HarddiskVolume1\path` - NT device path
//! - `/mnt/disk/path` - Unix-style path (for compatibility)

/// Maximum path length
pub const MAX_PATH: usize = 260;

/// Maximum path component length
pub const MAX_COMPONENT: usize = 255;

/// Path separator characters
pub const PATH_SEPARATOR: char = '\\';
pub const ALT_PATH_SEPARATOR: char = '/';

/// Path component (a single directory or file name)
#[derive(Clone, Copy)]
pub struct PathComponent {
    /// Component characters
    pub chars: [u8; MAX_COMPONENT],
    /// Component length
    pub length: u8,
}

impl PathComponent {
    /// Create empty component
    pub const fn empty() -> Self {
        Self {
            chars: [0; MAX_COMPONENT],
            length: 0,
        }
    }

    /// Create from string slice
    pub fn new_from(s: &str) -> Self {
        let mut comp = Self::empty();
        let bytes = s.as_bytes();
        let len = bytes.len().min(MAX_COMPONENT);
        comp.chars[..len].copy_from_slice(&bytes[..len]);
        comp.length = len as u8;
        comp
    }

    /// Get as string slice
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.chars[..self.length as usize]).unwrap_or("")
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Compare with string (case-insensitive)
    pub fn equals_ignore_case(&self, s: &str) -> bool {
        let self_str = self.as_str();
        if self_str.len() != s.len() {
            return false;
        }
        self_str.chars().zip(s.chars()).all(|(a, b)| {
            a.eq_ignore_ascii_case(&b)
        })
    }
}

impl Default for PathComponent {
    fn default() -> Self {
        Self::empty()
    }
}

/// Parsed path
#[derive(Clone, Copy)]
pub struct ParsedPath {
    /// Drive letter (if present, 0 means none)
    pub drive: u8,
    /// Whether path is absolute
    pub is_absolute: bool,
    /// Path components
    pub components: [PathComponent; 16],
    /// Number of components
    pub component_count: u8,
}

impl ParsedPath {
    /// Create empty path
    pub const fn empty() -> Self {
        Self {
            drive: 0,
            is_absolute: false,
            components: [PathComponent::empty(); 16],
            component_count: 0,
        }
    }

    /// Parse a path string
    pub fn parse(path: &str) -> Self {
        let mut parsed = Self::empty();
        let mut remaining = path;

        // Check for drive letter (C:)
        let bytes = path.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' {
            let drive = bytes[0].to_ascii_uppercase();
            if drive.is_ascii_uppercase() {
                parsed.drive = drive;
                remaining = &path[2..];
            }
        }

        // Check if absolute
        if remaining.starts_with('\\') || remaining.starts_with('/') {
            parsed.is_absolute = true;
            remaining = remaining.trim_start_matches(['\\', '/']);
        } else if parsed.drive != 0 {
            // Drive letter without leading slash is still absolute
            parsed.is_absolute = true;
        }

        // Split into components
        for component in remaining.split(['\\', '/']) {
            if component.is_empty() {
                continue;
            }

            // Handle . and ..
            if component == "." {
                continue;
            }

            if component == ".." {
                if parsed.component_count > 0 {
                    parsed.component_count -= 1;
                }
                continue;
            }

            if parsed.component_count as usize >= 16 {
                break;
            }

            parsed.components[parsed.component_count as usize] = PathComponent::new_from(component);
            parsed.component_count += 1;
        }

        parsed
    }

    /// Get the file name (last component)
    pub fn file_name(&self) -> Option<&PathComponent> {
        if self.component_count > 0 {
            Some(&self.components[self.component_count as usize - 1])
        } else {
            None
        }
    }

    /// Get the parent path (all but last component)
    pub fn parent(&self) -> Self {
        let mut parent = *self;
        if parent.component_count > 0 {
            parent.component_count -= 1;
        }
        parent
    }

    /// Check if this is a root path
    pub fn is_root(&self) -> bool {
        self.is_absolute && self.component_count == 0
    }

    /// Get component at index
    pub fn get(&self, index: usize) -> Option<&PathComponent> {
        if index < self.component_count as usize {
            Some(&self.components[index])
        } else {
            None
        }
    }

    /// Iterate over components
    pub fn iter(&self) -> impl Iterator<Item = &PathComponent> {
        self.components[..self.component_count as usize].iter()
    }

    /// Get extension (if any)
    pub fn extension(&self) -> Option<&str> {
        let name = self.file_name()?.as_str();
        let dot_pos = name.rfind('.')?;
        if dot_pos == 0 || dot_pos == name.len() - 1 {
            None
        } else {
            Some(&name[dot_pos + 1..])
        }
    }

    /// Get stem (file name without extension)
    pub fn stem(&self) -> Option<&str> {
        let name = self.file_name()?.as_str();
        if let Some(dot_pos) = name.rfind('.') {
            if dot_pos > 0 {
                return Some(&name[..dot_pos]);
            }
        }
        Some(name)
    }
}

impl Default for ParsedPath {
    fn default() -> Self {
        Self::empty()
    }
}

/// Convert 8.3 short name to string
pub fn short_name_to_string(name: &[u8; 8], ext: &[u8; 3]) -> [u8; 12] {
    let mut result = [b' '; 12];
    let mut pos = 0;

    // Copy name, trimming trailing spaces
    for &b in name.iter() {
        if b == b' ' {
            break;
        }
        result[pos] = b;
        pos += 1;
    }

    // Add dot and extension if present
    let has_ext = ext[0] != b' ';
    if has_ext {
        result[pos] = b'.';
        pos += 1;
        for &b in ext.iter() {
            if b == b' ' {
                break;
            }
            result[pos] = b;
            pos += 1;
        }
    }

    result
}

/// Convert string to 8.3 short name format
pub fn string_to_short_name(name: &str) -> ([u8; 8], [u8; 3]) {
    let mut short_name = [b' '; 8];
    let mut short_ext = [b' '; 3];

    let bytes = name.as_bytes();

    // Find last dot for extension
    let dot_pos = bytes.iter().rposition(|&b| b == b'.');

    let (name_part, ext_part): (&[u8], &[u8]) = if let Some(pos) = dot_pos {
        (&bytes[..pos], &bytes[pos + 1..])
    } else {
        (bytes, &[])
    };

    // Copy name (up to 8 chars), converting to uppercase
    let name_len = name_part.len().min(8);
    for (i, &b) in name_part.iter().take(name_len).enumerate() {
        let upper = b.to_ascii_uppercase();
        // Replace invalid characters with underscore
        short_name[i] = if is_valid_short_name_char(upper) { upper } else { b'_' };
    }

    // Copy extension (up to 3 chars), converting to uppercase
    let ext_len = ext_part.len().min(3);
    for (i, &b) in ext_part.iter().take(ext_len).enumerate() {
        let upper = b.to_ascii_uppercase();
        short_ext[i] = if is_valid_short_name_char(upper) { upper } else { b'_' };
    }

    (short_name, short_ext)
}

/// Check if character is valid in 8.3 short name
fn is_valid_short_name_char(c: u8) -> bool {
    matches!(c, b'A'..=b'Z' | b'0'..=b'9' | b'!' | b'#' | b'$' | b'%' |
             b'&' | b'\'' | b'(' | b')' | b'-' | b'@' | b'^' | b'_' |
             b'`' | b'{' | b'}' | b'~')
}

/// Validate a file name
pub fn is_valid_filename(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_COMPONENT {
        return false;
    }

    // Check for invalid characters
    for c in name.chars() {
        if matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
            return false;
        }
        if c < ' ' {
            return false;
        }
    }

    // Check for reserved names (case-insensitive comparison)
    let reserved = ["CON", "PRN", "AUX", "NUL",
                   "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
                   "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"];

    let name_bytes = name.as_bytes();

    for r in reserved.iter() {
        let r_bytes = r.as_bytes();
        let r_len = r_bytes.len();

        // Check exact match (case-insensitive)
        if name_bytes.len() == r_len {
            let mut matches = true;
            for i in 0..r_len {
                if name_bytes[i].to_ascii_uppercase() != r_bytes[i] {
                    matches = false;
                    break;
                }
            }
            if matches {
                return false;
            }
        }

        // Check for reserved name followed by extension (e.g., "CON.txt")
        if name_bytes.len() > r_len + 1 {
            let mut prefix_matches = true;
            for i in 0..r_len {
                if name_bytes[i].to_ascii_uppercase() != r_bytes[i] {
                    prefix_matches = false;
                    break;
                }
            }
            if prefix_matches && name_bytes[r_len] == b'.' {
                return false;
            }
        }
    }

    // Can't end with dot or space
    if name.ends_with('.') || name.ends_with(' ') {
        return false;
    }

    true
}

/// Normalize a path (resolve . and .., convert separators)
pub fn normalize_path(path: &str) -> ParsedPath {
    ParsedPath::parse(path)
}

/// Join two paths
pub fn join_paths(base: &ParsedPath, relative: &str) -> ParsedPath {
    let rel = ParsedPath::parse(relative);

    // If relative is absolute, just return it
    if rel.is_absolute {
        return rel;
    }

    let mut result = *base;

    // Append relative components
    for i in 0..rel.component_count as usize {
        let comp = &rel.components[i];

        if comp.as_str() == ".." {
            if result.component_count > 0 {
                result.component_count -= 1;
            }
        } else if comp.as_str() != "."
            && (result.component_count as usize) < 16 {
                result.components[result.component_count as usize] = *comp;
                result.component_count += 1;
            }
    }

    result
}

/// Initialize path subsystem
pub fn init() {
    crate::serial_println!("[FS] Path utilities initialized");
}
