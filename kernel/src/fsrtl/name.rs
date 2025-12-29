//! Name Comparison and Parsing Utilities
//!
//! Provides file system name operations:
//! - Path component extraction
//! - Wildcard detection and matching
//! - Name comparison (case-sensitive and insensitive)
//! - File system specific name validation
//!
//! This implementation is NT 5.2 (Windows Server 2003) compatible.

/// Name legality flags
pub const FSRTL_FAT_LEGAL: u8 = 0x01;
pub const FSRTL_HPFS_LEGAL: u8 = 0x02;
pub const FSRTL_NTFS_LEGAL: u8 = 0x04;
pub const FSRTL_WILD_CHARACTER: u8 = 0x08;
pub const FSRTL_OLE_LEGAL: u8 = 0x10;
pub const FSRTL_NTFS_STREAM_LEGAL: u8 = FSRTL_NTFS_LEGAL | FSRTL_OLE_LEGAL;

/// Wildcard characters
const WILDCARD_STAR: char = '*';
const WILDCARD_QUESTION: char = '?';
const WILDCARD_DOS_STAR: char = '<';      // Match zero or more before dot
const WILDCARD_DOS_QUESTION: char = '>';  // Match one char, not dot
const WILDCARD_DOS_DOT: char = '"';       // Match period or end

/// Path separator
const PATH_SEPARATOR: char = '\\';

/// Characters illegal in all file systems
const ILLEGAL_CHARS: &[char] = &['<', '>', ':', '"', '/', '\\', '|'];

/// Additional characters illegal in FAT
const FAT_ILLEGAL_CHARS: &[char] = &['*', '?', '+', ',', ';', '=', '[', ']'];

/// Dissect a path into first component and remainder
///
/// # Arguments
/// * `path` - The path to dissect
///
/// # Returns
/// (first_component, remaining_path)
///
/// # Example
/// `\Directory\SubDir\File.txt` -> (`Directory`, `SubDir\File.txt`)
pub fn fsrtl_dissect_name(path: &str) -> (&str, &str) {
    // Skip leading separator if present
    let path = path.strip_prefix('\\').unwrap_or(path);

    // Find the next separator
    if let Some(sep_pos) = path.find('\\') {
        (&path[..sep_pos], &path[sep_pos + 1..])
    } else {
        // No more separators - this is the last component
        (path, "")
    }
}

/// Check if a name contains wildcard characters
pub fn fsrtl_does_name_contain_wild_cards(name: &str) -> bool {
    name.chars().any(|c| matches!(c, '*' | '?' | '<' | '>' | '"'))
}

/// Compare two names for equality
///
/// # Arguments
/// * `name1` - First name
/// * `name2` - Second name
/// * `ignore_case` - Whether to ignore case differences
///
/// # Returns
/// true if names are equal
pub fn fsrtl_are_names_equal(name1: &str, name2: &str, ignore_case: bool) -> bool {
    if name1.len() != name2.len() {
        return false;
    }

    if ignore_case {
        name1.chars().zip(name2.chars()).all(|(c1, c2)| {
            c1.to_ascii_uppercase() == c2.to_ascii_uppercase()
        })
    } else {
        name1 == name2
    }
}

/// Check if a name matches an expression with wildcards
///
/// # Arguments
/// * `expression` - Pattern with wildcards
/// * `name` - Name to match against
/// * `ignore_case` - Whether to ignore case
///
/// # Returns
/// true if name matches expression
pub fn fsrtl_is_name_in_expression(expression: &str, name: &str, ignore_case: bool) -> bool {
    if expression.is_empty() {
        return name.is_empty();
    }

    if !fsrtl_does_name_contain_wild_cards(expression) {
        return fsrtl_are_names_equal(expression, name, ignore_case);
    }

    // Work with bytes for file system names (ASCII-safe)
    let expr = expression.as_bytes();
    let name_bytes = name.as_bytes();

    match_expression(expr, name_bytes, ignore_case)
}

/// Internal wildcard matching (operates on bytes for efficiency)
fn match_expression(expr: &[u8], name: &[u8], ignore_case: bool) -> bool {
    let mut ei = 0; // expression index
    let mut ni = 0; // name index

    // Stack for backtracking on * matches
    let mut star_ei = None;
    let mut star_ni = None;

    while ni < name.len() {
        if ei < expr.len() {
            let ec = expr[ei];

            match ec {
                b'*' | b'<' => {
                    // Star matches zero or more characters
                    star_ei = Some(ei);
                    star_ni = Some(ni);
                    ei += 1;
                    continue;
                }
                b'?' | b'>' => {
                    // Question matches exactly one character
                    // '>' matches one char but not a dot
                    if ec == b'>' && name[ni] == b'.' {
                        // Try backtracking
                        if let (Some(sei), Some(sni)) = (star_ei, star_ni) {
                            ei = sei + 1;
                            star_ni = Some(sni + 1);
                            ni = sni + 1;
                            continue;
                        }
                        return false;
                    }
                    ei += 1;
                    ni += 1;
                    continue;
                }
                b'"' => {
                    // DOS_DOT matches period or end of name
                    if name[ni] == b'.' {
                        ei += 1;
                        ni += 1;
                        continue;
                    }
                    ei += 1;
                    continue;
                }
                c => {
                    // Regular character - must match
                    let matches = if ignore_case {
                        c.to_ascii_uppercase() == name[ni].to_ascii_uppercase()
                    } else {
                        c == name[ni]
                    };

                    if matches {
                        ei += 1;
                        ni += 1;
                        continue;
                    }
                }
            }
        }

        // No match - try backtracking on previous *
        if let (Some(sei), Some(sni)) = (star_ei, star_ni) {
            ei = sei + 1;
            star_ni = Some(sni + 1);
            ni = sni + 1;
        } else {
            return false;
        }
    }

    // Consume any trailing wildcards
    while ei < expr.len() {
        match expr[ei] {
            b'*' | b'<' => ei += 1,
            _ => return false,
        }
    }

    true
}

/// Check if a name is legal for FAT file system
pub fn fsrtl_is_fat_legal(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }

    // Check for illegal characters
    for c in name.chars() {
        if ILLEGAL_CHARS.contains(&c) || FAT_ILLEGAL_CHARS.contains(&c) {
            return false;
        }
        // Control characters are illegal
        if c < ' ' {
            return false;
        }
    }

    // Check 8.3 format for short names
    if name.len() <= 12 {
        // Find the position of the first dot
        let dot_pos = name.find('.');

        match dot_pos {
            None => {
                // No extension - name must be <= 8 chars
                name.len() <= 8
            }
            Some(pos) => {
                // Has extension - check name.ext format
                let base = &name[..pos];
                let rest = &name[pos + 1..];

                // Check for additional dots (invalid in 8.3)
                if rest.contains('.') {
                    return false;
                }

                base.len() <= 8 && rest.len() <= 3
            }
        }
    } else {
        // Long file name - just check characters
        true
    }
}

/// Check if a name is legal for NTFS file system
pub fn fsrtl_is_ntfs_legal(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }

    // Check for illegal characters
    for c in name.chars() {
        if ILLEGAL_CHARS.contains(&c) {
            return false;
        }
        // Control characters (except some special) are illegal
        if c < ' ' && c != '\0' {
            return false;
        }
    }

    // Name cannot be just dots
    if name.chars().all(|c| c == '.') {
        return false;
    }

    // Name cannot end with space or period (except "." and "..")
    if name != "." && name != ".." {
        if let Some(last) = name.chars().last() {
            if last == ' ' || last == '.' {
                return false;
            }
        }
    }

    true
}

/// Get the extension from a file name
pub fn get_extension(name: &str) -> Option<&str> {
    if let Some(dot_pos) = name.rfind('.') {
        let ext = &name[dot_pos + 1..];
        if !ext.is_empty() && !ext.contains('\\') {
            return Some(ext);
        }
    }
    None
}

/// Get the base name without extension
pub fn get_base_name(name: &str) -> &str {
    if let Some(dot_pos) = name.rfind('.') {
        &name[..dot_pos]
    } else {
        name
    }
}

/// Check if a path is a UNC path
pub fn is_unc_path(path: &str) -> bool {
    path.starts_with("\\\\")
}

/// Check if a character is a path separator
pub fn is_path_separator(c: char) -> bool {
    c == '\\' || c == '/'
}

/// Normalize path separators in-place (convert / to \)
///
/// Modifies a mutable byte slice in-place.
pub fn normalize_separators_in_place(path: &mut [u8]) {
    for byte in path.iter_mut() {
        if *byte == b'/' {
            *byte = b'\\';
        }
    }
}
