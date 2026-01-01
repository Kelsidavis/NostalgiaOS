//! String Helper Functions
//!
//! Windows shlwapi.h string manipulation utilities.
//! Based on Windows Server 2003 shlwapi.h.
//!
//! # Features
//!
//! - String comparison (case-sensitive and insensitive)
//! - String searching
//! - String formatting
//! - Path manipulation
//! - Character classification
//!
//! # References
//!
//! - `public/sdk/inc/shlwapi.h` - String functions

// ============================================================================
// Character Constants
// ============================================================================

/// Null terminator
pub const NUL: u8 = 0;

/// Space character
pub const SPACE: u8 = b' ';

/// Tab character
pub const TAB: u8 = b'\t';

/// Newline character
pub const NEWLINE: u8 = b'\n';

/// Carriage return
pub const CR: u8 = b'\r';

/// Path separator
pub const PATH_SEP: u8 = b'\\';

/// Alt path separator
pub const PATH_SEP_ALT: u8 = b'/';

/// Drive separator
pub const DRIVE_SEP: u8 = b':';

/// Extension separator
pub const EXT_SEP: u8 = b'.';

// ============================================================================
// String Comparison
// ============================================================================

/// Compare two strings (case-sensitive)
pub fn str_cmp(s1: &[u8], s2: &[u8]) -> i32 {
    let len = s1.len().min(s2.len());

    for i in 0..len {
        if s1[i] == NUL && s2[i] == NUL {
            return 0;
        }
        if s1[i] == NUL {
            return -1;
        }
        if s2[i] == NUL {
            return 1;
        }
        if s1[i] < s2[i] {
            return -1;
        }
        if s1[i] > s2[i] {
            return 1;
        }
    }

    if s1.len() < s2.len() {
        -1
    } else if s1.len() > s2.len() {
        1
    } else {
        0
    }
}

/// Compare two strings (case-insensitive)
pub fn str_cmp_i(s1: &[u8], s2: &[u8]) -> i32 {
    let len = s1.len().min(s2.len());

    for i in 0..len {
        if s1[i] == NUL && s2[i] == NUL {
            return 0;
        }
        if s1[i] == NUL {
            return -1;
        }
        if s2[i] == NUL {
            return 1;
        }

        let c1 = to_lower(s1[i]);
        let c2 = to_lower(s2[i]);

        if c1 < c2 {
            return -1;
        }
        if c1 > c2 {
            return 1;
        }
    }

    if s1.len() < s2.len() {
        -1
    } else if s1.len() > s2.len() {
        1
    } else {
        0
    }
}

/// Compare n characters (case-sensitive)
pub fn str_cmp_n(s1: &[u8], s2: &[u8], n: usize) -> i32 {
    let len = s1.len().min(s2.len()).min(n);

    for i in 0..len {
        if s1[i] == NUL && s2[i] == NUL {
            return 0;
        }
        if s1[i] == NUL {
            return -1;
        }
        if s2[i] == NUL {
            return 1;
        }
        if s1[i] < s2[i] {
            return -1;
        }
        if s1[i] > s2[i] {
            return 1;
        }
    }

    0
}

/// Compare n characters (case-insensitive)
pub fn str_cmp_ni(s1: &[u8], s2: &[u8], n: usize) -> i32 {
    let len = s1.len().min(s2.len()).min(n);

    for i in 0..len {
        if s1[i] == NUL && s2[i] == NUL {
            return 0;
        }
        if s1[i] == NUL {
            return -1;
        }
        if s2[i] == NUL {
            return 1;
        }

        let c1 = to_lower(s1[i]);
        let c2 = to_lower(s2[i]);

        if c1 < c2 {
            return -1;
        }
        if c1 > c2 {
            return 1;
        }
    }

    0
}

// ============================================================================
// String Searching
// ============================================================================

/// Find first occurrence of character
pub fn str_chr(s: &[u8], c: u8) -> Option<usize> {
    for (i, &ch) in s.iter().enumerate() {
        if ch == NUL {
            break;
        }
        if ch == c {
            return Some(i);
        }
    }
    None
}

/// Find first occurrence of character (case-insensitive)
pub fn str_chr_i(s: &[u8], c: u8) -> Option<usize> {
    let c_lower = to_lower(c);
    for (i, &ch) in s.iter().enumerate() {
        if ch == NUL {
            break;
        }
        if to_lower(ch) == c_lower {
            return Some(i);
        }
    }
    None
}

/// Find last occurrence of character
pub fn str_rchr(s: &[u8], c: u8) -> Option<usize> {
    let mut last = None;
    for (i, &ch) in s.iter().enumerate() {
        if ch == NUL {
            break;
        }
        if ch == c {
            last = Some(i);
        }
    }
    last
}

/// Find last occurrence of character (case-insensitive)
pub fn str_rchr_i(s: &[u8], c: u8) -> Option<usize> {
    let c_lower = to_lower(c);
    let mut last = None;
    for (i, &ch) in s.iter().enumerate() {
        if ch == NUL {
            break;
        }
        if to_lower(ch) == c_lower {
            last = Some(i);
        }
    }
    last
}

/// Find substring
pub fn str_str(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let needle_len = str_len(needle);
    if needle_len == 0 {
        return Some(0);
    }

    let haystack_len = str_len(haystack);
    if needle_len > haystack_len {
        return None;
    }

    for i in 0..=haystack_len - needle_len {
        if str_cmp_n(&haystack[i..], needle, needle_len) == 0 {
            return Some(i);
        }
    }

    None
}

/// Find substring (case-insensitive)
pub fn str_str_i(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let needle_len = str_len(needle);
    if needle_len == 0 {
        return Some(0);
    }

    let haystack_len = str_len(haystack);
    if needle_len > haystack_len {
        return None;
    }

    for i in 0..=haystack_len - needle_len {
        if str_cmp_ni(&haystack[i..], needle, needle_len) == 0 {
            return Some(i);
        }
    }

    None
}

// ============================================================================
// String Length and Manipulation
// ============================================================================

/// Get string length (up to null terminator)
pub fn str_len(s: &[u8]) -> usize {
    for (i, &c) in s.iter().enumerate() {
        if c == NUL {
            return i;
        }
    }
    s.len()
}

/// Get string length with maximum
pub fn str_len_max(s: &[u8], max: usize) -> usize {
    let limit = s.len().min(max);
    for i in 0..limit {
        if s[i] == NUL {
            return i;
        }
    }
    limit
}

/// Copy string to buffer
pub fn str_cpy(dst: &mut [u8], src: &[u8]) -> usize {
    let len = str_len(src);
    let copy_len = len.min(dst.len().saturating_sub(1));

    dst[..copy_len].copy_from_slice(&src[..copy_len]);
    if dst.len() > copy_len {
        dst[copy_len] = NUL;
    }

    copy_len
}

/// Copy n characters
pub fn str_cpy_n(dst: &mut [u8], src: &[u8], n: usize) -> usize {
    let src_len = str_len(src);
    let copy_len = src_len.min(n).min(dst.len().saturating_sub(1));

    dst[..copy_len].copy_from_slice(&src[..copy_len]);
    if dst.len() > copy_len {
        dst[copy_len] = NUL;
    }

    copy_len
}

/// Concatenate strings
pub fn str_cat(dst: &mut [u8], src: &[u8]) -> usize {
    let dst_len = str_len(dst);
    let src_len = str_len(src);
    let available = dst.len().saturating_sub(dst_len + 1);
    let copy_len = src_len.min(available);

    if copy_len > 0 {
        dst[dst_len..dst_len + copy_len].copy_from_slice(&src[..copy_len]);
    }
    if dst.len() > dst_len + copy_len {
        dst[dst_len + copy_len] = NUL;
    }

    dst_len + copy_len
}

/// Duplicate string (copy to provided buffer)
pub fn str_dup(dst: &mut [u8], src: &[u8]) -> bool {
    let len = str_len(src);
    if len >= dst.len() {
        return false;
    }

    dst[..len].copy_from_slice(&src[..len]);
    dst[len] = NUL;
    true
}

// ============================================================================
// Character Classification
// ============================================================================

/// Check if character is alphanumeric
pub fn is_alnum(c: u8) -> bool {
    is_alpha(c) || is_digit(c)
}

/// Check if character is alphabetic
pub fn is_alpha(c: u8) -> bool {
    (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z')
}

/// Check if character is digit
pub fn is_digit(c: u8) -> bool {
    c >= b'0' && c <= b'9'
}

/// Check if character is hexadecimal digit
pub fn is_xdigit(c: u8) -> bool {
    is_digit(c) || (c >= b'a' && c <= b'f') || (c >= b'A' && c <= b'F')
}

/// Check if character is whitespace
pub fn is_space(c: u8) -> bool {
    c == SPACE || c == TAB || c == NEWLINE || c == CR
}

/// Check if character is uppercase
pub fn is_upper(c: u8) -> bool {
    c >= b'A' && c <= b'Z'
}

/// Check if character is lowercase
pub fn is_lower(c: u8) -> bool {
    c >= b'a' && c <= b'z'
}

/// Convert to uppercase
pub fn to_upper(c: u8) -> u8 {
    if is_lower(c) {
        c - 32
    } else {
        c
    }
}

/// Convert to lowercase
pub fn to_lower(c: u8) -> u8 {
    if is_upper(c) {
        c + 32
    } else {
        c
    }
}

// ============================================================================
// String Trimming
// ============================================================================

/// Trim leading whitespace (returns slice offset)
pub fn str_trim_left(s: &[u8]) -> usize {
    for (i, &c) in s.iter().enumerate() {
        if c == NUL {
            return i;
        }
        if !is_space(c) {
            return i;
        }
    }
    s.len()
}

/// Trim trailing whitespace (returns new length)
pub fn str_trim_right(s: &mut [u8]) -> usize {
    let len = str_len(s);
    let mut new_len = len;

    while new_len > 0 && is_space(s[new_len - 1]) {
        new_len -= 1;
    }

    if new_len < s.len() {
        s[new_len] = NUL;
    }

    new_len
}

/// Trim both sides
pub fn str_trim(s: &mut [u8]) -> usize {
    let left = str_trim_left(s);
    let len = str_len(s);

    if left > 0 && left < len {
        // Shift content left
        for i in 0..(len - left) {
            s[i] = s[i + left];
        }
        s[len - left] = NUL;
    }

    str_trim_right(s)
}

// ============================================================================
// Path Helpers
// ============================================================================

/// Check if character is path separator
pub fn is_path_sep(c: u8) -> bool {
    c == PATH_SEP || c == PATH_SEP_ALT
}

/// Find file extension (returns offset to extension including dot)
pub fn path_find_extension(path: &[u8]) -> Option<usize> {
    let len = str_len(path);
    if len == 0 {
        return None;
    }

    // Search backwards for dot
    for i in (0..len).rev() {
        if path[i] == EXT_SEP {
            // Make sure it's not a path separator before it
            if i == 0 || !is_path_sep(path[i - 1]) {
                return Some(i);
            }
        }
        if is_path_sep(path[i]) {
            break;
        }
    }

    None
}

/// Find filename in path (returns offset to filename)
pub fn path_find_filename(path: &[u8]) -> usize {
    let len = str_len(path);
    if len == 0 {
        return 0;
    }

    // Search backwards for path separator
    for i in (0..len).rev() {
        if is_path_sep(path[i]) {
            return i + 1;
        }
    }

    0
}

/// Check if path is relative
pub fn path_is_relative(path: &[u8]) -> bool {
    let len = str_len(path);
    if len == 0 {
        return true;
    }

    // Check for drive letter
    if len >= 2 && path[1] == DRIVE_SEP && is_alpha(path[0]) {
        return false;
    }

    // Check for UNC path
    if len >= 2 && is_path_sep(path[0]) && is_path_sep(path[1]) {
        return false;
    }

    // Check for root path
    if is_path_sep(path[0]) {
        return false;
    }

    true
}

/// Check if path has trailing slash
pub fn path_has_trailing_slash(path: &[u8]) -> bool {
    let len = str_len(path);
    if len == 0 {
        return false;
    }

    is_path_sep(path[len - 1])
}

/// Add trailing slash if needed
pub fn path_add_backslash(path: &mut [u8]) -> bool {
    let len = str_len(path);
    if len == 0 || len >= path.len() - 1 {
        return false;
    }

    if !is_path_sep(path[len - 1]) {
        path[len] = PATH_SEP;
        path[len + 1] = NUL;
    }

    true
}

/// Remove trailing slash
pub fn path_remove_backslash(path: &mut [u8]) -> bool {
    let len = str_len(path);
    if len == 0 {
        return false;
    }

    if is_path_sep(path[len - 1]) {
        path[len - 1] = NUL;
        return true;
    }

    false
}

/// Combine two paths
pub fn path_combine(dst: &mut [u8], dir: &[u8], file: &[u8]) -> bool {
    let dir_len = str_len(dir);
    let file_len = str_len(file);

    // Check if file is absolute
    if !path_is_relative(file) {
        return str_dup(dst, file);
    }

    // Check buffer size
    let need_sep = dir_len > 0 && !is_path_sep(dir[dir_len - 1]);
    let total = dir_len + (if need_sep { 1 } else { 0 }) + file_len;

    if total >= dst.len() {
        return false;
    }

    // Copy directory
    dst[..dir_len].copy_from_slice(&dir[..dir_len]);

    let mut pos = dir_len;

    // Add separator if needed
    if need_sep {
        dst[pos] = PATH_SEP;
        pos += 1;
    }

    // Copy filename
    dst[pos..pos + file_len].copy_from_slice(&file[..file_len]);
    pos += file_len;

    dst[pos] = NUL;
    true
}

// ============================================================================
// Number Conversion
// ============================================================================

/// Parse integer from string
pub fn str_to_int(s: &[u8]) -> Option<i32> {
    let len = str_len(s);
    if len == 0 {
        return None;
    }

    let mut i = 0;
    let mut negative = false;

    // Skip whitespace
    while i < len && is_space(s[i]) {
        i += 1;
    }

    if i >= len {
        return None;
    }

    // Check sign
    if s[i] == b'-' {
        negative = true;
        i += 1;
    } else if s[i] == b'+' {
        i += 1;
    }

    if i >= len {
        return None;
    }

    let mut result: i32 = 0;

    while i < len && is_digit(s[i]) {
        let digit = (s[i] - b'0') as i32;
        result = result.saturating_mul(10).saturating_add(digit);
        i += 1;
    }

    Some(if negative { -result } else { result })
}

/// Format integer to string
pub fn int_to_str(dst: &mut [u8], value: i32) -> usize {
    if dst.is_empty() {
        return 0;
    }

    let mut v = value;
    let negative = v < 0;
    if negative {
        v = -v;
    }

    // Build string in reverse
    let mut temp = [0u8; 12];
    let mut len = 0;

    if v == 0 {
        temp[0] = b'0';
        len = 1;
    } else {
        while v > 0 {
            temp[len] = (v % 10) as u8 + b'0';
            v /= 10;
            len += 1;
        }
    }

    if negative {
        temp[len] = b'-';
        len += 1;
    }

    // Reverse and copy to destination
    let copy_len = len.min(dst.len() - 1);
    for i in 0..copy_len {
        dst[i] = temp[len - 1 - i];
    }
    dst[copy_len] = NUL;

    copy_len
}

/// Format integer as hexadecimal
pub fn int_to_hex(dst: &mut [u8], value: u32) -> usize {
    if dst.is_empty() {
        return 0;
    }

    const HEX_CHARS: &[u8] = b"0123456789ABCDEF";

    let mut v = value;
    let mut temp = [0u8; 8];
    let mut len = 0;

    if v == 0 {
        temp[0] = b'0';
        len = 1;
    } else {
        while v > 0 {
            temp[len] = HEX_CHARS[(v & 0xF) as usize];
            v >>= 4;
            len += 1;
        }
    }

    // Reverse and copy to destination
    let copy_len = len.min(dst.len() - 1);
    for i in 0..copy_len {
        dst[i] = temp[len - 1 - i];
    }
    dst[copy_len] = NUL;

    copy_len
}

// ============================================================================
// URL Helpers
// ============================================================================

/// Find scheme in URL (returns length of scheme including "://")
pub fn url_get_scheme_length(url: &[u8]) -> usize {
    let len = str_len(url);

    for i in 0..len {
        if url[i] == b':' {
            if i + 2 < len && url[i + 1] == b'/' && url[i + 2] == b'/' {
                return i + 3;
            }
            return i + 1;
        }
        if !is_alnum(url[i]) && url[i] != b'+' && url[i] != b'-' && url[i] != b'.' {
            break;
        }
    }

    0
}

/// Check if URL is file URL
pub fn url_is_file(url: &[u8]) -> bool {
    str_cmp_ni(url, b"file:", 5) == 0 || str_cmp_ni(url, b"file://", 7) == 0
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize string helpers
pub fn init() {
    crate::serial_println!("[USER] String helpers initialized");
}
