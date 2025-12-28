//! NT String Types (UNICODE_STRING, ANSI_STRING)
//!
//! NT uses counted strings that track both current length and buffer capacity.
//! Unlike C strings, these are not necessarily null-terminated.
//!
//! # Key Differences from C Strings
//!
//! - Length is stored explicitly (no strlen() needed)
//! - Can contain embedded nulls
//! - Buffer capacity tracked separately from current length
//! - UTF-16 (wide) strings are the native format
//!
//! # Usage
//! ```
//! let mut buffer = [0u16; 64];
//! let mut us = UnicodeString::from_buffer(&mut buffer);
//! us.copy_from_str("Hello");
//! ```

use core::ptr;
use core::slice;
use core::fmt;

/// Unicode (wide) string - UTF-16LE
///
/// Equivalent to NT's UNICODE_STRING
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnicodeString {
    /// Current length in bytes (not characters)
    pub length: u16,
    /// Maximum length in bytes (buffer capacity)
    pub maximum_length: u16,
    /// Pointer to UTF-16 buffer
    pub buffer: *mut u16,
}

impl UnicodeString {
    /// Create an empty unicode string
    pub const fn empty() -> Self {
        Self {
            length: 0,
            maximum_length: 0,
            buffer: ptr::null_mut(),
        }
    }

    /// Create a unicode string from a buffer
    pub fn from_buffer(buffer: &mut [u16]) -> Self {
        Self {
            length: 0,
            maximum_length: (buffer.len() * 2) as u16,
            buffer: buffer.as_mut_ptr(),
        }
    }

    /// Create a unicode string from an existing buffer with content
    ///
    /// # Safety
    /// The buffer must contain valid UTF-16 data up to `length` bytes
    pub unsafe fn from_raw_parts(buffer: *mut u16, length: u16, max_length: u16) -> Self {
        Self {
            length,
            maximum_length: max_length,
            buffer,
        }
    }

    /// Create from a static wide string literal
    ///
    /// # Safety
    /// The buffer must remain valid for the lifetime of this string
    pub const unsafe fn from_static(s: &'static [u16]) -> Self {
        Self {
            length: (s.len() * 2) as u16,
            maximum_length: (s.len() * 2) as u16,
            buffer: s.as_ptr() as *mut u16,
        }
    }

    /// Check if the string is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Get length in characters (not bytes)
    #[inline]
    pub fn char_len(&self) -> usize {
        (self.length as usize) / 2
    }

    /// Get the string as a slice
    pub fn as_slice(&self) -> &[u16] {
        if self.buffer.is_null() || self.length == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(self.buffer, self.char_len()) }
        }
    }

    /// Get the string as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u16] {
        if self.buffer.is_null() || self.length == 0 {
            &mut []
        } else {
            unsafe { slice::from_raw_parts_mut(self.buffer, self.char_len()) }
        }
    }

    /// Copy from a Rust &str (ASCII/UTF-8 to UTF-16)
    ///
    /// Returns the number of characters copied, or None if buffer too small
    pub fn copy_from_str(&mut self, s: &str) -> Option<usize> {
        if self.buffer.is_null() {
            return None;
        }

        let max_chars = (self.maximum_length as usize) / 2;
        let mut count = 0;

        for (i, c) in s.chars().enumerate() {
            if i >= max_chars {
                break;
            }

            // Simple UTF-16 encoding (BMP only for simplicity)
            let code = c as u32;
            if code <= 0xFFFF {
                unsafe {
                    *self.buffer.add(i) = code as u16;
                }
                count = i + 1;
            } else {
                // Surrogate pair for characters outside BMP
                if i + 1 >= max_chars {
                    break;
                }
                let code = code - 0x10000;
                unsafe {
                    *self.buffer.add(i) = (0xD800 + (code >> 10)) as u16;
                    *self.buffer.add(i + 1) = (0xDC00 + (code & 0x3FF)) as u16;
                }
                count = i + 2;
            }
        }

        self.length = (count * 2) as u16;
        Some(count)
    }

    /// Copy from another unicode string
    pub fn copy_from(&mut self, other: &UnicodeString) -> bool {
        if self.buffer.is_null() || other.length > self.maximum_length {
            return false;
        }

        if !other.buffer.is_null() && other.length > 0 {
            unsafe {
                ptr::copy_nonoverlapping(
                    other.buffer,
                    self.buffer,
                    other.char_len(),
                );
            }
        }
        self.length = other.length;
        true
    }

    /// Append a character
    pub fn push(&mut self, c: u16) -> bool {
        let new_len = self.length + 2;
        if new_len > self.maximum_length || self.buffer.is_null() {
            return false;
        }

        unsafe {
            *self.buffer.add(self.char_len()) = c;
        }
        self.length = new_len;
        true
    }

    /// Clear the string
    pub fn clear(&mut self) {
        self.length = 0;
    }

    /// Compare two unicode strings (case-sensitive)
    pub fn equals(&self, other: &UnicodeString) -> bool {
        if self.length != other.length {
            return false;
        }

        if self.length == 0 {
            return true;
        }

        self.as_slice() == other.as_slice()
    }

    /// Compare two unicode strings (case-insensitive, ASCII only)
    pub fn equals_ignore_case(&self, other: &UnicodeString) -> bool {
        if self.length != other.length {
            return false;
        }

        if self.length == 0 {
            return true;
        }

        let s1 = self.as_slice();
        let s2 = other.as_slice();

        for (a, b) in s1.iter().zip(s2.iter()) {
            let a_lower = if *a >= 'A' as u16 && *a <= 'Z' as u16 {
                *a + 32
            } else {
                *a
            };
            let b_lower = if *b >= 'A' as u16 && *b <= 'Z' as u16 {
                *b + 32
            } else {
                *b
            };
            if a_lower != b_lower {
                return false;
            }
        }

        true
    }

    /// Check if string starts with a prefix (case-insensitive)
    pub fn starts_with(&self, prefix: &UnicodeString) -> bool {
        if prefix.length > self.length {
            return false;
        }

        let s1 = self.as_slice();
        let s2 = prefix.as_slice();

        for (a, b) in s1.iter().zip(s2.iter()) {
            let a_lower = if *a >= 'A' as u16 && *a <= 'Z' as u16 {
                *a + 32
            } else {
                *a
            };
            let b_lower = if *b >= 'A' as u16 && *b <= 'Z' as u16 {
                *b + 32
            } else {
                *b
            };
            if a_lower != b_lower {
                return false;
            }
        }

        true
    }

    /// Find a character in the string
    pub fn find(&self, c: u16) -> Option<usize> {
        self.as_slice().iter().position(|&x| x == c)
    }

    /// Find last occurrence of a character
    pub fn rfind(&self, c: u16) -> Option<usize> {
        self.as_slice().iter().rposition(|&x| x == c)
    }

    /// Get a substring
    pub fn substring(&self, start: usize, len: usize) -> Option<UnicodeString> {
        let char_len = self.char_len();
        if start >= char_len {
            return None;
        }

        let actual_len = (char_len - start).min(len);
        Some(unsafe {
            UnicodeString::from_raw_parts(
                self.buffer.add(start),
                (actual_len * 2) as u16,
                (actual_len * 2) as u16,
            )
        })
    }
}

impl Default for UnicodeString {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for UnicodeString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnicodeString(\"")?;
        for &c in self.as_slice() {
            if c < 128 {
                write!(f, "{}", c as u8 as char)?;
            } else {
                write!(f, "\\u{:04x}", c)?;
            }
        }
        write!(f, "\")")
    }
}

/// ANSI string - single-byte characters
///
/// Equivalent to NT's ANSI_STRING / STRING
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AnsiString {
    /// Current length in bytes
    pub length: u16,
    /// Maximum length in bytes (buffer capacity)
    pub maximum_length: u16,
    /// Pointer to byte buffer
    pub buffer: *mut u8,
}

impl AnsiString {
    /// Create an empty ANSI string
    pub const fn empty() -> Self {
        Self {
            length: 0,
            maximum_length: 0,
            buffer: ptr::null_mut(),
        }
    }

    /// Create an ANSI string from a buffer
    pub fn from_buffer(buffer: &mut [u8]) -> Self {
        Self {
            length: 0,
            maximum_length: buffer.len() as u16,
            buffer: buffer.as_mut_ptr(),
        }
    }

    /// Create from raw parts
    ///
    /// # Safety
    /// The buffer must contain valid data up to `length` bytes
    pub unsafe fn from_raw_parts(buffer: *mut u8, length: u16, max_length: u16) -> Self {
        Self {
            length,
            maximum_length: max_length,
            buffer,
        }
    }

    /// Check if the string is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Get length in characters
    #[inline]
    pub fn len(&self) -> usize {
        self.length as usize
    }

    /// Get the string as a slice
    pub fn as_slice(&self) -> &[u8] {
        if self.buffer.is_null() || self.length == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(self.buffer, self.length as usize) }
        }
    }

    /// Get the string as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        if self.buffer.is_null() || self.length == 0 {
            &mut []
        } else {
            unsafe { slice::from_raw_parts_mut(self.buffer, self.length as usize) }
        }
    }

    /// Get as &str if valid UTF-8
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(self.as_slice()).ok()
    }

    /// Copy from a Rust &str
    pub fn copy_from_str(&mut self, s: &str) -> Option<usize> {
        if self.buffer.is_null() {
            return None;
        }

        let bytes = s.as_bytes();
        let copy_len = bytes.len().min(self.maximum_length as usize);

        if copy_len > 0 {
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), self.buffer, copy_len);
            }
        }
        self.length = copy_len as u16;
        Some(copy_len)
    }

    /// Copy from another ANSI string
    pub fn copy_from(&mut self, other: &AnsiString) -> bool {
        if self.buffer.is_null() || other.length > self.maximum_length {
            return false;
        }

        if !other.buffer.is_null() && other.length > 0 {
            unsafe {
                ptr::copy_nonoverlapping(other.buffer, self.buffer, other.length as usize);
            }
        }
        self.length = other.length;
        true
    }

    /// Clear the string
    pub fn clear(&mut self) {
        self.length = 0;
    }

    /// Compare two ANSI strings (case-sensitive)
    pub fn equals(&self, other: &AnsiString) -> bool {
        if self.length != other.length {
            return false;
        }
        self.as_slice() == other.as_slice()
    }

    /// Compare two ANSI strings (case-insensitive)
    pub fn equals_ignore_case(&self, other: &AnsiString) -> bool {
        if self.length != other.length {
            return false;
        }

        for (a, b) in self.as_slice().iter().zip(other.as_slice().iter()) {
            let a_lower = a.to_ascii_lowercase();
            let b_lower = b.to_ascii_lowercase();
            if a_lower != b_lower {
                return false;
            }
        }

        true
    }
}

impl Default for AnsiString {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for AnsiString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AnsiString(\"")?;
        for &c in self.as_slice() {
            if c >= 32 && c < 127 {
                write!(f, "{}", c as char)?;
            } else {
                write!(f, "\\x{:02x}", c)?;
            }
        }
        write!(f, "\")")
    }
}

/// Object Attributes - used for opening/creating kernel objects
///
/// Equivalent to NT's OBJECT_ATTRIBUTES
#[repr(C)]
pub struct ObjectAttributes {
    /// Size of this structure
    pub length: u32,
    /// Root directory handle (optional)
    pub root_directory: usize,
    /// Object name
    pub object_name: *mut UnicodeString,
    /// Attributes flags
    pub attributes: u32,
    /// Security descriptor (optional)
    pub security_descriptor: *mut u8,
    /// Security QoS (optional)
    pub security_quality_of_service: *mut u8,
}

/// Object attribute flags
pub mod obj_flags {
    pub const OBJ_INHERIT: u32 = 0x00000002;
    pub const OBJ_PERMANENT: u32 = 0x00000010;
    pub const OBJ_EXCLUSIVE: u32 = 0x00000020;
    pub const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;
    pub const OBJ_OPENIF: u32 = 0x00000080;
    pub const OBJ_OPENLINK: u32 = 0x00000100;
    pub const OBJ_KERNEL_HANDLE: u32 = 0x00000200;
    pub const OBJ_FORCE_ACCESS_CHECK: u32 = 0x00000400;
}

impl ObjectAttributes {
    /// Create new object attributes
    pub fn new(name: *mut UnicodeString, attributes: u32) -> Self {
        Self {
            length: core::mem::size_of::<Self>() as u32,
            root_directory: 0,
            object_name: name,
            attributes,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        }
    }

    /// Create object attributes with a root directory
    pub fn with_root(
        root: usize,
        name: *mut UnicodeString,
        attributes: u32,
    ) -> Self {
        Self {
            length: core::mem::size_of::<Self>() as u32,
            root_directory: root,
            object_name: name,
            attributes,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        }
    }
}

// NT API compatibility type aliases
#[allow(non_camel_case_types)]
pub type UNICODE_STRING = UnicodeString;
#[allow(non_camel_case_types)]
pub type PUNICODE_STRING = *mut UnicodeString;
#[allow(non_camel_case_types)]
pub type ANSI_STRING = AnsiString;
#[allow(non_camel_case_types)]
pub type STRING = AnsiString;
#[allow(non_camel_case_types)]
pub type OBJECT_ATTRIBUTES = ObjectAttributes;
#[allow(non_camel_case_types)]
pub type POBJECT_ATTRIBUTES = *mut ObjectAttributes;

/// Initialize a unicode string from a buffer (NT API)
#[inline]
pub fn rtl_init_unicode_string(dest: &mut UnicodeString, buffer: &mut [u16]) {
    *dest = UnicodeString::from_buffer(buffer);
}

/// Copy a unicode string (NT API)
#[inline]
pub fn rtl_copy_unicode_string(dest: &mut UnicodeString, src: &UnicodeString) -> bool {
    dest.copy_from(src)
}

/// Compare unicode strings (NT API)
#[inline]
pub fn rtl_equal_unicode_string(
    s1: &UnicodeString,
    s2: &UnicodeString,
    case_insensitive: bool,
) -> bool {
    if case_insensitive {
        s1.equals_ignore_case(s2)
    } else {
        s1.equals(s2)
    }
}

/// Compare unicode strings with prefix (NT API)
#[inline]
pub fn rtl_prefix_unicode_string(
    prefix: &UnicodeString,
    string: &UnicodeString,
    case_insensitive: bool,
) -> bool {
    if case_insensitive {
        string.starts_with(prefix)
    } else {
        if prefix.length > string.length {
            false
        } else {
            string.as_slice()[..prefix.char_len()] == prefix.as_slice()[..]
        }
    }
}

/// Append unicode string (NT API)
pub fn rtl_append_unicode_string_to_string(
    dest: &mut UnicodeString,
    src: &UnicodeString,
) -> bool {
    let new_len = dest.length + src.length;
    if new_len > dest.maximum_length || dest.buffer.is_null() {
        return false;
    }

    if !src.buffer.is_null() && src.length > 0 {
        unsafe {
            ptr::copy_nonoverlapping(
                src.buffer,
                dest.buffer.add(dest.char_len()),
                src.char_len(),
            );
        }
    }
    dest.length = new_len;
    true
}

/// Append unicode to ANSI (NT API)
pub fn rtl_append_unicode_to_string(dest: &mut AnsiString, src: &UnicodeString) -> bool {
    if dest.buffer.is_null() {
        return false;
    }

    let available = (dest.maximum_length - dest.length) as usize;
    let src_chars = src.char_len();

    if src_chars > available {
        return false;
    }

    // Simple conversion: just take low byte of each UTF-16 char
    let src_slice = src.as_slice();
    for (i, &c) in src_slice.iter().enumerate() {
        if i >= available {
            break;
        }
        unsafe {
            *dest.buffer.add(dest.length as usize + i) = c as u8;
        }
    }
    dest.length += src_chars as u16;
    true
}

/// Convert ANSI to Unicode (NT API)
pub fn rtl_ansi_string_to_unicode_string(
    dest: &mut UnicodeString,
    src: &AnsiString,
) -> bool {
    if dest.buffer.is_null() {
        return false;
    }

    let src_len = src.length as usize;
    let max_chars = (dest.maximum_length as usize) / 2;

    if src_len > max_chars {
        return false;
    }

    let src_slice = src.as_slice();
    for (i, &c) in src_slice.iter().enumerate() {
        unsafe {
            *dest.buffer.add(i) = c as u16;
        }
    }
    dest.length = (src_len * 2) as u16;
    true
}

/// Convert Unicode to ANSI (NT API)
pub fn rtl_unicode_string_to_ansi_string(
    dest: &mut AnsiString,
    src: &UnicodeString,
) -> bool {
    if dest.buffer.is_null() {
        return false;
    }

    let src_chars = src.char_len();
    if src_chars > dest.maximum_length as usize {
        return false;
    }

    let src_slice = src.as_slice();
    for (i, &c) in src_slice.iter().enumerate() {
        unsafe {
            *dest.buffer.add(i) = c as u8; // Simple truncation
        }
    }
    dest.length = src_chars as u16;
    true
}

/// Hash a unicode string (for hash tables)
pub fn rtl_hash_unicode_string(s: &UnicodeString, case_insensitive: bool) -> u32 {
    let mut hash: u32 = 0;

    for &c in s.as_slice() {
        let c = if case_insensitive && c >= 'A' as u16 && c <= 'Z' as u16 {
            c + 32
        } else {
            c
        };
        hash = hash.wrapping_mul(31).wrapping_add(c as u32);
    }

    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unicode_string_basic() {
        let mut buffer = [0u16; 32];
        let mut us = UnicodeString::from_buffer(&mut buffer);

        assert!(us.is_empty());
        assert_eq!(us.char_len(), 0);

        us.copy_from_str("Hello");
        assert!(!us.is_empty());
        assert_eq!(us.char_len(), 5);
        assert_eq!(us.length, 10); // 5 chars * 2 bytes
    }

    #[test]
    fn test_unicode_string_compare() {
        let mut buf1 = [0u16; 32];
        let mut buf2 = [0u16; 32];

        let mut us1 = UnicodeString::from_buffer(&mut buf1);
        let mut us2 = UnicodeString::from_buffer(&mut buf2);

        us1.copy_from_str("Hello");
        us2.copy_from_str("Hello");
        assert!(us1.equals(&us2));

        us2.copy_from_str("HELLO");
        assert!(!us1.equals(&us2));
        assert!(us1.equals_ignore_case(&us2));
    }

    #[test]
    fn test_ansi_string_basic() {
        let mut buffer = [0u8; 32];
        let mut as_ = AnsiString::from_buffer(&mut buffer);

        as_.copy_from_str("Test");
        assert_eq!(as_.len(), 4);
        assert_eq!(as_.as_str(), Some("Test"));
    }
}
