//! Environment Variable Handling
//!
//! Implements Windows environment variable APIs for getting, setting,
//! and expanding environment variables.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `base/win32/client/environ.c` - Environment functions
//! - `base/ntdll/ldrinit.c` - Process environment initialization

use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum environment variables
const MAX_ENV_VARS: usize = 256;

/// Maximum variable name length
const MAX_VAR_NAME: usize = 256;

/// Maximum variable value length
const MAX_VAR_VALUE: usize = 32767;

/// Maximum expanded string length
const MAX_EXPANDED_LENGTH: usize = 32767;

// ============================================================================
// Environment Variable Entry
// ============================================================================

/// Environment variable entry
#[derive(Debug)]
struct EnvVar {
    in_use: bool,
    name: [u8; MAX_VAR_NAME],
    value: [u8; 4096], // Reduced for static allocation
}

impl EnvVar {
    const fn new() -> Self {
        Self {
            in_use: false,
            name: [0u8; MAX_VAR_NAME],
            value: [0u8; 4096],
        }
    }
}

// ============================================================================
// State
// ============================================================================

static ENV_INITIALIZED: AtomicBool = AtomicBool::new(false);
static ENV_VARS: SpinLock<[EnvVar; MAX_ENV_VARS]> = SpinLock::new(
    [const { EnvVar::new() }; MAX_ENV_VARS]
);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize environment variable subsystem
pub fn init() {
    if ENV_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[ENVIRON] Initializing environment variables...");

    // Set up default environment variables
    set_default_environment();

    crate::serial_println!("[ENVIRON] Environment variables initialized");
}

/// Set up default environment variables
fn set_default_environment() {
    let defaults: &[(&[u8], &[u8])] = &[
        (b"ALLUSERSPROFILE", b"C:\\Documents and Settings\\All Users"),
        (b"APPDATA", b"C:\\Documents and Settings\\User\\Application Data"),
        (b"COMMONPROGRAMFILES", b"C:\\Program Files\\Common Files"),
        (b"COMPUTERNAME", b"NOSTALGIAOS"),
        (b"COMSPEC", b"C:\\Windows\\System32\\cmd.exe"),
        (b"HOMEDRIVE", b"C:"),
        (b"HOMEPATH", b"\\Documents and Settings\\User"),
        (b"LOCALAPPDATA", b"C:\\Documents and Settings\\User\\Local Settings\\Application Data"),
        (b"LOGONSERVER", b"\\\\NOSTALGIAOS"),
        (b"NUMBER_OF_PROCESSORS", b"1"),
        (b"OS", b"Windows_NT"),
        (b"PATH", b"C:\\Windows\\System32;C:\\Windows;C:\\Windows\\System32\\Wbem"),
        (b"PATHEXT", b".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"),
        (b"PROCESSOR_ARCHITECTURE", b"AMD64"),
        (b"PROCESSOR_IDENTIFIER", b"AMD64 Family 6 Model 0 Stepping 0, GenuineIntel"),
        (b"PROCESSOR_LEVEL", b"6"),
        (b"PROCESSOR_REVISION", b"0000"),
        (b"PROGRAMFILES", b"C:\\Program Files"),
        (b"PROMPT", b"$P$G"),
        (b"SYSTEMDRIVE", b"C:"),
        (b"SYSTEMROOT", b"C:\\Windows"),
        (b"TEMP", b"C:\\Documents and Settings\\User\\Local Settings\\Temp"),
        (b"TMP", b"C:\\Documents and Settings\\User\\Local Settings\\Temp"),
        (b"USERDOMAIN", b"NOSTALGIAOS"),
        (b"USERNAME", b"User"),
        (b"USERPROFILE", b"C:\\Documents and Settings\\User"),
        (b"WINDIR", b"C:\\Windows"),
    ];

    for &(name, value) in defaults {
        let _ = set_environment_variable(name, value);
    }
}

// ============================================================================
// Environment Variable Functions
// ============================================================================

/// Get an environment variable
pub fn get_environment_variable(name: &[u8], buffer: &mut [u8]) -> Option<usize> {
    let vars = ENV_VARS.lock();

    for var in vars.iter() {
        if var.in_use && name_matches(&var.name, name) {
            let value_len = str_len(&var.value);
            let copy_len = value_len.min(buffer.len().saturating_sub(1));

            buffer[..copy_len].copy_from_slice(&var.value[..copy_len]);
            if copy_len < buffer.len() {
                buffer[copy_len] = 0;
            }

            return Some(value_len);
        }
    }

    None
}

/// Set an environment variable
pub fn set_environment_variable(name: &[u8], value: &[u8]) -> bool {
    let mut vars = ENV_VARS.lock();

    // Check for empty value (delete)
    if value.is_empty() || (value.len() == 1 && value[0] == 0) {
        return delete_environment_variable_internal(&mut *vars, name);
    }

    // Look for existing variable
    for var in vars.iter_mut() {
        if var.in_use && name_matches(&var.name, name) {
            let value_len = str_len(value).min(var.value.len() - 1);
            var.value[..value_len].copy_from_slice(&value[..value_len]);
            var.value[value_len] = 0;
            return true;
        }
    }

    // Find free slot
    let slot_idx = vars.iter().position(|v| !v.in_use);
    let idx = match slot_idx {
        Some(i) => i,
        None => return false,
    };

    let var = &mut vars[idx];
    var.in_use = true;

    let name_len = str_len(name).min(MAX_VAR_NAME - 1);
    var.name[..name_len].copy_from_slice(&name[..name_len]);
    var.name[name_len] = 0;

    let value_len = str_len(value).min(var.value.len() - 1);
    var.value[..value_len].copy_from_slice(&value[..value_len]);
    var.value[value_len] = 0;

    true
}

/// Delete an environment variable
fn delete_environment_variable_internal(vars: &mut [EnvVar], name: &[u8]) -> bool {
    for var in vars.iter_mut() {
        if var.in_use && name_matches(&var.name, name) {
            var.in_use = false;
            return true;
        }
    }
    false
}

/// Delete an environment variable (public)
pub fn delete_environment_variable(name: &[u8]) -> bool {
    let mut vars = ENV_VARS.lock();
    delete_environment_variable_internal(&mut *vars, name)
}

// ============================================================================
// Environment String Expansion
// ============================================================================

/// Expand environment strings (e.g., %PATH% -> actual path)
pub fn expand_environment_strings(source: &[u8], dest: &mut [u8]) -> usize {
    let vars = ENV_VARS.lock();

    let source_len = str_len(source);
    let mut src_pos = 0;
    let mut dest_pos = 0;

    while src_pos < source_len && dest_pos < dest.len() - 1 {
        if source[src_pos] == b'%' {
            // Find closing %
            let var_start = src_pos + 1;
            let mut var_end = var_start;

            while var_end < source_len && source[var_end] != b'%' {
                var_end += 1;
            }

            if var_end < source_len && var_end > var_start {
                // Found a variable reference
                let var_name = &source[var_start..var_end];

                // Look up the variable
                let mut found = false;
                for var in vars.iter() {
                    if var.in_use && name_matches(&var.name, var_name) {
                        let value_len = str_len(&var.value);
                        let copy_len = value_len.min(dest.len() - dest_pos - 1);
                        dest[dest_pos..dest_pos + copy_len].copy_from_slice(&var.value[..copy_len]);
                        dest_pos += copy_len;
                        found = true;
                        break;
                    }
                }

                if !found {
                    // Variable not found, keep original text
                    let orig_len = var_end - src_pos + 1;
                    let copy_len = orig_len.min(dest.len() - dest_pos - 1);
                    dest[dest_pos..dest_pos + copy_len].copy_from_slice(&source[src_pos..src_pos + copy_len]);
                    dest_pos += copy_len;
                }

                src_pos = var_end + 1;
            } else {
                // No closing %, copy as-is
                dest[dest_pos] = source[src_pos];
                dest_pos += 1;
                src_pos += 1;
            }
        } else {
            dest[dest_pos] = source[src_pos];
            dest_pos += 1;
            src_pos += 1;
        }
    }

    dest[dest_pos] = 0;
    dest_pos
}

// ============================================================================
// Environment Block Functions
// ============================================================================

/// Get the environment block as a contiguous string
pub fn get_environment_strings(buffer: &mut [u8]) -> usize {
    let vars = ENV_VARS.lock();

    let mut pos = 0;

    for var in vars.iter() {
        if !var.in_use {
            continue;
        }

        let name_len = str_len(&var.name);
        let value_len = str_len(&var.value);

        // NAME=VALUE\0
        let entry_len = name_len + 1 + value_len + 1;

        if pos + entry_len >= buffer.len() {
            break;
        }

        buffer[pos..pos + name_len].copy_from_slice(&var.name[..name_len]);
        pos += name_len;
        buffer[pos] = b'=';
        pos += 1;
        buffer[pos..pos + value_len].copy_from_slice(&var.value[..value_len]);
        pos += value_len;
        buffer[pos] = 0;
        pos += 1;
    }

    // Double null terminator
    if pos < buffer.len() {
        buffer[pos] = 0;
        pos += 1;
    }

    pos
}

/// Free environment strings (no-op in this implementation)
pub fn free_environment_strings(_buffer: &[u8]) -> bool {
    true
}

// ============================================================================
// Path Environment Functions
// ============================================================================

/// Append to PATH environment variable
pub fn append_to_path(path: &[u8]) -> bool {
    let current = {
        let vars = ENV_VARS.lock();
        let mut current = [0u8; 4096];

        for var in vars.iter() {
            if var.in_use && name_matches(&var.name, b"PATH") {
                let len = str_len(&var.value);
                current[..len].copy_from_slice(&var.value[..len]);
                break;
            }
        }
        current
    };

    let current_len = str_len(&current);
    let path_len = str_len(path);

    if current_len + 1 + path_len >= 4096 {
        return false;
    }

    let mut new_path = [0u8; 4096];
    new_path[..current_len].copy_from_slice(&current[..current_len]);

    if current_len > 0 {
        new_path[current_len] = b';';
        new_path[current_len + 1..current_len + 1 + path_len].copy_from_slice(&path[..path_len]);
    } else {
        new_path[..path_len].copy_from_slice(&path[..path_len]);
    }

    set_environment_variable(b"PATH", &new_path)
}

/// Prepend to PATH environment variable
pub fn prepend_to_path(path: &[u8]) -> bool {
    let current = {
        let vars = ENV_VARS.lock();
        let mut current = [0u8; 4096];

        for var in vars.iter() {
            if var.in_use && name_matches(&var.name, b"PATH") {
                let len = str_len(&var.value);
                current[..len].copy_from_slice(&var.value[..len]);
                break;
            }
        }
        current
    };

    let current_len = str_len(&current);
    let path_len = str_len(path);

    if current_len + 1 + path_len >= 4096 {
        return false;
    }

    let mut new_path = [0u8; 4096];
    new_path[..path_len].copy_from_slice(&path[..path_len]);

    if current_len > 0 {
        new_path[path_len] = b';';
        new_path[path_len + 1..path_len + 1 + current_len].copy_from_slice(&current[..current_len]);
    }

    set_environment_variable(b"PATH", &new_path)
}

/// Search for executable in PATH
pub fn search_path(
    path: Option<&[u8]>,
    filename: &[u8],
    extension: Option<&[u8]>,
    buffer: &mut [u8],
) -> Option<usize> {
    // Get PATH to search
    let search_path = if let Some(p) = path {
        let mut sp = [0u8; 4096];
        let len = p.len().min(4095);
        sp[..len].copy_from_slice(&p[..len]);
        sp
    } else {
        let vars = ENV_VARS.lock();
        let mut sp = [0u8; 4096];

        for var in vars.iter() {
            if var.in_use && name_matches(&var.name, b"PATH") {
                let len = str_len(&var.value).min(4095);
                sp[..len].copy_from_slice(&var.value[..len]);
                break;
            }
        }
        sp
    };

    let path_len = str_len(&search_path);
    let filename_len = str_len(filename);
    let ext_len = extension.map(|e| str_len(e)).unwrap_or(0);

    // Parse PATH and search each directory
    let mut start = 0;
    while start < path_len {
        // Find end of this path component
        let mut end = start;
        while end < path_len && search_path[end] != b';' {
            end += 1;
        }

        if end > start {
            let dir = &search_path[start..end];
            let dir_len = end - start;

            // Build full path: dir\filename[.ext]
            let mut full_path = [0u8; 512];
            let mut pos = 0;

            // Copy directory
            let copy_len = dir_len.min(full_path.len() - 1);
            full_path[..copy_len].copy_from_slice(&dir[..copy_len]);
            pos += copy_len;

            // Add separator
            if pos < full_path.len() - 1 && full_path[pos - 1] != b'\\' {
                full_path[pos] = b'\\';
                pos += 1;
            }

            // Add filename
            let fn_copy = filename_len.min(full_path.len() - pos - 1);
            full_path[pos..pos + fn_copy].copy_from_slice(&filename[..fn_copy]);
            pos += fn_copy;

            // Add extension if provided and not already present
            if ext_len > 0 {
                let has_ext = filename.iter().any(|&c| c == b'.');
                if !has_ext && pos + ext_len < full_path.len() {
                    if let Some(ext) = extension {
                        full_path[pos..pos + ext_len].copy_from_slice(&ext[..ext_len]);
                        pos += ext_len;
                    }
                }
            }

            // For now, just return the first path we'd check
            // In a real implementation, we'd verify the file exists
            if pos < buffer.len() {
                buffer[..pos].copy_from_slice(&full_path[..pos]);
                buffer[pos] = 0;
                return Some(pos);
            }
        }

        start = end + 1;
    }

    None
}

// ============================================================================
// Special Environment Variables
// ============================================================================

/// Get current directory
pub fn get_current_directory(buffer: &mut [u8]) -> Option<usize> {
    get_environment_variable(b"CD", buffer)
        .or_else(|| get_environment_variable(b"PWD", buffer))
        .or_else(|| {
            // Default to root
            let default = b"C:\\";
            let len = default.len().min(buffer.len() - 1);
            buffer[..len].copy_from_slice(&default[..len]);
            buffer[len] = 0;
            Some(len)
        })
}

/// Set current directory
pub fn set_current_directory(path: &[u8]) -> bool {
    set_environment_variable(b"CD", path)
}

/// Get system directory
pub fn get_system_directory(buffer: &mut [u8]) -> Option<usize> {
    get_environment_variable(b"SYSTEMROOT", buffer)
        .map(|_| {
            // Append System32
            let len = str_len(buffer);
            let suffix = b"\\System32";
            let suffix_len = suffix.len();

            if len + suffix_len < buffer.len() {
                buffer[len..len + suffix_len].copy_from_slice(suffix);
                buffer[len + suffix_len] = 0;
                len + suffix_len
            } else {
                len
            }
        })
}

/// Get Windows directory
pub fn get_windows_directory(buffer: &mut [u8]) -> Option<usize> {
    get_environment_variable(b"WINDIR", buffer)
        .or_else(|| get_environment_variable(b"SYSTEMROOT", buffer))
}

/// Get temp path
pub fn get_temp_path(buffer: &mut [u8]) -> Option<usize> {
    get_environment_variable(b"TEMP", buffer)
        .or_else(|| get_environment_variable(b"TMP", buffer))
        .or_else(|| {
            let default = b"C:\\Temp";
            let len = default.len().min(buffer.len() - 1);
            buffer[..len].copy_from_slice(&default[..len]);
            buffer[len] = 0;
            Some(len)
        })
}

// ============================================================================
// Enumeration
// ============================================================================

/// Environment variable enumeration callback
pub type EnvVarCallback = fn(name: &[u8], value: &[u8], lparam: usize) -> bool;

/// Enumerate all environment variables
pub fn enum_environment_variables(callback: EnvVarCallback, lparam: usize) -> bool {
    let vars = ENV_VARS.lock();

    for var in vars.iter() {
        if var.in_use {
            let name_len = str_len(&var.name);
            let value_len = str_len(&var.value);

            if !callback(&var.name[..name_len], &var.value[..value_len], lparam) {
                return false;
            }
        }
    }

    true
}

/// Count environment variables
pub fn count_environment_variables() -> usize {
    let vars = ENV_VARS.lock();
    vars.iter().filter(|v| v.in_use).count()
}

// ============================================================================
// Helper Functions
// ============================================================================

fn str_len(s: &[u8]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

fn name_matches(stored: &[u8], search: &[u8]) -> bool {
    let stored_len = str_len(stored);
    let search_len = str_len(search);

    if stored_len != search_len {
        return false;
    }

    for i in 0..stored_len {
        if stored[i].to_ascii_uppercase() != search[i].to_ascii_uppercase() {
            return false;
        }
    }

    true
}

// ============================================================================
// Statistics
// ============================================================================

/// Environment statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct EnvironStats {
    pub initialized: bool,
    pub variable_count: u32,
}

/// Get environment statistics
pub fn get_stats() -> EnvironStats {
    let vars = ENV_VARS.lock();

    EnvironStats {
        initialized: ENV_INITIALIZED.load(Ordering::Relaxed),
        variable_count: vars.iter().filter(|v| v.in_use).count() as u32,
    }
}
