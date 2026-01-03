//! Object Manager Symbolic Links
//!
//! Implements symbolic link objects for the object namespace:
//! - NtCreateSymbolicLinkObject: Create a symbolic link
//! - NtOpenSymbolicLinkObject: Open an existing symbolic link
//! - NtQuerySymbolicLinkObject: Query the link target
//! - Symbolic link parsing and resolution
//!
//! Symbolic links provide indirection in the object namespace,
//! allowing names like "\DosDevices\C:" to redirect to "\Device\HarddiskVolume1"
//!
//! Based on Windows Server 2003 base/ntos/ob/oblink.c

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::RwLock;

/// Symbolic link object signature
pub const SYMLINK_OBJECT_SIGNATURE: u32 = 0x4B4E4C53; // 'SLNK'

/// Symbolic link object flags
pub mod symlink_flags {
    /// Link was created by kernel
    pub const KERNEL_CREATED: u32 = 0x01;
    /// Link is permanent (cannot be deleted when handle count goes to 0)
    pub const PERMANENT: u32 = 0x02;
    /// Link represents a DOS device
    pub const DOS_DEVICE: u32 = 0x04;
    /// Link target has been resolved
    pub const TARGET_RESOLVED: u32 = 0x08;
}

/// Access rights for symbolic link objects
pub mod symlink_access {
    pub const SYMBOLIC_LINK_QUERY: u32 = 0x0001;
    pub const SYMBOLIC_LINK_SET: u32 = 0x0002;
    pub const SYMBOLIC_LINK_ALL_ACCESS: u32 = 0x000F0003;
}

/// Symbolic link object
#[derive(Debug)]
pub struct ObjectSymbolicLink {
    /// Signature for validation
    pub signature: u32,
    /// Creation time (100ns intervals since 1601)
    pub creation_time: i64,
    /// Link target string
    pub link_target: String,
    /// Remaining path after target (for partial resolution)
    pub link_target_remaining: String,
    /// Resolved target object (if any)
    pub link_target_object: Option<usize>,
    /// DOS device drive index (0-25 for A-Z, 0 if not a drive)
    pub dos_device_drive_index: u8,
    /// Flags
    pub flags: AtomicU32,
    /// Reference count
    pub reference_count: AtomicU32,
}

impl ObjectSymbolicLink {
    /// Create a new symbolic link object
    pub fn new(target: &str) -> Self {
        Self {
            signature: SYMLINK_OBJECT_SIGNATURE,
            creation_time: crate::rtl::rtl_get_system_time(),
            link_target: String::from(target),
            link_target_remaining: String::new(),
            link_target_object: None,
            dos_device_drive_index: 0,
            flags: AtomicU32::new(0),
            reference_count: AtomicU32::new(1),
        }
    }

    /// Create a new symbolic link for a DOS device
    pub fn new_dos_device(drive_letter: char, target: &str) -> Self {
        let mut link = Self::new(target);
        if drive_letter.is_ascii_alphabetic() {
            link.dos_device_drive_index = (drive_letter.to_ascii_uppercase() as u8) - b'A' + 1;
            link.flags.fetch_or(symlink_flags::DOS_DEVICE, Ordering::Relaxed);
        }
        link
    }

    /// Get the link target
    pub fn get_target(&self) -> &str {
        &self.link_target
    }

    /// Set the link target
    pub fn set_target(&mut self, target: &str) {
        self.link_target = String::from(target);
        self.link_target_object = None;
        self.flags.fetch_and(!symlink_flags::TARGET_RESOLVED, Ordering::Relaxed);
    }

    /// Check if this is a DOS device link
    pub fn is_dos_device(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & symlink_flags::DOS_DEVICE != 0
    }

    /// Check if the link is permanent
    pub fn is_permanent(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & symlink_flags::PERMANENT != 0
    }

    /// Make the link permanent
    pub fn make_permanent(&self) {
        self.flags.fetch_or(symlink_flags::PERMANENT, Ordering::Relaxed);
    }

    /// Increment reference count
    pub fn reference(&self) -> u32 {
        self.reference_count.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Decrement reference count
    pub fn dereference(&self) -> u32 {
        self.reference_count.fetch_sub(1, Ordering::AcqRel) - 1
    }

    /// Get reference count
    pub fn ref_count(&self) -> u32 {
        self.reference_count.load(Ordering::Acquire)
    }
}

/// Symbolic link table entry
struct SymlinkEntry {
    /// Link name (without leading backslash)
    name: String,
    /// The symbolic link object
    link: ObjectSymbolicLink,
}

/// Global symbolic link table
static SYMLINK_TABLE: RwLock<Vec<SymlinkEntry>> = RwLock::new(Vec::new());

/// Statistics
static SYMLINK_COUNT: AtomicU32 = AtomicU32::new(0);
static SYMLINK_LOOKUPS: AtomicU32 = AtomicU32::new(0);
static SYMLINK_HITS: AtomicU32 = AtomicU32::new(0);

/// Create a symbolic link in the object namespace
pub fn ob_create_symbolic_link(name: &str, target: &str) -> i32 {
    ob_create_symbolic_link_ex(name, target, 0)
}

/// Create a symbolic link with flags
pub fn ob_create_symbolic_link_ex(name: &str, target: &str, flags: u32) -> i32 {
    // Validate parameters
    if name.is_empty() || target.is_empty() {
        return -1073741811; // STATUS_INVALID_PARAMETER
    }

    // Normalize the name (remove leading backslash for storage)
    let normalized_name = if name.starts_with('\\') {
        &name[1..]
    } else {
        name
    };

    // Check if link already exists
    {
        let table = SYMLINK_TABLE.read();
        for entry in table.iter() {
            if entry.name.eq_ignore_ascii_case(normalized_name) {
                return -1073741790; // STATUS_OBJECT_NAME_COLLISION
            }
        }
    }

    // Create the new link
    let mut link = ObjectSymbolicLink::new(target);
    link.flags.store(flags, Ordering::Relaxed);

    // Add to table
    {
        let mut table = SYMLINK_TABLE.write();
        table.push(SymlinkEntry {
            name: String::from(normalized_name),
            link,
        });
    }

    SYMLINK_COUNT.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[OB] Created symbolic link: \\{} -> {}", normalized_name, target);

    0 // STATUS_SUCCESS
}

/// Create a DOS device symbolic link (e.g., C: -> \Device\HarddiskVolume1)
pub fn ob_create_dos_device_link(drive_letter: char, target: &str) -> i32 {
    if !drive_letter.is_ascii_alphabetic() {
        return -1073741811; // STATUS_INVALID_PARAMETER
    }

    let name = alloc::format!("DosDevices\\{}:", drive_letter.to_ascii_uppercase());

    // Normalize the name
    let normalized_name = if name.starts_with('\\') {
        &name[1..]
    } else {
        &name
    };

    // Check if link already exists
    {
        let table = SYMLINK_TABLE.read();
        for entry in table.iter() {
            if entry.name.eq_ignore_ascii_case(normalized_name) {
                return -1073741790; // STATUS_OBJECT_NAME_COLLISION
            }
        }
    }

    // Create the new DOS device link
    let link = ObjectSymbolicLink::new_dos_device(drive_letter, target);

    // Add to table
    {
        let mut table = SYMLINK_TABLE.write();
        table.push(SymlinkEntry {
            name: String::from(normalized_name),
            link,
        });
    }

    SYMLINK_COUNT.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[OB] Created DOS device link: \\{} -> {}", normalized_name, target);

    0 // STATUS_SUCCESS
}

/// Delete a symbolic link
pub fn ob_delete_symbolic_link(name: &str) -> i32 {
    let normalized_name = if name.starts_with('\\') {
        &name[1..]
    } else {
        name
    };

    let mut table = SYMLINK_TABLE.write();

    for i in 0..table.len() {
        if table[i].name.eq_ignore_ascii_case(normalized_name) {
            // Check if link is permanent
            if table[i].link.is_permanent() {
                return -1073741800; // STATUS_CANNOT_DELETE
            }

            table.remove(i);
            SYMLINK_COUNT.fetch_sub(1, Ordering::Relaxed);
            return 0; // STATUS_SUCCESS
        }
    }

    -1073741772 // STATUS_OBJECT_NAME_NOT_FOUND
}

/// Query a symbolic link target
pub fn ob_query_symbolic_link(name: &str) -> Option<String> {
    SYMLINK_LOOKUPS.fetch_add(1, Ordering::Relaxed);

    let normalized_name = if name.starts_with('\\') {
        &name[1..]
    } else {
        name
    };

    let table = SYMLINK_TABLE.read();

    for entry in table.iter() {
        if entry.name.eq_ignore_ascii_case(normalized_name) {
            SYMLINK_HITS.fetch_add(1, Ordering::Relaxed);
            return Some(entry.link.link_target.clone());
        }
    }

    None
}

/// Parse and resolve a symbolic link in a path
/// Returns the resolved path or None if no symbolic link found
pub fn ob_parse_symbolic_link(path: &str) -> Option<String> {
    SYMLINK_LOOKUPS.fetch_add(1, Ordering::Relaxed);

    // Remove leading backslash for comparison
    let path_normalized = if path.starts_with('\\') {
        &path[1..]
    } else {
        path
    };

    let table = SYMLINK_TABLE.read();

    // Find the longest matching prefix
    let mut best_match: Option<(&str, &str)> = None;
    let mut best_match_len = 0;

    for entry in table.iter() {
        let name = &entry.name;
        let name_len = name.len();

        // Check if this link name is a prefix of our path
        if path_normalized.len() >= name_len {
            let path_prefix = &path_normalized[..name_len];
            if path_prefix.eq_ignore_ascii_case(name) {
                // Check that it's a complete component match
                if path_normalized.len() == name_len ||
                   path_normalized.as_bytes()[name_len] == b'\\' {
                    if name_len > best_match_len {
                        best_match = Some((name, &entry.link.link_target));
                        best_match_len = name_len;
                    }
                }
            }
        }
    }

    if let Some((matched_prefix, target)) = best_match {
        SYMLINK_HITS.fetch_add(1, Ordering::Relaxed);

        // Construct the resolved path
        let remaining = &path_normalized[matched_prefix.len()..];
        let mut resolved = String::from(target);

        if !remaining.is_empty() {
            if !resolved.ends_with('\\') && !remaining.starts_with('\\') {
                resolved.push('\\');
            }
            if remaining.starts_with('\\') {
                resolved.push_str(&remaining[1..]);
            } else {
                resolved.push_str(remaining);
            }
        }

        return Some(resolved);
    }

    None
}

/// Resolve a path by following all symbolic links (up to a limit)
pub fn ob_resolve_symbolic_links(path: &str, max_depth: u32) -> String {
    let mut current = String::from(path);
    let mut depth = 0;

    while depth < max_depth {
        if let Some(resolved) = ob_parse_symbolic_link(&current) {
            current = resolved;
            depth += 1;
        } else {
            break;
        }
    }

    current
}

/// Check if a path contains a symbolic link
pub fn ob_is_symbolic_link(name: &str) -> bool {
    let normalized_name = if name.starts_with('\\') {
        &name[1..]
    } else {
        name
    };

    let table = SYMLINK_TABLE.read();

    for entry in table.iter() {
        if entry.name.eq_ignore_ascii_case(normalized_name) {
            return true;
        }
    }

    false
}

/// Get symbolic link statistics
pub fn ob_get_symlink_stats() -> (u32, u32, u32) {
    (
        SYMLINK_COUNT.load(Ordering::Relaxed),
        SYMLINK_LOOKUPS.load(Ordering::Relaxed),
        SYMLINK_HITS.load(Ordering::Relaxed),
    )
}

/// List all symbolic links (for debugging)
pub fn ob_list_symbolic_links() -> Vec<(String, String)> {
    let table = SYMLINK_TABLE.read();
    let mut result = Vec::with_capacity(table.len());

    for entry in table.iter() {
        result.push((
            alloc::format!("\\{}", entry.name),
            entry.link.link_target.clone(),
        ));
    }

    result
}

/// Initialize symbolic link subsystem
pub fn obp_symlink_init() {
    // Create standard symbolic links
    crate::serial_println!("[OB-SYMLINK] Creating standard symlinks...");

    // DosDevices aliases
    crate::serial_println!("[OB-SYMLINK] Creating ??...");
    let _ = ob_create_symbolic_link("??", "\\DosDevices");
    crate::serial_println!("[OB-SYMLINK] Creating GLOBAL??...");
    let _ = ob_create_symbolic_link("GLOBAL??", "\\DosDevices");

    // Common device links
    crate::serial_println!("[OB-SYMLINK] Creating device links...");
    let _ = ob_create_symbolic_link("DosDevices\\NUL", "\\Device\\Null");
    let _ = ob_create_symbolic_link("DosDevices\\CON", "\\Device\\Console");
    let _ = ob_create_symbolic_link("DosDevices\\AUX", "\\Device\\Serial0");
    let _ = ob_create_symbolic_link("DosDevices\\PRN", "\\Device\\Parallel0");

    // PhysicalDrive links (for raw disk access)
    crate::serial_println!("[OB-SYMLINK] Creating PhysicalDrive0...");
    let _ = ob_create_symbolic_link("DosDevices\\PhysicalDrive0", "\\Device\\Harddisk0\\Partition0");

    crate::serial_println!("[OB] Symbolic link subsystem initialized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_symbolic_link() {
        let result = ob_create_symbolic_link("\\Test\\Link", "\\Device\\TestDevice");
        assert_eq!(result, 0);

        let target = ob_query_symbolic_link("\\Test\\Link");
        assert_eq!(target, Some(String::from("\\Device\\TestDevice")));
    }

    #[test]
    fn test_parse_symbolic_link() {
        ob_create_symbolic_link("\\DosDevices\\C:", "\\Device\\HarddiskVolume1");

        let resolved = ob_parse_symbolic_link("\\DosDevices\\C:\\Windows\\System32");
        assert!(resolved.is_some());
        assert!(resolved.unwrap().contains("HarddiskVolume1"));
    }
}
