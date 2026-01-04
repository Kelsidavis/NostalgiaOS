//! Virtual File System (VFS) Layer
//!
//! Provides a unified interface for file system access across different
//! file system types. Currently supports FAT32.
//!
//! # Features
//! - Path-based file access (e.g., "C:\Windows\System32")
//! - Drive letter mapping
//! - Directory listing
//! - File reading

use crate::ke::SpinLock;
use super::fat32;

/// Maximum drives
pub const MAX_DRIVES: usize = 26; // A-Z

/// Maximum path components
pub const MAX_PATH_COMPONENTS: usize = 32;

/// Drive type
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DriveType {
    /// No drive mounted
    None,
    /// Local FAT32 volume
    Fat32,
    /// RAM disk
    RamDisk,
    /// CD-ROM (future)
    CdRom,
    /// Network drive (future)
    Network,
}

impl Default for DriveType {
    fn default() -> Self {
        DriveType::None
    }
}

/// Drive information
#[derive(Clone, Copy)]
pub struct DriveInfo {
    /// Drive type
    pub drive_type: DriveType,
    /// FAT32 slot (if applicable)
    pub fat32_slot: usize,
    /// Volume label
    pub label: [u8; 12],
    /// Total size in MB
    pub total_mb: u64,
    /// Free size in MB
    pub free_mb: u64,
}

impl DriveInfo {
    pub const fn empty() -> Self {
        Self {
            drive_type: DriveType::None,
            fat32_slot: 0,
            label: [0; 12],
            total_mb: 0,
            free_mb: 0,
        }
    }

    pub fn label_str(&self) -> &str {
        let len = self.label.iter().position(|&b| b == 0 || b == b' ').unwrap_or(11);
        core::str::from_utf8(&self.label[..len]).unwrap_or("")
    }

    /// Get display name (e.g., "Local Disk (C:)")
    pub fn display_name(&self, letter: char, buf: &mut [u8]) -> usize {
        let mut pos = 0;
        let label = self.label_str();

        if !label.is_empty() {
            for b in label.bytes() {
                if pos < buf.len() {
                    buf[pos] = b;
                    pos += 1;
                }
            }
        } else {
            let default_name = match self.drive_type {
                DriveType::Fat32 => "Local Disk",
                DriveType::RamDisk => "RAM Disk",
                DriveType::CdRom => "CD-ROM",
                DriveType::Network => "Network Drive",
                DriveType::None => "Unknown",
            };
            for b in default_name.bytes() {
                if pos < buf.len() {
                    buf[pos] = b;
                    pos += 1;
                }
            }
        }

        // Add " (X:)"
        if pos + 5 < buf.len() {
            buf[pos] = b' ';
            buf[pos + 1] = b'(';
            buf[pos + 2] = letter as u8;
            buf[pos + 3] = b':';
            buf[pos + 4] = b')';
            pos += 5;
        }

        pos
    }
}

/// Directory entry from VFS
#[derive(Clone, Copy)]
pub struct VfsEntry {
    /// File/directory name
    pub name: [u8; 256],
    pub name_len: usize,
    /// Is directory
    pub is_directory: bool,
    /// File size
    pub size: u64,
    /// Icon type hint
    pub icon_type: VfsIconType,
}

impl VfsEntry {
    pub const fn empty() -> Self {
        Self {
            name: [0; 256],
            name_len: 0,
            is_directory: false,
            size: 0,
            icon_type: VfsIconType::File,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }
}

/// Icon type hints for display
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VfsIconType {
    File,
    Folder,
    Drive,
    MyComputer,
    MyDocuments,
    RecycleBin,
    NetworkPlaces,
    ControlPanel,
    Executable,
    Document,
    Image,
    Audio,
    Video,
}

// ============================================================================
// Global State
// ============================================================================

/// Mounted drives (A-Z)
static mut DRIVES: [DriveInfo; MAX_DRIVES] = {
    const INIT: DriveInfo = DriveInfo::empty();
    [INIT; MAX_DRIVES]
};

/// VFS lock
static VFS_LOCK: SpinLock<()> = SpinLock::new(());

// ============================================================================
// Drive Operations
// ============================================================================

/// Get drive index from letter (A=0, B=1, ... Z=25)
pub fn drive_index(letter: char) -> Option<usize> {
    let upper = letter.to_ascii_uppercase();
    if upper >= 'A' && upper <= 'Z' {
        Some((upper as u8 - b'A') as usize)
    } else {
        None
    }
}

/// Get drive letter from index
pub fn drive_letter(index: usize) -> char {
    if index < 26 {
        (b'A' + index as u8) as char
    } else {
        '?'
    }
}

/// Mount a RAM disk to a drive letter
pub fn mount_ramdisk(letter: char, size_mb: u64) -> bool {
    let idx = match drive_index(letter) {
        Some(i) => i,
        None => return false,
    };

    let _guard = VFS_LOCK.lock();

    unsafe {
        let drive = &mut DRIVES[idx];
        drive.drive_type = DriveType::RamDisk;
        drive.fat32_slot = 0;
        drive.label = *b"RAMDISK     ";
        drive.total_mb = size_mb;
        drive.free_mb = size_mb;
    }

    crate::serial_println!("[VFS] Mounted RAM disk at {}:", letter);
    true
}

/// Mount a FAT32 volume to a drive letter
pub fn mount_fat32(letter: char, fat32_slot: usize) -> bool {
    let idx = match drive_index(letter) {
        Some(i) => i,
        None => return false,
    };

    let vol_info = match fat32::get_mounted_volume(fat32_slot) {
        Some(v) => v,
        None => return false,
    };

    let _guard = VFS_LOCK.lock();

    unsafe {
        let drive = &mut DRIVES[idx];
        drive.drive_type = DriveType::Fat32;
        drive.fat32_slot = fat32_slot;
        drive.label = vol_info.label;
        drive.total_mb = (vol_info.bpb.total_clusters() as u64 *
                         vol_info.bpb.bytes_per_cluster() as u64) / (1024 * 1024);
        if vol_info.free_clusters != 0xFFFFFFFF {
            drive.free_mb = (vol_info.free_clusters as u64 *
                            vol_info.bpb.bytes_per_cluster() as u64) / (1024 * 1024);
        }
    }

    crate::serial_println!("[VFS] Mounted FAT32 volume at {}:", letter);
    true
}

/// Unmount a drive
pub fn unmount(letter: char) -> bool {
    let idx = match drive_index(letter) {
        Some(i) => i,
        None => return false,
    };

    let _guard = VFS_LOCK.lock();

    unsafe {
        if DRIVES[idx].drive_type != DriveType::None {
            DRIVES[idx] = DriveInfo::empty();
            return true;
        }
    }

    false
}

/// Get drive info
pub fn get_drive(letter: char) -> Option<DriveInfo> {
    let idx = drive_index(letter)?;

    unsafe {
        let drive = &DRIVES[idx];
        if drive.drive_type != DriveType::None {
            Some(*drive)
        } else {
            None
        }
    }
}

/// List all mounted drives
pub fn list_drives(entries: &mut [VfsEntry]) -> usize {
    let _guard = VFS_LOCK.lock();

    let mut count = 0;

    unsafe {
        for (i, drive) in DRIVES.iter().enumerate() {
            if count >= entries.len() {
                break;
            }

            if drive.drive_type != DriveType::None {
                let entry = &mut entries[count];
                let letter = drive_letter(i);

                // Build display name
                entry.name_len = drive.display_name(letter, &mut entry.name);
                entry.is_directory = true;
                entry.size = drive.total_mb * 1024 * 1024;
                entry.icon_type = VfsIconType::Drive;

                crate::serial_println!("[VFS] list_drives: found {}:", letter);
                count += 1;
            }
        }
    }

    crate::serial_println!("[VFS] list_drives: returning {} drives", count);
    count
}

// ============================================================================
// Path Operations
// ============================================================================

/// Parse a path into drive letter and remaining path
pub fn parse_path(path: &str) -> (Option<char>, &str) {
    let bytes = path.as_bytes();

    // Check for drive letter (e.g., "C:" or "C:\")
    if bytes.len() >= 2 && bytes[1] == b':' {
        let letter = bytes[0] as char;
        if drive_index(letter).is_some() {
            let remaining = if bytes.len() >= 3 && (bytes[2] == b'\\' || bytes[2] == b'/') {
                &path[3..]
            } else if bytes.len() > 2 {
                &path[2..]
            } else {
                ""
            };
            return (Some(letter), remaining);
        }
    }

    // No drive letter
    (None, path)
}

/// Read directory contents
pub fn read_directory(path: &str, entries: &mut [VfsEntry]) -> usize {
    let (drive_letter, subpath) = parse_path(path);

    let drive_letter = match drive_letter {
        Some(l) => l,
        None => {
            // No drive specified - list all drives (My Computer)
            return list_drives(entries);
        }
    };

    let drive_idx = match drive_index(drive_letter) {
        Some(i) => i,
        None => return 0,
    };

    let drive = unsafe { &DRIVES[drive_idx] };

    match drive.drive_type {
        DriveType::Fat32 => {
            // Use FAT32 driver to read directory
            let slot = drive.fat32_slot;

            // Resolve path to get starting cluster
            let entry_info = match fat32::resolve_path(slot, subpath) {
                Some(e) => e,
                None => return 0,
            };

            if !entry_info.is_directory {
                return 0;
            }

            // Read directory entries
            let mut fat_entries = [fat32::DirEntryInfo::empty(); 256];
            let count = fat32::read_directory(slot, entry_info.first_cluster, &mut fat_entries);

            // Convert to VFS entries
            let result_count = count.min(entries.len());
            for i in 0..result_count {
                let fat_entry = &fat_entries[i];
                let vfs_entry = &mut entries[i];

                // Copy name
                vfs_entry.name_len = fat_entry.name_len;
                vfs_entry.name[..fat_entry.name_len].copy_from_slice(&fat_entry.name[..fat_entry.name_len]);

                vfs_entry.is_directory = fat_entry.is_directory;
                vfs_entry.size = fat_entry.size;

                // Determine icon type
                vfs_entry.icon_type = if fat_entry.is_directory {
                    VfsIconType::Folder
                } else {
                    guess_icon_type(fat_entry.name_str())
                };
            }

            result_count
        }
        DriveType::RamDisk => {
            // RAM disk not implemented yet
            0
        }
        _ => 0,
    }
}

/// Guess icon type from file extension
fn guess_icon_type(filename: &str) -> VfsIconType {
    let lower = filename.to_ascii_lowercase();

    if lower.ends_with(".exe") || lower.ends_with(".com") || lower.ends_with(".bat") {
        VfsIconType::Executable
    } else if lower.ends_with(".txt") || lower.ends_with(".doc") || lower.ends_with(".pdf") {
        VfsIconType::Document
    } else if lower.ends_with(".jpg") || lower.ends_with(".png") || lower.ends_with(".bmp") || lower.ends_with(".gif") {
        VfsIconType::Image
    } else if lower.ends_with(".mp3") || lower.ends_with(".wav") || lower.ends_with(".wma") {
        VfsIconType::Audio
    } else if lower.ends_with(".avi") || lower.ends_with(".mpg") || lower.ends_with(".wmv") {
        VfsIconType::Video
    } else {
        VfsIconType::File
    }
}

// ============================================================================
// Special Folders
// ============================================================================

/// Special folder type
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SpecialFolder {
    MyComputer,
    MyDocuments,
    RecycleBin,
    NetworkPlaces,
    ControlPanel,
    Desktop,
}

/// Get special folder contents
pub fn read_special_folder(folder: SpecialFolder, entries: &mut [VfsEntry]) -> usize {
    match folder {
        SpecialFolder::MyComputer => {
            let mut count = list_drives(entries);

            // If no drives mounted, show demo drives for display
            if count == 0 {
                // Add demo C: drive
                if count < entries.len() {
                    let entry = &mut entries[count];
                    let name = b"Local Disk (C:)";
                    entry.name[..name.len()].copy_from_slice(name);
                    entry.name_len = name.len();
                    entry.is_directory = true;
                    entry.size = 0;
                    entry.icon_type = VfsIconType::Drive;
                    count += 1;
                }

                // Add demo D: drive
                if count < entries.len() {
                    let entry = &mut entries[count];
                    let name = b"Data (D:)";
                    entry.name[..name.len()].copy_from_slice(name);
                    entry.name_len = name.len();
                    entry.is_directory = true;
                    entry.size = 0;
                    entry.icon_type = VfsIconType::Drive;
                    count += 1;
                }
            }

            // Add Control Panel entry
            if count < entries.len() {
                let entry = &mut entries[count];
                let name = b"Control Panel";
                entry.name[..name.len()].copy_from_slice(name);
                entry.name_len = name.len();
                entry.is_directory = true;
                entry.size = 0;
                entry.icon_type = VfsIconType::ControlPanel;
                count += 1;
            }

            count
        }
        SpecialFolder::Desktop => {
            let mut count = 0;

            // My Computer
            if count < entries.len() {
                let entry = &mut entries[count];
                let name = b"My Computer";
                entry.name[..name.len()].copy_from_slice(name);
                entry.name_len = name.len();
                entry.is_directory = true;
                entry.icon_type = VfsIconType::MyComputer;
                count += 1;
            }

            // My Documents
            if count < entries.len() {
                let entry = &mut entries[count];
                let name = b"My Documents";
                entry.name[..name.len()].copy_from_slice(name);
                entry.name_len = name.len();
                entry.is_directory = true;
                entry.icon_type = VfsIconType::MyDocuments;
                count += 1;
            }

            // Recycle Bin
            if count < entries.len() {
                let entry = &mut entries[count];
                let name = b"Recycle Bin";
                entry.name[..name.len()].copy_from_slice(name);
                entry.name_len = name.len();
                entry.is_directory = true;
                entry.icon_type = VfsIconType::RecycleBin;
                count += 1;
            }

            // Network Places
            if count < entries.len() {
                let entry = &mut entries[count];
                let name = b"My Network Places";
                entry.name[..name.len()].copy_from_slice(name);
                entry.name_len = name.len();
                entry.is_directory = true;
                entry.icon_type = VfsIconType::NetworkPlaces;
                count += 1;
            }

            count
        }
        SpecialFolder::MyDocuments => {
            // Try to read from real file system first
            let count = read_directory("C:\\Documents and Settings\\User\\My Documents", entries);
            if count > 0 {
                return count;
            }

            // Fallback: show demo folders
            let mut count = 0;
            let demo_folders = [
                ("My Pictures", VfsIconType::Folder),
                ("My Music", VfsIconType::Folder),
                ("My Videos", VfsIconType::Folder),
                ("Downloads", VfsIconType::Folder),
            ];

            for (name, icon) in demo_folders.iter() {
                if count >= entries.len() {
                    break;
                }
                let entry = &mut entries[count];
                let name_bytes = name.as_bytes();
                entry.name[..name_bytes.len()].copy_from_slice(name_bytes);
                entry.name_len = name_bytes.len();
                entry.is_directory = true;
                entry.icon_type = *icon;
                count += 1;
            }
            count
        }
        SpecialFolder::RecycleBin => {
            // Show empty recycle bin message
            if entries.len() > 0 {
                let entry = &mut entries[0];
                let name = b"(Empty)";
                entry.name[..name.len()].copy_from_slice(name);
                entry.name_len = name.len();
                entry.is_directory = false;
                entry.icon_type = VfsIconType::File;
                return 1;
            }
            0
        }
        SpecialFolder::NetworkPlaces => {
            // Show demo network items
            let mut count = 0;
            let items = [
                ("Entire Network", VfsIconType::NetworkPlaces),
                ("Workgroup", VfsIconType::Folder),
            ];

            for (name, icon) in items.iter() {
                if count >= entries.len() {
                    break;
                }
                let entry = &mut entries[count];
                let name_bytes = name.as_bytes();
                entry.name[..name_bytes.len()].copy_from_slice(name_bytes);
                entry.name_len = name_bytes.len();
                entry.is_directory = true;
                entry.icon_type = *icon;
                count += 1;
            }
            count
        }
        SpecialFolder::ControlPanel => {
            // Control Panel applets - show virtual entries
            let items = [
                ("Add/Remove Programs", VfsIconType::ControlPanel),
                ("Display", VfsIconType::ControlPanel),
                ("System", VfsIconType::ControlPanel),
                ("Network Connections", VfsIconType::ControlPanel),
                ("User Accounts", VfsIconType::ControlPanel),
                ("Sound and Audio", VfsIconType::ControlPanel),
                ("Date and Time", VfsIconType::ControlPanel),
            ];

            let mut count = 0;
            for (name, icon) in items.iter() {
                if count >= entries.len() {
                    break;
                }
                let entry = &mut entries[count];
                let name_bytes = name.as_bytes();
                entry.name[..name_bytes.len()].copy_from_slice(name_bytes);
                entry.name_len = name_bytes.len();
                entry.is_directory = false;
                entry.icon_type = *icon;
                count += 1;
            }

            count
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize VFS and auto-mount drives
pub fn init() {
    crate::serial_println!("[VFS] Initializing Virtual File System...");

    // Get mounted FAT32 volumes and assign drive letters
    let (vol_infos, count) = fat32::get_volume_info(MAX_DRIVES);

    // Assign drive letters starting from C:
    let mut next_letter = 'C';
    let mut drives_mounted = 0;

    for i in 0..count {
        let vol = &vol_infos[i];

        if next_letter > 'Z' {
            break;
        }

        if mount_fat32(next_letter, vol.slot as usize) {
            crate::serial_println!(
                "[VFS] Mounted {} as {}:",
                vol.label_str(),
                next_letter
            );
            drives_mounted += 1;
        }

        next_letter = ((next_letter as u8) + 1) as char;
    }

    // If no drives were mounted, create a RAM disk so explorer has something to show
    if drives_mounted == 0 {
        crate::serial_println!("[VFS] No FAT32 volumes found, creating RAM disk...");
        if mount_ramdisk('C', 64) {
            drives_mounted += 1;
        }
    }

    crate::serial_println!("[VFS] Virtual File System initialized ({} drives)", drives_mounted);
}

/// Get number of mounted drives
pub fn drive_count() -> usize {
    let _guard = VFS_LOCK.lock();
    unsafe {
        DRIVES.iter().filter(|d| d.drive_type != DriveType::None).count()
    }
}

/// Create a new directory at the specified path
/// Path format: "C:/folder/path" or "C:\folder\path"
pub fn create_directory(path: &str, name: &str) -> bool {
    // Parse path to get drive letter
    if path.len() < 2 {
        crate::serial_println!("[VFS] create_directory: path too short: {}", path);
        return false;
    }

    let drive_letter = path.chars().next().unwrap_or('C');
    let idx = match drive_index(drive_letter) {
        Some(i) => i,
        None => {
            crate::serial_println!("[VFS] create_directory: invalid drive letter: {}", drive_letter);
            return false;
        }
    };

    let drive = unsafe { &DRIVES[idx] };
    if drive.drive_type == DriveType::None {
        crate::serial_println!("[VFS] create_directory: drive {} not mounted", drive_letter);
        return false;
    }

    // Extract path within drive (skip "C:" or "C:/" prefix)
    let inner_path = if path.len() > 2 {
        let start = if path.as_bytes()[2] == b'/' || path.as_bytes()[2] == b'\\' { 3 } else { 2 };
        &path[start..]
    } else {
        ""
    };

    crate::serial_println!("[VFS] create_directory: drive={} slot={} inner='{}' name='{}'",
        drive_letter, drive.fat32_slot, inner_path, name);

    match drive.drive_type {
        DriveType::Fat32 => {
            fat32::create_directory(drive.fat32_slot, inner_path, name)
        }
        _ => {
            crate::serial_println!("[VFS] create_directory: unsupported drive type");
            false
        }
    }
}

/// Open a file for reading
/// Returns file handle index, or None if file doesn't exist
pub fn open_file(path: &str) -> Option<usize> {
    let (drive_letter, subpath) = parse_path(path);

    let drive_letter = drive_letter?;
    let drive_idx = drive_index(drive_letter)?;

    let drive = unsafe { &DRIVES[drive_idx] };
    if drive.drive_type == DriveType::None {
        return None;
    }

    match drive.drive_type {
        DriveType::Fat32 => {
            fat32::open_file(drive.fat32_slot, subpath)
        }
        _ => None,
    }
}

/// Read from an open file
pub fn read_file(handle: usize, buf: &mut [u8]) -> usize {
    fat32::read_file(handle, buf)
}

/// Close an open file
pub fn close_file(handle: usize) {
    fat32::close_file(handle);
}

/// Get file size from path
pub fn get_file_size(path: &str) -> Option<u64> {
    let (drive_letter, subpath) = parse_path(path);

    let drive_letter = drive_letter?;
    let drive_idx = drive_index(drive_letter)?;

    let drive = unsafe { &DRIVES[drive_idx] };
    if drive.drive_type == DriveType::None {
        return None;
    }

    match drive.drive_type {
        DriveType::Fat32 => {
            let entry = fat32::resolve_path(drive.fat32_slot, subpath)?;
            if entry.is_directory {
                None
            } else {
                Some(entry.size)
            }
        }
        _ => None,
    }
}

/// Check if a file exists
pub fn file_exists(path: &str) -> bool {
    let (drive_letter, subpath) = parse_path(path);

    let drive_letter = match drive_letter {
        Some(l) => l,
        None => return false,
    };

    let drive_idx = match drive_index(drive_letter) {
        Some(i) => i,
        None => return false,
    };

    let drive = unsafe { &DRIVES[drive_idx] };
    if drive.drive_type == DriveType::None {
        return false;
    }

    match drive.drive_type {
        DriveType::Fat32 => {
            fat32::resolve_path(drive.fat32_slot, subpath).is_some()
        }
        _ => false,
    }
}

/// Create a new file at the specified path
/// Path format: "C:/folder/path" or "C:\folder\path"
pub fn create_file(path: &str, name: &str) -> bool {
    // Parse path to get drive letter
    if path.len() < 2 {
        crate::serial_println!("[VFS] create_file: path too short: {}", path);
        return false;
    }

    let drive_letter = path.chars().next().unwrap_or('C');
    let idx = match drive_index(drive_letter) {
        Some(i) => i,
        None => {
            crate::serial_println!("[VFS] create_file: invalid drive letter: {}", drive_letter);
            return false;
        }
    };

    let drive = unsafe { &DRIVES[idx] };
    if drive.drive_type == DriveType::None {
        crate::serial_println!("[VFS] create_file: drive {} not mounted", drive_letter);
        return false;
    }

    // Extract path within drive (skip "C:" or "C:/" prefix)
    let inner_path = if path.len() > 2 {
        let start = if path.as_bytes()[2] == b'/' || path.as_bytes()[2] == b'\\' { 3 } else { 2 };
        &path[start..]
    } else {
        ""
    };

    match drive.drive_type {
        DriveType::Fat32 => {
            fat32::create_file(drive.fat32_slot, inner_path, name)
        }
        _ => {
            crate::serial_println!("[VFS] create_file: unsupported drive type");
            false
        }
    }
}

/// Delete a file at the specified path
/// Path format: "C:/folder/file.txt" or "C:\folder\file.txt"
pub fn delete_file(path: &str) -> bool {
    use crate::fs;

    // Convert forward slashes to backslashes for fs module
    let mut path_buf = [0u8; 256];
    let mut len = 0;
    for b in path.bytes() {
        if len < 255 {
            path_buf[len] = if b == b'/' { b'\\' } else { b };
            len += 1;
        }
    }
    let converted = core::str::from_utf8(&path_buf[..len]).unwrap_or(path);

    match fs::delete(converted) {
        Ok(()) => {
            crate::serial_println!("[VFS] Deleted: {}", path);
            true
        }
        Err(e) => {
            crate::serial_println!("[VFS] delete_file failed: {:?}", e);
            false
        }
    }
}

/// Rename a file or directory
/// old_path and new_path format: "C:/folder/old.txt" or "C:\folder\new.txt"
pub fn rename_file(old_path: &str, new_path: &str) -> bool {
    use crate::fs;

    // Convert forward slashes to backslashes for fs module
    let mut old_buf = [0u8; 256];
    let mut old_len = 0;
    for b in old_path.bytes() {
        if old_len < 255 {
            old_buf[old_len] = if b == b'/' { b'\\' } else { b };
            old_len += 1;
        }
    }
    let old_converted = core::str::from_utf8(&old_buf[..old_len]).unwrap_or(old_path);

    let mut new_buf = [0u8; 256];
    let mut new_len = 0;
    for b in new_path.bytes() {
        if new_len < 255 {
            new_buf[new_len] = if b == b'/' { b'\\' } else { b };
            new_len += 1;
        }
    }
    let new_converted = core::str::from_utf8(&new_buf[..new_len]).unwrap_or(new_path);

    match fs::rename(old_converted, new_converted) {
        Ok(()) => {
            crate::serial_println!("[VFS] Renamed: {} -> {}", old_path, new_path);
            true
        }
        Err(e) => {
            crate::serial_println!("[VFS] rename_file failed: {:?}", e);
            false
        }
    }
}

/// Copy a file from source to destination
/// src_path and dst_path format: "C:/folder/src.txt", "C:/folder/dst.txt"
pub fn copy_file(src_path: &str, dst_path: &str) -> bool {
    use crate::fs;

    // Convert forward slashes to backslashes for fs module
    let mut src_buf = [0u8; 256];
    let mut src_len = 0;
    for b in src_path.bytes() {
        if src_len < 255 {
            src_buf[src_len] = if b == b'/' { b'\\' } else { b };
            src_len += 1;
        }
    }
    let src_converted = core::str::from_utf8(&src_buf[..src_len]).unwrap_or(src_path);

    let mut dst_buf = [0u8; 256];
    let mut dst_len = 0;
    for b in dst_path.bytes() {
        if dst_len < 255 {
            dst_buf[dst_len] = if b == b'/' { b'\\' } else { b };
            dst_len += 1;
        }
    }
    let dst_converted = core::str::from_utf8(&dst_buf[..dst_len]).unwrap_or(dst_path);

    match fs::copy(src_converted, dst_converted) {
        Ok(bytes) => {
            crate::serial_println!("[VFS] Copied {} bytes: {} -> {}", bytes, src_path, dst_path);
            true
        }
        Err(e) => {
            crate::serial_println!("[VFS] copy_file failed: {:?}", e);
            false
        }
    }
}
