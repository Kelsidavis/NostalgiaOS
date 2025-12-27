//! Mount Point Management
//!
//! Manages file system mount points, providing:
//! - Drive letter mapping (C:, D:, etc.)
//! - NT device path support (\\Device\\HarddiskVolume1)
//! - Volume mounting and unmounting
//!
//! # Mount Table
//! Maps drive letters to file system instances and device paths.

use crate::ke::SpinLock;
use crate::fs::vfs::{FsStatus, FsType};

/// Maximum mount points
pub const MAX_MOUNT_POINTS: usize = 26;  // A-Z

/// Maximum device path length
pub const MAX_DEVICE_PATH: usize = 128;

/// Mount flags
pub mod mount_flags {
    /// Read-only mount
    pub const MF_READONLY: u32 = 0x0001;
    /// System volume
    pub const MF_SYSTEM: u32 = 0x0002;
    /// Boot volume
    pub const MF_BOOT: u32 = 0x0004;
    /// Removable media
    pub const MF_REMOVABLE: u32 = 0x0008;
    /// Network volume
    pub const MF_NETWORK: u32 = 0x0010;
    /// RAM disk
    pub const MF_RAMDISK: u32 = 0x0020;
}

/// Mount point entry
#[derive(Clone, Copy)]
pub struct MountPoint {
    /// Is this entry active
    pub active: bool,
    /// Drive letter (A-Z, 0 for none)
    pub drive_letter: u8,
    /// File system type
    pub fs_type: FsType,
    /// File system index (in VFS)
    pub fs_index: u16,
    /// Mount flags
    pub flags: u32,
    /// Device path (NT style)
    pub device_path: [u8; MAX_DEVICE_PATH],
    /// Device path length
    pub device_path_len: u8,
    /// Volume label
    pub volume_label: [u8; 16],
    /// Volume serial number
    pub volume_serial: u32,
    /// Root vnode ID
    pub root_vnode: u64,
}

impl MountPoint {
    /// Create empty mount point
    pub const fn empty() -> Self {
        Self {
            active: false,
            drive_letter: 0,
            fs_type: FsType::Unknown,
            fs_index: 0,
            flags: 0,
            device_path: [0; MAX_DEVICE_PATH],
            device_path_len: 0,
            volume_label: [0; 16],
            volume_serial: 0,
            root_vnode: 0,
        }
    }

    /// Check if read-only
    pub fn is_readonly(&self) -> bool {
        (self.flags & mount_flags::MF_READONLY) != 0
    }

    /// Check if system volume
    pub fn is_system(&self) -> bool {
        (self.flags & mount_flags::MF_SYSTEM) != 0
    }

    /// Check if boot volume
    pub fn is_boot(&self) -> bool {
        (self.flags & mount_flags::MF_BOOT) != 0
    }

    /// Get device path as string
    pub fn device_path_str(&self) -> &str {
        core::str::from_utf8(&self.device_path[..self.device_path_len as usize]).unwrap_or("")
    }

    /// Get volume label as string
    pub fn volume_label_str(&self) -> &str {
        let len = self.volume_label.iter()
            .position(|&b| b == 0)
            .unwrap_or(16);
        core::str::from_utf8(&self.volume_label[..len]).unwrap_or("")
    }

    /// Set device path
    pub fn set_device_path(&mut self, path: &str) {
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_DEVICE_PATH);
        self.device_path[..len].copy_from_slice(&bytes[..len]);
        self.device_path_len = len as u8;
    }

    /// Set volume label
    pub fn set_volume_label(&mut self, label: &str) {
        let bytes = label.as_bytes();
        let len = bytes.len().min(16);
        self.volume_label = [0; 16];
        self.volume_label[..len].copy_from_slice(&bytes[..len]);
    }
}

impl Default for MountPoint {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Mount Table
// ============================================================================

/// Mount table (indexed by drive letter - 'A')
static mut MOUNT_TABLE: [MountPoint; MAX_MOUNT_POINTS] = {
    const INIT: MountPoint = MountPoint::empty();
    [INIT; MAX_MOUNT_POINTS]
};

/// Mount table lock
static MOUNT_LOCK: SpinLock<()> = SpinLock::new(());

// ============================================================================
// Mount Operations
// ============================================================================

/// Mount a file system at a drive letter
pub fn mount(
    drive_letter: char,
    fs_type: FsType,
    fs_index: u16,
    device_path: &str,
    flags: u32,
) -> Result<(), FsStatus> {
    let drive = drive_letter.to_ascii_uppercase();
    if drive < 'A' || drive > 'Z' {
        return Err(FsStatus::InvalidPath);
    }

    let index = (drive as u8 - b'A') as usize;

    let _guard = MOUNT_LOCK.lock();

    unsafe {
        if MOUNT_TABLE[index].active {
            return Err(FsStatus::AlreadyExists);
        }

        let mp = &mut MOUNT_TABLE[index];
        mp.active = true;
        mp.drive_letter = drive as u8;
        mp.fs_type = fs_type;
        mp.fs_index = fs_index;
        mp.flags = flags;
        mp.set_device_path(device_path);
        mp.root_vnode = 0;  // Root of file system

        crate::serial_println!("[FS] Mounted {}:\\ -> {}", drive, device_path);
        Ok(())
    }
}

/// Unmount a file system
pub fn unmount(drive_letter: char) -> Result<(), FsStatus> {
    let drive = drive_letter.to_ascii_uppercase();
    if drive < 'A' || drive > 'Z' {
        return Err(FsStatus::InvalidPath);
    }

    let index = (drive as u8 - b'A') as usize;

    let _guard = MOUNT_LOCK.lock();

    unsafe {
        if !MOUNT_TABLE[index].active {
            return Err(FsStatus::NotMounted);
        }

        // Check if system/boot volume
        let mp = &MOUNT_TABLE[index];
        if mp.is_system() || mp.is_boot() {
            return Err(FsStatus::DeviceBusy);
        }

        MOUNT_TABLE[index] = MountPoint::empty();

        crate::serial_println!("[FS] Unmounted {}:\\", drive);
        Ok(())
    }
}

/// Get mount point by drive letter
pub fn get_mount_point(drive_letter: char) -> Option<MountPoint> {
    let drive = drive_letter.to_ascii_uppercase();
    if drive < 'A' || drive > 'Z' {
        return None;
    }

    let index = (drive as u8 - b'A') as usize;

    let _guard = MOUNT_LOCK.lock();

    unsafe {
        if MOUNT_TABLE[index].active {
            Some(MOUNT_TABLE[index])
        } else {
            None
        }
    }
}

/// Get mount point for a path
pub fn resolve_path_mount(path: &str) -> Option<(MountPoint, &str)> {
    let bytes = path.as_bytes();

    // Check for drive letter path (C:\...)
    if bytes.len() >= 2 && bytes[1] == b':' {
        let drive = bytes[0].to_ascii_uppercase();
        if drive >= b'A' && drive <= b'Z' {
            if let Some(mp) = get_mount_point(drive as char) {
                // Return mount point and remaining path
                let remaining = if bytes.len() >= 3 && (bytes[2] == b'\\' || bytes[2] == b'/') {
                    &path[3..]
                } else {
                    &path[2..]
                };
                return Some((mp, remaining));
            }
        }
    }

    // Check for device path (\\Device\\...)
    if path.starts_with("\\Device\\") || path.starts_with("\\\\Device\\") {
        let _guard = MOUNT_LOCK.lock();
        unsafe {
            for mp in MOUNT_TABLE.iter() {
                if mp.active && path.starts_with(mp.device_path_str()) {
                    let remaining = &path[mp.device_path_len as usize..];
                    return Some((*mp, remaining));
                }
            }
        }
    }

    None
}

/// Get the system drive letter
pub fn get_system_drive() -> Option<char> {
    let _guard = MOUNT_LOCK.lock();

    unsafe {
        for mp in MOUNT_TABLE.iter() {
            if mp.active && mp.is_system() {
                return Some(mp.drive_letter as char);
            }
        }
    }

    None
}

/// Get the boot drive letter
pub fn get_boot_drive() -> Option<char> {
    let _guard = MOUNT_LOCK.lock();

    unsafe {
        for mp in MOUNT_TABLE.iter() {
            if mp.active && mp.is_boot() {
                return Some(mp.drive_letter as char);
            }
        }
    }

    None
}

/// List all mounted volumes
pub fn list_mounts() -> [Option<(char, FsType)>; MAX_MOUNT_POINTS] {
    let mut result = [None; MAX_MOUNT_POINTS];
    let _guard = MOUNT_LOCK.lock();

    unsafe {
        for (i, mp) in MOUNT_TABLE.iter().enumerate() {
            if mp.active {
                result[i] = Some((mp.drive_letter as char, mp.fs_type));
            }
        }
    }

    result
}

/// Count mounted volumes
pub fn mount_count() -> u32 {
    let _guard = MOUNT_LOCK.lock();
    unsafe {
        MOUNT_TABLE.iter().filter(|m| m.active).count() as u32
    }
}

/// Set volume label
pub fn set_volume_label(drive_letter: char, label: &str) -> Result<(), FsStatus> {
    let drive = drive_letter.to_ascii_uppercase();
    if drive < 'A' || drive > 'Z' {
        return Err(FsStatus::InvalidPath);
    }

    let index = (drive as u8 - b'A') as usize;

    let _guard = MOUNT_LOCK.lock();

    unsafe {
        if !MOUNT_TABLE[index].active {
            return Err(FsStatus::NotMounted);
        }

        MOUNT_TABLE[index].set_volume_label(label);
        Ok(())
    }
}

/// Set volume serial number
pub fn set_volume_serial(drive_letter: char, serial: u32) -> Result<(), FsStatus> {
    let drive = drive_letter.to_ascii_uppercase();
    if drive < 'A' || drive > 'Z' {
        return Err(FsStatus::InvalidPath);
    }

    let index = (drive as u8 - b'A') as usize;

    let _guard = MOUNT_LOCK.lock();

    unsafe {
        if !MOUNT_TABLE[index].active {
            return Err(FsStatus::NotMounted);
        }

        MOUNT_TABLE[index].volume_serial = serial;
        Ok(())
    }
}

/// Initialize mount point management
pub fn init() {
    crate::serial_println!("[FS] Mount point manager initializing...");

    // Initialize mount table (already done by static init)
    // Actual volume mounting is done by fs::volume::init() after storage detection

    crate::serial_println!("[FS] Mount point manager initialized");
}
