//! Volume Integration
//!
//! Integrates block device volumes with the file system layer.
//! Provides automatic mounting of detected FAT32 volumes.
//!
//! # Volume to Mount Flow
//! 1. Storage subsystem detects physical disks
//! 2. Disk driver scans MBR for partitions
//! 3. Volumes are created for each partition
//! 4. This module mounts FAT32 volumes to drive letters

use crate::io::disk::{
    Volume, get_volume, partition_type,
    get_volume_read_callback, get_volume_write_callback,
};
use crate::io::block::SECTOR_SIZE;
use crate::fs::vfs::{FsType, FsStatus};
use crate::fs::mount::{mount, mount_flags};
use crate::fs::fat32::bpb::Fat32BootSector;

/// Boot sector buffer for reading
static mut BOOT_SECTOR: [u8; SECTOR_SIZE] = [0; SECTOR_SIZE];

/// Check if a volume contains a FAT32 file system
pub fn is_fat32_volume(volume_number: u8) -> bool {
    let vol = match get_volume(volume_number) {
        Some(v) => v,
        None => return false,
    };

    // Check partition type first
    if !partition_type::is_fat(vol.partition_type) {
        // Could still be FAT if partition type is wrong, check boot sector
        if vol.partition_type != partition_type::EMPTY {
            return false;
        }
    }

    // Read boot sector and validate
    unsafe {
        if !read_boot_sector(volume_number) {
            return false;
        }

        // Check for FAT32 signature
        let bs = &*(BOOT_SECTOR.as_ptr() as *const Fat32BootSector);

        // Check jump instruction (0xEB or 0xE9)
        if bs.jump[0] != 0xEB && bs.jump[0] != 0xE9 {
            return false;
        }

        // Check bytes per sector (must be power of 2, 512-4096)
        let bps = bs.bpb.bytes_per_sector;
        if !(512..=4096).contains(&bps) || (bps & (bps - 1)) != 0 {
            return false;
        }

        // Check sectors per cluster (must be power of 2)
        let spc = bs.bpb.sectors_per_cluster;
        if spc == 0 || (spc & (spc - 1)) != 0 {
            return false;
        }

        // FAT32 has 0 root entries and non-zero sectors per FAT32
        if bs.bpb.root_entry_count != 0 {
            return false;  // FAT12/16
        }

        if bs.ext_bpb.sectors_per_fat_32 == 0 {
            return false;  // Not FAT32
        }

        // Check signature
        if bs.signature != [0x55, 0xAA] {
            return false;
        }

        true
    }
}

/// Read boot sector from volume
unsafe fn read_boot_sector(volume_number: u8) -> bool {
    let read_fn = match get_volume_read_callback(volume_number) {
        Some(f) => f,
        None => return false,
    };

    read_fn(volume_number as *mut u8, 0, &mut BOOT_SECTOR)
}

/// Get FAT32 boot sector from volume
pub fn get_fat32_boot_sector(volume_number: u8) -> Option<Fat32BootSector> {
    unsafe {
        if !read_boot_sector(volume_number) {
            return None;
        }
        Some(core::ptr::read(BOOT_SECTOR.as_ptr() as *const Fat32BootSector))
    }
}

/// Mount a volume with a specific drive letter
pub fn mount_volume(
    volume_number: u8,
    drive_letter: char,
    flags: u32,
) -> Result<(), FsStatus> {
    let vol = get_volume(volume_number).ok_or(FsStatus::NotFound)?;

    // Determine file system type and get the VFS driver index
    let (fs_type, vfs_index) = if is_fat32_volume(volume_number) {
        let idx = crate::fs::fat32::vfs_index().ok_or(FsStatus::NotSupported)?;
        (FsType::Fat32, idx)
    } else if vol.partition_type == partition_type::NTFS {
        // NTFS not yet implemented
        return Err(FsStatus::NotSupported);
    } else {
        return Err(FsStatus::NotSupported);
    };

    // Create device path
    let device_path = format_device_path(volume_number);
    let path_str = core::str::from_utf8(&device_path)
        .unwrap_or("\\Device\\HarddiskVolume0")
        .trim_end_matches('\0');

    // If FAT32, register with FAT32 driver first (before VFS mount)
    // This sets up the mount with the volume_number as identifier
    if fs_type == FsType::Fat32 {
        mount_fat32_volume(volume_number)?;
    }

    // Mount to VFS with the correct driver index
    mount(
        drive_letter,
        fs_type,
        vfs_index,  // Use the FAT32 driver's VFS index
        path_str,
        flags,
    )?;

    Ok(())
}

/// Format device path for volume
fn format_device_path(volume_number: u8) -> [u8; 32] {
    let mut path = [0u8; 32];
    let prefix = b"\\Device\\HarddiskVolume";
    let len = prefix.len();
    path[..len].copy_from_slice(prefix);

    // Add volume number as ASCII
    if volume_number < 10 {
        path[len] = b'0' + volume_number;
    } else {
        path[len] = b'0' + (volume_number / 10);
        path[len + 1] = b'0' + (volume_number % 10);
    }

    path
}

/// Mount a FAT32 volume to the FAT32 driver
fn mount_fat32_volume(volume_number: u8) -> Result<(), FsStatus> {
    let read_cb = get_volume_read_callback(volume_number)
        .ok_or(FsStatus::IoError)?;
    let write_cb = get_volume_write_callback(volume_number)
        .ok_or(FsStatus::IoError)?;

    // Get the FAT32 VFS driver index - this is what VFS will pass to lookup
    let vfs_index = crate::fs::fat32::vfs_index()
        .ok_or(FsStatus::NotSupported)?;

    let status = unsafe {
        crate::fs::fat32::mount_volume(
            vfs_index,  // Use FAT32 VFS index, not volume_number
            volume_number as *mut u8,
            read_cb,
            write_cb,
        )
    };

    if status == FsStatus::Success {
        Ok(())
    } else {
        Err(status)
    }
}

/// Unmount a volume
pub fn unmount_volume(drive_letter: char) -> Result<(), FsStatus> {
    crate::fs::mount::unmount(drive_letter)
}

/// Auto-mount detected FAT32 volumes
/// Assigns drive letters starting from C:
pub fn auto_mount_volumes() -> u32 {
    let mut mounted = 0u32;
    let mut next_letter = b'C';

    crate::serial_println!("[FS] Auto-mounting volumes...");

    // Iterate through all volumes
    for vol_num in 1..=32u8 {
        if let Some(vol) = get_volume(vol_num) {
            if !vol.active {
                continue;
            }

            // Check if FAT32
            if is_fat32_volume(vol_num) {
                let drive = next_letter as char;

                // Determine mount flags
                let mut flags = 0u32;
                if vol.bootable {
                    flags |= mount_flags::MF_BOOT;
                }
                if mounted == 0 {
                    flags |= mount_flags::MF_SYSTEM;
                }

                match mount_volume(vol_num, drive, flags) {
                    Ok(()) => {
                        crate::serial_println!(
                            "[FS] Mounted Volume {} as {}:\\ (FAT32, {} MB)",
                            vol_num,
                            drive,
                            vol.size_mb()
                        );
                        mounted += 1;
                        next_letter += 1;

                        if next_letter > b'Z' {
                            break;  // No more drive letters
                        }
                    }
                    Err(e) => {
                        crate::serial_println!(
                            "[FS] Failed to mount Volume {}: {:?}",
                            vol_num,
                            e
                        );
                    }
                }
            } else {
                crate::serial_println!(
                    "[FS] Volume {}: {} (not FAT32, skipping)",
                    vol_num,
                    partition_type::name(vol.partition_type)
                );
            }
        }
    }

    if mounted == 0 {
        crate::serial_println!("[FS] No FAT32 volumes found to mount");
    } else {
        crate::serial_println!("[FS] Auto-mounted {} volume(s)", mounted);
    }

    mounted
}

/// Get volume information for a drive letter
pub fn get_drive_volume(drive_letter: char) -> Option<Volume> {
    let mp = crate::fs::mount::get_mount_point(drive_letter)?;
    get_volume(mp.fs_index as u8).copied()
}

/// List all mountable volumes
pub fn list_mountable_volumes() {
    crate::serial_println!("[FS] Mountable volumes:");

    for vol_num in 1..=32u8 {
        if let Some(vol) = get_volume(vol_num) {
            if !vol.active {
                continue;
            }

            let fs_type = if is_fat32_volume(vol_num) {
                "FAT32"
            } else {
                partition_type::name(vol.partition_type)
            };

            crate::serial_println!(
                "  Volume {}: Disk {} Part {} - {} ({} MB) {}",
                vol_num,
                vol.disk_index,
                vol.partition_index,
                fs_type,
                vol.size_mb(),
                if vol.bootable { "*" } else { "" }
            );
        }
    }
}

/// Initialize volume integration
pub fn init() {
    crate::serial_println!("[FS] Volume integration initializing...");

    // List detected volumes
    list_mountable_volumes();

    // Auto-mount FAT32 volumes
    auto_mount_volumes();

    crate::serial_println!("[FS] Volume integration initialized");
}
