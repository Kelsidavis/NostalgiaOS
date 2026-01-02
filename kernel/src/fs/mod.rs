//! File System Subsystem
//!
//! Provides file system support for Nostalgia OS, implementing:
//! - Virtual File System (VFS) abstraction layer
//! - FAT32 file system driver
//! - Mount point management
//! - Path utilities
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    User-Mode I/O                            │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    I/O Manager                              │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │              Virtual File System (VFS)                       │
//! │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
//! │  │   VNode     │ │  FileHandle │ │  Mount Pts  │            │
//! │  └─────────────┘ └─────────────┘ └─────────────┘            │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!          ┌───────────────────┼───────────────────┐
//!          ▼                   ▼                   ▼
//! ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
//! │     FAT32       │ │     NTFS        │ │      ISO9660    │
//! │     Driver      │ │     Driver      │ │      Driver     │
//! └─────────────────┘ └─────────────────┘ └─────────────────┘
//!          │                   │                   │
//!          └───────────────────┼───────────────────┘
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Block I/O Layer                          │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Supported File Systems
//! - **FAT32**: Full read support, basic write support
//!   - 8.3 short names
//!   - Long File Names (LFN)
//!   - Directory traversal
//!   - File reading
//!
//! # Mount Points
//! Supports Windows-style drive letters (C:, D:, etc.) and
//! NT device paths (\\Device\\HarddiskVolume1).

pub mod path;
pub mod vfs;
pub mod mount;
pub mod fat32;
pub mod ntfs;
pub mod volume;
pub mod npfs;

// Re-export common types
pub use path::{ParsedPath, PathComponent, MAX_PATH, MAX_COMPONENT};
pub use vfs::{FsStatus, FileType, FileInfo, DirEntry, FsType, FsOps};
pub use vfs::{VNode, FileHandle, INVALID_HANDLE};
pub use mount::{MountPoint, mount_flags};

/// File system statistics
#[derive(Debug, Clone, Copy)]
pub struct FsStats {
    /// Number of registered file systems
    pub registered_fs: u32,
    /// Number of mounted volumes
    pub mounted_volumes: u32,
    /// Number of allocated vnodes
    pub vnodes: u32,
    /// Number of open file handles
    pub handles: u32,
}

impl FsStats {
    /// Get current file system statistics
    pub fn current() -> Self {
        Self {
            registered_fs: vfs::registered_fs_count(),
            mounted_volumes: mount::mount_count(),
            vnodes: vfs::vnode_count(),
            handles: vfs::handle_count(),
        }
    }
}

// ============================================================================
// High-Level File Operations
// ============================================================================

/// Open a file by path
pub fn open(path: &str, _mode: u32) -> Result<u16, FsStatus> {
    // Resolve mount point
    let (mp, remaining) = mount::resolve_path_mount(path)
        .ok_or(FsStatus::NotMounted)?;

    // Lookup through VFS
    let vnode_id = unsafe {
        vfs::vfs_lookup(mp.fs_index, remaining)?
    };

    // Allocate file handle
    let handle = vfs::vfs_alloc_handle(mp.fs_index, vnode_id)
        .ok_or(FsStatus::TooManyFiles)?;

    Ok(handle)
}

/// Close a file handle
pub fn close(handle: u16) -> Result<(), FsStatus> {
    vfs::vfs_free_handle(handle)
}

/// Read from a file
pub fn read(handle: u16, buf: &mut [u8]) -> Result<usize, FsStatus> {
    vfs::vfs_read(handle, buf)
}

/// Write to a file
pub fn write(handle: u16, buf: &[u8]) -> Result<usize, FsStatus> {
    vfs::vfs_write(handle, buf)
}

/// Seek in a file
pub fn seek(handle: u16, offset: i64, whence: SeekWhence) -> Result<u64, FsStatus> {
    vfs::vfs_seek(handle, offset, whence)
}

/// Sync/flush file data and metadata to disk
pub fn sync(handle: u16) -> Result<(), FsStatus> {
    vfs::vfs_sync(handle)
}

/// Seek origin
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekWhence {
    /// Seek from beginning
    Set = 0,
    /// Seek from current position
    Cur = 1,
    /// Seek from end
    End = 2,
}

/// Create a new file
pub fn create(path: &str, attrs: u32) -> Result<u16, FsStatus> {
    // Path must have at least a drive letter and filename
    if !path.contains('\\') {
        return Err(FsStatus::InvalidParameter);
    }

    // Get mount point and resolve path
    let (mp, remaining) = mount::resolve_path_mount(path)
        .ok_or(FsStatus::NotMounted)?;

    // Get parent directory's vnode
    let parent_vnode = if remaining.is_empty() || !remaining.contains('\\') {
        0  // Root directory
    } else {
        // Find parent directory
        let parent_remaining = match remaining.rfind('\\') {
            Some(pos) => &remaining[..pos],
            None => "",
        };
        if parent_remaining.is_empty() {
            0
        } else {
            unsafe { vfs::vfs_lookup(mp.fs_index, parent_remaining)? }
        }
    };

    // Extract just the filename from the remaining path
    let file_name = match remaining.rfind('\\') {
        Some(pos) => &remaining[pos + 1..],
        None => remaining,
    };

    // Create the file
    let vnode_id = unsafe {
        vfs::vfs_create(mp.fs_index, parent_vnode, file_name, attrs)?
    };

    // Allocate file handle
    let handle = vfs::vfs_alloc_handle(mp.fs_index, vnode_id)
        .ok_or(FsStatus::TooManyFiles)?;

    Ok(handle)
}

/// Get file information by path
pub fn stat(path: &str) -> Result<FileInfo, FsStatus> {
    let (mp, remaining) = mount::resolve_path_mount(path)
        .ok_or(FsStatus::NotMounted)?;

    let vnode_id = unsafe {
        vfs::vfs_lookup(mp.fs_index, remaining)?
    };

    unsafe {
        vfs::vfs_getattr(mp.fs_index, vnode_id)
    }
}

/// Get file information by handle
pub fn fstat(handle: u16) -> Result<FileInfo, FsStatus> {
    vfs::vfs_fstat(handle)
}

/// Delete a file
pub fn delete(path: &str) -> Result<(), FsStatus> {
    // Path must have at least a drive letter and filename
    if !path.contains('\\') {
        return Err(FsStatus::InvalidParameter);
    }

    // Get mount point and resolve path
    let (mp, remaining) = mount::resolve_path_mount(path)
        .ok_or(FsStatus::NotMounted)?;

    // Get parent directory's vnode
    let parent_vnode = if remaining.is_empty() || !remaining.contains('\\') {
        0  // Root directory
    } else {
        // Find parent directory
        let parent_remaining = match remaining.rfind('\\') {
            Some(pos) => &remaining[..pos],
            None => "",
        };
        if parent_remaining.is_empty() {
            0
        } else {
            unsafe { vfs::vfs_lookup(mp.fs_index, parent_remaining)? }
        }
    };

    // Extract just the filename from the remaining path
    let file_name = match remaining.rfind('\\') {
        Some(pos) => &remaining[pos + 1..],
        None => remaining,
    };

    // Delete the file
    let status = unsafe {
        vfs::vfs_unlink(mp.fs_index, parent_vnode, file_name)
    };

    if status == FsStatus::Success {
        Ok(())
    } else {
        Err(status)
    }
}

/// Create a directory
pub fn mkdir(path: &str) -> Result<(), FsStatus> {
    // Path must have at least a drive letter and directory name
    if !path.contains('\\') {
        return Err(FsStatus::InvalidParameter);
    }

    // Get mount point and resolve path
    let (mp, remaining) = mount::resolve_path_mount(path)
        .ok_or(FsStatus::NotMounted)?;

    // Get parent directory's vnode
    let parent_vnode = if remaining.is_empty() || !remaining.contains('\\') {
        0  // Root directory
    } else {
        // Find parent directory
        let parent_remaining = match remaining.rfind('\\') {
            Some(pos) => &remaining[..pos],
            None => "",
        };
        if parent_remaining.is_empty() {
            0
        } else {
            unsafe { vfs::vfs_lookup(mp.fs_index, parent_remaining)? }
        }
    };

    // Extract just the directory name from the remaining path
    let dir_name = match remaining.rfind('\\') {
        Some(pos) => &remaining[pos + 1..],
        None => remaining,
    };

    // Create the directory
    unsafe {
        vfs::vfs_mkdir(mp.fs_index, parent_vnode, dir_name)?;
    }

    Ok(())
}

/// Remove an empty directory
pub fn rmdir(path: &str) -> Result<(), FsStatus> {
    // Path must have at least a drive letter and directory name
    if !path.contains('\\') {
        return Err(FsStatus::InvalidParameter);
    }

    // Get mount point and resolve path
    let (mp, remaining) = mount::resolve_path_mount(path)
        .ok_or(FsStatus::NotMounted)?;

    // Get parent directory's vnode
    let parent_vnode = if remaining.is_empty() || !remaining.contains('\\') {
        0  // Root directory
    } else {
        // Find parent directory
        let parent_remaining = match remaining.rfind('\\') {
            Some(pos) => &remaining[..pos],
            None => "",
        };
        if parent_remaining.is_empty() {
            0
        } else {
            unsafe { vfs::vfs_lookup(mp.fs_index, parent_remaining)? }
        }
    };

    // Extract just the directory name from the remaining path
    let dir_name = match remaining.rfind('\\') {
        Some(pos) => &remaining[pos + 1..],
        None => remaining,
    };

    // Remove the directory
    let status = unsafe {
        vfs::vfs_rmdir(mp.fs_index, parent_vnode, dir_name)
    };

    if status == FsStatus::Success {
        Ok(())
    } else {
        Err(status)
    }
}

/// Rename or move a file or directory
pub fn rename(old_path: &str, new_path: &str) -> Result<(), FsStatus> {
    // Both paths must have at least a drive letter and name
    if !old_path.contains('\\') || !new_path.contains('\\') {
        return Err(FsStatus::InvalidParameter);
    }

    // Get mount point for old path
    let (old_mp, old_remaining) = mount::resolve_path_mount(old_path)
        .ok_or(FsStatus::NotMounted)?;

    // Get mount point for new path
    let (new_mp, new_remaining) = mount::resolve_path_mount(new_path)
        .ok_or(FsStatus::NotMounted)?;

    // Cross-filesystem rename is not supported
    if old_mp.fs_index != new_mp.fs_index {
        return Err(FsStatus::NotSupported);
    }

    // Get old parent directory's vnode
    let old_parent_vnode = if old_remaining.is_empty() || !old_remaining.contains('\\') {
        0  // Root directory
    } else {
        let parent_remaining = match old_remaining.rfind('\\') {
            Some(pos) => &old_remaining[..pos],
            None => "",
        };
        if parent_remaining.is_empty() {
            0
        } else {
            unsafe { vfs::vfs_lookup(old_mp.fs_index, parent_remaining)? }
        }
    };

    // Get new parent directory's vnode
    let new_parent_vnode = if new_remaining.is_empty() || !new_remaining.contains('\\') {
        0  // Root directory
    } else {
        let parent_remaining = match new_remaining.rfind('\\') {
            Some(pos) => &new_remaining[..pos],
            None => "",
        };
        if parent_remaining.is_empty() {
            0
        } else {
            unsafe { vfs::vfs_lookup(new_mp.fs_index, parent_remaining)? }
        }
    };

    // Extract just the names
    let old_name = match old_remaining.rfind('\\') {
        Some(pos) => &old_remaining[pos + 1..],
        None => old_remaining,
    };

    let new_name = match new_remaining.rfind('\\') {
        Some(pos) => &new_remaining[pos + 1..],
        None => new_remaining,
    };

    // Perform the rename
    let status = unsafe {
        vfs::vfs_rename(old_mp.fs_index, old_parent_vnode, old_name, new_parent_vnode, new_name)
    };

    if status == FsStatus::Success {
        Ok(())
    } else {
        Err(status)
    }
}

/// Truncate a file to a specific size
///
/// The file must be open. This can shrink or extend the file.
pub fn truncate(handle: u16, new_size: u64) -> Result<(), FsStatus> {
    // Get the file handle to extract fs_index and vnode_id
    let (fs_index, vnode_id) = unsafe {
        let fh = vfs::vfs_get_handle(handle as u32)
            .ok_or(FsStatus::InvalidHandle)?;
        (fh.flags as u16, fh.vnode_index as u64)
    };

    let status = unsafe {
        vfs::vfs_truncate(fs_index, vnode_id, new_size)
    };

    if status == FsStatus::Success {
        Ok(())
    } else {
        Err(status)
    }
}

/// Copy a file from source to destination
///
/// Creates a new file at dst_path with the contents of src_path.
/// If the destination exists, it will be overwritten.
pub fn copy(src_path: &str, dst_path: &str) -> Result<u64, FsStatus> {
    // Buffer for copying data (use stack buffer to avoid allocation)
    let mut buffer = [0u8; 512];
    let mut total_copied: u64 = 0;

    // Open source file
    let src_handle = open(src_path, 0)?;

    // Get source file size
    let src_size = match fstat(src_handle) {
        Ok(info) => info.size,
        Err(e) => {
            let _ = close(src_handle);
            return Err(e);
        }
    };

    // Create destination file (or truncate if exists)
    let dst_handle = match create(dst_path, 0) {
        Ok(h) => h,
        Err(e) => {
            let _ = close(src_handle);
            return Err(e);
        }
    };

    // Copy data in chunks
    loop {
        // Read from source
        let bytes_read = match read(src_handle, &mut buffer) {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(e) => {
                let _ = close(src_handle);
                let _ = close(dst_handle);
                let _ = delete(dst_path); // Clean up partial copy
                return Err(e);
            }
        };

        // Write to destination
        match write(dst_handle, &buffer[..bytes_read]) {
            Ok(n) if n == bytes_read => {
                total_copied += n as u64;
            }
            Ok(_) => {
                // Partial write - shouldn't happen but handle it
                let _ = close(src_handle);
                let _ = close(dst_handle);
                let _ = delete(dst_path);
                return Err(FsStatus::IoError);
            }
            Err(e) => {
                let _ = close(src_handle);
                let _ = close(dst_handle);
                let _ = delete(dst_path);
                return Err(e);
            }
        }

        // Check if we've copied everything
        if total_copied >= src_size {
            break;
        }
    }

    // Sync destination to ensure data is written
    let _ = sync(dst_handle);

    // Close both files
    let _ = close(src_handle);
    let _ = close(dst_handle);

    Ok(total_copied)
}

/// Read a directory
pub fn readdir(path: &str, offset: u32) -> Result<DirEntry, FsStatus> {
    let (mp, remaining) = mount::resolve_path_mount(path)
        .ok_or(FsStatus::NotMounted)?;

    let vnode_id = if remaining.is_empty() {
        0  // Root of mount
    } else {
        unsafe { vfs::vfs_lookup(mp.fs_index, remaining)? }
    };

    let mut entry = DirEntry::empty();
    unsafe {
        vfs::vfs_readdir(mp.fs_index, vnode_id, offset, &mut entry)?;
    }

    Ok(entry)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the file system subsystem
pub fn init() {
    crate::serial_println!("[FS] File system subsystem initializing...");

    // Initialize sub-modules in order
    path::init();
    vfs::init();
    mount::init();

    // Initialize file system drivers
    fat32::init();
    ntfs::init();

    // Initialize pseudo-filesystems
    npfs::init();

    // Initialize volume integration (auto-mounts detected volumes)
    volume::init();

    // Print statistics
    let stats = FsStats::current();
    crate::serial_println!(
        "[FS] File system subsystem initialized ({} fs, {} mounts)",
        stats.registered_fs,
        stats.mounted_volumes
    );
}
