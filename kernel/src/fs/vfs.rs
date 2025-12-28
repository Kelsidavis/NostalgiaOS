//! Virtual File System (VFS) Abstraction
//!
//! Provides a unified interface for different file system implementations.
//! File systems register with the VFS and are accessed through common operations.
//!
//! # Key Concepts
//! - **FileSystem**: A file system driver (FAT32, NTFS, etc.)
//! - **VNode**: Virtual node representing a file or directory
//! - **FileHandle**: Open file descriptor
//! - **DirEntry**: Directory entry for enumeration

use core::sync::atomic::{AtomicU32, Ordering};
use crate::ke::SpinLock;
use super::path::MAX_COMPONENT;

/// Maximum number of registered file systems
pub const MAX_FILE_SYSTEMS: usize = 8;

/// Maximum number of open files
pub const MAX_OPEN_FILES: usize = 128;

/// Maximum number of vnodes
pub const MAX_VNODES: usize = 256;

/// Invalid handle constant
pub const INVALID_HANDLE: u16 = 0xFFFF;

/// File system status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum FsStatus {
    /// Operation succeeded
    Success = 0,
    /// File not found
    NotFound = -1,
    /// Access denied
    AccessDenied = -2,
    /// File already exists
    AlreadyExists = -3,
    /// Not a directory
    NotDirectory = -4,
    /// Is a directory
    IsDirectory = -5,
    /// Directory not empty
    DirectoryNotEmpty = -6,
    /// Disk full
    DiskFull = -7,
    /// Invalid parameter
    InvalidParameter = -8,
    /// End of file
    EndOfFile = -9,
    /// No more entries
    NoMoreEntries = -10,
    /// File system full
    NoSpace = -11,
    /// Read-only file system
    ReadOnly = -12,
    /// I/O error
    IoError = -13,
    /// Invalid file system
    InvalidFileSystem = -14,
    /// Not mounted
    NotMounted = -15,
    /// Too many open files
    TooManyFiles = -16,
    /// Name too long
    NameTooLong = -17,
    /// Cross-device link
    CrossDevice = -18,
    /// Not supported
    NotSupported = -19,
    /// Invalid path
    InvalidPath = -20,
    /// Device busy
    DeviceBusy = -21,
    /// Invalid handle
    InvalidHandle = -22,
}

impl FsStatus {
    pub fn is_success(&self) -> bool {
        *self == FsStatus::Success
    }
}

/// File type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileType {
    /// Regular file
    Regular = 0,
    /// Directory
    Directory = 1,
    /// Symbolic link
    SymLink = 2,
    /// Block device
    BlockDevice = 3,
    /// Character device
    CharDevice = 4,
    /// Named pipe (FIFO)
    Fifo = 5,
    /// Socket
    Socket = 6,
}

impl Default for FileType {
    fn default() -> Self {
        Self::Regular
    }
}

/// File attributes
pub mod file_attrs {
    pub const ATTR_READONLY: u32 = 0x0001;
    pub const ATTR_HIDDEN: u32 = 0x0002;
    pub const ATTR_SYSTEM: u32 = 0x0004;
    pub const ATTR_DIRECTORY: u32 = 0x0010;
    pub const ATTR_ARCHIVE: u32 = 0x0020;
    pub const ATTR_DEVICE: u32 = 0x0040;
    pub const ATTR_NORMAL: u32 = 0x0080;
    pub const ATTR_TEMPORARY: u32 = 0x0100;
    pub const ATTR_SPARSE: u32 = 0x0200;
    pub const ATTR_REPARSE: u32 = 0x0400;
    pub const ATTR_COMPRESSED: u32 = 0x0800;
    pub const ATTR_OFFLINE: u32 = 0x1000;
    pub const ATTR_ENCRYPTED: u32 = 0x4000;
}

/// Open mode flags
pub mod open_flags {
    pub const O_RDONLY: u32 = 0x0000;
    pub const O_WRONLY: u32 = 0x0001;
    pub const O_RDWR: u32 = 0x0002;
    pub const O_APPEND: u32 = 0x0008;
    pub const O_CREAT: u32 = 0x0100;
    pub const O_TRUNC: u32 = 0x0200;
    pub const O_EXCL: u32 = 0x0400;
    pub const O_DIRECTORY: u32 = 0x10000;
}

/// Seek origin
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SeekFrom {
    /// From beginning of file
    Start = 0,
    /// From current position
    Current = 1,
    /// From end of file
    End = 2,
}

/// File information
#[derive(Debug, Clone, Copy)]
pub struct FileInfo {
    /// File size in bytes
    pub size: u64,
    /// File type
    pub file_type: FileType,
    /// File attributes
    pub attributes: u32,
    /// Creation time (ticks)
    pub created: u64,
    /// Last access time
    pub accessed: u64,
    /// Last modification time
    pub modified: u64,
    /// Number of hard links
    pub nlink: u32,
    /// Block size
    pub block_size: u32,
    /// Blocks allocated
    pub blocks: u64,
}

impl FileInfo {
    pub const fn empty() -> Self {
        Self {
            size: 0,
            file_type: FileType::Regular,
            attributes: 0,
            created: 0,
            accessed: 0,
            modified: 0,
            nlink: 1,
            block_size: 512,
            blocks: 0,
        }
    }

    pub fn is_directory(&self) -> bool {
        self.file_type == FileType::Directory ||
        (self.attributes & file_attrs::ATTR_DIRECTORY) != 0
    }

    pub fn is_regular(&self) -> bool {
        self.file_type == FileType::Regular
    }

    pub fn is_readonly(&self) -> bool {
        (self.attributes & file_attrs::ATTR_READONLY) != 0
    }
}

impl Default for FileInfo {
    fn default() -> Self {
        Self::empty()
    }
}

/// Directory entry
#[derive(Clone, Copy)]
pub struct DirEntry {
    /// Entry name
    pub name: [u8; MAX_COMPONENT],
    /// Name length
    pub name_len: u8,
    /// File type
    pub file_type: FileType,
    /// File size
    pub size: u64,
    /// Attributes
    pub attributes: u32,
    /// Next offset for iteration (use this as offset for next readdir call)
    pub next_offset: u32,
}

impl DirEntry {
    pub const fn empty() -> Self {
        Self {
            name: [0; MAX_COMPONENT],
            name_len: 0,
            file_type: FileType::Regular,
            size: 0,
            attributes: 0,
            next_offset: 0,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("")
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_COMPONENT);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name_len = len as u8;
    }

    pub fn is_directory(&self) -> bool {
        self.file_type == FileType::Directory ||
        (self.attributes & file_attrs::ATTR_DIRECTORY) != 0
    }
}

impl Default for DirEntry {
    fn default() -> Self {
        Self::empty()
    }
}

/// Virtual node (inode equivalent)
#[repr(C)]
pub struct VNode {
    /// VNode ID (unique within file system)
    pub id: u64,
    /// File system index
    pub fs_index: u16,
    /// File type
    pub file_type: FileType,
    /// Reference count
    pub ref_count: AtomicU32,
    /// File size
    pub size: u64,
    /// Attributes
    pub attributes: u32,
    /// First cluster (for FAT32)
    pub first_cluster: u32,
    /// Flags
    pub flags: u32,
    /// Parent vnode ID
    pub parent_id: u64,
}

impl VNode {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            fs_index: 0,
            file_type: FileType::Regular,
            ref_count: AtomicU32::new(0),
            size: 0,
            attributes: 0,
            first_cluster: 0,
            flags: 0,
            parent_id: 0,
        }
    }

    pub fn is_in_use(&self) -> bool {
        self.ref_count.load(Ordering::SeqCst) > 0
    }

    pub fn add_ref(&self) -> u32 {
        self.ref_count.fetch_add(1, Ordering::SeqCst)
    }

    pub fn release(&self) -> u32 {
        self.ref_count.fetch_sub(1, Ordering::SeqCst)
    }

    pub fn is_directory(&self) -> bool {
        self.file_type == FileType::Directory
    }
}

impl Default for VNode {
    fn default() -> Self {
        Self::empty()
    }
}

/// VNode flags
pub mod vnode_flags {
    pub const VNODE_ROOT: u32 = 0x0001;
    pub const VNODE_DIRTY: u32 = 0x0002;
    pub const VNODE_MOUNTED: u32 = 0x0004;
}

/// Open file handle
#[repr(C)]
pub struct FileHandle {
    /// VNode index
    pub vnode_index: u32,
    /// Current position
    pub position: u64,
    /// Open flags
    pub flags: u32,
    /// Handle flags
    pub handle_flags: u32,
    /// In use
    pub in_use: bool,
}

impl FileHandle {
    pub const fn empty() -> Self {
        Self {
            vnode_index: u32::MAX,
            position: 0,
            flags: 0,
            handle_flags: 0,
            in_use: false,
        }
    }

    pub fn is_readable(&self) -> bool {
        let mode = self.flags & 0x3;
        mode == open_flags::O_RDONLY || mode == open_flags::O_RDWR
    }

    pub fn is_writable(&self) -> bool {
        let mode = self.flags & 0x3;
        mode == open_flags::O_WRONLY || mode == open_flags::O_RDWR
    }
}

impl Default for FileHandle {
    fn default() -> Self {
        Self::empty()
    }
}

/// File system type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FsType {
    Unknown = 0,
    Fat12 = 1,
    Fat16 = 2,
    Fat32 = 3,
    ExFat = 4,
    Ntfs = 5,
    Ext2 = 6,
    Ext4 = 7,
    Iso9660 = 8,
}

impl Default for FsType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// File system operations trait (vtable)
#[repr(C)]
pub struct FsOps {
    /// Mount the file system
    pub mount: Option<unsafe fn(fs_index: u16, device: *mut u8) -> FsStatus>,
    /// Unmount the file system
    pub unmount: Option<unsafe fn(fs_index: u16) -> FsStatus>,
    /// Get file system info
    pub statfs: Option<unsafe fn(fs_index: u16) -> FsInfo>,
    /// Lookup a path component
    pub lookup: Option<unsafe fn(fs_index: u16, parent: u64, name: &str) -> Result<u64, FsStatus>>,
    /// Read directory entries
    pub readdir: Option<unsafe fn(fs_index: u16, dir_id: u64, offset: u32, entry: &mut DirEntry) -> FsStatus>,
    /// Get file info
    pub getattr: Option<unsafe fn(fs_index: u16, node_id: u64) -> Result<FileInfo, FsStatus>>,
    /// Read file data
    pub read: Option<unsafe fn(fs_index: u16, node_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize, FsStatus>>,
    /// Write file data
    pub write: Option<unsafe fn(fs_index: u16, node_id: u64, offset: u64, buf: &[u8]) -> Result<usize, FsStatus>>,
    /// Create a file
    pub create: Option<unsafe fn(fs_index: u16, parent: u64, name: &str, attrs: u32) -> Result<u64, FsStatus>>,
    /// Create a directory
    pub mkdir: Option<unsafe fn(fs_index: u16, parent: u64, name: &str) -> Result<u64, FsStatus>>,
    /// Remove a file
    pub unlink: Option<unsafe fn(fs_index: u16, parent: u64, name: &str) -> FsStatus>,
    /// Remove a directory
    pub rmdir: Option<unsafe fn(fs_index: u16, parent: u64, name: &str) -> FsStatus>,
    /// Truncate a file
    pub truncate: Option<unsafe fn(fs_index: u16, node_id: u64, size: u64) -> FsStatus>,
    /// Close a file (flush metadata)
    pub close: Option<unsafe fn(fs_index: u16, node_id: u64) -> FsStatus>,
    /// Rename/move a file or directory
    pub rename: Option<unsafe fn(fs_index: u16, old_parent: u64, old_name: &str, new_parent: u64, new_name: &str) -> FsStatus>,
    /// Get file size (for seek)
    pub getsize: Option<unsafe fn(fs_index: u16, node_id: u64) -> Result<u64, FsStatus>>,
    /// Sync/flush file data and metadata to disk
    pub sync: Option<unsafe fn(fs_index: u16, node_id: u64) -> FsStatus>,
}

impl FsOps {
    pub const fn empty() -> Self {
        Self {
            mount: None,
            unmount: None,
            statfs: None,
            lookup: None,
            readdir: None,
            getattr: None,
            read: None,
            write: None,
            create: None,
            mkdir: None,
            unlink: None,
            rmdir: None,
            truncate: None,
            close: None,
            rename: None,
            getsize: None,
            sync: None,
        }
    }
}

impl Default for FsOps {
    fn default() -> Self {
        Self::empty()
    }
}

/// File system info
#[derive(Debug, Clone, Copy)]
pub struct FsInfo {
    /// File system type
    pub fs_type: FsType,
    /// Block size
    pub block_size: u32,
    /// Total blocks
    pub total_blocks: u64,
    /// Free blocks
    pub free_blocks: u64,
    /// Total inodes/files
    pub total_files: u64,
    /// Free inodes/files
    pub free_files: u64,
    /// Volume label
    pub label: [u8; 16],
}

impl FsInfo {
    pub const fn empty() -> Self {
        Self {
            fs_type: FsType::Unknown,
            block_size: 512,
            total_blocks: 0,
            free_blocks: 0,
            total_files: 0,
            free_files: 0,
            label: [0; 16],
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_blocks * self.block_size as u64
    }

    pub fn free_bytes(&self) -> u64 {
        self.free_blocks * self.block_size as u64
    }

    pub fn used_bytes(&self) -> u64 {
        (self.total_blocks - self.free_blocks) * self.block_size as u64
    }
}

impl Default for FsInfo {
    fn default() -> Self {
        Self::empty()
    }
}

/// Registered file system
#[repr(C)]
pub struct RegisteredFs {
    /// File system type
    pub fs_type: FsType,
    /// File system name
    pub name: [u8; 16],
    /// Is mounted
    pub mounted: bool,
    /// Operations
    pub ops: FsOps,
    /// Root vnode ID
    pub root_vnode: u64,
    /// Device pointer
    pub device: *mut u8,
    /// Private data
    pub private: *mut u8,
}

impl RegisteredFs {
    pub const fn empty() -> Self {
        Self {
            fs_type: FsType::Unknown,
            name: [0; 16],
            mounted: false,
            ops: FsOps::empty(),
            root_vnode: 0,
            device: core::ptr::null_mut(),
            private: core::ptr::null_mut(),
        }
    }

    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(16);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }
}

impl Default for RegisteredFs {
    fn default() -> Self {
        Self::empty()
    }
}

// Safety: File system accessed with proper locking
unsafe impl Sync for RegisteredFs {}
unsafe impl Send for RegisteredFs {}

// ============================================================================
// VFS Global State
// ============================================================================

/// Registered file systems
static mut FILE_SYSTEMS: [RegisteredFs; MAX_FILE_SYSTEMS] = {
    const INIT: RegisteredFs = RegisteredFs::empty();
    [INIT; MAX_FILE_SYSTEMS]
};

/// VNode table
static mut VNODES: [VNode; MAX_VNODES] = {
    const INIT: VNode = VNode::empty();
    [INIT; MAX_VNODES]
};

/// Open file handles
static mut FILE_HANDLES: [FileHandle; MAX_OPEN_FILES] = {
    const INIT: FileHandle = FileHandle::empty();
    [INIT; MAX_OPEN_FILES]
};

/// VFS lock
static VFS_LOCK: SpinLock<()> = SpinLock::new(());

/// Registered file system count
static FS_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// VFS Operations
// ============================================================================

/// Register a file system
pub unsafe fn vfs_register_fs(name: &str, fs_type: FsType, ops: FsOps) -> Option<u16> {
    let _guard = VFS_LOCK.lock();

    // Find a free slot
    for i in 0..MAX_FILE_SYSTEMS {
        if FILE_SYSTEMS[i].fs_type == FsType::Unknown {
            let fs = &mut FILE_SYSTEMS[i];
            fs.fs_type = fs_type;
            fs.ops = ops;

            let bytes = name.as_bytes();
            let len = bytes.len().min(15);
            fs.name[..len].copy_from_slice(&bytes[..len]);

            FS_COUNT.fetch_add(1, Ordering::SeqCst);
            return Some(i as u16);
        }
    }

    None
}

/// Get file system by index
pub unsafe fn vfs_get_fs(index: u16) -> Option<&'static RegisteredFs> {
    if (index as usize) < MAX_FILE_SYSTEMS {
        let fs = &FILE_SYSTEMS[index as usize];
        if fs.fs_type != FsType::Unknown {
            return Some(fs);
        }
    }
    None
}

/// Get mutable file system
pub unsafe fn vfs_get_fs_mut(index: u16) -> Option<&'static mut RegisteredFs> {
    if (index as usize) < MAX_FILE_SYSTEMS {
        let fs = &mut FILE_SYSTEMS[index as usize];
        if fs.fs_type != FsType::Unknown {
            return Some(fs);
        }
    }
    None
}

/// Allocate a vnode
pub unsafe fn vfs_alloc_vnode() -> Option<u32> {
    let _guard = VFS_LOCK.lock();

    for i in 0..MAX_VNODES {
        if !VNODES[i].is_in_use() {
            VNODES[i].ref_count.store(1, Ordering::SeqCst);
            return Some(i as u32);
        }
    }

    None
}

/// Get vnode by index
pub unsafe fn vfs_get_vnode(index: u32) -> Option<&'static VNode> {
    if (index as usize) < MAX_VNODES {
        let vnode = &VNODES[index as usize];
        if vnode.is_in_use() {
            return Some(vnode);
        }
    }
    None
}

/// Get mutable vnode
pub unsafe fn vfs_get_vnode_mut(index: u32) -> Option<&'static mut VNode> {
    if (index as usize) < MAX_VNODES {
        let vnode = &mut VNODES[index as usize];
        if vnode.is_in_use() {
            return Some(vnode);
        }
    }
    None
}

/// Free a vnode
pub unsafe fn vfs_free_vnode(index: u32) {
    if (index as usize) < MAX_VNODES {
        let vnode = &mut VNODES[index as usize];
        vnode.ref_count.store(0, Ordering::SeqCst);
        *vnode = VNode::empty();
    }
}

/// Allocate a raw file handle (internal use)
unsafe fn vfs_alloc_handle_raw() -> Option<u32> {
    for i in 0..MAX_OPEN_FILES {
        if !FILE_HANDLES[i].in_use {
            FILE_HANDLES[i].in_use = true;
            return Some(i as u32);
        }
    }

    None
}

/// Get file handle
pub unsafe fn vfs_get_handle(index: u32) -> Option<&'static FileHandle> {
    if (index as usize) < MAX_OPEN_FILES {
        let handle = &FILE_HANDLES[index as usize];
        if handle.in_use {
            return Some(handle);
        }
    }
    None
}

/// Get mutable file handle
pub unsafe fn vfs_get_handle_mut(index: u32) -> Option<&'static mut FileHandle> {
    if (index as usize) < MAX_OPEN_FILES {
        let handle = &mut FILE_HANDLES[index as usize];
        if handle.in_use {
            return Some(handle);
        }
    }
    None
}

/// Free a file handle (by u32 index)
pub unsafe fn vfs_free_handle_u32(index: u32) {
    if (index as usize) < MAX_OPEN_FILES {
        FILE_HANDLES[index as usize] = FileHandle::empty();
    }
}

/// Free a file handle (by u16 handle)
pub fn vfs_free_handle(handle: u16) -> Result<(), FsStatus> {
    if handle == INVALID_HANDLE {
        return Err(FsStatus::InvalidParameter);
    }
    let index = handle as usize;
    if index >= MAX_OPEN_FILES {
        return Err(FsStatus::InvalidParameter);
    }
    unsafe {
        if !FILE_HANDLES[index].in_use {
            return Err(FsStatus::InvalidParameter);
        }

        // Get file info before freeing
        let fs_index = FILE_HANDLES[index].flags as u16;
        let vnode_id = FILE_HANDLES[index].vnode_index as u64;

        // Call close callback to flush metadata
        if let Some(fs) = vfs_get_fs(fs_index) {
            if let Some(close_fn) = fs.ops.close {
                let _ = close_fn(fs_index, vnode_id);
            }
        }

        FILE_HANDLES[index] = FileHandle::empty();
    }
    Ok(())
}

/// Allocate a file handle for a specific vnode
pub fn vfs_alloc_handle(fs_index: u16, vnode_id: u64) -> Option<u16> {
    let _guard = VFS_LOCK.lock();

    unsafe {
        for i in 0..MAX_OPEN_FILES {
            if !FILE_HANDLES[i].in_use {
                FILE_HANDLES[i].in_use = true;
                FILE_HANDLES[i].vnode_index = vnode_id as u32;
                FILE_HANDLES[i].position = 0;
                FILE_HANDLES[i].flags = fs_index as u32;  // Store fs_index in flags temporarily
                return Some(i as u16);
            }
        }
    }

    None
}

/// Get registered file system count
pub fn registered_fs_count() -> u32 {
    FS_COUNT.load(Ordering::SeqCst)
}

/// Get vnode count
pub fn vnode_count() -> u32 {
    unsafe {
        VNODES.iter().filter(|v| v.is_in_use()).count() as u32
    }
}

/// Get handle count
pub fn handle_count() -> u32 {
    unsafe {
        FILE_HANDLES.iter().filter(|h| h.in_use).count() as u32
    }
}

/// Lookup a path through VFS
pub unsafe fn vfs_lookup(fs_index: u16, path: &str) -> Result<u64, FsStatus> {
    let fs = vfs_get_fs(fs_index).ok_or(FsStatus::NotMounted)?;
    let lookup_fn = fs.ops.lookup.ok_or(FsStatus::NotSupported)?;

    // Parse path and walk components
    let parsed = crate::fs::path::ParsedPath::parse(path);

    let mut current = 0u64;  // Start at root

    for i in 0..parsed.component_count as usize {
        let component = &parsed.components[i];
        current = lookup_fn(fs_index, current, component.as_str())?;
    }

    Ok(current)
}

/// Read from a file handle
pub fn vfs_read(handle: u16, buf: &mut [u8]) -> Result<usize, FsStatus> {
    if handle == INVALID_HANDLE {
        return Err(FsStatus::InvalidParameter);
    }

    unsafe {
        let index = handle as usize;
        if index >= MAX_OPEN_FILES || !FILE_HANDLES[index].in_use {
            return Err(FsStatus::InvalidParameter);
        }

        let fh = &mut FILE_HANDLES[index];
        let fs_index = fh.flags as u16;  // Retrieve fs_index from flags
        let vnode_id = fh.vnode_index as u64;
        let position = fh.position;

        let fs = vfs_get_fs(fs_index).ok_or(FsStatus::NotMounted)?;
        let read_fn = fs.ops.read.ok_or(FsStatus::NotSupported)?;

        let bytes_read = read_fn(fs_index, vnode_id, position, buf)?;
        fh.position += bytes_read as u64;

        Ok(bytes_read)
    }
}

/// Write to a file handle
pub fn vfs_write(handle: u16, buf: &[u8]) -> Result<usize, FsStatus> {
    if handle == INVALID_HANDLE {
        return Err(FsStatus::InvalidParameter);
    }

    unsafe {
        let index = handle as usize;
        if index >= MAX_OPEN_FILES || !FILE_HANDLES[index].in_use {
            return Err(FsStatus::InvalidParameter);
        }

        let fh = &mut FILE_HANDLES[index];
        let fs_index = fh.flags as u16;
        let vnode_id = fh.vnode_index as u64;
        let position = fh.position;

        let fs = vfs_get_fs(fs_index).ok_or(FsStatus::NotMounted)?;
        let write_fn = fs.ops.write.ok_or(FsStatus::NotSupported)?;

        let bytes_written = write_fn(fs_index, vnode_id, position, buf)?;
        fh.position += bytes_written as u64;

        Ok(bytes_written)
    }
}

/// Seek in a file
pub fn vfs_seek(handle: u16, offset: i64, whence: crate::fs::SeekWhence) -> Result<u64, FsStatus> {
    if handle == INVALID_HANDLE {
        return Err(FsStatus::InvalidParameter);
    }

    unsafe {
        let index = handle as usize;
        if index >= MAX_OPEN_FILES || !FILE_HANDLES[index].in_use {
            return Err(FsStatus::InvalidParameter);
        }

        let fh = &mut FILE_HANDLES[index];

        let new_pos = match whence {
            crate::fs::SeekWhence::Set => {
                if offset < 0 {
                    return Err(FsStatus::InvalidParameter);
                }
                offset as u64
            }
            crate::fs::SeekWhence::Cur => {
                let current = fh.position as i64;
                let new = current + offset;
                if new < 0 {
                    return Err(FsStatus::InvalidParameter);
                }
                new as u64
            }
            crate::fs::SeekWhence::End => {
                // Get file size from the filesystem
                let fs_index = fh.flags as u16;
                let node_id = fh.vnode_index as u64;

                let fs = vfs_get_fs(fs_index).ok_or(FsStatus::NotMounted)?;
                let getsize_fn = fs.ops.getsize.ok_or(FsStatus::NotSupported)?;
                let file_size = getsize_fn(fs_index, node_id)? as i64;

                let new = file_size + offset;
                if new < 0 {
                    return Err(FsStatus::InvalidParameter);
                }
                new as u64
            }
        };

        fh.position = new_pos;
        Ok(new_pos)
    }
}

/// Get file attributes
pub unsafe fn vfs_getattr(fs_index: u16, vnode_id: u64) -> Result<FileInfo, FsStatus> {
    let fs = vfs_get_fs(fs_index).ok_or(FsStatus::NotMounted)?;
    let getattr_fn = fs.ops.getattr.ok_or(FsStatus::NotSupported)?;
    getattr_fn(fs_index, vnode_id)
}

/// Get file attributes by handle (fstat)
pub fn vfs_fstat(handle: u16) -> Result<FileInfo, FsStatus> {
    if handle == INVALID_HANDLE {
        return Err(FsStatus::InvalidParameter);
    }

    let _guard = VFS_LOCK.lock();

    unsafe {
        let index = handle as usize;
        if index >= MAX_OPEN_FILES || !FILE_HANDLES[index].in_use {
            return Err(FsStatus::InvalidHandle);
        }

        let fh = &FILE_HANDLES[index];
        let fs_index = fh.flags as u16;
        let vnode_id = fh.vnode_index as u64;

        let fs = vfs_get_fs(fs_index).ok_or(FsStatus::NotMounted)?;
        let getattr_fn = fs.ops.getattr.ok_or(FsStatus::NotSupported)?;
        getattr_fn(fs_index, vnode_id)
    }
}

/// Sync/flush file data and metadata to disk by handle
pub fn vfs_sync(handle: u16) -> Result<(), FsStatus> {
    if handle == INVALID_HANDLE {
        return Err(FsStatus::InvalidParameter);
    }

    let _guard = VFS_LOCK.lock();

    unsafe {
        let index = handle as usize;
        if index >= MAX_OPEN_FILES || !FILE_HANDLES[index].in_use {
            return Err(FsStatus::InvalidHandle);
        }

        let fh = &FILE_HANDLES[index];
        let fs_index = fh.flags as u16;
        let vnode_id = fh.vnode_index as u64;

        let fs = vfs_get_fs(fs_index).ok_or(FsStatus::NotMounted)?;
        let sync_fn = fs.ops.sync.ok_or(FsStatus::NotSupported)?;
        let status = sync_fn(fs_index, vnode_id);
        if status == FsStatus::Success {
            Ok(())
        } else {
            Err(status)
        }
    }
}

/// Read directory entries
pub unsafe fn vfs_readdir(
    fs_index: u16,
    dir_id: u64,
    offset: u32,
    entry: &mut DirEntry,
) -> Result<(), FsStatus> {
    let fs = vfs_get_fs(fs_index).ok_or(FsStatus::NotMounted)?;
    let readdir_fn = fs.ops.readdir.ok_or(FsStatus::NotSupported)?;
    let status = readdir_fn(fs_index, dir_id, offset, entry);
    if status == FsStatus::Success {
        Ok(())
    } else {
        Err(status)
    }
}

/// Create a new file
pub unsafe fn vfs_create(fs_index: u16, parent: u64, name: &str, attrs: u32) -> Result<u64, FsStatus> {
    let fs = vfs_get_fs(fs_index).ok_or(FsStatus::NotMounted)?;
    let create_fn = fs.ops.create.ok_or(FsStatus::NotSupported)?;
    create_fn(fs_index, parent, name, attrs)
}

/// Create a directory
pub unsafe fn vfs_mkdir(fs_index: u16, parent: u64, name: &str) -> Result<u64, FsStatus> {
    let fs = vfs_get_fs(fs_index).ok_or(FsStatus::NotMounted)?;
    let mkdir_fn = fs.ops.mkdir.ok_or(FsStatus::NotSupported)?;
    mkdir_fn(fs_index, parent, name)
}

/// Delete a file
pub unsafe fn vfs_unlink(fs_index: u16, parent: u64, name: &str) -> FsStatus {
    let fs = match vfs_get_fs(fs_index) {
        Some(f) => f,
        None => return FsStatus::NotMounted,
    };
    let unlink_fn = match fs.ops.unlink {
        Some(f) => f,
        None => return FsStatus::NotSupported,
    };
    unlink_fn(fs_index, parent, name)
}

/// Remove a directory
pub unsafe fn vfs_rmdir(fs_index: u16, parent: u64, name: &str) -> FsStatus {
    let fs = match vfs_get_fs(fs_index) {
        Some(f) => f,
        None => return FsStatus::NotMounted,
    };
    let rmdir_fn = match fs.ops.rmdir {
        Some(f) => f,
        None => return FsStatus::NotSupported,
    };
    rmdir_fn(fs_index, parent, name)
}

/// Rename/move a file or directory
pub unsafe fn vfs_rename(
    fs_index: u16,
    old_parent: u64,
    old_name: &str,
    new_parent: u64,
    new_name: &str,
) -> FsStatus {
    let fs = match vfs_get_fs(fs_index) {
        Some(f) => f,
        None => return FsStatus::NotMounted,
    };
    let rename_fn = match fs.ops.rename {
        Some(f) => f,
        None => return FsStatus::NotSupported,
    };
    rename_fn(fs_index, old_parent, old_name, new_parent, new_name)
}

/// Truncate a file to a specific size
pub unsafe fn vfs_truncate(fs_index: u16, node_id: u64, size: u64) -> FsStatus {
    let fs = match vfs_get_fs(fs_index) {
        Some(f) => f,
        None => return FsStatus::NotMounted,
    };
    let truncate_fn = match fs.ops.truncate {
        Some(f) => f,
        None => return FsStatus::NotSupported,
    };
    truncate_fn(fs_index, node_id, size)
}

/// Get VFS statistics
pub fn vfs_get_stats() -> VfsStats {
    VfsStats {
        registered_fs: FS_COUNT.load(Ordering::SeqCst),
        max_fs: MAX_FILE_SYSTEMS as u32,
        max_vnodes: MAX_VNODES as u32,
        max_handles: MAX_OPEN_FILES as u32,
    }
}

/// VFS statistics
#[derive(Debug, Clone, Copy)]
pub struct VfsStats {
    pub registered_fs: u32,
    pub max_fs: u32,
    pub max_vnodes: u32,
    pub max_handles: u32,
}

/// Initialize VFS
pub fn init() {
    crate::serial_println!("[FS] VFS initialized ({} max file systems, {} max files)",
        MAX_FILE_SYSTEMS, MAX_OPEN_FILES);
}
