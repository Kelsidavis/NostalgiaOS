//! I/O Manager (io)
//!
//! The I/O manager handles all input/output operations:
//!
//! - **IRPs**: I/O Request Packets for async I/O
//! - **Device Objects**: Represent hardware/logical devices
//! - **Driver Objects**: Driver dispatch tables and state
//! - **File Objects**: Open file state
//! - **Device Stacking**: Filter drivers and layered I/O
//!
//! # I/O Flow
//!
//! 1. User calls NtReadFile/NtWriteFile
//! 2. I/O manager allocates IRP
//! 3. IRP dispatched to top device in stack
//! 4. Each driver processes and passes down
//! 5. Bottom driver completes I/O
//! 6. Completion bubbles back up the stack
//!
//! # Key Structures
//!
//! - `IRP`: I/O Request Packet
//! - `IO_STACK_LOCATION`: Per-driver IRP parameters
//! - `DEVICE_OBJECT`: Device instance
//! - `DRIVER_OBJECT`: Driver dispatch table
//! - `FILE_OBJECT`: Open file handle state

pub mod irp;
pub mod device;
pub mod driver;
pub mod file;
pub mod complete;
pub mod block;
pub mod disk;
pub mod iocp;
pub mod pipe;
pub mod ramdisk;
pub mod pnp;
pub mod csq;
pub mod volmgr;
pub mod mup;
pub mod fat32;
pub mod vfs;

// Re-export main structures and types
pub use irp::{
    Irp,
    IoStackLocation,
    IoStatusBlock,
    IrpMajorFunction,
    IrpMinorFunction,
    irp_flags,
    sl_control,
    io_allocate_irp,
    io_free_irp,
    IrpPoolStats,
    IrpSnapshot,
    io_get_irp_stats,
    io_get_irp_snapshots,
    irp_major_function_name,
};

pub use device::{
    DeviceObject,
    DeviceQueue,
    device_type,
    device_characteristics,
    device_flags,
    io_create_device,
    io_delete_device,
    io_attach_device,
    DevicePoolStats,
    DeviceSnapshot,
    io_get_device_stats,
    io_get_device_snapshots,
    device_type_name,
};

pub use driver::{
    DriverObject,
    DriverExtension,
    FastIoDispatch,
    DriverDispatch,
    DriverUnload,
    DriverInitialize,
    DriverAddDevice,
    DriverStartIo,
    io_create_driver,
    io_delete_driver,
    io_call_driver,
    DriverPoolStats,
    DriverSnapshot,
    io_get_driver_stats,
    io_get_driver_snapshots,
};

pub use file::{
    FileObject,
    CompletionContext,
    file_flags,
    file_access,
    file_share,
    io_create_file_object,
    io_close_file_object,
    FilePoolStats,
    FileSnapshot,
    io_get_file_stats,
    io_get_file_snapshots,
};

pub use complete::{
    priority_boost,
    io_complete_request,
    io_mark_irp_pending,
    io_set_completion_routine,
    io_copy_current_irp_stack_location_to_next,
    io_skip_current_irp_stack_location,
    io_get_current_irp_stack_location,
    io_get_next_irp_stack_location,
    io_cancel_irp,
    io_start_next_packet,
    io_start_packet,
};

pub use block::{
    BlockDevice,
    BlockDeviceType,
    BlockDeviceSnapshot,
    BlockOps,
    BlockStatus,
    BlockStats,
    DiskGeometry,
    block_flags,
    SECTOR_SIZE,
    MAX_BLOCK_DEVICES,
    register_block_device,
    get_block_device,
    read_sectors,
    write_sectors,
    device_count as block_device_count,
    get_stats as get_block_stats,
    io_get_block_snapshots,
    block_device_type_name,
};

pub use disk::{
    Volume,
    VolumeStats,
    VolumeSnapshot,
    MbrPartitionEntry,
    partition_type,
    get_volume,
    volume_read,
    volume_write,
    volume_count,
    list_volumes,
    get_volume_stats,
    io_get_volume_snapshots,
    MAX_VOLUMES,
};

pub use iocp::{
    IoCompletionPort,
    IoCompletionPacket,
    IoCompletionInfo,
    io_create_completion_port,
    io_close_completion_port,
    io_set_completion,
    io_remove_completion,
    io_query_completion,
    io_associate_file_completion_port,
    io_post_irp_completion,
    MAX_COMPLETION_PORTS,
    MAX_QUEUED_COMPLETIONS,
    CompletionPortStats,
    CompletionPortSnapshot,
    io_get_iocp_stats,
    io_get_iocp_snapshots,
};

pub use pipe::{
    NamedPipe,
    PipeInstance,
    PipeState,
    PipeEnd,
    PipeBuffer,
    PipeStats,
    PipeSnapshot,
    pipe_type,
    io_create_named_pipe,
    io_open_named_pipe,
    io_close_pipe_instance,
    io_write_pipe,
    io_read_pipe,
    io_listen_pipe,
    io_peek_pipe,
    io_get_pipe_state,
    get_pipe_stats,
    io_get_pipe_snapshots,
    pipe_type_name,
    MAX_NAMED_PIPES,
    MAX_PIPE_INSTANCES,
    DEFAULT_BUFFER_SIZE,
};

pub use ramdisk::{
    create_ramdisk,
    create_ramdisk_with_size,
    destroy_ramdisk,
    ramdisk_count,
    RamdiskStats,
    RamdiskSnapshot,
    get_ramdisk_stats,
    io_get_ramdisk_snapshots,
    DEFAULT_RAMDISK_SIZE,
    MAX_RAMDISK_SIZE,
    MAX_RAM_DISKS,
};

pub use pnp::{
    PnpMinorFunction,
    PnpDeviceState,
    DeviceRelationType,
    BusQueryIdType,
    DeviceCapabilities,
    DevicePowerState,
    ResourceType,
    ResourceDescriptor,
    ResourceList,
    IoPortResource,
    MemoryResource,
    InterruptResource,
    DmaResource,
    DeviceNode,
    DeviceNodeSnapshot,
    create_device_node,
    start_device as pnp_start_device,
    stop_device as pnp_stop_device,
    remove_device as pnp_remove_device,
    set_device_capabilities,
    assign_resources,
    device_node_count,
    get_device_node_snapshots,
    device_state_name,
    get_stats as pnp_get_stats,
    MAX_DEVICE_NODES,
};

pub use csq::{
    IoCsq,
    IoCsqIrpContext,
    CsqInsertIrpFn,
    CsqInsertIrpExFn,
    CsqRemoveIrpFn,
    CsqPeekNextIrpFn,
    CsqAcquireLockFn,
    CsqReleaseLockFn,
    CsqCompleteCanceledIrpFn,
    CsqStats,
    io_csq_initialize,
    io_csq_initialize_ex,
    io_csq_insert_irp,
    io_csq_insert_irp_ex,
    io_csq_remove_irp,
    io_csq_remove_next_irp,
    get_csq_stats,
    IO_TYPE_CSQ,
    IO_TYPE_CSQ_EX,
    IO_TYPE_CSQ_IRP_CONTEXT,
};

pub use volmgr::{
    DynamicVolume,
    DynamicVolumeType,
    DynamicVolumeSnapshot,
    VolumeMember,
    MemberState,
    VolumeState,
    VolMgrStats,
    create_simple_volume,
    create_spanned_volume,
    create_striped_volume,
    create_mirrored_volume,
    create_raid5_volume,
    get_dynamic_volume,
    delete_dynamic_volume,
    volmgr_read,
    volmgr_write,
    fail_member,
    start_rebuild,
    dynamic_volume_count,
    get_volmgr_stats,
    get_dynamic_volume_snapshots,
    list_dynamic_volumes,
    MAX_DYNAMIC_VOLUMES,
    DEFAULT_STRIPE_SIZE,
};

pub use fat32::{
    Fat32Volume,
    Fat32Stats,
    Fat32VolumeInfo,
    DirEntryInfo,
    FileHandle,
    mount as fat32_mount,
    unmount as fat32_unmount,
    read_directory as fat32_read_directory,
    read_root_directory as fat32_read_root_directory,
    resolve_path as fat32_resolve_path,
    open_file as fat32_open_file,
    close_file as fat32_close_file,
    read_file as fat32_read_file,
    seek_file as fat32_seek_file,
    create_directory as fat32_create_directory,
    create_file as fat32_create_file,
    get_stats as fat32_get_stats,
    get_volume_info as fat32_get_volume_info,
    get_mounted_volume as fat32_get_mounted_volume,
    auto_mount as fat32_auto_mount,
    MAX_FAT_VOLUMES,
    MAX_OPEN_FILES,
};

pub use vfs::{
    DriveType,
    DriveInfo,
    VfsEntry,
    VfsIconType,
    SpecialFolder,
    drive_index,
    drive_letter,
    mount_fat32 as vfs_mount_fat32,
    unmount as vfs_unmount,
    get_drive as vfs_get_drive,
    list_drives as vfs_list_drives,
    read_directory as vfs_read_directory,
    read_special_folder as vfs_read_special_folder,
    parse_path as vfs_parse_path,
    drive_count as vfs_drive_count,
    create_directory as vfs_create_directory,
    create_file as vfs_create_file,
    open_file as vfs_open_file,
    read_file as vfs_read_file,
    close_file as vfs_close_file,
    get_file_size as vfs_get_file_size,
    file_exists as vfs_file_exists,
    MAX_DRIVES,
};

/// Initialize the I/O Manager
///
/// This initializes all I/O subsystems in the correct order:
/// 1. IRP pool
/// 2. Device subsystem
/// 3. Driver subsystem
/// 4. File object subsystem
/// 5. Block device subsystem
pub fn init() {
    crate::serial_println!("[IO] Initializing I/O Manager...");

    unsafe {
        // Initialize IRP pool
        irp::init_irp_system();

        // Initialize device subsystem
        device::init_device_system();

        // Initialize driver subsystem
        driver::init_driver_system();

        // Initialize file object subsystem
        file::init_file_system();
    }

    // Initialize block device subsystem
    block::init();

    // Initialize I/O completion port subsystem
    iocp::init();

    // Initialize named pipe subsystem
    pipe::init();

    // Initialize PnP manager
    pnp::init();

    // Initialize Cancel-Safe Queue support
    csq::init();

    // Initialize Multiple UNC Provider
    mup::init();

    crate::serial_println!("[IO] I/O Manager initialized");
}

/// Initialize storage subsystem (called after HAL init)
/// This detects physical disks and scans partitions
pub fn init_storage() {
    crate::serial_println!("[IO] Initializing storage subsystem...");

    // Initialize ATA/IDE driver (detects disks)
    crate::hal::ata::init();

    // Initialize RAM disk subsystem
    ramdisk::init();

    // Initialize disk subsystem (scans partitions)
    disk::init();

    // Initialize volume manager (dynamic disks, RAID)
    volmgr::init();

    // Initialize FAT32 file system driver
    fat32::init();

    // Auto-mount FAT32 volumes
    fat32::auto_mount();

    // Initialize VFS and assign drive letters
    vfs::init();

    crate::serial_println!("[IO] Storage subsystem initialized");
}
