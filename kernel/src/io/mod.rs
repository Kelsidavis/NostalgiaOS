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

    crate::serial_println!("[IO] Storage subsystem initialized");
}
