//! RAW Dispatch Routines
//!
//! Handles IRP dispatch for RAW file system operations.

use super::{vcb, irp_mj, fsctl_mn};

// ============================================================================
// Status Codes
// ============================================================================

/// Operation status codes
pub mod status {
    pub const SUCCESS: i32 = 0;
    pub const INVALID_PARAMETER: i32 = -1;
    pub const NOT_FOUND: i32 = -2;
    pub const ACCESS_DENIED: i32 = -3;
    pub const DEVICE_BUSY: i32 = -4;
    pub const END_OF_FILE: i32 = -5;
    pub const INVALID_DEVICE_REQUEST: i32 = -6;
    pub const NOT_SUPPORTED: i32 = -7;
    pub const BUFFER_TOO_SMALL: i32 = -8;
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize dispatch
pub fn init() {
    crate::serial_println!("[RAW] Dispatch initialized");
}

// ============================================================================
// Create/Open Operations
// ============================================================================

/// Handle create (open) request
pub fn raw_create(vcb_idx: usize) -> Result<u32, i32> {
    // Verify VCB is valid and mounted
    let vcb = vcb::get_vcb(vcb_idx).ok_or(status::NOT_FOUND)?;

    if !vcb.is_mounted() {
        return Err(status::NOT_FOUND);
    }

    if vcb.is_dismount_pending() {
        return Err(status::DEVICE_BUSY);
    }

    // Allocate a handle
    vcb::alloc_handle(vcb_idx).ok_or(status::DEVICE_BUSY)
}

/// Handle cleanup request (prepare for close)
pub fn raw_cleanup(vcb_idx: usize, handle: u32) -> Result<(), i32> {
    // Verify handle is valid
    if !vcb::is_handle_valid(vcb_idx, handle) {
        return Err(status::INVALID_PARAMETER);
    }

    // No cleanup needed for RAW - just return success
    Ok(())
}

/// Handle close request
pub fn raw_close(vcb_idx: usize, handle: u32) -> Result<(), i32> {
    // Free the handle
    if vcb::free_handle(vcb_idx, handle) {
        Ok(())
    } else {
        Err(status::INVALID_PARAMETER)
    }
}

// ============================================================================
// Read/Write Operations
// ============================================================================

/// Handle read or write request
///
/// For RAW, this is a direct pass-through to the underlying device.
pub fn raw_read_write(vcb_idx: usize, offset: u64, buffer: &mut [u8], _is_write: bool) -> Result<usize, i32> {
    // Verify VCB is valid
    let vcb = vcb::get_vcb(vcb_idx).ok_or(status::NOT_FOUND)?;

    if !vcb.is_mounted() {
        return Err(status::NOT_FOUND);
    }

    if buffer.is_empty() {
        return Ok(0);
    }

    // Check bounds
    let volume_size = vcb.volume_size;
    if volume_size > 0 && offset >= volume_size {
        return Err(status::END_OF_FILE);
    }

    // Calculate actual bytes to transfer
    let bytes_available = if volume_size > 0 {
        (volume_size - offset) as usize
    } else {
        buffer.len()
    };
    let bytes_to_transfer = buffer.len().min(bytes_available);

    // In a full implementation, this would:
    // 1. Build an IRP
    // 2. Set up the next stack location
    // 3. Call IoCallDriver to the target device
    // 4. Wait for completion
    //
    // For now, simulate successful transfer
    // The actual I/O would be performed by the block device driver

    Ok(bytes_to_transfer)
}

/// Handle write with const buffer
pub fn raw_read_write_const(vcb_idx: usize, offset: u64, buffer: &[u8]) -> Result<usize, i32> {
    // Verify VCB is valid
    let vcb = vcb::get_vcb(vcb_idx).ok_or(status::NOT_FOUND)?;

    if !vcb.is_mounted() {
        return Err(status::NOT_FOUND);
    }

    if buffer.is_empty() {
        return Ok(0);
    }

    // Check bounds and writability
    let volume_size = vcb.volume_size;
    if volume_size > 0 && offset >= volume_size {
        return Err(status::END_OF_FILE);
    }

    // Calculate actual bytes to transfer
    let bytes_available = if volume_size > 0 {
        (volume_size - offset) as usize
    } else {
        buffer.len()
    };
    let bytes_to_transfer = buffer.len().min(bytes_available);

    Ok(bytes_to_transfer)
}

// ============================================================================
// Query/Set Information
// ============================================================================

/// File information class
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileInfoClass {
    Basic = 4,
    Standard = 5,
    Position = 14,
    EndOfFile = 20,
    Alignment = 17,
}

/// Standard file information
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileStandardInfo {
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub number_of_links: u32,
    pub delete_pending: bool,
    pub directory: bool,
}

/// Handle query information request
pub fn raw_query_information(vcb_idx: usize, info_class: FileInfoClass) -> Result<FileStandardInfo, i32> {
    let vcb = vcb::get_vcb(vcb_idx).ok_or(status::NOT_FOUND)?;

    match info_class {
        FileInfoClass::Standard => {
            Ok(FileStandardInfo {
                allocation_size: vcb.volume_size,
                end_of_file: vcb.volume_size,
                number_of_links: 1,
                delete_pending: false,
                directory: false,
            })
        }
        _ => Err(status::NOT_SUPPORTED),
    }
}

/// Handle set information request
pub fn raw_set_information(vcb_idx: usize, info_class: FileInfoClass, _value: u64) -> Result<(), i32> {
    let _vcb = vcb::get_vcb(vcb_idx).ok_or(status::NOT_FOUND)?;

    match info_class {
        FileInfoClass::Position => {
            // Position tracking is handled by file object, not VCB
            Ok(())
        }
        _ => Err(status::NOT_SUPPORTED),
    }
}

// ============================================================================
// Volume Information
// ============================================================================

/// Volume information class
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeInfoClass {
    /// Volume size information
    Size = 3,
    /// Volume device type
    Device = 4,
    /// File system attributes
    Attribute = 5,
}

/// Volume size information
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VolumeSizeInfo {
    pub total_allocation_units: u64,
    pub available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

/// Handle query volume information request
pub fn raw_query_volume_info(vcb_idx: usize, info_class: VolumeInfoClass) -> Result<VolumeSizeInfo, i32> {
    let vcb = vcb::get_vcb(vcb_idx).ok_or(status::NOT_FOUND)?;

    match info_class {
        VolumeInfoClass::Size => {
            let sector_size = vcb.sector_size as u64;
            let total_sectors = if sector_size > 0 {
                vcb.volume_size / sector_size
            } else {
                0
            };

            Ok(VolumeSizeInfo {
                total_allocation_units: total_sectors,
                available_allocation_units: 0, // RAW doesn't track free space
                sectors_per_allocation_unit: 1,
                bytes_per_sector: vcb.sector_size,
            })
        }
        _ => Err(status::NOT_SUPPORTED),
    }
}

// ============================================================================
// File System Control
// ============================================================================

/// Handle file system control request
pub fn raw_fs_control(vcb_idx: usize, minor_code: u8, _control_code: u32) -> Result<(), i32> {
    match minor_code {
        fsctl_mn::MOUNT_VOLUME => {
            // Mount is handled at higher level
            Ok(())
        }
        fsctl_mn::DISMOUNT_VOLUME => {
            // Mark volume for dismount
            vcb::with_vcb_mut(vcb_idx, |vcb| {
                vcb.set_dismount_pending();
            }).ok_or(status::NOT_FOUND)
        }
        fsctl_mn::USER_FS_REQUEST => {
            // Pass through to device
            Err(status::NOT_SUPPORTED)
        }
        _ => Err(status::INVALID_DEVICE_REQUEST),
    }
}

// ============================================================================
// Device Control
// ============================================================================

/// IOCTL codes
pub mod ioctl {
    pub const GET_VOLUME_SIZE: u32 = 0x00700000;
    pub const SET_VOLUME_SIZE: u32 = 0x00700004;
    pub const LOCK_VOLUME: u32 = 0x00090018;
    pub const UNLOCK_VOLUME: u32 = 0x0009001C;
    pub const GET_DISK_GEOMETRY: u32 = 0x00070000;
    pub const IS_WRITABLE: u32 = 0x00070024;
}

/// Handle device control request
pub fn raw_device_control(vcb_idx: usize, code: u32, in_buf: &[u8], out_buf: &mut [u8]) -> Result<usize, i32> {
    let vcb = vcb::get_vcb(vcb_idx).ok_or(status::NOT_FOUND)?;

    match code {
        ioctl::GET_VOLUME_SIZE => {
            if out_buf.len() < 8 {
                return Err(status::BUFFER_TOO_SMALL);
            }
            let size_bytes = vcb.volume_size.to_le_bytes();
            out_buf[..8].copy_from_slice(&size_bytes);
            Ok(8)
        }
        ioctl::SET_VOLUME_SIZE => {
            if in_buf.len() < 8 {
                return Err(status::BUFFER_TOO_SMALL);
            }
            let size = u64::from_le_bytes([
                in_buf[0], in_buf[1], in_buf[2], in_buf[3],
                in_buf[4], in_buf[5], in_buf[6], in_buf[7],
            ]);
            vcb::set_volume_size(vcb_idx, size)?;
            Ok(0)
        }
        ioctl::LOCK_VOLUME => {
            vcb::lock_volume(vcb_idx)?;
            Ok(0)
        }
        ioctl::UNLOCK_VOLUME => {
            vcb::unlock_volume(vcb_idx)?;
            Ok(0)
        }
        ioctl::GET_DISK_GEOMETRY => {
            // Return basic geometry info
            if out_buf.len() < 24 {
                return Err(status::BUFFER_TOO_SMALL);
            }
            // Cylinders (8 bytes)
            let cylinders = vcb.volume_size / (512 * 63 * 255);
            out_buf[..8].copy_from_slice(&cylinders.to_le_bytes());
            // MediaType (4 bytes)
            out_buf[8..12].copy_from_slice(&0x0Cu32.to_le_bytes()); // FixedMedia
            // TracksPerCylinder (4 bytes)
            out_buf[12..16].copy_from_slice(&255u32.to_le_bytes());
            // SectorsPerTrack (4 bytes)
            out_buf[16..20].copy_from_slice(&63u32.to_le_bytes());
            // BytesPerSector (4 bytes)
            out_buf[20..24].copy_from_slice(&vcb.sector_size.to_le_bytes());
            Ok(24)
        }
        ioctl::IS_WRITABLE => {
            // RAW volumes are always writable unless read-only flag is set
            let is_writable: u32 = if (vcb.state & super::vcb_state::READ_ONLY) != 0 { 0 } else { 1 };
            if out_buf.len() >= 4 {
                out_buf[..4].copy_from_slice(&is_writable.to_le_bytes());
                Ok(4)
            } else {
                Ok(0)
            }
        }
        _ => {
            // Pass through to underlying device
            // In full implementation, would forward IRP to target device
            Err(status::NOT_SUPPORTED)
        }
    }
}

// ============================================================================
// IRP Dispatch
// ============================================================================

/// Main dispatch function
///
/// Routes requests to appropriate handlers based on major function code.
pub fn raw_dispatch(vcb_idx: usize, major_function: u8, minor_function: u8) -> Result<(), i32> {
    match major_function {
        irp_mj::CREATE => {
            raw_create(vcb_idx)?;
            Ok(())
        }
        irp_mj::CLEANUP => {
            // Cleanup needs handle parameter
            Ok(())
        }
        irp_mj::CLOSE => {
            // Close needs handle parameter
            Ok(())
        }
        irp_mj::READ | irp_mj::WRITE | irp_mj::DEVICE_CONTROL => {
            // These need additional parameters
            Ok(())
        }
        irp_mj::QUERY_INFORMATION => {
            // Needs info class
            Ok(())
        }
        irp_mj::SET_INFORMATION => {
            // Needs info class and value
            Ok(())
        }
        irp_mj::QUERY_VOLUME_INFORMATION => {
            // Needs info class
            Ok(())
        }
        irp_mj::FILE_SYSTEM_CONTROL => {
            raw_fs_control(vcb_idx, minor_function, 0)?;
            Ok(())
        }
        irp_mj::PNP => {
            // PnP requests
            Ok(())
        }
        irp_mj::SHUTDOWN => {
            // Mark for dismount
            vcb::with_vcb_mut(vcb_idx, |vcb| {
                vcb.set_dismount_pending();
            }).ok_or(status::NOT_FOUND)
        }
        _ => Err(status::INVALID_DEVICE_REQUEST),
    }
}
