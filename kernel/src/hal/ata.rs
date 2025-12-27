//! ATA/IDE Driver
//!
//! Implements ATA/IDE disk driver using PIO mode.
//! Supports both primary and secondary IDE channels.
//!
//! # I/O Ports
//! Primary channel: 0x1F0-0x1F7, control at 0x3F6
//! Secondary channel: 0x170-0x177, control at 0x376
//!
//! # Commands
//! - IDENTIFY (0xEC): Get device information
//! - READ SECTORS (0x20): Read sectors in PIO mode
//! - WRITE SECTORS (0x30): Write sectors in PIO mode
//! - FLUSH CACHE (0xE7): Flush write cache
//! - READ SECTORS EXT (0x24): 48-bit LBA read
//! - WRITE SECTORS EXT (0x34): 48-bit LBA write

use crate::arch::io::{inb, inw, outb, outw};
use crate::io::block::{
    BlockDeviceType, BlockOps, BlockStatus, DiskGeometry,
    register_block_device, block_flags, SECTOR_SIZE,
};
use crate::ke::SpinLock;

/// IDE channel ports
pub mod ide_ports {
    // Primary channel
    pub const PRIMARY_DATA: u16 = 0x1F0;
    pub const PRIMARY_ERROR: u16 = 0x1F1;      // Read
    pub const PRIMARY_FEATURES: u16 = 0x1F1;   // Write
    pub const PRIMARY_SECTOR_COUNT: u16 = 0x1F2;
    pub const PRIMARY_LBA_LO: u16 = 0x1F3;
    pub const PRIMARY_LBA_MID: u16 = 0x1F4;
    pub const PRIMARY_LBA_HI: u16 = 0x1F5;
    pub const PRIMARY_DRIVE: u16 = 0x1F6;
    pub const PRIMARY_STATUS: u16 = 0x1F7;     // Read
    pub const PRIMARY_COMMAND: u16 = 0x1F7;    // Write
    pub const PRIMARY_CONTROL: u16 = 0x3F6;

    // Secondary channel
    pub const SECONDARY_DATA: u16 = 0x170;
    pub const SECONDARY_ERROR: u16 = 0x171;
    pub const SECONDARY_FEATURES: u16 = 0x171;
    pub const SECONDARY_SECTOR_COUNT: u16 = 0x172;
    pub const SECONDARY_LBA_LO: u16 = 0x173;
    pub const SECONDARY_LBA_MID: u16 = 0x174;
    pub const SECONDARY_LBA_HI: u16 = 0x175;
    pub const SECONDARY_DRIVE: u16 = 0x176;
    pub const SECONDARY_STATUS: u16 = 0x177;
    pub const SECONDARY_COMMAND: u16 = 0x177;
    pub const SECONDARY_CONTROL: u16 = 0x376;
}

/// ATA commands
pub mod ata_cmd {
    pub const IDENTIFY: u8 = 0xEC;
    pub const IDENTIFY_PACKET: u8 = 0xA1;
    pub const READ_SECTORS: u8 = 0x20;
    pub const READ_SECTORS_EXT: u8 = 0x24;
    pub const WRITE_SECTORS: u8 = 0x30;
    pub const WRITE_SECTORS_EXT: u8 = 0x34;
    pub const FLUSH_CACHE: u8 = 0xE7;
    pub const FLUSH_CACHE_EXT: u8 = 0xEA;
    pub const SET_FEATURES: u8 = 0xEF;
}

/// ATA status register bits
pub mod ata_status {
    pub const ERR: u8 = 0x01;   // Error
    pub const IDX: u8 = 0x02;   // Index
    pub const CORR: u8 = 0x04;  // Corrected data
    pub const DRQ: u8 = 0x08;   // Data request
    pub const SRV: u8 = 0x10;   // Service
    pub const DF: u8 = 0x20;    // Drive fault
    pub const RDY: u8 = 0x40;   // Ready
    pub const BSY: u8 = 0x80;   // Busy
}

/// ATA error register bits
pub mod ata_error {
    pub const AMNF: u8 = 0x01;  // Address mark not found
    pub const TK0NF: u8 = 0x02; // Track 0 not found
    pub const ABRT: u8 = 0x04;  // Aborted command
    pub const MCR: u8 = 0x08;   // Media change request
    pub const IDNF: u8 = 0x10;  // ID not found
    pub const MC: u8 = 0x20;    // Media changed
    pub const UNC: u8 = 0x40;   // Uncorrectable data
    pub const BBK: u8 = 0x80;   // Bad block
}

/// IDE channel information
#[derive(Clone, Copy)]
pub struct IdeChannel {
    pub base: u16,
    pub control: u16,
    pub irq: u8,
}

impl IdeChannel {
    pub const fn primary() -> Self {
        Self {
            base: ide_ports::PRIMARY_DATA,
            control: ide_ports::PRIMARY_CONTROL,
            irq: 14,
        }
    }

    pub const fn secondary() -> Self {
        Self {
            base: ide_ports::SECONDARY_DATA,
            control: ide_ports::SECONDARY_CONTROL,
            irq: 15,
        }
    }
}

/// ATA device information
#[derive(Clone, Copy)]
pub struct AtaDevice {
    pub present: bool,
    pub is_atapi: bool,
    pub channel: u8,      // 0 = primary, 1 = secondary
    pub drive: u8,        // 0 = master, 1 = slave
    pub lba48: bool,
    pub total_sectors: u64,
    pub sector_size: u32,
    pub model: [u8; 48],
    pub serial: [u8; 24],
    pub firmware: [u8; 12],
}

impl AtaDevice {
    pub const fn empty() -> Self {
        Self {
            present: false,
            is_atapi: false,
            channel: 0,
            drive: 0,
            lba48: false,
            total_sectors: 0,
            sector_size: SECTOR_SIZE as u32,
            model: [0; 48],
            serial: [0; 24],
            firmware: [0; 12],
        }
    }
}

impl Default for AtaDevice {
    fn default() -> Self {
        Self::empty()
    }
}

/// Maximum ATA devices (2 channels x 2 devices)
pub const MAX_ATA_DEVICES: usize = 4;

/// ATA device table
static mut ATA_DEVICES: [AtaDevice; MAX_ATA_DEVICES] = {
    const INIT: AtaDevice = AtaDevice::empty();
    [INIT; MAX_ATA_DEVICES]
};

/// ATA lock
static ATA_LOCK: SpinLock<()> = SpinLock::new(());

/// IDE channels
static IDE_CHANNELS: [IdeChannel; 2] = [
    IdeChannel::primary(),
    IdeChannel::secondary(),
];

// ============================================================================
// Low-level I/O
// ============================================================================

/// Wait for BSY to clear
unsafe fn wait_bsy(base: u16) -> bool {
    for _ in 0..100000 {
        let status = inb(base + 7);
        if (status & ata_status::BSY) == 0 {
            return true;
        }
    }
    false
}

/// Wait for DRQ to set
unsafe fn wait_drq(base: u16) -> bool {
    for _ in 0..100000 {
        let status = inb(base + 7);
        if (status & ata_status::BSY) == 0 {
            if (status & ata_status::DRQ) != 0 {
                return true;
            }
            if (status & (ata_status::ERR | ata_status::DF)) != 0 {
                return false;
            }
        }
    }
    false
}

/// Wait for device ready
unsafe fn wait_ready(base: u16) -> bool {
    for _ in 0..100000 {
        let status = inb(base + 7);
        if (status & ata_status::BSY) == 0 {
            if (status & ata_status::RDY) != 0 {
                return true;
            }
            if (status & (ata_status::ERR | ata_status::DF)) != 0 {
                return false;
            }
        }
    }
    false
}

/// 400ns delay (read alternate status 4 times)
unsafe fn ata_delay(control: u16) {
    for _ in 0..4 {
        let _ = inb(control);
    }
}

/// Select drive
unsafe fn select_drive(channel: &IdeChannel, drive: u8) {
    let drive_byte = 0xA0 | ((drive & 1) << 4);
    outb(channel.base + 6, drive_byte);
    ata_delay(channel.control);
}

/// Select drive with LBA
unsafe fn select_drive_lba(channel: &IdeChannel, drive: u8, lba: u64, lba48: bool) {
    if lba48 {
        // LBA48: high bytes first
        outb(channel.base + 2, 0); // Sector count high
        outb(channel.base + 3, ((lba >> 24) & 0xFF) as u8);
        outb(channel.base + 4, ((lba >> 32) & 0xFF) as u8);
        outb(channel.base + 5, ((lba >> 40) & 0xFF) as u8);
    }

    // LBA28 or LBA48 low bytes
    let drive_byte = 0xE0 | ((drive & 1) << 4) | if lba48 { 0 } else { ((lba >> 24) & 0x0F) as u8 };
    outb(channel.base + 6, drive_byte);
    outb(channel.base + 3, (lba & 0xFF) as u8);
    outb(channel.base + 4, ((lba >> 8) & 0xFF) as u8);
    outb(channel.base + 5, ((lba >> 16) & 0xFF) as u8);
}

// ============================================================================
// IDENTIFY Command
// ============================================================================

/// Parse IDENTIFY data
fn parse_identify_data(data: &[u16; 256], device: &mut AtaDevice) {
    // Word 0: Configuration
    let config = data[0];
    device.is_atapi = (config & 0x8000) != 0;

    // Words 27-46: Model number (swap bytes)
    for i in 0..20 {
        let word = data[27 + i];
        device.model[i * 2] = (word >> 8) as u8;
        device.model[i * 2 + 1] = (word & 0xFF) as u8;
    }
    // Trim trailing spaces
    for i in (0..40).rev() {
        if device.model[i] == b' ' || device.model[i] == 0 {
            device.model[i] = 0;
        } else {
            break;
        }
    }

    // Words 10-19: Serial number
    for i in 0..10 {
        let word = data[10 + i];
        device.serial[i * 2] = (word >> 8) as u8;
        device.serial[i * 2 + 1] = (word & 0xFF) as u8;
    }
    for i in (0..20).rev() {
        if device.serial[i] == b' ' || device.serial[i] == 0 {
            device.serial[i] = 0;
        } else {
            break;
        }
    }

    // Words 23-26: Firmware revision
    for i in 0..4 {
        let word = data[23 + i];
        device.firmware[i * 2] = (word >> 8) as u8;
        device.firmware[i * 2 + 1] = (word & 0xFF) as u8;
    }
    for i in (0..8).rev() {
        if device.firmware[i] == b' ' || device.firmware[i] == 0 {
            device.firmware[i] = 0;
        } else {
            break;
        }
    }

    // Word 83: Command set 2 - check LBA48 support
    let cmd_set2 = data[83];
    device.lba48 = (cmd_set2 & (1 << 10)) != 0;

    // Words 60-61: Total sectors (LBA28)
    let sectors_28 = (data[61] as u64) << 16 | (data[60] as u64);

    // Words 100-103: Total sectors (LBA48)
    if device.lba48 {
        let sectors_48 = (data[103] as u64) << 48
            | (data[102] as u64) << 32
            | (data[101] as u64) << 16
            | (data[100] as u64);
        device.total_sectors = if sectors_48 > 0 { sectors_48 } else { sectors_28 };
    } else {
        device.total_sectors = sectors_28;
    }

    // Word 106: Logical sector size
    let logical_sector = data[106];
    if (logical_sector & 0x4000) != 0 && (logical_sector & 0x1000) != 0 {
        // Words 117-118 contain logical sector size
        device.sector_size = ((data[118] as u32) << 16) | (data[117] as u32);
        if device.sector_size == 0 {
            device.sector_size = SECTOR_SIZE as u32;
        }
    } else {
        device.sector_size = SECTOR_SIZE as u32;
    }

    device.present = true;
}

/// Identify a drive
unsafe fn identify_drive(channel_idx: u8, drive: u8) -> Option<AtaDevice> {
    let channel = &IDE_CHANNELS[channel_idx as usize];
    let _guard = ATA_LOCK.lock();

    // Select drive
    select_drive(channel, drive);

    // Clear sector count and LBA registers
    outb(channel.base + 2, 0);
    outb(channel.base + 3, 0);
    outb(channel.base + 4, 0);
    outb(channel.base + 5, 0);

    // Send IDENTIFY command
    outb(channel.base + 7, ata_cmd::IDENTIFY);

    // Check if drive exists
    let status = inb(channel.base + 7);
    if status == 0 {
        return None; // No drive
    }

    // Wait for BSY to clear
    if !wait_bsy(channel.base) {
        return None;
    }

    // Check for ATAPI
    let lba_mid = inb(channel.base + 4);
    let lba_hi = inb(channel.base + 5);

    let is_atapi = if lba_mid == 0x14 && lba_hi == 0xEB {
        // ATAPI device - send IDENTIFY PACKET DEVICE
        outb(channel.base + 7, ata_cmd::IDENTIFY_PACKET);
        if !wait_bsy(channel.base) {
            return None;
        }
        true
    } else if lba_mid == 0 && lba_hi == 0 {
        // ATA device
        false
    } else {
        // Not ATA/ATAPI
        return None;
    };

    // Wait for DRQ
    if !wait_drq(channel.base) {
        return None;
    }

    // Read IDENTIFY data
    let mut data = [0u16; 256];
    for i in 0..256 {
        data[i] = inw(channel.base);
    }

    // Parse data
    let mut device = AtaDevice::empty();
    device.channel = channel_idx;
    device.drive = drive;
    device.is_atapi = is_atapi;
    parse_identify_data(&data, &mut device);

    Some(device)
}

// ============================================================================
// Read/Write Operations
// ============================================================================

/// Read sectors using PIO
unsafe fn ata_read(dev_index: u8, lba: u64, count: u32, buf: *mut u8) -> BlockStatus {
    // Look up the block device to get controller and device_num
    let block_dev = match crate::io::block::get_block_device(dev_index) {
        Some(d) => d,
        None => return BlockStatus::NotFound,
    };

    // Compute ATA device index: controller * 2 + device_num
    let ata_index = (block_dev.controller as usize) * 2 + (block_dev.device_num as usize);

    if ata_index >= MAX_ATA_DEVICES {
        return BlockStatus::NotFound;
    }

    let device = &ATA_DEVICES[ata_index];
    if !device.present {
        return BlockStatus::NotFound;
    }

    let channel = &IDE_CHANNELS[device.channel as usize];
    let _guard = ATA_LOCK.lock();

    // Check bounds
    if lba + count as u64 > device.total_sectors {
        return BlockStatus::InvalidParameter;
    }

    // Select the drive first (just the drive select byte)
    let drive_byte = 0xE0 | ((device.drive & 1) << 4);
    outb(channel.base + 6, drive_byte);
    ata_delay(channel.control);

    // Wait for drive ready after selection
    if !wait_ready(channel.base) {
        return BlockStatus::NotReady;
    }

    // Select drive with full LBA
    select_drive_lba(channel, device.drive, lba, device.lba48);

    // Set sector count
    if device.lba48 {
        outb(channel.base + 2, ((count >> 8) & 0xFF) as u8);
    }
    outb(channel.base + 2, (count & 0xFF) as u8);

    // Send read command
    let cmd = if device.lba48 { ata_cmd::READ_SECTORS_EXT } else { ata_cmd::READ_SECTORS };
    outb(channel.base + 7, cmd);

    // Read sectors
    let mut buf_ptr = buf;
    for _ in 0..count {
        // Wait for DRQ
        if !wait_drq(channel.base) {
            return BlockStatus::IoError;
        }

        // Check for errors
        let status = inb(channel.base + 7);
        if (status & ata_status::ERR) != 0 {
            return BlockStatus::IoError;
        }

        // Read sector data
        for _ in 0..256 {
            let word = inw(channel.base);
            *buf_ptr = (word & 0xFF) as u8;
            *buf_ptr.add(1) = (word >> 8) as u8;
            buf_ptr = buf_ptr.add(2);
        }
    }

    BlockStatus::Success
}

/// Write sectors using PIO
unsafe fn ata_write(dev_index: u8, lba: u64, count: u32, buf: *const u8) -> BlockStatus {
    // Look up the block device to get controller and device_num
    let block_dev = match crate::io::block::get_block_device(dev_index) {
        Some(d) => d,
        None => return BlockStatus::NotFound,
    };

    // Compute ATA device index: controller * 2 + device_num
    let ata_index = (block_dev.controller as usize) * 2 + (block_dev.device_num as usize);

    if ata_index >= MAX_ATA_DEVICES {
        return BlockStatus::NotFound;
    }

    let device = &ATA_DEVICES[ata_index];
    if !device.present {
        return BlockStatus::NotFound;
    }

    if device.is_atapi {
        return BlockStatus::WriteProtected; // ATAPI is read-only for now
    }

    let channel = &IDE_CHANNELS[device.channel as usize];
    let _guard = ATA_LOCK.lock();

    // Check bounds
    if lba + count as u64 > device.total_sectors {
        return BlockStatus::InvalidParameter;
    }

    // Select the drive first (just the drive select byte)
    let drive_byte = 0xE0 | ((device.drive & 1) << 4);
    outb(channel.base + 6, drive_byte);
    ata_delay(channel.control);

    // Wait for drive ready after selection
    if !wait_ready(channel.base) {
        return BlockStatus::NotReady;
    }

    // Select drive with full LBA
    select_drive_lba(channel, device.drive, lba, device.lba48);

    // Set sector count
    if device.lba48 {
        outb(channel.base + 2, ((count >> 8) & 0xFF) as u8);
    }
    outb(channel.base + 2, (count & 0xFF) as u8);

    // Send write command
    let cmd = if device.lba48 { ata_cmd::WRITE_SECTORS_EXT } else { ata_cmd::WRITE_SECTORS };
    outb(channel.base + 7, cmd);

    // Write sectors
    let mut buf_ptr = buf;
    for _ in 0..count {
        // Wait for DRQ
        if !wait_drq(channel.base) {
            return BlockStatus::IoError;
        }

        // Write sector data
        for _ in 0..256 {
            let word = (*buf_ptr as u16) | ((*buf_ptr.add(1) as u16) << 8);
            outw(channel.base, word);
            buf_ptr = buf_ptr.add(2);
        }
    }

    // Wait for completion
    if !wait_bsy(channel.base) {
        return BlockStatus::IoError;
    }

    let status = inb(channel.base + 7);
    if (status & ata_status::ERR) != 0 {
        return BlockStatus::IoError;
    }

    BlockStatus::Success
}

/// Flush cache
unsafe fn ata_flush(dev_index: u8) -> BlockStatus {
    // Look up the block device to get controller and device_num
    let block_dev = match crate::io::block::get_block_device(dev_index) {
        Some(d) => d,
        None => return BlockStatus::NotFound,
    };

    let ata_index = (block_dev.controller as usize) * 2 + (block_dev.device_num as usize);

    if ata_index >= MAX_ATA_DEVICES {
        return BlockStatus::NotFound;
    }

    let device = &ATA_DEVICES[ata_index];
    if !device.present {
        return BlockStatus::NotFound;
    }

    let channel = &IDE_CHANNELS[device.channel as usize];
    let _guard = ATA_LOCK.lock();

    // Select drive
    let drive_byte = 0xE0 | ((device.drive & 1) << 4);
    outb(channel.base + 6, drive_byte);
    ata_delay(channel.control);

    // Send flush command
    let cmd = if device.lba48 { ata_cmd::FLUSH_CACHE_EXT } else { ata_cmd::FLUSH_CACHE };
    outb(channel.base + 7, cmd);

    // Wait for completion
    if !wait_bsy(channel.base) {
        return BlockStatus::Timeout;
    }

    let status = inb(channel.base + 7);
    if (status & ata_status::ERR) != 0 {
        BlockStatus::IoError
    } else {
        BlockStatus::Success
    }
}

/// Get device geometry
unsafe fn ata_get_geometry(dev_index: u8) -> DiskGeometry {
    // Look up the block device to get controller and device_num
    let block_dev = match crate::io::block::get_block_device(dev_index) {
        Some(d) => d,
        None => return DiskGeometry::empty(),
    };

    let ata_index = (block_dev.controller as usize) * 2 + (block_dev.device_num as usize);

    if ata_index >= MAX_ATA_DEVICES {
        return DiskGeometry::empty();
    }

    let device = &ATA_DEVICES[ata_index];
    if !device.present {
        return DiskGeometry::empty();
    }

    DiskGeometry {
        total_sectors: device.total_sectors,
        sector_size: device.sector_size,
        cylinders: 0,
        heads: 0,
        sectors_per_track: 0,
    }
}

/// Check if device is ready
unsafe fn ata_is_ready(dev_index: u8) -> bool {
    // Look up the block device to get controller and device_num
    let block_dev = match crate::io::block::get_block_device(dev_index) {
        Some(d) => d,
        None => return false,
    };

    let ata_index = (block_dev.controller as usize) * 2 + (block_dev.device_num as usize);

    if ata_index >= MAX_ATA_DEVICES {
        return false;
    }

    let device = &ATA_DEVICES[ata_index];
    if !device.present {
        return false;
    }

    let channel = &IDE_CHANNELS[device.channel as usize];
    let status = inb(channel.base + 7);
    (status & ata_status::RDY) != 0 && (status & ata_status::BSY) == 0
}

/// Reset device
unsafe fn ata_reset(dev_index: u8) -> BlockStatus {
    // Look up the block device to get controller and device_num
    let block_dev = match crate::io::block::get_block_device(dev_index) {
        Some(d) => d,
        None => return BlockStatus::NotFound,
    };

    let ata_index = (block_dev.controller as usize) * 2 + (block_dev.device_num as usize);

    if ata_index >= MAX_ATA_DEVICES {
        return BlockStatus::NotFound;
    }

    let device = &ATA_DEVICES[ata_index];
    if !device.present {
        return BlockStatus::NotFound;
    }

    let channel = &IDE_CHANNELS[device.channel as usize];
    let _guard = ATA_LOCK.lock();

    // Software reset
    outb(channel.control, 0x04); // Set SRST
    ata_delay(channel.control);
    outb(channel.control, 0x00); // Clear SRST
    ata_delay(channel.control);

    // Wait for reset to complete
    if !wait_bsy(channel.base) {
        return BlockStatus::Timeout;
    }

    BlockStatus::Success
}

// ============================================================================
// Initialization
// ============================================================================

/// Create ATA block operations
fn ata_ops() -> BlockOps {
    BlockOps {
        read: Some(ata_read),
        write: Some(ata_write),
        flush: Some(ata_flush),
        get_geometry: Some(ata_get_geometry),
        is_ready: Some(ata_is_ready),
        reset: Some(ata_reset),
    }
}

/// Detect and initialize ATA devices
pub fn detect_devices() -> u32 {
    let mut count = 0u32;

    crate::serial_println!("[ATA] Detecting IDE devices...");

    for channel_idx in 0..2 {
        for drive in 0..2 {
            let dev_idx = channel_idx * 2 + drive;

            if let Some(device) = unsafe { identify_drive(channel_idx, drive) } {
                // Store device info
                unsafe {
                    ATA_DEVICES[dev_idx as usize] = device;
                }

                // Determine device type and flags
                let dev_type = if device.is_atapi {
                    BlockDeviceType::Optical
                } else {
                    BlockDeviceType::HardDisk
                };

                let mut flags = 0u32;
                if device.lba48 {
                    flags |= block_flags::LBA48;
                }
                if device.is_atapi {
                    flags |= block_flags::REMOVABLE | block_flags::READONLY;
                }

                // Create geometry
                let geometry = DiskGeometry {
                    total_sectors: device.total_sectors,
                    sector_size: device.sector_size,
                    cylinders: 0,
                    heads: 0,
                    sectors_per_track: 0,
                };

                // Register with block device layer
                if let Some(block_idx) = register_block_device(
                    dev_type,
                    channel_idx,
                    drive,
                    geometry,
                    ata_ops(),
                    flags,
                ) {
                    let model = core::str::from_utf8(&device.model).unwrap_or("Unknown");
                    let model = model.trim_end_matches('\0').trim();

                    crate::serial_println!(
                        "[ATA] {}.{}: {} ({} MB, LBA48: {})",
                        if channel_idx == 0 { "Primary" } else { "Secondary" },
                        if drive == 0 { "Master" } else { "Slave" },
                        model,
                        geometry.size_mb(),
                        if device.lba48 { "yes" } else { "no" }
                    );

                    // Update block device with model/serial
                    if let Some(bdev) = crate::io::block::get_block_device_mut(block_idx) {
                        bdev.set_model(model);
                        let serial = core::str::from_utf8(&device.serial)
                            .unwrap_or("")
                            .trim_end_matches('\0')
                            .trim();
                        bdev.set_serial(serial);
                    }

                    count += 1;
                }
            }
        }
    }

    if count == 0 {
        crate::serial_println!("[ATA] No IDE devices detected");
    } else {
        crate::serial_println!("[ATA] Detected {} IDE device(s)", count);
    }

    count
}

/// Initialize ATA driver
pub fn init() {
    crate::serial_println!("[ATA] ATA/IDE driver initializing...");

    // Disable interrupts on both channels (use polling)
    unsafe {
        outb(ide_ports::PRIMARY_CONTROL, 0x02);
        outb(ide_ports::SECONDARY_CONTROL, 0x02);
    }

    // Detect devices
    let count = detect_devices();

    crate::serial_println!("[ATA] ATA/IDE driver initialized ({} devices)", count);
}
