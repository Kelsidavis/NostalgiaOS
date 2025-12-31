//! Volume Control Block (VCB) Management
//!
//! The VCB represents a mounted RAW volume and tracks its state.

use core::sync::atomic::{AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::{RawDeviceType, RAW_NTC_VCB, MAX_RAW_VOLUMES, MAX_HANDLES_PER_VOLUME, vcb_state};

/// Volume Control Block
///
/// Represents a mounted RAW volume.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Vcb {
    /// Node type code (RAW_NTC_VCB)
    pub node_type: u16,
    /// Node byte size
    pub node_size: u16,
    /// VCB state flags
    pub state: u32,
    /// Device type (Disk, CdRom, Tape)
    pub device_type: RawDeviceType,
    /// Target device object (physical device)
    pub target_device: usize,
    /// Volume size in bytes
    pub volume_size: u64,
    /// Sector size (typically 512)
    pub sector_size: u32,
    /// Number of open handles
    pub open_count: u32,
    /// VCB in use
    pub in_use: bool,
    /// Handle allocation bitmap
    pub handle_bitmap: u32,
}

impl Default for Vcb {
    fn default() -> Self {
        Self::new()
    }
}

impl Vcb {
    pub const fn new() -> Self {
        Self {
            node_type: RAW_NTC_VCB,
            node_size: core::mem::size_of::<Vcb>() as u16,
            state: 0,
            device_type: RawDeviceType::Disk,
            target_device: 0,
            volume_size: 0,
            sector_size: 512,
            open_count: 0,
            in_use: false,
            handle_bitmap: 0,
        }
    }

    /// Initialize VCB for a new mount
    pub fn init(&mut self, target_device: usize, device_type: RawDeviceType) {
        self.node_type = RAW_NTC_VCB;
        self.node_size = core::mem::size_of::<Vcb>() as u16;
        self.state = vcb_state::MOUNTED;
        self.device_type = device_type;
        self.target_device = target_device;
        self.volume_size = 0;
        self.sector_size = 512;
        self.open_count = 0;
        self.in_use = true;
        self.handle_bitmap = 0;
    }

    /// Reset VCB for reuse
    pub fn reset(&mut self) {
        self.state = 0;
        self.device_type = RawDeviceType::Disk;
        self.target_device = 0;
        self.volume_size = 0;
        self.sector_size = 512;
        self.open_count = 0;
        self.in_use = false;
        self.handle_bitmap = 0;
    }

    /// Check if VCB is mounted
    pub fn is_mounted(&self) -> bool {
        self.in_use && (self.state & vcb_state::MOUNTED) != 0
    }

    /// Check if VCB is locked
    pub fn is_locked(&self) -> bool {
        (self.state & vcb_state::LOCKED) != 0
    }

    /// Check if dismount is pending
    pub fn is_dismount_pending(&self) -> bool {
        (self.state & vcb_state::DISMOUNTED) != 0
    }

    /// Set volume size
    pub fn set_volume_size(&mut self, size: u64) {
        self.volume_size = size;
    }

    /// Set sector size
    pub fn set_sector_size(&mut self, size: u32) {
        self.sector_size = size;
    }

    /// Lock the volume
    pub fn lock(&mut self) {
        self.state |= vcb_state::LOCKED;
    }

    /// Unlock the volume
    pub fn unlock(&mut self) {
        self.state &= !vcb_state::LOCKED;
    }

    /// Mark as dismount pending
    pub fn set_dismount_pending(&mut self) {
        self.state |= vcb_state::DISMOUNTED;
    }

    /// Allocate a handle
    pub fn alloc_handle(&mut self) -> Option<u32> {
        for i in 0..MAX_HANDLES_PER_VOLUME {
            if (self.handle_bitmap & (1 << i)) == 0 {
                self.handle_bitmap |= 1 << i;
                self.open_count += 1;
                return Some(i as u32);
            }
        }
        None
    }

    /// Free a handle
    pub fn free_handle(&mut self, handle: u32) -> bool {
        if handle as usize >= MAX_HANDLES_PER_VOLUME {
            return false;
        }
        if (self.handle_bitmap & (1 << handle)) != 0 {
            self.handle_bitmap &= !(1 << handle);
            if self.open_count > 0 {
                self.open_count -= 1;
            }
            true
        } else {
            false
        }
    }

    /// Check if handle is valid
    pub fn is_handle_valid(&self, handle: u32) -> bool {
        if handle as usize >= MAX_HANDLES_PER_VOLUME {
            return false;
        }
        (self.handle_bitmap & (1 << handle)) != 0
    }
}

// ============================================================================
// VCB Pool
// ============================================================================

/// VCB pool
static mut VCB_POOL: [Vcb; MAX_RAW_VOLUMES] = {
    const INIT: Vcb = Vcb::new();
    [INIT; MAX_RAW_VOLUMES]
};

/// VCB pool lock
static VCB_LOCK: SpinLock<()> = SpinLock::new(());

/// Number of active VCBs
static ACTIVE_VCB_COUNT: AtomicU32 = AtomicU32::new(0);

/// Initialize VCB pool
pub fn init() {
    let _guard = VCB_LOCK.lock();
    unsafe {
        for vcb in VCB_POOL.iter_mut() {
            *vcb = Vcb::new();
        }
    }
    ACTIVE_VCB_COUNT.store(0, Ordering::Release);
    crate::serial_println!("[RAW] VCB pool initialized ({} slots)", MAX_RAW_VOLUMES);
}

/// Allocate a VCB
pub fn allocate_vcb(target_device: usize, device_type: RawDeviceType) -> Result<usize, i32> {
    let _guard = VCB_LOCK.lock();

    unsafe {
        for (i, vcb) in VCB_POOL.iter_mut().enumerate() {
            if !vcb.in_use {
                vcb.init(target_device, device_type);
                ACTIVE_VCB_COUNT.fetch_add(1, Ordering::AcqRel);
                return Ok(i);
            }
        }
    }

    Err(-1) // STATUS_INSUFFICIENT_RESOURCES
}

/// Free a VCB
pub fn free_vcb(vcb_idx: usize) -> Result<(), i32> {
    if vcb_idx >= MAX_RAW_VOLUMES {
        return Err(-2); // STATUS_INVALID_PARAMETER
    }

    let _guard = VCB_LOCK.lock();

    unsafe {
        let vcb = &mut VCB_POOL[vcb_idx];
        if !vcb.in_use {
            return Err(-3); // STATUS_NOT_FOUND
        }

        // Check for open handles
        if vcb.open_count > 0 {
            return Err(-4); // STATUS_DEVICE_BUSY
        }

        vcb.reset();
        ACTIVE_VCB_COUNT.fetch_sub(1, Ordering::AcqRel);
    }

    Ok(())
}

/// Get VCB reference
pub fn get_vcb(vcb_idx: usize) -> Option<Vcb> {
    if vcb_idx >= MAX_RAW_VOLUMES {
        return None;
    }

    let _guard = VCB_LOCK.lock();
    unsafe {
        let vcb = &VCB_POOL[vcb_idx];
        if vcb.in_use {
            Some(*vcb)
        } else {
            None
        }
    }
}

/// Get mutable VCB access (internal)
pub fn with_vcb_mut<F, R>(vcb_idx: usize, f: F) -> Option<R>
where
    F: FnOnce(&mut Vcb) -> R,
{
    if vcb_idx >= MAX_RAW_VOLUMES {
        return None;
    }

    let _guard = VCB_LOCK.lock();
    unsafe {
        let vcb = &mut VCB_POOL[vcb_idx];
        if vcb.in_use {
            Some(f(vcb))
        } else {
            None
        }
    }
}

/// Get volume size
pub fn get_volume_size(vcb_idx: usize) -> Option<u64> {
    get_vcb(vcb_idx).map(|v| v.volume_size)
}

/// Set volume size
pub fn set_volume_size(vcb_idx: usize, size: u64) -> Result<(), i32> {
    with_vcb_mut(vcb_idx, |vcb| {
        vcb.set_volume_size(size);
    }).ok_or(-2)
}

/// Get active VCB count
pub fn active_vcb_count() -> u32 {
    ACTIVE_VCB_COUNT.load(Ordering::Acquire)
}

/// List active VCB indices
pub fn list_active_vcbs() -> ([usize; MAX_RAW_VOLUMES], usize) {
    let mut indices = [0usize; MAX_RAW_VOLUMES];
    let mut count = 0;

    let _guard = VCB_LOCK.lock();
    unsafe {
        for (i, vcb) in VCB_POOL.iter().enumerate() {
            if vcb.in_use {
                indices[count] = i;
                count += 1;
            }
        }
    }

    (indices, count)
}

/// Allocate handle on VCB
pub fn alloc_handle(vcb_idx: usize) -> Option<u32> {
    with_vcb_mut(vcb_idx, |vcb| {
        vcb.alloc_handle()
    }).flatten()
}

/// Free handle on VCB
pub fn free_handle(vcb_idx: usize, handle: u32) -> bool {
    with_vcb_mut(vcb_idx, |vcb| {
        vcb.free_handle(handle)
    }).unwrap_or(false)
}

/// Check if handle is valid
pub fn is_handle_valid(vcb_idx: usize, handle: u32) -> bool {
    get_vcb(vcb_idx).map(|v| v.is_handle_valid(handle)).unwrap_or(false)
}

/// Lock volume
pub fn lock_volume(vcb_idx: usize) -> Result<(), i32> {
    with_vcb_mut(vcb_idx, |vcb| {
        vcb.lock();
    }).ok_or(-2)
}

/// Unlock volume
pub fn unlock_volume(vcb_idx: usize) -> Result<(), i32> {
    with_vcb_mut(vcb_idx, |vcb| {
        vcb.unlock();
    }).ok_or(-2)
}

/// Get target device
pub fn get_target_device(vcb_idx: usize) -> Option<usize> {
    get_vcb(vcb_idx).map(|v| v.target_device)
}

/// Get sector size
pub fn get_sector_size(vcb_idx: usize) -> Option<u32> {
    get_vcb(vcb_idx).map(|v| v.sector_size)
}

/// Set sector size
pub fn set_sector_size(vcb_idx: usize, size: u32) -> Result<(), i32> {
    with_vcb_mut(vcb_idx, |vcb| {
        vcb.set_sector_size(size);
    }).ok_or(-2)
}
