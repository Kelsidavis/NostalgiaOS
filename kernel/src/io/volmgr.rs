//! Volume Manager (VOLMGR)
//!
//! Provides dynamic disk and RAID volume management similar to
//! Windows Logical Disk Manager (LDM). Supports:
//!
//! - Simple volumes (single partition)
//! - Spanned volumes (multiple disks concatenated)
//! - Striped volumes (RAID-0)
//! - Mirrored volumes (RAID-1)
//! - RAID-5 volumes (parity striping)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    File System (NTFS/FAT)                    │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Volume Manager                           │
//! │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
//! │  │   Simple    │ │  Spanned    │ │   Striped   │            │
//! │  └─────────────┘ └─────────────┘ └─────────────┘            │
//! │  ┌─────────────┐ ┌─────────────┐                            │
//! │  │  Mirrored   │ │   RAID-5    │                            │
//! │  └─────────────┘ └─────────────┘                            │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                   Partition Manager                          │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `drivers/storage/partmgr/partmgr.c`
//! - `drivers/ftapi/` (Fault Tolerant API)

extern crate alloc;

use crate::ke::spinlock::SpinLock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use super::block::{BlockStatus, SECTOR_SIZE};
use super::disk;

// ============================================================================
// Constants
// ============================================================================

/// Maximum dynamic volumes
pub const MAX_DYNAMIC_VOLUMES: usize = 64;

/// Maximum members per volume
pub const MAX_VOLUME_MEMBERS: usize = 32;

/// Default stripe size (64KB)
pub const DEFAULT_STRIPE_SIZE: u32 = 65536;

/// LDM signature for dynamic disks
pub const LDM_SIGNATURE: u32 = 0x4D44594E; // "NYDM" backwards

// ============================================================================
// Volume Types
// ============================================================================

/// Dynamic volume type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DynamicVolumeType {
    /// Simple volume (single partition)
    #[default]
    Simple = 0,
    /// Spanned volume (concatenated)
    Spanned = 1,
    /// Striped volume (RAID-0)
    Striped = 2,
    /// Mirrored volume (RAID-1)
    Mirrored = 3,
    /// RAID-5 (striped with parity)
    Raid5 = 4,
}

impl DynamicVolumeType {
    /// Get type name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Simple => "Simple",
            Self::Spanned => "Spanned",
            Self::Striped => "Striped (RAID-0)",
            Self::Mirrored => "Mirrored (RAID-1)",
            Self::Raid5 => "RAID-5",
        }
    }

    /// Check if volume provides redundancy
    pub fn is_redundant(&self) -> bool {
        matches!(self, Self::Mirrored | Self::Raid5)
    }

    /// Minimum members required
    pub fn min_members(&self) -> usize {
        match self {
            Self::Simple => 1,
            Self::Spanned => 2,
            Self::Striped => 2,
            Self::Mirrored => 2,
            Self::Raid5 => 3,
        }
    }
}

/// Volume member state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemberState {
    /// Member is healthy
    #[default]
    Healthy = 0,
    /// Member is rebuilding
    Rebuilding = 1,
    /// Member has failed
    Failed = 2,
    /// Member is missing
    Missing = 3,
    /// Member is stale (out of sync)
    Stale = 4,
}

impl MemberState {
    /// Get state name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Healthy => "Healthy",
            Self::Rebuilding => "Rebuilding",
            Self::Failed => "Failed",
            Self::Missing => "Missing",
            Self::Stale => "Stale",
        }
    }
}

/// Volume state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VolumeState {
    /// Volume is healthy (all members operational)
    #[default]
    Healthy = 0,
    /// Volume is degraded (redundant volume with failed member)
    Degraded = 1,
    /// Volume has failed (non-redundant or too many failures)
    Failed = 2,
    /// Volume is resyncing/rebuilding
    Resyncing = 3,
    /// Volume is initializing
    Initializing = 4,
}

impl VolumeState {
    /// Get state name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Healthy => "Healthy",
            Self::Degraded => "Degraded",
            Self::Failed => "Failed",
            Self::Resyncing => "Resyncing",
            Self::Initializing => "Initializing",
        }
    }
}

// ============================================================================
// Volume Member
// ============================================================================

/// Volume member (a disk extent that's part of a dynamic volume)
#[derive(Clone, Copy)]
pub struct VolumeMember {
    /// Is this member active
    pub active: bool,
    /// Disk index (physical disk)
    pub disk_index: u8,
    /// Partition/volume number on that disk
    pub partition_index: u8,
    /// Member state
    pub state: MemberState,
    /// Starting LBA on the disk
    pub start_lba: u64,
    /// Number of sectors in this member
    pub sector_count: u64,
    /// Member index in the volume
    pub member_index: u8,
}

impl VolumeMember {
    /// Create empty member
    pub const fn empty() -> Self {
        Self {
            active: false,
            disk_index: 0,
            partition_index: 0,
            state: MemberState::Healthy,
            start_lba: 0,
            sector_count: 0,
            member_index: 0,
        }
    }

    /// Get size in bytes
    pub fn size_bytes(&self) -> u64 {
        self.sector_count * SECTOR_SIZE as u64
    }

    /// Get size in MB
    pub fn size_mb(&self) -> u64 {
        self.size_bytes() / (1024 * 1024)
    }
}

impl Default for VolumeMember {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Dynamic Volume
// ============================================================================

/// Dynamic volume configuration
pub struct DynamicVolume {
    /// Volume is active
    pub active: bool,
    /// Volume ID
    pub volume_id: u32,
    /// Volume type
    pub volume_type: DynamicVolumeType,
    /// Volume state
    pub state: VolumeState,
    /// Volume label
    pub label: [u8; 32],
    /// GUID for the volume
    pub guid: [u8; 16],
    /// Total logical size in sectors
    pub total_sectors: u64,
    /// Stripe size (for striped/RAID-5)
    pub stripe_size: u32,
    /// Number of active members
    pub member_count: u8,
    /// Volume members
    pub members: [VolumeMember; MAX_VOLUME_MEMBERS],
    /// Read operations
    pub reads: AtomicU64,
    /// Write operations
    pub writes: AtomicU64,
    /// Read bytes
    pub bytes_read: AtomicU64,
    /// Write bytes
    pub bytes_written: AtomicU64,
    /// Rebuild progress (0-100)
    pub rebuild_progress: u8,
}

impl DynamicVolume {
    /// Create empty volume
    pub const fn empty() -> Self {
        Self {
            active: false,
            volume_id: 0,
            volume_type: DynamicVolumeType::Simple,
            state: VolumeState::Healthy,
            label: [0; 32],
            guid: [0; 16],
            total_sectors: 0,
            stripe_size: DEFAULT_STRIPE_SIZE,
            member_count: 0,
            members: [const { VolumeMember::empty() }; MAX_VOLUME_MEMBERS],
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            rebuild_progress: 0,
        }
    }

    /// Get volume label as string
    pub fn label_str(&self) -> &str {
        let len = self.label.iter().position(|&b| b == 0).unwrap_or(32);
        core::str::from_utf8(&self.label[..len]).unwrap_or("")
    }

    /// Set volume label
    pub fn set_label(&mut self, label: &str) {
        let bytes = label.as_bytes();
        let len = bytes.len().min(31);
        self.label = [0; 32];
        self.label[..len].copy_from_slice(&bytes[..len]);
    }

    /// Get size in bytes
    pub fn size_bytes(&self) -> u64 {
        self.total_sectors * SECTOR_SIZE as u64
    }

    /// Get size in MB
    pub fn size_mb(&self) -> u64 {
        self.size_bytes() / (1024 * 1024)
    }

    /// Get size in GB
    pub fn size_gb(&self) -> u64 {
        self.size_bytes() / (1024 * 1024 * 1024)
    }

    /// Check if volume is readable
    pub fn is_readable(&self) -> bool {
        match self.state {
            VolumeState::Healthy | VolumeState::Degraded | VolumeState::Resyncing => true,
            _ => false,
        }
    }

    /// Check if volume is writable
    pub fn is_writable(&self) -> bool {
        match self.state {
            VolumeState::Healthy | VolumeState::Degraded => true,
            _ => false,
        }
    }

    /// Count healthy members
    pub fn healthy_member_count(&self) -> usize {
        self.members.iter()
            .take(self.member_count as usize)
            .filter(|m| m.active && m.state == MemberState::Healthy)
            .count()
    }

    /// Update volume state based on member states
    pub fn update_state(&mut self) {
        let healthy = self.healthy_member_count();
        let total = self.member_count as usize;

        self.state = match self.volume_type {
            DynamicVolumeType::Simple | DynamicVolumeType::Striped => {
                // These types require all members
                if healthy == total { VolumeState::Healthy }
                else { VolumeState::Failed }
            }
            DynamicVolumeType::Spanned => {
                // Spanned requires all members
                if healthy == total { VolumeState::Healthy }
                else { VolumeState::Failed }
            }
            DynamicVolumeType::Mirrored => {
                // Mirror can survive one failure
                if healthy == total { VolumeState::Healthy }
                else if healthy >= 1 { VolumeState::Degraded }
                else { VolumeState::Failed }
            }
            DynamicVolumeType::Raid5 => {
                // RAID-5 can survive one failure
                if healthy == total { VolumeState::Healthy }
                else if healthy >= total - 1 { VolumeState::Degraded }
                else { VolumeState::Failed }
            }
        };
    }
}

impl Default for DynamicVolume {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Volume Manager State
// ============================================================================

/// Volume manager state
struct VolMgrState {
    /// Dynamic volumes
    volumes: [DynamicVolume; MAX_DYNAMIC_VOLUMES],
    /// Next volume ID
    next_volume_id: u32,
    /// Is initialized
    initialized: bool,
}

impl VolMgrState {
    const fn new() -> Self {
        Self {
            volumes: [const { DynamicVolume::empty() }; MAX_DYNAMIC_VOLUMES],
            next_volume_id: 1,
            initialized: false,
        }
    }
}

static VOLMGR_STATE: SpinLock<VolMgrState> = SpinLock::new(VolMgrState::new());

// ============================================================================
// Volume Creation
// ============================================================================

/// Create a simple volume from a single partition
pub fn create_simple_volume(disk_index: u8, partition_index: u8) -> Option<u32> {
    // Get the underlying volume info
    let vol = disk::get_volume_by_partition(disk_index, partition_index)?;

    let mut state = VOLMGR_STATE.lock();

    // Get next volume ID first
    let volume_id = state.next_volume_id;

    // Find free slot
    let mut found_slot = None;
    for (idx, dv) in state.volumes.iter_mut().enumerate() {
        if !dv.active {
            dv.active = true;
            dv.volume_id = volume_id;
            dv.volume_type = DynamicVolumeType::Simple;
            dv.state = VolumeState::Healthy;
            dv.total_sectors = vol.total_sectors;
            dv.member_count = 1;

            dv.members[0] = VolumeMember {
                active: true,
                disk_index,
                partition_index,
                state: MemberState::Healthy,
                start_lba: vol.start_lba,
                sector_count: vol.total_sectors,
                member_index: 0,
            };

            found_slot = Some(idx);
            break;
        }
    }

    if let Some(idx) = found_slot {
        state.next_volume_id += 1;
        let size_mb = state.volumes[idx].size_mb();
        crate::serial_println!(
            "[VOLMGR] Created simple volume {} ({} MB)",
            volume_id,
            size_mb
        );
        Some(volume_id)
    } else {
        None
    }
}

/// Create a spanned volume from multiple partitions
pub fn create_spanned_volume(members: &[(u8, u8)]) -> Option<u32> {
    if members.len() < 2 || members.len() > MAX_VOLUME_MEMBERS {
        return None;
    }

    // Collect member info
    let mut total_sectors = 0u64;
    let mut member_info: Vec<(u64, u64)> = Vec::new(); // (start_lba, sector_count)

    for &(disk_idx, part_idx) in members {
        let vol = disk::get_volume_by_partition(disk_idx, part_idx)?;
        member_info.push((vol.start_lba, vol.total_sectors));
        total_sectors += vol.total_sectors;
    }

    let mut state = VOLMGR_STATE.lock();
    let volume_id = state.next_volume_id;
    let member_len = members.len();

    let mut found_slot = None;
    for (idx, dv) in state.volumes.iter_mut().enumerate() {
        if !dv.active {
            dv.active = true;
            dv.volume_id = volume_id;
            dv.volume_type = DynamicVolumeType::Spanned;
            dv.state = VolumeState::Healthy;
            dv.total_sectors = total_sectors;
            dv.member_count = member_len as u8;

            for (i, (&(disk_idx, part_idx), &(start_lba, sector_count)))
                in members.iter().zip(member_info.iter()).enumerate()
            {
                dv.members[i] = VolumeMember {
                    active: true,
                    disk_index: disk_idx,
                    partition_index: part_idx,
                    state: MemberState::Healthy,
                    start_lba,
                    sector_count,
                    member_index: i as u8,
                };
            }

            found_slot = Some(idx);
            break;
        }
    }

    if let Some(idx) = found_slot {
        state.next_volume_id += 1;
        let size_mb = state.volumes[idx].size_mb();
        crate::serial_println!(
            "[VOLMGR] Created spanned volume {} ({} MB, {} members)",
            volume_id,
            size_mb,
            member_len
        );
        Some(volume_id)
    } else {
        None
    }
}

/// Create a striped volume (RAID-0)
pub fn create_striped_volume(members: &[(u8, u8)], stripe_size: Option<u32>) -> Option<u32> {
    if members.len() < 2 || members.len() > MAX_VOLUME_MEMBERS {
        return None;
    }

    let stripe = stripe_size.unwrap_or(DEFAULT_STRIPE_SIZE);

    // Find minimum member size (all stripes must be same size)
    let mut min_sectors = u64::MAX;
    let mut member_info: Vec<(u64, u64)> = Vec::new();

    for &(disk_idx, part_idx) in members {
        let vol = disk::get_volume_by_partition(disk_idx, part_idx)?;
        member_info.push((vol.start_lba, vol.total_sectors));
        min_sectors = min_sectors.min(vol.total_sectors);
    }

    // Total usable sectors (striped across all members)
    let total_sectors = min_sectors * members.len() as u64;

    let mut state = VOLMGR_STATE.lock();
    let volume_id = state.next_volume_id;
    let member_len = members.len();

    let mut found_slot = None;
    for idx in 0..MAX_DYNAMIC_VOLUMES {
        if !state.volumes[idx].active {
            state.volumes[idx].active = true;
            state.volumes[idx].volume_id = volume_id;
            state.volumes[idx].volume_type = DynamicVolumeType::Striped;
            state.volumes[idx].state = VolumeState::Healthy;
            state.volumes[idx].total_sectors = total_sectors;
            state.volumes[idx].stripe_size = stripe;
            state.volumes[idx].member_count = member_len as u8;

            for (i, (&(disk_idx, part_idx), &(start_lba, _)))
                in members.iter().zip(member_info.iter()).enumerate()
            {
                state.volumes[idx].members[i] = VolumeMember {
                    active: true,
                    disk_index: disk_idx,
                    partition_index: part_idx,
                    state: MemberState::Healthy,
                    start_lba,
                    sector_count: min_sectors,
                    member_index: i as u8,
                };
            }

            found_slot = Some(idx);
            break;
        }
    }

    if let Some(idx) = found_slot {
        state.next_volume_id += 1;
        let size_mb = state.volumes[idx].size_mb();
        crate::serial_println!(
            "[VOLMGR] Created striped volume {} ({} MB, {} members, {}KB stripe)",
            volume_id,
            size_mb,
            member_len,
            stripe / 1024
        );
        Some(volume_id)
    } else {
        None
    }
}

/// Create a mirrored volume (RAID-1)
pub fn create_mirrored_volume(disk1: (u8, u8), disk2: (u8, u8)) -> Option<u32> {
    let vol1 = disk::get_volume_by_partition(disk1.0, disk1.1)?;
    let vol2 = disk::get_volume_by_partition(disk2.0, disk2.1)?;

    // Use smaller size
    let usable_sectors = vol1.total_sectors.min(vol2.total_sectors);

    let mut state = VOLMGR_STATE.lock();
    let volume_id = state.next_volume_id;

    let mut found_slot = None;
    for idx in 0..MAX_DYNAMIC_VOLUMES {
        if !state.volumes[idx].active {
            state.volumes[idx].active = true;
            state.volumes[idx].volume_id = volume_id;
            state.volumes[idx].volume_type = DynamicVolumeType::Mirrored;
            state.volumes[idx].state = VolumeState::Initializing;
            state.volumes[idx].total_sectors = usable_sectors;
            state.volumes[idx].member_count = 2;

            state.volumes[idx].members[0] = VolumeMember {
                active: true,
                disk_index: disk1.0,
                partition_index: disk1.1,
                state: MemberState::Healthy,
                start_lba: vol1.start_lba,
                sector_count: usable_sectors,
                member_index: 0,
            };

            state.volumes[idx].members[1] = VolumeMember {
                active: true,
                disk_index: disk2.0,
                partition_index: disk2.1,
                state: MemberState::Rebuilding,
                start_lba: vol2.start_lba,
                sector_count: usable_sectors,
                member_index: 1,
            };

            found_slot = Some(idx);
            break;
        }
    }

    if let Some(idx) = found_slot {
        crate::serial_println!(
            "[VOLMGR] Created mirrored volume {} ({} MB)",
            volume_id,
            state.volumes[idx].size_mb()
        );
        state.next_volume_id += 1;
        Some(volume_id)
    } else {
        None
    }
}

/// Create a RAID-5 volume
pub fn create_raid5_volume(members: &[(u8, u8)], stripe_size: Option<u32>) -> Option<u32> {
    if members.len() < 3 || members.len() > MAX_VOLUME_MEMBERS {
        return None;
    }

    let stripe = stripe_size.unwrap_or(DEFAULT_STRIPE_SIZE);
    let mut min_sectors = u64::MAX;
    let mut member_info: Vec<(u64, u64)> = Vec::new();

    for &(disk_idx, part_idx) in members {
        let vol = disk::get_volume_by_partition(disk_idx, part_idx)?;
        member_info.push((vol.start_lba, vol.total_sectors));
        min_sectors = min_sectors.min(vol.total_sectors);
    }

    // RAID-5: One disk worth of space is used for parity
    let data_members = members.len() - 1;
    let total_sectors = min_sectors * data_members as u64;

    let mut state = VOLMGR_STATE.lock();
    let volume_id = state.next_volume_id;

    let mut found_slot = None;
    for idx in 0..MAX_DYNAMIC_VOLUMES {
        if !state.volumes[idx].active {
            state.volumes[idx].active = true;
            state.volumes[idx].volume_id = volume_id;
            state.volumes[idx].volume_type = DynamicVolumeType::Raid5;
            state.volumes[idx].state = VolumeState::Initializing;
            state.volumes[idx].total_sectors = total_sectors;
            state.volumes[idx].stripe_size = stripe;
            state.volumes[idx].member_count = members.len() as u8;

            for (i, (&(disk_idx, part_idx), &(start_lba, _)))
                in members.iter().zip(member_info.iter()).enumerate()
            {
                state.volumes[idx].members[i] = VolumeMember {
                    active: true,
                    disk_index: disk_idx,
                    partition_index: part_idx,
                    state: MemberState::Healthy,
                    start_lba,
                    sector_count: min_sectors,
                    member_index: i as u8,
                };
            }

            found_slot = Some(idx);
            break;
        }
    }

    if let Some(idx) = found_slot {
        crate::serial_println!(
            "[VOLMGR] Created RAID-5 volume {} ({} MB, {} members, {}KB stripe)",
            volume_id,
            state.volumes[idx].size_mb(),
            members.len(),
            stripe / 1024
        );
        state.next_volume_id += 1;
        Some(volume_id)
    } else {
        None
    }
}

// ============================================================================
// Volume Operations
// ============================================================================

/// Get dynamic volume by ID
pub fn get_dynamic_volume(volume_id: u32) -> Option<&'static DynamicVolume> {
    let state = VOLMGR_STATE.lock();

    for dv in state.volumes.iter() {
        if dv.active && dv.volume_id == volume_id {
            // Safety: Volume table is static
            return Some(unsafe {
                &*(dv as *const DynamicVolume)
            });
        }
    }

    None
}

/// Delete a dynamic volume
pub fn delete_dynamic_volume(volume_id: u32) -> bool {
    let mut state = VOLMGR_STATE.lock();

    for dv in state.volumes.iter_mut() {
        if dv.active && dv.volume_id == volume_id {
            crate::serial_println!("[VOLMGR] Deleted volume {}", volume_id);
            *dv = DynamicVolume::empty();
            return true;
        }
    }

    false
}

/// Count dynamic volumes
pub fn dynamic_volume_count() -> usize {
    let state = VOLMGR_STATE.lock();
    state.volumes.iter().filter(|v| v.active).count()
}

/// Mark a volume member as failed
pub fn fail_member(volume_id: u32, member_index: u8) -> bool {
    let mut state = VOLMGR_STATE.lock();

    for dv in state.volumes.iter_mut() {
        if dv.active && dv.volume_id == volume_id {
            if member_index < dv.member_count {
                dv.members[member_index as usize].state = MemberState::Failed;
                dv.update_state();

                crate::serial_println!(
                    "[VOLMGR] Volume {} member {} marked as failed, state: {}",
                    volume_id,
                    member_index,
                    dv.state.name()
                );

                return true;
            }
        }
    }

    false
}

/// Start rebuilding a degraded volume
pub fn start_rebuild(volume_id: u32, new_disk: u8, new_partition: u8) -> bool {
    let vol = disk::get_volume_by_partition(new_disk, new_partition);
    if vol.is_none() {
        return false;
    }
    let vol = vol.unwrap();

    let mut state = VOLMGR_STATE.lock();

    for dv in state.volumes.iter_mut() {
        if dv.active && dv.volume_id == volume_id {
            if dv.state != VolumeState::Degraded {
                return false;
            }

            // Find failed member and replace
            for member in dv.members.iter_mut().take(dv.member_count as usize) {
                if member.state == MemberState::Failed {
                    member.disk_index = new_disk;
                    member.partition_index = new_partition;
                    member.start_lba = vol.start_lba;
                    member.sector_count = vol.total_sectors;
                    member.state = MemberState::Rebuilding;

                    dv.state = VolumeState::Resyncing;
                    dv.rebuild_progress = 0;

                    crate::serial_println!(
                        "[VOLMGR] Started rebuild for volume {} with disk {}/{}",
                        volume_id,
                        new_disk,
                        new_partition
                    );

                    return true;
                }
            }
        }
    }

    false
}

// ============================================================================
// Volume I/O (Logical to Physical Mapping)
// ============================================================================

/// Calculate physical location for a logical sector
fn map_sector(dv: &DynamicVolume, logical_sector: u64) -> Option<(u8, u64)> {
    if logical_sector >= dv.total_sectors {
        return None;
    }

    match dv.volume_type {
        DynamicVolumeType::Simple => {
            // Simple: direct mapping
            let member = &dv.members[0];
            Some((member.disk_index, member.start_lba + logical_sector))
        }

        DynamicVolumeType::Spanned => {
            // Spanned: find which member contains this sector
            let mut offset = logical_sector;
            for member in dv.members.iter().take(dv.member_count as usize) {
                if offset < member.sector_count {
                    return Some((member.disk_index, member.start_lba + offset));
                }
                offset -= member.sector_count;
            }
            None
        }

        DynamicVolumeType::Striped => {
            // Striped: calculate stripe and offset
            let stripe_sectors = dv.stripe_size as u64 / SECTOR_SIZE as u64;
            let stripe_row = logical_sector / (stripe_sectors * dv.member_count as u64);
            let stripe_offset = logical_sector % (stripe_sectors * dv.member_count as u64);
            let member_index = (stripe_offset / stripe_sectors) as usize;
            let offset_in_stripe = stripe_offset % stripe_sectors;

            let member = &dv.members[member_index];
            let physical_offset = stripe_row * stripe_sectors + offset_in_stripe;
            Some((member.disk_index, member.start_lba + physical_offset))
        }

        DynamicVolumeType::Mirrored => {
            // Mirrored: read from first healthy member
            for member in dv.members.iter().take(dv.member_count as usize) {
                if member.state == MemberState::Healthy {
                    return Some((member.disk_index, member.start_lba + logical_sector));
                }
            }
            None
        }

        DynamicVolumeType::Raid5 => {
            // RAID-5: calculate stripe, data/parity member
            let stripe_sectors = dv.stripe_size as u64 / SECTOR_SIZE as u64;
            let data_members = dv.member_count as u64 - 1;
            let stripe_row = logical_sector / (stripe_sectors * data_members);
            let stripe_offset = logical_sector % (stripe_sectors * data_members);

            // Parity rotates each stripe row
            let parity_member = (stripe_row % dv.member_count as u64) as usize;

            // Calculate actual data member (skip parity)
            let data_stripe = (stripe_offset / stripe_sectors) as usize;
            let mut member_index = data_stripe;
            if member_index >= parity_member {
                member_index += 1;
            }

            let offset_in_stripe = stripe_offset % stripe_sectors;
            let member = &dv.members[member_index];
            let physical_offset = stripe_row * stripe_sectors + offset_in_stripe;

            Some((member.disk_index, member.start_lba + physical_offset))
        }
    }
}

/// Read from dynamic volume
pub fn volmgr_read(volume_id: u32, logical_sector: u64, buf: &mut [u8]) -> BlockStatus {
    // Extract read info while holding lock
    let read_info: Option<(u8, u64, bool)> = {
        let state = VOLMGR_STATE.lock();
        let mut info = None;
        for idx in 0..MAX_DYNAMIC_VOLUMES {
            if state.volumes[idx].active && state.volumes[idx].volume_id == volume_id {
                if !state.volumes[idx].is_readable() {
                    return BlockStatus::NotReady;
                }
                if let Some((disk_idx, physical_sector)) = map_sector(&state.volumes[idx], logical_sector) {
                    info = Some((disk_idx, physical_sector, true));
                } else {
                    return BlockStatus::InvalidParameter;
                }
                break;
            }
        }
        info
    };

    if let Some((disk_idx, physical_sector, _)) = read_info {
        let result = super::block::read_sectors(disk_idx, physical_sector, 1, buf);

        if result == BlockStatus::Success {
            // Update statistics
            if let Some(vol) = get_dynamic_volume(volume_id) {
                vol.reads.fetch_add(1, Ordering::Relaxed);
                vol.bytes_read.fetch_add(buf.len() as u64, Ordering::Relaxed);
            }
        }

        result
    } else {
        BlockStatus::NotFound
    }
}

/// Write to dynamic volume
pub fn volmgr_write(volume_id: u32, logical_sector: u64, buf: &[u8]) -> BlockStatus {
    // Extract write info while holding lock
    enum WriteInfo {
        Single { disk_idx: u8, physical_sector: u64 },
        Mirrored { targets: Vec<(u8, u64)> },
        NotWritable,
        NotFound,
        InvalidParameter,
    }

    let write_info: WriteInfo = {
        let state = VOLMGR_STATE.lock();
        let mut info = WriteInfo::NotFound;

        for idx in 0..MAX_DYNAMIC_VOLUMES {
            if state.volumes[idx].active && state.volumes[idx].volume_id == volume_id {
                if !state.volumes[idx].is_writable() {
                    info = WriteInfo::NotWritable;
                    break;
                }

                let volume_type = state.volumes[idx].volume_type;
                let member_count = state.volumes[idx].member_count;

                match volume_type {
                    DynamicVolumeType::Mirrored => {
                        // Collect all healthy member targets
                        let mut targets = Vec::new();
                        for m_idx in 0..member_count as usize {
                            let member = &state.volumes[idx].members[m_idx];
                            if member.state == MemberState::Healthy {
                                let physical_sector = member.start_lba + logical_sector;
                                targets.push((member.disk_index, physical_sector));
                            }
                        }
                        info = WriteInfo::Mirrored { targets };
                    }

                    _ => {
                        // Single write for other types
                        if let Some((disk_idx, physical_sector)) = map_sector(&state.volumes[idx], logical_sector) {
                            info = WriteInfo::Single { disk_idx, physical_sector };
                        } else {
                            info = WriteInfo::InvalidParameter;
                        }
                    }
                }
                break;
            }
        }
        info
    };

    match write_info {
        WriteInfo::NotWritable => BlockStatus::WriteProtected,
        WriteInfo::NotFound => BlockStatus::NotFound,
        WriteInfo::InvalidParameter => BlockStatus::InvalidParameter,

        WriteInfo::Single { disk_idx, physical_sector } => {
            let result = super::block::write_sectors(disk_idx, physical_sector, 1, buf);

            if result == BlockStatus::Success {
                if let Some(vol) = get_dynamic_volume(volume_id) {
                    vol.writes.fetch_add(1, Ordering::Relaxed);
                    vol.bytes_written.fetch_add(buf.len() as u64, Ordering::Relaxed);
                }
            }

            result
        }

        WriteInfo::Mirrored { targets } => {
            let mut success = false;
            for (disk_idx, physical_sector) in targets {
                if super::block::write_sectors(disk_idx, physical_sector, 1, buf) == BlockStatus::Success {
                    success = true;
                }
            }

            if success {
                if let Some(vol) = get_dynamic_volume(volume_id) {
                    vol.writes.fetch_add(1, Ordering::Relaxed);
                    vol.bytes_written.fetch_add(buf.len() as u64, Ordering::Relaxed);
                }
                BlockStatus::Success
            } else {
                BlockStatus::IoError
            }
        }
    }
}

// ============================================================================
// Statistics and Inspection
// ============================================================================

/// Volume manager statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct VolMgrStats {
    /// Total dynamic volumes
    pub volume_count: usize,
    /// Healthy volumes
    pub healthy_count: usize,
    /// Degraded volumes
    pub degraded_count: usize,
    /// Failed volumes
    pub failed_count: usize,
    /// Total capacity in MB
    pub total_capacity_mb: u64,
}

/// Get volume manager statistics
pub fn get_volmgr_stats() -> VolMgrStats {
    let state = VOLMGR_STATE.lock();

    let mut stats = VolMgrStats::default();

    for dv in state.volumes.iter() {
        if dv.active {
            stats.volume_count += 1;
            stats.total_capacity_mb += dv.size_mb();

            match dv.state {
                VolumeState::Healthy => stats.healthy_count += 1,
                VolumeState::Degraded => stats.degraded_count += 1,
                VolumeState::Failed => stats.failed_count += 1,
                _ => {}
            }
        }
    }

    stats
}

/// Dynamic volume snapshot for inspection
#[derive(Clone, Copy)]
pub struct DynamicVolumeSnapshot {
    pub volume_id: u32,
    pub volume_type: DynamicVolumeType,
    pub state: VolumeState,
    pub size_mb: u64,
    pub member_count: u8,
    pub healthy_members: u8,
    pub stripe_size_kb: u32,
    pub reads: u64,
    pub writes: u64,
    pub rebuild_progress: u8,
}

impl DynamicVolumeSnapshot {
    pub const fn empty() -> Self {
        Self {
            volume_id: 0,
            volume_type: DynamicVolumeType::Simple,
            state: VolumeState::Healthy,
            size_mb: 0,
            member_count: 0,
            healthy_members: 0,
            stripe_size_kb: 0,
            reads: 0,
            writes: 0,
            rebuild_progress: 0,
        }
    }
}

/// Get snapshots of all dynamic volumes
pub fn get_dynamic_volume_snapshots(max_count: usize) -> ([DynamicVolumeSnapshot; 32], usize) {
    let mut snapshots = [DynamicVolumeSnapshot::empty(); 32];
    let mut count = 0;

    let limit = max_count.min(32).min(MAX_DYNAMIC_VOLUMES);
    let state = VOLMGR_STATE.lock();

    for dv in state.volumes.iter() {
        if count >= limit {
            break;
        }

        if dv.active {
            snapshots[count] = DynamicVolumeSnapshot {
                volume_id: dv.volume_id,
                volume_type: dv.volume_type,
                state: dv.state,
                size_mb: dv.size_mb(),
                member_count: dv.member_count,
                healthy_members: dv.healthy_member_count() as u8,
                stripe_size_kb: dv.stripe_size / 1024,
                reads: dv.reads.load(Ordering::Relaxed),
                writes: dv.writes.load(Ordering::Relaxed),
                rebuild_progress: dv.rebuild_progress,
            };
            count += 1;
        }
    }

    (snapshots, count)
}

/// List all dynamic volumes
pub fn list_dynamic_volumes() {
    let state = VOLMGR_STATE.lock();

    crate::serial_println!("[VOLMGR] Dynamic volumes:");

    for dv in state.volumes.iter() {
        if dv.active {
            crate::serial_println!(
                "  Volume {}: {} - {} ({} MB) - {} members, {}",
                dv.volume_id,
                dv.volume_type.name(),
                dv.label_str(),
                dv.size_mb(),
                dv.member_count,
                dv.state.name()
            );
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the volume manager
pub fn init() {
    let mut state = VOLMGR_STATE.lock();

    if state.initialized {
        return;
    }

    state.initialized = true;

    crate::serial_println!("[VOLMGR] Volume Manager initialized (max {} volumes)", MAX_DYNAMIC_VOLUMES);
}
