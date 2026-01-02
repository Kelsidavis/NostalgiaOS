//! Removable Storage Manager
//!
//! Windows Server 2003 Removable Storage snap-in implementation.
//! Provides tape library and media management.
//!
//! # Features
//!
//! - Media libraries (tape, optical)
//! - Media pools
//! - Physical media tracking
//! - Work queues
//! - Operator requests
//!
//! # References
//!
//! Based on Windows Server 2003 Removable Storage (ntmsmgr.msc)

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::UserHandle;
use bitflags::bitflags;

/// HWND type alias
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum libraries
const MAX_LIBRARIES: usize = 8;

/// Maximum drives per library
const MAX_DRIVES: usize = 16;

/// Maximum slots per library
const MAX_SLOTS: usize = 64;

/// Maximum media pools
const MAX_POOLS: usize = 32;

/// Maximum media per pool
const MAX_MEDIA: usize = 128;

/// Maximum work queue items
const MAX_WORK_ITEMS: usize = 64;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum barcode length
const MAX_BARCODE_LEN: usize = 32;

// ============================================================================
// Library Type
// ============================================================================

/// Media library type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum LibraryType {
    /// Standalone drive (no changer)
    #[default]
    Standalone = 0,
    /// Robotic tape library
    Changer = 1,
    /// Optical jukebox
    OpticalJukebox = 2,
    /// Offline library (manual)
    Offline = 3,
}

impl LibraryType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Standalone => "Standalone Drive",
            Self::Changer => "Automated Library",
            Self::OpticalJukebox => "Optical Jukebox",
            Self::Offline => "Offline Library",
        }
    }
}

// ============================================================================
// Media Type
// ============================================================================

/// Physical media type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum MediaType {
    /// Unknown media
    #[default]
    Unknown = 0,
    /// 4mm DAT/DDS tape
    Dat4mm = 1,
    /// 8mm tape
    Tape8mm = 2,
    /// DLT tape
    Dlt = 3,
    /// LTO Ultrium
    Lto = 4,
    /// AIT tape
    Ait = 5,
    /// SDLT tape
    Sdlt = 6,
    /// CD-ROM
    CdRom = 7,
    /// DVD
    Dvd = 8,
    /// MO disk
    MagnetoOptical = 9,
    /// Floppy disk
    Floppy = 10,
}

impl MediaType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Dat4mm => "4mm DAT",
            Self::Tape8mm => "8mm Tape",
            Self::Dlt => "DLT",
            Self::Lto => "LTO Ultrium",
            Self::Ait => "AIT",
            Self::Sdlt => "SDLT",
            Self::CdRom => "CD-ROM",
            Self::Dvd => "DVD",
            Self::MagnetoOptical => "MO",
            Self::Floppy => "Floppy",
        }
    }

    pub const fn capacity_mb(&self) -> u32 {
        match self {
            Self::Unknown => 0,
            Self::Dat4mm => 40000,      // 40 GB
            Self::Tape8mm => 20000,     // 20 GB
            Self::Dlt => 80000,         // 80 GB
            Self::Lto => 400000,        // 400 GB (LTO-3)
            Self::Ait => 100000,        // 100 GB
            Self::Sdlt => 160000,       // 160 GB
            Self::CdRom => 700,         // 700 MB
            Self::Dvd => 4700,          // 4.7 GB
            Self::MagnetoOptical => 9100, // 9.1 GB
            Self::Floppy => 1,          // 1.44 MB
        }
    }
}

// ============================================================================
// Media State
// ============================================================================

/// Physical media state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum MediaState {
    /// Media is idle (in slot)
    #[default]
    Idle = 0,
    /// Media is in use (mounted)
    InUse = 1,
    /// Media is being mounted
    Mounting = 2,
    /// Media is being dismounted
    Dismounting = 3,
    /// Media is being moved
    Moving = 4,
    /// Media is offline
    Offline = 5,
    /// Media has error
    Error = 6,
}

impl MediaState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::InUse => "In Use",
            Self::Mounting => "Mounting",
            Self::Dismounting => "Dismounting",
            Self::Moving => "Moving",
            Self::Offline => "Offline",
            Self::Error => "Error",
        }
    }
}

// ============================================================================
// Pool Type
// ============================================================================

/// Media pool type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum PoolType {
    /// System pool (scratch, import, etc.)
    #[default]
    System = 0,
    /// Free pool (available media)
    Free = 1,
    /// Application pool
    Application = 2,
    /// Unrecognized media
    Unrecognized = 3,
    /// Import pool
    Import = 4,
}

impl PoolType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::System => "System",
            Self::Free => "Free",
            Self::Application => "Application",
            Self::Unrecognized => "Unrecognized",
            Self::Import => "Import",
        }
    }
}

// ============================================================================
// Drive State
// ============================================================================

/// Drive state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum DriveState {
    /// Drive is idle (empty)
    #[default]
    Idle = 0,
    /// Drive has media loaded
    Loaded = 1,
    /// Drive is busy (I/O in progress)
    Busy = 2,
    /// Drive is offline
    Offline = 3,
    /// Drive has error
    Error = 4,
    /// Drive needs cleaning
    NeedsCleaning = 5,
}

impl DriveState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Loaded => "Loaded",
            Self::Busy => "Busy",
            Self::Offline => "Offline",
            Self::Error => "Error",
            Self::NeedsCleaning => "Needs Cleaning",
        }
    }
}

bitflags! {
    /// Media pool allocation flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct PoolFlags: u32 {
        /// Draw media from free pool automatically
        const AUTO_DRAW = 0x0001;
        /// Return media to free pool on deallocation
        const AUTO_RETURN = 0x0002;
        /// Allow multiple allocation
        const MULTI_ALLOCATE = 0x0004;
    }
}

// ============================================================================
// Drive
// ============================================================================

/// Media drive
#[derive(Clone, Copy)]
pub struct MediaDrive {
    /// Drive in use
    pub in_use: bool,
    /// Drive ID
    pub drive_id: u32,
    /// Drive name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Drive state
    pub state: DriveState,
    /// Loaded media ID (0 if empty)
    pub loaded_media: u32,
    /// Drive number in library
    pub drive_number: u8,
    /// Total mounts
    pub mount_count: u64,
    /// Hours of use
    pub hours_used: u32,
    /// Cleaning cycles remaining
    pub clean_cycles: u16,
}

impl MediaDrive {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            drive_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            state: DriveState::Idle,
            loaded_media: 0,
            drive_number: 0,
            mount_count: 0,
            hours_used: 0,
            clean_cycles: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

// ============================================================================
// Slot
// ============================================================================

/// Media slot (storage element)
#[derive(Clone, Copy)]
pub struct MediaSlot {
    /// Slot in use
    pub in_use: bool,
    /// Slot number
    pub slot_number: u16,
    /// Media ID in slot (0 if empty)
    pub media_id: u32,
    /// Slot is a mail slot (I/E port)
    pub is_mail_slot: bool,
    /// Slot is a cleaning slot
    pub is_cleaning_slot: bool,
}

impl MediaSlot {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            slot_number: 0,
            media_id: 0,
            is_mail_slot: false,
            is_cleaning_slot: false,
        }
    }
}

// ============================================================================
// Physical Media
// ============================================================================

/// Physical media (cartridge/disc)
#[derive(Clone, Copy)]
pub struct PhysicalMedia {
    /// Media in use
    pub in_use: bool,
    /// Media ID
    pub media_id: u32,
    /// Media type
    pub media_type: MediaType,
    /// Media state
    pub state: MediaState,
    /// Barcode
    pub barcode: [u8; MAX_BARCODE_LEN],
    /// Barcode length
    pub barcode_len: usize,
    /// Pool ID (which pool media belongs to)
    pub pool_id: u32,
    /// Library ID
    pub library_id: u32,
    /// Current location (slot number, or drive ID + 0x8000)
    pub location: u16,
    /// Home slot
    pub home_slot: u16,
    /// Mount count
    pub mount_count: u32,
    /// Side (for dual-sided media)
    pub side: u8,
    /// Write protected
    pub write_protected: bool,
    /// Capacity used (MB)
    pub capacity_used: u32,
    /// Last mounted timestamp
    pub last_mounted: u64,
    /// Allocated to application
    pub allocated: bool,
    /// Allocated application name
    pub app_name: [u8; 32],
    /// App name length
    pub app_name_len: usize,
}

impl PhysicalMedia {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            media_id: 0,
            media_type: MediaType::Unknown,
            state: MediaState::Idle,
            barcode: [0u8; MAX_BARCODE_LEN],
            barcode_len: 0,
            pool_id: 0,
            library_id: 0,
            location: 0,
            home_slot: 0,
            mount_count: 0,
            side: 0,
            write_protected: false,
            capacity_used: 0,
            last_mounted: 0,
            allocated: false,
            app_name: [0u8; 32],
            app_name_len: 0,
        }
    }

    pub fn set_barcode(&mut self, barcode: &[u8]) {
        let len = barcode.len().min(MAX_BARCODE_LEN);
        self.barcode[..len].copy_from_slice(&barcode[..len]);
        self.barcode_len = len;
    }
}

// ============================================================================
// Media Pool
// ============================================================================

/// Media pool
#[derive(Clone, Copy)]
pub struct MediaPool {
    /// Pool in use
    pub in_use: bool,
    /// Pool ID
    pub pool_id: u32,
    /// Pool name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Pool type
    pub pool_type: PoolType,
    /// Media type for this pool
    pub media_type: MediaType,
    /// Allocation flags
    pub flags: PoolFlags,
    /// Maximum allocations per media
    pub max_allocations: u32,
    /// Media IDs in this pool
    pub media: [u32; MAX_MEDIA],
    /// Media count
    pub media_count: usize,
    /// Draw pool (where to get new media from)
    pub draw_pool_id: u32,
}

impl MediaPool {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            pool_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            pool_type: PoolType::Application,
            media_type: MediaType::Unknown,
            flags: PoolFlags::empty(),
            max_allocations: 1,
            media: [0u32; MAX_MEDIA],
            media_count: 0,
            draw_pool_id: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn add_media(&mut self, media_id: u32) -> bool {
        if self.media_count >= MAX_MEDIA {
            return false;
        }
        self.media[self.media_count] = media_id;
        self.media_count += 1;
        true
    }
}

// ============================================================================
// Media Library
// ============================================================================

/// Media library (changer or standalone)
#[derive(Clone, Copy)]
pub struct MediaLibrary {
    /// Library in use
    pub in_use: bool,
    /// Library ID
    pub library_id: u32,
    /// Library name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Library type
    pub library_type: LibraryType,
    /// Media type supported
    pub media_type: MediaType,
    /// Enabled
    pub enabled: bool,
    /// Drives
    pub drives: [MediaDrive; MAX_DRIVES],
    /// Drive count
    pub drive_count: usize,
    /// Slots
    pub slots: [MediaSlot; MAX_SLOTS],
    /// Slot count
    pub slot_count: usize,
    /// Number of mail slots
    pub mail_slot_count: u8,
    /// Serial number
    pub serial_number: [u8; 32],
    /// Serial number length
    pub serial_len: usize,
}

impl MediaLibrary {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            library_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            library_type: LibraryType::Standalone,
            media_type: MediaType::Unknown,
            enabled: true,
            drives: [const { MediaDrive::new() }; MAX_DRIVES],
            drive_count: 0,
            slots: [const { MediaSlot::new() }; MAX_SLOTS],
            slot_count: 0,
            mail_slot_count: 0,
            serial_number: [0u8; 32],
            serial_len: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn add_drive(&mut self, name: &[u8]) -> Option<usize> {
        if self.drive_count >= MAX_DRIVES {
            return None;
        }
        let drive = &mut self.drives[self.drive_count];
        drive.in_use = true;
        drive.drive_number = self.drive_count as u8;
        drive.set_name(name);
        let idx = self.drive_count;
        self.drive_count += 1;
        Some(idx)
    }

    pub fn add_slot(&mut self) -> Option<usize> {
        if self.slot_count >= MAX_SLOTS {
            return None;
        }
        let slot = &mut self.slots[self.slot_count];
        slot.in_use = true;
        slot.slot_number = self.slot_count as u16;
        let idx = self.slot_count;
        self.slot_count += 1;
        Some(idx)
    }
}

// ============================================================================
// Work Queue Item
// ============================================================================

/// Work request type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum WorkType {
    /// Mount media
    #[default]
    Mount = 0,
    /// Dismount media
    Dismount = 1,
    /// Move media
    Move = 2,
    /// Inventory library
    Inventory = 3,
    /// Eject media
    Eject = 4,
    /// Inject media
    Inject = 5,
    /// Clean drive
    CleanDrive = 6,
}

/// Work queue item
#[derive(Clone, Copy)]
pub struct WorkItem {
    /// Item in use
    pub in_use: bool,
    /// Work ID
    pub work_id: u32,
    /// Work type
    pub work_type: WorkType,
    /// Library ID
    pub library_id: u32,
    /// Media ID (if applicable)
    pub media_id: u32,
    /// Target drive/slot
    pub target: u16,
    /// Priority (higher = more urgent)
    pub priority: u8,
    /// Submitted timestamp
    pub submitted: u64,
    /// Completed
    pub completed: bool,
    /// Error code (0 = success)
    pub error_code: u32,
}

impl WorkItem {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            work_id: 0,
            work_type: WorkType::Mount,
            library_id: 0,
            media_id: 0,
            target: 0,
            priority: 5,
            submitted: 0,
            completed: false,
            error_code: 0,
        }
    }
}

// ============================================================================
// Manager State
// ============================================================================

/// Removable Storage Manager state
struct NtmsManagerState {
    /// Libraries
    libraries: [MediaLibrary; MAX_LIBRARIES],
    /// Library count
    library_count: usize,
    /// Media pools
    pools: [MediaPool; MAX_POOLS],
    /// Pool count
    pool_count: usize,
    /// Physical media
    media: [PhysicalMedia; MAX_MEDIA],
    /// Media count
    media_count: usize,
    /// Work queue
    work_queue: [WorkItem; MAX_WORK_ITEMS],
    /// Work queue count
    work_count: usize,
    /// Next IDs
    next_library_id: u32,
    next_pool_id: u32,
    next_media_id: u32,
    next_work_id: u32,
    next_drive_id: u32,
    /// Dialog handle
    dialog_handle: HWND,
}

impl NtmsManagerState {
    pub const fn new() -> Self {
        Self {
            libraries: [const { MediaLibrary::new() }; MAX_LIBRARIES],
            library_count: 0,
            pools: [const { MediaPool::new() }; MAX_POOLS],
            pool_count: 0,
            media: [const { PhysicalMedia::new() }; MAX_MEDIA],
            media_count: 0,
            work_queue: [const { WorkItem::new() }; MAX_WORK_ITEMS],
            work_count: 0,
            next_library_id: 1,
            next_pool_id: 1,
            next_media_id: 1,
            next_work_id: 1,
            next_drive_id: 1,
            dialog_handle: UserHandle::from_raw(0),
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static NTMS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NTMS_MANAGER: SpinLock<NtmsManagerState> = SpinLock::new(NtmsManagerState::new());

// Statistics
static LIBRARY_COUNT: AtomicU32 = AtomicU32::new(0);
static MEDIA_COUNT: AtomicU32 = AtomicU32::new(0);
static MOUNT_COUNT: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Removable Storage Manager
pub fn init() {
    if NTMS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = NTMS_MANAGER.lock();

    // Create system pools
    let free_pool_id = state.next_pool_id;
    state.next_pool_id += 1;

    let pool = &mut state.pools[0];
    pool.in_use = true;
    pool.pool_id = free_pool_id;
    pool.set_name(b"Free");
    pool.pool_type = PoolType::Free;
    pool.flags = PoolFlags::empty();
    state.pool_count = 1;

    let import_pool_id = state.next_pool_id;
    state.next_pool_id += 1;

    let pool = &mut state.pools[1];
    pool.in_use = true;
    pool.pool_id = import_pool_id;
    pool.set_name(b"Import");
    pool.pool_type = PoolType::Import;
    state.pool_count = 2;

    let unrec_pool_id = state.next_pool_id;
    state.next_pool_id += 1;

    let pool = &mut state.pools[2];
    pool.in_use = true;
    pool.pool_id = unrec_pool_id;
    pool.set_name(b"Unrecognized");
    pool.pool_type = PoolType::Unrecognized;
    state.pool_count = 3;
}

// ============================================================================
// Library Management
// ============================================================================

/// Create a library
pub fn create_library(
    name: &[u8],
    library_type: LibraryType,
    media_type: MediaType,
) -> Option<usize> {
    let mut state = NTMS_MANAGER.lock();

    if state.library_count >= MAX_LIBRARIES {
        return None;
    }

    let library_id = state.next_library_id;
    state.next_library_id += 1;

    let idx = state.library_count;
    let library = &mut state.libraries[idx];
    library.in_use = true;
    library.library_id = library_id;
    library.set_name(name);
    library.library_type = library_type;
    library.media_type = media_type;
    library.enabled = true;

    state.library_count += 1;
    LIBRARY_COUNT.fetch_add(1, Ordering::Relaxed);

    Some(idx)
}

/// Get library
pub fn get_library(index: usize) -> Option<MediaLibrary> {
    let state = NTMS_MANAGER.lock();
    if index < state.library_count && state.libraries[index].in_use {
        Some(state.libraries[index])
    } else {
        None
    }
}

/// Enable/disable library
pub fn set_library_enabled(index: usize, enabled: bool) -> bool {
    let mut state = NTMS_MANAGER.lock();
    if index >= MAX_LIBRARIES || !state.libraries[index].in_use {
        return false;
    }
    state.libraries[index].enabled = enabled;
    true
}

/// Add drive to library
pub fn add_drive(library_index: usize, name: &[u8]) -> Option<usize> {
    let mut state = NTMS_MANAGER.lock();
    if library_index >= MAX_LIBRARIES || !state.libraries[library_index].in_use {
        return None;
    }

    let drive_id = state.next_drive_id;
    state.next_drive_id += 1;

    let library = &mut state.libraries[library_index];
    if let Some(idx) = library.add_drive(name) {
        library.drives[idx].drive_id = drive_id;
        return Some(idx);
    }
    None
}

/// Add slots to library
pub fn add_slots(library_index: usize, count: usize) -> bool {
    let mut state = NTMS_MANAGER.lock();
    if library_index >= MAX_LIBRARIES || !state.libraries[library_index].in_use {
        return false;
    }

    let library = &mut state.libraries[library_index];
    for _ in 0..count {
        if library.add_slot().is_none() {
            return false;
        }
    }
    true
}

// ============================================================================
// Media Pool Management
// ============================================================================

/// Create a media pool
pub fn create_pool(name: &[u8], media_type: MediaType) -> Option<usize> {
    let mut state = NTMS_MANAGER.lock();

    if state.pool_count >= MAX_POOLS {
        return None;
    }

    let pool_id = state.next_pool_id;
    state.next_pool_id += 1;

    // Find free pool id first
    let mut draw_pool_id = 0u32;
    for p in state.pools.iter() {
        if p.in_use && p.pool_type == PoolType::Free {
            draw_pool_id = p.pool_id;
            break;
        }
    }

    let idx = state.pool_count;
    let pool = &mut state.pools[idx];
    pool.in_use = true;
    pool.pool_id = pool_id;
    pool.set_name(name);
    pool.pool_type = PoolType::Application;
    pool.media_type = media_type;
    pool.flags = PoolFlags::AUTO_DRAW | PoolFlags::AUTO_RETURN;
    pool.max_allocations = 1;
    pool.draw_pool_id = draw_pool_id;

    state.pool_count += 1;
    Some(idx)
}

/// Get pool
pub fn get_pool(index: usize) -> Option<MediaPool> {
    let state = NTMS_MANAGER.lock();
    if index < state.pool_count && state.pools[index].in_use {
        Some(state.pools[index])
    } else {
        None
    }
}

/// Delete a pool
pub fn delete_pool(index: usize) -> bool {
    let mut state = NTMS_MANAGER.lock();
    if index >= MAX_POOLS || !state.pools[index].in_use {
        return false;
    }

    // Don't allow deleting system pools
    if state.pools[index].pool_type != PoolType::Application {
        return false;
    }

    state.pools[index] = MediaPool::new();
    true
}

// ============================================================================
// Physical Media Management
// ============================================================================

/// Add physical media
pub fn add_media(
    library_index: usize,
    slot: u16,
    media_type: MediaType,
    barcode: &[u8],
) -> Option<u32> {
    let mut state = NTMS_MANAGER.lock();

    if library_index >= MAX_LIBRARIES || !state.libraries[library_index].in_use {
        return None;
    }

    if state.media_count >= MAX_MEDIA {
        return None;
    }

    let media_id = state.next_media_id;
    state.next_media_id += 1;

    let library_id = state.libraries[library_index].library_id;
    let library_slot_count = state.libraries[library_index].slot_count;

    // Find import pool index first
    let mut import_pool_idx = None;
    let mut import_pool_id = 0u32;
    for (i, pool) in state.pools.iter().enumerate() {
        if pool.in_use && pool.pool_type == PoolType::Import {
            import_pool_idx = Some(i);
            import_pool_id = pool.pool_id;
            break;
        }
    }

    let idx = state.media_count;
    let media = &mut state.media[idx];
    media.in_use = true;
    media.media_id = media_id;
    media.media_type = media_type;
    media.state = MediaState::Idle;
    media.set_barcode(barcode);
    media.library_id = library_id;
    media.location = slot;
    media.home_slot = slot;
    media.pool_id = import_pool_id;

    // Add to import pool
    if let Some(pool_idx) = import_pool_idx {
        state.pools[pool_idx].add_media(media_id);
    }

    // Update slot
    if (slot as usize) < library_slot_count {
        state.libraries[library_index].slots[slot as usize].media_id = media_id;
    }

    state.media_count += 1;
    MEDIA_COUNT.fetch_add(1, Ordering::Relaxed);

    Some(media_id)
}

/// Get media by ID
pub fn get_media(media_id: u32) -> Option<PhysicalMedia> {
    let state = NTMS_MANAGER.lock();
    for media in state.media.iter() {
        if media.in_use && media.media_id == media_id {
            return Some(*media);
        }
    }
    None
}

/// Move media to a pool
pub fn move_media_to_pool(media_id: u32, pool_id: u32) -> bool {
    let mut state = NTMS_MANAGER.lock();

    // Find media
    let mut media_idx = None;
    let mut old_pool_id = 0u32;
    for (i, media) in state.media.iter().enumerate() {
        if media.in_use && media.media_id == media_id {
            media_idx = Some(i);
            old_pool_id = media.pool_id;
            break;
        }
    }

    let media_idx = match media_idx {
        Some(i) => i,
        None => return false,
    };

    // Remove from old pool
    for pool in state.pools.iter_mut() {
        if pool.in_use && pool.pool_id == old_pool_id {
            for i in 0..pool.media_count {
                if pool.media[i] == media_id {
                    pool.media[i] = pool.media[pool.media_count - 1];
                    pool.media_count -= 1;
                    break;
                }
            }
            break;
        }
    }

    // Add to new pool
    for pool in state.pools.iter_mut() {
        if pool.in_use && pool.pool_id == pool_id {
            if !pool.add_media(media_id) {
                return false;
            }
            state.media[media_idx].pool_id = pool_id;
            return true;
        }
    }

    false
}

// ============================================================================
// Work Queue
// ============================================================================

/// Submit mount request
pub fn mount_media(library_id: u32, media_id: u32, drive_number: u16) -> Option<u32> {
    let mut state = NTMS_MANAGER.lock();

    if state.work_count >= MAX_WORK_ITEMS {
        return None;
    }

    let work_id = state.next_work_id;
    state.next_work_id += 1;

    let idx = state.work_count;
    let work = &mut state.work_queue[idx];
    work.in_use = true;
    work.work_id = work_id;
    work.work_type = WorkType::Mount;
    work.library_id = library_id;
    work.media_id = media_id;
    work.target = drive_number;
    work.priority = 5;
    work.completed = false;

    state.work_count += 1;
    MOUNT_COUNT.fetch_add(1, Ordering::Relaxed);

    Some(work_id)
}

/// Submit dismount request
pub fn dismount_media(library_id: u32, drive_number: u16) -> Option<u32> {
    let mut state = NTMS_MANAGER.lock();

    if state.work_count >= MAX_WORK_ITEMS {
        return None;
    }

    let work_id = state.next_work_id;
    state.next_work_id += 1;

    let idx = state.work_count;
    let work = &mut state.work_queue[idx];
    work.in_use = true;
    work.work_id = work_id;
    work.work_type = WorkType::Dismount;
    work.library_id = library_id;
    work.target = drive_number;
    work.priority = 5;
    work.completed = false;

    state.work_count += 1;

    Some(work_id)
}

/// Get work item status
pub fn get_work_status(work_id: u32) -> Option<(bool, u32)> {
    let state = NTMS_MANAGER.lock();
    for work in state.work_queue.iter() {
        if work.in_use && work.work_id == work_id {
            return Some((work.completed, work.error_code));
        }
    }
    None
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_statistics() -> (u32, u32, u64) {
    (
        LIBRARY_COUNT.load(Ordering::Relaxed),
        MEDIA_COUNT.load(Ordering::Relaxed),
        MOUNT_COUNT.load(Ordering::Relaxed),
    )
}

// ============================================================================
// Dialog Functions
// ============================================================================

/// Show Removable Storage Manager
pub fn show_dialog(_parent: HWND) -> HWND {
    let mut state = NTMS_MANAGER.lock();
    let handle = UserHandle::from_raw(0x4D01);
    state.dialog_handle = handle;
    handle
}

/// Show library properties
pub fn show_library_properties(_library_index: usize) -> HWND {
    UserHandle::from_raw(0x4D02)
}

/// Show drive properties
pub fn show_drive_properties(_library_index: usize, _drive_index: usize) -> HWND {
    UserHandle::from_raw(0x4D03)
}

/// Show media properties
pub fn show_media_properties(_media_id: u32) -> HWND {
    UserHandle::from_raw(0x4D04)
}

/// Show pool properties
pub fn show_pool_properties(_pool_index: usize) -> HWND {
    UserHandle::from_raw(0x4D05)
}

/// Show work queue
pub fn show_work_queue() -> HWND {
    UserHandle::from_raw(0x4D06)
}

/// Close dialog
pub fn close_dialog() {
    let mut state = NTMS_MANAGER.lock();
    state.dialog_handle = UserHandle::from_raw(0);
}
