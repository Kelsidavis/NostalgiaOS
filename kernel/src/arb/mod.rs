//! Resource Arbiter Subsystem (ARB)
//!
//! Windows NT PnP resource arbitration for managing hardware resources.
//! Arbiters manage allocations of I/O ports, memory ranges, IRQs, and DMA channels.
//!
//! Reference: Windows Server 2003 base/ntos/arb/

extern crate alloc;

pub mod arbiter;
pub mod range;
pub mod ordering;

use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering as AtomicOrdering};
use crate::ke::SpinLock;

/// Resource types that can be arbitrated
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ResourceType {
    /// Null resource (placeholder)
    Null = 0,
    /// I/O port resource
    Port = 1,
    /// Interrupt resource
    Interrupt = 2,
    /// Memory resource
    Memory = 3,
    /// DMA channel resource
    Dma = 4,
    /// Device-specific resource
    DeviceSpecific = 5,
    /// Bus number resource
    BusNumber = 6,
    /// Memory large (64-bit addressable)
    MemoryLarge = 7,
}

impl From<u32> for ResourceType {
    fn from(value: u32) -> Self {
        match value {
            0 => ResourceType::Null,
            1 => ResourceType::Port,
            2 => ResourceType::Interrupt,
            3 => ResourceType::Memory,
            4 => ResourceType::Dma,
            5 => ResourceType::DeviceSpecific,
            6 => ResourceType::BusNumber,
            7 => ResourceType::MemoryLarge,
            _ => ResourceType::Null,
        }
    }
}

/// Arbiter action types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ArbiterAction {
    /// Test if resources can be allocated
    TestAllocation = 0,
    /// Retry allocation
    RetestAllocation = 1,
    /// Commit pending allocation
    CommitAllocation = 2,
    /// Rollback pending allocation
    RollbackAllocation = 3,
    /// Add reserved resources
    AddReserved = 4,
    /// Query arbitration capability
    QueryArbitrate = 5,
    /// Query for conflicts
    QueryConflict = 6,
    /// Write PCI configuration
    WritePciConfig = 7,
    /// Boot allocation (legacy)
    BootAllocation = 8,
}

/// Request source for resource allocation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ArbiterRequestSource {
    /// Undefined request
    Undefined = 0,
    /// Legacy reported resources
    LegacyReported = 1,
    /// Legacy assigned resources
    LegacyAssigned = 2,
    /// PnP detected resources
    PnpDetected = 3,
    /// PnP enumerated resources
    PnpEnumerated = 4,
}

/// Arbiter result flags
pub mod result_flags {
    pub const NULL_CONFLICT_OK: u32 = 0x0001;
    pub const CONFLICT_DETECTED: u32 = 0x0002;
    pub const NEEDS_REBALANCE: u32 = 0x0004;
}

/// Range allocation flags
pub mod range_flags {
    pub const BOOT_ALLOCATED: u8 = 0x01;
    pub const SHARE_DRIVER_EXCLUSIVE: u8 = 0x02;
    pub const ALIAS: u8 = 0x10;
    pub const POSITIVE_DECODE: u8 = 0x20;
    pub const SHARED: u8 = 0x40;
}

/// Alternative resource flags
pub mod alternative_flags {
    pub const SHARED: u32 = 0x00000001;
    pub const FIXED: u32 = 0x00000002;
    pub const INVALID: u32 = 0x00000004;
}

/// State flags
pub mod state_flags {
    pub const RETEST: u16 = 0x0001;
    pub const BOOT: u16 = 0x0002;
    pub const CONFLICT: u16 = 0x0004;
    pub const NULL_CONFLICT_OK: u16 = 0x0008;
}

/// Maximum number of arbiters
pub const MAX_ARBITERS: usize = 16;

/// Arbiter instance signature
pub const ARBITER_SIGNATURE: u32 = 0x4172_6253; // "ArbS"

/// Global arbiter state
static ARB_LOCK: SpinLock<()> = SpinLock::new(());
static ARBITER_COUNT: AtomicU32 = AtomicU32::new(0);
static ALLOCATIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static CONFLICTS_DETECTED: AtomicU64 = AtomicU64::new(0);

/// Initialize the arbiter subsystem
pub fn init() {
    crate::serial_println!("[ARB] Initializing resource arbiter subsystem");

    // Initialize arbiters for each resource type
    arbiter::init();

    // Initialize range management
    range::init();

    // Initialize ordering lists
    ordering::init();

    crate::serial_println!("[ARB] Resource arbiter subsystem initialized");
}

/// Get arbiter statistics
#[derive(Debug, Clone, Copy)]
pub struct ArbiterStats {
    pub arbiters_registered: u32,
    pub total_allocations: u64,
    pub conflicts_detected: u64,
    pub port_ranges_used: u32,
    pub memory_ranges_used: u32,
    pub irq_ranges_used: u32,
    pub dma_ranges_used: u32,
}

pub fn get_stats() -> ArbiterStats {
    ArbiterStats {
        arbiters_registered: ARBITER_COUNT.load(AtomicOrdering::Relaxed),
        total_allocations: ALLOCATIONS_TOTAL.load(AtomicOrdering::Relaxed),
        conflicts_detected: CONFLICTS_DETECTED.load(AtomicOrdering::Relaxed),
        port_ranges_used: arbiter::get_port_range_count(),
        memory_ranges_used: arbiter::get_memory_range_count(),
        irq_ranges_used: arbiter::get_irq_range_count(),
        dma_ranges_used: arbiter::get_dma_range_count(),
    }
}

/// Record a successful allocation
pub fn record_allocation() {
    ALLOCATIONS_TOTAL.fetch_add(1, AtomicOrdering::Relaxed);
}

/// Record a conflict
pub fn record_conflict() {
    CONFLICTS_DETECTED.fetch_add(1, AtomicOrdering::Relaxed);
}

/// Increment arbiter count
pub fn register_arbiter() {
    ARBITER_COUNT.fetch_add(1, AtomicOrdering::Relaxed);
}

/// Decrement arbiter count
pub fn unregister_arbiter() {
    ARBITER_COUNT.fetch_sub(1, AtomicOrdering::Relaxed);
}

// Re-export key types
pub use arbiter::{
    ArbiterInstance, ArbiterInterface,
    arb_test_allocation, arb_commit_allocation, arb_rollback_allocation,
    arb_query_conflict, arb_add_reserved,
};

pub use range::{
    RangeList, RangeEntry,
    rtl_add_range, rtl_delete_range, rtl_find_range, rtl_is_range_available,
};

pub use ordering::{
    OrderingList, Ordering,
    arb_init_ordering_list, arb_add_ordering, arb_prune_ordering,
};
