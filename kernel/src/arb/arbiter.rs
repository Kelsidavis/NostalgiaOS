//! Arbiter Instance Management
//!
//! Core arbiter structures and allocation logic for PnP resource management.

extern crate alloc;

use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use crate::ke::SpinLock;
use super::{ResourceType, ArbiterAction, ArbiterRequestSource, ARBITER_SIGNATURE};
use super::range::{RangeList, RangeEntry};
use super::ordering::OrderingList;

/// Maximum allocations per arbiter
pub const MAX_ALLOCATIONS: usize = 256;

/// Arbiter instance
#[derive(Clone)]
pub struct ArbiterInstance {
    /// Signature for validation
    pub signature: u32,
    /// Arbiter name
    pub name: [u8; 32],
    pub name_len: usize,
    /// Resource type
    pub resource_type: ResourceType,
    /// Current allocation list
    pub allocation: RangeList,
    /// Pending allocation list (for test/commit)
    pub possible_allocation: RangeList,
    /// Ordering list for allocation priority
    pub ordering_list: OrderingList,
    /// Reserved resources list
    pub reserved_list: OrderingList,
    /// Reference count
    pub reference_count: u32,
    /// Transaction in progress
    pub transaction_in_progress: bool,
    /// Active flag
    pub active: bool,
}

impl ArbiterInstance {
    pub const fn new() -> Self {
        Self {
            signature: 0,
            name: [0; 32],
            name_len: 0,
            resource_type: ResourceType::Null,
            allocation: RangeList::new(),
            possible_allocation: RangeList::new(),
            ordering_list: OrderingList::new(),
            reserved_list: OrderingList::new(),
            reference_count: 0,
            transaction_in_progress: false,
            active: false,
        }
    }

    pub fn init(&mut self, resource_type: ResourceType, name: &str) {
        self.signature = ARBITER_SIGNATURE;
        self.resource_type = resource_type;
        self.name_len = name.len().min(31);
        self.name[..self.name_len].copy_from_slice(&name.as_bytes()[..self.name_len]);
        self.active = true;
        super::register_arbiter();
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("Unknown")
    }
}

/// Arbiter interface for driver use
pub struct ArbiterInterface {
    pub size: u16,
    pub version: u16,
    pub context: *mut ArbiterInstance,
    pub interface_reference: fn(),
    pub interface_dereference: fn(),
}

/// Alternative resource descriptor
#[derive(Clone, Copy)]
pub struct ArbiterAlternative {
    /// Minimum acceptable start
    pub minimum: u64,
    /// Maximum acceptable end
    pub maximum: u64,
    /// Length required
    pub length: u32,
    /// Alignment requirement
    pub alignment: u32,
    /// Priority
    pub priority: i32,
    /// Flags
    pub flags: u32,
}

impl ArbiterAlternative {
    pub const fn new() -> Self {
        Self {
            minimum: 0,
            maximum: u64::MAX,
            length: 0,
            alignment: 1,
            priority: 0,
            flags: 0,
        }
    }
}

/// Allocation state during arbitration
#[derive(Clone)]
pub struct AllocationState {
    /// Current start value being considered
    pub start: u64,
    /// Current end value being considered
    pub end: u64,
    /// Current minimum
    pub current_minimum: u64,
    /// Current maximum
    pub current_maximum: u64,
    /// Current alternative being considered
    pub current_alternative_idx: usize,
    /// Number of alternatives
    pub alternative_count: usize,
    /// Alternatives being considered
    pub alternatives: [ArbiterAlternative; 8],
    /// Flags
    pub flags: u16,
    /// Range attributes
    pub range_attributes: u8,
    /// Available range attributes
    pub range_available_attributes: u8,
}

impl AllocationState {
    pub const fn new() -> Self {
        Self {
            start: 0,
            end: 0,
            current_minimum: 0,
            current_maximum: u64::MAX,
            current_alternative_idx: 0,
            alternative_count: 0,
            alternatives: [ArbiterAlternative::new(); 8],
            flags: 0,
            range_attributes: 0,
            range_available_attributes: 0,
        }
    }
}

/// Global arbiter storage
static mut PORT_ARBITER: ArbiterInstance = ArbiterInstance::new();
static mut MEMORY_ARBITER: ArbiterInstance = ArbiterInstance::new();
static mut IRQ_ARBITER: ArbiterInstance = ArbiterInstance::new();
static mut DMA_ARBITER: ArbiterInstance = ArbiterInstance::new();
static mut BUS_NUMBER_ARBITER: ArbiterInstance = ArbiterInstance::new();

static ARBITER_LOCK: SpinLock<()> = SpinLock::new(());
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize arbiters
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let _guard = ARBITER_LOCK.lock();

    unsafe {
        // Initialize I/O port arbiter
        PORT_ARBITER.init(ResourceType::Port, "PnP I/O Port Arbiter");
        // Reserve standard PC ports
        reserve_standard_ports();

        // Initialize memory arbiter
        MEMORY_ARBITER.init(ResourceType::Memory, "PnP Memory Arbiter");
        // Reserve low memory and ROM areas
        reserve_standard_memory();

        // Initialize IRQ arbiter
        IRQ_ARBITER.init(ResourceType::Interrupt, "PnP IRQ Arbiter");
        // Reserve system IRQs
        reserve_standard_irqs();

        // Initialize DMA arbiter
        DMA_ARBITER.init(ResourceType::Dma, "PnP DMA Arbiter");
        // Reserve system DMA channels
        reserve_standard_dma();

        // Initialize bus number arbiter
        BUS_NUMBER_ARBITER.init(ResourceType::BusNumber, "PnP Bus Number Arbiter");
    }

    crate::serial_println!("[ARB] Initialized 5 resource arbiters");
}

/// Reserve standard PC I/O ports
fn reserve_standard_ports() {
    unsafe {
        // DMA controllers
        PORT_ARBITER.allocation.add_range(0x0000, 0x001F, super::range_flags::BOOT_ALLOCATED, 0);
        PORT_ARBITER.allocation.add_range(0x00C0, 0x00DF, super::range_flags::BOOT_ALLOCATED, 0);

        // PIC controllers
        PORT_ARBITER.allocation.add_range(0x0020, 0x0021, super::range_flags::BOOT_ALLOCATED, 0);
        PORT_ARBITER.allocation.add_range(0x00A0, 0x00A1, super::range_flags::BOOT_ALLOCATED, 0);

        // PIT (timer)
        PORT_ARBITER.allocation.add_range(0x0040, 0x0043, super::range_flags::BOOT_ALLOCATED, 0);

        // Keyboard controller
        PORT_ARBITER.allocation.add_range(0x0060, 0x0064, super::range_flags::BOOT_ALLOCATED, 0);

        // RTC/CMOS
        PORT_ARBITER.allocation.add_range(0x0070, 0x0071, super::range_flags::BOOT_ALLOCATED, 0);

        // System control ports
        PORT_ARBITER.allocation.add_range(0x0092, 0x0092, super::range_flags::BOOT_ALLOCATED, 0);

        // Math coprocessor
        PORT_ARBITER.allocation.add_range(0x00F0, 0x00FF, super::range_flags::BOOT_ALLOCATED, 0);

        // PCI configuration
        PORT_ARBITER.allocation.add_range(0x0CF8, 0x0CFF, super::range_flags::BOOT_ALLOCATED, 0);

        // Primary IDE
        PORT_ARBITER.allocation.add_range(0x01F0, 0x01F7, super::range_flags::BOOT_ALLOCATED, 0);
        PORT_ARBITER.allocation.add_range(0x03F6, 0x03F6, super::range_flags::BOOT_ALLOCATED, 0);

        // Secondary IDE
        PORT_ARBITER.allocation.add_range(0x0170, 0x0177, super::range_flags::BOOT_ALLOCATED, 0);
        PORT_ARBITER.allocation.add_range(0x0376, 0x0376, super::range_flags::BOOT_ALLOCATED, 0);

        // Serial ports
        PORT_ARBITER.allocation.add_range(0x03F8, 0x03FF, super::range_flags::BOOT_ALLOCATED, 0); // COM1
        PORT_ARBITER.allocation.add_range(0x02F8, 0x02FF, super::range_flags::BOOT_ALLOCATED, 0); // COM2

        // VGA
        PORT_ARBITER.allocation.add_range(0x03B0, 0x03DF, super::range_flags::BOOT_ALLOCATED, 0);
    }
}

/// Reserve standard memory regions
fn reserve_standard_memory() {
    unsafe {
        // Low memory (first 1MB) - various BIOS/legacy areas
        MEMORY_ARBITER.allocation.add_range(0x00000, 0x9FFFF, super::range_flags::BOOT_ALLOCATED, 0);

        // VGA buffer
        MEMORY_ARBITER.allocation.add_range(0xA0000, 0xBFFFF, super::range_flags::BOOT_ALLOCATED, 0);

        // ROM area
        MEMORY_ARBITER.allocation.add_range(0xC0000, 0xFFFFF, super::range_flags::BOOT_ALLOCATED, 0);
    }
}

/// Reserve standard IRQs
fn reserve_standard_irqs() {
    unsafe {
        // IRQ 0 - System timer
        IRQ_ARBITER.allocation.add_range(0, 0, super::range_flags::BOOT_ALLOCATED, 0);
        // IRQ 1 - Keyboard
        IRQ_ARBITER.allocation.add_range(1, 1, super::range_flags::BOOT_ALLOCATED, 0);
        // IRQ 2 - Cascade to slave PIC
        IRQ_ARBITER.allocation.add_range(2, 2, super::range_flags::BOOT_ALLOCATED, 0);
        // IRQ 8 - RTC
        IRQ_ARBITER.allocation.add_range(8, 8, super::range_flags::BOOT_ALLOCATED, 0);
        // IRQ 13 - Math coprocessor
        IRQ_ARBITER.allocation.add_range(13, 13, super::range_flags::BOOT_ALLOCATED, 0);
    }
}

/// Reserve standard DMA channels
fn reserve_standard_dma() {
    unsafe {
        // DMA 4 - Cascade
        DMA_ARBITER.allocation.add_range(4, 4, super::range_flags::BOOT_ALLOCATED, 0);
    }
}

/// Get arbiter for resource type
pub fn get_arbiter(resource_type: ResourceType) -> Option<&'static mut ArbiterInstance> {
    let _guard = ARBITER_LOCK.lock();
    unsafe {
        match resource_type {
            ResourceType::Port => Some(&mut PORT_ARBITER),
            ResourceType::Memory | ResourceType::MemoryLarge => Some(&mut MEMORY_ARBITER),
            ResourceType::Interrupt => Some(&mut IRQ_ARBITER),
            ResourceType::Dma => Some(&mut DMA_ARBITER),
            ResourceType::BusNumber => Some(&mut BUS_NUMBER_ARBITER),
            _ => None,
        }
    }
}

/// Test if resources can be allocated
pub fn arb_test_allocation(
    resource_type: ResourceType,
    start: u64,
    end: u64,
    flags: u8,
) -> Result<(), i32> {
    let arbiter = get_arbiter(resource_type).ok_or(-1)?;

    // Check if range is available
    if !arbiter.allocation.is_range_available(start, end, flags) {
        super::record_conflict();
        return Err(-2); // STATUS_CONFLICTING_ADDRESSES
    }

    // Add to possible allocation
    arbiter.possible_allocation.add_range(start, end, flags, 0);
    arbiter.transaction_in_progress = true;

    Ok(())
}

/// Commit pending allocation
pub fn arb_commit_allocation(resource_type: ResourceType) -> Result<(), i32> {
    let arbiter = get_arbiter(resource_type).ok_or(-1)?;

    if !arbiter.transaction_in_progress {
        return Err(-3); // No transaction
    }

    // Move possible allocations to actual allocations
    for i in 0..arbiter.possible_allocation.count {
        let entry = arbiter.possible_allocation.entries[i];
        arbiter.allocation.add_range(entry.start, entry.end, entry.attributes, entry.owner);
        super::record_allocation();
    }

    arbiter.possible_allocation.clear();
    arbiter.transaction_in_progress = false;

    Ok(())
}

/// Rollback pending allocation
pub fn arb_rollback_allocation(resource_type: ResourceType) -> Result<(), i32> {
    let arbiter = get_arbiter(resource_type).ok_or(-1)?;

    if !arbiter.transaction_in_progress {
        return Err(-3);
    }

    arbiter.possible_allocation.clear();
    arbiter.transaction_in_progress = false;

    Ok(())
}

/// Query for conflicts
pub fn arb_query_conflict(
    resource_type: ResourceType,
    start: u64,
    end: u64,
) -> Option<RangeEntry> {
    let arbiter = get_arbiter(resource_type)?;
    arbiter.allocation.find_conflict(start, end)
}

/// Add reserved resource
pub fn arb_add_reserved(
    resource_type: ResourceType,
    start: u64,
    end: u64,
) -> Result<(), i32> {
    let arbiter = get_arbiter(resource_type).ok_or(-1)?;

    // Add to reserved list ordering
    arbiter.reserved_list.add(start, end);

    // Also add to allocation if not already present
    if arbiter.allocation.is_range_available(start, end, 0) {
        arbiter.allocation.add_range(start, end, super::range_flags::BOOT_ALLOCATED, 0);
    }

    Ok(())
}

/// Allocate a resource range
pub fn arb_allocate_range(
    resource_type: ResourceType,
    minimum: u64,
    maximum: u64,
    length: u32,
    alignment: u32,
    flags: u8,
) -> Option<u64> {
    let arbiter = get_arbiter(resource_type)?;

    // Find a suitable range
    if let Some(start) = arbiter.allocation.find_available_range(minimum, maximum, length as u64, alignment as u64, flags) {
        let end = start + length as u64 - 1;
        arbiter.allocation.add_range(start, end, flags, 0);
        super::record_allocation();
        return Some(start);
    }

    None
}

/// Free a resource range
pub fn arb_free_range(
    resource_type: ResourceType,
    start: u64,
    end: u64,
) -> Result<(), i32> {
    let arbiter = get_arbiter(resource_type).ok_or(-1)?;
    arbiter.allocation.delete_range(start, end);
    Ok(())
}

/// Get port range count
pub fn get_port_range_count() -> u32 {
    unsafe { PORT_ARBITER.allocation.count as u32 }
}

/// Get memory range count
pub fn get_memory_range_count() -> u32 {
    unsafe { MEMORY_ARBITER.allocation.count as u32 }
}

/// Get IRQ range count
pub fn get_irq_range_count() -> u32 {
    unsafe { IRQ_ARBITER.allocation.count as u32 }
}

/// Get DMA range count
pub fn get_dma_range_count() -> u32 {
    unsafe { DMA_ARBITER.allocation.count as u32 }
}

/// List all allocated ranges for a resource type
pub fn list_ranges(resource_type: ResourceType) -> Vec<RangeEntry> {
    let mut result = Vec::new();

    if let Some(arbiter) = get_arbiter(resource_type) {
        for i in 0..arbiter.allocation.count {
            result.push(arbiter.allocation.entries[i]);
        }
    }

    result
}
