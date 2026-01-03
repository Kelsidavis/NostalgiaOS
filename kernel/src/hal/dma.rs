//! HAL DMA Support
//!
//! Provides Direct Memory Access abstraction for device drivers:
//!
//! - **DMA Adapter**: Per-device DMA configuration
//! - **Scatter/Gather**: Efficient multi-buffer transfers
//! - **Common Buffer**: Contiguous DMA-accessible memory
//! - **Map Registers**: Address translation for DMA
//!
//! # Architecture
//!
//! ```text
//! Device Driver
//!       │
//!       ▼
//! ┌─────────────┐
//! │ DMA Adapter │  Per-device DMA context
//! └──────┬──────┘
//!        │
//!        ▼
//! ┌─────────────┐
//! │ Map Register│  Physical/virtual translation
//! └──────┬──────┘
//!        │
//!        ▼
//! ┌─────────────┐
//! │ DMA Channel │  Hardware DMA controller
//! └─────────────┘
//! ```
//!
//! # NT Functions
//!
//! - `IoGetDmaAdapter` - Get DMA adapter for device
//! - `AllocateCommonBuffer` - Allocate contiguous DMA memory
//! - `FreeCommonBuffer` - Free DMA memory
//! - `GetScatterGatherList` - Build scatter/gather list
//! - `PutScatterGatherList` - Release scatter/gather list
//! - `MapTransfer` - Map a buffer for DMA
//!
//! # Usage
//!
//! ```ignore
//! // Get DMA adapter
//! let adapter = hal_get_dma_adapter(&device_desc)?;
//!
//! // Allocate common buffer
//! let (virt, phys) = adapter.allocate_common_buffer(4096)?;
//!
//! // Build scatter/gather list
//! let sg_list = adapter.build_scatter_gather_list(mdl, length)?;
//! ```

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;

/// Maximum number of DMA adapters
pub const MAX_DMA_ADAPTERS: usize = 64;

/// Maximum scatter/gather elements per transfer
pub const MAX_SG_ELEMENTS: usize = 64;

/// Maximum map registers per adapter
pub const MAX_MAP_REGISTERS: usize = 256;

/// DMA transfer width
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmaWidth {
    /// 8-bit transfers
    Width8Bits = 0,
    /// 16-bit transfers
    Width16Bits = 1,
    /// 32-bit transfers
    #[default]
    Width32Bits = 2,
    /// 64-bit transfers
    Width64Bits = 3,
}

/// DMA transfer speed
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmaSpeed {
    /// Compatible mode (ISA speed)
    Compatible = 0,
    /// Type A timing
    TypeA = 1,
    /// Type B timing
    TypeB = 2,
    /// Type C timing (burst)
    #[default]
    TypeC = 3,
    /// Type F timing (fast)
    TypeF = 4,
}

/// DMA channel mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmaMode {
    /// Demand transfer mode
    Demand = 0,
    /// Single transfer mode
    Single = 1,
    /// Block transfer mode
    #[default]
    Block = 2,
    /// Cascade mode (for chaining)
    Cascade = 3,
}

/// DMA direction
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// Read from device to memory
    ReadFromDevice = 0,
    /// Write from memory to device
    WriteToDevice = 1,
}

/// Device description for DMA adapter allocation
#[derive(Debug, Clone, Copy)]
pub struct DeviceDescription {
    /// Version (should be DEVICE_DESCRIPTION_VERSION)
    pub version: u32,
    /// Master device (can initiate DMA)
    pub master: bool,
    /// Scatter/gather capable
    pub scatter_gather: bool,
    /// Demands mode supported
    pub demand_mode: bool,
    /// Auto initialize supported
    pub auto_initialize: bool,
    /// DMA can cross 64K boundary
    pub dma_64k_boundary: bool,
    /// Ignore device count
    pub ignore_count: bool,
    /// DMA channel (for slave DMA)
    pub dma_channel: u32,
    /// Interface type
    pub interface_type: InterfaceType,
    /// DMA transfer width
    pub dma_width: DmaWidth,
    /// DMA speed
    pub dma_speed: DmaSpeed,
    /// Maximum physical address supported
    pub maximum_length: u32,
    /// DMA port (for ISA)
    pub dma_port: u32,
}

/// Device description version
pub const DEVICE_DESCRIPTION_VERSION: u32 = 2;

impl Default for DeviceDescription {
    fn default() -> Self {
        Self {
            version: DEVICE_DESCRIPTION_VERSION,
            master: true,
            scatter_gather: true,
            demand_mode: false,
            auto_initialize: false,
            dma_64k_boundary: false,
            ignore_count: false,
            dma_channel: 0,
            interface_type: InterfaceType::Pci,
            dma_width: DmaWidth::Width32Bits,
            dma_speed: DmaSpeed::TypeC,
            maximum_length: 0xFFFFFFFF,
            dma_port: 0,
        }
    }
}

/// Interface type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InterfaceType {
    /// Internal/unspecified
    Internal = 0,
    /// ISA bus
    Isa = 1,
    /// EISA bus
    Eisa = 2,
    /// MCA bus
    MicroChannel = 3,
    /// Turbo channel
    TurboChannel = 4,
    /// PCI bus
    #[default]
    Pci = 5,
    /// VME bus
    Vme = 6,
    /// NuBus
    NuBus = 7,
    /// PCMCIA
    Pcmcia = 8,
    /// C-Bus
    CBus = 9,
    /// MPI bus
    Mpi = 10,
    /// MPSA bus
    Mpsa = 11,
    /// ISA on PCI
    ProcessorInternal = 12,
    /// PNP ISA
    PnpIsa = 13,
    /// PNP bus
    PnpBus = 14,
}

/// Scatter/gather element
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ScatterGatherElement {
    /// Physical address
    pub address: u64,
    /// Length in bytes
    pub length: u32,
    /// Reserved
    pub reserved: u32,
}

/// Scatter/gather list
#[repr(C)]
pub struct ScatterGatherList {
    /// Number of elements
    pub number_of_elements: u32,
    /// Reserved
    pub reserved: u32,
    /// Array of elements
    pub elements: [ScatterGatherElement; MAX_SG_ELEMENTS],
}

impl Default for ScatterGatherList {
    fn default() -> Self {
        Self {
            number_of_elements: 0,
            reserved: 0,
            elements: [ScatterGatherElement::default(); MAX_SG_ELEMENTS],
        }
    }
}

impl ScatterGatherList {
    pub const fn new() -> Self {
        Self {
            number_of_elements: 0,
            reserved: 0,
            elements: [ScatterGatherElement {
                address: 0,
                length: 0,
                reserved: 0,
            }; MAX_SG_ELEMENTS],
        }
    }

    /// Get total transfer length
    pub fn total_length(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.number_of_elements as usize {
            if i < MAX_SG_ELEMENTS {
                total += self.elements[i].length as u64;
            }
        }
        total
    }

    /// Add an element
    pub fn add_element(&mut self, address: u64, length: u32) -> bool {
        if (self.number_of_elements as usize) >= MAX_SG_ELEMENTS {
            return false;
        }

        let idx = self.number_of_elements as usize;
        self.elements[idx] = ScatterGatherElement {
            address,
            length,
            reserved: 0,
        };
        self.number_of_elements += 1;
        true
    }

    /// Clear the list
    pub fn clear(&mut self) {
        self.number_of_elements = 0;
    }
}

/// Map register state
#[derive(Clone, Copy)]
struct MapRegister {
    /// Register is allocated
    allocated: bool,
    /// Virtual address mapped
    virtual_address: usize,
    /// Physical address
    physical_address: u64,
    /// Length mapped
    length: u32,
    /// Transfer direction
    direction: DmaDirection,
}

impl Default for MapRegister {
    fn default() -> Self {
        Self {
            allocated: false,
            virtual_address: 0,
            physical_address: 0,
            length: 0,
            direction: DmaDirection::ReadFromDevice,
        }
    }
}

/// DMA Adapter
///
/// Per-device DMA context and operations
#[repr(C)]
pub struct DmaAdapter {
    /// Adapter is valid
    pub valid: AtomicBool,
    /// Adapter ID
    pub id: u32,
    /// Device description
    pub device_description: DeviceDescription,
    /// Number of map registers available
    pub map_register_count: u32,
    /// Number of map registers allocated
    pub allocated_registers: AtomicU32,
    /// Map registers
    map_registers: [MapRegister; MAX_MAP_REGISTERS],
    /// Common buffers allocated
    pub common_buffers_allocated: AtomicU32,
    /// Total common buffer bytes
    pub common_buffer_bytes: AtomicU64,
    /// Scatter/gather operations count
    pub sg_operations: AtomicU64,
    /// Lock for synchronization
    lock: SpinLock<()>,
}

impl DmaAdapter {
    pub const fn new(id: u32) -> Self {
        Self {
            valid: AtomicBool::new(false),
            id,
            device_description: DeviceDescription {
                version: DEVICE_DESCRIPTION_VERSION,
                master: true,
                scatter_gather: true,
                demand_mode: false,
                auto_initialize: false,
                dma_64k_boundary: false,
                ignore_count: false,
                dma_channel: 0,
                interface_type: InterfaceType::Pci,
                dma_width: DmaWidth::Width32Bits,
                dma_speed: DmaSpeed::TypeC,
                maximum_length: 0xFFFFFFFF,
                dma_port: 0,
            },
            map_register_count: MAX_MAP_REGISTERS as u32,
            allocated_registers: AtomicU32::new(0),
            map_registers: [MapRegister {
                allocated: false,
                virtual_address: 0,
                physical_address: 0,
                length: 0,
                direction: DmaDirection::ReadFromDevice,
            }; MAX_MAP_REGISTERS],
            common_buffers_allocated: AtomicU32::new(0),
            common_buffer_bytes: AtomicU64::new(0),
            sg_operations: AtomicU64::new(0),
            lock: SpinLock::new(()),
        }
    }

    /// Initialize adapter with device description
    pub fn init(&mut self, desc: &DeviceDescription) {
        self.device_description = *desc;
        self.map_register_count = if desc.scatter_gather {
            MAX_MAP_REGISTERS as u32
        } else {
            16 // Fewer for non-scatter/gather
        };
        self.valid.store(true, Ordering::Release);
    }

    /// Allocate map registers
    pub fn allocate_map_registers(&mut self, count: u32) -> Option<u32> {
        if count == 0 || count > self.map_register_count {
            return None;
        }

        let _guard = self.lock.lock();

        // Find contiguous free registers
        let mut start = 0usize;
        let mut found = 0u32;

        for i in 0..MAX_MAP_REGISTERS {
            if !self.map_registers[i].allocated {
                if found == 0 {
                    start = i;
                }
                found += 1;
                if found >= count {
                    // Allocate them
                    for j in start..start + count as usize {
                        self.map_registers[j].allocated = true;
                    }
                    self.allocated_registers.fetch_add(count, Ordering::Relaxed);
                    return Some(start as u32);
                }
            } else {
                found = 0;
            }
        }

        None
    }

    /// Free map registers
    pub fn free_map_registers(&mut self, first_register: u32, count: u32) {
        let _guard = self.lock.lock();

        for i in first_register..first_register + count {
            if (i as usize) < MAX_MAP_REGISTERS {
                self.map_registers[i as usize] = MapRegister::default();
            }
        }

        self.allocated_registers.fetch_sub(count.min(self.allocated_registers.load(Ordering::Relaxed)), Ordering::Relaxed);
    }

    /// Map a buffer for DMA
    pub fn map_transfer(
        &mut self,
        register_base: u32,
        virtual_address: usize,
        physical_address: u64,
        length: u32,
        direction: DmaDirection,
    ) -> Option<u64> {
        if (register_base as usize) >= MAX_MAP_REGISTERS {
            return None;
        }

        let _guard = self.lock.lock();

        let reg = &mut self.map_registers[register_base as usize];
        if !reg.allocated {
            return None;
        }

        reg.virtual_address = virtual_address;
        reg.physical_address = physical_address;
        reg.length = length;
        reg.direction = direction;

        Some(physical_address)
    }

    /// Flush adapter buffers
    pub fn flush_adapter_buffers(
        &mut self,
        register_base: u32,
        _length: u32,
        _direction: DmaDirection,
    ) -> bool {
        if (register_base as usize) >= MAX_MAP_REGISTERS {
            return false;
        }

        // On x86, this is typically a no-op for cache-coherent DMA
        // For non-coherent platforms, this would flush caches

        true
    }

    /// Build scatter/gather list from physical address ranges
    pub fn build_scatter_gather_list(
        &mut self,
        physical_addresses: &[(u64, u32)],
    ) -> Option<ScatterGatherList> {
        if physical_addresses.len() > MAX_SG_ELEMENTS {
            return None;
        }

        let mut sg_list = ScatterGatherList::new();

        for (addr, len) in physical_addresses {
            if !sg_list.add_element(*addr, *len) {
                return None;
            }
        }

        self.sg_operations.fetch_add(1, Ordering::Relaxed);
        Some(sg_list)
    }

    /// Get adapter statistics
    pub fn get_stats(&self) -> DmaAdapterStats {
        DmaAdapterStats {
            id: self.id,
            map_register_count: self.map_register_count,
            allocated_registers: self.allocated_registers.load(Ordering::Relaxed),
            common_buffers: self.common_buffers_allocated.load(Ordering::Relaxed),
            common_buffer_bytes: self.common_buffer_bytes.load(Ordering::Relaxed),
            sg_operations: self.sg_operations.load(Ordering::Relaxed),
            scatter_gather: self.device_description.scatter_gather,
            interface_type: self.device_description.interface_type,
        }
    }
}

/// DMA adapter statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct DmaAdapterStats {
    pub id: u32,
    pub map_register_count: u32,
    pub allocated_registers: u32,
    pub common_buffers: u32,
    pub common_buffer_bytes: u64,
    pub sg_operations: u64,
    pub scatter_gather: bool,
    pub interface_type: InterfaceType,
}

// ============================================================================
// Global DMA State
// ============================================================================

static mut DMA_ADAPTERS: [DmaAdapter; MAX_DMA_ADAPTERS] = {
    const INIT: DmaAdapter = DmaAdapter::new(0);
    let mut adapters = [INIT; MAX_DMA_ADAPTERS];
    let mut i = 0;
    while i < MAX_DMA_ADAPTERS {
        adapters[i] = DmaAdapter::new(i as u32);
        i += 1;
    }
    adapters
};

static DMA_LOCK: SpinLock<()> = SpinLock::new(());
static DMA_INITIALIZED: AtomicBool = AtomicBool::new(false);
static ADAPTERS_ALLOCATED: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// DMA API
// ============================================================================

/// Get a DMA adapter for a device
///
/// Allocates and initializes a DMA adapter based on device requirements.
pub fn hal_get_dma_adapter(desc: &DeviceDescription) -> Option<*mut DmaAdapter> {
    if !DMA_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let _guard = DMA_LOCK.lock();

    unsafe {
        for adapter in DMA_ADAPTERS.iter_mut() {
            if !adapter.valid.load(Ordering::Relaxed) {
                adapter.init(desc);
                ADAPTERS_ALLOCATED.fetch_add(1, Ordering::Relaxed);
                return Some(adapter as *mut DmaAdapter);
            }
        }
    }

    None
}

/// Release a DMA adapter
pub fn hal_put_dma_adapter(adapter: *mut DmaAdapter) {
    if adapter.is_null() {
        return;
    }

    let _guard = DMA_LOCK.lock();

    unsafe {
        (*adapter).valid.store(false, Ordering::Release);
        (*adapter).allocated_registers.store(0, Ordering::Relaxed);
        (*adapter).common_buffers_allocated.store(0, Ordering::Relaxed);
        (*adapter).common_buffer_bytes.store(0, Ordering::Relaxed);

        if ADAPTERS_ALLOCATED.load(Ordering::Relaxed) > 0 {
            ADAPTERS_ALLOCATED.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Allocate common buffer (contiguous physical memory for DMA)
///
/// Returns (virtual_address, physical_address) or None on failure
pub fn hal_allocate_common_buffer(
    adapter: *mut DmaAdapter,
    length: usize,
    _cache_enabled: bool,
) -> Option<(usize, u64)> {
    if adapter.is_null() || length == 0 {
        return None;
    }

    // In a real implementation, this would:
    // 1. Allocate physically contiguous memory
    // 2. Map it for DMA access
    // 3. Return both addresses

    // For now, simulate allocation
    // Real implementation would use mm::allocate_contiguous_memory

    unsafe {
        (*adapter).common_buffers_allocated.fetch_add(1, Ordering::Relaxed);
        (*adapter).common_buffer_bytes.fetch_add(length as u64, Ordering::Relaxed);
    }

    // Placeholder - would return actual addresses
    None
}

/// Free common buffer
pub fn hal_free_common_buffer(
    adapter: *mut DmaAdapter,
    length: usize,
    _virtual_address: usize,
    _physical_address: u64,
    _cache_enabled: bool,
) {
    if adapter.is_null() {
        return;
    }

    unsafe {
        if (*adapter).common_buffers_allocated.load(Ordering::Relaxed) > 0 {
            (*adapter).common_buffers_allocated.fetch_sub(1, Ordering::Relaxed);
        }
        (*adapter).common_buffer_bytes.fetch_sub(
            (length as u64).min((*adapter).common_buffer_bytes.load(Ordering::Relaxed)),
            Ordering::Relaxed,
        );
    }
}

/// Allocate adapter channel (for slave DMA)
pub fn hal_allocate_adapter_channel(
    adapter: *mut DmaAdapter,
    map_register_count: u32,
) -> Option<u32> {
    if adapter.is_null() {
        return None;
    }

    unsafe { (*adapter).allocate_map_registers(map_register_count) }
}

/// Free adapter channel
pub fn hal_free_adapter_channel(adapter: *mut DmaAdapter) {
    if adapter.is_null() {
        return;
    }

    unsafe {
        let count = (*adapter).allocated_registers.load(Ordering::Relaxed);
        (*adapter).free_map_registers(0, count);
    }
}

/// Map transfer for DMA
pub fn hal_map_transfer(
    adapter: *mut DmaAdapter,
    virtual_address: usize,
    physical_address: u64,
    length: u32,
    write_to_device: bool,
) -> Option<u64> {
    if adapter.is_null() {
        return None;
    }

    let direction = if write_to_device {
        DmaDirection::WriteToDevice
    } else {
        DmaDirection::ReadFromDevice
    };

    unsafe {
        // Find an allocated map register
        for i in 0..MAX_MAP_REGISTERS {
            if (*adapter).map_registers[i].allocated && (*adapter).map_registers[i].virtual_address == 0 {
                return (*adapter).map_transfer(i as u32, virtual_address, physical_address, length, direction);
            }
        }
    }

    None
}

/// Flush adapter buffers
pub fn hal_flush_adapter_buffers(
    adapter: *mut DmaAdapter,
    write_to_device: bool,
) -> bool {
    if adapter.is_null() {
        return false;
    }

    let direction = if write_to_device {
        DmaDirection::WriteToDevice
    } else {
        DmaDirection::ReadFromDevice
    };

    unsafe {
        (*adapter).flush_adapter_buffers(0, 0, direction)
    }
}

/// Read DMA counter (for ISA DMA)
pub fn hal_read_dma_counter(adapter: *mut DmaAdapter) -> u32 {
    if adapter.is_null() {
        return 0;
    }

    // For PCI bus mastering, this is typically not applicable
    // For ISA DMA, would read from DMA controller

    0
}

// ============================================================================
// Statistics
// ============================================================================

/// Global DMA statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct GlobalDmaStats {
    pub adapters_allocated: u32,
    pub total_map_registers: u32,
    pub total_common_buffers: u32,
    pub total_common_buffer_bytes: u64,
    pub total_sg_operations: u64,
}

/// Get global DMA statistics
pub fn hal_get_dma_stats() -> GlobalDmaStats {
    let mut stats = GlobalDmaStats::default();

    unsafe {
        stats.adapters_allocated = ADAPTERS_ALLOCATED.load(Ordering::Relaxed);

        for adapter in DMA_ADAPTERS.iter() {
            if adapter.valid.load(Ordering::Relaxed) {
                stats.total_map_registers += adapter.allocated_registers.load(Ordering::Relaxed);
                stats.total_common_buffers += adapter.common_buffers_allocated.load(Ordering::Relaxed);
                stats.total_common_buffer_bytes += adapter.common_buffer_bytes.load(Ordering::Relaxed);
                stats.total_sg_operations += adapter.sg_operations.load(Ordering::Relaxed);
            }
        }
    }

    stats
}

/// Get adapter by index for inspection
pub fn hal_get_adapter_stats(index: usize) -> Option<DmaAdapterStats> {
    if index >= MAX_DMA_ADAPTERS {
        return None;
    }

    unsafe {
        if DMA_ADAPTERS[index].valid.load(Ordering::Relaxed) {
            Some(DMA_ADAPTERS[index].get_stats())
        } else {
            None
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize DMA subsystem
pub fn init() {
    let _guard = DMA_LOCK.lock();

    unsafe {
        for (i, adapter) in DMA_ADAPTERS.iter_mut().enumerate() {
            *adapter = DmaAdapter::new(i as u32);
        }
    }

    ADAPTERS_ALLOCATED.store(0, Ordering::Relaxed);
    DMA_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[HAL] DMA subsystem initialized");
}

/// Check if DMA subsystem is initialized
pub fn hal_is_dma_initialized() -> bool {
    DMA_INITIALIZED.load(Ordering::Acquire)
}
