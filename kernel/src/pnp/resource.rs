//! PnP Resource Management
//!
//! Handles resource arbitration and allocation for devices.

use super::PnpError;
use crate::ke::SpinLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

extern crate alloc;

/// Resource type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum ResourceType {
    #[default]
    Null = 0,
    /// I/O port
    Port = 1,
    /// Interrupt
    Interrupt = 2,
    /// Memory
    Memory = 3,
    /// DMA channel
    Dma = 4,
    /// Device-specific data
    DeviceSpecific = 5,
    /// Bus number
    BusNumber = 6,
    /// Memory Large
    MemoryLarge = 7,
    /// Configuration data
    ConfigData = 128,
    /// Device private
    DevicePrivate = 129,
    /// PCI config
    PcCardConfig = 130,
    /// MF card config
    MfCardConfig = 131,
    /// Connection
    Connection = 132,
}

/// Resource share disposition
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CmShareDisposition {
    #[default]
    Undetermined = 0,
    DeviceExclusive = 1,
    DriverExclusive = 2,
    Shared = 3,
}

// Resource flags for memory
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct CmMemoryFlags: u16 {
        /// Read/write memory
        const READ_WRITE = 0x0000;
        /// Read-only memory
        const READ_ONLY = 0x0001;
        /// Write-only memory
        const WRITE_ONLY = 0x0002;
        /// Prefetchable memory
        const PREFETCHABLE = 0x0004;
        /// Memory is combined write
        const COMBINEDWRITE = 0x0008;
        /// 24-bit memory
        const IS_24_BIT = 0x0010;
        /// Cacheable memory
        const CACHEABLE = 0x0020;
    }
}

// Resource flags for port
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct CmPortFlags: u16 {
        /// Memory mapped I/O
        const MEMORY = 0x0000;
        /// I/O port
        const IO = 0x0001;
        /// 10-bit decode
        const DECODE_10 = 0x0004;
        /// 12-bit decode
        const DECODE_12 = 0x0008;
        /// 16-bit decode
        const DECODE_16 = 0x0010;
        /// Positive decode
        const POSITIVE_DECODE = 0x0020;
        /// Passive decode
        const PASSIVE_DECODE = 0x0040;
        /// Window decode
        const WINDOW_DECODE = 0x0080;
    }
}

// Resource flags for interrupt
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct CmInterruptFlags: u16 {
        /// Level-triggered interrupt
        const LEVEL_SENSITIVE = 0x0000;
        /// Edge-triggered interrupt
        const LATCHED = 0x0001;
        /// Message-signaled interrupt
        const MESSAGE = 0x0002;
        /// Policy (secondary)
        const POLICY_INCLUDED = 0x0004;
        /// Secondary interrupt
        const SECONDARY_INTERRUPT = 0x0010;
    }
}

// Resource flags for DMA
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct CmDmaFlags: u16 {
        /// 8-bit DMA
        const TYPE_A = 0x0000;
        /// 16-bit DMA
        const TYPE_B = 0x0001;
        /// 32-bit DMA
        const TYPE_F = 0x0002;
    }
}

/// Partial resource descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CmPartialResourceDescriptor {
    /// Resource type
    pub resource_type: ResourceType,
    /// Share disposition
    pub share_disposition: CmShareDisposition,
    /// Flags (type-specific)
    pub flags: u16,
    /// Resource data
    pub data: ResourceData,
}

/// Resource data union
#[repr(C)]
#[derive(Clone, Copy)]
pub union ResourceData {
    /// Generic 3-field resource
    pub generic: GenericResource,
    /// Port resource
    pub port: PortResourceData,
    /// Interrupt resource
    pub interrupt: InterruptResourceData,
    /// Memory resource
    pub memory: MemoryResourceData,
    /// DMA resource
    pub dma: DmaResourceData,
    /// Bus number
    pub bus_number: BusNumberResourceData,
    /// Device private data
    pub device_private: DevicePrivateResourceData,
}

impl Default for ResourceData {
    fn default() -> Self {
        Self {
            generic: GenericResource::default(),
        }
    }
}

impl core::fmt::Debug for ResourceData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Debug as generic resource
        unsafe { write!(f, "{:?}", self.generic) }
    }
}

/// Generic resource (3 u32 fields)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GenericResource {
    pub data: [u32; 3],
}

/// Port resource data
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PortResourceData {
    /// Start port
    pub start: u64,
    /// Length
    pub length: u32,
}

/// Interrupt resource data
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct InterruptResourceData {
    /// Interrupt level
    pub level: u32,
    /// Interrupt vector
    pub vector: u32,
    /// Affinity
    pub affinity: u64,
}

/// Memory resource data
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryResourceData {
    /// Start address
    pub start: u64,
    /// Length
    pub length: u32,
}

/// DMA resource data
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DmaResourceData {
    /// DMA channel
    pub channel: u32,
    /// Port
    pub port: u32,
    /// Reserved
    pub reserved: u32,
}

/// Bus number resource data
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BusNumberResourceData {
    /// Start bus number
    pub start: u32,
    /// Length (range)
    pub length: u32,
    /// Reserved
    pub reserved: u32,
}

/// Device private resource data
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DevicePrivateResourceData {
    pub data: [u32; 3],
}

/// Partial resource list
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct CmPartialResourceList {
    /// Version
    pub version: u16,
    /// Revision
    pub revision: u16,
    /// Number of partial descriptors
    pub count: u32,
    /// Partial descriptors
    pub partial_descriptors: Vec<CmPartialResourceDescriptor>,
}

/// Full resource descriptor
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct CmFullResourceDescriptor {
    /// Interface type
    pub interface_type: super::InterfaceType,
    /// Bus number
    pub bus_number: u32,
    /// Partial resource list
    pub partial_resource_list: CmPartialResourceList,
}

/// Resource list
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct CmResourceList {
    /// Number of full resource descriptors
    pub count: u32,
    /// Full resource descriptors
    pub list: Vec<CmFullResourceDescriptor>,
}

impl CmResourceList {
    /// Create an empty resource list
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a full resource descriptor
    pub fn add_descriptor(&mut self, desc: CmFullResourceDescriptor) {
        self.list.push(desc);
        self.count = self.list.len() as u32;
    }

    /// Get all resources of a specific type
    pub fn get_resources(&self, resource_type: ResourceType) -> Vec<&CmPartialResourceDescriptor> {
        let mut resources = Vec::new();
        for full in &self.list {
            for partial in &full.partial_resource_list.partial_descriptors {
                if partial.resource_type == resource_type {
                    resources.push(partial);
                }
            }
        }
        resources
    }
}

/// Resource arbiter trait
pub trait ResourceArbiter: Send + Sync {
    /// Resource type this arbiter handles
    fn resource_type(&self) -> ResourceType;

    /// Allocate a resource
    fn allocate(
        &self,
        requirement: &super::enumerate::IoResourceDescriptor,
    ) -> Result<CmPartialResourceDescriptor, PnpError>;

    /// Free a resource
    fn free(&self, resource: &CmPartialResourceDescriptor) -> Result<(), PnpError>;

    /// Check if resource is available
    fn is_available(
        &self,
        requirement: &super::enumerate::IoResourceDescriptor,
    ) -> bool;
}

/// IRQ resource arbiter
pub struct IrqArbiter {
    /// Allocated IRQs
    allocated: SpinLock<BTreeMap<u32, AllocationInfo>>,
}

/// Resource allocation info
#[derive(Debug, Clone)]
pub struct AllocationInfo {
    /// Owner identifier
    pub owner: u64,
    /// Share disposition
    pub shared: bool,
    /// Number of sharers
    pub share_count: u32,
}

impl IrqArbiter {
    pub fn new() -> Self {
        Self {
            allocated: SpinLock::new(BTreeMap::new()),
        }
    }
}

impl Default for IrqArbiter {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceArbiter for IrqArbiter {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Interrupt
    }

    fn allocate(
        &self,
        requirement: &super::enumerate::IoResourceDescriptor,
    ) -> Result<CmPartialResourceDescriptor, PnpError> {
        let mut allocated = self.allocated.lock();

        // Try each IRQ in range
        let min_irq = requirement.data.memory.minimum_address as u32;
        let max_irq = requirement.data.memory.maximum_address as u32;

        for irq in min_irq..=max_irq {
            if let Some(info) = allocated.get_mut(&irq) {
                // Check if shareable
                if info.shared && requirement.share_disposition == super::enumerate::ShareDisposition::Shared {
                    info.share_count += 1;
                    return Ok(CmPartialResourceDescriptor {
                        resource_type: ResourceType::Interrupt,
                        share_disposition: CmShareDisposition::Shared,
                        flags: 0,
                        data: ResourceData {
                            interrupt: InterruptResourceData {
                                level: irq,
                                vector: irq,
                                affinity: 0xFFFFFFFF,
                            },
                        },
                    });
                }
            } else {
                // IRQ is free
                let shared = requirement.share_disposition == super::enumerate::ShareDisposition::Shared;
                allocated.insert(
                    irq,
                    AllocationInfo {
                        owner: 0,
                        shared,
                        share_count: 1,
                    },
                );

                return Ok(CmPartialResourceDescriptor {
                    resource_type: ResourceType::Interrupt,
                    share_disposition: if shared {
                        CmShareDisposition::Shared
                    } else {
                        CmShareDisposition::DeviceExclusive
                    },
                    flags: 0,
                    data: ResourceData {
                        interrupt: InterruptResourceData {
                            level: irq,
                            vector: irq,
                            affinity: 0xFFFFFFFF,
                        },
                    },
                });
            }
        }

        Err(PnpError::ResourceConflict)
    }

    fn free(&self, resource: &CmPartialResourceDescriptor) -> Result<(), PnpError> {
        let irq = unsafe { resource.data.interrupt.level };
        let mut allocated = self.allocated.lock();

        if let Some(info) = allocated.get_mut(&irq) {
            info.share_count -= 1;
            if info.share_count == 0 {
                allocated.remove(&irq);
            }
            Ok(())
        } else {
            Err(PnpError::InvalidParameter)
        }
    }

    fn is_available(
        &self,
        requirement: &super::enumerate::IoResourceDescriptor,
    ) -> bool {
        let allocated = self.allocated.lock();
        let min_irq = requirement.data.memory.minimum_address as u32;
        let max_irq = requirement.data.memory.maximum_address as u32;

        for irq in min_irq..=max_irq {
            if let Some(info) = allocated.get(&irq) {
                if info.shared && requirement.share_disposition == super::enumerate::ShareDisposition::Shared {
                    return true;
                }
            } else {
                return true;
            }
        }

        false
    }
}

/// Memory resource arbiter
pub struct MemoryArbiter {
    /// Allocated memory ranges
    allocated: SpinLock<Vec<MemoryRange>>,
}

/// Memory range allocation
#[derive(Debug, Clone)]
pub struct MemoryRange {
    /// Start address
    pub start: u64,
    /// End address
    pub end: u64,
    /// Owner
    pub owner: u64,
}

impl MemoryArbiter {
    pub fn new() -> Self {
        Self {
            allocated: SpinLock::new(Vec::new()),
        }
    }
}

impl Default for MemoryArbiter {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceArbiter for MemoryArbiter {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Memory
    }

    fn allocate(
        &self,
        requirement: &super::enumerate::IoResourceDescriptor,
    ) -> Result<CmPartialResourceDescriptor, PnpError> {
        let mut allocated = self.allocated.lock();

        let min_addr = requirement.data.memory.minimum_address;
        let max_addr = requirement.data.memory.maximum_address;
        let length = requirement.data.memory.length as u64;
        let alignment = requirement.data.memory.alignment as u64;

        // Find a suitable range
        let mut addr = (min_addr + alignment - 1) & !(alignment - 1);

        while addr + length <= max_addr {
            // Check for conflicts
            let conflicts = allocated
                .iter()
                .any(|r| !(addr + length <= r.start || addr >= r.end));

            if !conflicts {
                allocated.push(MemoryRange {
                    start: addr,
                    end: addr + length,
                    owner: 0,
                });

                return Ok(CmPartialResourceDescriptor {
                    resource_type: ResourceType::Memory,
                    share_disposition: CmShareDisposition::DeviceExclusive,
                    flags: 0,
                    data: ResourceData {
                        memory: MemoryResourceData {
                            start: addr,
                            length: length as u32,
                        },
                    },
                });
            }

            addr += alignment;
        }

        Err(PnpError::ResourceConflict)
    }

    fn free(&self, resource: &CmPartialResourceDescriptor) -> Result<(), PnpError> {
        let addr = unsafe { resource.data.memory.start };
        let mut allocated = self.allocated.lock();

        let idx = allocated.iter().position(|r| r.start == addr);
        if let Some(i) = idx {
            allocated.remove(i);
            Ok(())
        } else {
            Err(PnpError::InvalidParameter)
        }
    }

    fn is_available(
        &self,
        requirement: &super::enumerate::IoResourceDescriptor,
    ) -> bool {
        let allocated = self.allocated.lock();

        let min_addr = requirement.data.memory.minimum_address;
        let max_addr = requirement.data.memory.maximum_address;
        let length = requirement.data.memory.length as u64;
        let alignment = requirement.data.memory.alignment as u64;

        let mut addr = (min_addr + alignment - 1) & !(alignment - 1);

        while addr + length <= max_addr {
            let conflicts = allocated
                .iter()
                .any(|r| !(addr + length <= r.start || addr >= r.end));

            if !conflicts {
                return true;
            }

            addr += alignment;
        }

        false
    }
}

/// I/O port resource arbiter
pub struct IoPortArbiter {
    /// Allocated port ranges
    allocated: SpinLock<Vec<PortRange>>,
}

/// Port range allocation
#[derive(Debug, Clone)]
pub struct PortRange {
    /// Start port
    pub start: u64,
    /// End port
    pub end: u64,
    /// Owner
    pub owner: u64,
}

impl IoPortArbiter {
    pub fn new() -> Self {
        Self {
            allocated: SpinLock::new(Vec::new()),
        }
    }
}

impl Default for IoPortArbiter {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceArbiter for IoPortArbiter {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Port
    }

    fn allocate(
        &self,
        requirement: &super::enumerate::IoResourceDescriptor,
    ) -> Result<CmPartialResourceDescriptor, PnpError> {
        let mut allocated = self.allocated.lock();

        let min_port = requirement.data.memory.minimum_address;
        let max_port = requirement.data.memory.maximum_address;
        let length = requirement.data.memory.length as u64;

        // Find a suitable range
        let mut port = min_port;

        while port + length <= max_port {
            // Check for conflicts
            let conflicts = allocated
                .iter()
                .any(|r| !(port + length <= r.start || port >= r.end));

            if !conflicts {
                allocated.push(PortRange {
                    start: port,
                    end: port + length,
                    owner: 0,
                });

                return Ok(CmPartialResourceDescriptor {
                    resource_type: ResourceType::Port,
                    share_disposition: CmShareDisposition::DeviceExclusive,
                    flags: CmPortFlags::IO.bits(),
                    data: ResourceData {
                        port: PortResourceData {
                            start: port,
                            length: length as u32,
                        },
                    },
                });
            }

            port += 1;
        }

        Err(PnpError::ResourceConflict)
    }

    fn free(&self, resource: &CmPartialResourceDescriptor) -> Result<(), PnpError> {
        let port = unsafe { resource.data.port.start };
        let mut allocated = self.allocated.lock();

        let idx = allocated.iter().position(|r| r.start == port);
        if let Some(i) = idx {
            allocated.remove(i);
            Ok(())
        } else {
            Err(PnpError::InvalidParameter)
        }
    }

    fn is_available(
        &self,
        requirement: &super::enumerate::IoResourceDescriptor,
    ) -> bool {
        let allocated = self.allocated.lock();

        let min_port = requirement.data.memory.minimum_address;
        let max_port = requirement.data.memory.maximum_address;
        let length = requirement.data.memory.length as u64;

        let mut port = min_port;

        while port + length <= max_port {
            let conflicts = allocated
                .iter()
                .any(|r| !(port + length <= r.start || port >= r.end));

            if !conflicts {
                return true;
            }

            port += 1;
        }

        false
    }
}

/// DMA channel arbiter
pub struct DmaArbiter {
    /// Allocated DMA channels
    allocated: SpinLock<BTreeMap<u32, AllocationInfo>>,
}

impl DmaArbiter {
    pub fn new() -> Self {
        Self {
            allocated: SpinLock::new(BTreeMap::new()),
        }
    }
}

impl Default for DmaArbiter {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceArbiter for DmaArbiter {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Dma
    }

    fn allocate(
        &self,
        requirement: &super::enumerate::IoResourceDescriptor,
    ) -> Result<CmPartialResourceDescriptor, PnpError> {
        let mut allocated = self.allocated.lock();

        let min_channel = requirement.data.memory.minimum_address as u32;
        let max_channel = requirement.data.memory.maximum_address as u32;

        for channel in min_channel..=max_channel {
            if !allocated.contains_key(&channel) {
                allocated.insert(
                    channel,
                    AllocationInfo {
                        owner: 0,
                        shared: false,
                        share_count: 1,
                    },
                );

                return Ok(CmPartialResourceDescriptor {
                    resource_type: ResourceType::Dma,
                    share_disposition: CmShareDisposition::DeviceExclusive,
                    flags: 0,
                    data: ResourceData {
                        dma: DmaResourceData {
                            channel,
                            port: 0,
                            reserved: 0,
                        },
                    },
                });
            }
        }

        Err(PnpError::ResourceConflict)
    }

    fn free(&self, resource: &CmPartialResourceDescriptor) -> Result<(), PnpError> {
        let channel = unsafe { resource.data.dma.channel };
        let mut allocated = self.allocated.lock();

        if allocated.remove(&channel).is_some() {
            Ok(())
        } else {
            Err(PnpError::InvalidParameter)
        }
    }

    fn is_available(
        &self,
        requirement: &super::enumerate::IoResourceDescriptor,
    ) -> bool {
        let allocated = self.allocated.lock();

        let min_channel = requirement.data.memory.minimum_address as u32;
        let max_channel = requirement.data.memory.maximum_address as u32;

        for channel in min_channel..=max_channel {
            if !allocated.contains_key(&channel) {
                return true;
            }
        }

        false
    }
}
