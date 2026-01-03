//! PnP Device Enumeration
//!
//! Handles device discovery and driver loading.

use super::{DeviceNode, DeviceNodeState, InterfaceType, PnpBusInformation, PnpError};
use crate::ke::SpinLock;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

extern crate alloc;

/// Bus enumerator trait
pub trait BusEnumerator: Send + Sync {
    /// Get bus type
    fn bus_type(&self) -> InterfaceType;

    /// Enumerate devices on this bus
    fn enumerate(&self) -> Result<Vec<EnumeratedDevice>, PnpError>;

    /// Start a device
    fn start_device(&self, device: &DeviceNode) -> Result<(), PnpError>;

    /// Stop a device
    fn stop_device(&self, device: &DeviceNode) -> Result<(), PnpError>;

    /// Query device capabilities
    fn query_capabilities(
        &self,
        device: &DeviceNode,
    ) -> Result<super::DeviceCapabilities, PnpError>;
}

/// Enumerated device information
#[derive(Debug, Clone)]
pub struct EnumeratedDevice {
    /// Device ID
    pub device_id: String,
    /// Instance ID
    pub instance_id: String,
    /// Hardware IDs
    pub hardware_ids: Vec<String>,
    /// Compatible IDs
    pub compatible_ids: Vec<String>,
    /// Device description
    pub description: Option<String>,
    /// Bus information
    pub bus_info: PnpBusInformation,
    /// Resource requirements
    pub resource_requirements: Option<IoResourceRequirementsList>,
}

/// I/O resource requirements list
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct IoResourceRequirementsList {
    /// List size
    pub list_size: u32,
    /// Interface type
    pub interface_type: InterfaceType,
    /// Bus number
    pub bus_number: u32,
    /// Slot number
    pub slot_number: u32,
    /// Reserved
    pub reserved: [u32; 3],
    /// Number of alternatives
    pub alternative_lists: u32,
    /// Resource lists
    pub lists: Vec<IoResourceList>,
}

/// I/O resource list
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct IoResourceList {
    /// Version
    pub version: u16,
    /// Revision
    pub revision: u16,
    /// Number of descriptors
    pub count: u32,
    /// Resource descriptors
    pub descriptors: Vec<IoResourceDescriptor>,
}

/// I/O resource descriptor
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct IoResourceDescriptor {
    /// Option flags
    pub option: IoResourceOption,
    /// Resource type
    pub resource_type: super::ResourceType,
    /// Share disposition
    pub share_disposition: ShareDisposition,
    /// Flags
    pub flags: u16,
    /// Resource-specific data
    pub data: ResourceData,
}

// I/O resource option flags
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct IoResourceOption: u8 {
        /// Required resource
        const REQUIRED = 0x00;
        /// Preferred resource
        const PREFERRED = 0x01;
        /// Alternative resource
        const ALTERNATIVE = 0x08;
    }
}

/// Share disposition
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShareDisposition {
    #[default]
    Undetermined = 0,
    DeviceExclusive = 1,
    DriverExclusive = 2,
    Shared = 3,
}

/// Resource data union
#[derive(Debug, Clone, Copy, Default)]
pub struct ResourceData {
    pub memory: MemoryResource,
}

/// Memory resource descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryResource {
    /// Minimum address
    pub minimum_address: u64,
    /// Maximum address
    pub maximum_address: u64,
    /// Alignment
    pub alignment: u32,
    /// Length
    pub length: u32,
}

/// Port resource descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PortResource {
    /// Minimum port
    pub minimum_port: u64,
    /// Maximum port
    pub maximum_port: u64,
    /// Alignment
    pub alignment: u32,
    /// Length
    pub length: u32,
}

/// Interrupt resource descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct InterruptResource {
    /// Minimum vector
    pub minimum_vector: u32,
    /// Maximum vector
    pub maximum_vector: u32,
}

/// DMA resource descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DmaResource {
    /// Minimum channel
    pub minimum_channel: u32,
    /// Maximum channel
    pub maximum_channel: u32,
}

/// Root bus enumerator
pub struct RootEnumerator {
    /// Registered bus drivers
    bus_drivers: SpinLock<Vec<Arc<dyn BusEnumerator>>>,
}

impl RootEnumerator {
    pub fn new() -> Self {
        Self {
            bus_drivers: SpinLock::new(Vec::new()),
        }
    }

    /// Register a bus driver
    pub fn register_bus_driver(&self, driver: Arc<dyn BusEnumerator>) {
        let mut drivers = self.bus_drivers.lock();
        drivers.push(driver);
    }

    /// Unregister a bus driver
    pub fn unregister_bus_driver(&self, bus_type: InterfaceType) {
        let mut drivers = self.bus_drivers.lock();
        drivers.retain(|d| d.bus_type() != bus_type);
    }

    /// Enumerate all buses
    pub fn enumerate_all(&self) -> Vec<EnumeratedDevice> {
        let mut all_devices = Vec::new();
        let drivers = self.bus_drivers.lock();

        for driver in drivers.iter() {
            if let Ok(devices) = driver.enumerate() {
                all_devices.extend(devices);
            }
        }

        all_devices
    }
}

impl Default for RootEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

/// ACPI bus enumerator
pub struct AcpiBusEnumerator;

impl AcpiBusEnumerator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AcpiBusEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

impl BusEnumerator for AcpiBusEnumerator {
    fn bus_type(&self) -> InterfaceType {
        InterfaceType::ACPIBus
    }

    fn enumerate(&self) -> Result<Vec<EnumeratedDevice>, PnpError> {
        // In a real implementation, this would parse ACPI tables
        // and enumerate devices from DSDT/SSDT
        Ok(Vec::new())
    }

    fn start_device(&self, _device: &DeviceNode) -> Result<(), PnpError> {
        Ok(())
    }

    fn stop_device(&self, _device: &DeviceNode) -> Result<(), PnpError> {
        Ok(())
    }

    fn query_capabilities(
        &self,
        _device: &DeviceNode,
    ) -> Result<super::DeviceCapabilities, PnpError> {
        Ok(super::DeviceCapabilities::new())
    }
}

/// PCI bus enumerator
pub struct PciBusEnumerator;

impl PciBusEnumerator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PciBusEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

impl BusEnumerator for PciBusEnumerator {
    fn bus_type(&self) -> InterfaceType {
        InterfaceType::PCIBus
    }

    fn enumerate(&self) -> Result<Vec<EnumeratedDevice>, PnpError> {
        let mut devices = Vec::new();

        // Scan all PCI buses (simplified)
        for bus in 0..256u16 {
            for device in 0..32u8 {
                for function in 0..8u8 {
                    if let Some(dev_info) = probe_pci_device(bus as u8, device, function) {
                        devices.push(dev_info);
                    }
                }
            }
        }

        Ok(devices)
    }

    fn start_device(&self, device: &DeviceNode) -> Result<(), PnpError> {
        device.set_state(DeviceNodeState::Started);
        Ok(())
    }

    fn stop_device(&self, device: &DeviceNode) -> Result<(), PnpError> {
        device.set_state(DeviceNodeState::Stopped);
        Ok(())
    }

    fn query_capabilities(
        &self,
        _device: &DeviceNode,
    ) -> Result<super::DeviceCapabilities, PnpError> {
        let mut caps = super::DeviceCapabilities::new();
        // PCI devices typically support D0-D3 power states
        caps.capabilities = 0x0003; // DeviceD1 | DeviceD2
        Ok(caps)
    }
}

/// Probe a PCI device at a specific location
fn probe_pci_device(bus: u8, device: u8, function: u8) -> Option<EnumeratedDevice> {
    // Read PCI configuration space
    let address = pci_config_address(bus, device, function, 0);

    unsafe {
        // Write address
        x86_64::instructions::port::Port::new(0xCF8).write(address);
        // Read vendor/device ID
        let value: u32 = x86_64::instructions::port::Port::new(0xCFC).read();

        let vendor_id = (value & 0xFFFF) as u16;
        let device_id = ((value >> 16) & 0xFFFF) as u16;

        // Check for valid device
        if vendor_id == 0xFFFF || vendor_id == 0x0000 {
            return None;
        }

        // Read class code
        x86_64::instructions::port::Port::new(0xCF8).write(pci_config_address(bus, device, function, 0x08));
        let class_value: u32 = x86_64::instructions::port::Port::new(0xCFC).read();
        let class_code = ((class_value >> 24) & 0xFF) as u8;
        let subclass = ((class_value >> 16) & 0xFF) as u8;

        // Create device info
        let device_id_str = alloc::format!(
            "PCI\\VEN_{:04X}&DEV_{:04X}&SUBSYS_00000000&REV_00",
            vendor_id, device_id
        );
        let instance_id_str = alloc::format!("{:02X}{:02X}{:02X}", bus, device, function);

        let hardware_id = format!(
            "PCI\\VEN_{:04X}&DEV_{:04X}&CC_{:02X}{:02X}",
            vendor_id, device_id, class_code, subclass
        );

        let compatible_id = format!(
            "PCI\\CC_{:02X}{:02X}",
            class_code, subclass
        );

        let description = get_pci_device_description(class_code, subclass);

        Some(EnumeratedDevice {
            device_id: device_id_str,
            instance_id: instance_id_str,
            hardware_ids: alloc::vec![hardware_id],
            compatible_ids: alloc::vec![compatible_id],
            description: Some(String::from(description)),
            bus_info: PnpBusInformation {
                legacy_bus_type: InterfaceType::PCIBus,
                bus_number: bus as u32,
                ..Default::default()
            },
            resource_requirements: None,
        })
    }
}

/// Generate PCI configuration address
fn pci_config_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    0x80000000
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC)
}

/// Get PCI device description from class code
fn get_pci_device_description(class_code: u8, subclass: u8) -> &'static str {
    match (class_code, subclass) {
        (0x00, 0x00) => "Non-VGA Compatible Device",
        (0x00, 0x01) => "VGA-Compatible Device",
        (0x01, 0x00) => "SCSI Bus Controller",
        (0x01, 0x01) => "IDE Controller",
        (0x01, 0x02) => "Floppy Disk Controller",
        (0x01, 0x05) => "ATA Controller",
        (0x01, 0x06) => "Serial ATA Controller",
        (0x01, 0x07) => "Serial Attached SCSI Controller",
        (0x01, 0x08) => "Non-Volatile Memory Controller",
        (0x02, 0x00) => "Ethernet Controller",
        (0x02, 0x01) => "Token Ring Controller",
        (0x02, 0x02) => "FDDI Controller",
        (0x02, 0x03) => "ATM Controller",
        (0x02, 0x04) => "ISDN Controller",
        (0x02, 0x05) => "WorldFip Controller",
        (0x03, 0x00) => "VGA-Compatible Controller",
        (0x03, 0x01) => "XGA Controller",
        (0x03, 0x02) => "3D Controller",
        (0x04, 0x00) => "Video Device",
        (0x04, 0x01) => "Audio Device",
        (0x04, 0x02) => "Computer Telephony Device",
        (0x04, 0x03) => "High Definition Audio Device",
        (0x05, 0x00) => "RAM Controller",
        (0x05, 0x01) => "Flash Controller",
        (0x06, 0x00) => "Host Bridge",
        (0x06, 0x01) => "ISA Bridge",
        (0x06, 0x02) => "EISA Bridge",
        (0x06, 0x03) => "MCA Bridge",
        (0x06, 0x04) => "PCI-to-PCI Bridge",
        (0x06, 0x05) => "PCMCIA Bridge",
        (0x06, 0x06) => "NuBus Bridge",
        (0x06, 0x07) => "CardBus Bridge",
        (0x06, 0x08) => "RACEway Bridge",
        (0x07, 0x00) => "Serial Controller",
        (0x07, 0x01) => "Parallel Controller",
        (0x07, 0x02) => "Multiport Serial Controller",
        (0x07, 0x03) => "Modem",
        (0x08, 0x00) => "PIC",
        (0x08, 0x01) => "DMA Controller",
        (0x08, 0x02) => "Timer",
        (0x08, 0x03) => "RTC Controller",
        (0x08, 0x04) => "PCI Hot-Plug Controller",
        (0x08, 0x05) => "SD Host Controller",
        (0x09, 0x00) => "Keyboard Controller",
        (0x09, 0x01) => "Digitizer Pen",
        (0x09, 0x02) => "Mouse Controller",
        (0x09, 0x03) => "Scanner Controller",
        (0x09, 0x04) => "Gameport Controller",
        (0x0A, 0x00) => "Generic Docking Station",
        (0x0B, 0x00) => "386 Processor",
        (0x0B, 0x01) => "486 Processor",
        (0x0B, 0x02) => "Pentium Processor",
        (0x0B, 0x10) => "Alpha Processor",
        (0x0B, 0x20) => "PowerPC Processor",
        (0x0B, 0x30) => "MIPS Processor",
        (0x0B, 0x40) => "Co-Processor",
        (0x0C, 0x00) => "FireWire (IEEE 1394) Controller",
        (0x0C, 0x01) => "ACCESS Bus Controller",
        (0x0C, 0x02) => "SSA Controller",
        (0x0C, 0x03) => "USB Controller",
        (0x0C, 0x04) => "Fibre Channel Controller",
        (0x0C, 0x05) => "SMBus Controller",
        (0x0C, 0x06) => "InfiniBand Controller",
        (0x0C, 0x07) => "IPMI Controller",
        (0x0D, 0x00) => "iRDA Compatible Controller",
        (0x0D, 0x01) => "Consumer IR Controller",
        (0x0D, 0x10) => "RF Controller",
        (0x0D, 0x11) => "Bluetooth Controller",
        (0x0D, 0x12) => "Broadband Controller",
        (0x0D, 0x20) => "Ethernet Controller (802.1a)",
        (0x0D, 0x21) => "Ethernet Controller (802.1b)",
        (0x0E, 0x00) => "I2O Controller",
        (0x0F, _) => "Satellite Communications Controller",
        (0x10, _) => "Encryption Controller",
        (0x11, _) => "Signal Processing Controller",
        (0x12, _) => "Processing Accelerator",
        (0x13, _) => "Non-Essential Instrumentation",
        _ => "Unknown Device",
    }
}
