//! VirtIO Network Device Driver
//!
//! Implements the VirtIO network device driver.
//! Uses two virtqueues: RX (receive) and TX (transmit).

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::{VirtioTransport, device_status};
use super::virtqueue::{Virtqueue, virtqueue_size_legacy, PAGE_SIZE};
use crate::hal::pci::PciLocation;
use crate::net::{NetworkDevice, NetworkDeviceInfo, NetworkDeviceState, DeviceCapabilities};
use crate::net::ethernet::MacAddress;
use crate::ke::SpinLock;

/// Maximum packet size
const MAX_PACKET_SIZE: usize = 1514;

/// Number of RX buffers
const RX_QUEUE_SIZE: usize = 64;

/// Number of TX buffers
const TX_QUEUE_SIZE: usize = 64;

/// VirtIO network header (prepended to packets)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

/// VirtIO net header size
pub const VIRTIO_NET_HDR_SIZE: usize = core::mem::size_of::<VirtioNetHdr>();

/// GSO types
pub mod gso {
    pub const NONE: u8 = 0;
    pub const TCPV4: u8 = 1;
    pub const UDP: u8 = 3;
    pub const TCPV6: u8 = 4;
    pub const ECN: u8 = 0x80;
}

/// RX buffer
#[repr(C, align(4096))]
struct RxBuffer {
    header: VirtioNetHdr,
    data: [u8; MAX_PACKET_SIZE],
}

/// TX buffer
#[repr(C, align(4096))]
struct TxBuffer {
    header: VirtioNetHdr,
    data: [u8; MAX_PACKET_SIZE],
}

/// VirtIO network device
pub struct VirtioNetDevice {
    /// Transport layer
    transport: VirtioTransport,
    /// RX virtqueue
    rx_queue: Option<Virtqueue>,
    /// TX virtqueue
    tx_queue: Option<Virtqueue>,
    /// RX buffers
    rx_buffers: Vec<Box<RxBuffer>>,
    /// TX buffers
    tx_buffers: Vec<Box<TxBuffer>>,
    /// Free TX buffer indices
    tx_free: Vec<usize>,
    /// MAC address
    mac: MacAddress,
    /// Device is initialized
    initialized: AtomicBool,
    /// Queue memory (keep alive)
    _rx_queue_mem: Option<Vec<u8>>,
    _tx_queue_mem: Option<Vec<u8>>,
}

// SAFETY: VirtioNetDevice is carefully designed to be thread-safe
unsafe impl Sync for VirtioNetDevice {}
unsafe impl Send for VirtioNetDevice {}

/// Global virtio-net device instance
static mut VIRTIO_NET_DEVICE: Option<VirtioNetDevice> = None;
static VIRTIO_NET_LOCK: SpinLock<()> = SpinLock::new(());

/// Device index after registration
static mut VIRTIO_NET_INDEX: Option<usize> = None;

impl VirtioNetDevice {
    /// Create a new VirtIO network device
    pub fn new(loc: PciLocation) -> Option<Self> {
        let mut transport = VirtioTransport::new(loc)?;

        // Initialize transport
        if transport.init().is_err() {
            return None;
        }

        // Read MAC address
        let mac_bytes = transport.read_mac();
        let mac = MacAddress::new(mac_bytes);
        crate::serial_println!("[VIRTIO-NET] MAC address: {:?}", mac);

        Some(Self {
            transport,
            rx_queue: None,
            tx_queue: None,
            rx_buffers: Vec::new(),
            tx_buffers: Vec::new(),
            tx_free: Vec::new(),
            mac,
            initialized: AtomicBool::new(false),
            _rx_queue_mem: None,
            _tx_queue_mem: None,
        })
    }

    /// Initialize the device queues
    pub fn init_queues(&mut self) -> Result<(), &'static str> {
        // Setup RX queue (queue 0)
        self.transport.queue_select(0);
        let rx_size = self.transport.queue_size();
        if rx_size == 0 {
            return Err("RX queue size is 0");
        }
        crate::serial_println!("[VIRTIO-NET] RX queue size: {}", rx_size);

        // Allocate RX queue memory
        let rx_mem_size = virtqueue_size_legacy(rx_size);
        let mut rx_mem = vec![0u8; rx_mem_size + PAGE_SIZE];
        let rx_aligned = ((rx_mem.as_ptr() as usize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)) as *mut u8;
        let rx_phys = rx_aligned as u64; // In real system, this would be virt_to_phys

        let rx_queue = unsafe { Virtqueue::new(0, rx_size, rx_phys, rx_aligned) };

        // Tell device about queue
        self.transport.queue_set_pfn((rx_phys / PAGE_SIZE as u64) as u32);

        // Setup TX queue (queue 1)
        self.transport.queue_select(1);
        let tx_size = self.transport.queue_size();
        if tx_size == 0 {
            return Err("TX queue size is 0");
        }
        crate::serial_println!("[VIRTIO-NET] TX queue size: {}", tx_size);

        // Allocate TX queue memory
        let tx_mem_size = virtqueue_size_legacy(tx_size);
        let mut tx_mem = vec![0u8; tx_mem_size + PAGE_SIZE];
        let tx_aligned = ((tx_mem.as_ptr() as usize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)) as *mut u8;
        let tx_phys = tx_aligned as u64;

        let tx_queue = unsafe { Virtqueue::new(1, tx_size, tx_phys, tx_aligned) };

        self.transport.queue_set_pfn((tx_phys / PAGE_SIZE as u64) as u32);

        // Store queues
        self.rx_queue = Some(rx_queue);
        self.tx_queue = Some(tx_queue);
        self._rx_queue_mem = Some(rx_mem);
        self._tx_queue_mem = Some(tx_mem);

        // Allocate RX buffers and add to queue
        for i in 0..RX_QUEUE_SIZE.min(rx_size as usize / 2) {
            let buf = Box::new(RxBuffer {
                header: VirtioNetHdr::default(),
                data: [0u8; MAX_PACKET_SIZE],
            });

            let buf_phys = buf.as_ref() as *const _ as u64;
            let total_len = (VIRTIO_NET_HDR_SIZE + MAX_PACKET_SIZE) as u32;

            // Add buffer to RX queue (device writes to it)
            if let Some(ref mut rx_q) = self.rx_queue {
                rx_q.add_buf(&[], &[(buf_phys, total_len)]);
            }

            self.rx_buffers.push(buf);
        }

        // Allocate TX buffers
        for i in 0..TX_QUEUE_SIZE.min(tx_size as usize / 2) {
            let buf = Box::new(TxBuffer {
                header: VirtioNetHdr::default(),
                data: [0u8; MAX_PACKET_SIZE],
            });
            self.tx_buffers.push(buf);
            self.tx_free.push(i);
        }

        // Mark driver OK
        self.transport.driver_ok();
        self.initialized.store(true, Ordering::SeqCst);

        // Notify device about RX buffers
        self.transport.queue_notify(0);

        crate::serial_println!("[VIRTIO-NET] Device initialized");
        Ok(())
    }

    /// Get MAC address
    pub fn mac_address(&self) -> MacAddress {
        self.mac
    }

    /// Check if initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Transmit a packet
    pub fn transmit(&mut self, packet: &[u8]) -> Result<usize, &'static str> {
        if !self.is_initialized() {
            return Err("Device not initialized");
        }

        if packet.len() > MAX_PACKET_SIZE {
            return Err("Packet too large");
        }

        // Get a free TX buffer
        let buf_idx = self.tx_free.pop().ok_or("No TX buffers available")?;
        let buf = &mut self.tx_buffers[buf_idx];

        // Setup header (no offload)
        buf.header = VirtioNetHdr::default();

        // Copy packet data
        buf.data[..packet.len()].copy_from_slice(packet);

        // Add to TX queue
        let buf_phys = buf as *const _ as u64;
        let total_len = (VIRTIO_NET_HDR_SIZE + packet.len()) as u32;

        if let Some(ref mut tx_q) = self.tx_queue {
            tx_q.add_buf(&[(buf_phys, total_len)], &[]);
        }

        // Notify device
        self.transport.queue_notify(1);

        Ok(packet.len())
    }

    /// Poll for received packets
    pub fn poll_rx(&mut self) -> Option<Vec<u8>> {
        if !self.is_initialized() {
            return None;
        }

        if let Some(ref mut rx_q) = self.rx_queue {
            if let Some((desc_id, len)) = rx_q.poll() {
                // Get the buffer
                let buf_idx = desc_id as usize;
                if buf_idx < self.rx_buffers.len() {
                    let buf = &self.rx_buffers[buf_idx];

                    // Skip virtio header
                    let data_len = len as usize - VIRTIO_NET_HDR_SIZE;
                    if data_len <= MAX_PACKET_SIZE {
                        let packet = buf.data[..data_len].to_vec();

                        // Re-add buffer to queue
                        let buf_phys = buf.as_ref() as *const _ as u64;
                        let total_len = (VIRTIO_NET_HDR_SIZE + MAX_PACKET_SIZE) as u32;
                        rx_q.add_buf(&[], &[(buf_phys, total_len)]);
                        self.transport.queue_notify(0);

                        return Some(packet);
                    }
                }

                // Free the descriptor chain even if we couldn't process it
                rx_q.free_chain(desc_id);
            }
        }

        // Also poll TX completions
        self.poll_tx_completions();

        None
    }

    /// Poll for TX completions
    fn poll_tx_completions(&mut self) {
        if let Some(ref mut tx_q) = self.tx_queue {
            while let Some((desc_id, _)) = tx_q.poll() {
                let buf_idx = desc_id as usize;
                if buf_idx < self.tx_buffers.len() {
                    self.tx_free.push(buf_idx);
                }
                tx_q.free_chain(desc_id);
            }
        }
    }
}

/// TX callback for network device abstraction
fn virtio_net_tx(_device: &NetworkDevice, packet: &[u8]) -> Result<usize, &'static str> {
    let _guard = VIRTIO_NET_LOCK.lock();
    unsafe {
        if let Some(ref mut dev) = VIRTIO_NET_DEVICE {
            dev.transmit(packet)
        } else {
            Err("VirtIO-NET not initialized")
        }
    }
}

/// Initialize VirtIO network driver
pub fn init() -> Result<usize, &'static str> {
    crate::serial_println!("[VIRTIO-NET] Scanning for VirtIO network devices...");

    // Find VirtIO network devices
    let devices = crate::hal::pci::find_virtio_net_devices();

    if devices.is_empty() {
        crate::serial_println!("[VIRTIO-NET] No VirtIO network devices found");
        return Err("No VirtIO network devices found");
    }

    // Initialize first device
    let loc = devices[0];
    crate::serial_println!(
        "[VIRTIO-NET] Initializing device at {:02X}:{:02X}.{}",
        loc.bus, loc.device, loc.function
    );

    let mut dev = VirtioNetDevice::new(loc).ok_or("Failed to create device")?;
    dev.init_queues()?;

    let mac = dev.mac_address();

    // Store device globally
    unsafe {
        VIRTIO_NET_DEVICE = Some(dev);
    }

    // Create network device abstraction
    let info = NetworkDeviceInfo {
        name: String::from("eth0"),
        mac_address: mac,
        capabilities: DeviceCapabilities {
            flags: 0,
            mtu: 1500,
            max_frame_size: 1514,
            link_speed: 1000,
        },
        vendor_id: crate::hal::pci::VIRTIO_VENDOR_ID,
        device_id: crate::hal::pci::virtio_legacy::NETWORK,
    };

    let mut net_dev = NetworkDevice::new(info);
    net_dev.tx_callback = Some(virtio_net_tx);
    net_dev.set_state(NetworkDeviceState::Connected);

    // Register with network subsystem
    let index = crate::net::register_device(net_dev)?;
    unsafe {
        VIRTIO_NET_INDEX = Some(index);
    }

    crate::serial_println!("[VIRTIO-NET] Registered as network device {}", index);
    Ok(index)
}

/// Get the VirtIO-NET device index
pub fn get_device_index() -> Option<usize> {
    unsafe { VIRTIO_NET_INDEX }
}

/// Poll for received packets (should be called periodically)
pub fn poll() {
    let _guard = VIRTIO_NET_LOCK.lock();
    unsafe {
        if let Some(ref mut dev) = VIRTIO_NET_DEVICE {
            while let Some(packet) = dev.poll_rx() {
                // Deliver packet to network stack
                if let Some(idx) = VIRTIO_NET_INDEX {
                    drop(_guard); // Release lock before calling handle_rx_packet
                    crate::net::handle_rx_packet(idx, &packet);
                    return; // Only process one packet per poll to avoid holding lock too long
                }
            }
        }
    }
}
