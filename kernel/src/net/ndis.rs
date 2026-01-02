//! NDIS (Network Driver Interface Specification)
//!
//! NDIS provides a standard interface between network adapter drivers
//! (miniport drivers) and higher-level protocol drivers.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                   Protocol Drivers                          │
//! │           (TCPIP.SYS, NWLINK, NetBEUI)                      │
//! └─────────────────────────────────────────────────────────────┘
//!                            │
//!                 NDIS Protocol Interface
//!                            ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    NDIS.SYS                                  │
//! │     (NDIS Library - Wrapper Functions)                      │
//! └─────────────────────────────────────────────────────────────┘
//!                            │
//!                 NDIS Miniport Interface
//!                            ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                  Miniport Drivers                            │
//! │        (Network Adapter-Specific Drivers)                   │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # NDIS Versions
//! - NDIS 5.1: Windows XP/Server 2003
//! - NDIS 6.x: Windows Vista and later
//!
//! This implementation targets NDIS 5.1 compatibility.
//!
//! Based on Windows Server 2003 ndis/

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

// ============================================================================
// NDIS Constants
// ============================================================================

/// NDIS version 5.1 (Windows XP/Server 2003)
pub const NDIS_VERSION_5_1: u32 = 0x00050001;

/// Maximum miniport adapters
pub const MAX_MINIPORT_ADAPTERS: usize = 32;

/// Maximum protocol bindings
pub const MAX_PROTOCOL_BINDINGS: usize = 64;

/// Maximum packet descriptors per adapter
pub const MAX_PACKET_POOL_SIZE: usize = 1024;

/// Maximum buffer descriptors per adapter
pub const MAX_BUFFER_POOL_SIZE: usize = 2048;

/// NDIS packet header size
pub const NDIS_PACKET_HEADER_SIZE: usize = 64;

/// Maximum multicast addresses
pub const MAX_MULTICAST_ADDRESSES: usize = 32;

// ============================================================================
// NDIS Medium Types
// ============================================================================

/// NDIS medium types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NdisMedium {
    /// 802.3 Ethernet
    #[default]
    Medium802_3 = 0,
    /// 802.5 Token Ring
    Medium802_5 = 1,
    /// FDDI
    Fddi = 2,
    /// WAN
    Wan = 3,
    /// LocalTalk
    LocalTalk = 4,
    /// DIX Ethernet (obsolete)
    Dix = 5,
    /// Raw (proprietary)
    ArcnetRaw = 6,
    /// ARCNET 878.2
    Arcnet878_2 = 7,
    /// ATM
    Atm = 8,
    /// Wireless WAN
    WirelessWan = 9,
    /// IrDA
    Irda = 10,
    /// Broadcast PC
    Bpc = 11,
    /// Connection-oriented WAN
    CoWan = 12,
    /// IEEE 1394 (FireWire)
    Ieee1394 = 13,
    /// InfiniBand
    InfiniBand = 14,
    /// Tunnel
    Tunnel = 15,
    /// Native 802.11
    Native802_11 = 16,
    /// Loopback
    Loopback = 17,
}

// ============================================================================
// NDIS Physical Medium Types
// ============================================================================

/// NDIS physical medium types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NdisPhysicalMedium {
    /// Unspecified
    #[default]
    Unspecified = 0,
    /// Wireless LAN
    WirelessLan = 1,
    /// Cable modem
    CableModem = 2,
    /// Phone line
    PhoneLine = 3,
    /// Power line
    PowerLine = 4,
    /// DSL
    Dsl = 5,
    /// Fibre Channel
    FibreChannel = 6,
    /// IEEE 1394
    Ieee1394 = 7,
    /// Wireless WAN
    WirelessWan = 8,
    /// Native 802.11
    Native802_11 = 9,
    /// Bluetooth
    Bluetooth = 10,
    /// InfiniBand
    InfiniBand = 11,
    /// WiMAX
    WiMax = 12,
    /// UWB
    Uwb = 13,
    /// 802.3 (Ethernet)
    Ethernet802_3 = 14,
    /// 802.5 (Token Ring)
    TokenRing802_5 = 15,
    /// IrDA
    IrDA = 16,
    /// Wired WAN
    WiredWan = 17,
    /// Wired CoWan
    WiredCoWan = 18,
    /// Other
    Other = 19,
}

// ============================================================================
// NDIS Status Codes
// ============================================================================

/// NDIS status codes
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdisStatus {
    /// Success
    Success = 0x00000000,
    /// Pending
    Pending = 0x00000103,
    /// Not recognized
    NotRecognized = 0x00010001,
    /// Not copied
    NotCopied = 0x00010002,
    /// Not accepted
    NotAccepted = 0x00010003,
    /// Call active
    CallActive = 0x00010007,
    /// Failure
    Failure = 0xC0000001,
    /// Resources
    Resources = 0xC000009A,
    /// Not supported
    NotSupported = 0xC00000BB,
    /// Closing
    Closing = 0xC0010002,
    /// Bad version
    BadVersion = 0xC0010004,
    /// Bad characteristics
    BadCharacteristics = 0xC0010005,
    /// Adapter not found
    AdapterNotFound = 0xC0010006,
    /// Open failed
    OpenFailed = 0xC0010007,
    /// Device failed
    DeviceFailed = 0xC0010008,
    /// Multicast full
    MulticastFull = 0xC0010009,
    /// Multicast exists
    MulticastExists = 0xC001000A,
    /// Multicast not found
    MulticastNotFound = 0xC001000B,
    /// Request aborted
    RequestAborted = 0xC001000C,
    /// Reset in progress
    ResetInProgress = 0xC001000D,
    /// Invalid packet
    InvalidPacket = 0xC001000F,
    /// Invalid length
    InvalidLength = 0xC0010014,
    /// Invalid data
    InvalidData = 0xC0010015,
    /// Buffer too short
    BufferTooShort = 0xC0010016,
    /// Invalid OID
    InvalidOid = 0xC0010017,
    /// Adapter removed
    AdapterRemoved = 0xC0010018,
    /// Unsupported media
    UnsupportedMedia = 0xC0010019,
    /// Group address in use
    GroupAddressInUse = 0xC001001A,
    /// File not found
    FileNotFound = 0xC001001B,
    /// Error reading file
    ErrorReadingFile = 0xC001001C,
    /// Already mapped
    AlreadyMapped = 0xC001001D,
    /// Resource conflict
    ResourceConflict = 0xC001001E,
    /// Media disconnected
    MediaDisconnected = 0xC001001F,
    /// Invalid address
    InvalidAddress = 0xC0010022,
    /// Paused
    Paused = 0xC0010029,
    /// Interface not found
    InterfaceNotFound = 0xC001002A,
    /// Unsupported revision
    UnsupportedRevision = 0xC001002B,
    /// Invalid port
    InvalidPort = 0xC001002C,
    /// Invalid port state
    InvalidPortState = 0xC001002D,
    /// Low power state
    LowPowerState = 0xC001002E,
}

// ============================================================================
// NDIS OID (Object Identifier)
// ============================================================================

/// NDIS OID categories
pub mod oid {
    /// General OIDs
    pub mod general {
        pub const OID_GEN_SUPPORTED_LIST: u32 = 0x00010101;
        pub const OID_GEN_HARDWARE_STATUS: u32 = 0x00010102;
        pub const OID_GEN_MEDIA_SUPPORTED: u32 = 0x00010103;
        pub const OID_GEN_MEDIA_IN_USE: u32 = 0x00010104;
        pub const OID_GEN_MAXIMUM_LOOKAHEAD: u32 = 0x00010105;
        pub const OID_GEN_MAXIMUM_FRAME_SIZE: u32 = 0x00010106;
        pub const OID_GEN_LINK_SPEED: u32 = 0x00010107;
        pub const OID_GEN_TRANSMIT_BUFFER_SPACE: u32 = 0x00010108;
        pub const OID_GEN_RECEIVE_BUFFER_SPACE: u32 = 0x00010109;
        pub const OID_GEN_TRANSMIT_BLOCK_SIZE: u32 = 0x0001010A;
        pub const OID_GEN_RECEIVE_BLOCK_SIZE: u32 = 0x0001010B;
        pub const OID_GEN_VENDOR_ID: u32 = 0x0001010C;
        pub const OID_GEN_VENDOR_DESCRIPTION: u32 = 0x0001010D;
        pub const OID_GEN_CURRENT_PACKET_FILTER: u32 = 0x0001010E;
        pub const OID_GEN_CURRENT_LOOKAHEAD: u32 = 0x0001010F;
        pub const OID_GEN_DRIVER_VERSION: u32 = 0x00010110;
        pub const OID_GEN_MAXIMUM_TOTAL_SIZE: u32 = 0x00010111;
        pub const OID_GEN_PROTOCOL_OPTIONS: u32 = 0x00010112;
        pub const OID_GEN_MAC_OPTIONS: u32 = 0x00010113;
        pub const OID_GEN_MEDIA_CONNECT_STATUS: u32 = 0x00010114;
        pub const OID_GEN_MAXIMUM_SEND_PACKETS: u32 = 0x00010115;
        pub const OID_GEN_VENDOR_DRIVER_VERSION: u32 = 0x00010116;
        pub const OID_GEN_NETWORK_LAYER_ADDRESSES: u32 = 0x00010118;
        pub const OID_GEN_TRANSPORT_HEADER_OFFSET: u32 = 0x00010119;
        pub const OID_GEN_PHYSICAL_MEDIUM: u32 = 0x00010202;

        // Statistics
        pub const OID_GEN_XMIT_OK: u32 = 0x00020101;
        pub const OID_GEN_RCV_OK: u32 = 0x00020102;
        pub const OID_GEN_XMIT_ERROR: u32 = 0x00020103;
        pub const OID_GEN_RCV_ERROR: u32 = 0x00020104;
        pub const OID_GEN_RCV_NO_BUFFER: u32 = 0x00020105;
    }

    /// 802.3 (Ethernet) OIDs
    pub mod ethernet {
        pub const OID_802_3_PERMANENT_ADDRESS: u32 = 0x01010101;
        pub const OID_802_3_CURRENT_ADDRESS: u32 = 0x01010102;
        pub const OID_802_3_MULTICAST_LIST: u32 = 0x01010103;
        pub const OID_802_3_MAXIMUM_LIST_SIZE: u32 = 0x01010104;
        pub const OID_802_3_MAC_OPTIONS: u32 = 0x01010105;

        // Statistics
        pub const OID_802_3_RCV_ERROR_ALIGNMENT: u32 = 0x01020101;
        pub const OID_802_3_XMIT_ONE_COLLISION: u32 = 0x01020102;
        pub const OID_802_3_XMIT_MORE_COLLISIONS: u32 = 0x01020103;
        pub const OID_802_3_XMIT_DEFERRED: u32 = 0x01020201;
        pub const OID_802_3_XMIT_MAX_COLLISIONS: u32 = 0x01020202;
        pub const OID_802_3_RCV_OVERRUN: u32 = 0x01020203;
        pub const OID_802_3_XMIT_UNDERRUN: u32 = 0x01020204;
        pub const OID_802_3_XMIT_HEARTBEAT_FAILURE: u32 = 0x01020205;
        pub const OID_802_3_XMIT_TIMES_CRS_LOST: u32 = 0x01020206;
        pub const OID_802_3_XMIT_LATE_COLLISIONS: u32 = 0x01020207;
    }

    /// PnP and PM OIDs
    pub mod pnp {
        pub const OID_PNP_CAPABILITIES: u32 = 0xFD010100;
        pub const OID_PNP_SET_POWER: u32 = 0xFD010101;
        pub const OID_PNP_QUERY_POWER: u32 = 0xFD010102;
        pub const OID_PNP_ADD_WAKE_UP_PATTERN: u32 = 0xFD010103;
        pub const OID_PNP_REMOVE_WAKE_UP_PATTERN: u32 = 0xFD010104;
        pub const OID_PNP_WAKE_UP_PATTERN_LIST: u32 = 0xFD010105;
        pub const OID_PNP_ENABLE_WAKE_UP: u32 = 0xFD010106;
    }
}

// ============================================================================
// NDIS Packet Filter Flags
// ============================================================================

/// NDIS packet filter flags
pub mod packet_filter {
    /// Direct packets to us
    pub const NDIS_PACKET_TYPE_DIRECTED: u32 = 0x00000001;
    /// Multicast packets
    pub const NDIS_PACKET_TYPE_MULTICAST: u32 = 0x00000002;
    /// All multicast packets
    pub const NDIS_PACKET_TYPE_ALL_MULTICAST: u32 = 0x00000004;
    /// Broadcast packets
    pub const NDIS_PACKET_TYPE_BROADCAST: u32 = 0x00000008;
    /// Source routing
    pub const NDIS_PACKET_TYPE_SOURCE_ROUTING: u32 = 0x00000010;
    /// Promiscuous mode
    pub const NDIS_PACKET_TYPE_PROMISCUOUS: u32 = 0x00000020;
    /// SMT packets (FDDI)
    pub const NDIS_PACKET_TYPE_SMT: u32 = 0x00000040;
    /// All local packets
    pub const NDIS_PACKET_TYPE_ALL_LOCAL: u32 = 0x00000080;
    /// Group addresses
    pub const NDIS_PACKET_TYPE_GROUP: u32 = 0x00001000;
    /// All functional addresses
    pub const NDIS_PACKET_TYPE_ALL_FUNCTIONAL: u32 = 0x00002000;
    /// Functional address
    pub const NDIS_PACKET_TYPE_FUNCTIONAL: u32 = 0x00004000;
    /// MAC frame
    pub const NDIS_PACKET_TYPE_MAC_FRAME: u32 = 0x00008000;
}

// ============================================================================
// NDIS MAC Options
// ============================================================================

/// NDIS MAC options flags
pub mod mac_options {
    /// Copy lookahead data
    pub const NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA: u32 = 0x00000001;
    /// Receive serialized
    pub const NDIS_MAC_OPTION_RECEIVE_SERIALIZED: u32 = 0x00000002;
    /// Transfers not pended
    pub const NDIS_MAC_OPTION_TRANSFERS_NOT_PEND: u32 = 0x00000004;
    /// No loopback
    pub const NDIS_MAC_OPTION_NO_LOOPBACK: u32 = 0x00000008;
    /// Full duplex
    pub const NDIS_MAC_OPTION_FULL_DUPLEX: u32 = 0x00000010;
    /// Eotx indicator
    pub const NDIS_MAC_OPTION_EOTX_INDICATOR: u32 = 0x00000020;
    /// 8021P priority
    pub const NDIS_MAC_OPTION_8021P_PRIORITY: u32 = 0x00000040;
    /// 8021Q vlan
    pub const NDIS_MAC_OPTION_8021Q_VLAN: u32 = 0x00000200;
}

// ============================================================================
// NDIS Hardware Status
// ============================================================================

/// NDIS hardware status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NdisHardwareStatus {
    /// Ready
    #[default]
    Ready = 0,
    /// Initializing
    Initializing = 1,
    /// Reset
    Reset = 2,
    /// Closing
    Closing = 3,
    /// Not ready
    NotReady = 4,
}

/// NDIS media connect status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NdisMediaState {
    /// Connected
    #[default]
    Connected = 0,
    /// Disconnected
    Disconnected = 1,
}

// ============================================================================
// NDIS Miniport Adapter
// ============================================================================

/// NDIS miniport adapter characteristics
pub struct NdisMiniportCharacteristics {
    /// Major NDIS version
    pub major_ndis_version: u8,
    /// Minor NDIS version
    pub minor_ndis_version: u8,
    /// Flags
    pub flags: u32,
    /// Check for hang handler
    pub check_for_hang: Option<fn(adapter: &NdisMiniportAdapter) -> bool>,
    /// Halt handler
    pub halt: Option<fn(adapter: &mut NdisMiniportAdapter)>,
    /// Initialize handler
    pub initialize: Option<fn(adapter: &mut NdisMiniportAdapter) -> NdisStatus>,
    /// Query information handler
    pub query_info: Option<fn(adapter: &NdisMiniportAdapter, oid: u32, buffer: &mut [u8]) -> NdisStatus>,
    /// Reset handler
    pub reset: Option<fn(adapter: &mut NdisMiniportAdapter) -> NdisStatus>,
    /// Send handler
    pub send: Option<fn(adapter: &NdisMiniportAdapter, packet: &NdisPacket) -> NdisStatus>,
    /// Set information handler
    pub set_info: Option<fn(adapter: &mut NdisMiniportAdapter, oid: u32, buffer: &[u8]) -> NdisStatus>,
    /// Return packet handler
    pub return_packet: Option<fn(adapter: &NdisMiniportAdapter, packet: &NdisPacket)>,
    /// Send packets handler (for NDIS 4.0+)
    pub send_packets: Option<fn(adapter: &NdisMiniportAdapter, packets: &[&NdisPacket])>,
    /// ISR handler
    pub isr: Option<fn(adapter: &NdisMiniportAdapter) -> bool>,
    /// Handle interrupt handler
    pub handle_interrupt: Option<fn(adapter: &mut NdisMiniportAdapter)>,
}

impl Default for NdisMiniportCharacteristics {
    fn default() -> Self {
        Self {
            major_ndis_version: 5,
            minor_ndis_version: 1,
            flags: 0,
            check_for_hang: None,
            halt: None,
            initialize: None,
            query_info: None,
            reset: None,
            send: None,
            set_info: None,
            return_packet: None,
            send_packets: None,
            isr: None,
            handle_interrupt: None,
        }
    }
}

/// NDIS miniport adapter
pub struct NdisMiniportAdapter {
    /// Adapter ID
    pub adapter_id: u32,
    /// Active flag
    pub active: bool,
    /// Adapter name
    pub name: [u8; 64],
    /// Medium type
    pub medium_type: NdisMedium,
    /// Physical medium
    pub physical_medium: NdisPhysicalMedium,
    /// Hardware status
    pub hardware_status: NdisHardwareStatus,
    /// Media state
    pub media_state: NdisMediaState,
    /// Current MAC address
    pub current_address: [u8; 6],
    /// Permanent MAC address
    pub permanent_address: [u8; 6],
    /// Maximum frame size
    pub max_frame_size: u32,
    /// Link speed (in 100bps units)
    pub link_speed: u32,
    /// Current packet filter
    pub packet_filter: u32,
    /// Current lookahead size
    pub lookahead_size: u32,
    /// MAC options
    pub mac_options: u32,
    /// Multicast addresses
    pub multicast_list: [[u8; 6]; MAX_MULTICAST_ADDRESSES],
    /// Multicast count
    pub multicast_count: usize,
    /// Driver context
    pub driver_context: usize,
    /// Miniport context
    pub miniport_context: usize,
    /// Protocol bindings
    pub binding_count: u32,
    /// Statistics
    pub stats: NdisAdapterStats,
    /// Reference count
    pub ref_count: AtomicU32,
}

impl NdisMiniportAdapter {
    pub const fn empty() -> Self {
        Self {
            adapter_id: 0,
            active: false,
            name: [0; 64],
            medium_type: NdisMedium::Medium802_3,
            physical_medium: NdisPhysicalMedium::Unspecified,
            hardware_status: NdisHardwareStatus::NotReady,
            media_state: NdisMediaState::Disconnected,
            current_address: [0; 6],
            permanent_address: [0; 6],
            max_frame_size: 1514,
            link_speed: 100000, // 10 Mbps default
            packet_filter: 0,
            lookahead_size: 256,
            mac_options: 0,
            multicast_list: [[0; 6]; MAX_MULTICAST_ADDRESSES],
            multicast_count: 0,
            driver_context: 0,
            miniport_context: 0,
            binding_count: 0,
            stats: NdisAdapterStats::new(),
            ref_count: AtomicU32::new(0),
        }
    }

    /// Set adapter name
    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(63);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name[len] = 0;
    }

    /// Get adapter name as string
    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&c| c == 0).unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }
}

/// NDIS adapter statistics
#[derive(Debug)]
pub struct NdisAdapterStats {
    /// Packets transmitted successfully
    pub xmit_ok: AtomicU64,
    /// Packets received successfully
    pub rcv_ok: AtomicU64,
    /// Transmit errors
    pub xmit_error: AtomicU64,
    /// Receive errors
    pub rcv_error: AtomicU64,
    /// Receive no buffer
    pub rcv_no_buffer: AtomicU64,
    /// Bytes transmitted
    pub bytes_xmit: AtomicU64,
    /// Bytes received
    pub bytes_rcv: AtomicU64,
    /// Directed packets transmitted
    pub directed_xmit: AtomicU64,
    /// Directed packets received
    pub directed_rcv: AtomicU64,
    /// Multicast packets transmitted
    pub multicast_xmit: AtomicU64,
    /// Multicast packets received
    pub multicast_rcv: AtomicU64,
    /// Broadcast packets transmitted
    pub broadcast_xmit: AtomicU64,
    /// Broadcast packets received
    pub broadcast_rcv: AtomicU64,
}

impl NdisAdapterStats {
    pub const fn new() -> Self {
        Self {
            xmit_ok: AtomicU64::new(0),
            rcv_ok: AtomicU64::new(0),
            xmit_error: AtomicU64::new(0),
            rcv_error: AtomicU64::new(0),
            rcv_no_buffer: AtomicU64::new(0),
            bytes_xmit: AtomicU64::new(0),
            bytes_rcv: AtomicU64::new(0),
            directed_xmit: AtomicU64::new(0),
            directed_rcv: AtomicU64::new(0),
            multicast_xmit: AtomicU64::new(0),
            multicast_rcv: AtomicU64::new(0),
            broadcast_xmit: AtomicU64::new(0),
            broadcast_rcv: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// NDIS Packet Structure
// ============================================================================

/// NDIS packet descriptor
#[derive(Debug)]
pub struct NdisPacket {
    /// Packet ID
    pub packet_id: u32,
    /// Active flag
    pub active: bool,
    /// Owner adapter ID
    pub adapter_id: u32,
    /// First buffer in chain
    pub first_buffer_id: u32,
    /// Total packet length
    pub total_length: u32,
    /// Private data area
    pub private: [u8; 48],
    /// Protocol reserved area
    pub protocol_reserved: [u8; 16],
    /// Miniport reserved area
    pub miniport_reserved: [u8; 16],
    /// Wrapper reserved
    pub wrapper_reserved: [u8; 8],
    /// Status
    pub status: NdisStatus,
}

impl NdisPacket {
    pub const fn empty() -> Self {
        Self {
            packet_id: 0,
            active: false,
            adapter_id: 0,
            first_buffer_id: 0,
            total_length: 0,
            private: [0; 48],
            protocol_reserved: [0; 16],
            miniport_reserved: [0; 16],
            wrapper_reserved: [0; 8],
            status: NdisStatus::Success,
        }
    }
}

/// NDIS buffer descriptor
#[derive(Debug)]
pub struct NdisBuffer {
    /// Buffer ID
    pub buffer_id: u32,
    /// Active flag
    pub active: bool,
    /// Next buffer in chain
    pub next_buffer_id: u32,
    /// Virtual address of data
    pub virtual_address: usize,
    /// Length of data
    pub length: u32,
    /// MDL for physical mapping
    pub mdl: usize,
}

impl NdisBuffer {
    pub const fn empty() -> Self {
        Self {
            buffer_id: 0,
            active: false,
            next_buffer_id: 0,
            virtual_address: 0,
            length: 0,
            mdl: 0,
        }
    }
}

// ============================================================================
// NDIS Protocol Binding
// ============================================================================

/// NDIS protocol binding
pub struct NdisProtocolBinding {
    /// Binding ID
    pub binding_id: u32,
    /// Active flag
    pub active: bool,
    /// Protocol name
    pub protocol_name: [u8; 32],
    /// Bound adapter ID
    pub adapter_id: u32,
    /// Open context
    pub open_context: usize,
    /// Receive handler
    pub receive_handler: Option<fn(binding: &NdisProtocolBinding, packet: &NdisPacket)>,
    /// Receive complete handler
    pub receive_complete_handler: Option<fn(binding: &NdisProtocolBinding)>,
    /// Status handler
    pub status_handler: Option<fn(binding: &NdisProtocolBinding, status: NdisStatus)>,
    /// Send complete handler
    pub send_complete_handler: Option<fn(binding: &NdisProtocolBinding, packet: &NdisPacket, status: NdisStatus)>,
    /// Reference count
    pub ref_count: AtomicU32,
}

impl NdisProtocolBinding {
    pub const fn empty() -> Self {
        Self {
            binding_id: 0,
            active: false,
            protocol_name: [0; 32],
            adapter_id: 0,
            open_context: 0,
            receive_handler: None,
            receive_complete_handler: None,
            status_handler: None,
            send_complete_handler: None,
            ref_count: AtomicU32::new(0),
        }
    }

    /// Set protocol name
    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(31);
        self.protocol_name[..len].copy_from_slice(&bytes[..len]);
        self.protocol_name[len] = 0;
    }

    /// Get protocol name
    pub fn name_str(&self) -> &str {
        let len = self.protocol_name.iter().position(|&c| c == 0).unwrap_or(self.protocol_name.len());
        core::str::from_utf8(&self.protocol_name[..len]).unwrap_or("")
    }
}

// ============================================================================
// NDIS Global State
// ============================================================================

/// NDIS subsystem state
struct NdisState {
    /// Miniport adapters
    adapters: [NdisMiniportAdapter; MAX_MINIPORT_ADAPTERS],
    /// Protocol bindings
    bindings: [NdisProtocolBinding; MAX_PROTOCOL_BINDINGS],
    /// Next adapter ID
    next_adapter_id: u32,
    /// Next binding ID
    next_binding_id: u32,
}

const EMPTY_ADAPTER: NdisMiniportAdapter = NdisMiniportAdapter::empty();
const EMPTY_BINDING: NdisProtocolBinding = NdisProtocolBinding::empty();

static NDIS_STATE: Mutex<NdisState> = Mutex::new(NdisState {
    adapters: [EMPTY_ADAPTER; MAX_MINIPORT_ADAPTERS],
    bindings: [EMPTY_BINDING; MAX_PROTOCOL_BINDINGS],
    next_adapter_id: 1,
    next_binding_id: 1,
});

static NDIS_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// NDIS Miniport Functions
// ============================================================================

/// Register a miniport adapter
pub fn ndis_register_miniport(
    name: &str,
    medium_type: NdisMedium,
    mac_address: [u8; 6],
    driver_context: usize,
) -> Result<u32, NdisStatus> {
    let mut state = NDIS_STATE.lock();
    let adapter_id = state.next_adapter_id;

    for idx in 0..MAX_MINIPORT_ADAPTERS {
        if !state.adapters[idx].active {
            state.adapters[idx].adapter_id = adapter_id;
            state.adapters[idx].active = true;
            state.adapters[idx].set_name(name);
            state.adapters[idx].medium_type = medium_type;
            state.adapters[idx].current_address = mac_address;
            state.adapters[idx].permanent_address = mac_address;
            state.adapters[idx].driver_context = driver_context;
            state.adapters[idx].hardware_status = NdisHardwareStatus::Ready;
            state.adapters[idx].media_state = NdisMediaState::Connected;
            state.adapters[idx].ref_count = AtomicU32::new(1);

            // Set default values based on medium
            match medium_type {
                NdisMedium::Medium802_3 => {
                    state.adapters[idx].max_frame_size = 1514;
                    state.adapters[idx].physical_medium = NdisPhysicalMedium::Ethernet802_3;
                    state.adapters[idx].mac_options = mac_options::NDIS_MAC_OPTION_NO_LOOPBACK;
                }
                NdisMedium::Loopback => {
                    state.adapters[idx].max_frame_size = 65535;
                    state.adapters[idx].link_speed = 10000000; // 1 Gbps
                }
                _ => {}
            }

            state.next_adapter_id += 1;

            crate::serial_println!("[NDIS] Registered miniport '{}' (ID={}, MAC={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X})",
                name, adapter_id,
                mac_address[0], mac_address[1], mac_address[2],
                mac_address[3], mac_address[4], mac_address[5]);

            return Ok(adapter_id);
        }
    }

    Err(NdisStatus::Resources)
}

/// Deregister a miniport adapter
pub fn ndis_deregister_miniport(adapter_id: u32) -> NdisStatus {
    let mut state = NDIS_STATE.lock();

    for idx in 0..MAX_MINIPORT_ADAPTERS {
        if state.adapters[idx].active && state.adapters[idx].adapter_id == adapter_id {
            // Close all bindings first
            for b_idx in 0..MAX_PROTOCOL_BINDINGS {
                if state.bindings[b_idx].active && state.bindings[b_idx].adapter_id == adapter_id {
                    state.bindings[b_idx].active = false;
                }
            }

            let name = String::from(state.adapters[idx].name_str());
            state.adapters[idx].active = false;

            crate::serial_println!("[NDIS] Deregistered miniport '{}'", name);
            return NdisStatus::Success;
        }
    }

    NdisStatus::AdapterNotFound
}

/// Indicate receive to protocols
pub fn ndis_indicate_receive(
    adapter_id: u32,
    header: &[u8],
    lookahead: &[u8],
    packet_size: u32,
) -> NdisStatus {
    let state = NDIS_STATE.lock();

    // Find adapter
    let mut adapter_found = false;
    for idx in 0..MAX_MINIPORT_ADAPTERS {
        if state.adapters[idx].active && state.adapters[idx].adapter_id == adapter_id {
            adapter_found = true;
            state.adapters[idx].stats.rcv_ok.fetch_add(1, Ordering::Relaxed);
            state.adapters[idx].stats.bytes_rcv.fetch_add(packet_size as u64, Ordering::Relaxed);
            break;
        }
    }

    if !adapter_found {
        return NdisStatus::AdapterNotFound;
    }

    // Notify all bound protocols
    // In a real implementation, we would call each protocol's receive handler

    NdisStatus::Success
}

/// Indicate send complete
pub fn ndis_send_complete(
    adapter_id: u32,
    packet_id: u32,
    status: NdisStatus,
) {
    let state = NDIS_STATE.lock();

    // Update stats
    for idx in 0..MAX_MINIPORT_ADAPTERS {
        if state.adapters[idx].active && state.adapters[idx].adapter_id == adapter_id {
            if status == NdisStatus::Success {
                state.adapters[idx].stats.xmit_ok.fetch_add(1, Ordering::Relaxed);
            } else {
                state.adapters[idx].stats.xmit_error.fetch_add(1, Ordering::Relaxed);
            }
            break;
        }
    }

    // Notify protocol of completion
    // In a real implementation, we would call the protocol's send complete handler
}

/// Indicate status change
pub fn ndis_indicate_status(
    adapter_id: u32,
    status: NdisStatus,
) {
    let state = NDIS_STATE.lock();

    // Notify all bound protocols
    for idx in 0..MAX_PROTOCOL_BINDINGS {
        if state.bindings[idx].active && state.bindings[idx].adapter_id == adapter_id {
            if let Some(handler) = state.bindings[idx].status_handler {
                handler(&state.bindings[idx], status);
            }
        }
    }
}

// ============================================================================
// NDIS Protocol Functions
// ============================================================================

/// Open adapter for protocol
pub fn ndis_open_adapter(
    protocol_name: &str,
    adapter_id: u32,
    open_context: usize,
) -> Result<u32, NdisStatus> {
    let mut state = NDIS_STATE.lock();

    // Verify adapter exists
    let mut adapter_found = false;
    for idx in 0..MAX_MINIPORT_ADAPTERS {
        if state.adapters[idx].active && state.adapters[idx].adapter_id == adapter_id {
            adapter_found = true;
            state.adapters[idx].binding_count += 1;
            break;
        }
    }

    if !adapter_found {
        return Err(NdisStatus::AdapterNotFound);
    }

    let binding_id = state.next_binding_id;

    for idx in 0..MAX_PROTOCOL_BINDINGS {
        if !state.bindings[idx].active {
            state.bindings[idx].binding_id = binding_id;
            state.bindings[idx].active = true;
            state.bindings[idx].set_name(protocol_name);
            state.bindings[idx].adapter_id = adapter_id;
            state.bindings[idx].open_context = open_context;
            state.bindings[idx].ref_count = AtomicU32::new(1);

            state.next_binding_id += 1;

            crate::serial_println!("[NDIS] Protocol '{}' bound to adapter {} (binding={})",
                protocol_name, adapter_id, binding_id);

            return Ok(binding_id);
        }
    }

    Err(NdisStatus::Resources)
}

/// Close adapter binding
pub fn ndis_close_adapter(binding_id: u32) -> NdisStatus {
    let mut state = NDIS_STATE.lock();

    for idx in 0..MAX_PROTOCOL_BINDINGS {
        if state.bindings[idx].active && state.bindings[idx].binding_id == binding_id {
            let adapter_id = state.bindings[idx].adapter_id;
            let protocol = String::from(state.bindings[idx].name_str());

            state.bindings[idx].active = false;

            // Decrement adapter binding count
            for a_idx in 0..MAX_MINIPORT_ADAPTERS {
                if state.adapters[a_idx].active && state.adapters[a_idx].adapter_id == adapter_id {
                    state.adapters[a_idx].binding_count =
                        state.adapters[a_idx].binding_count.saturating_sub(1);
                    break;
                }
            }

            crate::serial_println!("[NDIS] Protocol '{}' unbound from adapter {}",
                protocol, adapter_id);
            return NdisStatus::Success;
        }
    }

    NdisStatus::Failure
}

/// Send packet via binding
pub fn ndis_send(binding_id: u32, data: &[u8]) -> NdisStatus {
    let state = NDIS_STATE.lock();

    // Find binding
    for idx in 0..MAX_PROTOCOL_BINDINGS {
        if state.bindings[idx].active && state.bindings[idx].binding_id == binding_id {
            let adapter_id = state.bindings[idx].adapter_id;

            // Find adapter and record stats
            for a_idx in 0..MAX_MINIPORT_ADAPTERS {
                if state.adapters[a_idx].active && state.adapters[a_idx].adapter_id == adapter_id {
                    state.adapters[a_idx].stats.bytes_xmit.fetch_add(data.len() as u64, Ordering::Relaxed);
                    // In a real implementation, we would call the miniport's send handler
                    return NdisStatus::Pending;
                }
            }

            return NdisStatus::AdapterNotFound;
        }
    }

    NdisStatus::Failure
}

/// Query adapter information
pub fn ndis_query_information(
    binding_id: u32,
    oid: u32,
    buffer: &mut [u8],
) -> Result<usize, NdisStatus> {
    let state = NDIS_STATE.lock();

    // Find binding and adapter
    for idx in 0..MAX_PROTOCOL_BINDINGS {
        if state.bindings[idx].active && state.bindings[idx].binding_id == binding_id {
            let adapter_id = state.bindings[idx].adapter_id;

            for a_idx in 0..MAX_MINIPORT_ADAPTERS {
                if state.adapters[a_idx].active && state.adapters[a_idx].adapter_id == adapter_id {
                    return query_adapter_oid(&state.adapters[a_idx], oid, buffer);
                }
            }

            return Err(NdisStatus::AdapterNotFound);
        }
    }

    Err(NdisStatus::Failure)
}

/// Handle OID query for adapter
fn query_adapter_oid(
    adapter: &NdisMiniportAdapter,
    oid: u32,
    buffer: &mut [u8],
) -> Result<usize, NdisStatus> {
    match oid {
        oid::general::OID_GEN_HARDWARE_STATUS => {
            if buffer.len() >= 4 {
                let val = adapter.hardware_status as u32;
                buffer[0..4].copy_from_slice(&val.to_le_bytes());
                Ok(4)
            } else {
                Err(NdisStatus::BufferTooShort)
            }
        }
        oid::general::OID_GEN_MEDIA_IN_USE |
        oid::general::OID_GEN_MEDIA_SUPPORTED => {
            if buffer.len() >= 4 {
                let val = adapter.medium_type as u32;
                buffer[0..4].copy_from_slice(&val.to_le_bytes());
                Ok(4)
            } else {
                Err(NdisStatus::BufferTooShort)
            }
        }
        oid::general::OID_GEN_MAXIMUM_FRAME_SIZE => {
            if buffer.len() >= 4 {
                buffer[0..4].copy_from_slice(&adapter.max_frame_size.to_le_bytes());
                Ok(4)
            } else {
                Err(NdisStatus::BufferTooShort)
            }
        }
        oid::general::OID_GEN_LINK_SPEED => {
            if buffer.len() >= 4 {
                buffer[0..4].copy_from_slice(&adapter.link_speed.to_le_bytes());
                Ok(4)
            } else {
                Err(NdisStatus::BufferTooShort)
            }
        }
        oid::general::OID_GEN_CURRENT_PACKET_FILTER => {
            if buffer.len() >= 4 {
                buffer[0..4].copy_from_slice(&adapter.packet_filter.to_le_bytes());
                Ok(4)
            } else {
                Err(NdisStatus::BufferTooShort)
            }
        }
        oid::general::OID_GEN_MEDIA_CONNECT_STATUS => {
            if buffer.len() >= 4 {
                let val = adapter.media_state as u32;
                buffer[0..4].copy_from_slice(&val.to_le_bytes());
                Ok(4)
            } else {
                Err(NdisStatus::BufferTooShort)
            }
        }
        oid::ethernet::OID_802_3_CURRENT_ADDRESS => {
            if buffer.len() >= 6 {
                buffer[0..6].copy_from_slice(&adapter.current_address);
                Ok(6)
            } else {
                Err(NdisStatus::BufferTooShort)
            }
        }
        oid::ethernet::OID_802_3_PERMANENT_ADDRESS => {
            if buffer.len() >= 6 {
                buffer[0..6].copy_from_slice(&adapter.permanent_address);
                Ok(6)
            } else {
                Err(NdisStatus::BufferTooShort)
            }
        }
        oid::general::OID_GEN_XMIT_OK => {
            if buffer.len() >= 8 {
                let val = adapter.stats.xmit_ok.load(Ordering::Relaxed);
                buffer[0..8].copy_from_slice(&val.to_le_bytes());
                Ok(8)
            } else {
                Err(NdisStatus::BufferTooShort)
            }
        }
        oid::general::OID_GEN_RCV_OK => {
            if buffer.len() >= 8 {
                let val = adapter.stats.rcv_ok.load(Ordering::Relaxed);
                buffer[0..8].copy_from_slice(&val.to_le_bytes());
                Ok(8)
            } else {
                Err(NdisStatus::BufferTooShort)
            }
        }
        _ => Err(NdisStatus::InvalidOid),
    }
}

// ============================================================================
// NDIS Statistics and Diagnostics
// ============================================================================

/// NDIS statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct NdisStats {
    /// Registered adapters
    pub adapter_count: usize,
    /// Active bindings
    pub binding_count: usize,
    /// Total packets transmitted
    pub total_xmit: u64,
    /// Total packets received
    pub total_rcv: u64,
}

/// Get NDIS statistics
pub fn ndis_get_stats() -> NdisStats {
    let state = NDIS_STATE.lock();

    let mut stats = NdisStats::default();

    for adapter in state.adapters.iter() {
        if adapter.active {
            stats.adapter_count += 1;
            stats.total_xmit += adapter.stats.xmit_ok.load(Ordering::Relaxed);
            stats.total_rcv += adapter.stats.rcv_ok.load(Ordering::Relaxed);
        }
    }

    for binding in state.bindings.iter() {
        if binding.active {
            stats.binding_count += 1;
        }
    }

    stats
}

/// NDIS adapter snapshot for diagnostics
#[derive(Debug, Clone)]
pub struct NdisAdapterSnapshot {
    pub adapter_id: u32,
    pub name: String,
    pub medium_type: NdisMedium,
    pub hardware_status: NdisHardwareStatus,
    pub media_state: NdisMediaState,
    pub mac_address: [u8; 6],
    pub link_speed: u32,
    pub binding_count: u32,
    pub xmit_ok: u64,
    pub rcv_ok: u64,
}

/// Get adapter snapshots
pub fn ndis_get_adapter_snapshots() -> Vec<NdisAdapterSnapshot> {
    let state = NDIS_STATE.lock();
    let mut snapshots = Vec::new();

    for adapter in state.adapters.iter() {
        if adapter.active {
            snapshots.push(NdisAdapterSnapshot {
                adapter_id: adapter.adapter_id,
                name: String::from(adapter.name_str()),
                medium_type: adapter.medium_type,
                hardware_status: adapter.hardware_status,
                media_state: adapter.media_state,
                mac_address: adapter.current_address,
                link_speed: adapter.link_speed,
                binding_count: adapter.binding_count,
                xmit_ok: adapter.stats.xmit_ok.load(Ordering::Relaxed),
                rcv_ok: adapter.stats.rcv_ok.load(Ordering::Relaxed),
            });
        }
    }

    snapshots
}

// ============================================================================
// NDIS Initialization
// ============================================================================

/// Initialize NDIS subsystem
pub fn init() {
    if NDIS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[NDIS] Network Driver Interface Specification initialized");
    crate::serial_println!("[NDIS]   Version: 5.1");
    crate::serial_println!("[NDIS]   Max adapters: {}", MAX_MINIPORT_ADAPTERS);
    crate::serial_println!("[NDIS]   Max bindings: {}", MAX_PROTOCOL_BINDINGS);
}

/// Check if NDIS is initialized
pub fn is_initialized() -> bool {
    NDIS_INITIALIZED.load(Ordering::SeqCst)
}
