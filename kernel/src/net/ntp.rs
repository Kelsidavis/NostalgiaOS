//! NTP (Network Time Protocol) Client
//!
//! RFC 5905 - Network Time Protocol Version 4
//! Simple NTP client for time synchronization.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use super::udp;
use super::ip::Ipv4Address;

/// NTP server port
pub const NTP_PORT: u16 = 123;

/// NTP packet size
pub const NTP_PACKET_SIZE: usize = 48;

/// NTP epoch (Jan 1, 1900) to Unix epoch (Jan 1, 1970) in seconds
pub const NTP_UNIX_EPOCH_DIFF: u64 = 2208988800;

/// Timeout for NTP request in polls
pub const NTP_TIMEOUT_POLLS: usize = 3000;

/// NTP Leap Indicator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LeapIndicator {
    NoWarning = 0,
    LastMinute61 = 1,
    LastMinute59 = 2,
    Unsynchronized = 3,
}

/// NTP Mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NtpMode {
    Reserved = 0,
    SymmetricActive = 1,
    SymmetricPassive = 2,
    Client = 3,
    Server = 4,
    Broadcast = 5,
    Control = 6,
    Private = 7,
}

/// NTP Stratum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stratum {
    /// Unspecified or invalid
    Unspecified,
    /// Primary reference (GPS, atomic clock)
    Primary,
    /// Secondary reference (via NTP)
    Secondary(u8),
    /// Unsynchronized
    Unsynchronized,
}

impl From<u8> for Stratum {
    fn from(value: u8) -> Self {
        match value {
            0 => Stratum::Unspecified,
            1 => Stratum::Primary,
            2..=15 => Stratum::Secondary(value),
            _ => Stratum::Unsynchronized,
        }
    }
}

/// NTP timestamp (64-bit: 32 bits seconds + 32 bits fraction)
#[derive(Debug, Clone, Copy, Default)]
pub struct NtpTimestamp {
    /// Seconds since NTP epoch (Jan 1, 1900)
    pub seconds: u32,
    /// Fractional seconds (2^32 per second)
    pub fraction: u32,
}

impl NtpTimestamp {
    /// Create a new NTP timestamp
    pub const fn new(seconds: u32, fraction: u32) -> Self {
        Self { seconds, fraction }
    }

    /// Convert to Unix timestamp (seconds since Jan 1, 1970)
    pub fn to_unix(&self) -> u64 {
        if self.seconds as u64 >= NTP_UNIX_EPOCH_DIFF {
            self.seconds as u64 - NTP_UNIX_EPOCH_DIFF
        } else {
            0
        }
    }

    /// Convert to milliseconds since Unix epoch
    pub fn to_unix_millis(&self) -> u64 {
        let secs = self.to_unix();
        let frac_ms = ((self.fraction as u64) * 1000) >> 32;
        secs * 1000 + frac_ms
    }

    /// Parse from 8 bytes (big-endian)
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        Some(Self {
            seconds: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            fraction: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        })
    }

    /// Serialize to 8 bytes (big-endian)
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0..4].copy_from_slice(&self.seconds.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.fraction.to_be_bytes());
        bytes
    }
}

/// NTP packet
#[derive(Debug, Clone)]
pub struct NtpPacket {
    /// Leap indicator (2 bits)
    pub leap: LeapIndicator,
    /// Version number (3 bits) - usually 3 or 4
    pub version: u8,
    /// Mode (3 bits)
    pub mode: NtpMode,
    /// Stratum
    pub stratum: Stratum,
    /// Poll interval (log2 seconds)
    pub poll: i8,
    /// Precision (log2 seconds)
    pub precision: i8,
    /// Root delay (32-bit fixed point, seconds)
    pub root_delay: u32,
    /// Root dispersion (32-bit fixed point, seconds)
    pub root_dispersion: u32,
    /// Reference identifier (4 bytes)
    pub reference_id: [u8; 4],
    /// Reference timestamp
    pub reference_ts: NtpTimestamp,
    /// Originate timestamp
    pub originate_ts: NtpTimestamp,
    /// Receive timestamp
    pub receive_ts: NtpTimestamp,
    /// Transmit timestamp
    pub transmit_ts: NtpTimestamp,
}

impl NtpPacket {
    /// Create a client request packet
    pub fn new_request() -> Self {
        Self {
            leap: LeapIndicator::NoWarning,
            version: 4,
            mode: NtpMode::Client,
            stratum: Stratum::Unspecified,
            poll: 0,
            precision: 0,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: [0; 4],
            reference_ts: NtpTimestamp::default(),
            originate_ts: NtpTimestamp::default(),
            receive_ts: NtpTimestamp::default(),
            transmit_ts: NtpTimestamp::default(),
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; NTP_PACKET_SIZE] {
        let mut bytes = [0u8; NTP_PACKET_SIZE];

        // LI (2) + VN (3) + Mode (3)
        let li_vn_mode = ((self.leap as u8) << 6) | ((self.version & 0x7) << 3) | (self.mode as u8 & 0x7);
        bytes[0] = li_vn_mode;

        // Stratum
        bytes[1] = match self.stratum {
            Stratum::Unspecified => 0,
            Stratum::Primary => 1,
            Stratum::Secondary(s) => s,
            Stratum::Unsynchronized => 16,
        };

        // Poll
        bytes[2] = self.poll as u8;

        // Precision
        bytes[3] = self.precision as u8;

        // Root delay
        bytes[4..8].copy_from_slice(&self.root_delay.to_be_bytes());

        // Root dispersion
        bytes[8..12].copy_from_slice(&self.root_dispersion.to_be_bytes());

        // Reference ID
        bytes[12..16].copy_from_slice(&self.reference_id);

        // Reference timestamp
        bytes[16..24].copy_from_slice(&self.reference_ts.to_bytes());

        // Originate timestamp
        bytes[24..32].copy_from_slice(&self.originate_ts.to_bytes());

        // Receive timestamp
        bytes[32..40].copy_from_slice(&self.receive_ts.to_bytes());

        // Transmit timestamp
        bytes[40..48].copy_from_slice(&self.transmit_ts.to_bytes());

        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < NTP_PACKET_SIZE {
            return None;
        }

        let li_vn_mode = data[0];
        let leap = match (li_vn_mode >> 6) & 0x3 {
            0 => LeapIndicator::NoWarning,
            1 => LeapIndicator::LastMinute61,
            2 => LeapIndicator::LastMinute59,
            _ => LeapIndicator::Unsynchronized,
        };
        let version = (li_vn_mode >> 3) & 0x7;
        let mode = match li_vn_mode & 0x7 {
            1 => NtpMode::SymmetricActive,
            2 => NtpMode::SymmetricPassive,
            3 => NtpMode::Client,
            4 => NtpMode::Server,
            5 => NtpMode::Broadcast,
            6 => NtpMode::Control,
            7 => NtpMode::Private,
            _ => NtpMode::Reserved,
        };

        Some(Self {
            leap,
            version,
            mode,
            stratum: Stratum::from(data[1]),
            poll: data[2] as i8,
            precision: data[3] as i8,
            root_delay: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            root_dispersion: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            reference_id: [data[12], data[13], data[14], data[15]],
            reference_ts: NtpTimestamp::from_bytes(&data[16..24])?,
            originate_ts: NtpTimestamp::from_bytes(&data[24..32])?,
            receive_ts: NtpTimestamp::from_bytes(&data[32..40])?,
            transmit_ts: NtpTimestamp::from_bytes(&data[40..48])?,
        })
    }
}

/// NTP synchronization result
#[derive(Debug, Clone)]
pub struct NtpResult {
    /// Server IP
    pub server_ip: Ipv4Address,
    /// Unix timestamp (seconds since 1970)
    pub unix_timestamp: u64,
    /// Milliseconds component
    pub milliseconds: u64,
    /// Server stratum
    pub stratum: Stratum,
    /// Round-trip delay in milliseconds
    pub delay_ms: u64,
    /// Offset from local clock in milliseconds (signed)
    pub offset_ms: i64,
}

/// Global NTP state
static NTP_INITIALIZED: AtomicBool = AtomicBool::new(false);
static LAST_SYNC_TIME: AtomicU64 = AtomicU64::new(0);
static NTP_OFFSET_MS: AtomicU64 = AtomicU64::new(0);

/// Initialize NTP module
pub fn init() {
    NTP_INITIALIZED.store(true, Ordering::SeqCst);
    crate::serial_println!("[NTP] NTP client initialized");
}

/// Synchronize time with an NTP server
pub fn sync_time(device_index: usize, server_ip: Ipv4Address) -> Result<NtpResult, &'static str> {
    if !NTP_INITIALIZED.load(Ordering::SeqCst) {
        return Err("NTP not initialized");
    }

    crate::serial_println!("[NTP] Syncing with {:?}...", server_ip);

    // Create UDP socket
    let socket = udp::socket_create().ok_or("Failed to create UDP socket")?;

    // Bind to ephemeral port
    let result = ntp_request(socket, device_index, server_ip);

    // Close socket
    let _ = udp::socket_close(socket);

    result
}

/// Perform NTP request
fn ntp_request(socket: usize, device_index: usize, server_ip: Ipv4Address) -> Result<NtpResult, &'static str> {
    // Record local time before sending (using APIC ticks as substitute)
    let t1_local = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed);

    // Build request packet
    let request = NtpPacket::new_request();
    let request_bytes = request.to_bytes();

    // Send request
    udp::socket_sendto(socket, device_index, server_ip, NTP_PORT, &request_bytes)?;
    crate::serial_println!("[NTP] Request sent to {:?}", server_ip);

    // Wait for response
    let mut polls = 0;
    loop {
        if polls > NTP_TIMEOUT_POLLS {
            return Err("NTP request timeout");
        }

        // Poll network
        crate::drivers::virtio::net::poll();

        // Check for response
        if let Some(datagram) = udp::socket_recvfrom(socket) {
            if datagram.src_ip == server_ip && datagram.data.len() >= NTP_PACKET_SIZE {
                let t4_local = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed);

                if let Some(response) = NtpPacket::from_bytes(&datagram.data) {
                    return process_ntp_response(response, server_ip, t1_local, t4_local);
                }
            }
        }

        polls += 1;
        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }
}

/// Process NTP response
fn process_ntp_response(
    response: NtpPacket,
    server_ip: Ipv4Address,
    t1_local: u64,
    t4_local: u64,
) -> Result<NtpResult, &'static str> {
    // Validate response
    if response.mode != NtpMode::Server {
        return Err("Invalid NTP response mode");
    }

    // Check stratum (16 = unsynchronized/kiss-o-death)
    if let Stratum::Unsynchronized = response.stratum {
        return Err("Server is unsynchronized");
    }

    // Calculate round-trip delay (in local ticks, ~ms)
    let delay_ms = t4_local.saturating_sub(t1_local);

    // Get server transmit time
    let unix_ts = response.transmit_ts.to_unix();
    let unix_ms = response.transmit_ts.to_unix_millis();

    // Store sync time
    LAST_SYNC_TIME.store(unix_ms, Ordering::SeqCst);

    // Calculate approximate offset (local time was at t1, server time was transmit_ts)
    // This is simplified - real NTP uses T1, T2, T3, T4 for accurate offset
    let offset_ms = 0i64; // Simplified for now

    crate::serial_println!(
        "[NTP] Response: stratum={:?}, time={}s, delay={}ms",
        response.stratum,
        unix_ts,
        delay_ms
    );

    // Format reference ID (often ASCII for stratum 1)
    let ref_id = &response.reference_id;
    if ref_id.iter().all(|&b| b >= 0x20 && b < 0x7F) {
        crate::serial_println!(
            "[NTP] Reference: {}{}{}{}",
            ref_id[0] as char,
            ref_id[1] as char,
            ref_id[2] as char,
            ref_id[3] as char
        );
    }

    Ok(NtpResult {
        server_ip,
        unix_timestamp: unix_ts,
        milliseconds: unix_ms % 1000,
        stratum: response.stratum,
        delay_ms,
        offset_ms,
    })
}

/// Get last sync time (Unix timestamp in ms)
pub fn get_last_sync_time() -> u64 {
    LAST_SYNC_TIME.load(Ordering::SeqCst)
}

/// Convert Unix timestamp to human-readable date/time
/// Returns (year, month, day, hour, minute, second)
pub fn unix_to_datetime(unix_secs: u64) -> (u32, u8, u8, u8, u8, u8) {
    // Days since Unix epoch
    let mut days = (unix_secs / 86400) as u32;
    let time_of_day = (unix_secs % 86400) as u32;

    let hour = (time_of_day / 3600) as u8;
    let minute = ((time_of_day % 3600) / 60) as u8;
    let second = (time_of_day % 60) as u8;

    // Calculate year (starting from 1970)
    let mut year = 1970u32;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    // Calculate month and day
    let leap = is_leap_year(year);
    let days_in_month: [u32; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 0u8;
    for (i, &dim) in days_in_month.iter().enumerate() {
        if days < dim {
            month = (i + 1) as u8;
            break;
        }
        days -= dim;
    }

    let day = (days + 1) as u8;

    (year, month, day, hour, minute, second)
}

/// Check if year is a leap year
fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Well-known NTP servers
pub mod servers {
    use super::Ipv4Address;

    /// pool.ntp.org (example IPs - these change)
    pub const POOL_NTP_ORG: Ipv4Address = Ipv4Address::new([129, 6, 15, 28]);

    /// time.google.com
    pub const TIME_GOOGLE: Ipv4Address = Ipv4Address::new([216, 239, 35, 0]);

    /// time.cloudflare.com
    pub const TIME_CLOUDFLARE: Ipv4Address = Ipv4Address::new([162, 159, 200, 1]);

    /// time.nist.gov
    pub const TIME_NIST: Ipv4Address = Ipv4Address::new([129, 6, 15, 28]);

    /// time.windows.com (approximate)
    pub const TIME_WINDOWS: Ipv4Address = Ipv4Address::new([168, 61, 215, 74]);
}
