//! TFTP (Trivial File Transfer Protocol) Client
//!
//! RFC 1350 - The TFTP Protocol (Revision 2)
//! Simple UDP-based file transfer for network boot and configuration.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use super::udp;
use super::ip::Ipv4Address;

/// TFTP server port
pub const TFTP_PORT: u16 = 69;

/// Maximum TFTP data block size
pub const TFTP_BLOCK_SIZE: usize = 512;

/// TFTP timeout in polls
pub const TFTP_TIMEOUT_POLLS: usize = 5000;

/// Maximum retries per block
pub const TFTP_MAX_RETRIES: usize = 5;

/// TFTP opcodes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TftpOpcode {
    /// Read request (RRQ)
    Rrq = 1,
    /// Write request (WRQ)
    Wrq = 2,
    /// Data packet
    Data = 3,
    /// Acknowledgment
    Ack = 4,
    /// Error
    Error = 5,
}

/// TFTP error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TftpError {
    /// Not defined, see error message
    Undefined = 0,
    /// File not found
    FileNotFound = 1,
    /// Access violation
    AccessViolation = 2,
    /// Disk full or allocation exceeded
    DiskFull = 3,
    /// Illegal TFTP operation
    IllegalOperation = 4,
    /// Unknown transfer ID
    UnknownTid = 5,
    /// File already exists
    FileExists = 6,
    /// No such user
    NoSuchUser = 7,
}

impl TftpError {
    fn from_u16(code: u16) -> Self {
        match code {
            1 => TftpError::FileNotFound,
            2 => TftpError::AccessViolation,
            3 => TftpError::DiskFull,
            4 => TftpError::IllegalOperation,
            5 => TftpError::UnknownTid,
            6 => TftpError::FileExists,
            7 => TftpError::NoSuchUser,
            _ => TftpError::Undefined,
        }
    }

    fn message(&self) -> &'static str {
        match self {
            TftpError::Undefined => "Not defined",
            TftpError::FileNotFound => "File not found",
            TftpError::AccessViolation => "Access violation",
            TftpError::DiskFull => "Disk full",
            TftpError::IllegalOperation => "Illegal operation",
            TftpError::UnknownTid => "Unknown transfer ID",
            TftpError::FileExists => "File already exists",
            TftpError::NoSuchUser => "No such user",
        }
    }
}

/// Transfer mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferMode {
    /// Binary mode (octet)
    Binary,
    /// ASCII mode (netascii)
    Ascii,
}

impl TransferMode {
    fn as_str(&self) -> &'static str {
        match self {
            TransferMode::Binary => "octet",
            TransferMode::Ascii => "netascii",
        }
    }
}

/// TFTP transfer result
#[derive(Debug)]
pub struct TftpResult {
    /// Downloaded data
    pub data: Vec<u8>,
    /// Number of blocks transferred
    pub blocks: u16,
    /// Total bytes transferred
    pub bytes: usize,
}

/// Statistics
static TRANSFERS_COMPLETED: AtomicU32 = AtomicU32::new(0);
static TRANSFERS_FAILED: AtomicU32 = AtomicU32::new(0);
static BYTES_RECEIVED: AtomicU32 = AtomicU32::new(0);

/// Build a RRQ (Read Request) packet
fn build_rrq(filename: &str, mode: TransferMode) -> Vec<u8> {
    let mode_str = mode.as_str();
    let mut packet = Vec::with_capacity(4 + filename.len() + mode_str.len() + 2);

    // Opcode (2 bytes, big-endian)
    packet.extend_from_slice(&(TftpOpcode::Rrq as u16).to_be_bytes());

    // Filename (null-terminated)
    packet.extend_from_slice(filename.as_bytes());
    packet.push(0);

    // Mode (null-terminated)
    packet.extend_from_slice(mode_str.as_bytes());
    packet.push(0);

    packet
}

/// Build an ACK packet
fn build_ack(block_num: u16) -> [u8; 4] {
    let mut packet = [0u8; 4];
    packet[0..2].copy_from_slice(&(TftpOpcode::Ack as u16).to_be_bytes());
    packet[2..4].copy_from_slice(&block_num.to_be_bytes());
    packet
}

/// Parse a TFTP packet
fn parse_packet(data: &[u8]) -> Option<(TftpOpcode, &[u8])> {
    if data.len() < 4 {
        return None;
    }

    let opcode = u16::from_be_bytes([data[0], data[1]]);
    let opcode = match opcode {
        1 => TftpOpcode::Rrq,
        2 => TftpOpcode::Wrq,
        3 => TftpOpcode::Data,
        4 => TftpOpcode::Ack,
        5 => TftpOpcode::Error,
        _ => return None,
    };

    Some((opcode, &data[2..]))
}

/// Download a file via TFTP
pub fn get(
    device_index: usize,
    server_ip: Ipv4Address,
    filename: &str,
    mode: TransferMode,
) -> Result<TftpResult, &'static str> {
    crate::serial_println!("[TFTP] Downloading '{}' from {:?}", filename, server_ip);

    // Create UDP socket
    let socket = udp::socket_create().ok_or("Failed to create UDP socket")?;

    // Send RRQ
    let rrq = build_rrq(filename, mode);
    udp::socket_sendto(socket, device_index, server_ip, TFTP_PORT, &rrq)?;

    let mut data = Vec::new();
    let mut expected_block: u16 = 1;
    let mut server_port: u16 = 0;
    let mut retries = 0;

    loop {
        // Poll for response
        let mut polls = 0;
        let mut received = false;

        while polls < TFTP_TIMEOUT_POLLS {
            crate::drivers::virtio::net::poll();

            if let Some(datagram) = udp::socket_recvfrom(socket) {
                if datagram.src_ip == server_ip {
                    // First response gives us the server's TID (port)
                    if server_port == 0 {
                        server_port = datagram.src_port;
                    } else if datagram.src_port != server_port {
                        // Wrong TID, ignore
                        continue;
                    }

                    if let Some((opcode, payload)) = parse_packet(&datagram.data) {
                        match opcode {
                            TftpOpcode::Data => {
                                if payload.len() < 2 {
                                    continue;
                                }
                                let block_num = u16::from_be_bytes([payload[0], payload[1]]);
                                let block_data = &payload[2..];

                                if block_num == expected_block {
                                    // Append data
                                    data.extend_from_slice(block_data);

                                    // Send ACK
                                    let ack = build_ack(block_num);
                                    let _ = udp::socket_sendto(
                                        socket,
                                        device_index,
                                        server_ip,
                                        server_port,
                                        &ack,
                                    );

                                    // Check if last block
                                    if block_data.len() < TFTP_BLOCK_SIZE {
                                        // Transfer complete
                                        let _ = udp::socket_close(socket);
                                        let total_bytes = data.len();
                                        TRANSFERS_COMPLETED.fetch_add(1, Ordering::Relaxed);
                                        BYTES_RECEIVED.fetch_add(total_bytes as u32, Ordering::Relaxed);

                                        crate::serial_println!(
                                            "[TFTP] Download complete: {} bytes, {} blocks",
                                            total_bytes,
                                            expected_block
                                        );

                                        return Ok(TftpResult {
                                            data,
                                            blocks: expected_block,
                                            bytes: total_bytes,
                                        });
                                    }

                                    expected_block += 1;
                                    retries = 0;
                                    received = true;
                                    break;
                                } else if block_num < expected_block {
                                    // Duplicate, re-ACK
                                    let ack = build_ack(block_num);
                                    let _ = udp::socket_sendto(
                                        socket,
                                        device_index,
                                        server_ip,
                                        server_port,
                                        &ack,
                                    );
                                }
                            }
                            TftpOpcode::Error => {
                                let error_code = if payload.len() >= 2 {
                                    u16::from_be_bytes([payload[0], payload[1]])
                                } else {
                                    0
                                };
                                let error = TftpError::from_u16(error_code);

                                crate::serial_println!(
                                    "[TFTP] Error from server: {:?} - {}",
                                    error,
                                    error.message()
                                );

                                let _ = udp::socket_close(socket);
                                TRANSFERS_FAILED.fetch_add(1, Ordering::Relaxed);
                                return Err(error.message());
                            }
                            _ => {}
                        }
                    }
                }
            }

            polls += 1;
            for _ in 0..100 {
                core::hint::spin_loop();
            }
        }

        if !received {
            retries += 1;
            if retries >= TFTP_MAX_RETRIES {
                let _ = udp::socket_close(socket);
                TRANSFERS_FAILED.fetch_add(1, Ordering::Relaxed);
                return Err("Transfer timeout");
            }

            // Resend last ACK or RRQ
            if expected_block == 1 {
                let _ = udp::socket_sendto(socket, device_index, server_ip, TFTP_PORT, &rrq);
            } else {
                let ack = build_ack(expected_block - 1);
                let _ = udp::socket_sendto(socket, device_index, server_ip, server_port, &ack);
            }
        }
    }
}

/// Get TFTP statistics
pub fn get_stats() -> (u32, u32, u32) {
    (
        TRANSFERS_COMPLETED.load(Ordering::Relaxed),
        TRANSFERS_FAILED.load(Ordering::Relaxed),
        BYTES_RECEIVED.load(Ordering::Relaxed),
    )
}

/// Initialize TFTP module
pub fn init() {
    crate::serial_println!("[TFTP] TFTP client initialized");
}
