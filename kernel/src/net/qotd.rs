//! Quote of the Day (QOTD) Service
//!
//! RFC 865 - Quote of the Day Protocol
//!
//! Simple service that returns a random quote when a connection is made.
//! Used for testing and entertainment.

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use super::udp;
use super::ip::Ipv4Address;

/// QOTD port (RFC 865)
pub const QOTD_PORT: u16 = 17;

/// Server state
static QOTD_UDP_RUNNING: AtomicBool = AtomicBool::new(false);
static QOTD_TCP_RUNNING: AtomicBool = AtomicBool::new(false);

/// Statistics
static QOTD_UDP_REQUESTS: AtomicU32 = AtomicU32::new(0);
static QOTD_TCP_REQUESTS: AtomicU32 = AtomicU32::new(0);

/// Quote counter for cycling through quotes
static QUOTE_COUNTER: AtomicU32 = AtomicU32::new(0);

/// UDP Socket
static mut QOTD_UDP_SOCKET: Option<usize> = None;

/// Collection of quotes
const QUOTES: &[&str] = &[
    "The only way to do great work is to love what you do. - Steve Jobs\r\n",
    "In the middle of difficulty lies opportunity. - Albert Einstein\r\n",
    "First, solve the problem. Then, write the code. - John Johnson\r\n",
    "Any fool can write code that a computer can understand. Good programmers write code that humans can understand. - Martin Fowler\r\n",
    "Talk is cheap. Show me the code. - Linus Torvalds\r\n",
    "Programs must be written for people to read, and only incidentally for machines to execute. - Abelson and Sussman\r\n",
    "The best error message is the one that never shows up. - Thomas Fuchs\r\n",
    "Debugging is twice as hard as writing the code in the first place. - Brian Kernighan\r\n",
    "Simplicity is the soul of efficiency. - Austin Freeman\r\n",
    "Make it work, make it right, make it fast. - Kent Beck\r\n",
    "Code is like humor. When you have to explain it, it's bad. - Cory House\r\n",
    "The best thing about a boolean is even if you are wrong, you are only off by a bit. - Anonymous\r\n",
    "There are only two hard things in Computer Science: cache invalidation and naming things. - Phil Karlton\r\n",
    "It works on my machine. - Every Developer\r\n",
    "The computer was born to solve problems that did not exist before. - Bill Gates\r\n",
    "Perfection is achieved not when there is nothing more to add, but when there is nothing left to take away. - Antoine de Saint-Exupery\r\n",
];

/// Get the next quote (cycles through quotes)
fn get_quote() -> &'static [u8] {
    let idx = QUOTE_COUNTER.fetch_add(1, Ordering::Relaxed) as usize % QUOTES.len();
    QUOTES[idx].as_bytes()
}

/// Get a specific quote by index
pub fn get_quote_by_index(idx: usize) -> Option<&'static str> {
    QUOTES.get(idx % QUOTES.len()).copied()
}

/// Get total number of quotes
pub fn quote_count() -> usize {
    QUOTES.len()
}

/// Start UDP QOTD server
pub fn start_qotd_udp() -> Result<(), &'static str> {
    if QOTD_UDP_RUNNING.load(Ordering::SeqCst) {
        return Err("QOTD UDP server already running");
    }

    let socket = udp::socket_create().ok_or("Failed to create socket")?;
    udp::socket_bind(socket, QOTD_PORT)?;

    unsafe {
        QOTD_UDP_SOCKET = Some(socket);
    }
    QOTD_UDP_RUNNING.store(true, Ordering::SeqCst);

    crate::serial_println!("[QOTD] UDP server started on port {}", QOTD_PORT);
    Ok(())
}

/// Stop UDP QOTD server
pub fn stop_qotd_udp() {
    if !QOTD_UDP_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    unsafe {
        if let Some(socket) = QOTD_UDP_SOCKET.take() {
            let _ = udp::socket_close(socket);
        }
    }
    QOTD_UDP_RUNNING.store(false, Ordering::SeqCst);
    crate::serial_println!("[QOTD] UDP server stopped");
}

/// Process UDP QOTD packets
pub fn process_qotd_udp(device_index: usize) {
    if !QOTD_UDP_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    let socket = unsafe { QOTD_UDP_SOCKET };
    if let Some(socket) = socket {
        while let Some(datagram) = udp::socket_recvfrom(socket) {
            // Send a quote back
            let quote = get_quote();
            let _ = udp::socket_sendto(
                socket,
                device_index,
                datagram.src_ip,
                datagram.src_port,
                quote,
            );
            QOTD_UDP_REQUESTS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Request a quote from a QOTD server (client)
pub fn request_quote(
    device_index: usize,
    server_ip: Ipv4Address,
    timeout_ms: u32,
) -> Result<alloc::vec::Vec<u8>, &'static str> {
    let socket = udp::socket_create().ok_or("Failed to create socket")?;
    udp::socket_bind(socket, 0)?;

    let start = crate::hal::apic::get_tick_count();

    // Send empty request (any data triggers response)
    udp::socket_sendto(socket, device_index, server_ip, QOTD_PORT, &[0])?;

    // Wait for response
    let timeout_ticks = timeout_ms as u64 * 1000;

    loop {
        if let Some(datagram) = udp::socket_recvfrom(socket) {
            let _ = udp::socket_close(socket);
            return Ok(datagram.data);
        }

        let elapsed = crate::hal::apic::get_tick_count() - start;
        if elapsed > timeout_ticks {
            let _ = udp::socket_close(socket);
            return Err("QOTD timeout");
        }

        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }
}

/// QOTD service statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct QotdStats {
    pub udp_requests: u32,
    pub tcp_requests: u32,
    pub udp_running: bool,
    pub tcp_running: bool,
    pub total_quotes: usize,
}

/// Get QOTD service statistics
pub fn get_stats() -> QotdStats {
    QotdStats {
        udp_requests: QOTD_UDP_REQUESTS.load(Ordering::Relaxed),
        tcp_requests: QOTD_TCP_REQUESTS.load(Ordering::Relaxed),
        udp_running: QOTD_UDP_RUNNING.load(Ordering::SeqCst),
        tcp_running: QOTD_TCP_RUNNING.load(Ordering::SeqCst),
        total_quotes: QUOTES.len(),
    }
}

/// Initialize QOTD service
pub fn init() {
    crate::serial_println!("[QOTD] Quote of the Day service initialized ({} quotes)", QUOTES.len());
}
