//! Local Procedure Call (LPC) / Advanced Local Procedure Call (ALPC)
//!
//! LPC is the NT inter-process communication mechanism. It provides:
//!
//! - **Ports**: Named communication endpoints
//! - **Messages**: Data transfer between processes
//! - **Connections**: Client-server relationships
//!
//! # Architecture
//!
//! ```text
//! Server Process                    Client Process
//! ┌────────────────┐                ┌────────────────┐
//! │  Server Port   │◄───────────────│  Client Port   │
//! │ (connection)   │    connect     │ (communication)│
//! └───────┬────────┘                └───────┬────────┘
//!         │                                 │
//!         │ listen/reply                    │ send/receive
//!         ▼                                 ▼
//! ┌────────────────┐                ┌────────────────┐
//! │  Message Queue │                │  Reply Port    │
//! └────────────────┘                └────────────────┘
//! ```
//!
//! # Message Types
//!
//! - LPC_REQUEST: Client request to server
//! - LPC_REPLY: Server reply to client
//! - LPC_DATAGRAM: One-way message (no reply)
//! - LPC_CONNECTION_REQUEST: Client connecting to server port
//! - LPC_CONNECTION_REPLY: Server accepting/rejecting connection
//! - LPC_CLIENT_DIED: Client process terminated
//! - LPC_PORT_CLOSED: Port was closed
//!
//! # ALPC Extensions
//!
//! ALPC (Advanced LPC) adds:
//! - Completion ports
//! - Views (shared memory sections)
//! - Cancellation
//! - Security contexts

pub mod port;
pub mod message;

use port::*;
use message::*;

// Re-export types
pub use port::{
    LpcPort,
    LpcPortType,
    LpcConnection,
    LpcConnectionState,
    LpcPortInfo,
    LpcPortStats,
    PortFlags,
    MAX_PORTS,
    MAX_PORT_NAME_LENGTH,
    MAX_CONNECTIONS_PER_PORT,
    lpc_create_port,
    lpc_close_port,
    lpc_connect_port,
    lpc_listen_port,
    lpc_accept_connection,
    lpc_get_port_info,
    lpc_get_port_stats,
};

pub use message::{
    LpcMessage,
    LpcMessageHeader,
    LpcMessageType,
    LpcMessageFlags,
    MAX_MESSAGE_SIZE,
    MAX_LPC_DATA_SIZE,
    lpc_send_message,
    lpc_receive_message,
    lpc_reply_message,
    lpc_send_datagram,
};

/// Initialize the LPC subsystem
pub fn init() {
    crate::serial_println!("[LPC] Initializing Local Procedure Call subsystem...");

    port::init();
    message::init();

    crate::serial_println!("[LPC] LPC subsystem initialized");
}
