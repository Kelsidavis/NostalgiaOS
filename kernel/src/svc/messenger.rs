//! Messenger Service
//!
//! The Messenger service transmits net send and Alerter service messages
//! between clients and servers. This is used for administrative alerts
//! and network notifications.
//!
//! # Features
//!
//! - **Message Reception**: Receive messages from other computers
//! - **Message Sending**: Send messages via net send command
//! - **Alerter Integration**: Receive administrative alerts
//! - **User Notification**: Display messages to logged-on users
//!
//! # Message Types
//!
//! - User messages (net send)
//! - Alerter messages (system alerts)
//! - Broadcast messages (domain/workgroup wide)
//!
//! # Protocol
//!
//! Uses NetBIOS mailslot for message delivery.
//! Messages are received on \\mailslot\messngr

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum messages in queue
const MAX_MESSAGES: usize = 64;

/// Maximum recipients list
const MAX_RECIPIENTS: usize = 32;

/// Maximum computer name length
const MAX_COMPUTER_NAME: usize = 16;

/// Maximum message length
const MAX_MESSAGE_LEN: usize = 512;

/// Message type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// User message (net send)
    User = 0,
    /// Alerter message (system alert)
    Alert = 1,
    /// Broadcast message
    Broadcast = 2,
    /// Shutdown warning
    Shutdown = 3,
}

impl MessageType {
    const fn empty() -> Self {
        MessageType::User
    }
}

/// Message status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageStatus {
    /// Pending delivery
    Pending = 0,
    /// Delivered
    Delivered = 1,
    /// Failed
    Failed = 2,
    /// Read by user
    Read = 3,
    /// Expired
    Expired = 4,
}

impl MessageStatus {
    const fn empty() -> Self {
        MessageStatus::Pending
    }
}

/// Message entry
#[repr(C)]
#[derive(Clone)]
pub struct Message {
    /// Message ID
    pub message_id: u64,
    /// Message type
    pub msg_type: MessageType,
    /// Status
    pub status: MessageStatus,
    /// Sender name
    pub sender: [u8; MAX_COMPUTER_NAME],
    /// Recipient name
    pub recipient: [u8; MAX_COMPUTER_NAME],
    /// Message text
    pub text: [u8; MAX_MESSAGE_LEN],
    /// Text length
    pub text_len: usize,
    /// Timestamp
    pub timestamp: i64,
    /// Is incoming message
    pub incoming: bool,
    /// Entry is valid
    pub valid: bool,
}

impl Message {
    const fn empty() -> Self {
        Message {
            message_id: 0,
            msg_type: MessageType::empty(),
            status: MessageStatus::empty(),
            sender: [0; MAX_COMPUTER_NAME],
            recipient: [0; MAX_COMPUTER_NAME],
            text: [0; MAX_MESSAGE_LEN],
            text_len: 0,
            timestamp: 0,
            incoming: false,
            valid: false,
        }
    }
}

/// Registered recipient (name alias)
#[repr(C)]
#[derive(Clone)]
pub struct Recipient {
    /// Name to receive messages for
    pub name: [u8; MAX_COMPUTER_NAME],
    /// Is registered
    pub valid: bool,
}

impl Recipient {
    const fn empty() -> Self {
        Recipient {
            name: [0; MAX_COMPUTER_NAME],
            valid: false,
        }
    }
}

/// Message callback for notification
pub type MessageCallback = fn(message: &Message);

/// Messenger service state
pub struct MessengerState {
    /// Service is running
    pub running: bool,
    /// Our computer name
    pub computer_name: [u8; MAX_COMPUTER_NAME],
    /// Messages queue
    pub messages: [Message; MAX_MESSAGES],
    /// Message count
    pub message_count: usize,
    /// Next message ID
    pub next_message_id: u64,
    /// Registered recipients (names we receive for)
    pub recipients: [Recipient; MAX_RECIPIENTS],
    /// Recipient count
    pub recipient_count: usize,
    /// Message callback
    pub callback: Option<MessageCallback>,
    /// Accept broadcast messages
    pub accept_broadcast: bool,
    /// Service start time
    pub start_time: i64,
}

impl MessengerState {
    const fn new() -> Self {
        MessengerState {
            running: false,
            computer_name: [0; MAX_COMPUTER_NAME],
            messages: [const { Message::empty() }; MAX_MESSAGES],
            message_count: 0,
            next_message_id: 1,
            recipients: [const { Recipient::empty() }; MAX_RECIPIENTS],
            recipient_count: 0,
            callback: None,
            accept_broadcast: true,
            start_time: 0,
        }
    }
}

/// Global state
static MESSENGER_STATE: Mutex<MessengerState> = Mutex::new(MessengerState::new());

/// Statistics
static MESSAGES_SENT: AtomicU64 = AtomicU64::new(0);
static MESSAGES_RECEIVED: AtomicU64 = AtomicU64::new(0);
static MESSAGES_FAILED: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize Messenger service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = MESSENGER_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    // Set default computer name
    let name = b"NOSTALGOS";
    state.computer_name[..name.len()].copy_from_slice(name);

    // Register computer name as recipient
    state.recipients[0].name[..name.len()].copy_from_slice(name);
    state.recipients[0].valid = true;
    state.recipient_count = 1;

    crate::serial_println!("[MESSENGER] Messenger service initialized");
}

/// Send a message to another computer
pub fn send_message(
    recipient: &[u8],
    text: &[u8],
) -> Result<u64, u32> {
    let mut state = MESSENGER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.messages.iter().position(|m| !m.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let message_id = state.next_message_id;
    state.next_message_id += 1;

    let now = crate::rtl::time::rtl_get_system_time();
    state.message_count += 1;

    let sender_name = state.computer_name;
    let recipient_len = recipient.len().min(MAX_COMPUTER_NAME);
    let text_len = text.len().min(MAX_MESSAGE_LEN);

    let msg = &mut state.messages[slot];
    msg.message_id = message_id;
    msg.msg_type = MessageType::User;
    msg.status = MessageStatus::Pending;
    msg.sender = sender_name;
    msg.recipient[..recipient_len].copy_from_slice(&recipient[..recipient_len]);
    msg.text[..text_len].copy_from_slice(&text[..text_len]);
    msg.text_len = text_len;
    msg.timestamp = now;
    msg.incoming = false;
    msg.valid = true;

    // Would actually send via NetBIOS mailslot here
    // Simulate success
    msg.status = MessageStatus::Delivered;

    MESSAGES_SENT.fetch_add(1, Ordering::SeqCst);

    Ok(message_id)
}

/// Send a broadcast message
pub fn send_broadcast(
    domain: &[u8],
    text: &[u8],
) -> Result<u64, u32> {
    let mut state = MESSENGER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.messages.iter().position(|m| !m.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let message_id = state.next_message_id;
    state.next_message_id += 1;

    let now = crate::rtl::time::rtl_get_system_time();
    state.message_count += 1;

    let sender_name = state.computer_name;
    let domain_len = domain.len().min(MAX_COMPUTER_NAME);
    let text_len = text.len().min(MAX_MESSAGE_LEN);

    let msg = &mut state.messages[slot];
    msg.message_id = message_id;
    msg.msg_type = MessageType::Broadcast;
    msg.status = MessageStatus::Pending;
    msg.sender = sender_name;
    msg.recipient[..domain_len].copy_from_slice(&domain[..domain_len]);
    msg.text[..text_len].copy_from_slice(&text[..text_len]);
    msg.text_len = text_len;
    msg.timestamp = now;
    msg.incoming = false;
    msg.valid = true;

    // Would broadcast via NetBIOS mailslot
    msg.status = MessageStatus::Delivered;

    MESSAGES_SENT.fetch_add(1, Ordering::SeqCst);

    Ok(message_id)
}

/// Receive a message (from network)
pub fn receive_message(
    sender: &[u8],
    recipient: &[u8],
    text: &[u8],
    msg_type: MessageType,
) -> Result<u64, u32> {
    let mut state = MESSENGER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Check if we accept this message
    let recipient_len = recipient.len().min(MAX_COMPUTER_NAME);

    // Check if broadcast and we accept broadcasts
    if msg_type == MessageType::Broadcast && !state.accept_broadcast {
        return Err(0x80070005);
    }

    // Check if addressed to one of our registered names
    let is_for_us = state.recipients.iter().any(|r| {
        r.valid && r.name[..recipient_len] == recipient[..recipient_len]
    });

    if !is_for_us && msg_type != MessageType::Broadcast {
        return Err(0x80070057);
    }

    let slot = state.messages.iter().position(|m| !m.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let message_id = state.next_message_id;
    state.next_message_id += 1;

    let now = crate::rtl::time::rtl_get_system_time();
    state.message_count += 1;

    let sender_len = sender.len().min(MAX_COMPUTER_NAME);
    let text_len = text.len().min(MAX_MESSAGE_LEN);

    // Extract callback before mutable borrow
    let callback = state.callback;

    let msg = &mut state.messages[slot];
    msg.message_id = message_id;
    msg.msg_type = msg_type;
    msg.status = MessageStatus::Delivered;
    msg.sender[..sender_len].copy_from_slice(&sender[..sender_len]);
    msg.recipient[..recipient_len].copy_from_slice(&recipient[..recipient_len]);
    msg.text[..text_len].copy_from_slice(&text[..text_len]);
    msg.text_len = text_len;
    msg.timestamp = now;
    msg.incoming = true;
    msg.valid = true;

    // Clone message for callback before releasing borrow
    let msg_copy = msg.clone();

    MESSAGES_RECEIVED.fetch_add(1, Ordering::SeqCst);

    // Notify callback if registered
    if let Some(cb) = callback {
        drop(state); // Release lock before callback
        cb(&msg_copy);
    }

    Ok(message_id)
}

/// Register a name to receive messages
pub fn add_name(name: &[u8]) -> Result<usize, u32> {
    let mut state = MESSENGER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let name_len = name.len().min(MAX_COMPUTER_NAME);

    // Check if already registered
    for recipient in state.recipients.iter() {
        if recipient.valid && recipient.name[..name_len] == name[..name_len] {
            return Err(0x80070055); // ERROR_DUP_NAME
        }
    }

    let slot = state.recipients.iter().position(|r| !r.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    state.recipients[slot].name = [0; MAX_COMPUTER_NAME];
    state.recipients[slot].name[..name_len].copy_from_slice(&name[..name_len]);
    state.recipients[slot].valid = true;
    state.recipient_count += 1;

    Ok(slot)
}

/// Remove a registered name
pub fn remove_name(name: &[u8]) -> Result<(), u32> {
    let mut state = MESSENGER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let name_len = name.len().min(MAX_COMPUTER_NAME);

    // Don't allow removing computer name
    if state.computer_name[..name_len] == name[..name_len] {
        return Err(0x80070005);
    }

    let idx = state.recipients.iter().position(|r| {
        r.valid && r.name[..name_len] == name[..name_len]
    });

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.recipients[idx].valid = false;
    state.recipient_count = state.recipient_count.saturating_sub(1);

    Ok(())
}

/// Get unread messages
pub fn get_unread_messages() -> ([Message; MAX_MESSAGES], usize) {
    let state = MESSENGER_STATE.lock();
    let mut result = [const { Message::empty() }; MAX_MESSAGES];
    let mut count = 0;

    for msg in state.messages.iter() {
        if msg.valid && msg.incoming && msg.status == MessageStatus::Delivered && count < MAX_MESSAGES {
            result[count] = msg.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get all messages
pub fn get_all_messages() -> ([Message; MAX_MESSAGES], usize) {
    let state = MESSENGER_STATE.lock();
    let mut result = [const { Message::empty() }; MAX_MESSAGES];
    let mut count = 0;

    for msg in state.messages.iter() {
        if msg.valid && count < MAX_MESSAGES {
            result[count] = msg.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Mark message as read
pub fn mark_read(message_id: u64) -> Result<(), u32> {
    let mut state = MESSENGER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let msg = state.messages.iter_mut()
        .find(|m| m.valid && m.message_id == message_id);

    let msg = match msg {
        Some(m) => m,
        None => return Err(0x80070057),
    };

    if msg.incoming && msg.status == MessageStatus::Delivered {
        msg.status = MessageStatus::Read;
    }

    Ok(())
}

/// Delete a message
pub fn delete_message(message_id: u64) -> Result<(), u32> {
    let mut state = MESSENGER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.messages.iter().position(|m| m.valid && m.message_id == message_id);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.messages[idx].valid = false;
    state.message_count = state.message_count.saturating_sub(1);

    Ok(())
}

/// Register message callback
pub fn set_callback(callback: Option<MessageCallback>) {
    let mut state = MESSENGER_STATE.lock();
    state.callback = callback;
}

/// Enable/disable broadcast messages
pub fn set_accept_broadcast(accept: bool) {
    let mut state = MESSENGER_STATE.lock();
    state.accept_broadcast = accept;
}

/// Get registered names
pub fn get_names() -> ([Recipient; MAX_RECIPIENTS], usize) {
    let state = MESSENGER_STATE.lock();
    let mut result = [const { Recipient::empty() }; MAX_RECIPIENTS];
    let mut count = 0;

    for recipient in state.recipients.iter() {
        if recipient.valid && count < MAX_RECIPIENTS {
            result[count] = recipient.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Send an alert message (from Alerter service)
pub fn send_alert(
    recipient: &[u8],
    alert_text: &[u8],
) -> Result<u64, u32> {
    let mut state = MESSENGER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.messages.iter().position(|m| !m.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let message_id = state.next_message_id;
    state.next_message_id += 1;

    let now = crate::rtl::time::rtl_get_system_time();
    state.message_count += 1;

    let sender_name = state.computer_name;
    let recipient_len = recipient.len().min(MAX_COMPUTER_NAME);
    let text_len = alert_text.len().min(MAX_MESSAGE_LEN);

    let msg = &mut state.messages[slot];
    msg.message_id = message_id;
    msg.msg_type = MessageType::Alert;
    msg.status = MessageStatus::Pending;
    msg.sender = sender_name;
    msg.recipient[..recipient_len].copy_from_slice(&recipient[..recipient_len]);
    msg.text[..text_len].copy_from_slice(&alert_text[..text_len]);
    msg.text_len = text_len;
    msg.timestamp = now;
    msg.incoming = false;
    msg.valid = true;

    msg.status = MessageStatus::Delivered;

    MESSAGES_SENT.fetch_add(1, Ordering::SeqCst);

    Ok(message_id)
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64) {
    (
        MESSAGES_SENT.load(Ordering::SeqCst),
        MESSAGES_RECEIVED.load(Ordering::SeqCst),
        MESSAGES_FAILED.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = MESSENGER_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = MESSENGER_STATE.lock();
    state.running = false;
    state.callback = None;

    crate::serial_println!("[MESSENGER] Messenger service stopped");
}
