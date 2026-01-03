//! Message Queuing (MSMQ)
//!
//! Windows Server 2003 Message Queuing snap-in implementation.
//! Provides message queue management.
//!
//! # Features
//!
//! - Queue management (public, private, system)
//! - Message handling
//! - Queue properties
//! - Journal queues
//! - Dead letter queues
//! - Triggers
//!
//! # References
//!
//! Based on Windows Server 2003 Message Queuing snap-in

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::UserHandle;

/// HWND type alias
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum queues per computer
const MAX_QUEUES: usize = 8;

/// Maximum messages per queue
const MAX_MESSAGES: usize = 16;

/// Maximum queue name length
const MAX_NAME_LEN: usize = 64;

/// Maximum label length
const MAX_LABEL_LEN: usize = 64;

/// Maximum message body size
const MAX_BODY_SIZE: usize = 256;

// ============================================================================
// Queue Type
// ============================================================================

/// Queue type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QueueType {
    /// Public queue (AD integrated)
    #[default]
    Public = 0,
    /// Private queue (local only)
    Private = 1,
    /// System queue
    System = 2,
    /// Outgoing queue
    Outgoing = 3,
}

impl QueueType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "Public",
            Self::Private => "Private",
            Self::System => "System",
            Self::Outgoing => "Outgoing",
        }
    }
}

// ============================================================================
// Queue Access
// ============================================================================

bitflags::bitflags! {
    /// Queue access permissions
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct QueueAccess: u32 {
        /// Receive messages
        const RECEIVE = 0x0001;
        /// Peek messages
        const PEEK = 0x0002;
        /// Send messages
        const SEND = 0x0004;
        /// Full control
        const FULL_CONTROL = 0x0010;
        /// Delete queue
        const DELETE = 0x0020;
        /// Get queue properties
        const GET_PROPERTIES = 0x0040;
        /// Set queue properties
        const SET_PROPERTIES = 0x0080;
    }
}

// ============================================================================
// Message Priority
// ============================================================================

/// Message priority (0-7, higher = more priority)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MessagePriority {
    Lowest = 0,
    VeryLow = 1,
    Low = 2,
    #[default]
    Normal = 3,
    AboveNormal = 4,
    High = 5,
    VeryHigh = 6,
    Highest = 7,
}

// ============================================================================
// Message Delivery
// ============================================================================

/// Message delivery mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeliveryMode {
    /// Express (in memory, faster)
    #[default]
    Express = 0,
    /// Recoverable (persistent, survives restart)
    Recoverable = 1,
}

impl DeliveryMode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Express => "Express",
            Self::Recoverable => "Recoverable",
        }
    }
}

// ============================================================================
// Message
// ============================================================================

/// Queue message
#[derive(Clone, Copy)]
pub struct QueueMessage {
    /// Message ID
    pub message_id: u64,
    /// Message label
    pub label: [u8; MAX_LABEL_LEN],
    /// Label length
    pub label_len: u8,
    /// Message body (first bytes)
    pub body: [u8; MAX_BODY_SIZE],
    /// Body size
    pub body_size: u16,
    /// Full body size (if larger than buffer)
    pub full_body_size: u32,
    /// Message priority
    pub priority: MessagePriority,
    /// Delivery mode
    pub delivery: DeliveryMode,
    /// Time to reach queue (seconds, 0 = infinite)
    pub time_to_reach: u32,
    /// Time to receive (seconds, 0 = infinite)
    pub time_to_receive: u32,
    /// Arrival time (epoch seconds)
    pub arrival_time: u64,
    /// Sent time (epoch seconds)
    pub sent_time: u64,
    /// Source machine ID
    pub source_machine: u32,
    /// Correlation ID
    pub correlation_id: u64,
    /// Response queue format name
    pub response_queue: [u8; MAX_NAME_LEN],
    /// Response queue length
    pub response_queue_len: u8,
    /// Acknowledgment type
    pub ack_type: u8,
    /// Message is in use
    pub in_use: bool,
    /// Message has been looked at (peeked)
    pub looked_at: bool,
}

impl QueueMessage {
    pub const fn new() -> Self {
        Self {
            message_id: 0,
            label: [0u8; MAX_LABEL_LEN],
            label_len: 0,
            body: [0u8; MAX_BODY_SIZE],
            body_size: 0,
            full_body_size: 0,
            priority: MessagePriority::Normal,
            delivery: DeliveryMode::Express,
            time_to_reach: 0,
            time_to_receive: 0,
            arrival_time: 0,
            sent_time: 0,
            source_machine: 0,
            correlation_id: 0,
            response_queue: [0u8; MAX_NAME_LEN],
            response_queue_len: 0,
            ack_type: 0,
            in_use: false,
            looked_at: false,
        }
    }

    pub fn set_label(&mut self, label: &[u8]) {
        let len = label.len().min(MAX_LABEL_LEN);
        self.label[..len].copy_from_slice(&label[..len]);
        self.label_len = len as u8;
    }

    pub fn get_label(&self) -> &[u8] {
        &self.label[..self.label_len as usize]
    }

    pub fn set_body(&mut self, body: &[u8]) {
        let len = body.len().min(MAX_BODY_SIZE);
        self.body[..len].copy_from_slice(&body[..len]);
        self.body_size = len as u16;
        self.full_body_size = body.len() as u32;
    }

    pub fn get_body(&self) -> &[u8] {
        &self.body[..self.body_size as usize]
    }
}

// ============================================================================
// Queue
// ============================================================================

/// Message queue
pub struct MessageQueue {
    /// Queue format name
    pub format_name: [u8; MAX_NAME_LEN],
    /// Format name length
    pub format_name_len: u8,
    /// Queue path name
    pub path_name: [u8; MAX_NAME_LEN],
    /// Path name length
    pub path_name_len: u8,
    /// Queue label
    pub label: [u8; MAX_LABEL_LEN],
    /// Label length
    pub label_len: u8,
    /// Queue type
    pub queue_type: QueueType,
    /// Queue is transactional
    pub transactional: bool,
    /// Messages in queue
    pub messages: [QueueMessage; MAX_MESSAGES],
    /// Message count
    pub message_count: u32,
    /// Journal queue enabled
    pub journal_enabled: bool,
    /// Journal queue size limit (bytes)
    pub journal_quota: u32,
    /// Queue size limit (bytes)
    pub quota: u32,
    /// Authentication required
    pub authenticate: bool,
    /// Privacy level (0=none, 1=optional, 2=body)
    pub privacy_level: u8,
    /// Next message ID
    pub next_message_id: u64,
    /// Total messages sent
    pub messages_sent: u64,
    /// Total messages received
    pub messages_received: u64,
    /// Queue is in use
    pub in_use: bool,
}

impl MessageQueue {
    pub const fn new() -> Self {
        Self {
            format_name: [0u8; MAX_NAME_LEN],
            format_name_len: 0,
            path_name: [0u8; MAX_NAME_LEN],
            path_name_len: 0,
            label: [0u8; MAX_LABEL_LEN],
            label_len: 0,
            queue_type: QueueType::Private,
            transactional: false,
            messages: [const { QueueMessage::new() }; MAX_MESSAGES],
            message_count: 0,
            journal_enabled: false,
            journal_quota: 1048576, // 1 MB default
            quota: 65536,           // 64 KB default
            authenticate: false,
            privacy_level: 0,
            next_message_id: 1,
            messages_sent: 0,
            messages_received: 0,
            in_use: false,
        }
    }

    pub fn set_format_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.format_name[..len].copy_from_slice(&name[..len]);
        self.format_name_len = len as u8;
    }

    pub fn set_path_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.path_name[..len].copy_from_slice(&name[..len]);
        self.path_name_len = len as u8;
    }

    pub fn set_label(&mut self, label: &[u8]) {
        let len = label.len().min(MAX_LABEL_LEN);
        self.label[..len].copy_from_slice(&label[..len]);
        self.label_len = len as u8;
    }

    /// Send a message to this queue
    pub fn send_message(&mut self, label: &[u8], body: &[u8], priority: MessagePriority, current_time: u64) -> Option<u64> {
        for msg in self.messages.iter_mut() {
            if !msg.in_use {
                msg.message_id = self.next_message_id;
                msg.set_label(label);
                msg.set_body(body);
                msg.priority = priority;
                msg.delivery = DeliveryMode::Express;
                msg.sent_time = current_time;
                msg.arrival_time = current_time;
                msg.in_use = true;
                self.next_message_id += 1;
                self.message_count += 1;
                self.messages_sent += 1;
                return Some(msg.message_id);
            }
        }
        None
    }

    /// Receive (remove) the next message
    pub fn receive_message(&mut self) -> Option<u64> {
        // Find highest priority message
        let mut best_idx: Option<usize> = None;
        let mut best_priority = 0u8;

        for (i, msg) in self.messages.iter().enumerate() {
            if msg.in_use {
                let pri = msg.priority as u8;
                if best_idx.is_none() || pri > best_priority {
                    best_idx = Some(i);
                    best_priority = pri;
                }
            }
        }

        if let Some(idx) = best_idx {
            let msg_id = self.messages[idx].message_id;
            self.messages[idx].in_use = false;
            self.message_count = self.message_count.saturating_sub(1);
            self.messages_received += 1;
            return Some(msg_id);
        }
        None
    }

    /// Peek at the next message (don't remove)
    pub fn peek_message(&mut self) -> Option<u64> {
        let mut best_idx: Option<usize> = None;
        let mut best_priority = 0u8;

        for (i, msg) in self.messages.iter().enumerate() {
            if msg.in_use {
                let pri = msg.priority as u8;
                if best_idx.is_none() || pri > best_priority {
                    best_idx = Some(i);
                    best_priority = pri;
                }
            }
        }

        if let Some(idx) = best_idx {
            self.messages[idx].looked_at = true;
            return Some(self.messages[idx].message_id);
        }
        None
    }

    /// Purge all messages
    pub fn purge(&mut self) {
        for msg in self.messages.iter_mut() {
            msg.in_use = false;
        }
        self.message_count = 0;
    }
}

// ============================================================================
// Manager State
// ============================================================================

/// MSMQ Manager state
struct MsmqManagerState {
    /// Message queues
    queues: [MessageQueue; MAX_QUEUES],
    /// Queue count
    queue_count: u32,
    /// Selected queue
    selected_queue: Option<usize>,
    /// Dialog handle
    dialog_handle: HWND,
    /// View mode (0=queues, 1=messages)
    view_mode: u8,
    /// Machine ID
    machine_id: u32,
}

impl MsmqManagerState {
    pub const fn new() -> Self {
        Self {
            queues: [const { MessageQueue::new() }; MAX_QUEUES],
            queue_count: 0,
            selected_queue: None,
            dialog_handle: UserHandle::from_raw(0),
            view_mode: 0,
            machine_id: 1,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static MSMQ_INITIALIZED: AtomicBool = AtomicBool::new(false);
static MSMQ_MANAGER: SpinLock<MsmqManagerState> = SpinLock::new(MsmqManagerState::new());

// Statistics
static QUEUE_COUNT: AtomicU32 = AtomicU32::new(0);
static MESSAGES_SENT: AtomicU64 = AtomicU64::new(0);
static MESSAGES_RECEIVED: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize MSMQ Manager
pub fn init() {
    if MSMQ_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = MSMQ_MANAGER.lock();

    // Create system queues
    create_system_queues(&mut state);

    crate::serial_println!("[WIN32K] MSMQ Manager initialized");
}

/// Create default system queues
fn create_system_queues(state: &mut MsmqManagerState) {
    // Dead letter queue
    let q = &mut state.queues[0];
    q.set_format_name(b"DIRECT=OS:.\\SYSTEM$;DEADLETTER");
    q.set_path_name(b".\\SYSTEM$;DEADLETTER");
    q.set_label(b"Dead Letter Queue");
    q.queue_type = QueueType::System;
    q.in_use = true;

    // Dead Xact queue
    let q = &mut state.queues[1];
    q.set_format_name(b"DIRECT=OS:.\\SYSTEM$;DEADXACT");
    q.set_path_name(b".\\SYSTEM$;DEADXACT");
    q.set_label(b"Transactional Dead Letter Queue");
    q.queue_type = QueueType::System;
    q.transactional = true;
    q.in_use = true;

    // Journal queue
    let q = &mut state.queues[2];
    q.set_format_name(b"DIRECT=OS:.\\SYSTEM$;JOURNAL");
    q.set_path_name(b".\\SYSTEM$;JOURNAL");
    q.set_label(b"Journal Messages");
    q.queue_type = QueueType::System;
    q.in_use = true;

    state.queue_count = 3;
    QUEUE_COUNT.store(3, Ordering::Relaxed);
}

// ============================================================================
// Queue Management
// ============================================================================

/// Create a new queue
pub fn create_queue(
    path_name: &[u8],
    label: &[u8],
    queue_type: QueueType,
    transactional: bool,
) -> Option<usize> {
    let mut state = MSMQ_MANAGER.lock();

    for (i, queue) in state.queues.iter_mut().enumerate() {
        if !queue.in_use {
            queue.set_path_name(path_name);
            queue.set_label(label);
            queue.queue_type = queue_type;
            queue.transactional = transactional;
            queue.in_use = true;

            // Generate format name
            let mut format = [0u8; MAX_NAME_LEN];
            let prefix = b"DIRECT=OS:";
            let prefix_len = prefix.len();
            format[..prefix_len].copy_from_slice(prefix);
            let path_len = path_name.len().min(MAX_NAME_LEN - prefix_len);
            format[prefix_len..prefix_len + path_len].copy_from_slice(&path_name[..path_len]);
            queue.format_name[..prefix_len + path_len].copy_from_slice(&format[..prefix_len + path_len]);
            queue.format_name_len = (prefix_len + path_len) as u8;

            state.queue_count += 1;
            QUEUE_COUNT.fetch_add(1, Ordering::Relaxed);
            return Some(i);
        }
    }
    None
}

/// Delete a queue
pub fn delete_queue(index: usize) -> bool {
    let mut state = MSMQ_MANAGER.lock();

    if index < MAX_QUEUES && state.queues[index].in_use {
        // Don't delete system queues
        if state.queues[index].queue_type == QueueType::System {
            return false;
        }
        state.queues[index].in_use = false;
        state.queue_count = state.queue_count.saturating_sub(1);
        QUEUE_COUNT.fetch_sub(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// Purge a queue
pub fn purge_queue(index: usize) -> bool {
    let mut state = MSMQ_MANAGER.lock();

    if index < MAX_QUEUES && state.queues[index].in_use {
        state.queues[index].purge();
        true
    } else {
        false
    }
}

/// Get queue info
pub fn get_queue_info(index: usize) -> Option<(QueueType, bool, u32, u64, u64)> {
    let state = MSMQ_MANAGER.lock();

    if index < MAX_QUEUES && state.queues[index].in_use {
        let q = &state.queues[index];
        Some((
            q.queue_type,
            q.transactional,
            q.message_count,
            q.messages_sent,
            q.messages_received,
        ))
    } else {
        None
    }
}

// ============================================================================
// Message Operations
// ============================================================================

/// Send a message to a queue
pub fn send_message(
    queue_index: usize,
    label: &[u8],
    body: &[u8],
    priority: MessagePriority,
    current_time: u64,
) -> Option<u64> {
    let mut state = MSMQ_MANAGER.lock();

    if queue_index < MAX_QUEUES && state.queues[queue_index].in_use {
        let result = state.queues[queue_index].send_message(label, body, priority, current_time);
        if result.is_some() {
            MESSAGES_SENT.fetch_add(1, Ordering::Relaxed);
        }
        result
    } else {
        None
    }
}

/// Receive a message from a queue
pub fn receive_message(queue_index: usize) -> Option<u64> {
    let mut state = MSMQ_MANAGER.lock();

    if queue_index < MAX_QUEUES && state.queues[queue_index].in_use {
        let result = state.queues[queue_index].receive_message();
        if result.is_some() {
            MESSAGES_RECEIVED.fetch_add(1, Ordering::Relaxed);
        }
        result
    } else {
        None
    }
}

/// Peek at a message (don't remove)
pub fn peek_message(queue_index: usize) -> Option<u64> {
    let mut state = MSMQ_MANAGER.lock();

    if queue_index < MAX_QUEUES && state.queues[queue_index].in_use {
        state.queues[queue_index].peek_message()
    } else {
        None
    }
}

// ============================================================================
// Queue Properties
// ============================================================================

/// Set queue quota
pub fn set_queue_quota(index: usize, quota: u32) -> bool {
    let mut state = MSMQ_MANAGER.lock();

    if index < MAX_QUEUES && state.queues[index].in_use {
        state.queues[index].quota = quota;
        true
    } else {
        false
    }
}

/// Enable/disable journal
pub fn set_journal_enabled(index: usize, enabled: bool) -> bool {
    let mut state = MSMQ_MANAGER.lock();

    if index < MAX_QUEUES && state.queues[index].in_use {
        state.queues[index].journal_enabled = enabled;
        true
    } else {
        false
    }
}

/// Set journal quota
pub fn set_journal_quota(index: usize, quota: u32) -> bool {
    let mut state = MSMQ_MANAGER.lock();

    if index < MAX_QUEUES && state.queues[index].in_use {
        state.queues[index].journal_quota = quota;
        true
    } else {
        false
    }
}

/// Set authentication required
pub fn set_authenticate(index: usize, required: bool) -> bool {
    let mut state = MSMQ_MANAGER.lock();

    if index < MAX_QUEUES && state.queues[index].in_use {
        state.queues[index].authenticate = required;
        true
    } else {
        false
    }
}

/// Set privacy level
pub fn set_privacy_level(index: usize, level: u8) -> bool {
    let mut state = MSMQ_MANAGER.lock();

    if index < MAX_QUEUES && state.queues[index].in_use {
        state.queues[index].privacy_level = level;
        true
    } else {
        false
    }
}

// ============================================================================
// Dialog Management
// ============================================================================

/// Show MSMQ Manager dialog
pub fn show_dialog(parent: HWND) -> HWND {
    let mut state = MSMQ_MANAGER.lock();

    let handle = UserHandle::from_raw(0xE701);
    state.dialog_handle = handle;
    state.selected_queue = None;
    state.view_mode = 0;

    let _ = parent;
    handle
}

/// Close MSMQ Manager dialog
pub fn close_dialog() {
    let mut state = MSMQ_MANAGER.lock();
    state.dialog_handle = UserHandle::from_raw(0);
}

/// Select a queue
pub fn select_queue(index: usize) {
    let mut state = MSMQ_MANAGER.lock();
    if index < MAX_QUEUES && state.queues[index].in_use {
        state.selected_queue = Some(index);
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// MSMQ statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct MsmqStats {
    pub initialized: bool,
    pub queue_count: u32,
    pub messages_sent: u64,
    pub messages_received: u64,
}

/// Get MSMQ statistics
pub fn get_stats() -> MsmqStats {
    MsmqStats {
        initialized: MSMQ_INITIALIZED.load(Ordering::Relaxed),
        queue_count: QUEUE_COUNT.load(Ordering::Relaxed),
        messages_sent: MESSAGES_SENT.load(Ordering::Relaxed),
        messages_received: MESSAGES_RECEIVED.load(Ordering::Relaxed),
    }
}
