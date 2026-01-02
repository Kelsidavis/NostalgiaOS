//! Smart Card Service (SCardSvr)
//!
//! The Smart Card service manages smart card readers and access to
//! smart cards for authentication, digital signatures, and encryption.
//!
//! # Features
//!
//! - **Reader Management**: Detect and manage smart card readers
//! - **Card Access**: Provide access to inserted smart cards
//! - **Resource Manager**: Manage smart card resources
//! - **Card Tracking**: Monitor card insertion and removal
//!
//! # Smart Card Types
//!
//! - Contact cards (ISO 7816)
//! - Contactless cards (ISO 14443)
//! - USB tokens
//!
//! # API
//!
//! - PC/SC compatible interface
//! - Windows Smart Card API

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum readers
const MAX_READERS: usize = 8;

/// Maximum cards
const MAX_CARDS: usize = 16;

/// Maximum name length
const MAX_NAME: usize = 64;

/// Maximum ATR length
const MAX_ATR: usize = 33;

/// Reader state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderState {
    /// Reader unknown
    Unknown = 0,
    /// Reader empty
    Empty = 1,
    /// Card present
    Present = 2,
    /// Card mute (unresponsive)
    Mute = 3,
    /// Card in use
    InUse = 4,
}

impl ReaderState {
    const fn empty() -> Self {
        ReaderState::Unknown
    }
}

/// Card protocol
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardProtocol {
    /// Undefined
    Undefined = 0,
    /// T=0 (character-oriented)
    T0 = 1,
    /// T=1 (block-oriented)
    T1 = 2,
    /// Raw protocol
    Raw = 3,
}

impl CardProtocol {
    const fn empty() -> Self {
        CardProtocol::Undefined
    }
}

/// Card share mode
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareMode {
    /// Exclusive access
    Exclusive = 0,
    /// Shared access
    Shared = 1,
    /// Direct access (no protocol)
    Direct = 2,
}

impl ShareMode {
    const fn empty() -> Self {
        ShareMode::Shared
    }
}

/// Disposition action on disconnect
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Leave card as is
    Leave = 0,
    /// Reset card
    Reset = 1,
    /// Power down card
    Unpower = 2,
    /// Eject card
    Eject = 3,
}

/// Smart card reader
#[repr(C)]
#[derive(Clone)]
pub struct Reader {
    /// Reader ID
    pub reader_id: u32,
    /// Reader name
    pub name: [u8; MAX_NAME],
    /// Device path
    pub device: [u8; MAX_NAME],
    /// Reader state
    pub state: ReaderState,
    /// Current event count
    pub event_count: u32,
    /// ATR of inserted card (if any)
    pub atr: [u8; MAX_ATR],
    /// ATR length
    pub atr_len: usize,
    /// Is connected
    pub connected: bool,
    /// Entry is valid
    pub valid: bool,
}

impl Reader {
    const fn empty() -> Self {
        Reader {
            reader_id: 0,
            name: [0; MAX_NAME],
            device: [0; MAX_NAME],
            state: ReaderState::empty(),
            event_count: 0,
            atr: [0; MAX_ATR],
            atr_len: 0,
            connected: false,
            valid: false,
        }
    }
}

/// Smart card context (connection)
#[repr(C)]
#[derive(Clone)]
pub struct CardContext {
    /// Context handle
    pub handle: u64,
    /// Reader ID
    pub reader_id: u32,
    /// Share mode
    pub share_mode: ShareMode,
    /// Active protocol
    pub protocol: CardProtocol,
    /// Created time
    pub created: i64,
    /// Transaction active
    pub in_transaction: bool,
    /// Entry is valid
    pub valid: bool,
}

impl CardContext {
    const fn empty() -> Self {
        CardContext {
            handle: 0,
            reader_id: 0,
            share_mode: ShareMode::empty(),
            protocol: CardProtocol::empty(),
            created: 0,
            in_transaction: false,
            valid: false,
        }
    }
}

/// Smart Card service state
pub struct SCardState {
    /// Service is running
    pub running: bool,
    /// Readers
    pub readers: [Reader; MAX_READERS],
    /// Reader count
    pub reader_count: usize,
    /// Next reader ID
    pub next_reader_id: u32,
    /// Card contexts
    pub contexts: [CardContext; MAX_CARDS],
    /// Context count
    pub context_count: usize,
    /// Next context handle
    pub next_handle: u64,
    /// Resource manager enabled
    pub rm_enabled: bool,
    /// Service start time
    pub start_time: i64,
}

impl SCardState {
    const fn new() -> Self {
        SCardState {
            running: false,
            readers: [const { Reader::empty() }; MAX_READERS],
            reader_count: 0,
            next_reader_id: 1,
            contexts: [const { CardContext::empty() }; MAX_CARDS],
            context_count: 0,
            next_handle: 0x1000,
            rm_enabled: true,
            start_time: 0,
        }
    }
}

/// Global state
static SCARD_STATE: Mutex<SCardState> = Mutex::new(SCardState::new());

/// Statistics
static CARDS_INSERTED: AtomicU64 = AtomicU64::new(0);
static CARDS_REMOVED: AtomicU64 = AtomicU64::new(0);
static TRANSACTIONS: AtomicU64 = AtomicU64::new(0);
static APDU_COMMANDS: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize Smart Card service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = SCARD_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    crate::serial_println!("[SCARDSVR] Smart Card service initialized");
}

/// Register a reader
pub fn register_reader(name: &[u8], device: &[u8]) -> Result<u32, u32> {
    let mut state = SCARD_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.readers.iter().position(|r| !r.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let reader_id = state.next_reader_id;
    state.next_reader_id += 1;
    state.reader_count += 1;

    let name_len = name.len().min(MAX_NAME);
    let device_len = device.len().min(MAX_NAME);

    let reader = &mut state.readers[slot];
    reader.reader_id = reader_id;
    reader.name = [0; MAX_NAME];
    reader.name[..name_len].copy_from_slice(&name[..name_len]);
    reader.device = [0; MAX_NAME];
    reader.device[..device_len].copy_from_slice(&device[..device_len]);
    reader.state = ReaderState::Empty;
    reader.connected = true;
    reader.valid = true;

    Ok(reader_id)
}

/// Unregister a reader
pub fn unregister_reader(reader_id: u32) -> Result<(), u32> {
    let mut state = SCARD_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Check for active connections
    for ctx in state.contexts.iter() {
        if ctx.valid && ctx.reader_id == reader_id {
            return Err(0x80070005);
        }
    }

    let idx = state.readers.iter()
        .position(|r| r.valid && r.reader_id == reader_id);

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.readers[idx].valid = false;
    state.reader_count = state.reader_count.saturating_sub(1);

    Ok(())
}

/// Report card insertion
pub fn card_inserted(reader_id: u32, atr: &[u8]) -> Result<(), u32> {
    let mut state = SCARD_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let reader = state.readers.iter_mut()
        .find(|r| r.valid && r.reader_id == reader_id);

    let reader = match reader {
        Some(r) => r,
        None => return Err(0x80070057),
    };

    let atr_len = atr.len().min(MAX_ATR);
    reader.atr = [0; MAX_ATR];
    reader.atr[..atr_len].copy_from_slice(&atr[..atr_len]);
    reader.atr_len = atr_len;
    reader.state = ReaderState::Present;
    reader.event_count += 1;

    CARDS_INSERTED.fetch_add(1, Ordering::SeqCst);

    Ok(())
}

/// Report card removal
pub fn card_removed(reader_id: u32) -> Result<(), u32> {
    let mut state = SCARD_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let reader = state.readers.iter_mut()
        .find(|r| r.valid && r.reader_id == reader_id);

    let reader = match reader {
        Some(r) => r,
        None => return Err(0x80070057),
    };

    reader.atr = [0; MAX_ATR];
    reader.atr_len = 0;
    reader.state = ReaderState::Empty;
    reader.event_count += 1;

    // Disconnect any active contexts on this reader
    let reader_id_copy = reader.reader_id;
    drop(reader);

    let mut disconnected = 0usize;
    for ctx in state.contexts.iter_mut() {
        if ctx.valid && ctx.reader_id == reader_id_copy {
            ctx.valid = false;
            disconnected += 1;
        }
    }
    state.context_count = state.context_count.saturating_sub(disconnected);

    CARDS_REMOVED.fetch_add(1, Ordering::SeqCst);

    Ok(())
}

/// Connect to a card
pub fn connect(
    reader_id: u32,
    share_mode: ShareMode,
    preferred_protocol: CardProtocol,
) -> Result<u64, u32> {
    let mut state = SCARD_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Find reader and check for card
    let reader_idx = state.readers.iter()
        .position(|r| r.valid && r.reader_id == reader_id);

    let reader_idx = match reader_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let reader_state = state.readers[reader_idx].state;
    if reader_state != ReaderState::Present && reader_state != ReaderState::InUse {
        return Err(0x80100009); // SCARD_E_NO_SMARTCARD
    }

    // Check exclusive access
    if share_mode == ShareMode::Exclusive {
        for ctx in state.contexts.iter() {
            if ctx.valid && ctx.reader_id == reader_id {
                return Err(0x8010000C); // SCARD_E_SHARING_VIOLATION
            }
        }
    }

    let ctx_slot = state.contexts.iter().position(|c| !c.valid);
    let ctx_slot = match ctx_slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let handle = state.next_handle;
    state.next_handle += 1;
    state.context_count += 1;

    let now = crate::rtl::time::rtl_get_system_time();

    state.readers[reader_idx].state = ReaderState::InUse;

    let ctx = &mut state.contexts[ctx_slot];
    ctx.handle = handle;
    ctx.reader_id = reader_id;
    ctx.share_mode = share_mode;
    ctx.protocol = preferred_protocol;
    ctx.created = now;
    ctx.in_transaction = false;
    ctx.valid = true;

    Ok(handle)
}

/// Reconnect to a card
pub fn reconnect(
    handle: u64,
    share_mode: ShareMode,
    preferred_protocol: CardProtocol,
    init_disposition: Disposition,
) -> Result<(), u32> {
    let mut state = SCARD_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let ctx = state.contexts.iter_mut()
        .find(|c| c.valid && c.handle == handle);

    let ctx = match ctx {
        Some(c) => c,
        None => return Err(0x80070057),
    };

    ctx.share_mode = share_mode;
    ctx.protocol = preferred_protocol;
    ctx.in_transaction = false;

    // Apply disposition (simulated)
    let _ = init_disposition;

    Ok(())
}

/// Disconnect from a card
pub fn disconnect(handle: u64, disposition: Disposition) -> Result<(), u32> {
    let mut state = SCARD_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let ctx_idx = state.contexts.iter()
        .position(|c| c.valid && c.handle == handle);

    let ctx_idx = match ctx_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let reader_id = state.contexts[ctx_idx].reader_id;
    state.contexts[ctx_idx].valid = false;
    state.context_count = state.context_count.saturating_sub(1);

    // Check if reader still has other contexts
    let has_other = state.contexts.iter()
        .any(|c| c.valid && c.reader_id == reader_id);

    if !has_other {
        for reader in state.readers.iter_mut() {
            if reader.valid && reader.reader_id == reader_id {
                if reader.atr_len > 0 {
                    reader.state = ReaderState::Present;
                } else {
                    reader.state = ReaderState::Empty;
                }
                break;
            }
        }
    }

    let _ = disposition;

    Ok(())
}

/// Begin a transaction
pub fn begin_transaction(handle: u64) -> Result<(), u32> {
    let mut state = SCARD_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let ctx = state.contexts.iter_mut()
        .find(|c| c.valid && c.handle == handle);

    let ctx = match ctx {
        Some(c) => c,
        None => return Err(0x80070057),
    };

    if ctx.in_transaction {
        return Err(0x80100021); // SCARD_E_NOT_TRANSACTED
    }

    ctx.in_transaction = true;
    TRANSACTIONS.fetch_add(1, Ordering::SeqCst);

    Ok(())
}

/// End a transaction
pub fn end_transaction(handle: u64, disposition: Disposition) -> Result<(), u32> {
    let mut state = SCARD_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let ctx = state.contexts.iter_mut()
        .find(|c| c.valid && c.handle == handle);

    let ctx = match ctx {
        Some(c) => c,
        None => return Err(0x80070057),
    };

    if !ctx.in_transaction {
        return Err(0x80100021);
    }

    ctx.in_transaction = false;
    let _ = disposition;

    Ok(())
}

/// Transmit APDU command
pub fn transmit(
    handle: u64,
    _send_buffer: &[u8],
    _recv_buffer: &mut [u8],
) -> Result<usize, u32> {
    let state = SCARD_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let ctx = state.contexts.iter()
        .find(|c| c.valid && c.handle == handle);

    if ctx.is_none() {
        return Err(0x80070057);
    }

    APDU_COMMANDS.fetch_add(1, Ordering::SeqCst);

    // Would transmit APDU to card and receive response
    // For now, return empty response
    Ok(0)
}

/// Get reader status
pub fn get_status(handle: u64) -> Result<(ReaderState, CardProtocol, [u8; MAX_ATR], usize), u32> {
    let state = SCARD_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let ctx = state.contexts.iter()
        .find(|c| c.valid && c.handle == handle);

    let ctx = match ctx {
        Some(c) => c,
        None => return Err(0x80070057),
    };

    let reader = state.readers.iter()
        .find(|r| r.valid && r.reader_id == ctx.reader_id);

    let reader = match reader {
        Some(r) => r,
        None => return Err(0x80070057),
    };

    Ok((reader.state, ctx.protocol, reader.atr, reader.atr_len))
}

/// List readers
pub fn list_readers() -> ([Reader; MAX_READERS], usize) {
    let state = SCARD_STATE.lock();
    let mut result = [const { Reader::empty() }; MAX_READERS];
    let mut count = 0;

    for reader in state.readers.iter() {
        if reader.valid && count < MAX_READERS {
            result[count] = reader.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get reader by name
pub fn get_reader_by_name(name: &[u8]) -> Option<Reader> {
    let state = SCARD_STATE.lock();
    let name_len = name.len().min(MAX_NAME);

    state.readers.iter()
        .find(|r| r.valid && r.name[..name_len] == name[..name_len])
        .cloned()
}

/// Check if card is present in reader
pub fn is_card_present(reader_id: u32) -> bool {
    let state = SCARD_STATE.lock();

    state.readers.iter()
        .find(|r| r.valid && r.reader_id == reader_id)
        .map(|r| r.state == ReaderState::Present || r.state == ReaderState::InUse)
        .unwrap_or(false)
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64, u64) {
    (
        CARDS_INSERTED.load(Ordering::SeqCst),
        CARDS_REMOVED.load(Ordering::SeqCst),
        TRANSACTIONS.load(Ordering::SeqCst),
        APDU_COMMANDS.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = SCARD_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = SCARD_STATE.lock();
    state.running = false;

    // Disconnect all contexts
    for ctx in state.contexts.iter_mut() {
        if ctx.valid {
            ctx.valid = false;
        }
    }
    state.context_count = 0;

    crate::serial_println!("[SCARDSVR] Smart Card service stopped");
}
