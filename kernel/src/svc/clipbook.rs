//! ClipBook Service (ClipSrv)
//!
//! The ClipBook service enables ClipBook Viewer to create and share
//! pages of data that can be viewed by remote computers.
//!
//! # Features
//!
//! - **ClipBook Pages**: Named clipboard data pages
//! - **Sharing**: Share pages over the network
//! - **Remote Viewing**: Allow remote clipboard viewing
//! - **Format Support**: Multiple clipboard formats
//!
//! # Clipboard Formats
//!
//! - CF_TEXT: Text data
//! - CF_BITMAP: Bitmap image
//! - CF_METAFILEPICT: Metafile picture
//! - CF_UNICODETEXT: Unicode text
//! - CF_ENHMETAFILE: Enhanced metafile
//!
//! # Security
//!
//! - Access control per page
//! - Sharing permissions

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum ClipBook pages
const MAX_PAGES: usize = 64;

/// Maximum page name length
const MAX_PAGE_NAME: usize = 32;

/// Maximum page data size
const MAX_PAGE_SIZE: usize = 65536;

/// Clipboard format
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipFormat {
    /// Text (CF_TEXT = 1)
    Text = 1,
    /// Bitmap (CF_BITMAP = 2)
    Bitmap = 2,
    /// Metafile picture (CF_METAFILEPICT = 3)
    MetafilePict = 3,
    /// OEM text (CF_OEMTEXT = 7)
    OemText = 7,
    /// Device-independent bitmap (CF_DIB = 8)
    Dib = 8,
    /// Unicode text (CF_UNICODETEXT = 13)
    UnicodeText = 13,
    /// Enhanced metafile (CF_ENHMETAFILE = 14)
    EnhMetafile = 14,
    /// HTML format
    Html = 0xC001,
    /// Rich text format
    Rtf = 0xC002,
}

impl ClipFormat {
    const fn empty() -> Self {
        ClipFormat::Text
    }
}

/// Page access level
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageAccess {
    /// Private (owner only)
    Private = 0,
    /// Shared read-only
    ReadOnly = 1,
    /// Shared read-write
    ReadWrite = 2,
}

impl PageAccess {
    const fn empty() -> Self {
        PageAccess::Private
    }
}

/// ClipBook page
#[repr(C)]
#[derive(Clone)]
pub struct ClipPage {
    /// Page ID
    pub page_id: u64,
    /// Page name
    pub name: [u8; MAX_PAGE_NAME],
    /// Data format
    pub format: ClipFormat,
    /// Page data
    pub data: [u8; MAX_PAGE_SIZE],
    /// Data length
    pub data_len: usize,
    /// Access level
    pub access: PageAccess,
    /// Owner (user name)
    pub owner: [u8; 32],
    /// Created timestamp
    pub created: i64,
    /// Modified timestamp
    pub modified: i64,
    /// Is shared over network
    pub shared: bool,
    /// Entry is valid
    pub valid: bool,
}

impl ClipPage {
    const fn empty() -> Self {
        ClipPage {
            page_id: 0,
            name: [0; MAX_PAGE_NAME],
            format: ClipFormat::empty(),
            data: [0; MAX_PAGE_SIZE],
            data_len: 0,
            access: PageAccess::empty(),
            owner: [0; 32],
            created: 0,
            modified: 0,
            shared: false,
            valid: false,
        }
    }

    fn clone_metadata(&self) -> ClipPageInfo {
        ClipPageInfo {
            page_id: self.page_id,
            name: self.name,
            format: self.format,
            data_size: self.data_len,
            access: self.access,
            owner: self.owner,
            created: self.created,
            modified: self.modified,
            shared: self.shared,
        }
    }
}

/// Page info (without data)
#[repr(C)]
#[derive(Clone)]
pub struct ClipPageInfo {
    /// Page ID
    pub page_id: u64,
    /// Page name
    pub name: [u8; MAX_PAGE_NAME],
    /// Data format
    pub format: ClipFormat,
    /// Data size
    pub data_size: usize,
    /// Access level
    pub access: PageAccess,
    /// Owner
    pub owner: [u8; 32],
    /// Created timestamp
    pub created: i64,
    /// Modified timestamp
    pub modified: i64,
    /// Is shared
    pub shared: bool,
}

impl ClipPageInfo {
    const fn empty() -> Self {
        ClipPageInfo {
            page_id: 0,
            name: [0; MAX_PAGE_NAME],
            format: ClipFormat::empty(),
            data_size: 0,
            access: PageAccess::empty(),
            owner: [0; 32],
            created: 0,
            modified: 0,
            shared: false,
        }
    }
}

/// ClipBook service state
pub struct ClipBookState {
    /// Service is running
    pub running: bool,
    /// Pages
    pub pages: [ClipPage; MAX_PAGES],
    /// Page count
    pub page_count: usize,
    /// Next page ID
    pub next_page_id: u64,
    /// Local computer name
    pub computer_name: [u8; 16],
    /// Service start time
    pub start_time: i64,
}

impl ClipBookState {
    const fn new() -> Self {
        ClipBookState {
            running: false,
            pages: [const { ClipPage::empty() }; MAX_PAGES],
            page_count: 0,
            next_page_id: 1,
            computer_name: [0; 16],
            start_time: 0,
        }
    }
}

/// Global state
static CLIPBOOK_STATE: Mutex<ClipBookState> = Mutex::new(ClipBookState::new());

/// Statistics
static PAGES_CREATED: AtomicU64 = AtomicU64::new(0);
static PAGES_SHARED: AtomicU64 = AtomicU64::new(0);
static REMOTE_VIEWS: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize ClipBook service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = CLIPBOOK_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    let name = b"NOSTALGOS";
    state.computer_name[..name.len()].copy_from_slice(name);

    crate::serial_println!("[CLIPBOOK] ClipBook service initialized");
}

/// Create a new page
pub fn create_page(
    name: &[u8],
    format: ClipFormat,
    data: &[u8],
    owner: &[u8],
) -> Result<u64, u32> {
    let mut state = CLIPBOOK_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let name_len = name.len().min(MAX_PAGE_NAME);

    // Check for duplicate name
    for page in state.pages.iter() {
        if page.valid && page.name[..name_len] == name[..name_len] {
            return Err(0x80070055); // ERROR_DUP_NAME
        }
    }

    // Check data size
    if data.len() > MAX_PAGE_SIZE {
        return Err(0x800700DE); // ERROR_MORE_DATA
    }

    // Find free slot
    let slot_idx = state.pages.iter().position(|p| !p.valid);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x8007000E),
    };

    let page_id = state.next_page_id;
    state.next_page_id += 1;

    let now = crate::rtl::time::rtl_get_system_time();
    let owner_len = owner.len().min(32);
    let data_len = data.len();

    state.page_count += 1;

    let page = &mut state.pages[slot_idx];
    page.page_id = page_id;
    page.name = [0; MAX_PAGE_NAME];
    page.name[..name_len].copy_from_slice(&name[..name_len]);
    page.format = format;
    page.data = [0; MAX_PAGE_SIZE];
    page.data[..data_len].copy_from_slice(data);
    page.data_len = data_len;
    page.access = PageAccess::Private;
    page.owner = [0; 32];
    page.owner[..owner_len].copy_from_slice(&owner[..owner_len]);
    page.created = now;
    page.modified = now;
    page.shared = false;
    page.valid = true;

    PAGES_CREATED.fetch_add(1, Ordering::SeqCst);

    Ok(page_id)
}

/// Delete a page
pub fn delete_page(page_id: u64) -> Result<(), u32> {
    let mut state = CLIPBOOK_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.pages.iter().position(|p| p.valid && p.page_id == page_id);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.pages[idx].valid = false;
    state.pages[idx].data_len = 0;
    state.page_count = state.page_count.saturating_sub(1);

    Ok(())
}

/// Update page data
pub fn update_page(page_id: u64, data: &[u8]) -> Result<(), u32> {
    let mut state = CLIPBOOK_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    if data.len() > MAX_PAGE_SIZE {
        return Err(0x800700DE);
    }

    let page = state.pages.iter_mut().find(|p| p.valid && p.page_id == page_id);

    let page = match page {
        Some(p) => p,
        None => return Err(0x80070057),
    };

    page.data = [0; MAX_PAGE_SIZE];
    page.data[..data.len()].copy_from_slice(data);
    page.data_len = data.len();
    page.modified = crate::rtl::time::rtl_get_system_time();

    Ok(())
}

/// Get page data
pub fn get_page_data(page_id: u64) -> Option<([u8; MAX_PAGE_SIZE], usize)> {
    let state = CLIPBOOK_STATE.lock();

    state.pages.iter()
        .find(|p| p.valid && p.page_id == page_id)
        .map(|p| (p.data, p.data_len))
}

/// Get page info
pub fn get_page_info(page_id: u64) -> Option<ClipPageInfo> {
    let state = CLIPBOOK_STATE.lock();

    state.pages.iter()
        .find(|p| p.valid && p.page_id == page_id)
        .map(|p| p.clone_metadata())
}

/// Share a page
pub fn share_page(page_id: u64, access: PageAccess) -> Result<(), u32> {
    let mut state = CLIPBOOK_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let page = state.pages.iter_mut().find(|p| p.valid && p.page_id == page_id);

    let page = match page {
        Some(p) => p,
        None => return Err(0x80070057),
    };

    page.shared = true;
    page.access = access;

    PAGES_SHARED.fetch_add(1, Ordering::SeqCst);

    Ok(())
}

/// Unshare a page
pub fn unshare_page(page_id: u64) -> Result<(), u32> {
    let mut state = CLIPBOOK_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let page = state.pages.iter_mut().find(|p| p.valid && p.page_id == page_id);

    let page = match page {
        Some(p) => p,
        None => return Err(0x80070057),
    };

    page.shared = false;
    page.access = PageAccess::Private;

    Ok(())
}

/// Enumerate local pages
pub fn enum_pages() -> ([ClipPageInfo; MAX_PAGES], usize) {
    let state = CLIPBOOK_STATE.lock();
    let mut result = [const { ClipPageInfo::empty() }; MAX_PAGES];
    let mut count = 0;

    for page in state.pages.iter() {
        if page.valid && count < MAX_PAGES {
            result[count] = page.clone_metadata();
            count += 1;
        }
    }

    (result, count)
}

/// Enumerate shared pages
pub fn enum_shared_pages() -> ([ClipPageInfo; MAX_PAGES], usize) {
    let state = CLIPBOOK_STATE.lock();
    let mut result = [const { ClipPageInfo::empty() }; MAX_PAGES];
    let mut count = 0;

    for page in state.pages.iter() {
        if page.valid && page.shared && count < MAX_PAGES {
            result[count] = page.clone_metadata();
            count += 1;
        }
    }

    (result, count)
}

/// Get remote page (from another computer)
pub fn get_remote_page(
    _computer: &[u8],
    _page_name: &[u8],
) -> Result<(ClipPageInfo, [u8; MAX_PAGE_SIZE], usize), u32> {
    // Would connect to remote ClipBook service via RPC
    // For now, return not found
    REMOTE_VIEWS.fetch_add(1, Ordering::SeqCst);
    Err(0x80070057)
}

/// Rename a page
pub fn rename_page(page_id: u64, new_name: &[u8]) -> Result<(), u32> {
    let mut state = CLIPBOOK_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let name_len = new_name.len().min(MAX_PAGE_NAME);

    // Check for duplicate name
    for page in state.pages.iter() {
        if page.valid && page.page_id != page_id && page.name[..name_len] == new_name[..name_len] {
            return Err(0x80070055);
        }
    }

    let page = state.pages.iter_mut().find(|p| p.valid && p.page_id == page_id);

    let page = match page {
        Some(p) => p,
        None => return Err(0x80070057),
    };

    page.name = [0; MAX_PAGE_NAME];
    page.name[..name_len].copy_from_slice(&new_name[..name_len]);
    page.modified = crate::rtl::time::rtl_get_system_time();

    Ok(())
}

/// Set page access level
pub fn set_access(page_id: u64, access: PageAccess) -> Result<(), u32> {
    let mut state = CLIPBOOK_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let page = state.pages.iter_mut().find(|p| p.valid && p.page_id == page_id);

    let page = match page {
        Some(p) => p,
        None => return Err(0x80070057),
    };

    page.access = access;

    Ok(())
}

/// Get page count
pub fn get_page_count() -> usize {
    let state = CLIPBOOK_STATE.lock();
    state.pages.iter().filter(|p| p.valid).count()
}

/// Get shared page count
pub fn get_shared_count() -> usize {
    let state = CLIPBOOK_STATE.lock();
    state.pages.iter().filter(|p| p.valid && p.shared).count()
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64) {
    (
        PAGES_CREATED.load(Ordering::SeqCst),
        PAGES_SHARED.load(Ordering::SeqCst),
        REMOTE_VIEWS.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = CLIPBOOK_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = CLIPBOOK_STATE.lock();
    state.running = false;

    // Clear all pages
    for page in state.pages.iter_mut() {
        page.valid = false;
        page.data_len = 0;
    }
    state.page_count = 0;

    crate::serial_println!("[CLIPBOOK] ClipBook service stopped");
}
