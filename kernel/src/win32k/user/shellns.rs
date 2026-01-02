//! Shell Namespace Extensions
//!
//! Windows Shell namespace support for virtual folders, shell extensions,
//! and namespace navigation. Implements the shell folder architecture.
//!
//! # Shell Namespace
//!
//! The shell namespace is a hierarchical view of objects (files, folders,
//! virtual objects) organized under the Desktop. Each object has a PIDL
//! (Pointer to Item ID List) that uniquely identifies it.
//!
//! # Key Objects
//!
//! - **Desktop**: Root of the namespace
//! - **My Computer**: File system roots and drives
//! - **My Documents**: User document folder
//! - **Network Neighborhood**: Network resources
//! - **Recycle Bin**: Deleted files
//! - **Control Panel**: System settings
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/shell32/shitemid.h` - Item ID definitions
//! - `shell/shell32/pidl.c` - PIDL manipulation
//! - `shell/shell32/shellfld.cpp` - Shell folder implementation

extern crate alloc;

use crate::ke::spinlock::SpinLock;
use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::format;

// ============================================================================
// Constants
// ============================================================================

/// Maximum PIDL size
const MAX_PIDL_SIZE: usize = 2048;

/// Maximum namespace items
const MAX_NAMESPACE_ITEMS: usize = 4096;

// ============================================================================
// CSIDLs (Shell Special Folder IDs)
// ============================================================================

/// Desktop folder
pub const CSIDL_DESKTOP: u32 = 0x0000;
/// Internet Explorer (virtual folder)
pub const CSIDL_INTERNET: u32 = 0x0001;
/// Programs folder
pub const CSIDL_PROGRAMS: u32 = 0x0002;
/// Control Panel
pub const CSIDL_CONTROLS: u32 = 0x0003;
/// Printers folder
pub const CSIDL_PRINTERS: u32 = 0x0004;
/// Personal (My Documents)
pub const CSIDL_PERSONAL: u32 = 0x0005;
/// Favorites folder
pub const CSIDL_FAVORITES: u32 = 0x0006;
/// Startup folder
pub const CSIDL_STARTUP: u32 = 0x0007;
/// Recent documents
pub const CSIDL_RECENT: u32 = 0x0008;
/// Send To folder
pub const CSIDL_SENDTO: u32 = 0x0009;
/// Recycle Bin
pub const CSIDL_BITBUCKET: u32 = 0x000A;
/// Start Menu
pub const CSIDL_STARTMENU: u32 = 0x000B;
/// My Documents (same as PERSONAL)
pub const CSIDL_MYDOCUMENTS: u32 = 0x000C;
/// My Music
pub const CSIDL_MYMUSIC: u32 = 0x000D;
/// My Video
pub const CSIDL_MYVIDEO: u32 = 0x000E;
/// Desktop directory
pub const CSIDL_DESKTOPDIRECTORY: u32 = 0x0010;
/// My Computer
pub const CSIDL_DRIVES: u32 = 0x0011;
/// Network Neighborhood
pub const CSIDL_NETWORK: u32 = 0x0012;
/// Network Neighborhood directory
pub const CSIDL_NETHOOD: u32 = 0x0013;
/// Fonts folder
pub const CSIDL_FONTS: u32 = 0x0014;
/// Templates folder
pub const CSIDL_TEMPLATES: u32 = 0x0015;
/// Common Start Menu
pub const CSIDL_COMMON_STARTMENU: u32 = 0x0016;
/// Common Programs
pub const CSIDL_COMMON_PROGRAMS: u32 = 0x0017;
/// Common Startup
pub const CSIDL_COMMON_STARTUP: u32 = 0x0018;
/// Common Desktop
pub const CSIDL_COMMON_DESKTOPDIRECTORY: u32 = 0x0019;
/// Application Data
pub const CSIDL_APPDATA: u32 = 0x001A;
/// Print Neighborhood directory
pub const CSIDL_PRINTHOOD: u32 = 0x001B;
/// Local Application Data
pub const CSIDL_LOCAL_APPDATA: u32 = 0x001C;
/// Alt Startup
pub const CSIDL_ALTSTARTUP: u32 = 0x001D;
/// Common Alt Startup
pub const CSIDL_COMMON_ALTSTARTUP: u32 = 0x001E;
/// Common Favorites
pub const CSIDL_COMMON_FAVORITES: u32 = 0x001F;
/// Internet Cache
pub const CSIDL_INTERNET_CACHE: u32 = 0x0020;
/// Cookies
pub const CSIDL_COOKIES: u32 = 0x0021;
/// History
pub const CSIDL_HISTORY: u32 = 0x0022;
/// Common Application Data
pub const CSIDL_COMMON_APPDATA: u32 = 0x0023;
/// Windows directory
pub const CSIDL_WINDOWS: u32 = 0x0024;
/// System directory
pub const CSIDL_SYSTEM: u32 = 0x0025;
/// Program Files
pub const CSIDL_PROGRAM_FILES: u32 = 0x0026;
/// My Pictures
pub const CSIDL_MYPICTURES: u32 = 0x0027;
/// User Profile
pub const CSIDL_PROFILE: u32 = 0x0028;
/// System32 (x86 on 64-bit)
pub const CSIDL_SYSTEMX86: u32 = 0x0029;
/// Program Files (x86)
pub const CSIDL_PROGRAM_FILESX86: u32 = 0x002A;
/// Common Files
pub const CSIDL_PROGRAM_FILES_COMMON: u32 = 0x002B;
/// Common Files (x86)
pub const CSIDL_PROGRAM_FILES_COMMONX86: u32 = 0x002C;
/// Common Templates
pub const CSIDL_COMMON_TEMPLATES: u32 = 0x002D;
/// Common Documents
pub const CSIDL_COMMON_DOCUMENTS: u32 = 0x002E;
/// Common Administrative Tools
pub const CSIDL_COMMON_ADMINTOOLS: u32 = 0x002F;
/// Administrative Tools
pub const CSIDL_ADMINTOOLS: u32 = 0x0030;
/// Connections folder
pub const CSIDL_CONNECTIONS: u32 = 0x0031;
/// Common Music
pub const CSIDL_COMMON_MUSIC: u32 = 0x0035;
/// Common Pictures
pub const CSIDL_COMMON_PICTURES: u32 = 0x0036;
/// Common Video
pub const CSIDL_COMMON_VIDEO: u32 = 0x0037;
/// Resources folder
pub const CSIDL_RESOURCES: u32 = 0x0038;
/// Localized Resources
pub const CSIDL_RESOURCES_LOCALIZED: u32 = 0x0039;
/// Common OEM Links
pub const CSIDL_COMMON_OEM_LINKS: u32 = 0x003A;
/// CD Burning folder
pub const CSIDL_CDBURN_AREA: u32 = 0x003B;
/// Computersnearme folder
pub const CSIDL_COMPUTERSNEARME: u32 = 0x003D;

/// Create folder if doesn't exist
pub const CSIDL_FLAG_CREATE: u32 = 0x8000;
/// Don't verify folder exists
pub const CSIDL_FLAG_DONT_VERIFY: u32 = 0x4000;
/// Return default path (don't use real folder)
pub const CSIDL_FLAG_NO_ALIAS: u32 = 0x1000;
/// Per-user path
pub const CSIDL_FLAG_PER_USER_INIT: u32 = 0x0800;
/// Mask for CSIDL value
pub const CSIDL_FLAG_MASK: u32 = 0xFF00;

// ============================================================================
// PIDL (Pointer to Item ID List)
// ============================================================================

/// Item identifier (single component of a PIDL)
#[derive(Debug, Clone)]
pub struct ShItemId {
    /// Size of this structure (including size field)
    pub cb: u16,
    /// Item data
    pub data: Vec<u8>,
}

impl ShItemId {
    /// Create empty (terminating) item ID
    pub fn empty() -> Self {
        Self {
            cb: 0,
            data: Vec::new(),
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            cb: (data.len() + 2) as u16,
            data: data.to_vec(),
        }
    }

    /// Check if this is a terminating item ID
    pub fn is_empty(&self) -> bool {
        self.cb == 0
    }

    /// Get total size including cb field
    pub fn size(&self) -> usize {
        if self.cb == 0 {
            2 // Terminating null has 2 bytes
        } else {
            self.cb as usize
        }
    }
}

/// Item ID List (path in shell namespace)
#[derive(Debug, Clone, Default)]
pub struct ItemIdList {
    /// List of item IDs
    pub items: Vec<ShItemId>,
}

impl ItemIdList {
    /// Create empty PIDL (represents Desktop)
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Create from a single item
    pub fn from_item(item: ShItemId) -> Self {
        Self { items: vec![item] }
    }

    /// Append an item to this PIDL
    pub fn append(&mut self, item: ShItemId) {
        self.items.push(item);
    }

    /// Get the last item (simple PIDL)
    pub fn last_item(&self) -> Option<&ShItemId> {
        self.items.last()
    }

    /// Get parent PIDL (without last item)
    pub fn parent(&self) -> Self {
        let mut parent = self.clone();
        parent.items.pop();
        parent
    }

    /// Check if this is an empty (Desktop) PIDL
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Get total size in bytes
    pub fn size(&self) -> usize {
        let mut size = 2; // Terminating null
        for item in &self.items {
            size += item.size();
        }
        size
    }

    /// Concatenate two PIDLs
    pub fn concat(&self, other: &ItemIdList) -> Self {
        let mut result = self.clone();
        for item in &other.items {
            result.items.push(item.clone());
        }
        result
    }
}

// ============================================================================
// Shell Folder Attributes
// ============================================================================

bitflags::bitflags! {
    /// Shell folder/item attributes
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct SfgaoFlags: u32 {
        /// Item can be copied
        const CANCOPY = 0x00000001;
        /// Item can be moved
        const CANMOVE = 0x00000002;
        /// Item can be linked
        const CANLINK = 0x00000004;
        /// Item supports storage
        const STORAGE = 0x00000008;
        /// Item can be renamed
        const CANRENAME = 0x00000010;
        /// Item can be deleted
        const CANDELETE = 0x00000020;
        /// Item has property sheet
        const HASPROPSHEET = 0x00000040;
        /// Item is a drop target
        const DROPTARGET = 0x00000100;
        /// Caption should use system font
        const CAPABILITYMASK = 0x00000177;
        /// Item is encrypted
        const ENCRYPTED = 0x00002000;
        /// Item is slow to access
        const ISSLOW = 0x00004000;
        /// Item is ghosted (hidden or system)
        const GHOSTED = 0x00008000;
        /// Item is a shortcut
        const LINK = 0x00010000;
        /// Item is shared
        const SHARE = 0x00020000;
        /// Item is read-only
        const READONLY = 0x00040000;
        /// Item is hidden
        const HIDDEN = 0x00080000;
        /// Display attributes mask
        const DISPLAYATTRMASK = 0x000FC000;
        /// Item is a file system object
        const FILESYSANCESTOR = 0x10000000;
        /// Item is a folder
        const FOLDER = 0x20000000;
        /// Item is part of file system
        const FILESYSTEM = 0x40000000;
        /// Item has subfolders
        const HASSUBFOLDER = 0x80000000;
        /// Content attributes mask
        const CONTENTSMASK = 0x80000000;
        /// Item should be validated
        const VALIDATE = 0x01000000;
        /// Item is removable
        const REMOVABLE = 0x02000000;
        /// Item is compressed
        const COMPRESSED = 0x04000000;
        /// Item is browsable
        const BROWSABLE = 0x08000000;
        /// Item doesn't enumerate
        const NONENUMERATED = 0x00100000;
        /// Item contains new content
        const NEWCONTENT = 0x00200000;
        /// Item can be monitored
        const CANMONIKER = 0x00400000;
        /// Item has associations
        const HASSTORAGE = 0x00400000;
        /// Item is a stream
        const STREAM = 0x00400000;
        /// Storage capability mask
        const STORAGECAPMASK = 0x70C50008;
    }
}

// ============================================================================
// Shell Folder Types
// ============================================================================

/// Known folder type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderType {
    /// Desktop (root)
    Desktop,
    /// My Computer
    MyComputer,
    /// File system folder
    FileSystem,
    /// Virtual folder
    Virtual,
    /// Control Panel
    ControlPanel,
    /// Network Neighborhood
    Network,
    /// Printers folder
    Printers,
    /// Recycle Bin
    RecycleBin,
    /// User folder
    UserFolder,
}

// ============================================================================
// Namespace Item
// ============================================================================

/// Item in the shell namespace
#[derive(Debug, Clone)]
pub struct NamespaceItem {
    /// Unique ID
    pub id: u32,
    /// Item name
    pub name: String,
    /// Display name
    pub display_name: String,
    /// Parent ID (0 for desktop)
    pub parent_id: u32,
    /// Item type
    pub folder_type: FolderType,
    /// Attributes
    pub attributes: SfgaoFlags,
    /// File system path (if applicable)
    pub path: Option<String>,
    /// CSIDL (if known folder)
    pub csidl: Option<u32>,
    /// Icon index
    pub icon_index: i32,
}

impl NamespaceItem {
    /// Create a new namespace item
    pub fn new(name: &str, folder_type: FolderType) -> Self {
        Self {
            id: 0,
            name: String::from(name),
            display_name: String::from(name),
            parent_id: 0,
            folder_type,
            attributes: SfgaoFlags::empty(),
            path: None,
            csidl: None,
            icon_index: 0,
        }
    }

    /// Set as folder
    pub fn as_folder(mut self) -> Self {
        self.attributes |= SfgaoFlags::FOLDER | SfgaoFlags::HASSUBFOLDER;
        self
    }

    /// Set attributes
    pub fn with_attributes(mut self, attrs: SfgaoFlags) -> Self {
        self.attributes = attrs;
        self
    }

    /// Set path
    pub fn with_path(mut self, path: &str) -> Self {
        self.path = Some(String::from(path));
        self.attributes |= SfgaoFlags::FILESYSTEM;
        self
    }

    /// Set CSIDL
    pub fn with_csidl(mut self, csidl: u32) -> Self {
        self.csidl = Some(csidl);
        self
    }
}

// ============================================================================
// Namespace Manager
// ============================================================================

static NAMESPACE: SpinLock<NamespaceManager> = SpinLock::new(NamespaceManager::new());

struct NamespaceManager {
    items: Vec<NamespaceItem>,
    next_id: u32,
    initialized: bool,
}

impl NamespaceManager {
    const fn new() -> Self {
        Self {
            items: Vec::new(),
            next_id: 1,
            initialized: false,
        }
    }

    fn init(&mut self) {
        if self.initialized {
            return;
        }

        // Create Desktop (root)
        let desktop = NamespaceItem::new("Desktop", FolderType::Desktop)
            .as_folder()
            .with_csidl(CSIDL_DESKTOP)
            .with_attributes(SfgaoFlags::FOLDER | SfgaoFlags::HASSUBFOLDER);
        let desktop_id = self.add_item(desktop);

        // My Computer
        let my_computer = NamespaceItem {
            id: 0,
            name: String::from("My Computer"),
            display_name: String::from("My Computer"),
            parent_id: desktop_id,
            folder_type: FolderType::MyComputer,
            attributes: SfgaoFlags::FOLDER | SfgaoFlags::HASSUBFOLDER | SfgaoFlags::CANRENAME,
            path: None,
            csidl: Some(CSIDL_DRIVES),
            icon_index: 15, // Standard My Computer icon
        };
        let my_computer_id = self.add_item(my_computer);

        // Add drives to My Computer
        for drive in ['C', 'D'] {
            let drive_item = NamespaceItem {
                id: 0,
                name: format!("{}: Drive", drive),
                display_name: format!("Local Disk ({}:)", drive),
                parent_id: my_computer_id,
                folder_type: FolderType::FileSystem,
                attributes: SfgaoFlags::FOLDER | SfgaoFlags::HASSUBFOLDER | SfgaoFlags::FILESYSTEM,
                path: Some(format!("{}:\\", drive)),
                csidl: None,
                icon_index: 8, // Drive icon
            };
            self.add_item(drive_item);
        }

        // My Documents
        let my_docs = NamespaceItem {
            id: 0,
            name: String::from("My Documents"),
            display_name: String::from("My Documents"),
            parent_id: desktop_id,
            folder_type: FolderType::UserFolder,
            attributes: SfgaoFlags::FOLDER | SfgaoFlags::HASSUBFOLDER | SfgaoFlags::FILESYSTEM | SfgaoFlags::CANRENAME,
            path: Some(String::from("C:\\Documents and Settings\\User\\My Documents")),
            csidl: Some(CSIDL_PERSONAL),
            icon_index: 1,
        };
        self.add_item(my_docs);

        // Network Neighborhood
        let network = NamespaceItem::new("My Network Places", FolderType::Network)
            .as_folder()
            .with_csidl(CSIDL_NETWORK);
        self.add_item(NamespaceItem {
            parent_id: desktop_id,
            ..network
        });

        // Recycle Bin
        let recycle = NamespaceItem {
            id: 0,
            name: String::from("Recycle Bin"),
            display_name: String::from("Recycle Bin"),
            parent_id: desktop_id,
            folder_type: FolderType::RecycleBin,
            attributes: SfgaoFlags::FOLDER | SfgaoFlags::HASSUBFOLDER | SfgaoFlags::DROPTARGET,
            path: None,
            csidl: Some(CSIDL_BITBUCKET),
            icon_index: 31, // Recycle bin icon
        };
        self.add_item(recycle);

        // Control Panel
        let control_panel = NamespaceItem {
            id: 0,
            name: String::from("Control Panel"),
            display_name: String::from("Control Panel"),
            parent_id: my_computer_id,
            folder_type: FolderType::ControlPanel,
            attributes: SfgaoFlags::FOLDER | SfgaoFlags::HASSUBFOLDER,
            path: None,
            csidl: Some(CSIDL_CONTROLS),
            icon_index: 21, // Control panel icon
        };
        self.add_item(control_panel);

        self.initialized = true;
    }

    fn add_item(&mut self, mut item: NamespaceItem) -> u32 {
        item.id = self.next_id;
        self.next_id += 1;
        let id = item.id;
        self.items.push(item);
        id
    }

    fn get_item(&self, id: u32) -> Option<&NamespaceItem> {
        self.items.iter().find(|i| i.id == id)
    }

    fn get_children(&self, parent_id: u32) -> Vec<&NamespaceItem> {
        self.items.iter().filter(|i| i.parent_id == parent_id).collect()
    }

    fn find_by_csidl(&self, csidl: u32) -> Option<&NamespaceItem> {
        self.items.iter().find(|i| i.csidl == Some(csidl))
    }

    fn find_by_path(&self, path: &str) -> Option<&NamespaceItem> {
        self.items.iter().find(|i| {
            if let Some(ref p) = i.path {
                p.eq_ignore_ascii_case(path)
            } else {
                false
            }
        })
    }
}

// ============================================================================
// Shell Namespace API
// ============================================================================

/// Initialize shell namespace
pub fn init() {
    let mut ns = NAMESPACE.lock();
    ns.init();
    crate::serial_println!("[SHELL] Namespace initialized with {} items", ns.items.len());
}

/// Get the desktop folder ID
pub fn get_desktop_folder() -> u32 {
    let ns = NAMESPACE.lock();
    ns.find_by_csidl(CSIDL_DESKTOP).map(|i| i.id).unwrap_or(0)
}

/// Get special folder by CSIDL
pub fn get_special_folder(csidl: u32) -> Option<u32> {
    let ns = NAMESPACE.lock();
    ns.find_by_csidl(csidl & !CSIDL_FLAG_MASK).map(|i| i.id)
}

/// Get folder path by CSIDL
pub fn get_folder_path(csidl: u32) -> Option<String> {
    let ns = NAMESPACE.lock();
    ns.find_by_csidl(csidl & !CSIDL_FLAG_MASK)
        .and_then(|i| i.path.clone())
}

/// Get namespace item by ID
pub fn get_item(id: u32) -> Option<NamespaceItem> {
    let ns = NAMESPACE.lock();
    ns.get_item(id).cloned()
}

/// Get children of a folder
pub fn get_children(parent_id: u32) -> Vec<NamespaceItem> {
    let ns = NAMESPACE.lock();
    ns.get_children(parent_id).into_iter().cloned().collect()
}

/// Find item by file system path
pub fn find_by_path(path: &str) -> Option<u32> {
    let ns = NAMESPACE.lock();
    ns.find_by_path(path).map(|i| i.id)
}

/// Get item display name
pub fn get_display_name(id: u32) -> Option<String> {
    let ns = NAMESPACE.lock();
    ns.get_item(id).map(|i| i.display_name.clone())
}

/// Get item attributes
pub fn get_attributes(id: u32) -> SfgaoFlags {
    let ns = NAMESPACE.lock();
    ns.get_item(id).map(|i| i.attributes).unwrap_or_default()
}

/// Check if item is a folder
pub fn is_folder(id: u32) -> bool {
    get_attributes(id).contains(SfgaoFlags::FOLDER)
}

/// Get parent folder
pub fn get_parent(id: u32) -> Option<u32> {
    let ns = NAMESPACE.lock();
    ns.get_item(id).map(|i| i.parent_id)
}

/// Create PIDL from namespace item
pub fn create_pidl(id: u32) -> ItemIdList {
    let mut pidl = ItemIdList::new();
    let ns = NAMESPACE.lock();

    // Build path from item to root
    let mut current_id = id;
    let mut path: Vec<u32> = Vec::new();

    while current_id != 0 {
        path.push(current_id);
        if let Some(item) = ns.get_item(current_id) {
            current_id = item.parent_id;
        } else {
            break;
        }
    }

    // Reverse to get root-to-item order
    path.reverse();

    // Create item IDs
    for item_id in path {
        let id_bytes = item_id.to_le_bytes();
        pidl.append(ShItemId::from_bytes(&id_bytes));
    }

    pidl
}

/// Get item ID from PIDL
pub fn get_id_from_pidl(pidl: &ItemIdList) -> Option<u32> {
    if let Some(last) = pidl.last_item() {
        if last.data.len() >= 4 {
            let bytes: [u8; 4] = [last.data[0], last.data[1], last.data[2], last.data[3]];
            return Some(u32::from_le_bytes(bytes));
        }
    }
    None
}

/// Navigate to a path and return item ID
pub fn navigate_to_path(path: &str) -> Option<u32> {
    // Check if it's a known path
    if let Some(id) = find_by_path(path) {
        return Some(id);
    }

    // TODO: Create items for file system paths not yet in namespace
    None
}

/// Get icon index for an item
pub fn get_icon_index(id: u32) -> i32 {
    let ns = NAMESPACE.lock();
    ns.get_item(id).map(|i| i.icon_index).unwrap_or(0)
}
