//! Administrative Tools
//!
//! Kernel-mode administrative tools folder following Windows NT patterns.
//! Provides access to system management MMC snap-ins and utilities.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `admin/adminpak/` - Administrative tools

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// Constants
// ============================================================================

/// Maximum administrative tools
const MAX_TOOLS: usize = 64;

/// Maximum tool name length
const MAX_NAME: usize = 128;

/// Maximum command length
const MAX_COMMAND: usize = 260;

/// Maximum description length
const MAX_DESCRIPTION: usize = 256;

/// Tool categories
pub mod tool_category {
    /// Computer management
    pub const COMPUTER_MGMT: u32 = 0;
    /// Active Directory
    pub const ACTIVE_DIRECTORY: u32 = 1;
    /// Services
    pub const SERVICES: u32 = 2;
    /// Security
    pub const SECURITY: u32 = 3;
    /// Storage
    pub const STORAGE: u32 = 4;
    /// Performance
    pub const PERFORMANCE: u32 = 5;
    /// Networking
    pub const NETWORKING: u32 = 6;
    /// Other
    pub const OTHER: u32 = 7;
}

/// Tool flags
pub mod tool_flags {
    /// Requires administrator
    pub const REQUIRE_ADMIN: u32 = 0x0001;
    /// Requires domain controller
    pub const REQUIRE_DC: u32 = 0x0002;
    /// Is MMC snap-in
    pub const IS_MMC: u32 = 0x0004;
    /// Can run remotely
    pub const REMOTE_CAPABLE: u32 = 0x0008;
    /// Server only
    pub const SERVER_ONLY: u32 = 0x0010;
    /// Hidden by default
    pub const HIDDEN: u32 = 0x0020;
}

// ============================================================================
// Types
// ============================================================================

/// Administrative tool information
#[derive(Clone, Copy)]
pub struct AdminTool {
    /// Tool name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: u8,
    /// Description
    pub description: [u8; MAX_DESCRIPTION],
    /// Description length
    pub desc_len: u16,
    /// Command to execute
    pub command: [u8; MAX_COMMAND],
    /// Command length
    pub cmd_len: u16,
    /// Icon index
    pub icon_index: i32,
    /// Category
    pub category: u32,
    /// Flags
    pub flags: u32,
}

impl AdminTool {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_NAME],
            name_len: 0,
            description: [0; MAX_DESCRIPTION],
            desc_len: 0,
            command: [0; MAX_COMMAND],
            cmd_len: 0,
            icon_index: 0,
            category: tool_category::OTHER,
            flags: 0,
        }
    }
}

/// Admin tools dialog state
struct AdminToolsDialog {
    /// Parent window
    parent: HWND,
    /// Selected tool index
    selected: i32,
    /// View mode
    view_mode: u32,
    /// Show hidden tools
    show_hidden: bool,
}

impl AdminToolsDialog {
    const fn new() -> Self {
        Self {
            parent: UserHandle::NULL,
            selected: -1,
            view_mode: 0,
            show_hidden: false,
        }
    }
}

// ============================================================================
// Static State
// ============================================================================

/// Module initialized
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Administrative tools
static TOOLS: SpinLock<[AdminTool; MAX_TOOLS]> =
    SpinLock::new([const { AdminTool::new() }; MAX_TOOLS]);

/// Tool count
static TOOL_COUNT: AtomicU32 = AtomicU32::new(0);

/// Dialog state
static DIALOG: SpinLock<AdminToolsDialog> = SpinLock::new(AdminToolsDialog::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize administrative tools
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Initialize default administrative tools
    init_admin_tools();

    crate::serial_println!("[ADMINTOOLS] Administrative tools initialized");
}

/// Initialize default administrative tools
fn init_admin_tools() {
    let mut tools = TOOLS.lock();
    let mut count = 0;

    let default_tools: &[(&[u8], &[u8], &[u8], u32, u32)] = &[
        // Computer Management
        (b"Computer Management",
         b"Manage local or remote computers",
         b"compmgmt.msc",
         tool_category::COMPUTER_MGMT,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::REMOTE_CAPABLE),

        // Event Viewer
        (b"Event Viewer",
         b"View system, security, and application event logs",
         b"eventvwr.msc",
         tool_category::COMPUTER_MGMT,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::REMOTE_CAPABLE),

        // Services
        (b"Services",
         b"Start, stop, and configure Windows services",
         b"services.msc",
         tool_category::SERVICES,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::REMOTE_CAPABLE),

        // Component Services
        (b"Component Services",
         b"Configure and administer COM+ applications",
         b"dcomcnfg.exe",
         tool_category::SERVICES,
         tool_flags::REQUIRE_ADMIN),

        // Data Sources (ODBC)
        (b"Data Sources (ODBC)",
         b"Configure ODBC data sources and drivers",
         b"odbcad32.exe",
         tool_category::OTHER,
         tool_flags::REQUIRE_ADMIN),

        // Disk Management
        (b"Disk Management",
         b"Manage disks, partitions, and volumes",
         b"diskmgmt.msc",
         tool_category::STORAGE,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC),

        // Device Manager
        (b"Device Manager",
         b"View and configure hardware devices",
         b"devmgmt.msc",
         tool_category::COMPUTER_MGMT,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::REMOTE_CAPABLE),

        // Disk Defragmenter
        (b"Disk Defragmenter",
         b"Defragment volumes for optimal performance",
         b"dfrg.msc",
         tool_category::STORAGE,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC),

        // DNS
        (b"DNS",
         b"Manage DNS servers and zones",
         b"dnsmgmt.msc",
         tool_category::NETWORKING,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::SERVER_ONLY),

        // DHCP
        (b"DHCP",
         b"Manage DHCP servers and scopes",
         b"dhcpmgmt.msc",
         tool_category::NETWORKING,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::SERVER_ONLY),

        // Local Security Policy
        (b"Local Security Policy",
         b"Configure local security settings",
         b"secpol.msc",
         tool_category::SECURITY,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC),

        // Local Users and Groups
        (b"Local Users and Groups",
         b"Manage local users and groups",
         b"lusrmgr.msc",
         tool_category::SECURITY,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC),

        // Performance
        (b"Performance",
         b"Monitor system and application performance",
         b"perfmon.msc",
         tool_category::PERFORMANCE,
         tool_flags::IS_MMC | tool_flags::REMOTE_CAPABLE),

        // Reliability and Performance Monitor
        (b"Reliability and Performance Monitor",
         b"Advanced performance and reliability monitoring",
         b"perfmon.exe",
         tool_category::PERFORMANCE,
         tool_flags::REQUIRE_ADMIN),

        // Routing and Remote Access
        (b"Routing and Remote Access",
         b"Configure routing and VPN services",
         b"rrasmgmt.msc",
         tool_category::NETWORKING,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::SERVER_ONLY),

        // Server Manager
        (b"Server Manager",
         b"Manage server roles and features",
         b"servermanager.msc",
         tool_category::COMPUTER_MGMT,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::SERVER_ONLY),

        // Shared Folders
        (b"Shared Folders",
         b"View and manage shared folders and sessions",
         b"fsmgmt.msc",
         tool_category::STORAGE,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::REMOTE_CAPABLE),

        // Task Scheduler
        (b"Task Scheduler",
         b"Schedule automated tasks",
         b"taskschd.msc",
         tool_category::COMPUTER_MGMT,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC),

        // Terminal Services Configuration
        (b"Terminal Services Configuration",
         b"Configure terminal server settings",
         b"tscc.msc",
         tool_category::SERVICES,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::SERVER_ONLY),

        // Windows Firewall with Advanced Security
        (b"Windows Firewall with Advanced Security",
         b"Configure advanced firewall rules",
         b"wf.msc",
         tool_category::SECURITY,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC),

        // Active Directory Users and Computers
        (b"Active Directory Users and Computers",
         b"Manage AD users, groups, and computers",
         b"dsa.msc",
         tool_category::ACTIVE_DIRECTORY,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::REQUIRE_DC),

        // Active Directory Sites and Services
        (b"Active Directory Sites and Services",
         b"Manage AD replication topology",
         b"dssite.msc",
         tool_category::ACTIVE_DIRECTORY,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::REQUIRE_DC),

        // Active Directory Domains and Trusts
        (b"Active Directory Domains and Trusts",
         b"Manage domain trusts and UPN suffixes",
         b"domain.msc",
         tool_category::ACTIVE_DIRECTORY,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::REQUIRE_DC),

        // Group Policy Management
        (b"Group Policy Management",
         b"Manage Group Policy Objects",
         b"gpmc.msc",
         tool_category::ACTIVE_DIRECTORY,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::REQUIRE_DC),

        // Certificate Authority
        (b"Certificate Authority",
         b"Manage certificate services",
         b"certsrv.msc",
         tool_category::SECURITY,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::SERVER_ONLY),

        // Certificates
        (b"Certificates",
         b"Manage certificates for current user",
         b"certmgr.msc",
         tool_category::SECURITY,
         tool_flags::IS_MMC),

        // Internet Information Services (IIS) Manager
        (b"Internet Information Services (IIS) Manager",
         b"Manage web server configuration",
         b"inetmgr.exe",
         tool_category::SERVICES,
         tool_flags::REQUIRE_ADMIN | tool_flags::SERVER_ONLY),

        // Hyper-V Manager
        (b"Hyper-V Manager",
         b"Manage virtual machines",
         b"virtmgmt.msc",
         tool_category::COMPUTER_MGMT,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::SERVER_ONLY),

        // iSCSI Initiator
        (b"iSCSI Initiator",
         b"Configure iSCSI storage connections",
         b"iscsicpl.exe",
         tool_category::STORAGE,
         tool_flags::REQUIRE_ADMIN),

        // Print Management
        (b"Print Management",
         b"Manage printers and print servers",
         b"printmanagement.msc",
         tool_category::SERVICES,
         tool_flags::REQUIRE_ADMIN | tool_flags::IS_MMC | tool_flags::REMOTE_CAPABLE),
    ];

    for (name, desc, cmd, category, flags) in default_tools.iter() {
        if count >= MAX_TOOLS {
            break;
        }

        let tool = &mut tools[count];

        let nlen = name.len().min(MAX_NAME);
        tool.name[..nlen].copy_from_slice(&name[..nlen]);
        tool.name_len = nlen as u8;

        let dlen = desc.len().min(MAX_DESCRIPTION);
        tool.description[..dlen].copy_from_slice(&desc[..dlen]);
        tool.desc_len = dlen as u16;

        let clen = cmd.len().min(MAX_COMMAND);
        tool.command[..clen].copy_from_slice(&cmd[..clen]);
        tool.cmd_len = clen as u16;

        tool.category = *category;
        tool.flags = *flags;
        tool.icon_index = count as i32;

        count += 1;
    }

    TOOL_COUNT.store(count as u32, Ordering::Release);
}

// ============================================================================
// Tool Management
// ============================================================================

/// Get number of administrative tools
pub fn get_tool_count() -> u32 {
    TOOL_COUNT.load(Ordering::Acquire)
}

/// Get tool by index
pub fn get_tool(index: usize, tool: &mut AdminTool) -> bool {
    let tools = TOOLS.lock();
    let count = TOOL_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    *tool = tools[index];
    true
}

/// Find tool by name
pub fn find_tool(name: &[u8]) -> Option<usize> {
    let tools = TOOLS.lock();
    let count = TOOL_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = tools[i].name_len as usize;
        if &tools[i].name[..len] == name {
            return Some(i);
        }
    }
    None
}

/// Get tools by category
pub fn get_tools_by_category(category: u32, results: &mut [AdminTool]) -> usize {
    let tools = TOOLS.lock();
    let count = TOOL_COUNT.load(Ordering::Acquire) as usize;

    let mut found = 0;
    for i in 0..count {
        if tools[i].category == category {
            if found < results.len() {
                results[found] = tools[i];
            }
            found += 1;
        }
    }
    found
}

/// Check if tool can run (based on current permissions/context)
pub fn can_run_tool(name: &[u8], is_admin: bool, is_dc: bool, is_server: bool) -> bool {
    let tools = TOOLS.lock();
    let count = TOOL_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = tools[i].name_len as usize;
        if &tools[i].name[..len] == name {
            let flags = tools[i].flags;

            if flags & tool_flags::REQUIRE_ADMIN != 0 && !is_admin {
                return false;
            }
            if flags & tool_flags::REQUIRE_DC != 0 && !is_dc {
                return false;
            }
            if flags & tool_flags::SERVER_ONLY != 0 && !is_server {
                return false;
            }

            return true;
        }
    }
    false
}

/// Launch an administrative tool
pub fn launch_tool(name: &[u8]) -> bool {
    let tools = TOOLS.lock();
    let count = TOOL_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = tools[i].name_len as usize;
        if &tools[i].name[..len] == name {
            // Would execute the command
            let _cmd_len = tools[i].cmd_len as usize;
            // let cmd = &tools[i].command[..cmd_len];
            return true;
        }
    }
    false
}

/// Launch tool with remote computer target
pub fn launch_tool_remote(name: &[u8], computer: &[u8]) -> bool {
    let tools = TOOLS.lock();
    let count = TOOL_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = tools[i].name_len as usize;
        if &tools[i].name[..len] == name {
            if tools[i].flags & tool_flags::REMOTE_CAPABLE == 0 {
                return false;
            }
            // Would execute with /computer: parameter
            let _ = computer;
            return true;
        }
    }
    false
}

// ============================================================================
// MMC Operations
// ============================================================================

/// Check if a tool is an MMC snap-in
pub fn is_mmc_snapin(name: &[u8]) -> bool {
    let tools = TOOLS.lock();
    let count = TOOL_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = tools[i].name_len as usize;
        if &tools[i].name[..len] == name {
            return tools[i].flags & tool_flags::IS_MMC != 0;
        }
    }
    false
}

/// Create custom MMC console
pub fn create_mmc_console(_snapins: &[&[u8]], _save_path: &[u8]) -> bool {
    // Would create .msc file with specified snap-ins
    true
}

// ============================================================================
// Dialog API
// ============================================================================

/// Show Administrative Tools folder
pub fn show_admin_tools(parent: HWND) -> bool {
    let mut dialog = DIALOG.lock();

    dialog.parent = parent;
    dialog.selected = -1;
    dialog.view_mode = 0;
    dialog.show_hidden = false;

    // Would show explorer-style folder with:
    // - Tool icons
    // - Context menu with Run as administrator
    // - Description in status bar

    true
}

/// Show Server Manager (for Windows Server)
pub fn show_server_manager(parent: HWND) -> bool {
    let _ = parent;
    // Would launch Server Manager application
    true
}

/// Add shortcut to Administrative Tools
pub fn add_tool_shortcut(name: &[u8], command: &[u8], description: &[u8],
                         category: u32, flags: u32) -> bool {
    let mut tools = TOOLS.lock();
    let count = TOOL_COUNT.load(Ordering::Acquire) as usize;

    if count >= MAX_TOOLS {
        return false;
    }

    let tool = &mut tools[count];

    let nlen = name.len().min(MAX_NAME);
    tool.name[..nlen].copy_from_slice(&name[..nlen]);
    tool.name_len = nlen as u8;

    let dlen = description.len().min(MAX_DESCRIPTION);
    tool.description[..dlen].copy_from_slice(&description[..dlen]);
    tool.desc_len = dlen as u16;

    let clen = command.len().min(MAX_COMMAND);
    tool.command[..clen].copy_from_slice(&command[..clen]);
    tool.cmd_len = clen as u16;

    tool.category = category;
    tool.flags = flags;

    TOOL_COUNT.store((count + 1) as u32, Ordering::Release);

    true
}
