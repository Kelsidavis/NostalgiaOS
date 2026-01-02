//! Computer Management Console
//!
//! Implements the Computer Management MMC snap-in following Windows Server 2003.
//! Provides centralized access to system management tools.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - compmgmt.msc - Computer Management console
//! - MMC snap-in architecture
//! - System Tools, Storage, Services and Applications

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum snap-ins
const MAX_SNAPINS: usize = 32;

/// Maximum name length
const MAX_NAME: usize = 64;

/// Maximum description length
const MAX_DESC: usize = 128;

/// Maximum tree nodes
const MAX_NODES: usize = 128;

// ============================================================================
// Snap-in Category
// ============================================================================

/// Snap-in category
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SnapinCategory {
    /// System Tools
    #[default]
    SystemTools = 0,
    /// Storage
    Storage = 1,
    /// Services and Applications
    ServicesApps = 2,
}

impl SnapinCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            SnapinCategory::SystemTools => "System Tools",
            SnapinCategory::Storage => "Storage",
            SnapinCategory::ServicesApps => "Services and Applications",
        }
    }
}

// ============================================================================
// Snap-in Type
// ============================================================================

/// Built-in snap-in types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SnapinType {
    /// Event Viewer
    #[default]
    EventViewer = 0,
    /// Shared Folders
    SharedFolders = 1,
    /// Local Users and Groups
    LocalUsersGroups = 2,
    /// Performance Logs and Alerts
    PerformanceLogs = 3,
    /// Device Manager
    DeviceManager = 4,
    /// Disk Management
    DiskManagement = 5,
    /// Disk Defragmenter
    DiskDefrag = 6,
    /// Removable Storage
    RemovableStorage = 7,
    /// Services
    Services = 8,
    /// WMI Control
    WmiControl = 9,
    /// Indexing Service
    IndexingService = 10,
    /// Internet Information Services
    Iis = 11,
    /// Custom snap-in
    Custom = 255,
}

impl SnapinType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SnapinType::EventViewer => "Event Viewer",
            SnapinType::SharedFolders => "Shared Folders",
            SnapinType::LocalUsersGroups => "Local Users and Groups",
            SnapinType::PerformanceLogs => "Performance Logs and Alerts",
            SnapinType::DeviceManager => "Device Manager",
            SnapinType::DiskManagement => "Disk Management",
            SnapinType::DiskDefrag => "Disk Defragmenter",
            SnapinType::RemovableStorage => "Removable Storage",
            SnapinType::Services => "Services",
            SnapinType::WmiControl => "WMI Control",
            SnapinType::IndexingService => "Indexing Service",
            SnapinType::Iis => "Internet Information Services",
            SnapinType::Custom => "Custom",
        }
    }

    pub fn get_category(&self) -> SnapinCategory {
        match self {
            SnapinType::EventViewer |
            SnapinType::SharedFolders |
            SnapinType::LocalUsersGroups |
            SnapinType::PerformanceLogs |
            SnapinType::DeviceManager => SnapinCategory::SystemTools,
            SnapinType::DiskManagement |
            SnapinType::DiskDefrag |
            SnapinType::RemovableStorage => SnapinCategory::Storage,
            SnapinType::Services |
            SnapinType::WmiControl |
            SnapinType::IndexingService |
            SnapinType::Iis |
            SnapinType::Custom => SnapinCategory::ServicesApps,
        }
    }
}

// ============================================================================
// Tree Node Type
// ============================================================================

/// Tree node type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NodeType {
    /// Root node (Computer Management)
    #[default]
    Root = 0,
    /// Category node
    Category = 1,
    /// Snap-in node
    Snapin = 2,
    /// Folder node
    Folder = 3,
    /// Item node (leaf)
    Item = 4,
}

// ============================================================================
// Snap-in Entry
// ============================================================================

/// Snap-in registration entry
#[derive(Debug, Clone, Copy)]
pub struct SnapinEntry {
    /// Snap-in type
    pub snapin_type: SnapinType,
    /// Display name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC],
    /// Description length
    pub desc_len: usize,
    /// Category
    pub category: SnapinCategory,
    /// Is enabled
    pub enabled: bool,
    /// Icon index
    pub icon_index: u32,
}

impl SnapinEntry {
    pub const fn new() -> Self {
        Self {
            snapin_type: SnapinType::EventViewer,
            name: [0u8; MAX_NAME],
            name_len: 0,
            description: [0u8; MAX_DESC],
            desc_len: 0,
            category: SnapinCategory::SystemTools,
            enabled: true,
            icon_index: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_description(&mut self, desc: &[u8]) {
        let len = desc.len().min(MAX_DESC);
        self.description[..len].copy_from_slice(&desc[..len]);
        self.desc_len = len;
    }
}

impl Default for SnapinEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tree Node
// ============================================================================

/// Console tree node
#[derive(Debug, Clone, Copy)]
pub struct TreeNode {
    /// Node ID
    pub node_id: u32,
    /// Parent node ID (0 for root)
    pub parent_id: u32,
    /// Node type
    pub node_type: NodeType,
    /// Associated snap-in index (if applicable)
    pub snapin_index: Option<usize>,
    /// Display name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Is expanded
    pub expanded: bool,
    /// Is selected
    pub selected: bool,
    /// Icon index
    pub icon_index: u32,
}

impl TreeNode {
    pub const fn new() -> Self {
        Self {
            node_id: 0,
            parent_id: 0,
            node_type: NodeType::Root,
            snapin_index: None,
            name: [0u8; MAX_NAME],
            name_len: 0,
            expanded: false,
            selected: false,
            icon_index: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

impl Default for TreeNode {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Console View
// ============================================================================

/// Console view mode
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ViewMode {
    /// Large icons
    #[default]
    LargeIcons = 0,
    /// Small icons
    SmallIcons = 1,
    /// List view
    List = 2,
    /// Details view
    Details = 3,
}

/// Console pane
#[derive(Debug, Clone, Copy)]
pub struct ConsolePane {
    /// Current view mode
    pub view_mode: ViewMode,
    /// Show description bar
    pub show_description: bool,
    /// Column widths (for details view)
    pub column_widths: [u32; 4],
}

impl ConsolePane {
    pub const fn new() -> Self {
        Self {
            view_mode: ViewMode::Details,
            show_description: true,
            column_widths: [200, 100, 150, 100],
        }
    }
}

impl Default for ConsolePane {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Computer Management State
// ============================================================================

/// Computer Management state
struct CompMgmtState {
    /// Registered snap-ins
    snapins: [SnapinEntry; MAX_SNAPINS],
    /// Snap-in count
    snapin_count: usize,
    /// Console tree nodes
    nodes: [TreeNode; MAX_NODES],
    /// Node count
    node_count: usize,
    /// Next node ID
    next_node_id: u32,
    /// Selected node ID
    selected_node: u32,
    /// Console pane settings
    pane: ConsolePane,
    /// Target computer name
    target_computer: [u8; MAX_NAME],
    /// Target computer name length
    target_len: usize,
    /// Is connected to remote computer
    is_remote: bool,
}

impl CompMgmtState {
    pub const fn new() -> Self {
        Self {
            snapins: [const { SnapinEntry::new() }; MAX_SNAPINS],
            snapin_count: 0,
            nodes: [const { TreeNode::new() }; MAX_NODES],
            node_count: 0,
            next_node_id: 1,
            selected_node: 0,
            pane: ConsolePane::new(),
            target_computer: [0u8; MAX_NAME],
            target_len: 0,
            is_remote: false,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static COMPMGMT_INITIALIZED: AtomicBool = AtomicBool::new(false);
static COMPMGMT_STATE: SpinLock<CompMgmtState> = SpinLock::new(CompMgmtState::new());

// Statistics
static CONSOLE_OPENS: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Computer Management
pub fn init() {
    if COMPMGMT_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = COMPMGMT_STATE.lock();

    // Register built-in snap-ins
    register_builtin_snapins(&mut state);

    // Build console tree
    build_console_tree(&mut state);

    // Set local computer as target
    let local = b"(Local)";
    let len = local.len().min(MAX_NAME);
    state.target_computer[..len].copy_from_slice(&local[..len]);
    state.target_len = len;

    crate::serial_println!("[WIN32K] Computer Management initialized");
}

/// Register built-in snap-ins
fn register_builtin_snapins(state: &mut CompMgmtState) {
    let snapins: [(SnapinType, &[u8], &[u8]); 12] = [
        (SnapinType::EventViewer, b"Event Viewer", b"View application, security, and system event logs"),
        (SnapinType::SharedFolders, b"Shared Folders", b"Manage shared folders, sessions, and open files"),
        (SnapinType::LocalUsersGroups, b"Local Users and Groups", b"Manage local user accounts and groups"),
        (SnapinType::PerformanceLogs, b"Performance Logs and Alerts", b"Configure performance data logs and alerts"),
        (SnapinType::DeviceManager, b"Device Manager", b"View and manage hardware devices"),
        (SnapinType::DiskManagement, b"Disk Management", b"Manage disk partitions and volumes"),
        (SnapinType::DiskDefrag, b"Disk Defragmenter", b"Analyze and defragment disk volumes"),
        (SnapinType::RemovableStorage, b"Removable Storage", b"Manage removable storage devices"),
        (SnapinType::Services, b"Services", b"Start, stop, and configure system services"),
        (SnapinType::WmiControl, b"WMI Control", b"Configure Windows Management Instrumentation"),
        (SnapinType::IndexingService, b"Indexing Service", b"Manage content indexing"),
        (SnapinType::Iis, b"Internet Information Services", b"Manage web server configuration"),
    ];

    for (snapin_type, name, desc) in snapins.iter() {
        if state.snapin_count >= MAX_SNAPINS {
            break;
        }
        let mut entry = SnapinEntry::new();
        entry.snapin_type = *snapin_type;
        entry.set_name(name);
        entry.set_description(desc);
        entry.category = snapin_type.get_category();
        entry.icon_index = *snapin_type as u32;

        let idx = state.snapin_count;
        state.snapins[idx] = entry;
        state.snapin_count += 1;
    }
}

/// Build console tree structure
fn build_console_tree(state: &mut CompMgmtState) {
    // Root node: Computer Management (Local)
    let root_id = state.next_node_id;
    state.next_node_id += 1;
    let mut root = TreeNode::new();
    root.node_id = root_id;
    root.node_type = NodeType::Root;
    root.set_name(b"Computer Management (Local)");
    root.expanded = true;
    state.nodes[state.node_count] = root;
    state.node_count += 1;
    state.selected_node = root_id;

    // Category nodes
    let categories = [
        (SnapinCategory::SystemTools, b"System Tools" as &[u8]),
        (SnapinCategory::Storage, b"Storage"),
        (SnapinCategory::ServicesApps, b"Services and Applications"),
    ];

    for (cat, name) in categories.iter() {
        if state.node_count >= MAX_NODES {
            break;
        }

        let cat_id = state.next_node_id;
        state.next_node_id += 1;

        let mut cat_node = TreeNode::new();
        cat_node.node_id = cat_id;
        cat_node.parent_id = root_id;
        cat_node.node_type = NodeType::Category;
        cat_node.set_name(name);
        cat_node.expanded = true;
        cat_node.icon_index = *cat as u32 + 100;

        let node_idx = state.node_count;
        state.nodes[node_idx] = cat_node;
        state.node_count += 1;

        // Add snap-ins under this category
        for i in 0..state.snapin_count {
            if state.node_count >= MAX_NODES {
                break;
            }
            if state.snapins[i].category != *cat {
                continue;
            }

            let snapin_id = state.next_node_id;
            state.next_node_id += 1;

            let mut snapin_node = TreeNode::new();
            snapin_node.node_id = snapin_id;
            snapin_node.parent_id = cat_id;
            snapin_node.node_type = NodeType::Snapin;
            snapin_node.snapin_index = Some(i);
            let name_len = state.snapins[i].name_len;
            snapin_node.name[..name_len].copy_from_slice(&state.snapins[i].name[..name_len]);
            snapin_node.name_len = name_len;
            snapin_node.icon_index = state.snapins[i].icon_index;

            let sidx = state.node_count;
            state.nodes[sidx] = snapin_node;
            state.node_count += 1;
        }
    }
}

// ============================================================================
// Snap-in Management
// ============================================================================

/// Get snap-in count
pub fn get_snapin_count() -> usize {
    COMPMGMT_STATE.lock().snapin_count
}

/// Get snap-in by index
pub fn get_snapin(index: usize) -> Option<SnapinEntry> {
    let state = COMPMGMT_STATE.lock();
    if index < state.snapin_count {
        Some(state.snapins[index])
    } else {
        None
    }
}

/// Get snap-in by type
pub fn get_snapin_by_type(snapin_type: SnapinType) -> Option<SnapinEntry> {
    let state = COMPMGMT_STATE.lock();
    for i in 0..state.snapin_count {
        if state.snapins[i].snapin_type == snapin_type {
            return Some(state.snapins[i]);
        }
    }
    None
}

/// Enable/disable snap-in
pub fn set_snapin_enabled(snapin_type: SnapinType, enabled: bool) -> bool {
    let mut state = COMPMGMT_STATE.lock();
    for i in 0..state.snapin_count {
        if state.snapins[i].snapin_type == snapin_type {
            state.snapins[i].enabled = enabled;
            return true;
        }
    }
    false
}

// ============================================================================
// Tree Navigation
// ============================================================================

/// Get node count
pub fn get_node_count() -> usize {
    COMPMGMT_STATE.lock().node_count
}

/// Get node by ID
pub fn get_node(node_id: u32) -> Option<TreeNode> {
    let state = COMPMGMT_STATE.lock();
    for i in 0..state.node_count {
        if state.nodes[i].node_id == node_id {
            return Some(state.nodes[i]);
        }
    }
    None
}

/// Get node by index
pub fn get_node_by_index(index: usize) -> Option<TreeNode> {
    let state = COMPMGMT_STATE.lock();
    if index < state.node_count {
        Some(state.nodes[index])
    } else {
        None
    }
}

/// Get child nodes of a parent
pub fn get_child_nodes(parent_id: u32, buffer: &mut [TreeNode]) -> usize {
    let state = COMPMGMT_STATE.lock();
    let mut count = 0;
    for i in 0..state.node_count {
        if state.nodes[i].parent_id == parent_id {
            if count < buffer.len() {
                buffer[count] = state.nodes[i];
                count += 1;
            }
        }
    }
    count
}

/// Select a node
pub fn select_node(node_id: u32) -> bool {
    let mut state = COMPMGMT_STATE.lock();

    // Find and select the node
    let mut found = false;
    for i in 0..state.node_count {
        if state.nodes[i].node_id == node_id {
            state.nodes[i].selected = true;
            found = true;
        } else {
            state.nodes[i].selected = false;
        }
    }

    if found {
        state.selected_node = node_id;
    }
    found
}

/// Get selected node
pub fn get_selected_node() -> Option<TreeNode> {
    let state = COMPMGMT_STATE.lock();
    let selected = state.selected_node;
    for i in 0..state.node_count {
        if state.nodes[i].node_id == selected {
            return Some(state.nodes[i]);
        }
    }
    None
}

/// Expand/collapse a node
pub fn set_node_expanded(node_id: u32, expanded: bool) -> bool {
    let mut state = COMPMGMT_STATE.lock();
    for i in 0..state.node_count {
        if state.nodes[i].node_id == node_id {
            state.nodes[i].expanded = expanded;
            return true;
        }
    }
    false
}

// ============================================================================
// Console Operations
// ============================================================================

/// Connect to a computer
pub fn connect_to_computer(computer_name: &[u8]) -> bool {
    let mut state = COMPMGMT_STATE.lock();

    let len = computer_name.len().min(MAX_NAME);
    state.target_computer[..len].copy_from_slice(&computer_name[..len]);
    state.target_len = len;
    state.is_remote = true;

    // Update root node name
    if state.node_count > 0 {
        let name = b"Computer Management (";
        let suffix = b")";
        let mut full_name = [0u8; MAX_NAME];
        let mut pos = 0;

        if pos + name.len() < MAX_NAME {
            full_name[pos..pos + name.len()].copy_from_slice(name);
            pos += name.len();
        }
        if pos + len < MAX_NAME {
            full_name[pos..pos + len].copy_from_slice(&computer_name[..len]);
            pos += len;
        }
        if pos + suffix.len() < MAX_NAME {
            full_name[pos..pos + suffix.len()].copy_from_slice(suffix);
            pos += suffix.len();
        }

        state.nodes[0].name[..pos].copy_from_slice(&full_name[..pos]);
        state.nodes[0].name_len = pos;
    }

    CONSOLE_OPENS.fetch_add(1, Ordering::Relaxed);
    true
}

/// Get target computer
pub fn get_target_computer(buffer: &mut [u8]) -> usize {
    let state = COMPMGMT_STATE.lock();
    let len = state.target_len.min(buffer.len());
    buffer[..len].copy_from_slice(&state.target_computer[..len]);
    len
}

/// Is connected to remote computer
pub fn is_remote() -> bool {
    COMPMGMT_STATE.lock().is_remote
}

/// Set view mode
pub fn set_view_mode(mode: ViewMode) {
    COMPMGMT_STATE.lock().pane.view_mode = mode;
}

/// Get view mode
pub fn get_view_mode() -> ViewMode {
    COMPMGMT_STATE.lock().pane.view_mode
}

/// Set column width (for details view)
pub fn set_column_width(column: usize, width: u32) {
    let mut state = COMPMGMT_STATE.lock();
    if column < 4 {
        state.pane.column_widths[column] = width;
    }
}

// ============================================================================
// Action Commands
// ============================================================================

/// Action command for snap-in
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionCommand {
    /// Open/activate
    Open = 0,
    /// Refresh
    Refresh = 1,
    /// Export list
    ExportList = 2,
    /// Properties
    Properties = 3,
    /// Help
    Help = 4,
}

/// Execute action on selected node
pub fn execute_action(command: ActionCommand) -> bool {
    let state = COMPMGMT_STATE.lock();
    let selected = state.selected_node;

    // Find the selected node and its snap-in
    for i in 0..state.node_count {
        if state.nodes[i].node_id == selected {
            if let Some(snapin_idx) = state.nodes[i].snapin_index {
                if snapin_idx < state.snapin_count && state.snapins[snapin_idx].enabled {
                    // Would dispatch to the appropriate snap-in handler
                    return true;
                }
            }
            // Non-snap-in nodes support limited actions
            return matches!(command, ActionCommand::Refresh | ActionCommand::Help);
        }
    }
    false
}

// ============================================================================
// Statistics
// ============================================================================

/// Computer Management statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct CompMgmtStats {
    pub initialized: bool,
    pub snapin_count: usize,
    pub node_count: usize,
    pub selected_node: u32,
    pub is_remote: bool,
    pub console_opens: u32,
}

/// Get Computer Management statistics
pub fn get_stats() -> CompMgmtStats {
    let state = COMPMGMT_STATE.lock();
    CompMgmtStats {
        initialized: COMPMGMT_INITIALIZED.load(Ordering::Relaxed),
        snapin_count: state.snapin_count,
        node_count: state.node_count,
        selected_node: state.selected_node,
        is_remote: state.is_remote,
        console_opens: CONSOLE_OPENS.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Computer Management dialog handle
pub type HCOMPMGMTDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Computer Management dialog
pub fn create_compmgmt_dialog(_parent: super::super::HWND) -> HCOMPMGMTDLG {
    CONSOLE_OPENS.fetch_add(1, Ordering::Relaxed);
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}
