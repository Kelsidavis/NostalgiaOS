//! Group Policy Editor
//!
//! Implements the Group Policy Editor following Windows Server 2003.
//! Provides local and domain group policy management.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - gpedit.msc - Group Policy Editor
//! - Computer Configuration, User Configuration
//! - Administrative Templates, Windows Settings, Software Settings

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum policies
const MAX_POLICIES: usize = 256;

/// Maximum categories
const MAX_CATEGORIES: usize = 64;

/// Maximum name length
const MAX_NAME: usize = 128;

/// Maximum description length
const MAX_DESC: usize = 512;

// ============================================================================
// Policy Scope
// ============================================================================

/// Policy scope (Computer or User)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyScope {
    /// Computer Configuration
    #[default]
    Computer = 0,
    /// User Configuration
    User = 1,
}

impl PolicyScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyScope::Computer => "Computer Configuration",
            PolicyScope::User => "User Configuration",
        }
    }
}

// ============================================================================
// Policy Category
// ============================================================================

/// Policy category
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpCategory {
    /// Software Settings
    #[default]
    SoftwareSettings = 0,
    /// Windows Settings
    WindowsSettings = 1,
    /// Administrative Templates
    AdminTemplates = 2,
}

impl GpCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            GpCategory::SoftwareSettings => "Software Settings",
            GpCategory::WindowsSettings => "Windows Settings",
            GpCategory::AdminTemplates => "Administrative Templates",
        }
    }
}

// ============================================================================
// Policy State
// ============================================================================

/// Policy state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyState {
    /// Not Configured
    #[default]
    NotConfigured = 0,
    /// Enabled
    Enabled = 1,
    /// Disabled
    Disabled = 2,
}

impl PolicyState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyState::NotConfigured => "Not Configured",
            PolicyState::Enabled => "Enabled",
            PolicyState::Disabled => "Disabled",
        }
    }
}

// ============================================================================
// Administrative Template Subcategory
// ============================================================================

/// Administrative template subcategory
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AdminSubcategory {
    /// Windows Components
    #[default]
    WindowsComponents = 0,
    /// System
    System = 1,
    /// Network
    Network = 2,
    /// Printers
    Printers = 3,
    /// Start Menu and Taskbar
    StartMenu = 4,
    /// Desktop
    Desktop = 5,
    /// Control Panel
    ControlPanel = 6,
    /// Shared Folders
    SharedFolders = 7,
}

impl AdminSubcategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            AdminSubcategory::WindowsComponents => "Windows Components",
            AdminSubcategory::System => "System",
            AdminSubcategory::Network => "Network",
            AdminSubcategory::Printers => "Printers",
            AdminSubcategory::StartMenu => "Start Menu and Taskbar",
            AdminSubcategory::Desktop => "Desktop",
            AdminSubcategory::ControlPanel => "Control Panel",
            AdminSubcategory::SharedFolders => "Shared Folders",
        }
    }
}

// ============================================================================
// Group Policy Entry
// ============================================================================

/// Group policy entry
#[derive(Debug, Clone, Copy)]
pub struct GpEntry {
    /// Policy ID
    pub policy_id: u32,
    /// Scope (Computer/User)
    pub scope: PolicyScope,
    /// Category
    pub category: GpCategory,
    /// Subcategory (for Admin Templates)
    pub subcategory: AdminSubcategory,
    /// Policy name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC],
    /// Description length
    pub desc_len: usize,
    /// Current state
    pub state: PolicyState,
    /// Registry key affected
    pub reg_key: [u8; MAX_NAME],
    /// Reg key length
    pub reg_key_len: usize,
    /// Registry value name
    pub reg_value: [u8; 64],
    /// Reg value length
    pub reg_value_len: usize,
    /// Supported on (e.g., "At least Windows 2000")
    pub supported_on: [u8; 64],
    /// Supported on length
    pub supported_len: usize,
}

impl GpEntry {
    pub const fn new() -> Self {
        Self {
            policy_id: 0,
            scope: PolicyScope::Computer,
            category: GpCategory::AdminTemplates,
            subcategory: AdminSubcategory::System,
            name: [0u8; MAX_NAME],
            name_len: 0,
            description: [0u8; MAX_DESC],
            desc_len: 0,
            state: PolicyState::NotConfigured,
            reg_key: [0u8; MAX_NAME],
            reg_key_len: 0,
            reg_value: [0u8; 64],
            reg_value_len: 0,
            supported_on: [0u8; 64],
            supported_len: 0,
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

    pub fn set_reg_key(&mut self, key: &[u8]) {
        let len = key.len().min(MAX_NAME);
        self.reg_key[..len].copy_from_slice(&key[..len]);
        self.reg_key_len = len;
    }

    pub fn set_reg_value(&mut self, value: &[u8]) {
        let len = value.len().min(64);
        self.reg_value[..len].copy_from_slice(&value[..len]);
        self.reg_value_len = len;
    }

    pub fn set_supported_on(&mut self, supported: &[u8]) {
        let len = supported.len().min(64);
        self.supported_on[..len].copy_from_slice(&supported[..len]);
        self.supported_len = len;
    }
}

impl Default for GpEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Category Node
// ============================================================================

/// Category tree node
#[derive(Debug, Clone, Copy)]
pub struct CategoryNode {
    /// Node ID
    pub node_id: u32,
    /// Parent ID (0 for root)
    pub parent_id: u32,
    /// Scope
    pub scope: PolicyScope,
    /// Category
    pub category: GpCategory,
    /// Subcategory (for admin templates)
    pub subcategory: Option<AdminSubcategory>,
    /// Display name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Has children
    pub has_children: bool,
    /// Is expanded
    pub expanded: bool,
}

impl CategoryNode {
    pub const fn new() -> Self {
        Self {
            node_id: 0,
            parent_id: 0,
            scope: PolicyScope::Computer,
            category: GpCategory::AdminTemplates,
            subcategory: None,
            name: [0u8; MAX_NAME],
            name_len: 0,
            has_children: false,
            expanded: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

impl Default for CategoryNode {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Group Policy State
// ============================================================================

/// Group Policy Editor state
struct GpeditState {
    /// Policies
    policies: [GpEntry; MAX_POLICIES],
    /// Policy count
    policy_count: usize,
    /// Next policy ID
    next_policy_id: u32,
    /// Category nodes
    categories: [CategoryNode; MAX_CATEGORIES],
    /// Category count
    category_count: usize,
    /// Next node ID
    next_node_id: u32,
    /// Selected node ID
    selected_node: u32,
    /// Selected policy ID
    selected_policy: u32,
    /// Show policies filter
    show_all_settings: bool,
    /// Filter text
    filter_text: [u8; 64],
    /// Filter length
    filter_len: usize,
}

impl GpeditState {
    pub const fn new() -> Self {
        Self {
            policies: [const { GpEntry::new() }; MAX_POLICIES],
            policy_count: 0,
            next_policy_id: 1,
            categories: [const { CategoryNode::new() }; MAX_CATEGORIES],
            category_count: 0,
            next_node_id: 1,
            selected_node: 0,
            selected_policy: 0,
            show_all_settings: false,
            filter_text: [0u8; 64],
            filter_len: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static GPEDIT_INITIALIZED: AtomicBool = AtomicBool::new(false);
static GPEDIT_STATE: SpinLock<GpeditState> = SpinLock::new(GpeditState::new());

// Statistics
static POLICY_CHANGES: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Group Policy Editor
pub fn init() {
    if GPEDIT_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = GPEDIT_STATE.lock();

    // Build category tree
    build_category_tree(&mut state);

    // Add sample policies
    add_sample_policies(&mut state);

    crate::serial_println!("[WIN32K] Group Policy Editor initialized");
}

/// Build category tree
fn build_category_tree(state: &mut GpeditState) {
    // Root nodes for Computer and User Configuration
    for scope in [PolicyScope::Computer, PolicyScope::User] {
        let scope_id = state.next_node_id;
        state.next_node_id += 1;

        let mut scope_node = CategoryNode::new();
        scope_node.node_id = scope_id;
        scope_node.parent_id = 0;
        scope_node.scope = scope;
        scope_node.set_name(scope.as_str().as_bytes());
        scope_node.has_children = true;
        scope_node.expanded = true;

        let idx = state.category_count;
        state.categories[idx] = scope_node;
        state.category_count += 1;

        // Add category nodes under each scope
        for category in [GpCategory::SoftwareSettings, GpCategory::WindowsSettings, GpCategory::AdminTemplates] {
            if state.category_count >= MAX_CATEGORIES {
                break;
            }

            let cat_id = state.next_node_id;
            state.next_node_id += 1;

            let mut cat_node = CategoryNode::new();
            cat_node.node_id = cat_id;
            cat_node.parent_id = scope_id;
            cat_node.scope = scope;
            cat_node.category = category;
            cat_node.set_name(category.as_str().as_bytes());
            cat_node.has_children = category == GpCategory::AdminTemplates;

            let cidx = state.category_count;
            state.categories[cidx] = cat_node;
            state.category_count += 1;

            // Add subcategories for Administrative Templates
            if category == GpCategory::AdminTemplates {
                for subcat in [
                    AdminSubcategory::WindowsComponents,
                    AdminSubcategory::System,
                    AdminSubcategory::Network,
                    AdminSubcategory::Desktop,
                    AdminSubcategory::ControlPanel,
                ] {
                    if state.category_count >= MAX_CATEGORIES {
                        break;
                    }

                    let sub_id = state.next_node_id;
                    state.next_node_id += 1;

                    let mut sub_node = CategoryNode::new();
                    sub_node.node_id = sub_id;
                    sub_node.parent_id = cat_id;
                    sub_node.scope = scope;
                    sub_node.category = category;
                    sub_node.subcategory = Some(subcat);
                    sub_node.set_name(subcat.as_str().as_bytes());

                    let sidx = state.category_count;
                    state.categories[sidx] = sub_node;
                    state.category_count += 1;
                }
            }
        }
    }

    // Select first scope node
    if state.category_count > 0 {
        state.selected_node = state.categories[0].node_id;
    }
}

/// Add sample policies
fn add_sample_policies(state: &mut GpeditState) {
    let policies: [(PolicyScope, AdminSubcategory, &[u8], &[u8]); 15] = [
        (PolicyScope::Computer, AdminSubcategory::System, b"Turn off Autoplay", b"Disables the Autoplay feature"),
        (PolicyScope::Computer, AdminSubcategory::System, b"Specify settings for optional component installation", b"Configure Windows Update settings for features"),
        (PolicyScope::Computer, AdminSubcategory::Network, b"Prohibit access to the Network Connections settings", b"Prevent users from modifying network settings"),
        (PolicyScope::Computer, AdminSubcategory::WindowsComponents, b"Turn off Windows Update device driver searching", b"Disable driver searching on Windows Update"),
        (PolicyScope::Computer, AdminSubcategory::WindowsComponents, b"Do not display the Getting Started welcome screen", b"Disable the Getting Started page"),
        (PolicyScope::Computer, AdminSubcategory::ControlPanel, b"Prohibit access to the Control Panel", b"Prevent users from starting Control Panel"),
        (PolicyScope::User, AdminSubcategory::Desktop, b"Remove Recycle Bin icon from desktop", b"Hide the Recycle Bin from the desktop"),
        (PolicyScope::User, AdminSubcategory::Desktop, b"Hide and disable all items on the desktop", b"Remove all icons and prevent right-click"),
        (PolicyScope::User, AdminSubcategory::System, b"Prevent access to registry editing tools", b"Disable regedit and regedt32"),
        (PolicyScope::User, AdminSubcategory::System, b"Prevent access to the command prompt", b"Disable CMD.EXE"),
        (PolicyScope::User, AdminSubcategory::System, b"Don't run specified Windows applications", b"Prevent specific applications from running"),
        (PolicyScope::User, AdminSubcategory::ControlPanel, b"Prohibit access to Control Panel and PC settings", b"Block Control Panel access"),
        (PolicyScope::User, AdminSubcategory::Network, b"Remove Network Connections from Start Menu", b"Hide network connections menu item"),
        (PolicyScope::User, AdminSubcategory::WindowsComponents, b"Remove Search link from Start Menu", b"Hide the Search option"),
        (PolicyScope::User, AdminSubcategory::WindowsComponents, b"Remove Run menu from Start Menu", b"Hide the Run option"),
    ];

    for (scope, subcat, name, desc) in policies.iter() {
        if state.policy_count >= MAX_POLICIES {
            break;
        }

        let mut policy = GpEntry::new();
        policy.policy_id = state.next_policy_id;
        state.next_policy_id += 1;
        policy.scope = *scope;
        policy.category = GpCategory::AdminTemplates;
        policy.subcategory = *subcat;
        policy.set_name(name);
        policy.set_description(desc);
        policy.set_supported_on(b"At least Windows 2000");

        let idx = state.policy_count;
        state.policies[idx] = policy;
        state.policy_count += 1;
    }
}

// ============================================================================
// Category Navigation
// ============================================================================

/// Get category count
pub fn get_category_count() -> usize {
    GPEDIT_STATE.lock().category_count
}

/// Get category by index
pub fn get_category(index: usize) -> Option<CategoryNode> {
    let state = GPEDIT_STATE.lock();
    if index < state.category_count {
        Some(state.categories[index])
    } else {
        None
    }
}

/// Get category by ID
pub fn get_category_by_id(node_id: u32) -> Option<CategoryNode> {
    let state = GPEDIT_STATE.lock();
    for i in 0..state.category_count {
        if state.categories[i].node_id == node_id {
            return Some(state.categories[i]);
        }
    }
    None
}

/// Get child categories
pub fn get_child_categories(parent_id: u32, buffer: &mut [CategoryNode]) -> usize {
    let state = GPEDIT_STATE.lock();
    let mut count = 0;
    for i in 0..state.category_count {
        if state.categories[i].parent_id == parent_id {
            if count < buffer.len() {
                buffer[count] = state.categories[i];
                count += 1;
            }
        }
    }
    count
}

/// Select category
pub fn select_category(node_id: u32) -> bool {
    let mut state = GPEDIT_STATE.lock();
    for i in 0..state.category_count {
        if state.categories[i].node_id == node_id {
            state.selected_node = node_id;
            return true;
        }
    }
    false
}

/// Get selected category
pub fn get_selected_category() -> u32 {
    GPEDIT_STATE.lock().selected_node
}

/// Expand/collapse category
pub fn set_category_expanded(node_id: u32, expanded: bool) -> bool {
    let mut state = GPEDIT_STATE.lock();
    for i in 0..state.category_count {
        if state.categories[i].node_id == node_id {
            state.categories[i].expanded = expanded;
            return true;
        }
    }
    false
}

// ============================================================================
// Policy Management
// ============================================================================

/// Get policy count
pub fn get_policy_count() -> usize {
    GPEDIT_STATE.lock().policy_count
}

/// Get policies for category
pub fn get_policies_for_category(scope: PolicyScope, subcat: AdminSubcategory, buffer: &mut [GpEntry]) -> usize {
    let state = GPEDIT_STATE.lock();
    let mut count = 0;
    for i in 0..state.policy_count {
        if state.policies[i].scope == scope && state.policies[i].subcategory == subcat {
            if count < buffer.len() {
                buffer[count] = state.policies[i];
                count += 1;
            }
        }
    }
    count
}

/// Get policy by ID
pub fn get_policy(policy_id: u32) -> Option<GpEntry> {
    let state = GPEDIT_STATE.lock();
    for i in 0..state.policy_count {
        if state.policies[i].policy_id == policy_id {
            return Some(state.policies[i]);
        }
    }
    None
}

/// Set policy state
pub fn set_policy_state(policy_id: u32, new_state: PolicyState) -> bool {
    let mut state = GPEDIT_STATE.lock();
    for i in 0..state.policy_count {
        if state.policies[i].policy_id == policy_id {
            state.policies[i].state = new_state;
            POLICY_CHANGES.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

/// Select policy
pub fn select_policy(policy_id: u32) {
    GPEDIT_STATE.lock().selected_policy = policy_id;
}

/// Get selected policy
pub fn get_selected_policy() -> u32 {
    GPEDIT_STATE.lock().selected_policy
}

// ============================================================================
// Filtering
// ============================================================================

/// Set filter text
pub fn set_filter(text: &[u8]) {
    let mut state = GPEDIT_STATE.lock();
    let len = text.len().min(64);
    state.filter_text[..len].copy_from_slice(&text[..len]);
    state.filter_len = len;
}

/// Clear filter
pub fn clear_filter() {
    let mut state = GPEDIT_STATE.lock();
    state.filter_len = 0;
}

/// Set show all settings
pub fn set_show_all_settings(show: bool) {
    GPEDIT_STATE.lock().show_all_settings = show;
}

// ============================================================================
// GPO Operations
// ============================================================================

/// Refresh policy
pub fn refresh_policy() -> bool {
    // Would trigger gpupdate
    true
}

/// Export settings to file
pub fn export_settings(_path: &[u8]) -> bool {
    // Would export to file
    true
}

/// Import settings from file
pub fn import_settings(_path: &[u8]) -> bool {
    // Would import from file
    POLICY_CHANGES.fetch_add(1, Ordering::Relaxed);
    true
}

// ============================================================================
// Statistics
// ============================================================================

/// Group Policy statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct GpeditStats {
    pub initialized: bool,
    pub policy_count: usize,
    pub category_count: usize,
    pub configured_count: usize,
    pub policy_changes: u32,
}

/// Get Group Policy statistics
pub fn get_stats() -> GpeditStats {
    let state = GPEDIT_STATE.lock();
    let configured = state.policies[..state.policy_count]
        .iter()
        .filter(|p| p.state != PolicyState::NotConfigured)
        .count();
    GpeditStats {
        initialized: GPEDIT_INITIALIZED.load(Ordering::Relaxed),
        policy_count: state.policy_count,
        category_count: state.category_count,
        configured_count: configured,
        policy_changes: POLICY_CHANGES.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Group Policy dialog handle
pub type HGPEDITDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Group Policy dialog
pub fn create_gpedit_dialog(_parent: super::super::HWND) -> HGPEDITDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}
