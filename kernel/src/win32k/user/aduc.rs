//! Active Directory Users and Computers (dsa.msc) implementation
//!
//! Provides management of Active Directory users, groups, computers,
//! organizational units, and other directory objects.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use crate::win32k::user::UserHandle;

/// Local type alias for window handles
type HWND = UserHandle;

/// Maximum objects per container
const MAX_OBJECTS: usize = 256;

/// Maximum OUs
const MAX_OUS: usize = 64;

/// Maximum groups
const MAX_GROUPS: usize = 128;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum distinguished name length
const MAX_DN_LEN: usize = 256;

/// Maximum description length
const MAX_DESC_LEN: usize = 128;

/// Maximum group members
const MAX_MEMBERS: usize = 64;

/// Object class type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ObjectClass {
    /// Unknown object
    Unknown = 0,
    /// User account
    User = 1,
    /// Computer account
    Computer = 2,
    /// Security group
    Group = 3,
    /// Organizational Unit
    OrganizationalUnit = 4,
    /// Contact
    Contact = 5,
    /// Shared folder
    SharedFolder = 6,
    /// Printer
    Printer = 7,
    /// InetOrgPerson
    InetOrgPerson = 8,
    /// Domain
    Domain = 9,
    /// Container
    Container = 10,
}

impl ObjectClass {
    /// Create new object class
    pub const fn new() -> Self {
        Self::Unknown
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::User => "User",
            Self::Computer => "Computer",
            Self::Group => "Group",
            Self::OrganizationalUnit => "Organizational Unit",
            Self::Contact => "Contact",
            Self::SharedFolder => "Shared Folder",
            Self::Printer => "Printer",
            Self::InetOrgPerson => "InetOrgPerson",
            Self::Domain => "Domain",
            Self::Container => "Container",
        }
    }
}

impl Default for ObjectClass {
    fn default() -> Self {
        Self::new()
    }
}

// User account control flags
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UserAccountControl: u32 {
        /// Account is disabled
        const ACCOUNTDISABLE = 0x0002;
        /// Home directory required
        const HOMEDIR_REQUIRED = 0x0008;
        /// Account locked out
        const LOCKOUT = 0x0010;
        /// Password not required
        const PASSWD_NOTREQD = 0x0020;
        /// Password cannot change
        const PASSWD_CANT_CHANGE = 0x0040;
        /// Encrypted text password allowed
        const ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080;
        /// Normal account
        const NORMAL_ACCOUNT = 0x0200;
        /// Interdomain trust account
        const INTERDOMAIN_TRUST_ACCOUNT = 0x0800;
        /// Workstation trust account
        const WORKSTATION_TRUST_ACCOUNT = 0x1000;
        /// Server trust account (DC)
        const SERVER_TRUST_ACCOUNT = 0x2000;
        /// Password never expires
        const DONT_EXPIRE_PASSWORD = 0x10000;
        /// MNS logon account
        const MNS_LOGON_ACCOUNT = 0x20000;
        /// Smart card required
        const SMARTCARD_REQUIRED = 0x40000;
        /// Trusted for delegation
        const TRUSTED_FOR_DELEGATION = 0x80000;
        /// Not delegated
        const NOT_DELEGATED = 0x100000;
        /// Use DES encryption only
        const USE_DES_KEY_ONLY = 0x200000;
        /// Preauth not required
        const DONT_REQ_PREAUTH = 0x400000;
        /// Password expired
        const PASSWORD_EXPIRED = 0x800000;
        /// Trusted to auth for delegation
        const TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000;
    }
}

impl Default for UserAccountControl {
    fn default() -> Self {
        Self::NORMAL_ACCOUNT
    }
}

/// Group type flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GroupType {
    /// Global distribution group
    GlobalDistribution = 0x00000002,
    /// Domain local distribution group
    DomainLocalDistribution = 0x00000004,
    /// Universal distribution group
    UniversalDistribution = 0x00000008,
    /// Global security group
    GlobalSecurity = 0x80000002,
    /// Domain local security group
    DomainLocalSecurity = 0x80000004,
    /// Universal security group
    UniversalSecurity = 0x80000008,
}

impl GroupType {
    /// Create new group type
    pub const fn new() -> Self {
        Self::GlobalSecurity
    }

    /// Check if security group
    pub fn is_security(&self) -> bool {
        matches!(
            self,
            Self::GlobalSecurity | Self::DomainLocalSecurity | Self::UniversalSecurity
        )
    }

    /// Get scope name
    pub fn scope_name(&self) -> &'static str {
        match self {
            Self::GlobalDistribution | Self::GlobalSecurity => "Global",
            Self::DomainLocalDistribution | Self::DomainLocalSecurity => "Domain local",
            Self::UniversalDistribution | Self::UniversalSecurity => "Universal",
        }
    }
}

impl Default for GroupType {
    fn default() -> Self {
        Self::new()
    }
}

/// AD User object
#[derive(Clone)]
pub struct AdUser {
    /// Object ID
    pub object_id: u32,
    /// SAM account name (logon name)
    pub sam_account_name: [u8; MAX_NAME_LEN],
    /// SAM account name length
    pub sam_len: usize,
    /// User principal name (UPN)
    pub upn: [u8; MAX_NAME_LEN],
    /// UPN length
    pub upn_len: usize,
    /// First name
    pub first_name: [u8; MAX_NAME_LEN],
    /// First name length
    pub first_len: usize,
    /// Last name
    pub last_name: [u8; MAX_NAME_LEN],
    /// Last name length
    pub last_len: usize,
    /// Display name
    pub display_name: [u8; MAX_NAME_LEN],
    /// Display name length
    pub display_len: usize,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub desc_len: usize,
    /// Distinguished name
    pub dn: [u8; MAX_DN_LEN],
    /// DN length
    pub dn_len: usize,
    /// Email address
    pub email: [u8; MAX_NAME_LEN],
    /// Email length
    pub email_len: usize,
    /// Phone number
    pub phone: [u8; 32],
    /// Phone length
    pub phone_len: usize,
    /// User account control flags
    pub uac: UserAccountControl,
    /// Password last set (timestamp)
    pub pwd_last_set: u64,
    /// Account expires (timestamp, 0 = never)
    pub account_expires: u64,
    /// Last logon (timestamp)
    pub last_logon: u64,
    /// Logon count
    pub logon_count: u32,
    /// Bad password count
    pub bad_pwd_count: u32,
    /// Home directory
    pub home_dir: [u8; MAX_NAME_LEN],
    /// Home dir length
    pub home_len: usize,
    /// Profile path
    pub profile_path: [u8; MAX_NAME_LEN],
    /// Profile path length
    pub profile_len: usize,
    /// Logon script
    pub logon_script: [u8; MAX_NAME_LEN],
    /// Logon script length
    pub script_len: usize,
    /// Parent OU ID
    pub parent_ou: u32,
    /// In use flag
    pub in_use: bool,
}

impl AdUser {
    /// Create new user
    pub const fn new() -> Self {
        Self {
            object_id: 0,
            sam_account_name: [0; MAX_NAME_LEN],
            sam_len: 0,
            upn: [0; MAX_NAME_LEN],
            upn_len: 0,
            first_name: [0; MAX_NAME_LEN],
            first_len: 0,
            last_name: [0; MAX_NAME_LEN],
            last_len: 0,
            display_name: [0; MAX_NAME_LEN],
            display_len: 0,
            description: [0; MAX_DESC_LEN],
            desc_len: 0,
            dn: [0; MAX_DN_LEN],
            dn_len: 0,
            email: [0; MAX_NAME_LEN],
            email_len: 0,
            phone: [0; 32],
            phone_len: 0,
            uac: UserAccountControl::NORMAL_ACCOUNT,
            pwd_last_set: 0,
            account_expires: 0,
            last_logon: 0,
            logon_count: 0,
            bad_pwd_count: 0,
            home_dir: [0; MAX_NAME_LEN],
            home_len: 0,
            profile_path: [0; MAX_NAME_LEN],
            profile_len: 0,
            logon_script: [0; MAX_NAME_LEN],
            script_len: 0,
            parent_ou: 0,
            in_use: false,
        }
    }

    /// Set SAM account name
    pub fn set_sam_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.sam_account_name[..len].copy_from_slice(&name[..len]);
        self.sam_len = len;
    }

    /// Get SAM account name
    pub fn get_sam_name(&self) -> &[u8] {
        &self.sam_account_name[..self.sam_len]
    }

    /// Set display name
    pub fn set_display_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.display_name[..len].copy_from_slice(&name[..len]);
        self.display_len = len;
    }

    /// Set first name
    pub fn set_first_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.first_name[..len].copy_from_slice(&name[..len]);
        self.first_len = len;
    }

    /// Set last name
    pub fn set_last_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.last_name[..len].copy_from_slice(&name[..len]);
        self.last_len = len;
    }

    /// Check if account is disabled
    pub fn is_disabled(&self) -> bool {
        self.uac.contains(UserAccountControl::ACCOUNTDISABLE)
    }

    /// Check if account is locked
    pub fn is_locked(&self) -> bool {
        self.uac.contains(UserAccountControl::LOCKOUT)
    }

    /// Check if password expired
    pub fn is_password_expired(&self) -> bool {
        self.uac.contains(UserAccountControl::PASSWORD_EXPIRED)
    }
}

impl Default for AdUser {
    fn default() -> Self {
        Self::new()
    }
}

/// AD Computer object
#[derive(Clone)]
pub struct AdComputer {
    /// Object ID
    pub object_id: u32,
    /// SAM account name (ends with $)
    pub sam_account_name: [u8; MAX_NAME_LEN],
    /// SAM account name length
    pub sam_len: usize,
    /// Computer name
    pub cn: [u8; MAX_NAME_LEN],
    /// CN length
    pub cn_len: usize,
    /// DNS host name
    pub dns_hostname: [u8; MAX_NAME_LEN],
    /// DNS hostname length
    pub dns_len: usize,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub desc_len: usize,
    /// Distinguished name
    pub dn: [u8; MAX_DN_LEN],
    /// DN length
    pub dn_len: usize,
    /// Operating system
    pub os: [u8; MAX_NAME_LEN],
    /// OS length
    pub os_len: usize,
    /// OS version
    pub os_version: [u8; 32],
    /// OS version length
    pub os_ver_len: usize,
    /// OS service pack
    pub os_sp: [u8; 32],
    /// OS SP length
    pub os_sp_len: usize,
    /// User account control
    pub uac: UserAccountControl,
    /// Last logon timestamp
    pub last_logon: u64,
    /// Location
    pub location: [u8; MAX_NAME_LEN],
    /// Location length
    pub location_len: usize,
    /// Managed by (DN of user/group)
    pub managed_by: [u8; MAX_DN_LEN],
    /// Managed by length
    pub managed_len: usize,
    /// Parent OU ID
    pub parent_ou: u32,
    /// Is domain controller
    pub is_dc: bool,
    /// Reserved
    pub reserved: [u8; 3],
    /// In use flag
    pub in_use: bool,
}

impl AdComputer {
    /// Create new computer
    pub const fn new() -> Self {
        Self {
            object_id: 0,
            sam_account_name: [0; MAX_NAME_LEN],
            sam_len: 0,
            cn: [0; MAX_NAME_LEN],
            cn_len: 0,
            dns_hostname: [0; MAX_NAME_LEN],
            dns_len: 0,
            description: [0; MAX_DESC_LEN],
            desc_len: 0,
            dn: [0; MAX_DN_LEN],
            dn_len: 0,
            os: [0; MAX_NAME_LEN],
            os_len: 0,
            os_version: [0; 32],
            os_ver_len: 0,
            os_sp: [0; 32],
            os_sp_len: 0,
            uac: UserAccountControl::WORKSTATION_TRUST_ACCOUNT,
            last_logon: 0,
            location: [0; MAX_NAME_LEN],
            location_len: 0,
            managed_by: [0; MAX_DN_LEN],
            managed_len: 0,
            parent_ou: 0,
            is_dc: false,
            reserved: [0; 3],
            in_use: false,
        }
    }

    /// Set computer name
    pub fn set_cn(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.cn[..len].copy_from_slice(&name[..len]);
        self.cn_len = len;
    }

    /// Get computer name
    pub fn get_cn(&self) -> &[u8] {
        &self.cn[..self.cn_len]
    }

    /// Set operating system info
    pub fn set_os(&mut self, os: &[u8], version: &[u8]) {
        let os_len = os.len().min(MAX_NAME_LEN);
        self.os[..os_len].copy_from_slice(&os[..os_len]);
        self.os_len = os_len;

        let ver_len = version.len().min(32);
        self.os_version[..ver_len].copy_from_slice(&version[..ver_len]);
        self.os_ver_len = ver_len;
    }
}

impl Default for AdComputer {
    fn default() -> Self {
        Self::new()
    }
}

/// AD Group object
#[derive(Clone)]
pub struct AdGroup {
    /// Object ID
    pub object_id: u32,
    /// SAM account name
    pub sam_account_name: [u8; MAX_NAME_LEN],
    /// SAM account name length
    pub sam_len: usize,
    /// Common name
    pub cn: [u8; MAX_NAME_LEN],
    /// CN length
    pub cn_len: usize,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub desc_len: usize,
    /// Distinguished name
    pub dn: [u8; MAX_DN_LEN],
    /// DN length
    pub dn_len: usize,
    /// Email address
    pub email: [u8; MAX_NAME_LEN],
    /// Email length
    pub email_len: usize,
    /// Group type
    pub group_type: GroupType,
    /// Member object IDs
    pub members: [u32; MAX_MEMBERS],
    /// Member count
    pub member_count: usize,
    /// Member of (group IDs this group belongs to)
    pub member_of: [u32; 16],
    /// Member of count
    pub member_of_count: usize,
    /// Managed by user ID
    pub managed_by: u32,
    /// Notes
    pub notes: [u8; MAX_DESC_LEN],
    /// Notes length
    pub notes_len: usize,
    /// Parent OU ID
    pub parent_ou: u32,
    /// In use flag
    pub in_use: bool,
}

impl AdGroup {
    /// Create new group
    pub const fn new() -> Self {
        Self {
            object_id: 0,
            sam_account_name: [0; MAX_NAME_LEN],
            sam_len: 0,
            cn: [0; MAX_NAME_LEN],
            cn_len: 0,
            description: [0; MAX_DESC_LEN],
            desc_len: 0,
            dn: [0; MAX_DN_LEN],
            dn_len: 0,
            email: [0; MAX_NAME_LEN],
            email_len: 0,
            group_type: GroupType::GlobalSecurity,
            members: [0; MAX_MEMBERS],
            member_count: 0,
            member_of: [0; 16],
            member_of_count: 0,
            managed_by: 0,
            notes: [0; MAX_DESC_LEN],
            notes_len: 0,
            parent_ou: 0,
            in_use: false,
        }
    }

    /// Set group name
    pub fn set_cn(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.cn[..len].copy_from_slice(&name[..len]);
        self.cn_len = len;

        // Also set SAM name
        self.sam_account_name[..len].copy_from_slice(&name[..len]);
        self.sam_len = len;
    }

    /// Add member
    pub fn add_member(&mut self, object_id: u32) -> bool {
        if self.member_count >= MAX_MEMBERS {
            return false;
        }
        // Check for duplicates
        for i in 0..self.member_count {
            if self.members[i] == object_id {
                return true; // Already a member
            }
        }
        self.members[self.member_count] = object_id;
        self.member_count += 1;
        true
    }

    /// Remove member
    pub fn remove_member(&mut self, object_id: u32) -> bool {
        for i in 0..self.member_count {
            if self.members[i] == object_id {
                // Shift remaining members
                for j in i..self.member_count - 1 {
                    self.members[j] = self.members[j + 1];
                }
                self.member_count -= 1;
                return true;
            }
        }
        false
    }
}

impl Default for AdGroup {
    fn default() -> Self {
        Self::new()
    }
}

/// Organizational Unit
#[derive(Clone)]
pub struct OrganizationalUnit {
    /// OU ID
    pub ou_id: u32,
    /// Name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub desc_len: usize,
    /// Distinguished name
    pub dn: [u8; MAX_DN_LEN],
    /// DN length
    pub dn_len: usize,
    /// Parent OU ID (0 for root)
    pub parent_id: u32,
    /// Country/region
    pub country: [u8; 32],
    /// Country length
    pub country_len: usize,
    /// City
    pub city: [u8; 64],
    /// City length
    pub city_len: usize,
    /// Street address
    pub street: [u8; MAX_NAME_LEN],
    /// Street length
    pub street_len: usize,
    /// Protected from accidental deletion
    pub protected: bool,
    /// Reserved
    pub reserved: [u8; 3],
    /// In use flag
    pub in_use: bool,
}

impl OrganizationalUnit {
    /// Create new OU
    pub const fn new() -> Self {
        Self {
            ou_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            description: [0; MAX_DESC_LEN],
            desc_len: 0,
            dn: [0; MAX_DN_LEN],
            dn_len: 0,
            parent_id: 0,
            country: [0; 32],
            country_len: 0,
            city: [0; 64],
            city_len: 0,
            street: [0; MAX_NAME_LEN],
            street_len: 0,
            protected: false,
            reserved: [0; 3],
            in_use: false,
        }
    }

    /// Set OU name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Get OU name
    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

impl Default for OrganizationalUnit {
    fn default() -> Self {
        Self::new()
    }
}

/// ADUC State
pub struct AducState {
    /// Connected domain
    pub domain: [u8; MAX_NAME_LEN],
    /// Domain length
    pub domain_len: usize,
    /// Domain DN
    pub domain_dn: [u8; MAX_DN_LEN],
    /// Domain DN length
    pub domain_dn_len: usize,
    /// Is connected
    pub connected: bool,
    /// Reserved
    pub reserved: [u8; 3],
    /// Users
    pub users: [AdUser; MAX_OBJECTS],
    /// User count
    pub user_count: usize,
    /// Computers
    pub computers: [AdComputer; MAX_OBJECTS],
    /// Computer count
    pub computer_count: usize,
    /// Groups
    pub groups: [AdGroup; MAX_GROUPS],
    /// Group count
    pub group_count: usize,
    /// Organizational Units
    pub ous: [OrganizationalUnit; MAX_OUS],
    /// OU count
    pub ou_count: usize,
    /// Next object ID
    pub next_object_id: u32,
    /// Show advanced features
    pub advanced_features: bool,
    /// Show deleted objects
    pub show_deleted: bool,
}

impl AducState {
    /// Create new state
    pub const fn new() -> Self {
        Self {
            domain: [0; MAX_NAME_LEN],
            domain_len: 0,
            domain_dn: [0; MAX_DN_LEN],
            domain_dn_len: 0,
            connected: false,
            reserved: [0; 3],
            users: [const { AdUser::new() }; MAX_OBJECTS],
            user_count: 0,
            computers: [const { AdComputer::new() }; MAX_OBJECTS],
            computer_count: 0,
            groups: [const { AdGroup::new() }; MAX_GROUPS],
            group_count: 0,
            ous: [const { OrganizationalUnit::new() }; MAX_OUS],
            ou_count: 0,
            next_object_id: 1000,
            advanced_features: false,
            show_deleted: false,
        }
    }

    /// Set domain
    pub fn set_domain(&mut self, domain: &[u8]) {
        let len = domain.len().min(MAX_NAME_LEN);
        self.domain[..len].copy_from_slice(&domain[..len]);
        self.domain_len = len;
    }

    /// Find user by ID
    pub fn find_user(&self, object_id: u32) -> Option<usize> {
        for (i, user) in self.users.iter().enumerate() {
            if user.in_use && user.object_id == object_id {
                return Some(i);
            }
        }
        None
    }

    /// Find computer by ID
    pub fn find_computer(&self, object_id: u32) -> Option<usize> {
        for (i, comp) in self.computers.iter().enumerate() {
            if comp.in_use && comp.object_id == object_id {
                return Some(i);
            }
        }
        None
    }

    /// Find group by ID
    pub fn find_group(&self, object_id: u32) -> Option<usize> {
        for (i, group) in self.groups.iter().enumerate() {
            if group.in_use && group.object_id == object_id {
                return Some(i);
            }
        }
        None
    }

    /// Find OU by ID
    pub fn find_ou(&self, ou_id: u32) -> Option<usize> {
        for (i, ou) in self.ous.iter().enumerate() {
            if ou.in_use && ou.ou_id == ou_id {
                return Some(i);
            }
        }
        None
    }
}

impl Default for AducState {
    fn default() -> Self {
        Self::new()
    }
}

/// Global state
static ADUC_STATE: SpinLock<AducState> = SpinLock::new(AducState::new());

/// Initialization flag
static ADUC_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Statistics
static ADUC_OPERATION_COUNT: AtomicU32 = AtomicU32::new(0);

/// Error codes
pub mod error {
    pub const SUCCESS: u32 = 0;
    pub const NOT_INITIALIZED: u32 = 0xAD000001;
    pub const NOT_CONNECTED: u32 = 0xAD000002;
    pub const OBJECT_NOT_FOUND: u32 = 0xAD000003;
    pub const OBJECT_EXISTS: u32 = 0xAD000004;
    pub const INVALID_PARAMETER: u32 = 0xAD000005;
    pub const ACCESS_DENIED: u32 = 0xAD000006;
    pub const CONSTRAINT_VIOLATION: u32 = 0xAD000007;
    pub const NO_MORE_OBJECTS: u32 = 0xAD000008;
    pub const INVALID_DN: u32 = 0xAD000009;
}

/// Initialize ADUC
pub fn init() {
    if ADUC_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = ADUC_STATE.lock();

    // Set default domain
    state.set_domain(b"DOMAIN");
    state.connected = true;

    // Create default OUs
    let users_ou_id = state.next_object_id;
    state.next_object_id += 1;

    let users_ou = &mut state.ous[0];
    users_ou.in_use = true;
    users_ou.ou_id = users_ou_id;
    users_ou.set_name(b"Users");
    users_ou.parent_id = 0;
    state.ou_count = 1;

    let computers_ou_id = state.next_object_id;
    state.next_object_id += 1;

    let computers_ou = &mut state.ous[1];
    computers_ou.in_use = true;
    computers_ou.ou_id = computers_ou_id;
    computers_ou.set_name(b"Computers");
    computers_ou.parent_id = 0;
    state.ou_count = 2;

    // Create default admin user
    let admin_id = state.next_object_id;
    state.next_object_id += 1;

    let admin = &mut state.users[0];
    admin.in_use = true;
    admin.object_id = admin_id;
    admin.set_sam_name(b"Administrator");
    admin.set_display_name(b"Administrator");
    admin.uac = UserAccountControl::NORMAL_ACCOUNT;
    admin.parent_ou = users_ou_id;
    state.user_count = 1;

    // Create Domain Admins group
    let da_id = state.next_object_id;
    state.next_object_id += 1;

    let domain_admins = &mut state.groups[0];
    domain_admins.in_use = true;
    domain_admins.object_id = da_id;
    domain_admins.set_cn(b"Domain Admins");
    domain_admins.group_type = GroupType::GlobalSecurity;
    domain_admins.members[0] = admin_id;
    domain_admins.member_count = 1;
    state.group_count = 1;

    // Create Domain Users group
    let du_id = state.next_object_id;
    state.next_object_id += 1;

    let domain_users = &mut state.groups[1];
    domain_users.in_use = true;
    domain_users.object_id = du_id;
    domain_users.set_cn(b"Domain Users");
    domain_users.group_type = GroupType::GlobalSecurity;
    state.group_count = 2;
}

/// Connect to a domain
pub fn connect_domain(domain: &[u8]) -> Result<(), u32> {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADUC_STATE.lock();
    state.set_domain(domain);
    state.connected = true;

    ADUC_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Create a user
pub fn create_user(
    sam_name: &[u8],
    first_name: &[u8],
    last_name: &[u8],
    parent_ou: u32,
) -> Result<u32, u32> {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADUC_STATE.lock();

    if !state.connected {
        return Err(error::NOT_CONNECTED);
    }

    // Find free slot
    let mut slot_idx = None;
    for (i, user) in state.users.iter().enumerate() {
        if !user.in_use {
            slot_idx = Some(i);
            break;
        }
    }

    let idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::NO_MORE_OBJECTS),
    };

    let object_id = state.next_object_id;
    state.next_object_id += 1;

    let user = &mut state.users[idx];
    user.in_use = true;
    user.object_id = object_id;
    user.set_sam_name(sam_name);
    user.set_first_name(first_name);
    user.set_last_name(last_name);
    user.parent_ou = parent_ou;
    user.uac = UserAccountControl::NORMAL_ACCOUNT | UserAccountControl::ACCOUNTDISABLE;

    state.user_count += 1;
    ADUC_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(object_id)
}

/// Enable user account
pub fn enable_user(object_id: u32) -> Result<(), u32> {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADUC_STATE.lock();

    let idx = match state.find_user(object_id) {
        Some(i) => i,
        None => return Err(error::OBJECT_NOT_FOUND),
    };

    state.users[idx].uac.remove(UserAccountControl::ACCOUNTDISABLE);

    ADUC_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Disable user account
pub fn disable_user(object_id: u32) -> Result<(), u32> {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADUC_STATE.lock();

    let idx = match state.find_user(object_id) {
        Some(i) => i,
        None => return Err(error::OBJECT_NOT_FOUND),
    };

    state.users[idx].uac.insert(UserAccountControl::ACCOUNTDISABLE);

    ADUC_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Reset user password
pub fn reset_password(object_id: u32, must_change: bool) -> Result<(), u32> {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADUC_STATE.lock();

    let idx = match state.find_user(object_id) {
        Some(i) => i,
        None => return Err(error::OBJECT_NOT_FOUND),
    };

    state.users[idx].pwd_last_set = if must_change { 0 } else { 1 };

    ADUC_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Delete user
pub fn delete_user(object_id: u32) -> Result<(), u32> {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADUC_STATE.lock();

    let idx = match state.find_user(object_id) {
        Some(i) => i,
        None => return Err(error::OBJECT_NOT_FOUND),
    };

    state.users[idx].in_use = false;
    state.user_count = state.user_count.saturating_sub(1);

    ADUC_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Create a computer account
pub fn create_computer(name: &[u8], parent_ou: u32) -> Result<u32, u32> {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADUC_STATE.lock();

    if !state.connected {
        return Err(error::NOT_CONNECTED);
    }

    // Find free slot
    let mut slot_idx = None;
    for (i, comp) in state.computers.iter().enumerate() {
        if !comp.in_use {
            slot_idx = Some(i);
            break;
        }
    }

    let idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::NO_MORE_OBJECTS),
    };

    let object_id = state.next_object_id;
    state.next_object_id += 1;

    let computer = &mut state.computers[idx];
    computer.in_use = true;
    computer.object_id = object_id;
    computer.set_cn(name);
    computer.parent_ou = parent_ou;
    computer.uac = UserAccountControl::WORKSTATION_TRUST_ACCOUNT | UserAccountControl::ACCOUNTDISABLE;

    state.computer_count += 1;
    ADUC_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(object_id)
}

/// Delete computer
pub fn delete_computer(object_id: u32) -> Result<(), u32> {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADUC_STATE.lock();

    let idx = match state.find_computer(object_id) {
        Some(i) => i,
        None => return Err(error::OBJECT_NOT_FOUND),
    };

    state.computers[idx].in_use = false;
    state.computer_count = state.computer_count.saturating_sub(1);

    ADUC_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Create a group
pub fn create_group(name: &[u8], group_type: GroupType, parent_ou: u32) -> Result<u32, u32> {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADUC_STATE.lock();

    if !state.connected {
        return Err(error::NOT_CONNECTED);
    }

    // Find free slot
    let mut slot_idx = None;
    for (i, group) in state.groups.iter().enumerate() {
        if !group.in_use {
            slot_idx = Some(i);
            break;
        }
    }

    let idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::NO_MORE_OBJECTS),
    };

    let object_id = state.next_object_id;
    state.next_object_id += 1;

    let group = &mut state.groups[idx];
    group.in_use = true;
    group.object_id = object_id;
    group.set_cn(name);
    group.group_type = group_type;
    group.parent_ou = parent_ou;

    state.group_count += 1;
    ADUC_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(object_id)
}

/// Add member to group
pub fn add_group_member(group_id: u32, member_id: u32) -> Result<(), u32> {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADUC_STATE.lock();

    let idx = match state.find_group(group_id) {
        Some(i) => i,
        None => return Err(error::OBJECT_NOT_FOUND),
    };

    if !state.groups[idx].add_member(member_id) {
        return Err(error::CONSTRAINT_VIOLATION);
    }

    ADUC_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Remove member from group
pub fn remove_group_member(group_id: u32, member_id: u32) -> Result<(), u32> {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADUC_STATE.lock();

    let idx = match state.find_group(group_id) {
        Some(i) => i,
        None => return Err(error::OBJECT_NOT_FOUND),
    };

    if !state.groups[idx].remove_member(member_id) {
        return Err(error::OBJECT_NOT_FOUND);
    }

    ADUC_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Delete group
pub fn delete_group(object_id: u32) -> Result<(), u32> {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADUC_STATE.lock();

    let idx = match state.find_group(object_id) {
        Some(i) => i,
        None => return Err(error::OBJECT_NOT_FOUND),
    };

    state.groups[idx].in_use = false;
    state.group_count = state.group_count.saturating_sub(1);

    ADUC_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Create OU
pub fn create_ou(name: &[u8], parent_id: u32) -> Result<u32, u32> {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADUC_STATE.lock();

    if !state.connected {
        return Err(error::NOT_CONNECTED);
    }

    // Find free slot
    let mut slot_idx = None;
    for (i, ou) in state.ous.iter().enumerate() {
        if !ou.in_use {
            slot_idx = Some(i);
            break;
        }
    }

    let idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::NO_MORE_OBJECTS),
    };

    let ou_id = state.next_object_id;
    state.next_object_id += 1;

    let ou = &mut state.ous[idx];
    ou.in_use = true;
    ou.ou_id = ou_id;
    ou.set_name(name);
    ou.parent_id = parent_id;

    state.ou_count += 1;
    ADUC_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(ou_id)
}

/// Delete OU
pub fn delete_ou(ou_id: u32) -> Result<(), u32> {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADUC_STATE.lock();

    let idx = match state.find_ou(ou_id) {
        Some(i) => i,
        None => return Err(error::OBJECT_NOT_FOUND),
    };

    // Check if protected
    if state.ous[idx].protected {
        return Err(error::ACCESS_DENIED);
    }

    state.ous[idx].in_use = false;
    state.ou_count = state.ou_count.saturating_sub(1);

    ADUC_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Get user count
pub fn get_user_count() -> usize {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = ADUC_STATE.lock();
    state.user_count
}

/// Get computer count
pub fn get_computer_count() -> usize {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = ADUC_STATE.lock();
    state.computer_count
}

/// Get group count
pub fn get_group_count() -> usize {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = ADUC_STATE.lock();
    state.group_count
}

/// Create ADUC window
pub fn create_aduc_dialog(parent: HWND) -> HWND {
    if !ADUC_INITIALIZED.load(Ordering::SeqCst) {
        init();
    }

    let id = 0xAD0C0000u32;
    let _parent = parent;

    UserHandle::from_raw(id)
}

/// Dialog messages
pub mod messages {
    pub const ADUC_REFRESH: u32 = 0x0700;
    pub const ADUC_CONNECT: u32 = 0x0701;
    pub const ADUC_CREATE_USER: u32 = 0x0702;
    pub const ADUC_CREATE_COMPUTER: u32 = 0x0703;
    pub const ADUC_CREATE_GROUP: u32 = 0x0704;
    pub const ADUC_CREATE_OU: u32 = 0x0705;
    pub const ADUC_DELETE_OBJECT: u32 = 0x0706;
    pub const ADUC_PROPERTIES: u32 = 0x0707;
    pub const ADUC_RESET_PASSWORD: u32 = 0x0708;
    pub const ADUC_ENABLE_ACCOUNT: u32 = 0x0709;
    pub const ADUC_DISABLE_ACCOUNT: u32 = 0x070A;
    pub const ADUC_MOVE_OBJECT: u32 = 0x070B;
    pub const ADUC_FIND: u32 = 0x070C;
}

/// Get statistics
pub fn get_statistics() -> (usize, usize, usize, u32) {
    let state = ADUC_STATE.lock();
    let op_count = ADUC_OPERATION_COUNT.load(Ordering::Relaxed);
    (state.user_count, state.computer_count, state.group_count, op_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aduc_init() {
        init();
        assert!(ADUC_INITIALIZED.load(Ordering::SeqCst));
    }

    #[test]
    fn test_group_type() {
        assert!(GroupType::GlobalSecurity.is_security());
        assert!(!GroupType::GlobalDistribution.is_security());
    }

    #[test]
    fn test_uac_flags() {
        let uac = UserAccountControl::NORMAL_ACCOUNT | UserAccountControl::ACCOUNTDISABLE;
        assert!(uac.contains(UserAccountControl::ACCOUNTDISABLE));
    }
}
