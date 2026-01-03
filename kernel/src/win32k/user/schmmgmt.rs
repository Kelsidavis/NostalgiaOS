//! Active Directory Schema (schmmgmt.msc) implementation
//!
//! Provides management of Active Directory schema classes and attributes.
//! Note: This snap-in must be registered before use (regsvr32 schmmgmt.dll).

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use crate::win32k::user::UserHandle;

/// Local type alias for window handles
type HWND = UserHandle;

/// Maximum classes
const MAX_CLASSES: usize = 256;

/// Maximum attributes
const MAX_ATTRIBUTES: usize = 512;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum OID length
const MAX_OID_LEN: usize = 128;

/// Maximum DN length
const MAX_DN_LEN: usize = 256;

/// Attribute syntax type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AttributeSyntax {
    /// Boolean
    Boolean = 1,
    /// Integer
    Integer = 2,
    /// Large Integer (Int64)
    LargeInteger = 3,
    /// Object(DS-DN) - Distinguished Name
    DnString = 4,
    /// String (Unicode)
    UnicodeString = 5,
    /// String (IA5/ASCII)
    Ia5String = 6,
    /// String (Printable)
    PrintableString = 7,
    /// String (Numeric)
    NumericString = 8,
    /// Object(Replica-Link)
    ReplicaLink = 9,
    /// Case-sensitive string
    CaseSensitiveString = 10,
    /// Generalized time
    GeneralizedTime = 11,
    /// UTC time
    UtcTime = 12,
    /// Octet string (binary)
    OctetString = 13,
    /// SID
    Sid = 14,
    /// NT Security Descriptor
    NtSecurityDescriptor = 15,
    /// Access point
    AccessPoint = 16,
    /// Presentation address
    PresentationAddress = 17,
    /// DN with binary
    DnBinary = 18,
    /// DN with string
    DnWithString = 19,
    /// DSDN (Object DN)
    ObjectDn = 20,
}

impl AttributeSyntax {
    /// Create new syntax
    pub const fn new() -> Self {
        Self::UnicodeString
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Boolean => "Boolean",
            Self::Integer => "Integer",
            Self::LargeInteger => "Large Integer",
            Self::DnString => "Distinguished Name",
            Self::UnicodeString => "Unicode String",
            Self::Ia5String => "IA5-String",
            Self::PrintableString => "Printable String",
            Self::NumericString => "Numeric String",
            Self::ReplicaLink => "Replica Link",
            Self::CaseSensitiveString => "Case Sensitive String",
            Self::GeneralizedTime => "Generalized-Time",
            Self::UtcTime => "UTC-Time",
            Self::OctetString => "Octet String",
            Self::Sid => "SID",
            Self::NtSecurityDescriptor => "NT Security Descriptor",
            Self::AccessPoint => "Access Point",
            Self::PresentationAddress => "Presentation Address",
            Self::DnBinary => "DN with Binary",
            Self::DnWithString => "DN with String",
            Self::ObjectDn => "Object DN",
        }
    }
}

impl Default for AttributeSyntax {
    fn default() -> Self {
        Self::new()
    }
}

/// Schema object category
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ObjectCategory {
    /// Class (structural, abstract, auxiliary)
    ClassSchema = 0,
    /// Attribute
    AttributeSchema = 1,
}

impl ObjectCategory {
    /// Create new category
    pub const fn new() -> Self {
        Self::ClassSchema
    }
}

impl Default for ObjectCategory {
    fn default() -> Self {
        Self::new()
    }
}

/// Class type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ClassType {
    /// Structural class (can create instances)
    Structural = 1,
    /// Abstract class (cannot create instances)
    Abstract = 2,
    /// Auxiliary class (can be added to other classes)
    Auxiliary = 3,
    /// Type 88 class (X.500 compatible)
    Type88 = 0,
}

impl ClassType {
    /// Create new class type
    pub const fn new() -> Self {
        Self::Structural
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Structural => "Structural",
            Self::Abstract => "Abstract",
            Self::Auxiliary => "Auxiliary",
            Self::Type88 => "88 Class",
        }
    }
}

impl Default for ClassType {
    fn default() -> Self {
        Self::new()
    }
}

// Search flags for attributes
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SearchFlags: u32 {
        /// Attribute is indexed
        const INDEX = 0x00000001;
        /// Attribute is indexed in container
        const INDEX_CONTAINER = 0x00000002;
        /// Preserve on delete
        const PRESERVE_ON_DELETE = 0x00000008;
        /// Copy on new parent
        const COPY_ON_PARENT = 0x00000010;
        /// Tuple indexing
        const TUPLE_INDEX = 0x00000020;
        /// Subtree indexing
        const SUBTREE_INDEX = 0x00000040;
        /// Confidential attribute
        const CONFIDENTIAL = 0x00000080;
        /// Do not audit
        const NEVER_AUDIT = 0x00000100;
        /// RODCs filter
        const RODC_FILTER = 0x00000200;
    }
}

impl Default for SearchFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// System flags for schema objects
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SystemFlags: u32 {
        /// Object is not replicated
        const NOT_REPLICATED = 0x00000001;
        /// Attribute is constructed (computed)
        const CONSTRUCTED = 0x00000004;
        /// Category 1 (base schema)
        const BASE_SCHEMA = 0x00000010;
        /// Cannot be deleted
        const DISALLOW_DELETE = 0x80000000;
        /// Cannot be renamed
        const DISALLOW_RENAME = 0x40000000;
        /// Cannot be moved
        const DISALLOW_MOVE = 0x20000000;
    }
}

impl Default for SystemFlags {
    fn default() -> Self {
        Self::empty()
    }
}

/// Schema attribute definition
#[derive(Clone)]
pub struct SchemaAttribute {
    /// Attribute ID (internal)
    pub attr_id: u32,
    /// LDAP display name
    pub ldap_name: [u8; MAX_NAME_LEN],
    /// LDAP name length
    pub ldap_len: usize,
    /// Common name
    pub cn: [u8; MAX_NAME_LEN],
    /// CN length
    pub cn_len: usize,
    /// Admin display name
    pub admin_name: [u8; MAX_NAME_LEN],
    /// Admin name length
    pub admin_len: usize,
    /// OID (attributeID)
    pub oid: [u8; MAX_OID_LEN],
    /// OID length
    pub oid_len: usize,
    /// Syntax
    pub syntax: AttributeSyntax,
    /// OM syntax
    pub om_syntax: u32,
    /// Is single valued
    pub single_valued: bool,
    /// Is indexed (searchFlags contains INDEX)
    pub indexed: bool,
    /// Is ANR (Ambiguous Name Resolution)
    pub anr: bool,
    /// Reserved
    pub reserved: u8,
    /// Search flags
    pub search_flags: SearchFlags,
    /// System flags
    pub system_flags: SystemFlags,
    /// Range lower
    pub range_lower: u32,
    /// Range upper
    pub range_upper: u32,
    /// Is system only
    pub system_only: bool,
    /// Show in advanced view only
    pub show_advanced: bool,
    /// Is defunct (marked for removal)
    pub is_defunct: bool,
    /// Is GC replicated
    pub gc_replicated: bool,
    /// Schema ID GUID
    pub schema_id_guid: [u8; 16],
    /// Link ID (for linked attributes)
    pub link_id: u32,
    /// In use flag
    pub in_use: bool,
}

impl SchemaAttribute {
    /// Create new attribute
    pub const fn new() -> Self {
        Self {
            attr_id: 0,
            ldap_name: [0; MAX_NAME_LEN],
            ldap_len: 0,
            cn: [0; MAX_NAME_LEN],
            cn_len: 0,
            admin_name: [0; MAX_NAME_LEN],
            admin_len: 0,
            oid: [0; MAX_OID_LEN],
            oid_len: 0,
            syntax: AttributeSyntax::UnicodeString,
            om_syntax: 64, // Unicode string
            single_valued: true,
            indexed: false,
            anr: false,
            reserved: 0,
            search_flags: SearchFlags::empty(),
            system_flags: SystemFlags::empty(),
            range_lower: 0,
            range_upper: 0,
            system_only: false,
            show_advanced: false,
            is_defunct: false,
            gc_replicated: false,
            schema_id_guid: [0; 16],
            link_id: 0,
            in_use: false,
        }
    }

    /// Set LDAP name
    pub fn set_ldap_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.ldap_name[..len].copy_from_slice(&name[..len]);
        self.ldap_len = len;
    }

    /// Get LDAP name
    pub fn get_ldap_name(&self) -> &[u8] {
        &self.ldap_name[..self.ldap_len]
    }

    /// Set OID
    pub fn set_oid(&mut self, oid: &[u8]) {
        let len = oid.len().min(MAX_OID_LEN);
        self.oid[..len].copy_from_slice(&oid[..len]);
        self.oid_len = len;
    }

    /// Set CN
    pub fn set_cn(&mut self, cn: &[u8]) {
        let len = cn.len().min(MAX_NAME_LEN);
        self.cn[..len].copy_from_slice(&cn[..len]);
        self.cn_len = len;
    }
}

impl Default for SchemaAttribute {
    fn default() -> Self {
        Self::new()
    }
}

/// Schema class definition
#[derive(Clone)]
pub struct SchemaClass {
    /// Class ID (internal)
    pub class_id: u32,
    /// LDAP display name
    pub ldap_name: [u8; MAX_NAME_LEN],
    /// LDAP name length
    pub ldap_len: usize,
    /// Common name
    pub cn: [u8; MAX_NAME_LEN],
    /// CN length
    pub cn_len: usize,
    /// Admin display name
    pub admin_name: [u8; MAX_NAME_LEN],
    /// Admin name length
    pub admin_len: usize,
    /// OID (governsID)
    pub oid: [u8; MAX_OID_LEN],
    /// OID length
    pub oid_len: usize,
    /// Class type
    pub class_type: ClassType,
    /// System flags
    pub system_flags: SystemFlags,
    /// Parent class ID (subClassOf)
    pub parent_class: u32,
    /// Auxiliary classes (IDs)
    pub auxiliary_classes: [u32; 16],
    /// Auxiliary class count
    pub aux_count: usize,
    /// Must contain (mandatory attribute IDs)
    pub must_contain: [u32; 32],
    /// Must contain count
    pub must_count: usize,
    /// May contain (optional attribute IDs)
    pub may_contain: [u32; 64],
    /// May contain count
    pub may_count: usize,
    /// Possible superiors (class IDs)
    pub poss_superiors: [u32; 32],
    /// Possible superiors count
    pub poss_count: usize,
    /// Default security descriptor
    pub default_sd: [u8; 128],
    /// Default SD length
    pub sd_len: usize,
    /// Is system only
    pub system_only: bool,
    /// Show in advanced view only
    pub show_advanced: bool,
    /// Is defunct
    pub is_defunct: bool,
    /// Default hiding value
    pub default_hiding: bool,
    /// Schema ID GUID
    pub schema_id_guid: [u8; 16],
    /// RDN attribute ID
    pub rdn_attr_id: u32,
    /// In use flag
    pub in_use: bool,
}

impl SchemaClass {
    /// Create new class
    pub const fn new() -> Self {
        Self {
            class_id: 0,
            ldap_name: [0; MAX_NAME_LEN],
            ldap_len: 0,
            cn: [0; MAX_NAME_LEN],
            cn_len: 0,
            admin_name: [0; MAX_NAME_LEN],
            admin_len: 0,
            oid: [0; MAX_OID_LEN],
            oid_len: 0,
            class_type: ClassType::Structural,
            system_flags: SystemFlags::empty(),
            parent_class: 0,
            auxiliary_classes: [0; 16],
            aux_count: 0,
            must_contain: [0; 32],
            must_count: 0,
            may_contain: [0; 64],
            may_count: 0,
            poss_superiors: [0; 32],
            poss_count: 0,
            default_sd: [0; 128],
            sd_len: 0,
            system_only: false,
            show_advanced: false,
            is_defunct: false,
            default_hiding: false,
            schema_id_guid: [0; 16],
            rdn_attr_id: 0,
            in_use: false,
        }
    }

    /// Set LDAP name
    pub fn set_ldap_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.ldap_name[..len].copy_from_slice(&name[..len]);
        self.ldap_len = len;
    }

    /// Get LDAP name
    pub fn get_ldap_name(&self) -> &[u8] {
        &self.ldap_name[..self.ldap_len]
    }

    /// Set OID
    pub fn set_oid(&mut self, oid: &[u8]) {
        let len = oid.len().min(MAX_OID_LEN);
        self.oid[..len].copy_from_slice(&oid[..len]);
        self.oid_len = len;
    }

    /// Add mandatory attribute
    pub fn add_must_contain(&mut self, attr_id: u32) -> bool {
        if self.must_count >= 32 {
            return false;
        }
        self.must_contain[self.must_count] = attr_id;
        self.must_count += 1;
        true
    }

    /// Add optional attribute
    pub fn add_may_contain(&mut self, attr_id: u32) -> bool {
        if self.may_count >= 64 {
            return false;
        }
        self.may_contain[self.may_count] = attr_id;
        self.may_count += 1;
        true
    }
}

impl Default for SchemaClass {
    fn default() -> Self {
        Self::new()
    }
}

/// Schema state
pub struct SchemaState {
    /// Schema attributes
    pub attributes: [SchemaAttribute; MAX_ATTRIBUTES],
    /// Attribute count
    pub attr_count: usize,
    /// Schema classes
    pub classes: [SchemaClass; MAX_CLASSES],
    /// Class count
    pub class_count: usize,
    /// Next ID
    pub next_id: u32,
    /// Schema master DN
    pub schema_master: [u8; MAX_DN_LEN],
    /// Schema master length
    pub master_len: usize,
    /// Is schema master
    pub is_master: bool,
    /// Schema is extensible
    pub extensible: bool,
    /// Reserved
    pub reserved: [u8; 2],
    /// Object version
    pub object_version: u32,
    /// Schema update allowed
    pub update_allowed: bool,
}

impl SchemaState {
    /// Create new state
    pub const fn new() -> Self {
        Self {
            attributes: [const { SchemaAttribute::new() }; MAX_ATTRIBUTES],
            attr_count: 0,
            classes: [const { SchemaClass::new() }; MAX_CLASSES],
            class_count: 0,
            next_id: 1,
            schema_master: [0; MAX_DN_LEN],
            master_len: 0,
            is_master: false,
            extensible: true,
            reserved: [0; 2],
            object_version: 30, // Windows 2003 schema
            update_allowed: true,
        }
    }

    /// Find attribute by LDAP name
    pub fn find_attribute(&self, ldap_name: &[u8]) -> Option<usize> {
        for (i, attr) in self.attributes.iter().enumerate() {
            if attr.in_use && &attr.ldap_name[..attr.ldap_len] == ldap_name {
                return Some(i);
            }
        }
        None
    }

    /// Find class by LDAP name
    pub fn find_class(&self, ldap_name: &[u8]) -> Option<usize> {
        for (i, class) in self.classes.iter().enumerate() {
            if class.in_use && &class.ldap_name[..class.ldap_len] == ldap_name {
                return Some(i);
            }
        }
        None
    }

    /// Find attribute by ID
    pub fn find_attribute_by_id(&self, attr_id: u32) -> Option<usize> {
        for (i, attr) in self.attributes.iter().enumerate() {
            if attr.in_use && attr.attr_id == attr_id {
                return Some(i);
            }
        }
        None
    }

    /// Find class by ID
    pub fn find_class_by_id(&self, class_id: u32) -> Option<usize> {
        for (i, class) in self.classes.iter().enumerate() {
            if class.in_use && class.class_id == class_id {
                return Some(i);
            }
        }
        None
    }
}

impl Default for SchemaState {
    fn default() -> Self {
        Self::new()
    }
}

/// Global state
static SCHEMA_STATE: SpinLock<SchemaState> = SpinLock::new(SchemaState::new());

/// Initialization flag
static SCHEMA_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Statistics
static SCHEMA_OPERATION_COUNT: AtomicU32 = AtomicU32::new(0);

/// Error codes
pub mod error {
    pub const SUCCESS: u32 = 0;
    pub const NOT_INITIALIZED: u32 = 0x5C000001;
    pub const NOT_SCHEMA_MASTER: u32 = 0x5C000002;
    pub const ATTRIBUTE_NOT_FOUND: u32 = 0x5C000003;
    pub const CLASS_NOT_FOUND: u32 = 0x5C000004;
    pub const ALREADY_EXISTS: u32 = 0x5C000005;
    pub const INVALID_OID: u32 = 0x5C000006;
    pub const INVALID_SYNTAX: u32 = 0x5C000007;
    pub const UPDATE_NOT_ALLOWED: u32 = 0x5C000008;
    pub const NO_MORE_OBJECTS: u32 = 0x5C000009;
    pub const SYSTEM_OBJECT: u32 = 0x5C00000A;
}

/// Initialize schema manager
pub fn init() {
    if SCHEMA_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = SCHEMA_STATE.lock();

    // Set schema master
    let master = b"CN=DC1,CN=Schema,CN=Configuration,DC=forest,DC=local";
    let len = master.len().min(MAX_DN_LEN);
    state.schema_master[..len].copy_from_slice(&master[..len]);
    state.master_len = len;
    state.is_master = true;

    // Create some base attributes
    let cn_id = state.next_id;
    state.next_id += 1;
    let cn_attr = &mut state.attributes[0];
    cn_attr.in_use = true;
    cn_attr.attr_id = cn_id;
    cn_attr.set_ldap_name(b"cn");
    cn_attr.set_cn(b"Common-Name");
    cn_attr.syntax = AttributeSyntax::UnicodeString;
    cn_attr.single_valued = true;
    cn_attr.indexed = true;
    cn_attr.anr = true;
    cn_attr.search_flags = SearchFlags::INDEX | SearchFlags::INDEX_CONTAINER;
    cn_attr.system_flags = SystemFlags::BASE_SCHEMA;
    cn_attr.system_only = false;

    let dn_id = state.next_id;
    state.next_id += 1;
    let dn_attr = &mut state.attributes[1];
    dn_attr.in_use = true;
    dn_attr.attr_id = dn_id;
    dn_attr.set_ldap_name(b"distinguishedName");
    dn_attr.set_cn(b"Distinguished-Name");
    dn_attr.syntax = AttributeSyntax::DnString;
    dn_attr.single_valued = true;
    dn_attr.system_flags = SystemFlags::BASE_SCHEMA | SystemFlags::CONSTRUCTED;
    dn_attr.system_only = true;

    let obj_class_id = state.next_id;
    state.next_id += 1;
    let obj_attr = &mut state.attributes[2];
    obj_attr.in_use = true;
    obj_attr.attr_id = obj_class_id;
    obj_attr.set_ldap_name(b"objectClass");
    obj_attr.set_cn(b"Object-Class");
    obj_attr.syntax = AttributeSyntax::ObjectDn;
    obj_attr.single_valued = false;
    obj_attr.system_flags = SystemFlags::BASE_SCHEMA;
    obj_attr.system_only = true;

    state.attr_count = 3;

    // Create base class: top
    let top_id = state.next_id;
    state.next_id += 1;
    let top_class = &mut state.classes[0];
    top_class.in_use = true;
    top_class.class_id = top_id;
    top_class.set_ldap_name(b"top");
    top_class.class_type = ClassType::Abstract;
    top_class.system_flags = SystemFlags::BASE_SCHEMA;
    top_class.system_only = true;
    top_class.must_contain[0] = obj_class_id;
    top_class.must_count = 1;

    // Create user class
    let user_id = state.next_id;
    state.next_id += 1;
    let user_class = &mut state.classes[1];
    user_class.in_use = true;
    user_class.class_id = user_id;
    user_class.set_ldap_name(b"user");
    user_class.class_type = ClassType::Structural;
    user_class.parent_class = top_id;
    user_class.system_flags = SystemFlags::BASE_SCHEMA;
    user_class.must_contain[0] = cn_id;
    user_class.must_count = 1;

    state.class_count = 2;
}

/// Create a new attribute
pub fn create_attribute(
    ldap_name: &[u8],
    oid: &[u8],
    syntax: AttributeSyntax,
    single_valued: bool,
) -> Result<u32, u32> {
    if !SCHEMA_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = SCHEMA_STATE.lock();

    if !state.is_master {
        return Err(error::NOT_SCHEMA_MASTER);
    }

    if !state.update_allowed {
        return Err(error::UPDATE_NOT_ALLOWED);
    }

    // Check if already exists
    if state.find_attribute(ldap_name).is_some() {
        return Err(error::ALREADY_EXISTS);
    }

    // Find free slot
    let mut slot_idx = None;
    for (i, attr) in state.attributes.iter().enumerate() {
        if !attr.in_use {
            slot_idx = Some(i);
            break;
        }
    }

    let idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::NO_MORE_OBJECTS),
    };

    let attr_id = state.next_id;
    state.next_id += 1;

    let attr = &mut state.attributes[idx];
    attr.in_use = true;
    attr.attr_id = attr_id;
    attr.set_ldap_name(ldap_name);
    attr.set_oid(oid);
    attr.syntax = syntax;
    attr.single_valued = single_valued;

    state.attr_count += 1;
    SCHEMA_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(attr_id)
}

/// Mark attribute as defunct
pub fn deactivate_attribute(attr_id: u32) -> Result<(), u32> {
    if !SCHEMA_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = SCHEMA_STATE.lock();

    if !state.is_master {
        return Err(error::NOT_SCHEMA_MASTER);
    }

    let idx = match state.find_attribute_by_id(attr_id) {
        Some(i) => i,
        None => return Err(error::ATTRIBUTE_NOT_FOUND),
    };

    if state.attributes[idx].system_flags.contains(SystemFlags::BASE_SCHEMA) {
        return Err(error::SYSTEM_OBJECT);
    }

    state.attributes[idx].is_defunct = true;

    SCHEMA_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Create a new class
pub fn create_class(
    ldap_name: &[u8],
    oid: &[u8],
    class_type: ClassType,
    parent_class: u32,
) -> Result<u32, u32> {
    if !SCHEMA_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = SCHEMA_STATE.lock();

    if !state.is_master {
        return Err(error::NOT_SCHEMA_MASTER);
    }

    if !state.update_allowed {
        return Err(error::UPDATE_NOT_ALLOWED);
    }

    // Check if already exists
    if state.find_class(ldap_name).is_some() {
        return Err(error::ALREADY_EXISTS);
    }

    // Verify parent class exists
    if parent_class != 0 && state.find_class_by_id(parent_class).is_none() {
        return Err(error::CLASS_NOT_FOUND);
    }

    // Find free slot
    let mut slot_idx = None;
    for (i, class) in state.classes.iter().enumerate() {
        if !class.in_use {
            slot_idx = Some(i);
            break;
        }
    }

    let idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::NO_MORE_OBJECTS),
    };

    let class_id = state.next_id;
    state.next_id += 1;

    let class = &mut state.classes[idx];
    class.in_use = true;
    class.class_id = class_id;
    class.set_ldap_name(ldap_name);
    class.set_oid(oid);
    class.class_type = class_type;
    class.parent_class = parent_class;

    state.class_count += 1;
    SCHEMA_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(class_id)
}

/// Mark class as defunct
pub fn deactivate_class(class_id: u32) -> Result<(), u32> {
    if !SCHEMA_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = SCHEMA_STATE.lock();

    if !state.is_master {
        return Err(error::NOT_SCHEMA_MASTER);
    }

    let idx = match state.find_class_by_id(class_id) {
        Some(i) => i,
        None => return Err(error::CLASS_NOT_FOUND),
    };

    if state.classes[idx].system_flags.contains(SystemFlags::BASE_SCHEMA) {
        return Err(error::SYSTEM_OBJECT);
    }

    state.classes[idx].is_defunct = true;

    SCHEMA_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Add attribute to class may contain
pub fn add_class_attribute(class_id: u32, attr_id: u32, mandatory: bool) -> Result<(), u32> {
    if !SCHEMA_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = SCHEMA_STATE.lock();

    // Verify attribute exists
    if state.find_attribute_by_id(attr_id).is_none() {
        return Err(error::ATTRIBUTE_NOT_FOUND);
    }

    let idx = match state.find_class_by_id(class_id) {
        Some(i) => i,
        None => return Err(error::CLASS_NOT_FOUND),
    };

    if mandatory {
        if !state.classes[idx].add_must_contain(attr_id) {
            return Err(error::NO_MORE_OBJECTS);
        }
    } else {
        if !state.classes[idx].add_may_contain(attr_id) {
            return Err(error::NO_MORE_OBJECTS);
        }
    }

    SCHEMA_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Reload schema
pub fn reload_schema() -> Result<(), u32> {
    if !SCHEMA_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    // In real implementation, would reload from AD
    SCHEMA_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Get attribute count
pub fn get_attribute_count() -> usize {
    if !SCHEMA_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = SCHEMA_STATE.lock();
    state.attr_count
}

/// Get class count
pub fn get_class_count() -> usize {
    if !SCHEMA_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = SCHEMA_STATE.lock();
    state.class_count
}

/// Create Schema Manager window
pub fn create_schema_dialog(parent: HWND) -> HWND {
    if !SCHEMA_INITIALIZED.load(Ordering::SeqCst) {
        init();
    }

    let id = 0x5C4E0000u32;
    let _parent = parent;

    UserHandle::from_raw(id)
}

/// Dialog messages
pub mod messages {
    pub const SCHEMA_REFRESH: u32 = 0x0800;
    pub const SCHEMA_CREATE_ATTRIBUTE: u32 = 0x0801;
    pub const SCHEMA_CREATE_CLASS: u32 = 0x0802;
    pub const SCHEMA_DEACTIVATE: u32 = 0x0803;
    pub const SCHEMA_PROPERTIES: u32 = 0x0804;
    pub const SCHEMA_RELOAD: u32 = 0x0805;
    pub const SCHEMA_OPERATIONS_MASTER: u32 = 0x0806;
    pub const SCHEMA_PERMISSIONS: u32 = 0x0807;
}

/// Get statistics
pub fn get_statistics() -> (usize, usize, u32) {
    let state = SCHEMA_STATE.lock();
    let op_count = SCHEMA_OPERATION_COUNT.load(Ordering::Relaxed);
    (state.attr_count, state.class_count, op_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_init() {
        init();
        assert!(SCHEMA_INITIALIZED.load(Ordering::SeqCst));
    }

    #[test]
    fn test_syntax_display() {
        assert_eq!(AttributeSyntax::Boolean.display_name(), "Boolean");
    }

    #[test]
    fn test_class_type() {
        assert_eq!(ClassType::Structural.display_name(), "Structural");
    }
}
