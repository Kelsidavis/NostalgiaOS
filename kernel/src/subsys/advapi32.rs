//! Advapi32.dll Stub Implementation
//!
//! Advanced Windows 32 Base APIs - Security, Registry, Services, Cryptography.
//! These wrap syscalls to kernel security and registry subsystems.

use core::ptr;

/// Syscall numbers for security/registry services
mod syscall {
    // Registry
    pub const NtOpenKey: u32 = 0x0077;
    pub const NtCreateKey: u32 = 0x001D;
    pub const NtDeleteKey: u32 = 0x003F;
    pub const NtQueryKey: u32 = 0x0013;
    pub const NtSetValueKey: u32 = 0x0061;
    pub const NtQueryValueKey: u32 = 0x0017;
    pub const NtDeleteValueKey: u32 = 0x0041;
    pub const NtEnumerateKey: u32 = 0x0047;
    pub const NtEnumerateValueKey: u32 = 0x0049;
    pub const NtFlushKey: u32 = 0x004B;
    pub const NtClose: u32 = 0x000C;

    // Security
    pub const NtOpenProcessToken: u32 = 0x0076;
    pub const NtOpenThreadToken: u32 = 0x0078;
    pub const NtDuplicateToken: u32 = 0x0043;
    pub const NtQueryInformationToken: u32 = 0x0020;
    pub const NtSetInformationToken: u32 = 0x0096;
    pub const NtAdjustPrivilegesToken: u32 = 0x0003;
    pub const NtAdjustGroupsToken: u32 = 0x0002;
    pub const NtCreateToken: u32 = 0x001F;
    pub const NtPrivilegeCheck: u32 = 0x0085;
    pub const NtAccessCheck: u32 = 0x0001;
    pub const NtImpersonateAnonymousToken: u32 = 0x0056;
    pub const NtSetSecurityObject: u32 = 0x0097;
    pub const NtQuerySecurityObject: u32 = 0x0093;

    // SID operations
    pub const RtlInitializeSid: u32 = 0x1100;
    pub const RtlLengthSid: u32 = 0x1101;
    pub const RtlEqualSid: u32 = 0x1102;
    pub const RtlCopySid: u32 = 0x1103;
    pub const RtlConvertSidToUnicodeString: u32 = 0x1104;

    // Service Control Manager (SCM)
    pub const NtOpenSCManager: u32 = 0x3000;
    pub const NtCreateService: u32 = 0x3001;
    pub const NtOpenService: u32 = 0x3002;
    pub const NtDeleteService: u32 = 0x3003;
    pub const NtStartService: u32 = 0x3004;
    pub const NtControlService: u32 = 0x3005;
    pub const NtQueryServiceStatus: u32 = 0x3006;
    pub const NtQueryServiceConfig: u32 = 0x3007;
    pub const NtChangeServiceConfig: u32 = 0x3008;
    pub const NtEnumServicesStatus: u32 = 0x3009;
    pub const NtCloseServiceHandle: u32 = 0x300A;

    // Event Log
    pub const NtOpenEventLog: u32 = 0x3100;
    pub const NtCloseEventLog: u32 = 0x3101;
    pub const NtReadEventLog: u32 = 0x3102;
    pub const NtReportEvent: u32 = 0x3103;
    pub const NtClearEventLog: u32 = 0x3104;
    pub const NtGetNumberOfEventLogRecords: u32 = 0x3105;
    pub const NtBackupEventLog: u32 = 0x3106;

    // Cryptography
    pub const NtCryptAcquireContext: u32 = 0x4000;
    pub const NtCryptReleaseContext: u32 = 0x4001;
    pub const NtCryptGenKey: u32 = 0x4002;
    pub const NtCryptDeriveKey: u32 = 0x4003;
    pub const NtCryptDestroyKey: u32 = 0x4004;
    pub const NtCryptExportKey: u32 = 0x4005;
    pub const NtCryptImportKey: u32 = 0x4006;
    pub const NtCryptEncrypt: u32 = 0x4007;
    pub const NtCryptDecrypt: u32 = 0x4008;
    pub const NtCryptCreateHash: u32 = 0x4009;
    pub const NtCryptHashData: u32 = 0x400A;
    pub const NtCryptDestroyHash: u32 = 0x400B;
    pub const NtCryptSignHash: u32 = 0x400C;
    pub const NtCryptVerifySignature: u32 = 0x400D;
    pub const NtCryptGenRandom: u32 = 0x400E;

    // LSA (Local Security Authority)
    pub const NtLsaOpenPolicy: u32 = 0x5000;
    pub const NtLsaClose: u32 = 0x5001;
    pub const NtLsaQueryInformationPolicy: u32 = 0x5002;
    pub const NtLsaSetInformationPolicy: u32 = 0x5003;
    pub const NtLsaEnumerateAccounts: u32 = 0x5004;
    pub const NtLsaLookupNames: u32 = 0x5005;
    pub const NtLsaLookupSids: u32 = 0x5006;
    pub const NtLsaAddAccountRights: u32 = 0x5007;
    pub const NtLsaRemoveAccountRights: u32 = 0x5008;
    pub const NtLsaEnumerateAccountRights: u32 = 0x5009;
}

/// Make a syscall
#[inline(always)]
unsafe fn do_syscall(num: u32, args: &[u64]) -> u64 {
    let result: u64;

    match args.len() {
        0 => {
            core::arch::asm!(
                "syscall",
                in("rax") num as u64,
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        1 => {
            core::arch::asm!(
                "syscall",
                in("rax") num as u64,
                in("rdi") args[0],
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        2 => {
            core::arch::asm!(
                "syscall",
                in("rax") num as u64,
                in("rdi") args[0],
                in("rsi") args[1],
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        3 => {
            core::arch::asm!(
                "syscall",
                in("rax") num as u64,
                in("rdi") args[0],
                in("rsi") args[1],
                in("rdx") args[2],
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        4 => {
            core::arch::asm!(
                "syscall",
                in("rax") num as u64,
                in("rdi") args[0],
                in("rsi") args[1],
                in("rdx") args[2],
                in("r10") args[3],
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        5 => {
            core::arch::asm!(
                "syscall",
                in("rax") num as u64,
                in("rdi") args[0],
                in("rsi") args[1],
                in("rdx") args[2],
                in("r10") args[3],
                in("r8") args[4],
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        _ => {
            core::arch::asm!(
                "syscall",
                in("rax") num as u64,
                in("rdi") args[0],
                in("rsi") args[1],
                in("rdx") args[2],
                in("r10") args[3],
                in("r8") args[4],
                in("r9") args[5],
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
    }
    result
}

// Type definitions
pub type HANDLE = u64;
pub type HKEY = u64;
pub type PHKEY = *mut HKEY;
pub type SC_HANDLE = u64;
pub type HCRYPTPROV = u64;
pub type HCRYPTKEY = u64;
pub type HCRYPTHASH = u64;
pub type DWORD = u32;
pub type BOOL = i32;
pub type LONG = i32;
pub type REGSAM = u32;
pub type LSTATUS = LONG;

pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;
pub const ERROR_SUCCESS: LSTATUS = 0;

// Predefined registry keys
pub const HKEY_CLASSES_ROOT: HKEY = 0x80000000;
pub const HKEY_CURRENT_USER: HKEY = 0x80000001;
pub const HKEY_LOCAL_MACHINE: HKEY = 0x80000002;
pub const HKEY_USERS: HKEY = 0x80000003;
pub const HKEY_PERFORMANCE_DATA: HKEY = 0x80000004;
pub const HKEY_CURRENT_CONFIG: HKEY = 0x80000005;
pub const HKEY_DYN_DATA: HKEY = 0x80000006;

// Registry access rights
pub const KEY_QUERY_VALUE: REGSAM = 0x0001;
pub const KEY_SET_VALUE: REGSAM = 0x0002;
pub const KEY_CREATE_SUB_KEY: REGSAM = 0x0004;
pub const KEY_ENUMERATE_SUB_KEYS: REGSAM = 0x0008;
pub const KEY_NOTIFY: REGSAM = 0x0010;
pub const KEY_CREATE_LINK: REGSAM = 0x0020;
pub const KEY_WOW64_32KEY: REGSAM = 0x0200;
pub const KEY_WOW64_64KEY: REGSAM = 0x0100;
pub const KEY_READ: REGSAM = 0x20019;
pub const KEY_WRITE: REGSAM = 0x20006;
pub const KEY_EXECUTE: REGSAM = 0x20019;
pub const KEY_ALL_ACCESS: REGSAM = 0xF003F;

// Registry value types
pub const REG_NONE: DWORD = 0;
pub const REG_SZ: DWORD = 1;
pub const REG_EXPAND_SZ: DWORD = 2;
pub const REG_BINARY: DWORD = 3;
pub const REG_DWORD: DWORD = 4;
pub const REG_DWORD_LITTLE_ENDIAN: DWORD = 4;
pub const REG_DWORD_BIG_ENDIAN: DWORD = 5;
pub const REG_LINK: DWORD = 6;
pub const REG_MULTI_SZ: DWORD = 7;
pub const REG_RESOURCE_LIST: DWORD = 8;
pub const REG_QWORD: DWORD = 11;

// Registry create/open options
pub const REG_OPTION_NON_VOLATILE: DWORD = 0;
pub const REG_OPTION_VOLATILE: DWORD = 1;
pub const REG_OPTION_CREATE_LINK: DWORD = 2;
pub const REG_OPTION_BACKUP_RESTORE: DWORD = 4;
pub const REG_OPTION_OPEN_LINK: DWORD = 8;

// Registry create disposition
pub const REG_CREATED_NEW_KEY: DWORD = 1;
pub const REG_OPENED_EXISTING_KEY: DWORD = 2;

// Service Control Manager access rights
pub const SC_MANAGER_CONNECT: DWORD = 0x0001;
pub const SC_MANAGER_CREATE_SERVICE: DWORD = 0x0002;
pub const SC_MANAGER_ENUMERATE_SERVICE: DWORD = 0x0004;
pub const SC_MANAGER_LOCK: DWORD = 0x0008;
pub const SC_MANAGER_QUERY_LOCK_STATUS: DWORD = 0x0010;
pub const SC_MANAGER_MODIFY_BOOT_CONFIG: DWORD = 0x0020;
pub const SC_MANAGER_ALL_ACCESS: DWORD = 0xF003F;

// Service access rights
pub const SERVICE_QUERY_CONFIG: DWORD = 0x0001;
pub const SERVICE_CHANGE_CONFIG: DWORD = 0x0002;
pub const SERVICE_QUERY_STATUS: DWORD = 0x0004;
pub const SERVICE_ENUMERATE_DEPENDENTS: DWORD = 0x0008;
pub const SERVICE_START: DWORD = 0x0010;
pub const SERVICE_STOP: DWORD = 0x0020;
pub const SERVICE_PAUSE_CONTINUE: DWORD = 0x0040;
pub const SERVICE_INTERROGATE: DWORD = 0x0080;
pub const SERVICE_USER_DEFINED_CONTROL: DWORD = 0x0100;
pub const SERVICE_ALL_ACCESS: DWORD = 0xF01FF;

// Service types
pub const SERVICE_KERNEL_DRIVER: DWORD = 0x00000001;
pub const SERVICE_FILE_SYSTEM_DRIVER: DWORD = 0x00000002;
pub const SERVICE_WIN32_OWN_PROCESS: DWORD = 0x00000010;
pub const SERVICE_WIN32_SHARE_PROCESS: DWORD = 0x00000020;
pub const SERVICE_INTERACTIVE_PROCESS: DWORD = 0x00000100;

// Service start types
pub const SERVICE_BOOT_START: DWORD = 0;
pub const SERVICE_SYSTEM_START: DWORD = 1;
pub const SERVICE_AUTO_START: DWORD = 2;
pub const SERVICE_DEMAND_START: DWORD = 3;
pub const SERVICE_DISABLED: DWORD = 4;

// Service control codes
pub const SERVICE_CONTROL_STOP: DWORD = 1;
pub const SERVICE_CONTROL_PAUSE: DWORD = 2;
pub const SERVICE_CONTROL_CONTINUE: DWORD = 3;
pub const SERVICE_CONTROL_INTERROGATE: DWORD = 4;

// Service states
pub const SERVICE_STOPPED: DWORD = 1;
pub const SERVICE_START_PENDING: DWORD = 2;
pub const SERVICE_STOP_PENDING: DWORD = 3;
pub const SERVICE_RUNNING: DWORD = 4;
pub const SERVICE_CONTINUE_PENDING: DWORD = 5;
pub const SERVICE_PAUSE_PENDING: DWORD = 6;
pub const SERVICE_PAUSED: DWORD = 7;

// Token access rights
pub const TOKEN_ASSIGN_PRIMARY: DWORD = 0x0001;
pub const TOKEN_DUPLICATE: DWORD = 0x0002;
pub const TOKEN_IMPERSONATE: DWORD = 0x0004;
pub const TOKEN_QUERY: DWORD = 0x0008;
pub const TOKEN_QUERY_SOURCE: DWORD = 0x0010;
pub const TOKEN_ADJUST_PRIVILEGES: DWORD = 0x0020;
pub const TOKEN_ADJUST_GROUPS: DWORD = 0x0040;
pub const TOKEN_ADJUST_DEFAULT: DWORD = 0x0080;
pub const TOKEN_ADJUST_SESSIONID: DWORD = 0x0100;
pub const TOKEN_READ: DWORD = 0x20008;
pub const TOKEN_WRITE: DWORD = 0x200E0;
pub const TOKEN_EXECUTE: DWORD = 0x20000;
pub const TOKEN_ALL_ACCESS: DWORD = 0xF01FF;

// Event log types
pub const EVENTLOG_ERROR_TYPE: u16 = 0x0001;
pub const EVENTLOG_WARNING_TYPE: u16 = 0x0002;
pub const EVENTLOG_INFORMATION_TYPE: u16 = 0x0004;
pub const EVENTLOG_AUDIT_SUCCESS: u16 = 0x0008;
pub const EVENTLOG_AUDIT_FAILURE: u16 = 0x0010;

// Crypto provider types
pub const PROV_RSA_FULL: DWORD = 1;
pub const PROV_RSA_SIG: DWORD = 2;
pub const PROV_DSS: DWORD = 3;
pub const PROV_FORTEZZA: DWORD = 4;
pub const PROV_MS_EXCHANGE: DWORD = 5;
pub const PROV_SSL: DWORD = 6;
pub const PROV_RSA_SCHANNEL: DWORD = 12;
pub const PROV_DSS_DH: DWORD = 13;
pub const PROV_DH_SCHANNEL: DWORD = 18;
pub const PROV_RSA_AES: DWORD = 24;

// Crypto flags
pub const CRYPT_VERIFYCONTEXT: DWORD = 0xF0000000;
pub const CRYPT_NEWKEYSET: DWORD = 0x00000008;
pub const CRYPT_DELETEKEYSET: DWORD = 0x00000010;
pub const CRYPT_MACHINE_KEYSET: DWORD = 0x00000020;
pub const CRYPT_SILENT: DWORD = 0x00000040;

// Algorithm IDs
pub const CALG_MD2: DWORD = 0x00008001;
pub const CALG_MD4: DWORD = 0x00008002;
pub const CALG_MD5: DWORD = 0x00008003;
pub const CALG_SHA: DWORD = 0x00008004;
pub const CALG_SHA1: DWORD = 0x00008004;
pub const CALG_SHA_256: DWORD = 0x0000800C;
pub const CALG_SHA_384: DWORD = 0x0000800D;
pub const CALG_SHA_512: DWORD = 0x0000800E;
pub const CALG_RC2: DWORD = 0x00006602;
pub const CALG_RC4: DWORD = 0x00006801;
pub const CALG_DES: DWORD = 0x00006601;
pub const CALG_3DES: DWORD = 0x00006603;
pub const CALG_AES_128: DWORD = 0x0000660E;
pub const CALG_AES_192: DWORD = 0x0000660F;
pub const CALG_AES_256: DWORD = 0x00006610;
pub const CALG_RSA_SIGN: DWORD = 0x00002400;
pub const CALG_RSA_KEYX: DWORD = 0x0000A400;

#[repr(C)]
pub struct SERVICE_STATUS {
    pub dwServiceType: DWORD,
    pub dwCurrentState: DWORD,
    pub dwControlsAccepted: DWORD,
    pub dwWin32ExitCode: DWORD,
    pub dwServiceSpecificExitCode: DWORD,
    pub dwCheckPoint: DWORD,
    pub dwWaitHint: DWORD,
}

#[repr(C)]
pub struct LUID {
    pub LowPart: DWORD,
    pub HighPart: i32,
}

#[repr(C)]
pub struct LUID_AND_ATTRIBUTES {
    pub Luid: LUID,
    pub Attributes: DWORD,
}

#[repr(C)]
pub struct TOKEN_PRIVILEGES {
    pub PrivilegeCount: DWORD,
    pub Privileges: [LUID_AND_ATTRIBUTES; 1],
}

#[repr(C)]
pub struct SID_IDENTIFIER_AUTHORITY {
    pub Value: [u8; 6],
}

// ============================================================================
// Registry Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn RegOpenKeyExA(
    key: HKEY,
    subkey: *const u8,
    options: DWORD,
    sam_desired: REGSAM,
    result: PHKEY,
) -> LSTATUS {
    do_syscall(syscall::NtOpenKey, &[key, subkey as u64, options as u64, sam_desired as u64, result as u64, 0]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegOpenKeyExW(
    key: HKEY,
    subkey: *const u16,
    options: DWORD,
    sam_desired: REGSAM,
    result: PHKEY,
) -> LSTATUS {
    do_syscall(syscall::NtOpenKey, &[key, subkey as u64, options as u64, sam_desired as u64, result as u64, 1]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegCreateKeyExA(
    key: HKEY,
    subkey: *const u8,
    reserved: DWORD,
    class: *const u8,
    options: DWORD,
    sam_desired: REGSAM,
    security: u64,
    result: PHKEY,
    disposition: *mut DWORD,
) -> LSTATUS {
    let params: [u64; 9] = [
        key, subkey as u64, reserved as u64, class as u64, options as u64,
        sam_desired as u64, security, result as u64, disposition as u64,
    ];
    do_syscall(syscall::NtCreateKey, &[params.as_ptr() as u64, 0]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegCreateKeyExW(
    key: HKEY,
    subkey: *const u16,
    reserved: DWORD,
    class: *const u16,
    options: DWORD,
    sam_desired: REGSAM,
    security: u64,
    result: PHKEY,
    disposition: *mut DWORD,
) -> LSTATUS {
    let params: [u64; 9] = [
        key, subkey as u64, reserved as u64, class as u64, options as u64,
        sam_desired as u64, security, result as u64, disposition as u64,
    ];
    do_syscall(syscall::NtCreateKey, &[params.as_ptr() as u64, 1]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegCloseKey(key: HKEY) -> LSTATUS {
    do_syscall(syscall::NtClose, &[key]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegDeleteKeyA(key: HKEY, subkey: *const u8) -> LSTATUS {
    do_syscall(syscall::NtDeleteKey, &[key, subkey as u64, 0]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegDeleteKeyW(key: HKEY, subkey: *const u16) -> LSTATUS {
    do_syscall(syscall::NtDeleteKey, &[key, subkey as u64, 1]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegSetValueExA(
    key: HKEY,
    value_name: *const u8,
    reserved: DWORD,
    value_type: DWORD,
    data: *const u8,
    data_size: DWORD,
) -> LSTATUS {
    do_syscall(syscall::NtSetValueKey, &[key, value_name as u64, reserved as u64, value_type as u64, data as u64, data_size as u64]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegSetValueExW(
    key: HKEY,
    value_name: *const u16,
    reserved: DWORD,
    value_type: DWORD,
    data: *const u8,
    data_size: DWORD,
) -> LSTATUS {
    let params: [u64; 6] = [key, value_name as u64, reserved as u64, value_type as u64, data as u64, data_size as u64];
    do_syscall(syscall::NtSetValueKey, &[params.as_ptr() as u64, 1]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegQueryValueExA(
    key: HKEY,
    value_name: *const u8,
    reserved: *mut DWORD,
    value_type: *mut DWORD,
    data: *mut u8,
    data_size: *mut DWORD,
) -> LSTATUS {
    let params: [u64; 6] = [key, value_name as u64, reserved as u64, value_type as u64, data as u64, data_size as u64];
    do_syscall(syscall::NtQueryValueKey, &[params.as_ptr() as u64, 0]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegQueryValueExW(
    key: HKEY,
    value_name: *const u16,
    reserved: *mut DWORD,
    value_type: *mut DWORD,
    data: *mut u8,
    data_size: *mut DWORD,
) -> LSTATUS {
    let params: [u64; 6] = [key, value_name as u64, reserved as u64, value_type as u64, data as u64, data_size as u64];
    do_syscall(syscall::NtQueryValueKey, &[params.as_ptr() as u64, 1]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegDeleteValueA(key: HKEY, value_name: *const u8) -> LSTATUS {
    do_syscall(syscall::NtDeleteValueKey, &[key, value_name as u64, 0]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegDeleteValueW(key: HKEY, value_name: *const u16) -> LSTATUS {
    do_syscall(syscall::NtDeleteValueKey, &[key, value_name as u64, 1]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegEnumKeyExA(
    key: HKEY,
    index: DWORD,
    name: *mut u8,
    name_len: *mut DWORD,
    reserved: *mut DWORD,
    class: *mut u8,
    class_len: *mut DWORD,
    last_write_time: *mut u64,
) -> LSTATUS {
    let params: [u64; 8] = [key, index as u64, name as u64, name_len as u64, reserved as u64, class as u64, class_len as u64, last_write_time as u64];
    do_syscall(syscall::NtEnumerateKey, &[params.as_ptr() as u64, 0]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegEnumKeyExW(
    key: HKEY,
    index: DWORD,
    name: *mut u16,
    name_len: *mut DWORD,
    reserved: *mut DWORD,
    class: *mut u16,
    class_len: *mut DWORD,
    last_write_time: *mut u64,
) -> LSTATUS {
    let params: [u64; 8] = [key, index as u64, name as u64, name_len as u64, reserved as u64, class as u64, class_len as u64, last_write_time as u64];
    do_syscall(syscall::NtEnumerateKey, &[params.as_ptr() as u64, 1]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegEnumValueA(
    key: HKEY,
    index: DWORD,
    value_name: *mut u8,
    value_name_len: *mut DWORD,
    reserved: *mut DWORD,
    value_type: *mut DWORD,
    data: *mut u8,
    data_len: *mut DWORD,
) -> LSTATUS {
    let params: [u64; 8] = [key, index as u64, value_name as u64, value_name_len as u64, reserved as u64, value_type as u64, data as u64, data_len as u64];
    do_syscall(syscall::NtEnumerateValueKey, &[params.as_ptr() as u64, 0]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegEnumValueW(
    key: HKEY,
    index: DWORD,
    value_name: *mut u16,
    value_name_len: *mut DWORD,
    reserved: *mut DWORD,
    value_type: *mut DWORD,
    data: *mut u8,
    data_len: *mut DWORD,
) -> LSTATUS {
    let params: [u64; 8] = [key, index as u64, value_name as u64, value_name_len as u64, reserved as u64, value_type as u64, data as u64, data_len as u64];
    do_syscall(syscall::NtEnumerateValueKey, &[params.as_ptr() as u64, 1]) as LSTATUS
}

#[no_mangle]
pub unsafe extern "system" fn RegFlushKey(key: HKEY) -> LSTATUS {
    do_syscall(syscall::NtFlushKey, &[key]) as LSTATUS
}

// ============================================================================
// Security/Token Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn OpenProcessToken(
    process: HANDLE,
    desired_access: DWORD,
    token: *mut HANDLE,
) -> BOOL {
    (do_syscall(syscall::NtOpenProcessToken, &[process, desired_access as u64, token as u64]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn OpenThreadToken(
    thread: HANDLE,
    desired_access: DWORD,
    open_as_self: BOOL,
    token: *mut HANDLE,
) -> BOOL {
    (do_syscall(syscall::NtOpenThreadToken, &[thread, desired_access as u64, open_as_self as u64, token as u64]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn DuplicateToken(
    existing_token: HANDLE,
    impersonation_level: u32,
    new_token: *mut HANDLE,
) -> BOOL {
    (do_syscall(syscall::NtDuplicateToken, &[existing_token, impersonation_level as u64, new_token as u64]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetTokenInformation(
    token: HANDLE,
    info_class: u32,
    info: *mut u8,
    info_len: DWORD,
    return_len: *mut DWORD,
) -> BOOL {
    (do_syscall(syscall::NtQueryInformationToken, &[token, info_class as u64, info as u64, info_len as u64, return_len as u64]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn SetTokenInformation(
    token: HANDLE,
    info_class: u32,
    info: *const u8,
    info_len: DWORD,
) -> BOOL {
    (do_syscall(syscall::NtSetInformationToken, &[token, info_class as u64, info as u64, info_len as u64]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn AdjustTokenPrivileges(
    token: HANDLE,
    disable_all: BOOL,
    new_state: *const TOKEN_PRIVILEGES,
    buffer_len: DWORD,
    previous_state: *mut TOKEN_PRIVILEGES,
    return_len: *mut DWORD,
) -> BOOL {
    let params: [u64; 6] = [token, disable_all as u64, new_state as u64, buffer_len as u64, previous_state as u64, return_len as u64];
    (do_syscall(syscall::NtAdjustPrivilegesToken, &params) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn LookupPrivilegeValueA(
    system_name: *const u8,
    name: *const u8,
    luid: *mut LUID,
) -> BOOL {
    // This would normally look up the privilege name in a table
    // For now, return a synthetic LUID
    if !luid.is_null() && !name.is_null() {
        (*luid).LowPart = 0;
        (*luid).HighPart = 0;
        TRUE
    } else {
        FALSE
    }
}

#[no_mangle]
pub unsafe extern "system" fn LookupPrivilegeValueW(
    system_name: *const u16,
    name: *const u16,
    luid: *mut LUID,
) -> BOOL {
    if !luid.is_null() && !name.is_null() {
        (*luid).LowPart = 0;
        (*luid).HighPart = 0;
        TRUE
    } else {
        FALSE
    }
}

#[no_mangle]
pub unsafe extern "system" fn ImpersonateSelf(impersonation_level: u32) -> BOOL {
    do_syscall(syscall::NtImpersonateAnonymousToken, &[impersonation_level as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn RevertToSelf() -> BOOL {
    do_syscall(syscall::NtSetInformationToken, &[0, 0, 0, 0]) as BOOL
}

// ============================================================================
// SID Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn AllocateAndInitializeSid(
    authority: *const SID_IDENTIFIER_AUTHORITY,
    sub_authority_count: u8,
    sub0: DWORD, sub1: DWORD, sub2: DWORD, sub3: DWORD,
    sub4: DWORD, sub5: DWORD, sub6: DWORD, sub7: DWORD,
    sid: *mut *mut u8,
) -> BOOL {
    let params: [u64; 11] = [
        authority as u64, sub_authority_count as u64,
        sub0 as u64, sub1 as u64, sub2 as u64, sub3 as u64,
        sub4 as u64, sub5 as u64, sub6 as u64, sub7 as u64,
        sid as u64,
    ];
    do_syscall(syscall::RtlInitializeSid, &[params.as_ptr() as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn FreeSid(sid: *mut u8) -> *mut u8 {
    // Would free the SID memory
    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "system" fn GetLengthSid(sid: *const u8) -> DWORD {
    do_syscall(syscall::RtlLengthSid, &[sid as u64]) as DWORD
}

#[no_mangle]
pub unsafe extern "system" fn EqualSid(sid1: *const u8, sid2: *const u8) -> BOOL {
    do_syscall(syscall::RtlEqualSid, &[sid1 as u64, sid2 as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn CopySid(dest_len: DWORD, dest: *mut u8, src: *const u8) -> BOOL {
    do_syscall(syscall::RtlCopySid, &[dest_len as u64, dest as u64, src as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn IsValidSid(sid: *const u8) -> BOOL {
    if sid.is_null() { FALSE } else { TRUE }
}

// ============================================================================
// Service Control Manager Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn OpenSCManagerA(
    machine_name: *const u8,
    database_name: *const u8,
    desired_access: DWORD,
) -> SC_HANDLE {
    do_syscall(syscall::NtOpenSCManager, &[machine_name as u64, database_name as u64, desired_access as u64, 0])
}

#[no_mangle]
pub unsafe extern "system" fn OpenSCManagerW(
    machine_name: *const u16,
    database_name: *const u16,
    desired_access: DWORD,
) -> SC_HANDLE {
    do_syscall(syscall::NtOpenSCManager, &[machine_name as u64, database_name as u64, desired_access as u64, 1])
}

#[no_mangle]
pub unsafe extern "system" fn CreateServiceA(
    scm: SC_HANDLE,
    service_name: *const u8,
    display_name: *const u8,
    desired_access: DWORD,
    service_type: DWORD,
    start_type: DWORD,
    error_control: DWORD,
    binary_path: *const u8,
    load_order_group: *const u8,
    tag_id: *mut DWORD,
    dependencies: *const u8,
    service_start_name: *const u8,
    password: *const u8,
) -> SC_HANDLE {
    let params: [u64; 13] = [
        scm, service_name as u64, display_name as u64, desired_access as u64,
        service_type as u64, start_type as u64, error_control as u64, binary_path as u64,
        load_order_group as u64, tag_id as u64, dependencies as u64,
        service_start_name as u64, password as u64,
    ];
    do_syscall(syscall::NtCreateService, &[params.as_ptr() as u64, 0])
}

#[no_mangle]
pub unsafe extern "system" fn OpenServiceA(
    scm: SC_HANDLE,
    service_name: *const u8,
    desired_access: DWORD,
) -> SC_HANDLE {
    do_syscall(syscall::NtOpenService, &[scm, service_name as u64, desired_access as u64, 0])
}

#[no_mangle]
pub unsafe extern "system" fn OpenServiceW(
    scm: SC_HANDLE,
    service_name: *const u16,
    desired_access: DWORD,
) -> SC_HANDLE {
    do_syscall(syscall::NtOpenService, &[scm, service_name as u64, desired_access as u64, 1])
}

#[no_mangle]
pub unsafe extern "system" fn CloseServiceHandle(handle: SC_HANDLE) -> BOOL {
    (do_syscall(syscall::NtCloseServiceHandle, &[handle]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn DeleteService(service: SC_HANDLE) -> BOOL {
    (do_syscall(syscall::NtDeleteService, &[service]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn StartServiceA(
    service: SC_HANDLE,
    argc: DWORD,
    argv: *const *const u8,
) -> BOOL {
    (do_syscall(syscall::NtStartService, &[service, argc as u64, argv as u64, 0]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn StartServiceW(
    service: SC_HANDLE,
    argc: DWORD,
    argv: *const *const u16,
) -> BOOL {
    (do_syscall(syscall::NtStartService, &[service, argc as u64, argv as u64, 1]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn ControlService(
    service: SC_HANDLE,
    control: DWORD,
    status: *mut SERVICE_STATUS,
) -> BOOL {
    (do_syscall(syscall::NtControlService, &[service, control as u64, status as u64]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn QueryServiceStatus(
    service: SC_HANDLE,
    status: *mut SERVICE_STATUS,
) -> BOOL {
    (do_syscall(syscall::NtQueryServiceStatus, &[service, status as u64]) == 0) as BOOL
}

// ============================================================================
// Event Log Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn OpenEventLogA(
    server_name: *const u8,
    source_name: *const u8,
) -> HANDLE {
    do_syscall(syscall::NtOpenEventLog, &[server_name as u64, source_name as u64, 0])
}

#[no_mangle]
pub unsafe extern "system" fn OpenEventLogW(
    server_name: *const u16,
    source_name: *const u16,
) -> HANDLE {
    do_syscall(syscall::NtOpenEventLog, &[server_name as u64, source_name as u64, 1])
}

#[no_mangle]
pub unsafe extern "system" fn CloseEventLog(event_log: HANDLE) -> BOOL {
    (do_syscall(syscall::NtCloseEventLog, &[event_log]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn ReadEventLogA(
    event_log: HANDLE,
    read_flags: DWORD,
    record_offset: DWORD,
    buffer: *mut u8,
    bytes_to_read: DWORD,
    bytes_read: *mut DWORD,
    min_bytes_needed: *mut DWORD,
) -> BOOL {
    let params: [u64; 7] = [event_log, read_flags as u64, record_offset as u64, buffer as u64, bytes_to_read as u64, bytes_read as u64, min_bytes_needed as u64];
    (do_syscall(syscall::NtReadEventLog, &[params.as_ptr() as u64, 0]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn ReportEventA(
    event_log: HANDLE,
    event_type: u16,
    category: u16,
    event_id: DWORD,
    user_sid: *const u8,
    num_strings: u16,
    data_size: DWORD,
    strings: *const *const u8,
    raw_data: *const u8,
) -> BOOL {
    let params: [u64; 9] = [
        event_log, event_type as u64, category as u64, event_id as u64,
        user_sid as u64, num_strings as u64, data_size as u64,
        strings as u64, raw_data as u64,
    ];
    (do_syscall(syscall::NtReportEvent, &[params.as_ptr() as u64, 0]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn ClearEventLogA(event_log: HANDLE, backup_file: *const u8) -> BOOL {
    (do_syscall(syscall::NtClearEventLog, &[event_log, backup_file as u64, 0]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn ClearEventLogW(event_log: HANDLE, backup_file: *const u16) -> BOOL {
    (do_syscall(syscall::NtClearEventLog, &[event_log, backup_file as u64, 1]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetNumberOfEventLogRecords(event_log: HANDLE, count: *mut DWORD) -> BOOL {
    (do_syscall(syscall::NtGetNumberOfEventLogRecords, &[event_log, count as u64]) == 0) as BOOL
}

// ============================================================================
// Cryptography Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn CryptAcquireContextA(
    prov: *mut HCRYPTPROV,
    container: *const u8,
    provider: *const u8,
    prov_type: DWORD,
    flags: DWORD,
) -> BOOL {
    (do_syscall(syscall::NtCryptAcquireContext, &[prov as u64, container as u64, provider as u64, prov_type as u64, flags as u64]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn CryptAcquireContextW(
    prov: *mut HCRYPTPROV,
    container: *const u16,
    provider: *const u16,
    prov_type: DWORD,
    flags: DWORD,
) -> BOOL {
    let params: [u64; 5] = [prov as u64, container as u64, provider as u64, prov_type as u64, flags as u64];
    (do_syscall(syscall::NtCryptAcquireContext, &[params.as_ptr() as u64, 1]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn CryptReleaseContext(prov: HCRYPTPROV, flags: DWORD) -> BOOL {
    (do_syscall(syscall::NtCryptReleaseContext, &[prov, flags as u64]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn CryptGenKey(
    prov: HCRYPTPROV,
    algid: DWORD,
    flags: DWORD,
    key: *mut HCRYPTKEY,
) -> BOOL {
    (do_syscall(syscall::NtCryptGenKey, &[prov, algid as u64, flags as u64, key as u64]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn CryptDestroyKey(key: HCRYPTKEY) -> BOOL {
    (do_syscall(syscall::NtCryptDestroyKey, &[key]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn CryptEncrypt(
    key: HCRYPTKEY,
    hash: HCRYPTHASH,
    is_final: BOOL,
    flags: DWORD,
    data: *mut u8,
    data_len: *mut DWORD,
    buf_len: DWORD,
) -> BOOL {
    let params: [u64; 7] = [key, hash, is_final as u64, flags as u64, data as u64, data_len as u64, buf_len as u64];
    (do_syscall(syscall::NtCryptEncrypt, &params) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn CryptDecrypt(
    key: HCRYPTKEY,
    hash: HCRYPTHASH,
    is_final: BOOL,
    flags: DWORD,
    data: *mut u8,
    data_len: *mut DWORD,
) -> BOOL {
    (do_syscall(syscall::NtCryptDecrypt, &[key, hash, is_final as u64, flags as u64, data as u64, data_len as u64]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn CryptCreateHash(
    prov: HCRYPTPROV,
    algid: DWORD,
    key: HCRYPTKEY,
    flags: DWORD,
    hash: *mut HCRYPTHASH,
) -> BOOL {
    (do_syscall(syscall::NtCryptCreateHash, &[prov, algid as u64, key, flags as u64, hash as u64]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn CryptHashData(
    hash: HCRYPTHASH,
    data: *const u8,
    data_len: DWORD,
    flags: DWORD,
) -> BOOL {
    (do_syscall(syscall::NtCryptHashData, &[hash, data as u64, data_len as u64, flags as u64]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn CryptDestroyHash(hash: HCRYPTHASH) -> BOOL {
    (do_syscall(syscall::NtCryptDestroyHash, &[hash]) == 0) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn CryptGenRandom(prov: HCRYPTPROV, len: DWORD, buffer: *mut u8) -> BOOL {
    (do_syscall(syscall::NtCryptGenRandom, &[prov, len as u64, buffer as u64]) == 0) as BOOL
}

// ============================================================================
// Module initialization
// ============================================================================

/// Initialize the advapi32 stub module
pub fn init() {
    crate::serial_println!("[ADVAPI32] Initializing advapi32.dll stub...");
}

/// Get the address of an exported function
pub fn get_export(name: &str) -> Option<u64> {
    let addr: u64 = match name {
        // Registry
        "RegOpenKeyExA" => RegOpenKeyExA as usize as u64,
        "RegOpenKeyExW" => RegOpenKeyExW as usize as u64,
        "RegCreateKeyExA" => RegCreateKeyExA as usize as u64,
        "RegCreateKeyExW" => RegCreateKeyExW as usize as u64,
        "RegCloseKey" => RegCloseKey as usize as u64,
        "RegDeleteKeyA" => RegDeleteKeyA as usize as u64,
        "RegDeleteKeyW" => RegDeleteKeyW as usize as u64,
        "RegSetValueExA" => RegSetValueExA as usize as u64,
        "RegSetValueExW" => RegSetValueExW as usize as u64,
        "RegQueryValueExA" => RegQueryValueExA as usize as u64,
        "RegQueryValueExW" => RegQueryValueExW as usize as u64,
        "RegDeleteValueA" => RegDeleteValueA as usize as u64,
        "RegDeleteValueW" => RegDeleteValueW as usize as u64,
        "RegEnumKeyExA" => RegEnumKeyExA as usize as u64,
        "RegEnumKeyExW" => RegEnumKeyExW as usize as u64,
        "RegEnumValueA" => RegEnumValueA as usize as u64,
        "RegEnumValueW" => RegEnumValueW as usize as u64,
        "RegFlushKey" => RegFlushKey as usize as u64,
        // Security
        "OpenProcessToken" => OpenProcessToken as usize as u64,
        "OpenThreadToken" => OpenThreadToken as usize as u64,
        "DuplicateToken" => DuplicateToken as usize as u64,
        "GetTokenInformation" => GetTokenInformation as usize as u64,
        "SetTokenInformation" => SetTokenInformation as usize as u64,
        "AdjustTokenPrivileges" => AdjustTokenPrivileges as usize as u64,
        "LookupPrivilegeValueA" => LookupPrivilegeValueA as usize as u64,
        "LookupPrivilegeValueW" => LookupPrivilegeValueW as usize as u64,
        "ImpersonateSelf" => ImpersonateSelf as usize as u64,
        "RevertToSelf" => RevertToSelf as usize as u64,
        // SID
        "AllocateAndInitializeSid" => AllocateAndInitializeSid as usize as u64,
        "FreeSid" => FreeSid as usize as u64,
        "GetLengthSid" => GetLengthSid as usize as u64,
        "EqualSid" => EqualSid as usize as u64,
        "CopySid" => CopySid as usize as u64,
        "IsValidSid" => IsValidSid as usize as u64,
        // SCM
        "OpenSCManagerA" => OpenSCManagerA as usize as u64,
        "OpenSCManagerW" => OpenSCManagerW as usize as u64,
        "CreateServiceA" => CreateServiceA as usize as u64,
        "OpenServiceA" => OpenServiceA as usize as u64,
        "OpenServiceW" => OpenServiceW as usize as u64,
        "CloseServiceHandle" => CloseServiceHandle as usize as u64,
        "DeleteService" => DeleteService as usize as u64,
        "StartServiceA" => StartServiceA as usize as u64,
        "StartServiceW" => StartServiceW as usize as u64,
        "ControlService" => ControlService as usize as u64,
        "QueryServiceStatus" => QueryServiceStatus as usize as u64,
        // Event Log
        "OpenEventLogA" => OpenEventLogA as usize as u64,
        "OpenEventLogW" => OpenEventLogW as usize as u64,
        "CloseEventLog" => CloseEventLog as usize as u64,
        "ReadEventLogA" => ReadEventLogA as usize as u64,
        "ReportEventA" => ReportEventA as usize as u64,
        "ClearEventLogA" => ClearEventLogA as usize as u64,
        "ClearEventLogW" => ClearEventLogW as usize as u64,
        "GetNumberOfEventLogRecords" => GetNumberOfEventLogRecords as usize as u64,
        // Crypto
        "CryptAcquireContextA" => CryptAcquireContextA as usize as u64,
        "CryptAcquireContextW" => CryptAcquireContextW as usize as u64,
        "CryptReleaseContext" => CryptReleaseContext as usize as u64,
        "CryptGenKey" => CryptGenKey as usize as u64,
        "CryptDestroyKey" => CryptDestroyKey as usize as u64,
        "CryptEncrypt" => CryptEncrypt as usize as u64,
        "CryptDecrypt" => CryptDecrypt as usize as u64,
        "CryptCreateHash" => CryptCreateHash as usize as u64,
        "CryptHashData" => CryptHashData as usize as u64,
        "CryptDestroyHash" => CryptDestroyHash as usize as u64,
        "CryptGenRandom" => CryptGenRandom as usize as u64,
        _ => return None,
    };
    Some(addr)
}
