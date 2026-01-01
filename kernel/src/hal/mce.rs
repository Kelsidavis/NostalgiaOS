//! Machine Check Exception (MCE) Handling
//!
//! Provides hardware error detection and reporting:
//!
//! - **MCE**: Machine Check Exceptions for fatal errors
//! - **MCA**: Machine Check Architecture banks
//! - **CMCI**: Corrected Machine Check Interrupt
//! - **Error Logging**: Hardware error history
//!
//! # MCA Banks
//!
//! Each CPU has multiple MCA banks for different error sources:
//! - Bank 0: Core errors
//! - Bank 1: Bus/interconnect errors
//! - Bank 2: Memory controller errors
//! - Bank 3+: Platform-specific
//!
//! # Error Types
//!
//! - **Corrected**: Hardware corrected, logged only
//! - **Uncorrected**: Requires software handling
//! - **Fatal**: System must halt or reset
//!
//! # NT Functions
//!
//! - `HalHandleMcheck` - Handle machine check exception
//! - `HalReportMcheckEvent` - Report error to OS
//!
//! # Usage
//!
//! ```ignore
//! // Initialize MCE handling
//! mce_init();
//!
//! // Check for pending errors
//! let errors = mce_poll_errors();
//!
//! // Get error history
//! let history = mce_get_error_log();
//! ```

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;

/// Maximum MCA banks per CPU
pub const MAX_MCA_BANKS: usize = 32;

/// Maximum CPUs for MCE tracking
pub const MAX_MCE_CPUS: usize = 64;

/// Maximum error log entries
pub const MAX_ERROR_LOG: usize = 64;

/// MCA bank MSR offsets
pub mod msr {
    /// MCG_CAP - Global capability
    pub const MCG_CAP: u32 = 0x179;
    /// MCG_STATUS - Global status
    pub const MCG_STATUS: u32 = 0x17A;
    /// MCG_CTL - Global control
    pub const MCG_CTL: u32 = 0x17B;
    /// MCG_EXT_CTL - Extended control
    pub const MCG_EXT_CTL: u32 = 0x4D0;

    /// MC0_CTL - Bank 0 control (base for all banks)
    pub const MC_CTL_BASE: u32 = 0x400;
    /// MC0_STATUS - Bank 0 status
    pub const MC_STATUS_BASE: u32 = 0x401;
    /// MC0_ADDR - Bank 0 address
    pub const MC_ADDR_BASE: u32 = 0x402;
    /// MC0_MISC - Bank 0 misc
    pub const MC_MISC_BASE: u32 = 0x403;

    /// Offset between banks
    pub const MC_BANK_OFFSET: u32 = 4;
}

/// MCG_CAP bits
pub mod mcg_cap {
    pub const COUNT_MASK: u64 = 0xFF;
    pub const CTL_P: u64 = 1 << 8;
    pub const EXT_P: u64 = 1 << 9;
    pub const CMCI_P: u64 = 1 << 10;
    pub const TES_P: u64 = 1 << 11;
    pub const EXT_CNT_MASK: u64 = 0xFF << 16;
    pub const SER_P: u64 = 1 << 24;
    pub const ELOG_P: u64 = 1 << 26;
    pub const LMCE_P: u64 = 1 << 27;
}

/// MCG_STATUS bits
pub mod mcg_status {
    pub const RIPV: u64 = 1 << 0;
    pub const EIPV: u64 = 1 << 1;
    pub const MCIP: u64 = 1 << 2;
    pub const LMCE_S: u64 = 1 << 3;
}

/// MC_STATUS bits
pub mod mc_status {
    pub const MCI_STATUS_VAL: u64 = 1 << 63;
    pub const MCI_STATUS_OVER: u64 = 1 << 62;
    pub const MCI_STATUS_UC: u64 = 1 << 61;
    pub const MCI_STATUS_EN: u64 = 1 << 60;
    pub const MCI_STATUS_MISCV: u64 = 1 << 59;
    pub const MCI_STATUS_ADDRV: u64 = 1 << 58;
    pub const MCI_STATUS_PCC: u64 = 1 << 57;
    pub const MCI_STATUS_S: u64 = 1 << 56;
    pub const MCI_STATUS_AR: u64 = 1 << 55;
}

/// Error severity
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ErrorSeverity {
    /// No error
    #[default]
    None = 0,
    /// Corrected error (hardware fixed it)
    Corrected = 1,
    /// Uncorrected recoverable
    UncorrectedRecoverable = 2,
    /// Uncorrected fatal
    Fatal = 3,
}

/// Error source type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ErrorSource {
    #[default]
    Unknown = 0,
    Processor = 1,
    Memory = 2,
    Pcie = 3,
    Platform = 4,
}

/// MCA bank status
#[derive(Debug, Clone, Copy, Default)]
pub struct McaBankStatus {
    /// Bank number
    pub bank: u8,
    /// Status MSR value
    pub status: u64,
    /// Address MSR value (if valid)
    pub address: u64,
    /// Misc MSR value (if valid)
    pub misc: u64,
    /// Error is valid
    pub valid: bool,
    /// Error is uncorrected
    pub uncorrected: bool,
    /// Error is fatal (processor context corrupt)
    pub fatal: bool,
    /// Address is valid
    pub addr_valid: bool,
    /// Misc is valid
    pub misc_valid: bool,
    /// Error was overflow (multiple errors)
    pub overflow: bool,
}

impl McaBankStatus {
    /// Parse from raw status value
    pub fn from_status(bank: u8, status: u64, address: u64, misc: u64) -> Self {
        let valid = (status & mc_status::MCI_STATUS_VAL) != 0;
        let uncorrected = (status & mc_status::MCI_STATUS_UC) != 0;
        let fatal = (status & mc_status::MCI_STATUS_PCC) != 0;
        let addr_valid = (status & mc_status::MCI_STATUS_ADDRV) != 0;
        let misc_valid = (status & mc_status::MCI_STATUS_MISCV) != 0;
        let overflow = (status & mc_status::MCI_STATUS_OVER) != 0;

        Self {
            bank,
            status,
            address: if addr_valid { address } else { 0 },
            misc: if misc_valid { misc } else { 0 },
            valid,
            uncorrected,
            fatal,
            addr_valid,
            misc_valid,
            overflow,
        }
    }

    /// Get error code (model-specific)
    pub fn error_code(&self) -> u16 {
        (self.status & 0xFFFF) as u16
    }

    /// Get extended error code
    pub fn extended_error_code(&self) -> u8 {
        ((self.status >> 16) & 0x3F) as u8
    }

    /// Get error severity
    pub fn severity(&self) -> ErrorSeverity {
        if !self.valid {
            ErrorSeverity::None
        } else if self.fatal {
            ErrorSeverity::Fatal
        } else if self.uncorrected {
            ErrorSeverity::UncorrectedRecoverable
        } else {
            ErrorSeverity::Corrected
        }
    }
}

/// Error log entry
#[derive(Debug, Clone, Copy, Default)]
pub struct ErrorLogEntry {
    /// Entry is valid
    pub valid: bool,
    /// CPU that reported error
    pub cpu: u32,
    /// MCA bank
    pub bank: u8,
    /// Error severity
    pub severity: ErrorSeverity,
    /// Error source
    pub source: ErrorSource,
    /// Timestamp (TSC)
    pub timestamp: u64,
    /// Status value
    pub status: u64,
    /// Address value
    pub address: u64,
    /// Misc value
    pub misc: u64,
}

/// Per-CPU MCE state
#[derive(Debug)]
pub struct CpuMceState {
    /// CPU ID
    pub cpu_id: u32,
    /// Number of MCA banks
    pub bank_count: u8,
    /// MCG capabilities
    pub mcg_cap: u64,
    /// CMCI supported
    pub cmci_supported: bool,
    /// MCE enabled
    pub enabled: AtomicBool,
    /// Errors detected
    pub errors_detected: AtomicU64,
    /// Corrected errors
    pub corrected_errors: AtomicU64,
    /// Uncorrected errors
    pub uncorrected_errors: AtomicU64,
    /// Fatal errors
    pub fatal_errors: AtomicU64,
    /// Last error timestamp
    pub last_error_time: AtomicU64,
}

impl CpuMceState {
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            bank_count: 0,
            mcg_cap: 0,
            cmci_supported: false,
            enabled: AtomicBool::new(false),
            errors_detected: AtomicU64::new(0),
            corrected_errors: AtomicU64::new(0),
            uncorrected_errors: AtomicU64::new(0),
            fatal_errors: AtomicU64::new(0),
            last_error_time: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Global MCE State
// ============================================================================

static mut CPU_MCE_STATE: [CpuMceState; MAX_MCE_CPUS] = {
    const INIT: CpuMceState = CpuMceState::new(0);
    let mut states = [INIT; MAX_MCE_CPUS];
    let mut i = 0;
    while i < MAX_MCE_CPUS {
        states[i] = CpuMceState::new(i as u32);
        i += 1;
    }
    states
};

static mut ERROR_LOG: [ErrorLogEntry; MAX_ERROR_LOG] = [ErrorLogEntry {
    valid: false,
    cpu: 0,
    bank: 0,
    severity: ErrorSeverity::None,
    source: ErrorSource::Unknown,
    timestamp: 0,
    status: 0,
    address: 0,
    misc: 0,
}; MAX_ERROR_LOG];

static ERROR_LOG_INDEX: AtomicU32 = AtomicU32::new(0);
static MCE_LOCK: SpinLock<()> = SpinLock::new(());
static MCE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static TOTAL_ERRORS: AtomicU64 = AtomicU64::new(0);
static MCA_SUPPORTED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// MSR Access
// ============================================================================

/// Read MSR
#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let (low, high): (u32, u32);
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
        ((high as u64) << 32) | (low as u64)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Write MSR
#[inline]
unsafe fn wrmsr(msr: u32, value: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        let low = value as u32;
        let high = (value >> 32) as u32;
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nostack, preserves_flags)
        );
    }
}

/// Read TSC
#[inline]
fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

// ============================================================================
// MCE Detection
// ============================================================================

/// Check if MCA is supported
pub fn mce_is_supported() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let edx: u32;
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            out("edx") edx,
            out("eax") _,
            out("ecx") _,
            options(preserves_flags)
        );
        // Check MCE (bit 7) and MCA (bit 14)
        (edx & (1 << 7)) != 0 && (edx & (1 << 14)) != 0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Get MCA bank count for current CPU
pub fn mce_get_bank_count() -> u8 {
    if !MCA_SUPPORTED.load(Ordering::Relaxed) {
        return 0;
    }

    unsafe {
        let mcg_cap = rdmsr(msr::MCG_CAP);
        (mcg_cap & mcg_cap::COUNT_MASK) as u8
    }
}

// ============================================================================
// MCE Initialization
// ============================================================================

/// Initialize MCE for a CPU
pub fn mce_init_cpu(cpu: u32) {
    if cpu as usize >= MAX_MCE_CPUS {
        return;
    }

    if !mce_is_supported() {
        return;
    }

    unsafe {
        let state = &mut CPU_MCE_STATE[cpu as usize];

        // Read capabilities
        state.mcg_cap = rdmsr(msr::MCG_CAP);
        state.bank_count = (state.mcg_cap & mcg_cap::COUNT_MASK) as u8;
        state.cmci_supported = (state.mcg_cap & mcg_cap::CMCI_P) != 0;

        // Enable MCE in CR4
        #[cfg(target_arch = "x86_64")]
        {
            let cr4: u64;
            core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack));
            core::arch::asm!("mov cr4, {}", in(reg) cr4 | (1 << 6), options(nostack));
        }

        // Clear all bank status registers
        for bank in 0..state.bank_count {
            let status_msr = msr::MC_STATUS_BASE + (bank as u32 * msr::MC_BANK_OFFSET);
            wrmsr(status_msr, 0);
        }

        // Enable all error reporting in banks
        if (state.mcg_cap & mcg_cap::CTL_P) != 0 {
            wrmsr(msr::MCG_CTL, !0u64);
        }

        for bank in 0..state.bank_count {
            let ctl_msr = msr::MC_CTL_BASE + (bank as u32 * msr::MC_BANK_OFFSET);
            wrmsr(ctl_msr, !0u64);
        }

        state.enabled.store(true, Ordering::Release);
    }
}

/// Initialize MCE subsystem
pub fn init() {
    if !mce_is_supported() {
        crate::serial_println!("[HAL] MCE: Machine Check not supported");
        return;
    }

    MCA_SUPPORTED.store(true, Ordering::Release);

    // Initialize BSP
    mce_init_cpu(0);

    unsafe {
        // Clear error log
        for entry in ERROR_LOG.iter_mut() {
            *entry = ErrorLogEntry::default();
        }
    }

    ERROR_LOG_INDEX.store(0, Ordering::Relaxed);
    TOTAL_ERRORS.store(0, Ordering::Relaxed);

    MCE_INITIALIZED.store(true, Ordering::Release);

    let bank_count = mce_get_bank_count();
    crate::serial_println!("[HAL] MCE initialized ({} banks)", bank_count);
}

// ============================================================================
// Error Polling
// ============================================================================

/// Poll MCA banks for errors
pub fn mce_poll_errors(cpu: u32) -> ([McaBankStatus; MAX_MCA_BANKS], usize) {
    let mut errors = [McaBankStatus::default(); MAX_MCA_BANKS];
    let mut count = 0;

    if cpu as usize >= MAX_MCE_CPUS {
        return (errors, 0);
    }

    unsafe {
        let state = &CPU_MCE_STATE[cpu as usize];
        if !state.enabled.load(Ordering::Acquire) {
            return (errors, 0);
        }

        for bank in 0..state.bank_count {
            if count >= MAX_MCA_BANKS {
                break;
            }

            let status_msr = msr::MC_STATUS_BASE + (bank as u32 * msr::MC_BANK_OFFSET);
            let status = rdmsr(status_msr);

            if (status & mc_status::MCI_STATUS_VAL) != 0 {
                let addr_msr = msr::MC_ADDR_BASE + (bank as u32 * msr::MC_BANK_OFFSET);
                let misc_msr = msr::MC_MISC_BASE + (bank as u32 * msr::MC_BANK_OFFSET);

                let address = if (status & mc_status::MCI_STATUS_ADDRV) != 0 {
                    rdmsr(addr_msr)
                } else {
                    0
                };

                let misc = if (status & mc_status::MCI_STATUS_MISCV) != 0 {
                    rdmsr(misc_msr)
                } else {
                    0
                };

                errors[count] = McaBankStatus::from_status(bank, status, address, misc);
                count += 1;

                // Log the error
                mce_log_error(cpu, &errors[count - 1]);

                // Clear the status (acknowledge)
                wrmsr(status_msr, 0);
            }
        }
    }

    (errors, count)
}

/// Log an error
fn mce_log_error(cpu: u32, status: &McaBankStatus) {
    let _guard = unsafe { MCE_LOCK.lock() };

    unsafe {
        let idx = ERROR_LOG_INDEX.fetch_add(1, Ordering::Relaxed) as usize % MAX_ERROR_LOG;

        ERROR_LOG[idx] = ErrorLogEntry {
            valid: true,
            cpu,
            bank: status.bank,
            severity: status.severity(),
            source: ErrorSource::Processor, // Could be refined based on bank/error code
            timestamp: read_tsc(),
            status: status.status,
            address: status.address,
            misc: status.misc,
        };

        // Update statistics
        let state = &CPU_MCE_STATE[cpu as usize];
        state.errors_detected.fetch_add(1, Ordering::Relaxed);
        state.last_error_time.store(read_tsc(), Ordering::Relaxed);

        match status.severity() {
            ErrorSeverity::Corrected => {
                state.corrected_errors.fetch_add(1, Ordering::Relaxed);
            }
            ErrorSeverity::UncorrectedRecoverable => {
                state.uncorrected_errors.fetch_add(1, Ordering::Relaxed);
            }
            ErrorSeverity::Fatal => {
                state.fatal_errors.fetch_add(1, Ordering::Relaxed);
            }
            ErrorSeverity::None => {}
        }

        TOTAL_ERRORS.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// MCE Exception Handler
// ============================================================================

/// Handle Machine Check Exception
///
/// Called from the exception handler when #MC occurs.
/// Returns true if error was handled, false if fatal.
pub fn mce_exception_handler(cpu: u32) -> bool {
    if !MCE_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    unsafe {
        // Check MCG_STATUS
        let mcg_status = rdmsr(msr::MCG_STATUS);

        // MCIP must be set
        if (mcg_status & mcg_status::MCIP) == 0 {
            return true; // Spurious?
        }

        // Poll all banks
        let (errors, count) = mce_poll_errors(cpu);

        // Check for fatal errors
        let mut fatal = false;
        for i in 0..count {
            if errors[i].fatal {
                fatal = true;
                crate::serial_println!(
                    "[MCE] FATAL: CPU {} Bank {} Status 0x{:016x} Addr 0x{:016x}",
                    cpu, errors[i].bank, errors[i].status, errors[i].address
                );
            } else if errors[i].uncorrected {
                crate::serial_println!(
                    "[MCE] Uncorrected: CPU {} Bank {} Status 0x{:016x}",
                    cpu, errors[i].bank, errors[i].status
                );
            }
        }

        // Clear MCIP
        wrmsr(msr::MCG_STATUS, mcg_status & !mcg_status::MCIP);

        !fatal
    }
}

// ============================================================================
// Query Functions
// ============================================================================

/// Get error log entries
pub fn mce_get_error_log(max_entries: usize) -> ([ErrorLogEntry; 32], usize) {
    let mut entries = [ErrorLogEntry::default(); 32];
    let mut count = 0;

    unsafe {
        for i in 0..MAX_ERROR_LOG {
            if count >= max_entries || count >= 32 {
                break;
            }
            if ERROR_LOG[i].valid {
                entries[count] = ERROR_LOG[i];
                count += 1;
            }
        }
    }

    (entries, count)
}

/// Clear error log
pub fn mce_clear_error_log() {
    let _guard = unsafe { MCE_LOCK.lock() };

    unsafe {
        for entry in ERROR_LOG.iter_mut() {
            entry.valid = false;
        }
    }

    ERROR_LOG_INDEX.store(0, Ordering::Relaxed);
}

/// MCE statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct MceStats {
    pub supported: bool,
    pub initialized: bool,
    pub bank_count: u8,
    pub cmci_supported: bool,
    pub total_errors: u64,
    pub corrected_errors: u64,
    pub uncorrected_errors: u64,
    pub fatal_errors: u64,
}

/// Get MCE statistics for a CPU
pub fn mce_get_stats(cpu: u32) -> MceStats {
    if cpu as usize >= MAX_MCE_CPUS {
        return MceStats::default();
    }

    unsafe {
        let state = &CPU_MCE_STATE[cpu as usize];

        MceStats {
            supported: MCA_SUPPORTED.load(Ordering::Relaxed),
            initialized: state.enabled.load(Ordering::Relaxed),
            bank_count: state.bank_count,
            cmci_supported: state.cmci_supported,
            total_errors: state.errors_detected.load(Ordering::Relaxed),
            corrected_errors: state.corrected_errors.load(Ordering::Relaxed),
            uncorrected_errors: state.uncorrected_errors.load(Ordering::Relaxed),
            fatal_errors: state.fatal_errors.load(Ordering::Relaxed),
        }
    }
}

/// Get global MCE statistics
pub fn mce_get_global_stats() -> MceStats {
    let mut stats = MceStats {
        supported: MCA_SUPPORTED.load(Ordering::Relaxed),
        initialized: MCE_INITIALIZED.load(Ordering::Relaxed),
        bank_count: mce_get_bank_count(),
        cmci_supported: false,
        total_errors: TOTAL_ERRORS.load(Ordering::Relaxed),
        corrected_errors: 0,
        uncorrected_errors: 0,
        fatal_errors: 0,
    };

    unsafe {
        for state in CPU_MCE_STATE.iter() {
            if state.enabled.load(Ordering::Relaxed) {
                stats.cmci_supported |= state.cmci_supported;
                stats.corrected_errors += state.corrected_errors.load(Ordering::Relaxed);
                stats.uncorrected_errors += state.uncorrected_errors.load(Ordering::Relaxed);
                stats.fatal_errors += state.fatal_errors.load(Ordering::Relaxed);
            }
        }
    }

    stats
}

/// Check if MCE is initialized
pub fn mce_is_initialized() -> bool {
    MCE_INITIALIZED.load(Ordering::Acquire)
}
