//! Model Specific Register (MSR) Access
//!
//! Provides unified MSR access and well-known register definitions:
//!
//! - **Read/Write**: Safe MSR access functions
//! - **Well-Known**: Common MSR addresses
//! - **Validation**: Range checking and feature detection
//!
//! # MSR Categories
//!
//! - **IA32_**: Architectural MSRs (stable across implementations)
//! - **MSR_**: Implementation-specific MSRs
//!
//! # Common MSRs
//!
//! - IA32_APIC_BASE: Local APIC configuration
//! - IA32_TSC: Time Stamp Counter
//! - IA32_EFER: Extended Feature Enable Register
//! - IA32_STAR/LSTAR/CSTAR: System call entry points
//!
//! # Safety
//!
//! MSR access is privileged and can:
//! - Cause #GP if MSR doesn't exist
//! - Change system behavior significantly
//! - Be vendor-specific
//!
//! # Usage
//!
//! ```ignore
//! // Read TSC
//! let tsc = msr_read(IA32_TSC);
//!
//! // Read APIC base
//! let apic_base = msr_read(IA32_APIC_BASE);
//!
//! // Write to syscall entry point
//! msr_write(IA32_LSTAR, handler_address);
//! ```

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// ============================================================================
// Well-Known MSR Addresses
// ============================================================================

/// Architectural MSRs (IA32_)
pub mod ia32 {
    /// Time Stamp Counter
    pub const TSC: u32 = 0x10;
    /// Platform ID
    pub const PLATFORM_ID: u32 = 0x17;
    /// APIC Base Address
    pub const APIC_BASE: u32 = 0x1B;
    /// Feature Control
    pub const FEATURE_CONTROL: u32 = 0x3A;
    /// TSC Adjust
    pub const TSC_ADJUST: u32 = 0x3B;
    /// BIOS Update Trigger
    pub const BIOS_UPDT_TRIG: u32 = 0x79;
    /// BIOS Sign ID
    pub const BIOS_SIGN_ID: u32 = 0x8B;
    /// SMM Monitor Control
    pub const SMM_MONITOR_CTL: u32 = 0x9B;
    /// PMC 0
    pub const PMC0: u32 = 0xC1;
    /// PMC 1
    pub const PMC1: u32 = 0xC2;
    /// PMC 2
    pub const PMC2: u32 = 0xC3;
    /// PMC 3
    pub const PMC3: u32 = 0xC4;
    /// MPERF (Maximum Performance)
    pub const MPERF: u32 = 0xE7;
    /// APERF (Actual Performance)
    pub const APERF: u32 = 0xE8;
    /// MTRR Capability
    pub const MTRRCAP: u32 = 0xFE;
    /// SYSENTER CS
    pub const SYSENTER_CS: u32 = 0x174;
    /// SYSENTER ESP
    pub const SYSENTER_ESP: u32 = 0x175;
    /// SYSENTER EIP
    pub const SYSENTER_EIP: u32 = 0x176;
    /// MCG Capability
    pub const MCG_CAP: u32 = 0x179;
    /// MCG Status
    pub const MCG_STATUS: u32 = 0x17A;
    /// MCG Control
    pub const MCG_CTL: u32 = 0x17B;
    /// Performance Event Select 0
    pub const PERFEVTSEL0: u32 = 0x186;
    /// Performance Event Select 1
    pub const PERFEVTSEL1: u32 = 0x187;
    /// Performance Status
    pub const PERF_STATUS: u32 = 0x198;
    /// Performance Control
    pub const PERF_CTL: u32 = 0x199;
    /// Clock Modulation
    pub const CLOCK_MODULATION: u32 = 0x19A;
    /// Thermal Interrupt
    pub const THERM_INTERRUPT: u32 = 0x19B;
    /// Thermal Status
    pub const THERM_STATUS: u32 = 0x19C;
    /// Misc Enable
    pub const MISC_ENABLE: u32 = 0x1A0;
    /// Package Thermal Status
    pub const PACKAGE_THERM_STATUS: u32 = 0x1B1;
    /// Package Thermal Interrupt
    pub const PACKAGE_THERM_INTERRUPT: u32 = 0x1B2;
    /// Debug Control
    pub const DEBUGCTL: u32 = 0x1D9;
    /// SMRR Phys Base
    pub const SMRR_PHYSBASE: u32 = 0x1F2;
    /// SMRR Phys Mask
    pub const SMRR_PHYSMASK: u32 = 0x1F3;
    /// Platform DCA Cap
    pub const PLATFORM_DCA_CAP: u32 = 0x1F8;
    /// MTRR Phys Base 0
    pub const MTRR_PHYSBASE0: u32 = 0x200;
    /// MTRR Phys Mask 0
    pub const MTRR_PHYSMASK0: u32 = 0x201;
    /// MTRR Fixed 64K 00000
    pub const MTRR_FIX64K_00000: u32 = 0x250;
    /// MTRR Fixed 16K 80000
    pub const MTRR_FIX16K_80000: u32 = 0x258;
    /// MTRR Fixed 16K A0000
    pub const MTRR_FIX16K_A0000: u32 = 0x259;
    /// MTRR Fixed 4K C0000
    pub const MTRR_FIX4K_C0000: u32 = 0x268;
    /// PAT (Page Attribute Table)
    pub const PAT: u32 = 0x277;
    /// MTRR Def Type
    pub const MTRR_DEF_TYPE: u32 = 0x2FF;
    /// Fixed Counter 0
    pub const FIXED_CTR0: u32 = 0x309;
    /// Fixed Counter 1
    pub const FIXED_CTR1: u32 = 0x30A;
    /// Fixed Counter 2
    pub const FIXED_CTR2: u32 = 0x30B;
    /// Performance Capabilities
    pub const PERF_CAPABILITIES: u32 = 0x345;
    /// Fixed Counter Control
    pub const FIXED_CTR_CTRL: u32 = 0x38D;
    /// Perf Global Status
    pub const PERF_GLOBAL_STATUS: u32 = 0x38E;
    /// Perf Global Control
    pub const PERF_GLOBAL_CTRL: u32 = 0x38F;
    /// Perf Global OVF Control
    pub const PERF_GLOBAL_OVF_CTRL: u32 = 0x390;
    /// MCx Control Base
    pub const MC0_CTL: u32 = 0x400;
    /// MCx Status Base
    pub const MC0_STATUS: u32 = 0x401;
    /// MCx Address Base
    pub const MC0_ADDR: u32 = 0x402;
    /// MCx Misc Base
    pub const MC0_MISC: u32 = 0x403;
    /// VMX Basic
    pub const VMX_BASIC: u32 = 0x480;
    /// VMX Pin Based Controls
    pub const VMX_PINBASED_CTLS: u32 = 0x481;
    /// VMX Procbased Controls
    pub const VMX_PROCBASED_CTLS: u32 = 0x482;
    /// VMX Exit Controls
    pub const VMX_EXIT_CTLS: u32 = 0x483;
    /// VMX Entry Controls
    pub const VMX_ENTRY_CTLS: u32 = 0x484;
    /// VMX Misc
    pub const VMX_MISC: u32 = 0x485;
    /// DS Area
    pub const DS_AREA: u32 = 0x600;
    /// X2APIC ID
    pub const X2APIC_APICID: u32 = 0x802;
    /// X2APIC Version
    pub const X2APIC_VERSION: u32 = 0x803;
    /// X2APIC TPR
    pub const X2APIC_TPR: u32 = 0x808;
    /// X2APIC PPR
    pub const X2APIC_PPR: u32 = 0x80A;
    /// X2APIC EOI
    pub const X2APIC_EOI: u32 = 0x80B;
    /// X2APIC LDR
    pub const X2APIC_LDR: u32 = 0x80D;
    /// X2APIC SIVR
    pub const X2APIC_SIVR: u32 = 0x80F;
    /// X2APIC ICR
    pub const X2APIC_ICR: u32 = 0x830;
    /// Extended Feature Enable Register
    pub const EFER: u32 = 0xC0000080;
    /// STAR (legacy syscall)
    pub const STAR: u32 = 0xC0000081;
    /// LSTAR (long mode syscall)
    pub const LSTAR: u32 = 0xC0000082;
    /// CSTAR (compat mode syscall)
    pub const CSTAR: u32 = 0xC0000083;
    /// SFMASK (syscall flag mask)
    pub const SFMASK: u32 = 0xC0000084;
    /// FS Base
    pub const FS_BASE: u32 = 0xC0000100;
    /// GS Base
    pub const GS_BASE: u32 = 0xC0000101;
    /// Kernel GS Base
    pub const KERNEL_GS_BASE: u32 = 0xC0000102;
    /// TSC Aux
    pub const TSC_AUX: u32 = 0xC0000103;
}

/// EFER bits
pub mod efer {
    /// System Call Enable
    pub const SCE: u64 = 1 << 0;
    /// Long Mode Enable
    pub const LME: u64 = 1 << 8;
    /// Long Mode Active
    pub const LMA: u64 = 1 << 10;
    /// No-Execute Enable
    pub const NXE: u64 = 1 << 11;
    /// SVME (AMD SVM)
    pub const SVME: u64 = 1 << 12;
    /// LMSLE (Long Mode Segment Limit Enable)
    pub const LMSLE: u64 = 1 << 13;
    /// FFXSR (Fast FXSAVE/FXRSTOR)
    pub const FFXSR: u64 = 1 << 14;
    /// TCE (Translation Cache Extension)
    pub const TCE: u64 = 1 << 15;
}

/// APIC Base bits
pub mod apic_base {
    /// BSP Flag
    pub const BSP: u64 = 1 << 8;
    /// x2APIC Enable
    pub const X2APIC_ENABLE: u64 = 1 << 10;
    /// APIC Global Enable
    pub const XAPIC_ENABLE: u64 = 1 << 11;
    /// Base Address Mask
    pub const BASE_MASK: u64 = 0xFFFFFF000;
}

// ============================================================================
// Global State
// ============================================================================

static MSR_INITIALIZED: AtomicBool = AtomicBool::new(false);
static MSR_READ_COUNT: AtomicU64 = AtomicU64::new(0);
static MSR_WRITE_COUNT: AtomicU64 = AtomicU64::new(0);
static MSR_GP_FAULTS: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Core MSR Access
// ============================================================================

/// Read MSR (unsafe, may #GP)
#[inline]
pub unsafe fn msr_read_raw(msr: u32) -> u64 {
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

/// Write MSR (unsafe, may #GP)
#[inline]
pub unsafe fn msr_write_raw(msr: u32, value: u64) {
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

/// Read MSR with statistics
pub fn msr_read(msr: u32) -> u64 {
    MSR_READ_COUNT.fetch_add(1, Ordering::Relaxed);
    unsafe { msr_read_raw(msr) }
}

/// Write MSR with statistics
pub fn msr_write(msr: u32, value: u64) {
    MSR_WRITE_COUNT.fetch_add(1, Ordering::Relaxed);
    unsafe { msr_write_raw(msr, value) }
}

/// Read MSR bits with mask
pub fn msr_read_bits(msr: u32, mask: u64) -> u64 {
    msr_read(msr) & mask
}

/// Set MSR bits (read-modify-write)
pub fn msr_set_bits(msr: u32, bits: u64) {
    let value = msr_read(msr);
    msr_write(msr, value | bits);
}

/// Clear MSR bits (read-modify-write)
pub fn msr_clear_bits(msr: u32, bits: u64) {
    let value = msr_read(msr);
    msr_write(msr, value & !bits);
}

// ============================================================================
// Common MSR Operations
// ============================================================================

/// Get APIC base address
pub fn msr_get_apic_base() -> u64 {
    msr_read(ia32::APIC_BASE) & apic_base::BASE_MASK
}

/// Check if BSP
pub fn msr_is_bsp() -> bool {
    (msr_read(ia32::APIC_BASE) & apic_base::BSP) != 0
}

/// Check if x2APIC enabled
pub fn msr_is_x2apic_enabled() -> bool {
    (msr_read(ia32::APIC_BASE) & apic_base::X2APIC_ENABLE) != 0
}

/// Get EFER
pub fn msr_get_efer() -> u64 {
    msr_read(ia32::EFER)
}

/// Check if long mode active
pub fn msr_is_long_mode() -> bool {
    (msr_get_efer() & efer::LMA) != 0
}

/// Check if NX enabled
pub fn msr_is_nx_enabled() -> bool {
    (msr_get_efer() & efer::NXE) != 0
}

/// Get syscall LSTAR
pub fn msr_get_syscall_handler() -> u64 {
    msr_read(ia32::LSTAR)
}

/// Set syscall LSTAR
pub fn msr_set_syscall_handler(handler: u64) {
    msr_write(ia32::LSTAR, handler);
}

/// Get FS base
pub fn msr_get_fs_base() -> u64 {
    msr_read(ia32::FS_BASE)
}

/// Set FS base
pub fn msr_set_fs_base(base: u64) {
    msr_write(ia32::FS_BASE, base);
}

/// Get GS base
pub fn msr_get_gs_base() -> u64 {
    msr_read(ia32::GS_BASE)
}

/// Set GS base
pub fn msr_set_gs_base(base: u64) {
    msr_write(ia32::GS_BASE, base);
}

/// Get kernel GS base
pub fn msr_get_kernel_gs_base() -> u64 {
    msr_read(ia32::KERNEL_GS_BASE)
}

/// Set kernel GS base
pub fn msr_set_kernel_gs_base(base: u64) {
    msr_write(ia32::KERNEL_GS_BASE, base);
}

/// Swap GS base (for syscall entry)
#[inline]
pub fn msr_swap_gs() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("swapgs", options(nostack, preserves_flags));
    }
}

// ============================================================================
// TSC Access
// ============================================================================

/// Read TSC via MSR
pub fn msr_read_tsc() -> u64 {
    msr_read(ia32::TSC)
}

/// Read TSC via RDTSC instruction (faster)
#[inline]
pub fn rdtsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Read TSC and processor ID via RDTSCP
#[inline]
pub fn rdtscp() -> (u64, u32) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let (tsc_low, tsc_high, aux): (u32, u32, u32);
        core::arch::asm!(
            "rdtscp",
            out("eax") tsc_low,
            out("edx") tsc_high,
            out("ecx") aux,
            options(nostack, preserves_flags)
        );
        (((tsc_high as u64) << 32) | (tsc_low as u64), aux)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        (0, 0)
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize MSR subsystem
pub fn init() {
    MSR_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[MSR] Initialized");
}

/// Check if MSR subsystem is initialized
pub fn msr_is_initialized() -> bool {
    MSR_INITIALIZED.load(Ordering::Acquire)
}

// ============================================================================
// Statistics
// ============================================================================

/// MSR statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct MsrStats {
    pub initialized: bool,
    pub read_count: u64,
    pub write_count: u64,
    pub gp_faults: u64,
}

/// Get MSR statistics
pub fn msr_get_stats() -> MsrStats {
    MsrStats {
        initialized: MSR_INITIALIZED.load(Ordering::Relaxed),
        read_count: MSR_READ_COUNT.load(Ordering::Relaxed),
        write_count: MSR_WRITE_COUNT.load(Ordering::Relaxed),
        gp_faults: MSR_GP_FAULTS.load(Ordering::Relaxed),
    }
}

/// Record GP fault from MSR access
pub fn msr_record_gp_fault() {
    MSR_GP_FAULTS.fetch_add(1, Ordering::Relaxed);
}

// ============================================================================
// NT Compatibility
// ============================================================================

/// HalReadMsr equivalent
pub fn hal_read_msr(msr: u32) -> u64 {
    msr_read(msr)
}

/// HalWriteMsr equivalent
pub fn hal_write_msr(msr: u32, value: u64) {
    msr_write(msr, value);
}
