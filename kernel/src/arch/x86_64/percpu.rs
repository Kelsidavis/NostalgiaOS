//! Per-CPU Data Access
//!
//! Provides mechanisms for accessing per-CPU data using the GS segment register.
//! Each CPU has its own GS base pointing to its KPRCB structure.
//!
//! On x86_64, we use the IA32_GS_BASE MSR (0xC0000101) to store the per-CPU
//! data pointer. This allows fast access to CPU-local data without locks.

use core::arch::asm;

/// MSR numbers for per-CPU data
pub mod msr {
    /// IA32_GS_BASE - GS segment base address (kernel mode)
    pub const IA32_GS_BASE: u32 = 0xC0000101;
    /// IA32_KERNEL_GS_BASE - Swapped with GS_BASE on SWAPGS
    pub const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
}

/// Read from an MSR
///
/// # Safety
/// Caller must ensure the MSR number is valid
#[inline]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") lo,
        out("edx") hi,
        options(nomem, nostack, preserves_flags)
    );
    ((hi as u64) << 32) | (lo as u64)
}

/// Write to an MSR
///
/// # Safety
/// Caller must ensure the MSR number is valid and the value is appropriate
#[inline]
pub unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") lo,
        in("edx") hi,
        options(nomem, nostack, preserves_flags)
    );
}

/// Set the GS base to point to per-CPU data
///
/// # Safety
/// Caller must ensure the address is valid and points to appropriate per-CPU structure
#[inline]
pub unsafe fn set_gs_base(addr: u64) {
    wrmsr(msr::IA32_GS_BASE, addr);
}

/// Get the current GS base address
///
/// # Safety
/// This is safe to call, but the returned address may be null if not initialized
#[inline]
pub unsafe fn get_gs_base() -> u64 {
    rdmsr(msr::IA32_GS_BASE)
}

/// Read a value from GS segment at given offset
///
/// # Safety
/// Caller must ensure offset is valid and within per-CPU data bounds
#[inline]
pub unsafe fn read_gs_u64(offset: usize) -> u64 {
    let value: u64;
    asm!(
        "mov {}, gs:[{offset}]",
        out(reg) value,
        offset = in(reg) offset,
        options(readonly, nostack, preserves_flags)
    );
    value
}

/// Write a value to GS segment at given offset
///
/// # Safety
/// Caller must ensure offset is valid and within per-CPU data bounds
#[inline]
pub unsafe fn write_gs_u64(offset: usize, value: u64) {
    asm!(
        "mov gs:[{offset}], {}",
        in(reg) value,
        offset = in(reg) offset,
        options(nostack, preserves_flags)
    );
}

/// Get the current CPU's APIC ID
///
/// # Safety
/// Requires APIC to be initialized
#[inline]
pub unsafe fn get_apic_id() -> u32 {
    crate::hal::apic::current_apic_id().into()
}

/// Map APIC ID to logical CPU number
///
/// # Safety
/// Requires ACPI to be initialized with processor information
pub unsafe fn apic_id_to_cpu_num(apic_id: u32) -> Option<usize> {
    // Look up the APIC ID in the ACPI processor table
    let processor_count = crate::hal::acpi::get_processor_count();

    for i in 0..processor_count {
        if let Some(proc_info) = crate::hal::acpi::get_processor(i) {
            if proc_info.apic_id == apic_id as u8 {
                return Some(i);
            }
        }
    }

    None
}

/// Get the current logical CPU number (0-based)
///
/// # Safety
/// Requires both APIC and ACPI to be initialized
pub unsafe fn get_cpu_id() -> usize {
    let apic_id = get_apic_id();
    apic_id_to_cpu_num(apic_id).unwrap_or(0)
}
