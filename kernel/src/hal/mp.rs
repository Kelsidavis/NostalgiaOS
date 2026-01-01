//! Multiprocessor Support
//!
//! Provides SMP (Symmetric Multiprocessing) initialization:
//!
//! - **AP Startup**: Application Processor initialization
//! - **IPI**: Inter-Processor Interrupts
//! - **Processor State**: Per-CPU state tracking
//! - **CPU Topology**: Core/package detection
//!
//! # Startup Sequence
//!
//! 1. BSP (Bootstrap Processor) boots normally
//! 2. BSP discovers APs via ACPI MADT
//! 3. BSP sends INIT-SIPI-SIPI to each AP
//! 4. APs execute trampoline code in real mode
//! 5. APs switch to protected/long mode
//! 6. APs call kernel entry point
//!
//! # IPI Types
//!
//! - **INIT**: Reset processor
//! - **SIPI**: Startup IPI (specify entry point)
//! - **NMI**: Non-maskable interrupt
//! - **Fixed**: Deliver to specific vector
//! - **SMI**: System management interrupt
//!
//! # NT Functions
//!
//! - `HalStartNextProcessor` - Start an AP
//! - `HalRequestIpi` - Send IPI
//! - `KeNumberProcessors` - Get processor count
//!
//! # Usage
//!
//! ```ignore
//! // Start all APs
//! mp_start_all_aps();
//!
//! // Send IPI to all processors
//! mp_send_ipi_all(IPI_VECTOR_TLB_FLUSH);
//!
//! // Get processor count
//! let count = mp_get_processor_count();
//! ```

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;

// ============================================================================
// Constants
// ============================================================================

/// Maximum supported processors
pub const MAX_PROCESSORS: usize = 64;

/// IPI vector for TLB flush
pub const IPI_VECTOR_TLB_FLUSH: u8 = 0xFD;

/// IPI vector for reschedule
pub const IPI_VECTOR_RESCHEDULE: u8 = 0xFC;

/// IPI vector for call function
pub const IPI_VECTOR_CALL_FUNCTION: u8 = 0xFB;

/// IPI vector for stop
pub const IPI_VECTOR_STOP: u8 = 0xFA;

/// IPI vector for NMI
pub const IPI_VECTOR_NMI: u8 = 0x02;

/// Trampoline code physical address (below 1MB)
pub const TRAMPOLINE_ADDR: u64 = 0x8000;

/// Trampoline code size limit
pub const TRAMPOLINE_SIZE: usize = 4096;

/// SIPI retry count
const SIPI_RETRY_COUNT: u32 = 2;

/// AP startup timeout (milliseconds)
const AP_STARTUP_TIMEOUT_MS: u32 = 200;

// ============================================================================
// APIC Constants
// ============================================================================

/// APIC register offsets (memory-mapped)
pub mod apic_regs {
    pub const ID: u32 = 0x20;
    pub const VERSION: u32 = 0x30;
    pub const TPR: u32 = 0x80;
    pub const EOI: u32 = 0xB0;
    pub const LDR: u32 = 0xD0;
    pub const DFR: u32 = 0xE0;
    pub const SIVR: u32 = 0xF0;
    pub const ICR_LOW: u32 = 0x300;
    pub const ICR_HIGH: u32 = 0x310;
}

/// ICR delivery modes
pub mod icr_delivery {
    pub const FIXED: u32 = 0b000 << 8;
    pub const LOWEST: u32 = 0b001 << 8;
    pub const SMI: u32 = 0b010 << 8;
    pub const NMI: u32 = 0b100 << 8;
    pub const INIT: u32 = 0b101 << 8;
    pub const SIPI: u32 = 0b110 << 8;
}

/// ICR destination modes
pub mod icr_dest {
    pub const PHYSICAL: u32 = 0 << 11;
    pub const LOGICAL: u32 = 1 << 11;
}

/// ICR shorthand modes
pub mod icr_shorthand {
    pub const NONE: u32 = 0b00 << 18;
    pub const SELF: u32 = 0b01 << 18;
    pub const ALL_INCLUDING_SELF: u32 = 0b10 << 18;
    pub const ALL_EXCLUDING_SELF: u32 = 0b11 << 18;
}

/// ICR status/flags
pub mod icr_flags {
    pub const LEVEL_DEASSERT: u32 = 0 << 14;
    pub const LEVEL_ASSERT: u32 = 1 << 14;
    pub const TRIGGER_EDGE: u32 = 0 << 15;
    pub const TRIGGER_LEVEL: u32 = 1 << 15;
    pub const PENDING: u32 = 1 << 12;
}

// ============================================================================
// Types
// ============================================================================

/// Processor state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProcessorState {
    #[default]
    NotPresent = 0,
    Present = 1,
    Starting = 2,
    Running = 3,
    Halted = 4,
    Idle = 5,
}

/// IPI type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpiType {
    Fixed = 0,
    LowestPriority = 1,
    Smi = 2,
    Nmi = 4,
    Init = 5,
    Sipi = 6,
}

/// IPI destination
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpiDestination {
    /// Send to specific processor
    Processor(u32),
    /// Send to self
    ToSelf,
    /// Send to all including self
    AllIncludingSelf,
    /// Send to all excluding self
    AllExcludingSelf,
}

/// Processor information
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessorInfo {
    /// Processor number (0 = BSP)
    pub number: u32,
    /// APIC ID
    pub apic_id: u8,
    /// Current state
    pub state: ProcessorState,
    /// Is bootstrap processor
    pub is_bsp: bool,
    /// APIC version
    pub apic_version: u8,
    /// Logical destination ID
    pub ldr: u8,
    /// Package ID (socket)
    pub package_id: u8,
    /// Core ID within package
    pub core_id: u8,
    /// Thread ID within core (SMT)
    pub thread_id: u8,
}

/// CPU topology information
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuTopology {
    /// Total processor count
    pub processor_count: u32,
    /// Number of physical packages
    pub package_count: u32,
    /// Cores per package
    pub cores_per_package: u32,
    /// Threads per core (SMT/HT)
    pub threads_per_core: u32,
}

// ============================================================================
// Global State
// ============================================================================

static MP_LOCK: SpinLock<()> = SpinLock::new(());
static MP_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Processor count
static PROCESSOR_COUNT: AtomicU32 = AtomicU32::new(1);
/// Active processor count
static ACTIVE_PROCESSOR_COUNT: AtomicU32 = AtomicU32::new(1);
/// BSP APIC ID
static BSP_APIC_ID: AtomicU32 = AtomicU32::new(0);

/// Per-processor state
static mut PROCESSOR_INFO: [ProcessorInfo; MAX_PROCESSORS] = {
    const INIT: ProcessorInfo = ProcessorInfo {
        number: 0,
        apic_id: 0,
        state: ProcessorState::NotPresent,
        is_bsp: false,
        apic_version: 0,
        ldr: 0,
        package_id: 0,
        core_id: 0,
        thread_id: 0,
    };
    [INIT; MAX_PROCESSORS]
};

/// AP ready flag (set by AP when started)
static AP_STARTED: AtomicBool = AtomicBool::new(false);

/// Current AP being started
static CURRENT_AP: AtomicU32 = AtomicU32::new(0);

/// Local APIC base address
static APIC_BASE: AtomicU64 = AtomicU64::new(0xFEE00000);

/// IPI statistics
static IPI_SENT: AtomicU64 = AtomicU64::new(0);
static IPI_RECEIVED: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// APIC Access
// ============================================================================

/// Read from local APIC register
#[inline]
unsafe fn apic_read(offset: u32) -> u32 {
    let base = APIC_BASE.load(Ordering::Relaxed);
    let addr = (base + offset as u64) as *const u32;
    core::ptr::read_volatile(addr)
}

/// Write to local APIC register
#[inline]
unsafe fn apic_write(offset: u32, value: u32) {
    let base = APIC_BASE.load(Ordering::Relaxed);
    let addr = (base + offset as u64) as *mut u32;
    core::ptr::write_volatile(addr, value)
}

/// Get current APIC ID
pub fn mp_get_apic_id() -> u8 {
    unsafe {
        ((apic_read(apic_regs::ID) >> 24) & 0xFF) as u8
    }
}

/// Wait for ICR to be ready
unsafe fn wait_for_icr_idle() -> bool {
    for _ in 0..100000 {
        let icr = apic_read(apic_regs::ICR_LOW);
        if (icr & icr_flags::PENDING) == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

// ============================================================================
// IPI Functions
// ============================================================================

/// Send IPI to destination
pub fn mp_send_ipi(dest: IpiDestination, ipi_type: IpiType, vector: u8) -> bool {
    let _guard = MP_LOCK.lock();

    unsafe {
        // Wait for previous IPI to complete
        if !wait_for_icr_idle() {
            return false;
        }

        // Build ICR value
        let mut icr_low = (vector as u32) | icr_flags::LEVEL_ASSERT;

        // Set delivery mode
        icr_low |= match ipi_type {
            IpiType::Fixed => icr_delivery::FIXED,
            IpiType::LowestPriority => icr_delivery::LOWEST,
            IpiType::Smi => icr_delivery::SMI,
            IpiType::Nmi => icr_delivery::NMI,
            IpiType::Init => icr_delivery::INIT | icr_flags::TRIGGER_LEVEL,
            IpiType::Sipi => icr_delivery::SIPI,
        };

        // Set destination
        let (icr_high, shorthand) = match dest {
            IpiDestination::Processor(apic_id) => {
                ((apic_id << 24), icr_shorthand::NONE | icr_dest::PHYSICAL)
            }
            IpiDestination::ToSelf => (0, icr_shorthand::SELF),
            IpiDestination::AllIncludingSelf => (0, icr_shorthand::ALL_INCLUDING_SELF),
            IpiDestination::AllExcludingSelf => (0, icr_shorthand::ALL_EXCLUDING_SELF),
        };

        icr_low |= shorthand;

        // Write ICR (high first, then low triggers the IPI)
        apic_write(apic_regs::ICR_HIGH, icr_high);
        apic_write(apic_regs::ICR_LOW, icr_low);

        IPI_SENT.fetch_add(1, Ordering::Relaxed);
        true
    }
}

/// Send fixed IPI to specific processor
pub fn mp_send_ipi_fixed(apic_id: u32, vector: u8) -> bool {
    mp_send_ipi(IpiDestination::Processor(apic_id), IpiType::Fixed, vector)
}

/// Send IPI to all processors (excluding self)
pub fn mp_send_ipi_all(vector: u8) -> bool {
    mp_send_ipi(IpiDestination::AllExcludingSelf, IpiType::Fixed, vector)
}

/// Send NMI to processor
pub fn mp_send_nmi(apic_id: u32) -> bool {
    mp_send_ipi(IpiDestination::Processor(apic_id), IpiType::Nmi, 0)
}

/// Send INIT to processor
pub fn mp_send_init(apic_id: u32) -> bool {
    mp_send_ipi(IpiDestination::Processor(apic_id), IpiType::Init, 0)
}

/// Send SIPI to processor (vector is page number of startup code)
pub fn mp_send_sipi(apic_id: u32, vector: u8) -> bool {
    mp_send_ipi(IpiDestination::Processor(apic_id), IpiType::Sipi, vector)
}

// ============================================================================
// AP Startup
// ============================================================================

/// Delay in microseconds (busy wait)
fn delay_us(us: u32) {
    // Use TSC for delay if available, otherwise busy loop
    for _ in 0..(us * 100) {
        core::hint::spin_loop();
    }
}

/// Start a single AP
pub fn mp_start_ap(apic_id: u8) -> bool {
    if !MP_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let _guard = MP_LOCK.lock();

    // Find processor slot
    let proc_num = unsafe {
        let mut found = None;
        for (i, info) in PROCESSOR_INFO.iter().enumerate() {
            if info.apic_id == apic_id && info.state == ProcessorState::Present {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(n) => n,
            None => return false,
        }
    };

    unsafe {
        PROCESSOR_INFO[proc_num].state = ProcessorState::Starting;
    }

    CURRENT_AP.store(proc_num as u32, Ordering::Release);
    AP_STARTED.store(false, Ordering::Release);

    // INIT-SIPI-SIPI sequence
    unsafe {
        // Send INIT IPI
        if !wait_for_icr_idle() {
            return false;
        }

        let icr_high = (apic_id as u32) << 24;
        apic_write(apic_regs::ICR_HIGH, icr_high);
        apic_write(
            apic_regs::ICR_LOW,
            icr_delivery::INIT | icr_flags::LEVEL_ASSERT | icr_flags::TRIGGER_LEVEL,
        );

        // Wait 10ms
        delay_us(10000);

        // De-assert INIT
        if !wait_for_icr_idle() {
            return false;
        }
        apic_write(apic_regs::ICR_HIGH, icr_high);
        apic_write(
            apic_regs::ICR_LOW,
            icr_delivery::INIT | icr_flags::LEVEL_DEASSERT | icr_flags::TRIGGER_LEVEL,
        );

        // Send SIPI (twice per specification)
        let sipi_vector = (TRAMPOLINE_ADDR >> 12) as u8;

        for _ in 0..SIPI_RETRY_COUNT {
            delay_us(200);

            if !wait_for_icr_idle() {
                continue;
            }

            apic_write(apic_regs::ICR_HIGH, icr_high);
            apic_write(
                apic_regs::ICR_LOW,
                icr_delivery::SIPI | (sipi_vector as u32),
            );
        }
    }

    // Wait for AP to signal ready
    let mut timeout = AP_STARTUP_TIMEOUT_MS * 1000;
    while timeout > 0 && !AP_STARTED.load(Ordering::Acquire) {
        delay_us(10);
        timeout -= 10;
    }

    let started = AP_STARTED.load(Ordering::Acquire);

    if started {
        unsafe {
            PROCESSOR_INFO[proc_num].state = ProcessorState::Running;
        }
        ACTIVE_PROCESSOR_COUNT.fetch_add(1, Ordering::Relaxed);
        crate::serial_println!("[MP] AP {} (APIC ID {}) started", proc_num, apic_id);
    } else {
        unsafe {
            PROCESSOR_INFO[proc_num].state = ProcessorState::Present;
        }
        crate::serial_println!("[MP] AP {} (APIC ID {}) failed to start", proc_num, apic_id);
    }

    started
}

/// Start all APs
pub fn mp_start_all_aps() -> u32 {
    if !MP_INITIALIZED.load(Ordering::Acquire) {
        return 0;
    }

    let mut started = 0u32;
    let bsp_apic_id = BSP_APIC_ID.load(Ordering::Relaxed) as u8;

    unsafe {
        for info in PROCESSOR_INFO.iter() {
            if info.state == ProcessorState::Present && info.apic_id != bsp_apic_id {
                if mp_start_ap(info.apic_id) {
                    started += 1;
                }
            }
        }
    }

    crate::serial_println!("[MP] Started {} APs", started);
    started
}

/// Called by AP when it has finished initialization
pub fn mp_ap_ready() {
    AP_STARTED.store(true, Ordering::Release);
    IPI_RECEIVED.fetch_add(1, Ordering::Relaxed);
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize MP subsystem (BSP only)
pub fn init() {
    let _guard = MP_LOCK.lock();

    // Get BSP APIC ID
    let bsp_id = mp_get_apic_id();
    BSP_APIC_ID.store(bsp_id as u32, Ordering::Relaxed);

    // Initialize BSP entry
    unsafe {
        PROCESSOR_INFO[0] = ProcessorInfo {
            number: 0,
            apic_id: bsp_id,
            state: ProcessorState::Running,
            is_bsp: true,
            apic_version: (apic_read(apic_regs::VERSION) & 0xFF) as u8,
            ldr: 0,
            package_id: 0,
            core_id: 0,
            thread_id: 0,
        };
    }

    PROCESSOR_COUNT.store(1, Ordering::Relaxed);
    ACTIVE_PROCESSOR_COUNT.store(1, Ordering::Relaxed);

    MP_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[MP] Initialized (BSP APIC ID {})", bsp_id);
}

/// Register a processor discovered from ACPI
pub fn mp_register_processor(apic_id: u8, _flags: u32) -> bool {
    let _guard = MP_LOCK.lock();

    let count = PROCESSOR_COUNT.load(Ordering::Relaxed) as usize;
    if count >= MAX_PROCESSORS {
        return false;
    }

    // Check for duplicates
    unsafe {
        for info in PROCESSOR_INFO[..count].iter() {
            if info.apic_id == apic_id {
                return false;
            }
        }

        // Add new processor
        PROCESSOR_INFO[count] = ProcessorInfo {
            number: count as u32,
            apic_id,
            state: ProcessorState::Present,
            is_bsp: apic_id == BSP_APIC_ID.load(Ordering::Relaxed) as u8,
            apic_version: 0,
            ldr: 0,
            package_id: 0,
            core_id: 0,
            thread_id: 0,
        };
    }

    PROCESSOR_COUNT.fetch_add(1, Ordering::Relaxed);
    true
}

/// Set APIC base address
pub fn mp_set_apic_base(base: u64) {
    APIC_BASE.store(base, Ordering::Relaxed);
}

// ============================================================================
// Query Functions
// ============================================================================

/// Get total processor count
pub fn mp_get_processor_count() -> u32 {
    PROCESSOR_COUNT.load(Ordering::Relaxed)
}

/// Get active (running) processor count
pub fn mp_get_active_processor_count() -> u32 {
    ACTIVE_PROCESSOR_COUNT.load(Ordering::Relaxed)
}

/// Get BSP APIC ID
pub fn mp_get_bsp_apic_id() -> u8 {
    BSP_APIC_ID.load(Ordering::Relaxed) as u8
}

/// Check if current processor is BSP
pub fn mp_is_bsp() -> bool {
    mp_get_apic_id() == mp_get_bsp_apic_id()
}

/// Get processor information
pub fn mp_get_processor_info(processor: u32) -> Option<ProcessorInfo> {
    if processor as usize >= MAX_PROCESSORS {
        return None;
    }

    unsafe {
        let info = &PROCESSOR_INFO[processor as usize];
        if info.state != ProcessorState::NotPresent {
            Some(*info)
        } else {
            None
        }
    }
}

/// Get processor by APIC ID
pub fn mp_get_processor_by_apic_id(apic_id: u8) -> Option<ProcessorInfo> {
    unsafe {
        for info in PROCESSOR_INFO.iter() {
            if info.apic_id == apic_id && info.state != ProcessorState::NotPresent {
                return Some(*info);
            }
        }
    }
    None
}

/// Get CPU topology
pub fn mp_get_topology() -> CpuTopology {
    // Simplified topology - would need CPUID parsing for accurate results
    let proc_count = PROCESSOR_COUNT.load(Ordering::Relaxed);

    CpuTopology {
        processor_count: proc_count,
        package_count: 1,
        cores_per_package: proc_count,
        threads_per_core: 1,
    }
}

// ============================================================================
// TLB Flush IPI
// ============================================================================

/// Request TLB flush on all processors
pub fn mp_flush_tlb_all() {
    if ACTIVE_PROCESSOR_COUNT.load(Ordering::Relaxed) > 1 {
        mp_send_ipi_all(IPI_VECTOR_TLB_FLUSH);
    }
}

/// Request reschedule on processor
pub fn mp_request_reschedule(processor: u32) {
    if let Some(info) = mp_get_processor_info(processor) {
        mp_send_ipi_fixed(info.apic_id as u32, IPI_VECTOR_RESCHEDULE);
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// MP statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct MpStats {
    pub initialized: bool,
    pub processor_count: u32,
    pub active_count: u32,
    pub bsp_apic_id: u8,
    pub ipi_sent: u64,
    pub ipi_received: u64,
}

/// Get MP statistics
pub fn mp_get_stats() -> MpStats {
    MpStats {
        initialized: MP_INITIALIZED.load(Ordering::Relaxed),
        processor_count: PROCESSOR_COUNT.load(Ordering::Relaxed),
        active_count: ACTIVE_PROCESSOR_COUNT.load(Ordering::Relaxed),
        bsp_apic_id: BSP_APIC_ID.load(Ordering::Relaxed) as u8,
        ipi_sent: IPI_SENT.load(Ordering::Relaxed),
        ipi_received: IPI_RECEIVED.load(Ordering::Relaxed),
    }
}

/// Check if MP is initialized
pub fn mp_is_initialized() -> bool {
    MP_INITIALIZED.load(Ordering::Acquire)
}

// ============================================================================
// NT Compatibility
// ============================================================================

/// KeNumberProcessors equivalent
pub fn ke_number_processors() -> u32 {
    mp_get_active_processor_count()
}

/// KeGetCurrentProcessorNumber equivalent
pub fn ke_get_current_processor_number() -> u32 {
    let apic_id = mp_get_apic_id();
    unsafe {
        for (i, info) in PROCESSOR_INFO.iter().enumerate() {
            if info.apic_id == apic_id {
                return i as u32;
            }
        }
    }
    0
}

/// HalStartNextProcessor equivalent
pub fn hal_start_next_processor() -> bool {
    let count = PROCESSOR_COUNT.load(Ordering::Relaxed) as usize;
    let active = ACTIVE_PROCESSOR_COUNT.load(Ordering::Relaxed) as usize;

    if active >= count {
        return false;
    }

    unsafe {
        for info in PROCESSOR_INFO[active..count].iter() {
            if info.state == ProcessorState::Present {
                return mp_start_ap(info.apic_id);
            }
        }
    }

    false
}

/// HalRequestIpi equivalent
pub fn hal_request_ipi(processor_mask: u64) {
    for i in 0..MAX_PROCESSORS {
        if (processor_mask & (1u64 << i)) != 0 {
            if let Some(info) = mp_get_processor_info(i as u32) {
                mp_send_ipi_fixed(info.apic_id as u32, IPI_VECTOR_RESCHEDULE);
            }
        }
    }
}
