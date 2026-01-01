//! Processor Power Management (PPM)
//!
//! Provides CPU power state management for power efficiency:
//!
//! - **C-States**: Processor idle power states (C0-Cn)
//! - **P-States**: Performance states (frequency/voltage scaling)
//! - **T-States**: Throttling states
//! - **Thermal Management**: Temperature monitoring and throttling
//!
//! # C-States (Idle States)
//!
//! ```text
//! C0 - Active (executing instructions)
//! C1 - Halt (clock gated, fast wake)
//! C2 - Stop-Clock (deeper sleep)
//! C3 - Deep Sleep (cache may be flushed)
//! C6 - Deep Power Down (core voltage reduced)
//! ```
//!
//! # P-States (Performance States)
//!
//! ```text
//! P0 - Maximum performance (highest frequency)
//! P1 - Reduced performance
//! ...
//! Pn - Minimum performance (lowest frequency)
//! ```
//!
//! # NT Functions
//!
//! - `PoRegisterPowerSettingCallback` - Register for power events
//! - `PoSetSystemState` - Set system power state
//! - `PoRequestPowerIrp` - Request power state change
//!
//! # Usage
//!
//! ```ignore
//! // Enter idle state
//! ppm_enter_idle_state(CState::C1);
//!
//! // Set performance state
//! ppm_set_performance_state(PState::P0);
//!
//! // Get current power info
//! let info = ppm_get_processor_power_info(cpu_id);
//! ```

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;

/// Maximum number of processors
pub const MAX_PROCESSORS: usize = 64;

/// Maximum C-states supported
pub const MAX_C_STATES: usize = 8;

/// Maximum P-states supported
pub const MAX_P_STATES: usize = 16;

/// C-State (Processor Idle State)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CState {
    /// Active - executing instructions
    #[default]
    C0 = 0,
    /// Halt - clock gated
    C1 = 1,
    /// Stop-Clock
    C2 = 2,
    /// Deep Sleep
    C3 = 3,
    /// Deeper Sleep
    C4 = 4,
    /// Deep Power Down (reduced voltage)
    C6 = 6,
    /// Package C-state
    C7 = 7,
}

impl CState {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::C0,
            1 => Self::C1,
            2 => Self::C2,
            3 => Self::C3,
            4 => Self::C4,
            6 => Self::C6,
            7 => Self::C7,
            _ => Self::C0,
        }
    }

    /// Get typical exit latency in microseconds
    pub fn exit_latency_us(&self) -> u32 {
        match self {
            Self::C0 => 0,
            Self::C1 => 1,
            Self::C2 => 20,
            Self::C3 => 100,
            Self::C4 => 200,
            Self::C6 => 500,
            Self::C7 => 1000,
        }
    }

    /// Get typical power consumption (relative, 0-100)
    pub fn power_consumption(&self) -> u8 {
        match self {
            Self::C0 => 100,
            Self::C1 => 70,
            Self::C2 => 50,
            Self::C3 => 30,
            Self::C4 => 20,
            Self::C6 => 10,
            Self::C7 => 5,
        }
    }
}

/// P-State (Performance State)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PState {
    /// Maximum performance
    #[default]
    P0 = 0,
    P1 = 1,
    P2 = 2,
    P3 = 3,
    P4 = 4,
    P5 = 5,
    P6 = 6,
    P7 = 7,
}

impl PState {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::P0,
            1 => Self::P1,
            2 => Self::P2,
            3 => Self::P3,
            4 => Self::P4,
            5 => Self::P5,
            6 => Self::P6,
            _ => Self::P7,
        }
    }

    /// Get approximate frequency percentage (relative to max)
    pub fn frequency_percent(&self) -> u8 {
        match self {
            Self::P0 => 100,
            Self::P1 => 90,
            Self::P2 => 80,
            Self::P3 => 70,
            Self::P4 => 60,
            Self::P5 => 50,
            Self::P6 => 40,
            Self::P7 => 30,
        }
    }
}

/// T-State (Throttling State)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TState {
    /// No throttling
    #[default]
    T0 = 0,
    /// 12.5% throttling
    T1 = 1,
    /// 25% throttling
    T2 = 2,
    /// 37.5% throttling
    T3 = 3,
    /// 50% throttling
    T4 = 4,
    /// 62.5% throttling
    T5 = 5,
    /// 75% throttling
    T6 = 6,
    /// 87.5% throttling
    T7 = 7,
}

/// Power policy
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PowerPolicy {
    /// Favor performance
    Performance = 0,
    /// Balance performance and power
    #[default]
    Balanced = 1,
    /// Favor power saving
    PowerSaver = 2,
}

/// C-State information
#[derive(Debug, Clone, Copy, Default)]
pub struct CStateInfo {
    /// State is supported
    pub supported: bool,
    /// Exit latency in microseconds
    pub exit_latency_us: u32,
    /// Power consumption (mW, if known)
    pub power_mw: u32,
    /// Times this state was entered
    pub entry_count: u64,
    /// Total time in this state (TSC ticks)
    pub total_time: u64,
}

/// P-State information
#[derive(Debug, Clone, Copy, Default)]
pub struct PStateInfo {
    /// State is supported
    pub supported: bool,
    /// Frequency in MHz
    pub frequency_mhz: u32,
    /// Voltage in mV
    pub voltage_mv: u32,
    /// Power consumption (mW, if known)
    pub power_mw: u32,
    /// Times this state was used
    pub usage_count: u64,
    /// Total time in this state (TSC ticks)
    pub total_time: u64,
}

/// Per-processor power state
#[derive(Debug)]
pub struct ProcessorPowerState {
    /// Processor ID
    pub processor_id: u32,
    /// Current C-state
    pub current_c_state: AtomicU32,
    /// Current P-state
    pub current_p_state: AtomicU32,
    /// Current T-state
    pub current_t_state: AtomicU32,
    /// Target P-state (requested)
    pub target_p_state: AtomicU32,
    /// Processor is idle
    pub idle: AtomicBool,
    /// Last state change timestamp
    pub last_state_change: AtomicU64,
    /// C-state info
    c_states: [CStateInfo; MAX_C_STATES],
    /// P-state info
    p_states: [PStateInfo; MAX_P_STATES],
    /// Current core temperature (Celsius)
    pub temperature: AtomicU32,
    /// Thermal throttling active
    pub thermal_throttle: AtomicBool,
    /// Power limit throttling active
    pub power_limit_throttle: AtomicBool,
}

impl ProcessorPowerState {
    pub const fn new(processor_id: u32) -> Self {
        Self {
            processor_id,
            current_c_state: AtomicU32::new(0),
            current_p_state: AtomicU32::new(0),
            current_t_state: AtomicU32::new(0),
            target_p_state: AtomicU32::new(0),
            idle: AtomicBool::new(false),
            last_state_change: AtomicU64::new(0),
            c_states: [CStateInfo {
                supported: false,
                exit_latency_us: 0,
                power_mw: 0,
                entry_count: 0,
                total_time: 0,
            }; MAX_C_STATES],
            p_states: [PStateInfo {
                supported: false,
                frequency_mhz: 0,
                voltage_mv: 0,
                power_mw: 0,
                usage_count: 0,
                total_time: 0,
            }; MAX_P_STATES],
            temperature: AtomicU32::new(0),
            thermal_throttle: AtomicBool::new(false),
            power_limit_throttle: AtomicBool::new(false),
        }
    }

    /// Get current C-state
    pub fn get_c_state(&self) -> CState {
        CState::from_u8(self.current_c_state.load(Ordering::Relaxed) as u8)
    }

    /// Get current P-state
    pub fn get_p_state(&self) -> PState {
        PState::from_u8(self.current_p_state.load(Ordering::Relaxed) as u8)
    }

    /// Set current C-state
    pub fn set_c_state(&self, state: CState) {
        self.current_c_state.store(state as u32, Ordering::Release);
        self.last_state_change.store(read_tsc(), Ordering::Relaxed);
    }

    /// Set current P-state
    pub fn set_p_state(&self, state: PState) {
        self.current_p_state.store(state as u32, Ordering::Release);
        self.last_state_change.store(read_tsc(), Ordering::Relaxed);
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
// Global Power State
// ============================================================================

static mut PROCESSOR_POWER: [ProcessorPowerState; MAX_PROCESSORS] = {
    const INIT: ProcessorPowerState = ProcessorPowerState::new(0);
    let mut states = [INIT; MAX_PROCESSORS];
    let mut i = 0;
    while i < MAX_PROCESSORS {
        states[i] = ProcessorPowerState::new(i as u32);
        i += 1;
    }
    states
};

static PPM_LOCK: SpinLock<()> = SpinLock::new(());
static PPM_INITIALIZED: AtomicBool = AtomicBool::new(false);
static CURRENT_POLICY: AtomicU32 = AtomicU32::new(PowerPolicy::Balanced as u32);
static ACTIVE_PROCESSORS: AtomicU32 = AtomicU32::new(1);

// Statistics
static TOTAL_C_STATE_TRANSITIONS: AtomicU64 = AtomicU64::new(0);
static TOTAL_P_STATE_TRANSITIONS: AtomicU64 = AtomicU64::new(0);
static TOTAL_IDLE_TIME: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// C-State Functions
// ============================================================================

/// Enter a C-state (idle state)
///
/// Called when processor is idle to reduce power consumption.
pub fn ppm_enter_idle_state(processor: u32, state: CState) {
    if processor as usize >= MAX_PROCESSORS {
        return;
    }

    unsafe {
        let power_state = &PROCESSOR_POWER[processor as usize];
        power_state.set_c_state(state);
        power_state.idle.store(true, Ordering::Release);
    }

    TOTAL_C_STATE_TRANSITIONS.fetch_add(1, Ordering::Relaxed);

    // Actually enter the idle state
    match state {
        CState::C0 => {
            // Active - do nothing
        }
        CState::C1 => {
            // HLT instruction
            #[cfg(target_arch = "x86_64")]
            unsafe {
                core::arch::asm!("hlt", options(nomem, nostack));
            }
        }
        CState::C2 | CState::C3 | CState::C4 | CState::C6 | CState::C7 => {
            // Deeper states would use MWAIT with appropriate hints
            // For now, just use HLT
            #[cfg(target_arch = "x86_64")]
            unsafe {
                core::arch::asm!("hlt", options(nomem, nostack));
            }
        }
    }
}

/// Exit C-state (wakeup from idle)
pub fn ppm_exit_idle_state(processor: u32) {
    if processor as usize >= MAX_PROCESSORS {
        return;
    }

    unsafe {
        let power_state = &PROCESSOR_POWER[processor as usize];
        let old_state = power_state.get_c_state();

        // Calculate time spent in idle
        let now = read_tsc();
        let last = power_state.last_state_change.load(Ordering::Relaxed);
        let idle_time = now.saturating_sub(last);

        TOTAL_IDLE_TIME.fetch_add(idle_time, Ordering::Relaxed);

        power_state.set_c_state(CState::C0);
        power_state.idle.store(false, Ordering::Release);

        // Update C-state statistics
        let state_idx = old_state as usize;
        if state_idx < MAX_C_STATES {
            // Would update c_states[state_idx] here
        }
    }
}

/// Get deepest C-state supported
pub fn ppm_get_deepest_c_state() -> CState {
    // Check CPUID for MWAIT support and available C-states
    // For now, assume C3 is the deepest supported
    CState::C3
}

/// Check if MWAIT is supported
pub fn ppm_is_mwait_supported() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let ecx: u32;
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            out("ecx") ecx,
            out("eax") _,
            out("edx") _,
            options(preserves_flags)
        );
        (ecx & (1 << 3)) != 0 // MONITOR/MWAIT bit
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

// ============================================================================
// P-State Functions
// ============================================================================

/// Set P-state (performance state)
///
/// Changes processor frequency/voltage.
pub fn ppm_set_performance_state(processor: u32, state: PState) -> bool {
    if processor as usize >= MAX_PROCESSORS {
        return false;
    }

    // Check if SpeedStep/Cool'n'Quiet is supported
    if !ppm_is_speedstep_supported() {
        return false;
    }

    unsafe {
        let power_state = &PROCESSOR_POWER[processor as usize];
        power_state.target_p_state.store(state as u32, Ordering::Release);

        // Write to IA32_PERF_CTL MSR (0x199) to change P-state
        // This requires knowing the specific FID/VID values
        // For now, just update our tracking

        power_state.set_p_state(state);
    }

    TOTAL_P_STATE_TRANSITIONS.fetch_add(1, Ordering::Relaxed);
    true
}

/// Get current P-state
pub fn ppm_get_current_p_state(processor: u32) -> PState {
    if processor as usize >= MAX_PROCESSORS {
        return PState::P0;
    }

    unsafe { PROCESSOR_POWER[processor as usize].get_p_state() }
}

/// Check if SpeedStep/EIST is supported
pub fn ppm_is_speedstep_supported() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let ecx: u32;
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            out("ecx") ecx,
            out("eax") _,
            out("edx") _,
            options(preserves_flags)
        );
        (ecx & (1 << 7)) != 0 // EIST bit
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Get number of P-states supported
pub fn ppm_get_p_state_count() -> u32 {
    // Would read from ACPI _PSS or MSRs
    // For now, assume 8 states
    8
}

// ============================================================================
// Thermal Management
// ============================================================================

/// Get processor temperature
pub fn ppm_get_temperature(processor: u32) -> Option<u32> {
    if processor as usize >= MAX_PROCESSORS {
        return None;
    }

    // Read from IA32_THERM_STATUS MSR (0x19C)
    // The actual temperature requires knowing TjMax from MSR 0x1A2

    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Read IA32_THERM_STATUS
        let status: u64;
        core::arch::asm!(
            "mov ecx, 0x19C",
            "rdmsr",
            "shl rdx, 32",
            "or rax, rdx",
            out("rax") status,
            out("rdx") _,
            out("ecx") _,
            options(nostack, preserves_flags)
        );

        // Digital readout is bits 22:16, relative to TjMax
        let readout = ((status >> 16) & 0x7F) as u32;

        // Assume TjMax of 100°C for now
        let tj_max = 100u32;
        let temp = tj_max.saturating_sub(readout);

        PROCESSOR_POWER[processor as usize].temperature.store(temp, Ordering::Relaxed);
        Some(temp)
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

/// Check if thermal throttling is active
pub fn ppm_is_thermal_throttling(processor: u32) -> bool {
    if processor as usize >= MAX_PROCESSORS {
        return false;
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Read IA32_THERM_STATUS
        let status: u64;
        core::arch::asm!(
            "mov ecx, 0x19C",
            "rdmsr",
            "shl rdx, 32",
            "or rax, rdx",
            out("rax") status,
            out("rdx") _,
            out("ecx") _,
            options(nostack, preserves_flags)
        );

        // Bit 0: Thermal status (1 = throttling)
        let throttling = (status & 1) != 0;
        PROCESSOR_POWER[processor as usize].thermal_throttle.store(throttling, Ordering::Relaxed);
        throttling
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Set thermal throttle point
pub fn ppm_set_thermal_throttle_point(_temperature: u32) -> bool {
    // Would write to IA32_THERM_INTERRUPT MSR
    // For now, just return success
    true
}

// ============================================================================
// Power Policy
// ============================================================================

/// Set power policy
pub fn ppm_set_power_policy(policy: PowerPolicy) {
    CURRENT_POLICY.store(policy as u32, Ordering::Release);

    // Adjust P-state limits based on policy
    let min_p_state = match policy {
        PowerPolicy::Performance => PState::P0,
        PowerPolicy::Balanced => PState::P2,
        PowerPolicy::PowerSaver => PState::P4,
    };

    // Apply to all processors
    let count = ACTIVE_PROCESSORS.load(Ordering::Relaxed);
    for i in 0..count {
        if policy == PowerPolicy::Performance {
            ppm_set_performance_state(i, PState::P0);
        } else {
            // Let the scheduler decide based on load
            unsafe {
                PROCESSOR_POWER[i as usize].target_p_state.store(min_p_state as u32, Ordering::Relaxed);
            }
        }
    }
}

/// Get current power policy
pub fn ppm_get_power_policy() -> PowerPolicy {
    match CURRENT_POLICY.load(Ordering::Relaxed) {
        0 => PowerPolicy::Performance,
        1 => PowerPolicy::Balanced,
        2 => PowerPolicy::PowerSaver,
        _ => PowerPolicy::Balanced,
    }
}

// ============================================================================
// Processor Registration
// ============================================================================

/// Register a processor with PPM
pub fn ppm_register_processor(processor: u32) {
    if processor as usize >= MAX_PROCESSORS {
        return;
    }

    unsafe {
        PROCESSOR_POWER[processor as usize] = ProcessorPowerState::new(processor);
    }

    ACTIVE_PROCESSORS.fetch_max(processor + 1, Ordering::Relaxed);
}

/// Unregister a processor
pub fn ppm_unregister_processor(processor: u32) {
    if processor as usize >= MAX_PROCESSORS {
        return;
    }

    unsafe {
        PROCESSOR_POWER[processor as usize].idle.store(true, Ordering::Release);
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// PPM statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct PpmStats {
    pub active_processors: u32,
    pub current_policy: PowerPolicy,
    pub total_c_state_transitions: u64,
    pub total_p_state_transitions: u64,
    pub total_idle_time: u64,
    pub mwait_supported: bool,
    pub speedstep_supported: bool,
}

/// Get PPM statistics
pub fn ppm_get_stats() -> PpmStats {
    PpmStats {
        active_processors: ACTIVE_PROCESSORS.load(Ordering::Relaxed),
        current_policy: ppm_get_power_policy(),
        total_c_state_transitions: TOTAL_C_STATE_TRANSITIONS.load(Ordering::Relaxed),
        total_p_state_transitions: TOTAL_P_STATE_TRANSITIONS.load(Ordering::Relaxed),
        total_idle_time: TOTAL_IDLE_TIME.load(Ordering::Relaxed),
        mwait_supported: ppm_is_mwait_supported(),
        speedstep_supported: ppm_is_speedstep_supported(),
    }
}

/// Per-processor power information
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessorPowerInfo {
    pub processor_id: u32,
    pub current_c_state: CState,
    pub current_p_state: PState,
    pub idle: bool,
    pub temperature: u32,
    pub thermal_throttle: bool,
}

/// Get processor power information
pub fn ppm_get_processor_info(processor: u32) -> Option<ProcessorPowerInfo> {
    if processor as usize >= MAX_PROCESSORS {
        return None;
    }

    unsafe {
        let state = &PROCESSOR_POWER[processor as usize];

        Some(ProcessorPowerInfo {
            processor_id: processor,
            current_c_state: state.get_c_state(),
            current_p_state: state.get_p_state(),
            idle: state.idle.load(Ordering::Relaxed),
            temperature: state.temperature.load(Ordering::Relaxed),
            thermal_throttle: state.thermal_throttle.load(Ordering::Relaxed),
        })
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize PPM subsystem
pub fn init() {
    let _guard = unsafe { PPM_LOCK.lock() };

    unsafe {
        for (i, state) in PROCESSOR_POWER.iter_mut().enumerate() {
            *state = ProcessorPowerState::new(i as u32);
        }
    }

    CURRENT_POLICY.store(PowerPolicy::Balanced as u32, Ordering::Relaxed);
    ACTIVE_PROCESSORS.store(1, Ordering::Relaxed);
    TOTAL_C_STATE_TRANSITIONS.store(0, Ordering::Relaxed);
    TOTAL_P_STATE_TRANSITIONS.store(0, Ordering::Relaxed);
    TOTAL_IDLE_TIME.store(0, Ordering::Relaxed);

    // Register BSP (bootstrap processor)
    ppm_register_processor(0);

    // Detect capabilities
    let mwait = ppm_is_mwait_supported();
    let speedstep = ppm_is_speedstep_supported();

    PPM_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[HAL] PPM initialized (MWAIT: {}, SpeedStep: {})", mwait, speedstep);
}

/// Check if PPM is initialized
pub fn ppm_is_initialized() -> bool {
    PPM_INITIALIZED.load(Ordering::Acquire)
}
