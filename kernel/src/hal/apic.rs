//! Local APIC (Advanced Programmable Interrupt Controller)
//!
//! Provides timer and inter-processor interrupt functionality.
//! The Local APIC is memory-mapped at 0xFEE00000 (default) or
//! at the address specified in MSR 0x1B.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};

/// Default Local APIC base address
const APIC_DEFAULT_BASE: u64 = 0xFEE0_0000;

/// APIC Register offsets
mod reg {
    pub const ID: u32 = 0x020;              // Local APIC ID
    pub const VERSION: u32 = 0x030;         // Local APIC Version
    pub const TPR: u32 = 0x080;             // Task Priority Register
    pub const EOI: u32 = 0x0B0;             // End of Interrupt
    pub const SPURIOUS: u32 = 0x0F0;        // Spurious Interrupt Vector
    pub const ICR_LOW: u32 = 0x300;         // Interrupt Command (low)
    pub const ICR_HIGH: u32 = 0x310;        // Interrupt Command (high)
    pub const LVT_TIMER: u32 = 0x320;       // LVT Timer Register
    pub const LVT_THERMAL: u32 = 0x330;     // LVT Thermal Sensor
    pub const LVT_PERF: u32 = 0x340;        // LVT Performance Counter
    pub const LVT_LINT0: u32 = 0x350;       // LVT LINT0
    pub const LVT_LINT1: u32 = 0x360;       // LVT LINT1
    pub const LVT_ERROR: u32 = 0x370;       // LVT Error
    pub const TIMER_INIT: u32 = 0x380;      // Timer Initial Count
    pub const TIMER_CURRENT: u32 = 0x390;   // Timer Current Count
    pub const TIMER_DIVIDE: u32 = 0x3E0;    // Timer Divide Configuration
}

/// LVT Timer modes
mod timer_mode {
    pub const ONE_SHOT: u32 = 0b00 << 17;
    pub const PERIODIC: u32 = 0b01 << 17;
    pub const TSC_DEADLINE: u32 = 0b10 << 17;
}

/// Timer divider values (maps to actual divisor)
/// Value -> Divisor: 0->2, 1->4, 2->8, 3->16, 8->32, 9->64, 10->128, 11->1
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum TimerDivide {
    Div2 = 0b0000,
    Div4 = 0b0001,
    Div8 = 0b0010,
    Div16 = 0b0011,
    Div32 = 0b1000,
    Div64 = 0b1001,
    Div128 = 0b1010,
    Div1 = 0b1011,
}

/// System tick counter (incremented by timer interrupt)
pub static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Local APIC instance
pub struct LocalApic {
    base_addr: u64,
}

/// Global APIC instance
static mut LOCAL_APIC: Option<LocalApic> = None;

impl LocalApic {
    /// Create a new Local APIC instance
    /// Reads the base address from MSR 0x1B
    pub fn new() -> Self {
        let base = unsafe {
            let lo: u32;
            let hi: u32;
            core::arch::asm!(
                "rdmsr",
                in("ecx") 0x1Bu32,
                out("eax") lo,
                out("edx") hi,
            );
            // Combine low and high parts, base address is bits 12-35
            let msr_value = ((hi as u64) << 32) | (lo as u64);
            msr_value & 0xFFFF_F000
        };

        // If MSR returns 0, use default
        let base_addr = if base == 0 { APIC_DEFAULT_BASE } else { base };

        Self { base_addr }
    }

    /// Read an APIC register
    #[inline]
    fn read(&self, offset: u32) -> u32 {
        unsafe {
            read_volatile((self.base_addr + offset as u64) as *const u32)
        }
    }

    /// Write to an APIC register
    #[inline]
    fn write(&self, offset: u32, value: u32) {
        unsafe {
            write_volatile((self.base_addr + offset as u64) as *mut u32, value);
        }
    }

    /// Initialize the Local APIC
    pub fn init(&self) {
        // Enable APIC via spurious interrupt vector register
        // Set bit 8 (APIC enable) and spurious vector to 0xFF
        self.write(reg::SPURIOUS, 0x1FF);

        // Clear task priority to accept all interrupts
        self.write(reg::TPR, 0);

        // Mask all LVT entries initially
        self.write(reg::LVT_TIMER, 1 << 16);    // Masked
        self.write(reg::LVT_THERMAL, 1 << 16);
        self.write(reg::LVT_PERF, 1 << 16);
        self.write(reg::LVT_LINT0, 1 << 16);
        self.write(reg::LVT_LINT1, 1 << 16);
        self.write(reg::LVT_ERROR, 1 << 16);
    }

    /// Get the Local APIC ID
    pub fn id(&self) -> u8 {
        ((self.read(reg::ID) >> 24) & 0xFF) as u8
    }

    /// Get the APIC version
    pub fn version(&self) -> u32 {
        self.read(reg::VERSION)
    }

    /// Configure the timer in periodic mode
    ///
    /// # Arguments
    /// * `vector` - Interrupt vector number (32-255)
    /// * `divider` - Timer clock divider
    /// * `initial_count` - Initial counter value (determines frequency)
    pub fn set_timer_periodic(&self, vector: u8, divider: TimerDivide, initial_count: u32) {
        // Set divide configuration
        self.write(reg::TIMER_DIVIDE, divider as u32);

        // Set LVT timer: periodic mode, not masked, specified vector
        let lvt = timer_mode::PERIODIC | (vector as u32);
        self.write(reg::LVT_TIMER, lvt);

        // Set initial count (starts the timer)
        self.write(reg::TIMER_INIT, initial_count);
    }

    /// Configure the timer in one-shot mode
    pub fn set_timer_oneshot(&self, vector: u8, divider: TimerDivide, initial_count: u32) {
        self.write(reg::TIMER_DIVIDE, divider as u32);
        let lvt = timer_mode::ONE_SHOT | (vector as u32);
        self.write(reg::LVT_TIMER, lvt);
        self.write(reg::TIMER_INIT, initial_count);
    }

    /// Stop the timer
    pub fn stop_timer(&self) {
        // Mask the timer
        self.write(reg::LVT_TIMER, 1 << 16);
        self.write(reg::TIMER_INIT, 0);
    }

    /// Read current timer count
    pub fn timer_current(&self) -> u32 {
        self.read(reg::TIMER_CURRENT)
    }

    /// Send End of Interrupt
    #[inline]
    pub fn eoi(&self) {
        self.write(reg::EOI, 0);
    }

    /// Get the APIC base address
    pub fn base_address(&self) -> u64 {
        self.base_addr
    }
}

/// Initialize the global APIC instance
pub fn init() {
    // Reset tick count to 0 (important since .bss may not be zeroed by bootloader)
    TICK_COUNT.store(0, Ordering::Relaxed);

    let apic = LocalApic::new();
    apic.init();

    unsafe {
        LOCAL_APIC = Some(apic);
    }
}

/// Get a reference to the global APIC
pub fn get() -> &'static LocalApic {
    unsafe {
        LOCAL_APIC.as_ref().expect("APIC not initialized")
    }
}

/// Send End of Interrupt (convenience function)
#[inline]
pub fn eoi() {
    get().eoi();
}

/// Start the APIC timer with a target frequency
///
/// # Arguments
/// * `vector` - Interrupt vector (should be 32 for timer)
/// * `frequency_hz` - Target frequency in Hz (e.g., 1000 for 1kHz)
///
/// Note: The actual frequency depends on the bus clock and may not be exact.
/// For a 100MHz bus with divider 16, initial_count of 6250 gives ~1000Hz.
pub fn start_timer(vector: u8, frequency_hz: u32) {
    let apic = get();

    // Use divider of 16 for reasonable precision
    // Typical bus frequency is 100MHz-200MHz
    // For 100MHz / 16 = 6.25MHz base
    // 6.25MHz / 1000Hz = 6250 count for 1ms period

    // We'll use a reasonable default assuming ~100MHz bus
    // The actual frequency can be calibrated later using PIT or TSC
    let base_freq = 6_250_000u32; // Assumed 6.25MHz after divide by 16
    let initial_count = base_freq / frequency_hz;

    apic.set_timer_periodic(vector, TimerDivide::Div16, initial_count);
}

/// Get the current tick count
#[inline]
pub fn get_tick_count() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
}
