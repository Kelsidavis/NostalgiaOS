//! Driver Verifier Settings
//!
//! Manages verifier options and configuration flags.

// Verifier flags - high-level feature categories
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct VerifierFlags: u32 {
        /// Special pool for allocations (catch overruns/underruns)
        const SPECIAL_POOL = 0x00000001;
        /// Force IRQL checking
        const FORCE_IRQL_CHECKING = 0x00000002;
        /// Low resources simulation
        const LOW_RESOURCES_SIMULATION = 0x00000004;
        /// Pool tracking
        const POOL_TRACKING = 0x00000008;
        /// I/O verification
        const IO_CHECKING = 0x00000010;
        /// Deadlock detection
        const DEADLOCK_DETECTION = 0x00000020;
        /// Enhanced I/O verification
        const ENHANCED_IO_CHECKING = 0x00000040;
        /// DMA verification
        const DMA_CHECKING = 0x00000080;
        /// Security checks
        const SECURITY_CHECKING = 0x00000100;
        /// Force pending I/O requests
        const FORCE_PENDING = 0x00000200;
        /// IRP logging
        const IRP_LOGGING = 0x00000400;
        /// Miscellaneous checks
        const MISC_CHECKING = 0x00000800;
        /// DDI compliance checking
        const DDI_COMPLIANCE = 0x00001000;
        /// Power framework delay fuzzing
        const POWER_FRAMEWORK_DELAY = 0x00002000;
        /// Port/miniport interface checking
        const PORT_MINIPORT = 0x00004000;
    }
}

// Verifier options - granular settings
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct VerifierOptions: u64 {
        // IRP verification options
        /// Track IRP history
        const TRACK_IRPS = 0x0000_0000_0000_0001;
        /// Monitor IRP allocations
        const MONITOR_IRP_ALLOCS = 0x0000_0000_0000_0002;
        /// Police IRP handling
        const POLICE_IRPS = 0x0000_0000_0000_0004;
        /// Monitor major functions
        const MONITOR_MAJORS = 0x0000_0000_0000_0008;
        /// Monitor pending I/O
        const MONITOR_PENDING_IO = 0x0000_0000_0000_0010;
        /// Monitor device removal
        const MONITOR_REMOVES = 0x0000_0000_0000_0020;
        /// Defer IRP completion
        const DEFER_COMPLETION = 0x0000_0000_0000_0040;
        /// Complete at passive level
        const COMPLETE_AT_PASSIVE = 0x0000_0000_0000_0080;
        /// Force pending on IRPs
        const FORCE_PENDING = 0x0000_0000_0000_0100;
        /// Expose IRP history to debugger
        const EXPOSE_IRP_HISTORY = 0x0000_0000_0000_0200;

        // Pool verification options
        /// Use special pool
        const SPECIAL_POOL = 0x0000_0000_0000_1000;
        /// Track pool allocations
        const TRACK_POOL = 0x0000_0000_0000_2000;
        /// Detect pool corruptions
        const DETECT_POOL_CORRUPTION = 0x0000_0000_0000_4000;
        /// Fill freed pool with pattern
        const FILL_FREED_POOL = 0x0000_0000_0000_8000;

        // Deadlock detection options
        /// Enable deadlock detection
        const DETECT_DEADLOCKS = 0x0000_0000_0001_0000;
        /// Strict deadlock checking
        const DEADLOCK_STRICT = 0x0000_0000_0002_0000;
        /// Only verify spinlocks
        const DEADLOCK_SPINLOCKS_ONLY = 0x0000_0000_0004_0000;

        // DMA verification options
        /// Verify DMA operations
        const VERIFY_DMA = 0x0000_0000_0010_0000;
        /// Double buffer DMA
        const DOUBLE_BUFFER_DMA = 0x0000_0000_0020_0000;

        // Miscellaneous options
        /// Seed stack with pattern
        const SEED_STACK = 0x0000_0000_0100_0000;
        /// Inject faults
        const FAULT_INJECTION = 0x0000_0000_0200_0000;
        /// Insert WDM filter drivers
        const INSERT_WDM_FILTERS = 0x0000_0000_0400_0000;
        /// Verify device object flags
        const VERIFY_DO_FLAGS = 0x0000_0000_0800_0000;

        // Power/PnP options
        /// Send bogus WMI IRPs
        const SEND_BOGUS_WMI_IRPS = 0x0000_0000_1000_0000;
        /// Send bogus power IRPs
        const SEND_BOGUS_POWER_IRPS = 0x0000_0000_2000_0000;
        /// Test relation ignorance
        const RELATION_IGNORANCE_TEST = 0x0000_0000_4000_0000;
        /// Examine relation PDOs
        const EXAMINE_RELATION_PDOS = 0x0000_0000_8000_0000;
    }
}

/// Verifier settings structure
#[derive(Debug, Clone)]
pub struct VerifierSettings {
    /// High-level feature flags
    pub flags: VerifierFlags,
    /// Granular options
    pub options: VerifierOptions,
    /// IRP deferral time in microseconds
    pub irp_deferral_time_us: u32,
    /// Number of IRPs to log per device
    pub irps_to_log_per_device: u32,
    /// Fault injection probability (0-100)
    pub fault_injection_probability: u8,
    /// Pool allocation tracking limit
    pub pool_tracking_limit: u32,
    /// Deadlock age window for trimming
    pub deadlock_age_window: u32,
    /// Deadlock trim threshold
    pub deadlock_trim_threshold: u32,
}

impl VerifierSettings {
    pub const fn new() -> Self {
        Self {
            flags: VerifierFlags::empty(),
            options: VerifierOptions::empty(),
            irp_deferral_time_us: 300,
            irps_to_log_per_device: 20,
            fault_injection_probability: 0,
            pool_tracking_limit: 65536,
            deadlock_age_window: 0x2000,
            deadlock_trim_threshold: 0x100,
        }
    }

    /// Check if a flag is set
    pub fn is_flag_set(&self, flag: VerifierFlags) -> bool {
        self.flags.contains(flag)
    }

    /// Check if an option is enabled
    pub fn is_option_set(&self, option: VerifierOptions) -> bool {
        self.options.contains(option)
    }
}

impl Default for VerifierSettings {
    fn default() -> Self {
        Self::new()
    }
}

/// Verifier level presets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierLevel {
    /// No verification
    None,
    /// Minimal verification (basic pool and IRP tracking)
    Minimal,
    /// Standard verification (IO checking, pool tracking)
    Standard,
    /// Full verification (all checks enabled)
    Full,
    /// Custom (use flags directly)
    Custom(VerifierFlags),
}

impl VerifierLevel {
    /// Convert level to flags
    pub fn to_flags(self) -> VerifierFlags {
        match self {
            VerifierLevel::None => VerifierFlags::empty(),
            VerifierLevel::Minimal => VerifierFlags::POOL_TRACKING | VerifierFlags::IO_CHECKING,
            VerifierLevel::Standard => {
                VerifierFlags::SPECIAL_POOL
                    | VerifierFlags::FORCE_IRQL_CHECKING
                    | VerifierFlags::POOL_TRACKING
                    | VerifierFlags::IO_CHECKING
                    | VerifierFlags::DEADLOCK_DETECTION
            }
            VerifierLevel::Full => {
                VerifierFlags::SPECIAL_POOL
                    | VerifierFlags::FORCE_IRQL_CHECKING
                    | VerifierFlags::LOW_RESOURCES_SIMULATION
                    | VerifierFlags::POOL_TRACKING
                    | VerifierFlags::IO_CHECKING
                    | VerifierFlags::DEADLOCK_DETECTION
                    | VerifierFlags::ENHANCED_IO_CHECKING
                    | VerifierFlags::DMA_CHECKING
                    | VerifierFlags::SECURITY_CHECKING
                    | VerifierFlags::IRP_LOGGING
                    | VerifierFlags::MISC_CHECKING
            }
            VerifierLevel::Custom(flags) => flags,
        }
    }
}

/// Verifier violation severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ViolationSeverity {
    /// Informational - logged but no action
    Info = 0,
    /// Warning - logged, may continue
    Warning = 1,
    /// Error - logged, operation may fail
    Error = 2,
    /// Critical - bugcheck imminent
    Critical = 3,
}

/// Verifier violation action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationAction {
    /// Log only
    Log,
    /// Log and break into debugger
    Break,
    /// Bugcheck immediately
    Bugcheck,
    /// Ignore (for testing)
    Ignore,
}

/// Per-violation configuration
#[derive(Debug, Clone, Copy)]
pub struct ViolationConfig {
    /// Whether this violation is enabled
    pub enabled: bool,
    /// Severity level
    pub severity: ViolationSeverity,
    /// Action to take
    pub action: ViolationAction,
}

impl Default for ViolationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            severity: ViolationSeverity::Error,
            action: ViolationAction::Log,
        }
    }
}
