//! CPU Identification
//!
//! Provides CPU feature detection and identification:
//!
//! - **Vendor**: Intel, AMD, VIA, etc.
//! - **Model**: Family, model, stepping
//! - **Features**: SSE, AVX, virtualization, etc.
//! - **Capabilities**: Performance, security features
//!
//! # CPU Vendors
//!
//! - Intel: "GenuineIntel"
//! - AMD: "AuthenticAMD"
//! - VIA: "VIA VIA VIA "
//! - Hygon: "HygonGenuine"
//!
//! # Feature Categories
//!
//! - Basic: FPU, MMX, SSE, SSE2
//! - Extended: SSE3, SSSE3, SSE4.1, SSE4.2
//! - Advanced: AVX, AVX2, AVX-512
//! - Security: AES-NI, SHA, SGX
//! - Virtualization: VMX, SVM
//!
//! # NT Functions
//!
//! - `ExIsProcessorFeaturePresent` - Check feature
//! - `KeGetProcessorIndexFromNumber` - CPU mapping
//!
//! # Usage
//!
//! ```ignore
//! // Get CPU vendor
//! let vendor = cpuid_get_vendor();
//!
//! // Check feature
//! if cpuid_has_feature(Feature::Avx2) {
//!     // Use AVX2
//! }
//! ```

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;

// ============================================================================
// Constants
// ============================================================================

/// Maximum CPUID basic leaf
pub const MAX_BASIC_LEAF: u32 = 0x20;

/// Maximum CPUID extended leaf
pub const MAX_EXTENDED_LEAF: u32 = 0x80000020;

// ============================================================================
// Types
// ============================================================================

/// CPU vendor
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CpuVendor {
    #[default]
    Unknown = 0,
    Intel = 1,
    Amd = 2,
    Via = 3,
    Hygon = 4,
    Centaur = 5,
    Cyrix = 6,
    Transmeta = 7,
    Virtual = 8,
}

/// CPU feature flags
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuFeature {
    // Basic features (CPUID.01H:EDX)
    Fpu = 0,
    Vme = 1,
    De = 2,
    Pse = 3,
    Tsc = 4,
    Msr = 5,
    Pae = 6,
    Mce = 7,
    Cx8 = 8,
    Apic = 9,
    Sep = 11,
    Mtrr = 12,
    Pge = 13,
    Mca = 14,
    Cmov = 15,
    Pat = 16,
    Pse36 = 17,
    Psn = 18,
    Clfsh = 19,
    Ds = 21,
    Acpi = 22,
    Mmx = 23,
    Fxsr = 24,
    Sse = 25,
    Sse2 = 26,
    Ss = 27,
    Htt = 28,
    Tm = 29,
    Ia64 = 30,
    Pbe = 31,

    // Extended features (CPUID.01H:ECX)
    Sse3 = 32,
    Pclmulqdq = 33,
    Dtes64 = 34,
    Monitor = 35,
    DsCpl = 36,
    Vmx = 37,
    Smx = 38,
    Est = 39,
    Tm2 = 40,
    Ssse3 = 41,
    CntxId = 42,
    Sdbg = 43,
    Fma = 44,
    Cx16 = 45,
    Xtpr = 46,
    Pdcm = 47,
    Pcid = 49,
    Dca = 50,
    Sse41 = 51,
    Sse42 = 52,
    X2apic = 53,
    Movbe = 54,
    Popcnt = 55,
    TscDeadline = 56,
    AesNi = 57,
    Xsave = 58,
    Osxsave = 59,
    Avx = 60,
    F16c = 61,
    Rdrand = 62,
    Hypervisor = 63,

    // Extended features (CPUID.07H:EBX)
    Fsgsbase = 64,
    Tsc_Adjust = 65,
    Sgx = 66,
    Bmi1 = 67,
    Hle = 68,
    Avx2 = 69,
    Smep = 71,
    Bmi2 = 72,
    Erms = 73,
    Invpcid = 74,
    Rtm = 75,
    Pqm = 76,
    Mpx = 78,
    Pqe = 79,
    Avx512f = 80,
    Avx512dq = 81,
    Rdseed = 82,
    Adx = 83,
    Smap = 84,
    Avx512ifma = 85,
    Clflushopt = 87,
    Clwb = 88,
    IntelPt = 89,
    Avx512pf = 90,
    Avx512er = 91,
    Avx512cd = 92,
    Sha = 93,
    Avx512bw = 94,
    Avx512vl = 95,

    // AMD extended features (CPUID.80000001H:ECX)
    Lahf = 128,
    CmpLegacy = 129,
    Svm = 130,
    Extapic = 131,
    Cr8Legacy = 132,
    Abm = 133,
    Sse4a = 134,
    MisalignSse = 135,
    Prefetch3d = 136,
    Osvw = 137,
    Ibs = 138,
    Xop = 139,
    Skinit = 140,
    Wdt = 141,
    Lwp = 143,
    Fma4 = 144,
    Tce = 145,
    Tbm = 149,
    TopoExt = 150,
    PerfctrCore = 151,
    PerfctrNb = 152,
}

/// CPU model information
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuModel {
    /// CPU vendor
    pub vendor: CpuVendor,
    /// Family (base + extended)
    pub family: u16,
    /// Model (base + extended)
    pub model: u16,
    /// Stepping
    pub stepping: u8,
    /// Processor type
    pub proc_type: u8,
    /// Brand ID
    pub brand_id: u8,
    /// CLFLUSH line size (bytes)
    pub clflush_size: u8,
    /// Maximum logical CPUs
    pub max_logical_cpus: u8,
    /// Initial APIC ID
    pub initial_apic_id: u8,
}

/// CPU capabilities
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuCapabilities {
    /// Maximum basic CPUID leaf
    pub max_basic_leaf: u32,
    /// Maximum extended CPUID leaf
    pub max_extended_leaf: u32,
    /// Feature bits (EDX from leaf 1)
    pub features_edx: u32,
    /// Feature bits (ECX from leaf 1)
    pub features_ecx: u32,
    /// Extended feature bits (EBX from leaf 7)
    pub ext_features_ebx: u32,
    /// Extended feature bits (ECX from leaf 7)
    pub ext_features_ecx: u32,
    /// AMD features (ECX from leaf 0x80000001)
    pub amd_features_ecx: u32,
    /// AMD features (EDX from leaf 0x80000001)
    pub amd_features_edx: u32,
}

// ============================================================================
// Global State
// ============================================================================

static CPUID_LOCK: SpinLock<()> = SpinLock::new(());
static CPUID_INITIALIZED: AtomicBool = AtomicBool::new(false);

static CPU_VENDOR: AtomicU32 = AtomicU32::new(CpuVendor::Unknown as u32);
static CPU_FAMILY: AtomicU32 = AtomicU32::new(0);
static CPU_MODEL: AtomicU32 = AtomicU32::new(0);
static CPU_STEPPING: AtomicU32 = AtomicU32::new(0);

static FEATURES_EDX: AtomicU32 = AtomicU32::new(0);
static FEATURES_ECX: AtomicU32 = AtomicU32::new(0);
static EXT_FEATURES_EBX: AtomicU32 = AtomicU32::new(0);
static EXT_FEATURES_ECX: AtomicU32 = AtomicU32::new(0);
static AMD_FEATURES_ECX: AtomicU32 = AtomicU32::new(0);
static AMD_FEATURES_EDX: AtomicU32 = AtomicU32::new(0);

static MAX_BASIC_LEAF_VAL: AtomicU32 = AtomicU32::new(0);
static MAX_EXTENDED_LEAF_VAL: AtomicU32 = AtomicU32::new(0);

/// Vendor string (12 bytes)
static mut VENDOR_STRING: [u8; 12] = [0; 12];

/// Brand string (48 bytes)
static mut BRAND_STRING: [u8; 48] = [0; 48];

static FEATURE_QUERIES: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Raw CPUID Access
// ============================================================================

/// Execute CPUID instruction
#[inline]
pub fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let (eax, ebx, ecx, edx): (u32, u32, u32, u32);
        core::arch::asm!(
            "push rbx",
            "mov eax, {0:e}",
            "mov ecx, {1:e}",
            "cpuid",
            "mov {2:e}, ebx",
            "pop rbx",
            in(reg) leaf,
            in(reg) subleaf,
            out(reg) ebx,
            out("eax") eax,
            out("ecx") ecx,
            out("edx") edx,
            options(preserves_flags)
        );
        (eax, ebx, ecx, edx)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        (0, 0, 0, 0)
    }
}

/// Execute CPUID without subleaf
#[inline]
pub fn cpuid_leaf(leaf: u32) -> (u32, u32, u32, u32) {
    cpuid(leaf, 0)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize CPUID subsystem
pub fn init() {
    let _guard = CPUID_LOCK.lock();

    // Get vendor string
    let (max_leaf, ebx, ecx, edx) = cpuid_leaf(0);
    MAX_BASIC_LEAF_VAL.store(max_leaf, Ordering::Relaxed);

    unsafe {
        VENDOR_STRING[0..4].copy_from_slice(&ebx.to_le_bytes());
        VENDOR_STRING[4..8].copy_from_slice(&edx.to_le_bytes());
        VENDOR_STRING[8..12].copy_from_slice(&ecx.to_le_bytes());
    }

    // Identify vendor
    let vendor = match unsafe { &VENDOR_STRING } {
        b"GenuineIntel" => CpuVendor::Intel,
        b"AuthenticAMD" => CpuVendor::Amd,
        b"VIA VIA VIA " => CpuVendor::Via,
        b"HygonGenuine" => CpuVendor::Hygon,
        b"CentaurHauls" => CpuVendor::Centaur,
        b"CyrixInstead" => CpuVendor::Cyrix,
        b"GenuineTMx86" => CpuVendor::Transmeta,
        _ => {
            // Check for hypervisor
            let (_, _, hv_ecx, _) = cpuid_leaf(1);
            if (hv_ecx & (1 << 31)) != 0 {
                CpuVendor::Virtual
            } else {
                CpuVendor::Unknown
            }
        }
    };
    CPU_VENDOR.store(vendor as u32, Ordering::Relaxed);

    // Get basic features
    if max_leaf >= 1 {
        let (eax, _ebx, ecx, edx) = cpuid_leaf(1);

        let stepping = (eax & 0xF) as u8;
        let model = ((eax >> 4) & 0xF) as u8;
        let family = ((eax >> 8) & 0xF) as u8;
        let ext_model = ((eax >> 16) & 0xF) as u8;
        let ext_family = ((eax >> 20) & 0xFF) as u8;

        let full_family = if family == 0xF {
            family as u16 + ext_family as u16
        } else {
            family as u16
        };

        let full_model = if family == 0x6 || family == 0xF {
            model as u16 + ((ext_model as u16) << 4)
        } else {
            model as u16
        };

        CPU_FAMILY.store(full_family as u32, Ordering::Relaxed);
        CPU_MODEL.store(full_model as u32, Ordering::Relaxed);
        CPU_STEPPING.store(stepping as u32, Ordering::Relaxed);

        FEATURES_EDX.store(edx, Ordering::Relaxed);
        FEATURES_ECX.store(ecx, Ordering::Relaxed);
    }

    // Get extended features
    if max_leaf >= 7 {
        let (_, ebx, ecx, _) = cpuid(7, 0);
        EXT_FEATURES_EBX.store(ebx, Ordering::Relaxed);
        EXT_FEATURES_ECX.store(ecx, Ordering::Relaxed);
    }

    // Get maximum extended leaf
    let (max_ext, _, _, _) = cpuid_leaf(0x80000000);
    MAX_EXTENDED_LEAF_VAL.store(max_ext, Ordering::Relaxed);

    // Get AMD features
    if max_ext >= 0x80000001 {
        let (_, _, ecx, edx) = cpuid_leaf(0x80000001);
        AMD_FEATURES_ECX.store(ecx, Ordering::Relaxed);
        AMD_FEATURES_EDX.store(edx, Ordering::Relaxed);
    }

    // Get brand string
    if max_ext >= 0x80000004 {
        unsafe {
            for i in 0..3 {
                let (eax, ebx, ecx, edx) = cpuid_leaf(0x80000002 + i);
                let offset = (i as usize) * 16;
                BRAND_STRING[offset..offset + 4].copy_from_slice(&eax.to_le_bytes());
                BRAND_STRING[offset + 4..offset + 8].copy_from_slice(&ebx.to_le_bytes());
                BRAND_STRING[offset + 8..offset + 12].copy_from_slice(&ecx.to_le_bytes());
                BRAND_STRING[offset + 12..offset + 16].copy_from_slice(&edx.to_le_bytes());
            }
        }
    }

    CPUID_INITIALIZED.store(true, Ordering::Release);

    let family = CPU_FAMILY.load(Ordering::Relaxed);
    let model = CPU_MODEL.load(Ordering::Relaxed);
    crate::serial_println!(
        "[CPUID] {:?} Family {} Model {} Step {}",
        vendor, family, model, CPU_STEPPING.load(Ordering::Relaxed)
    );
}

// ============================================================================
// Feature Detection
// ============================================================================

/// Check if a CPU feature is present
pub fn cpuid_has_feature(feature: CpuFeature) -> bool {
    FEATURE_QUERIES.fetch_add(1, Ordering::Relaxed);

    let feature_num = feature as u32;

    if feature_num < 32 {
        // EDX from leaf 1
        (FEATURES_EDX.load(Ordering::Relaxed) & (1 << feature_num)) != 0
    } else if feature_num < 64 {
        // ECX from leaf 1
        (FEATURES_ECX.load(Ordering::Relaxed) & (1 << (feature_num - 32))) != 0
    } else if feature_num < 96 {
        // EBX from leaf 7
        (EXT_FEATURES_EBX.load(Ordering::Relaxed) & (1 << (feature_num - 64))) != 0
    } else if feature_num < 128 {
        // ECX from leaf 7
        (EXT_FEATURES_ECX.load(Ordering::Relaxed) & (1 << (feature_num - 96))) != 0
    } else if feature_num < 160 {
        // AMD ECX from leaf 0x80000001
        (AMD_FEATURES_ECX.load(Ordering::Relaxed) & (1 << (feature_num - 128))) != 0
    } else {
        // AMD EDX from leaf 0x80000001
        (AMD_FEATURES_EDX.load(Ordering::Relaxed) & (1 << (feature_num - 160))) != 0
    }
}

/// Check for multiple features at once
pub fn cpuid_has_features(features: &[CpuFeature]) -> bool {
    features.iter().all(|&f| cpuid_has_feature(f))
}

// ============================================================================
// Query Functions
// ============================================================================

/// Get CPU vendor
pub fn cpuid_get_vendor() -> CpuVendor {
    match CPU_VENDOR.load(Ordering::Relaxed) {
        1 => CpuVendor::Intel,
        2 => CpuVendor::Amd,
        3 => CpuVendor::Via,
        4 => CpuVendor::Hygon,
        5 => CpuVendor::Centaur,
        6 => CpuVendor::Cyrix,
        7 => CpuVendor::Transmeta,
        8 => CpuVendor::Virtual,
        _ => CpuVendor::Unknown,
    }
}

/// Get vendor string
pub fn cpuid_get_vendor_string() -> &'static [u8; 12] {
    unsafe { &VENDOR_STRING }
}

/// Get brand string
pub fn cpuid_get_brand_string() -> &'static [u8; 48] {
    unsafe { &BRAND_STRING }
}

/// Get CPU model information
pub fn cpuid_get_model() -> CpuModel {
    CpuModel {
        vendor: cpuid_get_vendor(),
        family: CPU_FAMILY.load(Ordering::Relaxed) as u16,
        model: CPU_MODEL.load(Ordering::Relaxed) as u16,
        stepping: CPU_STEPPING.load(Ordering::Relaxed) as u8,
        proc_type: 0,
        brand_id: 0,
        clflush_size: 64,
        max_logical_cpus: 0,
        initial_apic_id: 0,
    }
}

/// Get CPU capabilities
pub fn cpuid_get_capabilities() -> CpuCapabilities {
    CpuCapabilities {
        max_basic_leaf: MAX_BASIC_LEAF_VAL.load(Ordering::Relaxed),
        max_extended_leaf: MAX_EXTENDED_LEAF_VAL.load(Ordering::Relaxed),
        features_edx: FEATURES_EDX.load(Ordering::Relaxed),
        features_ecx: FEATURES_ECX.load(Ordering::Relaxed),
        ext_features_ebx: EXT_FEATURES_EBX.load(Ordering::Relaxed),
        ext_features_ecx: EXT_FEATURES_ECX.load(Ordering::Relaxed),
        amd_features_ecx: AMD_FEATURES_ECX.load(Ordering::Relaxed),
        amd_features_edx: AMD_FEATURES_EDX.load(Ordering::Relaxed),
    }
}

/// Check if running in virtual machine
pub fn cpuid_is_virtual() -> bool {
    cpuid_get_vendor() == CpuVendor::Virtual || cpuid_has_feature(CpuFeature::Hypervisor)
}

/// Check if CPUID is initialized
pub fn cpuid_is_initialized() -> bool {
    CPUID_INITIALIZED.load(Ordering::Acquire)
}

// ============================================================================
// Statistics
// ============================================================================

/// CPUID statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuidStats {
    pub initialized: bool,
    pub vendor: CpuVendor,
    pub family: u16,
    pub model: u16,
    pub stepping: u8,
    pub max_basic_leaf: u32,
    pub max_extended_leaf: u32,
    pub feature_queries: u64,
    pub is_virtual: bool,
}

/// Get CPUID statistics
pub fn cpuid_get_stats() -> CpuidStats {
    CpuidStats {
        initialized: CPUID_INITIALIZED.load(Ordering::Relaxed),
        vendor: cpuid_get_vendor(),
        family: CPU_FAMILY.load(Ordering::Relaxed) as u16,
        model: CPU_MODEL.load(Ordering::Relaxed) as u16,
        stepping: CPU_STEPPING.load(Ordering::Relaxed) as u8,
        max_basic_leaf: MAX_BASIC_LEAF_VAL.load(Ordering::Relaxed),
        max_extended_leaf: MAX_EXTENDED_LEAF_VAL.load(Ordering::Relaxed),
        feature_queries: FEATURE_QUERIES.load(Ordering::Relaxed),
        is_virtual: cpuid_is_virtual(),
    }
}

// ============================================================================
// NT Compatibility
// ============================================================================

/// ExIsProcessorFeaturePresent equivalent
pub fn ex_is_processor_feature_present(feature: u32) -> bool {
    // Map NT processor feature numbers to our features
    match feature {
        0 => cpuid_has_feature(CpuFeature::Fpu),      // PF_FLOATING_POINT_PRECISION_ERRATA
        1 => true,                                     // PF_FLOATING_POINT_EMULATED
        2 => cpuid_has_feature(CpuFeature::Cmov),     // PF_COMPARE_EXCHANGE_DOUBLE
        3 => cpuid_has_feature(CpuFeature::Mmx),      // PF_MMX_INSTRUCTIONS_AVAILABLE
        6 => cpuid_has_feature(CpuFeature::Pae),      // PF_PAE_ENABLED
        7 => cpuid_has_feature(CpuFeature::Pge),      // PF_3DNOW_INSTRUCTIONS_AVAILABLE
        8 => cpuid_has_feature(CpuFeature::Rdrand),   // PF_RDTSC_INSTRUCTION_AVAILABLE
        10 => cpuid_has_feature(CpuFeature::Cx16),    // PF_COMPARE_EXCHANGE128
        12 => true,                                    // PF_CHANNELS_ENABLED
        13 => cpuid_has_feature(CpuFeature::Sse),     // PF_XMMI_INSTRUCTIONS_AVAILABLE
        17 => cpuid_has_feature(CpuFeature::Sse2),    // PF_XMMI64_INSTRUCTIONS_AVAILABLE
        20 => true,                                    // PF_NX_ENABLED
        21 => cpuid_has_feature(CpuFeature::Sse3),    // PF_SSE3_INSTRUCTIONS_AVAILABLE
        23 => cpuid_has_feature(CpuFeature::Cx16),    // PF_COMPARE64_EXCHANGE128
        25 => cpuid_has_feature(CpuFeature::Ssse3),   // PF_SSSE3_INSTRUCTIONS_AVAILABLE
        26 => cpuid_has_feature(CpuFeature::Sse41),   // PF_SSE4_1_INSTRUCTIONS_AVAILABLE
        27 => cpuid_has_feature(CpuFeature::Sse42),   // PF_SSE4_2_INSTRUCTIONS_AVAILABLE
        28 => cpuid_has_feature(CpuFeature::Avx),     // PF_AVX_INSTRUCTIONS_AVAILABLE
        29 => cpuid_has_feature(CpuFeature::Avx2),    // PF_AVX2_INSTRUCTIONS_AVAILABLE
        _ => false,
    }
}
