//! Prefetch Support
//!
//! Implements Windows-style application prefetching for faster startup times.
//!
//! # Overview
//!
//! The prefetcher tracks file access patterns during application launches (scenarios)
//! and uses this information to proactively load data into cache for subsequent launches.
//!
//! # Key Concepts
//!
//! - **Scenario**: An application launch or boot sequence being traced
//! - **Trace**: Record of pages accessed during a scenario
//! - **Section Info**: Information about file sections accessed
//!
//! # NT API
//!
//! - `CcPfBeginTrace` - Start tracing a scenario
//! - `CcPfEndTrace` - End tracing and save prefetch data
//! - `CcPfQueryScenario` - Query prefetch information

use crate::ke::spinlock::SpinLock;
use alloc::vec::Vec;

extern crate alloc;

/// Maximum number of concurrent traces
pub const MAX_CONCURRENT_TRACES: usize = 8;

/// Maximum sections per trace
pub const MAX_SECTIONS_PER_TRACE: usize = 64;

/// Maximum pages per section
pub const MAX_PAGES_PER_SECTION: usize = 256;

/// Maximum file name length
pub const MAX_FILE_NAME_LEN: usize = 260;

/// Maximum prefetch scenarios stored
pub const MAX_PREFETCH_SCENARIOS: usize = 128;

/// Prefetch scenario type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioType {
    /// Boot scenario
    Boot = 0,
    /// Application launch
    App = 1,
    /// Video preview (Vista+)
    Video = 2,
    /// Layout optimization
    Layout = 3,
}

impl Default for ScenarioType {
    fn default() -> Self {
        ScenarioType::App
    }
}

/// Prefetch trace state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceState {
    /// Trace slot is free
    Free = 0,
    /// Trace is being collected
    Active = 1,
    /// Trace is being processed
    Processing = 2,
    /// Trace completed, data available
    Complete = 3,
}

impl Default for TraceState {
    fn default() -> Self {
        TraceState::Free
    }
}

/// Section information in a prefetch trace
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrefetchSectionInfo {
    /// File object (opaque pointer)
    pub file_object: usize,
    /// File name hash for quick lookup
    pub file_hash: u32,
    /// Section offset in file
    pub section_offset: u64,
    /// Section length
    pub section_length: u64,
    /// Pages accessed bitmap (up to 256 pages = 1MB with 4KB pages)
    pub pages_accessed: [u64; 4],
    /// Number of pages accessed
    pub page_count: u32,
    /// Is this a data section (vs code)?
    pub is_data: bool,
    /// File name (truncated)
    pub file_name: [u8; 64],
    /// File name length
    pub file_name_len: u8,
}

impl Default for PrefetchSectionInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl PrefetchSectionInfo {
    pub const fn new() -> Self {
        Self {
            file_object: 0,
            file_hash: 0,
            section_offset: 0,
            section_length: 0,
            pages_accessed: [0; 4],
            page_count: 0,
            is_data: false,
            file_name: [0; 64],
            file_name_len: 0,
        }
    }

    /// Record a page access
    pub fn record_page(&mut self, page_index: usize) {
        if page_index < MAX_PAGES_PER_SECTION {
            let word = page_index / 64;
            let bit = page_index % 64;
            if self.pages_accessed[word] & (1 << bit) == 0 {
                self.pages_accessed[word] |= 1 << bit;
                self.page_count += 1;
            }
        }
    }

    /// Check if a page was accessed
    pub fn is_page_accessed(&self, page_index: usize) -> bool {
        if page_index < MAX_PAGES_PER_SECTION {
            let word = page_index / 64;
            let bit = page_index % 64;
            (self.pages_accessed[word] & (1 << bit)) != 0
        } else {
            false
        }
    }

    /// Get total accessed pages
    pub fn accessed_page_count(&self) -> u32 {
        self.pages_accessed.iter().map(|w| w.count_ones()).sum()
    }
}

/// Prefetch trace context
#[repr(C)]
pub struct PrefetchTrace {
    /// Current state
    pub state: TraceState,
    /// Scenario type
    pub scenario_type: ScenarioType,
    /// Scenario ID (hash of executable path)
    pub scenario_id: u32,
    /// Trace start time (in system ticks)
    pub start_time: u64,
    /// Trace end time
    pub end_time: u64,
    /// Total pages faulted
    pub pages_faulted: u32,
    /// Total I/O operations
    pub io_count: u32,
    /// Sections in this trace
    pub sections: [PrefetchSectionInfo; MAX_SECTIONS_PER_TRACE],
    /// Number of active sections
    pub section_count: usize,
    /// Executable path hash
    pub exe_hash: u32,
    /// Process ID being traced
    pub process_id: u32,
}

impl Default for PrefetchTrace {
    fn default() -> Self {
        Self::new()
    }
}

impl PrefetchTrace {
    pub const fn new() -> Self {
        Self {
            state: TraceState::Free,
            scenario_type: ScenarioType::App,
            scenario_id: 0,
            start_time: 0,
            end_time: 0,
            pages_faulted: 0,
            io_count: 0,
            sections: [PrefetchSectionInfo::new(); MAX_SECTIONS_PER_TRACE],
            section_count: 0,
            exe_hash: 0,
            process_id: 0,
        }
    }

    /// Reset the trace for reuse
    pub fn reset(&mut self) {
        self.state = TraceState::Free;
        self.scenario_type = ScenarioType::App;
        self.scenario_id = 0;
        self.start_time = 0;
        self.end_time = 0;
        self.pages_faulted = 0;
        self.io_count = 0;
        self.section_count = 0;
        self.exe_hash = 0;
        self.process_id = 0;

        for section in self.sections.iter_mut() {
            *section = PrefetchSectionInfo::new();
        }
    }

    /// Find or add a section for a file
    pub fn find_or_add_section(&mut self, file_object: usize, file_hash: u32) -> Option<usize> {
        // Look for existing section
        for i in 0..self.section_count {
            if self.sections[i].file_object == file_object {
                return Some(i);
            }
        }

        // Add new section
        if self.section_count < MAX_SECTIONS_PER_TRACE {
            let idx = self.section_count;
            self.sections[idx].file_object = file_object;
            self.sections[idx].file_hash = file_hash;
            self.section_count += 1;
            Some(idx)
        } else {
            None
        }
    }

    /// Record a page fault for the trace
    pub fn record_fault(&mut self, file_object: usize, file_hash: u32, page_offset: u64) {
        if self.state != TraceState::Active {
            return;
        }

        if let Some(section_idx) = self.find_or_add_section(file_object, file_hash) {
            let page_index = (page_offset / 4096) as usize;
            self.sections[section_idx].record_page(page_index);
            self.pages_faulted += 1;
        }
    }

    /// Record an I/O operation
    pub fn record_io(&mut self) {
        if self.state == TraceState::Active {
            self.io_count += 1;
        }
    }

    /// Get trace duration in ticks
    pub fn duration(&self) -> u64 {
        if self.end_time > self.start_time {
            self.end_time - self.start_time
        } else {
            0
        }
    }
}

/// Stored prefetch scenario (from completed traces)
#[derive(Clone)]
pub struct PrefetchScenario {
    /// Scenario ID
    pub scenario_id: u32,
    /// Scenario type
    pub scenario_type: ScenarioType,
    /// Number of times this scenario ran
    pub launch_count: u32,
    /// Average pages faulted
    pub avg_pages: u32,
    /// Last update time
    pub last_update: u64,
    /// Section data
    pub sections: Vec<PrefetchSectionInfo>,
}

impl PrefetchScenario {
    pub fn new(scenario_id: u32, scenario_type: ScenarioType) -> Self {
        Self {
            scenario_id,
            scenario_type,
            launch_count: 0,
            avg_pages: 0,
            last_update: 0,
            sections: Vec::new(),
        }
    }

    /// Merge data from a completed trace
    pub fn merge_trace(&mut self, trace: &PrefetchTrace) {
        self.launch_count += 1;

        // Update average pages (rolling average)
        self.avg_pages = (self.avg_pages * (self.launch_count - 1) + trace.pages_faulted)
            / self.launch_count;

        // Merge section data
        for i in 0..trace.section_count {
            let trace_section = &trace.sections[i];

            // Find matching section or add new
            let existing = self.sections.iter_mut()
                .find(|s| s.file_hash == trace_section.file_hash);

            if let Some(section) = existing {
                // Merge page bitmaps (union)
                for j in 0..4 {
                    section.pages_accessed[j] |= trace_section.pages_accessed[j];
                }
                section.page_count = section.accessed_page_count();
            } else if self.sections.len() < MAX_SECTIONS_PER_TRACE {
                self.sections.push(trace_section.clone());
            }
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Active traces
static mut ACTIVE_TRACES: [PrefetchTrace; MAX_CONCURRENT_TRACES] = {
    const INIT: PrefetchTrace = PrefetchTrace::new();
    [INIT; MAX_CONCURRENT_TRACES]
};

/// Trace lock
static TRACE_LOCK: SpinLock<()> = SpinLock::new(());

/// Stored scenarios
static mut STORED_SCENARIOS: Option<Vec<PrefetchScenario>> = None;

/// Prefetcher enabled flag
static mut PREFETCH_ENABLED: bool = true;

/// Prefetch statistics
static mut PREFETCH_STATS: PrefetchStats = PrefetchStats::new();

/// Prefetch statistics
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PrefetchStats {
    pub traces_started: u64,
    pub traces_completed: u64,
    pub traces_aborted: u64,
    pub pages_prefetched: u64,
    pub prefetch_hits: u64,
    pub prefetch_misses: u64,
    pub scenarios_stored: u32,
}

impl Default for PrefetchStats {
    fn default() -> Self {
        Self::new()
    }
}

impl PrefetchStats {
    pub const fn new() -> Self {
        Self {
            traces_started: 0,
            traces_completed: 0,
            traces_aborted: 0,
            pages_prefetched: 0,
            prefetch_hits: 0,
            prefetch_misses: 0,
            scenarios_stored: 0,
        }
    }

    /// Calculate prefetch hit rate
    pub fn hit_rate_percent(&self) -> u32 {
        let total = self.prefetch_hits + self.prefetch_misses;
        if total == 0 {
            0
        } else {
            ((self.prefetch_hits * 100) / total) as u32
        }
    }
}

// ============================================================================
// Prefetch API
// ============================================================================

/// Hash a file path for scenario identification
pub fn hash_path(path: &str) -> u32 {
    let mut hash: u32 = 0;
    for byte in path.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
    }
    hash
}

/// Begin tracing a prefetch scenario
pub fn pf_begin_trace(
    scenario_type: ScenarioType,
    exe_path: &str,
    process_id: u32,
) -> Option<usize> {
    unsafe {
        if !PREFETCH_ENABLED {
            return None;
        }

        let _guard = TRACE_LOCK.lock();

        // Find a free trace slot
        for i in 0..MAX_CONCURRENT_TRACES {
            if ACTIVE_TRACES[i].state == TraceState::Free {
                let trace = &mut ACTIVE_TRACES[i];
                trace.reset();
                trace.state = TraceState::Active;
                trace.scenario_type = scenario_type;
                trace.exe_hash = hash_path(exe_path);
                trace.scenario_id = trace.exe_hash ^ (process_id << 16);
                trace.process_id = process_id;
                // Would get actual time from HAL
                trace.start_time = 0;

                PREFETCH_STATS.traces_started += 1;
                return Some(i);
            }
        }

        None
    }
}

/// End a prefetch trace
pub fn pf_end_trace(trace_index: usize, success: bool) {
    unsafe {
        if trace_index >= MAX_CONCURRENT_TRACES {
            return;
        }

        let _guard = TRACE_LOCK.lock();
        let trace = &mut ACTIVE_TRACES[trace_index];

        if trace.state != TraceState::Active {
            return;
        }

        // Would get actual time from HAL
        trace.end_time = trace.start_time + 1;

        if success {
            trace.state = TraceState::Complete;
            PREFETCH_STATS.traces_completed += 1;

            // Store the scenario
            store_scenario(trace);
        } else {
            trace.state = TraceState::Free;
            PREFETCH_STATS.traces_aborted += 1;
        }
    }
}

/// Record a page fault during active trace
pub fn pf_record_fault(
    process_id: u32,
    file_object: usize,
    file_hash: u32,
    page_offset: u64,
) {
    unsafe {
        if !PREFETCH_ENABLED {
            return;
        }

        let _guard = TRACE_LOCK.lock();

        // Find the trace for this process
        for trace in ACTIVE_TRACES.iter_mut() {
            if trace.state == TraceState::Active && trace.process_id == process_id {
                trace.record_fault(file_object, file_hash, page_offset);
                return;
            }
        }
    }
}

/// Record an I/O operation during active trace
pub fn pf_record_io(process_id: u32) {
    unsafe {
        if !PREFETCH_ENABLED {
            return;
        }

        let _guard = TRACE_LOCK.lock();

        for trace in ACTIVE_TRACES.iter_mut() {
            if trace.state == TraceState::Active && trace.process_id == process_id {
                trace.record_io();
                return;
            }
        }
    }
}

/// Store a completed scenario
unsafe fn store_scenario(trace: &PrefetchTrace) {
    // Initialize storage if needed
    if STORED_SCENARIOS.is_none() {
        STORED_SCENARIOS = Some(Vec::with_capacity(MAX_PREFETCH_SCENARIOS));
    }

    let scenarios = STORED_SCENARIOS.as_mut().unwrap();

    // Find existing scenario or create new
    let existing = scenarios.iter_mut()
        .find(|s| s.scenario_id == trace.scenario_id);

    if let Some(scenario) = existing {
        scenario.merge_trace(trace);
    } else if scenarios.len() < MAX_PREFETCH_SCENARIOS {
        let mut scenario = PrefetchScenario::new(trace.scenario_id, trace.scenario_type);
        scenario.merge_trace(trace);
        scenarios.push(scenario);
        PREFETCH_STATS.scenarios_stored += 1;
    }
}

/// Query prefetch data for a scenario
pub fn pf_query_scenario(exe_path: &str) -> Option<PrefetchQueryResult> {
    unsafe {
        let exe_hash = hash_path(exe_path);

        let scenarios = STORED_SCENARIOS.as_ref()?;

        for scenario in scenarios.iter() {
            if scenario.sections.iter().any(|s| s.file_hash == exe_hash)
                || (scenario.scenario_id >> 16) == (exe_hash >> 16) {
                return Some(PrefetchQueryResult {
                    found: true,
                    launch_count: scenario.launch_count,
                    avg_pages: scenario.avg_pages,
                    section_count: scenario.sections.len() as u32,
                });
            }
        }

        None
    }
}

/// Result of prefetch query
#[derive(Debug, Clone, Copy)]
pub struct PrefetchQueryResult {
    pub found: bool,
    pub launch_count: u32,
    pub avg_pages: u32,
    pub section_count: u32,
}

/// Prefetch data for an application launch
pub fn pf_prefetch_scenario(exe_path: &str) -> u32 {
    unsafe {
        if !PREFETCH_ENABLED {
            return 0;
        }

        let exe_hash = hash_path(exe_path);

        let scenarios = match STORED_SCENARIOS.as_ref() {
            Some(s) => s,
            None => return 0,
        };

        // Find matching scenario
        for scenario in scenarios.iter() {
            // Match by executable hash in any section or scenario ID
            let matches = scenario.sections.iter().any(|s| s.file_hash == exe_hash);

            if matches {
                let mut pages_prefetched = 0u32;

                // Prefetch each section
                for section in &scenario.sections {
                    pages_prefetched += prefetch_section(section);
                }

                PREFETCH_STATS.pages_prefetched += pages_prefetched as u64;
                return pages_prefetched;
            }
        }

        PREFETCH_STATS.prefetch_misses += 1;
        0
    }
}

/// Prefetch a single section's pages
fn prefetch_section(section: &PrefetchSectionInfo) -> u32 {
    // In a real implementation, this would:
    // 1. Open the file by its stored path
    // 2. Map the required pages into the cache
    // 3. Issue async I/O to read pages marked in the bitmap

    // For now, return the count of pages that would be prefetched
    section.accessed_page_count()
}

/// Get prefetch statistics
pub fn pf_get_stats() -> PrefetchStats {
    unsafe { PREFETCH_STATS }
}

/// Enable or disable prefetching
pub fn pf_set_enabled(enabled: bool) {
    unsafe {
        PREFETCH_ENABLED = enabled;
    }
}

/// Check if prefetching is enabled
pub fn pf_is_enabled() -> bool {
    unsafe { PREFETCH_ENABLED }
}

/// Get active trace count
pub fn pf_active_trace_count() -> usize {
    unsafe {
        let _guard = TRACE_LOCK.lock();
        ACTIVE_TRACES.iter()
            .filter(|t| t.state == TraceState::Active)
            .count()
    }
}

/// Get stored scenario count
pub fn pf_scenario_count() -> usize {
    unsafe {
        STORED_SCENARIOS.as_ref()
            .map(|s| s.len())
            .unwrap_or(0)
    }
}

// ============================================================================
// Boot Prefetch
// ============================================================================

/// Boot prefetch state
static mut BOOT_TRACE_ACTIVE: bool = false;
static mut BOOT_TRACE_INDEX: usize = 0;

/// Begin boot prefetch tracing
pub fn pf_begin_boot_trace() -> bool {
    unsafe {
        if BOOT_TRACE_ACTIVE {
            return false;
        }

        if let Some(idx) = pf_begin_trace(ScenarioType::Boot, "\\SystemRoot\\System32\\ntoskrnl.exe", 0) {
            BOOT_TRACE_ACTIVE = true;
            BOOT_TRACE_INDEX = idx;
            true
        } else {
            false
        }
    }
}

/// End boot prefetch tracing
pub fn pf_end_boot_trace(success: bool) {
    unsafe {
        if !BOOT_TRACE_ACTIVE {
            return;
        }

        pf_end_trace(BOOT_TRACE_INDEX, success);
        BOOT_TRACE_ACTIVE = false;
    }
}

/// Apply boot prefetch data
pub fn pf_apply_boot_prefetch() -> u32 {
    pf_prefetch_scenario("\\SystemRoot\\System32\\ntoskrnl.exe")
}

// ============================================================================
// Prefetch File Format (for persistence)
// ============================================================================

/// Prefetch file header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PrefetchFileHeader {
    /// Version
    pub version: u32,
    /// Magic "SCCA"
    pub magic: [u8; 4],
    /// File size
    pub file_size: u32,
    /// Executable name offset
    pub exe_name_offset: u32,
    /// Executable name length
    pub exe_name_length: u32,
    /// Hash value
    pub hash: u32,
    /// Number of file references
    pub file_count: u32,
    /// Number of directory references
    pub dir_count: u32,
    /// Number of volumes
    pub volume_count: u32,
    /// Total length of volume info
    pub volume_info_length: u32,
    /// Last run time
    pub last_run_time: u64,
    /// Run count
    pub run_count: u32,
}

impl PrefetchFileHeader {
    pub const MAGIC: [u8; 4] = [b'S', b'C', b'C', b'A'];
    pub const VERSION_XP: u32 = 17;
    pub const VERSION_VISTA: u32 = 23;
    pub const VERSION_WIN8: u32 = 26;
    pub const VERSION_WIN10: u32 = 30;

    /// Create a new prefetch file header
    pub fn new(hash: u32, run_count: u32) -> Self {
        Self {
            version: Self::VERSION_XP,
            magic: Self::MAGIC,
            file_size: 0,
            exe_name_offset: core::mem::size_of::<Self>() as u32,
            exe_name_length: 0,
            hash,
            file_count: 0,
            dir_count: 0,
            volume_count: 0,
            volume_info_length: 0,
            last_run_time: 0,
            run_count,
        }
    }

    /// Validate header magic
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

/// File metrics entry in prefetch file
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileMetricsEntry {
    /// Start time
    pub start_time: u32,
    /// Duration
    pub duration: u32,
    /// Average duration
    pub avg_duration: u32,
    /// File name offset
    pub file_name_offset: u32,
    /// File name length
    pub file_name_length: u32,
    /// Flags
    pub flags: u32,
}

impl FileMetricsEntry {
    pub const fn new() -> Self {
        Self {
            start_time: 0,
            duration: 0,
            avg_duration: 0,
            file_name_offset: 0,
            file_name_length: 0,
            flags: 0,
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the prefetcher
pub fn init() {
    unsafe {
        PREFETCH_ENABLED = true;
        PREFETCH_STATS = PrefetchStats::new();
        STORED_SCENARIOS = Some(Vec::with_capacity(MAX_PREFETCH_SCENARIOS));
        BOOT_TRACE_ACTIVE = false;

        for trace in ACTIVE_TRACES.iter_mut() {
            trace.reset();
        }
    }

    crate::serial_println!("[CC] Prefetcher initialized");
}

/// Prefetch trace snapshot for diagnostics
#[derive(Debug, Clone, Copy)]
pub struct TraceSnapshot {
    pub index: usize,
    pub state: TraceState,
    pub scenario_type: ScenarioType,
    pub process_id: u32,
    pub pages_faulted: u32,
    pub section_count: usize,
}

/// Get snapshots of active traces
pub fn pf_get_trace_snapshots() -> ([TraceSnapshot; MAX_CONCURRENT_TRACES], usize) {
    let mut snapshots = [TraceSnapshot {
        index: 0,
        state: TraceState::Free,
        scenario_type: ScenarioType::App,
        process_id: 0,
        pages_faulted: 0,
        section_count: 0,
    }; MAX_CONCURRENT_TRACES];

    let mut count = 0;

    unsafe {
        let _guard = TRACE_LOCK.lock();

        for (i, trace) in ACTIVE_TRACES.iter().enumerate() {
            if trace.state != TraceState::Free {
                snapshots[count] = TraceSnapshot {
                    index: i,
                    state: trace.state,
                    scenario_type: trace.scenario_type,
                    process_id: trace.process_id,
                    pages_faulted: trace.pages_faulted,
                    section_count: trace.section_count,
                };
                count += 1;
            }
        }
    }

    (snapshots, count)
}
